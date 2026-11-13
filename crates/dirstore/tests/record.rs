//! The record codec: canonical round trip and bounded, fail-closed decoding.
//!
//! Source: the record layout documented in src/record.rs (this project's own
//! codec, docs/10 D34; bounded parser, docs/32 §8 / D138). Every byte vector
//! here is hand-derived from that documented layout; none comes from another
//! implementation.

use dirstore::record::{
    back_link_key, back_link_prefix, decode_back_link_body, decode_back_link_key,
    decode_child_count_body, decode_meta_body, decode_name_index_body, decode_object_body,
    decode_unique_index_body, encode_back_link_body, encode_child_count_body, encode_meta_body,
    encode_name_index_body, encode_object_body, encode_unique_index_body, name_index_key,
    name_index_prefix, unique_index_key, BACK_LINK_KEY_LEN, RECORD_FORMAT_V1,
};
use dirstore::{
    AttrId, AttrStamp, Attribute, ClassId, DecodeError, NodeId, Object, StampedValue, Timestamp,
    Violation, MAX_ATTRIBUTES_PER_OBJECT, MAX_CLASSES_PER_OBJECT, MAX_RDN_KEY_LEN,
    MAX_RECORD_BODY_LEN, MAX_VALUES_PER_ATTRIBUTE, MAX_VALUE_LEN,
};
use dtyp::Guid;
use std::num::NonZeroU64;

const G: Guid = Guid {
    data1: 0x0102_0304,
    data2: 0x0506,
    data3: 0x0708,
    data4: [9, 10, 11, 12, 13, 14, 15, 16],
};
const P: Guid = Guid {
    data1: 0xA1A2_A3A4,
    data2: 0xB1B2,
    data3: 0xC1C2,
    data4: [0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8],
};

fn st(version: u64) -> AttrStamp {
    AttrStamp {
        version,
        wall_clock: Timestamp(0x1122_3344_5566_7788),
        origin_node: NodeId([0xEE; 16]),
        origin_seq: 9,
    }
}

/// Big-endian body builder for hand-written vectors.
#[derive(Default)]
struct B(Vec<u8>);
impl B {
    fn u8(mut self, v: u8) -> B {
        self.0.push(v);
        self
    }
    fn u16(mut self, v: u16) -> B {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    fn u32(mut self, v: u32) -> B {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    fn bytes(mut self, b: &[u8]) -> B {
        self.0.extend_from_slice(b);
        self
    }
    fn stamp(self, s: &AttrStamp) -> B {
        self.bytes(&s.version.to_be_bytes())
            .bytes(&s.wall_clock.0.to_be_bytes())
            .bytes(&s.origin_node.0)
            .bytes(&s.origin_seq.to_be_bytes())
    }
}

/// Hand-derived from the documented layout: a root object, RDN "r", class 7,
/// one attribute 3 with one value "v" stamped st(1).
fn minimal_body() -> Vec<u8> {
    B::default()
        .u8(RECORD_FORMAT_V1)
        .u8(0x00) // flags: no parent, not a tombstone
        .u16(1)
        .bytes(b"r")
        .u16(1)
        .u32(7)
        .u16(1)
        .u32(3)
        .u16(1)
        .stamp(&st(1))
        .u32(1)
        .bytes(b"v")
        .0
}

fn minimal_object() -> Object {
    Object {
        guid: G,
        parent: None,
        rdn: b"r".to_vec(),
        classes: vec![ClassId(7)],
        attributes: vec![Attribute {
            id: AttrId(3),
            values: vec![StampedValue {
                value: b"v".to_vec(),
                stamp: st(1),
            }],
        }],
        tombstone: None,
    }
}

fn rich_object() -> Object {
    Object {
        guid: G,
        parent: Some(P),
        rdn: b"cn=x".to_vec(),
        classes: vec![ClassId(1), ClassId(5)],
        attributes: vec![
            Attribute {
                id: AttrId(1),
                values: vec![
                    StampedValue {
                        value: vec![],
                        stamp: st(1),
                    },
                    StampedValue {
                        value: b"a".to_vec(),
                        stamp: st(2),
                    },
                    StampedValue {
                        value: b"ab".to_vec(),
                        stamp: st(3),
                    },
                ],
            },
            Attribute {
                id: AttrId(9),
                values: vec![StampedValue {
                    value: vec![0xFF; 40],
                    stamp: st(4),
                }],
            },
        ],
        tombstone: None,
    }
}

/// A canonical tombstone: identity (classes) + deletion stamp only
/// (src/record.rs layout; Q-062 / A-18).
fn tombstone_object() -> Object {
    Object {
        guid: G,
        parent: None,
        rdn: Vec::new(),
        classes: vec![ClassId(1), ClassId(5)],
        attributes: Vec::new(),
        tombstone: Some(st(5)),
    }
}

/// Hand-derived from the documented layout: the tombstone of
/// `tombstone_object()`.
fn tombstone_body() -> Vec<u8> {
    B::default()
        .u8(RECORD_FORMAT_V1)
        .u8(0x02) // flags: TOMBSTONE only
        .u16(0) // rdn_len = 0, no RDN bytes
        .stamp(&st(5)) // deletion stamp
        .u16(2)
        .u32(1)
        .u32(5)
        .u16(0) // attribute_count = 0
        .0
}

#[test]
fn hand_derived_vector_decodes_and_encodes() {
    // Source: src/record.rs layout table.
    let body = minimal_body();
    assert_eq!(decode_object_body(G, &body).unwrap(), minimal_object());
    assert_eq!(encode_object_body(&minimal_object()).unwrap(), body);
}

#[test]
fn hand_derived_tombstone_vector_decodes_and_encodes() {
    // Source: src/record.rs layout table (tombstone form; Q-062 / A-18).
    let body = tombstone_body();
    assert_eq!(decode_object_body(G, &body).unwrap(), tombstone_object());
    assert_eq!(encode_object_body(&tombstone_object()).unwrap(), body);
}

#[test]
fn round_trip_with_parent_and_many_values() {
    // Source: src/record.rs — decode(encode(o)) == o; encode(decode(b)) == b.
    let obj = rich_object();
    let body = encode_object_body(&obj).unwrap();
    // Layout spot checks: flags = HAS_PARENT, then the parent.
    assert_eq!(body[0], RECORD_FORMAT_V1);
    assert_eq!(body[1], 0x01);
    assert_eq!(&body[2..18], &P.to_packet());
    let back = decode_object_body(G, &body).unwrap();
    assert_eq!(back, obj);
    assert_eq!(encode_object_body(&back).unwrap(), body);
}

#[test]
fn tombstone_carrying_content_is_rejected() {
    // Source: src/record.rs — a tombstone body with a parent, an RDN key or
    // any attribute is not canonical and is refused (Q-062 / A-18; docs/29
    // §5, docs/25 §5 "state").
    let stamp_and_classes = |b: B| b.stamp(&st(5)).u16(1).u32(1);

    // With a parent (HAS_PARENT | TOMBSTONE).
    let with_parent = stamp_and_classes(
        B::default()
            .u8(RECORD_FORMAT_V1)
            .u8(0x03)
            .bytes(&P.to_packet())
            .u16(0),
    )
    .u16(0);
    assert_eq!(
        decode_object_body(G, &with_parent.0),
        Err(DecodeError::TombstoneContent)
    );
    // With an RDN key.
    let with_rdn = stamp_and_classes(
        B::default()
            .u8(RECORD_FORMAT_V1)
            .u8(0x02)
            .u16(1)
            .bytes(b"r"),
    )
    .u16(0);
    assert_eq!(
        decode_object_body(G, &with_rdn.0),
        Err(DecodeError::TombstoneContent)
    );
    // With an attribute.
    let with_attr = stamp_and_classes(B::default().u8(RECORD_FORMAT_V1).u8(0x02).u16(0))
        .u16(1)
        .u32(3)
        .u16(1)
        .stamp(&st(1))
        .u32(1)
        .bytes(b"v");
    assert_eq!(
        decode_object_body(G, &with_attr.0),
        Err(DecodeError::TombstoneContent)
    );
    // A live object with rdn_len = 0 stays rejected as before.
    let live_empty_rdn = B::default()
        .u8(RECORD_FORMAT_V1)
        .u8(0x00)
        .u16(0)
        .u16(1)
        .u32(1)
        .u16(0);
    assert_eq!(
        decode_object_body(G, &live_empty_rdn.0),
        Err(DecodeError::RdnKeyLength)
    );

    // The encoder refuses the same three shapes.
    for o in [
        Object {
            parent: Some(P),
            ..tombstone_object()
        },
        Object {
            rdn: b"r".to_vec(),
            ..tombstone_object()
        },
        Object {
            attributes: minimal_object().attributes,
            ..tombstone_object()
        },
    ] {
        assert_eq!(
            encode_object_body(&o),
            Err(Violation::TombstoneCarriesContent)
        );
    }
}

#[test]
fn every_truncation_fails_closed() {
    // Source: docs/32 §8 — never read past the input, never panic.
    for body in [
        encode_object_body(&rich_object()).unwrap(),
        tombstone_body(),
    ] {
        for n in 0..body.len() {
            assert!(decode_object_body(G, &body[..n]).is_err(), "prefix {n}");
        }
    }
}

#[test]
fn single_byte_mutation_sweep_never_panics_and_stays_canonical() {
    // Source: docs/32 §8 (D138) — the property the fuzz target
    // (fuzz/fuzz_targets/dirstore_record_decode.rs) checks, run here
    // deterministically while the fuzz harness awaits owner approval (P-1):
    // decoding any mutated body fails closed or yields an object whose
    // canonical encoding is exactly the input. Live and tombstone bodies.
    for body in [
        encode_object_body(&rich_object()).unwrap(),
        tombstone_body(),
    ] {
        for i in 0..body.len() {
            for m in [
                0x00,
                0xFF,
                body[i] ^ 0x01,
                body[i] ^ 0x02,
                body[i] ^ 0x80,
                body[i].wrapping_add(1),
            ] {
                let mut mutated = body.clone();
                mutated[i] = m;
                if let Ok(obj) = decode_object_body(G, &mutated) {
                    assert_eq!(encode_object_body(&obj).unwrap(), mutated, "byte {i}");
                }
            }
        }
    }
}

#[test]
fn framing_and_format_errors() {
    // Source: src/record.rs rules (strict framing, defined flags, format).
    let good = minimal_body();
    let mut trailing = good.clone();
    trailing.push(0);
    assert_eq!(
        decode_object_body(G, &trailing),
        Err(DecodeError::TrailingData)
    );
    let mut format = good.clone();
    format[0] = 2;
    assert_eq!(
        decode_object_body(G, &format),
        Err(DecodeError::UnsupportedFormat)
    );
    let mut flags = good.clone();
    flags[1] = 0x04;
    assert_eq!(
        decode_object_body(G, &flags),
        Err(DecodeError::UndefinedFlags)
    );
    assert_eq!(decode_object_body(G, &[]), Err(DecodeError::Truncated));
    let huge = vec![0u8; MAX_RECORD_BODY_LEN + 1];
    assert_eq!(
        decode_object_body(G, &huge),
        Err(DecodeError::RecordTooLarge)
    );
}

#[test]
fn count_and_length_bounds_on_read() {
    // Source: docs/32 §8 — every count / length is checked against its bound
    // before use (read-side enforcement of the documented bounds).
    let head = || B::default().u8(RECORD_FORMAT_V1).u8(0);
    let rdn_too_long = u16::try_from(MAX_RDN_KEY_LEN + 1).unwrap();
    assert_eq!(
        decode_object_body(G, &head().u16(0).0),
        Err(DecodeError::RdnKeyLength)
    );
    assert_eq!(
        decode_object_body(G, &head().u16(rdn_too_long).0),
        Err(DecodeError::RdnKeyLength)
    );
    let with_rdn = || head().u16(1).bytes(b"r");
    assert_eq!(
        decode_object_body(G, &with_rdn().u16(0).0),
        Err(DecodeError::ClassCount)
    );
    let too_many_classes = u16::try_from(MAX_CLASSES_PER_OBJECT + 1).unwrap();
    assert_eq!(
        decode_object_body(G, &with_rdn().u16(too_many_classes).0),
        Err(DecodeError::ClassCount)
    );
    assert_eq!(
        decode_object_body(G, &with_rdn().u16(2).u32(5).u32(5).0),
        Err(DecodeError::ClassOrder)
    );
    assert_eq!(
        decode_object_body(G, &with_rdn().u16(2).u32(6).u32(5).0),
        Err(DecodeError::ClassOrder)
    );
    let with_class = || with_rdn().u16(1).u32(1);
    let too_many_attrs = u16::try_from(MAX_ATTRIBUTES_PER_OBJECT + 1).unwrap();
    assert_eq!(
        decode_object_body(G, &with_class().u16(too_many_attrs).0),
        Err(DecodeError::AttributeCount)
    );
    let value = |b: B, v: &[u8]| {
        b.stamp(&st(1))
            .u32(u32::try_from(v.len()).unwrap())
            .bytes(v)
    };
    // Attribute ids out of order.
    let two_attrs = value(
        value(with_class().u16(2).u32(4).u16(1), b"x").u32(4).u16(1),
        b"y",
    );
    assert_eq!(
        decode_object_body(G, &two_attrs.0),
        Err(DecodeError::AttributeOrder)
    );
    assert_eq!(
        decode_object_body(G, &with_class().u16(1).u32(4).u16(0).0),
        Err(DecodeError::ValueCount)
    );
    let too_many_values = u16::try_from(MAX_VALUES_PER_ATTRIBUTE + 1).unwrap();
    assert_eq!(
        decode_object_body(G, &with_class().u16(1).u32(4).u16(too_many_values).0),
        Err(DecodeError::ValueCount)
    );
    // A declared value length above the bound is refused before any read.
    let too_long = u32::try_from(MAX_VALUE_LEN + 1).unwrap();
    assert_eq!(
        decode_object_body(
            G,
            &with_class()
                .u16(1)
                .u32(4)
                .u16(1)
                .stamp(&st(1))
                .u32(too_long)
                .0
        ),
        Err(DecodeError::ValueLength)
    );
    // Values must be strictly ascending (a set).
    let dup = value(value(with_class().u16(1).u32(4).u16(2), b"a"), b"a");
    assert_eq!(decode_object_body(G, &dup.0), Err(DecodeError::ValueOrder));
    let desc = value(value(with_class().u16(1).u32(4).u16(2), b"b"), b"a");
    assert_eq!(decode_object_body(G, &desc.0), Err(DecodeError::ValueOrder));
    // A large declared count with no data behind it is just truncated (no
    // allocation follows from the count).
    let max_values = u16::try_from(MAX_VALUES_PER_ATTRIBUTE).unwrap();
    assert_eq!(
        decode_object_body(G, &with_class().u16(1).u32(4).u16(max_values).0),
        Err(DecodeError::Truncated)
    );
}

#[test]
fn encoder_refuses_what_the_decoder_rejects() {
    // Source: src/record.rs — the encoder is canonical and bounded.
    let mut o = minimal_object();
    o.rdn.clear();
    assert_eq!(encode_object_body(&o), Err(Violation::RdnKeyEmpty));
    let mut o = minimal_object();
    o.rdn = vec![b'r'; MAX_RDN_KEY_LEN + 1];
    assert_eq!(encode_object_body(&o), Err(Violation::RdnKeyTooLong));
    let mut o = minimal_object();
    o.classes = vec![ClassId(2), ClassId(1)];
    assert_eq!(encode_object_body(&o), Err(Violation::NotCanonical));
    let mut o = minimal_object();
    o.classes.clear();
    assert_eq!(encode_object_body(&o), Err(Violation::NoObjectClass));
    let mut o = rich_object();
    o.attributes[0].values.swap(0, 1);
    assert_eq!(encode_object_body(&o), Err(Violation::NotCanonical));
    let mut o = rich_object();
    o.attributes.swap(0, 1);
    assert_eq!(encode_object_body(&o), Err(Violation::NotCanonical));
    let mut o = minimal_object();
    o.attributes[0].values[0].value = vec![0; MAX_VALUE_LEN + 1];
    assert_eq!(
        encode_object_body(&o),
        Err(Violation::ValueTooLarge(AttrId(3)))
    );
    let mut o = minimal_object();
    o.attributes[0].values.clear();
    assert_eq!(
        encode_object_body(&o),
        Err(Violation::EmptyAttribute(AttrId(3)))
    );
}

#[test]
fn index_and_meta_bodies() {
    // Source: src/record.rs (name-index, child-count and meta layouts).
    let body = encode_name_index_body(G);
    assert_eq!(body.len(), 17);
    assert_eq!(body[0], RECORD_FORMAT_V1);
    assert_eq!(&body[1..], &G.to_packet());
    assert_eq!(decode_name_index_body(&body), Ok(G));
    assert_eq!(
        decode_name_index_body(&body[..16]),
        Err(DecodeError::Truncated)
    );
    let mut long = body.clone();
    long.push(0);
    assert_eq!(
        decode_name_index_body(&long),
        Err(DecodeError::TrailingData)
    );

    let three = NonZeroU64::new(3).unwrap();
    let count = encode_child_count_body(three);
    assert_eq!(count, vec![RECORD_FORMAT_V1, 0, 0, 0, 0, 0, 0, 0, 3]);
    assert_eq!(decode_child_count_body(&count), Ok(three));
    assert_eq!(
        decode_child_count_body(&[RECORD_FORMAT_V1, 0, 0, 0, 0, 0, 0, 0, 0]),
        Err(DecodeError::ZeroChildCount)
    );

    assert_eq!(encode_meta_body(), vec![RECORD_FORMAT_V1]);
    assert_eq!(decode_meta_body(&[RECORD_FORMAT_V1]), Ok(()));
    assert_eq!(decode_meta_body(&[2]), Err(DecodeError::UnsupportedFormat));
}

#[test]
fn back_link_key_and_body_layout() {
    // Source: src/record.rs reverse-link layout; docs/46 §8.4 ("key (target
    // GUID, back link_id u32 BE, source GUID)").
    let key = back_link_key(G, 3, P);
    assert_eq!(key.len(), BACK_LINK_KEY_LEN);
    assert_eq!(BACK_LINK_KEY_LEN, 36);
    assert_eq!(&key[..16], &G.to_packet());
    assert_eq!(&key[16..20], &[0, 0, 0, 3]);
    assert_eq!(&key[20..], &P.to_packet());
    assert_eq!(decode_back_link_key(&key), Ok((G, 3, P)));
    // The scan prefixes are exactly the leading parts of the key.
    assert_eq!(back_link_prefix(G, None).as_slice(), &key[..16]);
    assert_eq!(back_link_prefix(G, Some(3)).as_slice(), &key[..20]);
    // A key of any other length is refused (it is read back from disk).
    assert_eq!(
        decode_back_link_key(&key[..35]),
        Err(DecodeError::KeyLength)
    );
    let mut long = key.to_vec();
    long.push(0);
    assert_eq!(decode_back_link_key(&long), Err(DecodeError::KeyLength));
    // Body: the format byte only.
    assert_eq!(encode_back_link_body(), vec![RECORD_FORMAT_V1]);
    assert_eq!(decode_back_link_body(&[RECORD_FORMAT_V1]), Ok(()));
    assert_eq!(decode_back_link_body(&[]), Err(DecodeError::Truncated));
    assert_eq!(
        decode_back_link_body(&[2]),
        Err(DecodeError::UnsupportedFormat)
    );
    assert_eq!(
        decode_back_link_body(&[RECORD_FORMAT_V1, 0]),
        Err(DecodeError::TrailingData)
    );
}

#[test]
fn unique_index_key_and_body_layout() {
    // Source: src/record.rs unique-index layout; docs/46 §8.5.
    assert_eq!(
        unique_index_key(AttrId(0x0102_0304), b"ab"),
        vec![1, 2, 3, 4, b'a', b'b']
    );
    // Attribute 0 is an ordinary id (docs/46 §8.6); the empty key is a key.
    assert_eq!(unique_index_key(AttrId(0), b""), vec![0, 0, 0, 0]);
    let body = encode_unique_index_body(G);
    assert_eq!(body.len(), 17);
    assert_eq!(body[0], RECORD_FORMAT_V1);
    assert_eq!(&body[1..], &G.to_packet());
    assert_eq!(decode_unique_index_body(&body), Ok(G));
    assert_eq!(
        decode_unique_index_body(&body[..16]),
        Err(DecodeError::Truncated)
    );
    let mut long = body.clone();
    long.push(0);
    assert_eq!(
        decode_unique_index_body(&long),
        Err(DecodeError::TrailingData)
    );
    let mut format = body;
    format[0] = 2;
    assert_eq!(
        decode_unique_index_body(&format),
        Err(DecodeError::UnsupportedFormat)
    );
}

#[test]
fn name_index_keys_keep_roots_and_children_apart() {
    // Source: src/record.rs — 0x00 || rdn for a root, 0x01 || parent || rdn
    // for a child.
    assert_eq!(name_index_key(None, b"ab"), vec![0x00, b'a', b'b']);
    let child = name_index_key(Some(P), b"ab");
    assert_eq!(child[0], 0x01);
    assert_eq!(&child[1..17], &P.to_packet());
    assert_eq!(&child[17..], b"ab");
}

#[test]
fn name_index_prefix_is_the_key_without_its_rdn() {
    // Source: src/record.rs — every key under a parent is its prefix (0x00,
    // or 0x01 || parent) followed by the RDN key; docs/49 §6.1 item 3 scans
    // that prefix. Keys of another parent, and root keys, do not start with
    // a child prefix.
    assert_eq!(name_index_prefix(None), vec![0x00]);
    let prefix = name_index_prefix(Some(P));
    assert_eq!(prefix.len(), 17);
    assert_eq!(prefix[0], 0x01);
    assert_eq!(&prefix[1..], &P.to_packet());
    for rdn in [&b"a"[..], b"ab", b"zz"] {
        assert!(name_index_key(Some(P), rdn).starts_with(&prefix));
        assert!(name_index_key(None, rdn).starts_with(&name_index_prefix(None)));
        assert!(!name_index_key(Some(G), rdn).starts_with(&prefix));
        assert!(!name_index_key(None, rdn).starts_with(&prefix));
        assert!(!name_index_key(Some(P), rdn).starts_with(&name_index_prefix(None)));
    }
}
