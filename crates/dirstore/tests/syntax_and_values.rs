//! The new value syntaxes (Integer32, DsTime, ObjectRef), value ranges,
//! value constraints and Derived attributes.
//!
//! Source: docs/46 §1 and §8.1 (canonical forms and acceptance rules), §8.2
//! (storage, range, constraint), §5.4 (Derived = never stored, writes
//! refused); [MS-DRSR] v20260309 §5.51 (DSTIME = seconds since 1601-01-01),
//! §5.16.3.9 (the printed DSTIME example), §5.16.3.2 (the printed INT32
//! example); [MS-ADTS] v20261026 §3.1.1.2.3 (rangeLower / rangeUpper),
//! §3.1.1.1.3 (no object has the NULL GUID), §3.1.1.1.6 (back links are
//! read-only); Q-091 item 10 (the printable-ASCII constraint). Test data is
//! hand-made (tests/common).

mod common;

use common::*;
use dirstore::{
    AttrClass, AttrId, AttributeChange, Error, NewObject, Schema, Storage, Store, ValueSyntax,
    Violation,
};

/// Create `obj` under a fresh root; return the error and check that nothing
/// was written for it.
fn create_error(test: &str, obj: NewObject) -> Error {
    let dir = TempDir::new(test);
    let store = open_store(&dir);
    create_all(&store, vec![root(1, "root")]);
    let guid = obj.guid;
    let mut txn = store.begin_write().unwrap();
    let err = txn
        .create_object(obj, &origin(NODE_1, 1, 1))
        .expect_err("must be rejected");
    txn.commit().unwrap();
    let snap = store.snapshot().unwrap();
    assert_eq!(snap.get_object(guid).unwrap(), None);
    err
}

/// Create `obj` under a fresh root and read it back.
fn create_ok(test: &str, obj: NewObject) -> dirstore::Object {
    let dir = TempDir::new(test);
    let store = open_store(&dir);
    let guid = obj.guid;
    create_all(&store, vec![root(1, "root"), obj]);
    let back = store.snapshot().unwrap().get_object(guid).unwrap();
    back.expect("created")
}

fn with(extra: Vec<(AttrId, Vec<Vec<u8>>)>) -> NewObject {
    principal_with(2, guid(1), "p", extra)
}

fn int32(v: i32) -> Vec<u8> {
    v.to_be_bytes().to_vec()
}

// ---------------------------------------------------------------- syntaxes --

#[test]
fn integer32_accepts_exactly_four_bytes() {
    // Source: docs/46 §8.1 (`len == 4`, two's complement BE); [MS-DRSR]
    // 5.16.3.2 — the printed example "LDAP value: 5 / INT32 value: 0x5 /
    // payload: 05 00 00 00" (wire form little-endian); our canonical form is
    // the same integer big-endian.
    let wire_le = [0x05, 0x00, 0x00, 0x00];
    let v = i32::from_le_bytes(wire_le);
    assert_eq!(v, 5);
    assert!(ValueSyntax::Integer32.accepts(&v.to_be_bytes()));
    for v in [i32::MIN, -1, 0, i32::MAX] {
        assert!(ValueSyntax::Integer32.accepts(&v.to_be_bytes()));
    }
    for len in [0, 3, 5, 8] {
        assert!(!ValueSyntax::Integer32.accepts(&vec![0; len]), "len {len}");
    }
}

#[test]
fn dstime_accepts_eight_non_negative_bytes_and_the_drsr_vector() {
    // Source: [MS-DRSR] 5.16.3.9 — "LDAP value: 20060609211106.0Z ... This
    // corresponds to DSTIME value: 0x2fa9a74ea ... payload: ea 74 9a fa 02 00
    // 00 00" (wire form little-endian); [MS-DRSR] 5.51 — DSTIME is seconds
    // since January 1, 1601. docs/46 §8.1: canonical form = the i64
    // big-endian, accepted iff 8 bytes and >= 0.
    const WIRE_LE: [u8; 8] = [0xea, 0x74, 0x9a, 0xfa, 0x02, 0x00, 0x00, 0x00];
    const DSTIME: i64 = 0x2_fa9a_74ea;
    assert_eq!(i64::from_le_bytes(WIRE_LE), DSTIME);
    let canonical = DSTIME.to_be_bytes();
    assert_eq!(canonical, [0x00, 0x00, 0x00, 0x02, 0xfa, 0x9a, 0x74, 0xea]);
    assert!(ValueSyntax::DsTime.accepts(&canonical));
    assert!(ValueSyntax::DsTime.accepts(&0i64.to_be_bytes()));
    assert!(ValueSyntax::DsTime.accepts(&i64::MAX.to_be_bytes()));
    assert!(!ValueSyntax::DsTime.accepts(&(-1i64).to_be_bytes()));
    assert!(!ValueSyntax::DsTime.accepts(&i64::MIN.to_be_bytes()));
    for len in [0, 4, 7, 9] {
        assert!(!ValueSyntax::DsTime.accepts(&vec![0; len]), "len {len}");
    }
    // Stored and read back unchanged on a DsTime attribute.
    let back = create_ok(
        "dstime-store",
        with(vec![(ATTR_CREATED, vec![canonical.to_vec()])]),
    );
    assert_eq!(
        back.attribute(ATTR_CREATED).unwrap().values[0].value,
        canonical
    );
    assert!(matches!(
        create_error(
            "dstime-negative",
            with(vec![(ATTR_CREATED, vec![(-1i64).to_be_bytes().to_vec()])])
        ),
        Error::Rejected(Violation::InvalidValueSyntax(ATTR_CREATED))
    ));
}

#[test]
fn object_ref_accepts_sixteen_bytes_never_the_null_guid() {
    // Source: docs/46 §8.1 (`len == GUID_PACKET_LEN && v != [0; 16]`);
    // [MS-ADTS] 3.1.1.1.3 ("No actual object has objectGUID equal to the
    // NULL GUID").
    assert!(ValueSyntax::ObjectRef.accepts(&ref_to(1)));
    let mut one_bit = [0u8; 16];
    one_bit[15] = 1;
    assert!(ValueSyntax::ObjectRef.accepts(&one_bit));
    assert!(!ValueSyntax::ObjectRef.accepts(&[0u8; 16]));
    for len in [0, 15, 17] {
        assert!(!ValueSyntax::ObjectRef.accepts(&vec![1; len]), "len {len}");
    }
    assert!(matches!(
        create_error(
            "objref-null",
            with(vec![(ATTR_MEMBER, vec![vec![0u8; 16]])])
        ),
        Error::Rejected(Violation::InvalidValueSyntax(ATTR_MEMBER))
    ));
}

#[test]
fn null_guid_object_is_refused() {
    // Source: [MS-ADTS] 3.1.1.1.3 — no object has the NULL GUID (so no
    // ObjectRef can ever need to name one).
    let obj = NewObject {
        guid: dtyp::Guid::from_packet(&[0u8; 16]),
        ..principal(2, guid(1), "p")
    };
    assert!(matches!(
        create_error("null-guid", obj),
        Error::Rejected(Violation::NullGuid)
    ));
}

// ------------------------------------------------------------------ ranges --

#[test]
fn integer32_value_range_is_enforced() {
    // Source: docs/46 §8.2 (range = value range for integers); [MS-ADTS]
    // 3.1.1.2.3 (rangeLower / rangeUpper "equals the minimum / maximum
    // allowed value" for Integer). ATTR_LEVEL: -10..=10.
    for v in [-10, 0, 10] {
        create_ok(
            &format!("range-ok-{v}"),
            with(vec![(ATTR_LEVEL, vec![int32(v)])]),
        );
    }
    for v in [-11, 11, i32::MIN, i32::MAX] {
        assert!(matches!(
            create_error(
                &format!("range-bad-{v}"),
                with(vec![(ATTR_LEVEL, vec![int32(v)])])
            ),
            Error::Rejected(Violation::ValueOutOfRange(ATTR_LEVEL))
        ));
    }
}

#[test]
fn string_range_counts_utf16_code_units() {
    // Source: docs/46 §8.2 (Utf8String range = length in UTF-16 units);
    // [MS-ADTS] 3.1.1.2.3 ("For String(Unicode), rangeLower is the minimum
    // length in characters"); Q-080 item 4 (characters = UTF-16 code units).
    // ATTR_TEXT: 0..=4 units. U+00E9 is one unit (two UTF-8 bytes); U+1F600
    // is a surrogate pair, two units (four UTF-8 bytes).
    let ok = ["", "abcd", "\u{e9}\u{e9}\u{e9}\u{e9}", "\u{1F600}\u{1F600}"];
    for (i, s) in ok.iter().enumerate() {
        create_ok(
            &format!("utf16-ok-{i}"),
            with(vec![(ATTR_TEXT, vec![s.as_bytes().to_vec()])]),
        );
    }
    let bad = [
        "abcde",
        "\u{1F600}\u{1F600}a",
        "\u{1F600}\u{1F600}\u{1F600}",
    ];
    for (i, s) in bad.iter().enumerate() {
        assert!(matches!(
            create_error(
                &format!("utf16-bad-{i}"),
                with(vec![(ATTR_TEXT, vec![s.as_bytes().to_vec()])])
            ),
            Error::Rejected(Violation::ValueOutOfRange(ATTR_TEXT))
        ));
    }
    // A lower bound: ATTR_NAME is 1..=64 units, so an empty name is refused
    // by its range (before any RDN rule).
    assert!(matches!(
        create_error("utf16-empty-name", principal(2, guid(1), "")),
        Error::Rejected(Violation::ValueOutOfRange(ATTR_NAME))
    ));
}

// ------------------------------------------------------------- constraints --

#[test]
fn allowed_values_are_enforced() {
    // Source: docs/46 §8.2 (`AllowedValues`, R46-6 — e.g. groupType).
    // ATTR_KIND allows exactly KIND_VALUES.
    for v in KIND_VALUES {
        create_ok(
            &format!("kind-ok-{v}"),
            with(vec![(ATTR_KIND, vec![int32(v)])]),
        );
    }
    for v in [0, 8, i32::MIN, i32::MIN | 4 | 2] {
        assert!(matches!(
            create_error(
                &format!("kind-bad-{v}"),
                with(vec![(ATTR_KIND, vec![int32(v)])])
            ),
            Error::Rejected(Violation::ValueNotAllowed(ATTR_KIND))
        ));
    }
}

#[test]
fn allowed_bits_are_enforced_on_create_and_modify() {
    // Source: docs/46 §8.2 (`AllowedBits`, R46-6 — e.g. userAccountControl:
    // any bit outside the mask is refused). ATTR_CONTROL allows 0x202.
    for v in [0, 0x2, 0x200, 0x202] {
        create_ok(
            &format!("bits-ok-{v}"),
            with(vec![(ATTR_CONTROL, vec![int32(v)])]),
        );
    }
    for v in [0x1, 0x20, 0x222, i32::MIN] {
        assert!(matches!(
            create_error(
                &format!("bits-bad-{v}"),
                with(vec![(ATTR_CONTROL, vec![int32(v)])])
            ),
            Error::Rejected(Violation::DisallowedBits(ATTR_CONTROL))
        ));
    }
    // Modify is held to the same rule; a refusal changes nothing.
    let dir = TempDir::new("bits-modify");
    let store = open_store(&dir);
    create_all(
        &store,
        vec![
            root(1, "root"),
            with(vec![(ATTR_CONTROL, vec![int32(0x2)])]),
        ],
    );
    let before = store.snapshot().unwrap().get_object(guid(2)).unwrap();
    let mut txn = store.begin_write().unwrap();
    assert!(matches!(
        txn.modify_object(
            guid(2),
            vec![AttributeChange::Replace {
                id: ATTR_CONTROL,
                values: vec![int32(0x80)],
            }],
            &origin(NODE_1, 2, 2)
        ),
        Err(Error::Rejected(Violation::DisallowedBits(ATTR_CONTROL)))
    ));
    assert!(matches!(
        txn.modify_object(
            guid(2),
            vec![AttributeChange::Replace {
                id: ATTR_KIND,
                values: vec![int32(8)],
            }],
            &origin(NODE_1, 2, 3)
        ),
        Err(Error::Rejected(Violation::ValueNotAllowed(ATTR_KIND)))
    ));
    txn.commit().unwrap();
    assert_eq!(
        store.snapshot().unwrap().get_object(guid(2)).unwrap(),
        before
    );
}

#[test]
fn ascii_printable_is_enforced_on_create_and_modify() {
    // Source: Q-091 item 10 (A-30) — `AsciiPrintable` on a Utf8String
    // attribute: every byte 0x20..=0x7E (Q-080 item 1); anything else
    // (control byte, DEL, non-ASCII UTF-8) is refused. The TEST schema's
    // multi-valued note (ATTR_NOTE) is given the constraint here.
    let attrs = attribute_definitions(AttrClass::Secret)
        .into_iter()
        .map(|mut d| {
            if d.id == ATTR_NOTE {
                d.constraint = Some(dirstore::ValueConstraint::AsciiPrintable);
            }
            d
        })
        .collect();
    let schema = Schema::new(attrs, class_definitions()).unwrap();
    let dir = TempDir::new("ascii-printable");
    let store = Store::open(dir.db_path(), key_a(), schema).unwrap();
    create_all(&store, vec![root(1, "root")]);
    let note = |v: &[u8]| with(vec![(ATTR_NOTE, vec![v.to_vec()])]);
    let mut txn = store.begin_write().unwrap();
    for bad in [&b"a\tb"[..], b"a\x7Fb", b"a\x00b", "h\u{e9}te".as_bytes()] {
        assert!(matches!(
            txn.create_object(note(bad), &origin(NODE_1, 2, 1)),
            Err(Error::Rejected(Violation::ValueNotAsciiPrintable(
                ATTR_NOTE
            )))
        ));
    }
    // The whole printable range is accepted.
    let all: Vec<u8> = (0x20..=0x7E).collect();
    txn.create_object(note(&all), &origin(NODE_1, 2, 2))
        .unwrap();
    // Modify is held to the same rule; a refusal changes nothing.
    assert!(matches!(
        txn.modify_object(
            guid(2),
            vec![AttributeChange::Replace {
                id: ATTR_NOTE,
                values: vec![b"ok".to_vec(), b"line\nbreak".to_vec()],
            }],
            &origin(NODE_1, 2, 3)
        ),
        Err(Error::Rejected(Violation::ValueNotAsciiPrintable(
            ATTR_NOTE
        )))
    ));
    txn.commit().unwrap();
    let back = store
        .snapshot()
        .unwrap()
        .get_object(guid(2))
        .unwrap()
        .expect("created");
    let values = &back.attribute(ATTR_NOTE).unwrap().values;
    assert_eq!(values.len(), 1);
    assert_eq!(values[0].value, all);
}

// ----------------------------------------------------------------- derived --

#[test]
fn derived_attribute_write_is_refused() {
    // Source: docs/46 §5.4 / §8.2 — a Derived attribute is never stored and
    // every write naming it is refused; [MS-ADTS] 3.1.1.1.6 — "clients MUST
    // NOT write to the back link attribute, and servers MUST reject any such
    // writes".
    for (test, id) in [
        ("derived-create", ATTR_DISPLAY),
        ("derived-create-backlink", ATTR_MEMBER_OF),
    ] {
        assert!(matches!(
            create_error(test, with(vec![(id, vec![b"x".to_vec()])])),
            Error::Rejected(Violation::DerivedAttribute(x)) if x == id
        ));
    }
    let dir = TempDir::new("derived-modify");
    let store = open_store(&dir);
    create_all(&store, vec![root(1, "root"), principal(2, guid(1), "p")]);
    let before = store.snapshot().unwrap().get_object(guid(2)).unwrap();
    let mut txn = store.begin_write().unwrap();
    for (id, values) in [
        (ATTR_MEMBER_OF, vec![ref_to(1)]),
        (ATTR_MEMBER_OF, vec![]),
        (ATTR_DISPLAY, vec![]),
    ] {
        assert!(matches!(
            txn.modify_object(
                guid(2),
                vec![AttributeChange::Replace { id, values }],
                &origin(NODE_1, 2, 2)
            ),
            Err(Error::Rejected(Violation::DerivedAttribute(x))) if x == id
        ));
    }
    txn.commit().unwrap();
    assert_eq!(
        store.snapshot().unwrap().get_object(guid(2)).unwrap(),
        before
    );
}

#[test]
fn stored_attribute_later_declared_derived_is_never_returned() {
    // Source: docs/14 D60 (re-validate before use) with docs/46 §8.2: if the
    // schema given at open declares a stored attribute Derived, the object is
    // refused on read rather than returned with it.
    let dir = TempDir::new("derived-reclass");
    {
        let store = open_store(&dir);
        create_all(
            &store,
            vec![
                root(1, "root"),
                with(vec![(ATTR_PHONE, vec![b"+1".to_vec()])]),
            ],
        );
    }
    let attrs = attribute_definitions(AttrClass::Secret)
        .into_iter()
        .map(|mut d| {
            if d.id == ATTR_PHONE {
                d.storage = Storage::Derived;
            }
            d
        })
        .collect();
    let schema = Schema::new(attrs, class_definitions()).unwrap();
    let store = Store::open(dir.db_path(), key_a(), schema).unwrap();
    assert!(matches!(
        store.snapshot().unwrap().get_object(guid(2)),
        Err(Error::StoredObjectRejected(Violation::DerivedAttribute(
            ATTR_PHONE
        )))
    ));
}
