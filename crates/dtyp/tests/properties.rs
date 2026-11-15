//! Deterministic robustness / round-trip properties (docs/45 §5).
//!
//! Source of the seed: the self-relative security descriptor of [MS-DTYP]
//! v20241119 2.5.1.4. Every single-byte substitution and every truncation of
//! it is fed to each decoder. Properties checked (fail closed, docs/CLEAN-ROOM.md):
//! no decoder panics; whatever decodes re-encodes; re-encoding is a fixed
//! point (`decode(encode(v)) == v`, `encode(decode(encode(v))) == encode(v)`).
//! The last test also runs CreateSecurityDescriptor ([MS-DTYP] 2.5.3.4.1) on
//! every decodable substitution. This complements, and does not replace, the
//! cargo-fuzz target in `crates/dtyp/fuzz/`.

use dtyp::{
    create_security_descriptor, Ace, Acl, AutoInheritFlags, GenericMapping, Guid,
    SecurityDescriptor, Sid, Token,
};

const EXAMPLE: [u8; 0xb0] = [
    0x01, 0x00, 0x14, 0xb0, 0x90, 0x00, 0x00, 0x00, 0xa0, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00,
    0x30, 0x00, 0x00, 0x00, 0x02, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x80, 0x14, 0x00,
    0x00, 0x00, 0x00, 0x80, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x60, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x03, 0x18, 0x00, 0x00, 0x00, 0x00, 0xa0,
    0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x20, 0x00, 0x00, 0x00, 0x21, 0x02, 0x00, 0x00,
    0x00, 0x03, 0x18, 0x00, 0x00, 0x00, 0x00, 0x10, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
    0x20, 0x00, 0x00, 0x00, 0x20, 0x02, 0x00, 0x00, 0x00, 0x03, 0x14, 0x00, 0x00, 0x00, 0x00, 0x10,
    0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x12, 0x00, 0x00, 0x00, 0x00, 0x03, 0x14, 0x00,
    0x00, 0x00, 0x00, 0x10, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x20, 0x00, 0x00, 0x00, 0x20, 0x02, 0x00, 0x00,
    0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x20, 0x00, 0x00, 0x00, 0x20, 0x02, 0x00, 0x00,
];

/// Run every decoder on `input` and check the properties on any success.
fn check_all(input: &[u8]) {
    if let Ok(sd) = SecurityDescriptor::decode(input) {
        let bytes = sd.encode().expect("a decoded descriptor must re-encode");
        let again = SecurityDescriptor::decode(&bytes).expect("canonical output must decode");
        assert_eq!(again, sd);
        assert_eq!(again.encode().unwrap(), bytes);
    }
    if let Ok(acl) = Acl::decode(input) {
        let bytes = acl.encode().expect("a decoded ACL must re-encode");
        assert_eq!(Acl::decode(&bytes).unwrap(), acl);
    }
    if let Ok(ace) = Ace::decode(input) {
        let bytes = ace.encode().expect("a decoded ACE must re-encode");
        assert_eq!(Ace::decode(&bytes).unwrap(), ace);
    }
    if let Ok(sid) = Sid::decode(input) {
        assert_eq!(Sid::decode(&sid.encode()).unwrap(), sid);
    }
}

#[test]
fn every_single_byte_substitution_of_the_example() {
    let mut buf = EXAMPLE;
    for pos in 0..buf.len() {
        let original = buf[pos];
        for value in 0..=255u8 {
            buf[pos] = value;
            check_all(&buf);
            // Also from every component offset, as the stand-alone decoders
            // would see an embedded SID / ACL / ACE.
            for start in [0x14usize, 0x1c, 0x30, 0x38, 0x90, 0xa0] {
                check_all(&buf[start..]);
            }
        }
        buf[pos] = original;
    }
}

#[test]
fn every_truncation_and_window_of_the_example() {
    for end in 0..=EXAMPLE.len() {
        check_all(&EXAMPLE[..end]);
        for start in 0..end {
            check_all(&EXAMPLE[start..end]);
        }
    }
}

#[test]
fn every_sid_string_mutation_stays_consistent() {
    // Seeds: [MS-DTYP] 2.4.2.4 table string forms (including "S-1-5" with no
    // SubAuthority) and a hand-derived hexadecimal-authority form (2.4.2.1).
    // Every single-character substitution (printable ASCII) either fails or
    // parses to a SID whose canonical form re-parses to the same SID and
    // differs from the input only in letter case (RFC 5234 §2.3).
    for seed in [
        "S-1-5-32-544",
        "S-1-5-21-1-2-3-513",
        "S-1-16-12288",
        "S-1-5",
        "S-1-0x000100000000-7",
    ] {
        let mut chars: Vec<u8> = seed.bytes().collect();
        for pos in 0..chars.len() {
            let original = chars[pos];
            for c in 0x20u8..0x7F {
                chars[pos] = c;
                let text = String::from_utf8(chars.clone()).unwrap();
                if let Ok(sid) = Sid::parse_sid_string(&text) {
                    let canonical = sid.to_sid_string();
                    assert_eq!(Sid::parse_sid_string(&canonical).unwrap(), sid);
                    assert!(
                        canonical.eq_ignore_ascii_case(&text),
                        "{text} vs {canonical}"
                    );
                }
            }
            chars[pos] = original;
        }
    }
}

/// CreateSecurityDescriptor ([MS-DTYP] 2.5.3.4.1) on every descriptor that
/// decodes from a single-byte substitution of the 2.5.1.4 example, used as the
/// parent, for a container and a leaf child: never a panic; whatever it
/// computes encodes and decodes back to the same value (strict codec), and
/// carries the token's owner and group (Steps 1-2). Errors are allowed (fail
/// closed).
#[test]
fn create_security_descriptor_on_every_decodable_substitution_of_the_example() {
    let token = Token {
        owner: Sid::parse_sid_string("S-1-5-21-1-2-3-1000").unwrap(),
        primary_group: Sid::parse_sid_string("S-1-5-21-1-2-3-513").unwrap(),
        default_dacl: None,
    };
    // An arbitrary class GUID label.
    let class = [Guid {
        data1: 1,
        data2: 2,
        data3: 3,
        data4: [4; 8],
    }];
    let mut buf = EXAMPLE;
    for pos in 0..buf.len() {
        let original = buf[pos];
        for value in 0..=255u8 {
            buf[pos] = value;
            let Ok(parent) = SecurityDescriptor::decode(&buf) else {
                continue;
            };
            for container in [true, false] {
                let Ok(child) = create_security_descriptor(
                    Some(&parent),
                    None,
                    container,
                    Some(&class),
                    AutoInheritFlags::default(),
                    &token,
                    &GenericMapping::ACTIVE_DIRECTORY,
                ) else {
                    continue;
                };
                let bytes = child.encode().expect("a computed descriptor must encode");
                assert_eq!(SecurityDescriptor::decode(&bytes).unwrap(), child);
                assert_eq!(child.owner_sid, Some(token.owner));
                assert_eq!(child.group_sid, Some(token.primary_group));
            }
        }
        buf[pos] = original;
    }
}
