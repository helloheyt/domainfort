//! Key-material handling: EncryptionKey.keyvalue is redacted in Debug, kept in
//! zeroizing storage, returned in zeroizing encodings, and never reaches an
//! error. Source: RFC 4120 5.2.9 (keyvalue "contains the key itself");
//! docs/CLEAN-ROOM.md (secrets never in logs, debug output, or errors). Vectors
//! hand-derived from RFC 4120 Appendix A; none from another implementation.

mod common;

use common::*;
use krb_proto::{Authenticator, EncApRepPart, EncryptionKey, Error, KeyValue, Microseconds};
use zeroize::Zeroizing;

/// A key whose octets are all 0x5A ("90" in decimal, "5a" in hex) — easy to
/// spot if it leaked into a formatted string.
fn marker_key() -> Vec<u8> {
    vec![0x5A; 32]
}

fn assert_no_key_text(text: &str) {
    for needle in ["90", "5a", "5A", "Z"] {
        assert!(
            !text.contains(needle),
            "formatted output leaks key material ({needle}): {text}"
        );
    }
}

#[test]
fn encryption_key_debug_is_redacted() {
    // RFC 4120 5.2.9; docs/CLEAN-ROOM.md: the key octets never appear in Debug.
    let key = EncryptionKey {
        keytype: 18,
        keyvalue: KeyValue::new(marker_key()),
    };
    let text = format!("{key:?}");
    assert!(text.contains("redacted"), "{text}");
    assert_no_key_text(&text);
    let text = format!("{:#?}", key.keyvalue);
    assert!(text.contains("redacted"), "{text}");
    assert_no_key_text(&text);
}

#[test]
fn key_bearing_message_debug_is_redacted() {
    // RFC 4120 5.5.1 Authenticator subkey [6] / 5.5.2 EncAPRepPart subkey [2].
    let authenticator = Authenticator {
        crealm: realm("EXAMPLE.ORG"),
        cname: pname(1, &["alice"]),
        cksum: None,
        cusec: Microseconds::new(1).unwrap(),
        ctime: ktime("20261113090512Z"),
        subkey: Some(EncryptionKey {
            keytype: 18,
            keyvalue: KeyValue::new(marker_key()),
        }),
        seq_number: None,
        authorization_data: None,
    };
    let text = format!("{authenticator:?}");
    assert!(text.contains("redacted"));
    // Realm and name text are not secret and may appear; the key must not.
    assert!(!text.contains("90, 90") && !text.contains("0x5a"));
    let rep = EncApRepPart {
        ctime: ktime("20261113090512Z"),
        cusec: Microseconds::new(1).unwrap(),
        subkey: Some(EncryptionKey {
            keytype: 18,
            keyvalue: KeyValue::new(marker_key()),
        }),
        seq_number: None,
    };
    assert!(!format!("{rep:?}").contains("90, 90"));
}

#[test]
fn key_bearing_encodings_are_zeroizing() {
    // docs/CLEAN-ROOM.md: the DER of a key-bearing structure is itself key material
    // and is returned in a Zeroizing buffer (compile-time type check).
    let key = EncryptionKey {
        keytype: 18,
        keyvalue: KeyValue::from_slice(&marker_key()),
    };
    let encoded: Zeroizing<Vec<u8>> = key.encode().unwrap();
    assert_eq!(EncryptionKey::decode(&encoded).unwrap(), key);
}

#[test]
fn errors_carry_no_key_material() {
    // A structurally valid EncryptionKey followed by an undefined component
    // [2] (RFC 4120 5.2.9 defines [0], [1] only): decoding fails with a unit
    // error that cannot contain the key octets.
    let bytes = seq(&[
        &ctx(0, &int(&[0x12])),
        &ctx(1, &octets(&marker_key())),
        &ctx(2, &int(&[0x00])),
    ]);
    let err = EncryptionKey::decode(&bytes).unwrap_err();
    assert_eq!(err, Error::UnknownField);
    assert_no_key_text(&format!("{err:?}"));
    assert_no_key_text(&err.to_string());
}

#[test]
fn key_value_equality() {
    // Structural equality over every octet (lengths differ → unequal).
    let a = KeyValue::from_slice(&[1, 2, 3]);
    assert_eq!(a, KeyValue::new(vec![1, 2, 3]));
    assert_ne!(a, KeyValue::from_slice(&[1, 2, 4]));
    assert_ne!(a, KeyValue::from_slice(&[1, 2]));
    assert_eq!(a.len(), 3);
    assert!(!a.is_empty());
    assert_eq!(a.as_bytes(), &[1, 2, 3]);
}
