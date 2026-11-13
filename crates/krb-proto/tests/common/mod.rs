//! Shared helpers for hand-deriving DER test vectors.
//!
//! Every helper below writes octets directly from a named X.690 (02/2021)
//! clause — it does not call this crate or `parse-asn1` — so the vectors in the
//! test files are an independent derivation of the RFC 4120 Appendix A module,
//! clause by clause. No vector comes from any other implementation.
#![allow(dead_code)] // each test binary uses a different subset of helpers

use core::fmt::Debug;
use krb_proto::{EncryptedData, KerberosString, KerberosTime, PrincipalName, Realm, Ticket};

// ---------------------------------------------------------------------------
// X.690 encoders (hand-derived)
// ---------------------------------------------------------------------------

/// One definite-length TLV. Identifier octet as given (X.690 8.1.2); length in
/// the short form below 128 (8.1.3.4), else the long form with the minimum
/// number of octets (8.1.3.5, 10.1).
pub fn tlv(identifier: u8, contents: &[u8]) -> Vec<u8> {
    let n = contents.len();
    let mut out = vec![identifier];
    if n < 0x80 {
        out.push(n as u8);
    } else if n <= 0xFF {
        out.extend_from_slice(&[0x81, n as u8]);
    } else if n <= 0xFFFF {
        out.push(0x82);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else {
        assert!(n < 1 << 24, "test helper supports lengths below 2^24");
        out.push(0x83);
        out.extend_from_slice(&(n as u32).to_be_bytes()[1..]);
    }
    out.extend_from_slice(contents);
    out
}

/// Concatenate encodings.
pub fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.iter().flat_map(|p| p.iter().copied()).collect()
}

/// SEQUENCE / SEQUENCE OF: universal 16, constructed → 0x30.
/// X.690 8.9.1, 8.10.1; X.680 Table 1.
pub fn seq(parts: &[&[u8]]) -> Vec<u8> {
    tlv(0x30, &cat(parts))
}

/// Explicit context tag `[n]`: class bits 10, constructed bit set → 0xA0 | n
/// (n <= 30, low-tag-number form). X.690 8.1.2.2, 8.1.2.5, 8.14.3.
pub fn ctx(n: u8, inner: &[u8]) -> Vec<u8> {
    assert!(n <= 30);
    tlv(0xA0 | n, inner)
}

/// Explicit `[APPLICATION n]`: class bits 01, constructed → 0x60 | n.
/// X.690 8.1.2.2, 8.1.2.5, 8.14.3.
pub fn app(n: u8, inner: &[u8]) -> Vec<u8> {
    assert!(n <= 30);
    tlv(0x60 | n, inner)
}

/// INTEGER (universal 2) with hand-derived minimal two's-complement contents
/// octets (X.690 8.3.2, 8.3.3).
pub fn int(contents: &[u8]) -> Vec<u8> {
    tlv(0x02, contents)
}

/// OCTET STRING (universal 4, primitive). X.690 8.7, 10.2.
pub fn octets(bytes: &[u8]) -> Vec<u8> {
    tlv(0x04, bytes)
}

/// GeneralString (universal 27 = 0x1B, primitive). X.680 Table 8; X.690 10.2.
pub fn gstring(text: &[u8]) -> Vec<u8> {
    tlv(0x1B, text)
}

/// GeneralizedTime (universal 24 = 0x18, primitive). X.680 46.3; X.690 11.7.
pub fn gtime(text: &[u8]) -> Vec<u8> {
    tlv(0x18, text)
}

/// KerberosFlags as a 32-bit BIT STRING (universal 3 = 0x03): initial octet 0
/// (no unused bits) then the four octets, bit 0 in the MSB of the first.
/// X.690 8.6.2, 8.6.2.1; RFC 4120 5.2.8.
pub fn flags32(octets4: [u8; 4]) -> Vec<u8> {
    tlv(
        0x03,
        &[0x00, octets4[0], octets4[1], octets4[2], octets4[3]],
    )
}

// ---------------------------------------------------------------------------
// Typed-value helpers
// ---------------------------------------------------------------------------

pub fn kstr(text: &str) -> KerberosString {
    KerberosString::new(text).unwrap()
}

pub fn realm(text: &str) -> Realm {
    kstr(text)
}

pub fn pname(name_type: i32, parts: &[&str]) -> PrincipalName {
    PrincipalName {
        name_type,
        name_string: parts.iter().map(|p| kstr(p)).collect(),
    }
}

/// Parse "YYYYMMDDHHMMSSZ" (test inputs only).
pub fn ktime(text: &str) -> KerberosTime {
    let d = |a: usize, b: usize| text[a..b].parse::<u16>().unwrap();
    KerberosTime::new(
        d(0, 4),
        d(4, 6) as u8,
        d(6, 8) as u8,
        d(8, 10) as u8,
        d(10, 12) as u8,
        d(12, 14) as u8,
    )
    .unwrap()
}

/// PrincipalName DER, RFC 4120 5.2.2:
/// SEQUENCE { [0] INTEGER name-type, [1] SEQUENCE OF GeneralString }.
pub fn pname_der(name_type_contents: &[u8], parts: &[&str]) -> Vec<u8> {
    let strings: Vec<Vec<u8>> = parts.iter().map(|p| gstring(p.as_bytes())).collect();
    let refs: Vec<&[u8]> = strings.iter().map(Vec::as_slice).collect();
    seq(&[&ctx(0, &int(name_type_contents)), &ctx(1, &seq(&refs))])
}

/// EncryptedData DER, RFC 4120 5.2.9:
/// SEQUENCE { [0] etype, [1] kvno OPTIONAL, [2] OCTET STRING cipher }.
pub fn enc_data_der(etype_contents: &[u8], kvno_contents: Option<&[u8]>, cipher: &[u8]) -> Vec<u8> {
    match kvno_contents {
        Some(kvno) => seq(&[
            &ctx(0, &int(etype_contents)),
            &ctx(1, &int(kvno)),
            &ctx(2, &octets(cipher)),
        ]),
        None => seq(&[&ctx(0, &int(etype_contents)), &ctx(2, &octets(cipher))]),
    }
}

/// A TGT for EXAMPLE.ORG (RFC 4120 5.3 Ticket; sname krbtgt/EXAMPLE.ORG per
/// RFC 4120 7.3 / 6.2 NT-SRV-INST), enc-part opaque: etype 18
/// (aes256-cts-hmac-sha1-96, RFC 3962 §7), kvno 2, 24 arbitrary cipher octets.
pub fn tgt() -> (Vec<u8>, Ticket) {
    let cipher: Vec<u8> = (0xA0..0xB8).collect();
    let der = app(
        1,
        &seq(&[
            &ctx(0, &int(&[0x05])),
            &ctx(1, &gstring(b"EXAMPLE.ORG")),
            &ctx(2, &pname_der(&[0x02], &["krbtgt", "EXAMPLE.ORG"])),
            &ctx(3, &enc_data_der(&[0x12], Some(&[0x02]), &cipher)),
        ]),
    );
    let value = Ticket {
        realm: realm("EXAMPLE.ORG"),
        sname: pname(2, &["krbtgt", "EXAMPLE.ORG"]),
        enc_part: EncryptedData {
            etype: 18,
            kvno: Some(2),
            cipher,
        },
    };
    (der, value)
}

/// A service ticket for host/server.example.org (RFC 4120 6.2.1: NT-SRV-HST,
/// host name lowercase), enc-part etype 18, kvno 7, 16 arbitrary octets.
pub fn service_ticket() -> (Vec<u8>, Ticket) {
    let cipher: Vec<u8> = (0x10..0x20).collect();
    let der = app(
        1,
        &seq(&[
            &ctx(0, &int(&[0x05])),
            &ctx(1, &gstring(b"EXAMPLE.ORG")),
            &ctx(2, &pname_der(&[0x03], &["host", "server.example.org"])),
            &ctx(3, &enc_data_der(&[0x12], Some(&[0x07]), &cipher)),
        ]),
    );
    let value = Ticket {
        realm: realm("EXAMPLE.ORG"),
        sname: pname(3, &["host", "server.example.org"]),
        enc_part: EncryptedData {
            etype: 18,
            kvno: Some(7),
            cipher,
        },
    };
    (der, value)
}

// ---------------------------------------------------------------------------
// Assertions
// ---------------------------------------------------------------------------

/// The round-trip property in both directions (docs/45 §5):
/// `decode(bytes) == value`, `encode(value) == bytes`,
/// `decode(encode(value)) == value`, `encode(decode(bytes)) == bytes`.
pub fn round_trip<T, E>(
    bytes: &[u8],
    value: &T,
    decode: impl Fn(&[u8]) -> krb_proto::Result<T>,
    encode: impl Fn(&T) -> krb_proto::Result<E>,
) where
    T: PartialEq + Debug,
    E: AsRef<[u8]>,
{
    let decoded = decode(bytes).expect("vector must decode");
    assert_eq!(&decoded, value, "decoded value mismatch");
    let encoded = encode(value).expect("value must encode");
    assert_eq!(encoded.as_ref(), bytes, "encoded bytes mismatch");
    assert_eq!(
        &decode(encoded.as_ref()).unwrap(),
        value,
        "decode(encode(x)) != x"
    );
    assert_eq!(
        encode(&decoded).unwrap().as_ref(),
        bytes,
        "encode(decode(b)) != b"
    );
}
