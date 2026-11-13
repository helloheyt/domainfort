//! A DER builder for test certificates, from RFC 5280 §4.1 structures and
//! parse-asn1's encoder (`encode`, `encode_element`). It signs nothing and
//! knows no algorithm: the caller passes the AlgorithmIdentifier contents,
//! the SubjectPublicKeyInfo and the signature octets. Reused by
//! crates/ldap-front's tests (`#[path]`), which add real ECDSA keys and
//! rustls-pki-types' documented algorithm identifiers.
//!
//! Every object identifier below is one RFC 5280 Appendix A defines, with
//! its derivation: `id-at ::= { joint-iso-ccitt(2) ds(5) 4 }` (A.1),
//! `id-ce ::= { joint-iso-ccitt(2) ds(5) 29 }` (A.2), `id-pkix ::= { iso(1)
//! identified-organization(3) dod(6) internet(1) security(5) mechanisms(5)
//! pkix(7) }` and `id-kp ::= { id-pkix 3 }` (A.1). Universal tag numbers:
//! X.680 Table 1 (UTCTime 23, GeneralizedTime 24) and Table 8 (UTF8String
//! 12). Every value is made here; nothing comes from another
//! implementation's tests.
#![allow(dead_code)] // each test binary uses a different subset

use parse_asn1::{encode, encode_element, Tag, TagClass, Value};

/// `id-at-commonName ::= { id-at 3 }`. Spec: RFC 5280 A.1.
pub const ID_AT_COMMON_NAME: [u64; 4] = [2, 5, 4, 3];
/// `id-ce-subjectKeyIdentifier ::= { id-ce 14 }`. Spec: RFC 5280 4.2.1.2, A.2.
pub const ID_CE_SUBJECT_KEY_IDENTIFIER: [u64; 4] = [2, 5, 29, 14];
/// `id-ce-keyUsage ::= { id-ce 15 }`. Spec: RFC 5280 4.2.1.3, A.2.
pub const ID_CE_KEY_USAGE: [u64; 4] = [2, 5, 29, 15];
/// `id-ce-subjectAltName ::= { id-ce 17 }`. Spec: RFC 5280 4.2.1.6, A.2.
pub const ID_CE_SUBJECT_ALT_NAME: [u64; 4] = [2, 5, 29, 17];
/// `id-ce-basicConstraints ::= { id-ce 19 }`. Spec: RFC 5280 4.2.1.9, A.2.
pub const ID_CE_BASIC_CONSTRAINTS: [u64; 4] = [2, 5, 29, 19];
/// `id-ce-authorityKeyIdentifier ::= { id-ce 35 }`. Spec: RFC 5280 4.2.1.1, A.2.
pub const ID_CE_AUTHORITY_KEY_IDENTIFIER: [u64; 4] = [2, 5, 29, 35];
/// `id-ce-extKeyUsage ::= { id-ce 37 }`. Spec: RFC 5280 4.2.1.12, A.2.
pub const ID_CE_EXT_KEY_USAGE: [u64; 4] = [2, 5, 29, 37];
/// `id-kp-serverAuth ::= { id-kp 1 }` ("TLS WWW server authentication").
/// Spec: RFC 5280 4.2.1.12, A.2.
pub const ID_KP_SERVER_AUTH: [u64; 9] = [1, 3, 6, 1, 5, 5, 7, 3, 1];
/// `id-kp-clientAuth ::= { id-kp 2 }`. Spec: RFC 5280 4.2.1.12, A.2.
pub const ID_KP_CLIENT_AUTH: [u64; 9] = [1, 3, 6, 1, 5, 5, 7, 3, 2];

/// One element with canonical identifier and length octets.
/// Spec: X.690 8.1, 10.1.
pub fn element(class: TagClass, constructed: bool, number: u32, contents: &[u8]) -> Vec<u8> {
    encode_element(
        Tag {
            class,
            constructed,
            number,
        },
        contents,
    )
}

/// SEQUENCE of the given encodings, in order. Spec: X.690 8.9.
pub fn sequence(parts: &[Vec<u8>]) -> Vec<u8> {
    element(TagClass::Universal, true, 16, &parts.concat())
}

/// SET OF the given encodings, in the order given (the caller orders them;
/// X.690 11.6). Spec: X.690 8.12.
pub fn set_of(parts: &[Vec<u8>]) -> Vec<u8> {
    element(TagClass::Universal, true, 17, &parts.concat())
}

/// OBJECT IDENTIFIER. Spec: X.690 8.19.
pub fn oid(arcs: &[u64]) -> Vec<u8> {
    encode(&Value::ObjectIdentifier(arcs.to_vec())).expect("OID")
}

/// INTEGER. Spec: X.690 8.3.
pub fn integer(value: i64) -> Vec<u8> {
    encode(&Value::integer(value)).expect("INTEGER")
}

/// BOOLEAN (TRUE as 0xFF). Spec: X.690 8.2, 11.1.
pub fn boolean(value: bool) -> Vec<u8> {
    encode(&Value::Boolean(value)).expect("BOOLEAN")
}

/// OCTET STRING. Spec: X.690 8.7.
pub fn octet_string(octets: &[u8]) -> Vec<u8> {
    encode(&Value::OctetString(octets.to_vec())).expect("OCTET STRING")
}

/// BIT STRING. Spec: X.690 8.6, 11.2.
pub fn bit_string(unused_bits: u8, octets: &[u8]) -> Vec<u8> {
    encode(&Value::BitString {
        unused_bits,
        bytes: octets.to_vec(),
    })
    .expect("BIT STRING")
}

/// UTF8String (UNIVERSAL 12, primitive). Spec: X.680 Table 8; X.690 10.2.
pub fn utf8_string(text: &str) -> Vec<u8> {
    element(TagClass::Universal, false, 12, text.as_bytes())
}

/// UTCTime (UNIVERSAL 23) with the given contents (no check: tests build
/// invalid ones too). Spec: X.680 Table 1, 47.3; RFC 5280 4.1.2.5.1.
pub fn utc_time(text: &str) -> Vec<u8> {
    element(TagClass::Universal, false, 23, text.as_bytes())
}

/// GeneralizedTime (UNIVERSAL 24) with the given contents (no check).
/// Spec: X.680 Table 1, 46.3; RFC 5280 4.1.2.5.2.
pub fn generalized_time(text: &str) -> Vec<u8> {
    element(TagClass::Universal, false, 24, text.as_bytes())
}

/// `[n] EXPLICIT`: constructed, the contents the complete base encoding.
/// Spec: X.690 8.14.3.
pub fn explicit(number: u32, inner: &[u8]) -> Vec<u8> {
    element(TagClass::ContextSpecific, true, number, inner)
}

/// `[n] IMPLICIT` of a primitive base type: primitive, the base contents.
/// Spec: X.690 8.14.4.
pub fn implicit(number: u32, contents: &[u8]) -> Vec<u8> {
    element(TagClass::ContextSpecific, false, number, contents)
}

/// `AlgorithmIdentifier`: a SEQUENCE around `contents` (the algorithm OID
/// and parameters, already encoded). Spec: RFC 5280 4.1.1.2.
pub fn algorithm_identifier(contents: &[u8]) -> Vec<u8> {
    element(TagClass::Universal, true, 16, contents)
}

/// A Name with one RDN holding one commonName in UTF8String.
/// Spec: RFC 5280 4.1.2.4 (RDNSequence, SET OF AttributeTypeAndValue,
/// DirectoryString "MUST use either the PrintableString or UTF8String"), A.1
/// (`X520CommonName`).
pub fn name(common_name: &str) -> Vec<u8> {
    sequence(&[set_of(&[sequence(&[
        oid(&ID_AT_COMMON_NAME),
        utf8_string(common_name),
    ])])])
}

/// The empty Name (an empty RDNSequence). Spec: RFC 5280 4.1.2.6.
pub fn empty_name() -> Vec<u8> {
    sequence(&[])
}

/// `Validity ::= SEQUENCE { notBefore Time, notAfter Time }`.
/// Spec: RFC 5280 4.1.2.5.
pub fn validity(not_before: Vec<u8>, not_after: Vec<u8>) -> Vec<u8> {
    sequence(&[not_before, not_after])
}

/// `version [0] EXPLICIT Version` with value v3 (2). Spec: RFC 5280 4.1,
/// 4.1.2.1.
pub fn version_v3() -> Vec<u8> {
    explicit(0, &integer(2))
}

/// `SubjectPublicKeyInfo ::= SEQUENCE { algorithm, subjectPublicKey BIT
/// STRING }`. Spec: RFC 5280 4.1, 4.1.2.7.
pub fn subject_public_key_info(algorithm_contents: &[u8], public_key: &[u8]) -> Vec<u8> {
    sequence(&[
        algorithm_identifier(algorithm_contents),
        bit_string(0, public_key),
    ])
}

/// `Extension ::= SEQUENCE { extnID, critical BOOLEAN DEFAULT FALSE,
/// extnValue OCTET STRING }` — `critical` written only when TRUE (DER,
/// X.690 11.5). Spec: RFC 5280 4.1.
pub fn extension(id: &[u64], critical: bool, value: &[u8]) -> Vec<u8> {
    let mut parts = vec![oid(id)];
    if critical {
        parts.push(boolean(true));
    }
    parts.push(octet_string(value));
    sequence(&parts)
}

/// `extensions [3] EXPLICIT Extensions`. Spec: RFC 5280 4.1.
pub fn extensions(list: &[Vec<u8>]) -> Vec<u8> {
    explicit(3, &sequence(list))
}

/// subjectAltName value: `GeneralNames` of `dNSName [2] IA5String` (the
/// implicitly tagged module). Spec: RFC 5280 4.2.1.6, A.2.
pub fn subject_alt_name_dns(names: &[&str]) -> Vec<u8> {
    let general_names: Vec<Vec<u8>> = names.iter().map(|n| implicit(2, n.as_bytes())).collect();
    sequence(&general_names)
}

/// basicConstraints value for a CA: `SEQUENCE { cA TRUE }` (no
/// pathLenConstraint). Spec: RFC 5280 4.2.1.9.
pub fn basic_constraints_ca() -> Vec<u8> {
    sequence(&[boolean(true)])
}

/// keyUsage value with only digitalSignature (bit 0): the leading bit is
/// bit 8 of the first octet (X.690 8.6.2.1) and trailing 0 bits are removed
/// (X.690 11.2.2; X.680 22.7) ⇒ one octet 0x80 with 7 unused bits.
/// Spec: RFC 5280 4.2.1.3.
pub fn key_usage_digital_signature() -> Vec<u8> {
    bit_string(7, &[0x80])
}

/// keyUsage value with only keyCertSign (bit 5) ⇒ one octet 0x04 with 2
/// unused bits (X.690 8.6.2.1, 11.2.2). Spec: RFC 5280 4.2.1.3.
pub fn key_usage_key_cert_sign() -> Vec<u8> {
    bit_string(2, &[0x04])
}

/// extKeyUsage value: `SEQUENCE SIZE (1..MAX) OF KeyPurposeId`.
/// Spec: RFC 5280 4.2.1.12.
pub fn ext_key_usage(purposes: &[&[u64]]) -> Vec<u8> {
    let ids: Vec<Vec<u8>> = purposes.iter().map(|p| oid(p)).collect();
    sequence(&ids)
}

/// subjectKeyIdentifier value: `KeyIdentifier ::= OCTET STRING`.
/// Spec: RFC 5280 4.2.1.2.
pub fn subject_key_identifier(id: &[u8]) -> Vec<u8> {
    octet_string(id)
}

/// authorityKeyIdentifier value with `keyIdentifier [0] KeyIdentifier`
/// only (implicitly tagged module ⇒ primitive [0]). Spec: RFC 5280 4.2.1.1,
/// A.2.
pub fn authority_key_identifier(id: &[u8]) -> Vec<u8> {
    sequence(&[implicit(0, id)])
}

/// The components of a TBSCertificate, each already DER (so tests can put
/// any of them out of profile); [`Tbs::encode`] writes them in RFC 5280
/// §4.1 order.
#[derive(Clone)]
pub struct Tbs {
    /// The whole `[0]` element, or `None` (v1 by default).
    pub version: Option<Vec<u8>>,
    pub serial_number: Vec<u8>,
    pub signature: Vec<u8>,
    pub issuer: Vec<u8>,
    pub validity: Vec<u8>,
    pub subject: Vec<u8>,
    pub subject_public_key_info: Vec<u8>,
    /// Extra elements between the SPKI and the extensions (unique ids).
    pub unique_ids: Vec<Vec<u8>>,
    /// The whole `[3]` element, or `None`.
    pub extensions: Option<Vec<u8>>,
}

impl Tbs {
    /// `TBSCertificate ::= SEQUENCE { … }`. Spec: RFC 5280 4.1.
    pub fn encode(&self) -> Vec<u8> {
        let mut parts = Vec::new();
        if let Some(version) = &self.version {
            parts.push(version.clone());
        }
        parts.push(self.serial_number.clone());
        parts.push(self.signature.clone());
        parts.push(self.issuer.clone());
        parts.push(self.validity.clone());
        parts.push(self.subject.clone());
        parts.push(self.subject_public_key_info.clone());
        parts.extend(self.unique_ids.iter().cloned());
        if let Some(extensions) = &self.extensions {
            parts.push(extensions.clone());
        }
        sequence(&parts)
    }
}

/// `Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm,
/// signatureValue BIT STRING }`. Spec: RFC 5280 4.1.
pub fn certificate(tbs: &[u8], signature_algorithm: &[u8], signature_value: &[u8]) -> Vec<u8> {
    sequence(&[
        tbs.to_vec(),
        signature_algorithm.to_vec(),
        bit_string(0, signature_value),
    ])
}
