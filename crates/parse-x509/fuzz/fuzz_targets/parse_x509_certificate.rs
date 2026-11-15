#![no_main]
//! Fuzz target for `parse_x509::parse_certificate`, the RFC 5280 §4.1
//! certificate reader.
//!
//! docs/CLEAN-ROOM.md / docs/32 §8 (every parser gets a fuzz target before it
//! merges to main). On any input the reader must not panic, hang or
//! over-allocate, and:
//!
//! * input over `MAX_CERTIFICATE_OCTETS` is refused;
//! * an accepted certificate is the whole input; its tbsCertificate,
//!   signatureAlgorithm, SPKI and inner signature lie inside it, the
//!   tbsCertificate first (RFC 5280 4.1);
//! * the AlgorithmIdentifier contents sit inside their encoding, starting
//!   with the algorithm OID (RFC 5280 4.1.1.2);
//! * the extensions respect the bound and no extnID repeats (RFC 5280 4.2);
//! * the serialNumber respects its bound (RFC 5280 4.1.2.2);
//! * reading the same octets again gives the same result (no hidden state).
//!
//! Spec: RFC 5280 4.1, 4.1.1.2, 4.1.2.2, 4.2; X.690 8, 10, 11.

use libfuzzer_sys::fuzz_target;
use parse_x509::{
    parse_certificate, AlgorithmIdentifier, MAX_CERTIFICATE_OCTETS, MAX_EXTENSIONS,
    MAX_SERIAL_NUMBER_OCTETS,
};

/// Whether `inner` is a sub-slice of `outer` (by address range).
fn inside(inner: &[u8], outer: &[u8]) -> bool {
    let outer_start = outer.as_ptr() as usize;
    let inner_start = inner.as_ptr() as usize;
    inner_start >= outer_start && inner_start + inner.len() <= outer_start + outer.len()
}

fn check_algorithm(algorithm: &AlgorithmIdentifier<'_>, certificate: &[u8]) {
    assert!(inside(algorithm.encoding, certificate));
    assert!(inside(algorithm.contents, algorithm.encoding));
    assert!(algorithm.contents.starts_with(algorithm.algorithm));
    if let Some(parameters) = algorithm.parameters {
        assert!(algorithm.contents.ends_with(parameters));
    }
}

fuzz_target!(|data: &[u8]| {
    let parsed = parse_certificate(data);
    if data.len() > MAX_CERTIFICATE_OCTETS {
        assert!(parsed.is_err(), "input bound enforced");
    }
    assert_eq!(parse_certificate(data), parsed, "deterministic");
    let Ok(certificate) = parsed else {
        return;
    };
    assert_eq!(certificate.encoding, data, "the whole input");
    let tbs = &certificate.tbs_certificate;
    assert!(inside(tbs.encoding, data));
    check_algorithm(&tbs.signature, data);
    check_algorithm(&certificate.signature_algorithm, data);
    check_algorithm(&tbs.subject_public_key_info.algorithm, data);
    assert!(inside(tbs.subject_public_key_info.encoding, tbs.encoding));
    assert!(inside(tbs.issuer, tbs.encoding));
    assert!(inside(tbs.subject, tbs.encoding));
    assert!(tbs.serial_number.len() <= MAX_SERIAL_NUMBER_OCTETS);
    assert!(tbs.extensions.len() <= MAX_EXTENSIONS);
    for (i, a) in tbs.extensions.iter().enumerate() {
        for b in &tbs.extensions[i + 1..] {
            assert_ne!(a.extn_id, b.extn_id, "no extnID twice");
        }
    }
    let validity = tbs.validity;
    let _ = validity.contains(validity.not_before.unix_seconds());
});
