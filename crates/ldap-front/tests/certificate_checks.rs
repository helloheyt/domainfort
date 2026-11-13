//! Tier 1 (docs/50 §9: in-process): the DC certificate checks of
//! `DcCredential::from_der` (docs/50 R50-12, §5.3; docs/questions/Q-320),
//! each refused case built from a real per-run certificate with one thing
//! changed (tests/common/cert.rs):
//!
//! * (a) the outer signatureAlgorithm differs from tbsCertificate.signature
//!   — RFC 5280 §4.1.1.2 ("MUST contain the same algorithm identifier");
//! * (b) a signature algorithm other than ecdsa-with-SHA256, and a subject
//!   key on another curve — rustls-pki-types' documented `alg_id` constants
//!   (`ECDSA_SHA256`, `ECDSA_P256`; `ECDSA_SHA384`, `ECDSA_P384` for the
//!   refusals);
//! * (c) a subject key that is not the private key's;
//! * (d) a start time before notBefore or after notAfter — RFC 5280
//!   §4.1.2.5 ("from notBefore through notAfter, inclusive");
//! * the file is exactly one DER X.509 v3 certificate: trailing octets, a
//!   second certificate, a non-minimal long-form length, the indefinite
//!   length, a v1 certificate, truncation and an oversized file are
//!   refused (RFC 5280 §4.1, §4.1.2.1; X.690 8.1.3.6, 10.1).
//!
//! Sources: RFC 5280 §4.1, §4.1.1.2, §4.1.2.1, §4.1.2.3, §4.1.2.5,
//! §4.1.2.7, §4.1.2.9; X.690 8.1.3, 8.8, 10.1; docs.rs rustls-pki-types
//! 1.16.0 `alg_id`, `UnixTime::since_unix_epoch`. Every value is made here.

#[path = "common/cert.rs"]
mod cert_support;

use cert_support::build::{self, element, utc_time};
use cert_support::{algorithm, spki_of, test_pki, EndEntity, NOT_BEFORE_SECONDS};
use core::time::Duration;
use ldap_front::tls::{CredentialError, DcCredential};
use parse_asn1::TagClass;
use parse_x509::{Error as X509, Field, MAX_CERTIFICATE_OCTETS};
use rustls::pki_types::{alg_id, UnixTime};

fn now() -> UnixTime {
    ldap_front::startup::start_time().unwrap()
}

fn at(seconds: u64) -> UnixTime {
    UnixTime::since_unix_epoch(Duration::from_secs(seconds))
}

/// `from_der`'s refusal of `certificate` with `key` at `now`.
fn refusal(certificate: Vec<u8>, key: &[u8], now: UnixTime) -> CredentialError {
    DcCredential::from_der(certificate, key, now).expect_err("refused")
}

/// `NULL` (UNIVERSAL 5, empty contents) — X.680 Table 1; X.690 8.8.2 ("The
/// contents octets shall not contain any octets").
fn null() -> Vec<u8> {
    element(TagClass::Universal, false, 5, &[])
}

/// RFC 5280 §4.1.1.2, §4.1.2.3, §4.1.2.7: the in-profile certificate
/// passes, and its AlgorithmIdentifiers hold exactly the documented
/// constants' octets (the SEQUENCE contents — "The outer sequence encoding
/// is not included", docs.rs rustls-pki-types 1.16.0).
#[test]
fn the_real_certificate_passes_every_check() {
    let pki = test_pki();
    let parsed = parse_x509::parse_certificate(&pki.server_certificate).unwrap();
    let tbs = &parsed.tbs_certificate;
    assert_eq!(tbs.signature.contents, alg_id::ECDSA_SHA256.as_ref());
    assert_eq!(parsed.signature_algorithm.encoding, tbs.signature.encoding);
    assert_eq!(
        tbs.subject_public_key_info.algorithm.contents,
        alg_id::ECDSA_P256.as_ref()
    );
    assert_eq!(
        tbs.subject_public_key_info.encoding,
        spki_of(&pki.server_key).as_slice()
    );
    assert_eq!(tbs.extensions.len(), 4);
    assert!(DcCredential::from_der(pki.server_certificate.clone(), &pki.server_key, now()).is_ok());
}

/// (a) RFC 5280 §4.1.1.2: the outer signatureAlgorithm must be the same
/// AlgorithmIdentifier as tbsCertificate.signature — a different algorithm
/// on either side, or the same algorithm with parameters on one side only,
/// is refused (before the algorithm itself is judged).
#[test]
fn a_mismatched_inner_and_outer_algorithm_is_refused() {
    let pki = test_pki();
    let key = &pki.server_key;
    let mut outer_differs = EndEntity::server(key);
    outer_differs.signature_algorithm = algorithm(alg_id::ECDSA_SHA384);
    assert_eq!(
        refusal(pki.ca.issue(&outer_differs), key, now()),
        CredentialError::SignatureAlgorithmMismatch
    );
    let mut inner_differs = EndEntity::server(key);
    inner_differs.signature = algorithm(alg_id::ECDSA_SHA384);
    assert_eq!(
        refusal(pki.ca.issue(&inner_differs), key, now()),
        CredentialError::SignatureAlgorithmMismatch
    );
    let mut parameters_differ = EndEntity::server(key);
    parameters_differ.signature_algorithm =
        build::algorithm_identifier(&[alg_id::ECDSA_SHA256.as_ref(), &null()].concat());
    assert_eq!(
        refusal(pki.ca.issue(&parameters_differ), key, now()),
        CredentialError::SignatureAlgorithmMismatch
    );
}

/// (b) docs/50 R50-12, §5.3: consistent but not ecdsa-with-SHA256 — the
/// documented ecdsa-with-SHA384, and ecdsa-with-SHA256 carrying a
/// parameters element the constant does not have — is refused, before the
/// key is looked at.
#[test]
fn a_signature_algorithm_other_than_ecdsa_sha256_is_refused() {
    let pki = test_pki();
    let key = &pki.server_key;
    let mut sha384 = EndEntity::server(key);
    sha384.signature = algorithm(alg_id::ECDSA_SHA384);
    sha384.signature_algorithm = algorithm(alg_id::ECDSA_SHA384);
    let certificate = pki.ca.issue(&sha384);
    assert_eq!(
        refusal(certificate.clone(), key, now()),
        CredentialError::NotEcdsaSha256
    );
    // The certificate is judged before the key.
    assert_eq!(
        refusal(certificate, b"not a key", now()),
        CredentialError::NotEcdsaSha256
    );
    let with_parameters =
        build::algorithm_identifier(&[alg_id::ECDSA_SHA256.as_ref(), &null()].concat());
    let mut parameterised = EndEntity::server(key);
    parameterised.signature = with_parameters.clone();
    parameterised.signature_algorithm = with_parameters;
    assert_eq!(
        refusal(pki.ca.issue(&parameterised), key, now()),
        CredentialError::NotEcdsaSha256
    );
}

/// (b) docs/50 R50-12; RFC 5280 §4.1.2.7: a subject key on P-384 — a real
/// P-384 key's SPKI, whose algorithm is exactly the documented
/// `alg_id::ECDSA_P384` — and the P-256 key's point under the P-384
/// AlgorithmIdentifier are both refused as not P-256.
#[test]
fn a_subject_key_on_another_curve_is_refused() {
    let pki = test_pki();
    let key = &pki.server_key;
    let p384_spki = spki_of(&cert_support::p384_pkcs8());
    let mut p384 = EndEntity::server(key);
    p384.subject_public_key_info = p384_spki.clone();
    let certificate = pki.ca.issue(&p384);
    let parsed = parse_x509::parse_certificate(&certificate).unwrap();
    assert_eq!(
        parsed
            .tbs_certificate
            .subject_public_key_info
            .algorithm
            .contents,
        alg_id::ECDSA_P384.as_ref()
    );
    assert_eq!(
        refusal(certificate.clone(), key, now()),
        CredentialError::PublicKeyNotP256
    );
    // The P-256 point, relabelled as P-384.
    let p256_spki = spki_of(key);
    let point = parse_x509::parse_certificate(&pki.server_certificate)
        .unwrap()
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .to_vec();
    assert!(p256_spki.ends_with(&point));
    let mut relabelled = EndEntity::server(key);
    relabelled.subject_public_key_info =
        build::subject_public_key_info(alg_id::ECDSA_P384.as_ref(), &point);
    assert_eq!(
        refusal(pki.ca.issue(&relabelled), key, now()),
        CredentialError::PublicKeyNotP256
    );
}

/// (c) the certificate's SubjectPublicKeyInfo must be the private key's
/// (`CertifiedKey::keys_match`): another P-256 key is refused.
#[test]
fn a_subject_key_that_is_not_the_private_key_is_refused() {
    let pki = test_pki();
    let other = cert_support::p256_pkcs8();
    assert_eq!(
        refusal(pki.server_certificate.clone(), &other, now()),
        CredentialError::KeyMismatch
    );
    // And the other way round: a certificate for `other` with the DC key.
    let for_other = pki.ca.issue(&EndEntity::server(&other));
    assert_eq!(
        refusal(for_other, &pki.server_key, now()),
        CredentialError::KeyMismatch
    );
}

/// (d) RFC 5280 §4.1.2.5 ("the period of time from notBefore through
/// notAfter, inclusive"); Q-320 item 4 (fail closed at start): a ten-second
/// window from 2025-01-01T00:00:00Z (NOT_BEFORE_SECONDS, hand-derived) —
/// one second early is not yet valid, both ends are valid, one second late
/// is expired.
#[test]
fn a_start_time_outside_the_validity_is_refused() {
    let pki = test_pki();
    let key = &pki.server_key;
    let mut window = EndEntity::server(key);
    window.not_before = utc_time("250101000000Z");
    window.not_after = utc_time("250101000010Z");
    let certificate = pki.ca.issue(&window);
    let load = |seconds: u64| DcCredential::from_der(certificate.clone(), key, at(seconds));
    assert_eq!(
        load(NOT_BEFORE_SECONDS - 1).err(),
        Some(CredentialError::NotYetValid)
    );
    assert!(load(NOT_BEFORE_SECONDS).is_ok());
    assert!(load(NOT_BEFORE_SECONDS + 10).is_ok());
    assert_eq!(
        load(NOT_BEFORE_SECONDS + 11).err(),
        Some(CredentialError::Expired)
    );
    // The default certificate (until 99991231235959Z) is valid now and is
    // not yet valid before 2025.
    assert!(DcCredential::from_der(pki.server_certificate.clone(), key, now()).is_ok());
    assert_eq!(
        refusal(pki.server_certificate.clone(), key, at(0)),
        CredentialError::NotYetValid
    );
}

/// RFC 5280 §4.1 (one Certificate, nothing after it — the file holds no
/// chain); X.690 8.1.3.6, 10.1 (definite, minimal lengths); RFC 5280
/// §4.1.2.1 (v3 only); the size bound; truncation.
#[test]
fn the_file_is_exactly_one_der_v3_certificate() {
    let pki = test_pki();
    let key = &pki.server_key;
    let der = pki.server_certificate.clone();
    let malformed = |error| CredentialError::CertificateMalformed(error);

    let mut trailing = der.clone();
    trailing.push(0x00);
    assert_eq!(
        refusal(trailing, key, now()),
        malformed(X509::TrailingData(Field::Certificate))
    );
    let chain = [der.clone(), pki.ca.certificate.clone()].concat();
    assert_eq!(
        refusal(chain, key, now()),
        malformed(X509::TrailingData(Field::Certificate))
    );

    // The same contents under a long-form length with a leading zero
    // octet, and under the indefinite form.
    let contents = parse_asn1::split_element(&der).unwrap().0.contents.to_vec();
    let length = u16::try_from(contents.len()).unwrap().to_be_bytes();
    let mut long_form = vec![0x30, 0x83, 0x00, length[0], length[1]];
    long_form.extend_from_slice(&contents);
    assert_eq!(
        refusal(long_form, key, now()),
        malformed(X509::Der(
            Field::Certificate,
            parse_asn1::Error::NonMinimalLength
        ))
    );
    let mut indefinite = vec![0x30, 0x80];
    indefinite.extend_from_slice(&contents);
    indefinite.extend_from_slice(&[0x00, 0x00]);
    assert_eq!(
        refusal(indefinite, key, now()),
        malformed(X509::Der(
            Field::Certificate,
            parse_asn1::Error::IndefiniteLength
        ))
    );

    // A v1 certificate (no version, no extensions — RFC 5280 4.1.2.9),
    // otherwise in profile and properly signed.
    let mut v1 = EndEntity::server(key);
    v1.version = None;
    v1.with_extensions = false;
    assert_eq!(
        refusal(pki.ca.issue(&v1), key, now()),
        malformed(X509::VersionNotV3)
    );

    // Truncated anywhere.
    for cut in [1, 2, 4, der.len() / 2, der.len() - 1] {
        assert!(
            matches!(
                refusal(der[..cut].to_vec(), key, now()),
                CredentialError::CertificateMalformed(_)
            ),
            "cut at {cut}"
        );
    }

    // Oversized: refused before it is read.
    let mut oversized = der.clone();
    oversized.resize(MAX_CERTIFICATE_OCTETS + 1, 0);
    assert_eq!(refusal(oversized, key, now()), malformed(X509::TooLarge));
}

/// docs/50 §8.2; AGENTS.md §6: the refusal texts are fixed and name the
/// rule (and, for a malformed file, the field) — never an octet of the
/// file or of the key.
#[test]
fn refusal_texts_carry_no_material() {
    let pki = test_pki();
    let mut trailing = pki.server_certificate.clone();
    trailing.push(0xAB);
    let text = refusal(trailing, &pki.server_key, now()).to_string();
    assert_eq!(
        text,
        "DC certificate file is not one DER X.509 v3 certificate: Certificate: unexpected trailing octets"
    );
    assert_eq!(
        CredentialError::SignatureAlgorithmMismatch.to_string(),
        "DC certificate signatureAlgorithm differs from tbsCertificate.signature"
    );
    assert_eq!(
        CredentialError::Expired.to_string(),
        "DC certificate has expired (notAfter is before the start time)"
    );
}
