//! Real RFC 5280 test certificates, built in-test (docs/questions/Q-320;
//! Q-285 item 1 → A-71): a test CA and end-entity certificates it signs,
//! with fresh ECDSA P-256 keys per run.
//!
//! * The DER structure comes from crates/parse-x509's test builder
//!   (`build`, reused by `#[path]`): RFC 5280 §4.1 with parse-asn1's
//!   encoder; its object identifiers are RFC 5280 Appendix A's.
//! * The algorithm identifiers are rustls-pki-types' documented constants
//!   (docs.rs 1.16.0 `alg_id::ECDSA_SHA256` — "ecdsa-with-SHA256";
//!   `alg_id::ECDSA_P256` — "id-ecPublicKey with named curve secp256r1";
//!   `ECDSA_SHA384`, `ECDSA_P384` for the refusals), wrapped in the
//!   AlgorithmIdentifier SEQUENCE their documentation says they omit ("The
//!   outer sequence encoding is not included"). No ECDSA object identifier
//!   is written here (RFC 5480 / RFC 5758 are not in specs/SOURCES.md).
//! * Each SubjectPublicKeyInfo is the one rustls' aws-lc-rs provider reports
//!   for the key (`SigningKey::public_key`: "the RFC 5280-compliant
//!   SubjectPublicKeyInfo (SPKI) of this SigningKey") — so no EC point
//!   encoding is written here either.
//! * Signatures: aws-lc-rs `EcdsaKeyPair::sign` with
//!   `ECDSA_P256_SHA256_ASN1_SIGNING` ("Signing of ASN.1 DER-encoded ECDSA
//!   signatures using the P-256 curve and SHA-256") over the DER
//!   tbsCertificate (RFC 5280 §4.1.1.3: "The ASN.1 DER encoded
//!   tbsCertificate is used as the input to the signature function"); the
//!   octets go into signatureValue as a BIT STRING with no unused bits (RFC
//!   8446 §4.2.3: ECDSA signatures are "a DER-encoded [X690] ECDSA-Sig-Value
//!   structure").
//! * The CA: basicConstraints cA TRUE (critical, RFC 5280 §4.2.1.9 "MUST
//!   mark the extension as critical"), keyUsage keyCertSign (critical,
//!   §4.2.1.3 "SHOULD"), subjectKeyIdentifier (§4.2.1.2 "MUST appear in all
//!   conforming CA certificates"). An end entity: subjectAltName dNSName
//!   (non-critical with a non-empty subject, §4.2.1.6), keyUsage
//!   digitalSignature, extKeyUsage id-kp-serverAuth or id-kp-clientAuth
//!   (§4.2.1.12), authorityKeyIdentifier = the CA's key identifier
//!   (§4.2.1.1, §4.2.1.2). Key identifiers: SHA-256 of the SPKI (§4.2.1.2:
//!   "a similar method that uses a different hash algorithm").
//! * Validity: notBefore 2025-01-01T00:00:00Z (UTCTime), notAfter
//!   99991231235959Z (GeneralizedTime — RFC 5280 §4.1.2.5's value for "no
//!   well-defined expiration date"), unless a test sets its own window.
//!
//! Every value is made here, per run; nothing comes from another
//! implementation's tests (AGENTS.md §2).
//!
//! Sources: RFC 5280 §4.1, §4.1.1.2, §4.1.1.3, §4.1.2.1-§4.1.2.9,
//! §4.2.1.1-§4.2.1.3, §4.2.1.6, §4.2.1.9, §4.2.1.12, A.1, A.2; RFC 8446
//! §4.2.3; X.690 8.6.2, 8.14, 11.2.2; docs.rs rustls 0.23.46
//! (`crypto::aws_lc_rs::sign::any_ecdsa_type`, `sign::SigningKey::
//! public_key`), rustls-pki-types 1.16.0 (`alg_id`, `AlgorithmIdentifier`),
//! aws-lc-rs 1.19.0 (`signature::{EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_
//! SIGNING, ECDSA_P384_SHA384_ASN1_SIGNING}`, `rand::SystemRandom`,
//! `digest::{digest, SHA256}`).
#![allow(dead_code)] // each test binary uses a different subset

#[path = "../../../parse-x509/tests/common/build.rs"]
pub mod build;

use aws_lc_rs::digest::{digest, SHA256};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{
    EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P384_SHA384_ASN1_SIGNING,
};
use build::*;
use rustls::crypto::aws_lc_rs as provider_lc;
use rustls::pki_types::{alg_id, AlgorithmIdentifier, PrivateKeyDer, PrivatePkcs8KeyDer};

/// The server name the test clients ask for and the server certificate
/// carries (subjectAltName dNSName).
pub const SERVER_NAME: &str = "dc1.example.org";

/// The name in the client certificate.
pub const CLIENT_NAME: &str = "client.example.org";

/// notBefore of the default window: 2025-01-01T00:00:00Z.
pub const NOT_BEFORE: &str = "250101000000Z";

/// [`NOT_BEFORE`] in seconds since the epoch (hand-derived in
/// crates/parse-x509 src/time.rs: 20 089 days × 86 400).
pub const NOT_BEFORE_SECONDS: u64 = 1_735_689_600;

/// notAfter of the default window. Spec: RFC 5280 4.1.2.5.
pub const NO_EXPIRATION: &str = "99991231235959Z";

/// A fresh ECDSA P-256 key's PKCS#8 DER (aws-lc-rs).
pub fn p256_pkcs8() -> Vec<u8> {
    EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
        .expect("key generation")
        .as_ref()
        .to_vec()
}

/// A fresh ECDSA P-384 key's PKCS#8 DER (aws-lc-rs).
pub fn p384_pkcs8() -> Vec<u8> {
    EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, &SystemRandom::new())
        .expect("key generation")
        .as_ref()
        .to_vec()
}

/// The SubjectPublicKeyInfo of a PKCS#8 ECDSA key, as the provider reports
/// it (module documentation).
pub fn spki_of(pkcs8: &[u8]) -> Vec<u8> {
    let key =
        provider_lc::sign::any_ecdsa_type(&PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8)))
            .expect("ECDSA key");
    key.public_key().expect("SPKI").as_ref().to_vec()
}

/// The AlgorithmIdentifier DER of a documented constant: the SEQUENCE
/// header around the constant's octets (module documentation).
pub fn algorithm(id: AlgorithmIdentifier) -> Vec<u8> {
    algorithm_identifier(id.as_ref())
}

/// A key identifier: SHA-256 of the SPKI. Spec: RFC 5280 4.2.1.2.
fn key_identifier(spki: &[u8]) -> Vec<u8> {
    digest(&SHA256, spki).as_ref().to_vec()
}

/// Sign `tbs` with the P-256 key `signer` and assemble the Certificate
/// with `signature_algorithm` as the outer AlgorithmIdentifier.
/// Spec: RFC 5280 4.1, 4.1.1.2, 4.1.1.3.
pub fn sign(signer: &[u8], tbs: &[u8], signature_algorithm: &[u8]) -> Vec<u8> {
    let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, signer).expect("key");
    let signature = pair.sign(&SystemRandom::new(), tbs).expect("signature");
    certificate(tbs, signature_algorithm, signature.as_ref())
}

/// The test CA: its self-signed certificate, its key, name and key
/// identifier.
pub struct Ca {
    pub certificate: Vec<u8>,
    pub pkcs8: Vec<u8>,
    pub name: Vec<u8>,
    pub key_id: Vec<u8>,
}

/// A fresh test CA (module documentation).
pub fn ca() -> Ca {
    let pkcs8 = p256_pkcs8();
    let spki = spki_of(&pkcs8);
    let key_id = key_identifier(&spki);
    let name = name("ldap-front test CA");
    let tbs = Tbs {
        version: Some(version_v3()),
        serial_number: integer(1),
        signature: algorithm(alg_id::ECDSA_SHA256),
        issuer: name.clone(),
        validity: validity(utc_time(NOT_BEFORE), generalized_time(NO_EXPIRATION)),
        subject: name.clone(),
        subject_public_key_info: spki,
        unique_ids: Vec::new(),
        extensions: Some(extensions(&[
            extension(&ID_CE_BASIC_CONSTRAINTS, true, &basic_constraints_ca()),
            extension(&ID_CE_KEY_USAGE, true, &key_usage_key_cert_sign()),
            extension(
                &ID_CE_SUBJECT_KEY_IDENTIFIER,
                false,
                &subject_key_identifier(&key_id),
            ),
        ])),
    }
    .encode();
    let certificate = sign(&pkcs8, &tbs, &algorithm(alg_id::ECDSA_SHA256));
    Ca {
        certificate,
        pkcs8,
        name,
        key_id,
    }
}

/// What an end-entity certificate carries; each field DER, so a test can
/// put one out of profile.
#[derive(Clone)]
pub struct EndEntity {
    /// The `[0]` version element (`None`: absent, i.e. v1).
    pub version: Option<Vec<u8>>,
    pub serial: i64,
    /// tbsCertificate.signature.
    pub signature: Vec<u8>,
    /// The outer signatureAlgorithm.
    pub signature_algorithm: Vec<u8>,
    pub subject_public_key_info: Vec<u8>,
    pub not_before: Vec<u8>,
    pub not_after: Vec<u8>,
    pub dns_name: &'static str,
    pub purpose: [u64; 9],
    /// Whether the extensions are written (a v1 certificate has none,
    /// RFC 5280 4.1.2.9).
    pub with_extensions: bool,
}

impl EndEntity {
    /// The DC's server certificate for the key `pkcs8`, in profile.
    pub fn server(pkcs8: &[u8]) -> EndEntity {
        EndEntity {
            version: Some(version_v3()),
            serial: 2,
            signature: algorithm(alg_id::ECDSA_SHA256),
            signature_algorithm: algorithm(alg_id::ECDSA_SHA256),
            subject_public_key_info: spki_of(pkcs8),
            not_before: utc_time(NOT_BEFORE),
            not_after: generalized_time(NO_EXPIRATION),
            dns_name: SERVER_NAME,
            purpose: ID_KP_SERVER_AUTH,
            with_extensions: true,
        }
    }

    /// A client certificate for the key `pkcs8`.
    pub fn client(pkcs8: &[u8]) -> EndEntity {
        EndEntity {
            serial: 3,
            dns_name: CLIENT_NAME,
            purpose: ID_KP_CLIENT_AUTH,
            ..EndEntity::server(pkcs8)
        }
    }
}

impl Ca {
    /// The tbsCertificate of `entity`, issued by this CA.
    /// Spec: RFC 5280 4.1, 4.1.2.
    pub fn tbs(&self, entity: &EndEntity) -> Vec<u8> {
        let extensions = entity.with_extensions.then(|| {
            extensions(&[
                extension(
                    &ID_CE_SUBJECT_ALT_NAME,
                    false,
                    &subject_alt_name_dns(&[entity.dns_name]),
                ),
                extension(&ID_CE_KEY_USAGE, true, &key_usage_digital_signature()),
                extension(
                    &ID_CE_EXT_KEY_USAGE,
                    false,
                    &ext_key_usage(&[&entity.purpose]),
                ),
                extension(
                    &ID_CE_AUTHORITY_KEY_IDENTIFIER,
                    false,
                    &authority_key_identifier(&self.key_id),
                ),
            ])
        });
        Tbs {
            version: entity.version.clone(),
            serial_number: integer(entity.serial),
            signature: entity.signature.clone(),
            issuer: self.name.clone(),
            validity: validity(entity.not_before.clone(), entity.not_after.clone()),
            subject: name(entity.dns_name),
            subject_public_key_info: entity.subject_public_key_info.clone(),
            unique_ids: Vec::new(),
            extensions,
        }
        .encode()
    }

    /// `entity`'s certificate, signed by this CA.
    pub fn issue(&self, entity: &EndEntity) -> Vec<u8> {
        sign(&self.pkcs8, &self.tbs(entity), &entity.signature_algorithm)
    }
}

/// A test CA, the DC's server certificate and key, and a client
/// certificate and key — all fresh.
pub struct TestPki {
    pub ca: Ca,
    pub server_certificate: Vec<u8>,
    pub server_key: Vec<u8>,
    pub client_certificate: Vec<u8>,
    pub client_key: Vec<u8>,
}

/// A fresh [`TestPki`].
pub fn test_pki() -> TestPki {
    let ca = ca();
    let server_key = p256_pkcs8();
    let server_certificate = ca.issue(&EndEntity::server(&server_key));
    let client_key = p256_pkcs8();
    let client_certificate = ca.issue(&EndEntity::client(&client_key));
    TestPki {
        ca,
        server_certificate,
        server_key,
        client_certificate,
        client_key,
    }
}
