//! The TLS side of the harness, with **real X.509 certificates** built in
//! the test (docs/questions/Q-320, A-81 — the follow-up of Q-285 item 1 →
//! A-71). No custom certificate verifier remains (task F1).
//!
//! * **The certificates.** Per run, a test CA and the DC's server
//!   certificate, from RFC 5280 §4.1 structures with crates/parse-x509's
//!   test DER builder (`build`, reused through `#[path]`, as crates/
//!   ldap-front's tests/common/cert.rs reuses it) and fresh aws-lc-rs ECDSA
//!   P-256 keys — the subset of ldap-front's test CA design (this project's
//!   code) the end-to-end tests need:
//!   * algorithm identifiers: rustls-pki-types' documented constants
//!     (`alg_id::ECDSA_SHA256`, "ecdsa-with-SHA256"), wrapped in the
//!     AlgorithmIdentifier SEQUENCE their documentation says they omit;
//!   * each SubjectPublicKeyInfo: the one rustls' aws-lc-rs provider reports
//!     for the key (`SigningKey::public_key`, "the RFC 5280-compliant
//!     SubjectPublicKeyInfo (SPKI) of this SigningKey");
//!   * signatures: aws-lc-rs `EcdsaKeyPair::sign` with
//!     `ECDSA_P256_SHA256_ASN1_SIGNING` over the DER tbsCertificate (RFC
//!     5280 §4.1.1.3), carried as a BIT STRING with no unused bits;
//!   * the CA: basicConstraints cA TRUE (critical, §4.2.1.9), keyUsage
//!     keyCertSign (critical, §4.2.1.3), subjectKeyIdentifier (§4.2.1.2);
//!     the server: subjectAltName dNSName [`SERVER_NAME`] (§4.2.1.6),
//!     keyUsage digitalSignature (critical), extKeyUsage id-kp-serverAuth
//!     (§4.2.1.12), authorityKeyIdentifier = the CA's key identifier
//!     (§4.2.1.1); key identifiers: SHA-256 of the SPKI (§4.2.1.2: "a
//!     similar method that uses a different hash algorithm");
//!   * validity: notBefore 2025-01-01T00:00:00Z (UTCTime), notAfter
//!     99991231235959Z (GeneralizedTime, §4.1.2.5's "no well-defined
//!     expiration date").
//! * **The server side is the product's**: the certificate and key go
//!   through the production loader `ldap_front::tls::DcCredential::from_der`
//!   (every docs/50 R50-12 check, at the current time) and
//!   `ldap_front::tls::server_config` (R50-11: TLS 1.3 only, the suites,
//!   groups, no tickets, no key log, no client authentication).
//! * **The client side is rustls' standard verifier**:
//!   `WebPkiServerVerifier::builder_with_provider` over a `RootCertStore`
//!   holding **only the test CA** — "Signed by a trusted RootCertStore CA,
//!   Not Expired, Valid for DNS entry" (docs.rs rustls 0.23.46
//!   `WebPkiServerVerifier::verify_server_cert`) — so every handshake
//!   proves the chain, the name, the validity and the CertificateVerify
//!   signature (RFC 8446 §4.4.2, §4.4.3).
//!
//! Sources: RFC 5280 §4.1, §4.1.1.2, §4.1.1.3, §4.1.2.1-§4.1.2.9,
//! §4.2.1.1-§4.2.1.3, §4.2.1.6, §4.2.1.9, §4.2.1.12, A.1, A.2; RFC 8446
//! §4.2.3, §4.4.2, §4.4.3, §9.1; docs/50 R50-11, R50-12, §9; crates/
//! ldap-front tests/common/{cert.rs,tls.rs}; docs.rs rustls 0.23.46
//! (`ClientConfig`, `ConfigBuilder::with_webpki_verifier`,
//! `client::WebPkiServerVerifier`, `RootCertStore::{empty, add}`,
//! `crypto::aws_lc_rs::sign::any_ecdsa_type`, `sign::SigningKey::
//! public_key`), rustls-pki-types 1.16.0 (`alg_id`, `AlgorithmIdentifier`),
//! aws-lc-rs 1.19.0 (`signature::{EcdsaKeyPair,
//! ECDSA_P256_SHA256_ASN1_SIGNING}`, `rand::SystemRandom`, `digest::{digest,
//! SHA256}`) — API pages only. Every value is made here, per run.
#![allow(dead_code)]

#[path = "../../../parse-x509/tests/common/build.rs"]
pub mod build;

use aws_lc_rs::digest::{digest, SHA256};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use build::*;
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::{aws_lc_rs as provider_lc, CryptoProvider};
use rustls::pki_types::{alg_id, CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::server::ServerConfig;
use rustls::{ClientConfig, RootCertStore};
use std::sync::Arc;

/// The DC's DNS name: the server certificate's subjectAltName dNSName and
/// the name the test clients ask for (the harness's `DNS_HOST_NAME`).
pub const SERVER_NAME: &str = "dc1.example.org";

/// notBefore: 2025-01-01T00:00:00Z. Spec: RFC 5280 4.1.2.5.
const NOT_BEFORE: &str = "250101000000Z";

/// notAfter: no well-defined expiration date. Spec: RFC 5280 4.1.2.5.
const NO_EXPIRATION: &str = "99991231235959Z";

/// A fresh ECDSA P-256 key's PKCS#8 DER (aws-lc-rs).
fn p256_pkcs8() -> Vec<u8> {
    EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
        .expect("key generation")
        .as_ref()
        .to_vec()
}

/// The SubjectPublicKeyInfo of a PKCS#8 ECDSA key, as the provider reports
/// it (module documentation).
fn spki_of(pkcs8: &[u8]) -> Vec<u8> {
    let key =
        provider_lc::sign::any_ecdsa_type(&PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8)))
            .expect("ECDSA key");
    key.public_key().expect("SPKI").as_ref().to_vec()
}

/// ecdsa-with-SHA256 as an AlgorithmIdentifier: the SEQUENCE header around
/// the documented constant's octets.
fn ecdsa_sha256() -> Vec<u8> {
    algorithm_identifier(alg_id::ECDSA_SHA256.as_ref())
}

/// A key identifier: SHA-256 of the SPKI. Spec: RFC 5280 4.2.1.2.
fn key_identifier(spki: &[u8]) -> Vec<u8> {
    digest(&SHA256, spki).as_ref().to_vec()
}

/// Sign `tbs` with the P-256 key `signer` and assemble the Certificate.
/// Spec: RFC 5280 4.1, 4.1.1.2, 4.1.1.3.
fn sign(signer: &[u8], tbs: &[u8]) -> Vec<u8> {
    let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, signer).expect("key");
    let signature = pair.sign(&SystemRandom::new(), tbs).expect("signature");
    certificate(tbs, &ecdsa_sha256(), signature.as_ref())
}

/// The test CA and the DC's server certificate and key, all fresh.
pub struct TestPki {
    /// The test CA's self-signed certificate (DER) — the clients' only
    /// trust anchor.
    pub ca_certificate: Vec<u8>,
    /// The DC's server certificate (DER), issued by the test CA.
    pub server_certificate: Vec<u8>,
    /// The server certificate's key (PKCS#8 DER).
    pub server_key: Vec<u8>,
}

/// A fresh [`TestPki`] (module documentation).
pub fn test_pki() -> TestPki {
    // The CA.
    let ca_key = p256_pkcs8();
    let ca_spki = spki_of(&ca_key);
    let ca_key_id = key_identifier(&ca_spki);
    let ca_name = name("e2e-tests test CA");
    let ca_tbs = Tbs {
        version: Some(version_v3()),
        serial_number: integer(1),
        signature: ecdsa_sha256(),
        issuer: ca_name.clone(),
        validity: validity(utc_time(NOT_BEFORE), generalized_time(NO_EXPIRATION)),
        subject: ca_name.clone(),
        subject_public_key_info: ca_spki,
        unique_ids: Vec::new(),
        extensions: Some(extensions(&[
            extension(&ID_CE_BASIC_CONSTRAINTS, true, &basic_constraints_ca()),
            extension(&ID_CE_KEY_USAGE, true, &key_usage_key_cert_sign()),
            extension(
                &ID_CE_SUBJECT_KEY_IDENTIFIER,
                false,
                &subject_key_identifier(&ca_key_id),
            ),
        ])),
    }
    .encode();
    let ca_certificate = sign(&ca_key, &ca_tbs);

    // The DC's server certificate.
    let server_key = p256_pkcs8();
    let server_tbs = Tbs {
        version: Some(version_v3()),
        serial_number: integer(2),
        signature: ecdsa_sha256(),
        issuer: ca_name,
        validity: validity(utc_time(NOT_BEFORE), generalized_time(NO_EXPIRATION)),
        subject: name(SERVER_NAME),
        subject_public_key_info: spki_of(&server_key),
        unique_ids: Vec::new(),
        extensions: Some(extensions(&[
            extension(
                &ID_CE_SUBJECT_ALT_NAME,
                false,
                &subject_alt_name_dns(&[SERVER_NAME]),
            ),
            extension(&ID_CE_KEY_USAGE, true, &key_usage_digital_signature()),
            extension(
                &ID_CE_EXT_KEY_USAGE,
                false,
                &ext_key_usage(&[&ID_KP_SERVER_AUTH]),
            ),
            extension(
                &ID_CE_AUTHORITY_KEY_IDENTIFIER,
                false,
                &authority_key_identifier(&ca_key_id),
            ),
        ])),
    }
    .encode();
    let server_certificate = sign(&ca_key, &server_tbs);
    TestPki {
        ca_certificate,
        server_certificate,
        server_key,
    }
}

/// The product's server configuration serving `pki`'s server certificate:
/// the production loader (every R50-12 check, at the current time), then
/// the R50-11 configuration.
/// Spec: docs/50 R50-11, R50-12, §5.1, §5.3.
pub fn server_config(pki: &TestPki) -> Arc<ServerConfig> {
    let now = ldap_front::startup::start_time().expect("clock");
    let credential = ldap_front::tls::DcCredential::from_der(
        pki.server_certificate.clone(),
        &pki.server_key,
        now,
    )
    .expect("the test certificate passes every R50-12 check");
    ldap_front::tls::server_config(credential.resolver()).expect("server configuration")
}

/// A TLS 1.3 client (rustls, aws-lc-rs provider, every TLS 1.3 suite and
/// the R50-11 groups) whose only trust anchor is `pki`'s CA, verified by
/// rustls' standard `WebPkiServerVerifier` (module documentation).
/// Spec: docs/50 R50-11, §9; RFC 8446 §4.4.2, §9.1.
pub fn client_config(pki: &TestPki) -> Arc<ClientConfig> {
    let provider = Arc::new(CryptoProvider {
        cipher_suites: vec![
            provider_lc::cipher_suite::TLS13_AES_128_GCM_SHA256,
            provider_lc::cipher_suite::TLS13_AES_256_GCM_SHA384,
        ],
        kx_groups: vec![
            provider_lc::kx_group::X25519MLKEM768,
            provider_lc::kx_group::X25519,
            provider_lc::kx_group::SECP256R1,
        ],
        ..provider_lc::default_provider()
    });
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(pki.ca_certificate.clone()))
        .expect("the test CA parses as a trust anchor");
    let verifier =
        WebPkiServerVerifier::builder_with_provider(Arc::new(roots), Arc::clone(&provider))
            .build()
            .expect("verifier");
    let config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("versions")
        .with_webpki_verifier(verifier)
        .with_no_client_auth();
    Arc::new(config)
}

/// The name the test client asks for — the server certificate's dNSName
/// (checked by the verifier).
pub fn server_name() -> ServerName<'static> {
    ServerName::try_from(SERVER_NAME).expect("name")
}
