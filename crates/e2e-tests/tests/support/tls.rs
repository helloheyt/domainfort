//! The TLS side of the harness: ldap-front's **test-only trust model**
//! (crates/ldap-front/tests/common/tls.rs, this project's code; decision
//! A-71, docs/questions/Q-285 item 1), reproduced here in the subset the
//! end-to-end tests need, so that a parallel change of ldap-front's own test
//! file (the placeholder certificate is being replaced) does not reach into
//! this crate.
//!
//! * a fresh ECDSA P-256 key per run (aws-lc-rs
//!   `EcdsaKeyPair::generate_pkcs8`);
//! * the server presents an opaque placeholder in its Certificate message
//!   (RFC 8446 §4.4.2: `opaque cert_data<1..2^24-1>`) through
//!   `CertifiedKey::new`, and **everything else is the product's
//!   configuration** (`ldap_front::tls::server_config`: TLS 1.3 only, the
//!   suites, groups, no tickets, no key log, no client authentication —
//!   docs/50 R50-11);
//! * the client (rustls itself, docs/50 §9) trusts exactly that placeholder
//!   and verifies the server's CertificateVerify signature (RFC 8446
//!   §4.4.3) with the pinned public key — the handshake still proves
//!   possession of the server's private key.
//!
//! Sources: RFC 8446 §4.2.3, §4.4.2, §4.4.3, §9.1; docs/50 R50-11, R50-12,
//! §9; crates/ldap-front/tests/common/tls.rs; docs.rs rustls 0.23.46 and
//! aws-lc-rs 1.19.0 (API pages only). Every value is made here.
#![allow(dead_code)]

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{
    EcdsaKeyPair, KeyPair, UnparsedPublicKey, ECDSA_P256_SHA256_ASN1,
    ECDSA_P256_SHA256_ASN1_SIGNING,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{aws_lc_rs as provider_lc, CryptoProvider};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::ServerConfig;
use rustls::sign::{CertifiedKey, SigningKey, SingleCertAndKey};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use std::sync::Arc;

/// The opaque octets the test server presents instead of a certificate.
/// Not DER; never parsed (module documentation).
pub const PLACEHOLDER: &[u8] = b"e2e-tests test-only placeholder: not an X.509 certificate";

/// A fresh ECDSA P-256 key: its PKCS#8 DER and its public point.
pub struct TestKey {
    pub pkcs8: Vec<u8>,
    pub public: Vec<u8>,
}

/// A fresh ECDSA P-256 key (aws-lc-rs). Spec: RFC 8446 §9.1
/// (ecdsa_secp256r1_sha256 is mandatory to implement); docs/50 R50-12.
pub fn p256_key() -> TestKey {
    let document =
        EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
            .expect("key generation");
    let pkcs8 = document.as_ref().to_vec();
    let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &pkcs8).expect("parse");
    TestKey {
        public: pair.public_key().as_ref().to_vec(),
        pkcs8,
    }
}

/// A rustls signing key for a PKCS#8 DER ECDSA key.
fn signing_key(pkcs8: &[u8]) -> Arc<dyn SigningKey> {
    provider_lc::sign::any_ecdsa_type(&PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8)))
        .expect("ECDSA key")
}

/// The product's server configuration (docs/50 R50-11), serving
/// [`PLACEHOLDER`] with `key`.
pub fn placeholder_server_config(key: &TestKey) -> Arc<ServerConfig> {
    let certified = CertifiedKey::new(
        vec![CertificateDer::from(PLACEHOLDER.to_vec())],
        signing_key(&key.pkcs8),
    );
    ldap_front::tls::server_config(Arc::new(SingleCertAndKey::from(certified)))
        .expect("server configuration")
}

/// Trusts exactly [`PLACEHOLDER`] signed by the pinned key.
#[derive(Debug)]
struct PinnedKey {
    public: Vec<u8>,
}

impl ServerCertVerifier for PinnedKey {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if end_entity.as_ref() == PLACEHOLDER && intermediates.is_empty() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General(String::from("TLS 1.2 is not used")))
    }

    /// RFC 8446 §4.4.3: the signature over the content the client
    /// reconstructs, with ecdsa_secp256r1_sha256 (§4.2.3).
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        _cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        if dss.scheme != SignatureScheme::ECDSA_NISTP256_SHA256 {
            return Err(rustls::Error::General(String::from("scheme")));
        }
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &self.public)
            .verify(message, dss.signature())
            .map(|()| HandshakeSignatureValid::assertion())
            .map_err(|_| rustls::Error::General(String::from("signature")))
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ECDSA_NISTP256_SHA256]
    }
}

/// A TLS 1.3 client (rustls, aws-lc-rs provider, every TLS 1.3 suite and
/// the R50-11 groups) that trusts `key` (module documentation).
/// Spec: docs/50 R50-11, §9; RFC 8446 §9.1.
pub fn client_config(key: &TestKey) -> Arc<ClientConfig> {
    let provider = CryptoProvider {
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
    };
    let config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedKey {
            public: key.public.clone(),
        }))
        .with_no_client_auth();
    Arc::new(config)
}

/// The name the test client asks for (not checked by the pinned-key
/// verifier).
pub fn server_name() -> ServerName<'static> {
    ServerName::try_from("dc1.example.org").expect("name")
}
