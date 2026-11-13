//! Test-only TLS material (docs/50 §9: "TLS client — rustls itself as
//! client"), with a **test-only trust model** instead of an X.509
//! certificate.
//!
//! # Why no certificate (docs/questions/Q-285 item 1)
//!
//! R50-12 wants an ECDSA P-256 / SHA-256 certificate; the task allowed a
//! certificate generator only if no new crate is needed (none is approved)
//! and a hand-built DER certificate only if RFC 5280 is pinned (it is not —
//! tools/spec-pin/manifest.json has no RFC5280 entry). So the tests:
//!
//! * generate a fresh ECDSA P-256 key per run through aws-lc-rs
//!   (`EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, …)`);
//! * let the server present an **opaque placeholder** ([`PLACEHOLDER`]) in
//!   its Certificate message — RFC 8446 §4.4.2: `opaque cert_data<1..2^24-1>`
//!   — through `CertifiedKey::new` (which, unlike `with_single_cert` /
//!   `CertifiedKey::from_der`, does not parse it);
//! * let the client trust exactly that placeholder **and** the key: the
//!   [`PinnedKey`] verifier accepts the placeholder octets and then checks
//!   the server's CertificateVerify signature (RFC 8446 §4.4.3) with the
//!   pinned public key (aws-lc-rs `UnparsedPublicKey` with
//!   `ECDSA_P256_SHA256_ASN1`) — so the handshake still proves possession of
//!   the server's private key.
//!
//! Everything else in the server configuration is the product's
//! (`ldap_front::tls::server_config`: versions, suites, groups, tickets,
//! key log, client authentication). The production loader with a real
//! certificate (`DcCredential::from_der`, `with keys_match`) runs in
//! tests/tls_config.rs only with an operator-provided certificate
//! (`LDAP_FRONT_TEST_CERT_DIR`).
//!
//! Sources: RFC 8446 §4.2.3, §4.4.2, §4.4.3, §9.1; docs/50 R50-11, R50-12,
//! §9; docs.rs rustls 0.23.46 (`client::danger::ServerCertVerifier`,
//! `ClientConfig`, `ClientConnection`, `sign::CertifiedKey`,
//! `sign::SingleCertAndKey`, `crypto::aws_lc_rs`), aws-lc-rs 1.19.0
//! (`signature::{EcdsaKeyPair, KeyPair, UnparsedPublicKey,
//! ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_ASN1_SIGNING,
//! ECDSA_P384_SHA384_ASN1_SIGNING}`, `rand::SystemRandom`). Every value is
//! made here; no vector from any other implementation.
#![allow(dead_code)] // each test binary uses a different subset

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{
    EcdsaKeyPair, KeyPair, UnparsedPublicKey, ECDSA_P256_SHA256_ASN1,
    ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P384_SHA384_ASN1_SIGNING,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{aws_lc_rs as provider_lc, CryptoProvider};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::{ServerConfig, ServerConnection};
use rustls::sign::{CertifiedKey, SigningKey, SingleCertAndKey};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme, SupportedCipherSuite,
};
use std::sync::Arc;

/// The opaque octets the test server presents instead of a certificate
/// (module documentation). Not DER; never parsed.
pub const PLACEHOLDER: &[u8] = b"ldap-front test-only placeholder: not an X.509 certificate";

/// The opaque octets a test client offers as its "certificate".
pub const CLIENT_PLACEHOLDER: &[u8] = b"ldap-front test-only client placeholder";

/// A fresh ECDSA P-256 key: its PKCS#8 DER and its public point.
pub struct TestKey {
    pub pkcs8: Vec<u8>,
    pub public: Vec<u8>,
}

/// A fresh ECDSA P-256 key (aws-lc-rs).
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

/// A fresh ECDSA P-384 key's PKCS#8 DER (for the R50-12 refusal).
pub fn p384_pkcs8() -> Vec<u8> {
    EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, &SystemRandom::new())
        .expect("key generation")
        .as_ref()
        .to_vec()
}

/// A rustls signing key for a PKCS#8 DER ECDSA key.
pub fn signing_key(pkcs8: &[u8]) -> Arc<dyn SigningKey> {
    provider_lc::sign::any_ecdsa_type(&PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8)))
        .expect("ECDSA key")
}

/// The product's server configuration, serving [`PLACEHOLDER`] with `key`.
pub fn placeholder_server_config(key: &TestKey) -> Arc<ServerConfig> {
    let certified = CertifiedKey::new(
        vec![CertificateDer::from(PLACEHOLDER.to_vec())],
        signing_key(&key.pkcs8),
    );
    ldap_front::tls::server_config(Arc::new(SingleCertAndKey::from(certified)))
        .expect("server configuration")
}

/// Trusts exactly [`PLACEHOLDER`] signed by the pinned key (module
/// documentation).
#[derive(Debug)]
pub struct PinnedKey {
    public: Vec<u8>,
}

impl PinnedKey {
    pub fn new(key: &TestKey) -> Arc<PinnedKey> {
        Arc::new(PinnedKey {
            public: key.public.clone(),
        })
    }
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
    /// reconstructs, with ecdsa_secp256r1_sha256 (§4.2.3: the curve is the
    /// scheme's).
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

/// A client provider with the given suites and groups (the rest is
/// aws-lc-rs').
pub fn client_provider(
    suites: Vec<SupportedCipherSuite>,
    groups: Vec<&'static dyn rustls::crypto::SupportedKxGroup>,
) -> CryptoProvider {
    CryptoProvider {
        cipher_suites: suites,
        kx_groups: groups,
        ..provider_lc::default_provider()
    }
}

/// Every TLS 1.3 suite aws-lc-rs has, in an order that differs from the
/// server's (AES-128 first).
pub fn all_tls13_suites() -> Vec<SupportedCipherSuite> {
    vec![
        provider_lc::cipher_suite::TLS13_AES_128_GCM_SHA256,
        provider_lc::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
        provider_lc::cipher_suite::TLS13_AES_256_GCM_SHA384,
    ]
}

/// The R50-11 groups, client side.
pub fn profile_groups() -> Vec<&'static dyn rustls::crypto::SupportedKxGroup> {
    vec![
        provider_lc::kx_group::X25519MLKEM768,
        provider_lc::kx_group::X25519,
        provider_lc::kx_group::SECP256R1,
    ]
}

/// A TLS 1.3 client that trusts `key` (module documentation); with
/// `client_certificate`, it also holds a client "certificate" it would send
/// if asked.
pub fn client_config_with(
    provider: CryptoProvider,
    key: &TestKey,
    client_certificate: bool,
) -> Arc<ClientConfig> {
    let builder = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("versions")
        .dangerous()
        .with_custom_certificate_verifier(PinnedKey::new(key));
    let config = if client_certificate {
        let client_key = p256_key();
        let certified = CertifiedKey::new(
            vec![CertificateDer::from(CLIENT_PLACEHOLDER.to_vec())],
            signing_key(&client_key.pkcs8),
        );
        builder.with_client_cert_resolver(Arc::new(SingleCertAndKey::from(certified)))
    } else {
        builder.with_no_client_auth()
    };
    Arc::new(config)
}

/// The default test client: every TLS 1.3 suite, the R50-11 groups.
pub fn client_config(key: &TestKey) -> Arc<ClientConfig> {
    client_config_with(
        client_provider(all_tls13_suites(), profile_groups()),
        key,
        false,
    )
}

/// The name the test client asks for (not checked by [`PinnedKey`]).
pub fn server_name() -> ServerName<'static> {
    ServerName::try_from("dc1.example.org").expect("name")
}

/// Move every TLS octet `from` wants to write into `to`.
fn pump_client_to_server(client: &mut ClientConnection, server: &mut ServerConnection) -> bool {
    let mut octets = Vec::new();
    while client.wants_write() {
        client.write_tls(&mut octets).expect("write_tls");
    }
    let moved = !octets.is_empty();
    let mut input = octets.as_slice();
    while !input.is_empty() {
        if server.read_tls(&mut input).expect("read_tls") == 0 {
            break;
        }
    }
    moved
}

fn pump_server_to_client(server: &mut ServerConnection, client: &mut ClientConnection) -> bool {
    let mut octets = Vec::new();
    while server.wants_write() {
        server.write_tls(&mut octets).expect("write_tls");
    }
    let moved = !octets.is_empty();
    let mut input = octets.as_slice();
    while !input.is_empty() {
        if client.read_tls(&mut input).expect("read_tls") == 0 {
            break;
        }
    }
    moved
}

/// Run a handshake between `server` and `client` in memory (no socket).
/// `Err` names the side that failed.
pub fn handshake_in_memory(
    server: &mut ServerConnection,
    client: &mut ClientConnection,
) -> Result<(), String> {
    for _ in 0..32 {
        if pump_client_to_server(client, server) {
            server
                .process_new_packets()
                .map_err(|e| format!("server: {e}"))?;
        }
        if pump_server_to_client(server, client) {
            client
                .process_new_packets()
                .map_err(|e| format!("client: {e}"))?;
        }
        if !server.is_handshaking() && !client.is_handshaking() {
            return Ok(());
        }
    }
    Err(String::from("handshake did not finish"))
}

/// A new client connection for `config`.
pub fn client(config: &Arc<ClientConfig>) -> ClientConnection {
    ClientConnection::new(Arc::clone(config), server_name()).expect("client connection")
}

/// A new server connection for `config`.
pub fn server(config: &Arc<ServerConfig>) -> ServerConnection {
    ServerConnection::new(Arc::clone(config)).expect("server connection")
}
