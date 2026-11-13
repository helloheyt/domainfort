//! Test-only TLS material (docs/50 §9: "TLS client — rustls itself as
//! client") with **real X.509 certificates** (docs/questions/Q-320; the
//! follow-up of Q-285 item 1 → A-71).
//!
//! * tests/common/cert.rs builds, per run, a test CA and the DC's server
//!   certificate (subjectAltName dNSName `dc1.example.org`, ECDSA P-256 /
//!   SHA-256) from RFC 5280 structures, with fresh aws-lc-rs keys.
//! * The server side is the product's: the certificate and key go through
//!   the production loader `DcCredential::from_der` (every R50-12 check) and
//!   `ldap_front::tls::server_config`.
//! * The client side is rustls' **standard** verifier:
//!   `WebPkiServerVerifier::builder_with_provider` with a `RootCertStore`
//!   holding only the test CA — "Signed by a trusted RootCertStore CA, Not
//!   Expired, Valid for DNS entry" (docs.rs rustls 0.23.46
//!   `WebPkiServerVerifier::verify_server_cert`) — so a handshake proves
//!   the chain, the name, the validity and the CertificateVerify signature
//!   (RFC 8446 §4.4.2, §4.4.3). No custom certificate verifier remains.
//!
//! Sources: RFC 8446 §4.2.3, §4.4.2, §4.4.3, §9.1; RFC 5280 §4.1, §6;
//! docs/50 R50-11, R50-12, §9; docs.rs rustls 0.23.46 (`ClientConfig`,
//! `ConfigBuilder::with_webpki_verifier`, `client::WebPkiServerVerifier`,
//! `client::ServerCertVerifierBuilder::build`, `RootCertStore::{empty,
//! add}`, `ClientConnection`, `sign::CertifiedKey`, `sign::SingleCertAndKey`,
//! `crypto::aws_lc_rs`). Every value is made here.
#![allow(dead_code)] // each test binary uses a different subset

use crate::cert_support::{p256_pkcs8, test_pki, TestPki, SERVER_NAME};
use ldap_front::tls::DcCredential;
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::{aws_lc_rs as provider_lc, CryptoProvider};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::server::{ServerConfig, ServerConnection};
use rustls::sign::{CertifiedKey, SigningKey, SingleCertAndKey};
use rustls::{ClientConfig, ClientConnection, RootCertStore, SupportedCipherSuite};
use std::sync::Arc;

/// A fresh ECDSA P-384 key's PKCS#8 DER (for the R50-12 refusal).
pub fn p384_pkcs8() -> Vec<u8> {
    crate::cert_support::p384_pkcs8()
}

/// A fresh test PKI (tests/common/cert.rs).
pub fn pki() -> TestPki {
    test_pki()
}

/// A fresh ECDSA P-256 key's PKCS#8 DER.
pub fn p256_key() -> Vec<u8> {
    p256_pkcs8()
}

/// A rustls signing key for a PKCS#8 DER ECDSA key.
pub fn signing_key(pkcs8: &[u8]) -> Arc<dyn SigningKey> {
    provider_lc::sign::any_ecdsa_type(&PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8)))
        .expect("ECDSA key")
}

/// The DC credential of `pki`, through the production loader at the
/// current time.
pub fn credential(pki: &TestPki) -> DcCredential {
    let now = ldap_front::startup::start_time().expect("clock");
    DcCredential::from_der(pki.server_certificate.clone(), &pki.server_key, now)
        .expect("the test certificate passes every R50-12 check")
}

/// The product's server configuration serving `pki`'s server certificate.
pub fn server_config_for(pki: &TestPki) -> Arc<ServerConfig> {
    ldap_front::tls::server_config(credential(pki).resolver()).expect("server configuration")
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

/// rustls' standard verifier trusting only `root` (DER).
pub fn verifier(root: &[u8], provider: Arc<CryptoProvider>) -> Arc<WebPkiServerVerifier> {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(root.to_vec()))
        .expect("the test CA parses as a trust anchor");
    WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider)
        .build()
        .expect("verifier")
}

/// A TLS 1.3 client that trusts `pki`'s CA through the standard verifier
/// (module documentation); with `client_certificate`, it also holds the
/// client certificate it would send if asked.
pub fn client_config_with(
    provider: CryptoProvider,
    pki: &TestPki,
    client_certificate: bool,
) -> Arc<ClientConfig> {
    let provider = Arc::new(provider);
    let builder = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("versions")
        .with_webpki_verifier(verifier(&pki.ca.certificate, provider));
    let config = if client_certificate {
        let certified = CertifiedKey::new(
            vec![CertificateDer::from(pki.client_certificate.clone())],
            signing_key(&pki.client_key),
        );
        builder.with_client_cert_resolver(Arc::new(SingleCertAndKey::from(certified)))
    } else {
        builder.with_no_client_auth()
    };
    Arc::new(config)
}

/// The default test client: every TLS 1.3 suite, the R50-11 groups.
pub fn client_config(pki: &TestPki) -> Arc<ClientConfig> {
    client_config_with(
        client_provider(all_tls13_suites(), profile_groups()),
        pki,
        false,
    )
}

/// The name the test client asks for — the server certificate's dNSName.
pub fn server_name() -> ServerName<'static> {
    ServerName::try_from(SERVER_NAME).expect("name")
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

/// A new client connection for `config`, asking for [`server_name`].
pub fn client(config: &Arc<ClientConfig>) -> ClientConnection {
    ClientConnection::new(Arc::clone(config), server_name()).expect("client connection")
}

/// A new client connection for `config`, asking for `name`.
pub fn client_for(config: &Arc<ClientConfig>, name: &str) -> ClientConnection {
    let name = ServerName::try_from(name.to_owned()).expect("name");
    ClientConnection::new(Arc::clone(config), name).expect("client connection")
}

/// A new server connection for `config`.
pub fn server(config: &Arc<ServerConfig>) -> ServerConnection {
    ServerConnection::new(Arc::clone(config)).expect("server connection")
}
