//! Tier 1 (docs/50 §9: in-process, no sockets): the TLS configuration of
//! docs/50 R50-11 as built, its policy check, handshakes between the
//! product's `ServerConfig` and a rustls client in memory, the
//! post-handshake check, and the R50-12 credential checks.
//!
//! Sources: docs/50 R50-11, R50-12, §4.3 step 4, §5.1, §5.3; RFC 8446 §2.3
//! (0-RTT), §4.2.7 (groups, preference order), §4.3.2 / §4.4.2 (no
//! CertificateRequest ⇒ no client certificate), §4.6.1 (tickets), §9.1
//! (MTI suites and groups), App. B.4; RFC 5929 §4.1 (single hash); RFC
//! 4513 §3.1.4, §3.3; RFC 5280 §4.1, §6. The handshakes serve a real
//! per-run certificate through the production loader and the clients use
//! rustls' standard verifier (tests/common/cert.rs, tests/common/tls.rs;
//! docs/questions/Q-320). Every value is made here.

#[path = "common/cert.rs"]
mod cert_support;

#[path = "common/tls.rs"]
mod tls_support;

use ldap_front::tls::{
    check_negotiated, check_policy, provider, server_config, signs_p256_only, CredentialError,
    DcCredential, NegotiationRefused, PolicyField, CIPHER_SUITES, KX_GROUPS, PROTOCOL_VERSIONS,
};
use rustls::compress::{CertCompressor, CompressionFailed, CompressionLevel};
use rustls::crypto::{aws_lc_rs as provider_lc, CryptoProvider};
use rustls::server::{ServerConfig, ServerSessionMemoryCache};
use rustls::{
    CertificateCompressionAlgorithm, CipherSuite, HandshakeKind, KeyLog, NamedGroup,
    ProtocolVersion,
};
use std::sync::Arc;
use tls_support::*;

/// The key-log labels rustls documents (`KeyLog::log`).
const LABELS: [&str; 7] = [
    "CLIENT_RANDOM",
    "CLIENT_EARLY_TRAFFIC_SECRET",
    "SERVER_HANDSHAKE_TRAFFIC_SECRET",
    "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
    "SERVER_TRAFFIC_SECRET_0",
    "CLIENT_TRAFFIC_SECRET_0",
    "EXPORTER_SECRET",
];

/// docs/50 R50-11, §5.1; RFC 8446 §9.1, App. B.4, §4.2.7, §2.3, §4.6.1:
/// every observable setting of the built configuration, field by field.
#[test]
fn the_server_configuration_is_the_r50_11_profile() {
    let pki = pki();
    let config = server_config_for(&pki);
    let provider = config.crypto_provider();
    let suites: Vec<CipherSuite> = provider.cipher_suites.iter().map(|s| s.suite()).collect();
    assert_eq!(
        suites,
        vec![
            CipherSuite::TLS13_AES_256_GCM_SHA384,
            CipherSuite::TLS13_AES_128_GCM_SHA256
        ]
    );
    assert!(provider.cipher_suites.iter().all(|s| s.tls13().is_some()));
    let groups: Vec<NamedGroup> = provider.kx_groups.iter().map(|g| g.name()).collect();
    assert_eq!(
        groups,
        vec![
            NamedGroup::X25519MLKEM768,
            NamedGroup::X25519,
            NamedGroup::secp256r1
        ]
    );
    assert_eq!(CIPHER_SUITES.to_vec(), suites);
    assert_eq!(KX_GROUPS.to_vec(), groups);
    let versions: Vec<ProtocolVersion> = PROTOCOL_VERSIONS.iter().map(|v| v.version).collect();
    assert_eq!(versions, vec![ProtocolVersion::TLSv1_3]);
    assert!(config.ignore_client_order);
    assert_eq!(config.max_fragment_size, None);
    assert_eq!(config.max_early_data_size, 0);
    assert_eq!(config.send_tls13_tickets, 0);
    assert_eq!(config.max_tls13_tickets, 0);
    assert!(!config.ticketer.enabled());
    assert!(!config.session_storage.can_cache());
    assert!(LABELS.iter().all(|label| !config.key_log.will_log(label)));
    assert!(!config.enable_secret_extraction);
    assert!(!config.send_half_rtt_data);
    assert!(config.alpn_protocols.is_empty());
    assert!(config.cert_compressors.is_empty());
    assert!(config.cert_decompressors.is_empty());
    assert_eq!(check_policy(&config), Ok(()));
}

#[derive(Debug)]
struct LogsEverything;

impl KeyLog for LogsEverything {
    fn log(&self, _label: &str, _client_random: &[u8], _secret: &[u8]) {}
    fn will_log(&self, _label: &str) -> bool {
        true
    }
}

#[derive(Debug)]
struct Compresses;

impl CertCompressor for Compresses {
    fn compress(
        &self,
        input: Vec<u8>,
        _level: CompressionLevel,
    ) -> Result<Vec<u8>, CompressionFailed> {
        Ok(input)
    }
    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        CertificateCompressionAlgorithm::Zlib
    }
}

static COMPRESSES: Compresses = Compresses;

/// A configuration built from `provider` the product's way otherwise
/// (serving the real test certificate through the production loader).
fn config_with_provider(provider: CryptoProvider, pki: &cert_support::TestPki) -> ServerConfig {
    ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(PROTOCOL_VERSIONS)
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(credential(pki).resolver())
}

/// docs/50 R50-11, §5.1: the policy check names every deviation (the check
/// `serve` runs before it serves).
#[test]
fn the_policy_check_refuses_every_deviation() {
    let pki = pki();
    let good = (*server_config_for(&pki)).clone();
    let refused = |mutate: &dyn Fn(&mut ServerConfig)| {
        let mut config = good.clone();
        mutate(&mut config);
        check_policy(&config).err()
    };
    assert_eq!(
        refused(&|c| c.ignore_client_order = false),
        Some(PolicyField::ClientOrder)
    );
    assert_eq!(
        refused(&|c| c.max_early_data_size = 16_384),
        Some(PolicyField::EarlyData)
    );
    assert_eq!(
        refused(&|c| c.send_tls13_tickets = 2),
        Some(PolicyField::Tickets)
    );
    assert_eq!(
        refused(&|c| c.max_tls13_tickets = 1),
        Some(PolicyField::Tickets)
    );
    assert_eq!(
        refused(&|c| c.ticketer = provider_lc::Ticketer::new().unwrap()),
        Some(PolicyField::Ticketer)
    );
    assert_eq!(
        refused(&|c| c.session_storage = ServerSessionMemoryCache::new(256)),
        Some(PolicyField::SessionStorage)
    );
    assert_eq!(
        refused(&|c| c.key_log = Arc::new(LogsEverything)),
        Some(PolicyField::KeyLog)
    );
    assert_eq!(
        refused(&|c| c.enable_secret_extraction = true),
        Some(PolicyField::SecretExtraction)
    );
    assert_eq!(
        refused(&|c| c.send_half_rtt_data = true),
        Some(PolicyField::HalfRttData)
    );
    assert_eq!(
        refused(&|c| c.alpn_protocols = vec![b"ldap".to_vec()]),
        Some(PolicyField::Alpn)
    );
    assert_eq!(
        refused(&|c| c.cert_compressors = vec![&COMPRESSES]),
        Some(PolicyField::CertificateCompression)
    );

    // The provider: another suite, a missing group, the groups reordered.
    let chacha = CryptoProvider {
        cipher_suites: vec![provider_lc::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256],
        ..provider()
    };
    assert_eq!(
        check_policy(&config_with_provider(chacha, &pki)),
        Err(PolicyField::CipherSuites)
    );
    let reordered = CryptoProvider {
        cipher_suites: vec![
            provider_lc::cipher_suite::TLS13_AES_128_GCM_SHA256,
            provider_lc::cipher_suite::TLS13_AES_256_GCM_SHA384,
        ],
        ..provider()
    };
    assert_eq!(
        check_policy(&config_with_provider(reordered, &pki)),
        Err(PolicyField::CipherSuites)
    );
    let fewer_groups = CryptoProvider {
        kx_groups: vec![provider_lc::kx_group::X25519],
        ..provider()
    };
    assert_eq!(
        check_policy(&config_with_provider(fewer_groups, &pki)),
        Err(PolicyField::KxGroups)
    );
    let groups_reordered = CryptoProvider {
        kx_groups: vec![
            provider_lc::kx_group::X25519,
            provider_lc::kx_group::X25519MLKEM768,
            provider_lc::kx_group::SECP256R1,
        ],
        ..provider()
    };
    assert_eq!(
        check_policy(&config_with_provider(groups_reordered, &pki)),
        Err(PolicyField::KxGroups)
    );
}

/// docs/50 §4.3 step 4, R50-11; RFC 8446 §4.2.7 (the client's
/// X25519MLKEM768 share is accepted), §9.1; `ignore_client_order`: a client
/// that prefers AES-128 still gets AES-256 (the server's first choice); the
/// post-handshake check accepts the result.
#[test]
fn a_tls13_handshake_negotiates_the_profile() {
    let pki = pki();
    let config = server_config_for(&pki);
    let mut server = server(&config);
    let mut client = client(&client_config(&pki));
    handshake_in_memory(&mut server, &mut client).unwrap();
    assert_eq!(server.protocol_version(), Some(ProtocolVersion::TLSv1_3));
    let negotiated = check_negotiated(&server).unwrap();
    assert_eq!(
        negotiated.cipher_suite,
        CipherSuite::TLS13_AES_256_GCM_SHA384
    );
    assert_eq!(negotiated.kx_group, NamedGroup::X25519MLKEM768);
    assert_eq!(server.handshake_kind(), Some(HandshakeKind::Full));
    assert!(server.peer_certificates().is_none());
}

/// RFC 8446 §4.2.7, §9.1: each of the other profile groups is accepted when
/// it is the client's only one; a group outside the profile (secp384r1) and
/// a suite outside it (ChaCha20-Poly1305) fail the handshake.
#[test]
fn groups_and_suites_outside_the_profile_fail() {
    let pki = pki();
    let config = server_config_for(&pki);
    for (group, name) in [
        (provider_lc::kx_group::X25519, NamedGroup::X25519),
        (provider_lc::kx_group::SECP256R1, NamedGroup::secp256r1),
    ] {
        let mut server = server(&config);
        let mut client = client(&client_config_with(
            client_provider(all_tls13_suites(), vec![group]),
            &pki,
            false,
        ));
        handshake_in_memory(&mut server, &mut client).unwrap();
        assert_eq!(check_negotiated(&server).unwrap().kx_group, name);
    }
    let mut server_a = server(&config);
    let mut p384_only = client(&client_config_with(
        client_provider(all_tls13_suites(), vec![provider_lc::kx_group::SECP384R1]),
        &pki,
        false,
    ));
    assert!(handshake_in_memory(&mut server_a, &mut p384_only).is_err());
    let mut server_b = server(&config);
    let mut chacha_only = client(&client_config_with(
        client_provider(
            vec![provider_lc::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256],
            profile_groups(),
        ),
        &pki,
        false,
    ));
    assert!(handshake_in_memory(&mut server_b, &mut chacha_only).is_err());
}

/// docs/50 R50-11 ("no client certificate"); RFC 8446 §4.3.2 / §4.4.2 ("The
/// client MUST send a Certificate message if and only if the server has
/// requested client authentication"): a client holding a certificate never
/// sends it — the handshake completes and the server has no peer
/// certificate (ignored, not refused).
#[test]
fn a_client_certificate_is_never_requested() {
    let pki = pki();
    let config = server_config_for(&pki);
    let mut server = server(&config);
    let mut client = client(&client_config_with(
        client_provider(all_tls13_suites(), profile_groups()),
        &pki,
        true,
    ));
    handshake_in_memory(&mut server, &mut client).unwrap();
    assert!(server.peer_certificates().is_none());
    assert!(check_negotiated(&server).is_ok());
}

/// docs/50 §5.1 (no tickets, no resumption; RFC 8446 §2.3 0-RTT off): the
/// same client connects twice with its resumption cache and early data
/// enabled — the second handshake is full again and no early data is
/// possible.
#[test]
fn no_resumption_and_no_early_data() {
    let pki = pki();
    let config = server_config_for(&pki);
    let mut client_config = (*client_config(&pki)).clone();
    client_config.enable_early_data = true;
    let client_config = Arc::new(client_config);
    for _ in 0..2 {
        let mut server = server(&config);
        let mut client = client(&client_config);
        assert!(client.early_data().is_none());
        handshake_in_memory(&mut server, &mut client).unwrap();
        assert_eq!(server.handshake_kind(), Some(HandshakeKind::Full));
        assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));
        assert!(server.received_resumption_data().is_none());
    }
}

/// docs/50 §4.3 step 4: nothing counts as negotiated before the handshake.
#[test]
fn the_check_refuses_an_unfinished_handshake() {
    let pki = pki();
    let config = server_config_for(&pki);
    let server = server(&config);
    assert_eq!(
        check_negotiated(&server),
        Err(NegotiationRefused::Handshaking)
    );
}

/// docs/50 R50-12 (ECDSA P-256 / SHA-256); RFC 5929 §4.1; RFC 8446 §9.1;
/// RFC 5280 §4.1: the credential checks on the key — with the real test
/// certificate, a P-384 key is refused, octets that are not a key are
/// refused, an empty certificate is refused, a P-256 key that is not the
/// certificate's fails the key/certificate match, and the right key passes.
/// (The certificate's own checks: tests/certificate_checks.rs.)
#[test]
fn the_credential_checks() {
    let pki = pki();
    let now = ldap_front::startup::start_time().unwrap();
    assert!(signs_p256_only(signing_key(&pki.server_key).as_ref()));
    assert!(!signs_p256_only(signing_key(&p384_pkcs8()).as_ref()));
    let certificate = || pki.server_certificate.clone();
    assert_eq!(
        DcCredential::from_der(certificate(), &p384_pkcs8(), now).err(),
        Some(CredentialError::NotP256)
    );
    assert_eq!(
        DcCredential::from_der(certificate(), b"not a key", now).err(),
        Some(CredentialError::KeyRejected)
    );
    assert_eq!(
        DcCredential::from_der(Vec::new(), &pki.server_key, now).err(),
        Some(CredentialError::EmptyCertificate)
    );
    assert_eq!(
        DcCredential::from_der(certificate(), &p256_key(), now).err(),
        Some(CredentialError::KeyMismatch)
    );
    assert!(DcCredential::from_der(certificate(), &pki.server_key, now).is_ok());
}

/// docs/50 R50-12, §5.3; RFC 5280 §4.1, §6; RFC 8446 §4.4.2, §4.4.3: the
/// real certificate, loaded by the production loader, is accepted by
/// rustls' **standard** verifier trusting only the test CA — chain, name,
/// validity and CertificateVerify — and the client sees exactly the one
/// certificate the file holds (no chain).
#[test]
fn the_standard_verifier_accepts_the_dc_certificate() {
    let pki = pki();
    let config = server_config_for(&pki);
    let mut server = server(&config);
    let mut client = client(&client_config(&pki));
    handshake_in_memory(&mut server, &mut client).unwrap();
    assert!(check_negotiated(&server).is_ok());
    let presented: Vec<Vec<u8>> = client
        .peer_certificates()
        .unwrap()
        .iter()
        .map(|c| c.as_ref().to_vec())
        .collect();
    assert_eq!(presented, vec![pki.server_certificate.clone()]);
}

/// The verifier is not a formality (docs.rs rustls 0.23.46
/// `WebPkiServerVerifier::verify_server_cert`: "Signed by a trusted
/// RootCertStore CA … Valid for DNS entry"): a client asking for another
/// name, and a client trusting another CA, both refuse the server.
#[test]
fn the_standard_verifier_refuses_another_name_or_another_ca() {
    let pki = pki();
    let config = server_config_for(&pki);
    let mut server_a = server(&config);
    let mut wrong_name = client_for(&client_config(&pki), "dc2.example.org");
    let refused = handshake_in_memory(&mut server_a, &mut wrong_name).unwrap_err();
    assert!(
        refused.starts_with("client: invalid peer certificate"),
        "{refused}"
    );

    let other = pki_with_other_ca(&pki);
    let mut server_b = server(&config);
    let mut wrong_ca = client(&client_config(&other));
    let refused = handshake_in_memory(&mut server_b, &mut wrong_ca).unwrap_err();
    assert!(
        refused.starts_with("client: invalid peer certificate"),
        "{refused}"
    );
}

/// `pki` with its CA replaced by a fresh one (the client then trusts a CA
/// that did not sign the server certificate).
fn pki_with_other_ca(pki: &cert_support::TestPki) -> cert_support::TestPki {
    cert_support::TestPki {
        ca: cert_support::ca(),
        server_certificate: pki.server_certificate.clone(),
        server_key: pki.server_key.clone(),
        client_certificate: pki.client_certificate.clone(),
        client_key: pki.client_key.clone(),
    }
}

/// docs/50 R50-12, §5.3 with an **operator-provided** certificate: the
/// production loader (`DcCredential::from_der`: every R50-12 check at the
/// current time) and the R50-11 configuration over it. Skipped unless
/// `LDAP_FRONT_TEST_CERT_DIR` names a directory holding `cert.der` (one DER
/// certificate, ECDSA P-256 / SHA-256) and `key.der` (its PKCS#8 DER key)
/// — test material the operator makes; nothing is committed. The default
/// run proves the same path with the per-run certificate above.
#[test]
fn an_operator_certificate_loads() {
    let Some(dir) = std::env::var_os("LDAP_FRONT_TEST_CERT_DIR") else {
        println!("skipped: LDAP_FRONT_TEST_CERT_DIR not set");
        return;
    };
    let dir = std::path::PathBuf::from(dir);
    let certificate = std::fs::read(dir.join("cert.der")).unwrap();
    let key = zeroize::Zeroizing::new(std::fs::read(dir.join("key.der")).unwrap());
    let now = ldap_front::startup::start_time().unwrap();
    let credential = DcCredential::from_der(certificate, &key, now).unwrap();
    let config = server_config(credential.resolver()).unwrap();
    assert_eq!(check_policy(&config), Ok(()));
}
