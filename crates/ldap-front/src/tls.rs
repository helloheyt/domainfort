//! TLS: the rustls `ServerConfig` exactly as docs/50 R50-11 / §5.1 sets it,
//! the DC certificate and key of R50-12, and the check of the negotiated
//! parameters after every handshake (§4.3 step 4).
//!
//! # The configuration (docs/50 §5.1, R50-11)
//!
//! | setting | value | anchor |
//! |---|---|---|
//! | provider | aws-lc-rs, passed with `builder_with_provider` — never `install_default` ("at most once", process-wide), never `builder_with_protocol_versions` (documented to panic) | docs/50 §5.1; docs.rs rustls 0.23.46 `ServerConfig`, `CryptoProvider` |
//! | versions | TLS 1.3 only ([`PROTOCOL_VERSIONS`]) through `with_protocol_versions` (a `Result`) — the builder, not the absent `tls12` feature, is what excludes 1.2 ("other crates in your dependency graph could re-enable it") | docs/50 §5.1; docs/02 §4; rustls crate root (`tls12`) |
//! | cipher suites | `TLS13_AES_256_GCM_SHA384`, `TLS13_AES_128_GCM_SHA256` — the provider's list reduced to these ([`CIPHER_SUITES`]), server order (`ignore_client_order`) | RFC 8446 §9.1 (TLS_AES_128_GCM_SHA256 MUST; TLS_AES_256_GCM_SHA384 SHOULD), App. B.4 |
//! | kx groups | `X25519MLKEM768`, `X25519`, `SECP256R1`, in that order ([`KX_GROUPS`]) | RFC 8446 §4.2.7 (preference order), §9.1 (secp256r1 MUST, X25519 SHOULD); docs/38 §3 (hybrid key establishment) |
//! | client authentication | none (`with_no_client_auth`: no CertificateRequest is ever sent, so a client never sends a certificate) | docs/50 §5.1; RFC 8446 §4.3.2, §4.4.2; docs/49 §4.4 ([MS-ADTS] 5.1.1.2: no client certificate in phase 1) |
//! | 0-RTT | `max_early_data_size = 0` | RFC 8446 §2.3 ("There are no guarantees of non-replay between connections") |
//! | resumption | `send_tls13_tickets = 0`, `max_tls13_tickets = 0`, a ticketer that never produces tickets, `NoServerSessionStorage` | docs/50 §5.1; D104; RFC 8446 §4.6.1 |
//! | key log | `NoKeyLog` (never `KeyLogFile`, which reads SSLKEYLOGFILE) | docs/CLEAN-ROOM.md; docs/21 D95 |
//! | secret extraction | `enable_secret_extraction = false` | docs/50 §5.1 |
//! | 0.5-RTT data | `send_half_rtt_data = false` | docs/50 §5.1 |
//! | ALPN | empty | docs/50 §5.1 |
//! | certificate compression | no compressors, no decompressors, cache disabled | docs/50 §5.1; D104; D99 |
//! | fragment size | default | docs/50 §5.1 |
//!
//! [`check_policy`] verifies every observable field of a built
//! configuration; [`serve`](crate::serve) refuses to start with one that
//! fails it. The versions and the client-authentication choice are private
//! to rustls; they are enforced by construction and checked again on every
//! connection by [`check_negotiated`].
//!
//! # The DC certificate and key (docs/50 R50-12, §5.3; Q-221 → A-57 (A))
//!
//! Operator-supplied DER files; the key file root-owned 0400 and read as
//! root before the privilege drop (crate::startup). [`DcCredential::from_der`]:
//!
//! * the certificate file holds exactly one DER X.509 v3 certificate (no
//!   chain, nothing after it), read by crates/parse-x509 (RFC 5280 §4.1;
//!   strict DER, bounded);
//! * (a) its outer `signatureAlgorithm` is identical to
//!   `tbsCertificate.signature` (RFC 5280 §4.1.1.2: "This field MUST
//!   contain the same algorithm identifier as the signature field in the
//!   sequence tbsCertificate"; §4.1.2.3);
//! * (b) that algorithm is ecdsa-with-SHA256 and the subjectPublicKeyInfo
//!   algorithm is id-ecPublicKey on secp256r1 — compared with
//!   rustls-pki-types' documented constants `alg_id::ECDSA_SHA256` and
//!   `alg_id::ECDSA_P256` ("The outer sequence encoding is not included, so
//!   this is the DER encoding of an OID for algorithm plus the parameters
//!   value" — docs.rs rustls-pki-types 1.16.0 `AlgorithmIdentifier`), i.e.
//!   with the AlgorithmIdentifier SEQUENCE's **contents**. This project
//!   writes no ECDSA object identifier itself (RFC 5480 / RFC 5758 are not
//!   in specs/SOURCES.md);
//! * (d) the validity period contains the start-up time, inclusive (RFC
//!   5280 §4.1.2.5) — an expired or not-yet-valid certificate stops the
//!   start (docs/questions/Q-320 item 4);
//! * the key is a PKCS#8 DER ECDSA key, parsed by rustls' aws-lc-rs provider
//!   from a **borrowed** slice (`crypto::aws_lc_rs::sign::any_ecdsa_type(&
//!   PrivateKeyDer)`) — so no copy of the key octets is handed to anyone,
//!   and the caller's buffer is wiped right after (task P11: "zeroize the
//!   key bytes after building the rustls config");
//! * the key must sign `ecdsa_secp256r1_sha256` and nothing else (R50-12:
//!   ECDSA P-256 / SHA-256, a single-hash algorithm, RFC 5929 §4.1; RFC 8446
//!   §9.1 MTI);
//! * (c) `CertifiedKey::keys_match` must succeed: "a comparison of
//!   SubjectPublicKeyInfo bytes" between the key and the certificate — the
//!   same check `with_single_cert` documents ("fails if … the
//!   SubjectPublicKeyInfo from the private key does not match the public key
//!   for the end-entity certificate"). `with_single_cert` itself is not used
//!   because it takes the key by value (`PrivateKeyDer<'static>`), leaving a
//!   copy of the key octets whose wiping the documentation does not state;
//!   the resolver is rustls' `SingleCertAndKey` ("always resolves to the same
//!   certificate and key") — the same behaviour.
//!
//! The signatureAlgorithm is the field RFC 5929 §4.1's hash rule reads for
//! tls-server-end-point ("use the hash function associated with the
//! certificate's signatureAlgorithm" when it "uses a single hash
//! function"); with (a) and (b) the DC certificate always names exactly
//! one hash, SHA-256. The binding value is dird's to compute (R50-13) and
//! channel binding is not in phase 1 (P-13, Q-162); the check stands on its
//! own as docs/50 §5.3's algorithm constraint. The certificate's signature
//! itself is the relying party's
//! to verify (the clients, against the anchor of their join, docs/50 §5.3);
//! the front verifies none. Extensions are read but not interpreted
//! (docs/questions/Q-320 item 5). Follow-up of Q-285 items 1 and 3 (A-71).
//!
//! Spec: docs/50 R50-11, R50-12, R50-13, §4.3, §5.1-§5.4; RFC 8446 §2.3,
//! §4.2.1, §4.2.7, §4.3.2, §4.4.2, §4.6.1, §9.1, App. B.4; RFC 5929 §4.1;
//! RFC 5280 §4.1, §4.1.1.2, §4.1.2.3, §4.1.2.5, §4.1.2.7;
//! RFC 4513 §3.1.4, §3.3; docs.rs rustls 0.23.46 (`ServerConfig`,
//! `ConfigBuilder`, `CryptoProvider`, `crypto::aws_lc_rs`, `sign::CertifiedKey`,
//! `sign::SingleCertAndKey`, `sign::SigningKey`, `server::ProducesTickets`,
//! `server::StoresServerSessions`, `server::NoServerSessionStorage`,
//! `KeyLog`, `NoKeyLog`, `compress::CompressionCache`, `ServerConnection`,
//! `HandshakeKind`); docs.rs rustls-pki-types 1.16.0 (`alg_id::ECDSA_SHA256`,
//! `alg_id::ECDSA_P256`, `AlgorithmIdentifier`, `UnixTime`).

use core::fmt;
use rustls::compress::CompressionCache;
use rustls::crypto::{aws_lc_rs, CryptoProvider};
use rustls::pki_types::{alg_id, CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, UnixTime};
use rustls::server::{
    NoServerSessionStorage, ProducesTickets, ResolvesServerCert, ServerConfig, ServerConnection,
};
use rustls::sign::{CertifiedKey, SingleCertAndKey};
use rustls::{
    CipherSuite, HandshakeKind, NamedGroup, NoKeyLog, ProtocolVersion, SignatureAlgorithm,
    SignatureScheme, SupportedProtocolVersion,
};
use std::sync::Arc;

/// The protocol versions: TLS 1.3 only in phase 1.
/// Spec: docs/50 R50-11, §5.1 ("TLS 1.3 only in phase 1 (native face)");
/// docs/02 §4; docs/49 §4.1.
pub const PROTOCOL_VERSIONS: &[&SupportedProtocolVersion] = &[&rustls::version::TLS13];

/// The cipher suites, in the server's order of preference.
/// Spec: docs/50 R50-11, §5.1 (AES-GCM); RFC 8446 §9.1, App. B.4
/// (TLS_AES_128_GCM_SHA256 {0x13,0x01}, TLS_AES_256_GCM_SHA384 {0x13,0x02}).
pub const CIPHER_SUITES: [CipherSuite; 2] = [
    CipherSuite::TLS13_AES_256_GCM_SHA384,
    CipherSuite::TLS13_AES_128_GCM_SHA256,
];

/// The key-exchange groups, in the server's order of preference.
/// Spec: docs/50 R50-11 ("X25519MLKEM768 → X25519 → SECP256R1"), §5.1;
/// RFC 8446 §4.2.7 ("ordered from most preferred to least preferred"), §9.1;
/// docs/38 §3.
pub const KX_GROUPS: [NamedGroup; 3] = [
    NamedGroup::X25519MLKEM768,
    NamedGroup::X25519,
    NamedGroup::secp256r1,
];

/// The one signature scheme the DC key may use.
/// Spec: docs/50 R50-12 (ECDSA P-256 / SHA-256); RFC 8446 §9.1
/// (ecdsa_secp256r1_sha256 MTI); RFC 5929 §4.1 (a single hash function).
pub const DC_SIGNATURE_SCHEME: SignatureScheme = SignatureScheme::ECDSA_NISTP256_SHA256;

/// The key-log labels rustls documents (`KeyLog::log`); the configured key
/// log must decline every one.
/// Spec: docs/CLEAN-ROOM.md; docs.rs rustls 0.23.46 `KeyLog::log`.
const KEY_LOG_LABELS: [&str; 7] = [
    "CLIENT_RANDOM",
    "CLIENT_EARLY_TRAFFIC_SECRET",
    "SERVER_HANDSHAKE_TRAFFIC_SECRET",
    "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
    "SERVER_TRAFFIC_SECRET_0",
    "CLIENT_TRAFFIC_SECRET_0",
    "EXPORTER_SECRET",
];

/// A ticketer that never produces or accepts tickets: "Should return false
/// if this is a dummy implementation: the server will not send the
/// SessionTicket extension and will not call the other functions".
/// Spec: docs/50 §5.1 (no tickets, no resumption); docs.rs rustls 0.23.46
/// `server::ProducesTickets`.
#[derive(Debug)]
struct NoTickets;

impl ProducesTickets for NoTickets {
    fn enabled(&self) -> bool {
        false
    }

    fn lifetime(&self) -> u32 {
        0
    }

    fn encrypt(&self, _plain: &[u8]) -> Option<Vec<u8>> {
        None
    }

    fn decrypt(&self, _cipher: &[u8]) -> Option<Vec<u8>> {
        None
    }
}

/// The aws-lc-rs provider reduced to [`CIPHER_SUITES`] and [`KX_GROUPS`]
/// (the other fields — signature verification, randomness, key loading —
/// are the provider's own).
/// Spec: docs/50 §5.1 ("through a reduced `CryptoProvider.cipher_suites`");
/// docs.rs rustls 0.23.46 `CryptoProvider` ("Everything in it can be
/// overridden at runtime by replacing field values"), `crypto::aws_lc_rs::
/// {cipher_suite, kx_group, default_provider}`.
#[must_use]
pub fn provider() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: vec![
            aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384,
            aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256,
        ],
        kx_groups: vec![
            aws_lc_rs::kx_group::X25519MLKEM768,
            aws_lc_rs::kx_group::X25519,
            aws_lc_rs::kx_group::SECP256R1,
        ],
        ..aws_lc_rs::default_provider()
    }
}

/// Why a TLS configuration could not be built or is refused. Carries no key
/// material and no file content.
/// Spec: docs/50 §5.1, §7.5 (fail closed), §8.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsConfigError {
    /// The builder refused the protocol versions for the provider.
    Versions,
    /// A setting differs from docs/50 R50-11 (which one is named).
    Policy(PolicyField),
}

/// The setting [`check_policy`] found outside docs/50 R50-11.
/// Spec: docs/50 §5.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyField {
    /// The cipher suites are not exactly [`CIPHER_SUITES`], in order.
    CipherSuites,
    /// The key-exchange groups are not exactly [`KX_GROUPS`], in order.
    KxGroups,
    /// The client's order would be followed.
    ClientOrder,
    /// Early data is accepted.
    EarlyData,
    /// Tickets would be sent.
    Tickets,
    /// The ticketer would produce tickets.
    Ticketer,
    /// The session store can cache sessions.
    SessionStorage,
    /// The key log would log a secret.
    KeyLog,
    /// Secret extraction is enabled.
    SecretExtraction,
    /// 0.5-RTT data would be sent.
    HalfRttData,
    /// ALPN protocols are configured.
    Alpn,
    /// Certificate compression or decompression is configured.
    CertificateCompression,
}

impl fmt::Display for TlsConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TlsConfigError::Versions => f.write_str("TLS protocol versions refused by the builder"),
            TlsConfigError::Policy(field) => {
                write!(f, "TLS configuration outside the profile: {field:?}")
            }
        }
    }
}

impl std::error::Error for TlsConfigError {}

/// The server configuration of docs/50 R50-11 (module documentation),
/// serving the certificate and key `resolver` returns.
///
/// # Errors
/// [`TlsConfigError`].
///
/// Spec: docs/50 R50-11, §5.1; docs.rs rustls 0.23.46 `ServerConfig::
/// builder_with_provider`, `ConfigBuilder::{with_protocol_versions,
/// with_no_client_auth, with_cert_resolver}`.
pub fn server_config(
    resolver: Arc<dyn ResolvesServerCert>,
) -> Result<Arc<ServerConfig>, TlsConfigError> {
    let mut config = ServerConfig::builder_with_provider(Arc::new(provider()))
        .with_protocol_versions(PROTOCOL_VERSIONS)
        .map_err(|_| TlsConfigError::Versions)?
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    config.ignore_client_order = true;
    config.max_fragment_size = None;
    config.session_storage = Arc::new(NoServerSessionStorage {});
    config.ticketer = Arc::new(NoTickets);
    config.alpn_protocols = Vec::new();
    config.key_log = Arc::new(NoKeyLog);
    config.enable_secret_extraction = false;
    config.max_early_data_size = 0;
    config.send_half_rtt_data = false;
    config.send_tls13_tickets = 0;
    config.max_tls13_tickets = 0;
    config.cert_compressors = Vec::new();
    config.cert_compression_cache = Arc::new(CompressionCache::Disabled);
    config.cert_decompressors = Vec::new();
    check_policy(&config).map_err(TlsConfigError::Policy)?;
    Ok(Arc::new(config))
}

/// Verify every observable field of `config` against docs/50 R50-11
/// (module documentation).
///
/// # Errors
/// The first [`PolicyField`] that differs.
///
/// Spec: docs/50 R50-11, §5.1.
pub fn check_policy(config: &ServerConfig) -> Result<(), PolicyField> {
    let provider = config.crypto_provider();
    let suites_ok = provider.cipher_suites.len() == CIPHER_SUITES.len()
        && provider
            .cipher_suites
            .iter()
            .zip(CIPHER_SUITES.iter())
            .all(|(suite, wanted)| suite.tls13().is_some() && suite.suite() == *wanted);
    if !suites_ok {
        return Err(PolicyField::CipherSuites);
    }
    let groups_ok = provider.kx_groups.len() == KX_GROUPS.len()
        && provider
            .kx_groups
            .iter()
            .zip(KX_GROUPS.iter())
            .all(|(group, wanted)| group.name() == *wanted);
    if !groups_ok {
        return Err(PolicyField::KxGroups);
    }
    let checks = [
        (config.ignore_client_order, PolicyField::ClientOrder),
        (config.max_early_data_size == 0, PolicyField::EarlyData),
        (
            config.send_tls13_tickets == 0 && config.max_tls13_tickets == 0,
            PolicyField::Tickets,
        ),
        (!config.ticketer.enabled(), PolicyField::Ticketer),
        (
            !config.session_storage.can_cache(),
            PolicyField::SessionStorage,
        ),
        (
            KEY_LOG_LABELS
                .iter()
                .all(|label| !config.key_log.will_log(label)),
            PolicyField::KeyLog,
        ),
        (
            !config.enable_secret_extraction,
            PolicyField::SecretExtraction,
        ),
        (!config.send_half_rtt_data, PolicyField::HalfRttData),
        (config.alpn_protocols.is_empty(), PolicyField::Alpn),
        (
            config.cert_compressors.is_empty() && config.cert_decompressors.is_empty(),
            PolicyField::CertificateCompression,
        ),
    ];
    match checks.iter().find(|(ok, _)| !ok) {
        Some((_, field)) => Err(*field),
        None => Ok(()),
    }
}

/// Why the negotiated parameters were refused after a handshake.
/// Spec: docs/50 §4.3 step 4; RFC 4513 §3.1.4, §3.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NegotiationRefused {
    /// The handshake is not complete.
    Handshaking,
    /// The version is not TLS 1.3.
    Version,
    /// The cipher suite is not one of [`CIPHER_SUITES`].
    CipherSuite,
    /// The key-exchange group is not one of [`KX_GROUPS`].
    KxGroup,
    /// The handshake was a resumption.
    Resumed,
    /// The client presented a certificate.
    ClientCertificate,
}

/// What a completed handshake negotiated (no secret; for the counters).
/// Spec: docs/50 §5.1 ("check after the handshake").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Negotiated {
    /// The cipher suite.
    pub cipher_suite: CipherSuite,
    /// The key-exchange group.
    pub kx_group: NamedGroup,
}

/// Check what `connection` negotiated: TLS 1.3, a suite of
/// [`CIPHER_SUITES`], a group of [`KX_GROUPS`], a full handshake, no client
/// certificate. Only then may the front treat the session as protected
/// (docs/49 §4.3: "`encrypted` only after TLS completed with an AEAD
/// suite").
///
/// # Errors
/// [`NegotiationRefused`] — the front closes the connection.
///
/// Spec: docs/50 §4.3 step 4, §5.1; docs/49 §4.3; RFC 4513 §3.1.4 ("both
/// parties are to each independently decide whether or not to continue
/// based on local policy and the security level achieved"), §3.3 ("both
/// protocol peers should independently verify that the security services
/// provided by the negotiated ciphersuite are adequate"); RFC 8446 §4.2.1.
pub fn check_negotiated(connection: &ServerConnection) -> Result<Negotiated, NegotiationRefused> {
    if connection.is_handshaking() {
        return Err(NegotiationRefused::Handshaking);
    }
    if connection.protocol_version() != Some(ProtocolVersion::TLSv1_3) {
        return Err(NegotiationRefused::Version);
    }
    let cipher_suite = match connection.negotiated_cipher_suite() {
        Some(suite) if suite.tls13().is_some() && CIPHER_SUITES.contains(&suite.suite()) => {
            suite.suite()
        }
        _ => return Err(NegotiationRefused::CipherSuite),
    };
    let kx_group = match connection.negotiated_key_exchange_group() {
        Some(group) if KX_GROUPS.contains(&group.name()) => group.name(),
        _ => return Err(NegotiationRefused::KxGroup),
    };
    match connection.handshake_kind() {
        Some(HandshakeKind::Full | HandshakeKind::FullWithHelloRetryRequest) => {}
        _ => return Err(NegotiationRefused::Resumed),
    }
    if connection.peer_certificates().is_some() {
        return Err(NegotiationRefused::ClientCertificate);
    }
    Ok(Negotiated {
        cipher_suite,
        kx_group,
    })
}

/// Why the DC certificate and key were refused. Carries no key material and
/// no file content.
/// Spec: docs/50 R50-12, §7.5, §8.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialError {
    /// The certificate file is empty.
    EmptyCertificate,
    /// The certificate file is not exactly one DER X.509 v3 certificate
    /// (the field and rule are named; no octet of the file).
    /// Spec: RFC 5280 4.1.
    CertificateMalformed(parse_x509::Error),
    /// The outer signatureAlgorithm differs from tbsCertificate.signature.
    /// Spec: RFC 5280 4.1.1.2, 4.1.2.3.
    SignatureAlgorithmMismatch,
    /// The certificate is not signed with ecdsa-with-SHA256.
    /// Spec: docs/50 R50-12, §5.3; RFC 5929 4.1.
    NotEcdsaSha256,
    /// The certificate's public key is not an EC key on P-256.
    /// Spec: docs/50 R50-12; RFC 5280 4.1.2.7.
    PublicKeyNotP256,
    /// The key is not a PKCS#8 DER ECDSA key the provider accepts.
    KeyRejected,
    /// The key is not ECDSA P-256 / SHA-256.
    NotP256,
    /// The key does not match the certificate's public key (or the
    /// certificate's public key could not be read).
    KeyMismatch,
    /// The start-up time is before the certificate's notBefore.
    /// Spec: RFC 5280 4.1.2.5.
    NotYetValid,
    /// The start-up time is after the certificate's notAfter.
    /// Spec: RFC 5280 4.1.2.5.
    Expired,
}

impl fmt::Display for CredentialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CredentialError::EmptyCertificate => f.write_str("DC certificate file is empty"),
            CredentialError::CertificateMalformed(error) => write!(
                f,
                "DC certificate file is not one DER X.509 v3 certificate: {error}"
            ),
            CredentialError::SignatureAlgorithmMismatch => f.write_str(
                "DC certificate signatureAlgorithm differs from tbsCertificate.signature",
            ),
            CredentialError::NotEcdsaSha256 => {
                f.write_str("DC certificate is not signed with ecdsa-with-SHA256")
            }
            CredentialError::PublicKeyNotP256 => {
                f.write_str("DC certificate public key is not EC P-256")
            }
            CredentialError::KeyRejected => f.write_str("DC key is not a PKCS#8 DER ECDSA key"),
            CredentialError::NotP256 => f.write_str("DC key is not ECDSA P-256 / SHA-256"),
            CredentialError::KeyMismatch => f.write_str("DC key does not match the certificate"),
            CredentialError::NotYetValid => {
                f.write_str("DC certificate is not yet valid (notBefore is after the start time)")
            }
            CredentialError::Expired => {
                f.write_str("DC certificate has expired (notAfter is before the start time)")
            }
        }
    }
}

impl std::error::Error for CredentialError {}

/// The DC certificate and its checked signing key (module documentation).
/// Spec: docs/50 R50-12, §5.3.
#[derive(Debug, Clone)]
pub struct DcCredential {
    certified: Arc<CertifiedKey>,
}

impl DcCredential {
    /// Check and package the operator's DER certificate and PKCS#8 DER key
    /// (module documentation), at the start-up time `now`. `key` is only
    /// borrowed; the caller wipes it. The checks run in this order: the
    /// certificate's structure, (a), (b), the key, its curve, (c), (d).
    ///
    /// # Errors
    /// [`CredentialError`].
    ///
    /// Spec: docs/50 R50-12, §5.3; RFC 5280 §4.1, §4.1.1.2, §4.1.2.3,
    /// §4.1.2.5, §4.1.2.7; RFC 5929 §4.1; RFC 8446 §9.1; docs.rs rustls
    /// 0.23.46 `crypto::aws_lc_rs::sign::any_ecdsa_type`,
    /// `sign::SigningKey::{algorithm, choose_scheme}`, `sign::CertifiedKey::
    /// {new, keys_match}`; docs.rs rustls-pki-types 1.16.0 `alg_id`,
    /// `UnixTime::as_secs`.
    pub fn from_der(
        certificate: Vec<u8>,
        key: &[u8],
        now: UnixTime,
    ) -> Result<DcCredential, CredentialError> {
        if certificate.is_empty() {
            return Err(CredentialError::EmptyCertificate);
        }
        let validity = {
            let parsed = parse_x509::parse_certificate(&certificate)
                .map_err(CredentialError::CertificateMalformed)?;
            check_algorithms(&parsed)?;
            parsed.tbs_certificate.validity
        };
        let signing = {
            let borrowed = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key));
            aws_lc_rs::sign::any_ecdsa_type(&borrowed).map_err(|_| CredentialError::KeyRejected)?
        };
        if !signs_p256_only(signing.as_ref()) {
            return Err(CredentialError::NotP256);
        }
        let certified = CertifiedKey::new(vec![CertificateDer::from(certificate)], signing);
        certified
            .keys_match()
            .map_err(|_| CredentialError::KeyMismatch)?;
        check_validity(&validity, now)?;
        Ok(DcCredential {
            certified: Arc::new(certified),
        })
    }

    /// The resolver that always serves this certificate and key.
    /// Spec: docs.rs rustls 0.23.46 `sign::SingleCertAndKey`.
    #[must_use]
    pub fn resolver(&self) -> Arc<dyn ResolvesServerCert> {
        Arc::new(SingleCertAndKey::from(Arc::clone(&self.certified)))
    }
}

/// Checks (a) and (b) of the module documentation on a parsed certificate.
///
/// # Errors
/// [`CredentialError::SignatureAlgorithmMismatch`],
/// [`CredentialError::NotEcdsaSha256`], [`CredentialError::PublicKeyNotP256`].
///
/// Spec: RFC 5280 §4.1.1.2 ("MUST contain the same algorithm identifier as
/// the signature field in the sequence tbsCertificate"), §4.1.2.3,
/// §4.1.2.7; docs/50 R50-12, §5.3; docs.rs rustls-pki-types 1.16.0
/// `alg_id::ECDSA_SHA256` ("AlgorithmIdentifier for ecdsa-with-SHA256"),
/// `alg_id::ECDSA_P256` ("AlgorithmIdentifier for id-ecPublicKey with named
/// curve secp256r1"), `AlgorithmIdentifier` ("The outer sequence encoding is
/// not included").
pub fn check_algorithms(certificate: &parse_x509::Certificate<'_>) -> Result<(), CredentialError> {
    let tbs = &certificate.tbs_certificate;
    // (a) The same AlgorithmIdentifier, parameters included: DER gives one
    // encoding per value (X.690 clause 10), so the octets are compared.
    if certificate.signature_algorithm.encoding != tbs.signature.encoding {
        return Err(CredentialError::SignatureAlgorithmMismatch);
    }
    // (b) The constants hold the SEQUENCE's contents, so the contents are
    // compared.
    if tbs.signature.contents != alg_id::ECDSA_SHA256.as_ref() {
        return Err(CredentialError::NotEcdsaSha256);
    }
    if tbs.subject_public_key_info.algorithm.contents != alg_id::ECDSA_P256.as_ref() {
        return Err(CredentialError::PublicKeyNotP256);
    }
    Ok(())
}

/// Check (d): `now` lies in the validity period, both ends included.
///
/// # Errors
/// [`CredentialError::NotYetValid`], [`CredentialError::Expired`].
///
/// Spec: RFC 5280 §4.1.2.5 ("the period of time from notBefore through
/// notAfter, inclusive"); docs/questions/Q-320 item 4 (fail closed at
/// start).
pub fn check_validity(
    validity: &parse_x509::Validity,
    now: UnixTime,
) -> Result<(), CredentialError> {
    // A time past i64::MAX seconds is after every representable notAfter.
    let now = i64::try_from(now.as_secs()).unwrap_or(i64::MAX);
    if now < validity.not_before.unix_seconds() {
        return Err(CredentialError::NotYetValid);
    }
    if now > validity.not_after.unix_seconds() {
        return Err(CredentialError::Expired);
    }
    Ok(())
}

/// Whether `key` is an ECDSA key that signs [`DC_SIGNATURE_SCHEME`] and no
/// other ECDSA scheme (the curve is bound to the scheme in TLS 1.3 — docs.rs
/// rustls 0.23.46 `ServerCertVerifier::verify_tls13_signature`: "the tighter
/// ECDSA SignatureScheme semantics").
/// Spec: docs/50 R50-12; RFC 8446 §4.2.3, §9.1.
#[must_use]
pub fn signs_p256_only(key: &dyn rustls::sign::SigningKey) -> bool {
    key.algorithm() == SignatureAlgorithm::ECDSA
        && key.choose_scheme(&[DC_SIGNATURE_SCHEME]).is_some()
        && key
            .choose_scheme(&[
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::ECDSA_NISTP521_SHA512,
            ])
            .is_none()
}
