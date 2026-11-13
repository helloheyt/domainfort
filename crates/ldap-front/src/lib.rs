#![forbid(unsafe_code)]
//! `ldap-front`: the LDAP network front-end (docs/50 §10 task P11 = docs/49
//! L11; decision A-58).
//!
//! The front owns TCP, TLS (rustls) and the framer; the LDAP engine — the
//! PEP — runs in dird, which owns the directory (docs/49 R49-16: "ldap-front
//! — TLS + parse-ldap, no dirstore / keyd"; docs/25 §3.3: a compromised
//! ldap-front gets no direct access to dirstore or keyd — checked by
//! `tests/no_engine_dependency.rs`). For each client connection the front
//! opens **one** Unix connection to dird (R50-10: 1:1, no session ids),
//! cuts each LDAPMessage with dird's framing state, decodes it with
//! parse-ldap's wire profile and hands dird the **canonical** re-encoding
//! (R49-16), relays dird's responses, and follows its `ConnectionAction`.
//!
//! # Start-up (as built; docs/50 R50-14, R50-16, §6.2, §7.5)
//!
//! 1. claim the `SingleThreadProof` — the first statement of `main`;
//! 2. read the configuration path from argv and parse `LdapFrontSettings`
//!    ([`startup::read_settings`]: root-owned, not group/other-writable,
//!    bounded);
//! 3. as root, before the drop: read the DC certificate and the key (key
//!    file root-owned, mode 0400), check them (ECDSA P-256 / SHA-256, the key
//!    matches the certificate), build the docs/50 R50-11 `ServerConfig`, wipe
//!    the key octets ([`startup::load_tls_config`]); bind the `ldap_listen`
//!    / `ldaps_listen` addresses ([`startup::bind_listeners`]);
//! 4. apply the hardening plan ([`startup::hardening_plan`]) while the
//!    process has one thread (R50-14);
//! 5. only then build the tokio runtime (current-thread) and run [`serve`]:
//!    the TLS configuration re-checked, auditd verified, dird verified on
//!    the LDAP channel (`Ping`), and only now are the listeners served.
//!
//! # Per connection ([`connection`] module)
//!
//! LDAP: `Open { Ldap }`, then messages; StartTLS exactly per docs/50 §4.3
//! (no read while the request is out; after `Done { StartTls }` an empty
//! cleartext buffer is required and discarded; every later octet goes to
//! rustls; the negotiated version and suite are checked; then
//! `TlsEstablished`). LDAPS: the handshake first, the parameters checked,
//! then `Open { Ldaps }` and the same loop over TLS. dird not serving ⇒ a
//! Notice of Disconnection and close (§3.7). Limits and timeouts from
//! `LdapFrontSettings` and the daemon's constants ([`daemon`] module).
//!
//! # Audit
//!
//! dird audits every LDAP operation (docs/50 §4.2, §8.1; R49-14); the front
//! sends no events (ipc-audit has no front shape), verifies auditd at start
//! (R50-16) and **counts** its own layer ([`log::counts`]) — docs/questions/
//! Q-285 item 9.
//!
//! # Modules
//!
//! | module | what |
//! |---|---|
//! | [`tls`] | the R50-11 `ServerConfig`, its policy check, the R50-12 credential, the post-handshake check |
//! | [`relay`] | the cleartext buffer; frame with the framing state; wire → canonical |
//! | [`dird`] | the asynchronous client of `dird-ldap.sock` over ipc-ldap's `FrontChannel` |
//! | [`connection`] | one client connection: transport, StartTLS hand-over, timeouts |
//! | [`daemon`] | [`serve`], the start-up checks, accept loops, connection limits |
//! | [`audit`] | the start-up check of auditd |
//! | [`startup`] | configuration, certificate and key files, binding, hardening plan |
//! | [`log`] | fixed stderr messages and counters (docs/50 §8.2) |
//!
//! # Security
//!
//! `#![forbid(unsafe_code)]`; no `unwrap`, `expect` or `panic!` outside
//! tests (const evaluation only). Nothing logged carries request octets,
//! names, addresses, TLS secrets or a peer-supplied string (AGENTS.md §6;
//! docs/50 §8.2). The key octets, the cleartext LDAP buffer and the
//! canonical messages are wiped; the rustls provider is passed explicitly
//! (never a process default); no TLS 1.2, 0-RTT, resumption, key log,
//! secret extraction, certificate compression or client certificate has a
//! code path.
//!
//! # Residuals (documented, not hidden — docs/questions/Q-285)
//!
//! - The certificate's own signatureAlgorithm is not read (RFC 5280 not
//!   pinned); only the key (P-256) and the key/certificate match are checked.
//! - rustls' internal buffers (handshake state, plaintext before it is
//!   drained, the signing key inside the provider) are rustls' to wipe; the
//!   decoded `LdapMessage` (a SASL token, if any) is not wiped.
//! - Front-level events (TLS failures, non-LDAP streams, limits) are
//!   counted, not audited (no ipc-audit shape).
//! - Peer credentials on the client side use tokio `peer_cred` (works on
//!   Linux and macOS; the blocking clients' rustix path is Linux only).
//! - The TLS handshake tests use a test-only trust model (a pinned key and
//!   an opaque placeholder instead of an X.509 certificate — no certificate
//!   generator is approved and RFC 5280 is not pinned); the production
//!   loader with a real certificate runs only with an operator-provided
//!   certificate (`LDAP_FRONT_TEST_CERT_DIR`).
//! - SIGTERM is not handled; no chroot, no seccomp / landlock / namespaces
//!   (Q-216, P-19).
//!
//! # Provenance
//!
//! Written only from this project's decided design, opened in-session:
//! AGENT-ONBOARDING, AGENTS, docs/50 (R50-3, R50-7, R50-10..R50-16; §2.4;
//! §3.1-§3.7; §4.1-§4.3; §5.1-§5.4; §6; §7.1, §7.5; §8; §9; §10 P11),
//! docs/49 (R49-6, R49-14, R49-15, R49-16; §4; §10; §11), docs/questions
//! Q-162 / Q-163 (A-47), Q-185 (A-52), Q-221 (A-57), Q-230 (A-60), Q-275
//! (A-69), Q-280 (A-70), PENDING-OWNER (P-2, P-12, P-15, P-21); RFC 4511
//! (pinned, sha256 49c6aab6…06fd) §4.1.1, §4.4, §4.4.1, §4.14, §4.14.1-
//! §4.14.3, §5.2, §5.3; RFC 4513 (2215320f…2f6a) §3, §3.1, §3.1.1, §3.1.2,
//! §3.1.4, §3.1.5, §3.2, §3.3; RFC 8446 (47871bc8…b3bd) §2.3, §4.2.1,
//! §4.2.3, §4.2.7, §4.3.2, §4.4.2, §4.4.3, §4.6.1, §9.1, App. B.4; RFC 5929
//! (d32604f5…eab7) §4, §4.1; the public API of this project's crates
//! parse-ldap, ipc, ipc-ldap, ipc-audit, config, daemon-sandbox (kdc-daemon
//! and directory-daemon as the pattern); and the docs.rs API pages of tokio
//! 1.54.1, rustls 0.23.46, rustls-pki-types 1.16.0, aws-lc-rs 1.19.0 and
//! zeroize 1.9.1 — API documentation only, never source (P-2). No other
//! implementation, TLS-terminating proxy, LDAP server or daemon was
//! consulted or recalled (AGENTS.md §1-3).
//!
//! Spec: docs/50 §10 (P11), R50-10, R50-11, R50-12, R50-14, R50-16; docs/49
//! R49-15, R49-16; RFC 4511 §4.14; RFC 4513 §3; RFC 8446 §9.1; A-58.

pub mod audit;
pub mod connection;
mod daemon;
pub mod dird;
pub mod log;
pub mod relay;
pub mod startup;
pub mod tls;

pub use audit::{verify_auditd, AuditCheckError, AUDIT_CHECK_DEADLINE};
pub use connection::{Timeouts, CLIENT_WRITE_TIMEOUT};
pub use daemon::{
    serve, ConnectionLimits, DaemonControl, DaemonError, FrontParams, Listeners, MAX_CONNECTIONS,
    MAX_CONNECTIONS_PER_SOURCE, MAX_UNAUTHENTICATED_CONNECTIONS,
};
pub use dird::{DirdSession, Endpoint};
pub use log::{counts, Counts};
