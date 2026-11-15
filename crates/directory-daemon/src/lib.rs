#![forbid(unsafe_code)]
//! `directory-daemon` (dird): the directory process — its **directory-view
//! service** for the kdc (docs/50 §10 task P8; decision A-58) and its **LDAP
//! service** for ldap-front (task P10: the LDAP engine, the PEP, hosted in
//! dird — docs/50 R50-1, R50-10; docs/49 R49-16), and — when configured —
//! its **admin service** for admind (task A8, docs/51 §7): `dird-admin.sock`,
//! the write PEP (crates/directory-admin) on a dedicated admin thread, every
//! AP-REQ verified through keyd under Role::Ldap (A-73), every decision
//! acknowledged by auditd before the commit (A-85).
//!
//! dird is the only process that opens the redb file and holds the dirstore
//! `IntegrityKey` (R50-2; Q-213 → A-57). The kdc asks it over
//! `dird-kdc.sock` (crates/ipc-directory): each connection pins one snapshot
//! (`BeginView`), its queries are answered from that snapshot, and the
//! policy version of the view is checked by the kdc against its own.
//!
//! **Development sources only.** The integrity key comes from a root-only
//! development file (Q-213's interim — the sealed source is owner item
//! P-17), and the policy store is the UNSIGNED development format 2 of the
//! shared crate `policy-store` — the same file the kdc loads (A-68; the
//! signed format of Q-219 is not defined yet). Both must be named
//! explicitly in the configuration, and dird prints a fixed WARNING for each
//! at every start (docs/questions/Q-270 items 1-2). Not for deployment.
//!
//! # Start-up (as built)
//!
//! 1. claim the `SingleThreadProof` — the first statement of `main` (R50-14);
//! 2. read the configuration path from argv and parse `DirdSettings`
//!    ([`startup::read_settings`]: root-owned, not group/other-writable,
//!    bounded read);
//! 3. as root, before the drop: read the development integrity key
//!    ([`startup::read_integrity_key`]: root-owned, mode 0400, exactly 32
//!    octets, reading buffer wiped) and the development policy
//!    ([`startup::read_policy`]: root-owned, bounded, strictly decoded —
//!    absent or invalid ⇒ no start); prepare the socket directory;
//! 4. apply the hardening plan ([`startup::hardening_plan`]) while the
//!    process has one thread (R50-14);
//! 5. only then build the tokio runtime (current-thread) and run [`serve`]:
//!    verify auditd (R50-16), open the redb file as dird's account (it must
//!    exist, owned by dird, no group/other access), build the directory
//!    context and the tier map, check the domain (naming-context root,
//!    domain SID, krbtgt account), build the LDAP service (the engine, the
//!    PDP snapshot of the same policy file, the audit
//!    gate), spawn the directory-view engine thread and the LDAP engine
//!    thread (R50-7), bind `dird-kdc.sock` and `dird-ldap.sock`, accept.
//!
//! # Request path
//!
//! connection task: peer credentials → uid must be `kdc_uid` (else closed,
//! no reply) → connection quota → connection id → one frame (bounded by
//! `ipc_directory::REQUEST_LIMIT`, `frame_timeout` once started) → bounded
//! engine queue (full ⇒ `Busy`) → engine thread: monotonic clock → decode →
//! the view table (one view per connection, `max_views`, `view_lifetime`)
//! → the view's own answer → encode → reply → next frame; at the end of the
//! connection its view is released.
//!
//! # LDAP path (task P10)
//!
//! `dird-ldap.sock` connection task: peer credentials → uid must be
//! `ldap_front_uid` (else closed, no reply) → session bound (`Busy`, close)
//! → connection id → one frame (bounded by `ipc_ldap::REQUEST_LIMIT`) → the
//! LDAP engine queue with the connection's state (full ⇒ `Busy`, close) →
//! LDAP engine thread: the dispatcher (`ipc_ldap_server::LdapConnection`:
//! Open / Message / TlsEstablished / Close in the channel's order) → audit
//! slot (A-57) → one fresh snapshot as PIP, account source and directory →
//! `ldap::Engine::handle` over the connection's `ldap::Session` → the event
//! committed → the reply frames (response parts, `Done { action, framing
//! }`) → next frame; the session ends with the connection.
//!
//! # Modules
//!
//! | module | what |
//! |---|---|
//! | [`policy`] | the shared unsigned development policy file (crates/policy-store, A-68) and its tier map |
//! | [`audit_link`] | auditd verified first (R50-16): dird's expectation for the one ipc-audit client (task R9b) |
//! | `engine` | the engine thread, its bounded queue, the view sweep |
//! | `listener` | `dird-kdc.sock`: identity, quota, framing, deadlines |
//! | `ldap_engine` | the LDAP engine thread, its bounded queue, the per-request host |
//! | `ldap_listener` | `dird-ldap.sock`: identity, session bound, framing, deadlines |
//! | [`ldap_audit`] | the A-57 gate for LDAP events |
//! | [`clock`] | dird's clock for the LDAP engine |
//! | [`rate`] | the PDP's `RateLimit` obligation for LDAP |
//! | `daemon` | [`serve`], [`DaemonControl`], [`StoreSource`] |
//! | [`startup`] | configuration, key file, policy file, socket directory, hardening plan |
//! | [`log`] | fixed stderr messages (docs/50 §8.2) |
//! | [`admin_service`] | the admin service's parameters, keyd verifier (Role::Ldap), key-set lookup, protected objects, message mapping (task A8) |
//! | `admin_engine` | the admin thread: its bounded queue and the per-request steps of docs/51 §7.4 |
//! | `admin_listener` | `dird-admin.sock`: admind's uid only, ≤ 2 connections, framing, deadlines |
//! | [`policy_next`] | `policy.next`: an approved tier-map change written for root to activate (task A16, docs/51 §5.10) |
//!
//! # Security
//!
//! `#![forbid(unsafe_code)]`; no `unwrap`, `expect` or `panic!` outside
//! tests and const evaluation. The integrity key is read into zeroizing
//! buffers only, never logged, never on any channel. Nothing logged carries
//! request octets, directory values or a peer-supplied string (AGENTS.md §6;
//! docs/50 §8.2).
//!
//! # Residuals (documented, not hidden)
//!
//! - Development integrity key and unsigned policy (above; P-17, Q-219).
//! - dird sends the LDAP engine's events only: ipc-audit has no shape for
//!   dird's own events (refused peers, view limits, the policy loaded) —
//!   Q-270 item 6. A refusal of the LDAP channel's order (`TlsEstablished`
//!   out of turn, a TLS report the channel never accepted) never reaches
//!   the engine and has no event either (docs/questions/Q-280 item 7).
//! - The LDAP client's zone is the zone of the front it came through,
//!   derived from the peer uid of the `dird-ldap.sock` connection — never
//!   from the address the front reports, which only the audit record keeps
//!   (docs/52 R14; A-102 on docs/questions/Q-469 (b): one front per zone,
//!   phase 1 has only the internal one). The residual: a compromised
//!   internal front can relay any party's requests — they get what the
//!   front itself is entitled to (docs/questions/Q-580).
//! - keyd's configuration is assumed to be the library default for the
//!   realm (as keyd-daemon builds it); dird cannot ask keyd (Q-270 item 7).
//! - SIGTERM is not handled (Q-260 item 9); no chroot, no seccomp /
//!   landlock / namespaces (Q-216, P-19); the thread-guard residual of
//!   Q-235 item 2; the integrity key is not `mlock`ed (docs/50 §6.4 lists
//!   `mlockall` for keyd and admind only).
//!
//! # Provenance
//!
//! Written only from this project's decided design, opened in-session:
//! AGENT-ONBOARDING, AGENTS, docs/50 (R50-2, R50-3, R50-7, R50-14,
//! R50-16..R50-19; §2.4; §3.1-§3.7; §6; §7.1, §7.2, §7.4, §7.5; §8; §9; §10
//! P8; the channel-magic registry), docs/47 §8, docs/questions Q-213,
//! Q-214, Q-218..Q-220 (A-57), Q-230 (A-60), Q-235 (A-61), Q-245 (A-63),
//! Q-255 (A-65), Q-260 (A-67), Q-265 (A-66), Q-270, PENDING-OWNER; the
//! public API of this project's crates (ipc, ipc-directory,
//! ipc-directory-server, ipc-audit, directory-pip, dirstore, ad-schema,
//! keyd-types, krb-proto, pdp, dtyp, config, daemon-sandbox; keyd-daemon as
//! the pattern); and the docs.rs API pages of tokio 1.54.1 (crate root
//! features, `runtime::Builder`, `net::UnixListener`, `net::UnixStream`,
//! `net::unix::UCred`, `sync::oneshot`, `sync::Notify`, `time::{timeout,
//! sleep}`, `task::spawn`, `io::{AsyncReadExt, AsyncWriteExt}`) — API
//! documentation only, never source (P-2). No other implementation,
//! directory server, daemon or RPC system was consulted or recalled
//! (AGENTS.md §1-3).
//!
//! The shared gate, the proof of an acknowledged intent and the one stop
//! flush (task R6, decision A-102) were written only from docs/52 (§2,
//! §3.10, §3.11, §4.3, §7 R6), docs/50 §3.6 / §8.1, docs/51 §5.7,
//! PENDING-OWNER (A-85, A-87, A-88, A-93, A-102, A-105), docs/questions
//! Q-313, Q-350, Q-365, Q-470, Q-471 and this repository's own code
//! (docs/questions/Q-500..Q-503). No other implementation was consulted
//! or recalled (AGENTS.md §1-3).
//!
//! The LDAP engine's audit event is converted to its wire shape here
//! ([`ldap_event`], module `audit_convert`) since task IB1 moved it out of
//! an optional feature of crate ipc-audit (class C40; docs/questions/Q-851,
//! decision A-144).
//!
//! Spec: docs/50 §10 (P8), R50-2, R50-3, R50-7, R50-14, R50-16, R50-17;
//! docs/47 §8; A-57; A-58; Decision: A-144; Q-851 (task IB1).

mod admin_engine;
mod admin_listener;
pub mod admin_service;
mod audit_convert;
pub mod audit_link;
pub mod clock;
mod daemon;
mod engine;
pub mod ldap_audit;
mod ldap_engine;
mod ldap_listener;
mod listener;
pub mod log;
pub mod policy;
pub mod policy_next;
pub mod rate;
mod reconcile;
mod registration;
pub mod startup;

pub use admin_listener::admin_refused_peer_count;
pub use admin_service::{
    AdminParams, DecisionAckDeadline, DecisionAckDeadlineOutOfRange, KeydEndpoint,
    KeydTicketVerifier, NotStarted, RegistrationFailure, TicketVerifier, ADMIN_QUEUE_CAPACITY,
    DECISION_ACK_DEADLINE, DESTROY_RECONCILE_INTERVAL, MAX_ADMIN_CONNECTIONS,
    MAX_DECISION_ACK_DEADLINE, MAX_DESTROY_RECONCILE_INTERVAL, MIN_DESTROY_RECONCILE_INTERVAL,
    SET_SECRET_GRANT_LIFETIME_SECS,
};
pub use audit_convert::ldap_event;
pub use audit_link::{AuditEndpoint, AuditLinkError};
pub use clock::{Clock, SharedClock, SystemClock};
pub use daemon::{
    serve, serve_with_admin, DaemonControl, DaemonError, DaemonParams, OpenedStore, Stopped,
    StoreSource, AUDIT_FLUSH_GRACE, DRAIN_GRACE, ENGINE_QUEUE_CAPACITY, LDAP_QUEUE_CAPACITY,
    MAX_KDC_CONNECTIONS, MAX_LDAP_SESSIONS, MAX_OPEN_VIEWS, SOCKET_FILE_MODE,
};
pub use engine::{DirectoryEngine, EngineError, EngineHandle, EnginePanicked, EngineThread};
pub use ldap_engine::{LdapEngineHandle, LdapService, MAX_LDAP_QUEUE_CAPACITY};
pub use ldap_listener::ldap_refused_peer_count;
pub use listener::refused_peer_count;
pub use reconcile::{MAX_PAGES_PER_RUN, MAX_REGISTRATIONS_PER_RUN, MAX_SETTLED, TOMBSTONE_PAGE};
pub use registration::{destroy_decision_id, DecisionRegistration};

/// The test seams (docs/52 C18, task R15): the full parameters, the generic
/// serve, an already-opened store and any keyd verifier. Compiled only with
/// the feature `test-seams`, which only dev-dependencies enable; no product
/// source names this module (crates/e2e-tests
/// `tests/no_test_seams_in_product.rs`).
#[cfg(feature = "test-seams")]
#[doc(hidden)]
pub mod test_seams;
