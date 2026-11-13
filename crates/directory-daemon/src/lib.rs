#![forbid(unsafe_code)]
//! `directory-daemon` (dird): the directory process — in this task its
//! **directory-view service only** (docs/50 §10 task P8; decision A-58).
//! Hosting the LDAP engine is task P10, the admin channel P13: their sockets
//! are not bound.
//!
//! dird is the only process that opens the redb file and holds the dirstore
//! `IntegrityKey` (R50-2; Q-213 → A-57). The kdc asks it over
//! `dird-kdc.sock` (crates/ipc-directory): each connection pins one snapshot
//! (`BeginView`), its queries are answered from that snapshot, and the
//! policy version of the view is checked by the kdc against its own.
//!
//! **Development sources only.** The integrity key comes from a root-only
//! development file (Q-213's interim — the sealed source is owner item
//! P-17), and the policy store is the UNSIGNED development format (the
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
//!    domain SID, krbtgt account), spawn the engine thread (R50-7), bind
//!    `dird-kdc.sock` and accept.
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
//! # Modules
//!
//! | module | what |
//! |---|---|
//! | [`policy`] | the unsigned development policy file (format, decoder, encoder) |
//! | [`audit_link`] | auditd verified first (R50-16) |
//! | `engine` | the engine thread, its bounded queue, the view sweep |
//! | `listener` | `dird-kdc.sock`: identity, quota, framing, deadlines |
//! | `daemon` | [`serve`], [`DaemonControl`], [`StoreSource`] |
//! | [`startup`] | configuration, key file, policy file, socket directory, hardening plan |
//! | [`log`] | fixed stderr messages (docs/50 §8.2) |
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
//! - dird sends no audit event: ipc-audit has no shape for dird's events
//!   (refused peers, view limits, the policy loaded); auditd is verified at
//!   start only (Q-270 item 6).
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
//! Spec: docs/50 §10 (P8), R50-2, R50-3, R50-7, R50-14, R50-16, R50-17;
//! docs/47 §8; A-57; A-58.

pub mod audit_link;
mod daemon;
mod engine;
mod listener;
pub mod log;
pub mod policy;
pub mod startup;

pub use audit_link::{AuditEndpoint, AuditLinkError};
pub use daemon::{
    serve, DaemonControl, DaemonError, DaemonParams, Stopped, StoreSource, DRAIN_GRACE,
    ENGINE_QUEUE_CAPACITY, MAX_KDC_CONNECTIONS, MAX_OPEN_VIEWS, SOCKET_FILE_MODE,
};
pub use engine::{DirectoryEngine, EngineError, EngineHandle, EnginePanicked, EngineThread};
pub use listener::refused_peer_count;
