#![forbid(unsafe_code)]
//! `kdc-daemon`: the KDC process (docs/50 §10 task P9; decision A-58).
//!
//! The kdc library (`Kdc::handle`, crates/kdc) behind UDP and TCP listeners
//! on the configured internal interface addresses (RFC 4120 §7.2.1, §7.2.2;
//! docs/50 R50-9, §4.1), with keyd over `keyd.sock` (`ipc_keyd::IpcKeyd`)
//! and the directory over `dird-kdc.sock` (a view pinned per request,
//! `ipc_directory::RemoteView`). It holds no key (docs/30 §1) and links no
//! crypto (D182) and no store (R50-2) — `tests/no_store_or_crypto.rs`.
//!
//! **Development policy only.** The policy is the UNSIGNED development file
//! of crates/policy-store — the same file dird loads (docs/50 §7.2; A-68) —
//! named explicitly in the configuration; the daemon prints the fixed
//! warning at every start. Not for deployment (the signed store is Q-219).
//!
//! # Start-up (as built)
//!
//! 1. claim the `SingleThreadProof` — the first statement of `main`
//!    (R50-14);
//! 2. read the configuration path from argv and parse `KdcSettings`
//!    ([`startup::read_settings`]: root-owned, not group/other-writable,
//!    bounded; `policy_store_format = unsigned-development` required);
//! 3. as root, before the drop: read the policy file
//!    ([`startup::read_policy`], strictly decoded format 2 — absent or
//!    invalid ⇒ no start) and bind the listeners
//!    ([`startup::bind_listeners`]: UDP + TCP per address);
//! 4. apply the hardening plan ([`startup::hardening_plan`]) while the
//!    process has one thread (R50-14);
//! 5. only then build the tokio runtime (current-thread) and run [`serve`]:
//!    the engine thread (waiting), auditd verified first (R50-16), then on
//!    the engine thread keyd (`DescribeConfig`) and dird (`DescribeDomain`)
//!    verified, **dird's policy version equal to the file's** (R50-2; else no
//!    start), `Kdc::new` validated against keyd's configuration (§7.5 step
//!    4); the audit client; and only now are the listeners served.
//!
//! # Request path
//!
//! UDP: datagram → per-source / global limit (Q-223 option (a)) → queue by
//! the first identifier octet (AS / TGS) → engine → reply datagram (or
//! silence). TCP: connection limits → record framing with `tcp_decode_frame`
//! (reserved bit / bound ⇒ `reject_frame` ⇒ KRB_ERR_FIELD_TOOLONG + close)
//! → deadlines 10 s / 10 s / 30 s → queue → engine → framed reply → next
//! request, up to the per-connection maximum. Engine: own clock → audit
//! slot (A-57) → view pinned (`BeginView`) → `Kdc::handle(request, peer,
//! now, &PolicyInputs, &view)` → `EndView` → event committed → answer.
//!
//! # Modules
//!
//! | module | what |
//! |---|---|
//! | [`queues`] | first-octet classification; the two bounded queues (R50-9) |
//! | `engine` | the engine thread: start checks, per-request path |
//! | [`custody`] | keyd behind the A-57 gate |
//! | [`audit`] | the event buffer and the A-57 gate (the kdc gates) |
//! | `audit_client` | the kdc's expectation of auditd for the one ipc-audit client (R50-17; task R9b) |
//! | `udp` / `tcp` | the listeners (RFC 4120 §7.2.1 / §7.2.2) |
//! | [`rate`] | UDP per-source / global limits; the PDP's RateLimit obligation |
//! | [`zones`] | source address → `Peer.src_net` (docs/50 §4.1) |
//! | [`clock`] | the kdc's own clock |
//! | `daemon` | [`serve`], [`DaemonControl`], [`DaemonParams`], [`Listeners`] |
//! | [`startup`] | configuration, policy file, binding, hardening plan |
//! | [`log`] | fixed stderr messages (docs/50 §8.2) |
//!
//! # Security
//!
//! `#![forbid(unsafe_code)]`; no `unwrap`, `expect` or `panic!` outside
//! tests. Nothing logged carries request octets, names, tickets or a
//! peer-supplied string (AGENTS.md §6; docs/50 §8.2); the request buffers
//! never appear in `Debug` output.
//!
//! # Residuals (documented, not hidden)
//!
//! - The unsigned development policy (Q-219); keyd's development key store
//!   behind it (P-17).
//! - No policy reload: dird restarted with another policy file makes every
//!   request unavailable until the kdc restarts with the same file (Q-275
//!   item 7).
//! - The listeners are bound before the dependencies are verified (as root,
//!   docs/50 §6.2) and served only after (Q-275 item 3).
//! - SIGTERM is not handled (Q-260 item 9, P-16); no chroot, no seccomp /
//!   landlock / namespaces (Q-216, P-19); the thread-guard residual of Q-235
//!   item 2.
//! - Rate limits and queue sizes are constants (docs/50 gives none; A-60;
//!   Q-275 item 5); the UDP size-ratio rule of Q-223 option (b) is not built
//!   (lab).
//! - The client-side peer check uses rustix `socket_peercred`, Linux only
//!   (Q-245 item 11): elsewhere the daemon's keyd and dird connections fail
//!   closed; the tests use a connector that reads the uid through tokio.
//!
//! # Provenance
//!
//! Written only from this project's decided design, opened in-session:
//! AGENT-ONBOARDING, AGENTS, docs/50 (R50-2, R50-3, R50-7..R50-9, R50-14,
//! R50-16, R50-17, R50-19; §2.4; §3.1-§3.7; §4.1; §6; §7.1, §7.2, §7.5; §8;
//! §9; §10 P9; the channel registry), docs/07 §1, docs/questions Q-127 /
//! Q-130 (A-39), Q-217 / Q-222 (A-56), Q-218 / Q-219 / Q-223 (A-57), Q-230
//! (A-60), Q-252 (A-64), Q-260 (A-67), Q-265 (A-66), Q-270 (A-68),
//! PENDING-OWNER; RFC 4120 (pinned copy, sha256 368d3cd1…f75b) §5.4.1,
//! §7.2, §7.2.1, §7.2.2, §7.5.9; ITU-T X.690 (02/2021, pinned copy, sha256
//! 6ac799a2…6bd6c) 8.1.2.2, 8.1.2.5; the public API of this project's
//! crates kdc, keyd-types, ipc, ipc-keyd, ipc-directory, ipc-audit,
//! policy-store, pdp, krb-proto, config, daemon-sandbox (keyd-daemon and
//! directory-daemon as the pattern); and the docs.rs API pages of tokio
//! 1.54.1 (`net::UdpSocket`, `net::TcpListener`, `net::TcpStream`,
//! `net::UnixStream`, `runtime::Builder`, `sync::{oneshot, Notify}`,
//! `time::{timeout, sleep}`, `io::{AsyncReadExt, AsyncWriteExt}`) — API
//! documentation only, never source (P-2). No other implementation, KDC,
//! daemon, server framework or RPC system was consulted or recalled
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
//! Spec: docs/50 §10 (P9), R50-2, R50-3, R50-8, R50-9, R50-14, R50-16,
//! R50-17; RFC 4120 §7.2; A-56; A-57; A-58; A-68.

pub mod audit;
mod audit_client;
pub mod clock;
pub mod custody;
mod daemon;
mod engine;
pub mod log;
pub mod queues;
pub mod rate;
pub mod startup;
mod tcp;
mod udp;
pub mod zones;

pub use audit_client::{AuditEndpoint, AuditLinkError, AUDIT_DEADLINE, HEARTBEAT};
pub use clock::{kerberos_time_from_unix, Clock, SystemClock};
pub use daemon::{
    serve, DaemonControl, DaemonError, DaemonParams, Listeners, Stopped, AS_QUEUE_CAPACITY,
    AUDIT_FLUSH_GRACE, DRAIN_GRACE, TGS_QUEUE_CAPACITY,
};
pub use engine::{EnginePanicked, EngineThread, StartError};
pub use tcp::TcpLimits;

/// The test seams (docs/52 C18, task R15): the full parameters and the
/// generic `serve`. Compiled only with the feature `test-seams`, which only
/// dev-dependencies enable; no product source names this module
/// (crates/e2e-tests `tests/no_test_seams_in_product.rs`).
#[cfg(feature = "test-seams")]
#[doc(hidden)]
pub mod test_seams;
