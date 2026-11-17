#![forbid(unsafe_code)]
//! `keyd-daemon`: the keyd process (docs/50 §10 task P7; decision A-58) —
//! **development key store only** (R50-18; owner item P-17).
//!
//! The keyd library ("compute, don't give", docs/09, docs/10) behind
//! `keyd.sock`. The binary (`src/main.rs`) does the start-up steps that must
//! happen before any thread exists; everything testable lives here.
//!
//! # Start-up (as built)
//!
//! 1. claim the `SingleThreadProof` — the first statement of `main` (R50-14;
//!    docs/questions/Q-235 item 2);
//! 2. read the configuration path from argv and parse `KeydSettings`
//!    ([`startup::read_settings`]: root-owned, not group/other-writable,
//!    reached without following a symbolic link, bounded read);
//! 3. privileged set-up as root: the socket's own directory
//!    ([`startup::prepare_socket_directory`], docs/50 §3.1);
//! 4. apply the hardening plan ([`startup::hardening_plan`]: drop to
//!    `run_as_uid` / `run_as_gid`, no_new_privs, no capabilities, core 0,
//!    not dumpable, umask 077, `mlockall` with its MEMLOCK limit, small
//!    nofile) while the process has one thread (R50-14);
//! 5. only then build the tokio runtime (current-thread) and run [`serve`]:
//!    verify auditd (R50-16), build keyd with the hold-down start read from
//!    keyd's own clock (R50-5, R50-6, A-62) and log the development-store
//!    warning, spawn the engine thread (R50-7), start the audit client
//!    (R50-17), bind `keyd.sock` and accept.
//!
//! # Request path
//!
//! connection task: peer credentials → uid → [`CallerMap`] → `CallerId`
//! (unmapped ⇒ closed, no reply) → per-uid quota → one frame (bounded by
//! `ipc_keyd::REQUEST_LIMIT`, `frame_timeout` once started) → bounded engine
//! queue (full ⇒ `Busy`) → engine thread: own clock → decode → A-57 gate
//! (gating op: reserve a window slot or `Busy`) → keyd → commit the record →
//! encode → reply → next frame.
//!
//! A **key-state change** (`keyd::changes_key_state`: `set_secret`,
//! `create_key`, `rotate_key`, `rotate_krbtgt`, `retire_kvno`,
//! `destroy_key_set`, `complete_change_password`, and — task PN9 — the
//! ceremony's `install_attestation_key`) that keyd's authorization step admits takes the A-86
//! path instead: reserve two slots or `Busy` → commit the **intent** record
//! → wait (≤ the daemon's [`IntentAckBudget`] from queueing —
//! [`INTENT_ACK_BUDGET`] in production, never above
//! [`MAX_INTENT_ACK_BUDGET`]) for auditd to
//! **acknowledge** it, else a `NotPerformed` record and `Unavailable`, keyd
//! not called → keyd → commit keyd's record (the outcome) → reply with the
//! true result, even if that record could not be committed (the gap is
//! counted into the next `WindowSummary` — A-88 — and noted on stderr).
//! "Unavailable" always means "not done".
//!
//! # Modules
//!
//! | module | what |
//! |---|---|
//! | [`clock`] | keyd's own clock (R50-5) |
//! | [`callers`] | the `uid → Role` map (R50-3) |
//! | `engine` | the engine thread and its bounded queue (R50-7) |
//! | [`audit`] | the record buffer and the A-57 gate |
//! | [`audit_client`] | keyd's expectation of auditd for the one ipc-audit client (R50-17; task R9b) |
//! | `listener` | `keyd.sock`: identity, quota, framing, deadlines |
//! | `daemon` | [`serve`], [`DaemonControl`] |
//! | `test_seams` | feature `test-seams` only: the full parameters and the generic `serve` (docs/52 C18) |
//! | [`startup`] | configuration, socket directory, hardening plan, the development keyd |
//! | [`log`] | fixed stderr messages (docs/50 §8.2) |
//!
//! # Security
//!
//! `#![forbid(unsafe_code)]`; no `unwrap`, `expect` or `panic!` outside
//! tests. Request bodies (which may carry a password) live only in zeroizing
//! buffers. Nothing logged carries request octets, keys, tokens or a
//! peer-supplied string (docs/CLEAN-ROOM.md; docs/50 §8.2).
//!
//! # Residuals (documented, not hidden)
//!
//! - The key store is the in-memory development store: keys are lost on
//!   restart and krbtgt is not HSM-protected (D178, P-17). Not for
//!   deployment.
//! - SIGTERM is not handled (no tokio `signal` feature; no safe std/rustix
//!   handler): the default action ends the process; the window's
//!   unacknowledged events (≤ its capacity) are lost (Q-252 item 9; Q-260
//!   item 9).
//! - No chroot (the audit socket must stay reachable; Q-260 item 8); no
//!   seccomp / landlock / namespaces (Q-216, P-19).
//! - An unmapped peer and a quota refusal are not audit events (ipc-audit
//!   has no shape for them, Q-260 item 5); they are counted on stderr.
//! - No per-Role rate limit (docs/50 §3.6 names one without a number;
//!   Q-230 item 4; Q-260 item 7).
//! - The engine's thread-count guard has the residual of Q-235 item 2.
//! - A key-state change waits on the engine thread for its intent's
//!   acknowledgement (≤ the budget, [`INTENT_ACK_BUDGET`] in production;
//!   there is no configuration key for it); Kerberos requests queued
//!   behind it wait that long too (A-86; Q-365). A caller whose reply is
//!   lost or later than its own deadline still cannot tell a performed
//!   change from an unperformed one — the log can (intent + outcome).
//! - A lost outcome record is counted into the next `WindowSummary` of the
//!   window (`unrecorded_outcomes`, decision A-88; Q-366, Q-395) and on
//!   stderr; the summary itself waits in the window like every event, so it
//!   is lost only if keyd ends before auditd acknowledged it (Q-252 item 9).
//!
//! # Provenance
//!
//! Written only from this project's decided design, opened in-session:
//! docs/CLEAN-ROOM.md, docs/CLEAN-ROOM.md, docs/50 (§1 R50-3..R50-8, R50-14, R50-16..R50-19;
//! §2.4; §3.1-§3.7; §6; §7.1, §7.3, §7.5; §8; §9; §10 P7; the channel-magic
//! registry), docs/10 (§2, §3, §7a, §9-§12), docs/questions Q-212 (P-17),
//! Q-218 (A-57), Q-222 (A-56), Q-230 (A-60), Q-235 (A-61), Q-240 (A-62),
//! Q-245 (A-63), Q-250 / Q-252 (A-64), Q-255 (A-65), PENDING-OWNER; the
//! public API of this project's crates ipc, ipc-keyd, ipc-keyd-server,
//! ipc-audit, keyd, keyd-types, krb-proto, config, daemon-sandbox (and, for
//! the clock's inverse, the method of crates/kdc time.rs); and the docs.rs
//! API pages of tokio 1.54.1 (crate root features, `runtime::Builder`,
//! `runtime::Runtime`, `net::UnixListener`, `net::UnixStream`,
//! `net::unix::UCred`, `sync` index, `sync::mpsc::{channel, Sender,
//! Receiver}`, `sync::oneshot::{Sender, Receiver}`, `sync::Notify`,
//! `time::{timeout, sleep}`, `task::{spawn, JoinHandle}`,
//! `io::{AsyncReadExt, AsyncWriteExt}`) — API documentation only, never
//! source (P-2). No other implementation, daemon, server framework or RPC
//! system was consulted or recalled (docs/CLEAN-ROOM.md).
//!
//! The shared gate, the proof of an acknowledged intent and the one stop
//! flush (task R6, decision A-102) were written only from docs/52 (§2,
//! §3.10, §3.11, §4.3, §7 R6), docs/50 §3.6 / §8.1, docs/51 §5.7,
//! PENDING-OWNER (A-85, A-87, A-88, A-93, A-102, A-105), docs/questions
//! Q-313, Q-350, Q-365, Q-470, Q-471 and this repository's own code
//! (docs/questions/Q-500..Q-503). No other implementation was consulted
//! or recalled (docs/CLEAN-ROOM.md).
//!
//! The key-state change path (decision A-86, task F2) was written only from
//! docs/10 (§2, §5b, §6, §7, §10, §12), docs/50 (§3.5, §3.6, §3.7, §8),
//! docs/51 §5.7 (A-85, the precedent), PENDING-OWNER (A-57, A-62..A-67,
//! A-85), docs/questions Q-218, Q-252, Q-260, Q-265, Q-340, the task's
//! statement of A-86 / Q-346, and the public API of this project's crates
//! (ipc-audit `SendWindow`, keyd, ipc-keyd); the wait uses `std::sync::
//! Condvar` from the Rust standard library. Nothing else was consulted.
//! Counting a lost outcome into the window's summary (decision A-88, task
//! F4) was written only from PENDING-OWNER (A-88), docs/questions Q-366,
//! docs/50 §8, docs/37 and the public API of ipc-audit `SendWindow`. The
//! budget as a daemon parameter with a ceiling (A-93's follow-up, task F5)
//! was written only from PENDING-OWNER (A-88, A-93), docs/questions Q-365,
//! docs/50 §3.6 and the public constants of ipc-keyd (`DEFAULT_DEADLINE`)
//! and config (`limits::KEYD_DEADLINE_SECS`).
//!
//! Spec: docs/50 §10 (P7), R50-3, R50-5, R50-6, R50-7, R50-14, R50-16,
//! R50-17, R50-18; docs/10; A-56; A-57; A-62; A-64; A-86; A-88; A-93.

pub mod audit;
pub mod audit_client;
pub mod callers;
pub mod clock;
mod daemon;
mod engine;
mod listener;
pub mod log;
pub mod startup;

#[cfg(test)]
mod tier1_tests;

pub use audit::{is_gating, RecordBuffer};
pub use audit_client::{AuditEndpoint, AuditLinkError};
pub use callers::{CallerMap, CallerMapError};
pub use clock::{Clock, SystemClock};
pub use daemon::{
    serve, DaemonControl, DaemonError, DaemonParams, Stopped, AUDIT_FLUSH_GRACE, DRAIN_GRACE,
    ENGINE_QUEUE_CAPACITY, SOCKET_FILE_MODE,
};

/// The test seams (docs/52 C18, task R15): the full parameters and the
/// generic `serve`. Compiled only with the feature `test-seams`, which only
/// dev-dependencies enable; no product source names this module
/// (crates/e2e-tests `tests/no_test_seams_in_product.rs`).
#[cfg(feature = "test-seams")]
#[doc(hidden)]
pub mod test_seams;
pub use engine::{
    EngineError, EngineHandle, EnginePanicked, EngineThread, IntentAckBudget,
    IntentAckBudgetOutOfRange, INTENT_ACK_BUDGET, MAX_INTENT_ACK_BUDGET, MAX_QUEUE_CAPACITY,
};
