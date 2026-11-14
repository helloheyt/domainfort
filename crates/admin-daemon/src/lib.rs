#![forbid(unsafe_code)]
//! `admin-daemon` (admind): the management-plane process of phase 1
//! (docs/51 §5, §7.6, R51-7, R51-12, R51-13, §12 task A9; docs/50 §2.4).
//!
//! admind is **local-only** — `admin.sock` (crate ipc-admin, magic
//! `0x414D`), no network API in phase 1 (A-57: mTLS needs the PKI of
//! phase 3) — **stateless, with no store** (docs/51 §5.1). It:
//!
//! * checks each request **syntactically** (the codec; the password rules
//!   of [MS-SAMR] 3.1.1.7.2 for `SetPassword`);
//! * **forwards** every other operation to dird over `dird-admin.sock`
//!   (crate ipc-dird-admin) with the administrators' raw AP-REQs untouched —
//!   admind never interprets, logs or alters them and has no field in which
//!   it could claim an identity (docs/51 §5.3 option D; A-70, A-73): dird
//!   verifies the tickets through keyd, decides with the PDP and audits;
//! * for **`SetPassword`** runs dird's `BeginPasswordSet` ⇒ keyd
//!   `set_secret` (Role::Directory, ×1 for a user, ×2 for a computer) ⇒
//!   dird's `CompletePasswordSet` itself, so **the password never reaches
//!   dird** (docs/51 §7.6, §9; docs/47 §9.2) — crate::worker;
//! * is **not** in keyadm's path (A-102, docs/52 §4.6, §4.8;
//!   docs/questions/Q-460): keyadm's former requests (`FetchApproved`,
//!   `Complete`, `ListPendingDestruction`, task A10) and admind's
//!   `keyadm_uid` forward are gone — their kinds are not in admin.sock's
//!   closed table, so a frame of one is refused like any unknown kind and
//!   dird is never asked. keyadm executes, in keyd, the decisions dird
//!   registered there (N2: admind can no longer shape what keyadm runs);
//! * sends **its own audit events** to auditd (shape `Admind`): refused
//!   connections, malformed frames and rate-limited frames as noise, every
//!   `SetPassword` outcome gating
//!   (docs/51 §5.7 item 3; A-85; task F6) — crate::audit.
//!
//! # Start-up (as built)
//!
//! 1. claim the `SingleThreadProof` — the first statement of `main`
//!    (R50-14);
//! 2. read the configuration path from argv and parse `AdmindSettings`
//!    ([`startup::read_settings`]: root-owned, not group/other-writable,
//!    bounded read);
//! 3. as root: `admin.sock`'s directory (0750, owner admind, group
//!    `admin_socket_group` — [`startup::prepare_socket_directory`]);
//! 4. apply the hardening plan ([`startup::hardening_plan`]: identity drop,
//!    no_new_privs, capabilities, core 0, not dumpable, umask, **mlockall**
//!    — docs/50 §6.4 admind row) while the process has one thread;
//! 5. only then build the tokio runtime (current-thread) and run [`serve`]:
//!    verify auditd (no auditd ⇒ no start, R50-16), start the worker, bind
//!    `admin.sock`, accept.
//!
//! # Request path
//!
//! connection task: peer credentials (uid for the limits and the events
//! only, never a subject) → connection quota per uid → one frame (bounded
//! by `ipc_admin::REQUEST_LIMIT`, `frame_timeout` once started) → request
//! rate per uid (`Busy`) → decode (malformed ⇒ noise event + close) →
//! `Ping` answered, anything else to the worker's bounded queue (`Busy`) →
//! worker thread: forward to dird, or the `SetPassword` sequence → reply →
//! next frame.
//!
//! # Modules
//!
//! | module | what |
//! |---|---|
//! | [`startup`] | configuration, socket directory, hardening plan, parameters |
//! | `daemon` | [`serve`], [`DaemonControl`], [`DaemonParams`], [`Stopped`] |
//! | `listener` | `admin.sock`: peer uid, quota, framing, rate, decoding, dispatch |
//! | [`rate`] | the per-uid connection quota and request rate |
//! | `worker` | the worker thread: forwarding and the `SetPassword` sequence |
//! | [`password`] | the password rules of [MS-SAMR] 3.1.1.7.2 |
//! | [`links`] | the dird and keyd clients behind two traits |
//! | [`audit`] | the audit window, noise and gating events |
//! | [`audit_link`] | auditd verified first (R50-16), events delivered: admind's expectation for the one ipc-audit client (task R9b) |
//! | [`clock`] | the time of admind's events |
//! | [`log`] | fixed stderr messages (docs/50 §8.2) |
//!
//! # Security
//!
//! `#![forbid(unsafe_code)]`; no `unwrap`, `expect` or `panic!` outside
//! tests and const evaluation. The password lives only in zeroizing buffers
//! — the frame reader's body, the copy handed to the decoder (wiped right
//! after decoding), `ipc_admin::Password`, one zeroizing copy per keyd call —
//! and is never logged, never in an error or event, never sent to dird
//! (docs/51 §7.6; docs/50 §3.3, §8.2). AP-REQ octets are never logged.
//! admind links no store, PEP, keyd or Kerberos crypto (D182, A-73;
//! tests/no_store_or_crypto.rs).
//!
//! # Residuals (documented, not hidden)
//!
//! - **admind is equivalent to tier-0 in phase 1** (docs/51 §5.8, R51-13;
//!   A-74): as Role::Directory it can set any account's secret without
//!   dird's PDP; detection is the audit cross-check (keyd `SetSecret` vs dird
//!   `BeginPasswordSet`); prevention is task A15 (a keyd grant).
//! - admind forwards every AP-REQ untouched: each is bound by its client to
//!   the exact dird request it accompanies (the Authenticator's `cksum`
//!   over `ipc_dird_admin::operation_digest`, verified by keyd — R2, docs/52
//!   §5), so admind cannot attach one to another operation. For
//!   `SetPassword` the client binds `auth` to `BeginPasswordSet {target}`
//!   and `completion` to `CompletePasswordSet {target}` (its outcome and
//!   kvnos are admind's report, outside the digest — docs/52 §5 item 5).
//! - admind cannot positively verify keyd's role for it (Role::Directory may
//!   not call `DescribeConfig`, A-90): a cross-wired keyd refuses
//!   `set_secret` (`Denied`) — docs/questions/Q-403.
//! - No seccomp / landlock / namespaces (P-19); SIGTERM not handled (Q-260
//!   item 9); the MEMLOCK limit is unmeasured (Q-408).
//!
//! # Provenance
//!
//! Written only from this project's decided design, opened in-session:
//! AGENT-ONBOARDING, AGENTS, docs/51 (whole), docs/50 (§2.4, §3, §6.4, §7,
//! §8, §9, the channel-magic registry), docs/47 §9, docs/10 §2, §6, §10,
//! docs/questions Q-220, Q-290, Q-291, Q-340, Q-341, Q-350, Q-365, Q-367,
//! Q-370, Q-378, Q-385..Q-389 and PENDING-OWNER (A-57, A-63, A-64, A-70,
//! A-72..A-74, A-79, A-85, A-87, A-88, A-90..A-92, P-19, P-24); [MS-SAMR]
//! v20260427 §3.1.1.7.2 from `tools/spec-pin/cache/` (SHA-256 `083fe00a…8a4e`
//! verified against `tools/spec-pin/manifest.json`); the public API of this
//! project's crates (ipc, ipc-admin, ipc-dird-admin, ipc-keyd, ipc-audit,
//! keyd-types, krb-proto, dtyp, config, daemon-sandbox; directory-daemon and
//! keyd-daemon as the pattern); and the docs.rs API pages of tokio 1.54.1 as
//! cited in those daemons (P-2). No other implementation, management daemon
//! or password service was consulted or recalled (AGENTS.md §1-3).
//!
//! The shared gate, the proof of an acknowledged intent and the one stop
//! flush (task R6, decision A-102) were written only from docs/52 (§2,
//! §3.10, §3.11, §4.3, §7 R6), docs/50 §3.6 / §8.1, docs/51 §5.7,
//! PENDING-OWNER (A-85, A-87, A-88, A-93, A-102, A-105), docs/questions
//! Q-313, Q-350, Q-365, Q-470, Q-471 and this repository's own code
//! (docs/questions/Q-500..Q-503). No other implementation was consulted
//! or recalled (AGENTS.md §1-3).
//!
//! Spec: docs/51 §5.1, §5.2 row 5, §5.7, §5.8, §7.6, §9, §12 (A9); docs/50
//! §2.4, R50-3, R50-7, R50-14, R50-16, R50-17, §3, §6.4, §7.5, §8; A-57;
//! A-72; A-73; A-85; A-90.

pub mod audit;
pub mod audit_link;
pub mod clock;
mod daemon;
pub mod links;
mod listener;
pub mod log;
pub mod password;
pub mod rate;
pub mod startup;
mod worker;

pub use audit_link::{AuditEndpoint, AuditLinkError};
pub use daemon::{
    serve, DaemonControl, DaemonError, DaemonParams, Stopped, WorkerPanicked, AUDIT_FLUSH_GRACE,
    DRAIN_GRACE, SOCKET_FILE_MODE, WORKER_QUEUE_CAPACITY,
};
pub use links::{DirdLink, KeydLink};
pub use rate::Limits;
