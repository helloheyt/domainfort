//! The privilege drop of `provision first-admin-secret` — root becomes
//! admind's account for good — behind a trait, as the installer's
//! `Ownership` (task A6: "the privilege drop goes behind a trait, like
//! A4's `Ownership`"), so the command is tested without root while the
//! binary has no path that skips the drop.
//!
//! - [`SandboxDrop`] is the only implementation the binary uses. It exists
//!   only when the effective uid is 0 and it holds the process's
//!   `SingleThreadProof` (claimed as the first statement of `main`,
//!   daemon-sandbox R50-14). [`SandboxDrop::drop_to`] applies
//!   [`hardening_plan`] through `daemon_sandbox::apply`, which ends by
//!   reading the state back and comparing it with the plan (uid, gid,
//!   groups, no_new_privs, capabilities, core 0, not dumpable, memory
//!   limit) — any failure stops the command before a password is read.
//! - Tests implement [`PrivilegeDrop`] to record the requested account.
//!   There is no flag, setting or environment variable that selects a
//!   non-dropping implementation in the binary.
//!
//! **Why admind's account:** keyd maps admind's uid to Role::Directory
//! (A-73, keyd `uid_roles`), the role that may call `set_secret`
//! (docs/10 §2); keyd never maps uid 0 (R50-3). **The plan is admind's
//! own profile** (docs/51 §4.4: "the process `mlockall` and not dumpable
//! (docs/50 §6.4 for admind — the same profile)"; crates/admin-daemon
//! `startup::hardening_plan`): the docs/50 §6.4 baseline (uid/gid with the
//! supplementary groups cleared, no_new_privs, every capability dropped,
//! core 0, not dumpable, umask 077) plus `mlockall` with admind's MEMLOCK
//! limit, a small open-files limit and the working directory `/`. It is
//! applied **before** any password is read — files are only opened and
//! checked before it (module `password_file`), the terminal is read after
//! it — so no password is ever in a dumpable or swappable process
//! (docs/questions/Q-411 item 2).
//!
//! Off Linux `daemon_sandbox::apply` returns `Unsupported` (fail closed):
//! the binary refuses there, like keyadm.
//!
//! Spec: docs/51 §4.3 step 12 ("root ⇒ drops to admind's uid = Role::
//! Directory, through `daemon-sandbox`"), §4.4; docs/50 R50-3, R50-14,
//! §6.1, §6.4; A-61; A-73; A-77; docs/questions/Q-408, Q-411.

use core::fmt;

use daemon_sandbox::{HardeningPlan, PlanError, ProcessIdentity, SandboxError, SingleThreadProof};

use crate::ownership::NotRoot;

/// The locked-memory limit set before `mlockall`: admind's value
/// (crates/admin-daemon `startup::LOCKED_MEMORY_LIMIT`, ⚠ unmeasured —
/// docs/questions/Q-408), the same profile (docs/51 §4.4).
pub const LOCKED_MEMORY_LIMIT: u64 = 256 * 1024 * 1024;

/// The open-files limit: standard streams, the files of at most eight
/// first administrators, the keyd connection, and room. Project choice
/// (docs/50 §6.1: nofile by need).
pub const OPEN_FILES_LIMIT: u64 = 32;

/// The privilege drop failed; nothing was read and nothing sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DropError {
    /// The account cannot be a target (uid or gid 0) or the plan is invalid.
    Plan(PlanError),
    /// daemon-sandbox refused or failed a step (or this is not Linux).
    Sandbox(SandboxError),
    /// The drop was already used (one per process).
    AlreadyUsed,
}

impl fmt::Display for DropError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DropError::Plan(e) => write!(f, "the privilege drop cannot be planned: {e}"),
            DropError::Sandbox(e) => write!(
                f,
                "the privilege drop to admind's account failed: {e} (provision first-admin-secret runs on Linux only)"
            ),
            DropError::AlreadyUsed => f.write_str("the privilege drop was already used"),
        }
    }
}

impl std::error::Error for DropError {}

/// The privileged step of `provision first-admin-secret`.
pub trait PrivilegeDrop {
    /// Become `uid` / `gid` for good — not dumpable, memory locked, core 0
    /// ([`hardening_plan`]) — before any password is read.
    ///
    /// # Errors
    /// [`DropError`]: the command stops (fail closed).
    fn drop_to(&mut self, uid: u32, gid: u32) -> Result<(), DropError>;
}

/// The hardening plan of the drop (module documentation).
///
/// # Errors
/// [`PlanError`] (a uid or gid of 0 is refused).
///
/// Spec: docs/50 §6.1, §6.4 (admind row); docs/51 §4.4.
pub fn hardening_plan(uid: u32, gid: u32) -> Result<HardeningPlan, PlanError> {
    let identity = ProcessIdentity::new(uid, gid)?;
    HardeningPlan::daemon_baseline(identity)
        .lock_all_memory()
        .locked_memory_limit(LOCKED_MEMORY_LIMIT)
        .open_files_limit(OPEN_FILES_LIMIT)
        .working_directory("/")
        .build()
}

/// The production drop: daemon-sandbox, as root.
#[derive(Debug)]
pub struct SandboxDrop {
    proof: Option<SingleThreadProof>,
}

impl SandboxDrop {
    /// Refuses unless the effective uid is 0; holds `proof` for the drop.
    ///
    /// # Errors
    /// [`NotRoot`].
    ///
    /// Spec: rustix `process::geteuid`, `Uid::is_root` (as
    /// `RootOwnership::new`); docs/51 §4.3 step 12 ("root runs it").
    pub fn new(proof: SingleThreadProof) -> Result<SandboxDrop, NotRoot> {
        if rustix::process::geteuid().is_root() {
            Ok(SandboxDrop { proof: Some(proof) })
        } else {
            Err(NotRoot)
        }
    }
}

impl PrivilegeDrop for SandboxDrop {
    /// Spec: daemon-sandbox `apply` (steps in their documented order, then
    /// the read-back check); docs/50 R50-14.
    fn drop_to(&mut self, uid: u32, gid: u32) -> Result<(), DropError> {
        let plan = hardening_plan(uid, gid).map_err(DropError::Plan)?;
        let proof = self.proof.take().ok_or(DropError::AlreadyUsed)?;
        daemon_sandbox::apply(&plan, proof)
            .map(|_| ())
            .map_err(DropError::Sandbox)
    }
}
