#![forbid(unsafe_code)]
//! `daemon-sandbox`: process hardening for the phase-1 daemons through safe
//! rustix calls (docs/50 R50-14, §6; build task P3 of §10).
//!
//! # Use
//!
//! ```no_run
//! use daemon_sandbox::{apply, HardeningPlan, ProcessIdentity, SingleThreadProof};
//!
//! fn main() -> std::process::ExitCode {
//!     // First statement of main: the process has exactly one thread.
//!     let Ok(proof) = SingleThreadProof::claim() else {
//!         return std::process::ExitCode::FAILURE;
//!     };
//!     // ... read configuration, open files, bind sockets (as root) ...
//!     let Ok(identity) = ProcessIdentity::new(4001, 4001) else {
//!         return std::process::ExitCode::FAILURE;
//!     };
//!     let Ok(plan) = HardeningPlan::daemon_baseline(identity).open_files_limit(256).build() else {
//!         return std::process::ExitCode::FAILURE;
//!     };
//!     match apply(&plan, proof) {
//!         Ok(report) => { /* audit `report.applied` and `report.state` */ }
//!         Err(_) => return std::process::ExitCode::FAILURE, // fail closed: exit
//!     }
//!     // ... only now build the async runtime and spawn threads ...
//!     std::process::ExitCode::SUCCESS
//! }
//! ```
//!
//! # What a plan can do
//!
//! A [`HardeningPlan`] (built by [`HardeningPlanBuilder`];
//! [`HardeningPlan::daemon_baseline`] is the docs/50 §6.4 baseline):
//! drop to a numeric uid/gid with the supplementary groups cleared;
//! no_new_privs; rlimits (core 0, nofile, memlock); not dumpable; opt-in
//! mlockall (keyd); file-creation mask; optional chroot, then chdir; drop every
//! capability (bounding, ambient, effective, permitted, inheritable, and the
//! keep-capabilities flag).
//!
//! # Order
//!
//! [`apply`] runs the plan's steps in [`Step::ORDER`], whose documentation
//! gives the reason for each position. In short: everything that a capability
//! allows (rlimits, mlockall, chroot, bounding-set removal, groups, gid — per
//! the rustix `thread::Capability` documentation) runs while the process is
//! still privileged; groups and gid precede the uid; no_new_privs follows the
//! uid drop and precedes clearing the capability sets (docs/50 §6.2); the
//! process is made not dumpable before the transition and again after it;
//! the last steps confirm the ids cannot go back to 0 and read the state
//! back. The first failing step stops `apply` with its error — every earlier
//! step was applied, no later one was attempted — and the daemon must exit
//! (fail closed, docs/50 §7.5).
//!
//! # Threads
//!
//! rustix's identity functions act on the calling thread only, so `apply`
//! must run before any other thread exists (R50-14). [`apply`] requires a
//! [`SingleThreadProof`], claimed once per process as the first statement of
//! `main`; see its documentation for the design and its residual.
//!
//! # Verification
//!
//! [`read_state`] reads uid/gid (real and effective), supplementary groups,
//! no_new_privs, dumpable, the three rlimits and the capability state through
//! rustix getters; [`HardeningPlan::check`] compares a state with a plan;
//! [`verify`] does both. `apply` ends with this check, and its
//! [`HardeningReport`] carries the state for the audit record.
//!
//! # Platforms
//!
//! Linux only. On every other target [`apply`], [`read_state`] and [`verify`]
//! return [`SandboxError::Unsupported`] and change nothing — never a silent
//! success. Plans can still be built and checked there (pure code).
//!
//! # Out of scope
//!
//! seccomp filters, landlock and namespaces are not reachable through rustix
//! without `unsafe` or a new dependency (docs/50 §6.3; docs/questions/Q-216,
//! owner item P-19). Until that decision the isolation is a separate uid +
//! no_new_privs + no capabilities + rlimits + chroot.
//!
//! # Provenance
//!
//! Written only from the project's decided design docs/50 (R50-14, R50-19,
//! §6.1-§6.4, §9, §10, A-58), docs/03, docs/07 §9, docs/questions Q-215 /
//! Q-216, and the docs.rs API pages of rustix 1.1.6 (API documentation only,
//! never source — PENDING-OWNER P-2). Linux manual pages were not used (not an
//! allowed source: Q-215, P-18); the interpretations taken where the rustix
//! pages are silent are listed in docs/questions/Q-235. No other
//! implementation consulted or recalled.
//!
//! Spec: docs/50 R50-14, §6; rustix 1.1.6 thread, process, mm.

mod error;
mod plan;
mod proof;
mod state;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(any(not(target_os = "linux"), test))]
mod unsupported;

#[cfg(target_os = "linux")]
use linux as backend;
#[cfg(not(target_os = "linux"))]
use unsupported as backend;

pub use error::{PlanError, SandboxError, ThreadGuardError};
pub use plan::{HardeningPlan, HardeningPlanBuilder, ProcessIdentity, Step, DAEMON_FILE_MODE_MASK};
pub use proof::SingleThreadProof;
pub use state::{CapabilityState, DumpableState, LimitState, SandboxState, StateMismatch};

/// What a backend step reports besides success.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct StepOutcome {
    /// The mask `umask` returned (the one replaced).
    pub(crate) previous_file_mode_mask: Option<u32>,
}

/// The result of a successful [`apply`], for the daemon's start-up assertion
/// and its audit record.
// Spec: docs/50 R50-14; task P3 ("a report of what was applied").
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HardeningReport {
    /// Every step applied, in order — equal to [`HardeningPlan::steps`].
    pub applied: Vec<Step>,
    /// The file-creation mask in force before [`Step::SetFileModeMask`], if
    /// that step ran.
    pub previous_file_mode_mask: Option<u32>,
    /// The state read back by [`Step::VerifyState`]; it matches the plan.
    pub state: SandboxState,
}

/// Apply `plan` to the calling process, in [`Step::ORDER`], consuming the
/// single-thread `proof`.
///
/// Stops at the first failure and returns it; the steps before the failing
/// one (in `plan.steps()` order) were applied, none after it. The caller must
/// then exit. Ends with [`Step::VerifyState`]: the state is read back and must
/// match the plan.
///
/// On a non-Linux target returns [`SandboxError::Unsupported`] for the first
/// step and applies nothing.
// Spec: docs/50 R50-14, §6.1, §6.2, §7.5 (exit on any start-up failure).
pub fn apply(
    plan: &HardeningPlan,
    proof: SingleThreadProof,
) -> Result<HardeningReport, SandboxError> {
    proof.confirm_current_thread()?;
    let mut applied = Vec::new();
    let mut previous_file_mode_mask = None;
    for step in plan.steps() {
        if step == Step::VerifyState {
            // Always the last step (Step::ORDER); performed below.
            continue;
        }
        let outcome = backend::apply_step(step, plan)?;
        if outcome.previous_file_mode_mask.is_some() {
            previous_file_mode_mask = outcome.previous_file_mode_mask;
        }
        applied.push(step);
    }
    let state = verify(plan)?;
    applied.push(Step::VerifyState);
    Ok(HardeningReport {
        applied,
        previous_file_mode_mask,
        state,
    })
}

/// Read the hardening-relevant state of the calling process.
///
/// On a non-Linux target returns [`SandboxError::Unsupported`].
// Spec: docs/50 §6.1 ("verify, otherwise exit").
pub fn read_state() -> Result<SandboxState, SandboxError> {
    backend::read_state()
}

/// Read the state and compare it with `plan`; the daemon calls this at start
/// up (and `apply` calls it as its last step).
///
/// On a non-Linux target returns [`SandboxError::Unsupported`].
// Spec: docs/50 §6.1 ("verify, otherwise exit"), R50-14.
pub fn verify(plan: &HardeningPlan) -> Result<SandboxState, SandboxError> {
    let state = read_state()?;
    plan.check(&state).map_err(SandboxError::Mismatch)?;
    Ok(state)
}
