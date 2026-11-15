//! Typed errors. Every message is a fixed string plus, for an operating-system
//! failure, the numeric error code — never a path, a value read from a file,
//! or anything a caller supplied (docs/CLEAN-ROOM.md "secrets never in errors";
//! docs/50 §8.2 "IPC errors carry a code, not content").

use std::fmt;

use crate::plan::Step;
use crate::state::StateMismatch;

/// Why a [`HardeningPlan`](crate::HardeningPlan) could not be built. Checked
/// before anything is applied, so a mis-specified plan never reaches the
/// operating system (fail closed — docs/03 principles).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlanError {
    /// The plan contains no hardening step at all.
    // Spec: docs/50 R50-14 (every daemon applies the hardening baseline).
    NoHardeningStep,
    /// The target uid or gid is 0: that is not a privilege drop.
    // Spec: rustix 1.1.6 thread::Uid::ROOT ("uid 0"), thread::Gid::ROOT
    // ("gid 0"); docs/50 §2.4 (each daemon has its own account), §3.2
    // ("uid 0 is never mapped").
    RootIdentity,
    /// The target uid or gid is the all-ones value of the raw type, which
    /// rustix documents as not a valid identifier.
    // Spec: rustix 1.1.6 thread::Uid::from_raw / thread::Gid::from_raw
    // ("must be the value of a valid Unix group ID, and not -1"); RawUid /
    // RawGid are `c_uint`.
    InvalidIdentity,
    /// An identity drop was planned without also dropping every capability
    /// and setting no_new_privs; docs/50 §6.4 defines them as one baseline.
    // Spec: docs/50 §6.4 (baseline: own uid, empty groups, no_new_privs, no
    // capabilities, core = 0, non-dumpable, umask 077).
    IdentityDropIncomplete,
    /// mlockall was requested without an explicit locked-memory rlimit;
    /// docs/50 pairs the two for keyd.
    // Spec: docs/50 §6.1 ("keyd — also MEMLOCK before the drop"), §6.4.
    MemoryLockWithoutLimit,
    /// An open-files limit of zero was requested.
    // Spec: docs/50 §6.1 ("nofile according to the connection quotas") — a
    // daemon with no file descriptor cannot serve anything.
    ZeroOpenFilesLimit,
    /// The file-creation mask has bits beyond three octal digits.
    // Spec: docs/50 §6.1 (the mask is written as three octal digits, "077").
    FileModeMaskOutOfRange,
    /// A chroot or working directory path is not absolute.
    // Spec: docs/50 §7.1 (configuration paths are absolute).
    RelativePath,
}

impl fmt::Display for PlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            PlanError::NoHardeningStep => "hardening plan has no step",
            PlanError::RootIdentity => "target uid or gid is root",
            PlanError::InvalidIdentity => "target uid or gid is not a valid identifier",
            PlanError::IdentityDropIncomplete => {
                "identity drop requires dropping capabilities and setting no_new_privs"
            }
            PlanError::MemoryLockWithoutLimit => "mlockall requires a locked-memory limit",
            PlanError::ZeroOpenFilesLimit => "open-files limit must not be zero",
            PlanError::FileModeMaskOutOfRange => "file-creation mask out of range",
            PlanError::RelativePath => "chroot and working directory must be absolute paths",
        })
    }
}

impl std::error::Error for PlanError {}

/// Why the single-thread guard refused.
// Spec: docs/50 R50-14 (drop uid/gid before any thread exists: the rustix
// functions act on the calling thread).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreadGuardError {
    /// A [`SingleThreadProof`](crate::SingleThreadProof) was already claimed
    /// in this process; only one exists per process.
    AlreadyClaimed,
    /// `apply` ran on a different thread from the one that claimed the
    /// proof.
    WrongThread,
}

impl fmt::Display for ThreadGuardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ThreadGuardError::AlreadyClaimed => "single-thread proof already claimed",
            ThreadGuardError::WrongThread => "apply called from a thread other than the claimer",
        })
    }
}

impl std::error::Error for ThreadGuardError {}

/// Why hardening (or reading the hardened state back) failed. On any of these
/// the daemon must exit: a partly hardened process is not a hardened process
/// (docs/50 §7.5 "every daemon exits with an error code on any start-up
/// failure"; docs/03 principles, fail closed).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SandboxError {
    /// This target is not Linux: nothing was applied, nothing is claimed.
    // Spec: docs/50 R50-14 (hardening is defined only for the Linux API of
    // rustix); task P3 (never succeed silently on another target).
    Unsupported {
        /// The step that could not be performed (the first of the plan, or
        /// [`Step::VerifyState`] for a read-back).
        step: Step,
    },
    /// The operating system refused a step; `call` names the rustix function
    /// and `errno` is the raw error number it reported.
    // Spec: rustix 1.1.6 io::Errno::raw_os_error.
    Os {
        /// The step that failed. Every earlier step of the plan was applied;
        /// no later step was attempted.
        step: Step,
        /// The rustix function that failed (a fixed name, e.g. `"setrlimit"`).
        call: &'static str,
        /// The raw OS error number.
        errno: i32,
    },
    /// The single-thread guard refused before anything was applied.
    ThreadGuard(ThreadGuardError),
    /// The state read back after the steps differs from the plan.
    // Spec: docs/50 §6.1 ("after the drop — getuid/geteuid/getgid to verify,
    // otherwise exit").
    Mismatch(StateMismatch),
    /// After the identity drop, a request to set the real, effective and
    /// saved uid or gid back to 0 succeeded: the drop was not irreversible.
    // Spec: rustix 1.1.6 thread::set_thread_res_uid / set_thread_res_gid;
    // docs/50 R50-14.
    PrivilegeRegained,
    /// The file-creation mask is not a combination of rustix's permission
    /// bits (`Mode::RWXU | Mode::RWXG | Mode::RWXO`).
    // Spec: rustix 1.1.6 fs::Mode; docs/50 §6.1.
    InvalidFileModeMask,
}

impl fmt::Display for SandboxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SandboxError::Unsupported { step } => {
                write!(
                    f,
                    "process hardening is unsupported on this target (step {step})"
                )
            }
            SandboxError::Os { step, call, errno } => {
                write!(
                    f,
                    "hardening step {step} failed in {call}: os error {errno}"
                )
            }
            SandboxError::ThreadGuard(e) => write!(f, "thread guard: {e}"),
            SandboxError::Mismatch(m) => write!(f, "hardened state mismatch: {m}"),
            SandboxError::PrivilegeRegained => {
                f.write_str("identity drop is reversible: root could be regained")
            }
            SandboxError::InvalidFileModeMask => f.write_str("invalid file-creation mask"),
        }
    }
}

impl std::error::Error for SandboxError {}

impl From<ThreadGuardError> for SandboxError {
    fn from(e: ThreadGuardError) -> Self {
        SandboxError::ThreadGuard(e)
    }
}
