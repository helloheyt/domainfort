//! The Linux backend: each step is one or a few safe rustix calls; the
//! read-back uses rustix getters only. No `unsafe` (the crate forbids it).
//!
//! Only what the rustix 1.1.6 API pages state is relied on; where they are
//! silent (for example what a `None` process id means to `capabilities`, or
//! whether an identity change preserves the dumpable attribute) the code takes
//! the explicit choice and reads the result back — see docs/questions/Q-235.
// Spec: docs/50 R50-14, §6.1, §6.2; rustix 1.1.6 modules thread, process, mm,
// fs::Mode, io::Errno.

use rustix::fs::Mode;
use rustix::io::Errno;
use rustix::mm::{mlockall, MlockAllFlags};
use rustix::process::{self, DumpableBehavior, Resource, Rlimit};
use rustix::thread::{self, CapabilitySet, CapabilitySets, Gid, Uid};

use crate::error::SandboxError;
use crate::plan::{HardeningPlan, Step};
use crate::state::{CapabilityState, DumpableState, LimitState, SandboxState};
use crate::StepOutcome;

/// Map a rustix error of `call` during `step` to [`SandboxError::Os`].
// Spec: rustix 1.1.6 io::Errno::raw_os_error.
fn os(step: Step, call: &'static str) -> impl Fn(Errno) -> SandboxError {
    move |errno| SandboxError::Os {
        step,
        call,
        errno: errno.raw_os_error(),
    }
}

/// The value both limits of a planned resource are set to (soft = hard).
// Spec: rustix 1.1.6 process::Rlimit (`current` may be increased only up to
// `maximum`).
fn fixed(value: u64) -> Rlimit {
    Rlimit {
        current: Some(value),
        maximum: Some(value),
    }
}

/// Every capability rustix names, one single-bit value each.
///
/// `CapabilitySet::all()` sets "all known bits", and its `iter()` yields the
/// unknown bits "together as a final flags value"; that value is not one
/// capability (on Linux 6.17 the kernel answers it with EINVAL). `iter_names`
/// "only yields bits in contained named flags", so only those are used.
// Spec: rustix 1.1.6 thread::CapabilitySet::all, iter, iter_names; the
// deprecation note of thread::Capability ("Use CapabilitySet with a single
// bit instead").
fn named_capabilities() -> impl Iterator<Item = CapabilitySet> {
    CapabilitySet::all()
        .iter_names()
        .map(|(_name, capability)| capability)
}

/// Perform one step of `plan`.
pub(crate) fn apply_step(step: Step, plan: &HardeningPlan) -> Result<StepOutcome, SandboxError> {
    let mut outcome = StepOutcome::default();
    match step {
        // Spec: docs/50 §6.1 ("umask 077"); rustix 1.1.6 process::umask
        // ("Set the process file creation mask", returns the previous Mode),
        // fs::Mode (RWXU, RWXG, RWXO; from_bits returns None on unknown bits).
        Step::SetFileModeMask => {
            if let Some(mask) = plan.file_mode_mask() {
                let permission_bits = Mode::RWXU | Mode::RWXG | Mode::RWXO;
                let mode = Mode::from_bits(mask)
                    .filter(|mode| permission_bits.contains(*mode))
                    .ok_or(SandboxError::InvalidFileModeMask)?;
                let previous = process::umask(mode);
                outcome.previous_file_mode_mask = Some(previous.bits());
            }
        }
        // Spec: docs/50 R50-14 ("RLIMIT_CORE=0 and other rlimits"), §6.1;
        // rustix 1.1.6 process::setrlimit, Resource::{Core, Nofile, Memlock}.
        Step::SetResourceLimits => {
            if plan.disables_core_dumps() {
                process::setrlimit(Resource::Core, fixed(0)).map_err(os(step, "setrlimit"))?;
            }
            if let Some(limit) = plan.open_files_limit() {
                process::setrlimit(Resource::Nofile, fixed(limit))
                    .map_err(os(step, "setrlimit"))?;
            }
            if let Some(limit) = plan.locked_memory_limit() {
                process::setrlimit(Resource::Memlock, fixed(limit))
                    .map_err(os(step, "setrlimit"))?;
            }
        }
        // Spec: docs/50 R50-14, §6.1, §6.2; rustix 1.1.6
        // process::set_dumpable_behavior, DumpableBehavior::NotDumpable.
        Step::DisableDumpable | Step::ReassertNotDumpable => {
            process::set_dumpable_behavior(DumpableBehavior::NotDumpable)
                .map_err(os(step, "set_dumpable_behavior"))?;
        }
        // Spec: docs/50 §6.1 (keyd: mlockall against swap; mlock/madvise are
        // unsafe and unused); rustix 1.1.6 mm::mlockall, MlockAllFlags::CURRENT
        // (pages mapped now) | FUTURE (pages mapped later — keys loaded after
        // start-up).
        Step::LockAllMemory => {
            mlockall(MlockAllFlags::CURRENT | MlockAllFlags::FUTURE)
                .map_err(os(step, "mlockall"))?;
        }
        // Spec: docs/50 §6.1, §6.4; rustix 1.1.6 process::chroot (`P: Arg`;
        // `&Path` implements path::Arg).
        Step::ChangeRoot => {
            if let Some(dir) = plan.change_root() {
                process::chroot(dir).map_err(os(step, "chroot"))?;
            }
        }
        // Spec: docs/50 §6.1; rustix 1.1.6 process::chdir.
        Step::ChangeDirectory => {
            if let Some(dir) = plan.working_directory() {
                process::chdir(dir).map_err(os(step, "chdir"))?;
            }
        }
        // Spec: docs/50 §6.1 (remove_capability_from_bounding_set,
        // clear_ambient_capability_set); rustix 1.1.6
        // thread::capability_is_in_bounding_set, remove_capability_from_bounding_set
        // (needs SetPermittedCapabilities, so this runs before the identity
        // drop), clear_ambient_capability_set; one named capability at a time
        // (`named_capabilities`).
        Step::DropBoundingCapabilities => {
            for capability in named_capabilities() {
                if thread::capability_is_in_bounding_set(capability)
                    .map_err(os(step, "capability_is_in_bounding_set"))?
                {
                    thread::remove_capability_from_bounding_set(capability)
                        .map_err(os(step, "remove_capability_from_bounding_set"))?;
                }
            }
            thread::clear_ambient_capability_set()
                .map_err(os(step, "clear_ambient_capability_set"))?;
        }
        // Spec: docs/50 R50-14 (setgroups), §6.1; rustix 1.1.6
        // thread::set_thread_groups ("Sets the supplementary group IDs for the
        // calling thread").
        Step::ClearSupplementaryGroups => {
            thread::set_thread_groups(&[]).map_err(os(step, "set_thread_groups"))?;
        }
        // Spec: docs/50 R50-14, §6.1; rustix 1.1.6 thread::set_thread_res_gid
        // ("Sets the real, effective, and saved group ID"), Gid::from_raw (the
        // value was validated by ProcessIdentity::new: not 0, not -1).
        Step::SetGroupId => {
            if let Some(identity) = plan.identity() {
                let gid = Gid::from_raw(identity.gid());
                thread::set_thread_res_gid(gid, gid, gid)
                    .map_err(os(step, "set_thread_res_gid"))?;
            }
        }
        // Spec: docs/50 R50-14, §6.1; rustix 1.1.6 thread::set_thread_res_uid
        // ("Sets the real, effective, and saved user ID of the calling
        // thread"), Uid::from_raw.
        Step::SetUserId => {
            if let Some(identity) = plan.identity() {
                let uid = Uid::from_raw(identity.uid());
                thread::set_thread_res_uid(uid, uid, uid)
                    .map_err(os(step, "set_thread_res_uid"))?;
            }
        }
        // Spec: docs/50 R50-14, §6.1; rustix 1.1.6 thread::set_no_new_privs.
        Step::SetNoNewPrivs => {
            thread::set_no_new_privs(true).map_err(os(step, "set_no_new_privs"))?;
        }
        // Spec: docs/50 R50-14, §6.1 ("finish without any capability");
        // rustix 1.1.6 thread::set_capabilities (`capset(..., pid, effective,
        // permitted, inheritable)`), CapabilitySets, CapabilitySet::empty,
        // thread::gettid ("Returns the thread ID"; capabilities are documented
        // as "Linux per-thread capability", so the calling thread is named
        // explicitly — Q-235 item 1), set_keep_capabilities.
        Step::ClearCapabilitySets => {
            let none = CapabilitySets {
                effective: CapabilitySet::empty(),
                permitted: CapabilitySet::empty(),
                inheritable: CapabilitySet::empty(),
            };
            thread::set_capabilities(Some(thread::gettid()), none)
                .map_err(os(step, "set_capabilities"))?;
            thread::set_keep_capabilities(false).map_err(os(step, "set_keep_capabilities"))?;
        }
        // Spec: docs/50 R50-14; rustix 1.1.6 thread::set_thread_res_gid /
        // set_thread_res_uid with Gid::ROOT / Uid::ROOT. With no capability
        // left (thread::Capability::SetGroupID / SetUserID document what allows
        // these calls), both must be refused; success means the drop is
        // reversible and the daemon must exit. Any error counts as refused —
        // the read-back that follows confirms the ids are unchanged.
        Step::ConfirmIdentityIrreversible => {
            if thread::set_thread_res_gid(Gid::ROOT, Gid::ROOT, Gid::ROOT).is_ok() {
                return Err(SandboxError::PrivilegeRegained);
            }
            if thread::set_thread_res_uid(Uid::ROOT, Uid::ROOT, Uid::ROOT).is_ok() {
                return Err(SandboxError::PrivilegeRegained);
            }
        }
        // Performed by `crate::apply` itself (read back, then compare).
        Step::VerifyState => {}
    }
    Ok(outcome)
}

/// Read a resource limit.
// Spec: rustix 1.1.6 process::getrlimit, Rlimit.
fn limit(resource: Resource) -> LimitState {
    let value = process::getrlimit(resource);
    LimitState {
        soft: value.current,
        hard: value.maximum,
    }
}

/// Read the capability state of the calling thread. A query error is an
/// error of the read-back (fail closed), never "absent".
// Spec: rustix 1.1.6 thread::capabilities, capability_is_in_ambient_set,
// capability_is_in_bounding_set, get_keep_capabilities, gettid,
// CapabilitySet::is_empty; one named capability at a time
// (`named_capabilities`).
fn capability_state() -> Result<CapabilityState, SandboxError> {
    let step = Step::VerifyState;
    let sets = thread::capabilities(Some(thread::gettid())).map_err(os(step, "capabilities"))?;
    let mut ambient_empty = true;
    let mut bounding_empty = true;
    for capability in named_capabilities() {
        if thread::capability_is_in_ambient_set(capability)
            .map_err(os(step, "capability_is_in_ambient_set"))?
        {
            ambient_empty = false;
        }
        if thread::capability_is_in_bounding_set(capability)
            .map_err(os(step, "capability_is_in_bounding_set"))?
        {
            bounding_empty = false;
        }
    }
    Ok(CapabilityState {
        effective_empty: sets.effective.is_empty(),
        permitted_empty: sets.permitted.is_empty(),
        inheritable_empty: sets.inheritable.is_empty(),
        ambient_empty,
        bounding_empty,
        keep_capabilities: thread::get_keep_capabilities()
            .map_err(os(step, "get_keep_capabilities"))?,
    })
}

/// Read the hardening-relevant state back.
// Spec: docs/50 §6.1 ("process::getuid/geteuid/getgid to verify"); rustix
// 1.1.6 process::getuid ("the process' real user ID"), geteuid ("effective
// user ID"), getgid ("real group ID"), getegid ("effective group ID"),
// getgroups, getrlimit, dumpable_behavior ("the calling process' dumpable
// attribute"), DumpableBehavior; thread::no_new_privs ("for the calling
// thread").
pub(crate) fn read_state() -> Result<SandboxState, SandboxError> {
    let step = Step::VerifyState;
    let supplementary_groups = process::getgroups()
        .map_err(os(step, "getgroups"))?
        .into_iter()
        .map(Gid::as_raw)
        .collect();
    let dumpable = match process::dumpable_behavior().map_err(os(step, "dumpable_behavior"))? {
        DumpableBehavior::NotDumpable => DumpableState::NotDumpable,
        DumpableBehavior::Dumpable => DumpableState::Dumpable,
        DumpableBehavior::DumpableReadableOnlyByRoot => DumpableState::DumpableReadableOnlyByRoot,
    };
    Ok(SandboxState {
        real_uid: process::getuid().as_raw(),
        effective_uid: process::geteuid().as_raw(),
        real_gid: process::getgid().as_raw(),
        effective_gid: process::getegid().as_raw(),
        supplementary_groups,
        no_new_privs: thread::no_new_privs().map_err(os(step, "no_new_privs"))?,
        dumpable,
        core_limit: limit(Resource::Core),
        open_files_limit: limit(Resource::Nofile),
        locked_memory_limit: limit(Resource::Memlock),
        capabilities: capability_state()?,
    })
}
