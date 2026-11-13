//! The process state read back after hardening (docs/50 §6.1 "verify,
//! otherwise exit"): plain values, no rustix type, so the daemon can assert
//! it and the audit can record it on every target.

use std::fmt;

/// A resource limit as read back: the soft ("current") and hard ("maximum")
/// values.
// Spec: rustix 1.1.6 process::Rlimit (`current: Option<u64>` — "Current
// effective, “soft”, limit"; `maximum: Option<u64>` — "Maximum, “hard”, value
// that current may be dynamically increased to").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LimitState {
    /// The soft limit.
    pub soft: Option<u64>,
    /// The hard limit.
    pub hard: Option<u64>,
}

impl LimitState {
    /// The form every planned limit takes: soft = hard = `value`, so the
    /// process cannot raise it again (rustix: `current` may be increased only
    /// up to `maximum`).
    // Spec: rustix 1.1.6 process::Rlimit; docs/50 R50-14.
    pub const fn fixed(value: u64) -> Self {
        Self {
            soft: Some(value),
            hard: Some(value),
        }
    }
}

/// The dumpable attribute as read back.
// Spec: rustix 1.1.6 process::DumpableBehavior (NotDumpable — "Not
// dumpable."; Dumpable — "Dumpable."; DumpableReadableOnlyByRoot — "Dumpable
// but only readable by root.").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DumpableState {
    /// Not dumpable.
    NotDumpable,
    /// Dumpable.
    Dumpable,
    /// Dumpable but only readable by root.
    DumpableReadableOnlyByRoot,
}

/// The capability state of the calling thread as read back. The effective,
/// permitted and inheritable fields are true when the set has no bit at all;
/// the ambient and bounding fields are true when none of the capabilities
/// rustix names is in the set (they are queried one at a time).
// Spec: rustix 1.1.6 thread::capabilities (CapabilitySets: effective,
// permitted, inheritable), CapabilitySet::is_empty / iter_names,
// capability_is_in_ambient_set, capability_is_in_bounding_set,
// get_keep_capabilities.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapabilityState {
    /// The effective set is empty.
    pub effective_empty: bool,
    /// The permitted set is empty.
    pub permitted_empty: bool,
    /// The inheritable set is empty.
    pub inheritable_empty: bool,
    /// No capability is in the ambient set.
    pub ambient_empty: bool,
    /// No capability is in the bounding set.
    pub bounding_empty: bool,
    /// The keep-capabilities flag.
    pub keep_capabilities: bool,
}

impl CapabilityState {
    /// The state after [`Step::ClearCapabilitySets`](crate::Step::ClearCapabilitySets):
    /// every set empty, keep-capabilities off.
    // Spec: docs/50 §6.1 ("finish without any capability").
    pub const NONE: Self = Self {
        effective_empty: true,
        permitted_empty: true,
        inheritable_empty: true,
        ambient_empty: true,
        bounding_empty: true,
        keep_capabilities: false,
    };
}

/// The hardening-relevant state of the calling process, read through rustix
/// getters only.
// Spec: docs/50 §6.1; rustix 1.1.6 process::getuid ("the process' real user
// ID"), geteuid, getgid, getegid, getgroups, getrlimit, dumpable_behavior;
// thread::no_new_privs and the capability getters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SandboxState {
    /// Real uid.
    pub real_uid: u32,
    /// Effective uid.
    pub effective_uid: u32,
    /// Real gid.
    pub real_gid: u32,
    /// Effective gid.
    pub effective_gid: u32,
    /// Supplementary groups.
    pub supplementary_groups: Vec<u32>,
    /// The no_new_privs attribute of the calling thread.
    pub no_new_privs: bool,
    /// The dumpable attribute.
    pub dumpable: DumpableState,
    /// The core-file-size limit.
    pub core_limit: LimitState,
    /// The open-files limit.
    pub open_files_limit: LimitState,
    /// The locked-memory limit.
    pub locked_memory_limit: LimitState,
    /// The capability state.
    pub capabilities: CapabilityState,
}

/// The first property of a read-back state that differs from the plan.
// Spec: docs/50 §6.1 ("verify, otherwise exit").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StateMismatch {
    /// The real uid is not the target uid.
    RealUid,
    /// The effective uid is not the target uid.
    EffectiveUid,
    /// The real gid is not the target gid.
    RealGid,
    /// The effective gid is not the target gid.
    EffectiveGid,
    /// The supplementary groups are not empty.
    SupplementaryGroups,
    /// no_new_privs is not set.
    NoNewPrivs,
    /// The process is dumpable.
    Dumpable,
    /// The core-file-size limit is not 0/0.
    CoreLimit,
    /// The open-files limit is not the planned value.
    OpenFilesLimit,
    /// The locked-memory limit is not the planned value.
    LockedMemoryLimit,
    /// Some capability set is not empty, or keep-capabilities is on.
    Capabilities,
}

impl fmt::Display for StateMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            StateMismatch::RealUid => "real uid",
            StateMismatch::EffectiveUid => "effective uid",
            StateMismatch::RealGid => "real gid",
            StateMismatch::EffectiveGid => "effective gid",
            StateMismatch::SupplementaryGroups => "supplementary groups",
            StateMismatch::NoNewPrivs => "no_new_privs",
            StateMismatch::Dumpable => "dumpable",
            StateMismatch::CoreLimit => "core limit",
            StateMismatch::OpenFilesLimit => "open-files limit",
            StateMismatch::LockedMemoryLimit => "locked-memory limit",
            StateMismatch::Capabilities => "capabilities",
        })
    }
}
