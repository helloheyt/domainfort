//! The hardening plan: what to apply, validated before anything runs, and the
//! one fixed order its steps run in (docs/50 R50-14, §6.2, §6.4).
//!
//! This module is pure (no system call) and compiles on every target, so the
//! plan rules and the step order are tested everywhere.

use std::fmt;
use std::path::{Path, PathBuf};

use crate::error::PlanError;
use crate::state::{CapabilityState, DumpableState, LimitState, SandboxState, StateMismatch};

/// The file-creation mask of every daemon.
// Spec: docs/50 §6.1 ("umask 077 for all"), §6.4 (baseline).
pub const DAEMON_FILE_MODE_MASK: u32 = 0o077;

/// Upper bound of a file-creation mask: three octal digits, the notation
/// docs/50 §6.1 uses ("077"). On Linux the value is also checked against
/// rustix's own permission constants when it is applied (see
/// [`SandboxError::InvalidFileModeMask`](crate::SandboxError::InvalidFileModeMask)).
// Spec: docs/50 §6.1; rustix 1.1.6 fs::Mode (RWXU, RWXG, RWXO).
const FILE_MODE_MASK_MAX: u32 = 0o777;

/// The working directory used after a chroot when the plan names none: the
/// new root itself, so the working directory is inside it.
// Spec: rustix 1.1.6 process::chroot ("Change the process root directory")
// and process::chdir ("Change the current working directory") — two distinct
// attributes, so both are set.
const ROOT_DIRECTORY: &str = "/";

/// One step of a plan. [`HardeningPlan::steps`] lists the steps a plan
/// contains, always in the order of [`Step::ORDER`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Step {
    /// Set the process file-creation mask.
    // Spec: docs/50 §6.1; rustix 1.1.6 process::umask.
    SetFileModeMask,
    /// Set the planned resource limits (core = 0, nofile, memlock).
    // Spec: docs/50 R50-14, §6.1; rustix 1.1.6 process::setrlimit, Resource.
    SetResourceLimits,
    /// Make the process not dumpable, before the privileged-to-unprivileged
    /// transition.
    // Spec: docs/50 R50-14, §6.1; rustix 1.1.6 process::set_dumpable_behavior,
    // DumpableBehavior::NotDumpable.
    DisableDumpable,
    /// Lock all current and future pages in memory (keyd).
    // Spec: docs/50 R50-14, §6.1, §6.4; rustix 1.1.6 mm::mlockall,
    // MlockAllFlags::CURRENT | FUTURE.
    LockAllMemory,
    /// Change the process root directory.
    // Spec: docs/50 §6.1, §6.4; rustix 1.1.6 process::chroot.
    ChangeRoot,
    /// Change the working directory (after a chroot: inside the new root).
    // Spec: docs/50 §6.1; rustix 1.1.6 process::chdir.
    ChangeDirectory,
    /// Remove every capability from the bounding set and clear the ambient
    /// set.
    // Spec: docs/50 §6.1; rustix 1.1.6 thread::remove_capability_from_bounding_set,
    // thread::clear_ambient_capability_set.
    DropBoundingCapabilities,
    /// Clear the supplementary groups.
    // Spec: docs/50 R50-14, §6.1; rustix 1.1.6 thread::set_thread_groups.
    ClearSupplementaryGroups,
    /// Set the real, effective and saved gid to the target gid.
    // Spec: docs/50 R50-14, §6.1; rustix 1.1.6 thread::set_thread_res_gid.
    SetGroupId,
    /// Set the real, effective and saved uid to the target uid.
    // Spec: docs/50 R50-14, §6.1; rustix 1.1.6 thread::set_thread_res_uid.
    SetUserId,
    /// Set no_new_privs.
    // Spec: docs/50 R50-14, §6.1; rustix 1.1.6 thread::set_no_new_privs.
    SetNoNewPrivs,
    /// Empty the effective, permitted and inheritable capability sets and
    /// clear the keep-capabilities flag.
    // Spec: docs/50 R50-14, §6.1 ("finish without any capability"); rustix
    // 1.1.6 thread::set_capabilities, CapabilitySets, set_keep_capabilities.
    ClearCapabilitySets,
    /// Confirm that the uid and gid cannot be set back to 0.
    // Spec: docs/50 R50-14; rustix 1.1.6 thread::set_thread_res_gid /
    // set_thread_res_uid, Gid::ROOT / Uid::ROOT.
    ConfirmIdentityIrreversible,
    /// Set not-dumpable again at the position docs/50 §6.2 gives it (after the
    /// capabilities), because rustix does not document whether the identity
    /// change preserves the attribute (docs/questions/Q-215).
    // Spec: docs/50 §6.2; rustix 1.1.6 process::set_dumpable_behavior.
    ReassertNotDumpable,
    /// Read the state back and compare it with the plan.
    // Spec: docs/50 §6.1 ("after the drop — process::getuid/geteuid/getgid to
    // verify, otherwise exit").
    VerifyState,
}

impl Step {
    /// The one order every plan runs in. Rationale for each position (the
    /// capability names are the rustix 1.1.6 `thread::Capability` documentation
    /// of what each capability allows):
    ///
    /// 1. `SetFileModeMask` — needs no privilege; first, so it holds for
    ///    anything created from here on (docs/50 §6.1).
    /// 2. `SetResourceLimits` — while still privileged: setting a limit
    ///    (raising MEMLOCK for keyd) is what `SystemResource` allows ("Override
    ///    resource limits. Set resource limits."); docs/50 §6.1 ("MEMLOCK
    ///    before the drop") and §6.2 (setrlimit before the gid/uid drop).
    /// 3. `DisableDumpable` — before the transition, so the process that may
    ///    have read root-only material (the TLS key, docs/50 R50-12) is never
    ///    dumpable or traceable on the way down (rustix
    ///    `set_dumpable_behavior`: the attribute controls "whether the process
    ///    can be traced and whether core dumps are produced").
    /// 4. `LockAllMemory` — while privileged (`IPCLock`: "Allow mlock and
    ///    mlockall"), after the MEMLOCK limit of step 2 (docs/50 §6.1).
    /// 5. `ChangeRoot` — while privileged (`SystemChangeRoot`: "Allow use of
    ///    chroot").
    /// 6. `ChangeDirectory` — right after the chroot, so the working directory
    ///    is inside the new root.
    /// 7. `DropBoundingCapabilities` — rustix: removal from the bounding set
    ///    works "only if the thread has the SetPermittedCapabilities
    ///    capability", so it runs while the capabilities are still held.
    /// 8. `ClearSupplementaryGroups` — `SetGroupID` ("Allows setgroups");
    ///    before the uid change, since rustix does not document what the
    ///    thread still holds after it.
    /// 9. `SetGroupId` — `SetGroupID` ("Allows setgid manipulation"); before
    ///    the uid change for the same reason.
    /// 10. `SetUserId` — `SetUserID` ("Allows set*uid manipulation"); the
    ///     last identity step (docs/50 §6.2: gid/groups/uid).
    /// 11. `SetNoNewPrivs` — docs/50 §6.2 (after the uid drop).
    /// 12. `ClearCapabilitySets` — docs/50 §6.2 (after no_new_privs); last of
    ///     the privilege-reducing steps because steps 2, 4, 5, 7, 8, 9 and 10
    ///     are each allowed by a capability.
    /// 13. `ConfirmIdentityIrreversible` — with no capability left, setting
    ///     the ids back to 0 must be refused.
    /// 14. `ReassertNotDumpable` — docs/50 §6.2 places non-dumpable after the
    ///     capabilities; repeated because its preservation across the
    ///     identity change is undocumented in rustix (Q-215).
    /// 15. `VerifyState` — always last.
    // Spec: docs/50 R50-14, §6.1, §6.2, §6.4; rustix 1.1.6 thread::Capability
    // (deprecated enum, documentation of each variant),
    // thread::remove_capability_from_bounding_set, process::set_dumpable_behavior.
    pub const ORDER: [Step; 15] = [
        Step::SetFileModeMask,
        Step::SetResourceLimits,
        Step::DisableDumpable,
        Step::LockAllMemory,
        Step::ChangeRoot,
        Step::ChangeDirectory,
        Step::DropBoundingCapabilities,
        Step::ClearSupplementaryGroups,
        Step::SetGroupId,
        Step::SetUserId,
        Step::SetNoNewPrivs,
        Step::ClearCapabilitySets,
        Step::ConfirmIdentityIrreversible,
        Step::ReassertNotDumpable,
        Step::VerifyState,
    ];

    /// A fixed name for logs and the audit record.
    pub const fn name(self) -> &'static str {
        match self {
            Step::SetFileModeMask => "set-file-mode-mask",
            Step::SetResourceLimits => "set-resource-limits",
            Step::DisableDumpable => "disable-dumpable",
            Step::LockAllMemory => "lock-all-memory",
            Step::ChangeRoot => "change-root",
            Step::ChangeDirectory => "change-directory",
            Step::DropBoundingCapabilities => "drop-bounding-capabilities",
            Step::ClearSupplementaryGroups => "clear-supplementary-groups",
            Step::SetGroupId => "set-group-id",
            Step::SetUserId => "set-user-id",
            Step::SetNoNewPrivs => "set-no-new-privs",
            Step::ClearCapabilitySets => "clear-capability-sets",
            Step::ConfirmIdentityIrreversible => "confirm-identity-irreversible",
            Step::ReassertNotDumpable => "reassert-not-dumpable",
            Step::VerifyState => "verify-state",
        }
    }
}

impl fmt::Display for Step {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The unprivileged account a daemon runs as after the drop: a numeric uid and
/// gid (docs/50 §7.1: "uids/gids are numeric, no NSS lookup").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessIdentity {
    uid: u32,
    gid: u32,
}

impl ProcessIdentity {
    /// The all-ones raw value, which rustix documents as invalid ("not -1"
    /// for the unsigned `c_uint` raw type).
    // Spec: rustix 1.1.6 thread::Uid::from_raw, thread::Gid::from_raw,
    // thread::RawUid (`c_uint`).
    const INVALID_RAW: u32 = u32::MAX;

    /// A target identity. Refuses 0 (root: not a drop) and the invalid raw
    /// value.
    // Spec: rustix 1.1.6 thread::Uid::ROOT / Gid::ROOT, Uid::from_raw /
    // Gid::from_raw; docs/50 §2.4, §3.2.
    pub fn new(uid: u32, gid: u32) -> Result<Self, PlanError> {
        if uid == Self::INVALID_RAW || gid == Self::INVALID_RAW {
            return Err(PlanError::InvalidIdentity);
        }
        if uid == 0 || gid == 0 {
            return Err(PlanError::RootIdentity);
        }
        Ok(Self { uid, gid })
    }

    /// The target uid.
    pub const fn uid(self) -> u32 {
        self.uid
    }

    /// The target gid.
    pub const fn gid(self) -> u32 {
        self.gid
    }
}

/// What to apply to the calling process. Built and validated by
/// [`HardeningPlanBuilder::build`]; immutable afterwards.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HardeningPlan {
    identity: Option<ProcessIdentity>,
    no_new_privs: bool,
    drop_capabilities: bool,
    disable_core_dumps: bool,
    open_files_limit: Option<u64>,
    locked_memory_limit: Option<u64>,
    not_dumpable: bool,
    lock_all_memory: bool,
    file_mode_mask: Option<u32>,
    change_root: Option<PathBuf>,
    working_directory: Option<PathBuf>,
}

impl HardeningPlan {
    /// An empty builder: every step off.
    pub fn builder() -> HardeningPlanBuilder {
        HardeningPlanBuilder::default()
    }

    /// A builder preloaded with the docs/50 §6.4 baseline every daemon gets:
    /// run as `identity` with the supplementary groups cleared, no_new_privs,
    /// no capabilities, core limit 0, not dumpable, file-creation mask 077.
    /// Per-daemon additions (nofile, memlock + mlockall for keyd, chroot) are
    /// added on the returned builder.
    // Spec: docs/50 R50-14, §6.4 (baseline row).
    pub fn daemon_baseline(identity: ProcessIdentity) -> HardeningPlanBuilder {
        HardeningPlanBuilder::default()
            .drop_identity(identity)
            .no_new_privs()
            .drop_capabilities()
            .disable_core_dumps()
            .not_dumpable()
            .file_mode_mask(DAEMON_FILE_MODE_MASK)
    }

    /// The steps this plan contains, in [`Step::ORDER`]; always ends with
    /// [`Step::VerifyState`].
    pub fn steps(&self) -> Vec<Step> {
        Step::ORDER
            .iter()
            .copied()
            .filter(|step| self.contains(*step))
            .collect()
    }

    /// Whether the plan contains `step`.
    pub fn contains(&self, step: Step) -> bool {
        let identity = self.identity.is_some();
        match step {
            Step::SetFileModeMask => self.file_mode_mask.is_some(),
            Step::SetResourceLimits => {
                self.disable_core_dumps
                    || self.open_files_limit.is_some()
                    || self.locked_memory_limit.is_some()
            }
            Step::DisableDumpable => self.not_dumpable,
            Step::LockAllMemory => self.lock_all_memory,
            Step::ChangeRoot => self.change_root.is_some(),
            Step::ChangeDirectory => self.working_directory().is_some(),
            Step::DropBoundingCapabilities | Step::ClearCapabilitySets => self.drop_capabilities,
            Step::ClearSupplementaryGroups
            | Step::SetGroupId
            | Step::SetUserId
            | Step::ConfirmIdentityIrreversible => identity,
            Step::SetNoNewPrivs => self.no_new_privs,
            // Only meaningful when a privilege-changing step precedes it
            // (see `Step::ReassertNotDumpable`).
            Step::ReassertNotDumpable => self.not_dumpable && (identity || self.drop_capabilities),
            Step::VerifyState => true,
        }
    }

    /// The target identity, if the plan drops to one.
    pub fn identity(&self) -> Option<ProcessIdentity> {
        self.identity
    }

    /// Whether no_new_privs is set.
    pub fn sets_no_new_privs(&self) -> bool {
        self.no_new_privs
    }

    /// Whether every capability is dropped.
    pub fn drops_capabilities(&self) -> bool {
        self.drop_capabilities
    }

    /// Whether the core-file-size limit is set to 0.
    pub fn disables_core_dumps(&self) -> bool {
        self.disable_core_dumps
    }

    /// The open-files limit (soft = hard), if planned.
    pub fn open_files_limit(&self) -> Option<u64> {
        self.open_files_limit
    }

    /// The locked-memory limit in bytes (soft = hard), if planned.
    pub fn locked_memory_limit(&self) -> Option<u64> {
        self.locked_memory_limit
    }

    /// Whether the process is made not dumpable.
    pub fn makes_not_dumpable(&self) -> bool {
        self.not_dumpable
    }

    /// Whether all memory is locked (mlockall).
    pub fn locks_all_memory(&self) -> bool {
        self.lock_all_memory
    }

    /// The file-creation mask, if planned.
    pub fn file_mode_mask(&self) -> Option<u32> {
        self.file_mode_mask
    }

    /// The new root directory, if planned.
    pub fn change_root(&self) -> Option<&Path> {
        self.change_root.as_deref()
    }

    /// The directory changed to by [`Step::ChangeDirectory`]: the planned
    /// working directory, or `/` (the new root) after a chroot that names
    /// none. After a chroot the path is resolved inside the new root.
    pub fn working_directory(&self) -> Option<&Path> {
        match (&self.working_directory, &self.change_root) {
            (Some(dir), _) => Some(dir.as_path()),
            (None, Some(_)) => Some(Path::new(ROOT_DIRECTORY)),
            (None, None) => None,
        }
    }

    /// Compare a read-back state with this plan. Checks only what the plan
    /// sets; returns the first property that differs. The file-creation mask
    /// is not part of the state (rustix's `umask` only sets the mask and
    /// returns the previous one, so reading it would mean changing it).
    // Spec: docs/50 §6.1 ("verify, otherwise exit"), R50-14; rustix 1.1.6
    // process::getuid / geteuid / getgid / getegid / getgroups / getrlimit /
    // dumpable_behavior, thread::no_new_privs / capabilities /
    // capability_is_in_bounding_set / capability_is_in_ambient_set /
    // get_keep_capabilities.
    pub fn check(&self, state: &SandboxState) -> Result<(), StateMismatch> {
        if let Some(identity) = self.identity {
            if state.real_uid != identity.uid() {
                return Err(StateMismatch::RealUid);
            }
            if state.effective_uid != identity.uid() {
                return Err(StateMismatch::EffectiveUid);
            }
            if state.real_gid != identity.gid() {
                return Err(StateMismatch::RealGid);
            }
            if state.effective_gid != identity.gid() {
                return Err(StateMismatch::EffectiveGid);
            }
            if !state.supplementary_groups.is_empty() {
                return Err(StateMismatch::SupplementaryGroups);
            }
        }
        if self.no_new_privs && !state.no_new_privs {
            return Err(StateMismatch::NoNewPrivs);
        }
        if self.not_dumpable && state.dumpable != DumpableState::NotDumpable {
            return Err(StateMismatch::Dumpable);
        }
        if self.disable_core_dumps && state.core_limit != LimitState::fixed(0) {
            return Err(StateMismatch::CoreLimit);
        }
        if let Some(limit) = self.open_files_limit {
            if state.open_files_limit != LimitState::fixed(limit) {
                return Err(StateMismatch::OpenFilesLimit);
            }
        }
        if let Some(limit) = self.locked_memory_limit {
            if state.locked_memory_limit != LimitState::fixed(limit) {
                return Err(StateMismatch::LockedMemoryLimit);
            }
        }
        if self.drop_capabilities && state.capabilities != CapabilityState::NONE {
            return Err(StateMismatch::Capabilities);
        }
        Ok(())
    }
}

/// Builds a [`HardeningPlan`]. Every step is off until requested;
/// [`HardeningPlan::daemon_baseline`] starts from the docs/50 §6.4 baseline.
#[derive(Clone, Debug, Default)]
pub struct HardeningPlanBuilder {
    identity: Option<ProcessIdentity>,
    no_new_privs: bool,
    drop_capabilities: bool,
    disable_core_dumps: bool,
    open_files_limit: Option<u64>,
    locked_memory_limit: Option<u64>,
    not_dumpable: bool,
    lock_all_memory: bool,
    file_mode_mask: Option<u32>,
    change_root: Option<PathBuf>,
    working_directory: Option<PathBuf>,
}

impl HardeningPlanBuilder {
    /// Drop to `identity`: supplementary groups cleared, then real/effective/
    /// saved gid, then real/effective/saved uid. Requires
    /// [`drop_capabilities`](Self::drop_capabilities) and
    /// [`no_new_privs`](Self::no_new_privs) (docs/50 §6.4).
    // Spec: docs/50 R50-14, §6.1; rustix 1.1.6 thread::set_thread_groups,
    // set_thread_res_gid, set_thread_res_uid.
    pub fn drop_identity(mut self, identity: ProcessIdentity) -> Self {
        self.identity = Some(identity);
        self
    }

    /// Set no_new_privs.
    // Spec: docs/50 R50-14; rustix 1.1.6 thread::set_no_new_privs.
    pub fn no_new_privs(mut self) -> Self {
        self.no_new_privs = true;
        self
    }

    /// Drop every capability: bounding set, ambient set, and the effective,
    /// permitted and inheritable sets.
    // Spec: docs/50 R50-14, §6.1.
    pub fn drop_capabilities(mut self) -> Self {
        self.drop_capabilities = true;
        self
    }

    /// Set the core-file-size limit to 0 (soft and hard).
    // Spec: docs/50 R50-14 ("RLIMIT_CORE=0"), §6.1; rustix 1.1.6
    // process::Resource::Core.
    pub fn disable_core_dumps(mut self) -> Self {
        self.disable_core_dumps = true;
        self
    }

    /// Set the open-files limit to `limit` (soft and hard), sized from the
    /// daemon's connection quotas. Must not be 0.
    // Spec: docs/50 §6.1 ("nofile according to the connection quotas"), §6.4
    // (keyd: small nofile); rustix 1.1.6 process::Resource::Nofile, Rlimit.
    pub fn open_files_limit(mut self, limit: u64) -> Self {
        self.open_files_limit = Some(limit);
        self
    }

    /// Set the locked-memory limit to `bytes` (soft and hard). Required with
    /// [`lock_all_memory`](Self::lock_all_memory).
    // Spec: docs/50 §6.1 ("keyd — also MEMLOCK before the drop"); rustix 1.1.6
    // process::Resource::Memlock, Rlimit.
    pub fn locked_memory_limit(mut self, bytes: u64) -> Self {
        self.locked_memory_limit = Some(bytes);
        self
    }

    /// Make the process not dumpable.
    // Spec: docs/50 R50-14, §6.1 (all, keyd in particular); rustix 1.1.6
    // process::set_dumpable_behavior.
    pub fn not_dumpable(mut self) -> Self {
        self.not_dumpable = true;
        self
    }

    /// Lock all current and future memory (opt-in: keyd, admind).
    // Spec: docs/50 R50-14, §6.1, §6.4; rustix 1.1.6 mm::mlockall.
    pub fn lock_all_memory(mut self) -> Self {
        self.lock_all_memory = true;
        self
    }

    /// Set the file-creation mask (three octal digits; docs/50: `0o077`).
    // Spec: docs/50 §6.1; rustix 1.1.6 process::umask.
    pub fn file_mode_mask(mut self, mask: u32) -> Self {
        self.file_mode_mask = Some(mask);
        self
    }

    /// Change the root directory to `dir` (absolute). The working directory
    /// then changes to `/` inside it unless
    /// [`working_directory`](Self::working_directory) names another.
    // Spec: docs/50 §6.1, §6.4 (keyd, auditd); rustix 1.1.6 process::chroot.
    pub fn change_root(mut self, dir: impl Into<PathBuf>) -> Self {
        self.change_root = Some(dir.into());
        self
    }

    /// Change the working directory to `dir` (absolute; after a chroot,
    /// resolved inside the new root).
    // Spec: docs/50 §6.1; rustix 1.1.6 process::chdir.
    pub fn working_directory(mut self, dir: impl Into<PathBuf>) -> Self {
        self.working_directory = Some(dir.into());
        self
    }

    /// Validate and freeze the plan.
    // Spec: docs/50 R50-14, §6.1, §6.4; docs/03 principles (fail closed).
    pub fn build(self) -> Result<HardeningPlan, PlanError> {
        let plan = HardeningPlan {
            identity: self.identity,
            no_new_privs: self.no_new_privs,
            drop_capabilities: self.drop_capabilities,
            disable_core_dumps: self.disable_core_dumps,
            open_files_limit: self.open_files_limit,
            locked_memory_limit: self.locked_memory_limit,
            not_dumpable: self.not_dumpable,
            lock_all_memory: self.lock_all_memory,
            file_mode_mask: self.file_mode_mask,
            change_root: self.change_root,
            working_directory: self.working_directory,
        };
        if plan.steps() == [Step::VerifyState] {
            return Err(PlanError::NoHardeningStep);
        }
        if plan.identity.is_some() && !(plan.drop_capabilities && plan.no_new_privs) {
            return Err(PlanError::IdentityDropIncomplete);
        }
        if plan.lock_all_memory && plan.locked_memory_limit.is_none() {
            return Err(PlanError::MemoryLockWithoutLimit);
        }
        if plan.open_files_limit == Some(0) {
            return Err(PlanError::ZeroOpenFilesLimit);
        }
        if matches!(plan.file_mode_mask, Some(mask) if mask > FILE_MODE_MASK_MAX) {
            return Err(PlanError::FileModeMaskOutOfRange);
        }
        let relative = |p: &Option<PathBuf>| p.as_deref().is_some_and(|p| !p.is_absolute());
        if relative(&plan.change_root) || relative(&plan.working_directory) {
            return Err(PlanError::RelativePath);
        }
        Ok(plan)
    }
}

#[cfg(test)]
mod tests {
    //! Plan rules and step order. Sources: docs/50 R50-14, §6.1, §6.2, §6.4
    //! (the baseline and the order); rustix 1.1.6 API docs (the capability
    //! each step needs, the Uid/Gid preconditions, Rlimit's soft/hard fields).

    use super::*;

    fn identity() -> ProcessIdentity {
        // Arbitrary unprivileged ids (project test values).
        match ProcessIdentity::new(4001, 4002) {
            Ok(id) => id,
            Err(e) => panic!("valid identity refused: {e}"),
        }
    }

    fn build(builder: HardeningPlanBuilder) -> HardeningPlan {
        match builder.build() {
            Ok(plan) => plan,
            Err(e) => panic!("valid plan refused: {e}"),
        }
    }

    fn baseline_state() -> SandboxState {
        SandboxState {
            real_uid: 4001,
            effective_uid: 4001,
            real_gid: 4002,
            effective_gid: 4002,
            supplementary_groups: Vec::new(),
            no_new_privs: true,
            dumpable: DumpableState::NotDumpable,
            core_limit: LimitState::fixed(0),
            open_files_limit: LimitState::fixed(64),
            locked_memory_limit: LimitState::fixed(1 << 20),
            capabilities: CapabilityState::NONE,
        }
    }

    // Source: docs/50 §6.4 baseline + §6.2 order.
    #[test]
    fn baseline_steps_in_documented_order() {
        let plan = build(HardeningPlan::daemon_baseline(identity()));
        assert_eq!(
            plan.steps(),
            vec![
                Step::SetFileModeMask,
                Step::SetResourceLimits,
                Step::DisableDumpable,
                Step::DropBoundingCapabilities,
                Step::ClearSupplementaryGroups,
                Step::SetGroupId,
                Step::SetUserId,
                Step::SetNoNewPrivs,
                Step::ClearCapabilitySets,
                Step::ConfirmIdentityIrreversible,
                Step::ReassertNotDumpable,
                Step::VerifyState,
            ]
        );
        assert_eq!(plan.file_mode_mask(), Some(0o077));
        assert!(plan.disables_core_dumps());
        assert!(plan.sets_no_new_privs());
        assert!(plan.drops_capabilities());
        assert!(plan.makes_not_dumpable());
        assert!(!plan.locks_all_memory());
        assert_eq!(plan.identity(), Some(identity()));
        assert_eq!(plan.working_directory(), None);
    }

    // Source: docs/50 §6.4 (keyd: mlockall, chroot, small nofile; MEMLOCK
    // before the drop, §6.1) + the rustix capability rationale of Step::ORDER.
    #[test]
    fn keyd_style_plan_uses_every_step_in_order() {
        let plan = build(
            HardeningPlan::daemon_baseline(identity())
                .open_files_limit(64)
                .locked_memory_limit(1 << 20)
                .lock_all_memory()
                .change_root("/var/empty-keyd"),
        );
        assert_eq!(plan.steps(), Step::ORDER.to_vec());
        assert_eq!(plan.working_directory(), Some(Path::new("/")));
        assert_eq!(plan.change_root(), Some(Path::new("/var/empty-keyd")));
    }

    // Source: rustix 1.1.6 thread::Capability docs (SystemResource, IPCLock,
    // SystemChangeRoot, SetPermittedCapabilities via
    // remove_capability_from_bounding_set, SetGroupID, SetUserID): every step
    // a capability allows comes before the capability sets are cleared and
    // before the uid changes.
    #[test]
    fn privileged_steps_precede_identity_and_capability_drop() {
        let position = |step: Step| Step::ORDER.iter().position(|s| *s == step);
        let needs_capability = [
            Step::SetResourceLimits,
            Step::LockAllMemory,
            Step::ChangeRoot,
            Step::DropBoundingCapabilities,
            Step::ClearSupplementaryGroups,
            Step::SetGroupId,
        ];
        for step in needs_capability {
            assert!(position(step) < position(Step::SetUserId), "{step}");
        }
        assert!(position(Step::SetUserId) < position(Step::ClearCapabilitySets));
        assert!(position(Step::SetResourceLimits) < position(Step::LockAllMemory));
        assert!(position(Step::ChangeRoot) < position(Step::ChangeDirectory));
        assert!(position(Step::DisableDumpable) < position(Step::SetUserId));
        assert!(position(Step::ClearCapabilitySets) < position(Step::ConfirmIdentityIrreversible));
        assert_eq!(Step::ORDER.last(), Some(&Step::VerifyState));
    }

    // Source: task P3 (the unprivileged subset run in CI) — umask, rlimits,
    // dumpable off, no_new_privs; no identity or capability step.
    #[test]
    fn unprivileged_subset_order() {
        let plan = build(
            HardeningPlan::builder()
                .file_mode_mask(DAEMON_FILE_MODE_MASK)
                .disable_core_dumps()
                .open_files_limit(256)
                .not_dumpable()
                .no_new_privs(),
        );
        assert_eq!(
            plan.steps(),
            vec![
                Step::SetFileModeMask,
                Step::SetResourceLimits,
                Step::DisableDumpable,
                Step::SetNoNewPrivs,
                Step::VerifyState,
            ]
        );
    }

    // Source: docs/50 §6.1 (chdir), §6.4.
    #[test]
    fn working_directory_alone_and_after_chroot() {
        let plan = build(HardeningPlan::builder().working_directory("/srv"));
        assert_eq!(plan.steps(), vec![Step::ChangeDirectory, Step::VerifyState]);
        let plan = build(
            HardeningPlan::builder()
                .change_root("/jail")
                .working_directory("/inside"),
        );
        assert_eq!(
            plan.steps(),
            vec![Step::ChangeRoot, Step::ChangeDirectory, Step::VerifyState]
        );
        assert_eq!(plan.working_directory(), Some(Path::new("/inside")));
    }

    // Source: docs/50 R50-14 (every daemon hardens).
    #[test]
    fn empty_plan_refused() {
        assert_eq!(
            HardeningPlan::builder().build(),
            Err(PlanError::NoHardeningStep)
        );
    }

    // Source: rustix 1.1.6 Uid::ROOT / Gid::ROOT ("uid 0" / "gid 0"),
    // Uid::from_raw / Gid::from_raw ("not -1"); docs/50 §3.2.
    #[test]
    fn identity_rules() {
        assert_eq!(ProcessIdentity::new(0, 5), Err(PlanError::RootIdentity));
        assert_eq!(ProcessIdentity::new(5, 0), Err(PlanError::RootIdentity));
        assert_eq!(
            ProcessIdentity::new(u32::MAX, 5),
            Err(PlanError::InvalidIdentity)
        );
        assert_eq!(
            ProcessIdentity::new(5, u32::MAX),
            Err(PlanError::InvalidIdentity)
        );
        let id = identity();
        assert_eq!((id.uid(), id.gid()), (4001, 4002));
    }

    // Source: docs/50 §6.4 (identity drop, no_new_privs and no capabilities
    // form one baseline).
    #[test]
    fn identity_drop_requires_capabilities_and_no_new_privs() {
        let no_caps = HardeningPlan::builder()
            .drop_identity(identity())
            .no_new_privs()
            .build();
        assert_eq!(no_caps, Err(PlanError::IdentityDropIncomplete));
        let no_nnp = HardeningPlan::builder()
            .drop_identity(identity())
            .drop_capabilities()
            .build();
        assert_eq!(no_nnp, Err(PlanError::IdentityDropIncomplete));
    }

    // Source: docs/50 §6.1 (mlockall with MEMLOCK set before the drop).
    #[test]
    fn mlockall_requires_memlock_limit() {
        assert_eq!(
            HardeningPlan::builder().lock_all_memory().build(),
            Err(PlanError::MemoryLockWithoutLimit)
        );
        let plan = build(
            HardeningPlan::builder()
                .lock_all_memory()
                .locked_memory_limit(1 << 20),
        );
        assert_eq!(
            plan.steps(),
            vec![
                Step::SetResourceLimits,
                Step::LockAllMemory,
                Step::VerifyState
            ]
        );
    }

    // Source: docs/50 §6.1 (nofile from connection quotas).
    #[test]
    fn zero_open_files_limit_refused() {
        assert_eq!(
            HardeningPlan::builder().open_files_limit(0).build(),
            Err(PlanError::ZeroOpenFilesLimit)
        );
    }

    // Source: docs/50 §6.1 ("umask 077": three octal digits).
    #[test]
    fn file_mode_mask_range() {
        assert_eq!(
            HardeningPlan::builder().file_mode_mask(0o1000).build(),
            Err(PlanError::FileModeMaskOutOfRange)
        );
        assert!(HardeningPlan::builder()
            .file_mode_mask(0o777)
            .build()
            .is_ok());
    }

    // Source: docs/50 §7.1 (absolute paths).
    #[test]
    fn relative_paths_refused() {
        assert_eq!(
            HardeningPlan::builder().change_root("jail").build(),
            Err(PlanError::RelativePath)
        );
        assert_eq!(
            HardeningPlan::builder().working_directory("srv").build(),
            Err(PlanError::RelativePath)
        );
    }

    // Source: docs/50 §6.1 ("verify, otherwise exit").
    #[test]
    fn check_accepts_matching_state() {
        let plan = build(
            HardeningPlan::daemon_baseline(identity())
                .open_files_limit(64)
                .locked_memory_limit(1 << 20)
                .lock_all_memory(),
        );
        assert_eq!(plan.check(&baseline_state()), Ok(()));
    }

    // Source: docs/50 §6.1, R50-14 — each property the plan sets is checked.
    #[test]
    fn check_reports_each_mismatch() {
        let plan = build(
            HardeningPlan::daemon_baseline(identity())
                .open_files_limit(64)
                .locked_memory_limit(1 << 20)
                .lock_all_memory(),
        );
        type Mutation = fn(&mut SandboxState);
        let cases: [(Mutation, StateMismatch); 12] = [
            (|s| s.real_uid = 0, StateMismatch::RealUid),
            (|s| s.effective_uid = 0, StateMismatch::EffectiveUid),
            (|s| s.real_gid = 0, StateMismatch::RealGid),
            (|s| s.effective_gid = 0, StateMismatch::EffectiveGid),
            (
                |s| s.supplementary_groups = vec![10],
                StateMismatch::SupplementaryGroups,
            ),
            (|s| s.no_new_privs = false, StateMismatch::NoNewPrivs),
            (
                |s| s.dumpable = DumpableState::Dumpable,
                StateMismatch::Dumpable,
            ),
            (
                |s| {
                    s.core_limit = LimitState {
                        soft: Some(0),
                        hard: None,
                    }
                },
                StateMismatch::CoreLimit,
            ),
            (
                |s| s.open_files_limit = LimitState::fixed(65),
                StateMismatch::OpenFilesLimit,
            ),
            (
                |s| {
                    s.locked_memory_limit = LimitState {
                        soft: Some(1 << 20),
                        hard: Some(1 << 21),
                    }
                },
                StateMismatch::LockedMemoryLimit,
            ),
            (
                |s| s.capabilities.bounding_empty = false,
                StateMismatch::Capabilities,
            ),
            (
                |s| s.capabilities.keep_capabilities = true,
                StateMismatch::Capabilities,
            ),
        ];
        for (mutate, expected) in cases {
            let mut state = baseline_state();
            mutate(&mut state);
            assert_eq!(plan.check(&state), Err(expected));
        }
    }

    // Source: docs/50 §6.1 — only what the plan sets is required.
    #[test]
    fn check_ignores_properties_outside_the_plan() {
        let plan = build(HardeningPlan::builder().no_new_privs());
        let mut state = baseline_state();
        state.real_uid = 0;
        state.supplementary_groups = vec![0, 10];
        state.dumpable = DumpableState::Dumpable;
        state.capabilities.effective_empty = false;
        assert_eq!(plan.check(&state), Ok(()));
        state.no_new_privs = false;
        assert_eq!(plan.check(&state), Err(StateMismatch::NoNewPrivs));
    }

    #[test]
    fn step_names_are_unique() {
        let mut names: Vec<&str> = Step::ORDER.iter().map(|s| s.name()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), Step::ORDER.len());
    }
}
