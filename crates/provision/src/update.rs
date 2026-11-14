//! `provision policy`: the offline tier-map edit (R51-21, decided A-80 /
//! Q-299 (a)) and the activation of the online path's `policy.next` (Q-299
//! (b), task A16) — as root, with dird and kdc stopped.
//!
//! # The edit (`provision policy --policy-path <path> <change> …`)
//!
//! 1. The policy file must be a regular file (not a link), owned by root,
//!    not writable by group or others, and decode (policy-store
//!    `read_file`, the daemons' own loader); anything else is refused.
//! 2. The edit ([`crate::policy::edit_tier_map`] — crate policy-store's one
//!    tier-map edit, the edit dird's online path uses too): add / remove
//!    rows, bump `policy_version`.
//! 3. The installation ([`install_policy_file`]).
//!
//! # The activation (`provision policy --activate-next --dird-config <path>`)
//!
//! dird's admin service writes an approved, dual-controlled tier-map change
//! as `policy.next` (docs/51 §5.10); activating it is root's:
//!
//! 1. dird's configuration file is read (root-owned, the configuration-file
//!    rule, dird's own schema): the installed policy is `policy_store_path`,
//!    `policy.next` is `policy_next_path`, and its owner is dird's account
//!    (`run_as_uid`) — the file dird itself reads, so the two cannot
//!    disagree on a path or an owner;
//! 2. the installed policy is loaded as in the edit (root's);
//! 3. `policy.next` is read **through crates/protected-file with dird's
//!    account as its owner**: its path walked from `/` (no link in any
//!    component; every directory root's or dird's, none writable by group
//!    or others), the file inspected without following a link, opened with
//!    `O_NOFOLLOW`, a regular file owned by dird's account and not writable
//!    by group or others — then decoded and validated by the policy
//!    format's own decoder (policy-store `read_file`);
//! 4. it must be a **tier-map successor** of the installed policy
//!    (policy-store `check_tier_map_successor`: version = installed + 1, the
//!    rule set, the anonymous allowlist and the mandatory-FAST entry
//!    unchanged, a Tier0 principal left) — exactly what the online path can
//!    express; a malformed, older, equal, version-skipping or
//!    rule-changing file is refused and nothing is installed;
//! 5. the installation ([`install_policy_file`], the edit's installer) of
//!    the validated policy, re-encoded;
//! 6. `policy.next` is removed (relative to its walked directory, never
//!    following a link) and its directory `fsync`ed.
//!
//! An activation interrupted after step 5 is completed by running it again:
//! a `policy.next` equal to the installed policy is recognised as already
//! installed and only removed. Restart remains manual: dird and kdc must
//! both be restarted (no reload; A-69).
//!
//! # The installer (shared)
//!
//! A new file `<name>.next` beside the installed policy (created
//! exclusively without following links; a leftover from an interrupted run
//! is refused, never reused), root:0644, `fsync`; then renamed over the old
//! file and the directory `fsync`ed. A crash leaves either the old file
//! (plus possibly the `.next` file, which a re-run refuses until removed)
//! or the new one — never a torn file. (`<name>.next` is root's staging
//! file in root's policy directory; dird's `policy.next` is another file in
//! a directory of dird's own.)
//!
//! Every filesystem step goes through crates/protected-file (task R11c,
//! docs/questions Q-532 item 2): paths walked from `/`, every step relative
//! to the walked directory — never a lookup of the path from the current
//! directory.
//!
//! Signing: the installed file is the unsigned development format; where a
//! signature must attach once Q-219's algorithm and key custody are decided
//! is docs/questions/Q-593.
//!
//! Spec: docs/51 §5.10 (R51-21); A-80; A-69; Q-270 item 2(b); Q-299;
//! policy-store `read_file`, `check_tier_map_successor`; A-109 (Q-532 item
//! 2); A-113; docs/questions/Q-590, Q-591, Q-593; rustix docs.rs (P-2).

use core::fmt;
use std::io::Write;
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};

use pdp::PolicyVersion;
use policy_store::{check_tier_map_successor, tier_map_difference, SuccessorError, TierChange};
use protected_file::{EntryError, NewFileMode, PathBreak};

use crate::first_admin::root_files::{read_dird_settings, RootFileError};
use crate::input::FilePath;
use crate::ownership::{Ownership, OwnershipError, Staged};
use crate::plan::Owner;
use crate::policy::{edit_tier_map, EditError};

/// The fixed notice printed after an edit or an activation. Spec: A-69;
/// docs/51 §5.10.
pub const RESTART_NOTICE: &str =
    "dird and kdc must both be restarted to load the new policy (no reload; the kdc refuses a policy version different from dird's, A-69)";

/// Why the edit (or the installation) was refused or failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateError {
    /// The policy path is not a regular file (or is a link), or nothing is
    /// there.
    NotRegular,
    /// A directory on the policy's path is a link or not a directory, is not
    /// root's, or is writable by group or others (task R11c).
    Path(PathBreak),
    /// The policy file could not be loaded (permissions, decoding).
    Load(policy_store::LoadError),
    /// The edit was refused.
    Edit(EditError),
    /// The `.next` file could not be created (it may exist from an
    /// interrupted run).
    Next(PathBuf, EntryError),
    /// Another filesystem step failed; the `.next` file may remain.
    Io(&'static str, EntryError),
    /// Writing the `.next` file failed; it remains.
    Write(std::io::ErrorKind),
    /// The owner of the `.next` file could not be changed; it remains.
    Ownership(OwnershipError),
    /// The validated policy could not be encoded (cannot happen for a value
    /// the format decoded).
    Encode(policy_store::PolicyError),
}

impl fmt::Display for UpdateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UpdateError::NotRegular => f.write_str("the policy path is not a regular file"),
            UpdateError::Path(path) => write!(f, "the policy file's path {path}"),
            UpdateError::Load(e) => write!(f, "{e}"),
            UpdateError::Edit(e) => write!(f, "{e}"),
            UpdateError::Next(p, e) => write!(
                f,
                "{} could not be created ({e}); if it is left from an interrupted run, remove it",
                p.display()
            ),
            UpdateError::Io(op, e) => write!(f, "{op} failed: {e}"),
            UpdateError::Write(kind) => write!(f, "write failed: {kind}"),
            UpdateError::Ownership(e) => write!(f, "{e}"),
            UpdateError::Encode(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for UpdateError {}

/// The `.next` path beside `path`.
fn next_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(".next");
    path.with_file_name(name)
}

/// The directory `path` lies in (`/` for a top-level name).
fn parent_of(path: &Path) -> &Path {
    path.parent().unwrap_or_else(|| Path::new("/"))
}

/// The installed policy at `path` (root's): a regular file, loaded and
/// decoded by the daemons' own loader.
fn load_installed(path: &Path, root: u32) -> Result<policy_store::DevelopmentPolicy, UpdateError> {
    match protected_file::entry_facts(path, root) {
        Ok(Some(facts)) if facts.regular_file => {}
        Ok(_) | Err(EntryError::Io(_)) => return Err(UpdateError::NotRegular),
        Err(EntryError::Path(broken)) => return Err(UpdateError::Path(broken)),
    }
    policy_store::read_file(path, root).map_err(UpdateError::Load)
}

/// Install `bytes` as the policy file at `path` (module documentation, "the
/// installer"): the one installer of the edit and of the activation.
///
/// # Errors
/// [`UpdateError`].
///
/// Spec: docs/51 §5.10 (A-80: "write atomically"); A-109 (Q-532 item 2).
pub fn install_policy_file<O: Ownership>(
    path: &Path,
    bytes: &[u8],
    ownership: &mut O,
) -> Result<(), UpdateError> {
    let root = ownership.root_uid();
    let staged = next_path(path);
    let mut file =
        protected_file::create_new_file(&staged, root, NewFileMode::OwnerWriteEveryoneRead)
            .map_err(|e| UpdateError::Next(staged.clone(), e))?;
    file.write_all(bytes)
        .map_err(|e| UpdateError::Write(e.kind()))?;
    ownership
        .change_owner(file.as_fd(), Staged::PolicyUpdate, Owner::ROOT)
        .map_err(UpdateError::Ownership)?;
    rustix::fs::fsync(&file)
        .map_err(|errno| UpdateError::Io("fsync", EntryError::Io(errno.kind())))?;
    drop(file);
    protected_file::rename_replace(&staged, root, path, root)
        .map_err(|e| UpdateError::Io("rename", e))?;
    protected_file::sync_directory(parent_of(path), root).map_err(|e| UpdateError::Io("fsync", e))
}

/// Edit the tier map of the policy file at `path` (module documentation)
/// and return the new version.
///
/// # Errors
/// [`UpdateError`].
///
/// Spec: docs/51 §5.10; A-80; A-69.
pub fn update_policy<O: Ownership>(
    path: &FilePath,
    changes: &[TierChange],
    ownership: &mut O,
) -> Result<PolicyVersion, UpdateError> {
    let policy = load_installed(path.as_path(), ownership.root_uid())?;
    let (next, bytes) = edit_tier_map(&policy, changes).map_err(UpdateError::Edit)?;
    install_policy_file(path.as_path(), &bytes, ownership)?;
    Ok(next.version)
}

/// Why an activation was refused or failed (module documentation, "the
/// activation"). Fixed texts; never file content.
/// Spec: docs/51 §5.10; docs/questions/Q-591.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActivateError {
    /// dird's configuration file was refused.
    DirdConfig(RootFileError),
    /// dird's configuration names no `policy_next_path` (no admin service,
    /// or the online path not configured): there is nothing to activate.
    NotConfigured,
    /// No `policy.next` is pending.
    NothingPending,
    /// A directory on `policy.next`'s path is a link or not a directory, is
    /// owned by neither root nor dird's account, or is writable by group or
    /// others.
    NextPath(PathBreak),
    /// `policy.next` was refused: not a regular file (a link included), not
    /// owned by dird's account, writable by group or others, unreadable,
    /// too large, or it does not decode or validate.
    NextRefused(policy_store::LoadError),
    /// `policy.next` is not a tier-map successor of the installed policy
    /// (an older, equal or skipped version, a changed rule set, anonymous
    /// allowlist or mandatory-FAST entry, no Tier0 principal).
    NotASuccessor(SuccessorError),
    /// The installed policy could not be loaded, or the new one installed.
    Install(UpdateError),
    /// The new policy IS installed, but `policy.next` could not be removed
    /// (or its directory synced): remove it before dird's restart — a
    /// re-run removes it (it is recognised as installed).
    Remove(EntryError),
}

impl fmt::Display for ActivateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ActivateError::DirdConfig(e) => write!(f, "dird's configuration file {e}"),
            ActivateError::NotConfigured => {
                f.write_str("dird's configuration names no policy_next_path")
            }
            ActivateError::NothingPending => f.write_str("no policy.next is pending"),
            ActivateError::NextPath(path) => write!(f, "policy.next's path {path}"),
            ActivateError::NextRefused(e) => write!(f, "policy.next refused: {e}"),
            ActivateError::NotASuccessor(e) => {
                write!(f, "policy.next refused: {e}; nothing installed")
            }
            ActivateError::Install(e) => write!(f, "{e}"),
            ActivateError::Remove(e) => write!(
                f,
                "the new policy is installed but policy.next could not be removed ({e}); run the activation again"
            ),
        }
    }
}

impl std::error::Error for ActivateError {}

/// What an activation did.
/// Spec: docs/51 §5.10.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Activated {
    /// The installed `policy_version` now.
    pub version: PolicyVersion,
    /// The tier-map rows the activation changed, in the edit's vocabulary
    /// (empty when an interrupted activation is only completed).
    pub changes: Vec<TierChange>,
    /// `true` when `policy.next` was already installed (an interrupted
    /// activation completed: only the removal was done).
    pub completed_earlier: bool,
}

/// The installed policy's path, `policy.next`'s path and dird's account,
/// from dird's configuration file (module documentation, step 1).
fn activation_inputs(
    dird_config: &FilePath,
    root: u32,
) -> Result<(PathBuf, PathBuf, u32), ActivateError> {
    let settings =
        read_dird_settings(dird_config.as_path(), root).map_err(ActivateError::DirdConfig)?;
    let next = settings
        .admin_service()
        .and_then(config::AdminServiceSettings::policy_next)
        .ok_or(ActivateError::NotConfigured)?
        .as_path()
        .to_path_buf();
    let installed = settings.policy_store_path().as_path().to_path_buf();
    Ok((installed, next, settings.run_as().uid()))
}

/// Activate dird's `policy.next` (module documentation, "the activation").
///
/// # Errors
/// [`ActivateError`]; nothing is installed unless the error is
/// [`ActivateError::Remove`].
///
/// Spec: docs/51 §5.10 (R51-21: "activation — root"); A-69; A-80;
/// docs/questions/Q-591.
pub fn activate_policy_next<O: Ownership>(
    dird_config: &FilePath,
    ownership: &mut O,
) -> Result<Activated, ActivateError> {
    let root = ownership.root_uid();
    let (installed_path, next_path, dird_uid) = activation_inputs(dird_config, root)?;
    let installed = load_installed(&installed_path, root).map_err(ActivateError::Install)?;
    // `policy.next`: dird's file, reached by the walk with dird's account as
    // its owner.
    match protected_file::entry_facts(&next_path, dird_uid) {
        Ok(Some(_)) => {}
        Ok(None) => return Err(ActivateError::NothingPending),
        Err(EntryError::Path(broken)) => return Err(ActivateError::NextPath(broken)),
        Err(EntryError::Io(_)) => {
            return Err(ActivateError::NextRefused(
                policy_store::LoadError::Unreadable,
            ))
        }
    }
    let next = policy_store::read_file(&next_path, dird_uid).map_err(ActivateError::NextRefused)?;
    let completed_earlier = next == installed;
    let changes = if completed_earlier {
        Vec::new()
    } else {
        check_tier_map_successor(&installed, &next).map_err(ActivateError::NotASuccessor)?;
        let bytes = next
            .encode()
            .map_err(|e| ActivateError::Install(UpdateError::Encode(e)))?;
        install_policy_file(&installed_path, &bytes, ownership).map_err(ActivateError::Install)?;
        tier_map_difference(&installed, &next)
    };
    protected_file::remove_entry(&next_path, dird_uid).map_err(ActivateError::Remove)?;
    protected_file::sync_directory(parent_of(&next_path), dird_uid)
        .map_err(ActivateError::Remove)?;
    Ok(Activated {
        version: next.version,
        changes,
        completed_earlier,
    })
}
