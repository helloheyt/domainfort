//! `provision policy`: the offline tier-map edit (R51-21, decided A-80 /
//! Q-299 (a)) — as root, with dird and kdc stopped.
//!
//! 1. The policy file must be a regular file (not a link), owned by root,
//!    not writable by group or others, and decode (policy-store
//!    `read_file`, the daemons' own loader); anything else is refused.
//! 2. The edit ([`crate::policy::edit_tier_map`]): add / remove rows, bump
//!    `policy_version`.
//! 3. Atomic write: a new file `<name>.next` beside it (created
//!    exclusively without following links; a leftover from an interrupted
//!    run is refused, never reused), root:0644, `fsync`; then renamed over
//!    the old file and the directory `fsync`ed. A crash leaves either the
//!    old file (plus possibly the `.next` file, which a re-run refuses until
//!    removed) or the new one — never a torn file.
//! 4. dird and kdc must both be restarted: there is no reload, and the kdc
//!    refuses to start with a policy version different from dird's (A-69).
//!
//! Every filesystem step goes through crates/protected-file (task R11c,
//! docs/questions Q-532 item 2): the policy's path is walked from `/` (no
//! link in any directory component; every directory root's and not writable
//! by group or others), its facts are taken relative to the walked
//! directory, the `.next` file is created and renamed relative to it, and
//! the directory is `fsync`ed through the walk — never a lookup of the path
//! from the current directory.
//!
//! Spec: docs/51 §5.10 (R51-21); A-80; A-69; Q-270 item 2(b); Q-299;
//! policy-store `read_file`; A-109 (Q-532 item 2); rustix docs.rs (P-2).

use core::fmt;
use std::io::Write;
use std::os::fd::AsFd;
use std::path::PathBuf;

use pdp::PolicyVersion;
use protected_file::{EntryError, NewFileMode, PathBreak};

use crate::input::FilePath;
use crate::ownership::{Ownership, OwnershipError, Staged};
use crate::plan::Owner;
use crate::policy::{edit_tier_map, EditError, TierChange};

/// The fixed notice printed after an edit. Spec: A-69; docs/51 §5.10.
pub const RESTART_NOTICE: &str =
    "dird and kdc must both be restarted to load the new policy (no reload; the kdc refuses a policy version different from dird's, A-69)";

/// Why the edit was refused or failed.
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
        }
    }
}

impl std::error::Error for UpdateError {}

/// The `.next` path beside `path`.
fn next_path(path: &FilePath) -> PathBuf {
    let mut name = path
        .as_path()
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(".next");
    path.parent().join(name)
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
    let root = ownership.root_uid();
    match protected_file::entry_facts(path.as_path(), root) {
        Ok(Some(facts)) if facts.regular_file => {}
        Ok(_) | Err(EntryError::Io(_)) => return Err(UpdateError::NotRegular),
        Err(EntryError::Path(broken)) => return Err(UpdateError::Path(broken)),
    }
    let policy = policy_store::read_file(path.as_path(), root).map_err(UpdateError::Load)?;
    let (next, bytes) = edit_tier_map(&policy, changes).map_err(UpdateError::Edit)?;
    let staged = next_path(path);
    let mut file =
        protected_file::create_new_file(&staged, root, NewFileMode::OwnerWriteEveryoneRead)
            .map_err(|e| UpdateError::Next(staged.clone(), e))?;
    file.write_all(&bytes)
        .map_err(|e| UpdateError::Write(e.kind()))?;
    ownership
        .change_owner(file.as_fd(), Staged::PolicyUpdate, Owner::ROOT)
        .map_err(UpdateError::Ownership)?;
    rustix::fs::fsync(&file)
        .map_err(|errno| UpdateError::Io("fsync", EntryError::Io(errno.kind())))?;
    drop(file);
    protected_file::rename_replace(&staged, root, path.as_path(), root)
        .map_err(|e| UpdateError::Io("rename", e))?;
    protected_file::sync_directory(path.parent(), root).map_err(|e| UpdateError::Io("fsync", e))?;
    Ok(next.version)
}
