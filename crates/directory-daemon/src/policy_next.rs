//! dird's `policy.next` (task A16; docs/51 §5.10, R51-21; A-80 on
//! docs/questions/Q-299 option (b)): where an approved tier-map change waits
//! for root's activation.
//!
//! # Where it lives (docs/questions/Q-591)
//!
//! The file named by dird's `policy_next_path` (an admin-service setting,
//! crates/config): a file in a directory **of dird's own** — root's policy
//! directory is root-only (A-113: every directory on a protected path of
//! root's files is root's), so dird after its drop could never create
//! anything there. dird prepares the directory as root before the drop
//! ([`crate::startup::prepare_policy_next_directory`],
//! `protected_file::prepare_daemon_directory`: walked from `/`, created by
//! descriptor 0750 for dird's account, an existing one checked); root's
//! activation (`provision policy --activate-next`) reads the same key from
//! the same configuration file, so the two cannot disagree on the place.
//!
//! # How it is written (one pending change at a time)
//!
//! Only from a [`PolicyCandidate`] — which exists only once auditd has
//! acknowledged the change's decision event (docs/52 R6; crate
//! directory-admin) — and only through crates/protected-file, relative to
//! the walked directory, never by path:
//!
//! 1. a partial file `<name>.partial` an interrupted earlier write left is
//!    removed (dird's own file in dird's own directory; `remove_entry`);
//! 2. `policy.next` present ⇒ refused (a change is already pending);
//! 3. the partial file is created exclusively without following a link
//!    (`create_new_read_write`: `O_CREAT | O_EXCL | O_NOFOLLOW`, mode exactly
//!    0600), written whole and `fsync`ed;
//! 4. it is renamed to `policy.next` **without replacing** anything
//!    (`rename_no_replace`: `RENAME_NOREPLACE`) — a `policy.next` that
//!    appeared since step 2 makes the rename fail and the change is refused,
//!    never overwritten;
//! 5. the directory is `fsync`ed.
//!
//! A crash leaves either no `policy.next` (a partial file, removed by the
//! next write) or the complete one — never a torn `policy.next`.
//!
//! Spec: docs/51 §5.10; docs/50 §6.4 (dird's own files after the drop);
//! docs/52 §3.11 (R6), §3.13 (C13); A-80; A-113; docs/questions/Q-591;
//! crates/protected-file (`entry_facts`, `remove_entry`,
//! `create_new_read_write`, `rename_no_replace`, `sync_directory`).

use core::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};

use directory_admin::{PendingPolicy, PolicyCandidate};
use protected_file::EntryError;

/// Why `policy.next` was not written, or its state could not be read.
/// Carries no path and no content (docs/50 §8.2).
/// Spec: docs/51 §5.10; docs/questions/Q-591.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyNextError {
    /// A `policy.next` is already there (one pending change at a time).
    Pending,
    /// A file-system step was refused or failed (the walk's directory rule
    /// included); nothing was renamed into place.
    Io(EntryError),
    /// `policy.next` was renamed into place but its directory could not be
    /// made durable.
    Unsynced(EntryError),
}

impl PolicyNextError {
    /// The class of the log note (`Note::AdminPolicyNextNotWritten`).
    #[must_use]
    pub const fn code(self) -> u64 {
        match self {
            PolicyNextError::Pending | PolicyNextError::Io(_) => 1,
            PolicyNextError::Unsynced(_) => 2,
        }
    }
}

impl fmt::Display for PolicyNextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyNextError::Pending => f.write_str("a policy.next is already pending"),
            PolicyNextError::Io(e) => write!(f, "policy.next could not be written: {e}"),
            PolicyNextError::Unsynced(e) => {
                write!(f, "policy.next written but its directory not synced: {e}")
            }
        }
    }
}

impl std::error::Error for PolicyNextError {}

/// dird's `policy.next`: its path and the account that owns it (dird's;
/// every directory on the path must be root's or this account's, not
/// writable by group or others — the protected-file walk).
/// Spec: this module's documentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyNextFile {
    path: PathBuf,
    owner_uid: u32,
}

impl PolicyNextFile {
    /// The file at `path`, owned by `owner_uid` (dird's account; a test's
    /// own account in tests).
    #[must_use]
    pub fn new(path: PathBuf, owner_uid: u32) -> PolicyNextFile {
        PolicyNextFile { path, owner_uid }
    }

    /// The path (`policy_next_path`).
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The partial file beside it (`<name>.partial`).
    fn partial(&self) -> PathBuf {
        let mut name = self
            .path
            .file_name()
            .map(std::ffi::OsStr::to_os_string)
            .unwrap_or_default();
        name.push(".partial");
        self.path.with_file_name(name)
    }

    /// Whether a `policy.next` is there (anything at the name counts: a
    /// link or another kind of entry is pending too — fail closed).
    ///
    /// # Errors
    /// [`PolicyNextError::Io`] when the path cannot be walked or inspected.
    ///
    /// Spec: docs/questions/Q-591 ("one pending change at a time").
    pub fn pending(&self) -> Result<PendingPolicy, PolicyNextError> {
        match protected_file::entry_facts(&self.path, self.owner_uid) {
            Ok(Some(_)) => Ok(PendingPolicy::Present),
            Ok(None) => Ok(PendingPolicy::Absent),
            Err(e) => Err(PolicyNextError::Io(e)),
        }
    }

    /// Write `candidate` as `policy.next` (module documentation, steps 1-5).
    /// The candidate exists only after auditd acknowledged the decision.
    ///
    /// # Errors
    /// [`PolicyNextError`]; on `Pending` and `Io` nothing is left but at most
    /// a partial file (which the next write removes).
    ///
    /// Spec: this module's documentation.
    pub fn write(&self, candidate: &PolicyCandidate) -> Result<(), PolicyNextError> {
        let partial = self.partial();
        protected_file::remove_entry(&partial, self.owner_uid).map_err(PolicyNextError::Io)?;
        if self.pending()? == PendingPolicy::Present {
            return Err(PolicyNextError::Pending);
        }
        let written = protected_file::create_new_read_write(&partial, self.owner_uid)
            .map_err(PolicyNextError::Io)
            .and_then(|mut file| {
                file.write_all(candidate.file())
                    .and_then(|()| file.sync_all())
                    .map_err(|e| PolicyNextError::Io(EntryError::Io(e.kind())))
            });
        if let Err(error) = written {
            let _ = protected_file::remove_entry(&partial, self.owner_uid);
            return Err(error);
        }
        if let Err(error) =
            protected_file::rename_no_replace(&partial, self.owner_uid, &self.path, self.owner_uid)
        {
            let _ = protected_file::remove_entry(&partial, self.owner_uid);
            return Err(match error {
                EntryError::Io(std::io::ErrorKind::AlreadyExists) => PolicyNextError::Pending,
                other => PolicyNextError::Io(other),
            });
        }
        let directory = self.path.parent().unwrap_or_else(|| Path::new("/"));
        protected_file::sync_directory(directory, self.owner_uid).map_err(PolicyNextError::Unsynced)
    }
}
