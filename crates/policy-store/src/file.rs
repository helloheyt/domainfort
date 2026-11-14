//! Reading the policy file from disk, as both daemons do at start, as root
//! before the privilege drop (docs/50 §6.2, §7.2): a regular file owned by
//! the expected owner (root in the daemons), not writable by group or
//! others, at most [`MAX_POLICY_FILE`] octets (one more is read, so an
//! oversized file is detected without reading it whole), decoded by
//! [`DevelopmentPolicy::decode`]. Absent ⇒ refused (fail closed). Moved
//! from crates/directory-daemon `startup::read_policy` (A-68), unchanged
//! but for the way the file is reached: since task F7 (the A-86 follow-up
//! "O_NOFOLLOW in every reader") through crates/protected-file — the path
//! is inspected without following a symbolic link (a link is refused as
//! not a regular file, before any open), opened with O_NOFOLLOW, and the
//! rule applied again to the opened descriptor.
//!
//! Spec: docs/50 §7.1 (root-owned files), §7.2 ("invalid … ⇒ do not
//! start"); docs/questions/Q-219 (A-57), Q-270 item 2; A-86.

use crate::policy::{DevelopmentPolicy, PolicyError, MAX_POLICY_FILE};
use core::fmt;
use protected_file::Refusal;
use std::path::Path;

/// Why the policy file could not be loaded. Carries no file content.
/// Spec: docs/50 §7.5, §8.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadError {
    /// The file could not be opened or read.
    Unreadable,
    /// The file is not a regular file (a symbolic link included) of the
    /// expected owner, not writable by group or others.
    Permissions,
    /// The file was refused.
    Policy(PolicyError),
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoadError::Unreadable => f.write_str("policy file unreadable"),
            LoadError::Permissions => f.write_str(
                "policy file must be a regular file owned by root, not writable by group or others",
            ),
            LoadError::Policy(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for LoadError {}

/// Read and decode the policy file at `path`, which must belong to `owner`
/// (module documentation).
///
/// # Errors
/// [`LoadError`].
///
/// Spec: docs/50 §7.1, §7.2; docs/questions/Q-270 item 2.
pub fn read_file(path: &Path, owner: u32) -> Result<DevelopmentPolicy, LoadError> {
    let bound = MAX_POLICY_FILE as usize;
    let contents = protected_file::read_configuration_file(path, owner, bound).map_err(
        |refusal| match refusal {
            Refusal::Unreadable(_) => LoadError::Unreadable,
            Refusal::Rule(_) => LoadError::Permissions,
            Refusal::TooLarge => LoadError::Policy(PolicyError::TooLarge),
        },
    )?;
    DevelopmentPolicy::decode(&contents).map_err(LoadError::Policy)
}
