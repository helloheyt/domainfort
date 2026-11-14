//! Reading a manifest file: a regular file owned by root and not writable by
//! group or others, reached without following a symbolic link, read only up
//! to the size bound.
//!
//! The manifest is written by `provision domain` as root, mode 0644 (docs/51
//! §4.3 step 8: "non-secret manifest (root:0644)"). The tools that read it
//! act on what it names — keyadm creates the krbtgt and service key sets
//! with its GUIDs and bindings — so a manifest another account could write
//! would let that account choose which GUID a krbtgt key is bound to. The
//! rule is the configuration-file rule (docs/50 §7.1: "file root:0644"):
//! owner uid 0, `mode & 0o022 == 0`, regular file, bounded read.
//!
//! Since task F7 the file is reached through crates/protected-file (the A-86
//! follow-up "O_NOFOLLOW in every reader"; Q-414 item 4: one reader, owner
//! injectable, for keyadm, dird and provision): the path is inspected
//! without following a link (a link, a FIFO or a directory is refused before
//! any open), opened with O_NOFOLLOW, and the rule applied again to the
//! opened descriptor (`fstat`) — the authoritative check is on the file
//! actually read. The owner is a parameter of [`read_manifest_owned_by`]
//! (the test account in tests, as provision's `root_uid`); [`read_manifest`]
//! is that reader with owner 0.
//!
//! Spec: docs/51 §4.3 step 8; docs/50 §7.1; A-86; A-96; AGENTS.md §6
//! (bounded reads, fail closed).

use crate::error::ReadError;
use crate::limits::MAX_FILE_OCTETS;
use crate::manifest::Manifest;
use protected_file::{Refusal, RuleBreak};
use std::path::Path;

// What the file check looks at: crates/protected-file's facts (of the path,
// then of the opened descriptor). Spec: docs/50 §7.1.
pub use protected_file::FileFacts;

/// The mode bits that must be clear: write for group and for others.
/// Spec: docs/50 §7.1 ("root:0644"); crates/protected-file
/// `GROUP_OR_OTHER_WRITE`.
pub const FORBIDDEN_MODE_BITS: u32 = protected_file::GROUP_OR_OTHER_WRITE;

/// The owner a manifest file must have: root.
/// Spec: docs/51 §4.3 step 8 ("root:0644").
pub const REQUIRED_OWNER_UID: u32 = 0;

/// A break of the configuration-file rule as a [`ReadError`].
fn rule_error(rule: RuleBreak) -> ReadError {
    match rule {
        RuleBreak::NotRegularFile => ReadError::NotRegularFile,
        RuleBreak::WrongOwner => ReadError::NotRootOwned,
        RuleBreak::WritableByGroupOrOthers => ReadError::WritableByOthers,
    }
}

/// The manifest-file rule: a regular file, owned by root, not writable by
/// group or others.
///
/// # Errors
/// [`ReadError::NotRegularFile`], [`ReadError::NotRootOwned`],
/// [`ReadError::WritableByOthers`] — checked in that order.
///
/// Spec: docs/51 §4.3 step 8; docs/50 §7.1.
pub fn check_file(facts: &FileFacts) -> Result<(), ReadError> {
    protected_file::configuration_file_rule(facts, REQUIRED_OWNER_UID).map_err(rule_error)
}

/// Read, check and parse the manifest at `path`, which must be owned by
/// root ([`read_manifest_owned_by`] with owner 0).
///
/// # Errors
/// [`ReadError`]: unreadable, the file rule of [`check_file`] (a symbolic
/// link is [`ReadError::NotRegularFile`]), too large, or the content refused
/// by [`Manifest::parse`].
///
/// Spec: docs/51 §4.3 steps 8, 11, 12; docs/50 §7.1; AGENTS.md §6.
pub fn read_manifest(path: &Path) -> Result<Manifest, ReadError> {
    read_manifest_owned_by(path, REQUIRED_OWNER_UID)
}

/// Read, check and parse the manifest at `path`, which must be owned by
/// `owner_uid` (root in production) — module documentation.
///
/// At most [`MAX_FILE_OCTETS`] + 1 octets are read, so an oversized file is
/// refused without being read whole.
///
/// # Errors
/// [`ReadError`]: unreadable, the file rule (with `owner_uid` as the owner),
/// too large, or the content refused by [`Manifest::parse`].
///
/// Spec: docs/51 §4.3 steps 8, 11, 12; docs/50 §7.1; A-86; Q-414 item 4.
pub fn read_manifest_owned_by(path: &Path, owner_uid: u32) -> Result<Manifest, ReadError> {
    let contents = protected_file::read_configuration_file(path, owner_uid, MAX_FILE_OCTETS)
        .map_err(|refusal| match refusal {
            Refusal::Unreadable(_) => ReadError::Unreadable,
            Refusal::Rule(rule) => rule_error(rule),
            Refusal::TooLarge => ReadError::TooLarge,
        })?;
    Manifest::parse(&contents).map_err(ReadError::Manifest)
}
