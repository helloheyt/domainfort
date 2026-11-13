//! Reading a manifest file: a regular file owned by root and not writable by
//! group or others, read only up to the size bound.
//!
//! The manifest is written by `provision domain` as root, mode 0644 (docs/51
//! §4.3 step 8: "non-secret manifest (root:0644)"). The tools that read it
//! act on what it names — keyadm creates the krbtgt and service key sets
//! with its GUIDs and bindings — so a manifest another account could write
//! would let that account choose which GUID a krbtgt key is bound to. The
//! rule is the configuration-file rule (docs/50 §7.1: "file root:0644"),
//! applied the way the daemons apply it (crates/keyd-daemon
//! `startup::read_settings`): owner uid 0, `mode & 0o022 == 0`, regular
//! file, bounded read.
//!
//! The path is inspected before it is opened (so a FIFO or a directory is
//! refused without blocking on `open`) and the opened file is checked again
//! (the authoritative check is on the file actually read).
//!
//! Spec: docs/51 §4.3 step 8; docs/50 §7.1; AGENTS.md §6 (bounded reads,
//! fail closed).

use crate::error::ReadError;
use crate::limits::MAX_FILE_OCTETS;
use crate::manifest::Manifest;
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// The mode bits that must be clear: write for group and for others.
/// Spec: docs/50 §7.1 ("root:0644"); crates/keyd-daemon `read_settings`.
pub const FORBIDDEN_MODE_BITS: u32 = 0o022;

/// The owner a manifest file must have: root.
/// Spec: docs/51 §4.3 step 8 ("root:0644").
pub const REQUIRED_OWNER_UID: u32 = 0;

/// What the file check looks at, as read from the file's metadata.
/// Spec: docs/50 §7.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileFacts {
    /// The path names a regular file.
    pub regular_file: bool,
    /// The file's owner uid.
    pub owner_uid: u32,
    /// The file's mode bits.
    pub mode: u32,
}

impl FileFacts {
    /// The facts of `metadata`.
    #[must_use]
    pub fn of(metadata: &std::fs::Metadata) -> FileFacts {
        FileFacts {
            regular_file: metadata.is_file(),
            owner_uid: metadata.uid(),
            mode: metadata.mode(),
        }
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
    if !facts.regular_file {
        return Err(ReadError::NotRegularFile);
    }
    if facts.owner_uid != REQUIRED_OWNER_UID {
        return Err(ReadError::NotRootOwned);
    }
    if facts.mode & FORBIDDEN_MODE_BITS != 0 {
        return Err(ReadError::WritableByOthers);
    }
    Ok(())
}

/// Read, check and parse the manifest at `path`.
///
/// At most [`MAX_FILE_OCTETS`] + 1 octets are read, so an oversized file is
/// refused without being read whole.
///
/// # Errors
/// [`ReadError`]: unreadable, the file rule of [`check_file`], too large, or
/// the content refused by [`Manifest::parse`].
///
/// Spec: docs/51 §4.3 steps 8, 11, 12; docs/50 §7.1; AGENTS.md §6.
pub fn read_manifest(path: &Path) -> Result<Manifest, ReadError> {
    let before = std::fs::metadata(path).map_err(|_| ReadError::Unreadable)?;
    check_file(&FileFacts::of(&before))?;
    let file = File::open(path).map_err(|_| ReadError::Unreadable)?;
    let opened = file.metadata().map_err(|_| ReadError::Unreadable)?;
    check_file(&FileFacts::of(&opened))?;
    let bound = u64::try_from(MAX_FILE_OCTETS)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut contents = Vec::new();
    file.take(bound)
        .read_to_end(&mut contents)
        .map_err(|_| ReadError::Unreadable)?;
    if contents.len() > MAX_FILE_OCTETS {
        return Err(ReadError::TooLarge);
    }
    Manifest::parse(&contents).map_err(ReadError::Manifest)
}
