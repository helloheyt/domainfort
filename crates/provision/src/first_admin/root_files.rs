//! Reading the two root-owned inputs of `provision first-admin-secret` —
//! the provisioning manifest and admind's configuration file — as root,
//! before the privilege drop.
//!
//! Both were written by `provision domain` as root:0644 (docs/51 §4.3
//! steps 7-8), and both decide what this command does: the manifest names
//! the key sets and bindings (A-19), admind's file names the account to
//! drop to, keyd's socket and uid, and the minimum password length (A-79).
//! The rule is the configuration-file rule (docs/50 §7.1: "file root:0644";
//! crates/provision-manifest `check_file`), with the A-86 follow-up applied
//! here: the path is inspected without following a link (a link, a FIFO, a
//! directory are refused before any open), opened with O_NOFOLLOW, and the
//! opened file checked again — a regular file, owned by root, not writable
//! by group or others — and read only up to the format's size bound + 1.
//!
//! The owner required is a parameter: 0 in production (the binary), the
//! test account in tests — as `Ownership::root_uid` for `provision policy`.
//!
//! Spec: docs/51 §4.3 steps 7, 8, 12; docs/50 R50-15, §7.1; A-60 (errors
//! never echo a value); A-86 (O_NOFOLLOW in every reader); AGENTS.md §6
//! (bounded reads).

use core::fmt;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use config::AdmindSettings;
use provision_manifest::Manifest;

/// Write permission for group and others (must be clear).
/// Spec: docs/50 §7.1 ("root:0644"); crates/provision-manifest
/// `FORBIDDEN_MODE_BITS`.
const FORBIDDEN_MODE_BITS: u32 = 0o022;

/// Why a root-owned input was refused. Fixed texts (a configuration or
/// manifest error names a line or key, never a value — A-60).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootFileError {
    /// The file could not be inspected, opened or read.
    Unreadable,
    /// The path is a symbolic link or not a regular file.
    NotRegular,
    /// The file is not owned by root.
    NotRootOwned,
    /// The file is writable by group or others.
    WritableByOthers,
    /// The file is larger than its format allows.
    TooLarge,
    /// admind's configuration was refused by its schema.
    Config(config::Error),
    /// The manifest was refused by its parser.
    Manifest(provision_manifest::Error),
}

impl fmt::Display for RootFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RootFileError::Unreadable => f.write_str("cannot be inspected, opened or read"),
            RootFileError::NotRegular => f.write_str("is a symbolic link or not a regular file"),
            RootFileError::NotRootOwned => f.write_str("is not owned by root"),
            RootFileError::WritableByOthers => f.write_str("is writable by group or others"),
            RootFileError::TooLarge => f.write_str("is larger than its format allows"),
            RootFileError::Config(e) => write!(f, "was refused: {e}"),
            RootFileError::Manifest(e) => write!(f, "was refused: {e}"),
        }
    }
}

impl std::error::Error for RootFileError {}

/// The ownership rule on one file's metadata.
fn check(metadata: &std::fs::Metadata, root_uid: u32) -> Result<(), RootFileError> {
    if !metadata.file_type().is_file() {
        return Err(RootFileError::NotRegular);
    }
    if metadata.uid() != root_uid {
        return Err(RootFileError::NotRootOwned);
    }
    if metadata.mode() & FORBIDDEN_MODE_BITS != 0 {
        return Err(RootFileError::WritableByOthers);
    }
    Ok(())
}

/// The content of the root-owned file at `path`, at most `bound` octets
/// (module documentation).
fn read_root_owned(path: &Path, root_uid: u32, bound: usize) -> Result<Vec<u8>, RootFileError> {
    let link = std::fs::symlink_metadata(path).map_err(|_| RootFileError::Unreadable)?;
    check(&link, root_uid)?;
    let file = crate::fs::open_no_follow(path).map_err(|_| RootFileError::Unreadable)?;
    let opened = file.metadata().map_err(|_| RootFileError::Unreadable)?;
    check(&opened, root_uid)?;
    let limit = u64::try_from(bound).unwrap_or(u64::MAX).saturating_add(1);
    let mut contents = Vec::new();
    // std `io::Read::read_to_end` retries `ErrorKind::Interrupted` itself.
    file.take(limit)
        .read_to_end(&mut contents)
        .map_err(|_| RootFileError::Unreadable)?;
    if contents.len() > bound {
        return Err(RootFileError::TooLarge);
    }
    Ok(contents)
}

/// Read and parse admind's configuration file (owned by `root_uid`).
///
/// # Errors
/// [`RootFileError`].
///
/// Spec: docs/50 R50-15, §7.1; crates/config `AdmindSettings::parse`.
pub fn read_admind_settings(path: &Path, root_uid: u32) -> Result<AdmindSettings, RootFileError> {
    let contents = read_root_owned(path, root_uid, config::limits::MAX_FILE_OCTETS)?;
    AdmindSettings::parse(&contents).map_err(RootFileError::Config)
}

/// Read and parse the provisioning manifest (owned by `root_uid`).
///
/// # Errors
/// [`RootFileError`].
///
/// Spec: docs/51 §4.3 steps 8, 12; crates/provision-manifest
/// `Manifest::parse`.
pub fn read_manifest(path: &Path, root_uid: u32) -> Result<Manifest, RootFileError> {
    let contents = read_root_owned(path, root_uid, provision_manifest::limits::MAX_FILE_OCTETS)?;
    Manifest::parse(&contents).map_err(RootFileError::Manifest)
}
