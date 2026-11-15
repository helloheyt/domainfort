//! Reading the two root-owned inputs of `provision first-admin-secret` —
//! the provisioning manifest and admind's configuration file — as root,
//! before the privilege drop.
//!
//! Both were written by `provision domain` as root:0644 (docs/51 §4.3
//! steps 7-8), and both decide what this command does: the manifest names
//! the key sets and bindings (A-19), admind's file names the account to
//! drop to, keyd's socket and uid, and the minimum password length (A-79).
//! The rule is the configuration-file rule (docs/50 §7.1: "file root:0644";
//! crates/provision-manifest `check_file`), with the A-86 follow-up applied:
//! the path is inspected without following a link (a link, a FIFO, a
//! directory are refused before any open), opened with O_NOFOLLOW, and the
//! opened file checked again — a regular file, owned by root, not writable
//! by group or others — and read only up to the format's size bound + 1.
//!
//! Since task F7 there is one reader for this (A-96 / Q-414 item 4): the
//! manifest goes through crates/provision-manifest's owner-injectable
//! reader (`read_manifest_owned_by`, the one keyadm and dird use with owner
//! 0), admind's file through crates/protected-file, on which that reader is
//! built. This module only maps their errors onto [`RootFileError`].
//!
//! The owner required is a parameter: 0 in production (the binary), the
//! test account in tests — as `Ownership::root_uid` for `provision policy`.
//!
//! Spec: docs/51 §4.3 steps 7, 8, 12; docs/50 R50-15, §7.1; A-60 (errors
//! never echo a value); A-86 (O_NOFOLLOW in every reader); A-96; docs/CLEAN-ROOM.md
//! §6 (bounded reads).

use core::fmt;
use std::path::Path;

use config::AdmindSettings;
use protected_file::{Refusal, RuleBreak};
use provision_manifest::{Manifest, ReadError};

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

/// A break of the configuration-file rule as a [`RootFileError`].
fn rule_error(rule: RuleBreak) -> RootFileError {
    match rule {
        RuleBreak::NotRegularFile => RootFileError::NotRegular,
        RuleBreak::WrongOwner => RootFileError::NotRootOwned,
        RuleBreak::WritableByGroupOrOthers => RootFileError::WritableByOthers,
    }
}

/// Read and parse admind's configuration file (owned by `root_uid`).
///
/// # Errors
/// [`RootFileError`].
///
/// Spec: docs/50 R50-15, §7.1; crates/config `AdmindSettings::parse`;
/// crates/protected-file `read_configuration_file` (A-86).
pub fn read_admind_settings(path: &Path, root_uid: u32) -> Result<AdmindSettings, RootFileError> {
    let contents =
        protected_file::read_configuration_file(path, root_uid, config::limits::MAX_FILE_OCTETS)
            .map_err(|refusal| match refusal {
                Refusal::Unreadable(_) => RootFileError::Unreadable,
                Refusal::Rule(rule) => rule_error(rule),
                Refusal::TooLarge => RootFileError::TooLarge,
            })?;
    AdmindSettings::parse(&contents).map_err(RootFileError::Config)
}

/// Read and parse dird's configuration file (owned by `root_uid`) — for
/// `provision policy --activate-next` (task A16), which takes the installed
/// policy's path, `policy.next`'s path and dird's account from the file dird
/// itself reads.
///
/// # Errors
/// [`RootFileError`].
///
/// Spec: docs/50 R50-15, §7.1; docs/51 §5.10; crates/config
/// `DirdSettings::parse`; crates/protected-file `read_configuration_file`.
pub fn read_dird_settings(
    path: &Path,
    root_uid: u32,
) -> Result<config::DirdSettings, RootFileError> {
    let contents =
        protected_file::read_configuration_file(path, root_uid, config::limits::MAX_FILE_OCTETS)
            .map_err(|refusal| match refusal {
                Refusal::Unreadable(_) => RootFileError::Unreadable,
                Refusal::Rule(rule) => rule_error(rule),
                Refusal::TooLarge => RootFileError::TooLarge,
            })?;
    config::DirdSettings::parse(&contents).map_err(RootFileError::Config)
}

/// Read and parse the provisioning manifest (owned by `root_uid`), through
/// crates/provision-manifest's reader — the one keyadm and dird use (A-96
/// follow-up; Q-414 item 4).
///
/// # Errors
/// [`RootFileError`].
///
/// Spec: docs/51 §4.3 steps 8, 12; crates/provision-manifest
/// `read_manifest_owned_by`.
pub fn read_manifest(path: &Path, root_uid: u32) -> Result<Manifest, RootFileError> {
    provision_manifest::read_manifest_owned_by(path, root_uid).map_err(|error| match error {
        ReadError::Unreadable => RootFileError::Unreadable,
        ReadError::NotRegularFile => RootFileError::NotRegular,
        ReadError::NotRootOwned => RootFileError::NotRootOwned,
        ReadError::WritableByOthers => RootFileError::WritableByOthers,
        ReadError::TooLarge => RootFileError::TooLarge,
        ReadError::Manifest(error) => RootFileError::Manifest(error),
    })
}
