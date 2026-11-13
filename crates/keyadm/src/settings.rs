//! Reading keyadm's configuration file.
//!
//! The file must be a regular file owned by root and not writable by group
//! or others (docs/50 §7.1: "file root:0644"), checked the way the daemons
//! check theirs (crates/keyd-daemon `startup::read_settings`) and with the
//! same rule the manifest file obeys ([`provision_manifest::check_file`]);
//! at most `config::limits::MAX_FILE_OCTETS` + 1 octets are read.
//!
//! Spec: docs/50 R50-15, §7.1; docs/51 §6; AGENTS.md §6.

use config::KeyadmSettings;
use core::fmt;
use provision_manifest::{check_file, FileFacts, ReadError};
use std::fs::File;
use std::io::Read;
use std::path::Path;

/// Why the configuration file was not accepted. Carries no file content
/// (the configuration's own errors never echo a value, A-60).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettingsError {
    /// The file could not be opened, inspected or read.
    Unreadable,
    /// Not a regular file owned by root and writable only by its owner.
    Permissions,
    /// Larger than the format allows.
    TooLarge,
    /// The content was refused.
    Config(config::Error),
}

impl fmt::Display for SettingsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SettingsError::Unreadable => f.write_str("configuration file unreadable"),
            SettingsError::Permissions => f.write_str(
                "configuration file must be a regular file owned by root, not writable by group or others",
            ),
            SettingsError::TooLarge => f.write_str("configuration file too large"),
            SettingsError::Config(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for SettingsError {}

/// The file rule (regular, root-owned, not group/other-writable) as a
/// [`SettingsError`].
fn check(metadata: &std::fs::Metadata) -> Result<(), SettingsError> {
    check_file(&FileFacts::of(metadata)).map_err(|error| match error {
        ReadError::NotRegularFile | ReadError::NotRootOwned | ReadError::WritableByOthers => {
            SettingsError::Permissions
        }
        _ => SettingsError::Unreadable,
    })
}

/// Read and parse keyadm's configuration file.
///
/// # Errors
/// [`SettingsError`].
///
/// Spec: docs/50 R50-15, §7.1; crates/keyd-daemon `read_settings`.
pub fn read_settings(path: &Path) -> Result<KeyadmSettings, SettingsError> {
    let before = std::fs::metadata(path).map_err(|_| SettingsError::Unreadable)?;
    check(&before)?;
    let file = File::open(path).map_err(|_| SettingsError::Unreadable)?;
    let opened = file.metadata().map_err(|_| SettingsError::Unreadable)?;
    check(&opened)?;
    let bound = config::limits::MAX_FILE_OCTETS;
    let mut contents = Vec::new();
    file.take(u64::try_from(bound).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut contents)
        .map_err(|_| SettingsError::Unreadable)?;
    if contents.len() > bound {
        return Err(SettingsError::TooLarge);
    }
    KeyadmSettings::parse(&contents).map_err(SettingsError::Config)
}
