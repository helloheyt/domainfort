//! Reading keyadm's configuration file.
//!
//! The file must be a regular file owned by root and not writable by group
//! or others (docs/50 §7.1: "file root:0644"), the rule the daemons and the
//! manifest file obey; at most `config::limits::MAX_FILE_OCTETS` + 1 octets
//! are read. Since task F7 the file is reached through crates/protected-file
//! (A-86 follow-up): the path is inspected without following a symbolic link
//! (a link is refused as not a regular file), opened with O_NOFOLLOW, and
//! the rule applied again to the opened descriptor.
//!
//! Spec: docs/50 R50-15, §7.1; docs/51 §6; A-86; AGENTS.md §6.

use config::KeyadmSettings;
use core::fmt;
use protected_file::Refusal;
use std::path::Path;

/// The owner keyadm's configuration file must have: root.
/// Spec: docs/50 §7.1 ("file root:0644").
const ROOT_UID: u32 = 0;

/// Why the configuration file was not accepted. Carries no file content
/// (the configuration's own errors never echo a value, A-60).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettingsError {
    /// The file could not be opened, inspected or read.
    Unreadable,
    /// Not a regular file (a symbolic link included) owned by root and
    /// writable only by its owner.
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

/// Read and parse keyadm's configuration file (owned by root).
///
/// # Errors
/// [`SettingsError`].
///
/// Spec: docs/50 R50-15, §7.1.
pub fn read_settings(path: &Path) -> Result<KeyadmSettings, SettingsError> {
    read_settings_owned_by(path, ROOT_UID)
}

/// Read and parse keyadm's configuration file, which must be owned by
/// `owner` (root in the binary; the test account in tests, as kdc-daemon's
/// and ldap-front's `read_settings`).
///
/// # Errors
/// [`SettingsError`].
///
/// Spec: docs/50 R50-15, §7.1; A-86 (crates/protected-file).
pub fn read_settings_owned_by(path: &Path, owner: u32) -> Result<KeyadmSettings, SettingsError> {
    let contents =
        protected_file::read_configuration_file(path, owner, config::limits::MAX_FILE_OCTETS)
            .map_err(|refusal| match refusal {
                Refusal::Unreadable(_) => SettingsError::Unreadable,
                Refusal::Rule(_) => SettingsError::Permissions,
                Refusal::TooLarge => SettingsError::TooLarge,
            })?;
    KeyadmSettings::parse(&contents).map_err(SettingsError::Config)
}
