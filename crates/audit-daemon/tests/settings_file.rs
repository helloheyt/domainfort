//! Tier 1 (docs/50 §9): auditd's configuration-file reader — the checks of
//! startup step 3 (a regular file, not writable by group or others, owned by
//! the expected account; bounded), and task F7's: a symbolic link to a valid
//! file is refused (A-86 follow-up, "O_NOFOLLOW in every reader").
//!
//! The tests run as an ordinary account, so the owner is injected
//! (`read_settings_owned_by`; `main` uses `read_settings`, owner 0).
//!
//! Sources: docs/50 R50-15, §7.1 ("root:0644 (not secret)"); docs/questions/
//! Q-230 item 16; A-86. The configuration text is hand-written in the
//! docs/50 §7.1 format (obviously fake ids and paths).

use audit_daemon::startup::{read_settings, read_settings_owned_by, SettingsError};
use std::io::ErrorKind;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// auditd's required keys (docs/50 §2.4, §8.1).
const AUDITD: &str = "\
run_as_uid = 805
run_as_gid = 805
audit_socket = /run/auditd/audit.sock
audit_log_path = /var/log/audit/domain-audit.log
uid_sources = 801:keyd
";

/// A scratch directory, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        let path =
            std::env::temp_dir().join(format!("auditd-settings-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        Scratch(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn write(path: &Path, text: &[u8], mode: u32) {
    std::fs::write(path, text).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// docs/50 §7.1; Q-230 item 16: the checks in startup step 3's order — not a
/// regular file, writable by group or others, another owner — then the
/// bound and the content.
#[test]
fn the_configuration_file_checks() {
    let dir = Scratch::new("checks");
    let path = dir.0.join("auditd.conf");
    write(&path, AUDITD.as_bytes(), 0o644);
    let owner = std::fs::metadata(&path).unwrap().uid();
    let settings = read_settings_owned_by(&path, owner).unwrap();
    assert_eq!(settings.uid_sources().len(), 1);
    assert_eq!(
        read_settings_owned_by(&path, owner.wrapping_add(1)),
        Err(SettingsError::NotRootOwned)
    );
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o664)).unwrap();
    // Writable is checked before the owner (startup step 3's order).
    assert_eq!(
        read_settings_owned_by(&path, owner.wrapping_add(1)),
        Err(SettingsError::Writable)
    );
    assert_eq!(
        read_settings_owned_by(&dir.0, owner),
        Err(SettingsError::NotAFile)
    );
    assert_eq!(
        read_settings_owned_by(&dir.0.join("absent"), owner),
        Err(SettingsError::Io(ErrorKind::NotFound))
    );
    let large = dir.0.join("large.conf");
    write(
        &large,
        &vec![b'\n'; config::limits::MAX_FILE_OCTETS + 1],
        0o644,
    );
    assert_eq!(
        read_settings_owned_by(&large, owner),
        Err(SettingsError::TooLarge)
    );
}

/// Task F7 (A-86 follow-up): a symbolic link to the valid file is refused as
/// `NotAFile` — by the injected-owner reader and by `read_settings` (owner
/// 0) alike — and never followed.
#[test]
fn a_symbolic_link_to_a_valid_configuration_is_refused() {
    let dir = Scratch::new("link");
    let path = dir.0.join("auditd.conf");
    write(&path, AUDITD.as_bytes(), 0o644);
    let owner = std::fs::metadata(&path).unwrap().uid();
    assert!(read_settings_owned_by(&path, owner).is_ok());
    let link = dir.0.join("link.conf");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    assert_eq!(
        read_settings_owned_by(&link, owner),
        Err(SettingsError::NotAFile)
    );
    assert_eq!(read_settings(&link), Err(SettingsError::NotAFile));
}
