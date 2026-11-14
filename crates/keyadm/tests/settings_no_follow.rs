//! keyadm's configuration reader refuses a symbolic link to a valid file
//! (task F7: the A-86 follow-up "O_NOFOLLOW in every reader").
//!
//! The test runs as an ordinary account, so the owner is injected
//! (`read_settings_owned_by`, the test account standing in for root).
//!
//! Source: docs/50 §7.1 ("file root:0644"); A-86. Test-only.

use keyadm::settings::{read_settings, read_settings_owned_by, SettingsError};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use test_scratch::ScratchDir;

/// docs/50 §7.1; A-86: the file is accepted through its own path, and a link
/// to it is refused as `Permissions` (not a regular file), by the injected-
/// owner reader and by the root-owner reader alike.
#[test]
fn a_symbolic_link_to_a_valid_configuration_is_refused() {
    // Inside the workspace (crates/test-scratch): the protected-file walk
    // from `/` accepts it (Q-480).
    let scratch = ScratchDir::new("keyadm-nofollow").unwrap();
    let dir = scratch.path().to_path_buf();
    let path = dir.join("keyadm.conf");
    std::fs::write(
        &path,
        "keyd_socket = /run/test-keyd/keyd.sock\nkeyd_uid = 4101\n",
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let owner = std::fs::metadata(&path).unwrap().uid();
    let settings = read_settings_owned_by(&path, owner).unwrap();
    assert_eq!(settings.keyd().uid(), 4101);
    let link = dir.join("link.conf");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    assert_eq!(
        read_settings_owned_by(&link, owner),
        Err(SettingsError::Permissions)
    );
    assert_eq!(read_settings(&link), Err(SettingsError::Permissions));
}

/// Task T (docs/52 R11; Q-468 options 1, 2(b), A-102): every directory on
/// the configuration's path is checked — a symbolic link in a directory
/// component, or a directory writable by group or others, is refused as
/// `Permissions`; the file through real, unwritable directories is read.
#[test]
fn a_link_or_a_writable_directory_on_the_path_is_refused() {
    let scratch = ScratchDir::new("keyadm-dirs").unwrap();
    let dir = scratch.path().to_path_buf();
    let real = dir.join("real");
    std::fs::create_dir(&real).unwrap();
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = real.join("keyadm.conf");
    std::fs::write(
        &path,
        "keyd_socket = /run/test-keyd/keyd.sock\nkeyd_uid = 4101\n",
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let owner = std::fs::metadata(&path).unwrap().uid();
    assert!(read_settings_owned_by(&path, owner).is_ok());
    std::os::unix::fs::symlink(&real, dir.join("via")).unwrap();
    assert_eq!(
        read_settings_owned_by(&dir.join("via/keyadm.conf"), owner),
        Err(SettingsError::Permissions)
    );
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o757)).unwrap();
    assert_eq!(
        read_settings_owned_by(&path, owner),
        Err(SettingsError::Permissions)
    );
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(read_settings_owned_by(&path, owner).is_ok());
}
