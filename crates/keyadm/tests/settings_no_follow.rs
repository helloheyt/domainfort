//! keyadm's configuration reader refuses a symbolic link to a valid file
//! (task F7: the A-86 follow-up "O_NOFOLLOW in every reader").
//!
//! The test runs as an ordinary account, so the owner is injected
//! (`read_settings_owned_by`, the test account standing in for root).
//!
//! Source: docs/50 §7.1 ("file root:0644"); A-86. Test-only.

use keyadm::settings::{read_settings, read_settings_owned_by, SettingsError};
use std::os::unix::fs::{MetadataExt, PermissionsExt};

/// docs/50 §7.1; A-86: the file is accepted through its own path, and a link
/// to it is refused as `Permissions` (not a regular file), by the injected-
/// owner reader and by the root-owner reader alike.
#[test]
fn a_symbolic_link_to_a_valid_configuration_is_refused() {
    let dir = std::env::temp_dir().join(format!("keyadm-nofollow-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
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
    let _ = std::fs::remove_dir_all(&dir);
}
