//! `provision first-admin-secret`'s password files reached through
//! crates/protected-file's walk (task R11b; docs/52 §3.13 C13, §7 R11;
//! docs/questions/Q-481 item a, Q-530): a symbolic link in a directory
//! component, a directory writable by group or others, or a directory owned
//! by neither root nor the running uid is refused before the file is looked
//! at; a link at the file's own name is still reported as a link; a valid
//! file in valid directories is opened and read.
//!
//! The tests run as an ordinary account — the running uid is the test's
//! own — in a scratch directory inside the workspace (crates/test-scratch,
//! Q-480), which the walk from `/` accepts with that uid as the owner.
//!
//! Sources: docs/51 §4.4 ("a regular file (not a symlink), owned by the
//! running uid, mode 0400/0600, ≤ 1024 bytes, one line"); Q-468 options 1,
//! 2(b) (A-102); Q-481 (A-104). The password is test data made up here.

use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use protected_file::PathBreak;
use provision::first_admin::password_file::{open_password_file, FileRefusal};
use test_scratch::ScratchDir;

/// The test password (constructed by hand; obviously test data).
const PASSWORD: &str = "Saffron-Lantern-Mosaic-29";

struct Scratch(PathBuf, #[allow(dead_code)] ScratchDir);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        let dir = ScratchDir::new(&format!("prv-pw-{tag}")).unwrap();
        Scratch(dir.path().to_path_buf(), dir)
    }

    /// A directory `relative` (parents included), mode 0700.
    fn dir(&self, relative: &str) -> PathBuf {
        let path = self.0.join(relative);
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&path)
            .unwrap();
        path
    }

    /// A password file `relative`, mode 0600, holding the test password.
    fn password_file(&self, relative: &str) -> PathBuf {
        let path = self.0.join(relative);
        std::fs::write(&path, format!("{PASSWORD}\n")).unwrap();
        chmod(&path, 0o600);
        path
    }

    fn uid(&self) -> u32 {
        std::fs::metadata(&self.0).unwrap().uid()
    }
}

fn chmod(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

// docs/51 §4.4: a valid password file in valid directories is opened (as
// the running uid) and its one line read.
#[test]
fn a_valid_password_file_is_opened_and_read() {
    let dir = Scratch::new("ok");
    let uid = dir.uid();
    dir.dir("secrets/admin");
    let path = dir.password_file("secrets/admin/alice.pw");
    let opened = open_password_file(&path, uid).unwrap();
    assert_eq!(opened.read().unwrap().expose(), PASSWORD);
}

// docs/52 §3.13 (C13), Q-468 option 1: a symbolic link in a directory
// component is refused — whether it leads to the real directory or not —
// before the file is looked at; the same file through the real directory
// is accepted.
#[test]
fn a_link_in_a_directory_component_is_refused() {
    let dir = Scratch::new("dirlink");
    let uid = dir.uid();
    let real = dir.dir("real");
    let path = dir.password_file("real/alice.pw");
    assert!(open_password_file(&path, uid).is_ok());
    std::os::unix::fs::symlink(&real, dir.0.join("via")).unwrap();
    assert_eq!(
        open_password_file(&dir.0.join("via/alice.pw"), uid).unwrap_err(),
        FileRefusal::Path(PathBreak::NotADirectory)
    );
    // The file's own name as a link is still the file rule's `Symlink`.
    std::os::unix::fs::symlink(&path, real.join("link.pw")).unwrap();
    assert_eq!(
        open_password_file(&real.join("link.pw"), uid).unwrap_err(),
        FileRefusal::Symlink
    );
}

// Q-468 option 2(b): a directory writable by its group or by others is
// refused; with the write bits cleared the file is accepted again.
#[test]
fn a_group_or_other_writable_directory_is_refused() {
    let dir = Scratch::new("writable");
    let uid = dir.uid();
    let secrets = dir.dir("secrets");
    let path = dir.password_file("secrets/alice.pw");
    for mode in [0o770, 0o707, 0o1777] {
        chmod(&secrets, mode);
        assert_eq!(
            open_password_file(&path, uid).unwrap_err(),
            FileRefusal::Path(PathBreak::DirectoryWritableByGroupOrOthers),
            "{mode:o}"
        );
    }
    chmod(&secrets, 0o700);
    assert!(open_password_file(&path, uid).is_ok());
}

// Q-468 option 2(b): with another running uid, the test account's
// directories are owned by neither root nor that uid — refused before the
// file's own owner is looked at.
#[test]
fn a_directory_of_another_account_is_refused() {
    let dir = Scratch::new("owner");
    let uid = dir.uid();
    if uid == 0 {
        eprintln!("skipped: running as root (root's directories are always accepted)");
        return;
    }
    let path = dir.password_file("alice.pw");
    assert_eq!(
        open_password_file(&path, uid.wrapping_add(1000)).unwrap_err(),
        FileRefusal::Path(PathBreak::DirectoryWrongOwner)
    );
}

// The refusal texts name the path's break and never the content.
#[test]
fn a_path_refusal_names_the_break_only() {
    let text = FileRefusal::Path(PathBreak::NotADirectory).to_string();
    assert!(text.starts_with("the password file's path has a directory component"));
    assert!(!text.contains(PASSWORD));
}
