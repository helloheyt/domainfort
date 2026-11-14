//! The manifest-file rule: a regular file owned by root and not writable by
//! group or others, read only up to the bound.
//!
//! Source: docs/51 §4.3 step 8 (the manifest is root:0644); docs/50 §7.1
//! (the configuration-file rule it follows; crates/keyd-daemon
//! `read_settings`). The tests run as an ordinary user, who cannot create a
//! root-owned file: the root-owned cases are checked on [`FileFacts`], and
//! the real-file cases show that a file the test user owns — however its
//! mode — is refused.

mod common;

use common::SAMPLE;
use provision_manifest::{check_file, read_manifest, read_manifest_owned_by, FileFacts, ReadError};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;
use test_scratch::ScratchDir;

/// A unique scratch directory inside the workspace (crates/test-scratch:
/// the protected-file walk from `/` accepts it; Q-480), removed on drop.
struct Scratch(PathBuf, #[allow(dead_code)] ScratchDir);

impl Scratch {
    fn new() -> Scratch {
        let dir = ScratchDir::new("pm").unwrap();
        Scratch(dir.path().to_path_buf(), dir)
    }

    fn file(&self, name: &str, contents: &[u8], mode: u32) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, contents).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }
}

fn facts(regular_file: bool, owner_uid: u32, mode: u32) -> FileFacts {
    FileFacts {
        regular_file,
        symbolic_link: false,
        owner_uid,
        mode,
        size: 0,
    }
}

/// docs/51 §4.3 step 8 ("root:0644"): root-owned and not group/other
/// writable is accepted (0644, 0444, 0600, 0640); group or other write is
/// refused; another owner is refused; a non-regular file is refused.
#[test]
fn the_file_rule_on_facts() {
    const REGULAR: u32 = 0o100_000;
    for mode in [0o644, 0o444, 0o600, 0o640] {
        assert_eq!(
            check_file(&facts(true, 0, REGULAR | mode)),
            Ok(()),
            "{mode:o}"
        );
    }
    for mode in [0o664, 0o646, 0o666, 0o622, 0o777] {
        assert_eq!(
            check_file(&facts(true, 0, REGULAR | mode)),
            Err(ReadError::WritableByOthers),
            "{mode:o}"
        );
    }
    assert_eq!(
        check_file(&facts(true, 1000, REGULAR | 0o644)),
        Err(ReadError::NotRootOwned)
    );
    assert_eq!(
        check_file(&facts(false, 0, 0o040_755)),
        Err(ReadError::NotRegularFile)
    );
}

/// docs/51 §4.3 step 8: a valid manifest in a file the test user owns is
/// refused as not root-owned (wrong ownership), whatever its mode; a
/// directory and a missing path are refused too.
#[test]
fn a_file_not_owned_by_root_is_refused() {
    let scratch = Scratch::new();
    let path = scratch.file("manifest", SAMPLE.as_bytes(), 0o644);
    if std::fs::metadata(&path).unwrap().uid() == 0 {
        eprintln!("skipped: running as root (the file would be root-owned)");
        return;
    }
    assert_eq!(read_manifest(&path).unwrap_err(), ReadError::NotRootOwned);
    let writable = scratch.file("writable", SAMPLE.as_bytes(), 0o666);
    assert_eq!(
        read_manifest(&writable).unwrap_err(),
        ReadError::NotRootOwned
    );
    // A directory is not a regular file, and a missing file is unreadable —
    // asked with the test account standing in for root: with root's
    // expectation the walk refuses the first directory of the test account
    // on the path (task T, Q-468), as it does for the two files above.
    let uid = std::fs::metadata(&path).unwrap().uid();
    assert_eq!(
        read_manifest_owned_by(&scratch.0, uid).unwrap_err(),
        ReadError::NotRegularFile
    );
    assert_eq!(
        read_manifest_owned_by(&scratch.0.join("absent"), uid).unwrap_err(),
        ReadError::Unreadable
    );
}
