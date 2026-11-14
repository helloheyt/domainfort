//! The manifest reader with an injected owner: a valid manifest owned by the
//! test account is read, and a symbolic link to that same file is refused —
//! the link is never followed (task F7: the A-86 / A-96 follow-up
//! "O_NOFOLLOW in every reader"; Q-414 item 4: one reader, owner
//! injectable).
//!
//! Source: docs/51 §4.3 step 8 (root:0644); docs/50 §7.1; A-86; A-96.
//! Test-only; the sample is this crate's own (tests/common).

mod common;

use common::SAMPLE;
use provision_manifest::{read_manifest, read_manifest_owned_by, Manifest, ReadError};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;
use test_scratch::ScratchDir;

/// A scratch directory inside the workspace (crates/test-scratch: the
/// protected-file walk from `/` accepts it; Q-480), removed on drop.
struct Scratch(PathBuf, #[allow(dead_code)] ScratchDir);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        let dir = ScratchDir::new(&format!("pm-nofollow-{tag}")).unwrap();
        Scratch(dir.path().to_path_buf(), dir)
    }
}

/// A-86 / Q-414 item 4: with the test account as the owner, the manifest
/// file is read and parsed; a link to it is `NotRegularFile`; the rule's
/// other parts still hold (another owner, group write, a directory).
#[test]
fn a_symbolic_link_to_a_valid_manifest_is_refused() {
    let dir = Scratch::new("link");
    let path = dir.0.join("manifest");
    std::fs::write(&path, SAMPLE).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let uid = std::fs::metadata(&path).unwrap().uid();
    assert_eq!(
        read_manifest_owned_by(&path, uid).unwrap(),
        Manifest::parse(SAMPLE.as_bytes()).unwrap()
    );
    let link = dir.0.join("link");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    assert_eq!(
        read_manifest_owned_by(&link, uid).unwrap_err(),
        ReadError::NotRegularFile
    );
    // The owner-0 reader refuses it too — already at the first directory of
    // the test account on the path, which root's expectation does not accept
    // (task T: every directory on the path is root's or the file owner's,
    // Q-468).
    let as_root = if uid == 0 {
        ReadError::NotRegularFile
    } else {
        ReadError::NotRootOwned
    };
    assert_eq!(read_manifest(&link).unwrap_err(), as_root);
    assert_eq!(
        read_manifest_owned_by(&path, uid.wrapping_add(1)).unwrap_err(),
        ReadError::NotRootOwned
    );
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o664)).unwrap();
    assert_eq!(
        read_manifest_owned_by(&path, uid).unwrap_err(),
        ReadError::WritableByOthers
    );
    assert_eq!(
        read_manifest_owned_by(&dir.0, uid).unwrap_err(),
        ReadError::NotRegularFile
    );
}

/// docs/50 §7.1 ("file ≤ 64 KiB"): one octet over the bound is refused
/// without being parsed.
#[test]
fn an_oversized_manifest_is_refused() {
    let dir = Scratch::new("large");
    let path = dir.0.join("manifest");
    let mut content = SAMPLE.as_bytes().to_vec();
    content.resize(provision_manifest::limits::MAX_FILE_OCTETS + 1, b'\n');
    std::fs::write(&path, content).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let uid = std::fs::metadata(&path).unwrap().uid();
    assert_eq!(
        read_manifest_owned_by(&path, uid).unwrap_err(),
        ReadError::TooLarge
    );
}

/// Task T (docs/52 R11; Q-468 options 1, 2(b), A-102): every directory on
/// the manifest's path is checked, not only the file — a symbolic link in a
/// directory component is `NotRegularFile`, a directory writable by group or
/// others is `WritableByOthers`; the same manifest through real, unwritable
/// directories is read.
#[test]
fn a_link_or_a_writable_directory_on_the_path_is_refused() {
    let dir = Scratch::new("dirs");
    let real = dir.0.join("real");
    std::fs::create_dir(&real).unwrap();
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = real.join("manifest");
    std::fs::write(&path, SAMPLE).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let uid = std::fs::metadata(&path).unwrap().uid();
    assert!(read_manifest_owned_by(&path, uid).is_ok());
    std::os::unix::fs::symlink(&real, dir.0.join("via")).unwrap();
    assert_eq!(
        read_manifest_owned_by(&dir.0.join("via/manifest"), uid).unwrap_err(),
        ReadError::NotRegularFile
    );
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o775)).unwrap();
    assert_eq!(
        read_manifest_owned_by(&path, uid).unwrap_err(),
        ReadError::WritableByOthers
    );
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(read_manifest_owned_by(&path, uid).is_ok());
}
