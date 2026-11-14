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

/// A scratch directory under the system temporary directory, removed on
/// drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        let path = std::env::temp_dir().join(format!("pm-nofollow-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        Scratch(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
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
    // The owner-0 reader refuses the link the same way (before any owner
    // check: the link's own facts are not a regular file's).
    assert_eq!(read_manifest(&link).unwrap_err(), ReadError::NotRegularFile);
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
