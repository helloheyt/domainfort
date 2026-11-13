//! Tier 1: reading the policy file from disk (moved from dird's
//! `read_policy` with the decoder, A-68) — the owner and mode checks, the
//! absence, a refused file (docs/50 §7.1, §7.2: "absent or invalid ⇒ do not
//! start").
//!
//! The root-owned case cannot be made by an unprivileged test: the function
//! takes the expected owner, and the daemons pass uid 0.
//!
//! Sources: docs/50 §7.1, §7.2; docs/questions/Q-270 item 2. Hand-made
//! values.

mod common;

use common::sample_policy;
use policy_store::{read_file, LoadError, PolicyError, MARKER, MAX_POLICY_FILE};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// A unique temporary directory (0700), removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> TempDir {
        let path = std::env::temp_dir().join(format!("pst{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        TempDir(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn write(path: &Path, octets: &[u8], mode: u32) {
    std::fs::write(path, octets).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// docs/50 §7.2 ("dird loads the same file at start"; absent or invalid ⇒
/// do not start): the policy file must be of the expected owner and not
/// writable by group or others; absent, oversized or broken is refused.
#[test]
fn the_policy_file_is_checked_and_absent_is_refused() {
    let dir = TempDir::new("file");
    let uid = std::fs::metadata(&dir.0).unwrap().uid();
    let path = dir.0.join("policy.store");
    write(&path, &sample_policy().encode().unwrap(), 0o644);
    assert_eq!(read_file(&path, uid).unwrap(), sample_policy());
    assert_eq!(
        read_file(&path, uid + 1).err(),
        Some(LoadError::Permissions)
    );
    for mode in [0o664, 0o646, 0o666] {
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        assert_eq!(
            read_file(&path, uid).err(),
            Some(LoadError::Permissions),
            "mode {mode:o}"
        );
    }
    assert_eq!(
        read_file(&dir.0.join("absent"), uid).err(),
        Some(LoadError::Unreadable)
    );
    assert_eq!(read_file(&dir.0, uid).err(), Some(LoadError::Permissions));
    let broken = dir.0.join("broken.store");
    write(&broken, b"not a policy", 0o644);
    assert_eq!(
        read_file(&broken, uid).err(),
        Some(LoadError::Policy(PolicyError::NotMarked))
    );
    let huge = dir.0.join("huge.store");
    let mut octets = MARKER.to_vec();
    octets.resize(MAX_POLICY_FILE as usize + 10, 0);
    write(&huge, &octets, 0o644);
    assert_eq!(
        read_file(&huge, uid).err(),
        Some(LoadError::Policy(PolicyError::TooLarge))
    );
}
