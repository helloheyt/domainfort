//! Tier 2 (docs/50 §9): dird's redb file reached through
//! crates/protected-file (task R11b; docs/52 §3.13 C13, §7 R11;
//! docs/questions/Q-481 item c, Q-530) — the path is walked from `/` with
//! dird's account as the owner, the file is opened for reading and writing
//! relative to the checked directory without following a link, and redb is
//! handed that descriptor (dirstore `Store::open_file`): a symbolic link in
//! a directory component or a directory writable by group or others refuses
//! the start before anything is bound; a link at the file's own name is the
//! file rule's refusal; the store in valid directories serves.
//!
//! The tests run as an ordinary account (dird's account is the test's own);
//! the store lives inside the workspace (crates/test-scratch, Q-480), the
//! sockets in the support's temporary directory.
//!
//! Sources: docs/50 R50-2, R50-16, §6.4 ("access to the redb file only
//! (owned by dird, 0600)"), §7.5; Q-468 options 1, 2(b) (A-102); Q-481
//! (A-104). Every value is hand-made (tests/support).

mod support;

use core::time::Duration;
use directory_daemon::StoreSource;
use dirstore::IntegrityKey;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use support::{Dird, Directory, FakeAuditd, TempDir};

fn chmod(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// Start dird on the redb file at `path` (dird's account: `uid`).
fn start(dir: &TempDir, uid: u32, path: PathBuf) -> Result<Dird, String> {
    Dird::start(
        support::params(dir, uid, uid, Duration::from_secs(5), 4),
        StoreSource::File {
            path,
            key: IntegrityKey::from_bytes(&support::TEST_KEY),
            owner_uid: uid,
        },
        support::policy(1),
    )
}

// docs/52 §3.13 (C13), Q-468 options 1, 2(b): through a link in a directory
// component, or with a directory writable by group or others, dird refuses
// to start and binds nothing; through the real, unwritable directory it
// serves.
#[test]
fn the_store_path_is_walked_before_dird_starts() {
    let dir = TempDir::new();
    let uid = support::my_uid(&dir);
    if support::skip_as_root(uid) {
        return;
    }
    let files = test_scratch::ScratchDir::new("dird-walk").unwrap();
    let real = files.join("var");
    std::fs::create_dir(&real).unwrap();
    chmod(&real, 0o700);
    let path = real.join("directory.redb");
    drop(Directory::standard(&path));
    std::os::unix::fs::symlink(&real, files.join("via")).unwrap();
    let _auditd = FakeAuditd::start_recording_as(&dir.join("a.sock"), ipc_audit::EventSource::Dird);

    let through_link = start(&dir, uid, files.join("via/directory.redb"))
        .err()
        .unwrap();
    assert!(
        through_link.contains("directory file's path"),
        "{through_link}"
    );
    for mode in [0o770, 0o707] {
        chmod(&real, mode);
        let writable = start(&dir, uid, path.clone()).err().unwrap();
        assert!(writable.contains("directory file's path"), "{writable}");
    }
    chmod(&real, 0o700);
    // A link at the file's own name: the file rule (a link's facts are
    // never a regular file's).
    let link = real.join("link.redb");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    let named_link = start(&dir, uid, link).err().unwrap();
    assert!(named_link.contains("directory file must"), "{named_link}");
    assert!(!dir.join("d.sock").exists(), "nothing bound");

    start(&dir, uid, path).unwrap().stop().unwrap();
}
