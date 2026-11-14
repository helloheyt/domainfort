//! Tier 1 (docs/50 §9): the log's files through crates/protected-file
//! (task R11b; docs/52 §3.13 C13, §7 R11; docs/questions/Q-481 item b,
//! Q-530) — the listing, every read, every append and every new segment
//! walk the path from `/` with auditd's account as the owner: a symbolic
//! link in a directory component, a directory writable by group or others,
//! or a directory owned by neither root nor auditd's account refuses the
//! start (an operational refusal, not a chain break) and nothing is created
//! through it; an existing segment that is not auditd's, or has any
//! permission for group or others (task R11c: a group-readable segment
//! too), is refused; a rotation into a directory that has become writable
//! fails; the happy path still creates, appends and resumes.
//!
//! The tests run as an ordinary account: auditd's account is the test's own
//! (`common::log_uid`), and the log lives in a scratch directory inside the
//! workspace (crates/test-scratch, Q-480).
//!
//! Sources: docs/50 §2.4 (auditd "holds the audit file"), §6.4 ("append
//! write access to the audit file only"), §7.5; docs/37 §2; Q-468 options 1,
//! 2(b) (A-102); Q-481 (A-104); Q-531 item 4 (A-109: "no group/other
//! access at all, matching the 0600 it creates"). Payloads are arbitrary
//! test octets.

mod common;

use audit_daemon::recovery::{open_log, StartKind, StartupError};
use audit_daemon::segments::{segment_path, FileSegments, ListingError, SegmentFactory};
use audit_daemon::startup::prepare_socket_directory;
use audit_log::SegmentLimit;
use common::*;
use protected_file::{DataFileBreak, PathBreak, SocketDirectoryBreak, SocketDirectoryError};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

fn chmod(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn start_error(base: &Path, owner: u32) -> StartupError {
    open_log(base, SegmentLimit::DEFAULT, owner).expect_err("refused")
}

// docs/50 §7.5, §6.4: the happy path through the walk — segment 1 created
// (mode 0600), a batch appended, the log resumed at the next start.
#[test]
fn the_log_is_created_appended_and_resumed_through_the_walk() {
    let dir = TempDir::new();
    let opened = open_log(&dir.base(), SegmentLimit::DEFAULT, log_uid()).expect("created");
    assert_eq!(opened.start, StartKind::Created);
    let first = segment_path(&dir.base(), 1);
    let metadata = std::fs::symlink_metadata(&first).unwrap();
    assert_eq!(metadata.mode() & 0o7777, 0o600);
    assert_eq!(metadata.uid(), log_uid());
    drop(opened);
    build_log_after(&dir);
    let reopened = open_log(&dir.base(), SegmentLimit::DEFAULT, log_uid()).expect("resumed");
    assert_eq!(reopened.start, StartKind::Resumed);
}

/// Append a batch to the existing log in `dir` the way the writer does
/// after a start (resume through the walk — `open_append` — append, stop).
fn build_log_after(dir: &TempDir) {
    let mut sink = open_log(&dir.base(), SegmentLimit::DEFAULT, log_uid())
        .expect("resumed")
        .sink;
    let before = sink.head();
    let persisted = sink
        .append_events(audit_log::Source::Kdc, 803, 1, &events(2, 40, 3))
        .expect("persisted");
    assert_eq!(persisted.head.seq, before.seq + 2);
}

// docs/52 §3.13 (C13), Q-468 option 1: a symbolic link in a directory
// component of `audit_log_path` refuses the start before any segment is
// listed, read or created — nothing appears in the directory the link
// leads to.
#[test]
fn a_link_in_a_directory_component_refuses_the_start() {
    let dir = TempDir::new();
    let real = dir.path().join("real");
    std::fs::create_dir(&real).unwrap();
    chmod(&real, 0o700);
    std::os::unix::fs::symlink(&real, dir.path().join("via")).unwrap();
    let error = start_error(&dir.path().join("via/audit.log"), log_uid());
    assert_eq!(
        error,
        StartupError::Listing(ListingError::Directory(PathBreak::NotADirectory))
    );
    assert!(!error.is_chain_break());
    assert_eq!(
        std::fs::read_dir(&real).unwrap().count(),
        0,
        "nothing created"
    );
    // The same directory by its real path is accepted.
    assert_eq!(
        open_log(&real.join("audit.log"), SegmentLimit::DEFAULT, log_uid())
            .expect("created")
            .start,
        StartKind::Created
    );
}

// Q-468 option 2(b): a log directory writable by its group or by others,
// or owned by neither root nor auditd's account, refuses the start.
#[test]
fn a_writable_or_foreign_log_directory_refuses_the_start() {
    let dir = TempDir::new();
    build_log(&dir.base(), &[2], 64);
    for mode in [0o770, 0o707, 0o1777] {
        chmod(dir.path(), mode);
        assert_eq!(
            start_error(&dir.base(), log_uid()),
            StartupError::Listing(ListingError::Directory(
                PathBreak::DirectoryWritableByGroupOrOthers
            )),
            "{mode:o}"
        );
    }
    chmod(dir.path(), 0o700);
    if log_uid() != 0 {
        assert_eq!(
            start_error(&dir.base(), log_uid().wrapping_add(1)),
            StartupError::Listing(ListingError::Directory(PathBreak::DirectoryWrongOwner))
        );
    }
    assert!(open_log(&dir.base(), SegmentLimit::DEFAULT, log_uid()).is_ok());
}

// docs/50 §2.4, §6.4; Q-531 item 4 (A-109); crate::segments
// `segment_rule`: an existing segment with any permission for group or
// others — writable by them, or only readable (0640), or readable by others
// (0604) — is refused when it is opened (an operational refusal, not a
// chain break); the 0600 auditd creates is accepted.
#[test]
fn a_segment_accessible_by_group_or_others_refuses_the_start() {
    let dir = TempDir::new();
    build_log(&dir.base(), &[2, 1], 64);
    let second = segment_path(&dir.base(), 2);
    for refused in [0o620, 0o640, 0o604, 0o660] {
        chmod(&second, refused);
        let error = start_error(&dir.base(), log_uid());
        assert_eq!(
            error,
            StartupError::SegmentRule(DataFileBreak::AccessibleByGroupOrOthers),
            "{refused:o}"
        );
        assert!(!error.is_chain_break());
        assert_eq!(
            error.to_string(),
            "audit log segment refused: accessible by group or others"
        );
    }
    chmod(&second, 0o600);
    assert_eq!(
        open_log(&dir.base(), SegmentLimit::DEFAULT, log_uid())
            .expect("resumed")
            .start,
        StartKind::Resumed
    );
}

// docs/50 §6.4, Q-481 item b: a new segment is created only in a directory
// that passes the walk — after the directory became writable by its group
// the next segment is not created (the rotation fails; the writer
// acknowledges nothing), and an existing name is never reused.
#[test]
fn a_new_segment_needs_a_directory_that_passes_the_walk() {
    let dir = TempDir::new();
    build_log(&dir.base(), &[1], 64);
    let mut files = FileSegments::new(dir.base(), log_uid());
    assert_eq!(
        files.create(1).err().map(|e| e.kind()),
        Some(std::io::ErrorKind::AlreadyExists),
        "an existing segment is never reopened for writing"
    );
    chmod(dir.path(), 0o770);
    assert_eq!(
        files.create(2).err().map(|e| e.kind()),
        Some(std::io::ErrorKind::PermissionDenied)
    );
    chmod(dir.path(), 0o700);
    assert!(!segment_path(&dir.base(), 2).exists());
    assert!(files.create(2).is_ok());
}

// Task R11c (docs/50 §3.1; docs/52 C13; docs/questions Q-532 items 1, 5,
// A-109): auditd now prepares its socket directory as root before the drop,
// through the same crates/protected-file implementation as keyd, dird and
// admind — created by descriptor (mode 0750, auditd's account), a stale
// socket removed relative to it; a symbolic link at its name is refused and
// nothing is changed through it. The test account stands in for auditd's.
#[test]
fn the_socket_directory_is_prepared_by_descriptor() {
    use std::os::unix::fs::FileTypeExt;
    let dir = TempDir::new();
    let uid = log_uid();
    if uid == 0 {
        return;
    }
    // The scratch directory's group: one the test account belongs to, so
    // the owner change of a created directory is allowed unprivileged.
    let gid = std::fs::metadata(dir.path()).unwrap().gid();
    let settings = |socket_dir: &Path| {
        let text = format!(
            "run_as_uid = {uid}\nrun_as_gid = {gid}\naudit_socket = {}/audit.sock\n\
             audit_log_path = {}\nuid_sources = {}:kdc\n",
            socket_dir.display(),
            dir.base().display(),
            other_uid(&[uid])
        );
        config::AuditdSettings::parse(text.as_bytes()).unwrap()
    };
    let run = dir.path().join("run");
    assert_eq!(prepare_socket_directory(&settings(&run)), Ok(()));
    let metadata = std::fs::symlink_metadata(&run).unwrap();
    assert!(metadata.is_dir());
    assert_eq!(
        metadata.mode() & 0o7777,
        protected_file::SOCKET_DIRECTORY_MODE
    );
    assert_eq!((metadata.uid(), metadata.gid()), (uid, gid));
    // A socket left by an earlier run is removed.
    drop(std::os::unix::net::UnixListener::bind(run.join("audit.sock")).unwrap());
    assert!(std::fs::symlink_metadata(run.join("audit.sock"))
        .unwrap()
        .file_type()
        .is_socket());
    assert_eq!(prepare_socket_directory(&settings(&run)), Ok(()));
    assert!(std::fs::symlink_metadata(run.join("audit.sock")).is_err());
    // A link at the directory's name: refused, not followed.
    let real = dir.path().join("real");
    std::fs::create_dir(&real).unwrap();
    chmod(&real, 0o700);
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    assert_eq!(
        prepare_socket_directory(&settings(&link)),
        Err(SocketDirectoryError::Directory(
            SocketDirectoryBreak::NotADirectory
        ))
    );
    assert_eq!(std::fs::metadata(&real).unwrap().mode() & 0o7777, 0o700);
}
