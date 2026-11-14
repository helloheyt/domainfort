//! The opens that are not read-only, and the listing of a walked directory
//! (task R11b; docs/questions/Q-481 items b, c; Q-530): each goes through
//! the walk from `/` — a symbolic link in a directory component, a
//! directory writable by group or others, or a directory of another owner
//! is refused before the file is touched — and reaches the file relative to
//! the checked directory without following a link in its name.
//!
//! The tests run as an ordinary account (the expected owner is the test's
//! own uid); their directories live inside the workspace
//! (crates/test-scratch, Q-480), which the walk from `/` accepts.
//!
//! Sources: docs/50 §6.4 ("auditd: append write access to the audit file
//! only"; "dird: access to the redb file only (owned by dird, 0600)"),
//! §8.1; docs/52 §3.13 (C13), §7 R11; Q-468 options 1, 2(b), 3 (A-102);
//! Q-481 (A-104); rustix docs.rs `fs::OFlags` (`APPEND`, `CREATE`, `EXCL`,
//! `NOFOLLOW`, `RDWR`), `fs::fchmod`, `fs::Dir`. Test-only; no vector from
//! any other implementation.

use std::cell::Cell;
use std::io::{ErrorKind, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use protected_file::{
    create_new_append, for_each_entry_beside, open_append, open_read_write, FileFacts, OpenError,
    PathBreak,
};
use test_scratch::ScratchDir;

/// A scratch directory inside the workspace (mode 0700), removed at the end
/// of the test.
struct Scratch(PathBuf, #[allow(dead_code)] ScratchDir);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        let dir = ScratchDir::new(&format!("pf-write-{tag}")).unwrap();
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

    /// A file `relative` holding `content`, mode 0600.
    fn file(&self, relative: &str, content: &[u8]) -> PathBuf {
        let path = self.0.join(relative);
        std::fs::write(&path, content).unwrap();
        chmod(&path, 0o600);
        path
    }

    /// A symbolic link `relative` to `target`.
    fn link(&self, relative: &str, target: &Path) -> PathBuf {
        let path = self.0.join(relative);
        std::os::unix::fs::symlink(target, &path).unwrap();
        path
    }

    fn uid(&self) -> u32 {
        std::fs::metadata(&self.0).unwrap().uid()
    }
}

fn chmod(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// A data-file rule: a regular file owned by `owner` with no group or other
/// access (docs/50 §6.4, "0600"), counting its calls.
fn data_rule(
    owner: u32,
    calls: &Cell<u32>,
) -> impl Fn(&FileFacts) -> Result<(), &'static str> + '_ {
    move |facts| {
        calls.set(calls.get() + 1);
        if facts.symbolic_link {
            Err("link")
        } else if !facts.regular_file {
            Err("not regular")
        } else if facts.owner_uid != owner {
            Err("owner")
        } else if facts.mode & 0o077 != 0 {
            Err("mode")
        } else {
            Ok(())
        }
    }
}

// docs/50 §6.4, §8.1: a new data file is created exclusively, mode exactly
// 0600, opened for appending (a write lands at the end even after a seek);
// the rule sees the created file once; the same name cannot be created
// twice.
#[test]
fn a_new_file_is_created_exclusively_owner_only_and_append_only() {
    let dir = Scratch::new("create");
    let uid = dir.uid();
    let path = dir.0.join("segment");
    let calls = Cell::new(0);
    let mut file = create_new_append(&path, uid, data_rule(uid, &calls)).unwrap();
    assert_eq!(calls.get(), 1);
    let metadata = std::fs::symlink_metadata(&path).unwrap();
    assert!(metadata.file_type().is_file());
    assert_eq!(metadata.mode() & 0o7777, 0o600);
    file.write_all(b"head").unwrap();
    file.seek(SeekFrom::Start(0)).unwrap();
    file.write_all(b"-tail").unwrap();
    drop(file);
    assert_eq!(std::fs::read(&path).unwrap(), b"head-tail");
    assert_eq!(
        create_new_append(&path, uid, data_rule(uid, &calls)).err(),
        Some(OpenError::Io(ErrorKind::AlreadyExists))
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"head-tail", "not reused");
}

// Q-481 item b (`O_CREAT | O_EXCL | O_NOFOLLOW`): a symbolic link at the new
// name — to an existing file or dangling — is never followed: the creation
// fails and the link's target is neither created nor changed.
#[test]
fn a_new_file_is_not_created_through_a_link() {
    let dir = Scratch::new("create-link");
    let uid = dir.uid();
    let target = dir.file("target", b"keep");
    let link = dir.link("to-target", &target);
    let dangling = dir.link("to-absent", &dir.0.join("absent"));
    let calls = Cell::new(0);
    for name in [&link, &dangling] {
        assert!(
            matches!(
                create_new_append(name, uid, data_rule(uid, &calls)),
                Err(OpenError::Io(_))
            ),
            "{}",
            name.display()
        );
    }
    assert_eq!(calls.get(), 0, "the rule never ran");
    assert_eq!(std::fs::read(&target).unwrap(), b"keep");
    assert!(!dir.0.join("absent").exists());
}

// docs/50 §6.4, §8.1: an existing file opened for appending keeps its
// octets and every write lands at the end; the rule runs before and after
// the open.
#[test]
fn an_existing_file_is_opened_for_appending() {
    let dir = Scratch::new("append");
    let uid = dir.uid();
    let path = dir.file("segment", b"abc");
    let calls = Cell::new(0);
    let mut file = open_append(&path, uid, data_rule(uid, &calls)).unwrap();
    assert_eq!(calls.get(), 2);
    file.write_all(b"def").unwrap();
    drop(file);
    assert_eq!(std::fs::read(&path).unwrap(), b"abcdef");
}

// docs/50 R50-2, §6.4: an existing file opened for reading and writing.
#[test]
fn an_existing_file_is_opened_for_reading_and_writing() {
    let dir = Scratch::new("rw");
    let uid = dir.uid();
    let path = dir.file("store", b"0123");
    let calls = Cell::new(0);
    let mut file = open_read_write(&path, uid, data_rule(uid, &calls)).unwrap();
    assert_eq!(calls.get(), 2);
    let mut start = [0u8; 2];
    file.read_exact(&mut start).unwrap();
    assert_eq!(&start, b"01");
    file.seek(SeekFrom::Start(0)).unwrap();
    file.write_all(b"ab").unwrap();
    drop(file);
    assert_eq!(std::fs::read(&path).unwrap(), b"ab23");
}

// A-86 (O_NOFOLLOW), Q-481 items b, c: a link at the file's own name is
// refused by the rule on its inspected facts (a link's, never its
// target's), before any open — for appending and for reading and writing.
#[test]
fn a_link_at_the_name_is_refused_before_the_open() {
    let dir = Scratch::new("name-link");
    let uid = dir.uid();
    let target = dir.file("target", b"keep");
    let link = dir.link("to-target", &target);
    let calls = Cell::new(0);
    assert_eq!(
        open_append(&link, uid, data_rule(uid, &calls)).err(),
        Some(OpenError::Refused("link"))
    );
    assert_eq!(
        open_read_write(&link, uid, data_rule(uid, &calls)).err(),
        Some(OpenError::Refused("link"))
    );
    assert_eq!(calls.get(), 2, "once each, before the open");
    assert_eq!(std::fs::read(&target).unwrap(), b"keep");
}

// docs/52 §3.13 (C13), Q-468 option 1: a symbolic link in a directory
// component is refused before the file is touched — for every entry point
// of the write side and for the listing — even though the path through the
// real directory is accepted.
#[test]
fn a_link_in_a_directory_component_is_refused_everywhere() {
    let dir = Scratch::new("dir-link");
    let uid = dir.uid();
    let real = dir.dir("real");
    let existing = dir.file("real/existing", b"keep");
    assert!(open_append(&existing, uid, |_| Ok::<(), ()>(())).is_ok());
    dir.link("via", &real);
    let via_existing = dir.0.join("via/existing");
    let via_new = dir.0.join("via/new");
    let broken = Some(OpenError::Path(PathBreak::NotADirectory));
    let calls = Cell::new(0);
    assert_eq!(
        open_append(&via_existing, uid, data_rule(uid, &calls)).err(),
        broken
    );
    assert_eq!(
        open_read_write(&via_existing, uid, data_rule(uid, &calls)).err(),
        broken
    );
    assert_eq!(
        create_new_append(&via_new, uid, data_rule(uid, &calls)).err(),
        broken
    );
    assert_eq!(
        for_each_entry_beside(&via_new, uid, |_, _| {
            calls.set(calls.get() + 1);
            Ok::<(), &str>(())
        })
        .err(),
        broken
    );
    assert_eq!(calls.get(), 0, "nothing in the directory was looked at");
    assert!(
        !real.join("new").exists(),
        "nothing created through the link"
    );
    assert_eq!(std::fs::read(&existing).unwrap(), b"keep");
}

// Q-468 option 2(b): a directory writable by its group or by others, or
// owned by neither root nor the file's owner, is refused for every entry
// point; with the write bits cleared the same paths work.
#[test]
fn a_writable_or_foreign_directory_is_refused_everywhere() {
    let dir = Scratch::new("dir-rule");
    let uid = dir.uid();
    let data = dir.dir("data");
    let existing = dir.file("data/existing", b"x");
    let new = data.join("new");
    let calls = Cell::new(0);
    let attempts = |owner: u32| {
        [
            open_append(&existing, owner, data_rule(owner, &calls)).err(),
            open_read_write(&existing, owner, data_rule(owner, &calls)).err(),
            create_new_append(&new, owner, data_rule(owner, &calls)).err(),
            for_each_entry_beside(&new, owner, |_, _| Err("visited")).err(),
        ]
    };
    for mode in [0o770, 0o707, 0o1777] {
        chmod(&data, mode);
        for outcome in attempts(uid) {
            assert_eq!(
                outcome,
                Some(OpenError::Path(PathBreak::DirectoryWritableByGroupOrOthers)),
                "{mode:o}"
            );
        }
    }
    chmod(&data, 0o700);
    if uid != 0 {
        for outcome in attempts(uid.wrapping_add(1)) {
            assert_eq!(
                outcome,
                Some(OpenError::Path(PathBreak::DirectoryWrongOwner))
            );
        }
    }
    assert_eq!(calls.get(), 0, "no file rule ran");
    assert!(!new.exists());
    for outcome in &attempts(uid)[..3] {
        assert_eq!(*outcome, None);
    }
}

// Q-481 item b: the listing of the walked directory — every entry but `.`
// and `..`, with facts taken without following a link — whether or not the
// file the path names exists; a visitor error ends it.
#[test]
fn the_entries_beside_a_path_are_listed_with_their_own_facts() {
    let dir = Scratch::new("list");
    let uid = dir.uid();
    let logs = dir.dir("logs");
    dir.file("logs/audit.log.1", b"12345");
    dir.dir("logs/sub");
    dir.link("logs/audit.log.2", &logs.join("audit.log.1"));
    let mut seen = Vec::new();
    for_each_entry_beside(&logs.join("audit.log"), uid, |name, facts| {
        seen.push((
            String::from_utf8(name.to_vec()).unwrap(),
            facts.regular_file,
            facts.symbolic_link,
            facts.size,
        ));
        Ok::<(), ()>(())
    })
    .unwrap();
    seen.sort();
    assert_eq!(seen.len(), 3, "{seen:?}");
    assert_eq!(seen[0], ("audit.log.1".to_owned(), true, false, 5));
    assert_eq!(&seen[1].0, "audit.log.2");
    assert_eq!(
        (seen[1].1, seen[1].2),
        (false, true),
        "a link, not followed"
    );
    assert_eq!(&seen[2].0, "sub");
    assert!(!seen[2].1 && !seen[2].2);
    let mut visits = 0;
    assert_eq!(
        for_each_entry_beside(&logs.join("audit.log"), uid, |_, _| {
            visits += 1;
            Err("stop")
        })
        .err(),
        Some(OpenError::Refused("stop"))
    );
    assert_eq!(visits, 1);
    assert_eq!(
        for_each_entry_beside(
            &PathBuf::from(format!("{}/", logs.display())),
            uid,
            |_, _| { Ok::<(), ()>(()) }
        )
        .err(),
        Some(OpenError::Path(PathBreak::NoFileName))
    );
}
