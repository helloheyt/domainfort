//! The protected-file reader: the file's three steps, the bound, the
//! configuration-file rule, and — the point of task F7 — a symbolic link to
//! a file that would be accepted is refused. (The directories on the path:
//! tests/directories.rs.)
//!
//! The tests run as an ordinary account, so the expected owner is the
//! test's own uid (the readers take it as a parameter; root in production).
//! Their files live inside the workspace (crates/test-scratch, Q-480): the
//! walk from `/` accepts those directories, the test account's or root's and
//! not writable by others, with the test account as the expected owner.
//! With another expected owner it does not: "wrong owner" is then the
//! scratch directory's break, which a configuration-file reader reports as
//! the same `WrongOwner`.
//!
//! Sources: docs/50 §7.1 ("file root:0644"); docs/51 §4.3 step 8; A-86,
//! A-96 (O_NOFOLLOW in every reader); AGENTS.md §6 (bounded reads). Test-only;
//! no vector from any other implementation.

use std::io::ErrorKind;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use protected_file::{
    configuration_file_rule, open, read_configuration_file, read_to_bound, FileFacts, OpenError,
    ReadError, Refusal, RuleBreak, GROUP_OR_OTHER_WRITE, PERMISSION_BITS,
};
use test_scratch::ScratchDir;

/// A scratch directory inside the workspace (crates/test-scratch), removed
/// at the end of the test.
struct Scratch(PathBuf, #[allow(dead_code)] ScratchDir);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        let dir = ScratchDir::new(&format!("pf-{tag}")).unwrap();
        Scratch(dir.path().to_path_buf(), dir)
    }

    /// A file named `name` with `content` and permission bits `mode`.
    fn file(&self, name: &str, content: &[u8], mode: u32) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, content).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    /// A symbolic link named `name` to `target`.
    fn link(&self, name: &str, target: &Path) -> PathBuf {
        let path = self.0.join(name);
        std::os::unix::fs::symlink(target, &path).unwrap();
        path
    }
}

/// The test account's uid (the owner of the files it creates).
fn own_uid(dir: &Scratch) -> u32 {
    std::fs::metadata(&dir.0).unwrap().uid()
}

const BOUND: usize = 64;

// docs/50 §7.1: a regular file of the expected owner, not writable by group
// or others, within the bound, is read whole.
#[test]
fn an_acceptable_file_is_read() {
    let dir = Scratch::new("ok");
    let uid = own_uid(&dir);
    for mode in [0o644, 0o600, 0o400, 0o444] {
        let path = dir.file(&format!("f{mode:o}"), b"key = value\n", mode);
        assert_eq!(
            read_configuration_file(&path, uid, BOUND).unwrap(),
            b"key = value\n"
        );
    }
}

// A-86 / A-96: a symbolic link to a file that is itself accepted is refused
// as "not a regular file" — the link is never followed. A dangling link and
// a link to a directory likewise.
#[test]
fn a_symbolic_link_to_an_acceptable_file_is_refused() {
    let dir = Scratch::new("link");
    let uid = own_uid(&dir);
    let target = dir.file("target", b"key = value\n", 0o644);
    assert!(read_configuration_file(&target, uid, BOUND).is_ok());
    let link = dir.link("link", &target);
    assert_eq!(
        read_configuration_file(&link, uid, BOUND),
        Err(Refusal::Rule(RuleBreak::NotRegularFile))
    );
    let dangling = dir.link("dangling", &dir.0.join("absent"));
    assert_eq!(
        read_configuration_file(&dangling, uid, BOUND),
        Err(Refusal::Rule(RuleBreak::NotRegularFile))
    );
    let to_dir = dir.link("to-dir", &dir.0);
    assert_eq!(
        read_configuration_file(&to_dir, uid, BOUND),
        Err(Refusal::Rule(RuleBreak::NotRegularFile))
    );
}

// docs/50 §7.1: a directory is not a regular file.
#[test]
fn a_directory_is_refused() {
    let dir = Scratch::new("dir");
    let uid = own_uid(&dir);
    assert_eq!(
        read_configuration_file(&dir.0, uid, BOUND),
        Err(Refusal::Rule(RuleBreak::NotRegularFile))
    );
}

// docs/50 §7.1 ("root:0644"): another owner, or write for group or others,
// is refused — in the rule's order (owner before mode).
#[test]
fn owner_and_mode_are_checked() {
    let dir = Scratch::new("rule");
    let uid = own_uid(&dir);
    let path = dir.file("f", b"x\n", 0o644);
    assert_eq!(
        read_configuration_file(&path, uid.wrapping_add(1), BOUND),
        Err(Refusal::Rule(RuleBreak::WrongOwner))
    );
    for mode in [0o664, 0o646, 0o666, 0o620, 0o602] {
        let path = dir.file(&format!("w{mode:o}"), b"x\n", mode);
        assert_eq!(
            read_configuration_file(&path, uid, BOUND),
            Err(Refusal::Rule(RuleBreak::WritableByGroupOrOthers)),
            "{mode:o}"
        );
        assert_eq!(
            read_configuration_file(&path, uid.wrapping_add(1), BOUND),
            Err(Refusal::Rule(RuleBreak::WrongOwner)),
            "{mode:o}"
        );
    }
}

// AGENTS.md §6: exactly the bound is read; one octet more is refused.
#[test]
fn the_bound_is_enforced() {
    let dir = Scratch::new("bound");
    let uid = own_uid(&dir);
    let exact = dir.file("exact", &[b'a'; BOUND], 0o644);
    assert_eq!(
        read_configuration_file(&exact, uid, BOUND).unwrap().len(),
        BOUND
    );
    let over = dir.file("over", &[b'a'; BOUND + 1], 0o644);
    assert_eq!(
        read_configuration_file(&over, uid, BOUND),
        Err(Refusal::TooLarge)
    );
    let file = open(&over, uid, |_| Ok::<(), ()>(())).unwrap();
    assert_eq!(read_to_bound(file, BOUND), Err(ReadError::TooLarge));
}

// docs/50 §7.5 (fail closed): an absent path is unreadable, with the
// system's error kind.
#[test]
fn an_absent_file_is_unreadable() {
    let dir = Scratch::new("absent");
    let uid = own_uid(&dir);
    assert_eq!(
        read_configuration_file(&dir.0.join("absent"), uid, BOUND),
        Err(Refusal::Unreadable(ErrorKind::NotFound))
    );
}

// docs/50 R50-12, Q-270 item 1: a caller's own rule (a key file: owner and
// permission bits exactly 0400) sees the facts of the path and of the opened
// file; a link to a valid key file is refused by that rule too.
#[test]
fn a_caller_rule_sees_the_facts() {
    let dir = Scratch::new("custom");
    let uid = own_uid(&dir);
    let key_rule = |facts: &FileFacts| {
        if facts.regular_file && facts.owner_uid == uid && facts.mode & PERMISSION_BITS == 0o400 {
            Ok(())
        } else {
            Err("refused")
        }
    };
    let key = dir.file("key", &[7u8; 32], 0o400);
    let file = open(&key, uid, key_rule).unwrap();
    assert_eq!(read_to_bound(file, 32).unwrap(), [7u8; 32]);
    let loose = dir.file("loose", &[7u8; 32], 0o600);
    assert_eq!(
        open(&loose, uid, key_rule).err(),
        Some(OpenError::Refused("refused"))
    );
    let link = dir.link("key-link", &key);
    assert_eq!(
        open(&link, uid, key_rule).err(),
        Some(OpenError::Refused("refused"))
    );
    // The facts a rule sees for a link are a link's, never its target's.
    let seen = std::cell::RefCell::new(Vec::new());
    let _ = open(&link, uid, |facts: &FileFacts| {
        seen.borrow_mut().push(*facts);
        Err::<(), ()>(())
    });
    let seen = seen.into_inner();
    assert_eq!(seen.len(), 1);
    assert!(!seen[0].regular_file);
    // ... and say so (task R11b: provision's password-file rule reports a
    // link as a link, docs/51 §4.4 "not a symlink").
    assert!(seen[0].symbolic_link);
    // A regular file's facts, before and after the open, carry its size
    // (docs/51 §4.4: "≤ 1024 bytes", decided before any octet is read).
    let sizes = std::cell::RefCell::new(Vec::new());
    open(&key, uid, |facts: &FileFacts| {
        sizes.borrow_mut().push((facts.size, facts.symbolic_link));
        Ok::<(), ()>(())
    })
    .unwrap();
    assert_eq!(sizes.into_inner(), [(32, false), (32, false)]);
}

// docs/50 §7.1: the rule on its own facts (the order: regular, owner, mode).
#[test]
fn the_configuration_rule_on_facts() {
    const REGULAR: u32 = 0o100_000;
    let facts = |regular_file, owner_uid, mode| FileFacts {
        regular_file,
        symbolic_link: false,
        owner_uid,
        mode,
        size: 0,
    };
    assert_eq!(
        configuration_file_rule(&facts(true, 0, REGULAR | 0o644), 0),
        Ok(())
    );
    assert_eq!(
        configuration_file_rule(&facts(false, 1, 0o040_777), 0),
        Err(RuleBreak::NotRegularFile)
    );
    assert_eq!(
        configuration_file_rule(&facts(true, 1, REGULAR | 0o666), 0),
        Err(RuleBreak::WrongOwner)
    );
    assert_eq!(
        configuration_file_rule(&facts(true, 0, REGULAR | 0o664), 0),
        Err(RuleBreak::WritableByGroupOrOthers)
    );
    assert_eq!(GROUP_OR_OTHER_WRITE, 0o022);
}
