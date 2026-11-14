//! The walk (task T; docs/52 §3.13 R11; Q-468 options 1 and 2(b), decision
//! A-102): every directory component of a protected path is checked, not
//! only the last component — a symbolic link anywhere on the path, a
//! directory writable by group or others, or a directory owned by neither
//! root nor the file's owner is refused; valid nested paths still read.
//!
//! The tests run as an ordinary account (the expected owner is the test's
//! own uid). Every walk starts at `/` — there is no test seam — so their
//! scratch directories live inside the workspace (crates/test-scratch,
//! Q-480), whose directories pass the rule with the test account as the
//! expected owner; a path under the system's temporary directory does not.
//!
//! Sources: docs/52 §3.13, §7 (R11); docs/questions/Q-468 (options 1, 2(b),
//! A-102); docs/50 §7.1; rustix docs.rs `fs::openat` / `fs::OFlags`
//! (`NOFOLLOW`, `DIRECTORY`), `fs::statat` / `fs::AtFlags`
//! (`SYMLINK_NOFOLLOW`). Test-only; no vector from any other implementation.

use std::cell::Cell;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use protected_file::{open, read_configuration_file, OpenError, PathBreak, Refusal, RuleBreak};
use test_scratch::ScratchDir;

/// A scratch directory inside the workspace (crates/test-scratch; mode
/// 0700), removed at the end of the test.
struct Scratch(PathBuf, #[allow(dead_code)] ScratchDir);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        let dir = ScratchDir::new(&format!("pf-walk-{tag}")).unwrap();
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

    /// A file `relative` holding `key = value\n`, mode 0644.
    fn file(&self, relative: &str) -> PathBuf {
        let path = self.0.join(relative);
        std::fs::write(&path, b"key = value\n").unwrap();
        chmod(&path, 0o644);
        path
    }

    /// A symbolic link `relative` to `target`.
    fn link(&self, relative: &str, target: &Path) -> PathBuf {
        let path = self.0.join(relative);
        std::os::unix::fs::symlink(target, &path).unwrap();
        path
    }
}

fn chmod(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// The test account's uid (the owner of the directories it creates).
fn own_uid(dir: &Scratch) -> u32 {
    std::fs::metadata(&dir.0).unwrap().uid()
}

const BOUND: usize = 64;

/// A file rule that accepts any regular file and counts its calls.
fn counting_rule(calls: &Cell<u32>) -> impl Fn(&protected_file::FileFacts) -> Result<(), ()> + '_ {
    move |facts| {
        calls.set(calls.get() + 1);
        if facts.regular_file {
            Ok(())
        } else {
            Err(())
        }
    }
}

// Q-468 option 1: a path through several directories of the expected owner
// (0700, 0750, 0755 — none writable by group or others) is read; `.`, `..`
// and a doubled separator are walked like any component.
#[test]
fn a_valid_nested_path_is_read() {
    let dir = Scratch::new("nested");
    let uid = own_uid(&dir);
    dir.dir("a/b/c");
    chmod(&dir.0.join("a"), 0o750);
    chmod(&dir.0.join("a/b"), 0o755);
    let path = dir.file("a/b/c/f");
    assert_eq!(
        read_configuration_file(&path, uid, BOUND).unwrap(),
        b"key = value\n"
    );
    let winding = dir.0.join("a/./b/../b//c/f");
    assert_eq!(
        read_configuration_file(&winding, uid, BOUND).unwrap(),
        b"key = value\n"
    );
    let calls = Cell::new(0);
    assert!(open(&path, uid, counting_rule(&calls)).is_ok());
    assert_eq!(
        calls.get(),
        2,
        "the file rule runs before and after the open"
    );
}

// docs/52 §3.13 (C13), Q-468 option 1: a symbolic link in a directory
// component — absolute or relative target, at any depth, dangling or not —
// is refused before the file is looked at, even when the path through the
// real directory is accepted.
#[test]
fn a_symbolic_link_in_a_directory_component_is_refused() {
    let dir = Scratch::new("dirlink");
    let uid = own_uid(&dir);
    let real = dir.dir("real");
    let accepted = dir.file("real/f");
    assert!(read_configuration_file(&accepted, uid, BOUND).is_ok());
    dir.link("absolute", &real);
    dir.link("relative", Path::new("real"));
    dir.dir("a");
    dir.link("a/up", Path::new("../real"));
    dir.link("dangling", &dir.0.join("absent"));
    for through in ["absolute/f", "relative/f", "a/up/f", "dangling/f"] {
        let path = dir.0.join(through);
        let calls = Cell::new(0);
        assert_eq!(
            open(&path, uid, counting_rule(&calls)).err(),
            Some(OpenError::Path(PathBreak::NotADirectory)),
            "{through}"
        );
        assert_eq!(calls.get(), 0, "{through}: the file rule never ran");
        assert_eq!(
            read_configuration_file(&path, uid, BOUND),
            Err(Refusal::Rule(RuleBreak::NotRegularFile)),
            "{through}"
        );
    }
    // A link to a directory just above the file, with the rest real.
    dir.dir("real/inner");
    dir.file("real/inner/g");
    dir.link("real/to-inner", &dir.0.join("real/inner"));
    assert_eq!(
        open(&dir.0.join("real/to-inner/g"), uid, |_| Ok::<(), ()>(())).err(),
        Some(OpenError::Path(PathBreak::NotADirectory))
    );
}

// Q-468 option 1 (`O_DIRECTORY`): a regular file used as a directory
// component is not a directory.
#[test]
fn a_file_as_a_directory_component_is_refused() {
    let dir = Scratch::new("filedir");
    let uid = own_uid(&dir);
    dir.file("plain");
    assert_eq!(
        open(&dir.0.join("plain/f"), uid, |_| Ok::<(), ()>(())).err(),
        Some(OpenError::Path(PathBreak::NotADirectory))
    );
}

// Q-468 option 2(b): a directory writable by its group or by others — the
// file's own directory or any directory above it, sticky bit or not — is
// refused; the same tree with the write bits cleared is read again.
#[test]
fn a_directory_writable_by_group_or_others_is_refused() {
    let dir = Scratch::new("writable");
    let uid = own_uid(&dir);
    dir.dir("w/inner");
    let path = dir.file("w/inner/f");
    for (component, mode) in [
        ("w/inner", 0o770),
        ("w/inner", 0o707),
        ("w/inner", 0o730),
        ("w/inner", 0o703),
        ("w", 0o777),
        ("w", 0o1777),
        ("w", 0o720),
    ] {
        chmod(&dir.0.join(component), mode);
        let calls = Cell::new(0);
        assert_eq!(
            open(&path, uid, counting_rule(&calls)).err(),
            Some(OpenError::Path(PathBreak::DirectoryWritableByGroupOrOthers)),
            "{component} {mode:o}"
        );
        assert_eq!(
            calls.get(),
            0,
            "{component} {mode:o}: the file rule never ran"
        );
        assert_eq!(
            read_configuration_file(&path, uid, BOUND),
            Err(Refusal::Rule(RuleBreak::WritableByGroupOrOthers)),
            "{component} {mode:o}"
        );
        chmod(&dir.0.join(component), 0o700);
        assert!(read_configuration_file(&path, uid, BOUND).is_ok());
    }
}

// Q-468 option 2(b): a directory owned by neither root nor the file's owner
// is refused — here the scratch directory (the test account's) when the
// expected owner is another account; a configuration-file reader reports it
// as the same `WrongOwner` as a file of another owner.
#[test]
fn a_directory_of_another_owner_is_refused() {
    let dir = Scratch::new("owner");
    let uid = own_uid(&dir);
    if uid == 0 {
        eprintln!("skipped: running as root (root's directories are always accepted)");
        return;
    }
    let path = dir.file("f");
    let calls = Cell::new(0);
    assert_eq!(
        open(&path, uid.wrapping_add(1), counting_rule(&calls)).err(),
        Some(OpenError::Path(PathBreak::DirectoryWrongOwner))
    );
    assert_eq!(calls.get(), 0, "the file rule never ran");
    assert_eq!(
        read_configuration_file(&path, uid.wrapping_add(1), BOUND),
        Err(Refusal::Rule(RuleBreak::WrongOwner))
    );
    // Production's expectation (root) refuses the test account's directory
    // too.
    assert_eq!(
        open(&path, 0, |_| Ok::<(), ()>(())).err(),
        Some(OpenError::Path(PathBreak::DirectoryWrongOwner))
    );
}

// Q-468 option 1: a path that does not end in a file name is refused before
// any directory is entered.
#[test]
fn a_path_without_a_file_name_is_refused() {
    let dir = Scratch::new("noname");
    let uid = own_uid(&dir);
    dir.dir("a");
    let trailing = PathBuf::from(format!("{}/a/", dir.0.display()));
    for path in [
        trailing,
        dir.0.join("a/."),
        dir.0.join("a/.."),
        PathBuf::from("/"),
    ] {
        let calls = Cell::new(0);
        assert_eq!(
            open(&path, uid, counting_rule(&calls)).err(),
            Some(OpenError::Path(PathBreak::NoFileName)),
            "{}",
            path.display()
        );
        assert_eq!(calls.get(), 0);
    }
}

/// The outcome the directory rule predicts for `file`, judged component by
/// component from `/` with the standard library's `symlink_metadata` (an
/// inspection independent of the walk): the first directory that is a link
/// or not a directory, is owned by neither root nor `owner`, or is writable
/// by group or others decides it.
/// Source: Q-468 option 2(b).
fn predicted(file: &Path, owner: u32) -> Result<(), PathBreak> {
    let mut directories: Vec<&Path> = file.ancestors().skip(1).collect();
    directories.reverse();
    for directory in directories {
        let facts = std::fs::symlink_metadata(directory).unwrap();
        if !facts.file_type().is_dir() {
            return Err(PathBreak::NotADirectory);
        }
        if facts.uid() != 0 && facts.uid() != owner {
            return Err(PathBreak::DirectoryWrongOwner);
        }
        if facts.mode() & 0o022 != 0 {
            return Err(PathBreak::DirectoryWritableByGroupOrOthers);
        }
    }
    Ok(())
}

/// Open `path` expecting `owner`, with a file rule that accepts any regular
/// file.
fn open_regular(path: &Path, owner: u32) -> Result<std::fs::File, OpenError<()>> {
    open(path, owner, |facts| {
        if facts.regular_file {
            Ok(())
        } else {
            Err(())
        }
    })
}

// Q-480, Q-468 option 1 ("from `/`"): a file in the test scratch directory
// (`<workspace>/.test-scratch`, or `$HOME/.test-scratch` when the workspace
// path is not a valid configuration path — crates/test-scratch) is reached
// by the walk from `/` — every directory above it is root's or the test
// account's and not writable by others, as an independent inspection of
// each one confirms.
#[test]
fn a_path_in_the_test_scratch_is_walked_from_the_root() {
    let dir = Scratch::new("root");
    let uid = own_uid(&dir);
    let path = dir.file("f");
    assert!(path.starts_with(test_scratch::scratch_root().unwrap()));
    assert_eq!(predicted(&path, uid), Ok(()));
    assert!(open_regular(&path, uid).is_ok());
    assert_eq!(
        read_configuration_file(&path, uid, BOUND).unwrap(),
        b"key = value\n"
    );
}

// Q-480, Q-468 options 1, 2(b): a path under the system's temporary
// directory is walked from `/` like any other, and refused wherever a
// directory above it breaks the rule — on macOS always (`/var` is a symbolic
// link; `/private` and `/private/var` are group-writable), on Linux when it
// is `/tmp` (writable by all). The outcome agrees with an independent
// inspection of each directory.
#[test]
fn a_path_under_the_temporary_directory_is_judged_from_the_root() {
    let path = std::env::temp_dir().join(format!("pf-walk-tmp-{}.conf", std::process::id()));
    std::fs::write(&path, b"key = value\n").unwrap();
    chmod(&path, 0o644);
    let uid = std::fs::metadata(&path).unwrap().uid();
    let outcome = open_regular(&path, uid).err();
    let expected = predicted(&path, uid);
    let _ = std::fs::remove_file(&path);
    if cfg!(target_os = "macos") {
        assert!(matches!(outcome, Some(OpenError::Path(_))), "{outcome:?}");
    }
    assert_eq!(outcome, expected.err().map(OpenError::Path));
}

// Q-468 option 1 ("from `/`") and 2(b) ("root or the file's owner"): the
// walk agrees, directory by directory, with an independent inspection —
// whatever the host's layout (root's directories above the account's are
// accepted; a group-writable or world-writable system directory is
// refused). The paths: this crate's manifest, by its absolute name and
// relative to the current directory, and the canonical name of a file under
// the temporary directory (on macOS `/private/var/...`).
#[test]
fn the_walk_from_the_root_agrees_with_each_component() {
    let dir = Scratch::new("agree");
    let uid = own_uid(&dir);
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let current = std::env::current_dir().unwrap();
    let mut cases = vec![(manifest.clone(), manifest)];
    if current.join("Cargo.toml").is_file() {
        cases.push((PathBuf::from("Cargo.toml"), current.join("Cargo.toml")));
    }
    let temporary_file =
        std::env::temp_dir().join(format!("pf-walk-agree-{}.conf", std::process::id()));
    std::fs::write(&temporary_file, b"key = value\n").unwrap();
    let canonical = std::fs::canonicalize(&temporary_file).unwrap();
    cases.push((canonical.clone(), canonical));
    for (given, absolute) in cases {
        let outcome = open_regular(&given, uid).err();
        let expected = predicted(&absolute, uid);
        assert_eq!(
            outcome,
            expected.err().map(OpenError::Path),
            "{}",
            given.display()
        );
    }
    let _ = std::fs::remove_file(&temporary_file);
}
