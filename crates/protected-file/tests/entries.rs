//! The installer's operations relative to walked directories (task R11c;
//! docs/questions/Q-532 item 2; A-92, A-109): each walks its path from `/`
//! — a symbolic link in a directory component, a directory writable by group
//! or others, or a directory of another owner is refused before anything is
//! touched — and acts relative to the checked directory on the last
//! component only, without following a link there either.
//!
//! The tests run as an ordinary account (the expected owner is the test's
//! own uid); their directories live inside the workspace
//! (crates/test-scratch, Q-480), which the walk from `/` accepts.
//!
//! Sources: docs/51 §4.3 steps 1, 3-9, §4.4 (absent targets; staging root
//! 0700; key 0400; database 0600; configuration, policy, manifest 0644;
//! rename without replacing; the empty staging directory removed), §5.10
//! (the policy edit's atomic replace); docs/52 §3.13 (C13); Q-468 options 1,
//! 2(b) (A-102); Q-532 (A-109); rustix docs.rs `fs::mkdirat`, `fs::openat`
//! (`O_CREAT | O_EXCL | O_NOFOLLOW`), `fs::renameat_with`
//! (`RENAME_NOREPLACE`), `fs::renameat`, `fs::unlinkat` (`REMOVEDIR`),
//! `fs::fsync`, `fs::Stat::st_dev`. Test-only; no vector from any other
//! implementation.

use std::cell::Cell;
use std::io::{ErrorKind, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use protected_file::{
    create_new_directory, create_new_file, create_new_read_write, directory_device, entry_facts,
    remove_empty_directory, rename_no_replace, rename_replace, sync_directory, EntryError,
    NewFileMode, OpenError, PathBreak,
};
use test_scratch::ScratchDir;

/// A scratch directory inside the workspace (mode 0700), removed at the end
/// of the test.
struct Scratch(PathBuf, #[allow(dead_code)] ScratchDir);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        let dir = ScratchDir::new(&format!("pf-entries-{tag}")).unwrap();
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

fn mode(path: &Path) -> u32 {
    std::fs::symlink_metadata(path).unwrap().mode() & 0o7777
}

fn exists(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

// docs/51 §4.3 steps 4-8: a created file has exactly its mode, whatever the
// umask; an existing name of any kind — a dangling link included — is
// refused and never reused or followed.
#[test]
fn files_are_created_exclusively_with_their_exact_mode() {
    let scratch = Scratch::new("files");
    let uid = scratch.uid();
    let etc = scratch.dir("etc");
    let key = etc.join("integrity.key");
    let mut file = create_new_file(&key, uid, NewFileMode::OwnerRead).unwrap();
    file.write_all(&[7; 32]).unwrap();
    assert_eq!(mode(&key), 0o400);
    let config = etc.join("keyd.conf");
    drop(create_new_file(&config, uid, NewFileMode::OwnerWriteEveryoneRead).unwrap());
    assert_eq!(mode(&config), 0o644);
    assert_eq!(
        create_new_file(&key, uid, NewFileMode::OwnerRead).err(),
        Some(EntryError::Io(ErrorKind::AlreadyExists))
    );
    assert_eq!(std::fs::read(&key).unwrap(), [7; 32], "never reused");
    let target = etc.join("target");
    scratch.link("etc/dangling", &target);
    assert!(create_new_file(&etc.join("dangling"), uid, NewFileMode::OwnerRead).is_err());
    assert!(!exists(&target), "a dangling link is not followed");
}

// docs/51 §4.3 step 5 (database 0600); Q-532 item 3: the read-write
// creation gives a descriptor redb can both write and read.
#[test]
fn the_database_file_is_created_0600_for_reading_and_writing() {
    let scratch = Scratch::new("rw");
    let path = scratch.dir("var").join("directory.redb");
    let mut file = create_new_read_write(&path, scratch.uid()).unwrap();
    file.write_all(b"pages").unwrap();
    file.seek(SeekFrom::Start(0)).unwrap();
    let mut back = Vec::new();
    file.read_to_end(&mut back).unwrap();
    assert_eq!(back, b"pages");
    assert_eq!(mode(&path), 0o600);
    assert!(create_new_read_write(&path, scratch.uid()).is_err());
}

// docs/51 §4.3 step 1 (every target absent; a dangling link counts as
// present): the facts of what is at a path, without following a link.
#[test]
fn entry_facts_see_absent_present_and_links() {
    let scratch = Scratch::new("facts");
    let uid = scratch.uid();
    let etc = scratch.dir("etc");
    assert_eq!(entry_facts(&etc.join("absent"), uid), Ok(None));
    std::fs::write(etc.join("file"), b"x").unwrap();
    let file = entry_facts(&etc.join("file"), uid).unwrap().unwrap();
    assert!(file.regular_file && !file.symbolic_link);
    scratch.link("etc/dangling", &etc.join("nowhere"));
    let link = entry_facts(&etc.join("dangling"), uid).unwrap().unwrap();
    assert!(link.symbolic_link && !link.regular_file);
    // A missing directory on the path is a failed inspection, not "absent".
    assert_eq!(
        entry_facts(&scratch.0.join("missing").join("file"), uid),
        Err(EntryError::Io(ErrorKind::NotFound))
    );
}

// docs/51 §4.3 step 3 (one filesystem for every rename): two directories
// of the scratch directory are on one device.
#[test]
fn directories_on_one_filesystem_have_one_device() {
    let scratch = Scratch::new("device");
    let uid = scratch.uid();
    let a = directory_device(&scratch.dir("a"), uid).unwrap();
    let b = directory_device(&scratch.dir("b/c"), uid).unwrap();
    assert_eq!(a, b);
    let file = scratch.0.join("plain");
    std::fs::write(&file, b"x").unwrap();
    assert_eq!(
        directory_device(&file, uid),
        Err(EntryError::Path(PathBreak::NotADirectory))
    );
}

// docs/51 §4.3 step 3 ("a new directory (root, 0700)"): created exactly
// 0700, its descriptor lent once to the owner change; an existing name is
// refused; an owner change that fails leaves the directory behind.
#[test]
fn the_staging_directory_is_created_0700_and_given_its_owner() {
    let scratch = Scratch::new("staging");
    let uid = scratch.uid();
    let staging = scratch.dir("etc").join("staging");
    let calls = Cell::new(0);
    create_new_directory(&staging, uid, |_fd| {
        calls.set(calls.get() + 1);
        Ok::<(), &str>(())
    })
    .unwrap();
    assert_eq!(calls.get(), 1);
    assert_eq!(mode(&staging), 0o700);
    assert_eq!(
        create_new_directory(&staging, uid, |_fd| Ok::<(), &str>(())),
        Err(OpenError::Io(ErrorKind::AlreadyExists))
    );
    let second = scratch.0.join("etc").join("second");
    assert_eq!(
        create_new_directory(&second, uid, |_fd| Err("refused")),
        Err(OpenError::Refused("refused"))
    );
    assert!(exists(&second), "left behind, never removed");
}

// docs/51 §4.3 step 9, §4.4 (rename into place, never replacing); §5.10
// (the policy edit replaces atomically).
#[test]
fn renames_refuse_or_replace_as_asked() {
    let scratch = Scratch::new("rename");
    let uid = scratch.uid();
    let staging = scratch.dir("staging");
    let etc = scratch.dir("etc");
    std::fs::write(staging.join("policy"), b"new").unwrap();
    rename_no_replace(&staging.join("policy"), uid, &etc.join("policy.store"), uid).unwrap();
    assert_eq!(std::fs::read(etc.join("policy.store")).unwrap(), b"new");
    assert!(!exists(&staging.join("policy")));
    std::fs::write(staging.join("again"), b"other").unwrap();
    assert_eq!(
        rename_no_replace(&staging.join("again"), uid, &etc.join("policy.store"), uid),
        Err(EntryError::Io(ErrorKind::AlreadyExists))
    );
    assert_eq!(std::fs::read(etc.join("policy.store")).unwrap(), b"new");
    rename_replace(&staging.join("again"), uid, &etc.join("policy.store"), uid).unwrap();
    assert_eq!(std::fs::read(etc.join("policy.store")).unwrap(), b"other");
}

// docs/51 §4.3 step 9 (the empty staging directory removed; directories
// synced): only an empty directory is removed.
#[test]
fn only_an_empty_directory_is_removed_and_directories_sync() {
    let scratch = Scratch::new("remove");
    let uid = scratch.uid();
    let staging = scratch.dir("staging");
    std::fs::write(staging.join("left"), b"x").unwrap();
    assert!(remove_empty_directory(&staging, uid).is_err());
    assert!(exists(&staging.join("left")));
    std::fs::remove_file(staging.join("left")).unwrap();
    sync_directory(&staging, uid).unwrap();
    remove_empty_directory(&staging, uid).unwrap();
    assert!(!exists(&staging));
    sync_directory(&scratch.0, uid).unwrap();
}

// docs/52 C13; Q-468 option 1: a symbolic link in a directory component is
// refused by every operation, and nothing is created, renamed or removed
// under the link's target.
#[test]
fn a_link_in_a_directory_component_is_refused_everywhere() {
    let scratch = Scratch::new("link");
    let uid = scratch.uid();
    let real = scratch.dir("real");
    std::fs::write(real.join("kept"), b"x").unwrap();
    scratch.dir("real/sub");
    let link = scratch.link("etc", &real);
    let refused = EntryError::Path(PathBreak::NotADirectory);
    assert_eq!(entry_facts(&link.join("kept"), uid), Err(refused));
    assert_eq!(
        create_new_file(&link.join("new"), uid, NewFileMode::OwnerRead).err(),
        Some(refused)
    );
    assert_eq!(
        create_new_read_write(&link.join("db"), uid).err(),
        Some(refused)
    );
    assert_eq!(
        create_new_directory(&link.join("staging"), uid, |_| Ok::<(), &str>(())),
        Err(OpenError::Path(PathBreak::NotADirectory))
    );
    let elsewhere = scratch.dir("elsewhere");
    std::fs::write(elsewhere.join("moved"), b"y").unwrap();
    assert_eq!(
        rename_no_replace(&elsewhere.join("moved"), uid, &link.join("moved"), uid),
        Err(refused)
    );
    assert_eq!(
        rename_replace(&link.join("kept"), uid, &elsewhere.join("kept"), uid),
        Err(refused)
    );
    assert_eq!(remove_empty_directory(&link.join("sub"), uid), Err(refused));
    assert_eq!(sync_directory(&link, uid), Err(refused));
    assert_eq!(directory_device(&link, uid), Err(refused));
    for name in ["new", "db", "staging", "moved"] {
        assert!(!exists(&real.join(name)), "{name}");
    }
    assert!(exists(&real.join("kept")) && exists(&real.join("sub")));
    assert!(exists(&elsewhere.join("moved")));
}

// Q-468 option 2(b): a directory writable by its group, or owned by
// neither root nor the expected owner, is refused by every operation before
// anything is touched.
#[test]
fn a_writable_or_foreign_directory_is_refused_everywhere() {
    let scratch = Scratch::new("rule");
    let uid = scratch.uid();
    let etc = scratch.dir("etc");
    std::fs::write(etc.join("kept"), b"x").unwrap();
    chmod(&etc, 0o770);
    let writable = EntryError::Path(PathBreak::DirectoryWritableByGroupOrOthers);
    assert_eq!(entry_facts(&etc.join("kept"), uid), Err(writable));
    assert_eq!(
        create_new_file(&etc.join("new"), uid, NewFileMode::OwnerRead).err(),
        Some(writable)
    );
    assert_eq!(sync_directory(&etc, uid), Err(writable));
    assert!(!exists(&etc.join("new")));
    chmod(&etc, 0o700);
    if uid != 0 {
        let stranger = uid.wrapping_add(1);
        let foreign = EntryError::Path(PathBreak::DirectoryWrongOwner);
        assert_eq!(entry_facts(&etc.join("kept"), stranger), Err(foreign));
        assert_eq!(
            create_new_read_write(&etc.join("db"), stranger).err(),
            Some(foreign)
        );
        assert_eq!(
            rename_no_replace(&etc.join("kept"), stranger, &etc.join("moved"), stranger),
            Err(foreign)
        );
        assert!(!exists(&etc.join("db")) && exists(&etc.join("kept")));
    }
}
