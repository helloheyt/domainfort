//! A daemon's socket directory prepared by descriptor (task R11c;
//! docs/questions/Q-532 items 1, 5; A-109): the parent walked from `/`, the
//! directory created relative to it and given its mode and owner on its own
//! descriptor, an existing one judged by the socket-directory rule, a stale
//! socket removed relative to it — and nothing is ever changed through a
//! symbolic link.
//!
//! The tests run as an ordinary account: the test's own uid (and the group
//! of its scratch directory, which it belongs to) stands in for the daemon's
//! account, so the owner change is one an unprivileged process may make.
//! Their directories live inside the workspace (crates/test-scratch, Q-480),
//! which the walk from `/` accepts; the socket paths stay short.
//!
//! Sources: docs/50 §3.1 ("each socket in its own directory, owned by the
//! server's uid, mode 0750, group = the channel's clients"; "deleting a
//! stale socket file before bind … the daemon manages this explicitly");
//! docs/51 §4.6 (`admin_socket_group`); docs/52 §3.13 (C13); Q-468 options
//! 1, 2(b) (A-102); Q-532 (A-109); rustix docs.rs `fs::mkdirat`,
//! `fs::fchmod`, `fs::fchown`, `fs::unlinkat`. Test-only; no vector from any
//! other implementation.

use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use protected_file::{
    prepare_socket_directory, ExistingGroup, PathBreak, SocketDirectoryBreak, SocketDirectoryError,
    SocketDirectoryOwner, SOCKET_DIRECTORY_MODE,
};
use test_scratch::ScratchDir;

/// A scratch directory inside the workspace (mode 0700), removed at the end
/// of the test.
struct Scratch(PathBuf, #[allow(dead_code)] ScratchDir);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        let dir = ScratchDir::new(&format!("pf-sock-{tag}")).unwrap();
        Scratch(dir.path().to_path_buf(), dir)
    }

    /// A directory `relative` (parents included) with exactly `mode`.
    fn dir(&self, relative: &str, mode: u32) -> PathBuf {
        let path = self.0.join(relative);
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&path)
            .unwrap();
        chmod(&path, mode);
        path
    }

    /// A symbolic link `relative` to `target`.
    fn link(&self, relative: &str, target: &Path) -> PathBuf {
        let path = self.0.join(relative);
        std::os::unix::fs::symlink(target, &path).unwrap();
        path
    }

    /// The test account, standing in for the daemon's, with the scratch
    /// directory's group and the given rule for an existing directory's
    /// group.
    fn owner(&self, existing_group: ExistingGroup) -> SocketDirectoryOwner {
        let metadata = std::fs::metadata(&self.0).unwrap();
        SocketDirectoryOwner {
            uid: metadata.uid(),
            gid: metadata.gid(),
            existing_group,
        }
    }
}

fn chmod(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn mode(path: &Path) -> u32 {
    std::fs::symlink_metadata(path).unwrap().mode() & 0o7777
}

/// A socket file at `path` left by an earlier run (bound, then the
/// listener dropped — the file stays).
fn stale_socket(path: &Path) {
    drop(std::os::unix::net::UnixListener::bind(path).unwrap());
    assert!(std::fs::symlink_metadata(path)
        .unwrap()
        .file_type()
        .is_socket());
}

// docs/50 §3.1: a missing socket directory is created mode 0750 exactly,
// owned by the daemon's account and its group; a second preparation accepts
// it unchanged.
#[test]
fn a_missing_directory_is_created_0750_with_its_owner_and_group() {
    let scratch = Scratch::new("create");
    let owner = scratch.owner(ExistingGroup::Configured);
    let socket = scratch.0.join("run").join("keyd.sock");
    assert_eq!(prepare_socket_directory(&socket, owner), Ok(()));
    let created = std::fs::symlink_metadata(scratch.0.join("run")).unwrap();
    assert!(created.is_dir());
    assert_eq!(created.mode() & 0o7777, SOCKET_DIRECTORY_MODE);
    assert_eq!(created.uid(), owner.uid);
    assert_eq!(created.gid(), owner.gid);
    assert_eq!(prepare_socket_directory(&socket, owner), Ok(()));
    assert_eq!(mode(&scratch.0.join("run")), SOCKET_DIRECTORY_MODE);
}

// docs/50 §3.1 ("deleting a stale socket file before bind"): a socket left
// by an earlier run is removed; anything else at the socket's name is left
// alone (the daemon's bind refuses it after the drop).
#[test]
fn a_stale_socket_is_removed_and_nothing_else() {
    let scratch = Scratch::new("stale");
    let owner = scratch.owner(ExistingGroup::ChosenByOperator);
    scratch.dir("run", 0o750);
    let socket = scratch.0.join("run").join("dird.sock");
    stale_socket(&socket);
    assert_eq!(prepare_socket_directory(&socket, owner), Ok(()));
    assert!(
        std::fs::symlink_metadata(&socket).is_err(),
        "stale socket removed"
    );
    std::fs::write(&socket, b"not a socket").unwrap();
    assert_eq!(prepare_socket_directory(&socket, owner), Ok(()));
    assert_eq!(std::fs::read(&socket).unwrap(), b"not a socket");
}

// docs/52 C13; Q-532 item 1: a symbolic link at the socket directory's own
// name — to a real directory or dangling — is refused, and nothing is
// changed through it: the target keeps its mode, a socket in it is not
// removed, a dangling link's target is not created.
#[test]
fn a_link_at_the_socket_directory_is_refused_and_not_followed() {
    let scratch = Scratch::new("link-dir");
    let owner = scratch.owner(ExistingGroup::ChosenByOperator);
    let real = scratch.dir("real", 0o700);
    stale_socket(&real.join("audit.sock"));
    scratch.link("run", &real);
    let refused = Err(SocketDirectoryError::Directory(
        SocketDirectoryBreak::NotADirectory,
    ));
    assert_eq!(
        prepare_socket_directory(&scratch.0.join("run").join("audit.sock"), owner),
        refused
    );
    assert_eq!(mode(&real), 0o700, "no chmod through the link");
    assert!(std::fs::symlink_metadata(real.join("audit.sock")).is_ok());
    // A dangling link: the directory it names is not created.
    scratch.link("gone", &scratch.0.join("nowhere"));
    assert_eq!(
        prepare_socket_directory(&scratch.0.join("gone").join("audit.sock"), owner),
        refused
    );
    assert!(std::fs::symlink_metadata(scratch.0.join("nowhere")).is_err());
}

// docs/52 C13; Q-468 option 1: a symbolic link in a directory component
// above the socket directory is refused by the walk; nothing is created
// under the link's target.
#[test]
fn a_link_in_a_directory_component_is_refused() {
    let scratch = Scratch::new("link-parent");
    let owner = scratch.owner(ExistingGroup::ChosenByOperator);
    let real = scratch.dir("real-parent", 0o700);
    scratch.link("parent", &real);
    assert_eq!(
        prepare_socket_directory(
            &scratch.0.join("parent").join("run").join("keyd.sock"),
            owner
        ),
        Err(SocketDirectoryError::Path(PathBreak::NotADirectory))
    );
    assert!(std::fs::symlink_metadata(real.join("run")).is_err());
}

// Q-468 option 2(b): a parent writable by its group, or a path with a
// directory owned by neither root nor the daemon's account, is refused
// before anything is created.
#[test]
fn a_writable_or_foreign_parent_is_refused() {
    let scratch = Scratch::new("parent-rule");
    let owner = scratch.owner(ExistingGroup::ChosenByOperator);
    let parent = scratch.dir("parent", 0o770);
    let socket = parent.join("run").join("admin.sock");
    assert_eq!(
        prepare_socket_directory(&socket, owner),
        Err(SocketDirectoryError::Path(
            PathBreak::DirectoryWritableByGroupOrOthers
        ))
    );
    assert!(std::fs::symlink_metadata(parent.join("run")).is_err());
    chmod(&parent, 0o700);
    if owner.uid != 0 {
        let stranger = SocketDirectoryOwner {
            uid: owner.uid.wrapping_add(1),
            ..owner
        };
        assert_eq!(
            prepare_socket_directory(&socket, stranger),
            Err(SocketDirectoryError::Path(PathBreak::DirectoryWrongOwner))
        );
        assert!(std::fs::symlink_metadata(parent.join("run")).is_err());
    }
    assert_eq!(prepare_socket_directory(&socket, owner), Ok(()));
}

// docs/50 §3.1; docs/51 §4.6: an existing socket directory must be the
// daemon's, without group write or any access for others, and — when the
// group is a setting — of that group; a refused directory is left as it is.
#[test]
fn an_existing_directory_is_judged_by_the_rule_and_left_unchanged() {
    let scratch = Scratch::new("existing");
    let configured = scratch.owner(ExistingGroup::Configured);
    let chosen = scratch.owner(ExistingGroup::ChosenByOperator);
    let run = scratch.dir("run", 0o750);
    let socket = run.join("admin.sock");
    for refused in [0o757, 0o770, 0o751, 0o755] {
        chmod(&run, refused);
        assert_eq!(
            prepare_socket_directory(&socket, chosen),
            Err(SocketDirectoryError::Directory(
                SocketDirectoryBreak::GroupWriteOrOtherAccess
            )),
            "{refused:o}"
        );
        assert_eq!(mode(&run), refused, "an existing directory is not changed");
    }
    chmod(&run, 0o700);
    assert_eq!(prepare_socket_directory(&socket, configured), Ok(()));
    assert_eq!(mode(&run), 0o700);
    let other_group = SocketDirectoryOwner {
        gid: configured.gid.wrapping_add(1),
        ..configured
    };
    assert_eq!(
        prepare_socket_directory(&socket, other_group),
        Err(SocketDirectoryError::Directory(
            SocketDirectoryBreak::WrongGroup
        ))
    );
    let operator_group = SocketDirectoryOwner {
        gid: chosen.gid.wrapping_add(1),
        ..chosen
    };
    assert_eq!(prepare_socket_directory(&socket, operator_group), Ok(()));
}

// The socket path must name a socket inside a directory below `/`; the
// all-ones id is not an account (rustix `Uid::from_raw`: "not -1").
#[test]
fn a_path_without_a_socket_directory_or_a_non_account_is_refused() {
    let scratch = Scratch::new("shape");
    let owner = scratch.owner(ExistingGroup::ChosenByOperator);
    assert_eq!(
        prepare_socket_directory(Path::new("/keyd.sock"), owner),
        Err(SocketDirectoryError::NoSocketDirectory)
    );
    assert_eq!(
        prepare_socket_directory(&scratch.0.join("run").join(".."), owner),
        Err(SocketDirectoryError::NoSocketDirectory)
    );
    for not_an_account in [
        SocketDirectoryOwner {
            uid: u32::MAX,
            ..owner
        },
        SocketDirectoryOwner {
            gid: u32::MAX,
            ..owner
        },
    ] {
        assert_eq!(
            prepare_socket_directory(&scratch.0.join("run").join("k.sock"), not_an_account),
            Err(SocketDirectoryError::NotAnAccount)
        );
    }
    assert!(std::fs::symlink_metadata(scratch.0.join("run")).is_err());
}
