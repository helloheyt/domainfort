//! A daemon's socket directory, prepared as root before the privilege drop
//! (task R11c; docs/questions/Q-532 items 1, 5; A-109): the one
//! implementation every socket-serving daemon uses (keyd, dird, admind,
//! auditd).
//!
//! # What it does
//!
//! For the socket path `<parent>/<directory>/<socket>`:
//!
//! 1. **the parent is walked** from `/` under the directory rule (every
//!    component inspected and opened without following a link, owned by root
//!    or by the daemon's account, not writable by group or others — the
//!    crate documentation, steps 0-1). The daemon's account is the owner the
//!    rule admits besides root because it is the owner of the thing at the
//!    end of the path, the socket directory (Q-468 option 2(b), "root or the
//!    file's owner");
//! 2. **the socket directory**, relative to the parent's descriptor:
//!    * present ⇒ inspected without following a link, the socket-directory
//!      rule applied (a directory — a link's facts never are —, owned by the
//!      daemon's account, of the configured group when the group is a
//!      setting, no group write and no access for others), opened without
//!      following a link, the rule applied again to the opened descriptor.
//!      Nothing about an existing directory is changed;
//!    * absent ⇒ created with `mkdirat` relative to the parent (an existing
//!      name of any kind, a dangling link included, makes it fail), opened
//!      without following a link, its mode set to exactly
//!      [`SOCKET_DIRECTORY_MODE`] with `fchmod` and its owner and group with
//!      `fchown` **on that descriptor** — never by path —, and the rule
//!      applied to the descriptor;
//! 3. **a stale socket** left at the socket's name by an earlier run is
//!    removed with `unlinkat` relative to the checked directory's descriptor
//!    (inspected first without following a link: only a socket is removed;
//!    anything else is left alone, and the daemon's bind refuses it after the
//!    drop).
//!
//! The class closed (docs/52 C13): the old preparation inspected the
//! directory by path, created it by path, then `chmod`ed and `chown`ed it
//! **by path** — both follow a link, so an account able to write in the
//! parent could, between the `mkdir` and the `chown`, have root hand any
//! file to the daemon's account. Here no operation follows a link and every
//! change is made on the descriptor of the directory that was checked.
//!
//! After the drop each daemon binds its socket and sets the socket's mode by
//! path (no descriptor-relative bind exists; `chmodat` cannot refuse a link
//! on Linux — docs.rs `fs::chmodat`). Those operations stay inside the
//! directory checked here, every component of whose path only root or the
//! daemon's own account can change (docs/questions/Q-550 item 2).
//!
//! Spec: docs/50 §3.1 ("each socket in its own directory, owned by the
//! server's uid, mode 0750, group = the channel's clients — defence in depth
//! only"; "deleting a stale socket file before bind … the daemon manages
//! this explicitly"), §6.2; docs/51 §4.6 (`admin_socket_group`);
//! docs/questions Q-260 item 6 (the group is not a setting for keyd and
//! dird); docs/52 §3.13 (C13); Q-468 options 1, 2(b) (A-102); Q-532 (A-109);
//! rustix docs.rs `fs::statat`, `fs::AtFlags::SYMLINK_NOFOLLOW`,
//! `fs::mkdirat`, `fs::openat`, `fs::fchmod`, `fs::fchown` ("Sets open file
//! or directory ownership"), `fs::Uid::from_raw` / `fs::Gid::from_raw` (not
//! `-1`), `fs::fstat`, `fs::unlinkat`, `fs::FileType::is_socket`,
//! `fs::Mode` (`RWXU`, `RGRP`, `XGRP`), `io::Errno::kind`.

use core::convert::Infallible;
use core::fmt;
use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use rustix::fs::{AtFlags, FileType, Gid, Mode, Uid};

use crate::{
    absolute, make_directory, open_directory_no_follow, split, walk, DirectoryFacts, OpenError,
    PathBreak,
};

/// The mode a created socket directory gets: rwx for its owner, r-x for its
/// group, nothing for others. Spec: docs/50 §3.1 ("mode 0750").
pub const SOCKET_DIRECTORY_MODE: u32 = 0o750;

/// The bits an existing socket directory must not have: write for its
/// group, any access for others. Spec: docs/50 §3.1 (0750 at most); the
/// daemons' rule before task R11c (`mode & 0o027 == 0`).
const SOCKET_DIRECTORY_FORBIDDEN: u32 = 0o027;

/// The all-ones id: not an account (`fchown` would read it as "leave
/// unchanged"). Spec: rustix docs.rs `fs::Uid::from_raw` / `fs::Gid::from_raw`
/// ("must be the value of a valid Unix user ID, and not `-1`"); crates/config
/// refuses it too (Q-230 item 6).
const ALL_ONES_ID: u32 = u32::MAX;

/// [`SOCKET_DIRECTORY_MODE`] as rustix mode bits.
/// Spec: rustix docs.rs `fs::Mode` (`RWXU` = `S_IRWXU`, `RGRP` = `S_IRGRP`,
/// `XGRP` = `S_IXGRP`).
fn socket_directory_mode() -> Mode {
    Mode::RWXU | Mode::RGRP | Mode::XGRP
}

/// How the group of an **existing** socket directory is judged.
/// Spec: docs/50 §3.1 ("group = the channel's clients"); docs/questions
/// Q-260 item 6; docs/51 §4.6 (`admin_socket_group`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExistingGroup {
    /// The group is a setting (admind's `admin_socket_group`): an existing
    /// directory must have exactly [`SocketDirectoryOwner::gid`].
    Configured,
    /// The group is not a setting (keyd, dird, auditd): an existing
    /// directory may carry the group the operator gave it for the channel's
    /// clients; a created one gets [`SocketDirectoryOwner::gid`].
    ChosenByOperator,
}

/// Who a socket directory belongs to.
/// Spec: docs/50 §3.1 ("owned by the server's uid … group = the channel's
/// clients").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketDirectoryOwner {
    /// The daemon's account: the directory's owner.
    pub uid: u32,
    /// The group a created directory is given (and an existing one must have
    /// under [`ExistingGroup::Configured`]).
    pub gid: u32,
    /// How an existing directory's group is judged.
    pub existing_group: ExistingGroup,
}

/// Which part of the socket-directory rule the directory broke.
/// Spec: docs/50 §3.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketDirectoryBreak {
    /// A symbolic link or not a directory.
    NotADirectory,
    /// Not owned by the daemon's account.
    WrongOwner,
    /// Not of the configured group ([`ExistingGroup::Configured`]).
    WrongGroup,
    /// Writable by its group, or accessible at all by others.
    GroupWriteOrOtherAccess,
}

/// Why [`prepare_socket_directory`] refused.
/// Spec: docs/50 §7.5 (fail closed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketDirectoryError {
    /// The socket path does not name a socket inside a directory below `/`
    /// (no directory part, or a part that ends in `/`, `.` or `..`).
    NoSocketDirectory,
    /// The owner or the group is the all-ones id, which is no account.
    NotAnAccount,
    /// A directory above the socket directory is a link or not a directory,
    /// is owned by neither root nor the daemon's account, or is writable by
    /// group or others.
    Path(PathBreak),
    /// The socket directory broke the socket-directory rule.
    Directory(SocketDirectoryBreak),
    /// A system call failed (the system's error kind; never a path).
    Io(io::ErrorKind),
}

impl fmt::Display for SocketDirectoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SocketDirectoryError::NoSocketDirectory => {
                f.write_str("the socket path does not name a socket inside its own directory")
            }
            SocketDirectoryError::NotAnAccount => {
                f.write_str("the socket directory's owner or group is not an account")
            }
            SocketDirectoryError::Path(path) => write!(f, "the socket directory's path {path}"),
            SocketDirectoryError::Directory(SocketDirectoryBreak::NotADirectory) => {
                f.write_str("the socket directory is a symbolic link or not a directory")
            }
            SocketDirectoryError::Directory(SocketDirectoryBreak::WrongOwner) => {
                f.write_str("the socket directory is not owned by the daemon's account")
            }
            SocketDirectoryError::Directory(SocketDirectoryBreak::WrongGroup) => {
                f.write_str("the socket directory is not of the configured group")
            }
            SocketDirectoryError::Directory(SocketDirectoryBreak::GroupWriteOrOtherAccess) => {
                f.write_str("the socket directory is writable by its group or accessible by others")
            }
            SocketDirectoryError::Io(kind) => {
                write!(f, "the socket directory could not be prepared: {kind}")
            }
        }
    }
}

impl std::error::Error for SocketDirectoryError {}

/// The [`SocketDirectoryError`] for a failed system call.
fn system(errno: rustix::io::Errno) -> SocketDirectoryError {
    SocketDirectoryError::Io(errno.kind())
}

/// The socket-directory rule on a directory's facts: a directory, owned by
/// `owner.uid`, of `owner.gid` under [`ExistingGroup::Configured`], no group
/// write and no access for others — checked in that order.
///
/// # Errors
/// [`SocketDirectoryBreak`].
///
/// Spec: docs/50 §3.1; the daemons' rule before task R11c (directory,
/// owner, admind's group, `mode & 0o027 == 0`).
fn socket_directory_rule(
    facts: &DirectoryFacts,
    owner: &SocketDirectoryOwner,
) -> Result<(), SocketDirectoryBreak> {
    if !facts.directory {
        return Err(SocketDirectoryBreak::NotADirectory);
    }
    if facts.owner_uid != owner.uid {
        return Err(SocketDirectoryBreak::WrongOwner);
    }
    if owner.existing_group == ExistingGroup::Configured && facts.group_gid != owner.gid {
        return Err(SocketDirectoryBreak::WrongGroup);
    }
    if facts.mode & SOCKET_DIRECTORY_FORBIDDEN != 0 {
        return Err(SocketDirectoryBreak::GroupWriteOrOtherAccess);
    }
    Ok(())
}

/// The rule on the facts of an opened directory descriptor.
fn check_opened(
    directory: impl AsFd,
    owner: &SocketDirectoryOwner,
) -> Result<(), SocketDirectoryError> {
    let opened = rustix::fs::fstat(directory).map_err(system)?;
    socket_directory_rule(&DirectoryFacts::of(&opened), owner)
        .map_err(SocketDirectoryError::Directory)
}

/// Prepare the directory of the socket at `socket` for the daemon whose
/// account is `owner` (module documentation, steps 1-3): walk its parent,
/// check an existing directory or create a new one by descriptor, and remove
/// a stale socket in it relative to its descriptor. Runs as root before the
/// privilege drop (an unprivileged test passes its own account as the
/// owner).
///
/// # Errors
/// [`SocketDirectoryError`]. A directory created and then refused (an
/// owner change the system refused) stays behind; nothing else is ever
/// removed but a stale socket.
///
/// Spec: this module's documentation.
pub fn prepare_socket_directory(
    socket: &Path,
    owner: SocketDirectoryOwner,
) -> Result<(), SocketDirectoryError> {
    if owner.uid == ALL_ONES_ID || owner.gid == ALL_ONES_ID {
        return Err(SocketDirectoryError::NotAnAccount);
    }
    let absolute = absolute(socket).map_err(|error| SocketDirectoryError::Io(error.kind()))?;
    let (directory_path, socket_name) = split(absolute.as_os_str().as_bytes())
        .map_err(|_| SocketDirectoryError::NoSocketDirectory)?;
    let (parent, name) =
        walk::<Infallible>(directory_path, owner.uid).map_err(|error| match error {
            OpenError::Path(PathBreak::NoFileName) => SocketDirectoryError::NoSocketDirectory,
            OpenError::Path(path) => SocketDirectoryError::Path(path),
            OpenError::Io(kind) => SocketDirectoryError::Io(kind),
            OpenError::Refused(never) => match never {},
        })?;
    let directory = match rustix::fs::statat(&parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(seen) => {
            socket_directory_rule(&DirectoryFacts::of(&seen), &owner)
                .map_err(SocketDirectoryError::Directory)?;
            let directory = open_directory_no_follow(&parent, name).map_err(system)?;
            check_opened(&directory, &owner)?;
            directory
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => create(&parent, name, &owner)?,
        Err(error) => return Err(system(error)),
    };
    remove_stale_socket(&directory, socket_name)
}

/// Create the socket directory `name` relative to `parent`, by descriptor
/// (module documentation, step 2, "absent").
///
/// # Errors
/// [`SocketDirectoryError::Io`], [`SocketDirectoryError::Directory`].
///
/// Spec: docs/50 §3.1 (mode 0750, the server's uid, a group); rustix
/// docs.rs `fs::mkdirat`, `fs::fchmod`, `fs::fchown`.
fn create(
    parent: impl AsFd,
    name: &[u8],
    owner: &SocketDirectoryOwner,
) -> Result<OwnedFd, SocketDirectoryError> {
    let directory = make_directory(&parent, name, socket_directory_mode()).map_err(system)?;
    rustix::fs::fchown(
        &directory,
        Some(Uid::from_raw(owner.uid)),
        Some(Gid::from_raw(owner.gid)),
    )
    .map_err(system)?;
    check_opened(&directory, owner)?;
    Ok(directory)
}

/// Remove a socket left at `name` in the checked `directory` by an earlier
/// run, relative to the directory's descriptor; anything else at that name
/// — or nothing — is left as it is.
///
/// # Errors
/// [`SocketDirectoryError::Io`] when the name cannot be inspected (other
/// than absent) or the socket cannot be removed.
///
/// Spec: docs/50 §3.1 ("deleting a stale socket file before bind … the
/// daemon manages this explicitly"); rustix docs.rs `fs::statat`,
/// `fs::FileType::is_socket` ("Returns `true` if this `FileType` is a
/// socket"), `fs::unlinkat` ("Unlinks a file or remove a directory"; without
/// `REMOVEDIR` a file).
fn remove_stale_socket(directory: impl AsFd, name: &[u8]) -> Result<(), SocketDirectoryError> {
    match rustix::fs::statat(&directory, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(seen) if FileType::from_raw_mode(seen.st_mode).is_socket() => {
            rustix::fs::unlinkat(&directory, name, AtFlags::empty()).map_err(system)
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(system(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Source: docs/50 §3.1 ("mode 0750") — the created directory's mode
    // bits are the published constant.
    #[test]
    #[allow(clippy::useless_conversion)]
    fn the_created_mode_is_0750() {
        assert_eq!(
            u32::from(socket_directory_mode().bits()),
            SOCKET_DIRECTORY_MODE
        );
    }

    // Source: docs/50 §3.1; the daemons' rule before task R11c — the rule on
    // facts, in its order (directory, owner, configured group, no group
    // write and no other access).
    #[test]
    fn the_socket_directory_rule_on_facts() {
        const DIRECTORY: u32 = 0o040_000;
        const LINK: u32 = 0o120_000;
        let owner = SocketDirectoryOwner {
            uid: 1000,
            gid: 2000,
            existing_group: ExistingGroup::Configured,
        };
        let any_group = SocketDirectoryOwner {
            existing_group: ExistingGroup::ChosenByOperator,
            ..owner
        };
        let facts = |directory, owner_uid, group_gid, mode| DirectoryFacts {
            directory,
            owner_uid,
            group_gid,
            mode,
        };
        for accepted in [0o750, 0o700, 0o710, 0o740, 0o1750] {
            assert_eq!(
                socket_directory_rule(&facts(true, 1000, 2000, DIRECTORY | accepted), &owner),
                Ok(()),
                "{accepted:o}"
            );
        }
        assert_eq!(
            socket_directory_rule(&facts(false, 1000, 2000, LINK | 0o750), &owner),
            Err(SocketDirectoryBreak::NotADirectory)
        );
        assert_eq!(
            socket_directory_rule(&facts(true, 1001, 2000, DIRECTORY | 0o750), &owner),
            Err(SocketDirectoryBreak::WrongOwner)
        );
        assert_eq!(
            socket_directory_rule(&facts(true, 1000, 2001, DIRECTORY | 0o750), &owner),
            Err(SocketDirectoryBreak::WrongGroup)
        );
        assert_eq!(
            socket_directory_rule(&facts(true, 1000, 2001, DIRECTORY | 0o750), &any_group),
            Ok(())
        );
        for refused in [0o770, 0o751, 0o755, 0o754, 0o752, 0o777] {
            assert_eq!(
                socket_directory_rule(&facts(true, 1000, 2000, DIRECTORY | refused), &owner),
                Err(SocketDirectoryBreak::GroupWriteOrOtherAccess),
                "{refused:o}"
            );
        }
    }
}
