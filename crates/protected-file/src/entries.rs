//! Creating, renaming, removing and syncing entries relative to walked
//! directories — the filesystem operations of provision's installer (task
//! R11c; docs/questions/Q-532 item 2; A-92, A-109).
//!
//! The installer runs once, as root, offline (docs/51 §4.3 steps 3-9, §4.4):
//! it checks that every target is absent, creates a staging directory,
//! creates each file in it exclusively, renames each into place without
//! replacing anything, `fsync`s the directories and removes the empty
//! staging directory. Before task R11c it did all of this by path from the
//! current directory: the last component never followed a link, but every
//! directory component above it did, and no directory's owner was checked
//! (Q-532 item 2). Here every operation:
//!
//! 1. walks its path from `/` under the directory rule (each component
//!    inspected and opened without following a link, owned by root or by the
//!    file's owner, not writable by group or others — the crate
//!    documentation, steps 0-1), with the caller's `owner_uid` as the owner
//!    the rule admits besides root (root's own files: root; dird's database:
//!    dird's account — the owner each file ends up with, Q-468 option 2(b));
//! 2. acts with the `*at` system call **relative to the walked directory's
//!    descriptor** on the last component only — never by path again.
//!
//! No function hands out a directory descriptor (the walk stays private,
//! Q-530 item 2), with one exception: [`create_new_directory`] lends the new
//! directory's descriptor to the caller's owner-change step (provision's
//! `Ownership`, which tests replace with a recorder) — a borrowed
//! descriptor, for the duration of that call.
//!
//! Spec: docs/51 §4.3 steps 1, 3-9, §4.4 (refuse to overwrite; staging and
//! rename; the database last); docs/52 §3.13 (C13), §7 R11; Q-468 options 1,
//! 2(b), 3 (A-102); Q-532 item 2 (A-109); rustix docs.rs `fs::statat`,
//! `fs::AtFlags` (`SYMLINK_NOFOLLOW`, `REMOVEDIR`), `fs::openat`,
//! `fs::OFlags` (`CREATE`, `EXCL`, `NOFOLLOW`, `WRONLY`, `RDWR`, `CLOEXEC`),
//! `fs::Mode` (`RUSR`, `WUSR`, `RGRP`, `ROTH`, `RWXU`), `fs::mkdirat`,
//! `fs::fchmod`, `fs::fstat`, `fs::Stat::st_dev`, `fs::renameat` ("Renames a
//! file or directory"), `fs::renameat_with` with `RenameFlags::NOREPLACE`
//! (`RENAME_NOREPLACE`), `fs::unlinkat`, `fs::fsync`.

use core::convert::Infallible;
use core::fmt;
use std::fs::File;
use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use rustix::fs::{AtFlags, FileType, Mode, OFlags, RenameFlags};

use crate::{
    absolute, directory_rule, make_directory, walk, walk_to_directory, DirectoryFacts, FileFacts,
    OpenError, PathBreak,
};

/// Why an installer operation refused or failed.
/// Spec: docs/51 §4.4 (every failure stops the installer; fail closed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryError {
    /// A system call failed (the system's error kind; never a path).
    Io(io::ErrorKind),
    /// The path's shape or one of its directories broke the directory rule.
    Path(PathBreak),
}

impl fmt::Display for EntryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EntryError::Io(kind) => write!(f, "{kind}"),
            EntryError::Path(path) => write!(f, "the path {path}"),
        }
    }
}

impl std::error::Error for EntryError {}

/// The [`EntryError`] of a walk (whose callers here have no file rule).
fn walk_error(error: OpenError<Infallible>) -> EntryError {
    match error {
        OpenError::Io(kind) => EntryError::Io(kind),
        OpenError::Path(path) => EntryError::Path(path),
        OpenError::Refused(never) => match never {},
    }
}

/// The [`EntryError`] for a failed system call.
fn system(errno: rustix::io::Errno) -> EntryError {
    EntryError::Io(errno.kind())
}

/// The walked directory a path lies in, and its last component.
fn parent_of(path: &[u8], owner_uid: u32) -> Result<(OwnedFd, &[u8]), EntryError> {
    walk::<Infallible>(path, owner_uid).map_err(walk_error)
}

/// The permission bits of a file the installer creates — a closed set, set
/// exactly with `fchmod` after the creation.
/// Spec: docs/51 §4.3 steps 4-8 (key root:0400; database 0600;
/// configuration, policy, manifest root:0644).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NewFileMode {
    /// 0400 — read by its owner only (the integrity key, step 4).
    OwnerRead,
    /// 0644 — read and written by its owner, read by everyone (the policy,
    /// the configuration files, the manifest: steps 6-8, "not secret").
    OwnerWriteEveryoneRead,
}

impl NewFileMode {
    /// The rustix mode bits.
    /// Spec: rustix docs.rs `fs::Mode` (`RUSR`, `WUSR`, `RGRP`, `ROTH`).
    fn bits(self) -> Mode {
        match self {
            NewFileMode::OwnerRead => Mode::RUSR,
            NewFileMode::OwnerWriteEveryoneRead => {
                Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::ROTH
            }
        }
    }
}

/// 0600 — read and written by its owner only (the database, docs/51 §4.3
/// step 5). Spec: rustix docs.rs `fs::Mode` (`RUSR`, `WUSR`).
fn owner_read_write() -> Mode {
    Mode::RUSR | Mode::WUSR
}

/// 0700 — the staging directory (docs/51 §4.3 step 3: "root, 0700").
/// Spec: rustix docs.rs `fs::Mode::RWXU`.
fn owner_only_directory() -> Mode {
    Mode::RWXU
}

/// The facts of whatever is at `path` — inspected without following a link
/// (a dangling link is present), relative to its walked directory — or
/// `None` if nothing is there.
///
/// # Errors
/// [`EntryError::Path`] when the path's shape or a directory on it breaks
/// the directory rule; [`EntryError::Io`] when a directory is missing or an
/// inspection fails (other than the entry being absent).
///
/// Spec: docs/51 §4.3 step 1 ("every target path absent (including the
/// staging directory)"), §4.4 (a dangling link counts as present); rustix
/// docs.rs `fs::statat` with `AtFlags::SYMLINK_NOFOLLOW`.
pub fn entry_facts(path: &Path, owner_uid: u32) -> Result<Option<FileFacts>, EntryError> {
    let absolute = absolute(path).map_err(|error| EntryError::Io(error.kind()))?;
    let (directory, name) = parent_of(absolute.as_os_str().as_bytes(), owner_uid)?;
    match rustix::fs::statat(&directory, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(seen) => Ok(Some(FileFacts::of(&seen))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(system(error)),
    }
}

/// The filesystem a directory is on, compared with another's to keep every
/// rename on one filesystem. Opaque: only equality is meaningful.
/// Spec: docs/51 §4.3 step 3 ("on the same filesystem as the targets");
/// rustix docs.rs `fs::Stat::st_dev`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Device(i128);

/// The [`Device`] of the directory at `path`, every component of which —
/// the last included — is walked under the directory rule.
///
/// # Errors
/// [`EntryError`].
///
/// Spec: docs/51 §4.3 steps 1, 3; rustix docs.rs `fs::fstat`,
/// `fs::Stat::st_dev`.
pub fn directory_device(path: &Path, owner_uid: u32) -> Result<Device, EntryError> {
    let absolute = absolute(path).map_err(|error| EntryError::Io(error.kind()))?;
    let directory = walk_to_directory::<Infallible>(absolute.as_os_str().as_bytes(), owner_uid)
        .map_err(walk_error)?;
    let facts = rustix::fs::fstat(&directory).map_err(system)?;
    Ok(Device(i128::from(facts.st_dev)))
}

/// Create the directory at `path`, which must not exist, mode exactly 0700
/// (`mkdirat` relative to the walked parent; opened without following a
/// link; `fchmod` on that descriptor); lend its descriptor to `give_owner`
/// (the caller's owner change); then apply the directory rule to it.
///
/// # Errors
/// [`OpenError::Io`] when the walk, the creation (an existing name of any
/// kind included), the open, the mode change or the inspection fails;
/// [`OpenError::Path`] when a directory on the path, or the created one
/// after the owner change, breaks the directory rule;
/// [`OpenError::Refused`] with `give_owner`'s error. A directory created and
/// then refused stays behind (nothing is removed here).
///
/// Spec: docs/51 §4.3 step 3 ("a new directory (root, 0700)"), §4.4 (a
/// crash after it leaves only the staging directory); rustix docs.rs
/// `fs::mkdirat`, `fs::openat`, `fs::fchmod`, `fs::fstat`.
pub fn create_new_directory<E>(
    path: &Path,
    owner_uid: u32,
    give_owner: impl FnOnce(BorrowedFd<'_>) -> Result<(), E>,
) -> Result<(), OpenError<E>> {
    let absolute = absolute(path).map_err(|error| OpenError::Io(error.kind()))?;
    let (parent, name) = walk::<E>(absolute.as_os_str().as_bytes(), owner_uid)?;
    let directory = make_directory(&parent, name, owner_only_directory())
        .map_err(|errno| OpenError::Io(errno.kind()))?;
    give_owner(directory.as_fd()).map_err(OpenError::Refused)?;
    let facts = rustix::fs::fstat(&directory).map_err(|errno| OpenError::Io(errno.kind()))?;
    directory_rule(&DirectoryFacts::of(&facts), owner_uid).map_err(OpenError::Path)?;
    Ok(())
}

/// Create the file at `path` for the given access: exclusively and without
/// following a link (any existing name is refused, never reused), relative
/// to the walked parent; then its mode set exactly with `fchmod`.
fn create_new(path: &Path, owner_uid: u32, access: OFlags, mode: Mode) -> Result<File, EntryError> {
    let absolute = absolute(path).map_err(|error| EntryError::Io(error.kind()))?;
    let (directory, name) = parent_of(absolute.as_os_str().as_bytes(), owner_uid)?;
    let created = rustix::fs::openat(
        &directory,
        name,
        access | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        mode,
    )
    .map_err(system)?;
    rustix::fs::fchmod(&created, mode).map_err(system)?;
    Ok(File::from(created))
}

/// Create the file at `path`, which must not exist, for writing, with
/// exactly `mode` (module documentation).
///
/// # Errors
/// [`EntryError`] (an existing name of any kind, a dangling link included,
/// is [`EntryError::Io`]).
///
/// Spec: docs/51 §4.3 steps 4, 6-8; docs/51 §5.10 (the policy edit's
/// `.next` file); rustix docs.rs `fs::openat` (`O_CREAT | O_EXCL |
/// O_NOFOLLOW | O_WRONLY | O_CLOEXEC`), `fs::fchmod`.
pub fn create_new_file(path: &Path, owner_uid: u32, mode: NewFileMode) -> Result<File, EntryError> {
    create_new(path, owner_uid, OFlags::WRONLY, mode.bits())
}

/// Create the file at `path`, which must not exist, for reading and writing,
/// mode exactly 0600 — a database file (redb needs read and write access on
/// the descriptor it is given).
///
/// # Errors
/// As [`create_new_file`].
///
/// Spec: docs/51 §4.3 step 5 ("dird, 0600"); docs/questions Q-532 item 3;
/// rustix docs.rs `fs::OFlags::RDWR`.
pub fn create_new_read_write(path: &Path, owner_uid: u32) -> Result<File, EntryError> {
    create_new(path, owner_uid, OFlags::RDWR, owner_read_write())
}

/// Rename `from` to `to`, each relative to its walked directory, refusing if
/// anything exists at `to` (the refuse-to-overwrite rule holds at the last
/// step too, not only at the pre-check).
///
/// # Errors
/// [`EntryError`].
///
/// Spec: docs/51 §4.3 step 9, §4.4; rustix docs.rs `fs::renameat_with` with
/// `RenameFlags::NOREPLACE`.
pub fn rename_no_replace(
    from: &Path,
    from_owner_uid: u32,
    to: &Path,
    to_owner_uid: u32,
) -> Result<(), EntryError> {
    rename(from, from_owner_uid, to, to_owner_uid, Replace::Refuse)
}

/// Rename `from` to `to`, each relative to its walked directory, atomically
/// replacing what is at `to` (the policy edit only).
///
/// # Errors
/// [`EntryError`].
///
/// Spec: docs/51 §5.10 (A-80: "write atomically"); rustix docs.rs
/// `fs::renameat` ("Renames a file or directory").
pub fn rename_replace(
    from: &Path,
    from_owner_uid: u32,
    to: &Path,
    to_owner_uid: u32,
) -> Result<(), EntryError> {
    rename(from, from_owner_uid, to, to_owner_uid, Replace::Atomically)
}

/// Whether a rename may replace what is at its target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Replace {
    /// `RENAME_NOREPLACE`: an existing target refuses the rename.
    Refuse,
    /// Plain `renameat`: an existing target is replaced atomically.
    Atomically,
}

/// The rename of [`rename_no_replace`] and [`rename_replace`].
/// Spec: rustix docs.rs `fs::renameat_with` ("the same as `renameat` but
/// adds an additional flags operand"), `fs::renameat`.
fn rename(
    from: &Path,
    from_owner_uid: u32,
    to: &Path,
    to_owner_uid: u32,
    replace: Replace,
) -> Result<(), EntryError> {
    let from = absolute(from).map_err(|error| EntryError::Io(error.kind()))?;
    let to = absolute(to).map_err(|error| EntryError::Io(error.kind()))?;
    let (from_directory, from_name) = parent_of(from.as_os_str().as_bytes(), from_owner_uid)?;
    let (to_directory, to_name) = parent_of(to.as_os_str().as_bytes(), to_owner_uid)?;
    match replace {
        Replace::Refuse => rustix::fs::renameat_with(
            &from_directory,
            from_name,
            &to_directory,
            to_name,
            RenameFlags::NOREPLACE,
        ),
        Replace::Atomically => {
            rustix::fs::renameat(&from_directory, from_name, &to_directory, to_name)
        }
    }
    .map_err(system)
}

/// Remove the (empty) directory at `path`, relative to its walked parent.
///
/// # Errors
/// [`EntryError`] (a directory that is not empty included).
///
/// Spec: docs/51 §4.3 step 9 ("removal of the staging"); rustix docs.rs
/// `fs::unlinkat` with `AtFlags::REMOVEDIR` ("this removes a directory").
pub fn remove_empty_directory(path: &Path, owner_uid: u32) -> Result<(), EntryError> {
    let absolute = absolute(path).map_err(|error| EntryError::Io(error.kind()))?;
    let (directory, name) = parent_of(absolute.as_os_str().as_bytes(), owner_uid)?;
    rustix::fs::unlinkat(&directory, name, AtFlags::REMOVEDIR).map_err(system)
}

/// Remove the entry at `path` that is **not a directory**, relative to its
/// walked parent: inspected without following a link (a directory is
/// refused — `remove_empty_directory` is the only way to remove one), then
/// `unlinkat` without `REMOVEDIR`. A link at the name is removed as the
/// link itself — `unlinkat` never follows the last component — so nothing
/// outside the walked directory is touched. `Ok(false)` when nothing is
/// there.
///
/// Callers: root's activation of dird's `policy.next` (it removes the file
/// it installed, owned by dird's account), and dird removing the partial
/// file an interrupted `policy.next` write left in its own directory (task
/// A16, docs/51 §5.10; docs/questions/Q-591).
///
/// # Errors
/// [`EntryError::Path`] when the path's shape or a directory on it breaks
/// the directory rule; [`EntryError::Io`] when the inspection (other than
/// "absent") or the removal fails, or with `IsADirectory` for a directory.
///
/// Spec: docs/51 §5.10; docs/52 §3.13 (C13); rustix docs.rs `fs::statat`
/// with `AtFlags::SYMLINK_NOFOLLOW`, `fs::FileType::is_dir`, `fs::unlinkat`
/// ("Unlinks a file or remove a directory"; without `REMOVEDIR` a file).
pub fn remove_entry(path: &Path, owner_uid: u32) -> Result<bool, EntryError> {
    let absolute = absolute(path).map_err(|error| EntryError::Io(error.kind()))?;
    let (directory, name) = parent_of(absolute.as_os_str().as_bytes(), owner_uid)?;
    match rustix::fs::statat(&directory, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(seen) if FileType::from_raw_mode(seen.st_mode).is_dir() => {
            Err(EntryError::Io(io::ErrorKind::IsADirectory))
        }
        Ok(_) => rustix::fs::unlinkat(&directory, name, AtFlags::empty())
            .map(|()| true)
            .map_err(system),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(system(error)),
    }
}

/// `fsync` the directory at `path` (makes a creation, rename or removal in
/// it durable), every component of which — the last included — is walked.
///
/// # Errors
/// [`EntryError`].
///
/// Spec: docs/51 §4.3 step 9 ("fsync for every file"); rustix docs.rs
/// `fs::fsync` ("Ensures that file data and metadata is written to the
/// underlying storage device"; on macOS not a persistence guarantee — the
/// product target is Linux).
pub fn sync_directory(path: &Path, owner_uid: u32) -> Result<(), EntryError> {
    let absolute = absolute(path).map_err(|error| EntryError::Io(error.kind()))?;
    let directory = walk_to_directory::<Infallible>(absolute.as_os_str().as_bytes(), owner_uid)
        .map_err(walk_error)?;
    rustix::fs::fsync(&directory).map_err(system)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Source: docs/51 §4.3 steps 3-8 — the closed set of created modes.
    #[test]
    #[allow(clippy::useless_conversion)]
    fn the_created_modes() {
        assert_eq!(u32::from(NewFileMode::OwnerRead.bits().bits()), 0o400);
        assert_eq!(
            u32::from(NewFileMode::OwnerWriteEveryoneRead.bits().bits()),
            0o644
        );
        assert_eq!(u32::from(owner_read_write().bits()), 0o600);
        assert_eq!(u32::from(owner_only_directory().bits()), 0o700);
    }
}
