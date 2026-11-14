//! The filesystem operations of the installer, through rustix's documented
//! safe API (docs.rs, rustix 1.1.6 — P-2, P-12): no symbolic link is ever
//! followed when a file or directory is created or opened by these helpers
//! (A-86 follow-up: O_NOFOLLOW), every file is created exclusively
//! (O_EXCL: an existing path — of any kind — is refused, never reused),
//! modes are set explicitly with `fchmod` after creation (the process
//! umask cannot widen or narrow them), and every rename either refuses to
//! replace (`renameat_with(…, RenameFlags::NOREPLACE)`) or — only for the
//! policy edit — replaces atomically (`renameat`).
//!
//! Spec: docs/51 §4.3 steps 3-4, 9, §4.4 (refuse to overwrite; staging and
//! rename); A-86 (O_NOFOLLOW in every reader/writer); rustix docs.rs
//! pages: `fs::openat`, `fs::OFlags`, `fs::Mode`, `fs::mkdirat`,
//! `fs::fchmod`, `fs::fsync`, `fs::renameat`, `fs::renameat_with`,
//! `fs::RenameFlags`, `fs::unlinkat`, `fs::AtFlags`, `fs::CWD`.

use std::fs::File;
use std::os::fd::{AsFd, OwnedFd};
use std::path::Path;

use rustix::fs::{AtFlags, Mode, OFlags, RenameFlags, CWD};
use rustix::io::Errno;

/// rw for the owner only (the database, docs/51 §4.3 step 5: 0600).
pub(crate) fn mode_0600() -> Mode {
    Mode::RUSR | Mode::WUSR
}

/// r for the owner only (the integrity key, docs/51 §4.3 step 4: 0400).
pub(crate) fn mode_0400() -> Mode {
    Mode::RUSR
}

/// rw owner, r group and other (configuration, policy, manifest: docs/51
/// §4.3 steps 6-8, root:0644).
pub(crate) fn mode_0644() -> Mode {
    Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::ROTH
}

/// rwx for the owner only (the staging directory, docs/51 §4.3 step 3:
/// root, 0700).
pub(crate) fn mode_0700() -> Mode {
    Mode::RWXU
}

/// Create a new regular file exclusively, without following a symbolic
/// link in its last component, opened for writing; then set its mode
/// exactly to `mode`.
/// Spec: rustix `openat` (O_CREAT | O_EXCL | O_NOFOLLOW | O_WRONLY |
/// O_CLOEXEC), `fchmod`; A-86.
pub(crate) fn create_new_file(path: &Path, mode: Mode) -> Result<File, Errno> {
    let fd = rustix::fs::openat(
        CWD,
        path,
        OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::WRONLY | OFlags::CLOEXEC,
        mode,
    )?;
    rustix::fs::fchmod(&fd, mode)?;
    Ok(File::from(fd))
}

/// Open an existing regular file for reading without following a symbolic
/// link in its last component.
/// Spec: rustix `openat` (O_RDONLY | O_NOFOLLOW | O_CLOEXEC); A-86.
pub(crate) fn open_no_follow(path: &Path) -> Result<File, Errno> {
    let fd = rustix::fs::openat(
        CWD,
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    Ok(File::from(fd))
}

/// Create a new directory with exactly `mode` (no symbolic link is followed:
/// `mkdirat` fails on any existing path), and open it.
/// Spec: rustix `mkdirat`, `openat` (O_DIRECTORY | O_NOFOLLOW), `fchmod`.
pub(crate) fn create_new_dir(path: &Path, mode: Mode) -> Result<OwnedFd, Errno> {
    rustix::fs::mkdirat(CWD, path, mode)?;
    let fd = open_dir(path)?;
    rustix::fs::fchmod(&fd, mode)?;
    Ok(fd)
}

/// Open a directory without following a symbolic link in its last
/// component. Spec: rustix `openat` (O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
/// O_CLOEXEC).
pub(crate) fn open_dir(path: &Path) -> Result<OwnedFd, Errno> {
    rustix::fs::openat(
        CWD,
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
}

/// `fsync` an open file or directory. Spec: rustix `fsync` ("Ensures that
/// file data and metadata is written to the underlying storage device";
/// on Apple platforms not a persistence guarantee — the product target is
/// Linux).
pub(crate) fn sync<Fd: AsFd>(fd: Fd) -> Result<(), Errno> {
    rustix::fs::fsync(fd)
}

/// `fsync` the directory at `path` (makes a rename or unlink in it
/// durable). Spec: rustix `fsync`.
pub(crate) fn sync_dir(path: &Path) -> Result<(), Errno> {
    sync(open_dir(path)?)
}

/// Rename `from` to `to`, refusing if `to` exists (the refuse-to-overwrite
/// rule holds at the last step too, not only at the pre-check).
/// Spec: docs/51 §4.4; rustix `renameat_with` with `RenameFlags::NOREPLACE`
/// (RENAME_NOREPLACE).
pub(crate) fn rename_no_replace(from: &Path, to: &Path) -> Result<(), Errno> {
    rustix::fs::renameat_with(CWD, from, CWD, to, RenameFlags::NOREPLACE)
}

/// Rename `from` to `to`, atomically replacing `to` (the policy edit).
/// Spec: docs/51 §5.10 (A-80: "write atomically"); rustix `renameat`.
pub(crate) fn rename_replace(from: &Path, to: &Path) -> Result<(), Errno> {
    rustix::fs::renameat(CWD, from, CWD, to)
}

/// Remove the (empty) directory at `path`. Spec: rustix `unlinkat` with
/// `AtFlags::REMOVEDIR`.
pub(crate) fn remove_dir(path: &Path) -> Result<(), Errno> {
    rustix::fs::unlinkat(CWD, path, AtFlags::REMOVEDIR)
}
