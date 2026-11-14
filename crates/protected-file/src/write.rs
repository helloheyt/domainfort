//! The opens that are not read-only, through the same walk (task R11b;
//! docs/questions/Q-481 items b, c; Q-530): the data files a daemon keeps
//! with its own account after the privilege drop — auditd's log segments
//! (docs/50 §6.4: "append write access to the audit file only") and dird's
//! directory store (docs/50 §6.4: "access to the redb file only (owned by
//! dird, 0600)").
//!
//! Every function walks the path from `/` under the directory rule with
//! `file_owner_uid` as the file's owner (the crate documentation, steps 0-1)
//! and then reaches the file **relative to the last directory's
//! descriptor** — never by its path again:
//!
//! * [`open_append`] and [`open_read_write`]: the file's three steps of
//!   [`crate::open`] (inspect without following a link and apply the rule,
//!   open with `O_NOFOLLOW`, apply the rule to the opened descriptor) with
//!   `O_WRONLY | O_APPEND` or `O_RDWR` in place of `O_RDONLY`;
//! * [`create_new_append`]: `O_WRONLY | O_APPEND | O_CREAT | O_EXCL |
//!   O_NOFOLLOW | O_CLOEXEC` with mode 0600 — an existing name of any kind,
//!   a link included, is refused, never reused — then the mode set exactly
//!   to 0600 on the descriptor (`fchmod`: the process umask can neither
//!   widen nor narrow it) and the caller's rule applied to the created
//!   descriptor (`fstat`).
//!
//! Why here and not in a sibling crate: the walk is the one thing every
//! privileged open must share, and it stays private to this crate — no
//! caller ever holds a checked directory's descriptor or can open beside it
//! with flags of its own (Q-530 item 2).
//!
//! Spec: docs/50 §6.4, §8.1; docs/52 §3.13 (C13), §7 R11; Q-468 options 1,
//! 2(b), 3 (A-102); Q-481 (A-104); rustix docs.rs `fs::openat` ("The `Mode`
//! argument is only significant when creating a file"), `fs::OFlags`
//! (`WRONLY`, `APPEND`, `CREATE`, `EXCL`, `NOFOLLOW`, `CLOEXEC`), `fs::Mode`
//! (`RUSR`, `WUSR`), `fs::fchmod` ("Sets open file or directory
//! permissions"), `fs::fstat`.

use std::fs::File;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use rustix::fs::{Mode, OFlags};

use crate::{absolute, open_existing, system, walk, Access, FileFacts, OpenError};

/// The permission bits of a created data file: read and write for its
/// owner only. Spec: docs/50 §6.4 ("owned by dird, 0600"); crates/audit-log
/// (segments created owner-read-write only); rustix docs.rs `fs::Mode`
/// (`RUSR` = `S_IRUSR`, `WUSR` = `S_IWUSR`).
fn owner_read_write() -> Mode {
    Mode::RUSR | Mode::WUSR
}

/// Walk the path from `/` under the directory rule, then open the existing
/// file for appending — every write lands at its end — in the file's three
/// steps (the rule on its facts before and after the open).
///
/// # Errors
/// As [`crate::open`].
///
/// Spec: docs/50 §6.4 ("append write access to the audit file only"),
/// §8.1; this module's documentation.
pub fn open_append<E>(
    path: &Path,
    file_owner_uid: u32,
    rule: impl Fn(&FileFacts) -> Result<(), E>,
) -> Result<File, OpenError<E>> {
    open_existing(path, file_owner_uid, Access::Append, rule)
}

/// Walk the path from `/` under the directory rule, then open the existing
/// file for reading and writing in the file's three steps (the rule on its
/// facts before and after the open).
///
/// # Errors
/// As [`crate::open`].
///
/// Spec: docs/50 R50-2, §6.4 ("access to the redb file only (owned by
/// dird, 0600)"); this module's documentation.
pub fn open_read_write<E>(
    path: &Path,
    file_owner_uid: u32,
    rule: impl Fn(&FileFacts) -> Result<(), E>,
) -> Result<File, OpenError<E>> {
    open_existing(path, file_owner_uid, Access::ReadWrite, rule)
}

/// Walk the path from `/` under the directory rule, then create the file,
/// which must not exist yet, for appending: exclusively and without
/// following a link (any existing name is refused), mode exactly 0600; and
/// apply `rule` to the created descriptor.
///
/// A file created and then refused by `rule` (an expected owner other than
/// the creating account) stays behind, empty: nothing is ever removed here.
///
/// # Errors
/// [`OpenError::Io`] when the walk, the creation (an existing name
/// included), the mode change or the `fstat` fails; [`OpenError::Path`]
/// when a directory breaks the directory rule; [`OpenError::Refused`] with
/// `rule`'s error.
///
/// Spec: docs/50 §6.4, §8.1 (a segment is never reopened for writing by
/// accident: crates/audit-log); this module's documentation.
pub fn create_new_append<E>(
    path: &Path,
    file_owner_uid: u32,
    rule: impl Fn(&FileFacts) -> Result<(), E>,
) -> Result<File, OpenError<E>> {
    let absolute = absolute(path).map_err(|error| OpenError::Io(error.kind()))?;
    let (directory, name) = walk(absolute.as_os_str().as_bytes(), file_owner_uid)?;
    let created = rustix::fs::openat(
        &directory,
        name,
        OFlags::WRONLY
            | OFlags::APPEND
            | OFlags::CREATE
            | OFlags::EXCL
            | OFlags::NOFOLLOW
            | OFlags::CLOEXEC,
        owner_read_write(),
    )
    .map_err(system)?;
    rustix::fs::fchmod(&created, owner_read_write()).map_err(system)?;
    let facts = rustix::fs::fstat(&created).map_err(system)?;
    rule(&FileFacts::of(&facts)).map_err(OpenError::Refused)?;
    Ok(File::from(created))
}
