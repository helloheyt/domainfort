#![forbid(unsafe_code)]
//! `protected-file`: the one way a daemon or a tool reaches the files it
//! reads or writes with its own privileges — the protected files it reads
//! (as root, before any privilege drop) to decide what it does
//! (configuration files, the provisioning manifest, the development policy,
//! the key and certificate files a configuration points to, provision's
//! password files) and the data files a daemon keeps after the drop
//! (auditd's log segments, dird's directory store; [`open_append`],
//! [`open_read_write`], [`create_new_append`], [`for_each_entry_beside`],
//! task R11b).
//!
//! # The walk
//!
//! [`open`] reaches the file **one path component at a time, from `/`**, so
//! that no component of the path — not only the last — can be a symbolic
//! link, and no directory on it can be one that an account other than root
//! or the file's owner may change (docs/52 §3.13, class C13; R11; Q-468
//! options 1 and 2(b), decision A-102):
//!
//! 0. **the path's shape**: a relative path is taken relative to the current
//!    directory (the system's absolute name for it, joined in front, so that
//!    directory's components are walked too); the path must end in a file
//!    name — `/`, a trailing `/`, a final `.` or `..` is
//!    [`PathBreak::NoFileName`];
//! 1. **each directory, starting with `/`**, relative to the descriptor of
//!    the directory before it: inspected without following a link
//!    (`statat` with `AT_SYMLINK_NOFOLLOW`), the directory rule applied to
//!    those facts, opened without following a link (`openat` with
//!    `O_RDONLY | O_NOFOLLOW | O_DIRECTORY | O_CLOEXEC`), and the directory
//!    rule applied again to the opened descriptor (`fstat`). A link put in
//!    the component's place between the inspection and the open makes the
//!    open fail; it is not followed. `.` and `..` components are walked like
//!    any other name, so the directory they lead to is checked too;
//! 2. **the file**, relative to the last directory's descriptor, in the three
//!    steps this crate always had: inspected without following a link
//!    (`statat` with `AT_SYMLINK_NOFOLLOW`) and the caller's rule applied to
//!    those facts — a link, a directory, a FIFO or any other non-regular file
//!    is refused **before any open**; opened with `O_RDONLY | O_NOFOLLOW |
//!    O_CLOEXEC`; and the caller's rule applied again to the opened
//!    descriptor (`fstat`), the authoritative check on the file actually
//!    read.
//!
//! **The directory rule** (Q-468 option 2(b)): a directory (a link's facts
//! never are a directory's), owned by root (uid 0) **or by the file's
//! owner** (the owner the caller expects of the file), not writable by its
//! group or by others — checked in that order. No exception for the sticky
//! bit. In production every protected file is root's, so every directory on
//! its path must be root's.
//!
//! [`read_to_bound`] then reads at most `bound + 1` octets, so an oversized
//! file is refused without being read whole (AGENTS.md §6: no unbounded
//! allocation). [`read_configuration_file`] is the walk plus the read under
//! the rule docs/50 §7.1 sets for a configuration file
//! ([`configuration_file_rule`]: a regular file, owned by the expected
//! account, not writable by group or others), which the provisioning
//! manifest (docs/51 §4.3 step 8, "root:0644") and the development policy
//! (Q-270 item 2) follow too.
//!
//! The file rule is a parameter: each reader keeps its own owner (root in
//! production, the test account in tests), its own mode rule (0400 exactly
//! for a key file) and its own error type and order — only the way the file
//! is reached is shared. The directory rule is the same for every reader;
//! only the file's owner, which it admits besides root, is the caller's.
//!
//! # Writing, and the entries of a directory (task R11b)
//!
//! The same walk serves the opens that are not read-only (`src/write.rs`):
//! [`open_append`] and [`open_read_write`] open an existing file for
//! appending or for reading and writing, in the file's three steps above
//! (only the access mode differs); [`create_new_append`] creates a file that
//! must not exist yet (`O_CREAT | O_EXCL | O_NOFOLLOW`, mode 0600 set
//! exactly) relative to the last directory and applies the caller's rule to
//! the created descriptor. [`for_each_entry_beside`] lists the directory a
//! file path lies in — the walked, checked directory, read through its own
//! descriptor — and gives each entry's facts without following a link. No
//! entry point takes a directory descriptor or a path from outside the walk,
//! so every open of a protected or data file passes the walk
//! (docs/questions/Q-481 items a-c; Q-530). An existing data file a daemon
//! keeps after its drop is judged by [`data_file_rule`] (a regular file, the
//! daemon's, no access at all for group or others — created 0600; task
//! R11c, Q-531 item 4).
//!
//! # Creating, renaming and removing entries (task R11c)
//!
//! The privileged path operations that are not opens go through the same
//! walk and are made **relative to the walked directory's descriptor**, so
//! no directory component is ever followed through a link and nothing is
//! changed by path after it was checked (docs/52 C13; Q-532 items 1, 2, 5;
//! A-109):
//!
//! * [`prepare_socket_directory`] (`src/socket_directory.rs`): a daemon's
//!   socket directory, as root before the privilege drop — the parent
//!   walked, the directory created with `mkdirat` relative to it if absent,
//!   opened without following a link, its mode and owner set with `fchmod` /
//!   `fchown` **on that descriptor**, its facts checked; and a stale socket
//!   in it removed with `unlinkat` relative to it;
//! * the installer's operations (`src/entries.rs`; provision, docs/51 §4.3
//!   steps 3-9, A-92): [`entry_facts`], [`directory_device`],
//!   [`create_new_directory`], [`create_new_file`],
//!   [`create_new_read_write`], [`rename_no_replace`], [`rename_replace`],
//!   [`remove_empty_directory`], [`sync_directory`] — each walks its path(s)
//!   and acts with the `*at` call relative to the walked descriptor;
//! * dird's `policy.next` (task A16, docs/51 §5.10): its directory prepared
//!   as root before the drop by [`prepare_daemon_directory`] (the socket
//!   directory's steps 1-2, nothing removed), the file written by dird with
//!   [`create_new_read_write`] + [`rename_no_replace`] (exclusive create of a
//!   partial file, no-replace rename — one pending change at a time), and
//!   removed by root's activation with [`remove_entry`] (`unlinkat` of a
//!   non-directory relative to the walked directory).
//!
//! Every mode a created entry gets is one of a closed set (0400, 0600, 0644
//! for files; 0700 for the installer's staging directory; 0750 for a socket
//! directory), set exactly with `fchmod` whatever the umask. No entry point
//! hands out a directory descriptor: the one place a caller sees one is the
//! owner-change step of [`create_new_directory`] (a borrowed descriptor of
//! the directory just created, for provision's `Ownership`), and the source
//! scans (`tests/single_open_path.rs`, `tests/single_path_operation.rs`)
//! make any `*at` call outside this crate fail a test.
//!
//! # Residuals
//!
//! * The walk opens each directory with `O_RDONLY`, so a reader that is not
//!   root needs read permission (not only search permission) on every
//!   directory of the path (docs/questions/Q-482).
//! * `/dev/urandom` is a device, not a protected file, and is opened by
//!   path outside this crate (docs/questions/Q-481 item d; Q-530).
//! * A non-regular file swapped in between the file's inspection and its open
//!   makes the open itself block on a FIFO (Q-442 item 7); the `fstat` check
//!   refuses anything else.
//! * A Unix socket is bound by path (there is no descriptor-relative bind),
//!   and its mode cannot be set by name without following a link on Linux
//!   (`chmodat` with `SYMLINK_NOFOLLOW` is not implemented there): the
//!   daemons bind and set the socket's mode by path after the drop, inside
//!   the socket directory [`prepare_socket_directory`] checked at start —
//!   so only root or the daemon's own account can change any component of
//!   that path (docs/questions/Q-550 item 2).
//! * The Linux behaviour (the `openat` error for a link under `O_NOFOLLOW`,
//!   the `Stat` field types) is taken from the docs.rs pages and has run on
//!   macOS only (P-27).
//!
//! # Tests
//!
//! There is no test seam: every walk starts at `/`. An unprivileged test
//! cannot make the directories above the system's temporary directory root's
//! and unwritable (`/var` is a link and `/private` group-writable on macOS;
//! `/tmp` is writable by all on Linux), so the tests whose files this crate
//! opens keep them under the workspace (crates/test-scratch,
//! `<workspace>/.test-scratch/…`; `$HOME/.test-scratch/…` when the workspace
//! path cannot appear in a configuration value), whose directories pass the
//! rule with the test account as the expected owner (docs/questions/Q-480).
//!
//! # Provenance
//!
//! Written only from this project's decided design (docs/50 §7.1, §7.2,
//! R50-12; docs/51 §4.3 steps 7, 8, §4.4; docs/52 §3.13, §7 R11;
//! PENDING-OWNER A-86, A-96, A-99, A-102, P-2, P-12; docs/questions Q-345
//! item 10, Q-414 item 4, Q-442, Q-468), the readers it replaces (this
//! project's own code), the Rust standard library's API, and the docs.rs API
//! pages of rustix 1.1.6: `fs::openat` ("The `Mode` argument is only
//! significant when creating a file"), `fs::statat` ("Queries metadata for a
//! file or directory"), `fs::AtFlags` (`SYMLINK_NOFOLLOW` =
//! `AT_SYMLINK_NOFOLLOW`), `fs::lstat` ("without following symlinks"),
//! `fs::OFlags` (`RDONLY`, `NOFOLLOW`, `DIRECTORY`, `CLOEXEC`), `fs::fstat`
//! ("Queries metadata for an open file or directory"), `fs::Stat`
//! (`st_mode`, `st_uid`), `fs::FileType::from_raw_mode` / `is_file` /
//! `is_dir`, `fs::RawMode`, `fs::Mode::empty`, `fs::CWD` (`AT_FDCWD`),
//! `path::Arg` (implemented for `&[u8]`), `io::Errno::kind` — API
//! documentation only, never its source (P-2); for task R11b also
//! `fs::OFlags` (`WRONLY`, `RDWR` — "not equal to `RDONLY | WRONLY`",
//! `APPEND`, `CREATE`, `EXCL`), `fs::fchmod` ("Sets open file or directory
//! permissions"), `fs::Mode` (`RUSR`, `WUSR`), `fs::FileType::is_symlink`,
//! `fs::Stat::st_size`, `fs::Dir::read_from` ("Borrow `fd` and construct a
//! `Dir` that reads entries from the given directory file descriptor"),
//! `fs::Dir::read` ("`None` means the end of the directory"),
//! `fs::DirEntry::file_name` and the crate's feature list (`std` enables
//! `alloc`, which `Dir` needs) — no feature added; for task R11c (read in
//! that session) `fs::mkdirat` ("Creates a directory"), `fs::fchown` ("Sets
//! open file or directory ownership"), `fs::Uid::from_raw` /
//! `fs::Gid::from_raw` ("must be the value of a valid Unix user ID, and not
//! `-1`"), `fs::unlinkat` (with `AtFlags::REMOVEDIR` "this removes a
//! directory"), `fs::renameat`, `fs::renameat_with`, `fs::RenameFlags`
//! (`NOREPLACE` = `RENAME_NOREPLACE`), `fs::fsync`, `fs::chmodat` (on Linux
//! `AtFlags::SYMLINK_NOFOLLOW` "is not implemented" — so a socket's mode
//! cannot be set by name without following a link; not used),
//! `fs::Stat` (`st_dev`, `st_gid`), `fs::FileType::is_socket`, `fs::Mode`
//! (`RWXU`, `RGRP`, `XGRP`, `ROTH`), `io::Errno::kind` — all under the `fs`
//! (and `std`) features already enabled: none added. No other
//! implementation consulted or recalled (AGENTS.md §1-3).
//!
//! Spec: docs/50 §3.1, §7.1, §7.2, R50-12, §6.4; docs/51 §4.3 steps 3-9,
//! §4.4; docs/52 §3.13 (R11); A-86; A-92; A-96; A-99; A-102; A-104; A-109;
//! Q-468; Q-481; Q-531; Q-532.

mod entries;
mod listing;
mod socket_directory;
mod write;

pub use entries::{
    create_new_directory, create_new_file, create_new_read_write, directory_device, entry_facts,
    remove_empty_directory, remove_entry, rename_no_replace, rename_replace, sync_directory,
    Device, EntryError, NewFileMode,
};
pub use listing::for_each_entry_beside;
pub use socket_directory::{
    prepare_daemon_directory, prepare_socket_directory, ExistingGroup, SocketDirectoryBreak,
    SocketDirectoryError, SocketDirectoryOwner, SOCKET_DIRECTORY_MODE,
};
pub use write::{create_new_append, open_append, open_read_write};

use core::fmt;
use std::borrow::Cow;
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use rustix::fs::{AtFlags, FileType, Mode, OFlags, RawMode, Stat, CWD};

/// Write permission for group and for others: the bits a configuration-like
/// file, and every directory on a protected path, must not have.
/// Spec: docs/50 §7.1 ("file root:0644"); Q-468 option 2(b).
pub const GROUP_OR_OTHER_WRITE: u32 = 0o022;

/// Every permission bit for group and for others: the bits a data file a
/// daemon keeps after its privilege drop must not have at all (created
/// 0600). Spec: docs/50 §6.4 ("owned by dird, 0600"); docs/questions Q-531
/// item 4 (A-109: "no group/other access; no reader group in the design").
pub const GROUP_OR_OTHER_ACCESS: u32 = 0o077;

/// Every permission bit of a mode (owner, group, other, and the set-user-id,
/// set-group-id and sticky bits), for a rule that requires an exact mode
/// (a key file's 0400). Spec: docs/50 R50-12 ("the file 0400"); Q-270
/// item 1.
pub const PERMISSION_BITS: u32 = 0o7777;

/// The account every directory on a protected path may belong to besides
/// the file's owner: root. Spec: Q-468 option 2(b) (A-102).
const ROOT_UID: u32 = 0;

/// The path separator, as an octet. Spec: Q-468 option 1 (the walk splits
/// the path into its components).
const SEPARATOR: u8 = b'/';

/// What a file rule looks at: the facts of the file's name in its directory
/// (step 2, before the open) or of the opened descriptor (after it).
/// Spec: docs/50 §7.1; docs/51 §4.4 (a password file: "not a symlink",
/// "≤ 1024 bytes" — both decided on these facts, before any octet is read;
/// task R11b).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileFacts {
    /// The facts are a regular file's (a link's facts never are: the
    /// inspection does not follow it).
    pub regular_file: bool,
    /// The facts are a symbolic link's (only the inspection before the open
    /// can see one: the open itself does not follow a link).
    pub symbolic_link: bool,
    /// The owner uid.
    pub owner_uid: u32,
    /// The whole `st_mode` (file type and permission bits).
    pub mode: u32,
    /// The size in octets (`st_size`; a negative value, which no file
    /// has, reads as the largest size, so a size rule refuses it).
    pub size: u64,
}

/// The `st_mode` value as a `u32`. `RawMode` is `u32` on Linux and narrower
/// on Apple targets (the development host), so the conversion widens there
/// and is the identity here — the lint is silenced for that reason only.
/// Spec: rustix docs.rs `fs::RawMode` (`mode_t`), `fs::Stat::st_mode`.
#[allow(clippy::useless_conversion)]
fn raw_mode_bits(st_mode: RawMode) -> u32 {
    u32::from(st_mode)
}

impl FileFacts {
    /// The facts of a `stat` result.
    /// Spec: rustix docs.rs `fs::FileType::from_raw_mode` ("from the
    /// `S_IFMT` bits of the `st_mode` field of a `Stat`"), `is_file`
    /// ("Returns true if this is a regular file"), `is_symlink` ("Returns
    /// `true` if this `FileType` is a symlink"), `fs::Stat::st_size`.
    fn of(stat: &Stat) -> FileFacts {
        let file_type = FileType::from_raw_mode(stat.st_mode);
        FileFacts {
            regular_file: file_type.is_file(),
            symbolic_link: file_type.is_symlink(),
            owner_uid: stat.st_uid,
            mode: raw_mode_bits(stat.st_mode),
            size: u64::try_from(stat.st_size).unwrap_or(u64::MAX),
        }
    }
}

/// What the directory rule looks at: the facts of one directory component
/// (its name in the directory before it, then its opened descriptor).
/// Spec: Q-468 options 1, 2(b).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DirectoryFacts {
    /// The facts are a directory's (a link's facts never are).
    pub(crate) directory: bool,
    /// The owner uid.
    pub(crate) owner_uid: u32,
    /// The group gid (the socket-directory rule's, task R11c).
    pub(crate) group_gid: u32,
    /// The whole `st_mode`.
    pub(crate) mode: u32,
}

impl DirectoryFacts {
    /// The facts of a `stat` result.
    /// Spec: rustix docs.rs `fs::FileType::from_raw_mode`, `is_dir`
    /// ("Returns true if this is a directory"), `fs::Stat` (`st_gid`).
    pub(crate) fn of(stat: &Stat) -> DirectoryFacts {
        DirectoryFacts {
            directory: FileType::from_raw_mode(stat.st_mode).is_dir(),
            owner_uid: stat.st_uid,
            group_gid: stat.st_gid,
            mode: raw_mode_bits(stat.st_mode),
        }
    }
}

/// Why the path to a protected file was refused before the file itself was
/// looked at.
/// Spec: docs/52 §3.13 (R11); Q-468 options 1, 2(b); docs/50 §7.5 (fail
/// closed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathBreak {
    /// The path does not end in a file name: it is `/`, or it ends in `/`,
    /// `.` or `..`.
    NoFileName,
    /// A directory component is a symbolic link or not a directory.
    NotADirectory,
    /// A directory component is owned by neither root nor the file's owner.
    DirectoryWrongOwner,
    /// A directory component is writable by its group or by others.
    DirectoryWritableByGroupOrOthers,
}

impl fmt::Display for PathBreak {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            PathBreak::NoFileName => "does not end in a file name",
            PathBreak::NotADirectory => {
                "has a directory component that is a symbolic link or not a directory"
            }
            PathBreak::DirectoryWrongOwner => {
                "has a directory component owned by neither root nor the file's owner"
            }
            PathBreak::DirectoryWritableByGroupOrOthers => {
                "has a directory component writable by its group or by others"
            }
        })
    }
}

/// The directory rule: a directory, owned by root or by `file_owner_uid`,
/// not writable by group or others — checked in that order.
///
/// # Errors
/// [`PathBreak::NotADirectory`], [`PathBreak::DirectoryWrongOwner`],
/// [`PathBreak::DirectoryWritableByGroupOrOthers`].
///
/// Spec: Q-468 option 2(b) ("root or the file's owner, no write for group
/// or other"), decision A-102; docs/52 §3.13.
fn directory_rule(facts: &DirectoryFacts, file_owner_uid: u32) -> Result<(), PathBreak> {
    if !facts.directory {
        return Err(PathBreak::NotADirectory);
    }
    if facts.owner_uid != ROOT_UID && facts.owner_uid != file_owner_uid {
        return Err(PathBreak::DirectoryWrongOwner);
    }
    if facts.mode & GROUP_OR_OTHER_WRITE != 0 {
        return Err(PathBreak::DirectoryWritableByGroupOrOthers);
    }
    Ok(())
}

/// Why [`open`] refused.
/// Spec: docs/50 §7.5 (fail closed); AGENTS.md §6.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenError<E> {
    /// A directory or the file could not be inspected or opened, or the
    /// opened descriptor inspected (the system's error kind; never a path or
    /// content).
    Io(io::ErrorKind),
    /// The path's shape or one of its directories broke the directory rule.
    Path(PathBreak),
    /// The caller's rule refused the facts of the file or of the opened
    /// file — a link or any non-regular file included.
    Refused(E),
}

/// The [`OpenError`] for a failed system call.
pub(crate) fn system<E>(errno: rustix::io::Errno) -> OpenError<E> {
    OpenError::Io(errno.kind())
}

/// Walk the path from `/` under the directory rule (with `file_owner_uid`
/// as the file's owner), then inspect the file without following a link,
/// open it without following a link, and apply `rule` to both the file's
/// facts and the opened file's (module documentation, steps 0-2). The open
/// file is returned unread.
///
/// # Errors
/// [`OpenError::Io`] when the current directory cannot be named (for a
/// relative path) or a `statat`, `openat` or `fstat` fails;
/// [`OpenError::Path`] when the path's shape or a directory breaks the
/// directory rule; [`OpenError::Refused`] with `rule`'s error otherwise.
///
/// Spec: docs/50 §7.1; A-86 (O_NOFOLLOW in every reader); docs/52 §3.13
/// (R11); Q-468 options 1, 2(b) (A-102); rustix docs.rs `fs::statat`,
/// `fs::AtFlags::SYMLINK_NOFOLLOW`, `fs::openat`, `fs::OFlags`,
/// `fs::fstat`.
pub fn open<E>(
    path: &Path,
    file_owner_uid: u32,
    rule: impl Fn(&FileFacts) -> Result<(), E>,
) -> Result<File, OpenError<E>> {
    open_existing(path, file_owner_uid, Access::Read, rule)
}

/// How an existing file is opened once its path is walked: the access mode.
/// Every mode adds `O_NOFOLLOW | O_CLOEXEC`.
/// Spec: A-86 (O_NOFOLLOW in every reader); docs/50 §6.4 ("auditd: append
/// write access to the audit file only"; "dird: access to the redb file
/// only"); rustix docs.rs `fs::OFlags` (`RDONLY`, `WRONLY`, `APPEND`,
/// `RDWR`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Access {
    /// `O_RDONLY`: the protected files a daemon or a tool reads.
    Read,
    /// `O_WRONLY | O_APPEND`: every write lands at the end (auditd's log).
    Append,
    /// `O_RDWR`: a database file (dird's store).
    ReadWrite,
}

impl Access {
    /// The `openat` flags of this access mode.
    /// Spec: rustix docs.rs `fs::OFlags` (`RDWR`: "not equal to
    /// `RDONLY | WRONLY`. It's a distinct flag").
    fn flags(self) -> OFlags {
        let mode = match self {
            Access::Read => OFlags::RDONLY,
            Access::Append => OFlags::WRONLY | OFlags::APPEND,
            Access::ReadWrite => OFlags::RDWR,
        };
        mode | OFlags::NOFOLLOW | OFlags::CLOEXEC
    }
}

/// [`open`] with any [`Access`]: walk, inspect the file without following
/// a link and apply `rule`, open it without following a link, apply `rule`
/// to the opened descriptor.
/// Spec: this module's documentation, steps 0-2.
pub(crate) fn open_existing<E>(
    path: &Path,
    file_owner_uid: u32,
    access: Access,
    rule: impl Fn(&FileFacts) -> Result<(), E>,
) -> Result<File, OpenError<E>> {
    let absolute = absolute(path).map_err(|error| OpenError::Io(error.kind()))?;
    let (directory, name) = walk(absolute.as_os_str().as_bytes(), file_owner_uid)?;
    let seen = rustix::fs::statat(&directory, name, AtFlags::SYMLINK_NOFOLLOW).map_err(system)?;
    rule(&FileFacts::of(&seen)).map_err(OpenError::Refused)?;
    let file = open_file_no_follow(&directory, name, access).map_err(system)?;
    let opened = rustix::fs::fstat(&file).map_err(system)?;
    rule(&FileFacts::of(&opened)).map_err(OpenError::Refused)?;
    Ok(file)
}

/// Steps 0 and 1 of the walk for the octets of an absolute path: split off
/// the file name, enter `/` and every directory component under the
/// directory rule, and return the last directory's descriptor with the
/// file name. Nothing about the file itself is looked at.
///
/// # Errors
/// [`OpenError::Path`], [`OpenError::Io`].
///
/// Spec: Q-468 options 1, 2(b) (A-102).
pub(crate) fn walk<E>(
    absolute: &[u8],
    file_owner_uid: u32,
) -> Result<(OwnedFd, &[u8]), OpenError<E>> {
    let (directories, name) = split(absolute).map_err(OpenError::Path)?;
    let mut directory = root(file_owner_uid)?;
    for component in components(directories) {
        directory = enter(&directory, component, file_owner_uid)?;
    }
    Ok((directory, name))
}

/// The path, absolute: a relative path is joined to the system's absolute
/// name of the current directory, so that directory's components are walked
/// and checked like the rest.
/// Spec: Q-468 option 1 (the walk starts at `/`); std `env::current_dir`,
/// `Path::is_absolute`, `Path::join`.
pub(crate) fn absolute(path: &Path) -> io::Result<Cow<'_, Path>> {
    if path.is_absolute() {
        Ok(Cow::Borrowed(path))
    } else {
        Ok(Cow::Owned(std::env::current_dir()?.join(path)))
    }
}

/// Steps 0 and 1 of the walk for a path that names a **directory**: every
/// component, the last included, entered under the directory rule (with
/// `file_owner_uid` as the owner it admits besides root); the last one's
/// descriptor is returned.
///
/// # Errors
/// [`OpenError::Path`], [`OpenError::Io`].
///
/// Spec: Q-468 options 1, 2(b) (A-102); task R11c (the installer's
/// directories, docs/51 §4.3 step 9: `fsync` of each target directory).
pub(crate) fn walk_to_directory<E>(
    absolute: &[u8],
    file_owner_uid: u32,
) -> Result<OwnedFd, OpenError<E>> {
    let (parent, name) = walk(absolute, file_owner_uid)?;
    enter(&parent, name, file_owner_uid)
}

/// Create a directory named `name` relative to `parent` (`mkdirat` fails on
/// any existing name, a dangling link included — nothing is followed), open
/// it without following a link, and set its mode exactly to `mode` on that
/// descriptor (the umask can neither widen nor narrow it). The descriptor
/// is returned for the owner change and the checks.
///
/// # Errors
/// The failing system call's [`rustix::io::Errno`].
///
/// Spec: docs/52 §3.13 (C13), Q-532 items 1, 2 (A-109); rustix docs.rs
/// `fs::mkdirat` ("Creates a directory"), `fs::openat`, `fs::fchmod` ("Sets
/// open file or directory permissions").
pub(crate) fn make_directory(
    parent: impl AsFd,
    name: &[u8],
    mode: Mode,
) -> Result<OwnedFd, rustix::io::Errno> {
    rustix::fs::mkdirat(&parent, name, mode)?;
    let directory = open_directory_no_follow(&parent, name)?;
    rustix::fs::fchmod(&directory, mode)?;
    Ok(directory)
}

/// The directory part and the file name of an absolute path's octets: the
/// name is what follows the last separator, and must be a file name.
///
/// # Errors
/// [`PathBreak::NoFileName`] for `/`, a trailing `/`, a final `.` or `..`.
///
/// Spec: Q-468 option 1 (the file is opened relative to the last directory
/// descriptor).
pub(crate) fn split(absolute: &[u8]) -> Result<(&[u8], &[u8]), PathBreak> {
    let mut parts = absolute.rsplitn(2, |octet| *octet == SEPARATOR);
    let name = parts.next().unwrap_or_default();
    let directories = parts.next().unwrap_or_default();
    if name.is_empty() || name == b"." || name == b".." {
        return Err(PathBreak::NoFileName);
    }
    Ok((directories, name))
}

/// The directory components of a directory part, in order; empty ones (a
/// doubled separator) name no directory and are skipped.
/// Spec: Q-468 option 1.
fn components(directories: &[u8]) -> impl Iterator<Item = &[u8]> {
    directories
        .split(|octet| *octet == SEPARATOR)
        .filter(|component| !component.is_empty())
}

/// The directory the walk starts from: `/`, itself checked under the
/// directory rule.
/// Spec: Q-468 option 1 ("from `/`").
fn root<E>(file_owner_uid: u32) -> Result<OwnedFd, OpenError<E>> {
    enter(CWD, b"/", file_owner_uid)
}

/// Enter one directory component relative to `parent`: inspect it without
/// following a link, apply the directory rule, open it without following a
/// link, and apply the directory rule to the opened descriptor.
///
/// # Errors
/// [`OpenError::Io`], [`OpenError::Path`].
///
/// Spec: Q-468 options 1, 2(b); rustix docs.rs `fs::statat` with
/// `AtFlags::SYMLINK_NOFOLLOW`, `fs::openat`, `fs::fstat`.
pub(crate) fn enter<E>(
    parent: impl AsFd,
    component: &[u8],
    file_owner_uid: u32,
) -> Result<OwnedFd, OpenError<E>> {
    let seen = rustix::fs::statat(&parent, component, AtFlags::SYMLINK_NOFOLLOW).map_err(system)?;
    directory_rule(&DirectoryFacts::of(&seen), file_owner_uid).map_err(OpenError::Path)?;
    let directory = open_directory_no_follow(&parent, component).map_err(system)?;
    let opened = rustix::fs::fstat(&directory).map_err(system)?;
    directory_rule(&DirectoryFacts::of(&opened), file_owner_uid).map_err(OpenError::Path)?;
    Ok(directory)
}

/// Open an existing directory read-only, relative to `parent`, without
/// following a link in `component`.
/// Spec: Q-468 option 1 (`O_RDONLY | O_NOFOLLOW | O_DIRECTORY |
/// O_CLOEXEC`); rustix docs.rs `fs::openat` (the mode is only significant
/// when creating a file).
pub(crate) fn open_directory_no_follow(
    parent: impl AsFd,
    component: &[u8],
) -> Result<OwnedFd, rustix::io::Errno> {
    rustix::fs::openat(
        parent,
        component,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
}

/// Open an existing file with `access`, relative to `directory`, without
/// following a link in `name`.
/// Spec: rustix docs.rs `fs::openat` with [`Access::flags`] (`O_NOFOLLOW |
/// O_CLOEXEC` always; the mode is only significant when creating a file);
/// A-86.
fn open_file_no_follow(
    directory: impl AsFd,
    name: &[u8],
    access: Access,
) -> Result<File, rustix::io::Errno> {
    let fd = rustix::fs::openat(directory, name, access.flags(), Mode::empty())?;
    Ok(File::from(fd))
}

/// Why [`read_to_bound`] refused.
/// Spec: AGENTS.md §6 (bounded reads).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadError {
    /// The read failed (the system's error kind).
    Io(io::ErrorKind),
    /// The file holds more than the bound; it was not read beyond
    /// `bound + 1` octets.
    TooLarge,
}

/// The whole content of `file`, at most `bound` octets: one more is read so
/// an oversized file is detected without reading it whole.
///
/// # Errors
/// [`ReadError`].
///
/// Spec: AGENTS.md §6; docs/50 §7.1 ("file ≤ 64 KiB" for a configuration);
/// std `io::Read::take`, `read_to_end` (which retries `Interrupted`).
pub fn read_to_bound(file: File, bound: usize) -> Result<Vec<u8>, ReadError> {
    let limit = u64::try_from(bound).unwrap_or(u64::MAX).saturating_add(1);
    let mut contents = Vec::new();
    file.take(limit)
        .read_to_end(&mut contents)
        .map_err(|e| ReadError::Io(e.kind()))?;
    if contents.len() > bound {
        return Err(ReadError::TooLarge);
    }
    Ok(contents)
}

/// Which part of the configuration-file rule a file — or a directory on its
/// path — broke. The configuration-file rule covers the path too (the
/// directory rule, Q-468 option 2(b)); a [`PathBreak`] is reported as the
/// break of the same kind ([`RuleBreak::from`]), so a reader's own mapping
/// of these three breaks covers the directories as well.
/// Spec: docs/50 §7.1; Q-468.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleBreak {
    /// Not a regular file — a symbolic link, a directory, a FIFO, a device
    /// or a socket — or a path that does not end in a file name or passes
    /// through a symbolic link or a non-directory.
    NotRegularFile,
    /// Not owned by the expected account (root in production), or a
    /// directory on the path owned by neither root nor that account.
    WrongOwner,
    /// Writable by its group or by others, or a directory on the path is.
    WritableByGroupOrOthers,
}

impl From<PathBreak> for RuleBreak {
    /// The break of the same kind: a path without a file name or through a
    /// link or a non-directory is "not a regular file"; a directory's owner
    /// is "the wrong owner"; a writable directory is "writable".
    /// Spec: Q-468 option 2(b) (the same three conditions as the file rule).
    fn from(path: PathBreak) -> RuleBreak {
        match path {
            PathBreak::NoFileName | PathBreak::NotADirectory => RuleBreak::NotRegularFile,
            PathBreak::DirectoryWrongOwner => RuleBreak::WrongOwner,
            PathBreak::DirectoryWritableByGroupOrOthers => RuleBreak::WritableByGroupOrOthers,
        }
    }
}

impl fmt::Display for RuleBreak {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            RuleBreak::NotRegularFile => {
                "is a symbolic link or not a regular file, or its path passes through one or a non-directory"
            }
            RuleBreak::WrongOwner => {
                "is not owned by the expected account, or a directory on its path is owned by neither root nor that account"
            }
            RuleBreak::WritableByGroupOrOthers => {
                "is writable by its group or by others, or a directory on its path is"
            }
        })
    }
}

/// The configuration-file rule on a file's facts: a regular file, owned by
/// `owner_uid`, not writable by group or others — checked in that order.
/// The provisioning manifest and the development policy follow the same
/// rule. (The directories on the path are checked by [`open`]'s walk.)
///
/// # Errors
/// [`RuleBreak`].
///
/// Spec: docs/50 §7.1 ("file root:0644 (not secret)"); docs/51 §4.3 steps
/// 6-8 (policy, configuration and manifest: root:0644); Q-270 item 2.
pub fn configuration_file_rule(facts: &FileFacts, owner_uid: u32) -> Result<(), RuleBreak> {
    if !facts.regular_file {
        return Err(RuleBreak::NotRegularFile);
    }
    if facts.owner_uid != owner_uid {
        return Err(RuleBreak::WrongOwner);
    }
    if facts.mode & GROUP_OR_OTHER_WRITE != 0 {
        return Err(RuleBreak::WritableByGroupOrOthers);
    }
    Ok(())
}

/// Which part of the data-file rule a file broke.
/// Spec: docs/50 §6.4; docs/questions Q-531 item 4 (A-109).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataFileBreak {
    /// Not a regular file — a symbolic link, a directory, a FIFO, a device
    /// or a socket.
    NotRegularFile,
    /// Not owned by the daemon's account.
    WrongOwner,
    /// Any permission bit for its group or for others is set (readable,
    /// writable or executable by them).
    AccessibleByGroupOrOthers,
}

impl fmt::Display for DataFileBreak {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            DataFileBreak::NotRegularFile => "not a regular file",
            DataFileBreak::WrongOwner => "not owned by the daemon's account",
            DataFileBreak::AccessibleByGroupOrOthers => "accessible by group or others",
        })
    }
}

/// The data-file rule on a file's facts — the files a daemon keeps with its
/// own account after the privilege drop (auditd's log segments, dird's
/// directory store), which this crate creates 0600: a regular file, owned
/// by `owner_uid`, **no** permission bit for group or others — checked in
/// that order. No reader group exists in the design, so none is admitted
/// (fail closed).
///
/// # Errors
/// [`DataFileBreak`].
///
/// Spec: docs/50 §2.4, §6.4 ("owned by dird, 0600"; "auditd: append write
/// access to the audit file only"); docs/questions Q-531 item 4 (A-109:
/// "mode & 0o077 == 0, matching the 0600 it creates").
pub fn data_file_rule(facts: &FileFacts, owner_uid: u32) -> Result<(), DataFileBreak> {
    if !facts.regular_file {
        return Err(DataFileBreak::NotRegularFile);
    }
    if facts.owner_uid != owner_uid {
        return Err(DataFileBreak::WrongOwner);
    }
    if facts.mode & GROUP_OR_OTHER_ACCESS != 0 {
        return Err(DataFileBreak::AccessibleByGroupOrOthers);
    }
    Ok(())
}

/// Why [`read_configuration_file`] refused.
/// Spec: docs/50 §7.1, §7.5.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The file (or a directory on its path) could not be inspected, opened
    /// or read.
    Unreadable(io::ErrorKind),
    /// The configuration-file rule refused it, or a directory on its path.
    Rule(RuleBreak),
    /// The file holds more than the bound.
    TooLarge,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::Unreadable(kind) => write!(f, "cannot be inspected, opened or read: {kind}"),
            Refusal::Rule(rule) => write!(f, "{rule}"),
            Refusal::TooLarge => f.write_str("is larger than its format allows"),
        }
    }
}

impl std::error::Error for Refusal {}

/// The content of the file at `path` under the configuration-file rule for
/// `owner_uid` — the file's own facts and every directory on its path — at
/// most `bound` octets ([`open`] then [`read_to_bound`]).
///
/// # Errors
/// [`Refusal`].
///
/// Spec: docs/50 §7.1; docs/51 §4.3 step 8; A-86; Q-468 (A-102).
pub fn read_configuration_file(
    path: &Path,
    owner_uid: u32,
    bound: usize,
) -> Result<Vec<u8>, Refusal> {
    let file = open(path, owner_uid, |facts| {
        configuration_file_rule(facts, owner_uid)
    })
    .map_err(|error| match error {
        OpenError::Io(kind) => Refusal::Unreadable(kind),
        OpenError::Path(path) => Refusal::Rule(RuleBreak::from(path)),
        OpenError::Refused(rule) => Refusal::Rule(rule),
    })?;
    read_to_bound(file, bound).map_err(|error| match error {
        ReadError::Io(kind) => Refusal::Unreadable(kind),
        ReadError::TooLarge => Refusal::TooLarge,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scratch directory under the system's temporary directory.
    struct Scratch(std::path::PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Scratch {
            let path = std::env::temp_dir()
                .join(format!("protected-file-unit-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).unwrap();
            Scratch(path)
        }

        /// The scratch directory, opened (test code: no walk).
        fn descriptor(&self) -> OwnedFd {
            rustix::fs::openat(
                CWD,
                &self.0,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .unwrap()
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    // Source: rustix docs.rs `fs::OFlags::NOFOLLOW` (O_NOFOLLOW) — the
    // file's open on its own, in every access mode (read, append, read and
    // write): a link in the last component is not followed, even when it
    // points to a readable regular file; the file itself opens.
    #[test]
    fn the_file_open_does_not_follow_a_link() {
        let dir = Scratch::new("nofollow");
        std::fs::write(dir.0.join("target"), b"x\n").unwrap();
        std::os::unix::fs::symlink(dir.0.join("target"), dir.0.join("link")).unwrap();
        let fd = dir.descriptor();
        for access in [Access::Read, Access::Append, Access::ReadWrite] {
            assert!(open_file_no_follow(&fd, b"target", access).is_ok());
            assert!(open_file_no_follow(&fd, b"link", access).is_err());
        }
    }

    // Source: Q-468 option 1 (`O_NOFOLLOW | O_DIRECTORY`) — a directory
    // component's open on its own, without the inspection before it: a link
    // to a directory is not followed, a regular file is not a directory, and
    // the directory itself opens.
    #[test]
    fn the_directory_open_does_not_follow_a_link() {
        let dir = Scratch::new("dir-nofollow");
        std::fs::create_dir(dir.0.join("real")).unwrap();
        std::fs::write(dir.0.join("file"), b"x\n").unwrap();
        std::os::unix::fs::symlink(dir.0.join("real"), dir.0.join("link")).unwrap();
        let fd = dir.descriptor();
        assert!(open_directory_no_follow(&fd, b"real").is_ok());
        assert!(open_directory_no_follow(&fd, b"link").is_err());
        assert!(open_directory_no_follow(&fd, b"file").is_err());
    }

    // Source: Q-468 option 2(b) — the directory rule on facts, in its order
    // (a directory, then root or the file's owner, then no write for group
    // or others); no exception for the sticky bit.
    #[test]
    fn the_directory_rule_on_facts() {
        const DIRECTORY: u32 = 0o040_000;
        const LINK: u32 = 0o120_000;
        let facts = |directory, owner_uid, mode| DirectoryFacts {
            directory,
            owner_uid,
            group_gid: 0,
            mode,
        };
        let owner = 1000;
        for accepted in [0o755, 0o700, 0o711, 0o555, 0o1755] {
            assert_eq!(
                directory_rule(&facts(true, 0, DIRECTORY | accepted), owner),
                Ok(()),
                "{accepted:o}"
            );
            assert_eq!(
                directory_rule(&facts(true, owner, DIRECTORY | accepted), owner),
                Ok(())
            );
        }
        assert_eq!(
            directory_rule(&facts(false, 0, LINK | 0o777), owner),
            Err(PathBreak::NotADirectory)
        );
        assert_eq!(
            directory_rule(&facts(true, owner + 1, DIRECTORY | 0o777), owner),
            Err(PathBreak::DirectoryWrongOwner)
        );
        for writable in [0o775, 0o757, 0o777, 0o1777, 0o730, 0o703] {
            assert_eq!(
                directory_rule(&facts(true, 0, DIRECTORY | writable), owner),
                Err(PathBreak::DirectoryWritableByGroupOrOthers),
                "{writable:o}"
            );
        }
        // With root as the file's owner (production), only root's
        // directories are accepted.
        assert_eq!(
            directory_rule(&facts(true, owner, DIRECTORY | 0o755), 0),
            Err(PathBreak::DirectoryWrongOwner)
        );
    }

    // Source: Q-468 option 1 — the path split into its directory part and
    // its file name; a path that does not end in a file name is refused.
    #[test]
    fn the_path_is_split_at_its_last_separator() {
        assert_eq!(
            split(b"/etc/kdcd/kdcd.conf"),
            Ok((&b"/etc/kdcd"[..], &b"kdcd.conf"[..]))
        );
        assert_eq!(split(b"/f"), Ok((&b""[..], &b"f"[..])));
        for no_name in [&b"/"[..], b"/etc/", b"/etc/.", b"/etc/..", b"//"] {
            assert_eq!(split(no_name), Err(PathBreak::NoFileName));
        }
        let walked: Vec<&[u8]> = components(b"/etc//kdcd/./..").collect();
        assert_eq!(walked, [&b"etc"[..], b"kdcd", b".", b".."]);
        assert_eq!(components(b"").count(), 0);
    }

    // Source: docs/questions Q-531 item 4 (A-109) — the data-file rule on
    // facts, in its order (regular, owner, no group or other access at
    // all): 0600 and 0400 pass; 0640, 0604, 0620, 0601 and 0660 are refused.
    #[test]
    fn the_data_file_rule_on_facts() {
        const REGULAR: u32 = 0o100_000;
        const LINK: u32 = 0o120_000;
        let owner = 1000;
        let facts = |regular_file, owner_uid, mode| FileFacts {
            regular_file,
            symbolic_link: !regular_file,
            owner_uid,
            mode,
            size: 0,
        };
        for accepted in [0o600, 0o400, 0o200, 0o700] {
            assert_eq!(
                data_file_rule(&facts(true, owner, REGULAR | accepted), owner),
                Ok(()),
                "{accepted:o}"
            );
        }
        assert_eq!(
            data_file_rule(&facts(false, owner, LINK | 0o777), owner),
            Err(DataFileBreak::NotRegularFile)
        );
        assert_eq!(
            data_file_rule(&facts(true, owner + 1, REGULAR | 0o777), owner),
            Err(DataFileBreak::WrongOwner)
        );
        for refused in [0o640, 0o604, 0o620, 0o601, 0o660, 0o610] {
            assert_eq!(
                data_file_rule(&facts(true, owner, REGULAR | refused), owner),
                Err(DataFileBreak::AccessibleByGroupOrOthers),
                "{refused:o}"
            );
        }
    }

    // Source: Q-468 option 2(b) — a directory break is reported to a
    // configuration-file reader as the file-rule break of the same kind.
    #[test]
    fn a_path_break_maps_to_the_rule_break_of_its_kind() {
        assert_eq!(
            RuleBreak::from(PathBreak::NoFileName),
            RuleBreak::NotRegularFile
        );
        assert_eq!(
            RuleBreak::from(PathBreak::NotADirectory),
            RuleBreak::NotRegularFile
        );
        assert_eq!(
            RuleBreak::from(PathBreak::DirectoryWrongOwner),
            RuleBreak::WrongOwner
        );
        assert_eq!(
            RuleBreak::from(PathBreak::DirectoryWritableByGroupOrOthers),
            RuleBreak::WritableByGroupOrOthers
        );
    }
}
