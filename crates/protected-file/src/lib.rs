#![forbid(unsafe_code)]
//! `protected-file`: the one reader of the protected files a daemon or a tool
//! reads (as root, before any privilege drop) to decide what it does —
//! configuration files, the provisioning manifest, the development policy,
//! and the key and certificate files a configuration points to.
//!
//! # The steps
//!
//! [`open`] does, in this order:
//!
//! 1. **inspect the path without following a link** (`lstat`): the caller's
//!    rule is applied to these facts, so a symbolic link (its facts are a
//!    link's, not a regular file's), a directory, a FIFO or any other
//!    non-regular file is refused **before any open** — nothing blocks on a
//!    FIFO and nothing behind a link is touched;
//! 2. **open it without following a link** (`openat` with `O_RDONLY |
//!    O_NOFOLLOW | O_CLOEXEC`): a link put in the path's place since step 1
//!    makes the open fail, it is not followed;
//! 3. **apply the rule again to the opened descriptor** (`fstat`): the
//!    authoritative check is on the file actually read, whatever happened to
//!    the path in between.
//!
//! [`read_to_bound`] then reads at most `bound + 1` octets, so an oversized
//! file is refused without being read whole (AGENTS.md §6: no unbounded
//! allocation). [`read_configuration_file`] is the three steps plus the read
//! under the rule docs/50 §7.1 sets for a configuration file
//! ([`configuration_file_rule`]: a regular file, owned by the expected
//! account, not writable by group or others), which the provisioning
//! manifest (docs/51 §4.3 step 8, "root:0644") and the development policy
//! (Q-270 item 2) follow too.
//!
//! The rule is a parameter: each reader keeps its own owner (root in
//! production, the test account in tests), its own mode rule (0400 exactly
//! for a key file) and its own error type and order — only the way the file
//! is reached is shared. Before this crate the daemons opened the path with
//! a plain `open` (which follows links) and checked the opened file; the
//! provisioning tools did what is described here, in two copies
//! (docs/questions/Q-345 item 10, Q-414 item 4; decisions A-86 and A-96:
//! "O_NOFOLLOW in every reader").
//!
//! # Residuals
//!
//! O_NOFOLLOW concerns the **last** component of the path only: a link in a
//! directory component is still followed, and the directories on the path
//! are not checked here (the same residual Q-345 item 10 recorded; provision
//! checks the parents it writes into). A non-regular file swapped in between
//! steps 1 and 2 is refused at step 3, after the open.
//!
//! # Provenance
//!
//! Written only from this project's decided design (docs/50 §7.1, §7.2,
//! R50-12; docs/51 §4.3 steps 7, 8, §4.4; PENDING-OWNER A-86, A-96, P-2,
//! P-12; docs/questions Q-345 item 10, Q-414 item 4), the readers it
//! replaces (this project's own code), the Rust standard library's API, and
//! the docs.rs API pages of rustix 1.1.6: `fs::openat` ("The `Mode` argument
//! is only significant when creating a file"), `fs::OFlags` (`RDONLY`,
//! `NOFOLLOW`, `CLOEXEC`), `fs::lstat` ("Queries metadata for a file or
//! directory, without following symlinks"), `fs::fstat` ("Queries metadata
//! for an open file or directory"), `fs::Stat` (`st_mode`, `st_uid`),
//! `fs::FileType::from_raw_mode` / `is_file`, `fs::RawMode`, `fs::CWD`,
//! `io::Errno::kind` — API documentation only, never its source (P-2). No
//! other implementation consulted or recalled (AGENTS.md §1-3).
//!
//! Spec: docs/50 §7.1, §7.2, R50-12; docs/51 §4.3 steps 7, 8; A-86; A-96.

use core::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use rustix::fs::{FileType, OFlags, RawMode, Stat, CWD};

/// Write permission for group and for others: the bits a configuration-like
/// file must not have. Spec: docs/50 §7.1 ("file root:0644").
pub const GROUP_OR_OTHER_WRITE: u32 = 0o022;

/// Every permission bit of a mode (owner, group, other, and the set-user-id,
/// set-group-id and sticky bits), for a rule that requires an exact mode
/// (a key file's 0400). Spec: docs/50 R50-12 ("the file 0400"); Q-270
/// item 1.
pub const PERMISSION_BITS: u32 = 0o7777;

/// What a rule looks at: the facts of the path (step 1) or of the opened
/// descriptor (step 3).
/// Spec: docs/50 §7.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileFacts {
    /// The facts are a regular file's (a link's facts never are: step 1
    /// does not follow it).
    pub regular_file: bool,
    /// The owner uid.
    pub owner_uid: u32,
    /// The whole `st_mode` (file type and permission bits).
    pub mode: u32,
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
    /// ("Returns true if this is a regular file").
    fn of(stat: &Stat) -> FileFacts {
        FileFacts {
            regular_file: FileType::from_raw_mode(stat.st_mode).is_file(),
            owner_uid: stat.st_uid,
            mode: raw_mode_bits(stat.st_mode),
        }
    }
}

/// Why [`open`] refused.
/// Spec: docs/50 §7.5 (fail closed); AGENTS.md §6.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenError<E> {
    /// The path could not be inspected, opened, or the opened descriptor
    /// inspected (the system's error kind; never a path or content).
    Io(io::ErrorKind),
    /// The caller's rule refused the facts of the path or of the opened
    /// file — a link or any non-regular path included.
    Refused(E),
}

/// Inspect the path without following a link, open it without following a
/// link, and apply `rule` to both the path's facts and the opened file's
/// (module documentation, steps 1-3). The open file is returned unread.
///
/// # Errors
/// [`OpenError::Io`] when `lstat`, `openat` or `fstat` fails;
/// [`OpenError::Refused`] with `rule`'s error otherwise.
///
/// Spec: docs/50 §7.1; A-86 (O_NOFOLLOW in every reader); rustix docs.rs
/// `fs::lstat`, `fs::openat`, `fs::OFlags`, `fs::fstat`.
pub fn open<E>(
    path: &Path,
    rule: impl Fn(&FileFacts) -> Result<(), E>,
) -> Result<File, OpenError<E>> {
    let link = rustix::fs::lstat(path).map_err(|e| OpenError::Io(e.kind()))?;
    rule(&FileFacts::of(&link)).map_err(OpenError::Refused)?;
    let file = open_no_follow(path).map_err(|e| OpenError::Io(e.kind()))?;
    let opened = rustix::fs::fstat(&file).map_err(|e| OpenError::Io(e.kind()))?;
    rule(&FileFacts::of(&opened)).map_err(OpenError::Refused)?;
    Ok(file)
}

/// Open an existing file read-only without following a link in its last
/// component.
/// Spec: rustix docs.rs `fs::openat` with `OFlags::RDONLY | NOFOLLOW |
/// CLOEXEC` (the mode is only significant when creating a file); A-86.
fn open_no_follow(path: &Path) -> Result<File, rustix::io::Errno> {
    let fd = rustix::fs::openat(
        CWD,
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?;
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

/// Which part of the configuration-file rule a file broke.
/// Spec: docs/50 §7.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleBreak {
    /// Not a regular file — a symbolic link, a directory, a FIFO, a device
    /// or a socket.
    NotRegularFile,
    /// Not owned by the expected account (root in production).
    WrongOwner,
    /// Writable by its group or by others.
    WritableByGroupOrOthers,
}

impl fmt::Display for RuleBreak {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            RuleBreak::NotRegularFile => "is a symbolic link or not a regular file",
            RuleBreak::WrongOwner => "is not owned by the expected account",
            RuleBreak::WritableByGroupOrOthers => "is writable by its group or by others",
        })
    }
}

/// The configuration-file rule: a regular file, owned by `owner_uid`, not
/// writable by group or others — checked in that order. The provisioning
/// manifest and the development policy follow the same rule.
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

/// Why [`read_configuration_file`] refused.
/// Spec: docs/50 §7.1, §7.5.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The file could not be inspected, opened or read.
    Unreadable(io::ErrorKind),
    /// The configuration-file rule refused it.
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
/// `owner_uid`, at most `bound` octets ([`open`] then [`read_to_bound`]).
///
/// # Errors
/// [`Refusal`].
///
/// Spec: docs/50 §7.1; docs/51 §4.3 step 8; A-86.
pub fn read_configuration_file(
    path: &Path,
    owner_uid: u32,
    bound: usize,
) -> Result<Vec<u8>, Refusal> {
    let file =
        open(path, |facts| configuration_file_rule(facts, owner_uid)).map_err(
            |error| match error {
                OpenError::Io(kind) => Refusal::Unreadable(kind),
                OpenError::Refused(rule) => Refusal::Rule(rule),
            },
        )?;
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
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    // Source: rustix docs.rs `fs::OFlags::NOFOLLOW` (O_NOFOLLOW) — step 2 on
    // its own: a link in the last component is not followed, even when it
    // points to a readable regular file; the file itself opens.
    #[test]
    fn step_2_does_not_follow_a_link() {
        let dir = Scratch::new("nofollow");
        let target = dir.0.join("target");
        std::fs::write(&target, b"x\n").unwrap();
        let link = dir.0.join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(open_no_follow(&target).is_ok());
        assert!(open_no_follow(&link).is_err());
    }
}
