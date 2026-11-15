//! Where the segments of the log live, and how new ones are created.
//!
//! The configuration names one path, `audit_log_path` (crates/config
//! `AuditdSettings`). The log is one chain spread over numbered segment files
//! next to it:
//!
//! ```text
//! <audit_log_path>.<n>    n = 1, 2, 3, …  written as exactly 20 decimal digits
//! e.g. /var/log/audit/domain-audit.log.00000000000000000001
//! ```
//!
//! Segment 1 is anchored at genesis; segment `n + 1` is anchored at the head
//! where segment `n` ends (rotation) or at the last good head of a torn
//! segment `n` (recovery). Twenty digits hold every `u64`, so the names also
//! sort in numeric order. Project choice: neither docs/37 nor
//! docs/questions/Q-250 names the files (docs/questions/Q-265 item 2).
//!
//! The listing is strict (fail closed): the numbers must be exactly
//! `1 ..= n` (a gap is a deleted segment); a regular file is required; a
//! name that starts with `<file name>.` but is not followed by 20 digits, or
//! a file at the base path itself, is refused rather than skipped. Other
//! names in the directory are not the log's and are left alone.
//!
//! # Every segment through crates/protected-file (task R11b)
//!
//! The listing, every read, every append and every new segment go through
//! crates/protected-file's walk from `/` with **auditd's own account** as
//! the owner (docs/52 R11; docs/questions/Q-481 item b, Q-530): every
//! directory on the path is entered without following a link and must be
//! root's or auditd's and not writable by group or others; the directory is
//! listed through its own checked descriptor
//! (`protected_file::for_each_entry_beside`); a segment is opened relative
//! to it without following a link — read-only for the walk at start
//! (`protected_file::open`), for appending to the verified last segment
//! (`open_append`), and created exclusively, mode 0600, for a new one
//! (`create_new_append`). An existing segment must satisfy
//! [`segment_rule`]: a regular file, auditd's, with no permission at all for
//! group or others — the 0600 it creates (task R11c, Q-531 item 4). The
//! reads and writes happen after the privilege drop, so the owner is
//! auditd's uid (docs/50 §2.4: auditd "holds the audit file").
//!
//! Spec: docs/37 §2 (append-only, hash-chain); docs/50 §2.4, §6.4, §8.1;
//! docs/52 §3.13 (C13), §7 R11; docs/questions/Q-250 items 6, 8;
//! docs/questions/Q-265 item 2; Q-468 (A-102); Q-481 (A-104); Q-530.

use audit_log::{FileStorage, Storage};
use protected_file::{DataFileBreak, FileFacts, OpenError, PathBreak};
use std::fs::File;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

/// Digits of a segment number in its file name. Project choice: enough for
/// every `u64` (docs/questions/Q-265 item 2).
pub const SEGMENT_DIGITS: usize = 20;

/// The first segment's number.
pub const FIRST_SEGMENT: u64 = 1;

/// The path of segment `index` of the log based at `base`.
///
/// Spec: this module's naming rule (docs/questions/Q-265 item 2).
#[must_use]
pub fn segment_path(base: &Path, index: u64) -> PathBuf {
    let mut name = base.as_os_str().to_os_string();
    name.push(format!(".{index:0width$}", width = SEGMENT_DIGITS));
    PathBuf::from(name)
}

/// Why the segment listing was refused.
///
/// Spec: docs/37 §2 (a deleted segment is a break); docs/CLEAN-ROOM.md (fail
/// closed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListingError {
    /// `audit_log_path` has no parent directory or no file name.
    BadBasePath,
    /// A directory on the path to the log is a symbolic link or not a
    /// directory, is owned by neither root nor auditd's account, or is
    /// writable by group or others (crates/protected-file walk; task R11b).
    Directory(PathBreak),
    /// The directory could not be read.
    Io(io::ErrorKind),
    /// A file named like a segment is not one: a file at the base path, a
    /// name with the segment prefix but not 20 digits, segment number 0, or
    /// not a regular file.
    UnexpectedFile,
    /// The numbers are not `1 ..= n`: segment `expected` is missing.
    SegmentMissing {
        /// The first number not found.
        expected: u64,
    },
}

/// The segment numbers present for the log based at `base`, ascending and
/// checked to be exactly `1 ..= n` (empty when there is no segment yet).
/// The directory is reached through crates/protected-file's walk with
/// `owner_uid` (auditd's account) as the files' owner and listed through
/// its own checked descriptor; each entry's type is taken without following
/// a link.
///
/// # Errors
/// [`ListingError`].
///
/// Spec: this module's rules; docs/37 §2; docs/50 §7.5 ("auditd — opens the
/// file, verifies the hash chain"); docs/52 R11; Q-530.
pub fn list_segments(base: &Path, owner_uid: u32) -> Result<Vec<u64>, ListingError> {
    let file_name = base.file_name().ok_or(ListingError::BadBasePath)?;
    if base.parent().is_none() {
        return Err(ListingError::BadBasePath);
    }
    let file_name = file_name.as_bytes();
    let mut prefix = file_name.to_vec();
    prefix.push(b'.');

    let mut indexes = Vec::new();
    protected_file::for_each_entry_beside(base, owner_uid, |name, facts| {
        if name == file_name {
            return Err(ListingError::UnexpectedFile);
        }
        let Some(suffix) = name.strip_prefix(prefix.as_slice()) else {
            return Ok(());
        };
        let index = parse_index(suffix).ok_or(ListingError::UnexpectedFile)?;
        // The facts are the entry's own: a link named like a segment is
        // refused, not followed.
        if !facts.regular_file {
            return Err(ListingError::UnexpectedFile);
        }
        indexes.push(index);
        Ok(())
    })
    .map_err(|error| match error {
        OpenError::Io(kind) => ListingError::Io(kind),
        OpenError::Path(PathBreak::NoFileName) => ListingError::BadBasePath,
        OpenError::Path(path) => ListingError::Directory(path),
        OpenError::Refused(listing) => listing,
    })?;
    indexes.sort_unstable();
    let mut expected = FIRST_SEGMENT;
    for &index in &indexes {
        if index != expected {
            return Err(ListingError::SegmentMissing { expected });
        }
        expected = expected.saturating_add(1);
    }
    Ok(indexes)
}

/// The rule every existing segment file must satisfy when it is opened —
/// read at start or appended to: a regular file (a link's facts never
/// are), owned by auditd's account, **no** permission bit for group or
/// others — exactly the 0600 auditd creates (`create_new_append`). No reader
/// group exists in the design, so a group-readable segment is refused too
/// (fail closed; task R11c — before it, read access for a group was
/// admitted).
///
/// # Errors
/// The [`DataFileBreak`] of the first condition broken, in that order.
///
/// Spec: docs/50 §2.4, §6.4; docs/37 §2; docs/questions Q-531 item 4
/// (A-109: "no group/other access at all (mode & 0o077 == 0), matching the
/// 0600 it creates"); crates/protected-file `data_file_rule` (the one rule
/// for a daemon's data files, dird's store included).
pub fn segment_rule(facts: &FileFacts, owner_uid: u32) -> Result<(), DataFileBreak> {
    protected_file::data_file_rule(facts, owner_uid)
}

/// The segment number in a name suffix: exactly [`SEGMENT_DIGITS`] ASCII
/// digits, at least 1.
fn parse_index(suffix: &[u8]) -> Option<u64> {
    if suffix.len() != SEGMENT_DIGITS || !suffix.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let mut value: u64 = 0;
    for digit in suffix {
        value = value
            .checked_mul(10)?
            .checked_add(u64::from(digit.wrapping_sub(b'0')))?;
    }
    (value >= FIRST_SEGMENT).then_some(value)
}

/// Creates the storage of a new segment. The writer calls it for rotation;
/// tests substitute storage that records or fails.
///
/// Spec: docs/questions/Q-250 item 6 (the caller rotates); this module's
/// naming rule.
pub trait SegmentFactory {
    /// The storage of one segment.
    type Storage: Storage;

    /// Create segment `index`, which must not exist yet.
    ///
    /// # Errors
    /// Any I/O failure, including an existing file.
    fn create(&mut self, index: u64) -> io::Result<Self::Storage>;
}

/// Segment files next to `audit_log_path`, owned by auditd's account and
/// reached only through crates/protected-file (module documentation).
///
/// Spec: this module's naming rule and its R11b section; crates/audit-log
/// `FileStorage` (the caller opens the file); crates/protected-file
/// `create_new_append` (never reopens an existing file; mode 0600),
/// `open_append`, `open`.
#[derive(Debug, Clone)]
pub struct FileSegments {
    base: PathBuf,
    owner_uid: u32,
}

impl FileSegments {
    /// Segments of the log based at `base` (`audit_log_path`), owned by
    /// `owner_uid` (auditd's account).
    #[must_use]
    pub fn new(base: PathBuf, owner_uid: u32) -> FileSegments {
        FileSegments { base, owner_uid }
    }

    /// The base path.
    #[must_use]
    pub fn base(&self) -> &Path {
        &self.base
    }

    /// The path of segment `index`.
    #[must_use]
    pub fn path(&self, index: u64) -> PathBuf {
        segment_path(&self.base, index)
    }

    /// The owner of the segments and of the directories on their path
    /// (besides root): auditd's account.
    #[must_use]
    pub fn owner_uid(&self) -> u32 {
        self.owner_uid
    }

    /// Open existing segment `index` read-only, through the walk and under
    /// [`segment_rule`].
    ///
    /// # Errors
    /// crates/protected-file's [`OpenError`] with the [`DataFileBreak`].
    ///
    /// Spec: module documentation; crates/protected-file `open`.
    pub fn open_read(&self, index: u64) -> Result<File, OpenError<DataFileBreak>> {
        protected_file::open(&self.path(index), self.owner_uid, |facts| {
            segment_rule(facts, self.owner_uid)
        })
    }

    /// Open existing (verified) segment `index` for appending, through the
    /// walk and under [`segment_rule`].
    ///
    /// # Errors
    /// crates/protected-file's [`OpenError`] with the [`DataFileBreak`].
    ///
    /// Spec: module documentation; docs/50 §6.4 ("append write access to the
    /// audit file only"); crates/protected-file `open_append`.
    pub fn open_append(&self, index: u64) -> Result<FileStorage, OpenError<DataFileBreak>> {
        protected_file::open_append(&self.path(index), self.owner_uid, |facts| {
            segment_rule(facts, self.owner_uid)
        })
        .map(FileStorage::new)
    }

    /// Create segment `index`, which must not exist, for appending: through
    /// the walk, exclusively, mode 0600, under [`segment_rule`].
    ///
    /// # Errors
    /// crates/protected-file's [`OpenError`] with the [`DataFileBreak`] (an
    /// existing name is an [`OpenError::Io`]).
    ///
    /// Spec: module documentation; crates/protected-file
    /// `create_new_append`.
    pub fn create_segment(&self, index: u64) -> Result<FileStorage, OpenError<DataFileBreak>> {
        protected_file::create_new_append(&self.path(index), self.owner_uid, |facts| {
            segment_rule(facts, self.owner_uid)
        })
        .map(FileStorage::new)
    }
}

impl SegmentFactory for FileSegments {
    type Storage = FileStorage;

    /// [`FileSegments::create_segment`]; a refusal of the walk or of the
    /// rule is reported as `PermissionDenied` (the writer treats every
    /// failed rotation alike: nothing is acknowledged).
    fn create(&mut self, index: u64) -> io::Result<FileStorage> {
        self.create_segment(index).map_err(|error| match error {
            OpenError::Io(kind) => io::Error::from(kind),
            OpenError::Path(_) | OpenError::Refused(_) => {
                io::Error::from(io::ErrorKind::PermissionDenied)
            }
        })
    }
}
