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
//! Spec: docs/37 §2 (append-only, hash-chain); docs/50 §2.4, §6.4, §8.1;
//! docs/questions/Q-250 items 6, 8; docs/questions/Q-265 item 2.

use audit_log::{FileStorage, Storage};
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
/// Spec: docs/37 §2 (a deleted segment is a break); AGENTS.md §6 (fail
/// closed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListingError {
    /// `audit_log_path` has no parent directory or no file name.
    BadBasePath,
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
///
/// # Errors
/// [`ListingError`].
///
/// Spec: this module's rules; docs/37 §2; docs/50 §7.5 ("auditd — opens the
/// file, verifies the hash chain").
pub fn list_segments(base: &Path) -> Result<Vec<u64>, ListingError> {
    let directory = base.parent().ok_or(ListingError::BadBasePath)?;
    let file_name = base.file_name().ok_or(ListingError::BadBasePath)?;
    let mut prefix = file_name.as_bytes().to_vec();
    prefix.push(b'.');

    let entries = std::fs::read_dir(directory).map_err(|e| ListingError::Io(e.kind()))?;
    let mut indexes = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| ListingError::Io(e.kind()))?;
        let name = entry.file_name();
        let name = name.as_bytes();
        if name == file_name.as_bytes() {
            return Err(ListingError::UnexpectedFile);
        }
        let Some(suffix) = name.strip_prefix(prefix.as_slice()) else {
            continue;
        };
        let index = parse_index(suffix).ok_or(ListingError::UnexpectedFile)?;
        // `DirEntry::file_type` does not follow a symbolic link: a link named
        // like a segment is refused, not followed.
        let file_type = entry.file_type().map_err(|e| ListingError::Io(e.kind()))?;
        if !file_type.is_file() {
            return Err(ListingError::UnexpectedFile);
        }
        indexes.push(index);
    }
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

/// Segment files next to `audit_log_path`.
///
/// Spec: this module's naming rule; crates/audit-log `FileStorage`
/// (`create_new`: never reopens an existing file; mode 0600).
#[derive(Debug, Clone)]
pub struct FileSegments {
    base: PathBuf,
}

impl FileSegments {
    /// Segments of the log based at `base` (`audit_log_path`).
    #[must_use]
    pub fn new(base: PathBuf) -> FileSegments {
        FileSegments { base }
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
}

impl SegmentFactory for FileSegments {
    type Storage = FileStorage;

    fn create(&mut self, index: u64) -> io::Result<FileStorage> {
        FileStorage::create_new(&self.path(index))
    }
}
