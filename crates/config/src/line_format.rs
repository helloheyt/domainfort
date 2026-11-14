//! The docs/50 §7.1 line format, at the line level: from file octets to the
//! `key = value` entries of one closed key table.
//!
//! ```text
//! file    = *( line LF )                 ; every line ends with LF (§7.1)
//! line    = empty / comment / entry
//! empty   = ""                           ; no spaces
//! comment = "#" *pchar                   ; "#" in the first column only
//! entry   = key " = " value
//! key     = lower *( lower / digit / "_" )   ; at most MAX_KEY_OCTETS
//! value   = vchar [ *pchar vchar ]       ; no leading/trailing space
//! pchar   = %x20-7E                      ; printable ASCII (§7.1)
//! vchar   = %x21-7E
//! ```
//!
//! Each line form has exactly one spelling, so two files with the same meaning
//! differ only in comments, empty lines and key order. There are no section
//! headers (one file per daemon, §7.1), no quoting, no escapes, no includes and
//! no interpolation: a value is the octets between the separator and the LF,
//! nothing else, and the per-key parser of the caller decides whether they are
//! acceptable. Unknown and repeated keys are refused here; a missing key is the
//! caller's rule (it knows which keys are required).
//!
//! This is the one copy of the line layer (A-86 follow-up, task F7): this
//! crate's daemon schemas use it, and so does crates/provision-manifest for
//! the provisioning manifest, which is written in the same format
//! (docs/questions/Q-345 item 2, Q-375 items 1 and 6). It is public so that a
//! second copy is never needed; it holds no schema, so [`Entries::parse`]
//! never refuses a value for its content, only for its shape.
//!
//! Every bound is a constant of [`crate::limits`] and is checked before the
//! octets it covers are copied anywhere; [`Entries::parse`] borrows its values
//! from the input and allocates one small record per entry (at most
//! [`crate::limits::MAX_LINES`]). An error carries a line number, a key of
//! the caller's table (a `&'static str`, never text from the input) and the
//! rule — never an octet of the input (AGENTS.md §6; A-60).
//!
//! Spec: docs/50 R50-15, §7.1; docs/21 area 4 (D96: "config deserialization —
//! the same strict parser discipline"); AGENTS.md §6; PENDING-OWNER A-86.

use crate::limits::{
    MAX_FILE_OCTETS, MAX_KEY_OCTETS, MAX_LINES, MAX_LINE_OCTETS, MAX_VALUE_OCTETS, SEPARATOR,
};
use core::fmt;

/// The line terminator. Spec: docs/50 §7.1 (line-based format).
pub const LF: u8 = b'\n';

/// The comment marker, valid only in the first column. Spec: docs/50 §7.1
/// ("`#` for a comment").
pub const COMMENT: u8 = b'#';

/// Whether `b` is printable ASCII (0x20..=0x7E). Spec: docs/50 §7.1
/// ("printable ASCII only"); PENDING-OWNER P-6.
#[must_use]
pub const fn is_printable(b: u8) -> bool {
    matches!(b, 0x20..=0x7E)
}

/// The key alphabet: lower-case letters, digits, underscore.
/// Spec: docs/50 R50-15; docs/questions/Q-230 item 2.
const fn is_key_octet(b: u8) -> bool {
    b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'
}

/// Which rule of the line format a file broke.
///
/// Exhaustive on purpose: a caller maps every rule onto its own error type,
/// and a new rule must not slip through a wildcard arm.
/// Spec: docs/50 R50-15, §7.1; AGENTS.md §6.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineErrorKind {
    /// The file is larger than [`crate::limits::MAX_FILE_OCTETS`].
    /// Spec: docs/50 §7.1 ("file ≤ 64 KiB").
    FileTooLarge,
    /// The file has more than [`crate::limits::MAX_LINES`] lines.
    /// Spec: AGENTS.md §6 (bounded parsers); docs/questions/Q-230.
    TooManyLines,
    /// A line (without its LF) is longer than
    /// [`crate::limits::MAX_LINE_OCTETS`]. Spec: docs/50 §7.1 ("line ≤ 1024").
    LineTooLong,
    /// An octet outside printable ASCII other than the LF terminator.
    /// Spec: docs/50 §7.1 ("printable ASCII only").
    InvalidCharacter,
    /// The file does not end with LF (a cut last line).
    /// Spec: docs/50 §7.1 (fail closed); AGENTS.md §6.
    MissingFinalNewline,
    /// A line that is neither empty, nor a `#` comment in its first column,
    /// nor exactly `key = value`. Spec: docs/50 R50-15, §7.1.
    MalformedLine,
    /// A key longer than [`crate::limits::MAX_KEY_OCTETS`].
    /// Spec: AGENTS.md §6; docs/questions/Q-230.
    KeyTooLong,
    /// A value longer than [`crate::limits::MAX_VALUE_OCTETS`].
    /// Spec: AGENTS.md §6; docs/questions/Q-230.
    ValueTooLong,
    /// A key that is not in the caller's closed key table.
    /// Spec: docs/50 R50-15 ("a closed key table"), §7.1.
    UnknownKey,
    /// A key that appears a second time. Spec: docs/50 §7.1 ("duplicate … ⇒
    /// do not start").
    DuplicateKey,
}

/// A line-format rejection: where (a line, or the whole file), which key of
/// the caller's table (when known), and which rule. Never input text.
/// Spec: docs/50 R50-15, §7.1; AGENTS.md §6; A-60.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LineError {
    line: Option<u32>,
    key: Option<&'static str>,
    kind: LineErrorKind,
}

impl LineError {
    /// An error about the whole file.
    const fn file(kind: LineErrorKind) -> LineError {
        LineError {
            line: None,
            key: None,
            kind,
        }
    }

    /// An error at a line, with no known key.
    const fn at_line(line: u32, kind: LineErrorKind) -> LineError {
        LineError {
            line: Some(line),
            key: None,
            kind,
        }
    }

    /// An error at a line about a key of the caller's table.
    const fn at(line: u32, key: &'static str, kind: LineErrorKind) -> LineError {
        LineError {
            line: Some(line),
            key: Some(key),
            kind,
        }
    }

    /// The 1-based line number; `None` for an error about the whole file.
    #[must_use]
    pub const fn line(&self) -> Option<u32> {
        self.line
    }

    /// The key involved, when known — always a name from the caller's
    /// table, never input text.
    #[must_use]
    pub const fn key(&self) -> Option<&'static str> {
        self.key
    }

    /// The rule that failed.
    #[must_use]
    pub const fn kind(&self) -> LineErrorKind {
        self.kind
    }
}

impl fmt::Display for LineErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            LineErrorKind::FileTooLarge => "file exceeds the size bound",
            LineErrorKind::TooManyLines => "file exceeds the line-count bound",
            LineErrorKind::LineTooLong => "line exceeds the length bound",
            LineErrorKind::InvalidCharacter => "octet outside printable ASCII",
            LineErrorKind::MissingFinalNewline => "last line is not terminated by LF",
            LineErrorKind::MalformedLine => "line is not empty, a comment, or `key = value`",
            LineErrorKind::KeyTooLong => "key exceeds the length bound",
            LineErrorKind::ValueTooLong => "value exceeds the length bound",
            LineErrorKind::UnknownKey => "key is not in the key table",
            LineErrorKind::DuplicateKey => "key appears more than once",
        })
    }
}

impl fmt::Display for LineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("line format")?;
        if let Some(line) = self.line {
            write!(f, " line {line}")?;
        }
        if let Some(key) = self.key {
            write!(f, " key `{key}`")?;
        }
        write!(f, ": {}", self.kind)
    }
}

impl std::error::Error for LineError {}

/// One `key = value` entry whose key is in the caller's table.
/// Spec: docs/50 R50-15.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry<'a> {
    line: u32,
    key: &'static str,
    value: &'a str,
}

impl<'a> Entry<'a> {
    /// The 1-based line the entry is on.
    #[must_use]
    pub const fn line(&self) -> u32 {
        self.line
    }

    /// The key — the caller's own `&'static str` from its table.
    #[must_use]
    pub const fn key(&self) -> &'static str {
        self.key
    }

    /// The value: printable ASCII, non-empty, no leading or trailing space,
    /// at most [`crate::limits::MAX_VALUE_OCTETS`] octets; not yet typed.
    #[must_use]
    pub const fn value(&self) -> &'a str {
        self.value
    }
}

/// The entries of one file, checked against one closed key table: every key
/// known, none repeated, in file order.
/// Spec: docs/50 R50-15, §7.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entries<'a> {
    entries: Vec<Entry<'a>>,
}

impl<'a> Entries<'a> {
    /// Splits `input` into lines and keeps the entries, checking every format
    /// rule and that each key is in `keys` and appears at most once. The
    /// rules are checked in this order: the file bound; then for each line in
    /// turn the line-count bound, the line bound, printable ASCII, the final
    /// LF, the entry's shape, the key bound, the key table, the value's
    /// shape, the value bound, and no repetition.
    ///
    /// # Errors
    /// [`LineError`] — the first rule broken.
    ///
    /// Spec: docs/50 R50-15, §7.1.
    pub fn parse(input: &'a [u8], keys: &[&'static str]) -> Result<Self, LineError> {
        if input.len() > MAX_FILE_OCTETS {
            return Err(LineError::file(LineErrorKind::FileTooLarge));
        }
        let mut entries: Vec<Entry<'a>> = Vec::new();
        let mut rest = input;
        let mut number: u32 = 0;
        while !rest.is_empty() {
            number = number.saturating_add(1);
            if usize::try_from(number).map_or(true, |n| n > MAX_LINES) {
                return Err(LineError::at_line(number, LineErrorKind::TooManyLines));
            }
            let (line, terminated, after) = match rest.iter().position(|&b| b == LF) {
                Some(end) => (
                    rest.get(..end).unwrap_or_default(),
                    true,
                    rest.get(end.saturating_add(1)..).unwrap_or_default(),
                ),
                None => (rest, false, &[][..]),
            };
            rest = after;
            if line.len() > MAX_LINE_OCTETS {
                return Err(LineError::at_line(number, LineErrorKind::LineTooLong));
            }
            if !line.iter().all(|&b| is_printable(b)) {
                return Err(LineError::at_line(number, LineErrorKind::InvalidCharacter));
            }
            if !terminated {
                return Err(LineError::at_line(
                    number,
                    LineErrorKind::MissingFinalNewline,
                ));
            }
            // Printable ASCII is UTF-8; the check cannot fail, but is not
            // unwrapped (AGENTS.md §6).
            let Ok(text) = core::str::from_utf8(line) else {
                return Err(LineError::at_line(number, LineErrorKind::InvalidCharacter));
            };
            if text.is_empty() || text.as_bytes().first() == Some(&COMMENT) {
                continue;
            }
            let entry = Self::entry(number, text, keys)?;
            if entries.iter().any(|seen| seen.key == entry.key) {
                return Err(LineError::at(
                    number,
                    entry.key,
                    LineErrorKind::DuplicateKey,
                ));
            }
            entries.push(entry);
        }
        Ok(Entries { entries })
    }

    /// Parses one non-empty, non-comment line as `key = value`.
    /// Spec: docs/50 R50-15, §7.1.
    fn entry(number: u32, text: &'a str, keys: &[&'static str]) -> Result<Entry<'a>, LineError> {
        let key_len = text.bytes().take_while(|&b| is_key_octet(b)).count();
        let (key, after_key) = text.split_at_checked(key_len).unwrap_or((text, ""));
        if !key.bytes().next().is_some_and(|b| b.is_ascii_lowercase()) {
            return Err(LineError::at_line(number, LineErrorKind::MalformedLine));
        }
        let Some(value) = after_key.strip_prefix(SEPARATOR) else {
            return Err(LineError::at_line(number, LineErrorKind::MalformedLine));
        };
        if key.len() > MAX_KEY_OCTETS {
            return Err(LineError::at_line(number, LineErrorKind::KeyTooLong));
        }
        let Some(&known) = keys.iter().find(|k| **k == key) else {
            return Err(LineError::at_line(number, LineErrorKind::UnknownKey));
        };
        let surrounded = value.starts_with(' ') || value.ends_with(' ');
        if value.is_empty() || surrounded {
            return Err(LineError::at(number, known, LineErrorKind::MalformedLine));
        }
        if value.len() > MAX_VALUE_OCTETS {
            return Err(LineError::at(number, known, LineErrorKind::ValueTooLong));
        }
        Ok(Entry {
            line: number,
            key: known,
            value,
        })
    }

    /// The entry for `key`, if present.
    #[must_use]
    pub fn find(&self, key: &str) -> Option<&Entry<'a>> {
        self.entries.iter().find(|e| e.key == key)
    }

    /// The entries, in file order.
    pub fn iter(&self) -> impl Iterator<Item = &Entry<'a>> {
        self.entries.iter()
    }

    /// How many entries the file has.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the file has no entry (only comments and empty lines).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}
