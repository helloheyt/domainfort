//! The line format: from file octets to the entries of one closed key table.
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
//! nothing else, and the per-key parser decides whether they are acceptable.
//!
//! Spec: docs/50 R50-15, §7.1; docs/21 area 4 (D96: "config deserialization —
//! the same strict parser discipline"); AGENTS.md §6.

use crate::error::{Error, ErrorKind};
use crate::limits::{
    MAX_FILE_OCTETS, MAX_KEY_OCTETS, MAX_LINES, MAX_LINE_OCTETS, MAX_VALUE_OCTETS, SEPARATOR,
};

/// The line terminator. Spec: docs/50 §7.1 (line-based format).
const LF: u8 = b'\n';

/// The comment marker, valid only in the first column. Spec: docs/50 §7.1
/// ("`#` for a comment").
const COMMENT: u8 = b'#';

/// One `key = value` entry whose key is in the table.
#[derive(Debug, Clone, Copy)]
struct Entry<'a> {
    line: u32,
    key: &'static str,
    value: &'a str,
}

/// A value together with the line it came from, for cross-setting checks.
#[derive(Debug, Clone)]
pub(crate) struct Located<T> {
    pub(crate) value: T,
    pub(crate) line: u32,
}

/// The entries of one file, checked against one daemon's closed key table:
/// every key known, none repeated.
#[derive(Debug)]
pub(crate) struct Document<'a> {
    entries: Vec<Entry<'a>>,
}

/// Whether `b` is printable ASCII. Spec: docs/50 §7.1 ("printable ASCII
/// only").
const fn is_printable(b: u8) -> bool {
    matches!(b, 0x20..=0x7E)
}

/// The key alphabet: lower-case letters, digits, underscore.
/// Spec: docs/50 R50-15; docs/questions/Q-230 item 2.
const fn is_key_octet(b: u8) -> bool {
    b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'
}

impl<'a> Document<'a> {
    /// Splits `input` into lines and keeps the entries, checking every format
    /// rule and that each key is in `keys` exactly once at most.
    ///
    /// Spec: docs/50 R50-15, §7.1.
    pub(crate) fn parse(input: &'a [u8], keys: &[&'static str]) -> Result<Self, Error> {
        if input.len() > MAX_FILE_OCTETS {
            return Err(Error::file(ErrorKind::FileTooLarge));
        }
        let mut entries: Vec<Entry<'a>> = Vec::new();
        let mut rest = input;
        let mut number: u32 = 0;
        while !rest.is_empty() {
            number = number.saturating_add(1);
            if usize::try_from(number).map_or(true, |n| n > MAX_LINES) {
                return Err(Error::at_line(number, ErrorKind::TooManyLines));
            }
            let (line, terminated, after) = match rest.iter().position(|&b| b == LF) {
                Some(end) => (
                    rest.get(..end).unwrap_or_default(),
                    true,
                    rest.get(end + 1..).unwrap_or_default(),
                ),
                None => (rest, false, &[][..]),
            };
            rest = after;
            if line.len() > MAX_LINE_OCTETS {
                return Err(Error::at_line(number, ErrorKind::LineTooLong));
            }
            if !line.iter().all(|&b| is_printable(b)) {
                return Err(Error::at_line(number, ErrorKind::InvalidCharacter));
            }
            if !terminated {
                return Err(Error::at_line(number, ErrorKind::MissingFinalNewline));
            }
            // Printable ASCII is UTF-8; the check cannot fail, but is not
            // unwrapped (AGENTS.md §6).
            let Ok(text) = core::str::from_utf8(line) else {
                return Err(Error::at_line(number, ErrorKind::InvalidCharacter));
            };
            if text.is_empty() || text.as_bytes().first() == Some(&COMMENT) {
                continue;
            }
            let entry = Self::entry(number, text, keys)?;
            if entries.iter().any(|seen| seen.key == entry.key) {
                return Err(Error::at(number, entry.key, ErrorKind::DuplicateKey));
            }
            entries.push(entry);
        }
        Ok(Document { entries })
    }

    /// Parses one non-empty, non-comment line as `key = value`.
    /// Spec: docs/50 R50-15, §7.1.
    fn entry(number: u32, text: &'a str, keys: &[&'static str]) -> Result<Entry<'a>, Error> {
        let key_len = text.bytes().take_while(|&b| is_key_octet(b)).count();
        let (key, after_key) = text.split_at_checked(key_len).unwrap_or((text, ""));
        if !key.bytes().next().is_some_and(|b| b.is_ascii_lowercase()) {
            return Err(Error::at_line(number, ErrorKind::MalformedLine));
        }
        let Some(value) = after_key.strip_prefix(SEPARATOR) else {
            return Err(Error::at_line(number, ErrorKind::MalformedLine));
        };
        if key.len() > MAX_KEY_OCTETS {
            return Err(Error::at_line(number, ErrorKind::KeyTooLong));
        }
        let Some(&known) = keys.iter().find(|k| **k == key) else {
            return Err(Error::at_line(number, ErrorKind::UnknownKey));
        };
        let surrounded = value.starts_with(' ') || value.ends_with(' ');
        if value.is_empty() || surrounded {
            return Err(Error::at(number, known, ErrorKind::MalformedLine));
        }
        if value.len() > MAX_VALUE_OCTETS {
            return Err(Error::at(number, known, ErrorKind::ValueTooLong));
        }
        Ok(Entry {
            line: number,
            key: known,
            value,
        })
    }

    /// The entry for `key`, if present.
    fn find(&self, key: &str) -> Option<&Entry<'a>> {
        self.entries.iter().find(|e| e.key == key)
    }

    /// The value of an optional key, parsed by `parse`; a parse failure is
    /// reported at the key's line.
    pub(crate) fn optional<T>(
        &self,
        key: &'static str,
        parse: impl FnOnce(&'a str) -> Result<T, ErrorKind>,
    ) -> Result<Option<Located<T>>, Error> {
        let Some(entry) = self.find(key) else {
            return Ok(None);
        };
        match parse(entry.value) {
            Ok(value) => Ok(Some(Located {
                value,
                line: entry.line,
            })),
            Err(kind) => Err(Error::at(entry.line, key, kind)),
        }
    }

    /// The value of a required key. Spec: docs/50 §7.1 ("missing-required ⇒
    /// do not start").
    pub(crate) fn required<T>(
        &self,
        key: &'static str,
        parse: impl FnOnce(&'a str) -> Result<T, ErrorKind>,
    ) -> Result<Located<T>, Error> {
        self.optional(key, parse)?.ok_or(Error::missing(key))
    }
}
