//! The line format: from octets to the entries of the closed key table.
//!
//! The manifest uses the configuration format of docs/50 §7.1 (option A,
//! R50-15), with the same strictness as crates/config:
//!
//! ```text
//! file    = *( line LF )                 ; every line ends with LF
//! line    = empty / comment / entry
//! empty   = ""                           ; no spaces
//! comment = "#" *pchar                   ; "#" in the first column only
//! entry   = key " = " value
//! key     = lower *( lower / digit / "_" )
//! value   = vchar [ *pchar vchar ]       ; no leading/trailing space
//! pchar   = %x20-7E                      ; printable ASCII
//! vchar   = %x21-7E
//! ```
//!
//! Every line form has exactly one spelling; there are no section headers,
//! quotes, escapes, includes or interpolation. Unknown and repeated keys are
//! refused here; a missing key is refused when it is asked for.
//!
//! Spec: docs/50 R50-15, §7.1 ("unknown / duplicate / missing-required key ⇒
//! refuse"; "printable ASCII only"; "file ≤ 64 KiB, line ≤ 1024"; and its
//! D96 citation: the same strict parser discipline for every
//! deserialization); PENDING-OWNER P-6 (ASCII only); AGENTS.md §6.

use crate::error::{Error, ErrorKind};
use crate::limits::{
    MAX_FILE_OCTETS, MAX_KEY_OCTETS, MAX_LINES, MAX_LINE_OCTETS, MAX_VALUE_OCTETS, SEPARATOR,
};

/// The line terminator. Spec: docs/50 §7.1.
pub(crate) const LF: u8 = b'\n';

/// The comment marker, valid only in the first column. Spec: docs/50 §7.1.
pub(crate) const COMMENT: u8 = b'#';

/// One `key = value` entry whose key is in the table.
#[derive(Debug, Clone, Copy)]
struct Entry<'a> {
    line: u32,
    key: &'static str,
    value: &'a str,
}

/// The entries of one manifest, each key of the table at most once.
/// Spec: docs/50 §7.1.
#[derive(Debug)]
pub(crate) struct Document<'a> {
    entries: Vec<Entry<'a>>,
}

/// Printable ASCII. Spec: docs/50 §7.1; P-6.
pub(crate) const fn is_printable(b: u8) -> bool {
    matches!(b, 0x20..=0x7E)
}

/// The key alphabet: lower-case letters, digits, underscore.
/// Spec: docs/50 R50-15.
const fn is_key_octet(b: u8) -> bool {
    b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'
}

impl<'a> Document<'a> {
    /// Split `input` into lines, check every format rule, and keep the
    /// entries; each key must be in `keys` and appear at most once.
    ///
    /// Spec: docs/50 R50-15, §7.1.
    pub(crate) fn parse(input: &'a [u8], keys: &[&'static str]) -> Result<Self, Error> {
        if input.len() > MAX_FILE_OCTETS {
            return Err(Error::whole(ErrorKind::FileTooLarge));
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
                    rest.get(end.saturating_add(1)..).unwrap_or_default(),
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
            // Printable ASCII is UTF-8; the conversion cannot fail, but is
            // not unwrapped (AGENTS.md §6).
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

    /// One non-empty, non-comment line as `key = value`.
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
        if value.is_empty() || value.starts_with(' ') || value.ends_with(' ') {
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

    /// The value of the required `key`, parsed by `parse`, with its line; a
    /// parse failure is reported at the key's line, naming the key.
    /// Spec: docs/50 §7.1 ("missing-required ⇒ refuse").
    pub(crate) fn required<T>(
        &self,
        key: &'static str,
        parse: impl FnOnce(&'a str) -> Result<T, ErrorKind>,
    ) -> Result<(T, u32), Error> {
        let entry = self
            .entries
            .iter()
            .find(|e| e.key == key)
            .ok_or(Error::missing(key))?;
        parse(entry.value)
            .map(|value| (value, entry.line))
            .map_err(|kind| Error::at(entry.line, key, kind))
    }
}
