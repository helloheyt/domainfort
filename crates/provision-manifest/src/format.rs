//! The line format: from octets to the entries of the closed key table.
//!
//! The manifest uses the configuration format of docs/50 §7.1 (option A,
//! R50-15), and since task F7 (the A-86 follow-up) the **same parser**: the
//! public line layer of crates/config, [`config::line_format`] — one fuzzed
//! copy instead of two (docs/questions/Q-345 item 2). Its grammar:
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
//! refused by the line layer; a missing key is refused here when it is asked
//! for. This module maps the line layer's errors onto the manifest's
//! [`Error`] rule for rule (same line, same key, same rule).
//!
//! Spec: docs/50 R50-15, §7.1 ("unknown / duplicate / missing-required key ⇒
//! refuse"; "printable ASCII only"; "file ≤ 64 KiB, line ≤ 1024"; and its
//! D96 citation: the same strict parser discipline for every
//! deserialization); PENDING-OWNER P-6 (ASCII only), A-86; AGENTS.md §6.

use crate::error::{Error, ErrorKind};
use config::line_format::{Entries, LineError, LineErrorKind};

/// Printable ASCII — the line layer's rule. Spec: docs/50 §7.1; P-6.
pub(crate) use config::line_format::is_printable;

/// The entries of one manifest, each key of the table at most once.
/// Spec: docs/50 §7.1.
#[derive(Debug)]
pub(crate) struct Document<'a> {
    entries: Entries<'a>,
}

/// The manifest rule a line-format rule is. One to one: every line rule is
/// a manifest rule of the same name (docs/50 §7.1).
const fn kind_of(kind: LineErrorKind) -> ErrorKind {
    match kind {
        LineErrorKind::FileTooLarge => ErrorKind::FileTooLarge,
        LineErrorKind::TooManyLines => ErrorKind::TooManyLines,
        LineErrorKind::LineTooLong => ErrorKind::LineTooLong,
        LineErrorKind::InvalidCharacter => ErrorKind::InvalidCharacter,
        LineErrorKind::MissingFinalNewline => ErrorKind::MissingFinalNewline,
        LineErrorKind::MalformedLine => ErrorKind::MalformedLine,
        LineErrorKind::KeyTooLong => ErrorKind::KeyTooLong,
        LineErrorKind::ValueTooLong => ErrorKind::ValueTooLong,
        LineErrorKind::UnknownKey => ErrorKind::UnknownKey,
        LineErrorKind::DuplicateKey => ErrorKind::DuplicateKey,
    }
}

/// The manifest error a line-format error is: the same line, key and rule.
/// Spec: docs/50 §7.1; A-60 (no input text either way).
fn error_of(error: LineError) -> Error {
    let kind = kind_of(error.kind());
    match (error.line(), error.key()) {
        (Some(line), Some(key)) => Error::at(line, key, kind),
        (Some(line), None) => Error::at_line(line, kind),
        // The line layer reports a key only together with its line.
        (None, _) => Error::whole(kind),
    }
}

impl<'a> Document<'a> {
    /// Split `input` into lines, check every format rule, and keep the
    /// entries; each key must be in `keys` and appear at most once.
    ///
    /// Spec: docs/50 R50-15, §7.1.
    pub(crate) fn parse(input: &'a [u8], keys: &[&'static str]) -> Result<Self, Error> {
        Entries::parse(input, keys)
            .map(|entries| Document { entries })
            .map_err(error_of)
    }

    /// The value of the optional `key`, parsed by `parse`, with its line, or
    /// `None` when the key is absent; a parse failure is reported at the
    /// key's line, naming the key.
    /// Spec: docs/50 §7.1.
    pub(crate) fn optional<T>(
        &self,
        key: &'static str,
        parse: impl FnOnce(&'a str) -> Result<T, ErrorKind>,
    ) -> Result<Option<(T, u32)>, Error> {
        match self.entries.find(key) {
            None => Ok(None),
            Some(entry) => parse(entry.value())
                .map(|value| Some((value, entry.line())))
                .map_err(|kind| Error::at(entry.line(), key, kind)),
        }
    }

    /// The value of the required `key`, parsed by `parse`, with its line; a
    /// parse failure is reported at the key's line, naming the key.
    /// Spec: docs/50 §7.1 ("missing-required ⇒ refuse").
    pub(crate) fn required<T>(
        &self,
        key: &'static str,
        parse: impl FnOnce(&'a str) -> Result<T, ErrorKind>,
    ) -> Result<(T, u32), Error> {
        let entry = self.entries.find(key).ok_or(Error::missing(key))?;
        parse(entry.value())
            .map(|value| (value, entry.line()))
            .map_err(|kind| Error::at(entry.line(), key, kind))
    }
}
