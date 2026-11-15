//! The schemas' view of one file: the entries of [`crate::line_format`] for a
//! daemon's closed key table, with the per-key typed accessors and this
//! crate's [`Error`].
//!
//! The line rules themselves (the grammar, the bounds, unknown and repeated
//! keys) are in the public module [`crate::line_format`], the one copy the
//! provisioning manifest shares (A-86 follow-up); this module only maps its
//! [`LineError`] onto [`Error`] rule for rule and adds what a schema needs:
//! a required key ("missing-required ⇒ do not start") and a typed value
//! reported at its line.
//!
//! Spec: docs/50 R50-15, §7.1; docs/21 area 4 (D96: "config deserialization —
//! the same strict parser discipline"); docs/CLEAN-ROOM.md

use crate::error::{Error, ErrorKind};
use crate::line_format::{Entries, LineError, LineErrorKind};

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
    entries: Entries<'a>,
}

/// The configuration rule a line-format rule is. One to one: every line rule
/// is a configuration rule of the same name (docs/50 §7.1).
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

/// The configuration error a line-format error is: the same line, key and
/// rule. Spec: docs/50 §7.1; A-60 (no input text either way).
fn error_of(error: LineError) -> Error {
    let kind = kind_of(error.kind());
    match (error.line(), error.key()) {
        (Some(line), Some(key)) => Error::at(line, key, kind),
        (Some(line), None) => Error::at_line(line, kind),
        // The line layer reports a key only together with its line.
        (None, _) => Error::file(kind),
    }
}

impl<'a> Document<'a> {
    /// Splits `input` into lines and keeps the entries, checking every format
    /// rule and that each key is in `keys` exactly once at most.
    ///
    /// Spec: docs/50 R50-15, §7.1.
    pub(crate) fn parse(input: &'a [u8], keys: &[&'static str]) -> Result<Self, Error> {
        Entries::parse(input, keys)
            .map(|entries| Document { entries })
            .map_err(error_of)
    }

    /// The value of an optional key, parsed by `parse`; a parse failure is
    /// reported at the key's line.
    pub(crate) fn optional<T>(
        &self,
        key: &'static str,
        parse: impl FnOnce(&'a str) -> Result<T, ErrorKind>,
    ) -> Result<Option<Located<T>>, Error> {
        let Some(entry) = self.entries.find(key) else {
            return Ok(None);
        };
        match parse(entry.value()) {
            Ok(value) => Ok(Some(Located {
                value,
                line: entry.line(),
            })),
            Err(kind) => Err(Error::at(entry.line(), key, kind)),
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
