//! Errors of the manifest parser, builder and file reader.
//!
//! Hand-rolled, zero-dependency (AGENTS.md §7). **No echo**: an [`Error`]
//! carries only a line number, the name of a manifest key (a
//! `&'static str` from the closed key table, never text from the input) and
//! the rule that failed — never a value or any other octet of the file, as
//! crates/config does (A-60: "an error never shows the value that was
//! written"; docs/50 §8.2).

use core::fmt;

/// Which rule a manifest broke.
///
/// Spec: docs/50 R50-15, §7.1 (the line format); docs/51 §4.3 step 8 (the
/// manifest); AGENTS.md §6 (strict, bounded parsers).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorKind {
    // ---- file and line structure (docs/50 §7.1) ----------------------------
    /// The input is larger than [`crate::limits::MAX_FILE_OCTETS`].
    FileTooLarge,
    /// More than [`crate::limits::MAX_LINES`] lines.
    TooManyLines,
    /// A line longer than [`crate::limits::MAX_LINE_OCTETS`].
    LineTooLong,
    /// An octet outside printable ASCII other than the LF terminator (a
    /// control character, TAB, CR, or any octet of a non-ASCII sequence).
    /// Spec: docs/50 §7.1; PENDING-OWNER P-6 (ASCII only).
    InvalidCharacter,
    /// The input does not end with LF (a cut last line).
    MissingFinalNewline,
    /// A line that is neither empty, nor a `#` comment in the first column,
    /// nor exactly `key = value`.
    MalformedLine,
    /// A key longer than [`crate::limits::MAX_KEY_OCTETS`].
    KeyTooLong,
    /// A value longer than [`crate::limits::MAX_VALUE_OCTETS`].
    ValueTooLong,

    // ---- the closed key table ----------------------------------------------
    /// The key is not in the manifest's closed key table.
    UnknownKey,
    /// The key appears a second time.
    DuplicateKey,
    /// A required key is absent (every manifest key is required).
    MissingKey,

    // ---- typed values ------------------------------------------------------
    /// `manifest_version` is not the one version this crate reads.
    UnsupportedVersion,
    /// Not an upper-case realm of `A-Z 0-9 . -`, at most
    /// [`crate::limits::MAX_DNS_NAME_OCTETS`] octets.
    InvalidRealm,
    /// Not a domain SID `S-1-5-21-<n>-<n>-<n>` in canonical form.
    InvalidDomainSid,
    /// Not a naming context `dc=<label>,…,dc=<label>`.
    InvalidNamingContext,
    /// The realm is not the naming context's DNS name in upper case.
    RealmMismatch,
    /// Not a lower-case DNS host name.
    InvalidHostName,
    /// Not a GUID in the lower-case `8-4-4-4-12` hexadecimal form.
    InvalidGuid,
    /// The NULL GUID (all zero), which no object has.
    NullGuid,
    /// A GUID used for two objects.
    DuplicateGuid,
    /// An object entry that is not `<guid>:<binding>`.
    InvalidObjectEntry,
    /// A binding other than the one the manifest's realm and DC name fix
    /// for that object.
    BindingMismatch,
    /// A sAMAccountName that breaks a rule of [MS-SAMR] 3.1.1.6 or of the
    /// manifest's list syntax.
    InvalidAccountName,
    /// The sAMAccountName `krbtgt`, which belongs to the krbtgt account.
    ReservedAccountName,
    /// Two first administrators with the same sAMAccountName (ASCII case
    /// folded).
    DuplicateAccountName,
    /// A list whose items are not separated by exactly `", "`.
    InvalidList,
    /// Fewer first administrators than [`crate::limits::MIN_FIRST_ADMINS`].
    TooFewFirstAdmins,
    /// More first administrators than [`crate::limits::MAX_FIRST_ADMINS`].
    TooManyFirstAdmins,
    /// A `first_admin_salts` item that is not a KerberosString, or a salt
    /// list whose count is not the number of first administrators (A-102).
    InvalidSalt,
}

impl ErrorKind {
    /// A fixed description of the rule. Never contains input text.
    const fn describe(self) -> &'static str {
        match self {
            ErrorKind::FileTooLarge => "manifest exceeds the size bound",
            ErrorKind::TooManyLines => "manifest exceeds the line-count bound",
            ErrorKind::LineTooLong => "line exceeds the length bound",
            ErrorKind::InvalidCharacter => "octet outside printable ASCII",
            ErrorKind::MissingFinalNewline => "last line is not terminated by LF",
            ErrorKind::MalformedLine => "line is not empty, a comment, or `key = value`",
            ErrorKind::KeyTooLong => "key exceeds the length bound",
            ErrorKind::ValueTooLong => "value exceeds the length bound",
            ErrorKind::UnknownKey => "key is not in the manifest's key table",
            ErrorKind::DuplicateKey => "key appears more than once",
            ErrorKind::MissingKey => "required key is missing",
            ErrorKind::UnsupportedVersion => "unsupported manifest version",
            ErrorKind::InvalidRealm => "value is not an upper-case realm name",
            ErrorKind::InvalidDomainSid => "value is not a canonical domain SID",
            ErrorKind::InvalidNamingContext => "value is not a `dc=` naming context",
            ErrorKind::RealmMismatch => "realm is not the naming context's DNS name in upper case",
            ErrorKind::InvalidHostName => "value is not a lower-case DNS host name",
            ErrorKind::InvalidGuid => "value is not a lower-case 8-4-4-4-12 GUID",
            ErrorKind::NullGuid => "the NULL GUID is not an object's GUID",
            ErrorKind::DuplicateGuid => "GUID is used for more than one object",
            ErrorKind::InvalidObjectEntry => "object entry is not `<guid>:<binding>`",
            ErrorKind::BindingMismatch => "binding is not the one fixed for this object",
            ErrorKind::InvalidAccountName => "value is not an acceptable sAMAccountName",
            ErrorKind::ReservedAccountName => "sAMAccountName is reserved for the krbtgt account",
            ErrorKind::DuplicateAccountName => "sAMAccountName appears more than once",
            ErrorKind::InvalidList => "list items must be non-empty and separated by \", \"",
            ErrorKind::TooFewFirstAdmins => "fewer first administrators than required",
            ErrorKind::TooManyFirstAdmins => "more first administrators than allowed",
            ErrorKind::InvalidSalt => {
                "first-administrator salts do not match the first administrators"
            }
        }
    }
}

/// A manifest rejection: where, which key, and which rule.
///
/// Spec: docs/50 §7.1; AGENTS.md §6 (no secrets — and here no input at all —
/// in errors).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error {
    line: Option<u32>,
    key: Option<&'static str>,
    kind: ErrorKind,
}

impl Error {
    /// An error about the whole input.
    pub(crate) const fn whole(kind: ErrorKind) -> Error {
        Error {
            line: None,
            key: None,
            kind,
        }
    }

    /// An error at a line, with no known key.
    pub(crate) const fn at_line(line: u32, kind: ErrorKind) -> Error {
        Error {
            line: Some(line),
            key: None,
            kind,
        }
    }

    /// An error at a line about a manifest key.
    pub(crate) const fn at(line: u32, key: &'static str, kind: ErrorKind) -> Error {
        Error {
            line: Some(line),
            key: Some(key),
            kind,
        }
    }

    /// A required key that is absent.
    pub(crate) const fn missing(key: &'static str) -> Error {
        Error::field(key, ErrorKind::MissingKey)
    }

    /// An error about a manifest key with no line (a builder field).
    pub(crate) const fn field(key: &'static str, kind: ErrorKind) -> Error {
        Error {
            line: None,
            key: Some(key),
            kind,
        }
    }

    /// The 1-based line number, when the error belongs to one line.
    #[must_use]
    pub const fn line(&self) -> Option<u32> {
        self.line
    }

    /// The manifest key involved, when known — always a name from the
    /// closed key table, never input text.
    #[must_use]
    pub const fn key(&self) -> Option<&'static str> {
        self.key
    }

    /// The rule that failed.
    #[must_use]
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.describe())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("manifest")?;
        if let Some(line) = self.line {
            write!(f, " line {line}")?;
        }
        if let Some(key) = self.key {
            write!(f, " key `{key}`")?;
        }
        write!(f, ": {}", self.kind.describe())
    }
}

impl std::error::Error for Error {}

/// Why a manifest file was not accepted.
///
/// Spec: docs/51 §4.3 step 8 (the manifest is root:0644); docs/50 §7.1 (the
/// same rule as a configuration file: owned by root, not writable by group
/// or others); AGENTS.md §6 (fail closed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadError {
    /// The file could not be opened, inspected or read.
    Unreadable,
    /// The path does not name a regular file.
    NotRegularFile,
    /// The file is not owned by root (uid 0).
    NotRootOwned,
    /// The file is writable by its group or by others.
    WritableByOthers,
    /// The file is larger than [`crate::limits::MAX_FILE_OCTETS`]; it was
    /// not read beyond the bound.
    TooLarge,
    /// The content was refused.
    Manifest(Error),
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReadError::Unreadable => f.write_str("manifest file unreadable"),
            ReadError::NotRegularFile => f.write_str("manifest path is not a regular file"),
            ReadError::NotRootOwned => f.write_str("manifest file is not owned by root"),
            ReadError::WritableByOthers => {
                f.write_str("manifest file is writable by its group or by others")
            }
            ReadError::TooLarge => f.write_str("manifest file exceeds the size bound"),
            ReadError::Manifest(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for ReadError {}
