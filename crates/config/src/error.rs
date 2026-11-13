//! Error type of the configuration parser.
//!
//! Hand-rolled, zero-dependency (AGENTS.md §7). Every [`ErrorKind`] names one
//! rule the parser enforces. Fail closed: any rejection means the daemon does
//! not start (docs/50 §7.1: "unknown / duplicate / missing-required key ⇒ do
//! not start"; §7.5: "every daemon exits with an error code on any start-up
//! failure").
//!
//! **No echo.** An [`Error`] carries only the line number, the name of the
//! schema key involved (a `&'static str` from the daemon's closed key table,
//! never text from the input) and the rule that failed. It never carries the
//! offending value or any other octet of the file: a value written in the wrong
//! place could be sensitive by mistake, and secrets never reach error messages
//! (AGENTS.md §6; docs/50 §8.2: "IPC errors carry a code, not content").

use core::fmt;

/// Which rule a configuration file broke.
///
/// Spec: docs/50 R50-15, §7.1 (the format and its rules); AGENTS.md §6
/// (strict, bounded parsers).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorKind {
    // ---- file and line structure -------------------------------------------
    /// The file is larger than [`crate::limits::MAX_FILE_OCTETS`].
    /// Spec: docs/50 §7.1 ("file ≤ 64 KiB").
    FileTooLarge,
    /// The file has more than [`crate::limits::MAX_LINES`] lines.
    /// Spec: AGENTS.md §6 (bounded parsers); project choice (limits).
    TooManyLines,
    /// A line (without its LF) is longer than
    /// [`crate::limits::MAX_LINE_OCTETS`]. Spec: docs/50 §7.1 ("line ≤ 1024").
    LineTooLong,
    /// An octet outside printable ASCII (0x20..=0x7E) other than the LF line
    /// terminator: a control character, TAB, CR, or any octet of a non-ASCII
    /// (or non-UTF-8) sequence. Spec: docs/50 §7.1 ("printable ASCII only").
    InvalidCharacter,
    /// The file does not end with LF: its last line is cut (for example a torn
    /// write), so its value cannot be trusted to be complete.
    /// Spec: docs/50 §7.1 (fail closed); AGENTS.md §6.
    MissingFinalNewline,
    /// A line that is neither empty, nor a comment starting with `#` in its
    /// first column, nor exactly `key = value` (a key at the start of the line,
    /// one space, `=`, one space, a value with no surrounding space). Section
    /// headers, indentation and trailing spaces all land here.
    /// Spec: docs/50 R50-15 ("`key = value` lines"), §7.1.
    MalformedLine,
    /// A key is longer than [`crate::limits::MAX_KEY_OCTETS`].
    /// Spec: AGENTS.md §6 (bounds); project choice (limits).
    KeyTooLong,
    /// A value is longer than [`crate::limits::MAX_VALUE_OCTETS`].
    /// Spec: AGENTS.md §6 (bounds); project choice (limits).
    ValueTooLong,

    // ---- the closed key table ----------------------------------------------
    /// The key is not in this daemon's closed key table.
    /// Spec: docs/50 R50-15 ("a closed key table per daemon"), §7.1.
    UnknownKey,
    /// The key appears a second time. Spec: docs/50 §7.1 ("duplicate … ⇒ do
    /// not start").
    DuplicateKey,
    /// A required key is absent. Spec: docs/50 §7.1 ("missing-required ⇒ do
    /// not start").
    MissingKey,
    /// One of two keys that only make sense together is present without the
    /// other (the [`Error::key`] names the present one).
    /// Spec: docs/50 §7.1 (fail closed); docs/questions/Q-230 item 11.
    IncompletePair,

    // ---- typed values ------------------------------------------------------
    /// Not a canonical unsigned decimal integer (digits only, no sign, no
    /// leading zero, fits the type). Spec: docs/50 §7.1 ("every value typed").
    InvalidInteger,
    /// An integer or duration outside the documented range of its setting.
    /// Spec: docs/50 §7.1 ("integer in range"); docs/questions/Q-230 item 4.
    OutOfRange,
    /// Not a duration `<seconds>s`. Spec: docs/50 §7.1 ("a duration with a
    /// unit"); docs/questions/Q-230 item 13.
    InvalidDuration,
    /// An account id (uid or gid) that is never accepted: 0 (root, "uid 0 is
    /// never mapped") or the all-ones value.
    /// Spec: docs/50 R50-3, §3.2; docs/questions/Q-230 item 6.
    ReservedId,
    /// Not a canonical absolute path (it must start with `/`; components from
    /// `A-Z a-z 0-9 . _ -`, never empty, `.` or `..`; no trailing `/`). An
    /// environment reference such as `$HOME/x` lands here: it is rejected,
    /// never expanded. Spec: docs/50 §7.1 ("absolute path"; "no override from
    /// the environment").
    InvalidPath,
    /// Not a realm name in the accepted character set (`A-Z a-z 0-9 . -`).
    /// Spec: docs/50 §7.1 ("realm"); docs/questions/Q-230 item 15.
    InvalidRealm,
    /// Not a DNS host name in the accepted form (labels of `A-Z a-z 0-9 -`
    /// separated by single dots, at most 255 octets).
    /// Spec: [MS-ADTS] 3.1.1.3.2.4 (dNSHostName); docs/questions/Q-280
    /// item 6.
    InvalidHostName,
    /// Not a naming context of the form `dc=<label>,…,dc=<label>`.
    /// Spec: docs/50 §7.1 ("naming context (A-53)"); docs/questions/Q-230
    /// item 15.
    InvalidNamingContext,
    /// Not a socket address in canonical form, with a non-zero port and no
    /// IPv6 flow information or scope.
    /// Spec: docs/50 §7.1 ("listen addresses"), §4.1; docs/questions/Q-230
    /// item 7.
    InvalidSocketAddress,
    /// A listener address that names no single interface: the unspecified
    /// address, a multicast address or the IPv4 broadcast address.
    /// Spec: docs/50 §4.1 ("bind to internal interfaces only"); docs/questions/
    /// Q-230 item 7.
    NotAnInterfaceAddress,
    /// Not a network `<address>/<prefix>` in canonical form.
    /// Spec: docs/50 §7.1 ("CIDR"), §4.1 ("CIDR → IpScope::Internal").
    InvalidNetwork,
    /// A network address with bits set past its prefix length.
    /// Spec: docs/50 §7.1 (CIDR; one encoding per value); docs/questions/Q-230
    /// item 8.
    NetworkHostBits,
    /// A network with prefix length 0: it would make every source address
    /// `Internal`. Spec: docs/50 §4.1; docs/questions/Q-230 item 8.
    NetworkTooBroad,
    /// A list whose items are not separated by exactly `", "`, or that has an
    /// empty item. Spec: docs/50 §7.1; docs/questions/Q-230 item 14.
    InvalidList,
    /// A list with more than [`crate::limits::MAX_LIST_ITEMS`] items.
    /// Spec: AGENTS.md §6 (bounds); project choice (limits).
    TooManyItems,
    /// A map entry that is not `<uid>:<name>`.
    /// Spec: docs/50 §3.2 (static `uid → Role` map); docs/questions/Q-230
    /// item 5.
    InvalidMapEntry,
    /// A name outside the fixed list of its setting (a role name, an audit
    /// source name, a key-store kind).
    /// Spec: docs/50 §3.2, §8.1, §7.3 (R50-18).
    UnknownName,
    /// The same item appears twice in one list or map (a role named for two
    /// uids, an address listed twice, a network listed twice).
    /// Spec: docs/50 §3.2 ("one Role per uid"); docs/questions/Q-230 item 5.
    DuplicateEntry,
    /// The same uid appears twice in the file — twice in a map ("a uid that
    /// appears twice ⇒ keyd does not start") or under two settings.
    /// Spec: docs/50 §3.2, §2.4 (one account per process); docs/questions/
    /// Q-230 item 6.
    DuplicateId,
    /// The same path is given to two settings of one file.
    /// Spec: docs/50 §3.1 ("a socket per (server, channel)"); docs/questions/
    /// Q-230 item 16.
    DuplicatePath,
    /// The daemon would have no network listener at all.
    /// Spec: docs/50 §4.2; docs/questions/Q-230 item 7.
    NoListener,
    /// Two limits contradict each other (a per-source bound above the global
    /// bound). Spec: docs/50 §4.1.
    InconsistentLimits,
}

impl ErrorKind {
    /// A fixed description of the rule. Never contains input text.
    fn describe(self) -> &'static str {
        match self {
            ErrorKind::FileTooLarge => "file exceeds the size bound",
            ErrorKind::TooManyLines => "file exceeds the line-count bound",
            ErrorKind::LineTooLong => "line exceeds the length bound",
            ErrorKind::InvalidCharacter => "octet outside printable ASCII",
            ErrorKind::MissingFinalNewline => "last line is not terminated by LF",
            ErrorKind::MalformedLine => "line is not empty, a comment, or `key = value`",
            ErrorKind::KeyTooLong => "key exceeds the length bound",
            ErrorKind::ValueTooLong => "value exceeds the length bound",
            ErrorKind::UnknownKey => "key is not in this daemon's key table",
            ErrorKind::DuplicateKey => "key appears more than once",
            ErrorKind::MissingKey => "required key is missing",
            ErrorKind::IncompletePair => "key requires its companion key",
            ErrorKind::InvalidInteger => "value is not a canonical unsigned integer",
            ErrorKind::OutOfRange => "value is outside the allowed range",
            ErrorKind::InvalidDuration => "value is not a duration in seconds (`<n>s`)",
            ErrorKind::ReservedId => "account id 0 or all-ones is never accepted",
            ErrorKind::InvalidPath => "value is not a canonical absolute path",
            ErrorKind::InvalidRealm => "value is not an acceptable realm name",
            ErrorKind::InvalidHostName => "value is not an acceptable DNS host name",
            ErrorKind::InvalidNamingContext => "value is not a `dc=` naming context",
            ErrorKind::InvalidSocketAddress => "value is not a canonical socket address",
            ErrorKind::NotAnInterfaceAddress => "listener address names no single interface",
            ErrorKind::InvalidNetwork => "value is not a canonical network address/prefix",
            ErrorKind::NetworkHostBits => "network has bits set past its prefix",
            ErrorKind::NetworkTooBroad => "network prefix length 0 is not accepted",
            ErrorKind::InvalidList => "list items must be non-empty and separated by \", \"",
            ErrorKind::TooManyItems => "list exceeds the item-count bound",
            ErrorKind::InvalidMapEntry => "map entry is not `<uid>:<name>`",
            ErrorKind::UnknownName => "name is not in the fixed list for this setting",
            ErrorKind::DuplicateEntry => "item appears more than once",
            ErrorKind::DuplicateId => "uid appears more than once in this file",
            ErrorKind::DuplicatePath => "path is used by more than one setting",
            ErrorKind::NoListener => "no network listener is configured",
            ErrorKind::InconsistentLimits => "per-source limit exceeds the global limit",
        }
    }
}

/// A configuration rejection: where, which setting, and which rule.
///
/// Spec: docs/50 R50-15, §7.1; AGENTS.md §6 (no secrets in errors).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error {
    line: Option<u32>,
    key: Option<&'static str>,
    kind: ErrorKind,
}

impl Error {
    /// An error about the whole file (no single line).
    pub(crate) const fn file(kind: ErrorKind) -> Error {
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

    /// An error at a line about a schema key.
    pub(crate) const fn at(line: u32, key: &'static str, kind: ErrorKind) -> Error {
        Error {
            line: Some(line),
            key: Some(key),
            kind,
        }
    }

    /// A required key that is absent.
    pub(crate) const fn missing(key: &'static str) -> Error {
        Error {
            line: None,
            key: Some(key),
            kind: ErrorKind::MissingKey,
        }
    }

    /// The 1-based line number, when the error belongs to one line.
    #[must_use]
    pub const fn line(&self) -> Option<u32> {
        self.line
    }

    /// The schema key involved, when known. Always a name from the daemon's
    /// own key table — never text from the input.
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
        f.write_str("configuration")?;
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
