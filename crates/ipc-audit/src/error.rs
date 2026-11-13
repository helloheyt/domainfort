//! Errors of the event encoding. No variant carries event octets
//! (AGENTS.md §6; docs/50 §8.2).

use core::fmt;

/// Why an event could not be encoded or decoded.
///
/// Spec: docs/50 §3.3 (strict decoding, one encoding per value), §8.2 (no
/// content in errors).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventError {
    /// A field primitive was refused: truncated, trailing octets, a marker
    /// other than `00`/`01`, a length or count over its bound, a code
    /// outside its closed table, or an event over
    /// [`crate::MAX_EVENT_OCTETS`].
    Codec(ipc::Error),
    /// The event's format version is not [`crate::EVENT_FORMAT`].
    UnsupportedFormat,
    /// A text field holds an octet outside printable ASCII.
    InvalidText,
    /// A calendar-time field is out of range.
    InvalidTime,
}

impl From<ipc::Error> for EventError {
    fn from(error: ipc::Error) -> EventError {
        EventError::Codec(error)
    }
}

impl fmt::Display for EventError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EventError::Codec(error) => write!(f, "audit event field refused: {error}"),
            EventError::UnsupportedFormat => f.write_str("audit event format not supported"),
            EventError::InvalidText => f.write_str("audit event text is not printable ASCII"),
            EventError::InvalidTime => f.write_str("audit event time field out of range"),
        }
    }
}

impl std::error::Error for EventError {}
