//! Error type for the IPC codec.
//!
//! Hand-rolled, no dependency (AGENTS.md §7). Every variant names one rule the
//! decoder enforces (or the encoder's matching representability rule). Fail
//! closed: a malformed frame is always a distinct `Err`, never a panic and
//! never a silent repair (AGENTS.md §6; docs/50 §3.3).
//!
//! Security: no variant carries octets of the frame — only which rule failed
//! — so nothing secret (a `SetSecret` password, a key-bearing value) can reach
//! an error, a log line or a panic message (AGENTS.md §6; docs/50 §8.2: "IPC
//! errors carry a code, not content").

use crate::refused::Refused;
use core::fmt;

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// A framing, envelope, field-decoding or encoding failure.
///
/// Disposition (docs/50 §3.3): every error ends the connection. Before closing,
/// a server answers some of them with the shared [`Refused`] reply — see
/// [`Error::refusal`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    // ---- framing ------------------------------------------------------------
    /// The declared body length is smaller than the body header (zero
    /// included), so no envelope can follow. Checked at the length prefix.
    /// Spec: docs/50 §3.3 ("0 or > MAX ⇒ close"); docs/questions/Q-225 item 1.
    FrameTooShort,

    /// The declared body length exceeds the channel's bound for this
    /// direction. Checked at the length prefix, before any body octet is
    /// allocated or awaited.
    /// Spec: docs/50 §3.3 ("bound before allocation"); R50-4.
    FrameTooLarge,

    // ---- envelope -----------------------------------------------------------
    /// The body's `magic` is not this channel's.
    /// Spec: docs/50 §3.3 ("`magic` per channel … mismatch ⇒ close").
    WrongMagic,

    /// The body's `version` is not exactly the version this build speaks.
    /// There is no negotiation and no fallback.
    /// Spec: docs/50 §3.3 ("exact version … no negotiation and no fallback");
    /// R50-4.
    VersionMismatch,

    /// The body's `kind` is not in the closed kind table of this channel and
    /// direction (or, when encoding, a message reported a kind outside its own
    /// table).
    /// Spec: docs/50 §3.3 ("`kind` closed: unknown op ⇒ close"); R50-4.
    UnknownKind,

    // ---- fields -------------------------------------------------------------
    /// The payload ended before a complete field.
    /// Spec: docs/50 §3.3 (fixed-order fields, each of a defined width).
    Truncated,

    /// Octets remain after the last field of the payload.
    /// Spec: docs/50 §3.3 ("no trailing byte: after the last field — the end of
    /// the body; otherwise `Malformed` + close"); R50-4.
    TrailingBytes,

    /// A boolean octet other than `00` or `01`.
    /// Spec: docs/50 §3.3 ("`bool` = `00`/`01` only").
    InvalidBoolean,

    /// An optional-field marker other than `00` (absent) or `01` (present).
    /// Spec: docs/50 §3.3 ("`Option<T>` = `00` | `01 T`").
    InvalidOptionMarker,

    /// A byte-string length above the field's bound (or, when encoding, a
    /// value longer than the bound or than a u32 can state).
    /// Spec: docs/50 §3.3 ("`bytes<max>` = `u32` length ≤ max + octets").
    LengthOverBound,

    /// A sequence count above the field's bound (or, when encoding, more items
    /// than the bound or than a u32 can state).
    /// Spec: docs/50 §3.3 ("`seq<T,max>` = `u32` count ≤ max + items").
    CountOverBound,

    /// An enumeration code outside the field's closed table.
    /// Spec: docs/50 §3.3 ("enum = `u8` from a closed table").
    UnknownCode,

    /// Optional and sequence fields nested deeper than
    /// [`crate::MAX_NESTING`].
    /// Spec: AGENTS.md §6 (recursion-depth limits); docs/questions/Q-225 item 5.
    NestingTooDeep,

    // ---- encoding -----------------------------------------------------------
    /// Encoding would produce a body longer than the channel's bound for this
    /// direction, which the peer would refuse.
    /// Spec: docs/50 §3.3 ("a bound per channel and per direction"; "replies
    /// are decoded with the same strictness").
    BodyOverBound,
}

impl Error {
    /// The shared [`Refused`] reply a server sends before closing, if any.
    ///
    /// * [`Error::VersionMismatch`] → [`Refused::VersionMismatch`]
    ///   (docs/50 §3.3: "`Refused{VersionMismatch}` + close").
    /// * Payload errors (truncation, trailing octets, a non-canonical marker,
    ///   an over-bound length or count, an unknown code, too-deep nesting) →
    ///   [`Refused::Malformed`] (docs/50 §3.3: "`Malformed` + close";
    ///   docs/questions/Q-225 item 3).
    /// * A bad length prefix, a wrong magic or an unknown kind → `None`:
    ///   close without a reply (docs/50 §3.3: "⇒ close").
    /// * Encoding errors → `None` (they are local, not the peer's).
    #[must_use]
    pub const fn refusal(self) -> Option<Refused> {
        match self {
            Error::VersionMismatch => Some(Refused::VersionMismatch),
            Error::Truncated
            | Error::TrailingBytes
            | Error::InvalidBoolean
            | Error::InvalidOptionMarker
            | Error::LengthOverBound
            | Error::CountOverBound
            | Error::UnknownCode
            | Error::NestingTooDeep => Some(Refused::Malformed),
            Error::FrameTooShort
            | Error::FrameTooLarge
            | Error::WrongMagic
            | Error::UnknownKind
            | Error::BodyOverBound => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Error::FrameTooShort => "declared frame body too short for the envelope",
            Error::FrameTooLarge => "declared frame body over the channel bound",
            Error::WrongMagic => "frame magic is not this channel's",
            Error::VersionMismatch => "frame version is not the exact version spoken",
            Error::UnknownKind => "frame kind outside the closed kind table",
            Error::Truncated => "payload ended before a complete field",
            Error::TrailingBytes => "octets remain after the last field",
            Error::InvalidBoolean => "boolean octet other than 00 or 01",
            Error::InvalidOptionMarker => "optional marker other than 00 or 01",
            Error::LengthOverBound => "byte string length over the field bound",
            Error::CountOverBound => "sequence count over the field bound",
            Error::UnknownCode => "enumeration code outside the closed table",
            Error::NestingTooDeep => "optional or sequence fields nested too deep",
            Error::BodyOverBound => "encoded body would exceed the channel bound",
        };
        f.write_str(text)
    }
}

impl std::error::Error for Error {}
