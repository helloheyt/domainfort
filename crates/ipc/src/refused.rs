//! The shared `Refused` reply: the transport-level refusals every channel
//! may answer with.
//!
//! The channel-specific refusal codes (keyd's `AuthnError` / `IssueError` /
//! `Error`, carried exactly as keyd classifies them — A-26) belong to the
//! channel crates; this crate holds only the codes docs/50 names for the
//! transport itself.
//!
//! `Refused` travels with one reply kind reserved on **every** channel,
//! [`REFUSED_KIND`], so any client can read a transport refusal whatever its
//! channel's message set. No [`crate::MessageSet`] may list that kind in its
//! own table ([`kinds_exclude_refused`]); the envelope functions enforce this
//! at compile time.
//!
//! Spec: docs/50 §3.3 (errors row: "plus `Busy`, `Unavailable`"; version row:
//! "`Refused{VersionMismatch}`"; trailing row: "`Malformed`"), §3.6, §3.7,
//! §10 ("`ipc` … shared `Refused`"); A-59 (docs/questions/Q-225 item 2).

use crate::envelope::Payload;
use crate::error::Result;
use crate::reader::Reader;
use crate::writer::Writer;

/// The reply kind reserved, on every channel, for the shared [`Refused`]
/// reply. It belongs to no channel's message set.
///
/// Spec: A-59 ("one reply kind reserved for all channels — `REFUSED_KIND =
/// 0xFF`, enforced in ipc"; docs/questions/Q-225 item 2); docs/50 §3.3.
pub const REFUSED_KIND: u8 = 0xFF;

/// Whether a kind table leaves out [`REFUSED_KIND`].
///
/// [`crate::encode_frame`], [`crate::decode_body`] and the reply functions
/// assert this for their message set at compile time, so a set that lists the
/// reserved kind does not build once it is used with the envelope. A channel
/// crate can also assert it where it defines the set:
///
/// ```
/// # struct Replies;
/// # impl Replies { const KINDS: &'static [u8] = &[0x01, 0x02]; }
/// const _: () = assert!(ipc::kinds_exclude_refused(Replies::KINDS));
/// ```
///
/// Spec: A-59 (docs/questions/Q-225 item 2).
#[must_use]
pub const fn kinds_exclude_refused(kinds: &[u8]) -> bool {
    let mut rest = kinds;
    while let [first, tail @ ..] = rest {
        if *first == REFUSED_KIND {
            return false;
        }
        rest = tail;
    }
    true
}

/// A transport-level refusal. On the wire: one `u8` code from a closed table
/// (codes are a project choice).
///
/// Spec: docs/50 §3.3 ("enum = `u8` from a closed table"), §3.6, §3.7.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// The frame's version is not the exact version the server speaks; the
    /// connection closes after this reply (no negotiation).
    /// Spec: docs/50 §3.3; R50-4.
    VersionMismatch,
    /// The server's bounded queue is full; try again later.
    /// Spec: docs/50 §3.6 ("immediate `Busy` reply"); R50-7.
    Busy,
    /// The server (or a dependency it needs) is not available; never a
    /// disguised "wrong password".
    /// Spec: docs/50 §3.7; R50-8.
    Unavailable,
    /// The frame's payload is malformed (truncated, non-canonical, over a
    /// bound, or followed by octets); the connection closes after this reply.
    /// Spec: docs/50 §3.3 ("otherwise `Malformed` + close").
    Malformed,
}

impl Refused {
    /// Wire code of `VersionMismatch`. Project choice.
    const CODE_VERSION_MISMATCH: u8 = 0x01;
    /// Wire code of `Busy`. Project choice.
    const CODE_BUSY: u8 = 0x02;
    /// Wire code of `Unavailable`. Project choice.
    const CODE_UNAVAILABLE: u8 = 0x03;
    /// Wire code of `Malformed`. Project choice.
    const CODE_MALFORMED: u8 = 0x04;

    /// The wire code. Spec: docs/50 §3.3.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Refused::VersionMismatch => Self::CODE_VERSION_MISMATCH,
            Refused::Busy => Self::CODE_BUSY,
            Refused::Unavailable => Self::CODE_UNAVAILABLE,
            Refused::Malformed => Self::CODE_MALFORMED,
        }
    }

    /// The refusal for a wire code, or `None` outside the closed table.
    /// Spec: docs/50 §3.3.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Refused> {
        match code {
            Self::CODE_VERSION_MISMATCH => Some(Refused::VersionMismatch),
            Self::CODE_BUSY => Some(Refused::Busy),
            Self::CODE_UNAVAILABLE => Some(Refused::Unavailable),
            Self::CODE_MALFORMED => Some(Refused::Malformed),
            _ => None,
        }
    }
}

impl Payload for Refused {
    /// One field: `code: u8`. Spec: docs/50 §3.3.
    fn write_fields(&self, writer: &mut Writer) -> Result<()> {
        writer.write_enum(self.code())
    }

    /// One field: `code: u8` from the closed table. Spec: docs/50 §3.3.
    fn read_fields(reader: &mut Reader<'_>) -> Result<Refused> {
        reader.read_enum(Refused::from_code)
    }
}
