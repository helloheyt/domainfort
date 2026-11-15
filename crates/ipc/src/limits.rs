//! Named bounds of the IPC codec, and the validated per-direction body bound.
//!
//! Every bound a decoder enforces is either one of these constants or a value
//! the caller passes in (a [`FrameLimit`] per channel and direction, a `max`
//! per byte string or sequence field). Spec: docs/50 §3.3, R50-4; docs/CLEAN-ROOM.md
//! (parsers are strict and bounded).

/// Octets of the frame length prefix: `length:u32`, big-endian.
///
/// Spec: docs/50 §3.3 ("`Frame := length:u32 (big-endian) ‖ body[length]`").
pub const LENGTH_PREFIX_LEN: usize = 4;

/// Octets of the body header that precedes every payload:
/// `magic:u16 ‖ version:u8 ‖ kind:u8`.
///
/// A declared body length below this cannot carry an envelope and is refused
/// at the length prefix, before any body octet is awaited.
///
/// Spec: docs/50 §3.3 ("body := magic:u16 ‖ version:u8 ‖ kind:u8 ‖ payload";
/// "0 or > MAX ⇒ close"); docs/questions/Q-225 item 1.
pub const BODY_HEADER_LEN: usize = 4;

/// [`BODY_HEADER_LEN`] as the wire integer type of the length prefix.
const BODY_HEADER_LEN_WIRE: u32 = 4;

/// Smallest per-direction body bound a [`FrameLimit`] may have: the envelope
/// plus one octet — enough for the shared `Refused` reply
/// (`magic ‖ version ‖ REFUSED_KIND ‖ code`), so every channel can always
/// send it. A body of exactly the envelope (no fields) still fits any bound.
///
/// Spec: docs/50 §3.3 (the shared `Refused{code}` reply); A-59 (one reserved
/// reply kind on every channel, docs/questions/Q-225 item 2).
pub const MIN_BODY_LIMIT: u32 = BODY_HEADER_LEN_WIRE + 1;

/// Ceiling on any channel's per-direction body bound: 8 MiB.
///
/// The largest bound docs/50 §3.3 names for anything that crosses an IPC
/// channel is the LDAP engine's `MAX_RESPONSE_OCTETS` (8 MiB, the total of one
/// response); no single frame may exceed it. A [`FrameLimit`] above this
/// ceiling cannot be constructed, so a misconfigured channel fails at build
/// time rather than accepting an oversized frame.
///
/// Spec: docs/50 §3.3 (frame bounds, "⚠ to be estimated"); project choice,
/// docs/questions/Q-225 item 4.
pub const MAX_BODY_CEILING: u32 = 8 * 1024 * 1024;

/// Deepest nesting of optional and sequence fields inside one payload.
///
/// The messages of docs/50 §3.4 nest at most two levels (an optional group
/// inside a request, a sequence inside a reply); the limit leaves headroom and
/// stops a recursive payload type from turning attacker-chosen depth into
/// stack depth. The [`crate::Reader`] and the [`crate::Writer`] apply the same
/// limit, so nothing encodable is undecodable.
///
/// Spec: docs/CLEAN-ROOM.md (recursion-depth limits); docs/50 §3.3; project choice,
/// docs/questions/Q-225 item 5.
pub const MAX_NESTING: usize = 8;

// Every length on the wire is a u32 and is converted to usize for slicing; the
// conversion is lossless only where usize has at least 32 bits. A compile-time
// check (not a runtime panic) keeps the crate off narrower targets.
const _: () = assert!(usize::BITS >= 32);

/// Lossless u32 → usize conversion (see the compile-time check above).
pub(crate) const fn to_usize(value: u32) -> usize {
    value as usize
}

/// A validated bound on the frame body length for one direction of one
/// channel.
///
/// The decoder compares the declared `length` with this bound **before** any
/// body octet is allocated or awaited; the encoder refuses to produce a body
/// longer than it. A value is always at least [`MIN_BODY_LIMIT`] and at most
/// [`MAX_BODY_CEILING`].
///
/// Spec: docs/50 §3.3 ("`length` is checked against the MAX of (channel,
/// direction) before any body byte is allocated or read"); R50-4 ("a bound per
/// channel and per direction").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameLimit(u32);

impl FrameLimit {
    /// Build a bound of `max_body` octets per frame body.
    ///
    /// `None` when `max_body` is below [`MIN_BODY_LIMIT`] (the shared
    /// `Refused` reply would not fit) or above [`MAX_BODY_CEILING`].
    ///
    /// Spec: docs/50 §3.3; docs/questions/Q-225 items 2 and 4 (A-59).
    #[must_use]
    pub const fn new(max_body: u32) -> Option<FrameLimit> {
        if max_body < MIN_BODY_LIMIT || max_body > MAX_BODY_CEILING {
            None
        } else {
            Some(FrameLimit(max_body))
        }
    }

    /// The bound, in octets of frame body.
    #[must_use]
    pub const fn max_body(self) -> u32 {
        self.0
    }

    /// The bound as a slice length.
    pub(crate) const fn max_body_len(self) -> usize {
        to_usize(self.0)
    }

    /// Whether a declared body length is too short to carry the envelope.
    /// Spec: docs/50 §3.3; docs/questions/Q-225 item 1.
    pub(crate) const fn is_below_header(declared: u32) -> bool {
        declared < BODY_HEADER_LEN_WIRE
    }
}
