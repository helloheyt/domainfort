//! Stream framing: cut one frame from a Unix stream socket's byte stream.
//!
//! `Frame := length:u32 (big-endian) ‖ body[length]` (docs/50 §3.3). The
//! declared length is compared with the caller's per-channel, per-direction
//! [`FrameLimit`] as soon as the four prefix octets are present — **before**
//! any body octet is allocated or awaited — and a length too short to hold
//! the envelope is refused at the same point.
//!
//! Two forms:
//! * [`decode_frame`] is stateless: given a buffer, it reports a complete
//!   frame, "need more", or an error. It allocates nothing.
//! * [`FrameReader`] accumulates a stream into one frame at a time. It
//!   allocates the body buffer once, at the declared (already checked) size,
//!   and wipes it when the frame is released (docs/50 §3.3: "the frame buffer
//!   is zeroized after decoding, in both sides").

use crate::error::{Error, Result};
use crate::limits::{to_usize, FrameLimit, LENGTH_PREFIX_LEN};
use core::fmt;
use zeroize::Zeroizing;

/// Check a declared body length against the envelope minimum and the bound.
///
/// Spec: docs/50 §3.3 ("`length` is checked against the MAX of (channel,
/// direction) **before** any body byte is allocated or read; 0 or > MAX ⇒
/// close"); R50-4; docs/questions/Q-225 item 1.
fn check_declared_length(declared: u32, limit: FrameLimit) -> Result<usize> {
    if FrameLimit::is_below_header(declared) {
        return Err(Error::FrameTooShort);
    }
    if declared > limit.max_body() {
        return Err(Error::FrameTooLarge);
    }
    Ok(to_usize(declared))
}

/// What [`decode_frame`] found at the start of a buffer.
///
/// `Debug` shows lengths only: a body may carry a secret (docs/50 §8.2).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FrameStatus<'a> {
    /// One whole frame occupies the first `frame_len` octets of the buffer;
    /// `body` is its body (the envelope and payload, without the prefix).
    Complete {
        /// The frame body: `magic ‖ version ‖ kind ‖ payload`.
        body: &'a [u8],
        /// Octets of the whole frame, prefix included; the next frame (if
        /// any) starts here.
        frame_len: usize,
    },
    /// The buffer holds only the start of a frame (possibly nothing). Once
    /// the prefix has arrived and passed the checks, `frame_len` is the total
    /// number of octets the frame occupies.
    NeedMore {
        /// Octets of the whole frame, prefix included, when known.
        frame_len: Option<usize>,
    },
}

impl fmt::Debug for FrameStatus<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FrameStatus::Complete { body, frame_len } => f
                .debug_struct("Complete")
                .field("body_len", &body.len())
                .field("frame_len", frame_len)
                .finish(),
            FrameStatus::NeedMore { frame_len } => f
                .debug_struct("NeedMore")
                .field("frame_len", frame_len)
                .finish(),
        }
    }
}

/// Locate the first frame in `buffer`, bounded by `limit`.
///
/// An error is final for the connection (docs/50 §3.3: "⇒ close"). Octets
/// after a complete frame are left to the caller: on a channel with one
/// request in flight (R50-7) the caller reads the next frame only after it
/// has replied.
///
/// Spec: docs/50 §3.3; R50-4; R50-7.
pub fn decode_frame(buffer: &[u8], limit: FrameLimit) -> Result<FrameStatus<'_>> {
    let Some((prefix, rest)) = buffer.split_first_chunk::<LENGTH_PREFIX_LEN>() else {
        return Ok(FrameStatus::NeedMore { frame_len: None });
    };
    let body_len = check_declared_length(u32::from_be_bytes(*prefix), limit)?;
    // Cannot overflow: body_len ≤ MAX_BODY_CEILING (8 MiB).
    let frame_len = LENGTH_PREFIX_LEN + body_len;
    Ok(match rest.get(..body_len) {
        Some(body) => FrameStatus::Complete { body, frame_len },
        None => FrameStatus::NeedMore {
            frame_len: Some(frame_len),
        },
    })
}

/// Where a [`FrameReader`] stands.
#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    /// Collecting the length prefix; this many prefix octets are in.
    Prefix { filled: usize },
    /// Collecting a body of this declared (checked) length.
    Body { len: usize },
    /// The stream broke a framing rule; it stays broken.
    Failed(Error),
}

/// Accumulates a byte stream into one frame at a time.
///
/// Feed received octets with [`FrameReader::push`]; ask
/// [`FrameReader::wanted`] how many more the current frame needs (reading at
/// most that many from the socket never pulls in the next frame). When
/// [`FrameReader::body`] returns the body, decode it, then call
/// [`FrameReader::reset`], which wipes it.
///
/// * The body buffer is allocated once, at the declared length, only after
///   that length has passed [`FrameLimit`]; it never grows, so it never
///   leaves a copy behind, and it is zeroizing.
/// * A framing error is sticky: every later call reports it again, and
///   [`FrameReader::reset`] does not clear it — the connection is closed
///   (docs/50 §3.3; docs/CLEAN-ROOM.md: fail closed).
/// * `Debug` shows lengths only.
///
/// Spec: docs/50 §3.3 (bound before allocation; frame buffer zeroized after
/// decoding); R50-4; R50-7.
pub struct FrameReader {
    limit: FrameLimit,
    prefix: [u8; LENGTH_PREFIX_LEN],
    state: State,
    body: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for FrameReader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FrameReader")
            .field("limit", &self.limit)
            .field("body_len", &self.body.len())
            .field("wanted", &self.wanted())
            .finish()
    }
}

impl FrameReader {
    /// A reader for frames whose bodies are bounded by `limit`.
    /// Spec: docs/50 §3.3.
    #[must_use]
    pub fn new(limit: FrameLimit) -> FrameReader {
        FrameReader {
            limit,
            prefix: [0; LENGTH_PREFIX_LEN],
            state: State::Prefix { filled: 0 },
            body: Zeroizing::new(Vec::new()),
        }
    }

    /// Octets the current frame still needs: the missing prefix octets, then
    /// the missing body octets; `0` when the frame is complete or the stream
    /// has failed.
    #[must_use]
    pub fn wanted(&self) -> usize {
        match self.state {
            State::Prefix { filled } => LENGTH_PREFIX_LEN.saturating_sub(filled),
            State::Body { len } => len.saturating_sub(self.body.len()),
            State::Failed(_) => 0,
        }
    }

    /// Take from `input` the octets that belong to the current frame and
    /// return how many were taken; the rest belong to whatever follows.
    ///
    /// The length prefix is checked the moment it is complete — before the
    /// body buffer is allocated and before any body octet is awaited.
    ///
    /// Spec: docs/50 §3.3; R50-4.
    pub fn push(&mut self, input: &[u8]) -> Result<usize> {
        let mut taken = 0;
        if let State::Prefix { filled } = self.state {
            let missing = self.prefix.get_mut(filled..).unwrap_or_default();
            let count = missing.len().min(input.len());
            let (source, _) = input.split_at_checked(count).ok_or(Error::Truncated)?;
            if let Some(target) = missing.get_mut(..count) {
                target.copy_from_slice(source);
            }
            taken = count;
            let filled = filled + count;
            if filled < LENGTH_PREFIX_LEN {
                self.state = State::Prefix { filled };
                return Ok(taken);
            }
            match check_declared_length(u32::from_be_bytes(self.prefix), self.limit) {
                Ok(len) => {
                    // Allocated once, at the checked size; never grown.
                    self.body = Zeroizing::new(Vec::with_capacity(len));
                    self.state = State::Body { len };
                }
                Err(error) => {
                    self.state = State::Failed(error);
                    return Err(error);
                }
            }
        }
        match self.state {
            State::Body { len } => {
                let rest = input.get(taken..).unwrap_or_default();
                let count = len.saturating_sub(self.body.len()).min(rest.len());
                let (source, _) = rest.split_at_checked(count).ok_or(Error::Truncated)?;
                // Within the reserved capacity: no reallocation.
                self.body.extend_from_slice(source);
                Ok(taken + count)
            }
            State::Failed(error) => Err(error),
            State::Prefix { .. } => Ok(taken),
        }
    }

    /// Whether the current frame is complete.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        matches!(self.state, State::Body { len } if self.body.len() == len)
    }

    /// The body of the current frame, once complete:
    /// `magic ‖ version ‖ kind ‖ payload`.
    #[must_use]
    pub fn body(&self) -> Option<&[u8]> {
        if self.is_complete() {
            Some(&self.body)
        } else {
            None
        }
    }

    /// Release the current frame: wipe its body and start the next frame. A
    /// failed stream stays failed.
    ///
    /// Spec: docs/50 §3.3 ("the frame buffer is zeroized after decoding");
    /// docs/CLEAN-ROOM.md (fail closed).
    pub fn reset(&mut self) {
        // The previous body drops here and is zeroized.
        self.body = Zeroizing::new(Vec::new());
        self.prefix = [0; LENGTH_PREFIX_LEN];
        if !matches!(self.state, State::Failed(_)) {
            self.state = State::Prefix { filled: 0 };
        }
    }
}
