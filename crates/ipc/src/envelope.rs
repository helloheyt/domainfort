//! The envelope (`magic ‖ version ‖ kind`) and the message-definition pattern.
//!
//! A channel crate (ipc-keyd, ipc-directory, …) defines:
//! 1. a [`Channel`] constant — its magic, the one version it speaks, and a
//!    [`FrameLimit`] per direction;
//! 2. one struct per message, implementing [`Payload`]: `write_fields` writes
//!    the fields in their fixed order, and `read_fields` reads the same fields
//!    in the same order (one `let` per field, top to bottom, mirrors the
//!    writer line for line);
//! 3. one enum per direction, implementing [`MessageSet`]: the closed table
//!    of kinds and the dispatch from a kind to its payload.
//!
//! [`encode_frame`] and [`decode_body`] then do the rest: the envelope, the
//! exact version check, the closed-kind check, the body bound and the
//! no-trailing-octet rule. Because every primitive has exactly one encoding,
//! a mirrored pair of `write_fields` / `read_fields` gives the canonical
//! round trip `encode(decode(b)) == b`; [`round_trip_is_canonical`] checks it
//! in tests and fuzz targets (docs/50 §3.3: "every decoder checks
//! `encode(decode(b)) == b` in property tests").
//!
//! Replies: the shared [`Refused`] reply travels with [`REFUSED_KIND`] on
//! every channel. A server sends it with [`encode_refused`]; a client decodes
//! every reply with [`decode_reply`], which routes that kind to [`Refused`]
//! before the channel's own table is consulted (A-59).

use crate::error::{Error, Result};
use crate::frame::{decode_frame, FrameStatus};
use crate::limits::{FrameLimit, LENGTH_PREFIX_LEN};
use crate::reader::Reader;
use crate::refused::{kinds_exclude_refused, Refused, REFUSED_KIND};
use crate::writer::Writer;
use core::fmt;
use zeroize::Zeroizing;

/// Which way a frame travels on a channel; each direction has its own bound
/// and its own kind table.
///
/// Spec: docs/50 §3.3 ("a bound per channel and per direction"); §3.4 ("each
/// row = a request `kind` + a reply `kind`").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Client to server.
    Request,
    /// Server to client. Replies are decoded with the same strictness as
    /// requests (docs/50 §3.3, citing docs/07 §5).
    Reply,
}

/// The fixed identity of one IPC channel (one socket, docs/50 §3.1).
///
/// Spec: docs/50 §3.3 ("`magic` per channel" — a project choice per channel;
/// "exact version, no negotiation"; per-direction bounds); R50-4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Channel {
    magic: u16,
    version: u8,
    request_limit: FrameLimit,
    reply_limit: FrameLimit,
}

impl Channel {
    /// Describe a channel: its magic, the exact version this build speaks,
    /// and the body bound of each direction.
    /// Spec: docs/50 §3.3.
    #[must_use]
    pub const fn new(
        magic: u16,
        version: u8,
        request_limit: FrameLimit,
        reply_limit: FrameLimit,
    ) -> Channel {
        Channel {
            magic,
            version,
            request_limit,
            reply_limit,
        }
    }

    /// The channel's magic.
    #[must_use]
    pub const fn magic(self) -> u16 {
        self.magic
    }

    /// The one version this build speaks on the channel.
    #[must_use]
    pub const fn version(self) -> u8 {
        self.version
    }

    /// The body bound for frames travelling in `direction`.
    /// Spec: docs/50 §3.3.
    #[must_use]
    pub const fn limit(self, direction: Direction) -> FrameLimit {
        match direction {
            Direction::Request => self.request_limit,
            Direction::Reply => self.reply_limit,
        }
    }
}

/// A fixed-order group of fields: one message's payload, or a group nested
/// inside one (for example a ticket template inside a request).
///
/// `read_fields` must read exactly the fields `write_fields` writes, in the
/// same order and with the same bounds. Do not make a payload type recursive
/// except through optional or sequence fields (their nesting is bounded by
/// [`crate::MAX_NESTING`]).
///
/// Spec: docs/50 §3.3 ("positional fields in a fixed order for each kind");
/// D34 (minimal, hand-defined codec — no general serializer); R50-4.
pub trait Payload: Sized {
    /// Write the fields, in order.
    fn write_fields(&self, writer: &mut Writer) -> Result<()>;
    /// Read the fields, in the same order.
    fn read_fields(reader: &mut Reader<'_>) -> Result<Self>;
}

/// The closed set of messages that travel in one direction of one channel.
///
/// The table must leave out [`REFUSED_KIND`], which is reserved on every
/// channel for the shared [`Refused`] reply. Every envelope function that
/// takes a message set asserts this at compile time, so a set that lists the
/// reserved kind does not build once it is used:
///
/// ```compile_fail,E0080
/// use ipc::{decode_body, Channel, Direction, FrameLimit, MessageSet, Reader, Result, Writer};
/// struct Rogue;
/// impl MessageSet for Rogue {
///     const KINDS: &'static [u8] = &[0x01, ipc::REFUSED_KIND];
///     fn kind(&self) -> u8 { 0x01 }
///     fn write_payload(&self, _: &mut Writer) -> Result<()> { Ok(()) }
///     fn read_payload(_: u8, _: &mut Reader<'_>) -> Result<Rogue> { Ok(Rogue) }
/// }
/// let limit = FrameLimit::new(64).unwrap();
/// let channel = Channel::new(0x0102, 1, limit, limit);
/// let _ = decode_body::<Rogue>(channel, Direction::Reply, &[]);
/// ```
///
/// The same definition with an ordinary table builds:
///
/// ```
/// use ipc::{decode_body, Channel, Direction, FrameLimit, MessageSet, Reader, Result, Writer};
/// struct Fine;
/// impl MessageSet for Fine {
///     const KINDS: &'static [u8] = &[0x01, 0x02];
///     fn kind(&self) -> u8 { 0x01 }
///     fn write_payload(&self, _: &mut Writer) -> Result<()> { Ok(()) }
///     fn read_payload(_: u8, _: &mut Reader<'_>) -> Result<Fine> { Ok(Fine) }
/// }
/// let limit = FrameLimit::new(64).unwrap();
/// let channel = Channel::new(0x0102, 1, limit, limit);
/// let _ = decode_body::<Fine>(channel, Direction::Reply, &[]);
/// ```
///
/// Spec: docs/50 §3.3 ("`kind` closed: unknown op ⇒ close"); §3.4; R50-4;
/// A-59 (docs/questions/Q-225 item 2).
pub trait MessageSet: Sized {
    /// The closed table of kind values of this direction (never
    /// [`REFUSED_KIND`]). A frame whose kind is not listed is refused with
    /// [`Error::UnknownKind`] before [`MessageSet::read_payload`] is called.
    const KINDS: &'static [u8];

    /// The kind of this message (must be listed in [`MessageSet::KINDS`]).
    fn kind(&self) -> u8;

    /// Write the payload (the fields after the envelope).
    fn write_payload(&self, writer: &mut Writer) -> Result<()>;

    /// Read the payload of a frame of kind `kind`. Only called with a kind
    /// listed in [`MessageSet::KINDS`]; for any other kind, return
    /// [`Error::UnknownKind`].
    fn read_payload(kind: u8, reader: &mut Reader<'_>) -> Result<Self>;
}

/// One encoded frame — `length:u32 ‖ magic ‖ version ‖ kind ‖ payload` — in
/// a zeroizing buffer (it may carry a secret).
///
/// `Debug` shows only the length.
///
/// Spec: docs/50 §3.3; R50-4 (secret-bearing buffers zeroized).
pub struct EncodedFrame {
    octets: Zeroizing<Vec<u8>>,
}

impl EncodedFrame {
    /// The whole frame, length prefix included: what goes on the socket.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.octets
    }

    /// The frame body (envelope and payload), without the length prefix.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        self.octets.get(LENGTH_PREFIX_LEN..).unwrap_or_default()
    }

    /// Octets of the whole frame.
    #[must_use]
    pub fn len(&self) -> usize {
        self.octets.len()
    }

    /// Always false: a frame has at least its prefix and envelope.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.octets.is_empty()
    }
}

impl fmt::Debug for EncodedFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncodedFrame")
            .field("len", &self.octets.len())
            .finish()
    }
}

/// Compile-time guard: `M`'s kind table leaves out [`REFUSED_KIND`].
///
/// The assertion is evaluated when the compiler instantiates a generic
/// envelope function for `M`, so it can never fail at run time: a set that
/// lists the reserved kind is a build error, not a runtime panic.
///
/// Spec: A-59 (docs/questions/Q-225 item 2).
const fn assert_kinds_exclude_refused<M: MessageSet>() {
    const {
        assert!(
            kinds_exclude_refused(M::KINDS),
            "a MessageSet lists REFUSED_KIND (0xFF), which is reserved for the shared Refused reply"
        );
    }
}

/// A writer for one frame, with the envelope already written.
/// Spec: docs/50 §3.3 ("body := magic:u16 ‖ version:u8 ‖ kind:u8 ‖ payload").
fn envelope_writer(channel: Channel, direction: Direction, kind: u8) -> Result<Writer> {
    let mut writer = Writer::for_frame(channel.limit(direction));
    writer.write_u16(channel.magic())?;
    writer.write_u8(channel.version())?;
    writer.write_u8(kind)?;
    Ok(writer)
}

/// Check a body's bound and envelope and return its kind and a reader over
/// its payload. Order: body bound and envelope minimum (again, in case the
/// body did not come through the framer), magic, exact version.
///
/// Spec: docs/50 §3.3 (magic mismatch ⇒ close; version ≠ current ⇒
/// `Refused{VersionMismatch}` + close); R50-4.
fn open_envelope(channel: Channel, direction: Direction, body: &[u8]) -> Result<(u8, Reader<'_>)> {
    if body.len() > channel.limit(direction).max_body_len() {
        return Err(Error::FrameTooLarge);
    }
    let mut reader = Reader::new(body);
    let magic = reader.read_u16().map_err(|_| Error::FrameTooShort)?;
    let version = reader.read_u8().map_err(|_| Error::FrameTooShort)?;
    let kind = reader.read_u8().map_err(|_| Error::FrameTooShort)?;
    if magic != channel.magic() {
        return Err(Error::WrongMagic);
    }
    if version != channel.version() {
        return Err(Error::VersionMismatch);
    }
    Ok((kind, reader))
}

/// Encode `message` as one frame of `channel` travelling in `direction`.
///
/// Refuses a message whose kind is not in its own table
/// ([`Error::UnknownKind`]) and a body longer than the direction's bound
/// ([`Error::BodyOverBound`]), so it never produces a frame the peer would
/// refuse. A set whose table lists [`REFUSED_KIND`] does not build.
///
/// Spec: docs/50 §3.3 ("`Frame := length:u32 (big-endian) ‖ body[length]`";
/// "body := magic:u16 ‖ version:u8 ‖ kind:u8 ‖ payload"); R50-4; A-59.
pub fn encode_frame<M: MessageSet>(
    channel: Channel,
    direction: Direction,
    message: &M,
) -> Result<EncodedFrame> {
    assert_kinds_exclude_refused::<M>();
    let kind = message.kind();
    if !M::KINDS.contains(&kind) {
        return Err(Error::UnknownKind);
    }
    let mut writer = envelope_writer(channel, direction, kind)?;
    message.write_payload(&mut writer)?;
    Ok(EncodedFrame {
        octets: writer.into_frame_octets()?,
    })
}

/// Decode one frame body (as cut by [`decode_frame`] or
/// [`crate::FrameReader`]) of `channel` travelling in `direction`.
///
/// Checks, in order: the body bound and the envelope minimum (again, in case
/// the body did not come through the framer), the magic, the exact version,
/// the closed kind table, the payload fields, and that no octet follows the
/// last field.
///
/// [`REFUSED_KIND`] is in no set's table, so here it is refused as
/// [`Error::UnknownKind`] and never reaches the set's
/// [`MessageSet::read_payload`]. A client decodes replies with
/// [`decode_reply`], which yields the [`Refused`] for that kind.
///
/// Spec: docs/50 §3.3 (magic mismatch ⇒ close; version ≠ current ⇒
/// `Refused{VersionMismatch}` + close; unknown kind ⇒ close; trailing ⇒
/// `Malformed` + close); R50-4; A-59.
pub fn decode_body<M: MessageSet>(
    channel: Channel,
    direction: Direction,
    body: &[u8],
) -> Result<M> {
    assert_kinds_exclude_refused::<M>();
    let (kind, mut reader) = open_envelope(channel, direction, body)?;
    if !M::KINDS.contains(&kind) {
        return Err(Error::UnknownKind);
    }
    let message = M::read_payload(kind, &mut reader)?;
    reader.finish()?;
    Ok(message)
}

/// Cut the first frame from `buffer` and decode it: [`decode_frame`] then
/// [`decode_body`]. Returns the message and the octets the frame occupied,
/// or `None` if the frame is not yet complete.
///
/// Spec: docs/50 §3.3; R50-4.
pub fn decode_message<M: MessageSet>(
    channel: Channel,
    direction: Direction,
    buffer: &[u8],
) -> Result<Option<(M, usize)>> {
    match decode_frame(buffer, channel.limit(direction))? {
        FrameStatus::Complete { body, frame_len } => {
            decode_body(channel, direction, body).map(|message| Some((message, frame_len)))
        }
        FrameStatus::NeedMore { .. } => Ok(None),
    }
}

/// A decoded reply: one of the channel's reply messages, or the shared
/// transport refusal.
///
/// Spec: docs/50 §3.3 (errors row: replies carry the channel's outcome or
/// `Refused{code}`); A-59.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply<M> {
    /// A message of the channel's reply set.
    Message(M),
    /// The shared transport refusal, sent with [`REFUSED_KIND`].
    Refused(Refused),
}

/// Encode the shared [`Refused`] reply on any channel: kind [`REFUSED_KIND`],
/// payload one code octet. Every [`FrameLimit`] has room for it
/// ([`crate::MIN_BODY_LIMIT`]).
///
/// Spec: docs/50 §3.3 ("`Refused{VersionMismatch}` + close"; `Busy`,
/// `Unavailable`, `Malformed`); A-59.
pub fn encode_refused(channel: Channel, refused: Refused) -> Result<EncodedFrame> {
    let mut writer = envelope_writer(channel, Direction::Reply, REFUSED_KIND)?;
    refused.write_fields(&mut writer)?;
    Ok(EncodedFrame {
        octets: writer.into_frame_octets()?,
    })
}

/// Encode a reply: a message of the channel's reply set
/// ([`encode_frame`] in the reply direction) or the shared refusal
/// ([`encode_refused`]).
///
/// Spec: docs/50 §3.3; A-59.
pub fn encode_reply<M: MessageSet>(channel: Channel, reply: &Reply<M>) -> Result<EncodedFrame> {
    match reply {
        Reply::Message(message) => encode_frame(channel, Direction::Reply, message),
        Reply::Refused(refused) => encode_refused(channel, *refused),
    }
}

/// Decode one reply body of `channel`.
///
/// After the envelope checks of [`decode_body`] (bound, magic, exact
/// version), a frame of kind [`REFUSED_KIND`] is decoded as the shared
/// [`Refused`] — **before** the set's table is consulted, so the set's
/// [`MessageSet::read_payload`] never sees that kind. Any other kind goes
/// through the set's closed table as in [`decode_body`]. No octet may follow
/// the last field either way.
///
/// Spec: docs/50 §3.3 ("replies are decoded with the same strictness");
/// R50-4; A-59.
pub fn decode_reply<M: MessageSet>(channel: Channel, body: &[u8]) -> Result<Reply<M>> {
    assert_kinds_exclude_refused::<M>();
    let (kind, mut reader) = open_envelope(channel, Direction::Reply, body)?;
    let reply = if kind == REFUSED_KIND {
        Reply::Refused(Refused::read_fields(&mut reader)?)
    } else if M::KINDS.contains(&kind) {
        Reply::Message(M::read_payload(kind, &mut reader)?)
    } else {
        return Err(Error::UnknownKind);
    };
    reader.finish()?;
    Ok(reply)
}

/// Cut the first reply frame from `buffer` and decode it: [`decode_frame`]
/// then [`decode_reply`]. Returns the reply and the octets the frame
/// occupied, or `None` if the frame is not yet complete.
///
/// Spec: docs/50 §3.3; R50-4; A-59.
pub fn decode_reply_message<M: MessageSet>(
    channel: Channel,
    buffer: &[u8],
) -> Result<Option<(Reply<M>, usize)>> {
    match decode_frame(buffer, channel.limit(Direction::Reply))? {
        FrameStatus::Complete { body, frame_len } => {
            decode_reply(channel, body).map(|reply| Some((reply, frame_len)))
        }
        FrameStatus::NeedMore { .. } => Ok(None),
    }
}

/// The canonical round-trip property for one reply body, refusals included:
/// [`decode_reply`], then [`encode_reply`], then compare the octets.
///
/// Spec: docs/50 §3.3 ("round-trip … in property tests"); A-59.
pub fn reply_round_trip_is_canonical<M: MessageSet>(channel: Channel, body: &[u8]) -> Result<bool> {
    let reply: Reply<M> = decode_reply(channel, body)?;
    let frame = encode_reply(channel, &reply)?;
    Ok(frame.body() == body)
}

/// Encode a standalone payload (no envelope) of at most `limit` octets.
/// Spec: docs/50 §3.3.
pub fn encode_payload<P: Payload>(payload: &P, limit: FrameLimit) -> Result<Zeroizing<Vec<u8>>> {
    let mut writer = Writer::new(limit);
    payload.write_fields(&mut writer)?;
    Ok(writer.into_payload())
}

/// Decode a standalone payload (no envelope): its fields, then the
/// no-trailing-octet rule.
/// Spec: docs/50 §3.3; R50-4.
pub fn decode_payload<P: Payload>(octets: &[u8]) -> Result<P> {
    let mut reader = Reader::new(octets);
    let payload = P::read_fields(&mut reader)?;
    reader.finish()?;
    Ok(payload)
}

/// The canonical round-trip property for one frame body: decode it, encode
/// the value again, and report whether the octets are identical.
///
/// `Err` — the body is refused (that is not a property failure);
/// `Ok(true)` — canonical; `Ok(false)` — the message definition's reader and
/// writer disagree (a bug in that definition).
///
/// Spec: docs/50 §3.3 ("round-trip: every decoder checks
/// `encode(decode(b)) == b` in property tests").
pub fn round_trip_is_canonical<M: MessageSet>(
    channel: Channel,
    direction: Direction,
    body: &[u8],
) -> Result<bool> {
    let message: M = decode_body(channel, direction, body)?;
    let frame = encode_frame(channel, direction, &message)?;
    Ok(frame.body() == body)
}
