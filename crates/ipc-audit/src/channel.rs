//! The audit channel (`audit.sock`): its envelope constants, bounds and
//! message set, and auditd's per-connection sequence check.
//!
//! ```text
//! request kinds (sender → auditd)       reply kinds (auditd → sender)
//!   0x01 Append { first_seq: u64,         0x01 Ack { through_seq: u64,
//!                 events: seq<bytes<8192>, 16> }      head_hash: [u8; 32] }
//!   0x02 Ping   { }                       0x02 Pong { source: u8 }
//!                                         0xFF Refused (ipc, every channel)
//! ```
//!
//! `Append` carries a batch of the sender's encoded events (crate::event),
//! numbered by the sender from `first_seq` upward. auditd appends them to the
//! log, syncs, and only then answers `Ack`: `through_seq` is the sender's
//! number of the last event persisted, `head_hash` the chain hash of the
//! record that holds it (crate `audit-log`). One request is in flight per
//! connection (docs/50 §3.6: strict request → reply, no pipelining); the
//! bounded window of unacknowledged events is the sender's
//! ([`crate::SendWindow`]). `Ping` is the health check every channel has
//! (docs/50 §7.5).
//!
//! The source of the events is the connection's peer uid, never a field
//! (docs/50 §3.2): no request carries a source. auditd **reports** it: the
//! `Pong` names the [`EventSource`] auditd records this connection's events
//! under — the one its own map gives the peer uid — so that a sender can
//! check, on every new connection and before its first batch, that auditd
//! records it under its own source (task R9b, docs/52 §3.12 C12,
//! docs/questions/Q-512, Q-560). The field was appended to the `Pong` that
//! was empty before (docs/50 §3.3: append-only; the channel version stays
//! 1 — docs/questions/Q-560 item 3).
//!
//! Spec: docs/50 R50-17, §3.2, §3.3, §3.6, §7.5, §8.1, §10; A-59
//! (REFUSED_KIND); docs/questions/Q-252 items 1, 2, Q-512 (A-112), Q-560.

use crate::event::{EventBytes, MAX_EVENT_OCTETS};
use ipc::{
    decode_body, decode_reply as ipc_decode_reply, encode_frame, encode_reply as ipc_encode_reply,
    Channel, Direction, EncodedFrame, FrameLimit, MessageSet, Payload, Reader, Reply, Writer,
    BODY_HEADER_LEN,
};

/// The audit channel's magic. Project choice (docs/50 §3.3: "a different
/// constant per channel"); docs/questions/Q-252 item 2.
pub const AUDIT_MAGIC: u16 = 0xA7D1;

/// The one version of the audit channel this build speaks (exact match).
/// Spec: docs/50 §3.3; D57.
pub const AUDIT_VERSION: u8 = 1;

/// Most events in one `Append`. Project choice (docs/questions/Q-252 item 1).
pub const MAX_BATCH_EVENTS: u32 = 16;

/// Octets of one `Append` event field at its largest: length + event.
const MAX_EVENT_FIELD: u32 = 4 + MAX_EVENT_OCTETS;

/// Request body bound: envelope + `first_seq` + count + the largest batch.
/// Spec: docs/50 §3.3 ("audit ≤ 8 KiB per event"; a bound per channel and
/// direction).
pub const REQUEST_BODY_LIMIT: u32 =
    BODY_HEADER_LEN as u32 + 8 + 4 + MAX_BATCH_EVENTS * MAX_EVENT_FIELD;

/// Reply body bound: envelope + `Ack` (the largest reply).
/// Spec: docs/50 §3.3.
pub const REPLY_BODY_LIMIT: u32 = BODY_HEADER_LEN as u32 + 8 + 32;

/// A frame limit, checked at compile time.
const fn limit(max_body: u32) -> FrameLimit {
    match FrameLimit::new(max_body) {
        Some(limit) => limit,
        None => panic!("audit channel bound outside the ipc range"),
    }
}

/// The audit channel. Spec: docs/50 §3.1 (`audit.sock`), §3.3.
pub const AUDIT_CHANNEL: Channel = Channel::new(
    AUDIT_MAGIC,
    AUDIT_VERSION,
    limit(REQUEST_BODY_LIMIT),
    limit(REPLY_BODY_LIMIT),
);

/// Request kind: `Append`. Project choice.
pub const KIND_APPEND: u8 = 0x01;
/// Request kind: `Ping`. Project choice.
pub const KIND_PING: u8 = 0x02;
/// Reply kind: `Ack`. Project choice.
pub const KIND_ACK: u8 = 0x01;
/// Reply kind: `Pong`. Project choice.
pub const KIND_PONG: u8 = 0x02;

/// A batch of encoded events, numbered by the sender from `first_seq`.
///
/// 1 to [`MAX_BATCH_EVENTS`] events, each 1 to [`MAX_EVENT_OCTETS`] octets;
/// `first_seq` ≥ 1 and the last number fits a `u64`.
///
/// Spec: docs/50 §8.1 ("an event … with the source's sequence number");
/// R50-17 (a bounded window).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Append {
    first_seq: u64,
    events: Vec<EventBytes>,
}

impl Append {
    /// A batch, or `None` if it breaks a bound above.
    #[must_use]
    pub fn new(first_seq: u64, events: Vec<EventBytes>) -> Option<Append> {
        let count = u64::try_from(events.len()).ok()?;
        let valid = first_seq >= 1
            && count >= 1
            && count <= u64::from(MAX_BATCH_EVENTS)
            && first_seq.checked_add(count - 1).is_some();
        valid.then_some(Append { first_seq, events })
    }

    /// The sender's number of the first event.
    #[must_use]
    pub fn first_seq(&self) -> u64 {
        self.first_seq
    }

    /// The sender's number of the last event.
    #[must_use]
    pub fn last_seq(&self) -> u64 {
        // `new` and `read_fields` ensure this does not overflow.
        let count = u64::try_from(self.events.len()).unwrap_or(1);
        self.first_seq.saturating_add(count.saturating_sub(1))
    }

    /// The events.
    #[must_use]
    pub fn events(&self) -> &[EventBytes] {
        &self.events
    }
}

impl Payload for Append {
    /// `first_seq: u64`, `events: seq<bytes<MAX_EVENT_OCTETS>, MAX_BATCH_EVENTS>`.
    /// Spec: docs/50 §3.3.
    fn write_fields(&self, writer: &mut Writer) -> ipc::Result<()> {
        writer.write_u64(self.first_seq)?;
        writer.write_seq(&self.events, MAX_BATCH_EVENTS, |w, event| {
            w.write_bytes(event.as_bytes(), MAX_EVENT_OCTETS)
        })
    }

    /// The same fields. An empty batch is refused as a count outside the
    /// bound, an empty event as a length outside the bound, `first_seq` 0 or
    /// a last number past `u64::MAX` as an unknown code — all
    /// `Refused::Malformed` + close (A-59; docs/questions/Q-252 item 1).
    fn read_fields(reader: &mut Reader<'_>) -> ipc::Result<Append> {
        let first_seq = reader.read_u64()?;
        let raw = reader.read_seq(MAX_BATCH_EVENTS, |r| r.read_bytes(MAX_EVENT_OCTETS))?;
        if raw.is_empty() {
            return Err(ipc::Error::CountOverBound);
        }
        let mut events = Vec::with_capacity(raw.len());
        for octets in raw {
            events.push(EventBytes::new(octets.to_vec()).ok_or(ipc::Error::LengthOverBound)?);
        }
        Append::new(first_seq, events).ok_or(ipc::Error::UnknownCode)
    }
}

/// auditd's acknowledgement: every event of the sender up to `through_seq`
/// is on stable storage; `head_hash` is the chain hash of the record that
/// holds event `through_seq`.
///
/// Spec: docs/50 §8.1 ("auditd acknowledges the last sequence number
/// persisted"), R50-17.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ack {
    /// The sender's number of the last event persisted.
    pub through_seq: u64,
    /// The chain hash of the record holding it.
    pub head_hash: [u8; 32],
}

impl Payload for Ack {
    /// `through_seq: u64`, `head_hash: [u8; 32]`. Spec: docs/50 §3.3.
    fn write_fields(&self, writer: &mut Writer) -> ipc::Result<()> {
        writer.write_u64(self.through_seq)?;
        writer.write_array(&self.head_hash)
    }

    fn read_fields(reader: &mut Reader<'_>) -> ipc::Result<Ack> {
        Ok(Ack {
            through_seq: reader.read_u64()?,
            head_hash: reader.read_array::<32>()?,
        })
    }
}

/// The source auditd records a connection's events under: the process the
/// connection's peer uid is mapped to in auditd's own `uid → source` map
/// (docs/50 §3.2: "auditd: every service's uid, each marked as the event's
/// source — the source is set from the uid, not from the event body";
/// §8.1: "the record's source is set from the connection's uid").
///
/// auditd names it in every `Pong` ([`AuditReply::Pong`]); a sender expects
/// its own on every new connection before it sends a batch (task R9b,
/// docs/52 §3.12 C12, docs/questions/Q-512).
///
/// Closed table: the processes that can be mapped to a uid (docs/50 §2.4;
/// crates/config `AuditSource`). The codes are the audit log's own source
/// codes (crates/audit-log `Source::code`: keyd 1, dird 2, kdc 3,
/// ldap-front 4, admind 5) — one numbering for "the source" on the wire and
/// on disk; crates/audit-daemon's tests pin them equal. auditd's own source
/// (code 6 in the log) names no peer, so it has no value here: 6, like 0 and
/// every other code, is outside the table (docs/questions/Q-560 item 2).
///
/// Spec: docs/50 §2.4, §3.2, §3.3 ("enum = `u8` from a closed table"), §8.1;
/// docs/52 §3.12; docs/questions/Q-512 (A-112), Q-560.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventSource {
    /// keyd. Spec: docs/50 §2.4.
    Keyd,
    /// dird (the LDAP engine's and the admin plane's events). Spec: docs/50
    /// §2.4, §4.2; docs/51 §5.7.
    Dird,
    /// The kdc. Spec: docs/50 §2.4.
    Kdc,
    /// ldap-front (sends no events; verifies auditd at start). Spec: docs/50
    /// §2.4, §4.2.
    LdapFront,
    /// admind. Spec: docs/51 §5.7 item 3.
    Admind,
}

impl EventSource {
    /// Every source, in code order.
    pub const ALL: [EventSource; 5] = [
        EventSource::Keyd,
        EventSource::Dird,
        EventSource::Kdc,
        EventSource::LdapFront,
        EventSource::Admind,
    ];

    /// The wire code (the audit log's source code). Project choice; 0 is
    /// never a code.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            EventSource::Keyd => 1,
            EventSource::Dird => 2,
            EventSource::Kdc => 3,
            EventSource::LdapFront => 4,
            EventSource::Admind => 5,
        }
    }

    /// The source for a wire code, or `None` outside the closed table.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<EventSource> {
        match code {
            1 => Some(EventSource::Keyd),
            2 => Some(EventSource::Dird),
            3 => Some(EventSource::Kdc),
            4 => Some(EventSource::LdapFront),
            5 => Some(EventSource::Admind),
            _ => None,
        }
    }
}

/// The request direction (sender → auditd). Spec: docs/50 §3.3, §7.5, §8.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditRequest {
    /// A batch of events.
    Append(Append),
    /// Health check (docs/50 §7.5).
    Ping,
}

impl MessageSet for AuditRequest {
    const KINDS: &'static [u8] = &[KIND_APPEND, KIND_PING];

    fn kind(&self) -> u8 {
        match self {
            AuditRequest::Append(_) => KIND_APPEND,
            AuditRequest::Ping => KIND_PING,
        }
    }

    fn write_payload(&self, writer: &mut Writer) -> ipc::Result<()> {
        match self {
            AuditRequest::Append(append) => append.write_fields(writer),
            AuditRequest::Ping => Ok(()),
        }
    }

    fn read_payload(kind: u8, reader: &mut Reader<'_>) -> ipc::Result<AuditRequest> {
        match kind {
            KIND_APPEND => Append::read_fields(reader).map(AuditRequest::Append),
            KIND_PING => Ok(AuditRequest::Ping),
            _ => Err(ipc::Error::UnknownKind),
        }
    }
}

/// The reply direction (auditd → sender), besides the shared `Refused`.
/// Spec: docs/50 §3.3, §7.5, §8.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditReply {
    /// Persistence acknowledgement.
    Ack(Ack),
    /// Health check answer: the source auditd records this connection's
    /// events under ([`EventSource`]; task R9b, docs/questions/Q-560).
    Pong(EventSource),
}

impl MessageSet for AuditReply {
    const KINDS: &'static [u8] = &[KIND_ACK, KIND_PONG];

    fn kind(&self) -> u8 {
        match self {
            AuditReply::Ack(_) => KIND_ACK,
            AuditReply::Pong(_) => KIND_PONG,
        }
    }

    /// `Pong`: `source: u8` — the one field, appended to the reply that was
    /// empty before (docs/50 §3.3: positional fields, enum = `u8` from a
    /// closed table). Spec: docs/questions/Q-560 item 1.
    fn write_payload(&self, writer: &mut Writer) -> ipc::Result<()> {
        match self {
            AuditReply::Ack(ack) => ack.write_fields(writer),
            AuditReply::Pong(source) => writer.write_u8(source.code()),
        }
    }

    /// The same fields. A `Pong` without its octet (the empty form of
    /// before) is `Truncated`, a code outside [`EventSource`]'s table
    /// `UnknownCode`, an octet after it `TrailingBytes` (ipc `decode_reply`)
    /// — the sender drops the connection (docs/50 §3.3). Spec: docs/50 §3.3;
    /// docs/questions/Q-560 item 1.
    fn read_payload(kind: u8, reader: &mut Reader<'_>) -> ipc::Result<AuditReply> {
        match kind {
            KIND_ACK => Ack::read_fields(reader).map(AuditReply::Ack),
            KIND_PONG => {
                let code = reader.read_u8()?;
                EventSource::from_code(code)
                    .map(AuditReply::Pong)
                    .ok_or(ipc::Error::UnknownCode)
            }
            _ => Err(ipc::Error::UnknownKind),
        }
    }
}

// The reserved shared-refusal kind is in neither table (A-59).
const _: () = assert!(ipc::kinds_exclude_refused(AuditRequest::KINDS));
const _: () = assert!(ipc::kinds_exclude_refused(AuditReply::KINDS));

/// Encode a request frame. Spec: docs/50 §3.3.
///
/// # Errors
/// As [`ipc::encode_frame`].
pub fn encode_request(request: &AuditRequest) -> ipc::Result<EncodedFrame> {
    encode_frame(AUDIT_CHANNEL, Direction::Request, request)
}

/// Decode a request body (as cut by the framer). Spec: docs/50 §3.3.
///
/// # Errors
/// As [`ipc::decode_body`].
pub fn decode_request(body: &[u8]) -> ipc::Result<AuditRequest> {
    decode_body(AUDIT_CHANNEL, Direction::Request, body)
}

/// Encode a reply frame (a message or the shared `Refused`).
/// Spec: docs/50 §3.3; A-59.
///
/// # Errors
/// As [`ipc::encode_reply`].
pub fn encode_reply(reply: &Reply<AuditReply>) -> ipc::Result<EncodedFrame> {
    ipc_encode_reply(AUDIT_CHANNEL, reply)
}

/// Decode a reply body. Spec: docs/50 §3.3 (replies decoded with the same
/// strictness); A-59.
///
/// # Errors
/// As [`ipc::decode_reply`].
pub fn decode_reply(body: &[u8]) -> ipc::Result<Reply<AuditReply>> {
    ipc_decode_reply(AUDIT_CHANNEL, body)
}

/// A range of the sender's sequence numbers, accepted for one `Append`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeqRange {
    /// First number.
    pub first: u64,
    /// Last number.
    pub last: u64,
}

/// Why auditd refuses an `Append` on a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SequenceError {
    /// The batch does not start where the previous one on this connection
    /// ended.
    OutOfOrder {
        /// The number expected.
        expected: u64,
    },
    /// The connection's numbering is exhausted.
    Exhausted,
}

/// auditd's per-connection check that a sender's numbering is contiguous.
///
/// The first `Append` on a connection sets the baseline (a reconnecting
/// sender resends its unacknowledged events from their numbers); every later
/// one must start right after the previous. An event persisted before a lost
/// acknowledgement can therefore appear twice in the log, never zero times
/// (docs/questions/Q-252 item 7).
///
/// Spec: docs/50 §8.1; docs/questions/Q-252 item 7.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AppendCursor {
    expected: Option<u64>,
}

impl AppendCursor {
    /// A cursor for a new connection.
    #[must_use]
    pub fn new() -> AppendCursor {
        AppendCursor { expected: None }
    }

    /// Check `append` against the connection's numbering (does not advance).
    ///
    /// # Errors
    /// [`SequenceError`].
    pub fn check(&self, append: &Append) -> Result<SeqRange, SequenceError> {
        if let Some(expected) = self.expected {
            if append.first_seq() != expected {
                return Err(SequenceError::OutOfOrder { expected });
            }
        }
        Ok(SeqRange {
            first: append.first_seq(),
            last: append.last_seq(),
        })
    }

    /// Advance past `range` — only after its events were persisted.
    ///
    /// # Errors
    /// [`SequenceError::Exhausted`] if no number follows `range.last`.
    pub fn advance(&mut self, range: SeqRange) -> Result<(), SequenceError> {
        let next = range.last.checked_add(1).ok_or(SequenceError::Exhausted)?;
        self.expected = Some(next);
        Ok(())
    }

    /// The acknowledgement for a persisted range.
    #[must_use]
    pub fn ack(range: SeqRange, head_hash: [u8; 32]) -> Ack {
        Ack {
            through_seq: range.last,
            head_hash,
        }
    }
}
