//! auditd's own records: the payload of every record whose source is
//! [`Source::Auditd`](audit_log::Source::Auditd).
//!
//! ```text
//! AuditdEvent      := format:u8 (= 0xAD) ‖ kind:u8 ‖ fields
//! kind 0x01 SegmentRecovered := segment:u64 ‖ torn:u8 ‖ last_good_seq:u64
//!                               ‖ last_good_hash:[32] ‖ break_offset:u64
//!                               ‖ segment_octets:u64
//! kind 0x02 PeersRefused     := unmapped:u64 ‖ over_quota:u64 ‖ last_uid:u32
//! kind 0x03 EventsMisbound   := refused_batches:u64 ‖ last_uid:u32
//! kind 0x04 ResendsRefused   := mismatched:u64 ‖ unverifiable:u64 ‖ last_uid:u32
//! torn := 0x01 HeaderTruncated | 0x02 RecordTruncated
//! ```
//!
//! Kind `0x03` was appended for the source binding of the admin-plane
//! shapes (task A7, crate::binding); kind `0x04` for the resend check
//! (task F8, crate::resend); kinds `0x01` and `0x02` are unchanged.
//!
//! Fixed width, big-endian (the convention of the IPC codec and of the log,
//! docs/50 §3.3; crates/audit-log `format`). Only identifiers and metadata:
//! segment numbers, sequence numbers, a chain hash, octet counts, counters
//! and a uid — nothing secret (docs/37 §2; AGENTS.md §6).
//!
//! The leading octet `0xAD` differs from `ipc_audit::EVENT_FORMAT` (the
//! senders' event format), so a reader that decodes a payload without first
//! looking at the record's source fails on the format octet instead of
//! misreading an auditd record as a sender's event. Project choice
//! (docs/questions/Q-265 item 4).
//!
//! There is **no decoder** in the daemon: at start the recovery check
//! re-encodes the record it expects and compares octets
//! ([`crate::recovery`]), so no new parser of on-disk data is added
//! (AGENTS.md §6).
//!
//! Spec: docs/50 §3.2 ("an unmapped uid ⇒ the connection is closed + an audit
//! record"), R50-17; docs/questions/Q-250 items 5, 8 (`Auditd` source; the
//! record noting a recovered break); docs/37 §2.

use audit_log::{BreakKind, ChainHead};

/// The format octet of every auditd record payload. Project choice
/// (docs/questions/Q-265 item 4).
pub const AUDITD_EVENT_FORMAT: u8 = 0xAD;

/// Kind code: [`SegmentRecovered`]. Project choice.
pub const KIND_SEGMENT_RECOVERED: u8 = 0x01;
/// Kind code: [`PeersRefused`]. Project choice.
pub const KIND_PEERS_REFUSED: u8 = 0x02;
/// Kind code: [`EventsMisbound`]. Project choice (docs/questions/Q-341).
pub const KIND_EVENTS_MISBOUND: u8 = 0x03;
/// Kind code: [`ResendsRefused`]. Project choice (docs/questions/Q-445).
pub const KIND_RESENDS_REFUSED: u8 = 0x04;

/// Octets of an encoded [`SegmentRecovered`].
pub const SEGMENT_RECOVERED_LEN: usize = 2 + 8 + 1 + 8 + audit_log::HASH_LEN + 8 + 8;
/// Octets of an encoded [`PeersRefused`].
pub const PEERS_REFUSED_LEN: usize = 2 + 8 + 8 + 4;
/// Octets of an encoded [`EventsMisbound`].
pub const EVENTS_MISBOUND_LEN: usize = 2 + 8 + 4;
/// Octets of an encoded [`ResendsRefused`].
pub const RESENDS_REFUSED_LEN: usize = 2 + 8 + 8 + 4;

/// How a segment ends early: the two verifier breaks that mean "the file
/// stops inside a structure" — a torn write (docs/questions/Q-250 item 8).
///
/// Spec: crates/audit-log `BreakKind::HeaderTruncated`,
/// `BreakKind::RecordTruncated`; docs/questions/Q-265 item 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TornKind {
    /// The segment ends inside its header (a crash while a segment was being
    /// started: rotation or recovery).
    HeaderTruncated,
    /// The segment ends inside a record (a crash during a batch write).
    RecordTruncated,
}

impl TornKind {
    /// The torn kind of a verifier break, or `None` for every other break
    /// (those are refused at start — docs/questions/Q-265 item 1).
    #[must_use]
    pub const fn of(kind: BreakKind) -> Option<TornKind> {
        match kind {
            BreakKind::HeaderTruncated => Some(TornKind::HeaderTruncated),
            BreakKind::RecordTruncated => Some(TornKind::RecordTruncated),
            _ => None,
        }
    }

    /// The wire code. Project choice.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            TornKind::HeaderTruncated => 0x01,
            TornKind::RecordTruncated => 0x02,
        }
    }
}

/// A torn segment was found at start and the log continues in a new segment
/// anchored at `last_good`. The torn segment is kept, unchanged, as evidence
/// (never truncated or rewritten: docs/37 §2, append-only).
///
/// Every field is fixed by the torn segment itself, so a later start
/// re-derives this record and compares it octet for octet.
///
/// Spec: docs/questions/Q-250 item 8; docs/37 §2; docs/50 §7.5.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentRecovered {
    /// The torn segment's number (its file name suffix).
    pub segment: u64,
    /// How it ends.
    pub torn: TornKind,
    /// The last head that verified before the break (the verifier's
    /// `last_good`): the new segment's anchor.
    pub last_good: ChainHead,
    /// Octet offset in the torn segment where the broken structure starts.
    pub break_offset: u64,
    /// The torn segment's length in octets when it was recovered.
    pub segment_octets: u64,
}

/// Connections refused since the previous summary, counted rather than
/// recorded one by one so that a flood of refused connections cannot fill
/// the log (the A-57 rule for noise: "summarised in counters").
///
/// Spec: docs/50 §3.2 ("unmapped uid ⇒ closed + an audit record"), R50-3;
/// docs/questions/Q-218 (A-57); docs/questions/Q-265 item 8.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeersRefused {
    /// Connections from a uid the `uid → source` map does not name.
    pub unmapped: u64,
    /// Connections from a mapped uid over its connection quota.
    pub over_quota: u64,
    /// The peer uid of the most recent refused connection.
    pub last_uid: u32,
}

/// `Append` batches refused since the previous summary because an event in
/// them has a shape its connection's source may not send (for example a
/// `Kdc` event not from kdc, or a `DirAdmin` event not from dird —
/// crate::binding).
/// Counted, like refused connections, so a sender repeating a refused batch
/// cannot fill the log (A-57: noise "summarised in counters").
///
/// Spec: docs/50 §3.2 ("closed + an audit record"); docs/51 §5.7;
/// docs/questions/Q-218 (A-57), Q-341.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventsMisbound {
    /// Batches refused.
    pub refused_batches: u64,
    /// The peer uid of the most recent refused batch.
    pub last_uid: u32,
}

/// `Append` batches refused since the previous summary because they carry
/// sequence numbers of their source that auditd has already persisted
/// without being a byte-identical resend of those events (crate::resend):
///
/// * `mismatched` — an event under an already-persisted number differs in
///   its octets from the persisted one: a forgery or corruption signal;
/// * `unverifiable` — the batch reuses a number auditd has no persisted
///   event for in the source's current numbering (a number inside a gap),
///   or stops short of the last persisted number — no sender's resend does
///   either.
///
/// Counted, like refused connections and misbound batches, so a sender
/// repeating a refused batch cannot fill the log (A-57: "summarised in
/// counters").
///
/// Spec: docs/50 §8.1 (numbered events, "auditd acknowledges the last
/// sequence number persisted"), §3.2 ("closed + an audit record");
/// docs/questions/Q-218 (A-57), Q-252 item 7, Q-432 (A-98, follow-up F8),
/// Q-445.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResendsRefused {
    /// Batches refused because an event differs from the persisted one.
    pub mismatched: u64,
    /// Batches refused because the overlap could not be verified.
    pub unverifiable: u64,
    /// The peer uid of the most recent refused batch.
    pub last_uid: u32,
}

/// One auditd record payload.
///
/// Spec: this module's layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditdEvent {
    /// A torn segment was recovered at start.
    SegmentRecovered(SegmentRecovered),
    /// A summary of refused connections.
    PeersRefused(PeersRefused),
    /// A summary of batches refused by the source binding.
    EventsMisbound(EventsMisbound),
    /// A summary of batches refused by the resend check.
    ResendsRefused(ResendsRefused),
}

impl AuditdEvent {
    /// The payload octets (this module's layout).
    ///
    /// Spec: this module's layout; docs/50 §3.3 (fixed width, big-endian).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        match self {
            AuditdEvent::SegmentRecovered(event) => {
                let mut out = Vec::with_capacity(SEGMENT_RECOVERED_LEN);
                out.push(AUDITD_EVENT_FORMAT);
                out.push(KIND_SEGMENT_RECOVERED);
                out.extend_from_slice(&event.segment.to_be_bytes());
                out.push(event.torn.code());
                out.extend_from_slice(&event.last_good.seq.to_be_bytes());
                out.extend_from_slice(event.last_good.hash.as_bytes());
                out.extend_from_slice(&event.break_offset.to_be_bytes());
                out.extend_from_slice(&event.segment_octets.to_be_bytes());
                out
            }
            AuditdEvent::PeersRefused(event) => {
                let mut out = Vec::with_capacity(PEERS_REFUSED_LEN);
                out.push(AUDITD_EVENT_FORMAT);
                out.push(KIND_PEERS_REFUSED);
                out.extend_from_slice(&event.unmapped.to_be_bytes());
                out.extend_from_slice(&event.over_quota.to_be_bytes());
                out.extend_from_slice(&event.last_uid.to_be_bytes());
                out
            }
            AuditdEvent::EventsMisbound(event) => {
                let mut out = Vec::with_capacity(EVENTS_MISBOUND_LEN);
                out.push(AUDITD_EVENT_FORMAT);
                out.push(KIND_EVENTS_MISBOUND);
                out.extend_from_slice(&event.refused_batches.to_be_bytes());
                out.extend_from_slice(&event.last_uid.to_be_bytes());
                out
            }
            AuditdEvent::ResendsRefused(event) => {
                let mut out = Vec::with_capacity(RESENDS_REFUSED_LEN);
                out.push(AUDITD_EVENT_FORMAT);
                out.push(KIND_RESENDS_REFUSED);
                out.extend_from_slice(&event.mismatched.to_be_bytes());
                out.extend_from_slice(&event.unverifiable.to_be_bytes());
                out.extend_from_slice(&event.last_uid.to_be_bytes());
                out
            }
        }
    }
}

// The format octet is not the senders' event format (docs/questions/Q-265
// item 4) — checked at compile time.
const _: () = assert!(AUDITD_EVENT_FORMAT != ipc_audit::EVENT_FORMAT);
// Both payloads fit the log's payload bounds.
const _: () = assert!(SEGMENT_RECOVERED_LEN <= audit_log::MAX_PAYLOAD_LEN);
const _: () = assert!(PEERS_REFUSED_LEN >= audit_log::MIN_PAYLOAD_LEN);
const _: () = assert!(EVENTS_MISBOUND_LEN >= audit_log::MIN_PAYLOAD_LEN);
const _: () = assert!(EVENTS_MISBOUND_LEN <= audit_log::MAX_PAYLOAD_LEN);
const _: () = assert!(RESENDS_REFUSED_LEN >= audit_log::MIN_PAYLOAD_LEN);
const _: () = assert!(RESENDS_REFUSED_LEN <= audit_log::MAX_PAYLOAD_LEN);
