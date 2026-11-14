//! The resend check: which events of an `Append` auditd has already
//! persisted, so that a batch resent after a lost acknowledgement is
//! acknowledged without being appended again.
//!
//! # Why
//!
//! Every sender numbers its events with its own sequence (ipc-audit
//! `SendWindow`: "the first event gets sequence number 1") and keeps them
//! until auditd acknowledges them (docs/50 §8.1: "auditd acknowledges the
//! last sequence number persisted; the sender has a bounded window of
//! unacknowledged events"). A sender that loses the acknowledgement — auditd
//! stopped right after the sync, or the connection broke while the batch
//! waited in the writer's queue — puts the batch back and resends it with
//! the same numbers on its next connection (`SendWindow::connection_lost`;
//! docs/50 §3.7). Before task F8 auditd appended such a batch again ("twice,
//! never zero times", docs/questions/Q-252 item 7); A13 saw dird's
//! `Outcome` logged twice after an auditd restart (Q-432 item 5). Decision
//! A-98 (follow-up F8): recognise a batch whose `(source, source_seq)`
//! range is already persisted — with the per-source state recovered from the
//! verified log at start — and acknowledge it without appending it again.
//!
//! # What auditd remembers
//!
//! Per sender source (the transport identity: the connection's peer uid,
//! mapped to its one source — docs/50 §3.2, R50-3; crates/config refuses a
//! uid or a source named twice), a [`SourceTail`]:
//!
//! * the **counter**: the `source_seq` of the source's most recent record,
//!   and the uid that record came from;
//! * the **remembered events**: the `source_seq`, the SHA-256 of the payload
//!   (through crates/audit-log [`RecordHash::of`], the approved `sha2`
//!   crate — AGENTS.md §6) and, where known, the chain head of the record
//!   holding it, for the source's last [`REMEMBERED_EVENTS`] events. A byte
//!   comparison needs the persisted octets or a collision-resistant digest
//!   of them; the digest keeps the state small.
//!
//! The table has one slot per sender source of the closed `Source` table,
//! so it is bounded by the uid map's image whatever the log holds; auditd's
//! own records are never in it. The state changes only when records are
//! persisted ([`PersistedTails::observe`]), and the start-up walk replays
//! the same function over every record of the verified log (A-66: the log
//! is verified from genesis at start), so the recovered state is exactly the
//! state the writer had when the log ended.
//!
//! # The rule (one numbering per source — [`Numbering::Single`])
//!
//! A sender resends only on a new connection, as its first `Append` there
//! (ipc-audit `AppendCursor`: "the first `Append` on a connection sets the
//! baseline; every later one must start right after the previous"); a
//! later batch on a connection continues the numbers the connection itself
//! had acknowledged, so it carries new events and is appended as it is.
//! For a connection's **first** `Append`, numbered from `F`:
//!
//! 1. **`F = 1`** — the sender's numbering starts again: a sender numbers
//!    from 1 at every start (`SendWindow::new`), and resends from 1 only if
//!    the acknowledgement of its very first batch was lost. auditd cannot
//!    tell the two apart, and of "twice" and "zero times" only the first is
//!    allowed (A-64: "logged twice, never zero"), so a batch from 1 is
//!    always appended as a new numbering — a restarted sender is never
//!    refused. Residual: the first batch of a sender lifetime, if its
//!    acknowledgement is lost, is still logged twice (docs/questions/Q-445).
//! 2. **Otherwise each event is looked up**, by its number, among the
//!    remembered events of the source's current numbering:
//!    * the leading events found with an **identical** digest are the
//!      resent part — already persisted, not appended again;
//!    * the events from the first one not found onward are new and are
//!      appended (a **partly persisted** batch: the sender had committed
//!      more events by the time it resent — `connection_lost` puts the batch
//!      in flight back in front and `next_batch` takes up to 16 — or a torn
//!      write kept only the start of a never-acknowledged batch);
//!    * a batch whose every event is found is acknowledged with the head of
//!      the record holding its last event, nothing appended.
//!
//!    The whole batch is refused ([`ResendRefusal`]) when an event is found
//!    with **other octets** — a forgery or corruption signal
//!    (`Mismatched`) — or when a found event follows a new one, or a wholly
//!    found batch ends inside a batch auditd appended (the head of that
//!    record is not known): no sender resends with a hole, or stops short
//!    of the batch it resends (`Unverifiable`). Nothing of it is persisted;
//!    the listener answers `Refused::Malformed` and closes, as for a
//!    numbering error (docs/questions/Q-265 item 3), and the refusal is
//!    counted into an `Auditd` `ResendsRefused` record.
//!
//! Nothing overlaps when `F` is past the source's last persisted number:
//! no event is found and all are appended. A gap is accepted the same way —
//! numbers in between were never received here (a log started afresh under
//! a running sender, say); refusing would block the sender for good, and the
//! gap stays visible in the log.
//!
//! "The current numbering" is the run of remembered events with rising
//! numbers that ends at the most recent one (a restart at 1 begins a new
//! run), so a restarted sender's resend is never compared with its previous
//! lifetime's events under the same numbers. A different uid under the same
//! source — a changed configuration between two runs — starts a fresh state.
//! A batch holds at most 16 events, far fewer than the
//! [`REMEMBERED_EVENTS`] remembered.
//!
//! # A source shared by several numberings ([`Numbering::Shared`])
//!
//! The daemon's binding table gives every source exactly one sender
//! (crate::binding `PRODUCTION`), so the rule above always applies. A test
//! harness whose senders all share one uid, and therefore one source label,
//! runs several independent numberings under that label
//! (docs/questions/Q-432 residual): there a reused number is normal, and a
//! differing event cannot be told from another sender's. For such a label
//! (crate::binding::numbering) nothing is refused: on a connection's first
//! batch, the leading events whose number and digest equal one of the
//! label's remembered events are duplicates; a batch from 1 is never a
//! duplicate (rule 1); everything else is appended.
//!
//! Spec: docs/50 §3.2, §3.7, §8.1, R50-3, R50-17; docs/37 §2; Q-218 (A-57);
//! Q-252 item 7 (A-64); Q-265 items 3, 11 (A-66); Q-341 (A-85); Q-432
//! (A-98); Q-445; crates/ipc-audit `SendWindow`, `Append`, `Ack`,
//! `AppendCursor`; crates/audit-log `Record`, `RecordHash::of`.

use audit_log::{ChainHead, RecordHash, Source};
use core::fmt;
use ipc_audit::EventBytes;
use std::collections::VecDeque;

/// How many of a source's most recent events auditd remembers. A sender's
/// resend overlaps at most one batch (`ipc_audit::MAX_BATCH_EVENTS`, 16
/// events); a shared test label needs one batch per sender sharing it.
/// 16 batches of 16 events. Project choice (docs/questions/Q-445 item 1).
pub const REMEMBERED_EVENTS: usize = 256;

// One batch of a sender must fit, whatever the numbering.
const _: () = assert!(REMEMBERED_EVENTS >= ipc_audit::MAX_BATCH_EVENTS as usize);

/// Sender sources: every `Source` except auditd's own.
const SENDER_SOURCES: usize = 5;

/// Whose numbering a source carries.
///
/// Spec: docs/50 §3.2, R50-3 (one source per uid); docs/questions/Q-432
/// residual (the single-uid harness's one label), Q-445.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Numbering {
    /// One sender: the strict rule of this module.
    Single,
    /// Several senders share the source label (test harnesses only): no
    /// refusal, duplicates recognised by number and digest.
    Shared,
}

/// Why a batch that reuses persisted numbers is refused.
///
/// Spec: this module's rule 2; docs/questions/Q-445.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResendRefusal {
    /// An event under a persisted number differs in its octets from the
    /// persisted one.
    Mismatched,
    /// A persisted event follows a new one in the batch (a resend with a
    /// hole), or a wholly persisted batch stops inside a batch auditd
    /// appended.
    Unverifiable,
}

impl fmt::Display for ResendRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ResendRefusal::Mismatched => "resent event differs from the persisted one",
            ResendRefusal::Unverifiable => {
                "batch reuses persisted numbers it cannot be checked against"
            }
        })
    }
}

/// What to do with a batch.
///
/// Spec: this module's rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Plan {
    /// Append the events after the first `skip` (which are already
    /// persisted); `skip` is less than the batch's length.
    Append {
        /// Leading events already persisted.
        skip: usize,
    },
    /// Every event is already persisted: acknowledge with this head (the
    /// record holding the batch's last event), append nothing.
    AlreadyPersisted(ChainHead),
    /// Refuse the whole batch.
    Refuse(ResendRefusal),
}

/// One remembered event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Remembered {
    /// The sender's number of the event.
    source_seq: u64,
    /// SHA-256 of the payload.
    digest: RecordHash,
    /// The record holding it, when known: always for a record read back at
    /// start, and for the last event of every batch appended since.
    record: Option<ChainHead>,
}

/// What auditd remembers about one sender source.
///
/// Spec: this module's documentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceTail {
    uid: u32,
    last_seq: u64,
    recent: VecDeque<Remembered>,
}

impl SourceTail {
    /// The uid of the source's most recent record.
    #[must_use]
    pub fn uid(&self) -> u32 {
        self.uid
    }

    /// The `source_seq` of the source's most recent record: the counter.
    #[must_use]
    pub fn last_seq(&self) -> u64 {
        self.last_seq
    }

    /// How many events are remembered (at most [`REMEMBERED_EVENTS`]).
    #[must_use]
    pub fn remembered(&self) -> usize {
        self.recent.len()
    }

    /// The remembered events of the current numbering: the longest run of
    /// rising numbers ending at the most recent event.
    fn current_numbering(&self) -> impl Iterator<Item = &Remembered> {
        let mut previous: Option<u64> = None;
        self.recent.iter().rev().take_while(move |event| {
            let rising = previous.is_none_or(|later| event.source_seq < later);
            previous = Some(event.source_seq);
            rising
        })
    }
}

/// The per-source state of the resend check.
///
/// Spec: this module's documentation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PersistedTails {
    tails: [Option<SourceTail>; SENDER_SOURCES],
}

/// The table slot of a sender source; `None` for auditd's own records.
const fn slot(source: Source) -> Option<usize> {
    match source {
        Source::Keyd => Some(0),
        Source::Dird => Some(1),
        Source::Kdc => Some(2),
        Source::LdapFront => Some(3),
        Source::Admind => Some(4),
        Source::Auditd => None,
    }
}

/// The digest of an event's octets. Spec: this module ("the remembered
/// events"); crates/audit-log `RecordHash::of` (SHA-256, approved crate).
fn digest_of(payload: &[u8]) -> RecordHash {
    RecordHash::of(payload)
}

/// The sender's number of the event at `offset` in a batch from `first`.
fn number_at(first: u64, offset: usize) -> Option<u64> {
    first.checked_add(u64::try_from(offset).ok()?)
}

impl PersistedTails {
    /// No source seen yet.
    #[must_use]
    pub fn new() -> PersistedTails {
        PersistedTails::default()
    }

    /// What is remembered about `source` (`None` before its first record,
    /// and always for `Auditd`).
    #[must_use]
    pub fn tail(&self, source: Source) -> Option<&SourceTail> {
        slot(source)
            .and_then(|index| self.tails.get(index))
            .and_then(Option::as_ref)
    }

    /// Record that the event numbered `source_seq` from `source` / `uid`,
    /// with `payload`, is persisted — in the record `record` when known.
    /// Called for every sender record, in log order: by the writer after a
    /// sync, and by the start-up walk for every record of the verified log.
    /// auditd's own records are ignored.
    ///
    /// Spec: this module ("what auditd remembers"); docs/50 §7.5, A-66.
    pub fn observe(
        &mut self,
        source: Source,
        uid: u32,
        source_seq: u64,
        payload: &[u8],
        record: Option<ChainHead>,
    ) {
        let Some(entry) = slot(source).and_then(|index| self.tails.get_mut(index)) else {
            return;
        };
        // A different uid under the same source is another transport
        // identity: start afresh.
        if entry.as_ref().is_some_and(|tail| tail.uid != uid) {
            *entry = None;
        }
        let tail = entry.get_or_insert_with(|| SourceTail {
            uid,
            last_seq: 0,
            recent: VecDeque::with_capacity(REMEMBERED_EVENTS),
        });
        if tail.recent.len() >= REMEMBERED_EVENTS {
            tail.recent.pop_front();
        }
        tail.recent.push_back(Remembered {
            source_seq,
            digest: digest_of(payload),
            record,
        });
        tail.last_seq = source_seq;
    }

    /// Decide what to do with an `Append` from `source` / `uid` numbered
    /// from `first_seq`. `numbering` is the source's (crate::binding);
    /// `first_on_connection` says whether this is the first batch on its
    /// connection — the only one a reconnecting sender's resend can be; a
    /// later batch on a connection is appended as it is.
    ///
    /// Spec: this module's rules.
    #[must_use]
    pub fn plan(
        &self,
        source: Source,
        uid: u32,
        first_seq: u64,
        events: &[EventBytes],
        numbering: Numbering,
        first_on_connection: bool,
    ) -> Plan {
        let append_all = Plan::Append { skip: 0 };
        let Some(tail) = self.tail(source).filter(|tail| tail.uid == uid) else {
            return append_all;
        };
        // Rule 1: a batch from 1 starts a numbering — never a duplicate.
        if !first_on_connection || first_seq == 1 || events.is_empty() {
            return append_all;
        }
        match numbering {
            Numbering::Single => plan_single(tail, first_seq, events),
            Numbering::Shared => plan_shared(tail, first_seq, events),
        }
    }
}

/// Rule 2 for a source with one numbering: the leading events found in the
/// current numbering with identical octets are already persisted; the rest
/// must all be new.
///
/// Spec: this module's rule 2; docs/questions/Q-445 items 2, 3.
fn plan_single(tail: &SourceTail, first_seq: u64, events: &[EventBytes]) -> Plan {
    let mut duplicates = 0usize;
    let mut new_seen = false;
    let mut last_head: Option<ChainHead> = None;
    for (offset, event) in events.iter().enumerate() {
        let Some(number) = number_at(first_seq, offset) else {
            return Plan::Refuse(ResendRefusal::Unverifiable);
        };
        let found = tail
            .current_numbering()
            .find(|remembered| remembered.source_seq == number);
        match found {
            Some(remembered) if remembered.digest != digest_of(event.as_bytes()) => {
                return Plan::Refuse(ResendRefusal::Mismatched);
            }
            // Persisted, after an event that was not: a hole.
            Some(_) if new_seen => return Plan::Refuse(ResendRefusal::Unverifiable),
            Some(remembered) => {
                duplicates = offset.saturating_add(1);
                last_head = remembered.record;
            }
            None => new_seen = true,
        }
    }
    if duplicates < events.len() {
        return Plan::Append { skip: duplicates };
    }
    // Wholly persisted: the head is known for the last event of every batch
    // appended and for every record read at start — which is where a
    // sender's resend ends.
    match last_head {
        Some(head) => Plan::AlreadyPersisted(head),
        None => Plan::Refuse(ResendRefusal::Unverifiable),
    }
}

/// A shared label: the leading events equal in number and digest to a
/// remembered event are duplicates; nothing is refused.
///
/// Spec: this module ("a source shared by several numberings");
/// docs/questions/Q-432 residual, Q-445 item 5.
fn plan_shared(tail: &SourceTail, first_seq: u64, events: &[EventBytes]) -> Plan {
    let append_all = Plan::Append { skip: 0 };
    let matches = |number: u64, digest: RecordHash| {
        tail.recent.iter().rev().filter(move |remembered| {
            remembered.source_seq == number && remembered.digest == digest
        })
    };
    let mut duplicates = 0usize;
    let mut last_head: Option<ChainHead> = None;
    for (offset, event) in events.iter().enumerate() {
        let Some(number) = number_at(first_seq, offset) else {
            break;
        };
        let digest = digest_of(event.as_bytes());
        let mut found = matches(number, digest).peekable();
        if found.peek().is_none() {
            break;
        }
        last_head = found.find_map(|remembered| remembered.record);
        duplicates = offset.saturating_add(1);
    }
    if duplicates == 0 {
        return append_all;
    }
    if duplicates < events.len() {
        return Plan::Append { skip: duplicates };
    }
    // Every event is a duplicate: acknowledge with the record holding the
    // last one if its head is known; otherwise append (twice, never zero).
    match last_head {
        Some(head) => Plan::AlreadyPersisted(head),
        None => append_all,
    }
}
