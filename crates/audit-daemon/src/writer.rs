//! The single writer: every connection funnels into one bounded queue, and
//! one thread owns the log, appends, syncs, rotates and answers.
//!
//! # Design
//!
//! * **One writer.** [`run`] owns the [`LogSink`] (the crates/audit-log
//!   [`LogWriter`] of the current segment). It runs on a dedicated OS thread
//!   — in the daemon, the main thread after start-up — because every batch
//!   ends in a blocking sync (docs/50 §3.6: an engine thread fed by a bounded
//!   queue, the reply in a `oneshot`; no `spawn_blocking`, whose queue has no
//!   back-pressure).
//! * **Bounded queue.** Connection tasks hand an [`AppendJob`] to
//!   [`Submitter::submit`], which never waits: a full queue is
//!   [`SubmitError::Busy`] at once, and the connection answers
//!   `Refused::Busy`. The sender's window keeps the events and keeps its
//!   issuance gated (docs/questions/Q-218, A-57: "no unaudited issuance, and
//!   log overflow does not turn into shutdown").
//! * **Acknowledge after sync.** A job is answered
//!   [`JobOutcome::Persisted`] only with the head [`LogWriter::append_batch`]
//!   returned — which it returns only after the batch was synced
//!   (docs/50 §8.1: "auditd acknowledges the last sequence number
//!   persisted"). Every record of a batch carries auditd's own clock, read
//!   once per batch (docs/50 R50-17, §3.5).
//! * **Rotation.** [`AppendError::SegmentFull`] is not an error to the
//!   sender: the writer creates the next segment file anchored at the
//!   current head, calls the signing hook, and appends again
//!   (docs/questions/Q-250 item 6; docs/07 §8). Retention is not implemented
//!   (OD-8 gives no numbers — docs/questions/Q-265 item 6).
//! * **Fail closed.** A failed write, flush or sync poisons the
//!   [`LogWriter`] (its tail is unknown). The writer then answers
//!   `Unavailable`, marks itself unavailable (so `Ping` is refused) and
//!   returns [`WriterFailure`]; the daemon exits and the service manager's
//!   restart runs the start-up verification and torn-tail recovery
//!   ([`crate::recovery`]) — never a retry that could report an unsynced
//!   batch as persisted (docs/questions/Q-265 item 7).
//! * **Refused connections** are counted by the listener ([`PeerRefusals`])
//!   and written by the writer as one `Auditd` summary record at most every
//!   [`SUMMARY_INTERVAL`] (docs/50 §3.2: "closed + an audit record";
//!   A-57: noise "summarised in counters"). Batches refused by the source
//!   binding of the event shapes (crate::binding) are counted and
//!   summarised the same way, in their own `EventsMisbound` record.
//!
//! Spec: docs/50 R50-7, R50-17, §3.6, §8.1; docs/37 §2; docs/07 §8;
//! docs/questions/Q-218 (A-57), Q-250 (A-64), Q-265.

use crate::own_event::{AuditdEvent, EventsMisbound, PeersRefused};
use crate::segments::SegmentFactory;
use crate::signing::{NoSignature, UnsignedHeads};
use audit_log::{AppendError, ChainHead, Entry, LogWriter, Persisted, Source, Timestamp};
use core::fmt;
use ipc_audit::EventBytes;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::oneshot;

/// Jobs the queue holds before [`Submitter::submit`] answers `Busy`. Project
/// choice: docs/50 gives no number for auditd (docs/questions/Q-230 item 4 →
/// A-60: "limits without a number in docs/50 are constants in the daemon";
/// docs/questions/Q-265 item 5).
pub const QUEUE_CAPACITY: usize = 8;

/// The shortest time between two refused-connection summaries, and the
/// longest a pending count waits. Project choice (docs/questions/Q-265
/// item 8).
pub const SUMMARY_INTERVAL: Duration = Duration::from_secs(1);

/// One `Append` to persist: its events, the connection's identity, and where
/// the answer goes.
///
/// `source` and `source_uid` come from the connection's peer credentials,
/// never from the payload (docs/50 §3.2).
///
/// Spec: docs/50 §3.2, §8.1; ipc-audit `Append`.
pub struct AppendJob {
    /// The sending process, from the `uid → source` map.
    pub source: Source,
    /// The connection's peer uid.
    pub source_uid: u32,
    /// The sender's number of the first event.
    pub first_source_seq: u64,
    /// The events (1 ..= 16, each 1 ..= 8192 octets — ipc-audit `Append`).
    pub events: Vec<EventBytes>,
    /// Where the outcome goes.
    pub reply: oneshot::Sender<JobOutcome>,
}

impl fmt::Debug for AppendJob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Event octets are never printed (docs/50 §8.2).
        f.debug_struct("AppendJob")
            .field("source", &self.source)
            .field("source_uid", &self.source_uid)
            .field("first_source_seq", &self.first_source_seq)
            .field("events", &self.events.len())
            .finish()
    }
}

/// What the writer did with a job.
///
/// Spec: docs/50 §8.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobOutcome {
    /// Every event is on stable storage; the head is the record holding the
    /// last event.
    Persisted(ChainHead),
    /// Nothing is acknowledged (the connection answers `Unavailable`).
    Unavailable,
}

/// Why a job was not queued.
///
/// Spec: docs/50 §3.6 ("queue full ⇒ an immediate `Busy`"), §3.7.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubmitError {
    /// The queue is full.
    Busy,
    /// The writer is gone or has failed.
    Unavailable,
}

/// Why the writer stopped. The daemon exits on either (fail closed); the
/// restart's start-up verification handles the segment's tail.
///
/// Spec: docs/questions/Q-250 item 7 (a poisoned writer refuses
/// everything); docs/questions/Q-265 item 7.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriterFailure {
    /// A write, flush or sync failed: the segment's tail is unknown.
    Poisoned,
    /// A new segment file was created for rotation but its header could not
    /// be written and synced.
    RotationTorn,
}

impl fmt::Display for WriterFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            WriterFailure::Poisoned => "audit log write failed",
            WriterFailure::RotationTorn => "audit log rotation failed after creating a segment",
        })
    }
}

impl std::error::Error for WriterFailure {}

/// Why one persist attempt failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersistError {
    /// This attempt failed and nothing was written; the writer can go on.
    Unavailable,
    /// The writer must stop.
    Fatal(WriterFailure),
}

/// Refused connections not yet recorded. The listener counts; the writer
/// records a summary.
///
/// Spec: docs/50 §3.2, R50-3; docs/questions/Q-218 (A-57);
/// docs/questions/Q-265 item 8.
#[derive(Debug, Default)]
pub struct PeerRefusals {
    unmapped: AtomicU64,
    over_quota: AtomicU64,
    last_uid: AtomicU32,
    /// Batches refused by the source binding (crate::binding), and the uid
    /// of the last one.
    misbound: AtomicU64,
    misbound_uid: AtomicU32,
}

/// Add one to a counter without wrapping.
fn bump(counter: &AtomicU64, by: u64) {
    // `fetch_update` with a closure that always returns `Some` cannot fail.
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
        Some(n.saturating_add(by))
    });
}

impl PeerRefusals {
    /// Count a connection from an unmapped uid.
    pub fn count_unmapped(&self, uid: u32) {
        self.last_uid.store(uid, Ordering::Relaxed);
        bump(&self.unmapped, 1);
    }

    /// Count a connection over its source's quota.
    pub fn count_over_quota(&self, uid: u32) {
        self.last_uid.store(uid, Ordering::Relaxed);
        bump(&self.over_quota, 1);
    }

    /// Count an `Append` refused because an event's shape may not come from
    /// the connection's source (crate::binding).
    /// Spec: docs/51 §5.7; docs/questions/Q-341.
    pub fn count_misbound(&self, uid: u32) {
        self.misbound_uid.store(uid, Ordering::Relaxed);
        bump(&self.misbound, 1);
    }

    /// Take the misbound-batch count (resetting it), if any.
    fn take_misbound(&self) -> Option<EventsMisbound> {
        let refused_batches = self.misbound.swap(0, Ordering::Relaxed);
        (refused_batches > 0).then(|| EventsMisbound {
            refused_batches,
            last_uid: self.misbound_uid.load(Ordering::Relaxed),
        })
    }

    /// Put back a misbound-batch count that could not be recorded.
    fn restore_misbound(&self, summary: EventsMisbound) {
        bump(&self.misbound, summary.refused_batches);
    }

    /// Take the counts (resetting them), if any connection was refused.
    fn take(&self) -> Option<PeersRefused> {
        let unmapped = self.unmapped.swap(0, Ordering::Relaxed);
        let over_quota = self.over_quota.swap(0, Ordering::Relaxed);
        (unmapped > 0 || over_quota > 0).then(|| PeersRefused {
            unmapped,
            over_quota,
            last_uid: self.last_uid.load(Ordering::Relaxed),
        })
    }

    /// Put back counts that could not be recorded.
    fn restore(&self, summary: PeersRefused) {
        bump(&self.unmapped, summary.unmapped);
        bump(&self.over_quota, summary.over_quota);
    }
}

/// State shared by the submitters and the writer.
#[derive(Debug)]
struct Shared {
    available: AtomicBool,
    refusals: PeerRefusals,
}

/// The connections' end of the queue. Cheap to clone (one per connection).
///
/// Spec: docs/50 §3.6 (bounded queue, `Busy` when full).
#[derive(Debug, Clone)]
pub struct Submitter {
    queue: SyncSender<AppendJob>,
    shared: Arc<Shared>,
}

impl Submitter {
    /// Queue `job` without waiting.
    ///
    /// # Errors
    /// [`SubmitError::Busy`] when the queue is full;
    /// [`SubmitError::Unavailable`] when the writer has stopped or failed.
    ///
    /// Spec: docs/50 §3.6 ("immediate `Busy` — not `spawn_blocking`");
    /// docs/questions/Q-218 (A-57).
    pub fn submit(&self, job: AppendJob) -> Result<(), SubmitError> {
        if !self.is_available() {
            return Err(SubmitError::Unavailable);
        }
        match self.queue.try_send(job) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => Err(SubmitError::Busy),
            Err(TrySendError::Disconnected(_)) => Err(SubmitError::Unavailable),
        }
    }

    /// Whether the writer is running and not failed (the `Ping` answer).
    /// Spec: docs/50 §7.5.
    #[must_use]
    pub fn is_available(&self) -> bool {
        self.shared.available.load(Ordering::Relaxed)
    }

    /// The refused-connection counters.
    #[must_use]
    pub fn refusals(&self) -> &PeerRefusals {
        &self.shared.refusals
    }
}

/// The writer's end of the queue.
#[derive(Debug)]
pub struct Inbox {
    queue: Receiver<AppendJob>,
    shared: Arc<Shared>,
}

/// A queue of `capacity` jobs (at least 1).
///
/// Spec: docs/50 §3.6 (a bounded queue).
#[must_use]
pub fn queue(capacity: usize) -> (Submitter, Inbox) {
    let (sender, receiver) = sync_channel(capacity.max(1));
    let shared = Arc::new(Shared {
        available: AtomicBool::new(true),
        refusals: PeerRefusals::default(),
    });
    (
        Submitter {
            queue: sender,
            shared: Arc::clone(&shared),
        },
        Inbox {
            queue: receiver,
            shared,
        },
    )
}

/// The log as the writer holds it: the current segment's [`LogWriter`], its
/// number, the factory for the next one, and auditd's own identity for its
/// records.
///
/// Spec: docs/50 R50-17, §8.1; docs/questions/Q-250 items 5, 6.
pub struct LogSink<F: SegmentFactory> {
    writer: LogWriter<F::Storage>,
    segment: u64,
    factory: F,
    own_uid: u32,
    own_seq: u64,
    signer: UnsignedHeads,
}

impl<F: SegmentFactory> fmt::Debug for LogSink<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LogSink")
            .field("writer", &self.writer)
            .field("segment", &self.segment)
            .field("own_uid", &self.own_uid)
            .field("own_seq", &self.own_seq)
            .finish()
    }
}

impl<F: SegmentFactory> LogSink<F> {
    /// A sink appending to `writer`, which writes segment `segment`; new
    /// segments come from `factory`; auditd's records carry `own_uid`.
    #[must_use]
    pub fn new(writer: LogWriter<F::Storage>, segment: u64, factory: F, own_uid: u32) -> Self {
        LogSink {
            writer,
            segment,
            factory,
            own_uid,
            own_seq: 0,
            signer: UnsignedHeads,
        }
    }

    /// The persisted head.
    #[must_use]
    pub fn head(&self) -> ChainHead {
        self.writer.head()
    }

    /// The current segment's number.
    #[must_use]
    pub fn segment(&self) -> u64 {
        self.segment
    }

    /// Append one batch of a sender's events (numbered from
    /// `first_source_seq`) and sync it.
    ///
    /// # Errors
    /// [`PersistError`].
    ///
    /// Spec: docs/50 §3.2 (source from the transport), §8.1.
    pub fn append_events(
        &mut self,
        source: Source,
        source_uid: u32,
        first_source_seq: u64,
        events: &[EventBytes],
    ) -> Result<Persisted, PersistError> {
        let entries: Vec<Entry<'_>> = (0u64..)
            .zip(events)
            .map(|(offset, event)| Entry {
                source,
                source_uid,
                source_seq: first_source_seq.saturating_add(offset),
                payload: event.as_bytes(),
            })
            .collect();
        self.persist(&entries)
    }

    /// Append one of auditd's own records (source `Auditd`, auditd's uid,
    /// auditd's own counter) and sync it.
    ///
    /// # Errors
    /// [`PersistError`].
    ///
    /// Spec: docs/questions/Q-250 item 5 (`Auditd`), item 8.
    pub fn append_own(&mut self, event: &AuditdEvent) -> Result<Persisted, PersistError> {
        let next = self.own_seq.saturating_add(1);
        let payload = event.encode();
        let entry = Entry {
            source: Source::Auditd,
            source_uid: self.own_uid,
            source_seq: next,
            payload: &payload,
        };
        let persisted = self.persist(core::slice::from_ref(&entry))?;
        self.own_seq = next;
        Ok(persisted)
    }

    /// Append `entries` as one batch at auditd's clock; on `SegmentFull`,
    /// rotate and append again.
    ///
    /// Spec: docs/50 R50-17 (auditd's clock), §8.1; docs/questions/Q-250
    /// items 6, 7.
    fn persist(&mut self, entries: &[Entry<'_>]) -> Result<Persisted, PersistError> {
        let time = Timestamp::now().map_err(|_| PersistError::Unavailable)?;
        match self.writer.append_batch(entries, time) {
            Err(AppendError::SegmentFull) => {
                self.rotate()?;
                self.writer
                    .append_batch(entries, time)
                    .map_err(Self::classify)
            }
            other => other.map_err(Self::classify),
        }
    }

    /// What an append refusal means for the writer.
    fn classify(error: AppendError) -> PersistError {
        match error {
            AppendError::Poisoned | AppendError::Io(_) => {
                PersistError::Fatal(WriterFailure::Poisoned)
            }
            // Nothing was written; the next job may succeed. (SegmentFull
            // here means a fresh segment refused one batch, which the
            // segment bound rules out — still not acknowledged.)
            AppendError::SegmentFull
            | AppendError::EmptyBatch
            | AppendError::BatchTooLarge
            | AppendError::PayloadOutOfBounds { .. }
            | AppendError::SequenceExhausted
            | AppendError::ResumeOverLimit => PersistError::Unavailable,
        }
    }

    /// Start the next segment, anchored at the current head, and switch to
    /// it.
    ///
    /// A file that cannot be created is a transient refusal (nothing exists
    /// yet; the next batch retries). A file created whose header cannot be
    /// synced is fatal: the next number is now taken by a torn file, which
    /// the restart's recovery handles (docs/questions/Q-265 item 7).
    ///
    /// Spec: docs/questions/Q-250 item 6; docs/07 §8; docs/questions/Q-251
    /// (sign at every rotation).
    fn rotate(&mut self) -> Result<(), PersistError> {
        let next = self
            .segment
            .checked_add(1)
            .ok_or(PersistError::Unavailable)?;
        let storage = self
            .factory
            .create(next)
            .map_err(|_| PersistError::Unavailable)?;
        match self.writer.rotate(storage) {
            // The previous segment's storage is dropped here, closing it.
            Ok(_previous) => {}
            Err(AppendError::Poisoned) => return Err(PersistError::Fatal(WriterFailure::Poisoned)),
            Err(_) => return Err(PersistError::Fatal(WriterFailure::RotationTorn)),
        }
        self.segment = next;
        self.sign_head();
        Ok(())
    }

    /// Call the signing hook with the persisted head
    /// ([`crate::signing::SigningMode::Unsigned`]: nothing is signed or
    /// stored).
    ///
    /// Spec: docs/37 §2, D157; docs/questions/Q-251 (P-20).
    pub fn sign_head(&mut self) {
        let Ok(NoSignature) = self.writer.sign_head(&mut self.signer);
    }
}

/// Run the writer until every [`Submitter`] is gone (`Ok`) or the log fails
/// ([`WriterFailure`]). Blocks the calling thread.
///
/// # Errors
/// [`WriterFailure`]: the job in hand is answered `Unavailable`, the queue
/// is dropped (its jobs' connections answer `Unavailable`), and `Ping` is
/// refused from then on.
///
/// Spec: this module's design; docs/50 §3.6, §8.1; docs/questions/Q-218
/// (A-57); docs/questions/Q-265 items 5, 7, 8.
pub fn run<F: SegmentFactory>(mut sink: LogSink<F>, inbox: Inbox) -> Result<(), WriterFailure> {
    let mut last_summary: Option<Instant> = None;
    let result = loop {
        match inbox.queue.recv_timeout(SUMMARY_INTERVAL) {
            Ok(job) => {
                let outcome = sink.append_events(
                    job.source,
                    job.source_uid,
                    job.first_source_seq,
                    &job.events,
                );
                // A dropped receiver means the connection closed: the batch
                // is persisted anyway, and the sender resends it (Q-252
                // item 7: twice, never zero times).
                match outcome {
                    Ok(persisted) => {
                        let _ = job.reply.send(JobOutcome::Persisted(persisted.head));
                    }
                    Err(PersistError::Unavailable) => {
                        let _ = job.reply.send(JobOutcome::Unavailable);
                    }
                    Err(PersistError::Fatal(failure)) => {
                        inbox.shared.available.store(false, Ordering::Relaxed);
                        let _ = job.reply.send(JobOutcome::Unavailable);
                        break Err(failure);
                    }
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break Ok(()),
        }
        if let Err(failure) = record_refusals(&mut sink, &inbox.shared.refusals, &mut last_summary)
        {
            break Err(failure);
        }
    };
    if result.is_err() {
        inbox.shared.available.store(false, Ordering::Relaxed);
    }
    result
}

/// Write a refused-connection summary if any connection was refused, and a
/// misbound-batch summary if any batch was refused by the source binding,
/// when the last summary is at least [`SUMMARY_INTERVAL`] old.
///
/// Spec: docs/50 §3.2; docs/questions/Q-218 (A-57); docs/questions/Q-265
/// item 8; docs/51 §5.7; docs/questions/Q-341.
fn record_refusals<F: SegmentFactory>(
    sink: &mut LogSink<F>,
    refusals: &PeerRefusals,
    last_summary: &mut Option<Instant>,
) -> Result<(), WriterFailure> {
    if last_summary.is_some_and(|at| at.elapsed() < SUMMARY_INTERVAL) {
        return Ok(());
    }
    let mut recorded = false;
    if let Some(summary) = refusals.take() {
        match sink.append_own(&AuditdEvent::PeersRefused(summary)) {
            Ok(_) => recorded = true,
            Err(PersistError::Unavailable) => refusals.restore(summary),
            Err(PersistError::Fatal(failure)) => return Err(failure),
        }
    }
    if let Some(summary) = refusals.take_misbound() {
        match sink.append_own(&AuditdEvent::EventsMisbound(summary)) {
            Ok(_) => recorded = true,
            Err(PersistError::Unavailable) => refusals.restore_misbound(summary),
            Err(PersistError::Fatal(failure)) => return Err(failure),
        }
    }
    if recorded {
        *last_summary = Some(Instant::now());
    }
    Ok(())
}
