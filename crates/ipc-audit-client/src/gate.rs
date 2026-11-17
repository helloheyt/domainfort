//! The sender's audit gate — one implementation for every daemon that sends
//! events (keyd, the kdc, dird, admind) — and the proof that an intent was
//! acknowledged (docs/52 §3.11, task R6, decision A-102).
//!
//! # The class (docs/52 §3.11, C11 / C10)
//!
//! "A binding audit record is lost, forged or not flushed." Two instances
//! were documentation rules, not code:
//!
//! * **"act only after the intent is acknowledged"** (A-85: dird's decision
//!   event acknowledged ⇒ commit; A-86 / A-88: keyd's intent acknowledged ⇒
//!   key-state change). Nothing stopped a caller from performing the change
//!   before the acknowledgement — `directory_admin::Prepared` was `Clone`
//!   and `apply` took it with no proof (docs/52 N5);
//! * **"wait (bounded) for every queued event to be acknowledged at stop"**
//!   (Q-313, A-82, A-87) was repeated in four daemons, each with its own
//!   loop and its own report.
//!
//! # The root-level change
//!
//! * [`AckedIntent<T>`] — a value whose intent record auditd acknowledged.
//!   It can be obtained **only** from [`AuditGate::wait_acknowledged`], for
//!   a [`PendingIntent<T>`] that [`AuditGate::begin_intent`] made by
//!   committing **that same value's** intent record
//!   ([`IntentRecord::intent_event`]) into this gate's window, and only once
//!   an acknowledgement from auditd covering that record's sequence number
//!   reached this gate ([`AuditGate::acknowledge`] — called only by the one
//!   audit client, `crate::client`, with auditd's `Ack` on the verified
//!   connection, docs/50 §8.1: an `Ack` comes only after the sync). It is neither `Clone` nor constructible
//!   elsewhere, so a mutation entry point that takes `AckedIntent<T>` **by
//!   value** cannot be reached without the acknowledgement, and one proof
//!   serves one mutation. No acknowledgement in time ⇒ the value comes back
//!   without a proof (the caller records "not performed").
//! * [`AuditGate::close`] — the one bounded flush at stop: wait up to the
//!   grace ([`AUDIT_FLUSH_GRACE`] in every daemon) until every queued event
//!   is acknowledged — the [`FlushWait`] rule says whether a link that counts
//!   as unreachable ends the wait early (keyd, the kdc) or not (dird, A-87;
//!   admind) — then end the audit link, then report what auditd did not
//!   receive ([`Unflushed`]: the events still unacknowledged **and** the
//!   counts still held — docs/questions/Q-990 item 4, A-166; Q-995).
//!
//! # The gate itself
//!
//! The window ([`SendWindow`]) and the audit client's view of auditd
//! (reachable or not) behind one lock, plus a condition variable that
//! [`AuditGate::acknowledge`] signals. Every daemon keeps its own wrapper for
//! what is its own (which operations gate, its event shapes, the tokio wake-up
//! of its audit client) and delegates the rest here. Gating reservations are
//! refused while auditd counts as unreachable (A-67 item 2: stricter than the
//! window alone) or the window is full (A-57). A poisoned lock is "audit not
//! available": no slot, no proof, no acknowledgement (fail closed).
//!
//! Several commits that must happen under one lock (a gating operation with
//! more than one record) go through [`AuditGate::with_steps`], whose
//! [`WindowSteps`] can reserve, commit, release, offer noise and count — but
//! not acknowledge: the only way an acknowledgement reaches the window is
//! [`AuditGate::acknowledge`].
//!
//! # Only the audit client supplies the evidence (task R15b)
//!
//! The proof is only as strong as its evidence: "auditd is reachable" and
//! "auditd acknowledged through sequence number N". Both are facts of the
//! verified connection to auditd, whose one owner is the audit client
//! (`crate::client`, task R9b: peer uid and reported source verified on
//! every connection). So the link side of the gate — marking auditd
//! reachable ([`AuditGate::set_reachable`]), taking the batch to send
//! ([`AuditGate::next_batch`]; the client's step `AuditGate::next_send`,
//! which applies the summary pace), feeding auditd's `Ack`
//! ([`AuditGate::acknowledge`]) and putting a lost batch back
//! ([`AuditGate::connection_lost`]) — is **crate-private**: no code outside
//! this crate (a daemon, its gate wrapper, a library) can mark auditd
//! reachable or acknowledge anything, so no code outside the client can
//! mint an [`AckedIntent`]. A daemon's gate counts auditd as reachable from
//! the moment the client attaches a verified connection to it
//! (`client::AuditLink::attach`) until that link ends. Class: "a proof
//! type whose evidence can be supplied by someone other than its owner"
//! (docs/questions/Q-630). In-process tests of a daemon's gate (tier 1,
//! docs/50 §9: "in-process … without sockets") reach the link side only
//! through `test_seams`, which exists only with the dev-only feature
//! `test-seams` (docs/52 R15 rules; guard crates/e2e-tests
//! `tests/no_test_seams_in_product.rs`).
//!
//! # The summary pace: counters leave on the gate's clock (docs/questions/Q-989)
//!
//! A [`WindowSummary`](ipc_audit::WindowSummary) carries the window's
//! counters (noise counted, gating refused, outcomes not recorded — A-57,
//! A-88). The window queues one whenever a counter is non-zero, and the
//! audit client looks at the window again right after every acknowledged
//! batch; so a sender that counts straight into the window (dnsd's and
//! kpasswd-front's noise, A-160, A-165) sent, under continuous noise, one
//! summary per auditd acknowledgement — a rate set by auditd's persistence,
//! not by any rule of the sender's (A-57: noise "summarised in counters and
//! rate-limited"). Class: "a counter-only report is paced by the transport's
//! acknowledgements instead of by its own clock" (Q-989 item 2).
//!
//! The root change is in the one place every batch passes — the gate's
//! crate-private next step of the audit client (`AuditGate::next_send`): a
//! window that holds **only** counters (no event waiting) leaves as a
//! summary at most once per `SUMMARY_PACE` — the client's [`HEARTBEAT`],
//! one value — counted from the last summary the gate queued; until then
//! the client is told how long to wait. Events are never held: whenever an
//! event is waiting the batch goes at once, as before, and the counts held
//! ride in it (the summary costs no exchange of its own, and its rate is
//! bounded by the events', which A-57's noise share and the gating rules
//! already bound). So every sender — dnsd, kpasswd-front, keyd, the kdc,
//! dird, admind, any later one — gets the bound by construction; no sender
//! keeps a pace of its own. [`AuditGate::count_noise_n`] counts a held
//! number of occurrences in one step (Q-988 item 5). The stop's flush
//! ([`AuditGate::close`]) also waits, while auditd is reachable, for the
//! counts still held to leave as a summary, so the pace never holds counts
//! past a stop it could have delivered them in.
//!
//! # Every count that never reached auditd is in the stop's report (docs/questions/Q-995)
//!
//! The flush waits for held counts only while auditd is reachable and only
//! for the grace (A-166); before Q-995 the counts still held when it gave up
//! were in no report — [`Unflushed`] counted events only. Class: "a count
//! that never reached auditd is invisible at stop". The root change: the
//! value the one way to finish a gate returns ([`AuditGate::close`] →
//! [`Unflushed`]) holds every count the window still has
//! (`suppressed_noise`, `refused_gating`, `unrecorded_outcomes`) beside the
//! unacknowledged events (a summary already queued is one of those events),
//! read even through a poisoned lock; and its whole-report reading
//! ([`Unflushed::undelivered`]) yields each kind as an [`Undelivered`]
//! variant that every daemon maps onto a note with an exhaustive `match`.
//!
//! [`HEARTBEAT`]: crate::HEARTBEAT
//!
//! Spec: docs/52 §3.11 (R6 (a), (b)), §7 R6, §2 rows 20, 23, 38 (N5);
//! docs/50 R50-17, §3.6 (bounded waits), §8.1; docs/51 §5.7 item 2 (A-85);
//! docs/questions/Q-218 (A-57), Q-252 items 8, 9 (A-64), Q-260 item 2
//! (A-67), Q-313 (A-82), Q-350 item 11 (A-87), Q-365 (A-88), Q-560 /
//! A-115 (the follow-up), Q-570 §5 item a (A-118), Q-630; Q-961 item 5,
//! Q-988 items 4, 5, Q-989 (A-165), Q-990 item 4 (A-166), Q-995.

use core::future::Future;
use core::time::Duration;
use ipc_audit::{
    Ack, Append, EventBody, NoiseAdmission, Reservation, SendWindow, WindowConfig, WindowError,
    WindowFull,
};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::Instant;

/// How long a stop waits for auditd to acknowledge the window — the bound
/// every daemon used (keyd-daemon, kdc-daemon, directory-daemon,
/// admin-daemon: 5 s). Project choice (docs/questions/Q-313, A-82; Q-350
/// item 11).
pub const AUDIT_FLUSH_GRACE: Duration = Duration::from_secs(5);

/// How often [`AuditGate::close`] looks at the window while it waits — the
/// poll interval every daemon's stop used (10 ms). Project choice.
pub const FLUSH_POLL: Duration = Duration::from_millis(10);

/// The shortest interval between two summaries of a window that holds only
/// counters (module documentation, "The summary pace"): the audit client's
/// heartbeat — one value, so "at most one summary per heartbeat"
/// (docs/questions/Q-961 item 5) holds by construction.
/// Spec: A-57 ("rate-limited"); docs/questions/Q-989 item 3 (A-165).
const SUMMARY_PACE: Duration = crate::client::HEARTBEAT;

/// Process-wide source of gate identities, so that a [`PendingIntent`] is
/// only ever proved by the gate that committed its record.
static NEXT_GATE: AtomicU64 = AtomicU64::new(1);

/// A value whose intent must be recorded — and acknowledged by auditd —
/// before it is acted on: its intent record.
///
/// Implemented by the values a mutation entry point takes: dird's prepared
/// write (`directory_admin::Prepared`: its `Decision` event), the `Approve`
/// that completed a quorum (`directory_admin::QuorumStep`), keyd's admitted
/// key-state change (`ipc_keyd_server::KeyStateCall`: its intent record).
/// The record is derived from the value itself, so the acknowledged record
/// describes exactly the value the proof carries.
///
/// Spec: docs/52 §3.11 R6 (a); docs/51 §5.7 item 2 (A-85); docs/questions/
/// Q-365 (A-88).
pub trait IntentRecord {
    /// The event that records the intent (a `DirAdmin` decision, a `Keyd`
    /// intent).
    fn intent_event(&self) -> EventBody;
}

/// A value whose intent record is in the window, waiting for auditd's
/// acknowledgement ([`AuditGate::wait_acknowledged`]). Not `Clone`.
///
/// Spec: docs/52 §3.11 R6 (a).
#[must_use = "an intent in the window must be waited for: the proof or the value back"]
#[derive(Debug)]
pub struct PendingIntent<T> {
    gate: u64,
    seq: u64,
    value: T,
}

impl<T> PendingIntent<T> {
    /// The intent record's sequence number in the window.
    #[must_use]
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// The value (read only: it is acted on only through its proof).
    #[must_use]
    pub fn get(&self) -> &T {
        &self.value
    }
}

/// **The proof**: a value whose intent record auditd acknowledged —
/// persisted (docs/50 §8.1) — in the gate that committed it. Obtained only
/// from [`AuditGate::wait_acknowledged`]; not `Clone`, no other constructor.
/// A mutation entry point takes it by value (module documentation).
///
/// Spec: docs/52 §3.11 R6 (a), §7 R6; docs/51 §5.7 item 2 (A-85);
/// docs/questions/Q-365 (A-88).
#[derive(Debug)]
pub struct AckedIntent<T> {
    seq: u64,
    value: T,
}

impl<T> AckedIntent<T> {
    /// The acknowledged intent record's sequence number.
    #[must_use]
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// The value.
    #[must_use]
    pub fn get(&self) -> &T {
        &self.value
    }

    /// Consume the proof for the value: the step the proof guards (the
    /// mutation entry point that took the proof does this).
    #[must_use]
    pub fn into_inner(self) -> T {
        self.value
    }
}

/// Whether [`AuditGate::close`] stops waiting when the audit link counts
/// auditd as unreachable.
///
/// Spec: docs/questions/Q-350 item 11 (A-87: "dird keeps the full bounded
/// wait … keyd and the kdc keep their rule").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlushWait {
    /// Wait the whole grace for the acknowledgements, also while the link
    /// counts as unreachable — the audit link keeps reconnecting meanwhile,
    /// and a link that dropped just before the stop can still deliver
    /// (dird, A-87; admind, built with the same full wait).
    UntilAcknowledged,
    /// Stop waiting as soon as the link counts as unreachable: nothing
    /// would be delivered before a reconnect (keyd, the kdc — their rule
    /// kept by A-87).
    UntilAcknowledgedOrUnreachable,
}

/// One kind of audit data a stop could not deliver to auditd, with its count
/// — a part of [`Unflushed`] ([`Unflushed::undelivered`]). Counts only: no
/// event content, no secret.
///
/// Spec: docs/questions/Q-313 (A-82); docs/50 §8.1 (`WindowSummary` =
/// `suppressed_noise ‖ refused_gating ‖ unrecorded_outcomes`); A-57, A-88;
/// docs/questions/Q-990 item 4 (A-166), Q-995.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Undelivered {
    /// Events in the window auditd did not acknowledge, plus reservations
    /// still outstanding. A `WindowSummary` already queued is one of these
    /// events, with the counts it carries (they are not counted again
    /// below).
    Events(u64),
    /// Noise counted for a `WindowSummary` that never left the window
    /// (`suppressed_noise`).
    SuppressedNoise(u64),
    /// Gating reservations refused, counted for a `WindowSummary` that never
    /// left the window (`refused_gating`).
    RefusedGating(u64),
    /// Outcome records lost after their intent or decision was recorded,
    /// counted for a `WindowSummary` that never left the window
    /// (`unrecorded_outcomes`).
    UnrecordedOutcomes(u64),
}

impl Undelivered {
    /// The count of this kind.
    #[must_use]
    pub fn count(self) -> u64 {
        match self {
            Undelivered::Events(count)
            | Undelivered::SuppressedNoise(count)
            | Undelivered::RefusedGating(count)
            | Undelivered::UnrecordedOutcomes(count) => count,
        }
    }
}

/// What a stop could not deliver to auditd ([`AuditGate::close`], the only
/// way a stop finishes a gate): the events in the window (and reservations
/// still outstanding) when the audit link ended, **and** the counts the
/// window still held — never queued as a summary because the pace held
/// them past the grace, or auditd was unreachable, or the window was full.
/// Both are lost with the process (the bounded loss of docs/questions/Q-252
/// item 9). Every count the gate took is either acknowledged by auditd, in
/// an unacknowledged event here, or one of the counts here — none is
/// invisible at stop (class of docs/questions/Q-995).
///
/// Read it whole through [`Unflushed::undelivered`] — the stop's report, one
/// entry per kind, which each daemon maps onto its notes with an exhaustive
/// `match`, so a kind added later reaches every daemon's report or fails to
/// compile there.
///
/// Spec: docs/questions/Q-313 (A-82: "reports what was not acknowledged"),
/// Q-990 item 4 (A-166: counts that never left reported), Q-995.
#[must_use = "a stop reports what auditd did not receive"]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unflushed {
    events: usize,
    suppressed_noise: u64,
    refused_gating: u64,
    unrecorded_outcomes: u64,
}

impl Unflushed {
    /// The events part alone: events not acknowledged plus outstanding
    /// reservations (0 after a clean stop) — for a stop result that keeps
    /// that number; the counts that never left are in
    /// [`Unflushed::undelivered`].
    #[must_use]
    pub fn events(self) -> usize {
        self.events
    }

    /// Everything the stop could not deliver, one entry per kind whose count
    /// is not zero, in a fixed order (events, then the counts in
    /// `WindowSummary` order); empty after a clean stop. The stop's whole
    /// report.
    /// Spec: docs/questions/Q-313 (A-82), Q-990 item 4 (A-166), Q-995.
    pub fn undelivered(self) -> impl Iterator<Item = Undelivered> {
        [
            Undelivered::Events(u64::try_from(self.events).unwrap_or(u64::MAX)),
            Undelivered::SuppressedNoise(self.suppressed_noise),
            Undelivered::RefusedGating(self.refused_gating),
            Undelivered::UnrecordedOutcomes(self.unrecorded_outcomes),
        ]
        .into_iter()
        .filter(|part| part.count() > 0)
    }

    /// Whether nothing was lost: every event acknowledged, no reservation
    /// outstanding, no count held.
    #[must_use]
    pub fn is_clean(self) -> bool {
        self.undelivered().next().is_none()
    }
}

/// The steps a caller may take on the window under the gate's lock
/// ([`AuditGate::with_steps`]): reserve, commit, release, offer noise,
/// count a lost outcome. There is no acknowledgement here.
/// Spec: module documentation; docs/questions/Q-218 (A-57).
#[derive(Debug)]
pub struct WindowSteps<'g> {
    window: &'g mut SendWindow,
}

impl WindowSteps<'_> {
    /// [`SendWindow::reserve`].
    ///
    /// # Errors
    /// [`WindowFull`].
    pub fn reserve(&mut self) -> Result<Reservation, WindowFull> {
        self.window.reserve()
    }

    /// [`SendWindow::commit`].
    ///
    /// # Errors
    /// [`WindowError`].
    pub fn commit(
        &mut self,
        reservation: Reservation,
        event: &EventBody,
    ) -> Result<u64, WindowError> {
        self.window.commit(reservation, event)
    }

    /// [`SendWindow::release`].
    pub fn release(&mut self, reservation: Reservation) {
        self.window.release(reservation);
    }

    /// [`SendWindow::offer_noise`].
    ///
    /// # Errors
    /// [`WindowError`].
    pub fn offer_noise(&mut self, event: &EventBody) -> Result<NoiseAdmission, WindowError> {
        self.window.offer_noise(event)
    }

    /// [`SendWindow::count_unrecorded_outcome`].
    pub fn count_unrecorded_outcome(&mut self) {
        self.window.count_unrecorded_outcome();
    }
}

/// The window and the audit client's view of auditd.
#[derive(Debug)]
struct GateState {
    window: SendWindow,
    reachable: bool,
    /// When the gate last queued a summary of the window's counters (the
    /// summary pace — module documentation); `None` before the first.
    last_summary: Option<Instant>,
}

/// Whether `window` holds counts not yet queued as a summary.
/// Spec: docs/50 §8.1 (`WindowSummary`); A-57, A-88.
fn holds_counts(window: &SendWindow) -> bool {
    window.suppressed_noise() > 0 || window.refused_gating() > 0 || window.unrecorded_outcomes() > 0
}

/// Events of `window` not yet acknowledged plus its outstanding
/// reservations ([`AuditGate::outstanding`]).
fn outstanding_in(window: &SendWindow) -> usize {
    window
        .unacknowledged()
        .saturating_add(usize::try_from(window.reserved()).unwrap_or(usize::MAX))
}

/// The audit client's next step on the gate (`AuditGate::next_send`) —
/// crate-private, as the link side it belongs to.
/// Spec: docs/50 §3.6, §8.1; docs/questions/Q-630, Q-989 (A-165).
#[derive(Debug)]
pub(crate) enum NextSend {
    /// Send this batch now.
    Batch(Append),
    /// The window holds only counters and the last summary is younger than
    /// the pace: nothing to send for this long (never zero) unless an event
    /// is recorded meanwhile.
    Paced(Duration),
    /// Nothing to send.
    Idle,
}

/// The sender's audit gate (module documentation). Shared (`Arc`) by the
/// threads that run operations and the audit client task.
///
/// # Only the audit client opens the gate or acknowledges (task R15b)
///
/// Outside ipc-audit-client the link side does not exist: code in a daemon, its
/// gate wrapper or a library cannot mark auditd reachable, take or put back
/// a batch, or feed an `Ack` — so it cannot mint an [`AckedIntent`]
/// (docs/questions/Q-630). Each of these is a privacy error (E0624):
///
/// ```compile_fail,E0624
/// let gate = ipc_audit_client::AuditGate::new(ipc_audit::WindowConfig::DEFAULT);
/// gate.set_reachable(true);
/// ```
///
/// ```compile_fail,E0624
/// let gate = ipc_audit_client::AuditGate::new(ipc_audit::WindowConfig::DEFAULT);
/// let ack = ipc_audit::Ack { through_seq: 1, head_hash: [0; 32] };
/// let _ = gate.acknowledge(&ack);
/// ```
///
/// ```compile_fail,E0624
/// let gate = ipc_audit_client::AuditGate::new(ipc_audit::WindowConfig::DEFAULT);
/// let _ = gate.next_batch();
/// ```
///
/// ```compile_fail,E0624
/// let gate = ipc_audit_client::AuditGate::new(ipc_audit::WindowConfig::DEFAULT);
/// gate.connection_lost();
/// ```
///
/// ```compile_fail,E0624
/// let gate = ipc_audit_client::AuditGate::new(ipc_audit::WindowConfig::DEFAULT);
/// let _ = gate.next_send();
/// ```
///
/// The same code with the public API only compiles — a new gate is closed
/// until the client attaches a verified connection (positive control):
///
/// ```
/// let gate = ipc_audit_client::AuditGate::new(ipc_audit::WindowConfig::DEFAULT);
/// let _ack = ipc_audit::Ack { through_seq: 1, head_hash: [0; 32] };
/// assert!(!gate.is_reachable());
/// assert!(gate.reserve().is_none());
/// ```
///
/// Spec: docs/50 R50-17, §8.1; docs/questions/Q-218 (A-57); docs/52 §3.11
/// R6; docs/questions/Q-630.
#[derive(Debug)]
pub struct AuditGate {
    id: u64,
    state: Mutex<GateState>,
    /// Signalled by every acknowledgement; paired with `state`.
    acked: Condvar,
}

impl AuditGate {
    /// A gate over an empty window; auditd counts as unreachable until the
    /// audit client says otherwise (fail closed).
    #[must_use]
    pub fn new(window: WindowConfig) -> AuditGate {
        AuditGate {
            id: NEXT_GATE.fetch_add(1, Ordering::Relaxed),
            state: Mutex::new(GateState {
                window: SendWindow::new(window),
                reachable: false,
                last_summary: None,
            }),
            acked: Condvar::new(),
        }
    }

    /// The state, or `None` if a holder panicked (fail closed).
    fn lock(&self) -> Option<MutexGuard<'_, GateState>> {
        self.state.lock().ok()
    }

    /// Record the audit client's view of auditd — the client's only
    /// (crate-private, module documentation "Only the audit client supplies
    /// the evidence"): reachable exactly while it holds a verified
    /// connection. Spec: docs/50 §8.1; A-57, A-67 item 2; docs/questions/
    /// Q-560 (A-115), Q-630.
    pub(crate) fn set_reachable(&self, reachable: bool) {
        if let Some(mut state) = self.lock() {
            state.reachable = reachable;
        }
    }

    /// Whether auditd is reachable (the audit client's view).
    #[must_use]
    pub fn is_reachable(&self) -> bool {
        self.lock().is_some_and(|state| state.reachable)
    }

    /// Reserve one slot for a gating event, with auditd reachable; `None`
    /// otherwise — auditd unreachable, the window full (counted for the next
    /// `WindowSummary`), or a poisoned lock: the operation is not performed.
    /// Spec: docs/questions/Q-218 (A-57), Q-252 item 8 (A-64), Q-260 item 2
    /// (A-67).
    #[must_use]
    pub fn reserve(&self) -> Option<Reservation> {
        let mut state = self.lock()?;
        if !state.reachable {
            return None;
        }
        state.window.reserve().ok()
    }

    /// Reserve `count` slots — all or none — with auditd reachable; `None`
    /// otherwise (a refused reservation is counted for the next summary;
    /// nothing is left reserved).
    /// Spec: docs/questions/Q-365 item 6 (A-88: intent and outcome together),
    /// docs/51 §5.7 items 1-2 (A-85).
    #[must_use]
    pub fn reserve_all(&self, count: usize) -> Option<Vec<Reservation>> {
        let mut state = self.lock()?;
        if !state.reachable {
            return None;
        }
        let mut slots = Vec::with_capacity(count);
        for _ in 0..count {
            match state.window.reserve() {
                Ok(slot) => slots.push(slot),
                Err(WindowFull) => {
                    for slot in slots {
                        state.window.release(slot);
                    }
                    return None;
                }
            }
        }
        Some(slots)
    }

    /// Give back a slot whose event will not be produced.
    pub fn release(&self, reservation: Reservation) {
        if let Some(mut state) = self.lock() {
            state.window.release(reservation);
        }
    }

    /// Commit `event` into its reserved slot; its sequence number.
    ///
    /// # Errors
    /// The window's [`WindowError`]; [`WindowError::UnexpectedAck`] stands
    /// for a poisoned lock (nothing committed).
    ///
    /// Spec: docs/questions/Q-252 item 9 ("commit, then reply").
    pub fn commit(&self, reservation: Reservation, event: &EventBody) -> Result<u64, WindowError> {
        match self.lock() {
            Some(mut state) => state.window.commit(reservation, event),
            None => Err(WindowError::UnexpectedAck),
        }
    }

    /// Offer an unauthenticated noise event (queued within the noise share,
    /// otherwise counted; an encoding failure is counted too).
    /// Spec: docs/questions/Q-218 (A-57).
    pub fn offer_noise(&self, event: &EventBody) {
        if let Some(mut state) = self.lock() {
            let _ = state.window.offer_noise(event);
        }
    }

    /// Count one noise occurrence that has no event of its own (into the
    /// next `WindowSummary`'s `suppressed_noise`; no slot is taken) — the
    /// counters-only senders of docs/54 §9 (dnsd) and docs/53 §9
    /// (kpasswd-front). The summary leaves on the gate's pace (module
    /// documentation), whatever the rate of the counts.
    /// Spec: docs/questions/Q-218 (A-57); docs/54 §9; docs/questions/Q-961,
    /// Q-989; ipc-audit `SendWindow::count_noise`.
    pub fn count_noise(&self) {
        self.count_noise_n(1);
    }

    /// Count `occurrences` noise occurrences in one step (one lock, one
    /// addition — never one call per occurrence), for a sender that holds a
    /// count; saturating; 0 counts nothing.
    /// Spec: docs/questions/Q-218 (A-57); docs/questions/Q-988 item 5, Q-989
    /// item 3 (A-165); ipc-audit `SendWindow::count_noise_n`.
    pub fn count_noise_n(&self, occurrences: u64) {
        if let Some(mut state) = self.lock() {
            state.window.count_noise_n(occurrences);
        }
    }

    /// Count an outcome record that could not be committed after its intent
    /// or decision was recorded (into the next `WindowSummary`).
    /// Spec: decision A-88; docs/questions/Q-366 option (a), Q-395.
    pub fn count_unrecorded_outcome(&self) {
        if let Some(mut state) = self.lock() {
            state.window.count_unrecorded_outcome();
        }
    }

    /// Run `steps` on the window under the gate's lock (several commits as
    /// one step); `None` if the lock is poisoned.
    pub fn with_steps<R>(&self, steps: impl FnOnce(&mut WindowSteps<'_>) -> R) -> Option<R> {
        let mut state = self.lock()?;
        let mut window = WindowSteps {
            window: &mut state.window,
        };
        Some(steps(&mut window))
    }

    /// Read the window (its counters, for the daemon's own reports and
    /// tests); `None` if the lock is poisoned.
    pub fn inspect<R>(&self, read: impl FnOnce(&SendWindow) -> R) -> Option<R> {
        self.lock().map(|state| read(&state.window))
    }

    /// Commit `value`'s intent record ([`IntentRecord::intent_event`]) into
    /// `slot`, a slot reserved from this gate; the value, now waiting for
    /// auditd ([`AuditGate::wait_acknowledged`]).
    ///
    /// # Errors
    /// The value back (nothing committed; the slot is consumed) when the
    /// record could not be committed — cannot happen for a record built from
    /// this crate's types; a poisoned lock.
    ///
    /// Spec: docs/52 §3.11 R6 (a); docs/51 §5.7 item 2 (A-85);
    /// docs/questions/Q-365 (A-88).
    pub fn begin_intent<T: IntentRecord>(
        &self,
        slot: Reservation,
        value: T,
    ) -> Result<PendingIntent<T>, T> {
        let event = value.intent_event();
        match self.commit(slot, &event) {
            Ok(seq) => Ok(PendingIntent {
                gate: self.id,
                seq,
                value,
            }),
            Err(_) => Err(value),
        }
    }

    /// Wait until auditd acknowledged the intent record of `pending` — an
    /// `Ack` whose `through_seq` reaches its sequence number reached this
    /// gate (acknowledgements are cumulative and in order: one batch in
    /// flight, oldest first) — or `deadline` passed. Blocks the calling
    /// thread (an engine or admin thread, never a runtime's) on a condition
    /// variable the audit client's acknowledgement signals; never past
    /// `deadline`.
    ///
    /// # Errors
    /// The value back, **without a proof**: not acknowledged by `deadline`, a
    /// poisoned lock, or a `pending` this gate did not make (fail closed).
    /// The caller does not perform the change and records it as not
    /// performed.
    ///
    /// Spec: docs/52 §3.11 R6 (a); docs/51 §5.7 item 2 ("a decision event
    /// acknowledged by auditd before the commit"); docs/questions/Q-365 item
    /// 8 (A-88); docs/50 §3.6 (bounded waits), §8.1.
    pub fn wait_acknowledged<T>(
        &self,
        pending: PendingIntent<T>,
        deadline: Instant,
    ) -> Result<AckedIntent<T>, T> {
        let PendingIntent { gate, seq, value } = pending;
        if gate != self.id {
            return Err(value);
        }
        let Some(mut state) = self.lock() else {
            return Err(value);
        };
        loop {
            if state
                .window
                .last_ack()
                .is_some_and(|ack| ack.through_seq >= seq)
            {
                return Ok(AckedIntent { seq, value });
            }
            let left = match deadline.checked_duration_since(Instant::now()) {
                Some(left) if !left.is_zero() => left,
                _ => return Err(value),
            };
            state = match self.acked.wait_timeout(state, left) {
                Ok((guard, _)) => guard,
                Err(_) => return Err(value),
            };
        }
    }

    /// The next batch to send, if nothing is in flight and anything is
    /// pending — [`AuditGate::next_send`]'s batch, the summary pace applied
    /// (crate-private: a batch taken by anyone else would never reach
    /// auditd). The client itself takes [`AuditGate::next_send`] (it also
    /// needs the pace's wait); this form serves the tier-1 seams
    /// (`test_seams::next_batch`) and this crate's tests — and stays
    /// crate-private like the rest of the link side (the E0624 example on
    /// [`AuditGate`]). Spec: docs/50 §3.6, §8.1; docs/questions/Q-630, Q-989.
    #[cfg_attr(not(any(test, feature = "test-seams")), allow(dead_code))]
    #[must_use]
    pub(crate) fn next_batch(&self) -> Option<Append> {
        match self.next_send() {
            NextSend::Batch(append) => Some(append),
            NextSend::Paced(_) | NextSend::Idle => None,
        }
    }

    /// The audit client's next step — crate-private, the one way a batch
    /// leaves the gate; the summary pace (module documentation) lives here:
    ///
    /// * an event waiting (and nothing in flight) ⇒ the batch at once, with
    ///   the counts held riding in it as its summary — events never wait;
    /// * only counters held, and a summary queued less than `SUMMARY_PACE`
    ///   ago ⇒ [`NextSend::Paced`] for the rest of the pace;
    /// * only counters held otherwise ⇒ the batch of their one summary;
    /// * nothing (or a full window, or a poisoned lock) ⇒ [`NextSend::Idle`].
    ///
    /// Whenever a summary is queued, the gate notes when.
    ///
    /// Spec: docs/50 §3.6 (one request in flight), §8.1 (`WindowSummary`);
    /// A-57 ("summarised in counters and rate-limited"); docs/52 §3.11 R6
    /// (events, and so intents, are not held); docs/questions/Q-961 item 5,
    /// Q-989 item 3 (A-165), Q-630.
    pub(crate) fn next_send(&self) -> NextSend {
        let Some(mut state) = self.lock() else {
            return NextSend::Idle;
        };
        let now = Instant::now();
        let counted = holds_counts(&state.window);
        let events_waiting = state.window.unacknowledged() > 0;
        if counted && !events_waiting {
            if let Some(last) = state.last_summary {
                let since = now.saturating_duration_since(last);
                if let Some(left) = SUMMARY_PACE.checked_sub(since) {
                    if !left.is_zero() {
                        return NextSend::Paced(left);
                    }
                }
            }
        }
        let batch = state.window.next_batch();
        if counted && !holds_counts(&state.window) {
            state.last_summary = Some(now);
        }
        batch.map_or(NextSend::Idle, NextSend::Batch)
    }

    /// auditd's acknowledgement of the batch in flight — the audit client's
    /// only (crate-private), with the `Ack` auditd sent on the verified
    /// connection: the evidence [`AuditGate::wait_acknowledged`] turns into
    /// an [`AckedIntent`]. Wakes every thread waiting for an intent.
    ///
    /// # Errors
    /// The window's [`WindowError`] (an acknowledgement that does not match;
    /// the connection is then closed); `UnexpectedAck` for a poisoned lock.
    ///
    /// Spec: docs/50 §8.1; docs/52 §3.11 R6 (a); docs/questions/Q-560
    /// (A-115), Q-630.
    pub(crate) fn acknowledge(&self, ack: &Ack) -> Result<usize, WindowError> {
        let result = match self.lock() {
            Some(mut state) => state.window.acknowledge(ack),
            None => Err(WindowError::UnexpectedAck),
        };
        self.acked.notify_all();
        result
    }

    /// The audit connection dropped: the batch in flight goes back to the
    /// front — the audit client's (crate-private). Spec: docs/50 §3.7, §8.1;
    /// docs/questions/Q-630.
    pub(crate) fn connection_lost(&self) {
        if let Some(mut state) = self.lock() {
            state.window.connection_lost();
        }
    }

    /// Events not yet acknowledged plus outstanding reservations (0 for a
    /// poisoned lock: nothing can be delivered from it).
    #[must_use]
    pub fn outstanding(&self) -> usize {
        self.lock().map_or(0, |state| outstanding_in(&state.window))
    }

    /// Whether the stop's wait is over under `wait`: every queued event
    /// acknowledged and — while auditd is reachable, the only time they can
    /// leave — no counts held back by the summary pace; or, under
    /// [`FlushWait::UntilAcknowledgedOrUnreachable`], auditd unreachable. A
    /// poisoned lock: over (nothing can be delivered from it).
    /// Spec: docs/questions/Q-313 (A-82), Q-350 item 11 (A-87), Q-961 item
    /// 6, Q-988 item 1, Q-989 (A-165).
    fn flushed(&self, wait: FlushWait) -> bool {
        let Some(state) = self.lock() else {
            return true;
        };
        let summarised = !state.reachable || !holds_counts(&state.window);
        (outstanding_in(&state.window) == 0 && summarised)
            || (wait == FlushWait::UntilAcknowledgedOrUnreachable && !state.reachable)
    }

    /// **The stop's flush** (module documentation), the one implementation
    /// every daemon calls once it answered its requests in flight:
    ///
    /// 1. wait, at most `grace` ([`AUDIT_FLUSH_GRACE`] in every daemon),
    ///    looking every [`FLUSH_POLL`] (`sleep` is the caller's runtime's
    ///    timer), until every queued event is acknowledged and, while auditd
    ///    is reachable, the counts the summary pace still holds have left as
    ///    a summary (at most one pace away) — or, under
    ///    [`FlushWait::UntilAcknowledgedOrUnreachable`], the link counts as
    ///    unreachable; the audit link keeps running (and reconnecting)
    ///    meanwhile;
    /// 2. end the audit link (`end_link`: the daemon aborts its audit task
    ///    and awaits it);
    /// 3. report what auditd did not receive — the events still
    ///    unacknowledged and the counts still held ([`Unflushed`]) — lost
    ///    with the process.
    ///
    /// Spec: docs/questions/Q-313 (A-82: "waits, bounded, for auditd's
    /// acknowledgement of every queued audit event before closing, and
    /// reports what was not acknowledged"), Q-350 item 11 (A-87), Q-252 item
    /// 9, Q-961 item 6, Q-988 item 1, Q-989 (A-165), Q-990 item 4 (A-166),
    /// Q-995; docs/52 §3.11 R6 (b); docs/50 §3.6, §8.1.
    pub async fn close<S, F, E>(
        &self,
        grace: Duration,
        wait: FlushWait,
        mut sleep: S,
        end_link: E,
    ) -> Unflushed
    where
        S: FnMut(Duration) -> F,
        F: Future<Output = ()>,
        E: Future<Output = ()>,
    {
        let start = Instant::now();
        while !self.flushed(wait) && start.elapsed() < grace {
            sleep(FLUSH_POLL).await;
        }
        end_link.await;
        self.undelivered()
    }

    /// The stop's report ([`AuditGate::close`] step 3): the window's events
    /// not acknowledged plus its outstanding reservations, and the three
    /// counts it still holds. Read through a poisoned lock too: the report
    /// only reads, and a window a panicking holder left behind is lost, not
    /// delivered — reporting it as empty would hide the loss (fail closed
    /// toward visibility; Q-995).
    /// Spec: docs/questions/Q-313 (A-82), Q-990 item 4 (A-166), Q-995.
    fn undelivered(&self) -> Unflushed {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Unflushed {
            events: outstanding_in(&state.window),
            suppressed_noise: state.window.suppressed_noise(),
            refused_gating: state.window.refused_gating(),
            unrecorded_outcomes: state.window.unrecorded_outcomes(),
        }
    }
}

#[cfg(test)]
mod tests {
    //! Sources: docs/52 §3.11 R6 (the proof only after the acknowledgement of
    //! the same record; one flush for every daemon), docs/50 §8.1 (`Ack`
    //! after the sync, cumulative), docs/questions/Q-350 item 11 (A-87: the
    //! two wait rules). Every value is constructed for these tests.
    use super::*;
    use core::pin::pin;
    use core::task::{Context, Poll, Waker};
    use ipc_audit::WindowSummary;
    use std::sync::Arc;

    /// A value whose intent record is a summary carrying `n` (any event
    /// built from this crate's types serves).
    #[derive(Debug, PartialEq, Eq)]
    struct Change(u64);

    impl IntentRecord for Change {
        fn intent_event(&self) -> EventBody {
            EventBody::WindowSummary(WindowSummary {
                suppressed_noise: self.0,
                refused_gating: 0,
                unrecorded_outcomes: 0,
            })
        }
    }

    fn open_gate() -> AuditGate {
        let gate = AuditGate::new(WindowConfig::DEFAULT);
        gate.set_reachable(true);
        gate
    }

    /// Play auditd: take the batch in flight and acknowledge all of it.
    fn auditd_acknowledges(gate: &AuditGate) {
        let append = gate.next_batch().unwrap();
        let ack = Ack {
            through_seq: append.last_seq(),
            head_hash: [0; 32],
        };
        gate.acknowledge(&ack).unwrap();
    }

    fn soon() -> Instant {
        Instant::now() + Duration::from_millis(30)
    }

    /// Drive a future whose every inner future is ready at once (the tests'
    /// `sleep` blocks the thread and returns a ready future).
    fn run_ready<F: Future>(future: F) -> F::Output {
        let mut future = pin!(future);
        match future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            Poll::Ready(output) => output,
            Poll::Pending => panic!("the test's futures are all ready"),
        }
    }

    fn blocking_sleep(d: Duration) -> core::future::Ready<()> {
        std::thread::sleep(d);
        core::future::ready(())
    }

    /// R6 (a): the intent committed, auditd acknowledges it ⇒ the proof,
    /// carrying the same value and the record's number; the record in the
    /// window is the value's own intent record.
    #[test]
    fn an_acknowledged_intent_yields_the_proof() {
        let gate = open_gate();
        let slot = gate.reserve().unwrap();
        let pending = gate.begin_intent(slot, Change(7)).unwrap();
        assert_eq!(pending.seq(), 1);
        assert_eq!(pending.get(), &Change(7));
        let batch = gate.next_batch().unwrap();
        assert_eq!(
            ipc_audit::decode_event(batch.events()[0].as_bytes()).unwrap(),
            Change(7).intent_event()
        );
        gate.acknowledge(&Ack {
            through_seq: batch.last_seq(),
            head_hash: [0; 32],
        })
        .unwrap();
        let acked = gate.wait_acknowledged(pending, soon()).unwrap();
        assert_eq!(acked.seq(), 1);
        assert_eq!(acked.into_inner(), Change(7));
    }

    /// R6 (a): no acknowledgement by the deadline ⇒ the value back and no
    /// proof; the wait never outlives the deadline.
    #[test]
    fn no_acknowledgement_means_no_proof() {
        let gate = open_gate();
        let slot = gate.reserve().unwrap();
        let pending = gate.begin_intent(slot, Change(1)).unwrap();
        let started = Instant::now();
        assert_eq!(
            gate.wait_acknowledged(pending, soon()).unwrap_err(),
            Change(1)
        );
        assert!(started.elapsed() < Duration::from_secs(5));
        // Sent but not acknowledged: still no proof.
        let slot = gate.reserve().unwrap();
        let pending = gate.begin_intent(slot, Change(2)).unwrap();
        let _in_flight = gate.next_batch().unwrap();
        assert_eq!(
            gate.wait_acknowledged(pending, soon()).unwrap_err(),
            Change(2)
        );
    }

    /// R6 (a), "the same record": an acknowledgement of earlier records does
    /// not prove a later intent; a pending intent of another gate is never
    /// proved by this one (even with a higher acknowledgement there).
    #[test]
    fn only_the_acknowledgement_of_the_same_record_proves_it() {
        let gate = open_gate();
        let first = gate
            .begin_intent(gate.reserve().unwrap(), Change(1))
            .unwrap();
        auditd_acknowledges(&gate);
        let second = gate
            .begin_intent(gate.reserve().unwrap(), Change(2))
            .unwrap();
        assert!(gate.wait_acknowledged(first, soon()).is_ok());
        assert_eq!(
            gate.wait_acknowledged(second, soon()).unwrap_err(),
            Change(2)
        );

        let other = open_gate();
        let foreign = other
            .begin_intent(other.reserve().unwrap(), Change(3))
            .unwrap();
        auditd_acknowledges(&other);
        for _ in 0..3 {
            let _ = gate
                .begin_intent(gate.reserve().unwrap(), Change(0))
                .unwrap();
        }
        auditd_acknowledges(&gate);
        assert_eq!(
            gate.wait_acknowledged(foreign, soon()).unwrap_err(),
            Change(3)
        );
    }

    /// The acknowledgement arriving from another thread (the audit client)
    /// wakes the waiting thread before its deadline.
    #[test]
    fn the_wait_is_woken_by_the_acknowledgement() {
        let gate = Arc::new(open_gate());
        let pending = gate
            .begin_intent(gate.reserve().unwrap(), Change(9))
            .unwrap();
        let client = {
            let gate = Arc::clone(&gate);
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(20));
                auditd_acknowledges(&gate);
            })
        };
        let deadline = Instant::now() + Duration::from_secs(10);
        assert!(gate.wait_acknowledged(pending, deadline).is_ok());
        client.join().unwrap();
    }

    /// A-57 / A-67 item 2: auditd unreachable ⇒ no slot; `reserve_all` takes
    /// all or none and counts the refusal.
    #[test]
    fn reservations_need_auditd_and_are_all_or_none() {
        let gate = AuditGate::new(WindowConfig::new(2, 1).unwrap());
        assert!(gate.reserve().is_none());
        assert!(gate.reserve_all(2).is_none());
        gate.set_reachable(true);
        let one = gate.reserve().unwrap();
        assert!(gate.reserve_all(2).is_none());
        assert_eq!(gate.outstanding(), 1, "nothing left reserved");
        assert_eq!(gate.inspect(SendWindow::refused_gating), Some(1));
        gate.release(one);
        assert_eq!(gate.reserve_all(2).map(|slots| slots.len()), Some(2));
    }

    /// docs/54 §9 (dnsd: counters only); A-57: noise counted without an
    /// event is kept whether or not auditd is reachable, takes no slot (none
    /// is outstanding) and leaves in the next batch as one `WindowSummary`.
    /// Task DN12, docs/questions/Q-961.
    #[test]
    fn counted_noise_reaches_the_next_summary() {
        let gate = AuditGate::new(WindowConfig::DEFAULT);
        gate.count_noise();
        gate.count_noise();
        assert_eq!(gate.outstanding(), 0, "no slot taken");
        assert_eq!(gate.inspect(SendWindow::suppressed_noise), Some(2));
        gate.set_reachable(true);
        gate.count_noise();
        let append = gate.next_batch().unwrap();
        assert_eq!(append.events().len(), 1);
        assert_eq!(
            ipc_audit::decode_event(append.events()[0].as_bytes()).unwrap(),
            EventBody::WindowSummary(WindowSummary {
                suppressed_noise: 3,
                refused_gating: 0,
                unrecorded_outcomes: 0,
            })
        );
    }

    /// The events of `batch`, decoded.
    fn decoded(batch: &Append) -> Vec<EventBody> {
        batch
            .events()
            .iter()
            .map(|event| ipc_audit::decode_event(event.as_bytes()).unwrap())
            .collect()
    }

    /// A summary of `noise` counted noise and nothing else.
    fn noise_summary(noise: u64) -> EventBody {
        EventBody::WindowSummary(WindowSummary {
            suppressed_noise: noise,
            refused_gating: 0,
            unrecorded_outcomes: 0,
        })
    }

    fn ack_of(batch: &Append) -> Ack {
        Ack {
            through_seq: batch.last_seq(),
            head_hash: [0; 32],
        }
    }

    /// docs/questions/Q-989 (A-165; class "a counter-only report is paced by
    /// the transport's acknowledgements instead of by its own clock"), Q-961
    /// item 5 ("at most one summary per heartbeat"); A-57: a window that
    /// holds only counters is summarised at once the first time, then —
    /// although auditd acknowledged at once and new counts are held — not
    /// again before the pace (the heartbeat) has passed; the counts are kept
    /// meanwhile and the next summary carries all of them.
    #[test]
    fn a_window_of_counters_only_is_summarised_at_most_once_per_pace() {
        assert_eq!(SUMMARY_PACE, crate::client::HEARTBEAT, "one value");
        let gate = open_gate();
        gate.count_noise();
        let first = gate.next_batch().expect("the first summary is not held");
        assert_eq!(decoded(&first), [noise_summary(1)]);
        gate.acknowledge(&ack_of(&first)).unwrap();

        gate.count_noise_n(3);
        gate.count_noise();
        let NextSend::Paced(left) = gate.next_send() else {
            panic!("counters only, a summary just sent: held by the pace");
        };
        assert!(!left.is_zero() && left <= SUMMARY_PACE, "{left:?}");
        assert!(gate.next_batch().is_none(), "nothing before the pace");
        assert_eq!(gate.inspect(SendWindow::suppressed_noise), Some(4), "kept");
        std::thread::sleep(left);
        let second = gate.next_batch().expect("the pace has passed");
        assert_eq!(decoded(&second), [noise_summary(4)], "every count, once");
        gate.acknowledge(&ack_of(&second)).unwrap();
        assert!(
            matches!(gate.next_send(), NextSend::Idle),
            "nothing counted since"
        );
    }

    /// docs/52 §3.11 R6 (an intent's acknowledgement is not delayed);
    /// docs/questions/Q-989 item 3 ("gating events are untouched: they never
    /// wait"): while the pace holds counters, an event committed into the
    /// window leaves at once, first in its batch, with the held counts riding
    /// in it as its summary (no exchange of its own); that summary restarts
    /// the pace.
    #[test]
    fn an_event_is_never_held_by_the_pace() {
        let gate = open_gate();
        gate.count_noise();
        auditd_acknowledges(&gate);
        gate.count_noise_n(2);
        assert!(matches!(gate.next_send(), NextSend::Paced(_)));
        let pending = gate
            .begin_intent(gate.reserve().unwrap(), Change(70))
            .unwrap();
        let batch = gate.next_batch().expect("an event is never held");
        assert_eq!(
            decoded(&batch),
            [Change(70).intent_event(), noise_summary(2)]
        );
        gate.acknowledge(&ack_of(&batch)).unwrap();
        assert!(gate.wait_acknowledged(pending, soon()).is_ok());
        gate.count_noise();
        assert!(
            matches!(gate.next_send(), NextSend::Paced(_)),
            "the summary that rode with the event restarted the pace"
        );
    }

    /// docs/questions/Q-988 item 5, Q-989 item 3 (A-165: a bulk count): a
    /// held count enters the window in one step and adds up with single
    /// counts into one summary; 0 counts nothing.
    #[test]
    fn counted_noise_in_bulk_reaches_one_summary() {
        let gate = open_gate();
        gate.count_noise_n(0);
        assert!(
            matches!(gate.next_send(), NextSend::Idle),
            "0 counts nothing"
        );
        gate.count_noise_n(1_000);
        gate.count_noise();
        assert_eq!(gate.outstanding(), 0, "no slot taken");
        let batch = gate.next_batch().unwrap();
        assert_eq!(decoded(&batch), [noise_summary(1_001)]);
    }

    /// R6 (b), docs/questions/Q-961 item 6, Q-989: the pace never holds
    /// counts past a stop that could deliver them — with auditd reachable,
    /// the flush waits for the held counts' summary (here delivered by a
    /// thread playing the audit client once the pace allows it) and its
    /// acknowledgement; with auditd unreachable the counts cannot leave, and
    /// even the full wait (dird, admind) does not wait for them.
    #[test]
    fn close_waits_for_held_counts_only_while_auditd_is_reachable() {
        let gate = Arc::new(open_gate());
        gate.count_noise();
        auditd_acknowledges(&gate);
        gate.count_noise_n(5);
        assert!(matches!(gate.next_send(), NextSend::Paced(_)));
        let client = {
            let gate = Arc::clone(&gate);
            std::thread::spawn(move || loop {
                match gate.next_send() {
                    NextSend::Batch(batch) => {
                        gate.acknowledge(&ack_of(&batch)).unwrap();
                        return decoded(&batch);
                    }
                    NextSend::Paced(left) => std::thread::sleep(left),
                    NextSend::Idle => panic!("the counts are held"),
                }
            })
        };
        let started = Instant::now();
        let unflushed = run_ready(gate.close(
            Duration::from_secs(10),
            FlushWait::UntilAcknowledgedOrUnreachable,
            blocking_sleep,
            async {},
        ));
        assert_eq!(client.join().unwrap(), [noise_summary(5)]);
        assert!(unflushed.is_clean(), "{unflushed:?}");
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(gate.inspect(SendWindow::suppressed_noise), Some(0));

        for wait in [
            FlushWait::UntilAcknowledged,
            FlushWait::UntilAcknowledgedOrUnreachable,
        ] {
            let gate = open_gate();
            gate.count_noise();
            gate.set_reachable(false);
            let grace = Duration::from_millis(200);
            let started = Instant::now();
            let unflushed = run_ready(gate.close(grace, wait, blocking_sleep, async {}));
            assert_eq!(unflushed.events(), 0, "{wait:?}");
            // Q-990 item 4 (A-166), Q-995: not waited for, but reported.
            assert_eq!(
                unflushed.undelivered().collect::<Vec<_>>(),
                [Undelivered::SuppressedNoise(1)],
                "{wait:?}"
            );
            assert!(started.elapsed() < grace, "{wait:?}: not waited for");
        }
    }

    /// docs/questions/Q-990 item 4 (A-166: "reporting counts that never left
    /// in `Unflushed`"), Q-995 (class "a count that never reached auditd is
    /// invisible at stop"); A-57, A-88 (the three counts of a
    /// `WindowSummary`): every count the window still holds when the stop
    /// gives up is in the report, kind by kind, in `WindowSummary` order —
    /// (a) auditd unreachable, under both wait rules; (b) auditd reachable
    /// but the pace holding the counts past the grace; while (c) a summary
    /// already queued and not acknowledged is reported as the event it is,
    /// its counts not counted twice.
    #[test]
    fn close_reports_the_counts_that_never_left() {
        // (a) Noise, a refused reservation (a window of one slot, full) and
        // a lost outcome, then auditd gone.
        for wait in [
            FlushWait::UntilAcknowledged,
            FlushWait::UntilAcknowledgedOrUnreachable,
        ] {
            let gate = AuditGate::new(WindowConfig::new(1, 0).unwrap());
            gate.set_reachable(true);
            let slot = gate.reserve().unwrap();
            assert!(gate.reserve().is_none(), "full: refused and counted");
            gate.release(slot);
            gate.count_noise_n(2);
            gate.count_unrecorded_outcome();
            gate.set_reachable(false);
            let grace = Duration::from_millis(100);
            let unflushed = run_ready(gate.close(grace, wait, blocking_sleep, async {}));
            assert_eq!(
                unflushed.undelivered().collect::<Vec<_>>(),
                [
                    Undelivered::SuppressedNoise(2),
                    Undelivered::RefusedGating(1),
                    Undelivered::UnrecordedOutcomes(1),
                ],
                "{wait:?}"
            );
            assert_eq!(unflushed.events(), 0, "{wait:?}");
            assert!(!unflushed.is_clean(), "{wait:?}");
        }

        // (b) auditd reachable, the pace holding new counts, a grace shorter
        // than the pace and no client to send them: reported, not lost
        // silently.
        let gate = open_gate();
        gate.count_noise();
        auditd_acknowledges(&gate);
        gate.count_noise_n(4);
        assert!(matches!(gate.next_send(), NextSend::Paced(_)));
        let grace = Duration::from_millis(50);
        assert!(grace < SUMMARY_PACE);
        let unflushed = run_ready(gate.close(
            grace,
            FlushWait::UntilAcknowledgedOrUnreachable,
            blocking_sleep,
            async {},
        ));
        assert_eq!(
            unflushed.undelivered().collect::<Vec<_>>(),
            [Undelivered::SuppressedNoise(4)]
        );

        // (c) The summary already queued (in flight, not acknowledged): one
        // event, and no count beside it.
        let gate = open_gate();
        gate.count_noise_n(3);
        let in_flight = gate.next_batch().unwrap();
        assert_eq!(decoded(&in_flight), [noise_summary(3)]);
        gate.set_reachable(false);
        let unflushed = run_ready(gate.close(
            Duration::from_millis(100),
            FlushWait::UntilAcknowledgedOrUnreachable,
            blocking_sleep,
            async {},
        ));
        assert_eq!(
            unflushed.undelivered().collect::<Vec<_>>(),
            [Undelivered::Events(1)]
        );
        assert_eq!(unflushed.events(), 1);
    }

    /// docs/questions/Q-995 (the same class, a poisoned lock): a window whose
    /// lock a panicking holder poisoned can deliver nothing — the flush does
    /// not wait for it — and its events and counts are still in the report,
    /// not reported as delivered (before Q-995: 0).
    #[test]
    fn close_reports_a_poisoned_window_whole() {
        let gate = Arc::new(open_gate());
        for n in 0..2 {
            let slot = gate.reserve().unwrap();
            gate.commit(slot, &Change(n).intent_event()).unwrap();
        }
        gate.count_noise_n(3);
        let poisoner = {
            let gate = Arc::clone(&gate);
            std::thread::spawn(move || {
                gate.with_steps(|_| panic!("a holder panics: the gate's lock is poisoned"))
            })
        };
        assert!(poisoner.join().is_err());
        assert!(gate.reserve().is_none(), "poisoned: audit not available");
        let started = Instant::now();
        let unflushed = run_ready(gate.close(
            Duration::from_secs(10),
            FlushWait::UntilAcknowledged,
            blocking_sleep,
            async {},
        ));
        assert!(started.elapsed() < Duration::from_secs(5), "not waited for");
        assert_eq!(
            unflushed.undelivered().collect::<Vec<_>>(),
            [Undelivered::Events(2), Undelivered::SuppressedNoise(3)]
        );
    }

    /// R6 (b), Q-313: a clean stop — everything acknowledged — reports 0 and
    /// ends the link after the wait.
    #[test]
    fn close_after_everything_was_acknowledged_reports_nothing() {
        let gate = open_gate();
        let slot = gate.reserve().unwrap();
        gate.commit(slot, &Change(1).intent_event()).unwrap();
        auditd_acknowledges(&gate);
        let mut ended = false;
        let unflushed = run_ready(gate.close(
            Duration::from_secs(5),
            FlushWait::UntilAcknowledged,
            blocking_sleep,
            async {
                ended = true;
            },
        ));
        assert_eq!(unflushed.events(), 0);
        assert!(unflushed.is_clean());
        assert_eq!(unflushed.undelivered().count(), 0, "an empty report");
        assert!(ended);
    }

    /// R6 (b), A-87: the full wait (dird, admind) waits the grace even with
    /// the link unreachable, and reports what is left; the early-exit rule
    /// (keyd, the kdc) ends at once when the link is unreachable, with the
    /// same report.
    #[test]
    fn close_reports_what_is_left_under_both_rules() {
        let grace = Duration::from_millis(80);
        for (wait, waits_the_grace) in [
            (FlushWait::UntilAcknowledged, true),
            (FlushWait::UntilAcknowledgedOrUnreachable, false),
        ] {
            let gate = open_gate();
            for n in 0..3 {
                let slot = gate.reserve().unwrap();
                gate.commit(slot, &Change(n).intent_event()).unwrap();
            }
            gate.set_reachable(false);
            let started = Instant::now();
            let unflushed = run_ready(gate.close(grace, wait, blocking_sleep, async {}));
            assert_eq!(unflushed.events(), 3, "{wait:?}");
            assert_eq!(started.elapsed() >= grace, waits_the_grace, "{wait:?}");
        }
    }

    /// R6 (b): an acknowledgement arriving during the wait ends it early,
    /// and the report counts only what is left (here an outstanding
    /// reservation, as every daemon counted it).
    #[test]
    fn close_ends_when_auditd_acknowledges_during_the_wait() {
        let gate = Arc::new(open_gate());
        let slot = gate.reserve().unwrap();
        gate.commit(slot, &Change(1).intent_event()).unwrap();
        let client = {
            let gate = Arc::clone(&gate);
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(30));
                auditd_acknowledges(&gate);
            })
        };
        let started = Instant::now();
        let unflushed = run_ready(gate.close(
            Duration::from_secs(10),
            FlushWait::UntilAcknowledged,
            blocking_sleep,
            async {},
        ));
        client.join().unwrap();
        assert_eq!(unflushed.events(), 0);
        assert!(started.elapsed() < Duration::from_secs(5));
        let _held = gate.reserve().unwrap();
        let unflushed = run_ready(gate.close(
            Duration::from_millis(20),
            FlushWait::UntilAcknowledged,
            blocking_sleep,
            async {},
        ));
        assert_eq!(unflushed.events(), 1);
    }
}
