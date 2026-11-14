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
//!   reached this gate ([`AuditGate::acknowledge`] — called by the daemon's
//!   audit client with auditd's verified `Ack`, docs/50 §8.1: an `Ack`
//!   comes only after the sync). It is neither `Clone` nor constructible
//!   elsewhere, so a mutation entry point that takes `AckedIntent<T>` **by
//!   value** cannot be reached without the acknowledgement, and one proof
//!   serves one mutation. No acknowledgement in time ⇒ the value comes back
//!   without a proof (the caller records "not performed").
//! * [`AuditGate::close`] — the one bounded flush at stop: wait up to the
//!   grace ([`AUDIT_FLUSH_GRACE`] in every daemon) until every queued event
//!   is acknowledged — the [`FlushWait`] rule says whether a link that counts
//!   as unreachable ends the wait early (keyd, the kdc) or not (dird, A-87;
//!   admind) — then end the audit link, then report what is still
//!   unacknowledged ([`Unflushed`]).
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
//! Spec: docs/52 §3.11 (R6 (a), (b)), §7 R6, §2 rows 20, 23, 38 (N5);
//! docs/50 R50-17, §3.6 (bounded waits), §8.1; docs/51 §5.7 item 2 (A-85);
//! docs/questions/Q-218 (A-57), Q-252 items 8, 9 (A-64), Q-260 item 2
//! (A-67), Q-313 (A-82), Q-350 item 11 (A-87), Q-365 (A-88).

use crate::channel::{Ack, Append};
use crate::event::EventBody;
use crate::window::{
    NoiseAdmission, Reservation, SendWindow, WindowConfig, WindowError, WindowFull,
};
use core::future::Future;
use core::time::Duration;
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

/// What a stop left unacknowledged ([`AuditGate::close`]): events in the
/// window (and reservations still outstanding) when the audit link ended —
/// lost with the process (the bounded loss of docs/questions/Q-252 item 9).
///
/// Spec: docs/questions/Q-313 (A-82: "reports what was not acknowledged").
#[must_use = "a stop reports what auditd did not acknowledge"]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unflushed {
    events: usize,
}

impl Unflushed {
    /// Events not acknowledged plus outstanding reservations (0 after a
    /// clean stop).
    #[must_use]
    pub fn events(self) -> usize {
        self.events
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
}

/// The sender's audit gate (module documentation). Shared (`Arc`) by the
/// threads that run operations and the audit client task.
///
/// Spec: docs/50 R50-17, §8.1; docs/questions/Q-218 (A-57); docs/52 §3.11
/// R6.
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
            }),
            acked: Condvar::new(),
        }
    }

    /// The state, or `None` if a holder panicked (fail closed).
    fn lock(&self) -> Option<MutexGuard<'_, GateState>> {
        self.state.lock().ok()
    }

    /// Record the audit client's view of auditd.
    pub fn set_reachable(&self, reachable: bool) {
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
    /// variable [`AuditGate::acknowledge`] signals; never past `deadline`.
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
    /// pending. Spec: docs/50 §3.6, §8.1.
    #[must_use]
    pub fn next_batch(&self) -> Option<Append> {
        self.lock().and_then(|mut state| state.window.next_batch())
    }

    /// auditd's acknowledgement of the batch in flight — for the daemon's
    /// audit client only, with the `Ack` auditd sent on the verified
    /// connection. Wakes every thread waiting for an intent
    /// ([`AuditGate::wait_acknowledged`]).
    ///
    /// # Errors
    /// The window's [`WindowError`] (an acknowledgement that does not match;
    /// the connection is then closed); `UnexpectedAck` for a poisoned lock.
    ///
    /// Spec: docs/50 §8.1.
    pub fn acknowledge(&self, ack: &Ack) -> Result<usize, WindowError> {
        let result = match self.lock() {
            Some(mut state) => state.window.acknowledge(ack),
            None => Err(WindowError::UnexpectedAck),
        };
        self.acked.notify_all();
        result
    }

    /// The audit connection dropped: the batch in flight goes back to the
    /// front. Spec: docs/50 §3.7, §8.1.
    pub fn connection_lost(&self) {
        if let Some(mut state) = self.lock() {
            state.window.connection_lost();
        }
    }

    /// Events not yet acknowledged plus outstanding reservations (0 for a
    /// poisoned lock: nothing can be delivered from it).
    #[must_use]
    pub fn outstanding(&self) -> usize {
        self.lock().map_or(0, |state| {
            state
                .window
                .unacknowledged()
                .saturating_add(usize::try_from(state.window.reserved()).unwrap_or(usize::MAX))
        })
    }

    /// Whether the stop's wait is over under `wait`.
    fn flushed(&self, wait: FlushWait) -> bool {
        self.outstanding() == 0
            || (wait == FlushWait::UntilAcknowledgedOrUnreachable && !self.is_reachable())
    }

    /// **The stop's flush** (module documentation), the one implementation
    /// every daemon calls once it answered its requests in flight:
    ///
    /// 1. wait, at most `grace` ([`AUDIT_FLUSH_GRACE`] in every daemon),
    ///    looking every [`FLUSH_POLL`] (`sleep` is the caller's runtime's
    ///    timer), until every queued event is acknowledged — or, under
    ///    [`FlushWait::UntilAcknowledgedOrUnreachable`], the link counts as
    ///    unreachable; the audit link keeps running (and reconnecting)
    ///    meanwhile;
    /// 2. end the audit link (`end_link`: the daemon aborts its audit task
    ///    and awaits it);
    /// 3. report what is still unacknowledged — lost with the process.
    ///
    /// Spec: docs/questions/Q-313 (A-82: "waits, bounded, for auditd's
    /// acknowledgement of every queued audit event before closing, and
    /// reports what was not acknowledged"), Q-350 item 11 (A-87), Q-252 item
    /// 9; docs/52 §3.11 R6 (b); docs/50 §3.6, §8.1.
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
        Unflushed {
            events: self.outstanding(),
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
    use crate::event::WindowSummary;
    use core::pin::pin;
    use core::task::{Context, Poll, Waker};
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
            crate::decode_event(batch.events()[0].as_bytes()).unwrap(),
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
