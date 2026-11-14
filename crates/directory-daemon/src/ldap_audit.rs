//! The LDAP engine's audit events in dird, and the A-57 gate in front of
//! every LDAP operation.
//!
//! # Where events go
//!
//! The engine returns exactly one `ldap::AuditEvent` per message in its
//! `Outcome` (R49-14; Q-190 item 13: "the event is returned in `Outcome`").
//! The PEP writes it (docs/50 §4.2: "the LDAP event is written by dird, the
//! PEP, not by the front"): dird moves it into the sender window
//! (`ipc_audit::SendWindow`) as an `LdapEvent` (ipc-audit's `ldap` feature),
//! from which the audit client (crate::audit_link) delivers it to auditd
//! over `audit.sock` (R50-17, §8.1).
//!
//! # LDAP operations are gating
//!
//! docs/questions Q-252 item 8 (b), accepted with A-64: "LDAP binds /
//! searches are gating in dird (fail closed)". So, as the kdc daemon does
//! for every KDC request (Q-275 item 6, A-69):
//!
//! * **Every message** handed to the engine reserves a window slot first
//!   ([`AuditGate::admit`]). auditd unreachable, or the window full ⇒ no
//!   slot ⇒ the engine is not run and the channel answers
//!   `Refused::Unavailable` — the front closes the client connection with a
//!   Notice of Disconnection (unavailable). "No unaudited issuance, and log
//!   overflow does not turn into shutdown" (A-57): the process keeps
//!   running; LDAP is refused until the window drains.
//! * After the engine ran, its event is committed into the slot, and only
//!   then do the responses leave (Q-252 item 9: "commit, then reply"). An
//!   event that cannot be committed withholds the responses
//!   ([`RecordLost`] → `Refused::Unavailable`).
//! * **Noise** — the event of a message the engine never decoded
//!   (`AuditOperation::Malformed`: not canonical, over the bound;
//!   `AuditOperation::NotDecoded`: a closed session, cleartext after
//!   StartTLS, a transport mismatch) — gives its slot back and is offered as
//!   noise (queued within the noise share, otherwise counted into a
//!   `WindowSummary`): Q-218 (a), "unauthenticated noise events (… a
//!   malformed frame) summarised in counters and rate-limited". Such a
//!   message performs no operation (no directory data leaves).
//!
//! "auditd unreachable" is the audit client's view: no verified connection,
//! or the last exchange failed (A-67 item 2: refused even with free slots).
//!
//! Spec: docs/50 R50-17, §4.2, §8.1; docs/49 R49-14; docs/questions Q-218
//! (A-57), Q-252 items 8, 9 (A-64), Q-260 item 2 (A-67), Q-275 item 6
//! (A-69).

use ipc_audit::{
    Ack, Append, DirAdminEvent, EventBody, LdapEvent, Reservation, SendWindow, WindowConfig,
    WindowError,
};
use ldap::{AuditEvent, AuditOperation};
use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::Instant;
use tokio::sync::Notify;

/// Whether `event` is noise: the engine never decoded the message, so no
/// operation was performed (module documentation).
/// Spec: docs/questions Q-218 (A-57: undecoded / malformed ⇒ noise);
/// crates/ldap audit.rs (`AuditOperation::Malformed`, `NotDecoded`).
#[must_use]
pub fn is_noise(event: &AuditEvent) -> bool {
    matches!(
        event.operation,
        AuditOperation::Malformed | AuditOperation::NotDecoded
    )
}

/// The wire event of one LDAP event. Spec: crates/ipc-audit convert.rs.
fn event_of(event: &AuditEvent) -> EventBody {
    EventBody::Ldap(Box::new(LdapEvent::from(event)))
}

/// The event of an operation could not be put into the window: its
/// responses must not be sent.
/// Spec: docs/questions/Q-252 item 9 ("commit, then reply").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordLost;

#[derive(Debug)]
struct GateState {
    window: SendWindow,
    reachable: bool,
}

/// Shared by the LDAP engine thread (admit, record), the admin thread
/// (reserve, commit, wait for an acknowledgement — crate::admin_engine) and
/// the audit client task (batches, acknowledgements, reachability): one
/// window, one link to auditd for every event dird sends (A-85: "reuse
/// dird's existing audit link and window").
/// Spec: docs/50 R50-17, §8.1; docs/questions/Q-218 (A-57); docs/51 §5.7.
#[derive(Debug)]
pub struct AuditGate {
    state: Mutex<GateState>,
    wake: Notify,
    /// Wakes the admin thread waiting for a decision event's
    /// acknowledgement (docs/51 §5.7 item 2); paired with `state`.
    acked: Condvar,
}

impl AuditGate {
    /// A gate over an empty window; auditd counts as unreachable until the
    /// audit client says otherwise (fail closed).
    #[must_use]
    pub fn new(window: WindowConfig) -> AuditGate {
        AuditGate {
            state: Mutex::new(GateState {
                window: SendWindow::new(window),
                reachable: false,
            }),
            wake: Notify::new(),
            acked: Condvar::new(),
        }
    }

    /// The state, or `None` if a holder panicked (no slot: fail closed).
    fn lock(&self) -> Option<MutexGuard<'_, GateState>> {
        self.state.lock().ok()
    }

    /// Reserve the slot of the next operation's event, or `None` (auditd
    /// unreachable, the window full): the operation is then not served.
    /// Spec: docs/questions/Q-218 (A-57), Q-252 item 8 (A-64).
    pub fn admit(&self) -> Option<Reservation> {
        let mut state = self.lock()?;
        if !state.reachable {
            return None;
        }
        state.window.reserve().ok()
    }

    /// Give back a slot whose operation did not run.
    pub fn release(&self, reservation: Reservation) {
        if let Some(mut state) = self.lock() {
            state.window.release(reservation);
        }
    }

    /// Put the event of the operation that just ran into the window (module
    /// documentation).
    ///
    /// # Errors
    /// [`RecordLost`]: the event could not be committed — its responses
    /// must not be sent.
    ///
    /// Spec: docs/questions/Q-218 (A-57), Q-252 items 8, 9 (A-64).
    pub fn record(&self, reservation: Reservation, event: &AuditEvent) -> Result<(), RecordLost> {
        let result = match self.lock() {
            Some(mut state) => {
                if is_noise(event) {
                    state.window.release(reservation);
                    let _ = state.window.offer_noise(&event_of(event));
                    Ok(())
                } else {
                    state
                        .window
                        .commit(reservation, &event_of(event))
                        .map(|_sequence| ())
                        .map_err(|_| RecordLost)
                }
            }
            None => Err(RecordLost),
        };
        self.wake.notify_one();
        result
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

    /// The next batch to send, if nothing is in flight and anything is
    /// pending. Spec: docs/50 §3.6, §8.1.
    pub(crate) fn next_batch(&self) -> Option<Append> {
        self.lock().and_then(|mut state| state.window.next_batch())
    }

    /// auditd's acknowledgement of the batch in flight; wakes a thread
    /// waiting for one ([`AuditGate::wait_acknowledged`]).
    pub(crate) fn acknowledge(&self, ack: &Ack) -> Result<usize, WindowError> {
        let result = match self.lock() {
            Some(mut state) => state.window.acknowledge(ack),
            None => Err(WindowError::UnexpectedAck),
        };
        self.acked.notify_all();
        result
    }

    /// Reserve `count` slots for the gating events of one admin operation —
    /// all or none — with auditd reachable; `None` otherwise (the operation
    /// is then not performed and is answered `Unavailable`: "auditd
    /// unavailable ⇒ the operation is refused before any commit", A-85). A
    /// refused reservation is counted for the next `WindowSummary`.
    /// Spec: docs/51 §5.7 items 1-2; docs/questions/Q-218 (A-57), Q-340
    /// item 8 (every `DirAdmin` event is gating); keyd-daemon's two-slot
    /// intent rule (A-88) as the pattern.
    pub(crate) fn admit_slots(&self, count: usize) -> Option<Vec<Reservation>> {
        let mut state = self.lock()?;
        if !state.reachable {
            return None;
        }
        let mut slots = Vec::with_capacity(count);
        for _ in 0..count {
            match state.window.reserve() {
                Ok(slot) => slots.push(slot),
                Err(_) => {
                    for slot in slots {
                        state.window.release(slot);
                    }
                    return None;
                }
            }
        }
        Some(slots)
    }

    /// Put one admin event into its reserved slot; returns its sequence
    /// number, and wakes the audit client to send it.
    ///
    /// # Errors
    /// [`RecordLost`] (cannot happen for an event built from ipc-audit's
    /// types): the caller does not go on with the operation, or — after a
    /// commit — reports the gap.
    ///
    /// Spec: docs/51 §5.7 item 2; docs/questions/Q-252 item 9 (A-64).
    pub(crate) fn commit_admin(
        &self,
        reservation: Reservation,
        event: &DirAdminEvent,
    ) -> Result<u64, RecordLost> {
        let result = match self.lock() {
            Some(mut state) => state
                .window
                .commit(reservation, &EventBody::DirAdmin(Box::new(event.clone())))
                .map_err(|_| RecordLost),
            None => Err(RecordLost),
        };
        self.wake.notify_one();
        result
    }

    /// Count an admin outcome event that could not be committed after its
    /// decision event was (the log then holds the decision without its
    /// outcome) into the window's next `WindowSummary`
    /// (`unrecorded_outcomes`), and wake the audit client to send it. A
    /// poisoned lock cannot count it; the caller's thinned stderr note still
    /// records it.
    /// Spec: decision A-88 (a lost-outcome count in the shared summary);
    /// docs/questions/Q-366 option (a) ("dird's `DirAdmin` outcome … would
    /// use the same counter"), Q-388 item 6, Q-395.
    pub(crate) fn count_unrecorded_outcome(&self) {
        if let Some(mut state) = self.lock() {
            state.window.count_unrecorded_outcome();
        }
        self.wake.notify_one();
    }

    /// Wait until auditd acknowledged the event numbered `seq` — persisted
    /// it (docs/50 §8.1: `Ack` only after the sync) — or `deadline` passed.
    /// Acknowledgements are cumulative and in order (one batch in flight,
    /// oldest first), so `seq` is acknowledged once the last `Ack` reaches
    /// it. A poisoned lock answers `false` (fail closed). Blocks the calling
    /// thread (the admin thread, never the runtime's).
    /// Spec: docs/51 §5.7 item 2 ("a decision event acknowledged by auditd
    /// before the commit"); A-85; docs/50 §3.6 (bounded waits); the same
    /// rule in keyd-daemon (A-88).
    pub(crate) fn wait_acknowledged(&self, seq: u64, deadline: Instant) -> bool {
        let Some(mut state) = self.lock() else {
            return false;
        };
        loop {
            if state
                .window
                .last_ack()
                .is_some_and(|ack| ack.through_seq >= seq)
            {
                return true;
            }
            let left = match deadline.checked_duration_since(Instant::now()) {
                Some(left) if !left.is_zero() => left,
                _ => return false,
            };
            state = match self.acked.wait_timeout(state, left) {
                Ok((guard, _)) => guard,
                Err(_) => return false,
            };
        }
    }

    /// The audit connection dropped: the batch in flight goes back.
    pub(crate) fn connection_lost(&self) {
        if let Some(mut state) = self.lock() {
            state.window.connection_lost();
        }
    }

    /// Events not yet acknowledged plus outstanding reservations.
    #[must_use]
    pub fn outstanding(&self) -> usize {
        self.lock().map_or(0, |state| {
            state
                .window
                .unacknowledged()
                .saturating_add(usize::try_from(state.window.reserved()).unwrap_or(usize::MAX))
        })
    }

    /// Wait until an event was recorded (or a stored wake-up is pending).
    pub(crate) async fn recorded(&self) {
        self.wake.notified().await;
    }
}
