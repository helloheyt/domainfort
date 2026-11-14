//! admind's audit events and the window in front of auditd.
//!
//! # What admind records (docs/51 §5.7 item 3; decision A-85)
//!
//! Its own events only — dird records every admin operation it decides
//! (`DirAdmin`), keyd every `set_secret` (intent and outcome, A-88):
//!
//! * a refused `admin.sock` connection (`ConnectionRefused`) and a frame
//!   that did not decode (`MalformedFrame`) — **noise** (A-57, A-64;
//!   `AdmindEvent::is_noise`): offered with `SendWindow::offer_noise`,
//!   queued within the window's noise share, otherwise counted into a
//!   `WindowSummary`, so a flood never takes a slot a gating event needs and
//!   never stops admind;
//! * every `SetPassword` (`Completed`, or the step that failed and its class)
//!   — **gating**: its slot is reserved before admind asks dird or keyd
//!   anything; auditd unreachable or the window full ⇒ no slot ⇒ the request
//!   is answered `Busy` and nothing is done (docs/51 §5.7: "auditd
//!   unavailable ⇒ refused"; A-64: "full window ⇒ Busy" — keyd-daemon's
//!   rule for a refused reservation). The event is committed into its slot
//!   before the reply ("commit, then reply", Q-252 item 9).
//!
//! The source of every record is set by auditd from admind's peer uid
//! (docs/50 §3.2); auditd accepts the `Admind` shape only from admind's uid
//! (docs/questions/Q-341).
//!
//! Spec: docs/51 §5.7 (R51-12); docs/50 R50-17, §8.1; docs/questions Q-218
//! (A-57), Q-252 items 8, 9 (A-64), Q-340 items 6-8 (A-85).

use ipc_audit::{Ack, AdmindEvent, Append, EventBody, Reservation, SendWindow, WindowConfig};
use std::sync::{Mutex, MutexGuard};
use tokio::sync::Notify;

/// An event could not be put into its reserved slot (cannot happen for an
/// event built from ipc-audit's types).
/// Spec: docs/questions/Q-252 item 9.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordLost;

#[derive(Debug)]
struct GateState {
    window: SendWindow,
    reachable: bool,
}

/// Shared by the admin listener (noise), the worker (reserve, commit) and
/// the audit client task (batches, acknowledgements, reachability).
/// Spec: docs/50 R50-17, §8.1; docs/questions/Q-218 (A-57).
#[derive(Debug)]
pub struct AuditGate {
    state: Mutex<GateState>,
    wake: Notify,
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
        }
    }

    /// The state, or `None` if a holder panicked (no slot: fail closed).
    fn lock(&self) -> Option<MutexGuard<'_, GateState>> {
        self.state.lock().ok()
    }

    /// Reserve the slot of a gating event, or `None` (auditd unreachable,
    /// the window full — counted for the next `WindowSummary`).
    /// Spec: docs/questions/Q-218 (A-57), Q-252 item 8 (A-64).
    pub fn reserve(&self) -> Option<Reservation> {
        let mut state = self.lock()?;
        if !state.reachable {
            return None;
        }
        state.window.reserve().ok()
    }

    /// Put a gating event into its reserved slot, and wake the audit client.
    ///
    /// # Errors
    /// [`RecordLost`].
    ///
    /// Spec: docs/questions/Q-252 item 9 ("commit, then reply").
    pub fn commit(&self, reservation: Reservation, event: &AdmindEvent) -> Result<u64, RecordLost> {
        let result = match self.lock() {
            Some(mut state) => state
                .window
                .commit(reservation, &EventBody::Admind(Box::new(event.clone())))
                .map_err(|_| RecordLost),
            None => Err(RecordLost),
        };
        self.wake.notify_one();
        result
    }

    /// Offer a noise event (queued within the noise share, otherwise
    /// counted), and wake the audit client.
    /// Spec: docs/questions/Q-218 (A-57); ipc-audit `AdmindEvent::is_noise`.
    pub fn noise(&self, event: &AdmindEvent) {
        if let Some(mut state) = self.lock() {
            let _ = state
                .window
                .offer_noise(&EventBody::Admind(Box::new(event.clone())));
        }
        self.wake.notify_one();
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

    /// auditd's acknowledgement of the batch in flight.
    pub(crate) fn acknowledge(&self, ack: &Ack) -> Result<usize, ipc_audit::WindowError> {
        match self.lock() {
            Some(mut state) => state.window.acknowledge(ack),
            None => Err(ipc_audit::WindowError::UnexpectedAck),
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
