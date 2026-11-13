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
    Ack, Append, EventBody, LdapEvent, Reservation, SendWindow, WindowConfig, WindowError,
};
use ldap::{AuditEvent, AuditOperation};
use std::sync::{Mutex, MutexGuard};
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

/// Shared by the LDAP engine thread (admit, record) and the audit client
/// task (batches, acknowledgements, reachability).
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

    /// auditd's acknowledgement of the batch in flight.
    pub(crate) fn acknowledge(&self, ack: &Ack) -> Result<usize, WindowError> {
        match self.lock() {
            Some(mut state) => state.window.acknowledge(ack),
            None => Err(WindowError::UnexpectedAck),
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
