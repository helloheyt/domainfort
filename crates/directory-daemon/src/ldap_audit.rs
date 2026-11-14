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
//! # The shared gate (docs/52 R6, A-102)
//!
//! The window, the reachability, the acknowledgement wait and the stop's
//! flush are `ipc_audit::AuditGate`'s — one implementation for every
//! sending daemon. This wrapper adds what is dird's: the LDAP and admin
//! event shapes, and the tokio wake-up of the audit link. The admin thread's
//! "decision acknowledged ⇒ apply / register" goes through
//! [`AuditGate::begin_intent`] and [`AuditGate::wait_acknowledged`], whose
//! `ipc_audit::AckedIntent` is the only way into `DirectoryAdmin::apply`
//! and into a decision's registration (crate::admin_engine,
//! crate::registration).
//!
//! Spec: docs/50 R50-17, §4.2, §8.1; docs/49 R49-14; docs/questions Q-218
//! (A-57), Q-252 items 8, 9 (A-64), Q-260 item 2 (A-67), Q-275 item 6
//! (A-69); docs/52 §3.11 R6.

use core::future::Future;
use core::time::Duration;
use ipc_audit::{
    Ack, AckedIntent, Append, DirAdminEvent, EventBody, FlushWait, IntentRecord, LdapEvent,
    PendingIntent, Reservation, Unflushed, WindowConfig, WindowError,
};
use ldap::{AuditEvent, AuditOperation};
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

/// Shared by the LDAP engine thread (admit, record), the admin thread
/// (reserve, commit, wait for an acknowledgement — crate::admin_engine) and
/// the audit client task (batches, acknowledgements, reachability): one
/// window, one link to auditd for every event dird sends (A-85: "reuse
/// dird's existing audit link and window"). The core is
/// `ipc_audit::AuditGate` (module documentation).
/// Spec: docs/50 R50-17, §8.1; docs/questions/Q-218 (A-57); docs/51 §5.7;
/// docs/52 §3.11 R6.
#[derive(Debug)]
pub struct AuditGate {
    core: ipc_audit::AuditGate,
    wake: Notify,
}

impl AuditGate {
    /// A gate over an empty window; auditd counts as unreachable until the
    /// audit client says otherwise (fail closed).
    #[must_use]
    pub fn new(window: WindowConfig) -> AuditGate {
        AuditGate {
            core: ipc_audit::AuditGate::new(window),
            wake: Notify::new(),
        }
    }

    /// Reserve the slot of the next operation's event, or `None` (auditd
    /// unreachable, the window full): the operation is then not served.
    /// Spec: docs/questions/Q-218 (A-57), Q-252 item 8 (A-64).
    pub fn admit(&self) -> Option<Reservation> {
        self.core.reserve()
    }

    /// Give back a slot whose operation did not run.
    pub fn release(&self, reservation: Reservation) {
        self.core.release(reservation);
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
        let result = if is_noise(event) {
            self.core.release(reservation);
            self.core.offer_noise(&event_of(event));
            Ok(())
        } else {
            self.core
                .commit(reservation, &event_of(event))
                .map(|_sequence| ())
                .map_err(|_| RecordLost)
        };
        self.wake.notify_one();
        result
    }

    /// Record the audit client's view of auditd.
    pub fn set_reachable(&self, reachable: bool) {
        self.core.set_reachable(reachable);
    }

    /// Whether auditd is reachable (the audit client's view).
    #[must_use]
    pub fn is_reachable(&self) -> bool {
        self.core.is_reachable()
    }

    /// The next batch to send, if nothing is in flight and anything is
    /// pending. Spec: docs/50 §3.6, §8.1.
    pub(crate) fn next_batch(&self) -> Option<Append> {
        self.core.next_batch()
    }

    /// auditd's acknowledgement of the batch in flight; wakes a thread
    /// waiting for one ([`AuditGate::wait_acknowledged`]).
    pub(crate) fn acknowledge(&self, ack: &Ack) -> Result<usize, WindowError> {
        self.core.acknowledge(ack)
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
        self.core.reserve_all(count)
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
        let result = self
            .core
            .commit(reservation, &EventBody::DirAdmin(Box::new(event.clone())))
            .map_err(|_| RecordLost);
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
        self.core.count_unrecorded_outcome();
        self.wake.notify_one();
    }

    /// Commit the decision event of `value` (its `IntentRecord`) into
    /// `slot` and wake the audit client to send it.
    ///
    /// # Errors
    /// The value back (cannot happen for an event built from ipc-audit's
    /// types).
    ///
    /// Spec: docs/51 §5.7 item 2 (A-85); docs/52 §3.11 R6 (a).
    pub(crate) fn begin_intent<T: IntentRecord>(
        &self,
        slot: Reservation,
        value: T,
    ) -> Result<PendingIntent<T>, T> {
        let result = self.core.begin_intent(slot, value);
        self.wake.notify_one();
        result
    }

    /// Wait until auditd acknowledged the decision event of `pending` —
    /// persisted it (docs/50 §8.1) — or `deadline` passed: the proof, or the
    /// value back without one (fail closed). Blocks the calling thread (the
    /// admin thread, never the runtime's).
    /// Spec: docs/51 §5.7 item 2 ("a decision event acknowledged by auditd
    /// before the commit"); A-85; docs/50 §3.6 (bounded waits); docs/52
    /// §3.11 R6 (a).
    pub(crate) fn wait_acknowledged<T>(
        &self,
        pending: PendingIntent<T>,
        deadline: Instant,
    ) -> Result<AckedIntent<T>, T> {
        self.core.wait_acknowledged(pending, deadline)
    }

    /// The audit connection dropped: the batch in flight goes back.
    pub(crate) fn connection_lost(&self) {
        self.core.connection_lost();
    }

    /// Events not yet acknowledged plus outstanding reservations.
    #[must_use]
    pub fn outstanding(&self) -> usize {
        self.core.outstanding()
    }

    /// The stop's flush (`ipc_audit::AuditGate::close`): dird waits the
    /// whole `grace` for the acknowledgements even while its link counts as
    /// unreachable (`FlushWait::UntilAcknowledged`, A-87), then ends the
    /// link (`end_link`), then reports what is left.
    /// Spec: docs/questions/Q-313 (A-82), Q-350 item 11 (A-87); docs/52
    /// §3.11 R6 (b).
    pub(crate) async fn close<E: Future<Output = ()>>(
        &self,
        grace: Duration,
        end_link: E,
    ) -> Unflushed {
        self.core
            .close(
                grace,
                FlushWait::UntilAcknowledged,
                tokio::time::sleep,
                end_link,
            )
            .await
    }

    /// Wait until an event was recorded (or a stored wake-up is pending).
    pub(crate) async fn recorded(&self) {
        self.wake.notified().await;
    }
}
