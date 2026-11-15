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

use crate::log::{note, Note};
use core::future::Future;
use core::time::Duration;
use ipc_audit::{AdmindEvent, EventBody, FlushWait, Reservation, Unflushed, WindowConfig};
use tokio::sync::Notify;

/// An event could not be put into its reserved slot (cannot happen for an
/// event built from ipc-audit's types).
/// Spec: docs/questions/Q-252 item 9.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordLost;

/// Shared by the admin listener (noise), the worker (reserve, commit) and
/// the audit client task (batches, acknowledgements, reachability): the
/// shared `ipc_audit::AuditGate` (its window, the reachability, the stop's
/// flush — docs/52 §3.11 R6) plus admind's event shape and the tokio
/// wake-up of the audit client.
/// Spec: docs/50 R50-17, §8.1; docs/questions/Q-218 (A-57); docs/52 §3.11
/// R6.
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

    /// Reserve the slot of a gating event, or `None` (auditd unreachable,
    /// the window full — counted for the next `WindowSummary`).
    /// Spec: docs/questions/Q-218 (A-57), Q-252 item 8 (A-64).
    pub fn reserve(&self) -> Option<Reservation> {
        self.core.reserve()
    }

    /// Put a gating event into its reserved slot, and wake the audit client.
    ///
    /// # Errors
    /// [`RecordLost`].
    ///
    /// Spec: docs/questions/Q-252 item 9 ("commit, then reply").
    pub fn commit(&self, reservation: Reservation, event: &AdmindEvent) -> Result<u64, RecordLost> {
        let result = self
            .core
            .commit(reservation, &EventBody::Admind(Box::new(event.clone())))
            .map_err(|_| RecordLost);
        self.wake.notify_one();
        result
    }

    /// Offer a noise event (queued within the noise share, otherwise
    /// counted), and wake the audit client.
    /// Spec: docs/questions/Q-218 (A-57); ipc-audit `AdmindEvent::is_noise`.
    pub fn noise(&self, event: &AdmindEvent) {
        self.core
            .offer_noise(&EventBody::Admind(Box::new(event.clone())));
        self.wake.notify_one();
    }

    // No `set_reachable` here (task R15b, docs/questions/Q-630): the shared
    // gate's reachability is the audit client's alone (crate-private to
    // ipc-audit); admind's start attaches the verified connection to this
    // gate (`ipc_audit::client::AuditLink::attach`).

    /// Whether auditd is reachable (the audit client's view).
    #[must_use]
    pub fn is_reachable(&self) -> bool {
        self.core.is_reachable()
    }

    /// Events not yet acknowledged plus outstanding reservations.
    #[must_use]
    pub fn outstanding(&self) -> usize {
        self.core.outstanding()
    }

    /// The stop's flush (`ipc_audit::AuditGate::close`): admind waits the
    /// whole `grace` for the acknowledgements even while its link counts as
    /// unreachable (`FlushWait::UntilAcknowledged` — the wait it was built
    /// with, as dird's, A-87), then ends the link (`end_link`), then reports
    /// what is left.
    /// Spec: docs/questions/Q-313 (A-82), Q-350 item 11 (A-87); docs/51
    /// §5.7; docs/52 §3.11 R6 (b).
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
}

/// What admind's gate gives the one audit client (`ipc_audit::client`, task
/// R9b): the shared gate, the wake-up of a recorded event, and admind's
/// notes when the link is restored or lost.
/// Spec: docs/52 §3.11 R6, §3.12; docs/questions/Q-512, Q-560 item 4.
impl ipc_audit::client::LinkedGate for AuditGate {
    fn audit_gate(&self) -> &ipc_audit::AuditGate {
        &self.core
    }

    fn recorded(&self) -> impl Future<Output = ()> + Send + '_ {
        self.wake.notified()
    }

    fn link_restored(&self) {
        note(Note::AuditRestored, None);
    }

    fn link_lost(&self) {
        note(Note::AuditLost, None);
    }
}
