//! The KDC's audit events in the daemon, and the A-57 gate in front of every
//! request.
//!
//! # Where events go
//!
//! `Kdc` emits exactly one `kdc::AuditEvent` per request (crates/kdc
//! audit.rs, main-session decision 14) into its sink. The daemon's sink,
//! [`EventBuffer`], only holds the event of the request in progress; right
//! after the request the engine moves it into the sender window
//! (`ipc_audit::SendWindow`), from which the audit client delivers it to
//! auditd over `audit.sock` (R50-17, §8.1), converted by ipc-audit's `kdc`
//! feature (`KdcEvent::from`).
//!
//! # Is the kdc an issuance-gating sender? Yes.
//!
//! keyd gates every issuing operation on its own window (A-67): no ticket
//! leaves keyd without keyd's record. The documents still make the kdc a
//! gating sender of its own: docs/50 §8.1 ("keyd operations **and kdc
//! issuance replies** are not performed when the window is full");
//! docs/questions/Q-218 option (a) as decided (A-57: "kdc refuses every
//! request that would produce issuance"); Q-252 item 8 (a) (A-64: the KDC
//! cannot know before processing whether a request will issue — "reserve for
//! every decoded request, so non-issuing requests are also refused,
//! KDC_ERR_SVC_UNAVAILABLE, when the window is full"). The kdc's event is
//! the one that names the client, the service, the armor principal and the
//! PDP's reason; keyd's record does not. So:
//!
//! * **Every request** handed to `Kdc::handle` reserves a slot first
//!   ([`AuditGate::admit`]). If auditd is unreachable or the window is full,
//!   there is no slot: the request is still answered, but as for an
//!   unavailable keyd and directory (`crate::custody::GatedCustody` closed,
//!   `ipc_directory::UnavailableDirectory`) — 29 over TCP, silence over UDP
//!   — and keyd is not asked.
//! * After the request its event is committed into the slot, and only then
//!   does the reply leave (window docs: "commit, then reply"). An event
//!   that cannot be committed withholds the reply ([`RecordLost`]): UDP
//!   silence, TCP close.
//! * **Noise** — the event of a message that never decoded (no exchange: an
//!   undecodable or oversized message, a TCP framing error) — gives its slot
//!   back and is offered as noise (queued within the noise share, otherwise
//!   counted into a `WindowSummary`): "unauthenticated noise events
//!   (undecoded UDP, a malformed frame) summarised in counters and
//!   rate-limited" (Q-218 (a)). So is every event of a request that had no
//!   slot.
//! * A request without a slot that is nevertheless answered with an issued
//!   reply — only a retransmission from the KDC's retransmit cache can be
//!   (RFC 4120 §3.1.2; nothing new is issued) — is withheld too: no
//!   issuing reply leaves without its event in the window.
//!
//! "auditd unreachable" is the audit client's view: no verified connection,
//! or the last exchange failed (as keyd-daemon, A-67 item 2: refused even
//! with free slots).
//!
//! Spec: docs/50 R50-17, §8.1; docs/questions/Q-218 (A-57), Q-252 items 8, 9
//! (A-64), Q-260 items 1-2 (A-67); docs/37 §2 (D63); docs/07 §8;
//! crates/kdc audit.rs.

use crate::log::{note, Note};
use core::future::Future;
use core::time::Duration;
use ipc_audit::{
    EventBody, FlushWait, KdcEvent, Reservation, Unflushed, WindowConfig, WindowSteps,
};
use kdc::{AuditEvent, AuditOutcome, AuditSink};
use tokio::sync::Notify;

/// Most events [`EventBuffer`] holds for one request. The KDC emits exactly
/// one; more is a fault the engine refuses on (fail closed). Project bound
/// (AGENTS.md §6).
pub const MAX_EVENTS_PER_REQUEST: usize = 4;

/// The KDC's audit sink in the daemon: the events of the request in
/// progress, bounded; past the bound it marks the request as overflowed,
/// which the engine treats as a failure to record.
/// Spec: crates/kdc audit.rs ("The durable sink … belongs to the daemon").
#[derive(Debug, Default)]
pub struct EventBuffer {
    events: Vec<AuditEvent>,
    overflowed: bool,
}

impl EventBuffer {
    /// An empty buffer.
    #[must_use]
    pub fn new() -> EventBuffer {
        EventBuffer::default()
    }

    /// Take the events of the request that just ran, and whether any was
    /// dropped; the buffer is empty afterwards.
    pub fn take(&mut self) -> (Vec<AuditEvent>, bool) {
        let overflowed = core::mem::take(&mut self.overflowed);
        (core::mem::take(&mut self.events), overflowed)
    }
}

impl AuditSink for EventBuffer {
    /// Spec: crates/kdc audit.rs (exactly one event per request).
    fn record(&mut self, event: &AuditEvent) {
        if self.events.len() < MAX_EVENTS_PER_REQUEST {
            self.events.push(event.clone());
        } else {
            self.overflowed = true;
        }
    }
}

/// Whether `event` is noise: the KDC never decoded the message, so it named
/// no exchange (crates/kdc kdc.rs `refuse_unscoped`).
/// Spec: docs/questions/Q-218 (A-57: undecoded / malformed ⇒ noise).
#[must_use]
pub fn is_noise(event: &AuditEvent) -> bool {
    event.exchange.is_none()
}

/// Whether `event` records an issued reply (a new one, or a retransmission).
/// Spec: crates/kdc audit.rs (`AuditOutcome::Issued`).
#[must_use]
pub fn is_issued(event: &AuditEvent) -> bool {
    matches!(event.outcome, AuditOutcome::Issued)
}

/// The wire event of one KDC event. Spec: crates/ipc-audit convert.rs.
fn event_of(event: &AuditEvent) -> EventBody {
    EventBody::Kdc(Box::new(KdcEvent::from(event)))
}

/// The record of a request could not be put into the window: its reply
/// must not be sent.
/// Spec: docs/questions/Q-252 item 9 ("commit, then reply").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordLost;

/// What happened to a request's events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recorded {
    /// Committed into the request's reserved slot (and fresh slots for any
    /// extra event): every reply may leave.
    Gating,
    /// Offered as noise: only a reply that issues nothing may leave.
    Noise,
}

/// Shared by the engine thread (admit, record) and the audit client task
/// (batches, acknowledgements, reachability): the shared
/// `ipc_audit::AuditGate` (its window, the reachability, the stop's flush —
/// docs/52 §3.11 R6) plus the kdc's event shape and the tokio wake-up of the
/// audit client.
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

    /// Reserve the slot of the next request's event, or `None` (auditd
    /// unreachable, the window full): the request is then not served.
    /// Spec: docs/questions/Q-218 (A-57), Q-252 item 8 (a) (A-64).
    pub fn admit(&self) -> Option<Reservation> {
        self.core.reserve()
    }

    /// Put the events of the request that just ran into the window (module
    /// documentation).
    ///
    /// # Errors
    /// [`RecordLost`] for a request with a slot whose events could not all
    /// be committed (none, too many, no slot for an extra one): its reply
    /// must not be sent.
    ///
    /// Spec: docs/questions/Q-218 (A-57), Q-252 items 8, 9 (A-64).
    pub fn record(
        &self,
        admission: Option<Reservation>,
        events: &[AuditEvent],
        overflowed: bool,
    ) -> Result<Recorded, RecordLost> {
        let gating = admission.is_some();
        let result = self
            .core
            .with_steps(|steps| match admission {
                Some(reservation) => {
                    if !overflowed && !events.is_empty() && events.iter().all(is_noise) {
                        steps.release(reservation);
                        Self::offer_all(steps, events);
                        Ok(Recorded::Noise)
                    } else {
                        Self::commit_all(steps, reservation, events, overflowed)
                    }
                }
                None => {
                    Self::offer_all(steps, events);
                    Ok(Recorded::Noise)
                }
            })
            // A poisoned lock: no event in the window — a reply that needed
            // one must not leave (fail closed).
            .unwrap_or(if gating {
                Err(RecordLost)
            } else {
                Ok(Recorded::Noise)
            });
        self.wake.notify_one();
        result
    }

    /// Offer events as noise (queued within the noise share, or counted; an
    /// encoding failure is counted too).
    fn offer_all(steps: &mut WindowSteps<'_>, events: &[AuditEvent]) {
        for event in events {
            let _ = steps.offer_noise(&event_of(event));
        }
    }

    /// Commit the events of a request with a slot.
    /// Spec: crates/kdc audit.rs (exactly one per request);
    /// docs/questions/Q-252 item 9.
    fn commit_all(
        steps: &mut WindowSteps<'_>,
        reservation: Reservation,
        events: &[AuditEvent],
        overflowed: bool,
    ) -> Result<Recorded, RecordLost> {
        let mut events = events.iter();
        let Some(first) = events.next() else {
            steps.release(reservation);
            return Err(RecordLost);
        };
        steps
            .commit(reservation, &event_of(first))
            .map_err(|_| RecordLost)?;
        for extra in events {
            let slot = steps.reserve().map_err(|_| RecordLost)?;
            steps
                .commit(slot, &event_of(extra))
                .map_err(|_| RecordLost)?;
        }
        if overflowed {
            return Err(RecordLost);
        }
        Ok(Recorded::Gating)
    }

    // No `set_reachable` here (task R15b, docs/questions/Q-630): the shared
    // gate's reachability is the audit client's alone (crate-private to
    // ipc-audit); the kdc's start attaches the verified connection to this
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

    /// The stop's flush (`ipc_audit::AuditGate::close`): the kdc stops
    /// waiting as soon as its link counts auditd as unreachable
    /// (`FlushWait::UntilAcknowledgedOrUnreachable` — the rule A-87 kept for
    /// the kdc), then ends the link (`end_link`), then reports what is left.
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
                FlushWait::UntilAcknowledgedOrUnreachable,
                tokio::time::sleep,
                end_link,
            )
            .await
    }
}

/// What the kdc's gate gives the one audit client (`ipc_audit::client`,
/// task R9b): the shared gate, the wake-up of a recorded event, and the
/// kdc's notes when the link is restored or lost.
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

// The unit tests open the gate through ipc-audit's dev-only test seams, so
// they live in a test file (task R15b, docs/questions/Q-630).
#[cfg(test)]
#[path = "audit_tests.rs"]
mod tests;
