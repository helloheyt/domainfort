//! keyd's audit records in the daemon, and the A-57 gate in front of every
//! operation.
//!
//! # Where records go
//!
//! keyd emits exactly one [`AuditRecord`] per operation (docs/10 I8) into
//! its sink. The daemon's sink, [`RecordBuffer`], only holds the records of
//! the operation in progress; right after the operation the engine moves
//! them into the sender window ([`ipc_audit::SendWindow`]), from which the
//! audit client delivers them to auditd over `audit.sock` (R50-17, §8.1).
//!
//! # The gate (docs/questions/Q-218, decided A-57; Q-252 item 8, A-64)
//!
//! "No unaudited issuance, and log overflow does not turn into shutdown."
//!
//! * **Gating operations** — every keyd operation except `describe_config`
//!   and `ping` ([`is_gating`]): a slot is reserved in the window **before**
//!   keyd runs the operation. If auditd is unreachable, or the window is full
//!   of unacknowledged events, the reservation is refused, keyd is **not**
//!   called, and the caller gets `Refused::Busy` (A-64: "full window → no
//!   issuance, keyd answers Busy"). After the operation its record is
//!   committed into the reserved slot, and only then does the reply leave
//!   (window docs: commit, then reply). A record that cannot be committed
//!   turns the reply into `Refused::Unavailable`: no result of a gating
//!   operation leaves without its record in the window.
//! * **Not gating** — `describe_config` and `ping`, which touch no key, token,
//!   throttle or replay cache (docs/10 §7א): they run whatever the audit
//!   state, and their records are offered as noise (queued within the noise
//!   share of the window, otherwise counted into a `WindowSummary`). This
//!   keeps the health check and the kdc's start-up `DescribeConfig` (docs/50
//!   §7.5) answerable while auditd is away. The literal Q-218 text "keyd
//!   refuses every op" is narrowed for these two — docs/questions/Q-260
//!   item 1.
//!
//! "auditd unreachable" is the audit client's view: no verified connection,
//! or the last exchange (an `Append` or the idle `Ping`) failed. It is
//! stricter than the window alone, which would let gating operations go on
//! into free slots while auditd is away (task P7 brief; docs/questions/Q-260
//! item 2).
//!
//! Spec: docs/50 R50-17, §8.1; docs/questions/Q-218 (A-57), Q-252 items 8, 9
//! (A-64); docs/10 §10, I8; docs/37 §2 (D63: no code path disables audit for
//! a sensitive operation); docs/07 §8.

use ipc_audit::{
    Ack, Append, EventBody, KeydRecord, Reservation, SendWindow, WindowConfig, WindowError,
};
use keyd::{AuditRecord, AuditSink, Operation};
use std::sync::{Mutex, MutexGuard};
use tokio::sync::Notify;

/// Most records [`RecordBuffer`] holds for one operation. keyd emits exactly
/// one (docs/10 I8); more is a fault the engine refuses on (fail closed).
/// Project bound (AGENTS.md §6: no unbounded growth).
pub const MAX_RECORDS_PER_OPERATION: usize = 4;

/// keyd's audit sink in the daemon: the records of the operation in progress.
///
/// Bounded: past [`MAX_RECORDS_PER_OPERATION`] records it keeps none of the
/// extra ones and marks the operation as overflowed, which the engine treats
/// as a failure to record (the reply becomes `Refused::Unavailable`).
///
/// Spec: docs/10 §10, I8; crates/keyd audit.rs ("The production sink …
/// belongs to the daemon crate").
#[derive(Debug, Default)]
pub struct RecordBuffer {
    records: Vec<AuditRecord>,
    overflowed: bool,
}

impl RecordBuffer {
    /// An empty buffer.
    #[must_use]
    pub fn new() -> RecordBuffer {
        RecordBuffer::default()
    }

    /// Take the records of the operation that just ran, and whether any was
    /// dropped; the buffer is empty afterwards.
    pub fn take(&mut self) -> (Vec<AuditRecord>, bool) {
        let overflowed = core::mem::take(&mut self.overflowed);
        (core::mem::take(&mut self.records), overflowed)
    }
}

impl AuditSink for RecordBuffer {
    /// Spec: docs/10 §10, I8.
    fn record(&mut self, record: &AuditRecord) {
        if self.records.len() < MAX_RECORDS_PER_OPERATION {
            self.records.push(record.clone());
        } else {
            self.overflowed = true;
        }
    }
}

/// Whether `operation` gates on the audit window (module documentation).
///
/// An exhaustive match: a new keyd operation does not compile until it is
/// classified here.
///
/// Spec: docs/questions/Q-218 (A-57), Q-252 item 8 (A-64); docs/10 §7א
/// (`describe_config` / `ping`: no key, no secret); docs/questions/Q-260
/// item 1.
#[must_use]
pub const fn is_gating(operation: Operation) -> bool {
    match operation {
        Operation::VerifyPreauth
        | Operation::IssueAsRep
        | Operation::OpenAndVerifyTgt
        | Operation::IssueTgsRep
        | Operation::SetSecret
        | Operation::VerifySecret
        | Operation::CreateKey
        | Operation::RotateKey
        | Operation::RotateKrbtgt
        | Operation::RetireKvno
        | Operation::OpenFastArmor
        | Operation::SealFastError
        | Operation::DestroyKeySet
        | Operation::OpenAndVerifyServiceTicket => true,
        Operation::DescribeConfig | Operation::Ping => false,
    }
}

/// What the gate granted an operation before keyd runs it.
/// Spec: docs/questions/Q-218 (A-57).
#[derive(Debug)]
pub(crate) enum Admission {
    /// A gating operation with its reserved slot.
    Gating(Reservation),
    /// A non-gating operation (`describe_config`, `ping`).
    NotGating,
}

/// The gate refused a gating operation: auditd unreachable or the window
/// full. keyd is not called; the caller gets `Refused::Busy`.
/// Spec: docs/questions/Q-218 (A-57), Q-252 item 8 (A-64).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GateClosed;

/// A gating operation's record could not be put into the window: its reply
/// must not be sent.
/// Spec: docs/questions/Q-252 item 9 (commit, then reply).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RecordLost;

/// The window and the audit client's view of auditd.
#[derive(Debug)]
struct GateState {
    window: SendWindow,
    reachable: bool,
}

/// Shared by the engine thread (admit, record) and the audit client task
/// (batches, acknowledgements, reachability).
///
/// Spec: docs/50 R50-17, §8.1; docs/questions/Q-218 (A-57).
#[derive(Debug)]
pub(crate) struct AuditGate {
    state: Mutex<GateState>,
    /// Wakes the audit client when an event was committed.
    wake: Notify,
}

/// The wire event of one keyd record. Spec: crates/ipc-audit convert.rs.
fn event_of(record: &AuditRecord) -> EventBody {
    EventBody::Keyd(Box::new(KeydRecord::from(record)))
}

impl AuditGate {
    /// A gate over an empty window; auditd counts as unreachable until the
    /// audit client says otherwise (fail closed).
    pub(crate) fn new(window: WindowConfig) -> AuditGate {
        AuditGate {
            state: Mutex::new(GateState {
                window: SendWindow::new(window),
                reachable: false,
            }),
            wake: Notify::new(),
        }
    }

    /// The state, or `None` if a holder panicked (treated as "audit not
    /// available": gating operations are refused).
    fn lock(&self) -> Option<MutexGuard<'_, GateState>> {
        self.state.lock().ok()
    }

    /// Admit `operation` before keyd runs it: a gating operation reserves a
    /// slot, or is refused.
    ///
    /// Spec: docs/questions/Q-218 (A-57), Q-252 item 8 (A-64).
    pub(crate) fn admit(&self, operation: Operation) -> Result<Admission, GateClosed> {
        if !is_gating(operation) {
            return Ok(Admission::NotGating);
        }
        let mut state = self.lock().ok_or(GateClosed)?;
        if !state.reachable {
            return Err(GateClosed);
        }
        state
            .window
            .reserve()
            .map(Admission::Gating)
            .map_err(|_| GateClosed)
    }

    /// Put the records of the operation that just ran into the window: the
    /// first into the reserved slot of a gating operation (any further one
    /// into a fresh slot), or, for a non-gating operation, offered as noise.
    ///
    /// # Errors
    /// [`RecordLost`] for a gating operation whose records could not all be
    /// committed (none, too many, or no slot for an extra one): the reply
    /// must not be sent.
    ///
    /// Spec: docs/questions/Q-252 items 8, 9 (A-64); docs/10 I8.
    pub(crate) fn record(
        &self,
        admission: Admission,
        records: &[AuditRecord],
        overflowed: bool,
    ) -> Result<(), RecordLost> {
        let result = match self.lock() {
            Some(mut state) => match admission {
                Admission::Gating(reservation) => {
                    Self::commit_all(&mut state.window, reservation, records, overflowed)
                }
                Admission::NotGating => {
                    for record in records {
                        // Queued within the noise share, or counted for the
                        // next summary; an encoding failure is counted too.
                        let _ = state.window.offer_noise(&event_of(record));
                    }
                    Ok(())
                }
            },
            None => match admission {
                Admission::Gating(_) => Err(RecordLost),
                Admission::NotGating => Ok(()),
            },
        };
        self.wake.notify_one();
        result
    }

    /// Commit the records of a gating operation. Spec: docs/10 I8;
    /// docs/questions/Q-252 item 9.
    fn commit_all(
        window: &mut SendWindow,
        reservation: Reservation,
        records: &[AuditRecord],
        overflowed: bool,
    ) -> Result<(), RecordLost> {
        let mut records = records.iter();
        let Some(first) = records.next() else {
            // keyd emitted no record (I8 broken): no unaudited result leaves.
            window.release(reservation);
            return Err(RecordLost);
        };
        window
            .commit(reservation, &event_of(first))
            .map_err(|_| RecordLost)?;
        for extra in records {
            let slot = window.reserve().map_err(|_| RecordLost)?;
            window
                .commit(slot, &event_of(extra))
                .map_err(|_| RecordLost)?;
        }
        if overflowed {
            return Err(RecordLost);
        }
        Ok(())
    }

    /// Record the audit client's view of auditd.
    pub(crate) fn set_reachable(&self, reachable: bool) {
        if let Some(mut state) = self.lock() {
            state.reachable = reachable;
        }
    }

    /// Whether auditd is reachable (the audit client's view).
    pub(crate) fn is_reachable(&self) -> bool {
        self.lock().is_some_and(|state| state.reachable)
    }

    /// The next batch to send, if nothing is in flight and anything is
    /// pending. Spec: docs/50 §3.6, §8.1.
    pub(crate) fn next_batch(&self) -> Option<Append> {
        self.lock().and_then(|mut state| state.window.next_batch())
    }

    /// auditd's acknowledgement of the batch in flight.
    ///
    /// # Errors
    /// The window's [`WindowError`] (an acknowledgement that does not match;
    /// the connection is then closed).
    ///
    /// Spec: docs/50 §8.1.
    pub(crate) fn acknowledge(&self, ack: &Ack) -> Result<usize, WindowError> {
        match self.lock() {
            Some(mut state) => state.window.acknowledge(ack),
            None => Err(WindowError::UnexpectedAck),
        }
    }

    /// The audit connection dropped: the batch in flight goes back to the
    /// front. Spec: docs/50 §3.7, §8.1.
    pub(crate) fn connection_lost(&self) {
        if let Some(mut state) = self.lock() {
            state.window.connection_lost();
        }
    }

    /// Events not yet acknowledged plus outstanding reservations.
    pub(crate) fn outstanding(&self) -> usize {
        self.lock().map_or(0, |state| {
            state
                .window
                .unacknowledged()
                .saturating_add(usize::try_from(state.window.reserved()).unwrap_or(usize::MAX))
        })
    }

    /// Wait until an event was committed (or a stored wake-up is pending).
    pub(crate) async fn committed(&self) {
        self.wake.notified().await;
    }

    /// Run `f` on the window (unit tests).
    #[cfg(test)]
    pub(crate) fn with_window<T>(&self, f: impl FnOnce(&mut SendWindow) -> T) -> Option<T> {
        self.lock().map(|mut state| f(&mut state.window))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// docs/10 §7א (`describe_config`, `ping`: no key, no secret) and A-57 /
    /// A-64 (every operation that touches a key, token or secret gates).
    #[test]
    fn only_describe_config_and_ping_do_not_gate() {
        for operation in Operation::ALL {
            let expected = !matches!(operation, Operation::DescribeConfig | Operation::Ping);
            assert_eq!(is_gating(operation), expected, "{operation:?}");
        }
    }

    /// A-57 (fail closed): a new gate counts auditd as unreachable, so a
    /// gating operation is refused until the audit client verified it.
    #[test]
    fn gate_starts_closed() {
        let gate = AuditGate::new(WindowConfig::DEFAULT);
        assert!(!gate.is_reachable());
        assert_eq!(
            gate.admit(Operation::IssueAsRep).map(|_| ()),
            Err(GateClosed)
        );
        assert!(matches!(
            gate.admit(Operation::Ping),
            Ok(Admission::NotGating)
        ));
        gate.set_reachable(true);
        assert!(matches!(
            gate.admit(Operation::IssueAsRep),
            Ok(Admission::Gating(_))
        ));
    }

    /// docs/10 I8: a gating operation with no record, or with more records
    /// than the buffer keeps, is refused (the reply is not sent).
    #[test]
    fn a_gating_operation_needs_its_record() {
        let gate = AuditGate::new(WindowConfig::DEFAULT);
        gate.set_reachable(true);
        let admission = gate.admit(Operation::CreateKey).unwrap();
        assert_eq!(gate.record(admission, &[], false), Err(RecordLost));
        assert_eq!(gate.outstanding(), 0, "the slot was given back");
    }

    /// The buffer is bounded (AGENTS.md §6) and reports the overflow.
    #[test]
    fn record_buffer_is_bounded() {
        let mut buffer = RecordBuffer::new();
        let record = AuditRecord {
            ts: krb_proto::KerberosTime::new(2026, 11, 13, 10, 0, 0).unwrap(),
            caller_role: keyd::Role::Kdc,
            caller_uid: 803,
            op: Operation::Ping,
            principal: None,
            purpose: None,
            kvno: None,
            secondary: None,
            approvers: None,
            result: keyd::AuditOutcome::Success,
            reason: keyd::AuditReason::None,
        };
        for _ in 0..MAX_RECORDS_PER_OPERATION + 2 {
            buffer.record(&record);
        }
        let (records, overflowed) = buffer.take();
        assert_eq!(records.len(), MAX_RECORDS_PER_OPERATION);
        assert!(overflowed);
        assert_eq!(buffer.take(), (Vec::new(), false));
    }
}
