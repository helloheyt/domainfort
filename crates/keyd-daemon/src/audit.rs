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
//!   operation leaves without its record in the window — except a key-state
//!   change, which keyd cannot take back and whose intent is already
//!   acknowledged (next section, A-86).
//! * **Not gating** — `describe_config` and `ping`, which touch no key, token,
//!   throttle or replay cache (docs/10 §7א): they run whatever the audit
//!   state, and their records are offered as noise (queued within the noise
//!   share of the window, otherwise counted into a `WindowSummary`). This
//!   keeps the health check and the kdc's start-up `DescribeConfig` (docs/50
//!   §7.5) answerable while auditd is away. The literal Q-218 text "keyd
//!   refuses every op" is narrowed for these two — docs/questions/Q-260
//!   item 1.
//!
//! # Key-state changes: the intent is acknowledged first (decision A-86)
//!
//! An issuing operation's reply can be withheld; a key-state change cannot be
//! undone once keyd ran it (`keyd::changes_key_state`: `set_secret`,
//! `create_key`, `rotate_key`, `rotate_krbtgt`, `retire_kvno`,
//! `destroy_key_set`) — nor can a grant that loosens keyd's authorization be
//! taken back once keyd registered it (`grant_set_secret`, task A15a;
//! `keyd::requires_acknowledged_intent` covers both — docs/questions/Q-452).
//! For those — once keyd's own authorization step admits them
//! (`keyd::Keyd::admits`) — the engine:
//!
//! 1. reserves **two** slots (intent and outcome) and commits the **intent**
//!    record ([`KeyStateIntent`], outcome code `Intent`) into the first
//!    ([`AuditGate::begin_key_state_change`]); auditd unreachable or the
//!    window short of two slots ⇒ `Busy`, nothing recorded, keyd not called
//!    (as for every gating operation);
//! 2. **waits for auditd's acknowledgement** of the intent
//!    ([`AuditGate::wait_acknowledged`]), bounded by the engine's deadline;
//!    none in time ⇒ a `NotPerformed` outcome goes into the outcome slot
//!    ([`AuditGate::abandon_key_state_change`]), the caller gets
//!    `Refused::Unavailable`, and keyd is **not** called — "unavailable"
//!    means "not done";
//! 3. only then has keyd run the operation, commits keyd's own record (the
//!    true result) into the reserved outcome slot
//!    ([`AuditGate::finish_key_state_change`]) and replies with the true
//!    result. If that record cannot be committed, the intent already
//!    documents the attempt: the reply is still the true result, and the gap
//!    is counted **into the window's next `WindowSummary`**
//!    (`unrecorded_outcomes`, decision A-88; docs/questions/Q-366,
//!    Q-395) — so it reaches the audit log — as well as in the daemon's own
//!    total ([`AuditGate::unrecorded_outcomes`]) and on stderr.
//!    The outcome slot was reserved in step 1, so only a fault can make this
//!    happen (keyd emitted no record, or more than [`RecordBuffer`] keeps).
//!    An outcome committed while auditd is away is not lost: it waits in the
//!    window and is delivered when auditd is back (lost only if keyd ends
//!    first — the bound of docs/questions/Q-252 item 9).
//!
//! An authorization refusal (role or purpose, docs/10 §2) changes nothing and
//! is audited exactly as before — one record, no intent, no wait. Every
//! intent is followed by exactly one outcome record (keyd's, or
//! `NotPerformed`), so an intent without one is a visible gap. Precedent:
//! dird's admin writes (docs/51 §5.7 item 2, A-85: decision acknowledged ⇒
//! commit ⇒ outcome).
//!
//! "auditd unreachable" is the audit client's view: no verified connection,
//! or the last exchange (an `Append` or the idle `Ping`) failed. It is
//! stricter than the window alone, which would let gating operations go on
//! into free slots while auditd is away (task P7 brief; docs/questions/Q-260
//! item 2).
//!
//! # The proof, and the shared gate (docs/52 §3.11 R6, A-102)
//!
//! Step 3 is no longer the engine's discipline: keyd runs an admitted
//! key-state change only through `ipc_keyd_server::execute_acknowledged`,
//! which takes an `ipc_audit::AckedIntent<ipc_keyd_server::KeyStateCall>`
//! by value — and [`AuditGate::wait_acknowledged`] is where it comes from:
//! the shared `ipc_audit::AuditGate`, after auditd acknowledged that very
//! call's intent record. Which calls need it is `ipc_keyd_server::classify`'s
//! decision (from keyd's own authorization step), not this crate's. The
//! window, the reachability, the acknowledgement wait and the stop's flush
//! ([`AuditGate::close`]) are the shared gate's; this wrapper adds keyd's
//! operation classification ([`is_gating`]), its record shape, the tokio
//! wake-up of the audit client and the daemon's own count of lost
//! outcomes.
//!
//! Spec: docs/50 R50-17, §8.1; docs/questions/Q-218 (A-57), Q-252 items 8, 9
//! (A-64), Q-346 (A-86), Q-365, Q-366 (A-88), Q-395; docs/10 §10, I8;
//! docs/37 §2 (D63: no code path disables audit for a sensitive operation),
//! §5; docs/07 §8; docs/51 §5.7 item 2 (A-85); docs/52 §3.11 R6.

use crate::log::{note, Note};
use core::future::Future;
use core::time::Duration;
#[cfg(test)]
use ipc_audit::{Ack, Append, WindowError};
use ipc_audit::{
    AckedIntent, EventBody, FlushWait, KeydRecord, PendingIntent, Reservation, Unflushed,
    WindowConfig, WindowSteps,
};
use ipc_keyd_server::KeyStateCall;
use keyd::{AuditRecord, AuditSink, Operation};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
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
        | Operation::OpenAndVerifyServiceTicket
        | Operation::VerifyOperationTicket
        | Operation::GrantSetSecret
        | Operation::RegisterDecision
        | Operation::SealCeremony
        | Operation::ListDestroyDecisions => true,
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

/// Why a key-state change was not started (keyd is not called either way).
/// Spec: docs/questions/Q-346 (A-86), Q-365.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IntentRefused {
    /// auditd unreachable or no two free slots: `Refused::Busy`, as for every
    /// gating operation (A-57, A-64). Nothing was recorded.
    GateClosed,
    /// The intent record could not be committed (cannot happen for a record
    /// built from ipc-audit's types): `Refused::Unavailable`.
    NotRecorded,
}

/// A key-state change whose intent is in the window: the change waiting for
/// auditd's acknowledgement ([`AuditGate::wait_acknowledged`]) and the
/// outcome's reserved slot. Finish it ([`AuditGate::finish_key_state_change`])
/// after keyd ran the change, or abandon it
/// ([`AuditGate::abandon_key_state_change`]) if the intent was not
/// acknowledged in time.
/// Spec: docs/questions/Q-346 (A-86), Q-365; docs/52 §3.11 R6 (a).
#[must_use = "the change must be waited for and its outcome slot filled"]
#[derive(Debug)]
pub(crate) struct PendingChange {
    pending: PendingIntent<KeyStateCall>,
    outcome: Reservation,
}

impl PendingChange {
    /// The intent record's sequence number in the window (unit tests).
    #[cfg(test)]
    pub(crate) fn intent_seq(&self) -> u64 {
        self.pending.seq()
    }
}

/// The outcome slot of a key-state change whose intent was acknowledged (or
/// not): filled by [`AuditGate::finish_key_state_change`] or
/// [`AuditGate::abandon_key_state_change`].
#[must_use = "the outcome slot must be filled"]
#[derive(Debug)]
pub(crate) struct OutcomeSlot(Reservation);

/// How the wait for a key-state change's intent ended
/// ([`AuditGate::wait_acknowledged`]).
/// Spec: docs/questions/Q-365 items 5, 8 (A-88); docs/52 §3.11 R6 (a).
#[must_use = "the outcome slot must be filled"]
#[derive(Debug)]
pub(crate) enum Waited {
    /// auditd acknowledged the intent: the proof keyd's change needs.
    Acknowledged(AckedIntent<KeyStateCall>, OutcomeSlot),
    /// Not acknowledged by the deadline: no proof — the change back, to be
    /// abandoned (`NotPerformed`), never run.
    NotAcknowledged(KeyStateCall, OutcomeSlot),
}

/// Shared by the engine thread (admit, record, the intent path) and the
/// audit client task (batches, acknowledgements, reachability): the shared
/// `ipc_audit::AuditGate` (module documentation), keyd's operation
/// classification, the tokio wake-up of the audit client, and the daemon's
/// own total of lost outcomes.
///
/// Spec: docs/50 R50-17, §8.1; docs/questions/Q-218 (A-57); docs/52 §3.11
/// R6.
#[derive(Debug)]
pub(crate) struct AuditGate {
    core: ipc_audit::AuditGate,
    /// Wakes the audit client when an event was committed.
    wake: Notify,
    /// Outcome records of key-state changes that could not be committed
    /// since start (A-86: the gap is counted) — the daemon's running total
    /// for stderr; each is also counted into the window's next summary
    /// (A-88).
    unrecorded: AtomicU64,
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
            core: ipc_audit::AuditGate::new(window),
            wake: Notify::new(),
            unrecorded: AtomicU64::new(0),
        }
    }

    /// Admit `operation` before keyd runs it: a gating operation reserves a
    /// slot, or is refused.
    ///
    /// Spec: docs/questions/Q-218 (A-57), Q-252 item 8 (A-64).
    pub(crate) fn admit(&self, operation: Operation) -> Result<Admission, GateClosed> {
        if !is_gating(operation) {
            return Ok(Admission::NotGating);
        }
        self.core.reserve().map(Admission::Gating).ok_or(GateClosed)
    }

    /// Give back the slot of an operation keyd did not run.
    pub(crate) fn release(&self, admission: Admission) {
        if let Admission::Gating(reservation) = admission {
            self.core.release(reservation);
        }
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
        let result = match admission {
            Admission::Gating(reservation) => self
                .core
                .with_steps(|steps| Self::commit_all(steps, reservation, records, overflowed))
                .unwrap_or(Err(RecordLost)),
            Admission::NotGating => {
                for record in records {
                    // Queued within the noise share, or counted for the
                    // next summary; an encoding failure is counted too.
                    self.core.offer_noise(&event_of(record));
                }
                Ok(())
            }
        };
        self.wake.notify_one();
        result
    }

    /// Commit the records of a gating operation. Spec: docs/10 I8;
    /// docs/questions/Q-252 item 9.
    fn commit_all(
        steps: &mut WindowSteps<'_>,
        reservation: Reservation,
        records: &[AuditRecord],
        overflowed: bool,
    ) -> Result<(), RecordLost> {
        let mut records = records.iter();
        let Some(first) = records.next() else {
            // keyd emitted no record (I8 broken): no unaudited result leaves.
            steps.release(reservation);
            return Err(RecordLost);
        };
        steps
            .commit(reservation, &event_of(first))
            .map_err(|_| RecordLost)?;
        for extra in records {
            let slot = steps.reserve().map_err(|_| RecordLost)?;
            steps
                .commit(slot, &event_of(extra))
                .map_err(|_| RecordLost)?;
        }
        if overflowed {
            return Err(RecordLost);
        }
        Ok(())
    }

    /// Start a key-state change (module documentation, step 1): with auditd
    /// reachable, reserve the intent's and the outcome's slots — both or
    /// neither — and commit `change`'s intent record into the first; then
    /// wake the audit client to send it.
    ///
    /// # Errors
    /// [`IntentRefused::GateClosed`] (auditd unreachable, or fewer than two
    /// free slots — counted for the next `WindowSummary`, as every refused
    /// gating reservation is); [`IntentRefused::NotRecorded`]. Nothing is
    /// left reserved or committed on an error.
    ///
    /// Spec: docs/questions/Q-346 (A-86), Q-365; Q-218 (A-57), Q-252 item 8
    /// (A-64); docs/52 §3.11 R6 (a).
    pub(crate) fn begin_key_state_change(
        &self,
        change: KeyStateCall,
    ) -> Result<PendingChange, IntentRefused> {
        let Some(slots) = self.core.reserve_all(2) else {
            return Err(IntentRefused::GateClosed);
        };
        let mut slots = slots.into_iter();
        let (Some(intent), Some(outcome)) = (slots.next(), slots.next()) else {
            return Err(IntentRefused::GateClosed);
        };
        let result = match self.core.begin_intent(intent, change) {
            Ok(pending) => Ok(PendingChange { pending, outcome }),
            Err(_) => {
                self.core.release(outcome);
                Err(IntentRefused::NotRecorded)
            }
        };
        if result.is_ok() {
            self.wake.notify_one();
        }
        result
    }

    /// Wait until auditd acknowledged the intent of `pending` — persisted it
    /// (docs/50 §8.1) — or `deadline` passed: the proof keyd's change needs
    /// (`ipc_keyd_server::execute_acknowledged`) with the outcome slot, or
    /// the change back without a proof (it is then abandoned, not run). A
    /// gate whose lock is poisoned gives no proof (fail closed). Blocks the
    /// engine thread on the shared gate's condition variable; never past
    /// `deadline`.
    ///
    /// Spec: docs/questions/Q-346 (A-86: "the record of the intent is
    /// acknowledged by auditd before the mutation"), Q-365; docs/50 §3.6
    /// (bounded waits), §8.1; docs/52 §3.11 R6 (a).
    pub(crate) fn wait_acknowledged(&self, pending: PendingChange, deadline: Instant) -> Waited {
        let PendingChange { pending, outcome } = pending;
        match self.core.wait_acknowledged(pending, deadline) {
            Ok(acked) => Waited::Acknowledged(acked, OutcomeSlot(outcome)),
            Err(change) => Waited::NotAcknowledged(change, OutcomeSlot(outcome)),
        }
    }

    /// A change whose wait could not even start (its deadline cannot be
    /// represented): no proof, the change back (fail closed).
    pub(crate) fn give_up(&self, pending: PendingChange) -> (KeyStateCall, OutcomeSlot) {
        match self.wait_acknowledged(pending, Instant::now()) {
            // Already acknowledged: still not run — the caller abandons it.
            Waited::Acknowledged(acked, slot) => (acked.into_inner(), slot),
            Waited::NotAcknowledged(change, slot) => (change, slot),
        }
    }

    /// Finish a key-state change keyd ran (module documentation, step 3):
    /// commit keyd's records into the reserved outcome slot (any further one
    /// into a fresh slot, as [`AuditGate::record`] does); then wake the audit
    /// client.
    ///
    /// # Errors
    /// [`RecordLost`] when the records could not all be committed (none, too
    /// many, or no slot for an extra one). The caller still replies with the
    /// operation's true result — the intent documents the attempt — and the
    /// gap is counted here: into the window's next `WindowSummary` (A-88)
    /// and into [`AuditGate::unrecorded_outcomes`].
    ///
    /// Spec: docs/questions/Q-346 (A-86), Q-365, Q-366 (A-88); docs/10 I8.
    pub(crate) fn finish_key_state_change(
        &self,
        slot: OutcomeSlot,
        records: &[AuditRecord],
        overflowed: bool,
    ) -> Result<(), RecordLost> {
        let OutcomeSlot(reservation) = slot;
        let result = self
            .core
            .with_steps(|steps| {
                let committed = Self::commit_all(steps, reservation, records, overflowed);
                Self::count_if_lost(steps, committed)
            })
            .unwrap_or(Err(RecordLost));
        self.settle_outcome(result)
    }

    /// Abandon a key-state change whose intent was not acknowledged in time
    /// (module documentation, step 2): keyd did not run it; its outcome
    /// record says so (`NotPerformed`) and goes into the reserved slot.
    ///
    /// # Errors
    /// [`RecordLost`] (counted, as for [`AuditGate::finish_key_state_change`]).
    ///
    /// Spec: docs/questions/Q-346 (A-86: "intent not acknowledged ⇒
    /// Unavailable, and nothing changed"), Q-365.
    pub(crate) fn abandon_key_state_change(
        &self,
        slot: OutcomeSlot,
        not_performed: &EventBody,
    ) -> Result<(), RecordLost> {
        let OutcomeSlot(reservation) = slot;
        let result = self
            .core
            .with_steps(|steps| {
                let committed = steps
                    .commit(reservation, not_performed)
                    .map(|_| ())
                    .map_err(|_| RecordLost);
                Self::count_if_lost(steps, committed)
            })
            .unwrap_or(Err(RecordLost));
        self.settle_outcome(result)
    }

    /// A lost outcome record goes into the window's next `WindowSummary`
    /// (`unrecorded_outcomes`), under the same lock as the failed commit, so
    /// the summary the audit client sends next carries it. A gate whose lock
    /// is poisoned cannot count it there; [`AuditGate::settle_outcome`]
    /// still counts it for stderr.
    /// Spec: decision A-88 (a lost-outcome count in the shared summary);
    /// docs/questions/Q-366 option (a), Q-395.
    fn count_if_lost(
        steps: &mut WindowSteps<'_>,
        result: Result<(), RecordLost>,
    ) -> Result<(), RecordLost> {
        if result.is_err() {
            steps.count_unrecorded_outcome();
        }
        result
    }

    /// Count an outcome that could not be committed in the daemon's total
    /// (for stderr), and wake the audit client (to send the summary that
    /// now counts it). Spec: docs/questions/Q-346 (A-86: "the gap is
    /// surfaced"), Q-366 (A-88).
    fn settle_outcome(&self, result: Result<(), RecordLost>) -> Result<(), RecordLost> {
        if result.is_err() {
            self.unrecorded.fetch_add(1, Ordering::Relaxed);
        }
        self.wake.notify_one();
        result
    }

    /// Outcome records of key-state changes that could not be committed
    /// since start (A-86).
    pub(crate) fn unrecorded_outcomes(&self) -> u64 {
        self.unrecorded.load(Ordering::Relaxed)
    }

    /// Record the audit client's view of auditd.
    pub(crate) fn set_reachable(&self, reachable: bool) {
        self.core.set_reachable(reachable);
    }

    /// Whether auditd is reachable (the audit client's view; tests — the
    /// stop's rule reads it inside the shared gate).
    #[cfg(test)]
    pub(crate) fn is_reachable(&self) -> bool {
        self.core.is_reachable()
    }

    /// The next batch to send, if nothing is in flight and anything is
    /// pending (unit tests play the audit client — in the daemon the shared
    /// client takes it from the shared gate, `ipc_audit::client`).
    /// Spec: docs/50 §3.6, §8.1.
    #[cfg(test)]
    pub(crate) fn next_batch(&self) -> Option<Append> {
        self.core.next_batch()
    }

    /// auditd's acknowledgement of the batch in flight; wakes the engine
    /// thread waiting for an intent's acknowledgement (A-86). Unit tests
    /// play auditd with it (in the daemon: the shared client).
    ///
    /// # Errors
    /// The window's [`WindowError`] (an acknowledgement that does not match;
    /// the connection is then closed).
    ///
    /// Spec: docs/50 §8.1.
    #[cfg(test)]
    pub(crate) fn acknowledge(&self, ack: &Ack) -> Result<usize, WindowError> {
        self.core.acknowledge(ack)
    }

    /// The audit connection dropped: the batch in flight goes back to the
    /// front (unit tests; in the daemon: the shared client).
    /// Spec: docs/50 §3.7, §8.1.
    #[cfg(test)]
    pub(crate) fn connection_lost(&self) {
        self.core.connection_lost();
    }

    /// Events not yet acknowledged plus outstanding reservations (tests —
    /// the stop's report comes from the shared gate's close).
    #[cfg(test)]
    pub(crate) fn outstanding(&self) -> usize {
        self.core.outstanding()
    }

    /// The stop's flush (`ipc_audit::AuditGate::close`): keyd stops waiting
    /// as soon as its link counts auditd as unreachable
    /// (`FlushWait::UntilAcknowledgedOrUnreachable` — the rule A-87 kept for
    /// keyd), then ends the link (`end_link`), then reports what is left.
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

    /// Read the window (unit tests).
    #[cfg(test)]
    pub(crate) fn inspect<T>(&self, read: impl FnOnce(&ipc_audit::SendWindow) -> T) -> Option<T> {
        self.core.inspect(read)
    }
}

/// What keyd's gate gives the one audit client (`ipc_audit::client`, task
/// R9b): the shared gate, the wake-up of a committed event, and keyd's
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

#[cfg(test)]
mod tests {
    use super::*;
    use ipc_audit::KeydOutcome;
    use ipc_keyd::Call;
    use ipc_keyd_server::{classify, Classified};
    use keyd::{CallerId, KeyHandle, PrincipalId};

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
            decision: None,
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

    /// A key-state change built for these tests: `create_key` by the admin
    /// (uid 807) on a PrincipalLongterm handle, classified against the
    /// development keyd (admitted: Provisioning, the Admin role, the
    /// purpose).
    fn change() -> KeyStateCall {
        let call = Call::CreateKey {
            handle: KeyHandle::new(
                PrincipalId::from_bytes([0xA1; 16]),
                keyd::KeyPurpose::PrincipalLongterm,
            ),
            binding: keyd::PrincipalBinding::new(
                krb_proto::Realm::new("EXAMPLE.ORG").unwrap(),
                krb_proto::PrincipalName {
                    name_type: 1,
                    name_string: vec![krb_proto::KerberosString::new("alice").unwrap()],
                },
            ),
        };
        let caller = CallerId {
            uid: 807,
            role: keyd::Role::Admin,
        };
        let started = krb_proto::KerberosTime::new(2026, 11, 13, 9, 0, 0).unwrap();
        let now = krb_proto::KerberosTime::new(2026, 11, 13, 10, 0, 0).unwrap();
        let keyd = crate::startup::development_keyd(krb_proto::Realm::new("EXAMPLE.ORG").unwrap())(
            &started,
        )
        .unwrap();
        match classify(&keyd, caller, now, call) {
            Classified::KeyStateChange(change) => change,
            other => panic!("{other:?}"),
        }
    }

    /// A-86 step 1: a key-state change takes its two slots (intent and
    /// outcome) or none — refused `GateClosed` (Busy) with auditd unreachable
    /// or one slot left, and nothing is left reserved or committed.
    #[test]
    fn a_key_state_change_takes_two_slots_or_none() {
        let gate = AuditGate::new(WindowConfig::new(2, 1).unwrap());
        assert_eq!(
            gate.begin_key_state_change(change()).map(|_| ()),
            Err(IntentRefused::GateClosed)
        );
        gate.set_reachable(true);
        let first = gate.admit(Operation::VerifySecret).unwrap();
        assert_eq!(
            gate.begin_key_state_change(change()).map(|_| ()),
            Err(IntentRefused::GateClosed)
        );
        assert_eq!(gate.outstanding(), 1, "only the other operation's slot");
        gate.release(first);
        let pending = gate.begin_key_state_change(change()).unwrap();
        assert_eq!(pending.intent_seq(), 1);
        assert_eq!(gate.outstanding(), 2, "the intent and the outcome's slot");
        let (_change, slot) = gate.give_up(pending);
        assert_eq!(
            gate.finish_key_state_change(slot, &[], false),
            Err(RecordLost)
        );
        assert_eq!(gate.unrecorded_outcomes(), 1, "the gap is counted");
        assert_eq!(gate.outstanding(), 1, "the intent alone");
        // A-88: and into the window's next summary, after the intent (the
        // summary takes the slot the lost outcome left free).
        assert_eq!(
            gate.inspect(ipc_audit::SendWindow::unrecorded_outcomes),
            Some(1)
        );
        let append = gate.next_batch().unwrap();
        let events: Vec<EventBody> = append
            .events()
            .iter()
            .map(|e| ipc_audit::decode_event(e.as_bytes()).unwrap())
            .collect();
        assert_eq!(events.len(), 2);
        assert!(matches!(&events[0], EventBody::Keyd(r) if r.result == KeydOutcome::Intent));
        // The refused second reservation above is counted apart: a refusal
        // ("not done") is not a lost outcome ("done, record lost").
        assert_eq!(
            events[1],
            EventBody::WindowSummary(ipc_audit::WindowSummary {
                suppressed_noise: 0,
                refused_gating: 1,
                unrecorded_outcomes: 1,
            })
        );
    }

    /// A-86 step 2 / docs/52 R6 (a): `wait_acknowledged` gives the proof
    /// once auditd acknowledged the intent — signalled from another thread,
    /// as the audit client does — and the change back, without a proof, at
    /// the deadline otherwise.
    #[test]
    fn the_proof_comes_only_with_the_acknowledgement() {
        let gate = std::sync::Arc::new(AuditGate::new(WindowConfig::DEFAULT));
        gate.set_reachable(true);
        let pending = gate.begin_key_state_change(change()).unwrap();
        let soon = Instant::now() + core::time::Duration::from_millis(50);
        let Waited::NotAcknowledged(change, slot) = gate.wait_acknowledged(pending, soon) else {
            panic!("not acknowledged");
        };
        assert_eq!(change.operation(), Operation::CreateKey);
        assert_eq!(
            gate.abandon_key_state_change(slot, &change.not_performed_event()),
            Ok(())
        );
        let pending = gate.begin_key_state_change(change).unwrap();
        let auditd = {
            let gate = std::sync::Arc::clone(&gate);
            std::thread::spawn(move || {
                std::thread::sleep(core::time::Duration::from_millis(20));
                let append = gate.next_batch().unwrap();
                let ack = Ack {
                    through_seq: append.last_seq(),
                    head_hash: [0; 32],
                };
                gate.acknowledge(&ack).unwrap();
            })
        };
        let later = Instant::now() + core::time::Duration::from_secs(10);
        let Waited::Acknowledged(acked, slot) = gate.wait_acknowledged(pending, later) else {
            panic!("acknowledged");
        };
        auditd.join().unwrap();
        assert_eq!(acked.get().operation(), Operation::CreateKey);
        assert_eq!(
            gate.finish_key_state_change(slot, &[], false),
            Err(RecordLost)
        );
        assert_eq!(gate.unrecorded_outcomes(), 1);
    }
}
