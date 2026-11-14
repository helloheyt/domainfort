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
//! Spec: docs/50 R50-17, §8.1; docs/questions/Q-218 (A-57), Q-252 items 8, 9
//! (A-64), Q-346 (A-86), Q-365, Q-366 (A-88), Q-395; docs/10 §10, I8;
//! docs/37 §2 (D63: no code path disables audit for a sensitive operation),
//! §5; docs/07 §8; docs/51 §5.7 item 2 (A-85).

use ipc_audit::{
    Ack, Append, EventBody, KeydOutcome, KeydReason, KeydRecord, Reservation, SendWindow,
    WindowConfig, WindowError,
};
use ipc_keyd::Call;
use keyd::authz::HandleSlot;
use keyd::{
    AuditKeyRef, AuditOutcome, AuditReason, AuditRecord, AuditSink, CallerId, DecisionId,
    DecisionIntent, KeyHandle, Kvno, Operation, PrincipalId,
};
use krb_proto::KerberosTime;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Condvar, Mutex, MutexGuard};
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

/// A key-state change whose intent is in the window: the intent's sequence
/// number, to wait for its acknowledgement, and the outcome's reserved slot.
/// Finish it ([`AuditGate::finish_key_state_change`]) after keyd ran the
/// operation, or abandon it ([`AuditGate::abandon_key_state_change`]) if the
/// intent was not acknowledged in time.
/// Spec: docs/questions/Q-346 (A-86), Q-365.
#[must_use = "the outcome slot must be filled"]
#[derive(Debug)]
pub(crate) struct PendingOutcome {
    intent_seq: u64,
    slot: Reservation,
}

impl PendingOutcome {
    /// The intent record's sequence number in the window.
    pub(crate) fn intent_seq(&self) -> u64 {
        self.intent_seq
    }
}

/// The non-secret identity of a key-state change, from which the daemon
/// writes its intent and, if keyd never ran it, its not-performed outcome:
/// the fields keyd's own record of the operation carries before keyd resolves
/// anything — the time, the caller, the operation, the handle, the kvno a
/// `retire_kvno` names, the approvers of a `rotate_krbtgt` (crates/keyd
/// admin.rs, directory.rs: `AuditFields::for_handle`, then those two). No
/// password, binding or key: the call's other arguments are not kept.
///
/// The same holds for `grant_set_secret` (task A15a), which loosens keyd's
/// authorization and so takes the same path (`keyd::requires_acknowledged_intent`):
/// its first key target is the record's handle, its second (a computer's
/// `Service` key set) the record's secondary key, as keyd's own record of it
/// (crates/keyd decision.rs); no binding and no lifetime.
///
/// **A-102 (docs/52 §4.5):** `register_decision` takes the same path (it
/// loosens keyd): the record names the decided key sets, the kvno a
/// `RetireKvno` decision names, the first two approvers and the decision
/// id. An **execution** of a decision (`rotate_key`, `rotate_krbtgt`,
/// `retire_kvno`, `destroy_key_set`) names only its id: its intent is built
/// from keyd's own table ([`KeyStateIntent::decided`],
/// `keyd::Keyd::decided_intent`) — never from the request.
///
/// Spec: docs/10 §10 (`{ ts, caller_role, caller_uid, op, principal,
/// purpose, kvno, result }`), §12 I8; docs/questions/Q-346 (A-86), Q-365,
/// Q-452 item 1; docs/52 §4.5.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KeyStateIntent {
    ts: KerberosTime,
    caller: CallerId,
    op: Operation,
    /// The handle in the operation's `Primary` slot (`None` only for a grant
    /// that names no key target — keyd refuses it as its outcome).
    primary: Option<KeyHandle>,
    /// A grant's second key target (`Secondary` slot).
    secondary: Option<KeyHandle>,
    kvno: Option<Kvno>,
    approvers: Option<[PrincipalId; 2]>,
    /// The decision registered or run (A-102).
    decision: Option<DecisionId>,
}

impl KeyStateIntent {
    /// The intent of `call` by `caller` at `now` if `call` needs one and
    /// names its parameters itself — `set_secret`, `create_key`,
    /// `grant_set_secret`, `register_decision` — else `None`. An execution of
    /// a decision names only its id: its intent is
    /// [`KeyStateIntent::decided`]. The match is exhaustive over [`Call`]: a
    /// new call does not compile until it is classified here. The engine
    /// checks this against `keyd::requires_acknowledged_intent` and refuses
    /// (fail closed) when they disagree.
    ///
    /// Spec: docs/10 §6, §7; docs/questions/Q-346 (A-86), Q-452 item 1;
    /// docs/52 §4.5 (A-102).
    pub(crate) fn of(caller: CallerId, now: KerberosTime, call: &Call) -> Option<KeyStateIntent> {
        let (op, primary, secondary, kvno, approvers, decision) = match call {
            Call::SetSecret { handle, .. } => {
                (Operation::SetSecret, Some(*handle), None, None, None, None)
            }
            Call::CreateKey { handle, .. } => {
                (Operation::CreateKey, Some(*handle), None, None, None, None)
            }
            Call::GrantSetSecret { targets, .. } => (
                Operation::GrantSetSecret,
                targets.first().map(|t| t.handle),
                targets.get(1).map(|t| t.handle),
                None,
                None,
                None,
            ),
            Call::RegisterDecision {
                id,
                operation,
                approvers,
                ..
            } => (
                Operation::RegisterDecision,
                operation.primary(),
                operation.secondary(),
                operation.kvno(),
                match approvers.as_slice() {
                    [first, second, ..] => Some([*first, *second]),
                    _ => None,
                },
                Some(*id),
            ),
            Call::RotateKey { .. }
            | Call::RotateKrbtgt { .. }
            | Call::RetireKvno { .. }
            | Call::DestroyKeySet { .. }
            | Call::VerifyPreauth { .. }
            | Call::IssueAsRep { .. }
            | Call::OpenFastArmor { .. }
            | Call::OpenAndVerifyTgt { .. }
            | Call::IssueTgsRep { .. }
            | Call::SealFastError { .. }
            | Call::OpenAndVerifyServiceTicket { .. }
            | Call::VerifySecret { .. }
            | Call::DescribeConfig
            | Call::Ping
            | Call::SealCeremony
            | Call::ListDestroyDecisions { .. } => return None,
        };
        Some(KeyStateIntent {
            ts: now,
            caller,
            op,
            primary,
            secondary,
            kvno,
            approvers,
            decision,
        })
    }

    /// This intent naming `decision` — the set-secret decision a
    /// `set_secret` will consume, as keyd's table names it
    /// (`keyd::Keyd::secret_decision`; docs/52 §4.5).
    #[must_use]
    pub(crate) fn with_decision(self, decision: Option<DecisionId>) -> KeyStateIntent {
        KeyStateIntent { decision, ..self }
    }

    /// The intent of executing a decision with `op` by `caller` at `now`,
    /// from the facts keyd's own table holds (`keyd::Keyd::decided_intent`;
    /// A-102, docs/52 §4.5): the decided key sets, kvno and approvers, and
    /// the decision id.
    /// Spec: docs/52 §4.2, §4.5; docs/questions/Q-346 (A-86).
    pub(crate) fn decided(
        caller: CallerId,
        now: KerberosTime,
        op: Operation,
        facts: &DecisionIntent,
    ) -> KeyStateIntent {
        KeyStateIntent {
            ts: now,
            caller,
            op,
            primary: facts.primary,
            secondary: facts.secondary,
            kvno: facts.kvno,
            approvers: facts.approvers,
            decision: Some(facts.decision),
        }
    }

    /// The operation.
    pub(crate) fn op(&self) -> Operation {
        self.op
    }

    /// The handles the operation acts on, in their slots — for keyd's
    /// authorization step (`keyd::Keyd::admits`): the `Primary` handle, and a
    /// grant's `Secondary` one. None for `register_decision`, whose
    /// authorization step is the role alone (keyd judges the decided key
    /// sets' purposes inside the operation, A-102).
    /// Spec: docs/10 §2 (I3); docs/questions/Q-452 item 1; docs/52 §4.2.
    pub(crate) fn handles(&self) -> Vec<(HandleSlot, &KeyHandle)> {
        if self.op == Operation::RegisterDecision {
            return Vec::new();
        }
        let mut handles = Vec::with_capacity(2);
        if let Some(primary) = &self.primary {
            handles.push((HandleSlot::Primary, primary));
        }
        if let Some(secondary) = &self.secondary {
            handles.push((HandleSlot::Secondary, secondary));
        }
        handles
    }

    /// The wire record of this change in `phase` (`Intent` or
    /// `NotPerformed`): keyd's record layout, filled as keyd fills its own
    /// record of the operation and converted by ipc-audit; its outcome is the
    /// phase and its reason `None` (ipc-audit `KeydOutcome`: the phases are
    /// the daemon's codes, not keyd's).
    ///
    /// Spec: docs/10 §10; docs/questions/Q-346 (A-86), Q-365.
    pub(crate) fn event(&self, phase: KeydOutcome) -> EventBody {
        let record = AuditRecord {
            ts: self.ts,
            caller_role: self.caller.role,
            caller_uid: self.caller.uid,
            op: self.op,
            principal: self.primary.map(|h| h.principal),
            purpose: self.primary.map(|h| h.purpose),
            kvno: self.kvno,
            secondary: self.secondary.map(|h| AuditKeyRef {
                principal: h.principal,
                purpose: h.purpose,
                kvno: None,
            }),
            approvers: self.approvers,
            decision: self.decision,
            // keyd has no phase outcome; replaced by `phase` below.
            result: AuditOutcome::Success,
            reason: AuditReason::None,
        };
        let mut wire = KeydRecord::from(&record);
        wire.result = phase;
        wire.reason = KeydReason::None;
        EventBody::Keyd(Box::new(wire))
    }
}

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
    /// Wakes the engine thread waiting for an intent's acknowledgement
    /// (A-86); paired with `state`.
    acked: Condvar,
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
            state: Mutex::new(GateState {
                window: SendWindow::new(window),
                reachable: false,
            }),
            wake: Notify::new(),
            acked: Condvar::new(),
            unrecorded: AtomicU64::new(0),
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

    /// Start a key-state change (module documentation, step 1): with auditd
    /// reachable, reserve the intent's and the outcome's slots — both or
    /// neither — and commit `intent` into the first; then wake the audit
    /// client to send it.
    ///
    /// # Errors
    /// [`IntentRefused::GateClosed`] (auditd unreachable, or fewer than two
    /// free slots — counted for the next `WindowSummary`, as every refused
    /// gating reservation is); [`IntentRefused::NotRecorded`]. Nothing is
    /// left reserved or committed on an error.
    ///
    /// Spec: docs/questions/Q-346 (A-86), Q-365; Q-218 (A-57), Q-252 item 8
    /// (A-64).
    pub(crate) fn begin_key_state_change(
        &self,
        intent: &EventBody,
    ) -> Result<PendingOutcome, IntentRefused> {
        let result = match self.lock() {
            None => Err(IntentRefused::GateClosed),
            Some(mut state) => {
                let reachable = state.reachable;
                Self::reserve_and_commit_intent(&mut state.window, reachable, intent)
            }
        };
        if result.is_ok() {
            self.wake.notify_one();
        }
        result
    }

    /// The two reservations and the intent's commit, under one lock.
    /// Spec: docs/questions/Q-346 (A-86).
    fn reserve_and_commit_intent(
        window: &mut SendWindow,
        reachable: bool,
        intent: &EventBody,
    ) -> Result<PendingOutcome, IntentRefused> {
        if !reachable {
            return Err(IntentRefused::GateClosed);
        }
        let intent_slot = window.reserve().map_err(|_| IntentRefused::GateClosed)?;
        let slot = match window.reserve() {
            Ok(slot) => slot,
            Err(_) => {
                window.release(intent_slot);
                return Err(IntentRefused::GateClosed);
            }
        };
        match window.commit(intent_slot, intent) {
            Ok(intent_seq) => Ok(PendingOutcome { intent_seq, slot }),
            Err(_) => {
                window.release(slot);
                Err(IntentRefused::NotRecorded)
            }
        }
    }

    /// Wait until auditd acknowledged the event numbered `seq` — persisted
    /// it (docs/50 §8.1: `Ack` only after the sync) — or `deadline` passed.
    /// Acknowledgements are cumulative and in order (one batch in flight,
    /// oldest first), so `seq` is acknowledged once the last `Ack` reaches
    /// it. A gate whose lock is poisoned answers `false` (fail closed).
    ///
    /// Blocks the calling thread (the engine's) on a condition variable that
    /// [`AuditGate::acknowledge`] signals; never past `deadline`.
    ///
    /// Spec: docs/questions/Q-346 (A-86: "the record of the intent is
    /// acknowledged by auditd before the mutation"), Q-365; docs/50 §3.6
    /// (bounded waits), §8.1.
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
        pending: PendingOutcome,
        records: &[AuditRecord],
        overflowed: bool,
    ) -> Result<(), RecordLost> {
        let PendingOutcome { slot, .. } = pending;
        let result = match self.lock() {
            Some(mut state) => {
                let committed = Self::commit_all(&mut state.window, slot, records, overflowed);
                Self::count_if_lost(&mut state.window, committed)
            }
            None => Err(RecordLost),
        };
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
        pending: PendingOutcome,
        not_performed: &EventBody,
    ) -> Result<(), RecordLost> {
        let PendingOutcome { slot, .. } = pending;
        let result = match self.lock() {
            Some(mut state) => {
                let committed = state
                    .window
                    .commit(slot, not_performed)
                    .map(|_| ())
                    .map_err(|_| RecordLost);
                Self::count_if_lost(&mut state.window, committed)
            }
            None => Err(RecordLost),
        };
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
        window: &mut SendWindow,
        result: Result<(), RecordLost>,
    ) -> Result<(), RecordLost> {
        if result.is_err() {
            window.count_unrecorded_outcome();
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
        let result = match self.lock() {
            Some(mut state) => state.window.acknowledge(ack),
            None => Err(WindowError::UnexpectedAck),
        };
        if result.is_ok() {
            // The engine thread may be waiting for this acknowledgement
            // (A-86, `wait_acknowledged`).
            self.acked.notify_all();
        }
        result
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

    /// An intent built for these tests: `create_key` by the admin (uid 807)
    /// on a PrincipalLongterm handle.
    fn intent() -> EventBody {
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
        let now = krb_proto::KerberosTime::new(2026, 11, 13, 10, 0, 0).unwrap();
        KeyStateIntent::of(caller, now, &call)
            .unwrap()
            .event(KeydOutcome::Intent)
    }

    /// A-86 step 1: a key-state change takes its two slots (intent and
    /// outcome) or none — refused `GateClosed` (Busy) with auditd unreachable
    /// or one slot left, and nothing is left reserved or committed.
    #[test]
    fn a_key_state_change_takes_two_slots_or_none() {
        let gate = AuditGate::new(WindowConfig::new(2, 1).unwrap());
        assert_eq!(
            gate.begin_key_state_change(&intent()).map(|_| ()),
            Err(IntentRefused::GateClosed)
        );
        gate.set_reachable(true);
        let first = gate.admit(Operation::VerifySecret).unwrap();
        assert_eq!(
            gate.begin_key_state_change(&intent()).map(|_| ()),
            Err(IntentRefused::GateClosed)
        );
        assert_eq!(gate.outstanding(), 1, "only the other operation's slot");
        let Admission::Gating(first) = first else {
            panic!("gating");
        };
        gate.with_window(|window| window.release(first));
        let pending = gate.begin_key_state_change(&intent()).unwrap();
        assert_eq!(pending.intent_seq(), 1);
        assert_eq!(gate.outstanding(), 2, "the intent and the outcome's slot");
        assert_eq!(
            gate.finish_key_state_change(pending, &[], false),
            Err(RecordLost)
        );
        assert_eq!(gate.unrecorded_outcomes(), 1, "the gap is counted");
        assert_eq!(gate.outstanding(), 1, "the intent alone");
        // A-88: and into the window's next summary, after the intent (the
        // summary takes the slot the lost outcome left free).
        assert_eq!(
            gate.with_window(|window| window.unrecorded_outcomes()),
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

    /// A-86 step 2: `wait_acknowledged` returns once auditd acknowledged the
    /// intent — signalled from another thread, as the audit client does —
    /// and returns `false` at the deadline otherwise.
    #[test]
    fn the_wait_ends_at_the_acknowledgement_or_the_deadline() {
        let gate = std::sync::Arc::new(AuditGate::new(WindowConfig::DEFAULT));
        gate.set_reachable(true);
        let pending = gate.begin_key_state_change(&intent()).unwrap();
        let soon = Instant::now() + core::time::Duration::from_millis(50);
        assert!(!gate.wait_acknowledged(pending.intent_seq(), soon));
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
        assert!(gate.wait_acknowledged(pending.intent_seq(), later));
        auditd.join().unwrap();
        let not_performed = intent();
        assert_eq!(
            gate.abandon_key_state_change(pending, &not_performed),
            Ok(())
        );
        assert_eq!(gate.unrecorded_outcomes(), 0);
    }
}
