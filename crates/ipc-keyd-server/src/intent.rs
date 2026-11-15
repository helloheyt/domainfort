//! Which calls need an acknowledged intent, and the proof-carrying path that
//! is the only way to run them (docs/52 §3.11 R6, decision A-102).
//!
//! # The class (docs/52 §3.11 C11)
//!
//! A-86 / A-88: a key-state change (`keyd::changes_key_state`) — or a call
//! that loosens keyd (`grant_set_secret`, `register_decision`;
//! `keyd::requires_acknowledged_intent`) — that keyd's authorization step
//! admits has its intent record acknowledged by auditd **before** keyd runs
//! it. Until task R6 that ordering was the keyd-daemon engine's discipline:
//! the one entry point, `execute`, ran any call it was given.
//!
//! # The root-level change
//!
//! [`classify`] is the one place that decides, from keyd's own
//! authorization step (`Keyd::admits`, `Keyd::decided_intent`), whether a
//! call needs an acknowledged intent:
//!
//! * [`Classified::Plain`] — it does not (no key state, nothing loosened, or
//!   keyd's authorization step refuses it — refused calls change nothing and
//!   keep their one record, A-88): run with [`crate::execute`], which checks
//!   again at the moment it runs and refuses to run an admitted change
//!   ([`crate::NotRun`]);
//! * [`Classified::KeyStateChange`] — it does: a [`KeyStateCall`], the call
//!   with its intent record (an `ipc_audit::IntentRecord`), runnable **only**
//!   through [`crate::execute_acknowledged`], which takes an
//!   `ipc_audit::AckedIntent<KeyStateCall>` by value — made only by the
//!   daemon's `ipc_audit::AuditGate` after auditd acknowledged **that**
//!   call's intent record.
//!
//! So keyd runs no admitted key-state change, and no loosening, without its
//! intent acknowledged — by construction of this crate's API, not of the
//! daemon's code.
//!
//! The intent record ([`KeyStateIntent`], moved here from keyd-daemon) is
//! derived from the call itself — or, for an execution of a decision, from
//! keyd's table — so the acknowledged record describes exactly the call the
//! proof carries.
//!
//! Spec: docs/52 §3.11 R6 (a), §4.5, §7 R6; docs/10 §2, §6, §7, §10, §12
//! I8; docs/questions/Q-346 (A-86), Q-365 (A-88), Q-452 item 1.

use ipc_audit::{EventBody, IntentRecord, KeydOutcome, KeydReason, KeydRecord};
use ipc_keyd::Call;
use keyd::authz::HandleSlot;
use keyd::{
    requires_acknowledged_intent, AuditKeyRef, AuditOutcome, AuditReason, AuditRecord, AuditSink,
    CallerId, DecisionId, DecisionIntent, EntropySource, KeyHandle, KeyStore, Keyd, Kvno,
    Operation, PrincipalId,
};
use krb_proto::KerberosTime;

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
/// **Task K4 (docs/53 §9):** `complete_change_password` is a key-state
/// change: its record names the target handle and — as for `set_secret` —
/// the decision keyd's table holds for it (`keyd::Keyd::secret_decision`).
/// The context id and the password are not kept (no field for them).
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
pub struct KeyStateIntent {
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
    /// `grant_set_secret`, `register_decision`, `complete_change_password`
    /// (task K4) — else `None`. An execution of
    /// a decision names only its id: its intent is
    /// [`KeyStateIntent::decided`]. The match is exhaustive over [`Call`]: a
    /// new call does not compile until it is classified here. [`classify`]
    /// checks this against `keyd::requires_acknowledged_intent` and answers
    /// [`Classified::Inconsistent`] (fail closed) when they disagree.
    ///
    /// Spec: docs/10 §6, §7; docs/questions/Q-346 (A-86), Q-452 item 1;
    /// docs/52 §4.5 (A-102).
    #[must_use]
    pub fn of(caller: CallerId, now: KerberosTime, call: &Call) -> Option<KeyStateIntent> {
        let (op, primary, secondary, kvno, approvers, decision) = match call {
            Call::SetSecret { handle, .. } => {
                (Operation::SetSecret, Some(*handle), None, None, None, None)
            }
            Call::CreateKey { handle, .. } => {
                (Operation::CreateKey, Some(*handle), None, None, None, None)
            }
            Call::CompleteChangePassword { target, .. } => (
                Operation::CompleteChangePassword,
                Some(*target),
                None,
                None,
                None,
                None,
            ),
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
            | Call::VerifyOperationTicket { .. }
            | Call::VerifySecret { .. }
            | Call::DescribeConfig
            | Call::Ping
            | Call::SealCeremony
            | Call::ListDestroyDecisions { .. }
            | Call::OpenChangePasswordRequest { .. }
            | Call::SealChangePasswordError { .. } => return None,
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
    pub fn with_decision(self, decision: Option<DecisionId>) -> KeyStateIntent {
        KeyStateIntent { decision, ..self }
    }

    /// The intent of executing a decision with `op` by `caller` at `now`,
    /// from the facts keyd's own table holds (`keyd::Keyd::decided_intent`;
    /// A-102, docs/52 §4.5): the decided key sets, kvno and approvers, and
    /// the decision id.
    /// Spec: docs/52 §4.2, §4.5; docs/questions/Q-346 (A-86).
    #[must_use]
    pub fn decided(
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
    #[must_use]
    pub fn op(&self) -> Operation {
        self.op
    }

    /// The handles the operation acts on, in their slots — for keyd's
    /// authorization step (`keyd::Keyd::admits`): the `Primary` handle, and a
    /// grant's `Secondary` one. None for `register_decision`, whose
    /// authorization step is the role alone (keyd judges the decided key
    /// sets' purposes inside the operation, A-102).
    /// Spec: docs/10 §2 (I3); docs/questions/Q-452 item 1; docs/52 §4.2.
    #[must_use]
    pub fn handles(&self) -> Vec<(HandleSlot, &KeyHandle)> {
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
    #[must_use]
    pub fn event(&self, phase: KeydOutcome) -> EventBody {
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

/// A call that needs an acknowledged intent and that keyd's authorization
/// step admits, with its intent record. Made only by [`classify`]; run only
/// through [`crate::execute_acknowledged`], which takes it as an
/// `ipc_audit::AckedIntent<KeyStateCall>`. Not `Clone`.
/// Spec: docs/52 §3.11 R6 (a); docs/questions/Q-365 (A-88).
#[derive(Debug)]
pub struct KeyStateCall {
    pub(crate) caller: CallerId,
    pub(crate) now: KerberosTime,
    pub(crate) call: Call,
    intent: KeyStateIntent,
}

impl KeyStateCall {
    /// The caller (the connection's identity).
    #[must_use]
    pub fn caller(&self) -> CallerId {
        self.caller
    }

    /// The operation.
    #[must_use]
    pub fn operation(&self) -> Operation {
        self.intent.op
    }

    /// Its intent's identity.
    #[must_use]
    pub fn intent(&self) -> &KeyStateIntent {
        &self.intent
    }

    /// The outcome record of this change when keyd never ran it — its intent
    /// was not acknowledged in time (`NotPerformed`, A-88).
    /// Spec: docs/questions/Q-365 item 5.
    #[must_use]
    pub fn not_performed_event(&self) -> EventBody {
        self.intent.event(KeydOutcome::NotPerformed)
    }
}

impl IntentRecord for KeyStateCall {
    /// The intent record (`KeydOutcome::Intent`).
    /// Spec: docs/questions/Q-365 items 4, 6 (A-88).
    fn intent_event(&self) -> EventBody {
        self.intent.event(KeydOutcome::Intent)
    }
}

/// A call that needs no acknowledged intent — or one keyd's authorization
/// step refuses — for [`crate::execute`]. Made only by [`classify`].
/// Spec: docs/questions/Q-365 item 3 (A-88: refusals keep one record).
#[derive(Debug)]
pub struct PlainCall {
    pub(crate) caller: CallerId,
    pub(crate) now: KerberosTime,
    pub(crate) call: Call,
}

impl PlainCall {
    /// The operation.
    #[must_use]
    pub fn operation(&self) -> Operation {
        self.call.operation()
    }
}

/// How a call is run (module documentation).
/// Spec: docs/52 §3.11 R6 (a); docs/questions/Q-365 (A-88).
#[derive(Debug)]
pub enum Classified {
    /// Run it with [`crate::execute`].
    Plain(PlainCall),
    /// Have its intent acknowledged, then run it with
    /// [`crate::execute_acknowledged`].
    KeyStateChange(KeyStateCall),
    /// keyd says it needs an intent but no intent can be derived from it
    /// (cannot happen: the classifications are pinned by tests) — not
    /// served (fail closed; AGENTS.md §6).
    Inconsistent,
}

/// Whether a call needs an acknowledged intent now.
enum Needs {
    No,
    Intent(KeyStateIntent),
    Inconsistent,
}

/// The decision (module documentation), from keyd's own authorization step
/// at `now`: reads only, no record.
/// Spec: docs/questions/Q-365 item 3 (A-88); docs/52 §4.5 (A-102).
fn needs<S: KeyStore, A: AuditSink, E: EntropySource>(
    keyd: &Keyd<S, A, E>,
    caller: &CallerId,
    now: &KerberosTime,
    call: &Call,
) -> Needs {
    let op = call.operation();
    if !requires_acknowledged_intent(op) {
        return Needs::No;
    }
    if let Some(decision) = call.decision() {
        // A-102: an execution names only dird's decision; its intent is
        // built from keyd's table. No pending decision (refused, or already
        // run and replayed) changes nothing.
        return match keyd.decided_intent(caller, op, decision, now) {
            Some(facts) => Needs::Intent(KeyStateIntent::decided(*caller, *now, op, &facts)),
            None => Needs::No,
        };
    }
    let Some(intent) = KeyStateIntent::of(*caller, *now, call).filter(|i| i.op() == op) else {
        return Needs::Inconsistent;
    };
    if !keyd.admits(caller, op, &intent.handles(), now) {
        return Needs::No;
    }
    // A-102 (docs/52 §4.5): a `set_secret` names its handle; the decision
    // it will consume is keyd's to say. The same for a change-password
    // completion's target (task K4).
    match call {
        Call::SetSecret { handle, .. } => {
            Needs::Intent(intent.with_decision(keyd.secret_decision(handle)))
        }
        Call::CompleteChangePassword { target, .. } => {
            Needs::Intent(intent.with_decision(keyd.secret_decision(target)))
        }
        _ => Needs::Intent(intent),
    }
}

/// Classify `call` by `caller` at `now` (the daemon's clock) against
/// `keyd`'s authorization step (module documentation).
/// Spec: docs/52 §3.11 R6 (a); docs/questions/Q-365 (A-88); docs/10 §2.
pub fn classify<S: KeyStore, A: AuditSink, E: EntropySource>(
    keyd: &Keyd<S, A, E>,
    caller: CallerId,
    now: KerberosTime,
    call: Call,
) -> Classified {
    match needs(keyd, &caller, &now, &call) {
        Needs::No => Classified::Plain(PlainCall { caller, now, call }),
        Needs::Intent(intent) => Classified::KeyStateChange(KeyStateCall {
            caller,
            now,
            call,
            intent,
        }),
        Needs::Inconsistent => Classified::Inconsistent,
    }
}

/// Whether `plain` still needs no acknowledged intent — checked by
/// [`crate::execute`] at the moment it runs, so a classification that went
/// stale (keyd's state changed in between) cannot run an admitted change.
/// Spec: docs/52 §3.11 R6 (a).
pub(crate) fn still_plain<S: KeyStore, A: AuditSink, E: EntropySource>(
    keyd: &Keyd<S, A, E>,
    plain: &PlainCall,
) -> bool {
    matches!(
        needs(keyd, &plain.caller, &plain.now, &plain.call),
        Needs::No
    )
}
