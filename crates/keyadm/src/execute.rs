//! `keyadm rotate-krbtgt | rotate-key | retire-kvno <decision id>`: run a
//! key operation dird decided (docs/51 §5.6, §6; A-102, docs/52 §4.2).
//!
//! # The flow (A-102)
//!
//! 1. A requester opens a request through admind; an approver approves it.
//!    The `Approve` that completes the quorum makes **dird** register the
//!    decision in keyd (Role::Ldap, `register_decision`): the operation,
//!    the key set it acts on and the approvers dird verified — under the
//!    request's id, which the `Approve` reply shows the operator.
//! 2. The operator runs `keyadm <command> <that id>`. keyadm sends keyd
//!    **only the decision id**, as Role::Admin, through `call_with_fate`
//!    (A-90): `rotate_krbtgt(id)`, `rotate_key(id)` or `retire_kvno(id)`.
//!    keyd runs the operation **it** holds under that id — never a handle,
//!    kvno or approval from keyadm; `rotate_krbtgt`'s dual-control token is
//!    built inside keyd from the decision's approvers (docs/52 §4.2).
//! 3. keyd answers the result. A decision of another kind than the command
//!    (`rotate-key` naming a `RetireKvno` decision), an unknown id, an
//!    expired decision or a wrong role is keyd's one uniform `Denied`; keyd's
//!    audit record names the reason (`NoDecision` / `DecisionMismatch`).
//!
//! **Exactly once** (docs/52 §3.10 (a)): keyd consumes a decision at its
//! first presentation and keeps the result until the decision expires; the
//! same id presented again returns that recorded result and runs nothing.
//! So after an unknown outcome the operator runs **the same command again**
//! and learns what keyd did — keyadm itself never retries and never
//! resends (A-87).
//!
//! keyadm has no channel to admind or dird any more (A-102: the
//! `FetchApproved` / `Complete` forwards of task A10 are retired): nothing a
//! compromised admind answers reaches keyadm (N2), and keyd's own records
//! — intent and outcome, with the decision id and its approvers — are the
//! record of what happened (docs/52 §3.3, §4.5).
//!
//! Spec: docs/51 §5.6, §6, §9; docs/52 §3.1, §3.3, §3.10, §4.2, §4.5, §4.6;
//! docs/10 §7, §9, §10; docs/33 §5; A-87; A-88; A-90; A-102.

use crate::ceremony::{classify, Outcome};
use crate::cli::Approved;
use crate::ports::KeydPort;
use ipc_keyd::{Answer, Call};
use keyd_types::{DecisionId, Kvno};

/// What one execution did.
/// Spec: module documentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionReport {
    /// The command.
    pub command: Approved,
    /// The decision id the command named.
    pub decision: DecisionId,
    /// keyd's call: the kvno of a rotation, `None` for `retire_kvno`.
    pub keyd: Outcome<Option<Kvno>>,
}

impl ExecutionReport {
    /// keyd performed the decided operation (now, or — for a replayed id —
    /// earlier, its recorded result).
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.keyd.succeeded()
    }

    /// keyd received the request and something is left to check: it
    /// refused (its audit record names why) or its outcome is unknown.
    /// Not sent and not performed mean keyd changed nothing (A-88).
    #[must_use]
    pub fn keyd_attempted(&self) -> bool {
        matches!(self.keyd, Outcome::Answered(Err(_)) | Outcome::Unknown(_))
    }
}

/// The keyd call of a command: the operation it names, with only the
/// decision id.
/// Spec: docs/52 §4.2, §4.6; docs/10 §7.
#[must_use]
pub fn call_of(command: Approved, decision: DecisionId) -> Call {
    match command {
        Approved::RotateKrbtgt => Call::RotateKrbtgt { decision },
        Approved::RotateKey => Call::RotateKey { decision },
        Approved::RetireKvno => Call::RetireKvno { decision },
    }
}

/// keyd's answer to the call, as an outcome carrying the kvno of a rotation.
/// Spec: docs/10 §7; crates/keyadm ceremony.rs (`classify`).
fn classify_call(
    command: Approved,
    result: Result<Answer, ipc_keyd::CallFailure>,
) -> Outcome<Option<Kvno>> {
    classify(result, |answer| match (command, answer) {
        (Approved::RotateKrbtgt, Answer::RotateKrbtgt(result))
        | (Approved::RotateKey, Answer::RotateKey(result)) => Some(result.map(Some)),
        (Approved::RetireKvno, Answer::RetireKvno(result)) => Some(result.map(|()| None)),
        _ => None,
    })
}

/// Run decision `id` with `command` (module documentation). Never retries.
///
/// Spec: docs/52 §3.10, §4.2; docs/51 §6; docs/10 §7; A-87; A-88; A-90.
pub fn run(keyd: &mut dyn KeydPort, command: Approved, id: u64) -> ExecutionReport {
    let decision = DecisionId::new(id);
    let outcome = classify_call(command, keyd.call_with_fate(&call_of(command, decision)));
    ExecutionReport {
        command,
        decision,
        keyd: outcome,
    }
}
