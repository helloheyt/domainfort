//! `keyadm rotate-krbtgt | rotate-key | retire-kvno <request id>`: execute
//! a key operation dird approved (docs/51 §5.6, §6; task A10).
//!
//! # The steps
//!
//! 1. **Fetch** — `FetchApproved {id}` to `admin.sock` (admind forwards it
//!    only because this process runs as `keyadm_uid`). dird answers the
//!    approved operation, the key set it acts on and the requester's and
//!    approvers' objectGUIDs — once: a fetched request cannot be fetched
//!    again (one approval, one execution).
//! 2. **Check** — the approved operation must be the one the command names
//!    (`rotate-krbtgt` executes only a `rotate_krbtgt`, …), and the reply
//!    must be coherent (a `rotate_krbtgt` names the krbtgt purpose and at
//!    least one approver; a service operation names its own object). Any
//!    mismatch ⇒ keyd is **not** called and dird is told "not performed".
//! 3. **keyd** — as Role::Admin, through `call_with_fate` (A-90):
//!    `rotate_krbtgt(DualControlToken { approver_1: requester, approver_2:
//!    first approver })`, `rotate_key(handle)` or `retire_kvno(handle,
//!    kvno)` (docs/10 §7). keyd still trusts keyadm for the token's
//!    truthfulness — the residual of crates/keyd-types model.rs — but the
//!    token comes from approvals dird verified (docs/51 §6).
//! 4. **Complete** — `Complete {id, outcome}`: performed (with the new kvno
//!    of a rotation), refused by keyd, not performed, or outcome unknown —
//!    exactly what the ipc-keyd client knows (A-88, A-90). dird records it
//!    and drops the request.
//!
//! keyadm never retries a keyd call and never resends a request (A-87); an
//! unknown outcome is reported as such, with where to look (keyd's audit
//! log holds the intent and the outcome, A-88).
//!
//! Spec: docs/51 §5.6, §6, §9 (the "krbtgt rotation" row); docs/10 §7, §9,
//! §10; docs/33 §5; A-87; A-88; A-90.

use crate::ceremony::{classify, Outcome};
use crate::cli::Approved;
use crate::ports::{AdmindPort, KeydPort};
use ipc_admin::{AdmindFailure, RefusalStatus, Reply, Request};
use ipc_dird_admin::{ApprovedKeyOperation, KeyOperation, KeyOperationOutcome, KeyadmRequest};
use ipc_keyd::{Answer, Call};
use keyd_types::{DualControlToken, KeyPurpose, Kvno, PrincipalId};

/// How the fetch ended.
/// Spec: docs/51 §6.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fetch {
    /// dird answered the approved operation.
    Fetched(ApprovedKeyOperation),
    /// dird (or admind) refused it: unknown or expired id (`NotFound`), not
    /// yet approved (`ApprovalRequired`), already fetched (`Conflict`), this
    /// account not `keyadm_uid` (`Denied`), … Nothing was fetched.
    Refused(RefusalStatus),
    /// admind did not answer usably.
    Failed(AdmindFailure),
}

/// Why an approved operation was not executed.
/// Spec: module documentation, step 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mismatch {
    /// The approved operation is not the one the command names.
    Command(KeyOperation),
    /// dird's reply is not coherent (purpose, approvers, object).
    Incoherent,
}

/// How dird took the completion report.
/// Spec: docs/51 §6 (`Complete {id, outcome, kvno}`, recorded in dird).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Completion {
    /// dird recorded it.
    Recorded,
    /// dird refused it (status).
    Refused(RefusalStatus),
    /// admind did not answer usably.
    Failed(AdmindFailure),
}

/// What one execution did.
/// Spec: module documentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionReport {
    /// The command.
    pub command: Approved,
    /// The request's id.
    pub id: u64,
    /// The fetch.
    pub fetch: Fetch,
    /// Why keyd was not called after a successful fetch, if so.
    pub mismatch: Option<Mismatch>,
    /// keyd's call: the kvno of a rotation, `None` for `retire_kvno`.
    pub keyd: Option<Outcome<Option<Kvno>>>,
    /// The completion report, if one was sent.
    pub completion: Option<Completion>,
}

impl ExecutionReport {
    /// keyd performed the operation and dird recorded it.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        matches!(self.keyd, Some(Outcome::Answered(Ok(_))))
            && self.completion == Some(Completion::Recorded)
    }

    /// keyd was asked (whatever came of it): something may have changed.
    #[must_use]
    pub fn keyd_attempted(&self) -> bool {
        matches!(
            self.keyd,
            Some(Outcome::Answered(_) | Outcome::NotPerformed(_) | Outcome::Unknown(_))
        )
    }
}

/// Whether `operation` is the command's. Spec: docs/51 §6.
fn same_command(command: Approved, operation: &KeyOperation) -> bool {
    matches!(
        (command, operation),
        (Approved::RotateKrbtgt, KeyOperation::RotateKrbtgt)
            | (Approved::RotateKey, KeyOperation::RotateKey { .. })
            | (Approved::RetireKvno, KeyOperation::RetireKvno { .. })
    )
}

/// The keyd call of an approved operation, if dird's reply is coherent.
/// Spec: docs/10 §7 (`rotate_krbtgt(DualControlToken)`, `rotate_key`,
/// `retire_kvno`); crates/keyd-types model.rs (`DualControlToken`: two
/// distinct approvers); docs/51 §6 (`approver_1` = the requester,
/// `approver_2` = the approver).
fn keyd_call(approved: &ApprovedKeyOperation) -> Option<Call> {
    let principal = PrincipalId::from_bytes(approved.principal.to_packet());
    match approved.operation {
        KeyOperation::RotateKrbtgt => {
            let approver = approved.approvers.first()?;
            if *approver == approved.requester {
                return None;
            }
            Some(Call::RotateKrbtgt {
                krbtgt: keyd_types::KeyHandle::new(principal, KeyPurpose::Krbtgt),
                approval: DualControlToken {
                    approver_1: PrincipalId::from_bytes(approved.requester.to_packet()),
                    approver_2: PrincipalId::from_bytes(approver.to_packet()),
                },
            })
        }
        KeyOperation::RotateKey { service } => {
            (service == approved.principal).then(|| Call::RotateKey {
                handle: keyd_types::KeyHandle::new(principal, KeyPurpose::Service),
            })
        }
        KeyOperation::RetireKvno { key, kvno } => {
            let purpose = match key {
                ipc_dird_admin::KeyRef::Krbtgt => KeyPurpose::Krbtgt,
                ipc_dird_admin::KeyRef::Service(service) => {
                    if service != approved.principal {
                        return None;
                    }
                    KeyPurpose::Service
                }
            };
            (kvno != 0).then(|| Call::RetireKvno {
                handle: keyd_types::KeyHandle::new(principal, purpose),
                kvno: Kvno::new(kvno),
            })
        }
    }
}

/// keyd's answer to the call, as an outcome carrying the kvno of a rotation.
/// Spec: docs/10 §7; crates/keyadm ceremony.rs (`classify`).
fn classify_call(result: Result<Answer, ipc_keyd::CallFailure>) -> Outcome<Option<Kvno>> {
    classify(result, |answer| match answer {
        Answer::RotateKrbtgt(result) | Answer::RotateKey(result) => Some(result.map(Some)),
        Answer::RetireKvno(result) => Some(result.map(|()| None)),
        _ => None,
    })
}

/// What dird is told: the outcome as the ipc-keyd client classified it.
/// Spec: docs/51 §6; A-88, A-90.
fn reported(outcome: &Outcome<Option<Kvno>>) -> KeyOperationOutcome {
    match outcome {
        Outcome::Answered(Ok(kvno)) => KeyOperationOutcome::Performed {
            kvno: kvno.map(Kvno::get),
        },
        Outcome::Answered(Err(_)) => KeyOperationOutcome::Refused,
        Outcome::NotSent(_) | Outcome::NotPerformed(_) => KeyOperationOutcome::NotPerformed,
        Outcome::Unknown(_) => KeyOperationOutcome::OutcomeUnknown,
    }
}

/// Send `Complete {id, outcome}`.
/// Spec: docs/51 §6.
fn complete(admind: &mut dyn AdmindPort, id: u64, outcome: KeyOperationOutcome) -> Completion {
    let request = Request::Keyadm(KeyadmRequest::Complete { id, outcome });
    match admind.call(&request) {
        Ok(Reply::Done) => Completion::Recorded,
        Ok(Reply::Refused(status)) => Completion::Refused(status),
        // The client checks the reply answers the request: unreachable.
        Ok(_) => Completion::Refused(RefusalStatus::OutcomeUnknown),
        Err(failure) => Completion::Failed(failure),
    }
}

/// Execute approved request `id` with `command` (module documentation).
/// Never retries.
///
/// Spec: docs/51 §5.6, §6; docs/10 §7; A-87; A-88; A-90.
pub fn run(
    admind: &mut dyn AdmindPort,
    keyd: &mut dyn KeydPort,
    command: Approved,
    id: u64,
) -> ExecutionReport {
    let mut report = ExecutionReport {
        command,
        id,
        fetch: Fetch::Refused(RefusalStatus::Unavailable),
        mismatch: None,
        keyd: None,
        completion: None,
    };
    let approved = match admind.call(&Request::Keyadm(KeyadmRequest::FetchApproved { id })) {
        Ok(Reply::Approved(approved)) if approved.id == id => approved,
        Ok(Reply::Approved(_)) => {
            report.fetch = Fetch::Refused(RefusalStatus::OutcomeUnknown);
            return report;
        }
        Ok(Reply::Refused(status)) => {
            report.fetch = Fetch::Refused(status);
            return report;
        }
        Ok(_) => {
            report.fetch = Fetch::Refused(RefusalStatus::OutcomeUnknown);
            return report;
        }
        Err(failure) => {
            report.fetch = Fetch::Failed(failure);
            return report;
        }
    };
    report.fetch = Fetch::Fetched(approved.clone());
    let call = if !same_command(command, &approved.operation) {
        report.mismatch = Some(Mismatch::Command(approved.operation));
        None
    } else {
        let call = keyd_call(&approved);
        if call.is_none() {
            report.mismatch = Some(Mismatch::Incoherent);
        }
        call
    };
    let Some(call) = call else {
        // Not executed: dird is told so, and drops the request.
        report.completion = Some(complete(admind, id, KeyOperationOutcome::NotPerformed));
        return report;
    };
    let outcome = classify_call(keyd.call_with_fate(&call));
    report.completion = Some(complete(admind, id, reported(&outcome)));
    report.keyd = Some(outcome);
    report
}
