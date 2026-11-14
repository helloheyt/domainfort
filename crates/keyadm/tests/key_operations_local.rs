//! keyadm's approved-request commands and its sweep (task A10) against
//! scripted peers — the command line, every fate of every call, the
//! "retry later" rule, the listing bounds, the reports and exit statuses —
//! without sockets (the tier-2 file `key_operations.rs` runs the real
//! daemons).
//!
//! Each test names its source (docs/51 §x, docs/10 §x, A-xx). Every value is
//! constructed by hand for these tests (obviously fake); no vector comes
//! from any other implementation.

use dtyp::Guid;
use ipc::Refused;
use ipc_admin::{AdmindFailure, AdmindUnserved, RefusalStatus, Reply, Request};
use ipc_dird_admin::{
    AccountKind, ApprovedKeyOperation, DestructionEntry, DestructionPage, KeyOperation,
    KeyOperationOutcome, KeyRef, KeyadmRequest, TransportError as DirdTransport,
};
use ipc_keyd::{Answer, Call, CallFailure, RequestFate, TransportError, Unserved};
use keyadm::ceremony::{NotSent, Outcome, Unknown};
use keyadm::cli::{self, Approved, Command};
use keyadm::execute::{self, Completion, Fetch, Mismatch};
use keyadm::ports::{AdmindPort, KeydPort};
use keyadm::report::{self, EXIT_COMPLETE, EXIT_INCOMPLETE, EXIT_NOTHING_ATTEMPTED};
use keyadm::sweep::{self, Stopped};
use keyd_types::{DualControlToken, Error as KeydError, KeyHandle, KeyPurpose, Kvno, PrincipalId};
use std::collections::VecDeque;
use std::ffi::OsString;

fn guid(n: u8) -> Guid {
    let mut packet = [0u8; 16];
    packet[0] = 0xA1;
    packet[15] = n;
    Guid::from_packet(&packet)
}

/// What a scripted keyd was asked: the operation and its handle (and, for
/// `rotate_krbtgt`, the token; for `retire_kvno`, the kvno).
#[derive(Debug, Clone, PartialEq, Eq)]
enum Asked {
    Ping,
    RotateKrbtgt(KeyHandle, DualControlToken),
    RotateKey(KeyHandle),
    RetireKvno(KeyHandle, Kvno),
    Destroy(KeyHandle),
    Other,
}

#[derive(Default)]
struct ScriptedKeyd {
    answers: VecDeque<Result<Answer, CallFailure>>,
    asked: Vec<Asked>,
}

impl KeydPort for ScriptedKeyd {
    fn call_with_fate(&mut self, call: &Call) -> Result<Answer, CallFailure> {
        self.asked.push(match call {
            Call::Ping => Asked::Ping,
            Call::RotateKrbtgt { krbtgt, approval } => Asked::RotateKrbtgt(*krbtgt, *approval),
            Call::RotateKey { handle } => Asked::RotateKey(*handle),
            Call::RetireKvno { handle, kvno } => Asked::RetireKvno(*handle, *kvno),
            Call::DestroyKeySet { handle } => Asked::Destroy(*handle),
            _ => Asked::Other,
        });
        self.answers.pop_front().unwrap_or(Err(CallFailure {
            unserved: Unserved::Transport(TransportError::Connect),
            fate: RequestFate::NotSent,
        }))
    }
}

#[derive(Default)]
struct ScriptedAdmind {
    answers: VecDeque<Result<Reply, AdmindFailure>>,
    asked: Vec<KeyadmRequest>,
}

impl AdmindPort for ScriptedAdmind {
    fn call(&mut self, request: &Request) -> Result<Reply, AdmindFailure> {
        match request {
            Request::Keyadm(keyadm) => self.asked.push(*keyadm),
            other => panic!("keyadm sent {other:?}"),
        }
        self.answers.pop_front().unwrap_or(Err(AdmindFailure {
            unserved: AdmindUnserved::Transport(DirdTransport::Connect),
            sent: false,
        }))
    }
}

fn approved(operation: KeyOperation, principal: Guid, approvers: Vec<Guid>) -> Reply {
    Reply::Approved(ApprovedKeyOperation {
        id: 7,
        digest: [0x5A; 32],
        operation,
        principal,
        requester: guid(1),
        approvers,
    })
}

fn handle(g: Guid, purpose: KeyPurpose) -> KeyHandle {
    KeyHandle::new(PrincipalId::from_bytes(g.to_packet()), purpose)
}

fn failure(unserved: Unserved, fate: RequestFate) -> Result<Answer, CallFailure> {
    Err(CallFailure { unserved, fate })
}

// ---- the command line ----------------------------------------------------------

/// docs/51 §6 (`rotate-key`, `rotate-krbtgt`, `retire-kvno`,
/// `destroy-sweep`); docs/50 §7.1 (one spelling per integer): the new
/// commands parse exactly; a request id is decimal digits without sign or
/// leading zero, within u64.
#[test]
fn the_new_commands_parse_exactly() {
    let parse = |args: &[&str]| cli::parse(args.iter().map(OsString::from));
    assert_eq!(
        parse(&["k.conf", "rotate-krbtgt", "17"]),
        Ok(Command::Execute {
            config: "k.conf".into(),
            command: Approved::RotateKrbtgt,
            id: 17
        })
    );
    assert_eq!(
        parse(&["k.conf", "rotate-key", "0"]).map(|c| matches!(
            c,
            Command::Execute {
                command: Approved::RotateKey,
                id: 0,
                ..
            }
        )),
        Ok(true)
    );
    assert!(matches!(
        parse(&["k.conf", "retire-kvno", "18446744073709551615"]),
        Ok(Command::Execute {
            command: Approved::RetireKvno,
            id: u64::MAX,
            ..
        })
    ));
    assert_eq!(
        parse(&["k.conf", "destroy-sweep"]),
        Ok(Command::DestroySweep {
            config: "k.conf".into()
        })
    );
    for bad in [
        &["k.conf", "rotate-krbtgt"][..],
        &["k.conf", "rotate-krbtgt", "017"],
        &["k.conf", "rotate-krbtgt", "+17"],
        &["k.conf", "rotate-krbtgt", "-1"],
        &["k.conf", "rotate-krbtgt", ""],
        &["k.conf", "rotate-krbtgt", "18446744073709551616"],
        &["k.conf", "rotate-krbtgt", "1 7"],
        &["k.conf", "rotate-krbtgt", "17", "x"],
        &["k.conf", "destroy-sweep", "now"],
        &["k.conf", "rotate_krbtgt", "17"],
        &["k.conf", "Rotate-Krbtgt", "17"],
    ] {
        assert!(parse(bad).is_err(), "{bad:?}");
    }
}

// ---- execution -----------------------------------------------------------------

/// docs/51 §6 ("`rotate_krbtgt(DualControlToken { approver_1: the
/// requester, approver_2: the approver })`"); crates/keyd-types model.rs:
/// the token names the requester and the first approver; keyd's new kvno is
/// reported to dird; exit 0.
#[test]
fn rotate_krbtgt_builds_the_token_from_dirds_answer() {
    let mut admind = ScriptedAdmind::default();
    admind.answers.push_back(Ok(approved(
        KeyOperation::RotateKrbtgt,
        guid(9),
        vec![guid(2)],
    )));
    admind.answers.push_back(Ok(Reply::Done));
    let mut keyd = ScriptedKeyd::default();
    keyd.answers
        .push_back(Ok(Answer::RotateKrbtgt(Ok(Kvno::new(3)))));
    let report = execute::run(&mut admind, &mut keyd, Approved::RotateKrbtgt, 7);
    assert_eq!(
        keyd.asked,
        vec![Asked::RotateKrbtgt(
            handle(guid(9), KeyPurpose::Krbtgt),
            DualControlToken {
                approver_1: PrincipalId::from_bytes(guid(1).to_packet()),
                approver_2: PrincipalId::from_bytes(guid(2).to_packet()),
            }
        )]
    );
    assert_eq!(
        admind.asked,
        vec![
            KeyadmRequest::FetchApproved { id: 7 },
            KeyadmRequest::Complete {
                id: 7,
                outcome: KeyOperationOutcome::Performed { kvno: Some(3) }
            }
        ]
    );
    assert!(report.is_complete());
    assert_eq!(report::execution_exit_code(&report), EXIT_COMPLETE);
}

/// docs/10 §7: `rotate_key` acts on the service object's `Service` key set
/// and `retire_kvno` names its kvno (and reports none back).
#[test]
fn rotate_key_and_retire_kvno_name_their_key_sets() {
    let mut admind = ScriptedAdmind::default();
    admind.answers.push_back(Ok(approved(
        KeyOperation::RotateKey { service: guid(4) },
        guid(4),
        vec![guid(2)],
    )));
    admind.answers.push_back(Ok(Reply::Done));
    let mut keyd = ScriptedKeyd::default();
    keyd.answers
        .push_back(Ok(Answer::RotateKey(Ok(Kvno::new(2)))));
    let report = execute::run(&mut admind, &mut keyd, Approved::RotateKey, 7);
    assert_eq!(
        keyd.asked,
        vec![Asked::RotateKey(handle(guid(4), KeyPurpose::Service))]
    );
    assert!(report.is_complete());

    let mut admind = ScriptedAdmind::default();
    admind.answers.push_back(Ok(approved(
        KeyOperation::RetireKvno {
            key: KeyRef::Krbtgt,
            kvno: 1,
        },
        guid(9),
        vec![guid(2)],
    )));
    admind.answers.push_back(Ok(Reply::Done));
    let mut keyd = ScriptedKeyd::default();
    keyd.answers.push_back(Ok(Answer::RetireKvno(Ok(()))));
    let report = execute::run(&mut admind, &mut keyd, Approved::RetireKvno, 7);
    assert_eq!(
        keyd.asked,
        vec![Asked::RetireKvno(
            handle(guid(9), KeyPurpose::Krbtgt),
            Kvno::new(1)
        )]
    );
    assert_eq!(
        admind.asked[1],
        KeyadmRequest::Complete {
            id: 7,
            outcome: KeyOperationOutcome::Performed { kvno: None }
        }
    );
    assert!(report.is_complete());
}

/// docs/51 §6: an operation other than the command's, or an incoherent
/// answer (a `rotate_krbtgt` without an approver, or approved by its own
/// requester; a service operation on another object), is not executed —
/// keyd is never asked, dird is told "not performed"; exit 1.
#[test]
fn a_mismatch_executes_nothing() {
    let cases = [
        (
            approved(KeyOperation::RotateKrbtgt, guid(9), vec![guid(2)]),
            Approved::RotateKey,
            Mismatch::Command(KeyOperation::RotateKrbtgt),
        ),
        (
            approved(KeyOperation::RotateKrbtgt, guid(9), vec![]),
            Approved::RotateKrbtgt,
            Mismatch::Incoherent,
        ),
        (
            approved(KeyOperation::RotateKrbtgt, guid(9), vec![guid(1)]),
            Approved::RotateKrbtgt,
            Mismatch::Incoherent,
        ),
        (
            approved(
                KeyOperation::RotateKey { service: guid(4) },
                guid(5),
                vec![guid(2)],
            ),
            Approved::RotateKey,
            Mismatch::Incoherent,
        ),
    ];
    for (reply, command, mismatch) in cases {
        let mut admind = ScriptedAdmind::default();
        admind.answers.push_back(Ok(reply));
        admind.answers.push_back(Ok(Reply::Done));
        let mut keyd = ScriptedKeyd::default();
        let report = execute::run(&mut admind, &mut keyd, command, 7);
        assert!(keyd.asked.is_empty(), "{mismatch:?}");
        assert_eq!(report.mismatch, Some(mismatch));
        assert_eq!(
            admind.asked[1],
            KeyadmRequest::Complete {
                id: 7,
                outcome: KeyOperationOutcome::NotPerformed
            }
        );
        assert_eq!(report::execution_exit_code(&report), EXIT_NOTHING_ATTEMPTED);
    }
}

/// A-88, A-90 (the three fates; "never 'not done' for something that may
/// have been done"): dird is told exactly what the ipc-keyd client knows —
/// refused, not performed, outcome unknown — and the exit status is 2
/// whenever keyd was asked; 1 when nothing was sent.
#[test]
fn every_keyd_fate_is_reported_to_dird() {
    let cases: Vec<(Result<Answer, CallFailure>, KeyOperationOutcome, u8)> = vec![
        (
            Ok(Answer::RotateKrbtgt(Err(KeydError::Denied))),
            KeyOperationOutcome::Refused,
            EXIT_INCOMPLETE,
        ),
        (
            Ok(Answer::RotateKrbtgt(Err(KeydError::Unavailable))),
            KeyOperationOutcome::Refused,
            EXIT_INCOMPLETE,
        ),
        (
            failure(Unserved::Refused(Refused::Busy), RequestFate::NotPerformed),
            KeyOperationOutcome::NotPerformed,
            EXIT_INCOMPLETE,
        ),
        (
            failure(
                Unserved::Transport(TransportError::Connect),
                RequestFate::NotSent,
            ),
            KeyOperationOutcome::NotPerformed,
            EXIT_NOTHING_ATTEMPTED,
        ),
        (
            failure(
                Unserved::Transport(TransportError::DeadlineExceeded),
                RequestFate::OutcomeUnknown,
            ),
            KeyOperationOutcome::OutcomeUnknown,
            EXIT_INCOMPLETE,
        ),
    ];
    for (answer, reported, exit) in cases {
        let mut admind = ScriptedAdmind::default();
        admind.answers.push_back(Ok(approved(
            KeyOperation::RotateKrbtgt,
            guid(9),
            vec![guid(2)],
        )));
        admind.answers.push_back(Ok(Reply::Done));
        let mut keyd = ScriptedKeyd::default();
        keyd.answers.push_back(answer);
        let report = execute::run(&mut admind, &mut keyd, Approved::RotateKrbtgt, 7);
        assert_eq!(keyd.asked.len(), 1, "never retried");
        assert_eq!(
            admind.asked[1],
            KeyadmRequest::Complete {
                id: 7,
                outcome: reported
            }
        );
        assert_eq!(report::execution_exit_code(&report), exit, "{reported:?}");
        if reported == KeyOperationOutcome::OutcomeUnknown {
            let lines = report::render_execution(&report);
            assert!(
                lines
                    .iter()
                    .any(|l| l.contains("outcome unknown") && l.contains("audit log")),
                "{lines:?}"
            );
        }
    }
}

/// docs/51 §6: a refused or failed fetch asks keyd nothing (exit 1); a
/// fetch whose answer was lost after sending says the request may have been
/// consumed; a performed operation whose completion dird did not record is
/// not "complete" (exit 2).
#[test]
fn fetch_and_completion_failures() {
    for (answer, expected) in [
        (
            Ok(Reply::Refused(RefusalStatus::ApprovalRequired)),
            Fetch::Refused(RefusalStatus::ApprovalRequired),
        ),
        (
            Ok(Reply::Refused(RefusalStatus::Denied)),
            Fetch::Refused(RefusalStatus::Denied),
        ),
        (
            Err(AdmindFailure {
                unserved: AdmindUnserved::Transport(DirdTransport::DeadlineExceeded),
                sent: true,
            }),
            Fetch::Failed(AdmindFailure {
                unserved: AdmindUnserved::Transport(DirdTransport::DeadlineExceeded),
                sent: true,
            }),
        ),
    ] {
        let mut admind = ScriptedAdmind::default();
        admind.answers.push_back(answer);
        let mut keyd = ScriptedKeyd::default();
        let report = execute::run(&mut admind, &mut keyd, Approved::RotateKrbtgt, 7);
        assert_eq!(report.fetch, expected);
        assert!(keyd.asked.is_empty());
        assert_eq!(admind.asked.len(), 1, "no Complete without a fetch");
        assert_eq!(report::execution_exit_code(&report), EXIT_NOTHING_ATTEMPTED);
        let lines = report::render_execution(&report);
        assert!(lines.iter().any(|l| l.contains("keyd was not asked")));
    }
    let mut admind = ScriptedAdmind::default();
    admind.answers.push_back(Ok(approved(
        KeyOperation::RotateKrbtgt,
        guid(9),
        vec![guid(2)],
    )));
    admind
        .answers
        .push_back(Ok(Reply::Refused(RefusalStatus::NotFound)));
    let mut keyd = ScriptedKeyd::default();
    keyd.answers
        .push_back(Ok(Answer::RotateKrbtgt(Ok(Kvno::new(2)))));
    let report = execute::run(&mut admind, &mut keyd, Approved::RotateKrbtgt, 7);
    assert_eq!(
        report.completion,
        Some(Completion::Refused(RefusalStatus::NotFound))
    );
    assert!(!report.is_complete());
    assert_eq!(report::execution_exit_code(&report), EXIT_INCOMPLETE);
    let lines = report::render_execution(&report);
    assert!(lines.iter().any(|l| l.contains("NOT recorded")));
}

// ---- the sweep -----------------------------------------------------------------

fn page(entries: &[(Guid, AccountKind)], next: Option<Guid>) -> Reply {
    Reply::PendingDestruction(DestructionPage {
        entries: entries
            .iter()
            .map(|(guid, kind)| DestructionEntry {
                guid: *guid,
                kind: *kind,
            })
            .collect(),
        next,
    })
}

/// docs/51 §6, §9; docs/10 §7: every listed account's two key sets are
/// destroyed in order across pages; keyd's uniform `Denied` (an unknown
/// handle) counts as done; exit 0.
#[test]
fn the_sweep_destroys_both_key_sets_across_pages() {
    let mut admind = ScriptedAdmind::default();
    admind
        .answers
        .push_back(Ok(page(&[(guid(3), AccountKind::Computer)], Some(guid(3)))));
    admind
        .answers
        .push_back(Ok(page(&[(guid(5), AccountKind::User)], None)));
    let mut keyd = ScriptedKeyd::default();
    keyd.answers.push_back(Ok(Answer::Ping(Ok(()))));
    keyd.answers.push_back(Ok(Answer::DestroyKeySet(Ok(()))));
    keyd.answers.push_back(Ok(Answer::DestroyKeySet(Ok(()))));
    keyd.answers.push_back(Ok(Answer::DestroyKeySet(Ok(()))));
    keyd.answers
        .push_back(Ok(Answer::DestroyKeySet(Err(KeydError::Denied))));
    let report = sweep::run(&mut admind, &mut keyd);
    assert!(report.is_complete());
    assert_eq!(report.accounts, 2);
    assert_eq!(
        report.destroyed,
        vec![
            (guid(3), KeyPurpose::PrincipalLongterm),
            (guid(3), KeyPurpose::Service),
            (guid(5), KeyPurpose::PrincipalLongterm),
        ]
    );
    assert_eq!(report.absent, 1);
    assert_eq!(
        admind.asked,
        vec![
            KeyadmRequest::ListPendingDestruction { cursor: None },
            KeyadmRequest::ListPendingDestruction {
                cursor: Some(guid(3))
            },
        ]
    );
    assert_eq!(
        keyd.asked[1..],
        [
            Asked::Destroy(handle(guid(3), KeyPurpose::PrincipalLongterm)),
            Asked::Destroy(handle(guid(3), KeyPurpose::Service)),
            Asked::Destroy(handle(guid(5), KeyPurpose::PrincipalLongterm)),
            Asked::Destroy(handle(guid(5), KeyPurpose::Service)),
        ]
    );
    assert_eq!(report::sweep_exit_code(&report), EXIT_COMPLETE);
}

/// docs/51 §6 ("`Unavailable` ⇒ try again"): keyd's `Unavailable` (or
/// `RateLimited`, not sent, not performed, outcome unknown) on one key set
/// stops the sweep at once — retry later, exit 2 — and a rerun with keyd
/// healthy finishes (`Denied` for what the first run destroyed: done).
#[test]
fn unavailable_stops_the_sweep_for_a_retry() {
    for failing in [
        Ok(Answer::DestroyKeySet(Err(KeydError::Unavailable))),
        Ok(Answer::DestroyKeySet(Err(KeydError::RateLimited))),
        failure(
            Unserved::Refused(Refused::Unavailable),
            RequestFate::NotPerformed,
        ),
        failure(
            Unserved::Transport(TransportError::Closed),
            RequestFate::OutcomeUnknown,
        ),
    ] {
        let mut admind = ScriptedAdmind::default();
        admind
            .answers
            .push_back(Ok(page(&[(guid(3), AccountKind::Computer)], None)));
        let mut keyd = ScriptedKeyd::default();
        keyd.answers.push_back(Ok(Answer::Ping(Ok(()))));
        keyd.answers.push_back(Ok(Answer::DestroyKeySet(Ok(()))));
        keyd.answers.push_back(failing);
        let report = sweep::run(&mut admind, &mut keyd);
        assert!(!report.is_complete());
        assert!(matches!(
            report.stopped,
            Some(Stopped::RetryLater {
                purpose: KeyPurpose::Service,
                ..
            })
        ));
        assert_eq!(keyd.asked.len(), 3, "stopped at once");
        assert_eq!(report::sweep_exit_code(&report), EXIT_INCOMPLETE);
        let lines = report::render_sweep(&report);
        assert!(lines.iter().any(|l| l.contains("retry later")), "{lines:?}");
        // The rerun.
        let mut admind = ScriptedAdmind::default();
        admind
            .answers
            .push_back(Ok(page(&[(guid(3), AccountKind::Computer)], None)));
        let mut keyd = ScriptedKeyd::default();
        keyd.answers.push_back(Ok(Answer::Ping(Ok(()))));
        keyd.answers
            .push_back(Ok(Answer::DestroyKeySet(Err(KeydError::Denied))));
        keyd.answers.push_back(Ok(Answer::DestroyKeySet(Ok(()))));
        let rerun = sweep::run(&mut admind, &mut keyd);
        assert!(rerun.is_complete());
        assert_eq!(rerun.absent, 1);
        assert_eq!(rerun.destroyed.len(), 1);
    }
}

/// AGENTS.md §6 (bounded work): a listing whose cursor does not move
/// forward is refused (`ListingLooped`); a failed contact attempts nothing
/// (exit 1); a refused listing stops the sweep.
#[test]
fn the_sweep_is_bounded_and_fails_closed() {
    let mut admind = ScriptedAdmind::default();
    admind.answers.push_back(Ok(page(&[], Some(guid(8)))));
    admind.answers.push_back(Ok(page(&[], Some(guid(8)))));
    let mut keyd = ScriptedKeyd::default();
    keyd.answers.push_back(Ok(Answer::Ping(Ok(()))));
    let report = sweep::run(&mut admind, &mut keyd);
    assert_eq!(report.stopped, Some(Stopped::ListingLooped));
    assert_eq!(admind.asked.len(), 2);

    let mut admind = ScriptedAdmind::default();
    let mut keyd = ScriptedKeyd::default();
    keyd.answers.push_back(failure(
        Unserved::Transport(TransportError::Connect),
        RequestFate::NotSent,
    ));
    let report = sweep::run(&mut admind, &mut keyd);
    assert_eq!(report.contact, Outcome::NotSent(NotSent::Connect));
    assert!(admind.asked.is_empty());
    assert_eq!(report::sweep_exit_code(&report), EXIT_NOTHING_ATTEMPTED);

    let mut admind = ScriptedAdmind::default();
    admind
        .answers
        .push_back(Ok(Reply::Refused(RefusalStatus::Denied)));
    let mut keyd = ScriptedKeyd::default();
    keyd.answers.push_back(Ok(Answer::Ping(Ok(()))));
    let report = sweep::run(&mut admind, &mut keyd);
    assert_eq!(
        report.stopped,
        Some(Stopped::ListingRefused(RefusalStatus::Denied))
    );
    assert_eq!(report::sweep_exit_code(&report), EXIT_NOTHING_ATTEMPTED);
    let unknown = Outcome::<()>::Unknown(Unknown::MalformedReply);
    assert!(unknown.outcome_unknown());
}
