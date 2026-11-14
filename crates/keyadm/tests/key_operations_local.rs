//! keyadm's decision commands and its sweep (task A10, as changed by A-102)
//! against a scripted keyd — the command line, every fate of every call,
//! the "retry later" rule, the listing bounds, the reports and exit
//! statuses — without sockets (the tier-2 file `key_operations.rs` runs the
//! real daemons).
//!
//! Since A-102 keyadm talks to keyd only: no scripted admind exists here
//! because keyadm has no admind client at all (docs/52 §4.6; N2 — nothing a
//! compromised admind answers can reach keyadm).
//!
//! Each test names its source (docs/52 §x, docs/51 §x, docs/10 §x, A-xx).
//! Every value is constructed by hand for these tests (obviously fake); no
//! vector comes from any other implementation.

use ipc::Refused;
use ipc_keyd::{Answer, Call, CallFailure, RequestFate, TransportError, Unserved};
use keyadm::ceremony::{NotSent, Outcome, Unknown};
use keyadm::cli::{self, Approved, Command};
use keyadm::execute;
use keyadm::ports::KeydPort;
use keyadm::report::{self, EXIT_COMPLETE, EXIT_INCOMPLETE, EXIT_NOTHING_ATTEMPTED};
use keyadm::sweep::{self, Stopped};
use keyd_types::{
    DecisionId, DestructionPage, Error as KeydError, Kvno, PendingDestruction, PrincipalId,
};
use std::collections::VecDeque;
use std::ffi::OsString;

/// What a scripted keyd was asked: the operation and the decision id —
/// everything keyadm sends (there is no handle, kvno or approval to send).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Asked {
    Ping,
    RotateKrbtgt(DecisionId),
    RotateKey(DecisionId),
    RetireKvno(DecisionId),
    Destroy(DecisionId),
    List(Option<DecisionId>),
    Other,
}

/// Every call a scripted keyd received, in order — the only thing keyadm
/// can send it.
#[derive(Default)]
struct ScriptedKeyd {
    answers: VecDeque<Result<Answer, CallFailure>>,
    asked: Vec<Asked>,
}

impl KeydPort for ScriptedKeyd {
    fn call_with_fate(&mut self, call: &Call) -> Result<Answer, CallFailure> {
        self.asked.push(match call {
            Call::Ping => Asked::Ping,
            Call::RotateKrbtgt { decision } => Asked::RotateKrbtgt(*decision),
            Call::RotateKey { decision } => Asked::RotateKey(*decision),
            Call::RetireKvno { decision } => Asked::RetireKvno(*decision),
            Call::DestroyKeySet { decision } => Asked::Destroy(*decision),
            Call::ListDestroyDecisions { after } => Asked::List(*after),
            _ => Asked::Other,
        });
        self.answers.pop_front().unwrap_or(Err(CallFailure {
            unserved: Unserved::Transport(TransportError::Connect),
            fate: RequestFate::NotSent,
        }))
    }
}

fn failure(unserved: Unserved, fate: RequestFate) -> Result<Answer, CallFailure> {
    Err(CallFailure { unserved, fate })
}

fn principal(n: u8) -> PrincipalId {
    let mut packet = [0u8; 16];
    packet[0] = 0xA1;
    packet[15] = n;
    PrincipalId::from_bytes(packet)
}

fn entry(id: u64, n: u8) -> PendingDestruction {
    PendingDestruction {
        decision: DecisionId::new(id),
        principal: principal(n),
    }
}

fn page(entries: &[PendingDestruction], next: Option<u64>) -> Result<Answer, CallFailure> {
    Ok(Answer::ListDestroyDecisions(Ok(DestructionPage {
        entries: entries.to_vec(),
        next: next.map(DecisionId::new),
    })))
}

// ---- the command line ----------------------------------------------------------

/// docs/51 §6 (`rotate-key`, `rotate-krbtgt`, `retire-kvno`,
/// `destroy-sweep`); docs/52 §4.2 (the id is dird's decision id); docs/50
/// §7.1 (one spelling per integer): the commands parse exactly; a decision
/// id is decimal digits without sign or leading zero, within u64.
#[test]
fn the_commands_parse_exactly() {
    let parse = |args: &[&str]| cli::parse(args.iter().map(OsString::from));
    assert_eq!(
        parse(&["k.conf", "rotate-krbtgt", "17"]),
        Ok(Command::Execute {
            config: "k.conf".into(),
            command: Approved::RotateKrbtgt,
            id: 17
        })
    );
    assert!(matches!(
        parse(&["k.conf", "rotate-key", "0"]),
        Ok(Command::Execute {
            command: Approved::RotateKey,
            id: 0,
            ..
        })
    ));
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
    assert!(cli::USAGE.contains("<decision id>"));
}

// ---- the decision commands -----------------------------------------------------

/// docs/52 §4.2, §4.6 (the executions carry only a decision id — keyd runs
/// the parameters dird registered and builds the dual-control token
/// itself): each command sends keyd exactly one call, its operation with
/// the decision id, and nothing else.
#[test]
fn each_command_sends_only_its_decision_id() {
    for (command, expected, answer) in [
        (
            Approved::RotateKrbtgt,
            Asked::RotateKrbtgt(DecisionId::new(41)),
            Answer::RotateKrbtgt(Ok(Kvno::new(2))),
        ),
        (
            Approved::RotateKey,
            Asked::RotateKey(DecisionId::new(41)),
            Answer::RotateKey(Ok(Kvno::new(2))),
        ),
        (
            Approved::RetireKvno,
            Asked::RetireKvno(DecisionId::new(41)),
            Answer::RetireKvno(Ok(())),
        ),
    ] {
        let mut keyd = ScriptedKeyd::default();
        keyd.answers.push_back(Ok(answer));
        let report = execute::run(&mut keyd, command, 41);
        assert_eq!(keyd.asked, vec![expected], "{command:?}");
        assert_eq!(report.decision, DecisionId::new(41));
        assert!(report.is_complete(), "{command:?}");
        assert_eq!(report::execution_exit_code(&report), EXIT_COMPLETE);
        let lines = report::render_execution(&report);
        assert!(lines[0].contains("decision 41"), "{lines:?}");
        assert!(
            lines.iter().any(|l| l.contains("never runs twice")),
            "{lines:?}"
        );
    }
    let mut keyd = ScriptedKeyd::default();
    keyd.answers
        .push_back(Ok(Answer::RotateKrbtgt(Ok(Kvno::new(3)))));
    let report = execute::run(&mut keyd, Approved::RotateKrbtgt, 41);
    assert_eq!(report.keyd, Outcome::Answered(Ok(Some(Kvno::new(3)))));
    assert!(report::render_execution(&report)
        .iter()
        .any(|l| l.contains("new kvno 3")));
}

/// docs/10 §9, §10 (A-88, A-90: each fate as the client knows it); docs/52
/// §3.10 (an unknown outcome is answered by presenting the same decision
/// again): keyd's refusal ⇒ exit 2 and "keyd's audit record names the
/// reason"; not sent / not performed ⇒ exit 1 (keyd changed nothing);
/// outcome unknown ⇒ exit 2 and "run the same command again"; a reply of
/// another operation ⇒ outcome unknown. keyadm never retries (one call).
#[test]
fn every_keyd_fate_is_reported() {
    let cases: [(Result<Answer, CallFailure>, u8, &str); 5] = [
        (
            Ok(Answer::RotateKey(Err(KeydError::Denied))),
            EXIT_INCOMPLETE,
            "audit record names the reason",
        ),
        (
            failure(
                Unserved::Transport(TransportError::Connect),
                RequestFate::NotSent,
            ),
            EXIT_NOTHING_ATTEMPTED,
            "nothing was sent",
        ),
        (
            failure(Unserved::Refused(Refused::Busy), RequestFate::NotPerformed),
            EXIT_NOTHING_ATTEMPTED,
            "not performed",
        ),
        (
            failure(
                Unserved::Transport(TransportError::DeadlineExceeded),
                RequestFate::OutcomeUnknown,
            ),
            EXIT_INCOMPLETE,
            "run the same command again",
        ),
        (
            Ok(Answer::RotateKrbtgt(Ok(Kvno::new(9)))),
            EXIT_INCOMPLETE,
            "run the same command again",
        ),
    ];
    for (answer, code, text) in cases {
        let mut keyd = ScriptedKeyd::default();
        keyd.answers.push_back(answer);
        let report = execute::run(&mut keyd, Approved::RotateKey, 5);
        assert_eq!(keyd.asked.len(), 1, "never a retry");
        assert!(!report.is_complete());
        assert_eq!(report::execution_exit_code(&report), code, "{text}");
        let lines = report::render_execution(&report);
        assert!(lines.iter().any(|l| l.contains(text)), "{lines:?}");
    }
    let mut keyd = ScriptedKeyd::default();
    keyd.answers
        .push_back(Ok(Answer::RotateKrbtgt(Ok(Kvno::new(9)))));
    let report = execute::run(&mut keyd, Approved::RotateKey, 5);
    assert_eq!(report.keyd, Outcome::Unknown(Unknown::UnexpectedReply));
}

// ---- the sweep -----------------------------------------------------------------

/// docs/52 §4.3, §4.6; docs/51 §6, §9: the sweep pings keyd, lists keyd's
/// pending destroy decisions page by page (the cursor moving forward), and
/// runs each by its id — and nothing else: every principal it names comes
/// from keyd's own list. A `Denied` decision is skipped and the sweep goes
/// on; exit 0.
#[test]
fn the_sweep_runs_only_keyds_decisions_across_pages() {
    let mut keyd = ScriptedKeyd::default();
    keyd.answers
        .push_back(Ok(Answer::Ping(Ok(keyd_types::Role::Admin))));
    keyd.answers
        .push_back(page(&[entry(10, 1), entry(11, 2)], Some(11)));
    keyd.answers.push_back(Ok(Answer::DestroyKeySet(Ok(()))));
    keyd.answers
        .push_back(Ok(Answer::DestroyKeySet(Err(KeydError::Denied))));
    keyd.answers.push_back(page(&[entry(12, 3)], None));
    keyd.answers.push_back(Ok(Answer::DestroyKeySet(Ok(()))));
    let report = sweep::run(&mut keyd);
    assert!(report.is_complete(), "{report:?}");
    assert_eq!(report.listed, 3);
    assert_eq!(report.destroyed, vec![entry(10, 1), entry(12, 3)]);
    assert_eq!(report.skipped, vec![entry(11, 2)]);
    assert_eq!(report::sweep_exit_code(&report), EXIT_COMPLETE);
    assert_eq!(
        keyd.asked,
        vec![
            Asked::Ping,
            Asked::List(None),
            Asked::Destroy(DecisionId::new(10)),
            Asked::Destroy(DecisionId::new(11)),
            Asked::List(Some(DecisionId::new(11))),
            Asked::Destroy(DecisionId::new(12)),
        ]
    );
    let lines = report::render_sweep(&report);
    assert!(lines.iter().any(|l| l.contains("destroyed: decision 10")));
    assert!(lines.iter().any(|l| l.contains("skipped: decision 11")));
    assert!(lines.iter().any(|l| l == "sweep complete"));
}

/// docs/51 §6 ("`Unavailable` ⇒ try again"); A-88: a `destroy_key_set` that
/// keyd did not perform stops the sweep with "retry later" (exit 2: a call
/// was sent); one keyd never reached at the contact is exit 1.
#[test]
fn unavailable_stops_the_sweep_for_a_retry() {
    let mut keyd = ScriptedKeyd::default();
    keyd.answers
        .push_back(Ok(Answer::Ping(Ok(keyd_types::Role::Admin))));
    keyd.answers
        .push_back(page(&[entry(10, 1), entry(11, 2)], None));
    keyd.answers.push_back(failure(
        Unserved::Refused(Refused::Unavailable),
        RequestFate::NotPerformed,
    ));
    let report = sweep::run(&mut keyd);
    assert!(!report.is_complete());
    assert_eq!(
        report.stopped,
        Some(Stopped::RetryLater {
            entry: entry(10, 1),
            outcome: Outcome::NotPerformed(Refused::Unavailable),
        })
    );
    assert_eq!(report::sweep_exit_code(&report), EXIT_INCOMPLETE);
    assert_eq!(keyd.asked.len(), 3, "decision 11 was not asked");
    let lines = report::render_sweep(&report);
    assert!(lines.iter().any(|l| l.contains("retry later")), "{lines:?}");

    let mut keyd = ScriptedKeyd::default();
    keyd.answers.push_back(failure(
        Unserved::Transport(TransportError::Connect),
        RequestFate::NotSent,
    ));
    let report = sweep::run(&mut keyd);
    assert_eq!(report.contact, Outcome::NotSent(NotSent::Connect));
    assert_eq!(keyd.asked, vec![Asked::Ping]);
    assert_eq!(report::sweep_exit_code(&report), EXIT_NOTHING_ATTEMPTED);
}

/// AGENTS.md §6 (a looping peer is refused; fail closed); docs/52 §4.6: a
/// listing whose cursor does not move forward stops the sweep; a listing
/// keyd refuses (e.g. this account is not Role::Admin) stops it with
/// nothing sent; exit 1.
#[test]
fn the_sweep_is_bounded_and_fails_closed() {
    let mut keyd = ScriptedKeyd::default();
    keyd.answers
        .push_back(Ok(Answer::Ping(Ok(keyd_types::Role::Admin))));
    keyd.answers.push_back(page(&[], Some(8)));
    keyd.answers.push_back(page(&[], Some(8)));
    let report = sweep::run(&mut keyd);
    assert_eq!(report.stopped, Some(Stopped::ListingLooped));
    assert_eq!(keyd.asked.len(), 3);

    let mut keyd = ScriptedKeyd::default();
    keyd.answers
        .push_back(Ok(Answer::Ping(Ok(keyd_types::Role::Admin))));
    keyd.answers
        .push_back(Ok(Answer::ListDestroyDecisions(Err(KeydError::Denied))));
    let report = sweep::run(&mut keyd);
    assert_eq!(
        report.stopped,
        Some(Stopped::Listing(Outcome::Answered(Err(KeydError::Denied))))
    );
    assert_eq!(report::sweep_exit_code(&report), EXIT_NOTHING_ATTEMPTED);
    assert!(report::render_sweep(&report)
        .iter()
        .any(|l| l.contains("listing failed")));
    let unknown = Outcome::<()>::Unknown(Unknown::MalformedReply);
    assert!(unknown.outcome_unknown());
}
