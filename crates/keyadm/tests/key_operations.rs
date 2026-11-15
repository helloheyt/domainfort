//! Tier 2 (docs/50 §9; task A10 as changed by A-102): keyadm's decision
//! commands and its `destroy-sweep` against the **real** one keyd (the
//! test's uid mapped to Role::Admin on keyadm's socket of the same engine,
//! which holds the krbtgt key set and ws9's two key sets), the real dird
//! with its admin service — which registers its decisions in that keyd as
//! Role::Ldap — and the real admind, all in this process over real Unix
//! sockets: crates/admin-daemon's tier-2 world, reused by `#[path]`.
//!
//! The administrators' steps (`RequestKeyOperation`, `Approve`, `Delete`) go
//! through admind with AP-REQs sealed under the admin service's key, as the
//! admin-plane tests build them; keyadm's steps go only to keyd, through
//! `ipc_keyd::KeydClient` (keyd's uid checked before sending) — the
//! production client, with the host's connector. keyadm has no channel to
//! admind or dird any more (A-102, docs/52 §4.6).
//!
//! What keyd did is read from its own audit records (docs/10 §10: op,
//! principal, purpose, kvno, approvers, decision, result, reason — no
//! secret).
//!
//! Sources: docs/52 §3.1 (N1), §3.10, §4.2, §4.3, §4.5, §4.6; docs/51 §5.6,
//! §6, §9; docs/10 §7, §9, §10; docs/33 §5; A-35; A-88; A-90; A-102. Every
//! value is constructed by hand for these tests; no vector comes from any
//! other implementation.

#[path = "../../admin-daemon/tests/support/mod.rs"]
mod support;

use core::time::Duration;
use ipc_admin::{Reply, Request};
use ipc_audit::{KeydOperation, KeydOutcome, KeydReason};
use ipc_dird_admin::{KeyOperation, Operation};
use ipc_keyd::KeydClient;
use keyadm::ceremony::Outcome;
use keyadm::cli::Approved;
use keyadm::execute;
use keyadm::report::{self, EXIT_COMPLETE, EXIT_INCOMPLETE, EXIT_NOTHING_ATTEMPTED};
use keyadm::sweep::{self, Stopped};
use keyd_types::{
    AccountKind, DecisionId, Error as KeydError, KeyHandle, KeyPurpose, Kvno, PrincipalBinding,
    PrincipalId, SetSecretTarget, MAX_INITIAL_SECRET_GRANT_SECS,
};
use krb_proto::constants::KRB_NT_PRINCIPAL;
use support::{
    auth, connectors, eventually, g, FakeAuditd, Got, Options, SilentServer, World, ADMIN1, ADMIN2,
    KRBTGT, WS9,
};
use zeroize::Zeroizing;

/// keyadm's client of the one keyd (Role::Admin on its socket).
fn keyd_client(world: &World) -> KeydClient<connectors::KeydConnector> {
    KeydClient::new(
        connectors::keyd(&world.keyadm_keyd_socket),
        ipc_keyd::ExpectedPeer::new(world.uid, keyd_types::Role::Admin).unwrap(),
        Duration::from_secs(1),
    )
}

/// admind's client of the same keyd (Role::Directory on `kd.sock`).
fn admind_keyd_client(world: &World) -> KeydClient<connectors::KeydConnector> {
    KeydClient::new(
        connectors::keyd(&world.keyd_dir_socket),
        ipc_keyd::ExpectedPeer::new(world.uid, keyd_types::Role::Directory).unwrap(),
        Duration::from_secs(1),
    )
}

/// admin1 proposes `operation` through admind (task D2-c, docs/questions/
/// Q-882: the one dual-control mechanism); admin2 approves it — the
/// approval that completes the quorum, at which dird registers the decision
/// in keyd under the request's id (A-102). Returns that id.
fn request_and_approve(world: &World, operation: KeyOperation) -> u64 {
    let mut conn = world.connect();
    let request = Operation::Propose {
        reason_ref: None,
        operation: Box::new(Operation::KeyOperation(operation)),
    };
    let state = match conn.call(&Request::Forward {
        auth: auth("admin1", &request),
        operation: request,
    }) {
        Got::Reply(Reply::PendingRequest(state)) => state,
        other => panic!("{other:?}"),
    };
    // R2: admin2's AP-REQ is bound to exactly this Approve.
    let approve = Operation::Approve {
        id: state.id,
        digest: state.digest,
    };
    match conn.call(&Request::Forward {
        auth: auth("admin2", &approve),
        operation: approve,
    }) {
        Got::Reply(Reply::PendingRequest(state)) => {
            assert_eq!(state.state, ipc_dird_admin::RequestState::Approved)
        }
        other => panic!("{other:?}"),
    }
    state.id
}

/// admin1 deletes ws9 through admind; dird registers the destroy decision.
fn delete_ws9(world: &World) {
    let mut conn = world.connect();
    assert_eq!(
        conn.call(&Request::Forward {
            auth: auth("admin1", &Operation::Delete { target: g(WS9) }),
            operation: Operation::Delete { target: g(WS9) },
        }),
        Got::Reply(Reply::Done)
    );
}

/// keyd's records of keyadm's (Role::Admin) calls of `operation`, in order.
fn keyd_records(world: &World, operation: KeydOperation) -> Vec<ipc_audit::KeydRecord> {
    world
        .keyadm_records()
        .into_iter()
        .filter(|r| r.op == operation)
        .collect()
}

/// keyd's records of any caller of `operation`, in order.
fn all_records(world: &World, operation: KeydOperation) -> Vec<ipc_audit::KeydRecord> {
    world
        .keyd_records()
        .into_iter()
        .filter(|r| r.op == operation)
        .collect()
}

fn ws9(purpose: KeyPurpose) -> KeyHandle {
    KeyHandle::new(PrincipalId::from_bytes(g(WS9).to_packet()), purpose)
}

/// docs/52 §4.2, §4.5 (keyd runs the registered parameters; its records
/// carry the decision id and the approvers from dird's decision), §3.10
/// (exactly once); docs/51 §6 (R51-14); docs/33 §5: admin1 requests, admin2
/// approves — dird registers the decision — and `keyadm rotate-krbtgt <id>`
/// rotates the krbtgt key set to kvno 2: keyd's intent and outcome name the
/// decision and {admin1, admin2}; exit 0. The same id again returns the
/// recorded kvno 2 (reason `DecisionReplayed`, no second intent, no second
/// rotation); exit 0.
#[test]
fn rotate_krbtgt_runs_dirds_decision_once() {
    let Some(world) = World::new(Options {
        keyadm_keyd: true,
        ..Options::default()
    }) else {
        return;
    };
    let id = request_and_approve(&world, KeyOperation::RotateKrbtgt);
    let report = execute::run(&mut keyd_client(&world), Approved::RotateKrbtgt, id);
    assert_eq!(report.keyd, Outcome::Answered(Ok(Some(Kvno::new(2)))));
    assert_eq!(report.decision, DecisionId::new(id));
    assert!(report.is_complete());
    assert_eq!(report::execution_exit_code(&report), EXIT_COMPLETE);
    let lines = report::render_execution(&report);
    assert!(lines.iter().any(|l| l.contains("new kvno 2")), "{lines:?}");

    assert!(eventually(Duration::from_secs(10), || keyd_records(
        &world,
        KeydOperation::RotateKrbtgt
    )
    .len()
        >= 2));
    let records = keyd_records(&world, KeydOperation::RotateKrbtgt);
    assert_eq!(records[0].result, KeydOutcome::Intent);
    assert_eq!(records[1].result, KeydOutcome::Success);
    for record in &records[..2] {
        assert_eq!(record.decision, Some(id));
        assert_eq!(
            record.approvers,
            Some([g(ADMIN1).to_packet(), g(ADMIN2).to_packet()])
        );
        assert_eq!(record.principal, Some(g(KRBTGT).to_packet()));
    }
    assert_eq!(records[1].kvno, Some(2));

    // The same decision again: the recorded result, nothing run.
    let again = execute::run(&mut keyd_client(&world), Approved::RotateKrbtgt, id);
    assert_eq!(again.keyd, Outcome::Answered(Ok(Some(Kvno::new(2)))));
    assert_eq!(report::execution_exit_code(&again), EXIT_COMPLETE);
    assert!(eventually(Duration::from_secs(10), || keyd_records(
        &world,
        KeydOperation::RotateKrbtgt
    )
    .len()
        >= 3));
    let records = keyd_records(&world, KeydOperation::RotateKrbtgt);
    assert_eq!(records.len(), 3, "one record, no intent");
    assert_eq!(records[2].reason, KeydReason::DecisionReplayed);
    assert_eq!(records[2].kvno, Some(2));
}

/// docs/52 §4.2 (a decision of another kind is refused and kept): an
/// approved `rotate_krbtgt` run as `rotate-key` is keyd's uniform Denied
/// (reason `DecisionMismatch`, no intent) — exit 2, the report points to
/// keyd's audit; the right command afterwards runs it (kvno 2).
#[test]
fn a_command_of_another_kind_runs_nothing_and_consumes_nothing() {
    let Some(world) = World::new(Options {
        keyadm_keyd: true,
        ..Options::default()
    }) else {
        return;
    };
    let id = request_and_approve(&world, KeyOperation::RotateKrbtgt);
    let wrong = execute::run(&mut keyd_client(&world), Approved::RotateKey, id);
    assert_eq!(wrong.keyd, Outcome::Answered(Err(KeydError::Denied)));
    assert_eq!(report::execution_exit_code(&wrong), EXIT_INCOMPLETE);
    assert!(report::render_execution(&wrong)
        .iter()
        .any(|l| l.contains("audit record names the reason")));
    assert!(eventually(Duration::from_secs(10), || !keyd_records(
        &world,
        KeydOperation::RotateKey
    )
    .is_empty()));
    let refused = keyd_records(&world, KeydOperation::RotateKey);
    assert_eq!(refused.len(), 1, "no intent");
    assert_eq!(refused[0].reason, KeydReason::DecisionMismatch);
    let right = execute::run(&mut keyd_client(&world), Approved::RotateKrbtgt, id);
    assert_eq!(right.keyd, Outcome::Answered(Ok(Some(Kvno::new(2)))));
}

/// docs/52 §4.2 (N2: keyadm executes only decision ids keyd knows — there is
/// nothing else it could name): an id dird never decided is keyd's uniform
/// Denied (`NoDecision`, no intent); exit 2; no key set changed.
#[test]
fn an_id_dird_never_decided_is_refused() {
    let Some(world) = World::new(Options {
        keyadm_keyd: true,
        ..Options::default()
    }) else {
        return;
    };
    for command in [
        Approved::RotateKrbtgt,
        Approved::RotateKey,
        Approved::RetireKvno,
    ] {
        let report = execute::run(&mut keyd_client(&world), command, 424_242);
        assert_eq!(report.keyd, Outcome::Answered(Err(KeydError::Denied)));
        assert_eq!(report::execution_exit_code(&report), EXIT_INCOMPLETE);
    }
    assert!(eventually(Duration::from_secs(10), || world
        .keyadm_records()
        .len()
        >= 3));
    for record in world.keyadm_records() {
        assert_eq!(record.result, KeydOutcome::Denied, "{record:?}");
        assert_eq!(record.reason, KeydReason::NoDecision);
        assert_eq!(record.decision, Some(424_242));
    }
}

/// A-88, A-90 (outcome unknown), docs/52 §3.10: keyadm's keyd accepts the
/// rotation and never answers — keyadm reports the outcome unknown and that
/// running the same command again returns keyd's recorded result; it never
/// retries itself; exit 2.
#[test]
fn a_keyd_that_never_answers_is_reported_as_outcome_unknown() {
    let Some(world) = World::new(Options::default()) else {
        return;
    };
    let silent = SilentServer::start(&world.keyadm_keyd_socket, keyd_types::Role::Admin);
    let id = request_and_approve(&world, KeyOperation::RotateKrbtgt);
    let report = execute::run(&mut keyd_client(&world), Approved::RotateKrbtgt, id);
    assert!(matches!(report.keyd, Outcome::Unknown(_)), "{report:?}");
    assert_eq!(report::execution_exit_code(&report), EXIT_INCOMPLETE);
    assert_eq!(silent.accepted(), 1, "one connection, no retry");
    let lines = report::render_execution(&report);
    assert!(
        lines
            .iter()
            .any(|l| l.contains("outcome unknown") && l.contains("run the same command again")),
        "{lines:?}"
    );
}

/// docs/52 §4.3 (dird registers a destroy decision after each `Delete`;
/// keyadm destroys only what dird decided); docs/51 §6, §9; docs/10 §7
/// (A-35): before any `Delete` the sweep lists nothing and destroys nothing
/// (ws9, live, keeps its key sets); after admin1 deletes ws9 the sweep runs
/// exactly that decision — both of ws9's key sets (kvno 1) destroyed,
/// keyd's records naming the decision; a second sweep lists nothing (the
/// decision ran); exit 0 each time.
#[test]
fn destroy_sweep_runs_only_dirds_destroy_decisions() {
    let Some(world) = World::new(Options {
        keyadm_keyd: true,
        ..Options::default()
    }) else {
        return;
    };
    let before = sweep::run(&mut keyd_client(&world));
    assert!(before.is_complete(), "{before:?}");
    assert_eq!(before.listed, 0);
    assert!(before.destroyed.is_empty());
    assert_eq!(report::sweep_exit_code(&before), EXIT_COMPLETE);
    assert!(keyd_records(&world, KeydOperation::DestroyKeySet).is_empty());

    delete_ws9(&world);
    let first = sweep::run(&mut keyd_client(&world));
    assert!(first.is_complete(), "{first:?}");
    assert_eq!(first.listed, 1);
    assert_eq!(first.destroyed.len(), 1);
    let decision = first.destroyed[0].decision;
    assert_eq!(
        first.destroyed[0].principal,
        PrincipalId::from_bytes(g(WS9).to_packet())
    );
    assert_eq!(report::sweep_exit_code(&first), EXIT_COMPLETE);
    assert!(eventually(Duration::from_secs(10), || keyd_records(
        &world,
        KeydOperation::DestroyKeySet
    )
    .len()
        >= 2));
    let records = keyd_records(&world, KeydOperation::DestroyKeySet);
    assert_eq!(records[0].result, KeydOutcome::Intent);
    assert_eq!(records[1].result, KeydOutcome::Success);
    assert_eq!(records[1].decision, Some(decision.get()));
    assert_eq!(records[1].principal, Some(g(WS9).to_packet()));
    assert_eq!(records[1].kvno, Some(1), "ws9's untouched key set");
    assert_eq!(records[1].secondary.map(|s| s.kvno), Some(Some(1)));

    let second = sweep::run(&mut keyd_client(&world));
    assert!(second.is_complete());
    assert_eq!(second.listed, 0);
    assert_eq!(report::sweep_exit_code(&second), EXIT_COMPLETE);
}

/// docs/51 §6 ("`Unavailable` ⇒ try again"); A-88: with keyd's auditd gone
/// keyd performs no state change and serves no gating listing — the sweep
/// stops with nothing destroyed (at the listing: exit 1; or at the first
/// destroy, not performed: exit 2, "retry later"); once auditd is back, the
/// rerun runs the decision (the sweep is idempotent).
#[test]
fn an_unavailable_keyd_means_retry_later() {
    let Some(mut world) = World::new(Options {
        keyadm_keyd: true,
        ..Options::default()
    }) else {
        return;
    };
    delete_ws9(&world);
    assert!(eventually(Duration::from_secs(10), || {
        all_records(&world, KeydOperation::RegisterDecision)
            .iter()
            .any(|r| r.result == KeydOutcome::Success)
    }));
    let auditd_path = world.dir.join("ka.sock");
    world.keyd_auditd.as_mut().unwrap().stop();
    let stopped = sweep::run(&mut keyd_client(&world));
    assert!(stopped.destroyed.is_empty(), "{stopped:?}");
    assert!(!stopped.is_complete());
    match &stopped.stopped {
        Some(Stopped::Listing(Outcome::NotPerformed(_))) => {
            assert_eq!(report::sweep_exit_code(&stopped), EXIT_NOTHING_ATTEMPTED);
        }
        Some(Stopped::RetryLater {
            outcome: Outcome::NotPerformed(_),
            ..
        }) => {
            assert_eq!(report::sweep_exit_code(&stopped), EXIT_INCOMPLETE);
            let lines = report::render_sweep(&stopped);
            assert!(lines.iter().any(|l| l.contains("retry later")), "{lines:?}");
        }
        other => panic!("{other:?}"),
    }
    world.keyd_auditd = Some(FakeAuditd::start(&auditd_path));
    let mut done = None;
    assert!(eventually(Duration::from_secs(20), || {
        let report = sweep::run(&mut keyd_client(&world));
        let complete = report.is_complete() && !report.destroyed.is_empty();
        if complete {
            done = Some(report);
        }
        complete
    }));
    let done = done.unwrap();
    assert_eq!(
        done.destroyed[0].principal,
        PrincipalId::from_bytes(g(WS9).to_packet())
    );
}

/// **The N1 attack at the tool level** (docs/52 §3.1 N1; Q-461; A-102): the
/// holder of keyadm's uid and admind's uid tries to take a live account
/// (ws9) over — destroy its key set, grant an "initial" secret, set it:
/// keyadm's sweep finds no destroy decision (dird decided none) and destroys
/// nothing; after keyd's ceremony is sealed, keyadm's uid gets no grant
/// (`CeremonySealed`); admind's uid gets no `set_secret` without dird's
/// decision (`NoGrant`). ws9's key set is untouched: when admin1 later
/// deletes ws9, the sweep destroys its key sets at kvno 1.
#[test]
fn the_n1_takeover_is_refused_at_every_step() {
    let Some(world) = World::new(Options {
        keyadm_keyd: true,
        ..Options::default()
    }) else {
        return;
    };
    // Step 1: destroy — keyadm can only run dird's destroy decisions.
    let sweep = sweep::run(&mut keyd_client(&world));
    assert!(sweep.destroyed.is_empty() && sweep.listed == 0, "{sweep:?}");
    // keyd's ceremony ends with the seal (keyadm's ceremony sends it last).
    assert_eq!(keyd_client(&world).seal_ceremony(), Ok(()));
    // Step 2: an initial-secret grant for the live account.
    let account = ws9(KeyPurpose::PrincipalLongterm);
    let binding = PrincipalBinding::new(
        support::common::realm(),
        support::common::name(KRB_NT_PRINCIPAL, &["ws9$"]),
    );
    assert_eq!(
        keyd_client(&world).grant_set_secret(
            AccountKind::User,
            &[SetSecretTarget {
                handle: account,
                binding: binding.clone(),
                salt: "test-salt-ws9".to_owned(),
            }],
            MAX_INITIAL_SECRET_GRANT_SECS,
        ),
        Ok(Err(KeydError::Denied))
    );
    // Step 3: admind's uid sets the secret without a decision.
    assert_eq!(
        admind_keyd_client(&world).set_secret(
            &account,
            &binding,
            Zeroizing::new("attacker-chosen-1".to_owned()),
            "test-salt-ws9",
        ),
        Ok(Err(KeydError::Denied))
    );
    assert!(eventually(Duration::from_secs(10), || {
        !all_records(&world, KeydOperation::SetSecret).is_empty()
            && !keyd_records(&world, KeydOperation::GrantSetSecret).is_empty()
    }));
    assert_eq!(
        keyd_records(&world, KeydOperation::GrantSetSecret)[0].reason,
        KeydReason::CeremonySealed
    );
    let set = all_records(&world, KeydOperation::SetSecret);
    assert_eq!(set.len(), 1, "refused at the authorization step, no intent");
    assert_eq!(set[0].reason, KeydReason::NoGrant);
    // ws9's key set is untouched (kvno 1) when dird's decision destroys it.
    delete_ws9(&world);
    let sweep = sweep::run(&mut keyd_client(&world));
    assert_eq!(sweep.destroyed.len(), 1, "{sweep:?}");
    assert!(eventually(Duration::from_secs(10), || keyd_records(
        &world,
        KeydOperation::DestroyKeySet
    )
    .len()
        >= 2));
    assert_eq!(
        keyd_records(&world, KeydOperation::DestroyKeySet)[1].kvno,
        Some(1)
    );
}
