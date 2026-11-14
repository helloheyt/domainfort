//! Tier 2 (docs/50 §9; task A10): keyadm's approved-request commands and
//! its `destroy-sweep` against a **real** keyd (the test's uid mapped to
//! Role::Admin, holding the krbtgt key set and ws9's two key sets), the
//! real dird with its admin service, and the real admind — all in this
//! process over real Unix sockets: crates/admin-daemon's tier-2 world,
//! reused by `#[path]` (A8 / A9 support).
//!
//! The administrators' steps (`RequestKeyOperation`, `Approve`, `Delete`)
//! go through admind with AP-REQs sealed under the admin service's key, as
//! A8 / A9 build them (A-91: accepted for tier 2); keyadm's steps go
//! through `ipc_admin::AdmindClient` (admind's uid checked before sending)
//! and `ipc_keyd::KeydClient` (keyd's uid checked before sending) — the
//! production clients, with the host's connectors.
//!
//! What keyd did is read from its own audit records (docs/10 §10: op,
//! principal, purpose, kvno, approvers, result — no secret); what dird
//! recorded from its `DirAdmin` events; what admind forwarded from its
//! verified audit log.
//!
//! Sources: docs/51 §5.6, §6, §9; docs/10 §7, §9, §10; docs/33 §5; A-35;
//! A-85; A-88; A-90; P-22. Every value is constructed by hand for these
//! tests; no vector comes from any other implementation.

#[path = "../../admin-daemon/tests/support/mod.rs"]
mod support;

use core::time::Duration;
use ipc_admin::{AdmindClient, RefusalStatus, Reply, Request};
use ipc_audit::{
    AdmindActivity, DecisionResult, DirAdminOperation, DirAdminStage, ForwardDecision,
    KeyadmOperation, KeydOperation, KeydOutcome, OutcomeResult,
};
use ipc_dird_admin::{KeyOperation, Operation};
use ipc_keyd::KeydClient;
use keyadm::ceremony::Outcome;
use keyadm::cli::Approved;
use keyadm::execute::{self, Completion, Fetch};
use keyadm::report::{self, EXIT_COMPLETE, EXIT_INCOMPLETE, EXIT_NOTHING_ATTEMPTED};
use keyadm::sweep::{self, Stopped};
use keyd_types::{KeyPurpose, Kvno};
use support::{
    auth, connectors, eventually, g, FakeAuditd, Got, Options, SilentServer, World, ADMIN1, ADMIN2,
    KRBTGT, WS9,
};

/// keyadm's client of admind (admin.sock), with the host's connector.
fn admind_client(world: &World) -> AdmindClient<connectors::DirdAdminConnector> {
    AdmindClient::new(
        connectors::dird_admin(&world.admin_socket),
        world.uid,
        ipc_admin::DEFAULT_DEADLINE,
    )
    .unwrap()
}

/// keyadm's client of its keyd (Role::Admin).
fn keyd_client(world: &World) -> KeydClient<connectors::KeydConnector> {
    KeydClient::new(
        connectors::keyd(&world.keyadm_keyd_socket),
        world.uid,
        Duration::from_secs(1),
    )
    .unwrap()
}

/// admin1 requests `operation` through admind; admin2 approves it.
/// Returns the request's id.
fn request_and_approve(world: &World, operation: KeyOperation) -> u64 {
    let mut conn = world.connect();
    let id = match conn.call(&Request::Forward {
        auth: auth("admin1", &[]),
        operation: Operation::RequestKeyOperation { operation },
    }) {
        Got::Reply(Reply::KeyRequest(state)) => state.id,
        other => panic!("{other:?}"),
    };
    match conn.call(&Request::Forward {
        auth: auth("admin2", &[]),
        operation: Operation::Approve { id, operation },
    }) {
        Got::Reply(Reply::KeyRequest(state)) => assert!(state.approved()),
        other => panic!("{other:?}"),
    }
    id
}

/// keyd's records of `operation`, in order.
fn keyd_records(world: &World, operation: KeydOperation) -> Vec<ipc_audit::KeydRecord> {
    world
        .keyadm_records()
        .into_iter()
        .filter(|r| r.op == operation)
        .collect()
}

/// docs/51 §6 (R51-14); docs/10 §7; docs/33 §5: `keyadm rotate-krbtgt <id>`
/// with a request admin1 asked for and admin2 approved — keyd rotates the
/// krbtgt key set to kvno 2 under the token {admin1, admin2} (its intent
/// and outcome records name both), dird records the completion with the
/// reported kvno, admind records both keyadm forwards; exit 0.
#[test]
fn rotate_krbtgt_with_an_approved_request() {
    let Some(mut world) = World::new(Options {
        keyadm_keyd: true,
        ..Options::default()
    }) else {
        return;
    };
    let id = request_and_approve(&world, KeyOperation::RotateKrbtgt);
    let report = execute::run(
        &mut admind_client(&world),
        &mut keyd_client(&world),
        Approved::RotateKrbtgt,
        id,
    );
    assert_eq!(report.keyd, Some(Outcome::Answered(Ok(Some(Kvno::new(2))))));
    assert_eq!(report.completion, Some(Completion::Recorded));
    assert!(report.is_complete());
    assert_eq!(report::execution_exit_code(&report), EXIT_COMPLETE);
    let lines = report::render_execution(&report);
    assert!(lines.iter().any(|l| l.contains("new kvno 2")), "{lines:?}");
    assert!(lines.iter().any(|l| l.contains("completion recorded")));

    // keyd: intent, then the outcome, both naming the two approvers.
    assert!(eventually(Duration::from_secs(10), || keyd_records(
        &world,
        KeydOperation::RotateKrbtgt
    )
    .len()
        >= 2));
    let records = keyd_records(&world, KeydOperation::RotateKrbtgt);
    assert_eq!(records[0].result, KeydOutcome::Intent);
    assert_eq!(records[1].result, KeydOutcome::Success);
    assert_eq!(records[1].kvno, Some(2));
    let approvers = records[1].approvers.unwrap();
    assert_eq!(approvers, [g(ADMIN1).to_packet(), g(ADMIN2).to_packet()]);
    assert_eq!(records[1].principal, Some(g(KRBTGT).to_packet()));

    // dird: the completion with the reported kvno.
    assert!(eventually(Duration::from_secs(10), || {
        world
            .dir_admin_events()
            .iter()
            .filter(|e| e.operation == DirAdminOperation::Complete)
            .count()
            >= 2
    }));
    let completes: Vec<_> = world
        .dir_admin_events()
        .into_iter()
        .filter(|e| e.operation == DirAdminOperation::Complete)
        .collect();
    assert_eq!(
        completes[0].stage,
        DirAdminStage::Decision(DecisionResult::Proceed)
    );
    assert_eq!(
        completes[1].stage,
        DirAdminStage::Outcome(OutcomeResult::Committed { allocated: None })
    );
    assert_eq!(completes[1].reported_kvnos.as_slice(), &[2]);
    assert_eq!(completes[1].key_request, Some(id));

    // The request is consumed: running it again fetches nothing.
    let again = execute::run(
        &mut admind_client(&world),
        &mut keyd_client(&world),
        Approved::RotateKrbtgt,
        id,
    );
    assert_eq!(again.fetch, Fetch::Refused(RefusalStatus::NotFound));
    assert_eq!(report::execution_exit_code(&again), EXIT_NOTHING_ATTEMPTED);

    // admind forwarded FetchApproved, Complete, FetchApproved.
    let uid = world.uid;
    let events = world.finish();
    let forwards: Vec<_> = events
        .iter()
        .filter_map(|e| match e.activity {
            AdmindActivity::KeyadmForward {
                operation,
                decision,
            } => Some((e.peer_uid, operation, decision)),
            _ => None,
        })
        .collect();
    assert_eq!(
        forwards,
        vec![
            (
                Some(uid),
                KeyadmOperation::FetchApproved,
                ForwardDecision::Forwarded
            ),
            (
                Some(uid),
                KeyadmOperation::Complete,
                ForwardDecision::Forwarded
            ),
            (
                Some(uid),
                KeyadmOperation::FetchApproved,
                ForwardDecision::Forwarded
            ),
        ]
    );
}

/// docs/51 §6 (a command executes only the operation it names): an approved
/// `rotate_krbtgt` run as `rotate-key` is not executed — keyd is not asked,
/// dird is told "not performed" and drops it; exit 1.
#[test]
fn a_command_for_another_operation_executes_nothing() {
    let Some(world) = World::new(Options {
        keyadm_keyd: true,
        ..Options::default()
    }) else {
        return;
    };
    let id = request_and_approve(&world, KeyOperation::RotateKrbtgt);
    let report = execute::run(
        &mut admind_client(&world),
        &mut keyd_client(&world),
        Approved::RotateKey,
        id,
    );
    assert!(report.keyd.is_none());
    assert_eq!(report.completion, Some(Completion::Recorded));
    assert_eq!(report::execution_exit_code(&report), EXIT_NOTHING_ATTEMPTED);
    assert!(keyd_records(&world, KeydOperation::RotateKrbtgt).is_empty());
    assert!(eventually(Duration::from_secs(10), || {
        world.dir_admin_events().iter().any(|e| {
            e.operation == DirAdminOperation::Complete
                && e.stage
                    == DirAdminStage::Outcome(OutcomeResult::Failed(
                        ipc_audit::AdminFailure::KeyOperationNotPerformed,
                    ))
        })
    }));
}

/// A-88, A-90 (outcome unknown): keyadm's keyd accepts the rotation and
/// never answers — keyadm reports "outcome unknown — check keyd's audit
/// log", tells dird so (recorded as `KeyOperationOutcomeUnknown`), never
/// retries; exit 2.
#[test]
fn a_keyd_that_never_answers_is_reported_as_outcome_unknown() {
    let Some(world) = World::new(Options::default()) else {
        return;
    };
    let silent = SilentServer::start(&world.keyadm_keyd_socket);
    let id = request_and_approve(&world, KeyOperation::RotateKrbtgt);
    let report = execute::run(
        &mut admind_client(&world),
        &mut keyd_client(&world),
        Approved::RotateKrbtgt,
        id,
    );
    assert!(matches!(report.keyd, Some(Outcome::Unknown(_))));
    assert_eq!(report.completion, Some(Completion::Recorded));
    assert_eq!(report::execution_exit_code(&report), EXIT_INCOMPLETE);
    assert_eq!(silent.accepted(), 1, "one connection, no retry");
    let lines = report::render_execution(&report);
    assert!(
        lines
            .iter()
            .any(|l| l.contains("outcome unknown") && l.contains("audit log")),
        "{lines:?}"
    );
    assert!(eventually(Duration::from_secs(10), || {
        world.dir_admin_events().iter().any(|e| {
            e.operation == DirAdminOperation::Complete
                && e.stage
                    == DirAdminStage::Outcome(OutcomeResult::Failed(
                        ipc_audit::AdminFailure::KeyOperationOutcomeUnknown,
                    ))
        })
    }));
}

/// docs/51 §6, §9 (`destroy-sweep` after a `Delete`); docs/10 §7 (A-35):
/// admin1 deletes ws9 through admind; the sweep lists its tombstone and
/// destroys both of its key sets (keyd's records: two `DestroyKeySet`
/// outcomes `Ok`); a second sweep is a no-op — keyd's uniform `Denied` for
/// both handles, counted as done; exit 0 both times.
#[test]
fn destroy_sweep_after_a_delete_is_idempotent() {
    let Some(world) = World::new(Options {
        keyadm_keyd: true,
        ..Options::default()
    }) else {
        return;
    };
    let mut conn = world.connect();
    assert_eq!(
        conn.call(&Request::Forward {
            auth: auth("admin1", &[]),
            operation: Operation::Delete { target: g(WS9) },
        }),
        Got::Reply(Reply::Done)
    );
    let first = sweep::run(&mut admind_client(&world), &mut keyd_client(&world));
    assert!(first.is_complete(), "{first:?}");
    assert_eq!(first.accounts, 1);
    assert_eq!(
        first.destroyed,
        vec![
            (g(WS9), KeyPurpose::PrincipalLongterm),
            (g(WS9), KeyPurpose::Service)
        ]
    );
    assert_eq!(first.absent, 0);
    assert_eq!(report::sweep_exit_code(&first), EXIT_COMPLETE);
    let second = sweep::run(&mut admind_client(&world), &mut keyd_client(&world));
    assert!(second.is_complete());
    assert!(second.destroyed.is_empty());
    assert_eq!(second.absent, 2);
    assert_eq!(report::sweep_exit_code(&second), EXIT_COMPLETE);
    assert!(eventually(Duration::from_secs(10), || keyd_records(
        &world,
        KeydOperation::DestroyKeySet
    )
    .len()
        >= 8));
    let outcomes: Vec<_> = keyd_records(&world, KeydOperation::DestroyKeySet)
        .into_iter()
        .map(|r| r.result)
        .collect();
    assert_eq!(
        outcomes,
        vec![
            KeydOutcome::Intent,
            KeydOutcome::Success,
            KeydOutcome::Intent,
            KeydOutcome::Success,
            KeydOutcome::Intent,
            KeydOutcome::Denied,
            KeydOutcome::Intent,
            KeydOutcome::Denied,
        ]
    );
}

/// docs/51 §6 ("`Unavailable` ⇒ try again"); A-88: with keyd's auditd gone
/// keyd performs no key-state change (an intent it cannot have acknowledged
/// ⇒ "not performed"; auditd known down ⇒ `Busy`) — the sweep stops with
/// nothing destroyed and says "retry later" (exit 2 once a
/// `destroy_key_set` was sent, 1 if even the contact failed); once auditd
/// is back, the rerun destroys both key sets (the sweep is idempotent).
#[test]
fn an_unavailable_keyd_means_retry_later() {
    let Some(mut world) = World::new(Options {
        keyadm_keyd: true,
        ..Options::default()
    }) else {
        return;
    };
    let mut conn = world.connect();
    assert_eq!(
        conn.call(&Request::Forward {
            auth: auth("admin1", &[]),
            operation: Operation::Delete { target: g(WS9) },
        }),
        Got::Reply(Reply::Done)
    );
    let auditd_path = world.dir.join("kc.sock");
    world.keyadm_keyd_auditd.as_mut().unwrap().stop();
    let stopped = sweep::run(&mut admind_client(&world), &mut keyd_client(&world));
    assert!(stopped.destroyed.is_empty(), "{stopped:?}");
    assert!(!stopped.is_complete());
    match (&stopped.contact, &stopped.stopped) {
        // The contact failed (keyd answered `Busy`): nothing attempted.
        (Outcome::NotPerformed(_), None) => {
            assert_eq!(report::sweep_exit_code(&stopped), EXIT_NOTHING_ATTEMPTED);
        }
        // The first destroy was not performed: retry later.
        (
            Outcome::Answered(Ok(())),
            Some(Stopped::RetryLater {
                guid,
                purpose,
                outcome: Outcome::NotPerformed(_),
            }),
        ) => {
            assert_eq!(*guid, g(WS9));
            assert_eq!(*purpose, KeyPurpose::PrincipalLongterm);
            assert_eq!(report::sweep_exit_code(&stopped), EXIT_INCOMPLETE);
            let lines = report::render_sweep(&stopped);
            assert!(lines.iter().any(|l| l.contains("retry later")), "{lines:?}");
        }
        other => panic!("{other:?}"),
    }
    // auditd back: the rerun completes.
    world.keyadm_keyd_auditd = Some(FakeAuditd::start(&auditd_path));
    let mut done = None;
    assert!(eventually(Duration::from_secs(20), || {
        let report = sweep::run(&mut admind_client(&world), &mut keyd_client(&world));
        let complete = report.is_complete();
        if complete {
            done = Some(report);
        }
        complete
    }));
    let done = done.unwrap();
    assert_eq!(
        done.destroyed,
        vec![
            (g(WS9), KeyPurpose::PrincipalLongterm),
            (g(WS9), KeyPurpose::Service)
        ]
    );
}

/// docs/51 §6 ("admind forwards only if the peer's uid = `keyadm_uid`"):
/// run from another account, keyadm's fetch is refused (`Denied`) and keyd
/// is never asked; exit 1.
#[test]
fn keyadm_from_another_uid_fetches_nothing() {
    let Some(world) = World::new(Options {
        keyadm_keyd: true,
        keyadm_uid_offset: 1,
        ..Options::default()
    }) else {
        return;
    };
    let id = request_and_approve(&world, KeyOperation::RotateKrbtgt);
    let report = execute::run(
        &mut admind_client(&world),
        &mut keyd_client(&world),
        Approved::RotateKrbtgt,
        id,
    );
    assert_eq!(report.fetch, Fetch::Refused(RefusalStatus::Denied));
    assert!(report.keyd.is_none());
    assert_eq!(report::execution_exit_code(&report), EXIT_NOTHING_ATTEMPTED);
    let sweep = sweep::run(&mut admind_client(&world), &mut keyd_client(&world));
    assert_eq!(
        sweep.stopped,
        Some(Stopped::ListingRefused(RefusalStatus::Denied))
    );
    assert!(keyd_records(&world, KeydOperation::RotateKrbtgt).is_empty());
}
