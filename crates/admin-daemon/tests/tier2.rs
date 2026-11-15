//! Tier 2, admind (docs/51 §5, §7.6, task A9): admind in-process over the
//! real `admin.sock`, with a real auditd (its events read back from the
//! verified log), a real keyd holding the admin service's key (dird's
//! ticket verification, Role::Ldap), a real keyd for admind's `set_secret`
//! (Role::Directory — or Admin, refusing; or a silent keyd) and dird with
//! its admin service (or a recording dird) — tests/support.
//!
//! Sources: docs/51 §5.1, §5.2 row 5, §5.7, §7.2, §7.6, §9; docs/47 §9.1,
//! §9.2; docs/50 §3.3, §3.6, §3.7, §9; docs/10 §6, §10; [MS-SAMR] 3.1.1.7.2
//! items 2, 3.2.1, 3.2.2; A-57; A-64; A-79; A-85; A-88; A-90;
//! docs/questions/Q-400..Q-405. Every value is constructed by hand for these
//! tests; no vector comes from any other implementation.

mod support;

use core::time::Duration;
use dtyp::Guid;
use ipc::Refused;
use ipc_admin::{PasswordChanged, RefusalStatus, Reply, Request, SetPassword};
use ipc_audit::{
    AdmindActivity, AdmindEvent, ConnectionRefusal, DecisionResult, DirAdminEvent,
    DirAdminOperation, DirAdminStage, FrameErrorCode, KeyPurposeCode, KeydOperation, KeydOutcome,
    PasswordFailure, PasswordResult, PasswordStep,
};
use ipc_dird_admin::{Auth, Operation};
use keyd::{KeyHandle, KeyPurpose, PrincipalId};
use support::{
    auth, begin_auth, completion, eventually, forward, fresh_unbound, g, DirdMode, Got, KeydMode,
    Options, World, BOB, JO, STAFF_OU, WS9,
};
use zeroize::Zeroizing;

/// A password that passes every rule for bob, ws9$ and jo (test data).
const GOOD: &str = "Granite-Orchard-Lantern-42";

fn password(text: &str) -> ipc_admin::Password {
    ipc_admin::Password::new(Zeroizing::new(text.to_owned()))
}

/// `SetPassword` of `target` by admin1 (two fresh AP-REQs: Begin's and
/// Complete's — docs/questions/Q-400).
fn set_password(target: Guid, text: &str) -> Request {
    Request::SetPassword(SetPassword {
        auth: begin_auth("admin1", &[], target),
        completion: completion("admin1", target),
        target,
        password: password(text),
    })
}

fn changed(kvnos: &[u32], recorded: bool) -> Got {
    Got::Reply(Reply::PasswordChanged(PasswordChanged {
        kvnos: kvnos.to_vec(),
        completion_recorded: recorded,
    }))
}

fn refused(status: RefusalStatus) -> Got {
    Got::Reply(Reply::Refused(status))
}

/// The `DirAdmin` events of `operation` for `target`, in arrival order.
fn events_for(world: &World, operation: DirAdminOperation, target: Guid) -> Vec<DirAdminEvent> {
    world
        .dir_admin_events()
        .into_iter()
        .filter(|e| e.operation == operation && e.target == Some(target.to_packet()))
        .collect()
}

/// Wait until dird's auditd holds `count` events of `operation` for
/// `target`.
fn await_events(
    world: &World,
    operation: DirAdminOperation,
    target: Guid,
    count: usize,
) -> Vec<DirAdminEvent> {
    assert!(
        eventually(Duration::from_secs(10), || events_for(
            world, operation, target
        )
        .len()
            >= count),
        "{operation:?}: {:?}",
        events_for(world, operation, target)
    );
    events_for(world, operation, target)
}

/// One `SetPassword` event: peer uid, target, kvnos, result.
type PasswordEvent = (Option<u32>, [u8; 16], Vec<u32>, PasswordResult);

/// admind's `SetPassword` events.
fn password_events(events: &[AdmindEvent]) -> Vec<PasswordEvent> {
    events
        .iter()
        .filter_map(|e| match &e.activity {
            AdmindActivity::SetPassword {
                target,
                kvnos,
                result,
            } => Some((e.peer_uid, *target, kvnos.as_slice().to_vec(), *result)),
            _ => None,
        })
        .collect()
}

/// keyd verifies `candidate` for `target`'s PrincipalLongterm key set, the
/// way the KDC does: `verify_preauth` of a PA-ENC-TIMESTAMP under the key
/// derived from `candidate` (RFC 4120 §5.2.7.2; docs/10 §4). No role holds
/// `verify_secret` since A-102 (docs/52 R4, Q-465).
fn keyd_verifies(world: &World, target: Guid, candidate: &str) -> bool {
    // The account's string-to-key salt (dird's `account_salt`, [MS-KILE]
    // 3.1.1.2 as docs/47 §9.1 applies it): a user's realm ‖ sAMAccountName;
    // ws9$'s realm ‖ "host" ‖ name ‖ "." ‖ DNS domain.
    let salt = if target == g(WS9) {
        "EXAMPLE.ORGhostws9.example.org"
    } else {
        "EXAMPLE.ORGbob"
    };
    let key = support::common::password_key(support::common::AES256, candidate, salt);
    // PA-ENC-TIMESTAMP (RFC 4120 §5.2.7.2) without a kvno, so that it names
    // the current key whatever its version.
    let mut padata = support::common::pa_enc_timestamp(&key, support::common::now());
    let mut sealed = krb_proto::EncryptedData::decode(&padata.padata_value).unwrap();
    sealed.kvno = None;
    padata.padata_value = sealed.encode().unwrap();
    let mut client = ipc_keyd::KeydClient::new(
        support::connectors::keyd(&world.keyd_kdc_socket),
        ipc_keyd::ExpectedPeer::new(world.uid, keyd::Role::Kdc).unwrap(),
        ipc_keyd::DEFAULT_DEADLINE,
    );
    client
        .verify_preauth(
            &KeyHandle::new(
                PrincipalId::from_bytes(target.to_packet()),
                KeyPurpose::PrincipalLongterm,
            ),
            &padata,
            None,
        )
        .is_ok()
}

/// docs/51 §7.6, §5.2 row 5; docs/47 §9.2; A-90: a user's password —
/// dird's `BeginPasswordSet`, ONE keyd `set_secret`, dird's
/// `CompletePasswordSet {Completed, [kvno]}`, admind's `Admind` event
/// `Completed` with the same kvno; keyd holds the new password; a second
/// set gives the next kvno (A-35: keyd chooses it).
#[test]
fn set_password_for_a_user() {
    let Some(mut world) = World::new(Options::default()) else {
        return;
    };
    let mut conn = world.connect();
    assert_eq!(conn.call(&Request::Ping), Got::Reply(Reply::Pong));
    assert_eq!(conn.call(&set_password(g(BOB), GOOD)), changed(&[1], true));
    assert!(keyd_verifies(&world, g(BOB), GOOD));
    assert!(!keyd_verifies(&world, g(BOB), "Granite-Orchard-Lantern-43"));

    // dird: BeginPasswordSet (decision, outcome) and CompletePasswordSet
    // (decision only) reporting the kvno keyd chose.
    let begin = await_events(&world, DirAdminOperation::BeginPasswordSet, g(BOB), 2);
    assert_eq!(
        begin[0].stage,
        DirAdminStage::Decision(DecisionResult::Proceed)
    );
    let complete = await_events(&world, DirAdminOperation::CompletePasswordSet, g(BOB), 1);
    assert_eq!(complete[0].reported_kvnos.as_slice(), &[1]);
    assert_eq!(
        complete[0].stage,
        DirAdminStage::Decision(DecisionResult::Proceed)
    );

    // keyd: one set_secret, intent then outcome (A-88).
    let records: Vec<_> = world
        .keyd_records()
        .into_iter()
        .filter(|r| r.op == KeydOperation::SetSecret)
        .collect();
    assert_eq!(records.len(), 2, "{records:?}");
    assert_eq!(records[0].result, KeydOutcome::Intent);
    assert_eq!(records[1].result, KeydOutcome::Success);
    assert_eq!(records[1].principal, Some(g(BOB).to_packet()));

    // Again: the next kvno.
    assert_eq!(conn.call(&set_password(g(BOB), GOOD)), changed(&[2], true));
    let complete = await_events(&world, DirAdminOperation::CompletePasswordSet, g(BOB), 2);
    assert_eq!(complete[1].reported_kvnos.as_slice(), &[2]);

    let events = world.finish();
    let sets = password_events(&events);
    assert_eq!(
        sets,
        vec![
            (
                Some(world.uid),
                g(BOB).to_packet(),
                vec![1],
                PasswordResult::Completed
            ),
            (
                Some(world.uid),
                g(BOB).to_packet(),
                vec![2],
                PasswordResult::Completed
            ),
        ]
    );
}

/// docs/47 §9.1; docs/51 §5.2 row 5: a computer with its SPN gets TWO
/// `set_secret` calls — PrincipalLongterm then Service, the same password
/// and salt — and both kvnos are reported to dird and in the event.
#[test]
fn set_password_for_a_computer() {
    let Some(mut world) = World::new(Options::default()) else {
        return;
    };
    let mut conn = world.connect();
    assert_eq!(
        conn.call(&set_password(g(WS9), GOOD)),
        changed(&[1, 1], true)
    );
    assert!(keyd_verifies(&world, g(WS9), GOOD));
    let complete = await_events(&world, DirAdminOperation::CompletePasswordSet, g(WS9), 1);
    assert_eq!(complete[0].reported_kvnos.as_slice(), &[1, 1]);
    let outcomes: Vec<_> = world
        .keyd_records()
        .into_iter()
        .filter(|r| r.op == KeydOperation::SetSecret && r.result == KeydOutcome::Success)
        .map(|r| (r.principal, r.purpose))
        .collect();
    assert_eq!(
        outcomes,
        vec![
            (
                Some(g(WS9).to_packet()),
                Some(KeyPurposeCode::PrincipalLongterm)
            ),
            (Some(g(WS9).to_packet()), Some(KeyPurposeCode::Service)),
        ]
    );
    let events = world.finish();
    assert_eq!(
        password_events(&events),
        vec![(
            Some(world.uid),
            g(WS9).to_packet(),
            vec![1, 1],
            PasswordResult::Completed
        )]
    );
}

/// keyd's rule set (crate admin-password-policy; [MS-SAMR] 3.1.1.7.2 and
/// docs/56 §7 P-24; Q-910 item 13) as admind's pre-check: a password that
/// breaks a rule on its text alone — under `min_password_length`
/// characters, over 256 UTF-16 units, a missing character class, a
/// sequence, a repeat, a weak word — is refused `Invalid` BEFORE dird is
/// asked (no `BeginPasswordSet` event); one containing the sAMAccountName
/// (any case) or the realm's organisation label is refused after
/// `BeginPasswordSet` — never handed to keyd, completion reported `Failed`
/// with no kvno; a two-character name is not checked. The events record
/// `Failed{Validation, PasswordPolicy}` and nothing of which rule. Test
/// data made up; the realm is EXAMPLE.ORG.
#[test]
fn every_password_rule_is_refused() {
    let Some(mut world) = World::new(Options {
        min_password_length: 16,
        ..Options::default()
    }) else {
        return;
    };
    let mut conn = world.connect();
    let clef = '\u{1D11E}';
    for (text, why) in [
        ("Short-Pass-74!x", "under the minimum (15 < 16)"),
        (&"a".repeat(257) as &str, "257 UTF-16 units"),
        (
            &format!("{}{}", "a".repeat(255), clef) as &str,
            "255 + 2 UTF-16 units",
        ),
        (&clef.to_string().repeat(15) as &str, "15 code points"),
        ("lantern-quartz-river-58", "no upper-case letter"),
        ("Lantern-Quartz-Abc-58", "a sequence"),
        ("Lantern-Quartz-111-Pw", "a repeat"),
        ("Lantern-Quartz-Admin-58", "a weak word"),
    ] {
        assert_eq!(
            conn.call(&set_password(g(BOB), text)),
            refused(RefusalStatus::Invalid),
            "{why}"
        );
    }
    // Nothing reached dird: no BeginPasswordSet event for bob.
    std::thread::sleep(Duration::from_millis(200));
    assert!(events_for(&world, DirAdminOperation::BeginPasswordSet, g(BOB)).is_empty());
    // The sAMAccountName "bob", in any case, anywhere; the realm's
    // organisation label "example" (the binding's realm, EXAMPLE.ORG).
    for text in [
        "Mountain-BOB-River-77",
        "bobcat-Lantern-Quartz-58",
        "Lantern-Quartz-bOb-58",
        "Lantern-Example-Quartz-58",
    ] {
        assert_eq!(
            conn.call(&set_password(g(BOB), text)),
            refused(RefusalStatus::Invalid),
            "{text}"
        );
    }
    let begin = await_events(&world, DirAdminOperation::BeginPasswordSet, g(BOB), 8);
    assert_eq!(begin.len(), 8, "decision + outcome for each of the four");
    let complete = await_events(&world, DirAdminOperation::CompletePasswordSet, g(BOB), 4);
    assert!(complete
        .iter()
        .all(|e| e.reported_kvnos.as_slice().is_empty()));
    assert!(
        world
            .keyd_records()
            .iter()
            .all(|r| r.op != KeydOperation::SetSecret),
        "keyd was never asked"
    );
    assert!(!keyd_verifies(&world, g(BOB), "Mountain-BOB-River-77"));
    // jo: a two-character name is not checked ([MS-SAMR] 3.1.1.7.2 item
    // 3.2.2 "more than two characters").
    assert_eq!(
        conn.call(&set_password(g(JO), "jo-jo-JO-Lantern-91")),
        changed(&[1], true)
    );
    let events = world.finish();
    let sets = password_events(&events);
    assert_eq!(sets.len(), 13);
    for (_, target, kvnos, result) in &sets[..12] {
        assert_eq!(*target, g(BOB).to_packet());
        assert!(kvnos.is_empty());
        assert_eq!(
            *result,
            PasswordResult::Failed {
                step: PasswordStep::Validation,
                cause: PasswordFailure::PasswordPolicy
            }
        );
    }
    assert_eq!(sets[12].3, PasswordResult::Completed);
}

/// **Attack test** — docs/10 §2; docs/50 R50-3, §3.7; docs/52 §3.12 (C12);
/// docs/questions/Q-403 option (c), Q-466 items 1-2 (A-102): a keyd that
/// maps admind's uid to **another role** (here Role::Admin) is found by the
/// `Ping` probe of admind's keyd connection, before anything else is sent:
/// **no `set_secret` reaches keyd** (keyd records no SetSecret at all — the
/// residual A-94 accepted, a `Denied` from keyd's capability check, is gone),
/// the `SetPassword` fails at step `SetSecret(PrincipalLongterm)` as keyd
/// unavailable (not sent), dird is told `Failed` with no kvno, and the
/// administrator gets `Unavailable`.
#[test]
fn a_keyd_giving_admind_another_role_receives_no_set_secret() {
    let Some(mut world) = World::new(Options {
        keyd: KeydMode::Admin,
        ..Options::default()
    }) else {
        return;
    };
    let mut conn = world.connect();
    assert_eq!(
        conn.call(&set_password(g(BOB), GOOD)),
        refused(RefusalStatus::Unavailable)
    );
    let complete = await_events(&world, DirAdminOperation::CompletePasswordSet, g(BOB), 1);
    assert!(complete[0].reported_kvnos.as_slice().is_empty());
    assert!(
        bob_records(&world, KeydOperation::SetSecret).is_empty(),
        "keyd received no set_secret"
    );
    let events = world.finish();
    assert_eq!(
        password_events(&events),
        vec![(
            Some(world.uid),
            g(BOB).to_packet(),
            vec![],
            PasswordResult::Failed {
                step: PasswordStep::SetSecret(KeyPurposeCode::PrincipalLongterm),
                cause: PasswordFailure::Unavailable
            }
        )]
    );
}

/// A-88, A-90 (docs/questions/Q-367): a `set_secret` that reached keyd and
/// got no answer within the deadline is "outcome unknown — check before
/// retrying", never "not done"; nothing further is attempted (no second
/// key, completion reported `Failed` with no kvno).
#[test]
fn keyd_never_answering_is_outcome_unknown() {
    let Some(mut world) = World::new(Options {
        keyd: KeydMode::Silent,
        keyd_deadline: Duration::from_secs(1),
        ..Options::default()
    }) else {
        return;
    };
    let mut conn = world.connect();
    assert_eq!(
        conn.call(&set_password(g(WS9), GOOD)),
        refused(RefusalStatus::OutcomeUnknown)
    );
    assert!(world.silent_keyd.as_ref().unwrap().accepted() >= 1);
    let complete = await_events(&world, DirAdminOperation::CompletePasswordSet, g(WS9), 1);
    assert!(complete[0].reported_kvnos.as_slice().is_empty());
    let events = world.finish();
    assert_eq!(
        password_events(&events),
        vec![(
            Some(world.uid),
            g(WS9).to_packet(),
            vec![],
            PasswordResult::Failed {
                step: PasswordStep::SetSecret(KeyPurposeCode::PrincipalLongterm),
                // Task F6 (A-94, Q-406 item 2): the event says so too.
                cause: PasswordFailure::OutcomeUnknown
            }
        )]
    );
}

/// docs/50 §3.7 (R50-8): dird down ⇒ `Unavailable` — for `SetPassword`
/// (failed at `BeginPasswordSet`, no key touched) and for a forwarded
/// operation (never sent).
#[test]
fn dird_down_is_unavailable() {
    let Some(mut world) = World::new(Options::default()) else {
        return;
    };
    let mut conn = world.connect();
    // A first call holds admind's connection to dird.
    assert_eq!(conn.call(&set_password(g(BOB), GOOD)), changed(&[1], true));
    world.dird.take().unwrap().stop().unwrap();
    assert_eq!(
        conn.call(&set_password(g(BOB), GOOD)),
        refused(RefusalStatus::Unavailable)
    );
    let create = forward(
        "admin1",
        &[],
        Operation::CreateUser {
            parent: g(STAFF_OU),
            sam: "carol".into(),
            upn: None,
            description: None,
        },
    );
    assert_eq!(conn.call(&create), refused(RefusalStatus::Unavailable));
    assert!(
        keyd_verifies(&world, g(BOB), GOOD),
        "the old password stays"
    );
    let events = world.finish();
    let sets = password_events(&events);
    assert_eq!(sets.len(), 2);
    assert_eq!(
        sets[1].3,
        PasswordResult::Failed {
            step: PasswordStep::BeginPasswordSet,
            cause: PasswordFailure::Unavailable
        }
    );
}

/// docs/51 §5.7 (auditd unavailable ⇒ refused); A-64: once admind's link to
/// auditd is down, `SetPassword` is refused `Busy` and nothing is asked of
/// dird or keyd.
#[test]
fn auditd_down_refuses_set_password() {
    // The rate limit raised out of the way: `Busy` here can only be the
    // audit reservation's.
    let Some(mut world) = World::new(Options {
        limits: admin_daemon::Limits {
            requests_per_window: 1_000_000,
            ..admin_daemon::Limits::DEFAULT
        },
        ..Options::default()
    }) else {
        return;
    };
    let mut conn = world.connect();
    let _ = world.auditd.take().unwrap().stop();
    // Until admind notices (its heartbeat), a password that breaks a rule
    // is refused `Invalid` without leaving admind; afterwards `Busy`.
    assert!(eventually(Duration::from_secs(10), || {
        conn.call(&set_password(g(BOB), "short")) == Got::Refused(Refused::Busy)
    }));
    assert_eq!(
        conn.call(&set_password(g(BOB), GOOD)),
        Got::Refused(Refused::Busy)
    );
    std::thread::sleep(Duration::from_millis(200));
    assert!(events_for(&world, DirAdminOperation::BeginPasswordSet, g(BOB)).is_empty());
    assert!(world
        .keyd_records()
        .iter()
        .all(|r| r.op != KeydOperation::SetSecret));
}

/// docs/51 §7.6 ("the same operations"): a forwarded operation round-trips
/// through admind with dird's own reply — here a real `CreateUser` (the
/// object exists with the GUID and SID dird answered) and a `Lookup`.
#[test]
fn a_forwarded_create_user_round_trips() {
    let Some(world) = World::new(Options::default()) else {
        return;
    };
    let mut conn = world.connect();
    let create = forward(
        "admin1",
        &[],
        Operation::CreateUser {
            parent: g(STAFF_OU),
            sam: "carol".into(),
            upn: Some("carol@example.org".into()),
            description: None,
        },
    );
    let Got::Reply(Reply::Created { guid, sid }) = conn.call(&create) else {
        panic!("not created");
    };
    let store = world.store.as_ref().unwrap();
    assert_eq!(
        store
            .snapshot()
            .unwrap()
            .lookup_child(Some(g(STAFF_OU)), b"carol")
            .unwrap(),
        Some(guid)
    );
    assert!(sid.is_some());
    let lookup = forward(
        "admin1",
        &[],
        Operation::Lookup(ipc_dird_admin::LookupKey::SamAccountName("carol".into())),
    );
    match conn.call(&lookup) {
        Got::Reply(Reply::Found(found)) => {
            assert_eq!(found.guid, guid);
            assert_eq!(found.sid, sid);
            assert_eq!(found.class, "user");
        }
        other => panic!("{other:?}"),
    }
    // A bad ticket: dird's uniform Denied passes through by name.
    let forged = Request::Forward {
        auth: Auth {
            requester: vec![0x6E, 0x00],
            approvals: vec![],
        },
        operation: Operation::Delete { target: guid },
    };
    assert_eq!(conn.call(&forged), refused(RefusalStatus::Denied));
}

/// R2 (docs/52 §3.2, §5; docs/questions/Q-292): admind forwards AP-REQs
/// untouched and each is bound by its client to the exact dird request it
/// accompanies — so an `auth` made for one operation and forwarded with
/// another is `Denied` by dird through admind (nothing created), and a
/// `SetPassword` whose `auth` is bound to another account's
/// `BeginPasswordSet` sets no password; the same requests correctly bound
/// succeed. (What a compromised admind could try: it holds the AP-REQs.)
#[test]
fn an_auth_bound_to_another_operation_is_refused_through_admind() {
    let Some(world) = World::new(Options::default()) else {
        return;
    };
    let mut conn = world.connect();
    let meant = Operation::CreateUser {
        parent: g(STAFF_OU),
        sam: "carol".into(),
        upn: None,
        description: None,
    };
    let other = Operation::CreateUser {
        parent: g(STAFF_OU),
        sam: "mallory".into(),
        upn: None,
        description: None,
    };
    let rebound = Request::Forward {
        auth: auth("admin1", &[], &meant),
        operation: other,
    };
    assert_eq!(conn.call(&rebound), refused(RefusalStatus::Denied));
    let store = world.store.as_ref().unwrap();
    assert_eq!(
        store
            .snapshot()
            .unwrap()
            .lookup_child(Some(g(STAFF_OU)), b"mallory")
            .unwrap(),
        None
    );
    let wrong_target = Request::SetPassword(SetPassword {
        auth: begin_auth("admin1", &[], g(WS9)),
        completion: completion("admin1", g(BOB)),
        target: g(BOB),
        password: password(GOOD),
    });
    assert_eq!(conn.call(&wrong_target), refused(RefusalStatus::Denied));
    assert!(!keyd_verifies(&world, g(BOB), GOOD), "no password was set");
    assert!(matches!(
        conn.call(&forward("admin1", &[], meant)),
        Got::Reply(Reply::Created { .. })
    ));
    assert_eq!(conn.call(&set_password(g(BOB), GOOD)), changed(&[1], true));
    assert!(keyd_verifies(&world, g(BOB), GOOD));
}

/// docs/51 §7.2, §7.6; A-70, A-73: the AP-REQs reach dird byte for byte as
/// the client sent them — a forwarded operation's `auth`; for `SetPassword`
/// the `auth` of `BeginPasswordSet` (approvals included) and the completion
/// AP-REQ of `CompletePasswordSet` (with no approvals); dird's reply comes
/// back unchanged; the password never reaches dird.
#[test]
fn ap_reqs_reach_dird_unchanged() {
    let created = ipc_dird_admin::Reply::Created {
        guid: g(77),
        sid: Some(support::sid_of(BOB)),
    };
    let Some(world) = World::new(Options {
        dird: DirdMode::Recording {
            reply: created,
            key_targets: true,
        },
        ..Options::default()
    }) else {
        return;
    };
    let mut conn = world.connect();
    let sent = Auth {
        requester: (0..=255u8).cycle().take(3000).collect(),
        approvals: vec![vec![0xA1; 17], vec![0xA2; 4096]],
    };
    let operation = Operation::CreateGroup {
        parent: g(STAFF_OU),
        sam: "team".into(),
        group_type: Some(0x8000_0002),
    };
    let reply = conn.call(&Request::Forward {
        auth: sent.clone(),
        operation: operation.clone(),
    });
    assert_eq!(
        reply,
        Got::Reply(Reply::Created {
            guid: g(77),
            sid: Some(support::sid_of(BOB))
        })
    );
    let begin_auth = Auth {
        requester: vec![0xB0; 999],
        approvals: vec![vec![0xB1; 5]],
    };
    let completion = vec![0xC0; 1234];
    let request = Request::SetPassword(SetPassword {
        auth: begin_auth.clone(),
        completion: completion.clone(),
        target: g(BOB),
        password: password(GOOD),
    });
    assert_eq!(conn.call(&request), changed(&[1], true));
    assert!(keyd_verifies(&world, g(BOB), GOOD));
    let received = world
        .recording
        .as_ref()
        .unwrap()
        .received
        .lock()
        .unwrap()
        .clone();
    assert_eq!(
        received,
        vec![
            ipc_dird_admin::Request::Operation {
                auth: sent,
                operation
            },
            ipc_dird_admin::Request::Operation {
                auth: begin_auth,
                operation: Operation::BeginPasswordSet { target: g(BOB) }
            },
            ipc_dird_admin::Request::Operation {
                auth: Auth {
                    requester: completion,
                    approvals: vec![]
                },
                operation: Operation::CompletePasswordSet {
                    target: g(BOB),
                    outcome: ipc_dird_admin::PasswordSetOutcome::Completed,
                    kvnos: vec![1]
                }
            },
        ]
    );
    // Nothing dird saw carries the password.
    assert!(!format!("{received:?}").contains(GOOD));
}

/// docs/47 §9.1 (fail closed on dird's answer): a `BeginPasswordSet`
/// answered with anything but the account's key targets sets nothing and
/// is `Unavailable` (no key touched).
#[test]
fn a_begin_answer_that_is_not_a_key_target_list_sets_nothing() {
    let Some(world) = World::new(Options {
        dird: DirdMode::Recording {
            reply: ipc_dird_admin::Reply::Done,
            key_targets: false,
        },
        ..Options::default()
    }) else {
        return;
    };
    let mut conn = world.connect();
    assert_eq!(
        conn.call(&set_password(g(BOB), GOOD)),
        refused(RefusalStatus::Unavailable)
    );
    assert!(!keyd_verifies(&world, g(BOB), GOOD));
}

/// A-85 (docs/questions/Q-340 item 8), docs/questions/Q-405: the per-uid
/// request rate — past the window's limit every request (a `Ping`
/// included) is answered `Busy`, and the connection is kept.
#[test]
fn the_per_uid_rate_limit_answers_busy() {
    let Some(world) = World::new(Options {
        limits: admin_daemon::Limits {
            requests_per_window: 3,
            ..admin_daemon::Limits::DEFAULT
        },
        ..Options::default()
    }) else {
        return;
    };
    let mut conn = world.connect();
    for _ in 0..3 {
        assert_eq!(conn.call(&Request::Ping), Got::Reply(Reply::Pong));
    }
    assert_eq!(conn.call(&Request::Ping), Got::Refused(Refused::Busy));
    assert_eq!(
        conn.call(&set_password(g(BOB), GOOD)),
        Got::Refused(Refused::Busy)
    );
    // The same uid on a new connection shares the budget.
    let mut other = world.connect();
    assert_eq!(other.call(&Request::Ping), Got::Refused(Refused::Busy));
}

/// docs/50 §3.6; A-57: over the per-uid connection quota a connection gets
/// `Busy` for its first request and is closed; a noise event
/// `ConnectionRefused{ConnectionLimit}` records it.
#[test]
fn the_connection_quota_refuses_with_a_noise_event() {
    let Some(mut world) = World::new(Options {
        limits: admin_daemon::Limits {
            max_connections_per_uid: 1,
            ..admin_daemon::Limits::DEFAULT
        },
        ..Options::default()
    }) else {
        return;
    };
    let mut first = world.connect();
    assert_eq!(first.call(&Request::Ping), Got::Reply(Reply::Pong));
    let mut second = world.connect();
    assert_eq!(second.call(&Request::Ping), Got::Refused(Refused::Busy));
    assert_eq!(second.receive(), Got::Closed);
    assert_eq!(first.call(&Request::Ping), Got::Reply(Reply::Pong));
    drop(first);
    let events = world.finish();
    assert!(events.iter().any(|e| e.peer_uid == Some(world.uid)
        && e.activity
            == AdmindActivity::ConnectionRefused {
                reason: ConnectionRefusal::ConnectionLimit
            }
        && e.is_noise()));
}

/// docs/50 §3.3; docs/51 §5.7 item 3; A-57: a malformed frame closes the
/// connection and is recorded as a noise event naming the rule broken —
/// a wrong magic (closed, no reply), a trailing octet (`Malformed`, then
/// closed), another version (`VersionMismatch`, then closed).
#[test]
fn a_malformed_frame_is_a_noise_event_and_a_close() {
    let Some(mut world) = World::new(Options::default()) else {
        return;
    };
    let ping = ipc_admin::encode_request(&Request::Ping).unwrap();
    let mut wrong_magic = ping.as_bytes().to_vec();
    wrong_magic[4..6].copy_from_slice(&ipc_dird_admin::ADMIN_MAGIC.to_be_bytes());
    let mut conn = world.connect();
    conn.send_raw(&wrong_magic);
    assert_eq!(conn.receive(), Got::Closed);

    let mut trailing = ping.as_bytes().to_vec();
    trailing.push(0);
    let length = u32::try_from(trailing.len() - 4).unwrap();
    trailing[..4].copy_from_slice(&length.to_be_bytes());
    let mut conn = world.connect();
    conn.send_raw(&trailing);
    assert_eq!(conn.receive(), Got::Refused(Refused::Malformed));
    assert_eq!(conn.receive(), Got::Closed);

    let mut version = ping.as_bytes().to_vec();
    version[6] = ipc_admin::ADMIN_VERSION + 1;
    let mut conn = world.connect();
    conn.send_raw(&version);
    assert_eq!(conn.receive(), Got::Refused(Refused::VersionMismatch));
    assert_eq!(conn.receive(), Got::Closed);

    let events = world.finish();
    let malformed: Vec<FrameErrorCode> = events
        .iter()
        .filter(|e| e.peer_uid == Some(world.uid) && e.is_noise())
        .filter_map(|e| match e.activity {
            AdmindActivity::MalformedFrame { error } => Some(error),
            _ => None,
        })
        .collect();
    assert_eq!(
        malformed,
        vec![
            FrameErrorCode::WrongMagic,
            FrameErrorCode::TrailingBytes,
            FrameErrorCode::VersionMismatch
        ]
    );
}

/// docs/50 §3.3 ("`length` checked against the MAX … before any body byte
/// is allocated or read"): a length prefix over 288 KiB closes the
/// connection at once — before any body octet is sent, well inside the
/// frame timeout — with a noise event `MalformedFrame{FrameTooLarge}`.
#[test]
fn an_oversize_frame_is_closed_before_the_body() {
    let Some(mut world) = World::new(Options {
        frame_timeout: Duration::from_secs(5),
        ..Options::default()
    }) else {
        return;
    };
    let mut conn = world.connect();
    let started = std::time::Instant::now();
    conn.send_raw(&(ipc_admin::MAX_REQUEST_BODY + 1).to_be_bytes());
    assert_eq!(conn.receive(), Got::Closed);
    assert!(started.elapsed() < Duration::from_secs(4));
    let events = world.finish();
    assert!(events.iter().any(|e| e.activity
        == AdmindActivity::MalformedFrame {
            error: FrameErrorCode::FrameTooLarge
        }));
}

/// docs/51 §9 (the password-set row): a computer whose first `set_secret`
/// succeeded and whose second failed is `Incomplete` — never "not done" —
/// and dird is told which kvno was set. Played with a keyd that already
/// holds the computer's Service key set under another binding (keyd refuses
/// a binding that does not match, A-19), so the second call is `Denied`.
#[test]
fn a_computer_set_in_part_is_incomplete() {
    let Some(mut world) = World::new(Options::default()) else {
        return;
    };
    // The Service key set of ws9$, created first under another name.
    let mut client = ipc_keyd::KeydClient::new(
        support::connectors::keyd(&world.keyd_dir_socket),
        ipc_keyd::ExpectedPeer::new(world.uid, keyd::Role::Directory).unwrap(),
        ipc_keyd::DEFAULT_DEADLINE,
    );
    let other = keyd::PrincipalBinding::new(
        support::common::realm(),
        support::common::name(
            krb_proto::constants::KRB_NT_SRV_HST,
            &["host", "elsewhere.example.org"],
        ),
    );
    // keyd sets no secret without a decision (task A15a; A-102): the test
    // registers one as dird would (Role::Ldap on keyd's own socket) for
    // ws9$'s two key sets, the Service one under the other name and salt.
    let mut ldap = ipc_keyd::KeydClient::new(
        support::connectors::keyd(&world.keyd_ldap_socket),
        ipc_keyd::ExpectedPeer::new(world.uid, keyd::Role::Ldap).unwrap(),
        ipc_keyd::DEFAULT_DEADLINE,
    );
    ldap.register_decision(
        keyd::DecisionId::new(1),
        &keyd::DecidedOperation::SetSecret {
            kind: keyd::AccountKind::Computer,
            targets: vec![
                keyd::SetSecretTarget {
                    handle: KeyHandle::new(
                        PrincipalId::from_bytes(g(WS9).to_packet()),
                        KeyPurpose::PrincipalLongterm,
                    ),
                    binding: keyd::PrincipalBinding::new(
                        support::common::realm(),
                        support::common::name(krb_proto::constants::KRB_NT_PRINCIPAL, &["ws9$"]),
                    ),
                    salt: String::from("EXAMPLE.ORGhostws9.example.org"),
                },
                keyd::SetSecretTarget {
                    handle: KeyHandle::new(
                        PrincipalId::from_bytes(g(WS9).to_packet()),
                        KeyPurpose::Service,
                    ),
                    binding: other.clone(),
                    salt: String::from("EXAMPLE.ORGhostelsewhere.example.org"),
                },
            ],
        },
        &[],
        keyd::MAX_SET_SECRET_GRANT_SECS,
    )
    .unwrap()
    .unwrap();
    let call = ipc_keyd::Call::SetSecret {
        handle: KeyHandle::new(
            PrincipalId::from_bytes(g(WS9).to_packet()),
            KeyPurpose::Service,
        ),
        binding: other,
        password: ipc_keyd::Password::new(Zeroizing::new(String::from("Some-Other-Secret-1"))),
        salt: String::from("EXAMPLE.ORGhostelsewhere.example.org"),
    };
    assert!(matches!(
        client.call_with_fate(&call),
        Ok(ipc_keyd::Answer::SetSecret(Ok(_)))
    ));
    let mut conn = world.connect();
    assert_eq!(
        conn.call(&set_password(g(WS9), GOOD)),
        refused(RefusalStatus::Incomplete)
    );
    let complete = await_events(&world, DirAdminOperation::CompletePasswordSet, g(WS9), 1);
    assert_eq!(complete[0].reported_kvnos.as_slice(), &[1]);
    let events = world.finish();
    assert_eq!(
        password_events(&events),
        vec![(
            Some(world.uid),
            g(WS9).to_packet(),
            vec![1],
            PasswordResult::Failed {
                step: PasswordStep::SetSecret(KeyPurposeCode::Service),
                cause: PasswordFailure::Denied
            }
        )]
    );
}

/// docs/51 §7.6; docs/questions/Q-400: a completion AP-REQ that dird does
/// not accept leaves the password SET (keyd changed it) — the reply is
/// `PasswordChanged` with `completion_recorded: false`, and the event
/// records the failed completion step.
#[test]
fn a_refused_completion_still_reports_the_password_set() {
    let Some(mut world) = World::new(Options::default()) else {
        return;
    };
    let mut conn = world.connect();
    let request = Request::SetPassword(SetPassword {
        auth: begin_auth("admin1", &[], g(BOB)),
        completion: vec![0x6E, 0x00],
        target: g(BOB),
        password: password(GOOD),
    });
    assert_eq!(conn.call(&request), changed(&[1], false));
    assert!(keyd_verifies(&world, g(BOB), GOOD));
    let events = world.finish();
    assert_eq!(
        password_events(&events),
        vec![(
            Some(world.uid),
            g(BOB).to_packet(),
            vec![1],
            PasswordResult::Failed {
                step: PasswordStep::CompletePasswordSet,
                cause: PasswordFailure::Denied
            }
        )]
    );
}

// ---------------------------------------------------------------------------
// A-102: keyadm's former channel is retired (N2); task F6: the appended
// codes.
// ---------------------------------------------------------------------------

use ipc_dird_admin::KeyOperation;

/// The `DirAdmin` events of `operation` (any target).
fn dird_events(world: &World, operation: DirAdminOperation) -> Vec<DirAdminEvent> {
    world
        .dir_admin_events()
        .into_iter()
        .filter(|e| e.operation == operation)
        .collect()
}

/// One frame of a retired keyadm kind (`0x10` `FetchApproved`, `0x11`
/// `Complete`, `0x12` `ListPendingDestruction`) with its former payload (an
/// id; an id and a "performed, kvno 3" outcome; no cursor) — what an
/// attacker holding admind's channel would forge (test data).
fn retired_frame(kind: u8) -> Vec<u8> {
    let payload: Vec<u8> = match kind {
        0x10 => 4242u64.to_be_bytes().to_vec(),
        0x11 => [4242u64.to_be_bytes().to_vec(), vec![1, 1, 0, 0, 0, 3]].concat(),
        _ => vec![0],
    };
    let mut body = ipc_admin::ADMIN_MAGIC.to_be_bytes().to_vec();
    body.push(ipc_admin::ADMIN_VERSION);
    body.push(kind);
    body.extend(payload);
    let mut frame = (body.len() as u32).to_be_bytes().to_vec();
    frame.extend(body);
    frame
}

/// **The N2 attack** (docs/52 §3.1 N2, §4.6, §4.8; docs/questions/Q-460,
/// A-102): admind used to forward keyadm's `FetchApproved` / `Complete` /
/// `ListPendingDestruction` to dird and hand keyadm dird's answer — so a
/// compromised admind could feed keyadm an "approved" operation with
/// invented approvers, or a live account as a tombstone. The channel no
/// longer exists: from the test's uid (what was `keyadm_uid`) each of the
/// three kinds is an unknown kind of admin.sock's closed table — the
/// connection is closed without a reply, admind records a
/// `MalformedFrame{UnknownKind}` noise event and no `KeyadmForward`, dird is
/// never asked (no `DirAdmin` event of those operations), and the
/// administrators' own key-operation request still reaches dird. keyadm now
/// takes nothing from admind or dird: it executes, in keyd, decisions only
/// dird could register (crates/keyd tests/decisions.rs).
#[test]
fn the_retired_keyadm_requests_never_reach_dird() {
    let Some(mut world) = World::new(Options::default()) else {
        return;
    };
    for kind in ipc_admin::channel::request_kind::RETIRED {
        let mut conn = world.connect();
        conn.send_raw(&retired_frame(*kind));
        assert_eq!(conn.receive(), Got::Closed, "{kind:#x}");
    }
    // The administrators' channel itself is unchanged.
    let mut conn = world.connect();
    let request = forward(
        "admin1",
        &[],
        Operation::RequestKeyOperation {
            operation: KeyOperation::RotateKrbtgt,
        },
    );
    assert!(matches!(
        conn.call(&request),
        Got::Reply(Reply::KeyRequest(state)) if state.operation == KeyOperation::RotateKrbtgt
    ));
    assert!(eventually(Duration::from_secs(10), || !dird_events(
        &world,
        DirAdminOperation::RequestKeyOperation
    )
    .is_empty()));
    for operation in [
        DirAdminOperation::FetchApproved,
        DirAdminOperation::Complete,
        DirAdminOperation::ListPendingDestruction,
    ] {
        assert!(
            dird_events(&world, operation).is_empty(),
            "{operation:?} must not reach dird"
        );
    }
    let events = world.finish();
    assert!(events
        .iter()
        .all(|e| !matches!(e.activity, AdmindActivity::KeyadmForward { .. })));
    let unknown = events
        .iter()
        .filter(|e| {
            e.activity
                == AdmindActivity::MalformedFrame {
                    error: ipc_audit::FrameErrorCode::UnknownKind,
                }
        })
        .count();
    assert_eq!(unknown, 3);
}

/// Task F6 (A-94; docs/questions/Q-406 item 3): a frame dropped by the
/// per-uid request rate is recorded as the noise activity `RateLimited`
/// (with the peer uid); a frame whose value the typed layer refuses (a
/// second spelling of "never") as `MalformedFrame{ValueRefused}`.
#[test]
fn rate_limited_and_refused_values_have_their_own_codes() {
    let Some(mut world) = World::new(Options {
        limits: admin_daemon::Limits {
            requests_per_window: 2,
            ..admin_daemon::Limits::DEFAULT
        },
        ..Options::default()
    }) else {
        return;
    };
    let mut conn = world.connect();
    assert_eq!(conn.call(&Request::Ping), Got::Reply(Reply::Pong));
    // A SetAccountExpires `At(0x7FFFFFFFFFFFFFFF)`: wire-valid, refused by
    // the typed layer (one spelling of "never", A-85). Hand-built from the
    // forwarded layout (docs/51 §7.3): auth, target, 2 ‖ u64.
    let mut body = vec![0x41, 0x4D, 1, 0x09];
    let requester = fresh_unbound("admin1");
    body.extend((requester.len() as u32).to_be_bytes());
    body.extend(&requester);
    body.extend(0u32.to_be_bytes());
    body.extend(g(BOB).to_packet());
    body.push(2);
    body.extend(0x7FFF_FFFF_FFFF_FFFFu64.to_be_bytes());
    let mut frame = (body.len() as u32).to_be_bytes().to_vec();
    frame.extend(body);
    conn.send_raw(&frame);
    assert_eq!(conn.receive(), Got::Refused(Refused::Malformed));
    let mut conn = world.connect();
    assert_eq!(conn.call(&Request::Ping), Got::Refused(Refused::Busy));
    let uid = world.uid;
    let events = world.finish();
    assert!(events.iter().any(|e| e.peer_uid == Some(uid)
        && e.activity
            == AdmindActivity::MalformedFrame {
                error: FrameErrorCode::ValueRefused
            }));
    assert!(events
        .iter()
        .any(|e| e.peer_uid == Some(uid) && e.activity == AdmindActivity::RateLimited));
}

// ---------------------------------------------------------------------------
// The set_secret grant (task A15a; docs/51 §5.8 option (b); docs/questions/
// Q-291, Q-450..Q-453).
// ---------------------------------------------------------------------------

/// bob's `(GUID, PrincipalLongterm)` handle and the NT-PRINCIPAL binding dird
/// answers for it (docs/47 §9.1).
fn bob_key_set() -> (KeyHandle, keyd::PrincipalBinding) {
    (
        KeyHandle::new(
            PrincipalId::from_bytes(g(BOB).to_packet()),
            KeyPurpose::PrincipalLongterm,
        ),
        keyd::PrincipalBinding::new(support::common::realm(), support::principal("bob")),
    )
}

/// An admind-like Directory client's `set_secret` of bob's key set, sent
/// straight to keyd (`kd.sock`); keyd's answer.
fn direct_set_secret(world: &World, password: &str) -> Option<Result<keyd::Kvno, keyd::Error>> {
    let (handle, binding) = bob_key_set();
    let mut client = ipc_keyd::KeydClient::new(
        support::connectors::keyd(&world.keyd_dir_socket),
        ipc_keyd::ExpectedPeer::new(world.uid, keyd::Role::Directory).unwrap(),
        ipc_keyd::DEFAULT_DEADLINE,
    );
    let call = ipc_keyd::Call::SetSecret {
        handle,
        binding,
        password: ipc_keyd::Password::new(Zeroizing::new(password.to_owned())),
        salt: String::from("EXAMPLE.ORGbob"),
    };
    match client.call_with_fate(&call) {
        Ok(ipc_keyd::Answer::SetSecret(result)) => Some(result),
        _ => None,
    }
}

/// keyd's records of `op` for bob's key set, in order.
fn bob_records(world: &World, op: KeydOperation) -> Vec<ipc_audit::KeydRecord> {
    world
        .keyd_records()
        .into_iter()
        .filter(|r| r.op == op && r.principal == Some(g(BOB).to_packet()))
        .collect()
}

/// docs/51 §5.8 option (b): a `SetPassword` works end to end with the grant
/// dird registers — keyd records dird's `RegisterDecision` (Role::Ldap, A-102) as an
/// acknowledged intent and its success **before** admind's `set_secret`
/// (Role::Directory) intent; the password is set.
#[test]
fn set_password_runs_on_the_grant_dird_registers() {
    let Some(world) = World::new(Options::default()) else {
        return;
    };
    let mut conn = world.connect();
    assert_eq!(conn.call(&set_password(g(BOB), GOOD)), changed(&[1], true));
    assert!(keyd_verifies(&world, g(BOB), GOOD));
    assert!(eventually(Duration::from_secs(10), || {
        bob_records(&world, KeydOperation::SetSecret)
            .iter()
            .any(|r| r.result == KeydOutcome::Success)
    }));
    let records = world.keyd_records();
    let position = |op: KeydOperation, result: KeydOutcome| {
        records
            .iter()
            .position(|r| {
                r.op == op && r.result == result && r.principal == Some(g(BOB).to_packet())
            })
            .unwrap_or_else(|| panic!("{op:?} {result:?} in {records:?}"))
    };
    let grant_intent = position(KeydOperation::RegisterDecision, KeydOutcome::Intent);
    let grant = position(KeydOperation::RegisterDecision, KeydOutcome::Success);
    let set_intent = position(KeydOperation::SetSecret, KeydOutcome::Intent);
    assert!(grant_intent < grant && grant < set_intent, "{records:?}");
    assert_eq!(records[grant].caller_role, ipc_audit::KeydRole::Ldap);
    assert_eq!(
        records[grant].purpose,
        Some(KeyPurposeCode::PrincipalLongterm)
    );
    assert_eq!(
        records[set_intent].caller_role,
        ipc_audit::KeydRole::Directory
    );
}

/// docs/questions/Q-291 (the attack): an admind-like Directory client that
/// calls keyd's `set_secret` with no `BeginPasswordSet` before it — so no
/// PDP decision and no grant — is refused with keyd's uniform `Denied`
/// (`NoGrant`, one record, no intent: A-88), and nothing changes. A grant
/// is consumed by one `set_secret`: dird's grant does not allow a second.
#[test]
fn a_set_secret_without_dirds_grant_is_denied() {
    let Some(world) = World::new(Options::default()) else {
        return;
    };
    assert_eq!(
        direct_set_secret(&world, "Rogue-Phrase-Without-Grant-1"),
        Some(Err(keyd::Error::Denied))
    );
    assert!(eventually(Duration::from_secs(10), || !bob_records(
        &world,
        KeydOperation::SetSecret
    )
    .is_empty()));
    let records = bob_records(&world, KeydOperation::SetSecret);
    assert_eq!(records.len(), 1, "one record, no intent: {records:?}");
    assert_eq!(records[0].result, KeydOutcome::Denied);
    assert_eq!(records[0].reason, ipc_audit::KeydReason::NoGrant);
    assert_eq!(records[0].caller_role, ipc_audit::KeydRole::Directory);
    assert!(!keyd_verifies(
        &world,
        g(BOB),
        "Rogue-Phrase-Without-Grant-1"
    ));
    // No BeginPasswordSet reached dird.
    assert!(events_for(&world, DirAdminOperation::BeginPasswordSet, g(BOB)).is_empty());

    // After a SetPassword the grant is spent: a direct set_secret is
    // refused again.
    let mut conn = world.connect();
    assert_eq!(conn.call(&set_password(g(BOB), GOOD)), changed(&[1], true));
    assert_eq!(
        direct_set_secret(&world, "Rogue-Phrase-Without-Grant-2"),
        Some(Err(keyd::Error::Denied))
    );
    assert!(keyd_verifies(&world, g(BOB), GOOD), "the password stays");
}

/// Q-450 item 3: dird's grant lives 30 s by keyd's clock. A
/// `BeginPasswordSet` sent to dird as admind would send it registers the
/// grant; 31 s later (keyd's clock moved) the `set_secret` finds none
/// (`NoGrant`); a fresh `BeginPasswordSet` followed at once works.
#[test]
fn dirds_grant_expires() {
    let Some(world) = World::new(Options::default()) else {
        return;
    };
    let mut dird = ipc_dird_admin::AdminClient::new(
        support::connectors::dird_admin(&world.dird_socket),
        world.uid,
        ipc_dird_admin::DEFAULT_DEADLINE,
    )
    .unwrap();
    let begin = || ipc_dird_admin::Request::Operation {
        auth: begin_auth("admin1", &[], g(BOB)),
        operation: Operation::BeginPasswordSet { target: g(BOB) },
    };
    assert!(matches!(
        dird.call(&begin()),
        Ok(ipc_dird_admin::Reply::PasswordSet(_))
    ));
    let clock = world.keyd_clock.as_ref().unwrap();
    clock.set(support::common::at(
        i64::from(directory_daemon::SET_SECRET_GRANT_LIFETIME_SECS) + 1,
    ));
    assert_eq!(
        direct_set_secret(&world, GOOD),
        Some(Err(keyd::Error::Denied))
    );
    assert!(eventually(Duration::from_secs(10), || {
        bob_records(&world, KeydOperation::SetSecret)
            .last()
            .is_some_and(|r| r.reason == ipc_audit::KeydReason::NoGrant)
    }));
    assert!(!keyd_verifies(&world, g(BOB), GOOD));

    assert!(matches!(
        dird.call(&begin()),
        Ok(ipc_dird_admin::Reply::PasswordSet(_))
    ));
    assert_eq!(
        direct_set_secret(&world, GOOD),
        Some(Ok(keyd::Kvno::INITIAL))
    );
    assert!(keyd_verifies(&world, g(BOB), GOOD));
}
