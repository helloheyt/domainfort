//! `BeginPasswordSet` / `CompletePasswordSet`.
//!
//! Sources: docs/51 §5.2 row 5, §7.3 (the reply: kind, handles 1 or 2,
//! bindings, salt), §9 (pwdLastSet first, then `set_secret`); docs/47 §9.1
//! (the key-set / binding table: user `(GUID, PrincipalLongterm)` bound to
//! NT-PRINCIPAL [sAMAccountName]; computer also `(GUID, Service)` bound to
//! NT-SRV-HST, the single SPN split on "/"; one salt for both), §9.2 step 2
//! (pwdLastSet = now), §3.3 (R47-4: the salt from `account_salt`); RFC 4120
//! §6.2 (name types); [MS-KILE] 3.1.1.2 via `directory_pip::account_salt`
//! (whose own tests carry the [MS-KILE] 4.4 example); A-79 (pwdLastSet
//! always "now"). Fixtures: tests/common.

mod common;

use common::*;
use directory_admin::{
    CompletePasswordSet, CreateGroup, Operation, PasswordSetOutcome, RefusalStatus, Reply,
};
use directory_pip::{account_salt, AccountKind};
use ipc_audit::{AdminRefusal, DecisionResult, DirAdminStage};
use keyd_types::{KeyHandle, KeyPurpose, PrincipalId};
use krb_proto::constants::{KRB_NT_PRINCIPAL, KRB_NT_SRV_HST};

fn refusal_code(r: &directory_admin::Refusal) -> AdminRefusal {
    match r.event().stage {
        DirAdminStage::Decision(DecisionResult::Refused(code)) => code,
        other => panic!("not a decision refusal: {other:?}"),
    }
}

fn principal(id: u32) -> PrincipalId {
    PrincipalId::from_bytes(guid(id).to_packet())
}

/// docs/47 §9.1-§9.2; docs/51 §7.3: a user gets one key set,
/// `(objectGUID, PrincipalLongterm)` bound to NT-PRINCIPAL ["alice"] in the
/// realm, the user salt "EXAMPLE.TEST" ‖ "alice", and pwdLastSet = now.
#[test]
fn a_user_password_set_returns_one_key_set() {
    let mut d = Domain::new("pw-user");
    let (_, applied) = d
        .run(
            Operation::BeginPasswordSet {
                target: guid(ALICE),
            },
            "admin1",
            &[],
        )
        .applied();
    let Reply::PasswordSet(reply) = applied.reply() else {
        panic!("{:?}", applied.reply());
    };
    assert_eq!(reply.kind, AccountKind::User);
    assert_eq!(reply.keys.len(), 1);
    assert_eq!(
        reply.keys[0].handle,
        KeyHandle::new(principal(ALICE), KeyPurpose::PrincipalLongterm)
    );
    assert_eq!(reply.keys[0].binding.realm, realm());
    assert_eq!(reply.keys[0].binding.name.name_type, KRB_NT_PRINCIPAL);
    assert_eq!(
        reply.keys[0]
            .binding
            .name
            .name_string
            .iter()
            .map(|c| c.as_str())
            .collect::<Vec<_>>(),
        ["alice"]
    );
    // [MS-KILE] 3.1.1.2 user rule: "<DNS of the realm, converted to
    // uppercase> | <user name>" — the same function the account source uses.
    assert_eq!(reply.salt.as_str(), "EXAMPLE.TESTalice");
    assert_eq!(
        reply.salt,
        account_salt(&realm(), AccountKind::User, "alice").unwrap()
    );
    let obj = d.object(guid(ALICE)).unwrap();
    assert_eq!(
        obj.attribute(d.attr("pwdLastSet")).unwrap().values[0].value,
        int64(NOW_FILETIME)
    );
    assert_eq!(
        obj.attribute(d.attr("whenChanged")).unwrap().values[0].value,
        int64(NOW_DSTIME)
    );
}

/// docs/47 §9.1: a computer with its SPN gets two key sets, the same salt:
/// `PrincipalLongterm` bound to NT-PRINCIPAL ["ws01$"] and `Service` bound
/// to NT-SRV-HST ["host", "ws01.example.test"]; the computer salt
/// "EXAMPLE.TEST" ‖ "host" ‖ "ws01" ‖ "." ‖ "example.test".
#[test]
fn a_computer_password_set_returns_two_key_sets() {
    let mut d = Domain::new("pw-computer");
    let (_, applied) = d
        .run(
            Operation::BeginPasswordSet { target: guid(WS01) },
            "admin1",
            &[],
        )
        .applied();
    let Reply::PasswordSet(reply) = applied.reply() else {
        panic!("{:?}", applied.reply());
    };
    assert_eq!(reply.kind, AccountKind::Computer);
    assert_eq!(reply.keys.len(), 2);
    assert_eq!(
        reply.keys[0].handle,
        KeyHandle::new(principal(WS01), KeyPurpose::PrincipalLongterm)
    );
    assert_eq!(reply.keys[0].binding.name.name_type, KRB_NT_PRINCIPAL);
    assert_eq!(reply.keys[0].binding.name.name_string[0].as_str(), "ws01$");
    assert_eq!(
        reply.keys[1].handle,
        KeyHandle::new(principal(WS01), KeyPurpose::Service)
    );
    assert_eq!(reply.keys[1].binding.name.name_type, KRB_NT_SRV_HST);
    assert_eq!(
        reply.keys[1]
            .binding
            .name
            .name_string
            .iter()
            .map(|c| c.as_str())
            .collect::<Vec<_>>(),
        ["host", "ws01.example.test"]
    );
    assert_eq!(reply.salt.as_str(), "EXAMPLE.TESThostws01.example.test");
    assert_eq!(
        reply.salt,
        account_salt(&realm(), AccountKind::Computer, "ws01$").unwrap()
    );
}

/// docs/51 §5.2 row 5: only a user or computer has a password; a group is
/// refused (and so is a protected account — tests/operations.rs).
#[test]
fn only_accounts_have_passwords() {
    let mut d = Domain::new("pw-group");
    let r = d
        .run(
            Operation::BeginPasswordSet {
                target: guid(READERS),
            },
            "admin1",
            &[],
        )
        .refused();
    assert_eq!(refusal_code(&r), AdminRefusal::ValueInvalid);
    assert_eq!(r.status(), RefusalStatus::Invalid);
    // Nothing for a requester who may not reset passwords (bob: read only).
    let r = d
        .run(
            Operation::BeginPasswordSet {
                target: guid(ALICE),
            },
            "bob",
            &[],
        )
        .refused();
    assert_eq!(refusal_code(&r), AdminRefusal::PolicyDenied);
    // A group created through the admin plane is no exception.
    let (_, applied) = d
        .run(
            Operation::CreateGroup(CreateGroup {
                parent: guid(STAFF_OU),
                sam: "g".into(),
                group_type: None,
            }),
            "admin1",
            &[],
        )
        .applied();
    let Reply::Created { guid: g, .. } = applied.reply() else {
        panic!();
    };
    let r = d
        .run(Operation::BeginPasswordSet { target: *g }, "admin1", &[])
        .refused();
    assert_eq!(refusal_code(&r), AdminRefusal::ValueInvalid);
}

/// docs/51 §7.3: `CompletePasswordSet` is audit only — no write, a decision
/// event carrying the reported key versions (Q-340 item 1); a completed set
/// reports one version per key set, so a mismatch is refused.
#[test]
fn complete_password_set_is_audit_only() {
    let mut d = Domain::new("pw-complete");
    let complete = |kvnos: Vec<u32>, outcome| {
        Operation::CompletePasswordSet(CompletePasswordSet {
            target: guid(WS01),
            outcome,
            kvnos,
        })
    };
    let before = d.object(guid(WS01)).unwrap();
    let prepared = d
        .run(
            complete(vec![3, 3], PasswordSetOutcome::Completed),
            "admin1",
            &[],
        )
        .read();
    assert_eq!(prepared.reply(), Some(&Reply::Done));
    assert_eq!(
        prepared.decision_event().stage,
        DirAdminStage::Decision(DecisionResult::Proceed)
    );
    assert_eq!(prepared.decision_event().reported_kvnos.as_slice(), &[3, 3]);
    assert_eq!(d.object(guid(WS01)).unwrap(), before);
    // A failed set reports fewer versions than key sets.
    d.run(complete(vec![4], PasswordSetOutcome::Failed), "admin1", &[])
        .read();
    for (kvnos, outcome) in [
        (vec![3], PasswordSetOutcome::Completed),
        (vec![3, 3], PasswordSetOutcome::Failed),
    ] {
        let r = d.run(complete(kvnos, outcome), "admin1", &[]).refused();
        assert_eq!(refusal_code(&r), AdminRefusal::ValueInvalid);
    }
}
