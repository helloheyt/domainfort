//! Decision A-86 (docs/questions/Q-346): the classification of the
//! operations that change keyd's key state, and `Keyd::admits` — an
//! operation's authorization step run on its own. Sources: docs/10 §2
//! (capability table; role, purpose, then the hold-down), §6, §7, §11,
//! §12 I2, I3, I8; docs/questions/Q-346 (A-86), Q-365; docs/52 §4.2, §4.5
//! (A-102: decisions). All values are constructed for these tests.

mod common;

use common::*;
use keyd::authz::{purpose_permitted, role_permits, HandleSlot};
use keyd::{
    changes_key_state, loosens_authorization, requires_acknowledged_intent, AuditReason, CallerId,
    DecidedOperation, Error, KeyHandle, KeyPurpose, Kvno, Operation, PrincipalId, Role,
};
use zeroize::Zeroizing;

const ROLES: [Role; 4] = [Role::Kdc, Role::Directory, Role::Admin, Role::Ldap];
const PURPOSES: [KeyPurpose; 5] = [
    KeyPurpose::PrincipalLongterm,
    KeyPurpose::Krbtgt,
    KeyPurpose::Service,
    KeyPurpose::AdminService,
    KeyPurpose::ChangePasswordService,
];

/// docs/10 §6, §7; A-86: exactly the six operations that install, rotate,
/// retire or destroy long-term key versions change key state — and the
/// change-password completion, which installs a password through the same
/// install path as `set_secret` (task K3, docs/53 §9) — and the attestation
/// key's install, which installs long-term key material (task PN9; docs/59
/// §7.4; docs/questions/Q-1033 item 3, A-177). The throttles, the replay
/// cache and the token tables are bookkeeping (the Kerberos exchanges,
/// `verify_secret`, the change-password open and error seal), and
/// `describe_config` / `ping` change nothing.
#[test]
fn exactly_the_key_lifecycle_operations_change_key_state() {
    let changing: Vec<Operation> = Operation::ALL
        .into_iter()
        .filter(|op| changes_key_state(*op))
        .collect();
    assert_eq!(
        changing,
        [
            Operation::SetSecret,
            Operation::CreateKey,
            Operation::RotateKey,
            Operation::RotateKrbtgt,
            Operation::RetireKvno,
            Operation::DestroyKeySet,
            Operation::CompleteChangePassword,
            Operation::InstallAttestationKey,
        ]
    );
}

/// Task A15a (docs/questions/Q-452 item 1) and A-102 (docs/52 §4.5):
/// `grant_set_secret` and `register_decision` are the operations that
/// loosen keyd's authorization; neither is a key-state change, but each
/// needs an acknowledged intent like one. The seal and the destroy listing
/// change nothing that loosens keyd.
#[test]
fn the_grant_and_the_decision_loosen_authorization_and_need_an_intent() {
    let loosening: Vec<Operation> = Operation::ALL
        .into_iter()
        .filter(|op| loosens_authorization(*op))
        .collect();
    assert_eq!(
        loosening,
        [Operation::GrantSetSecret, Operation::RegisterDecision]
    );
    assert!(!changes_key_state(Operation::GrantSetSecret));
    assert!(!changes_key_state(Operation::RegisterDecision));
    assert!(!requires_acknowledged_intent(Operation::SealCeremony));
    assert!(!requires_acknowledged_intent(
        Operation::ListDestroyDecisions
    ));
    for op in Operation::ALL {
        assert_eq!(
            requires_acknowledged_intent(op),
            changes_key_state(op)
                || op == Operation::GrantSetSecret
                || op == Operation::RegisterDecision,
            "{op:?}"
        );
    }
}

/// docs/10 §2, §12 I2, I3: `admits` is the role check and the purpose check
/// of the capability tables, for every role × purpose of every key-state
/// operation (none of which is held, docs/10 §11, except the
/// change-password completion — task K3 — which is held and, like
/// `set_secret`, needs a live decision) — and for `set_secret` also a live
/// grant (task A15a), of which none is registered here. The
/// four operations that run a decision by id are never admitted by
/// `admits` (A-102: their daemon asks `decided_intent`).
#[test]
fn admits_is_the_role_and_purpose_check() {
    let f = Fixture::new();
    for op in Operation::ALL
        .into_iter()
        .filter(|op| changes_key_state(*op))
    {
        for role in ROLES {
            for purpose in PURPOSES {
                let handle = KeyHandle::new(PrincipalId::from_bytes([0x44; 16]), purpose);
                let caller = CallerId { uid: 900, role };
                assert_eq!(
                    f.keyd
                        .admits(&caller, op, &[(HandleSlot::Primary, &handle)], &now()),
                    role_permits(role, op)
                        && purpose_permitted(op, HandleSlot::Primary, purpose)
                        && op == Operation::CreateKey,
                    "{op:?} {role:?} {purpose:?}"
                );
            }
        }
    }
}

/// docs/10 §2 ("(c) — only after them — the startup hold-down"), §11: for a
/// held operation `admits` is false inside the hold-down and true after it,
/// exactly when the operation itself would be held.
#[test]
fn admits_includes_the_hold_down() {
    let mut f = Fixture::started(config(), &now());
    let handles = [(HandleSlot::Primary, &ALICE)];
    assert!(!f
        .keyd
        .admits(&KDC, Operation::VerifyPreauth, &handles, &now()));
    assert!(!f
        .keyd
        .admits(&KDC, Operation::VerifyPreauth, &handles, &at(600)));
    assert!(f
        .keyd
        .admits(&KDC, Operation::VerifyPreauth, &handles, &at(601)));
    // A key-state operation is not held (docs/10 §11); set_secret needs its
    // grant (task A15a).
    let set_bob = [(HandleSlot::Primary, &BOB)];
    assert!(!f
        .keyd
        .admits(&DIRECTORY, Operation::SetSecret, &set_bob, &now()));
    f.grant(&BOB, &bob_binding(), BOB_SALT, &now()).unwrap();
    assert!(f.keyd.admits(
        &DIRECTORY,
        Operation::SetSecret,
        &[(HandleSlot::Primary, &BOB)],
        &now()
    ));
}

/// docs/10 §12 I8 ("every operation produces one audit record" — the
/// operation, not the check) and A-86 (the check alone changes nothing):
/// `admits` emits no record and leaves no state — the key set it was asked
/// about is still created at the initial kvno afterwards, and the
/// operation's own record is its only one.
#[test]
fn admits_emits_no_record_and_changes_nothing() {
    let mut f = Fixture::new();
    let carol = KeyHandle::new(
        PrincipalId::from_bytes([0xCA; 16]),
        KeyPurpose::PrincipalLongterm,
    );
    let handles = [(HandleSlot::Primary, &carol)];
    for _ in 0..3 {
        assert!(f
            .keyd
            .admits(&ADMIN, Operation::CreateKey, &handles, &now()));
        assert!(!f.keyd.admits(&KDC, Operation::CreateKey, &handles, &now()));
    }
    assert!(f.records().is_empty());
    assert_eq!(
        f.keyd
            .create_key(&ADMIN, &carol, &bound(alice_name()), &now()),
        Ok(Kvno::INITIAL)
    );
    assert_eq!(f.records().len(), 1);
}

/// docs/10 §2 ("mismatch → Denied, recorded"): when `admits` says no, the
/// operation is refused at its authorization step (reason RoleNotPermitted
/// or PurposeMismatch) and nothing changes; when it says yes, a later step
/// decides (here: the existing key set of `create_key`, KeyExists).
#[test]
fn admits_agrees_with_the_operations_own_refusal() {
    let mut f = Fixture::new();
    // Kdc may not set a secret: admits says no, the operation says why.
    let handles = [(HandleSlot::Primary, &BOB)];
    assert!(!f.keyd.admits(&KDC, Operation::SetSecret, &handles, &now()));
    assert_eq!(
        f.keyd.set_secret(
            &KDC,
            &BOB,
            &bob_binding(),
            Zeroizing::new(String::from("not-applied")),
            BOB_SALT,
            &now()
        ),
        Err(Error::Denied)
    );
    assert_eq!(
        f.records().last().map(|r| r.reason),
        Some(AuditReason::RoleNotPermitted)
    );
    // A krbtgt handle in rotate_key: never admitted, and the decision that
    // would name it is refused at registration (A-102).
    let handles = [(HandleSlot::Primary, &KRBTGT)];
    assert!(!f
        .keyd
        .admits(&ADMIN, Operation::RotateKey, &handles, &now()));
    assert_eq!(
        f.decide(DecidedOperation::RotateKey { handle: KRBTGT }, &now()),
        Err(Error::Denied)
    );
    assert_eq!(
        f.records().last().map(|r| r.reason),
        Some(AuditReason::DecisionInvalid)
    );
    // Admitted, then refused by a later step: the key set exists.
    let handles = [(HandleSlot::Primary, &SERVICE)];
    assert!(f
        .keyd
        .admits(&ADMIN, Operation::CreateKey, &handles, &now()));
    assert_eq!(
        f.keyd
            .create_key(&ADMIN, &SERVICE, &service_binding(), &now()),
        Err(Error::Denied)
    );
    assert_eq!(
        f.records().last().map(|r| r.reason),
        Some(AuditReason::KeyExists)
    );
    // Bob's password was never changed: his next set_secret is kvno 2.
    f.grant(&BOB, &bob_binding(), BOB_SALT, &now()).unwrap();
    assert_eq!(
        f.keyd.set_secret(
            &DIRECTORY,
            &BOB,
            &bob_binding(),
            Zeroizing::new(String::from("Lumen-Stoat-62-Birch")),
            BOB_SALT,
            &now()
        ),
        Ok(Kvno::new(2))
    );
}
