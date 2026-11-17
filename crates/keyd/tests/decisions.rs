//! keyd's decision table and ceremony state (decision A-102; docs/52 R1,
//! R3, R4): no Directory / Admin state change without a decision dird
//! (Role::Ldap) registered; each decision runs once, with exactly its
//! registered parameters, and its result is kept; `create_key` and Admin's
//! grants exist only before `seal_ceremony`; `verify_secret` is in no role.
//!
//! Sources: docs/52 §3.1 (C1, N1), §3.4 (N3), §3.10 (exactly once), §4.2
//! (the decision table), §4.3 (registration points), §4.4 (the ceremony
//! state), §4.5 (audit), §7 R1, R3, R4; docs/questions/Q-460, Q-461, Q-462
//! item 1, Q-465 (A-102); docs/51 §5.6 (dual control), §6, §9; docs/10 §2,
//! §7, §10. All values are constructed by hand for these tests.

mod common;

use common::*;
use keyd::{
    AccountKind, AuditOutcome, AuditReason, CeremonyState, DecidedOperation, DecisionId, Error,
    InMemoryKeyStore, KeyHandle, KeyPurpose, KeyStore, Keyd, Kvno, Operation, PrincipalBinding,
    PrincipalId, SetSecretTarget, StoreError, StoredKeySet, MAX_DESTROY_DECISION_SECS,
    MAX_KEY_DECISION_SECS,
};
use krb_proto::constants::KRB_NT_PRINCIPAL;
use krb_proto::PrincipalName;
use zeroize::Zeroizing;

fn z(s: &str) -> Zeroizing<String> {
    Zeroizing::new(s.to_owned())
}

fn last(f: &Fixture) -> keyd::AuditRecord {
    f.records().last().unwrap().clone()
}

/// A new user (no key set yet): carol.
const CAROL: KeyHandle = KeyHandle::new(
    PrincipalId::from_bytes([0xCA; 16]),
    KeyPurpose::PrincipalLongterm,
);
const CAROL_SALT: &str = "EXAMPLE.ORGcarol";

fn carol_binding() -> PrincipalBinding {
    bound(PrincipalName {
        name_type: KRB_NT_PRINCIPAL,
        name_string: vec![kstr("carol")],
    })
}

fn rotate_krbtgt_decision() -> DecidedOperation {
    DecidedOperation::RotateKrbtgt { krbtgt: KRBTGT }
}

fn rotate_service_decision() -> DecidedOperation {
    DecidedOperation::RotateKey { handle: SERVICE }
}

fn retire_service_decision(kvno: u32) -> DecidedOperation {
    DecidedOperation::RetireKvno {
        handle: SERVICE,
        kvno: Kvno::new(kvno),
    }
}

/// The kvno new TGTs are sealed under (the krbtgt key set's current one).
fn krbtgt_kvno(f: &mut Fixture) -> Option<u32> {
    obtain_tgt(f, now(), &as_template())
        .parts
        .ticket
        .enc_part
        .kvno
}

/// docs/52 §4.2, §7 R1 (A-102): every Admin key operation without a
/// decision is the uniform Denied (`NoDecision`, decided at the
/// authorization step — the record names the presented id), and
/// Directory's `set_secret` without one is `NoGrant`; nothing changes.
#[test]
fn every_mutation_without_a_decision_is_denied() {
    let mut f = Fixture::new();
    let invented = DecisionId::new(0x0BAD_1DEA);
    let results = [
        (
            Operation::RotateKey,
            f.keyd.rotate_key(&ADMIN, invented, &now()).map(|_| ()),
        ),
        (
            Operation::RotateKrbtgt,
            f.keyd.rotate_krbtgt(&ADMIN, invented, &now()).map(|_| ()),
        ),
        (
            Operation::RetireKvno,
            f.keyd.retire_kvno(&ADMIN, invented, &now()),
        ),
        (
            Operation::DestroyKeySet,
            f.keyd.destroy_key_set(&ADMIN, invented, &now()),
        ),
    ];
    let records = f.records();
    let tail = &records[records.len() - 4..];
    for ((op, result), record) in results.iter().zip(tail) {
        assert_eq!(*result, Err(Error::Denied), "{op:?}");
        assert_eq!(record.op, *op);
        assert_eq!(record.result, AuditOutcome::Denied);
        assert_eq!(record.reason, AuditReason::NoDecision, "{op:?}");
        assert_eq!(record.decision, Some(invented));
        assert_eq!(record.kvno, None);
    }
    assert_eq!(
        f.keyd.set_secret(
            &DIRECTORY,
            &ALICE,
            &alice_binding(),
            z("taken over"),
            ALICE_SALT,
            &now()
        ),
        Err(Error::Denied)
    );
    assert_eq!(last(&f).reason, AuditReason::NoGrant);
    // Nothing changed: TGTs are still sealed under kvno 1, alice's password
    // is hers.
    assert_eq!(krbtgt_kvno(&mut f), Some(1));
    assert!(f.password_works(&ALICE, ALICE_PASSWORD, ALICE_SALT));
}

/// docs/52 §4.2, §4.5; docs/51 §5.6: with a decision the operation runs
/// once; keyd builds the dual-control token from the decision's approvers,
/// and the record carries the decision id and those approvers.
#[test]
fn with_a_decision_the_operation_runs_once() {
    let mut f = Fixture::new();
    let id = f.decide(rotate_krbtgt_decision(), &now()).unwrap();
    let registered = last(&f);
    assert_eq!(registered.op, Operation::RegisterDecision);
    assert_eq!(registered.caller_role, LDAP.role);
    assert_eq!(registered.decision, Some(id));
    assert_eq!(registered.approvers, Some([APPROVER_1, APPROVER_2]));
    assert_eq!(registered.principal, Some(KRBTGT_ID));
    assert_eq!(registered.purpose, Some(KeyPurpose::Krbtgt));

    assert_eq!(f.keyd.rotate_krbtgt(&ADMIN, id, &now()), Ok(Kvno::new(2)));
    let ran = last(&f);
    assert_eq!(ran.op, Operation::RotateKrbtgt);
    assert_eq!(ran.result, AuditOutcome::Success);
    assert_eq!(ran.reason, AuditReason::None);
    assert_eq!(ran.decision, Some(id));
    assert_eq!(ran.approvers, Some([APPROVER_1, APPROVER_2]));
    assert_eq!(ran.kvno, Some(Kvno::new(2)));
    assert_eq!(krbtgt_kvno(&mut f), Some(2));
}

/// docs/52 §3.10 (a): presenting an executed decision's id again returns
/// the recorded result — the same kvno — and runs nothing (no second
/// rotation); the record says `DecisionReplayed`. A recorded refusal is
/// returned again too.
#[test]
fn a_replayed_id_returns_the_recorded_result() {
    let mut f = Fixture::new();
    let id = f.decide(rotate_krbtgt_decision(), &now()).unwrap();
    assert_eq!(f.keyd.rotate_krbtgt(&ADMIN, id, &now()), Ok(Kvno::new(2)));
    for _ in 0..2 {
        assert_eq!(f.keyd.rotate_krbtgt(&ADMIN, id, &now()), Ok(Kvno::new(2)));
        let replay = last(&f);
        assert_eq!(replay.reason, AuditReason::DecisionReplayed);
        assert_eq!(replay.result, AuditOutcome::Success);
        assert_eq!(replay.kvno, Some(Kvno::new(2)));
        assert_eq!(replay.decision, Some(id));
    }
    // Not rotated again: still kvno 2.
    assert_eq!(krbtgt_kvno(&mut f), Some(2));

    // A refused execution (kvno 7 is not retained) is recorded too.
    let retire = f.decide(retire_service_decision(7), &now()).unwrap();
    assert_eq!(
        f.keyd.retire_kvno(&ADMIN, retire, &now()),
        Err(Error::Denied)
    );
    assert_eq!(last(&f).reason, AuditReason::KvnoNotRetirable);
    assert_eq!(
        f.keyd.retire_kvno(&ADMIN, retire, &now()),
        Err(Error::Denied)
    );
    let replay = last(&f);
    assert_eq!(replay.reason, AuditReason::DecisionReplayed);
    assert_eq!(replay.result, AuditOutcome::Denied);
}

/// docs/52 §4.2 ("keyd … requires that the call's kind match, runs the
/// registered parameters, not the caller's"): an id presented by an
/// operation of another kind is refused (`DecisionMismatch`) and the
/// decision is not consumed — the right operation then runs it; an id of
/// another family is no decision at all.
#[test]
fn the_wrong_kind_is_refused_and_not_consumed() {
    let mut f = Fixture::new();
    let rotation = f.decide(rotate_service_decision(), &now()).unwrap();
    assert_eq!(
        f.keyd.rotate_key(&ADMIN, rotation, &now()),
        Ok(Kvno::new(2))
    );
    let retire = f.decide(retire_service_decision(1), &now()).unwrap();
    assert_eq!(
        f.keyd.rotate_key(&ADMIN, retire, &now()),
        Err(Error::Denied)
    );
    assert_eq!(last(&f).reason, AuditReason::DecisionMismatch);
    assert_eq!(
        f.keyd.rotate_krbtgt(&ADMIN, retire, &now()),
        Err(Error::Denied)
    );
    assert_eq!(last(&f).reason, AuditReason::DecisionMismatch);
    // The destroy family has its own ids: a key-operation id is unknown
    // there.
    assert_eq!(
        f.keyd.destroy_key_set(&ADMIN, retire, &now()),
        Err(Error::Denied)
    );
    assert_eq!(last(&f).reason, AuditReason::NoDecision);
    // Still pending: the right operation runs exactly the decided kvno.
    assert_eq!(f.keyd.retire_kvno(&ADMIN, retire, &now()), Ok(()));
    let ran = last(&f);
    assert_eq!(ran.kvno, Some(Kvno::new(1)));
    assert_eq!(ran.principal, Some(SERVICE_ID));
    // And a destroy id is unknown to the key operations.
    let destroy = f
        .decide(
            DecidedOperation::DestroyKeySet { principal: BOB_ID },
            &now(),
        )
        .unwrap();
    assert_eq!(
        f.keyd.rotate_key(&ADMIN, destroy, &now()),
        Err(Error::Denied)
    );
    assert_eq!(last(&f).reason, AuditReason::NoDecision);
}

/// docs/52 §2 row 37 (N4), §4.2: a set-secret decision binds the binding
/// and the salt; another of either is refused (`GrantMismatch`).
#[test]
fn set_secret_with_other_parameters_than_decided_is_refused() {
    let mut f = Fixture::new();
    let mut renamed = carol_binding();
    renamed.name.name_string = vec![kstr("caroline")];
    for (binding, salt) in [
        (renamed, CAROL_SALT),
        (carol_binding(), "EXAMPLE.ORGcaroline"),
    ] {
        f.grant(&CAROL, &carol_binding(), CAROL_SALT, &now())
            .unwrap();
        assert_eq!(
            f.keyd
                .set_secret(&DIRECTORY, &CAROL, &binding, z("pw"), salt, &now()),
            Err(Error::Denied)
        );
        assert_eq!(last(&f).reason, AuditReason::GrantMismatch);
    }
}

/// docs/52 §4.2 ("bounded, single-use, purged on expiry"): a decision lives
/// its lifetime by keyd's clock — refused one second after (`NoDecision`);
/// an executed decision's recorded result is forgotten after expiry too.
#[test]
fn an_expired_decision_is_refused() {
    let mut f = Fixture::new();
    let id = next_decision_id();
    f.keyd
        .register_decision(
            &LDAP,
            id,
            &rotate_service_decision(),
            &[APPROVER_1, APPROVER_2],
            10,
            &now(),
        )
        .unwrap();
    assert_eq!(f.keyd.rotate_key(&ADMIN, id, &at(11)), Err(Error::Denied));
    assert_eq!(last(&f).reason, AuditReason::NoDecision);

    let id = next_decision_id();
    f.keyd
        .register_decision(
            &LDAP,
            id,
            &rotate_service_decision(),
            &[APPROVER_1, APPROVER_2],
            10,
            &now(),
        )
        .unwrap();
    assert_eq!(f.keyd.rotate_key(&ADMIN, id, &at(10)), Ok(Kvno::new(2)));
    assert_eq!(f.keyd.rotate_key(&ADMIN, id, &at(10)), Ok(Kvno::new(2)));
    assert_eq!(last(&f).reason, AuditReason::DecisionReplayed);
    assert_eq!(f.keyd.rotate_key(&ADMIN, id, &at(11)), Err(Error::Denied));
    assert_eq!(last(&f).reason, AuditReason::NoDecision);
}

/// docs/10 §2 (I2); docs/52 §4.2, §7 R1 (A-102): only Role::Ldap (dird)
/// registers a decision; Kdc, Directory and Admin are refused at the
/// capability table, and nothing is registered.
#[test]
fn only_dird_registers_a_decision() {
    let mut f = Fixture::new();
    for caller in [KDC, DIRECTORY, ADMIN] {
        let id = next_decision_id();
        assert_eq!(
            f.keyd.register_decision(
                &caller,
                id,
                &rotate_krbtgt_decision(),
                &[APPROVER_1, APPROVER_2],
                MAX_KEY_DECISION_SECS,
                &now()
            ),
            Err(Error::Denied)
        );
        let record = last(&f);
        assert_eq!(record.op, Operation::RegisterDecision);
        assert_eq!(record.caller_role, caller.role);
        assert_eq!(record.reason, AuditReason::RoleNotPermitted);
        assert_eq!(f.keyd.rotate_krbtgt(&ADMIN, id, &now()), Err(Error::Denied));
        assert_eq!(last(&f).reason, AuditReason::NoDecision);
    }
}

/// docs/52 §4.2; docs/10 §2 (I3); docs/51 §5.6; Q-420 item 4: what
/// `register_decision` refuses (`DecisionInvalid`) — a kvno 0, a purpose
/// the executing operation does not accept, a lifetime of zero or above the
/// family's ceiling, approvers too few, too many or not distinct — and the
/// id rules: the same decision again is accepted unchanged, a different one
/// under the same id is `DecisionConflict`.
#[test]
fn register_decision_validates_and_ids_are_stable() {
    let mut f = Fixture::new();
    let a = APPROVER_1;
    let b = APPROVER_2;
    let c = PrincipalId::from_bytes([0xCC; 16]);
    let d = PrincipalId::from_bytes([0xDD; 16]);
    let destroy = DecidedOperation::DestroyKeySet { principal: BOB_ID };
    let cases: Vec<(DecidedOperation, Vec<PrincipalId>, u32)> = vec![
        (retire_service_decision(0), vec![a, b], 60),
        (
            DecidedOperation::RotateKey { handle: KRBTGT },
            vec![a, b],
            60,
        ),
        (
            DecidedOperation::RotateKrbtgt { krbtgt: SERVICE },
            vec![a, b],
            60,
        ),
        (rotate_service_decision(), vec![a, b], 0),
        (
            rotate_service_decision(),
            vec![a, b],
            MAX_KEY_DECISION_SECS + 1,
        ),
        (destroy.clone(), vec![], MAX_DESTROY_DECISION_SECS + 1),
        (rotate_service_decision(), vec![a], 60),
        (rotate_service_decision(), vec![a, a], 60),
        (rotate_service_decision(), vec![a, b, c, d], 60),
        (destroy.clone(), vec![c, c], 60),
    ];
    for (operation, approvers, lifetime) in cases {
        assert_eq!(
            f.keyd.register_decision(
                &LDAP,
                next_decision_id(),
                &operation,
                &approvers,
                lifetime,
                &now()
            ),
            Err(Error::Denied),
            "{operation:?} {approvers:?} {lifetime}"
        );
        assert_eq!(
            last(&f).reason,
            AuditReason::DecisionInvalid,
            "{operation:?} {approvers:?} {lifetime}"
        );
    }
    // Three distinct approvers and a destroy decision at its ceiling are
    // fine.
    assert!(f
        .keyd
        .register_decision(
            &LDAP,
            next_decision_id(),
            &rotate_service_decision(),
            &[a, b, c],
            60,
            &now()
        )
        .is_ok());
    assert!(f
        .keyd
        .register_decision(
            &LDAP,
            next_decision_id(),
            &destroy,
            &[],
            MAX_DESTROY_DECISION_SECS,
            &now()
        )
        .is_ok());
    // The same id: the same decision is accepted unchanged (a harmless
    // re-registration after an unknown outcome), another is a conflict.
    let id = next_decision_id();
    let register = |f: &mut Fixture, operation: &DecidedOperation| {
        f.keyd
            .register_decision(&LDAP, id, operation, &[a, b], 60, &now())
    };
    assert_eq!(register(&mut f, &rotate_service_decision()), Ok(()));
    assert_eq!(register(&mut f, &rotate_service_decision()), Ok(()));
    assert_eq!(
        register(&mut f, &retire_service_decision(1)),
        Err(Error::Denied)
    );
    assert_eq!(last(&f).reason, AuditReason::DecisionConflict);
    // It still holds the first decision, once.
    assert_eq!(f.keyd.rotate_key(&ADMIN, id, &now()), Ok(Kvno::new(2)));
    assert_eq!(register(&mut f, &rotate_service_decision()), Ok(()));
    assert_eq!(f.keyd.rotate_key(&ADMIN, id, &now()), Ok(Kvno::new(2)));
    assert_eq!(last(&f).reason, AuditReason::DecisionReplayed);
}

/// docs/52 §4.4, §7 R3; Q-462 item 1 (A-102): a keyd started with an empty
/// store is in its ceremony — `create_key` and Admin's grants work; only
/// Admin may seal; after `seal_ceremony` both are refused
/// (`CeremonySealed`) while a grant registered before the seal still
/// redeems; sealing again changes nothing.
#[test]
fn the_seal_ends_the_ceremony() {
    let mut f = Fixture::new();
    assert_eq!(f.keyd.ceremony_state(), CeremonyState::Provisioning);
    let new_service = KeyHandle::new(PrincipalId::from_bytes([0x5A; 16]), KeyPurpose::Service);
    let new_service_binding = bound(PrincipalName {
        name_type: KRB_NT_PRINCIPAL,
        name_string: vec![kstr("svc-5a")],
    });
    assert_eq!(
        f.keyd
            .create_key(&ADMIN, &new_service, &new_service_binding, &now()),
        Ok(Kvno::INITIAL)
    );
    assert_eq!(
        f.grant_as(&ADMIN, &CAROL, &carol_binding(), CAROL_SALT, &now()),
        Ok(())
    );
    for caller in [KDC, DIRECTORY, LDAP] {
        assert_eq!(f.keyd.seal_ceremony(&caller, &now()), Err(Error::Denied));
        assert_eq!(last(&f).reason, AuditReason::RoleNotPermitted);
        assert_eq!(f.keyd.ceremony_state(), CeremonyState::Provisioning);
    }
    assert_eq!(f.keyd.seal_ceremony(&ADMIN, &now()), Ok(()));
    let sealed = last(&f);
    assert_eq!(sealed.op, Operation::SealCeremony);
    assert_eq!(sealed.result, AuditOutcome::Success);
    assert_eq!(f.keyd.ceremony_state(), CeremonyState::Operational);

    let another = KeyHandle::new(PrincipalId::from_bytes([0x5B; 16]), KeyPurpose::Service);
    assert_eq!(
        f.keyd
            .create_key(&ADMIN, &another, &new_service_binding, &now()),
        Err(Error::Denied)
    );
    assert_eq!(last(&f).reason, AuditReason::CeremonySealed);
    let dave = KeyHandle::new(
        PrincipalId::from_bytes([0xDA; 16]),
        KeyPurpose::PrincipalLongterm,
    );
    assert_eq!(
        f.grant_as(&ADMIN, &dave, &carol_binding(), "EXAMPLE.ORGdave", &now()),
        Err(Error::Denied)
    );
    assert_eq!(last(&f).reason, AuditReason::CeremonySealed);
    // The grant made before the seal still redeems (docs/51 §4.3 step 12
    // follows the ceremony).
    assert_eq!(
        f.keyd.set_secret(
            &DIRECTORY,
            &CAROL,
            &carol_binding(),
            z("Sienna-Walrus-83-Kelp"),
            CAROL_SALT,
            &now()
        ),
        Ok(Kvno::INITIAL)
    );
    // Sealing a sealed keyd: harmless.
    assert_eq!(f.keyd.seal_ceremony(&ADMIN, &now()), Ok(()));
    assert_eq!(f.keyd.ceremony_state(), CeremonyState::Operational);
    // Decisions still work after the seal.
    let rotation = f.decide(rotate_service_decision(), &now()).unwrap();
    assert_eq!(
        f.keyd.rotate_key(&ADMIN, rotation, &now()),
        Ok(Kvno::new(2))
    );
}

/// A store that already holds keys when keyd starts (what a persistent
/// store does — P-17): it delegates to an in-memory store but reports
/// itself non-empty. Test double for docs/52 §4.4.
struct HeldKeys(InMemoryKeyStore);

impl KeyStore for HeldKeys {
    fn accepts(&self, purpose: KeyPurpose) -> bool {
        self.0.accepts(purpose)
    }
    fn is_empty(&self) -> bool {
        false
    }
    fn attestation_key(&self) -> Option<&keyd::AttestationKey> {
        self.0.attestation_key()
    }
    fn install_attestation_key(&mut self, key: keyd::AttestationKey) -> Result<(), StoreError> {
        self.0.install_attestation_key(key)
    }
    fn get(&self, handle: &KeyHandle) -> Option<&StoredKeySet> {
        self.0.get(handle)
    }
    fn get_mut(&mut self, handle: &KeyHandle) -> Option<&mut StoredKeySet> {
        self.0.get_mut(handle)
    }
    fn insert(&mut self, handle: KeyHandle, set: StoredKeySet) -> Result<(), StoreError> {
        self.0.insert(handle, set)
    }
    fn destroy(&mut self, handle: &KeyHandle) -> Result<(), StoreError> {
        self.0.destroy(handle)
    }
}

/// docs/52 §4.4 ("keyd comes up in `Provisioning` only when the store is
/// empty"): a keyd whose store holds keys at start is operational — no
/// ceremony operation exists — while an empty store starts the ceremony.
#[test]
fn a_store_with_keys_starts_operational() {
    let mut keyd = Keyd::with_entropy(
        config(),
        HeldKeys(InMemoryKeyStore::new_insecure_development_allowing_krbtgt(
            8,
        )),
        CollectingAudit::default(),
        TestEntropy::default(),
        &keyd_started(),
    )
    .unwrap();
    assert_eq!(keyd.ceremony_state(), CeremonyState::Operational);
    assert_eq!(
        keyd.create_key(&ADMIN, &SERVICE, &service_binding(), &now()),
        Err(Error::Denied)
    );
    assert_eq!(
        keyd.audit_sink().records.last().unwrap().reason,
        AuditReason::CeremonySealed
    );
    let empty = Keyd::with_entropy(
        config(),
        InMemoryKeyStore::new(8),
        CollectingAudit::default(),
        TestEntropy::default(),
        &keyd_started(),
    )
    .unwrap();
    assert_eq!(empty.ceremony_state(), CeremonyState::Provisioning);
}

/// docs/52 §4.3, §4.6; docs/51 §6, §9: Admin lists the pending destroy
/// decisions dird registered (id and principal), ascending, without the
/// executed ones; since task R6 (A-105, docs/questions/Q-503) dird (Ldap)
/// reads the same listing back, to re-register only what keyd lost; no
/// other role may list.
#[test]
fn the_destroy_listing_shows_pending_decisions_only() {
    let mut f = Fixture::new();
    let first = f
        .decide(
            DecidedOperation::DestroyKeySet { principal: BOB_ID },
            &now(),
        )
        .unwrap();
    // (R6b: a destroy decision needs a principal with a key set — alice's.)
    let second = f
        .decide(
            DecidedOperation::DestroyKeySet {
                principal: ALICE_ID,
            },
            &now(),
        )
        .unwrap();
    // A key-operation decision is not a destruction.
    f.decide(rotate_service_decision(), &now()).unwrap();
    let page = f.keyd.list_destroy_decisions(&ADMIN, None, &now()).unwrap();
    let listed: Vec<(DecisionId, PrincipalId)> = page
        .entries
        .iter()
        .map(|p| (p.decision, p.principal))
        .collect();
    assert_eq!(listed, [(first, BOB_ID), (second, ALICE_ID)]);
    assert_eq!(page.next, None);
    // Strictly after the first.
    let after = f
        .keyd
        .list_destroy_decisions(&ADMIN, Some(first), &now())
        .unwrap();
    assert_eq!(after.entries.len(), 1);
    assert_eq!(after.entries[0].decision, second);
    // An executed decision is no longer listed.
    f.keyd.destroy_key_set(&ADMIN, first, &now()).unwrap();
    let page = f.keyd.list_destroy_decisions(&ADMIN, None, &now()).unwrap();
    assert_eq!(page.entries.len(), 1);
    assert_eq!(page.entries[0].decision, second);
    assert_eq!(f.keyd.list_destroy_decisions(&LDAP, None, &now()), Ok(page));
    for caller in [KDC, DIRECTORY] {
        assert_eq!(
            f.keyd.list_destroy_decisions(&caller, None, &now()),
            Err(Error::Denied)
        );
        assert_eq!(last(&f).reason, AuditReason::RoleNotPermitted);
    }
}

/// docs/52 §4.2 (`DestroyKeySet { principal }` — both purposes); docs/51
/// §9; A-35: a destroy decision removes the principal's PrincipalLongterm
/// and Service key sets; a later set-secret decision recreates each from
/// kvno 1.
#[test]
fn a_destroy_decision_removes_both_key_sets() {
    let mut f = Fixture::new();
    let id = PrincipalId::from_bytes([0xC9; 16]);
    let account = KeyHandle::new(id, KeyPurpose::PrincipalLongterm);
    let service = KeyHandle::new(id, KeyPurpose::Service);
    let salt = "EXAMPLE.ORGhostws09.example.org";
    let account_binding = bound(PrincipalName {
        name_type: KRB_NT_PRINCIPAL,
        name_string: vec![kstr("ws09$")],
    });
    let service_binding = bound(PrincipalName {
        name_type: krb_proto::constants::KRB_NT_SRV_HST,
        name_string: vec![kstr("host"), kstr("ws09.example.org")],
    });
    let decision = DecidedOperation::SetSecret {
        kind: AccountKind::Computer,
        targets: vec![
            SetSecretTarget {
                handle: account,
                binding: account_binding.clone(),
                salt: salt.to_owned(),
            },
            SetSecretTarget {
                handle: service,
                binding: service_binding.clone(),
                salt: salt.to_owned(),
            },
        ],
    };
    for round in 0..2 {
        f.decide(decision.clone(), &now()).unwrap();
        for (handle, binding) in [
            (account, account_binding.clone()),
            (service, service_binding.clone()),
        ] {
            assert_eq!(
                f.keyd.set_secret(
                    &DIRECTORY,
                    &handle,
                    &binding,
                    z("Puffin-Sorrel-81-Tulip"),
                    salt,
                    &now()
                ),
                Ok(Kvno::INITIAL),
                "round {round}"
            );
        }
        let destroy = f
            .decide(DecidedOperation::DestroyKeySet { principal: id }, &now())
            .unwrap();
        assert_eq!(f.keyd.destroy_key_set(&ADMIN, destroy, &now()), Ok(()));
        let record = last(&f);
        assert_eq!(record.kvno, Some(Kvno::INITIAL));
        assert_eq!(record.secondary.unwrap().kvno, Some(Kvno::INITIAL));
    }
}

/// Attack test (R6b; docs/questions/Q-501 decision, Q-520): a destroy
/// decision cannot be registered for a principal that has no key set a
/// destruction would remove — an unknown principal, the krbtgt principal
/// (only a Krbtgt key set) — however dird (Role::Ldap) asks: the uniform
/// `Denied`, reason `KeyNotFound`, one record, and **no table slot**: the
/// listing stays empty, the id names no decision (an execution is
/// `NoDecision`), and the same id is free for a decision on a principal
/// with a key set (no `DecisionConflict`).
#[test]
fn a_destroy_decision_cannot_be_registered_without_a_key_set() {
    let mut f = Fixture::new();
    let id = DecisionId::new(0x0BAD_0001);
    for principal in [PrincipalId::from_bytes([0xEE; 16]), KRBTGT_ID] {
        let refused = DecidedOperation::DestroyKeySet { principal };
        let before = f.records().len();
        assert_eq!(
            f.keyd
                .register_decision(&LDAP, id, &refused, &[], MAX_DESTROY_DECISION_SECS, &now()),
            Err(Error::Denied)
        );
        assert_eq!(f.records().len(), before + 1);
        let record = last(&f);
        assert_eq!(record.op, Operation::RegisterDecision);
        assert_eq!(record.result, AuditOutcome::Denied);
        assert_eq!(record.reason, AuditReason::KeyNotFound);
        assert_eq!(record.principal, Some(principal));
        assert_eq!(record.decision, Some(id));
    }
    assert!(f
        .keyd
        .list_destroy_decisions(&ADMIN, None, &now())
        .unwrap()
        .entries
        .is_empty());
    assert_eq!(
        f.keyd.destroy_key_set(&ADMIN, id, &now()),
        Err(Error::Denied)
    );
    assert_eq!(last(&f).reason, AuditReason::NoDecision);
    // The refusals took no slot: the id registers a decision for bob.
    let bob = DecidedOperation::DestroyKeySet { principal: BOB_ID };
    assert_eq!(
        f.keyd
            .register_decision(&LDAP, id, &bob, &[], MAX_DESTROY_DECISION_SECS, &now()),
        Ok(())
    );
}

/// Attack test (R6b follow-up; docs/questions/Q-520): a password set begun
/// before the `Delete` must not create a key set for the deleted principal.
/// carol has no key set; dird registers her `SetSecret` decision (its
/// `BeginPasswordSet`), then — her `Delete` committed — her destroy
/// decision. The registration is refused (no key set: `KeyNotFound`) **and**
/// discards her live set-secret decision, with one `SecretDecisionDiscarded`
/// record after the registration's own; admind's `set_secret` with exactly
/// the decided binding and salt is then refused (`NoGrant`) and creates no key
/// set — the "complete" dird read is true. The same for a computer's two
/// handles (two discard records), for the ceremony's grant (no decision id),
/// and for an accepted registration (alice has a key set and a password
/// change in flight: accepted, the change discarded, the old password still
/// works until the destruction runs).
#[test]
fn a_destroy_registration_discards_the_principals_set_secret_decisions() {
    let mut f = Fixture::new();
    let destroy = |f: &mut Fixture, principal: PrincipalId| {
        f.keyd.register_decision(
            &LDAP,
            next_decision_id(),
            &DecidedOperation::DestroyKeySet { principal },
            &[],
            MAX_DESTROY_DECISION_SECS,
            &now(),
        )
    };
    let discards = |f: &Fixture, since: usize| -> Vec<(KeyHandle, Option<DecisionId>)> {
        f.records()[since..]
            .iter()
            .filter(|r| r.reason == AuditReason::SecretDecisionDiscarded)
            .map(|r| {
                assert_eq!(r.op, Operation::RegisterDecision);
                assert_eq!(r.result, AuditOutcome::Success);
                (
                    KeyHandle::new(r.principal.unwrap(), r.purpose.unwrap()),
                    r.decision,
                )
            })
            .collect()
    };

    // carol: the decision of her BeginPasswordSet, then her destroy decision.
    let carol_decision = f
        .decide(
            DecidedOperation::SetSecret {
                kind: AccountKind::User,
                targets: vec![SetSecretTarget {
                    handle: CAROL,
                    binding: carol_binding(),
                    salt: CAROL_SALT.to_owned(),
                }],
            },
            &now(),
        )
        .unwrap();
    let before = f.records().len();
    assert_eq!(destroy(&mut f, CAROL.principal), Err(Error::Denied));
    // The registration's own record first, then the discard.
    assert_eq!(f.records().len(), before + 2);
    assert_eq!(f.records()[before].reason, AuditReason::KeyNotFound);
    assert_eq!(discards(&f, before), [(CAROL, Some(carol_decision))]);
    // admind's set_secret with exactly what dird decided: no decision left.
    assert_eq!(
        f.keyd.set_secret(
            &DIRECTORY,
            &CAROL,
            &carol_binding(),
            z("Sienna-Walrus-83-Kelp"),
            CAROL_SALT,
            &now()
        ),
        Err(Error::Denied)
    );
    assert_eq!(last(&f).reason, AuditReason::NoGrant);
    // No key set came to exist: still nothing to destroy, nothing to log in
    // with.
    assert_eq!(destroy(&mut f, CAROL.principal), Err(Error::Denied));
    assert_eq!(
        f.records()[f.records().len() - 1].reason,
        AuditReason::KeyNotFound
    );
    assert!(!f.password_works(&CAROL, "Sienna-Walrus-83-Kelp", CAROL_SALT));

    // A computer: both handles' entries go, two records (PrincipalLongterm,
    // then Service).
    let ws = PrincipalId::from_bytes([0xC8; 16]);
    let service = KeyHandle::new(ws, KeyPurpose::Service);
    f.grant(&service, &service_binding(), "EXAMPLE.ORGhostws", &now())
        .unwrap();
    let before = f.records().len();
    assert_eq!(destroy(&mut f, ws), Err(Error::Denied));
    let found = discards(&f, before);
    assert_eq!(found.len(), 2);
    assert_eq!(
        found[0].0,
        KeyHandle::new(ws, KeyPurpose::PrincipalLongterm)
    );
    assert_eq!(found[1].0, service);

    // The ceremony's grant (Role::Admin, before the seal): discarded too,
    // its record without a decision id.
    let dave = KeyHandle::new(
        PrincipalId::from_bytes([0xDA; 16]),
        KeyPurpose::PrincipalLongterm,
    );
    f.grant_as(&ADMIN, &dave, &carol_binding(), CAROL_SALT, &now())
        .unwrap();
    let before = f.records().len();
    assert_eq!(destroy(&mut f, dave.principal), Err(Error::Denied));
    assert_eq!(discards(&f, before), [(dave, None)]);

    // Accepted: alice has a key set and a password change in flight.
    grant(&mut f.keyd, &ALICE, &alice_binding(), ALICE_SALT, &now()).unwrap();
    let before = f.records().len();
    assert_eq!(destroy(&mut f, ALICE_ID), Ok(()));
    assert_eq!(f.records()[before].result, AuditOutcome::Success);
    assert_eq!(f.records()[before].reason, AuditReason::None);
    assert_eq!(discards(&f, before).len(), 1);
    assert_eq!(
        f.keyd.set_secret(
            &DIRECTORY,
            &ALICE,
            &alice_binding(),
            z("Gecko-Iris-38-Kiwi"),
            ALICE_SALT,
            &now()
        ),
        Err(Error::Denied)
    );
    assert_eq!(last(&f).reason, AuditReason::NoGrant);
    assert!(f.password_works(&ALICE, ALICE_PASSWORD, ALICE_SALT));
}

/// R6b, the order of the two checks (docs/questions/Q-471 item 5, Q-501,
/// Q-520): while the principal has a key set, the identical registration
/// is accepted unchanged (a retry after an unknown outcome); once its
/// decision ran and destroyed the key sets, the identical registration is
/// **refused** (`KeyNotFound`) although keyd still holds the executed
/// decision — the key store, not the table, says "destroyed" — and the
/// executed decision's recorded result is still returned to keyadm.
#[test]
fn a_destroy_registration_reads_the_key_store_before_the_table() {
    let mut f = Fixture::new();
    let id = DecisionId::new(0x0BAD_0002);
    let destroy = DecidedOperation::DestroyKeySet { principal: BOB_ID };
    let register = |f: &mut Fixture| {
        f.keyd
            .register_decision(&LDAP, id, &destroy, &[], MAX_DESTROY_DECISION_SECS, &now())
    };
    assert_eq!(register(&mut f), Ok(()));
    // The identical retry: accepted unchanged, one pending decision.
    assert_eq!(register(&mut f), Ok(()));
    let page = f.keyd.list_destroy_decisions(&ADMIN, None, &now()).unwrap();
    assert_eq!(page.entries.len(), 1);
    assert_eq!(f.keyd.destroy_key_set(&ADMIN, id, &now()), Ok(()));
    // Executed: bob has no key set left — the identical registration is
    // refused, nothing becomes pending.
    assert_eq!(register(&mut f), Err(Error::Denied));
    assert_eq!(last(&f).reason, AuditReason::KeyNotFound);
    assert!(f
        .keyd
        .list_destroy_decisions(&ADMIN, None, &now())
        .unwrap()
        .entries
        .is_empty());
    // keyadm presenting the id again still gets the recorded result.
    assert_eq!(f.keyd.destroy_key_set(&ADMIN, id, &now()), Ok(()));
    assert_eq!(last(&f).reason, AuditReason::DecisionReplayed);
}

/// docs/52 §3.4 (N3), §7 R4; Q-465 (A-102): `verify_secret` from Directory
/// is refused at the capability table (RoleNotPermitted) — the right
/// password included.
#[test]
fn verify_secret_from_directory_is_refused_at_the_capability_table() {
    let mut f = Fixture::new();
    assert_eq!(
        f.keyd
            .verify_secret(&DIRECTORY, &ALICE, z(ALICE_PASSWORD), &now()),
        Err(Error::Denied)
    );
    let record = last(&f);
    assert_eq!(record.op, Operation::VerifySecret);
    assert_eq!(record.reason, AuditReason::RoleNotPermitted);
}

/// The N1 attack (docs/52 §3.1 N1; Q-461; A-102): a holder of the keyadm
/// uid (Role::Admin) and the admind uid (Role::Directory) tries to take
/// over a live account — destroy its key set, grant an "initial" secret,
/// set it. On a sealed keyd every step is refused (no dird decision; no
/// ceremony grant after the seal; no set-secret decision), and the
/// account's key set is unchanged. Before the seal the same chain fails at
/// its first two steps too (no decision; the key set exists).
#[test]
fn the_n1_takeover_is_refused_at_every_step() {
    for sealed in [true, false] {
        let mut f = Fixture::new();
        if sealed {
            f.keyd.seal_ceremony(&ADMIN, &now()).unwrap();
        }
        // (1) keyadm: destroy alice's key sets with an id it invented.
        assert_eq!(
            f.keyd
                .destroy_key_set(&ADMIN, DecisionId::new(0xA77AC4), &now()),
            Err(Error::Denied)
        );
        assert_eq!(last(&f).reason, AuditReason::NoDecision);
        // (2) keyadm: grant itself an "initial" secret for alice.
        assert_eq!(
            f.grant_as(&ADMIN, &ALICE, &alice_binding(), ALICE_SALT, &now()),
            Err(Error::Denied)
        );
        let expected = if sealed {
            AuditReason::CeremonySealed
        } else {
            AuditReason::KeyExists
        };
        assert_eq!(last(&f).reason, expected);
        // (3) admind: set alice's password.
        assert_eq!(
            f.keyd.set_secret(
                &DIRECTORY,
                &ALICE,
                &alice_binding(),
                z("Yarrow-Bramble-72-Pollen"),
                ALICE_SALT,
                &now()
            ),
            Err(Error::Denied)
        );
        assert_eq!(last(&f).reason, AuditReason::NoGrant);
        // alice's key set is untouched: her password works, the attacker's
        // does not, and her next decided password set is kvno 2.
        assert!(f.password_works(&ALICE, ALICE_PASSWORD, ALICE_SALT));
        assert!(!f.password_works(&ALICE, "Yarrow-Bramble-72-Pollen", ALICE_SALT));
        f.grant(&ALICE, &alice_binding(), ALICE_SALT, &now())
            .unwrap();
        assert_eq!(
            f.keyd.set_secret(
                &DIRECTORY,
                &ALICE,
                &alice_binding(),
                z("Walnut-Raven-15-Cedar"),
                ALICE_SALT,
                &now()
            ),
            Ok(Kvno::new(2))
        );
    }
}

/// docs/52 §4.5; Q-346 (A-86): `decided_intent` gives the daemon the
/// registered parameters of a pending decision the caller may run — and
/// nothing for an unknown id, another kind, another role, or a decision
/// that already ran. It emits no record.
#[test]
fn decided_intent_only_for_a_pending_matching_decision() {
    let mut f = Fixture::new();
    let rotation = f.decide(rotate_service_decision(), &now()).unwrap();
    f.keyd.rotate_key(&ADMIN, rotation, &now()).unwrap();
    let retire = f.decide(retire_service_decision(1), &now()).unwrap();
    let before = f.records().len();
    let intent = f
        .keyd
        .decided_intent(&ADMIN, Operation::RetireKvno, retire, &now())
        .unwrap();
    assert_eq!(intent.decision, retire);
    assert_eq!(intent.primary, Some(SERVICE));
    assert_eq!(intent.secondary, None);
    assert_eq!(intent.kvno, Some(Kvno::new(1)));
    assert_eq!(intent.approvers, Some([APPROVER_1, APPROVER_2]));
    assert_eq!(
        f.keyd.decided_intent(
            &ADMIN,
            Operation::RetireKvno,
            DecisionId::new(0xFFFF),
            &now()
        ),
        None
    );
    assert_eq!(
        f.keyd
            .decided_intent(&ADMIN, Operation::RotateKey, retire, &now()),
        None
    );
    assert_eq!(
        f.keyd
            .decided_intent(&DIRECTORY, Operation::RetireKvno, retire, &now()),
        None
    );
    assert_eq!(
        f.keyd
            .decided_intent(&ADMIN, Operation::RotateKey, rotation, &now()),
        None,
        "already executed"
    );
    assert_eq!(f.records().len(), before, "no record");
    // A destroy decision's intent names both key sets.
    let destroy = f
        .decide(
            DecidedOperation::DestroyKeySet { principal: BOB_ID },
            &now(),
        )
        .unwrap();
    let intent = f
        .keyd
        .decided_intent(&ADMIN, Operation::DestroyKeySet, destroy, &now())
        .unwrap();
    assert_eq!(
        intent.primary,
        Some(KeyHandle::new(BOB_ID, KeyPurpose::PrincipalLongterm))
    );
    assert_eq!(
        intent.secondary,
        Some(KeyHandle::new(BOB_ID, KeyPurpose::Service))
    );
    assert_eq!(intent.approvers, None);
}

// ---------------------------------------------------------------------------
// Task F3: revoking a key-operation decision (docs/questions/Q-937 item 6,
// the residual of A-159; Q-976). Sources: docs/52 §3.1 (C1), §3.10, §3.14
// (C14), §4.2, §4.5; docs/10 §2, §6a, §10. Values made up for these tests.
// ---------------------------------------------------------------------------

/// Q-976: dird (Role::Ldap) revokes a pending key decision; from then on it
/// is never consumed — keyadm's execution is refused (`DecisionRevoked`, at
/// the authorization step: one record, no intent), the same decision cannot
/// be registered again under its id, a second revocation is `Ok`, and the
/// key set was never rotated (the next decided rotation yields kvno 2).
#[test]
fn a_revoked_decision_is_never_consumed() {
    let mut f = Fixture::new();
    let id = f.decide(rotate_service_decision(), &now()).unwrap();
    assert_eq!(f.keyd.revoke_decision(&LDAP, id, &now()), Ok(()));
    let revoked = last(&f);
    assert_eq!(revoked.op, Operation::RevokeDecision);
    assert_eq!(revoked.caller_role, LDAP.role);
    assert_eq!(revoked.result, AuditOutcome::Success);
    assert_eq!(revoked.decision, Some(id));
    assert_eq!(revoked.principal, Some(SERVICE_ID));
    assert_eq!(revoked.purpose, Some(KeyPurpose::Service));
    assert_eq!(revoked.approvers, Some([APPROVER_1, APPROVER_2]));

    assert_eq!(
        f.keyd
            .decided_intent(&ADMIN, Operation::RotateKey, id, &now()),
        None,
        "no intent for a revoked decision"
    );
    let before = f.records().len();
    assert_eq!(f.keyd.rotate_key(&ADMIN, id, &now()), Err(Error::Denied));
    assert_eq!(f.records().len(), before + 1, "one record");
    let refused = last(&f);
    assert_eq!(refused.op, Operation::RotateKey);
    assert_eq!(refused.reason, AuditReason::DecisionRevoked);
    assert_eq!(refused.decision, Some(id));
    assert_eq!(refused.kvno, None);
    // Not under another kind either, and not registered again.
    assert_eq!(f.keyd.retire_kvno(&ADMIN, id, &now()), Err(Error::Denied));
    assert_eq!(last(&f).reason, AuditReason::DecisionRevoked);
    let operation = rotate_service_decision();
    assert_eq!(
        f.keyd.register_decision(
            &LDAP,
            id,
            &operation,
            &approvers_for(&operation),
            MAX_KEY_DECISION_SECS,
            &now()
        ),
        Err(Error::Denied)
    );
    assert_eq!(last(&f).reason, AuditReason::DecisionRevoked);
    // Idempotent.
    assert_eq!(f.keyd.revoke_decision(&LDAP, id, &now()), Ok(()));
    assert_eq!(last(&f).result, AuditOutcome::Success);
    // The key set was never rotated: a new decision rotates kvno 1 → 2.
    let next = f.decide(rotate_service_decision(), &now()).unwrap();
    assert_eq!(f.keyd.rotate_key(&ADMIN, next, &now()), Ok(Kvno::new(2)));
}

/// Q-976; docs/10 §2 (I2): only the role that registers decisions
/// (Role::Ldap) revokes one — Kdc, Directory and Admin are refused at the
/// capability table (`RoleNotPermitted`), and the decision is still
/// executable afterwards.
#[test]
fn revocation_by_another_role_is_refused() {
    let mut f = Fixture::new();
    let id = f.decide(rotate_krbtgt_decision(), &now()).unwrap();
    for caller in [KDC, DIRECTORY, ADMIN] {
        assert_eq!(
            f.keyd.revoke_decision(&caller, id, &now()),
            Err(Error::Denied),
            "{caller:?}"
        );
        let refused = last(&f);
        assert_eq!(refused.op, Operation::RevokeDecision);
        assert_eq!(refused.caller_role, caller.role);
        assert_eq!(refused.reason, AuditReason::RoleNotPermitted);
        assert_eq!(refused.decision, Some(id));
    }
    assert_eq!(f.keyd.rotate_krbtgt(&ADMIN, id, &now()), Ok(Kvno::new(2)));
}

/// Q-976; docs/52 §3.10 (the recorded result): a decision whose execution
/// changed key state is not revoked (`DecisionExecuted`) — its replay still
/// returns the recorded kvno; one whose execution keyd refused (nothing
/// ran) is revoked, after which its id answers `DecisionRevoked`.
#[test]
fn an_executed_decision_is_not_revoked() {
    let mut f = Fixture::new();
    let id = f.decide(rotate_service_decision(), &now()).unwrap();
    assert_eq!(f.keyd.rotate_key(&ADMIN, id, &now()), Ok(Kvno::new(2)));
    assert_eq!(
        f.keyd.revoke_decision(&LDAP, id, &now()),
        Err(Error::Denied)
    );
    let refused = last(&f);
    assert_eq!(refused.reason, AuditReason::DecisionExecuted);
    assert_eq!(refused.result, AuditOutcome::Denied);
    assert_eq!(refused.principal, Some(SERVICE_ID));
    assert_eq!(f.keyd.rotate_key(&ADMIN, id, &now()), Ok(Kvno::new(2)));
    assert_eq!(last(&f).reason, AuditReason::DecisionReplayed);

    // kvno 7 is not retained: keyd refuses the execution, nothing ran.
    let retire = f.decide(retire_service_decision(7), &now()).unwrap();
    assert_eq!(
        f.keyd.retire_kvno(&ADMIN, retire, &now()),
        Err(Error::Denied)
    );
    assert_eq!(f.keyd.revoke_decision(&LDAP, retire, &now()), Ok(()));
    assert_eq!(
        f.keyd.retire_kvno(&ADMIN, retire, &now()),
        Err(Error::Denied)
    );
    assert_eq!(last(&f).reason, AuditReason::DecisionRevoked);
}

/// Q-976 (a registration whose outcome dird did not learn may still
/// arrive): an id keyd does not hold is revoked too — kept for
/// `MAX_KEY_DECISION_SECS`, during which a registration under it is refused
/// (`DecisionRevoked`); afterwards the id is free again.
#[test]
fn an_unknown_id_is_revoked_ahead_of_any_registration() {
    let mut f = Fixture::new();
    let id = next_decision_id();
    assert_eq!(f.keyd.revoke_decision(&LDAP, id, &now()), Ok(()));
    let record = last(&f);
    assert_eq!(record.result, AuditOutcome::Success);
    assert_eq!(record.decision, Some(id));
    assert_eq!(record.principal, None, "keyd held no decision under it");
    let operation = rotate_service_decision();
    let approvers = approvers_for(&operation);
    let register = |f: &mut Fixture, when: &krb_proto::KerberosTime| {
        f.keyd
            .register_decision(&LDAP, id, &operation, &approvers, 60, when)
    };
    assert_eq!(register(&mut f, &now()), Err(Error::Denied));
    assert_eq!(last(&f).reason, AuditReason::DecisionRevoked);
    let edge = at(i64::from(MAX_KEY_DECISION_SECS));
    assert_eq!(register(&mut f, &edge), Err(Error::Denied));
    let after = at(i64::from(MAX_KEY_DECISION_SECS) + 1);
    assert_eq!(register(&mut f, &after), Ok(()));
    assert_eq!(f.keyd.rotate_key(&ADMIN, id, &after), Ok(Kvno::new(2)));
}

/// Q-976; docs/CLEAN-ROOM.md (bounded, fail closed): revoked ids count against the
/// key-operation family's bound — with the family full of live decisions a
/// revocation of an unknown id is `Unavailable` (`DecisionTableFull`) and
/// changes nothing, while revoking a held one replaces it in place.
#[test]
fn revocations_are_bounded_with_the_family() {
    let mut f = Fixture::new();
    let ids: Vec<DecisionId> = (0..keyd::MAX_KEY_DECISIONS)
        .map(|_| f.decide(rotate_service_decision(), &now()).unwrap())
        .collect();
    let unknown = next_decision_id();
    assert_eq!(
        f.keyd.revoke_decision(&LDAP, unknown, &now()),
        Err(Error::Unavailable)
    );
    assert_eq!(last(&f).reason, AuditReason::DecisionTableFull);
    assert_eq!(last(&f).result, AuditOutcome::Unavailable);
    assert_eq!(f.keyd.revoke_decision(&LDAP, ids[0], &now()), Ok(()));
    // Still full (the revoked id holds its place); a held one still runs.
    assert_eq!(
        f.decide(rotate_service_decision(), &now()),
        Err(Error::Unavailable)
    );
    assert_eq!(f.keyd.rotate_key(&ADMIN, ids[1], &now()), Ok(Kvno::new(2)));
}
