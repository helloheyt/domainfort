//! The set_secret grant (task A15a), generalized by A-102 into the
//! set-secret family of keyd's decision table: dird registers a `SetSecret`
//! decision (`register_decision`, Role::Ldap) and keyadm's ceremony grants
//! the first administrators' initial secrets (`grant_set_secret`,
//! Role::Admin, before the seal); Role::Directory's `set_secret` requires
//! and consumes one, with exactly its binding **and salt** (N4).
//!
//! Sources: docs/51 §4.3 steps 11-12, §5.2 row 5, §5.8 option (b), §7.3;
//! docs/47 §9.1; docs/10 §2, §6, §6a, §9, §10; docs/questions/Q-291 (A-74),
//! Q-450, Q-451; docs/52 §2 row 37 (N4), §4.2 (A-102). All values are
//! constructed by hand for these tests.

mod common;

use common::*;
use keyd::{
    AccountKind, AuditOutcome, AuditReason, DecidedOperation, DecisionId, Error, KeyHandle,
    KeyPurpose, Kvno, Operation, PrincipalBinding, PrincipalId, SetSecretTarget,
    MAX_INITIAL_SECRET_GRANT_SECS, MAX_SET_SECRET_GRANTS, MAX_SET_SECRET_GRANT_SECS,
};
use krb_crypto::EncType;
use krb_proto::constants::{KRB_NT_PRINCIPAL, KRB_NT_SRV_HST};
use krb_proto::PrincipalName;
use zeroize::Zeroizing;

fn z(s: &str) -> Zeroizing<String> {
    Zeroizing::new(s.to_owned())
}

fn target(handle: KeyHandle, binding: PrincipalBinding, salt: &str) -> SetSecretTarget {
    SetSecretTarget {
        handle,
        binding,
        salt: salt.to_owned(),
    }
}

/// dird's `SetSecret` decision (A-102): `register_decision` as Role::Ldap
/// under a fresh id. Returns the id.
fn decide_set(
    f: &mut Fixture,
    kind: AccountKind,
    targets: Vec<SetSecretTarget>,
    lifetime: u32,
    when: &krb_proto::KerberosTime,
) -> Result<DecisionId, Error> {
    let id = next_decision_id();
    f.keyd
        .register_decision(
            &LDAP,
            id,
            &DecidedOperation::SetSecret { kind, targets },
            &[],
            lifetime,
            when,
        )
        .map(|()| id)
}

/// A new user (no key set yet): carol.
const CAROL: KeyHandle = KeyHandle::new(
    PrincipalId::from_bytes([0xCA; 16]),
    KeyPurpose::PrincipalLongterm,
);
const CAROL_SALT: &str = "EXAMPLE.ORGcarol";
const GRANTED_PASSWORD: &str = "Pewter-Jaguar-46-Moss";

fn carol_binding() -> PrincipalBinding {
    bound(PrincipalName {
        name_type: KRB_NT_PRINCIPAL,
        name_string: vec![kstr("carol")],
    })
}

/// A computer (no key sets yet): ws07$ with host/ws07.example.org.
const WS07_ID: PrincipalId = PrincipalId::from_bytes([0xC7; 16]);
const WS07: KeyHandle = KeyHandle::new(WS07_ID, KeyPurpose::PrincipalLongterm);
const WS07_HOST: KeyHandle = KeyHandle::new(WS07_ID, KeyPurpose::Service);
const WS07_SALT: &str = "EXAMPLE.ORGhostws07.example.org";

fn ws07_binding() -> PrincipalBinding {
    bound(PrincipalName {
        name_type: KRB_NT_PRINCIPAL,
        name_string: vec![kstr("ws07$")],
    })
}

fn ws07_host_binding() -> PrincipalBinding {
    bound(PrincipalName {
        name_type: KRB_NT_SRV_HST,
        name_string: vec![kstr("host"), kstr("ws07.example.org")],
    })
}

fn set(
    f: &mut Fixture,
    handle: &KeyHandle,
    binding: &PrincipalBinding,
    salt: &str,
) -> Result<Kvno, Error> {
    f.keyd.set_secret(
        &DIRECTORY,
        handle,
        binding,
        z(GRANTED_PASSWORD),
        salt,
        &now(),
    )
}

fn set_at(
    f: &mut Fixture,
    handle: &KeyHandle,
    binding: &PrincipalBinding,
    salt: &str,
    when: &krb_proto::KerberosTime,
) -> Result<Kvno, Error> {
    f.keyd
        .set_secret(&DIRECTORY, handle, binding, z(GRANTED_PASSWORD), salt, when)
}

fn last_reason(f: &Fixture) -> AuditReason {
    f.records().last().unwrap().reason
}

/// docs/51 §5.8 option (b) ("refused unless a matching unexpired grant
/// exists, and consumes it"): a decision and its matching `set_secret`
/// succeed once; the second `set_secret` finds no decision (the uniform
/// `Denied`, reason `NoGrant`) and nothing changes.
#[test]
fn a_grant_allows_exactly_one_set_secret() {
    let mut f = Fixture::new();
    assert_eq!(
        f.grant(&CAROL, &carol_binding(), CAROL_SALT, &now()),
        Ok(())
    );
    assert_eq!(
        set(&mut f, &CAROL, &carol_binding(), CAROL_SALT),
        Ok(Kvno::INITIAL)
    );
    assert_eq!(
        set(&mut f, &CAROL, &carol_binding(), CAROL_SALT),
        Err(Error::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::NoGrant);
    // The refused call changed nothing: carol's key is still the granted
    // password at kvno 1, and the next decided set gives kvno 2.
    assert!(f.password_works(&CAROL, GRANTED_PASSWORD, CAROL_SALT));
    f.grant(&CAROL, &carol_binding(), CAROL_SALT, &now())
        .unwrap();
    assert_eq!(
        set(&mut f, &CAROL, &carol_binding(), CAROL_SALT),
        Ok(Kvno::new(2))
    );
}

/// Q-291 / A-74 (the attack the grant closes): Role::Directory alone cannot
/// set a password — not a new account's, not an existing administrator's.
#[test]
fn without_a_grant_set_secret_is_denied() {
    let mut f = Fixture::new();
    for (handle, binding, salt) in [
        (CAROL, carol_binding(), CAROL_SALT),
        (ALICE, alice_binding(), ALICE_SALT),
    ] {
        assert_eq!(set(&mut f, &handle, &binding, salt), Err(Error::Denied));
        let last = f.records().last().unwrap();
        assert_eq!(last.op, Operation::SetSecret);
        assert_eq!(last.result, AuditOutcome::Denied);
        assert_eq!(last.reason, AuditReason::NoGrant);
        assert_eq!(last.principal, Some(handle.principal));
        assert_eq!(last.kvno, None, "nothing was installed");
        assert_eq!(last.decision, None);
    }
    // alice's password is unchanged.
    assert!(f.password_works(&ALICE, ALICE_PASSWORD, ALICE_SALT));
}

/// Q-450 item 7, docs/52 N4: the decision names one handle, one binding and
/// one salt exactly — a `set_secret` of another handle finds no decision;
/// one naming another binding or another salt is refused (`GrantMismatch`)
/// and consumes the decision (treated as misused), so the right one is
/// refused afterwards too.
#[test]
fn another_handle_binding_or_salt_is_refused() {
    let mut f = Fixture::new();
    f.grant(&CAROL, &carol_binding(), CAROL_SALT, &now())
        .unwrap();
    // Another handle: bob has no decision.
    assert_eq!(
        set(&mut f, &BOB, &bob_binding(), BOB_SALT),
        Err(Error::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::NoGrant);
    // carol's handle with another (creation-valid) binding.
    let mut renamed = carol_binding();
    renamed.name.name_string = vec![kstr("caroline")];
    assert_eq!(
        set(&mut f, &CAROL, &renamed, CAROL_SALT),
        Err(Error::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::GrantMismatch);
    // The decision is gone.
    assert_eq!(
        set(&mut f, &CAROL, &carol_binding(), CAROL_SALT),
        Err(Error::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::NoGrant);
    // Exact match: even a name-type difference (the same principal under
    // RFC 4120 6.2) is another binding for the decision.
    f.grant(&CAROL, &carol_binding(), CAROL_SALT, &now())
        .unwrap();
    let mut retyped = carol_binding();
    retyped.name.name_type = krb_proto::constants::KRB_NT_UNKNOWN;
    assert_eq!(
        set(&mut f, &CAROL, &retyped, CAROL_SALT),
        Err(Error::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::GrantMismatch);
    // N4: another salt (keys no client would derive) is refused too, and
    // consumes the decision.
    f.grant(&CAROL, &carol_binding(), CAROL_SALT, &now())
        .unwrap();
    assert_eq!(
        set(&mut f, &CAROL, &carol_binding(), "EXAMPLE.ORGsomeone-else"),
        Err(Error::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::GrantMismatch);
    assert_eq!(
        set(&mut f, &CAROL, &carol_binding(), CAROL_SALT),
        Err(Error::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::NoGrant);
}

/// Q-450 item 3: a decision lives `lifetime_secs` by keyd's clock and no
/// longer — live at its last second, gone one second later.
#[test]
fn an_expired_grant_is_no_grant() {
    let mut f = Fixture::new();
    decide_set(
        &mut f,
        AccountKind::User,
        vec![target(CAROL, carol_binding(), CAROL_SALT)],
        10,
        &now(),
    )
    .unwrap();
    assert_eq!(
        set_at(&mut f, &CAROL, &carol_binding(), CAROL_SALT, &at(11)),
        Err(Error::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::NoGrant);

    decide_set(
        &mut f,
        AccountKind::User,
        vec![target(CAROL, carol_binding(), CAROL_SALT)],
        10,
        &now(),
    )
    .unwrap();
    assert_eq!(
        set_at(&mut f, &CAROL, &carol_binding(), CAROL_SALT, &at(10)),
        Ok(Kvno::INITIAL)
    );
}

/// docs/10 §2 (I2); docs/52 §4.2 (A-102): only dird (Role::Ldap) registers
/// a decision — never Directory (the role it is for), never the KDC, never
/// Admin; and only Admin calls the ceremony's `grant_set_secret` — never
/// Ldap any more. Each refusal is the uniform `Denied` with
/// `RoleNotPermitted`, and registers nothing.
#[test]
fn only_dird_decides_and_only_the_ceremony_grants() {
    let mut f = Fixture::new();
    let operation = DecidedOperation::SetSecret {
        kind: AccountKind::User,
        targets: vec![target(CAROL, carol_binding(), CAROL_SALT)],
    };
    for caller in [KDC, DIRECTORY, ADMIN] {
        assert_eq!(
            f.keyd.register_decision(
                &caller,
                next_decision_id(),
                &operation,
                &[],
                MAX_SET_SECRET_GRANT_SECS,
                &now()
            ),
            Err(Error::Denied)
        );
        let last = f.records().last().unwrap();
        assert_eq!(last.op, Operation::RegisterDecision);
        assert_eq!(last.caller_role, caller.role);
        assert_eq!(last.reason, AuditReason::RoleNotPermitted);
    }
    for caller in [KDC, DIRECTORY, LDAP] {
        assert_eq!(
            f.grant_as(&caller, &CAROL, &carol_binding(), CAROL_SALT, &now()),
            Err(Error::Denied)
        );
        let last = f.records().last().unwrap();
        assert_eq!(last.op, Operation::GrantSetSecret);
        assert_eq!(last.caller_role, caller.role);
        assert_eq!(last.reason, AuditReason::RoleNotPermitted);
    }
    assert_eq!(
        set(&mut f, &CAROL, &carol_binding(), CAROL_SALT),
        Err(Error::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::NoGrant);
}

/// docs/47 §9.1; Q-450 item 2: a computer's two key targets in one
/// decision, each consumed by its own `set_secret`; the decision's audit
/// record names the first target, the second as its secondary key, and the
/// decision id — which the consuming `set_secret` records carry too
/// (docs/52 §4.5).
#[test]
fn a_computer_grant_covers_both_key_sets_once_each() {
    let mut f = Fixture::new();
    let id = decide_set(
        &mut f,
        AccountKind::Computer,
        vec![
            target(WS07, ws07_binding(), WS07_SALT),
            target(WS07_HOST, ws07_host_binding(), WS07_SALT),
        ],
        MAX_SET_SECRET_GRANT_SECS,
        &now(),
    )
    .unwrap();
    let record = f.records().last().unwrap().clone();
    assert_eq!(record.op, Operation::RegisterDecision);
    assert_eq!(record.result, AuditOutcome::Success);
    assert_eq!(record.caller_role, LDAP.role);
    assert_eq!(record.principal, Some(WS07_ID));
    assert_eq!(record.purpose, Some(KeyPurpose::PrincipalLongterm));
    assert_eq!(record.kvno, None);
    assert_eq!(record.decision, Some(id));
    let secondary = record.secondary.unwrap();
    assert_eq!(secondary.principal, WS07_ID);
    assert_eq!(secondary.purpose, KeyPurpose::Service);
    assert_eq!(secondary.kvno, None);

    assert_eq!(
        set(&mut f, &WS07, &ws07_binding(), WS07_SALT),
        Ok(Kvno::INITIAL)
    );
    assert_eq!(f.records().last().unwrap().decision, Some(id));
    assert_eq!(
        set(&mut f, &WS07_HOST, &ws07_host_binding(), WS07_SALT),
        Ok(Kvno::INITIAL)
    );
    assert_eq!(f.records().last().unwrap().decision, Some(id));
    for (handle, binding) in [(WS07, ws07_binding()), (WS07_HOST, ws07_host_binding())] {
        assert_eq!(
            set(&mut f, &handle, &binding, WS07_SALT),
            Err(Error::Denied)
        );
        assert_eq!(last_reason(&f), AuditReason::NoGrant);
    }
    // A computer without a service principal name: one target.
    assert!(decide_set(
        &mut f,
        AccountKind::Computer,
        vec![target(WS07, ws07_binding(), WS07_SALT)],
        MAX_SET_SECRET_GRANT_SECS,
        &now(),
    )
    .is_ok());
}

/// Q-450 item 2 (the shape), docs/10 §2 (I3, the purposes of the slots),
/// docs/52 §4.2: what keyd refuses to register — and records why
/// (`DecisionInvalid`).
#[test]
fn malformed_grants_are_refused() {
    let mut f = Fixture::new();
    let other_host = KeyHandle::new(PrincipalId::from_bytes([0xC8; 16]), KeyPurpose::Service);
    let cases: Vec<(AccountKind, Vec<SetSecretTarget>, u32)> = vec![
        // No target; three targets.
        (AccountKind::User, vec![], 10),
        (
            AccountKind::Computer,
            vec![
                target(WS07, ws07_binding(), WS07_SALT),
                target(WS07_HOST, ws07_host_binding(), WS07_SALT),
                target(WS07_HOST, ws07_host_binding(), WS07_SALT),
            ],
            10,
        ),
        // A user with two targets; a computer with another principal's
        // service key set.
        (
            AccountKind::User,
            vec![
                target(WS07, ws07_binding(), WS07_SALT),
                target(WS07_HOST, ws07_host_binding(), WS07_SALT),
            ],
            10,
        ),
        (
            AccountKind::Computer,
            vec![
                target(WS07, ws07_binding(), WS07_SALT),
                target(other_host, ws07_host_binding(), WS07_SALT),
            ],
            10,
        ),
        // The purposes: a Service key set first, krbtgt anywhere, a
        // PrincipalLongterm key set second.
        (
            AccountKind::Computer,
            vec![target(WS07_HOST, ws07_host_binding(), WS07_SALT)],
            10,
        ),
        (
            AccountKind::User,
            vec![target(KRBTGT, krbtgt_binding(), "EXAMPLE.ORGkrbtgt")],
            10,
        ),
        (
            AccountKind::Computer,
            vec![
                target(WS07, ws07_binding(), WS07_SALT),
                target(CAROL, carol_binding(), CAROL_SALT),
            ],
            10,
        ),
        // The lifetime: zero, above the family's ceiling.
        (
            AccountKind::User,
            vec![target(CAROL, carol_binding(), CAROL_SALT)],
            0,
        ),
        (
            AccountKind::User,
            vec![target(CAROL, carol_binding(), CAROL_SALT)],
            MAX_SET_SECRET_GRANT_SECS + 1,
        ),
    ];
    for (kind, targets, lifetime) in cases {
        assert_eq!(
            decide_set(&mut f, kind, targets.clone(), lifetime, &now()),
            Err(Error::Denied),
            "{kind:?} {targets:?} {lifetime}"
        );
        let last = f.records().last().unwrap();
        assert_eq!(last.op, Operation::RegisterDecision);
        assert_eq!(
            last.reason,
            AuditReason::DecisionInvalid,
            "{kind:?} {targets:?} {lifetime}"
        );
    }
    // Nothing was registered.
    for (handle, binding, salt) in [
        (CAROL, carol_binding(), CAROL_SALT),
        (WS07, ws07_binding(), WS07_SALT),
        (ALICE, alice_binding(), ALICE_SALT),
    ] {
        assert_eq!(set(&mut f, &handle, &binding, salt), Err(Error::Denied));
        assert_eq!(last_reason(&f), AuditReason::NoGrant);
    }
}

/// Q-450 item 7 (A-19 unchanged): a decision does not judge bindings —
/// `set_secret` still does, after consuming the decision: a krbtgt name for
/// a new key set (`InvalidNameBinding`), another name for an existing key
/// set (`NameBindingMismatch`). Nothing is created or changed, and the
/// decision is gone. So a decision can only narrow what `set_secret`
/// accepts.
#[test]
fn set_secret_still_judges_a_granted_binding() {
    let mut f = Fixture::new();
    for (handle, binding, salt, reason) in [
        (
            CAROL,
            krbtgt_binding(),
            CAROL_SALT,
            AuditReason::InvalidNameBinding,
        ),
        (
            ALICE,
            bob_binding(),
            ALICE_SALT,
            AuditReason::NameBindingMismatch,
        ),
    ] {
        f.grant(&handle, &binding, salt, &now()).unwrap();
        assert_eq!(set(&mut f, &handle, &binding, salt), Err(Error::Denied));
        assert_eq!(last_reason(&f), reason);
        assert_eq!(set(&mut f, &handle, &binding, salt), Err(Error::Denied));
        assert_eq!(last_reason(&f), AuditReason::NoGrant);
    }
    assert!(f.password_works(&ALICE, ALICE_PASSWORD, ALICE_SALT));
}

/// Q-450 item 4; docs/52 §4.2: the set-secret family holds
/// `MAX_SET_SECRET_GRANTS` key targets; a decision that does not fit is
/// refused (`Unavailable`, `DecisionTableFull`) — a live entry is never
/// evicted — and an expired one makes room. A newer decision for a handle
/// replaces its live one (one per handle).
#[test]
fn a_full_table_refuses_and_expiry_makes_room() {
    let mut f = Fixture::new();
    let handle = |i: usize| {
        let mut id = [0x40u8; 16];
        id[14] = (i >> 8) as u8;
        id[15] = i as u8;
        KeyHandle::new(PrincipalId::from_bytes(id), KeyPurpose::PrincipalLongterm)
    };
    let name = |i: usize| {
        bound(PrincipalName {
            name_type: KRB_NT_PRINCIPAL,
            name_string: vec![kstr(&format!("user{i}"))],
        })
    };
    let salt = |i: usize| format!("EXAMPLE.ORGuser{i}");
    for i in 0..MAX_SET_SECRET_GRANTS {
        decide_set(
            &mut f,
            AccountKind::User,
            vec![target(handle(i), name(i), &salt(i))],
            10,
            &now(),
        )
        .unwrap();
    }
    // Replacing a live entry takes no room.
    assert!(decide_set(
        &mut f,
        AccountKind::User,
        vec![target(handle(0), name(0), &salt(0))],
        20,
        &now(),
    )
    .is_ok());
    // One more handle does not fit.
    assert_eq!(
        f.grant(&CAROL, &carol_binding(), CAROL_SALT, &now()),
        Err(Error::Unavailable)
    );
    assert_eq!(last_reason(&f), AuditReason::DecisionTableFull);
    assert_eq!(
        f.records().last().unwrap().result,
        AuditOutcome::Unavailable
    );
    // Every live entry is still there.
    assert_eq!(
        set(&mut f, &handle(5), &name(5), &salt(5)),
        Ok(Kvno::INITIAL)
    );
    // After the others expire (all but handle 0's replacement), there is room.
    assert!(decide_set(
        &mut f,
        AccountKind::User,
        vec![target(CAROL, carol_binding(), CAROL_SALT)],
        10,
        &at(11),
    )
    .is_ok());
    assert_eq!(
        set_at(&mut f, &handle(0), &name(0), &salt(0), &at(20)),
        Ok(Kvno::INITIAL)
    );
}

/// Q-451: Role::Admin (keyadm's ceremony) grants only a user's **initial**
/// secret — not a computer, not an existing key set, and a key set that
/// appeared after the grant makes the grant fail; its lifetime ceiling is
/// `MAX_INITIAL_SECRET_GRANT_SECS`.
#[test]
fn admin_grants_only_initial_user_secrets() {
    let mut f = Fixture::new();
    // A computer: refused.
    assert_eq!(
        f.keyd.grant_set_secret(
            &ADMIN,
            AccountKind::Computer,
            &[target(WS07, ws07_binding(), WS07_SALT)],
            60,
            &now(),
        ),
        Err(Error::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::GrantInvalid);
    // An existing key set (alice): refused.
    assert_eq!(
        f.grant_as(&ADMIN, &ALICE, &alice_binding(), ALICE_SALT, &now()),
        Err(Error::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::KeyExists);
    // Above the ceiling: refused; at the ceiling: accepted, and live until
    // its last second.
    assert_eq!(
        f.keyd.grant_set_secret(
            &ADMIN,
            AccountKind::User,
            &[target(CAROL, carol_binding(), CAROL_SALT)],
            MAX_INITIAL_SECRET_GRANT_SECS + 1,
            &now(),
        ),
        Err(Error::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::GrantInvalid);
    assert_eq!(
        f.keyd.grant_set_secret(
            &ADMIN,
            AccountKind::User,
            &[target(CAROL, carol_binding(), CAROL_SALT)],
            MAX_INITIAL_SECRET_GRANT_SECS,
            &now(),
        ),
        Ok(())
    );
    let horizon = i64::from(MAX_INITIAL_SECRET_GRANT_SECS);
    assert_eq!(
        set_at(&mut f, &CAROL, &carol_binding(), CAROL_SALT, &at(horizon)),
        Ok(Kvno::INITIAL)
    );
    // An initial-secret grant whose key set appeared meanwhile (here by
    // create_key) fails at the set_secret, and is consumed.
    let dave = KeyHandle::new(
        PrincipalId::from_bytes([0xDA; 16]),
        KeyPurpose::PrincipalLongterm,
    );
    let dave_binding = bound(PrincipalName {
        name_type: KRB_NT_PRINCIPAL,
        name_string: vec![kstr("dave")],
    });
    f.grant_as(&ADMIN, &dave, &dave_binding, "EXAMPLE.ORGdave", &now())
        .unwrap();
    f.keyd
        .create_key(&ADMIN, &dave, &dave_binding, &now())
        .unwrap();
    assert_eq!(
        set(&mut f, &dave, &dave_binding, "EXAMPLE.ORGdave"),
        Err(Error::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::GrantMismatch);
    assert_eq!(
        set(&mut f, &dave, &dave_binding, "EXAMPLE.ORGdave"),
        Err(Error::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::NoGrant);
}

/// docs/10 §7 (`destroy_key_set`: the handle is unknown afterwards);
/// Q-450 item 8: a live set-secret decision goes with the key set it names.
#[test]
fn destroying_a_key_set_drops_its_grant() {
    let mut f = Fixture::new();
    f.grant(&ALICE, &alice_binding(), ALICE_SALT, &now())
        .unwrap();
    let destroy = f
        .decide(
            DecidedOperation::DestroyKeySet {
                principal: ALICE_ID,
            },
            &now(),
        )
        .unwrap();
    f.keyd.destroy_key_set(&ADMIN, destroy, &now()).unwrap();
    assert_eq!(
        set(&mut f, &ALICE, &alice_binding(), ALICE_SALT),
        Err(Error::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::NoGrant);
}

/// docs/10 §10, I8: a decision record carries ids, purposes and the
/// outcome — no binding octets, no salt, no password; the consumed
/// decision's `set_secret` record is the ordinary one (the installed kvno)
/// plus the decision id.
#[test]
fn grant_and_set_records_carry_no_secret() {
    let mut f = Fixture::new();
    f.grant(&CAROL, &carol_binding(), CAROL_SALT, &now())
        .unwrap();
    f.keyd
        .set_secret(
            &DIRECTORY,
            &CAROL,
            &carol_binding(),
            z("Ochre-Lattice-61"),
            CAROL_SALT,
            &now(),
        )
        .unwrap();
    let records = f.records();
    let grant = &records[records.len() - 2];
    let set = &records[records.len() - 1];
    assert_eq!(grant.op, Operation::RegisterDecision);
    assert_eq!(grant.result, AuditOutcome::Success);
    assert_eq!(grant.reason, AuditReason::None);
    assert!(grant.decision.is_some());
    assert_eq!(set.op, Operation::SetSecret);
    assert_eq!(set.result, AuditOutcome::Success);
    assert_eq!(set.kvno, Some(Kvno::INITIAL));
    assert_eq!(set.decision, grant.decision);
    let rendered = format!("{records:?}");
    assert!(!rendered.contains("Ochre-Lattice-61"));
    assert!(!rendered.contains("carol"), "no name or salt in a record");
    // The derived key is not in a record either.
    let key = password_key(EncType::Aes256CtsHmacSha196, "Ochre-Lattice-61", CAROL_SALT);
    assert!(!contains_bytes(rendered.as_bytes(), key.octets()));
}
