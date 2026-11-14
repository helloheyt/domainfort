//! The set_secret grant (task A15a): `grant_set_secret` and the grant that
//! Role::Directory's `set_secret` requires and consumes.
//!
//! Sources: docs/51 §4.3 steps 11-12, §5.2 row 5, §5.8 option (b), §7.3;
//! docs/47 §9.1; docs/10 §2, §6, §9, §10; docs/questions/Q-291 (A-74),
//! Q-450, Q-451. All values are constructed by hand for these tests.

mod common;

use common::*;
use keyd::{
    AccountKind, AuditOutcome, AuditReason, Error, KeyHandle, KeyPurpose, Kvno, Operation,
    PrincipalBinding, PrincipalId, SetSecretTarget, MAX_INITIAL_SECRET_GRANT_SECS,
    MAX_SET_SECRET_GRANTS, MAX_SET_SECRET_GRANT_SECS,
};
use krb_crypto::EncType;
use krb_proto::constants::{KRB_NT_PRINCIPAL, KRB_NT_SRV_HST};
use krb_proto::PrincipalName;
use zeroize::Zeroizing;

fn z(s: &str) -> Zeroizing<String> {
    Zeroizing::new(s.to_owned())
}

fn target(handle: KeyHandle, binding: PrincipalBinding) -> SetSecretTarget {
    SetSecretTarget { handle, binding }
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
        z("a granted password"),
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
    f.keyd.set_secret(
        &DIRECTORY,
        handle,
        binding,
        z("a granted password"),
        salt,
        when,
    )
}

fn last_reason(f: &Fixture) -> AuditReason {
    f.records().last().unwrap().reason
}

/// docs/51 §5.8 option (b) ("refused unless a matching unexpired grant
/// exists, and consumes it"): a grant and its matching `set_secret` succeed
/// once; the second `set_secret` finds no grant (the uniform `Denied`,
/// reason `NoGrant`) and nothing changes.
#[test]
fn a_grant_allows_exactly_one_set_secret() {
    let mut f = Fixture::new();
    assert_eq!(f.grant(&CAROL, &carol_binding(), &now()), Ok(()));
    assert_eq!(
        set(&mut f, &CAROL, &carol_binding(), CAROL_SALT),
        Ok(Kvno::INITIAL)
    );
    assert_eq!(
        set(&mut f, &CAROL, &carol_binding(), CAROL_SALT),
        Err(Error::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::NoGrant);
    // The refused call changed nothing: carol's key is still kvno 1, and
    // the next granted set gives kvno 2.
    assert!(f
        .keyd
        .verify_secret(&DIRECTORY, &CAROL, z("a granted password"), &now())
        .is_ok());
    f.grant(&CAROL, &carol_binding(), &now()).unwrap();
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
    }
    // alice's password is unchanged.
    assert!(f
        .keyd
        .verify_secret(&DIRECTORY, &ALICE, z(ALICE_PASSWORD), &now())
        .is_ok());
}

/// Q-450 item 7: the grant names one handle and one binding exactly — a
/// `set_secret` of another handle finds no grant; one naming another
/// binding is refused (`GrantMismatch`) and consumes the grant (treated as
/// misused), so the right binding is refused afterwards too.
#[test]
fn another_handle_or_binding_is_refused() {
    let mut f = Fixture::new();
    f.grant(&CAROL, &carol_binding(), &now()).unwrap();
    // Another handle: bob has no grant.
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
    // The grant is gone.
    assert_eq!(
        set(&mut f, &CAROL, &carol_binding(), CAROL_SALT),
        Err(Error::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::NoGrant);
    // Exact match: even a name-type difference (the same principal under
    // RFC 4120 6.2) is another binding for the grant.
    f.grant(&CAROL, &carol_binding(), &now()).unwrap();
    let mut retyped = carol_binding();
    retyped.name.name_type = krb_proto::constants::KRB_NT_UNKNOWN;
    assert_eq!(
        set(&mut f, &CAROL, &retyped, CAROL_SALT),
        Err(Error::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::GrantMismatch);
}

/// Q-450 item 3: a grant lives `lifetime_secs` by keyd's clock and no
/// longer — live at its last second, gone one second later.
#[test]
fn an_expired_grant_is_no_grant() {
    let mut f = Fixture::new();
    f.keyd
        .grant_set_secret(
            &LDAP,
            AccountKind::User,
            &[target(CAROL, carol_binding())],
            10,
            &now(),
        )
        .unwrap();
    assert_eq!(
        set_at(&mut f, &CAROL, &carol_binding(), CAROL_SALT, &at(11)),
        Err(Error::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::NoGrant);

    f.keyd
        .grant_set_secret(
            &LDAP,
            AccountKind::User,
            &[target(CAROL, carol_binding())],
            10,
            &now(),
        )
        .unwrap();
    assert_eq!(
        set_at(&mut f, &CAROL, &carol_binding(), CAROL_SALT, &at(10)),
        Ok(Kvno::INITIAL)
    );
}

/// docs/10 §2 (I2): only Ldap and Admin may register a grant — never
/// Directory (the role it is for), never the KDC; the refusal is the
/// uniform `Denied` with `RoleNotPermitted`, and registers nothing.
#[test]
fn only_ldap_and_admin_may_grant() {
    let mut f = Fixture::new();
    for caller in [KDC, DIRECTORY] {
        assert_eq!(
            f.grant_as(&caller, &CAROL, &carol_binding(), &now()),
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

/// docs/47 §9.1; Q-450 item 2: a computer's two key targets in one grant,
/// each consumed by its own `set_secret`; the grant's audit record names
/// the first target and the second as its secondary key.
#[test]
fn a_computer_grant_covers_both_key_sets_once_each() {
    let mut f = Fixture::new();
    assert_eq!(
        f.keyd.grant_set_secret(
            &LDAP,
            AccountKind::Computer,
            &[
                target(WS07, ws07_binding()),
                target(WS07_HOST, ws07_host_binding())
            ],
            MAX_SET_SECRET_GRANT_SECS,
            &now(),
        ),
        Ok(())
    );
    let record = f.records().last().unwrap().clone();
    assert_eq!(record.op, Operation::GrantSetSecret);
    assert_eq!(record.result, AuditOutcome::Success);
    assert_eq!(record.caller_role, LDAP.role);
    assert_eq!(record.principal, Some(WS07_ID));
    assert_eq!(record.purpose, Some(KeyPurpose::PrincipalLongterm));
    assert_eq!(record.kvno, None);
    let secondary = record.secondary.unwrap();
    assert_eq!(secondary.principal, WS07_ID);
    assert_eq!(secondary.purpose, KeyPurpose::Service);
    assert_eq!(secondary.kvno, None);

    assert_eq!(
        set(&mut f, &WS07, &ws07_binding(), WS07_SALT),
        Ok(Kvno::INITIAL)
    );
    assert_eq!(
        set(&mut f, &WS07_HOST, &ws07_host_binding(), WS07_SALT),
        Ok(Kvno::INITIAL)
    );
    for (handle, binding) in [(WS07, ws07_binding()), (WS07_HOST, ws07_host_binding())] {
        assert_eq!(
            set(&mut f, &handle, &binding, WS07_SALT),
            Err(Error::Denied)
        );
        assert_eq!(last_reason(&f), AuditReason::NoGrant);
    }
    // A computer without a service principal name: one target.
    assert_eq!(
        f.keyd.grant_set_secret(
            &LDAP,
            AccountKind::Computer,
            &[target(WS07, ws07_binding())],
            MAX_SET_SECRET_GRANT_SECS,
            &now(),
        ),
        Ok(())
    );
}

/// Q-450 item 2 (the shape), docs/10 §2 (I3, the purposes of the slots):
/// what keyd refuses to grant — and records why.
#[test]
fn malformed_grants_are_refused() {
    let mut f = Fixture::new();
    let other_host = KeyHandle::new(PrincipalId::from_bytes([0xC8; 16]), KeyPurpose::Service);
    let cases: Vec<(AccountKind, Vec<SetSecretTarget>, u32, AuditReason)> = vec![
        // No target; three targets.
        (AccountKind::User, vec![], 10, AuditReason::GrantInvalid),
        (
            AccountKind::Computer,
            vec![
                target(WS07, ws07_binding()),
                target(WS07_HOST, ws07_host_binding()),
                target(WS07_HOST, ws07_host_binding()),
            ],
            10,
            AuditReason::GrantInvalid,
        ),
        // A user with two targets; a computer with another principal's
        // service key set.
        (
            AccountKind::User,
            vec![
                target(WS07, ws07_binding()),
                target(WS07_HOST, ws07_host_binding()),
            ],
            10,
            AuditReason::GrantInvalid,
        ),
        (
            AccountKind::Computer,
            vec![
                target(WS07, ws07_binding()),
                target(other_host, ws07_host_binding()),
            ],
            10,
            AuditReason::GrantInvalid,
        ),
        // The purposes: a Service key set first, krbtgt anywhere, a
        // PrincipalLongterm key set second.
        (
            AccountKind::Computer,
            vec![target(WS07_HOST, ws07_host_binding())],
            10,
            AuditReason::PurposeMismatch,
        ),
        (
            AccountKind::User,
            vec![target(KRBTGT, krbtgt_binding())],
            10,
            AuditReason::PurposeMismatch,
        ),
        (
            AccountKind::Computer,
            vec![target(WS07, ws07_binding()), target(CAROL, carol_binding())],
            10,
            AuditReason::PurposeMismatch,
        ),
        // The lifetime: zero, above Ldap's ceiling.
        (
            AccountKind::User,
            vec![target(CAROL, carol_binding())],
            0,
            AuditReason::GrantInvalid,
        ),
        (
            AccountKind::User,
            vec![target(CAROL, carol_binding())],
            MAX_SET_SECRET_GRANT_SECS + 1,
            AuditReason::GrantInvalid,
        ),
    ];
    for (kind, targets, lifetime, reason) in cases {
        assert_eq!(
            f.keyd
                .grant_set_secret(&LDAP, kind, &targets, lifetime, &now()),
            Err(Error::Denied),
            "{kind:?} {targets:?} {lifetime}"
        );
        let last = f.records().last().unwrap();
        assert_eq!(last.op, Operation::GrantSetSecret);
        assert_eq!(last.reason, reason, "{kind:?} {targets:?} {lifetime}");
    }
    // Nothing was granted.
    for (handle, binding, salt) in [
        (CAROL, carol_binding(), CAROL_SALT),
        (WS07, ws07_binding(), WS07_SALT),
        (ALICE, alice_binding(), ALICE_SALT),
    ] {
        assert_eq!(set(&mut f, &handle, &binding, salt), Err(Error::Denied));
        assert_eq!(last_reason(&f), AuditReason::NoGrant);
    }
}

/// Q-450 item 7 (A-19 unchanged): a grant does not judge bindings —
/// `set_secret` still does, after consuming the grant: a krbtgt name for a
/// new key set (`InvalidNameBinding`), another name for an existing key set
/// (`NameBindingMismatch`). Nothing is created or changed, and the grant is
/// gone. So a grant can only narrow what `set_secret` accepts.
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
        f.grant(&handle, &binding, &now()).unwrap();
        assert_eq!(set(&mut f, &handle, &binding, salt), Err(Error::Denied));
        assert_eq!(last_reason(&f), reason);
        assert_eq!(set(&mut f, &handle, &binding, salt), Err(Error::Denied));
        assert_eq!(last_reason(&f), AuditReason::NoGrant);
    }
    assert!(f
        .keyd
        .verify_secret(&DIRECTORY, &ALICE, z(ALICE_PASSWORD), &now())
        .is_ok());
}

/// Q-450 item 4: the table holds `MAX_SET_SECRET_GRANTS` key targets; a
/// grant that does not fit is refused (`Unavailable`, `GrantTableFull`) —
/// a live grant is never evicted — and an expired one makes room. A newer
/// grant of a handle replaces its live one (one per handle).
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
    for i in 0..MAX_SET_SECRET_GRANTS {
        f.keyd
            .grant_set_secret(
                &LDAP,
                AccountKind::User,
                &[target(handle(i), name(i))],
                10,
                &now(),
            )
            .unwrap();
    }
    // Replacing a live grant takes no room.
    assert_eq!(
        f.keyd.grant_set_secret(
            &LDAP,
            AccountKind::User,
            &[target(handle(0), name(0))],
            20,
            &now(),
        ),
        Ok(())
    );
    // One more handle does not fit.
    assert_eq!(
        f.grant(&CAROL, &carol_binding(), &now()),
        Err(Error::Unavailable)
    );
    assert_eq!(last_reason(&f), AuditReason::GrantTableFull);
    assert_eq!(
        f.records().last().unwrap().result,
        AuditOutcome::Unavailable
    );
    // Every live grant is still there.
    assert_eq!(
        set(&mut f, &handle(5), &name(5), "EXAMPLE.ORGuser5"),
        Ok(Kvno::INITIAL)
    );
    // After the others expire (all but handle 0's replacement), there is room.
    assert_eq!(
        f.keyd.grant_set_secret(
            &LDAP,
            AccountKind::User,
            &[target(CAROL, carol_binding())],
            10,
            &at(11),
        ),
        Ok(())
    );
    assert_eq!(
        set_at(&mut f, &handle(0), &name(0), "EXAMPLE.ORGuser0", &at(20)),
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
            &[target(WS07, ws07_binding())],
            60,
            &now(),
        ),
        Err(Error::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::GrantInvalid);
    // An existing key set (alice): refused.
    assert_eq!(
        f.grant_as(&ADMIN, &ALICE, &alice_binding(), &now()),
        Err(Error::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::KeyExists);
    // Above the ceiling: refused; at the ceiling: accepted, and live until
    // its last second.
    assert_eq!(
        f.keyd.grant_set_secret(
            &ADMIN,
            AccountKind::User,
            &[target(CAROL, carol_binding())],
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
            &[target(CAROL, carol_binding())],
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
    f.grant_as(&ADMIN, &dave, &dave_binding, &now()).unwrap();
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
/// Q-450 item 8: a live grant goes with the key set it names.
#[test]
fn destroying_a_key_set_drops_its_grant() {
    let mut f = Fixture::new();
    f.grant(&ALICE, &alice_binding(), &now()).unwrap();
    f.keyd.destroy_key_set(&ADMIN, &ALICE, &now()).unwrap();
    assert_eq!(
        set(&mut f, &ALICE, &alice_binding(), ALICE_SALT),
        Err(Error::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::NoGrant);
}

/// docs/10 §10, I8: a grant record carries ids, purposes and the outcome —
/// no binding octets, no password; the consumed grant's `set_secret` record
/// is the ordinary one (the installed kvno).
#[test]
fn grant_and_set_records_carry_no_secret() {
    let mut f = Fixture::new();
    f.grant(&CAROL, &carol_binding(), &now()).unwrap();
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
    assert_eq!(grant.op, Operation::GrantSetSecret);
    assert_eq!(grant.result, AuditOutcome::Success);
    assert_eq!(grant.reason, AuditReason::None);
    assert_eq!(set.op, Operation::SetSecret);
    assert_eq!(set.result, AuditOutcome::Success);
    assert_eq!(set.kvno, Some(Kvno::INITIAL));
    let rendered = format!("{records:?}");
    assert!(!rendered.contains("Ochre-Lattice-61"));
    assert!(!rendered.contains("carol"), "no name in a record");
    // The derived key is not in a record either.
    let key = password_key(EncType::Aes256CtsHmacSha196, "Ochre-Lattice-61", CAROL_SALT);
    assert!(!contains_bytes(rendered.as_bytes(), key.octets()));
}
