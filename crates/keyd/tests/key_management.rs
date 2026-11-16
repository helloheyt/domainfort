//! Key lifecycle and secrets: D178 (krbtgt refused by the non-development
//! store), create / rotate / rotate_krbtgt (dual control) / retire_kvno —
//! each rotation and retirement on a decision dird registered (A-102) —,
//! set_secret, `verify_secret` in no role (A-102, docs/52 R4), and entropy
//! failure (fail closed). Sources: docs/10 §6, §7, §12; docs/33 §5, §6.1;
//! RFC 4120 3.2.3 (ticket decrypted with the kvno it names); docs/52 §4.2,
//! §7 R1, R4; AGENTS.md §6. All values are constructed for these tests.

mod common;

use common::*;
use keyd::{
    AuditReason, AuthnError, DecidedOperation, Error, InMemoryKeyStore, IssueError, KeyHandle,
    KeyPurpose, Keyd, Kvno, PrincipalBinding, PrincipalId, MAX_KEY_DECISION_SECS,
};
use krb_crypto::EncType;
use krb_proto::constants::{
    KRB_NT_ENTERPRISE, KRB_NT_PRINCIPAL, KRB_NT_SRV_HST, KRB_NT_SRV_INST, KRB_NT_UNKNOWN,
};
use krb_proto::{EncTicketPart, PrincipalName};
use zeroize::Zeroizing;

fn z(s: &str) -> Zeroizing<String> {
    Zeroizing::new(s.to_owned())
}

/// The krbtgt rotation dird registers at the `Approve` completing the
/// quorum (A-102, docs/52 §4.3), with the dual-control pair.
fn krbtgt_rotation(f: &mut Fixture) -> keyd::DecisionId {
    f.decide(DecidedOperation::RotateKrbtgt { krbtgt: KRBTGT }, &now())
        .unwrap()
}

/// The retirement of `kvno` of the krbtgt key set (A-102).
fn krbtgt_retirement(f: &mut Fixture, kvno: u32) -> keyd::DecisionId {
    f.decide(
        DecidedOperation::RetireKvno {
            handle: KRBTGT,
            kvno: Kvno::new(kvno),
        },
        &now(),
    )
    .unwrap()
}

/// D178: the default in-memory store refuses to hold krbtgt keys, and keyd
/// refuses to create one there. Source: docs/33 §6.1 (D178: critical signing
/// requires a real HSM; refused on the weak profile by default); docs/10
/// D35.
#[test]
fn krbtgt_refused_by_non_development_store() {
    let store = InMemoryKeyStore::new(16);
    let mut keyd = Keyd::with_entropy(
        config(),
        store,
        CollectingAudit::default(),
        TestEntropy::default(),
        &keyd_started(),
    )
    .unwrap();
    assert_eq!(
        keyd.create_key(&ADMIN, &KRBTGT, &krbtgt_binding(), &now()),
        Err(Error::Denied)
    );
    let last = keyd.audit_sink().records.last().unwrap().clone();
    assert_eq!(last.reason, AuditReason::StoreRefusedCritical);
    // Principal and service keys are fine on the same store.
    assert_eq!(
        keyd.create_key(&ADMIN, &SERVICE, &service_binding(), &now()),
        Ok(Kvno::new(1))
    );
    // And no TGT can ever be issued from it.
    grant(&mut keyd, &ALICE, &alice_binding(), ALICE_SALT, &now()).unwrap();
    keyd.set_secret(
        &DIRECTORY,
        &ALICE,
        &alice_binding(),
        z(ALICE_PASSWORD),
        ALICE_SALT,
        &now(),
    )
    .unwrap();
    let proof = keyd
        .verify_preauth(
            &KDC,
            &ALICE,
            &pa_enc_timestamp(&alice_key(), Some(1), now()),
            None,
            &now(),
        )
        .unwrap();
    assert_eq!(
        keyd.issue_as(&KDC, &ALICE, &KRBTGT, &proof, None, &as_template(), &now()),
        Err(IssueError::Denied)
    );
}

/// create_key never overwrites (rotation is the only way to replace a key,
/// so dual control on krbtgt cannot be bypassed) — and so the binding fixed
/// at creation can never be replaced through it. Source: docs/10 §7;
/// docs/questions/Q-040 (A-19).
#[test]
fn create_key_does_not_overwrite() {
    let mut f = Fixture::new();
    assert_eq!(
        f.keyd
            .create_key(&ADMIN, &KRBTGT, &krbtgt_binding(), &now()),
        Err(Error::Denied)
    );
    assert_eq!(f.records().last().unwrap().reason, AuditReason::KeyExists);
    assert_eq!(
        f.keyd.create_key(&ADMIN, &SERVICE, &bob_binding(), &now()),
        Err(Error::Denied)
    );
    assert_eq!(f.records().last().unwrap().reason, AuditReason::KeyExists);
    // The service key is still bound to its original name: a ticket for it
    // is still issued.
    let tgt = obtain_tgt(&mut f, now(), &as_template());
    let ctx = open_tgt(&mut f, &tgt, 41, 41);
    assert!(f
        .keyd
        .issue_tgs(&KDC, &SERVICE, &ctx.ctx_id, &tgs_template(41), &now())
        .is_ok());
}

/// The binding given at creation must be acceptable: this realm, at least
/// one component, and "krbtgt" names only (and always) for krbtgt keys.
/// Source: RFC 4120 6.2 ("Names of any type with an initial component of
/// 'krbtgt' are reserved for the Kerberos ticket-granting service"), 7.3
/// (two-part TGS name); docs/questions/Q-040 (A-19).
#[test]
fn create_key_validates_binding() {
    let mut f = Fixture::new();
    let new_service = KeyHandle::new(PrincipalId::from_bytes([0x61; 16]), KeyPurpose::Service);
    let new_krbtgt = KeyHandle::new(PrincipalId::from_bytes([0x62; 16]), KeyPurpose::Krbtgt);
    let other_realm = PrincipalBinding::new(kstr("OTHER.ORG"), service_name());
    let empty = bound(PrincipalName {
        name_type: KRB_NT_PRINCIPAL,
        name_string: vec![],
    });
    let one_part_krbtgt = bound(PrincipalName {
        name_type: KRB_NT_SRV_INST,
        name_string: vec![kstr("krbtgt")],
    });
    for (handle, binding) in [
        (new_service, other_realm),
        (new_service, empty),
        (new_service, krbtgt_binding()),
        (new_krbtgt, service_binding()),
        (new_krbtgt, one_part_krbtgt),
    ] {
        assert_eq!(
            f.keyd.create_key(&ADMIN, &handle, &binding, &now()),
            Err(Error::Denied),
            "{binding:?}"
        );
        assert_eq!(
            f.records().last().unwrap().reason,
            AuditReason::InvalidNameBinding
        );
    }
    // set_secret applies the same rules when it creates a key set (with the
    // grant it needs since task A15a, which does not judge bindings).
    let carol = KeyHandle::new(
        PrincipalId::from_bytes([0xCA; 16]),
        KeyPurpose::PrincipalLongterm,
    );
    grant(
        &mut f.keyd,
        &carol,
        &krbtgt_binding(),
        "EXAMPLE.ORGcarol",
        &now(),
    )
    .unwrap();
    assert_eq!(
        f.keyd.set_secret(
            &DIRECTORY,
            &carol,
            &krbtgt_binding(),
            z("Marble-Pigeon-93-Cactus"),
            "EXAMPLE.ORGcarol",
            &now()
        ),
        Err(Error::Denied)
    );
    assert_eq!(
        f.records().last().unwrap().reason,
        AuditReason::InvalidNameBinding
    );
}

/// The creation rule judges the reserved names on the folded form, through
/// crate principal-names — the namespace's reading of a name and its
/// reserved-name predicate (class C49): every spelling of `krbtgt/X`,
/// `admind/<host>` and `kadmin/changepw` is bound only to its own purpose's
/// key set — and to that one in any case — and a name no object of the
/// namespace stores (more than two components in phase 1, an "@" or an
/// empty part inside a component, a key equal to the realm's name, a
/// one-part name in "@" form) is bound to no key set.
/// Source: RFC 4120 6.2 ("Names of any type with an initial component of
/// 'krbtgt' are reserved for the Kerberos ticket-granting service"; the
/// name-type is not significant), 7.3; RFC 3244 §2; A-73; docs/59 §4.2 (the
/// request table, the reserved-name predicates), §4.4 N4; [MS-ADTS]
/// 3.1.1.5.3.1.1.4 (a three-part SPN only on a DC's object — task PN16);
/// docs/questions/Q-1009 items 1-2, Q-1061 item 1 (A-190), Q-1066 (task
/// PN10c: the three-part name moved from accepted to refused).
#[test]
fn the_creation_rule_judges_reserved_names_folded() {
    fn named(name_type: i32, parts: &[&str]) -> PrincipalBinding {
        bound(PrincipalName {
            name_type,
            name_string: parts.iter().map(|p| kstr(p)).collect(),
        })
    }
    fn push_keys(f: &Fixture, octet: u8) {
        for e in &f.keyd.config().enctypes {
            let length = EncType::from_number(e.number()).unwrap().key_length();
            f.entropy.push(&[octet; 32][..length]);
        }
    }
    let mut f = Fixture::new();
    let service = KeyHandle::new(PrincipalId::from_bytes([0x71; 16]), KeyPurpose::Service);
    let longterm = KeyHandle::new(
        PrincipalId::from_bytes([0x72; 16]),
        KeyPurpose::PrincipalLongterm,
    );
    let reserved_spellings = [
        named(KRB_NT_SRV_INST, &["KRBTGT", "EXAMPLE.ORG"]),
        named(KRB_NT_SRV_INST, &["Krbtgt", "other.org"]),
        named(KRB_NT_SRV_HST, &["ADMIND", "dc01.example.org"]),
        named(KRB_NT_SRV_INST, &["KADMIN", "CHANGEPW"]),
    ];
    let no_namespace_names = [
        named(KRB_NT_SRV_HST, &["host", "a", "b", "c"]),
        named(KRB_NT_SRV_HST, &["host", "files@example.org"]),
        named(KRB_NT_SRV_HST, &["host", ""]),
        named(KRB_NT_PRINCIPAL, &["example.org"]),
        named(KRB_NT_PRINCIPAL, &["carol@OTHER.ORG"]),
        // Task PN10c: a three-part name is no phase-1 stored SPN.
        named(KRB_NT_SRV_HST, &["ldap", "dc01.example.org", "example.org"]),
    ];
    for binding in reserved_spellings.iter().chain(&no_namespace_names) {
        for handle in [service, longterm] {
            assert_eq!(
                f.keyd.create_key(&ADMIN, &handle, binding, &now()),
                Err(Error::Denied),
                "{handle:?} {binding:?}"
            );
            assert_eq!(
                f.records().last().unwrap().reason,
                AuditReason::InvalidNameBinding
            );
        }
    }
    // A Krbtgt key set takes no name outside the TGS's, in any case.
    let krbtgt = KeyHandle::new(PrincipalId::from_bytes([0x73; 16]), KeyPurpose::Krbtgt);
    for binding in [
        named(KRB_NT_SRV_INST, &["krbtgt"]),
        named(KRB_NT_SRV_INST, &["KRBTGT", "a", "b"]),
        named(KRB_NT_SRV_HST, &["ADMIND", "dc01.example.org"]),
    ] {
        assert_eq!(
            f.keyd.create_key(&ADMIN, &krbtgt, &binding, &now()),
            Err(Error::Denied),
            "{binding:?}"
        );
    }
    // Each reserved name, in another case, is its own purpose's name.
    for (id, purpose, binding) in [
        (
            0x74,
            KeyPurpose::Krbtgt,
            named(KRB_NT_SRV_INST, &["KRBTGT", "example.org"]),
        ),
        (
            0x75,
            KeyPurpose::AdminService,
            named(KRB_NT_SRV_HST, &["ADMIND", "dc01.example.org"]),
        ),
        (
            0x76,
            KeyPurpose::ChangePasswordService,
            named(KRB_NT_SRV_INST, &["KADMIN", "changepw"]),
        ),
    ] {
        push_keys(&f, id);
        let handle = KeyHandle::new(PrincipalId::from_bytes([id; 16]), purpose);
        assert!(
            f.keyd.create_key(&ADMIN, &handle, &binding, &now()).is_ok(),
            "{binding:?}"
        );
    }
    // A namespace name that is no reserved one takes a plain key set — in
    // any case, a two-part service name included.
    for (id, handle_purpose, binding) in [
        (
            0x77,
            KeyPurpose::Service,
            named(KRB_NT_SRV_HST, &["HOST", "ws9.example.org"]),
        ),
        (
            0x79,
            KeyPurpose::PrincipalLongterm,
            named(KRB_NT_PRINCIPAL, &["ws9$"]),
        ),
    ] {
        push_keys(&f, id);
        let handle = KeyHandle::new(PrincipalId::from_bytes([id; 16]), handle_purpose);
        assert!(
            f.keyd.create_key(&ADMIN, &handle, &binding, &now()).is_ok(),
            "{binding:?}"
        );
    }
}

/// Task PN10c (the A-190 residual of docs/questions/Q-1060; Q-1066): a key
/// set's binding is a stored name, so the creation rule reads it as one —
/// never as a request. A one-part `carol@<this realm>` (any case) is how a
/// request may spell carol (crate principal-names `key_of_request` maps it
/// to `carol`, [MS-KILE] 3.3.5.6.1), but no object stores it as a
/// sAMAccountName ("@" — docs/59 §4.4 N2) and a userPrincipalName is no
/// binding: it is bound to no key set, by `create_key` or by the
/// `set_secret` that would create one; nor is a final "$" that is no
/// computer's form ([MS-SAMR] 3.1.1.6 item 11: "a single '$'"), nor a host
/// part with an ":instancename" ([MS-ADTS] 3.1.1.5.3.1.1.4). The stored
/// spellings of the same principals are bound (controls): `carol`, `ws9$`,
/// `host/ws9.example.org:8080` (a numeric port, [MS-ADTS] 2.2.21).
/// Source: docs/59 §4.2 (the request table), §4.4 N2-N4, §7.3 (the stored
/// binding); [MS-SAMR] 3.1.1.6 items 10-11; [MS-ADTS] 2.2.21,
/// 3.1.1.5.3.1.1.4; [MS-KILE] 3.3.5.6.1 (as cited by principal-names);
/// RFC 4120 6.2. Every value is made up here.
#[test]
fn a_binding_is_read_as_a_stored_name_never_as_a_request() {
    fn named(name_type: i32, parts: &[&str]) -> PrincipalBinding {
        bound(PrincipalName {
            name_type,
            name_string: parts.iter().map(|p| kstr(p)).collect(),
        })
    }
    let mut f = Fixture::new();
    let carol = KeyHandle::new(
        PrincipalId::from_bytes([0xC1; 16]),
        KeyPurpose::PrincipalLongterm,
    );
    let service = KeyHandle::new(PrincipalId::from_bytes([0xC2; 16]), KeyPurpose::Service);
    let request_only = [
        named(KRB_NT_PRINCIPAL, &["carol@EXAMPLE.ORG"]),
        named(KRB_NT_ENTERPRISE, &["carol@example.org"]),
        named(KRB_NT_PRINCIPAL, &["ws9$$"]),
        named(KRB_NT_SRV_HST, &["host", "ws9.example.org:inst"]),
    ];
    for binding in &request_only {
        for handle in [carol, service] {
            assert_eq!(
                f.keyd.create_key(&ADMIN, &handle, binding, &now()),
                Err(Error::Denied),
                "{handle:?} {binding:?}"
            );
            assert_eq!(
                f.records().last().unwrap().reason,
                AuditReason::InvalidNameBinding
            );
        }
    }
    // The set_secret that would create carol's key set reads it the same
    // way (the grant does not judge bindings — task A15a).
    let upn = named(KRB_NT_ENTERPRISE, &["carol@EXAMPLE.ORG"]);
    grant(&mut f.keyd, &carol, &upn, "EXAMPLE.ORGcarol", &now()).unwrap();
    assert_eq!(
        f.keyd.set_secret(
            &DIRECTORY,
            &carol,
            &upn,
            z("Marble-Pigeon-93-Cactus"),
            "EXAMPLE.ORGcarol",
            &now()
        ),
        Err(Error::Denied)
    );
    assert_eq!(
        f.records().last().unwrap().reason,
        AuditReason::InvalidNameBinding
    );
    // Controls: the stored spellings are bound.
    let stored = named(KRB_NT_PRINCIPAL, &["carol"]);
    grant(&mut f.keyd, &carol, &stored, "EXAMPLE.ORGcarol", &now()).unwrap();
    assert!(f
        .keyd
        .set_secret(
            &DIRECTORY,
            &carol,
            &stored,
            z("Marble-Pigeon-93-Cactus"),
            "EXAMPLE.ORGcarol",
            &now()
        )
        .is_ok());
    for (id, purpose, binding) in [
        (
            0xC3,
            KeyPurpose::PrincipalLongterm,
            named(KRB_NT_PRINCIPAL, &["ws9$"]),
        ),
        (
            0xC4,
            KeyPurpose::Service,
            named(KRB_NT_SRV_HST, &["host", "ws9.example.org:8080"]),
        ),
    ] {
        for e in &f.keyd.config().enctypes {
            let length = EncType::from_number(e.number()).unwrap().key_length();
            f.entropy.push(&[id; 32][..length]);
        }
        let handle = KeyHandle::new(PrincipalId::from_bytes([id; 16]), purpose);
        assert!(
            f.keyd.create_key(&ADMIN, &handle, &binding, &now()).is_ok(),
            "{binding:?}"
        );
    }
}

/// set_secret cannot change the binding of an existing key set (no rename in
/// phase 1); a binding differing only in name-type is the same principal
/// (RFC 4120 6.2) and is accepted, the stored binding staying as created.
/// Source: docs/questions/Q-040 (A-19); RFC 4120 6.2.
#[test]
fn set_secret_cannot_rebind() {
    let mut f = Fixture::new();
    // Even with a grant naming the other binding (task A15a: the grant does
    // not judge bindings), set_secret refuses the rebinding.
    f.grant(&ALICE, &bob_binding(), ALICE_SALT, &now()).unwrap();
    assert_eq!(
        f.keyd.set_secret(
            &DIRECTORY,
            &ALICE,
            &bob_binding(),
            z("Saber-Lilac-28-Quail"),
            ALICE_SALT,
            &now()
        ),
        Err(Error::Denied)
    );
    assert_eq!(
        f.records().last().unwrap().reason,
        AuditReason::NameBindingMismatch
    );
    // A ticket naming bob is still refused for alice's key.
    let proof = f
        .keyd
        .verify_preauth(
            &KDC,
            &ALICE,
            &pa_enc_timestamp(&alice_key(), Some(1), now()),
            None,
            &now(),
        )
        .unwrap();
    let mut t = as_template();
    t.cname = bob_name();
    assert_eq!(
        f.keyd
            .issue_as(&KDC, &ALICE, &KRBTGT, &proof, None, &t, &now()),
        Err(IssueError::Denied)
    );

    let mut same = alice_binding();
    same.name.name_type = KRB_NT_UNKNOWN;
    f.grant(&ALICE, &same, ALICE_SALT, &now()).unwrap();
    assert_eq!(
        f.keyd.set_secret(
            &DIRECTORY,
            &ALICE,
            &same,
            z("Topaz-Heron-47-Dune"),
            ALICE_SALT,
            &now()
        ),
        Ok(Kvno::new(2))
    );
}

/// kvno rotation: tickets sealed under the old krbtgt kvno still open via
/// the previous version until retire_kvno; new tickets use the new kvno.
/// Source: docs/10 §1 (current + previous; decrypt may try both, seal with
/// current), §7 (rotate_krbtgt, retire_kvno); RFC 4120 3.2.3 (the version
/// named by the ticket); docs/33 §5 (D20 double rotation).
#[test]
fn krbtgt_rotation_and_retirement() {
    let mut f = Fixture::new();
    let old = obtain_tgt(&mut f, now(), &as_template());
    assert_eq!(old.parts.ticket.enc_part.kvno, Some(1));

    let rotation = krbtgt_rotation(&mut f);
    assert_eq!(
        f.keyd.rotate_krbtgt(&ADMIN, rotation, &now()),
        Ok(Kvno::new(2))
    );
    let last = f.records().last().unwrap();
    assert_eq!(last.approvers, Some([APPROVER_1, APPROVER_2]));
    assert_eq!(last.kvno, Some(Kvno::new(2)));

    // The old TGT still opens (previous kvno).
    open_tgt(&mut f, &old, 1, 1);
    assert_eq!(f.records().last().unwrap().kvno, Some(Kvno::new(1)));

    // A new TGT is sealed under kvno 2 and no longer opens with the old key.
    let new = obtain_tgt(&mut f, now(), &as_template());
    assert_eq!(new.parts.ticket.enc_part.kvno, Some(2));
    assert!(
        krb_crypto::decrypt(&krbtgt_key(), usage(2), &new.parts.ticket.enc_part.cipher).is_err()
    );
    open_tgt(&mut f, &new, 2, 2);

    // The current kvno cannot be retired; an unknown one neither.
    for kvno in [2, 7] {
        let retirement = krbtgt_retirement(&mut f, kvno);
        assert_eq!(
            f.keyd.retire_kvno(&ADMIN, retirement, &now()),
            Err(Error::Denied)
        );
        assert_eq!(
            f.records().last().unwrap().reason,
            AuditReason::KvnoNotRetirable
        );
    }
    // Retire kvno 1: the old TGT is refused, the new one still works.
    let retirement = krbtgt_retirement(&mut f, 1);
    assert_eq!(f.keyd.retire_kvno(&ADMIN, retirement, &now()), Ok(()));
    let (_, body) = tgs_req_body(3, service_name());
    let req = ap_req(
        &old.parts.ticket,
        authenticator(&old.session, &AuthenticatorSpec::new(now(), 3, &body)),
    );
    assert_eq!(
        f.keyd
            .open_and_verify_tgt(&KDC, &KRBTGT, &req, &body, None, &now()),
        Err(AuthnError::Denied)
    );
    open_tgt(&mut f, &new, 4, 4);
    let again = krbtgt_retirement(&mut f, 1);
    assert_eq!(
        f.keyd.retire_kvno(&ADMIN, again, &now()),
        Err(Error::Denied)
    );
}

/// A double rotation (compromise recovery) leaves the original kvno out of
/// the decryption set. Source: docs/33 §5 (D20); docs/10 §1.
#[test]
fn double_rotation_drops_original_key() {
    let mut f = Fixture::new();
    let old = obtain_tgt(&mut f, now(), &as_template());
    // Two rotations are two decisions (one decision, one execution —
    // docs/52 §3.10).
    for _ in 0..2 {
        let rotation = krbtgt_rotation(&mut f);
        f.keyd.rotate_krbtgt(&ADMIN, rotation, &now()).unwrap();
    }
    let (_, body) = tgs_req_body(5, service_name());
    let req = ap_req(
        &old.parts.ticket,
        authenticator(&old.session, &AuthenticatorSpec::new(now(), 5, &body)),
    );
    assert_eq!(
        f.keyd
            .open_and_verify_tgt(&KDC, &KRBTGT, &req, &body, None, &now()),
        Err(AuthnError::Denied)
    );
}

/// Dual control needs two DISTINCT approvers: a krbtgt rotation decision
/// naming one approver, or the same one twice, is refused at registration
/// (`DecisionInvalid`), so no token keyd could build from it ever exists
/// (A-102: the dual-control token is built inside keyd from the decision's
/// approvers; their authenticity is dird's — docs/43 D175). Source: docs/10
/// §7; docs/51 §5.6; docs/52 §4.2.
#[test]
fn rotate_krbtgt_requires_distinct_approvers() {
    let mut f = Fixture::new();
    let rotation = DecidedOperation::RotateKrbtgt { krbtgt: KRBTGT };
    for approvers in [vec![APPROVER_1, APPROVER_1], vec![APPROVER_1]] {
        let id = next_decision_id();
        assert_eq!(
            f.keyd.register_decision(
                &LDAP,
                id,
                &rotation,
                &approvers,
                MAX_KEY_DECISION_SECS,
                &now()
            ),
            Err(Error::Denied)
        );
        let last = f.records().last().unwrap();
        assert_eq!(last.reason, AuditReason::DecisionInvalid);
        // Nothing was registered under that id.
        assert_eq!(f.keyd.rotate_krbtgt(&ADMIN, id, &now()), Err(Error::Denied));
        assert_eq!(f.records().last().unwrap().reason, AuditReason::NoDecision);
    }
    // Nothing rotated: TGTs are still sealed under kvno 1.
    let tgt = obtain_tgt(&mut f, now(), &as_template());
    assert_eq!(tgt.parts.ticket.enc_part.kvno, Some(1));
}

/// rotate_key serves service keys (new service tickets use the new kvno);
/// the krbtgt is reachable only through rotate_krbtgt (I3): a RotateKey
/// decision on the krbtgt handle is refused at registration. Source:
/// docs/10 §7, §12 I3; docs/52 §4.2 (A-102).
#[test]
fn rotate_service_key() {
    let mut f = Fixture::new();
    assert_eq!(
        f.decide(DecidedOperation::RotateKey { handle: KRBTGT }, &now()),
        Err(Error::Denied)
    );
    assert_eq!(
        f.records().last().unwrap().reason,
        AuditReason::DecisionInvalid
    );
    let rotation = f
        .decide(DecidedOperation::RotateKey { handle: SERVICE }, &now())
        .unwrap();
    assert_eq!(
        f.keyd.rotate_key(&ADMIN, rotation, &now()),
        Ok(Kvno::new(2))
    );
    let tgt = obtain_tgt(&mut f, now(), &as_template());
    let ctx = open_tgt(&mut f, &tgt, 40, 40);
    let parts = f
        .keyd
        .issue_tgs(&KDC, &SERVICE, &ctx.ctx_id, &tgs_template(40), &now())
        .unwrap();
    assert_eq!(parts.ticket.enc_part.kvno, Some(2));
    assert!(krb_crypto::decrypt(&service_key(), usage(2), &parts.ticket.enc_part.cipher).is_err());
}

/// set_secret derives keys for every configured enctype; each one
/// pre-authenticates. Source: docs/10 §6; RFC 3961 §3; RFC 3962 §4;
/// RFC 8009 §4.
#[test]
fn set_secret_derives_every_configured_enctype() {
    let mut c = config();
    c.enctypes = vec![
        keyd::EncTypeId::Aes256CtsHmacSha196,
        keyd::EncTypeId::Aes128CtsHmacSha196,
        keyd::EncTypeId::Aes128CtsHmacSha256128,
    ];
    let mut f = Fixture::with_config(c);
    for enctype in [
        EncType::Aes256CtsHmacSha196,
        EncType::Aes128CtsHmacSha196,
        EncType::Aes128CtsHmacSha256128,
    ] {
        let key = password_key(enctype, ALICE_PASSWORD, ALICE_SALT);
        assert!(
            f.keyd
                .verify_preauth(
                    &KDC,
                    &ALICE,
                    &pa_enc_timestamp(&key, Some(1), now()),
                    None,
                    &now()
                )
                .is_ok(),
            "{enctype:?}"
        );
    }
}

/// `verify_secret` is in no role's row (A-102; docs/52 §3.4 N3, §7 R4;
/// docs/questions/Q-465): Directory — and every other role — is refused at
/// the capability table, before any key is looked at (even the right
/// password is the uniform Denied, reason RoleNotPermitted). Source:
/// docs/52 §7 R4; docs/questions/Q-465.
#[test]
fn verify_secret_has_no_role() {
    let mut f = Fixture::new();
    for caller in [DIRECTORY, KDC, ADMIN, LDAP] {
        assert_eq!(
            f.keyd
                .verify_secret(&caller, &ALICE, z(ALICE_PASSWORD), &now()),
            Err(Error::Denied)
        );
        let last = f.records().last().unwrap();
        assert_eq!(last.op, keyd::Operation::VerifySecret);
        assert_eq!(last.reason, AuditReason::RoleNotPermitted);
        assert_eq!(last.kvno, None, "no key was looked at");
    }
}

/// keyd chooses the kvno of set_secret (current + 1, or the initial kvno
/// for a new set); krbtgt is never password-derived.
/// Source: docs/10 §6, §12 I3; docs/questions/Q-115 (A-35); RFC 4120 5.2.9.
#[test]
fn set_secret_rules() {
    let mut f = Fixture::new();
    f.grant(&ALICE, &alice_binding(), ALICE_SALT, &now())
        .unwrap();
    assert_eq!(
        f.keyd.set_secret(
            &DIRECTORY,
            &ALICE,
            &alice_binding(),
            z("Russet-Badger-63-Briar"),
            ALICE_SALT,
            &now()
        ),
        Ok(Kvno::new(2))
    );
    let carol = KeyHandle::new(
        PrincipalId::from_bytes([0xCA; 16]),
        KeyPurpose::PrincipalLongterm,
    );
    let carol_binding = bound(PrincipalName {
        name_type: KRB_NT_PRINCIPAL,
        name_string: vec![kstr("carol")],
    });
    f.grant(&carol, &carol_binding, "EXAMPLE.ORGcarol", &now())
        .unwrap();
    assert_eq!(
        f.keyd.set_secret(
            &DIRECTORY,
            &carol,
            &carol_binding,
            z("Russet-Badger-63-Briar"),
            "EXAMPLE.ORGcarol",
            &now()
        ),
        Ok(Kvno::INITIAL)
    );
    assert_eq!(
        f.keyd.set_secret(
            &DIRECTORY,
            &KRBTGT,
            &krbtgt_binding(),
            z("Russet-Badger-63-Briar"),
            "salt",
            &now()
        ),
        Err(Error::Denied)
    );
    assert_eq!(
        f.records().last().unwrap().reason,
        AuditReason::PurposeMismatch
    );
    // The iteration cap applies (RFC 3962 §4): 00 00 00 00 = 2^32 iterations
    // cannot even be configured.
    let mut c = config();
    c.s2k_params = Some([0, 0, 0, 0]);
    assert!(c.validate().is_err());
}

/// Entropy failure fails closed in every operation that needs randomness;
/// keyd never falls back. Source: AGENTS.md §6; RFC 4120 3.1.3.
#[test]
fn entropy_failure_fails_closed() {
    let mut f = Fixture::new();
    let proof = f
        .keyd
        .verify_preauth(
            &KDC,
            &ALICE,
            &pa_enc_timestamp(&alice_key(), Some(1), now()),
            None,
            &now(),
        )
        .unwrap();
    f.entropy.set_fail(true);
    let new_service = KeyHandle::new(PrincipalId::from_bytes([0x5F; 16]), KeyPurpose::Service);
    assert_eq!(
        f.keyd.create_key(
            &ADMIN,
            &new_service,
            &bound(PrincipalName {
                name_type: KRB_NT_PRINCIPAL,
                name_string: vec![kstr("svc-new")],
            }),
            &now()
        ),
        Err(Error::Unavailable)
    );
    assert_eq!(
        f.records().last().unwrap().reason,
        AuditReason::EntropyFailure
    );
    let rotation = f
        .decide(DecidedOperation::RotateKey { handle: SERVICE }, &now())
        .unwrap();
    assert_eq!(
        f.keyd.rotate_key(&ADMIN, rotation, &now()),
        Err(Error::Unavailable)
    );
    assert_eq!(
        f.keyd
            .issue_as(&KDC, &ALICE, &KRBTGT, &proof, None, &as_template(), &now()),
        Err(IssueError::Denied)
    );
    assert_eq!(
        f.records().last().unwrap().reason,
        AuditReason::EntropyFailure
    );
    assert_eq!(
        f.keyd.verify_preauth(
            &KDC,
            &ALICE,
            &pa_enc_timestamp(&alice_key(), Some(1), now()),
            None,
            &now()
        ),
        Err(AuthnError::Denied)
    );
    // Nothing was created or rotated.
    f.entropy.set_fail(false);
    let tgt = obtain_tgt(&mut f, now(), &as_template());
    let ctx = open_tgt(&mut f, &tgt, 50, 50);
    let parts = f
        .keyd
        .issue_tgs(&KDC, &SERVICE, &ctx.ctx_id, &tgs_template(50), &now())
        .unwrap();
    assert!(EncTicketPart::decode(&open(&service_key(), 2, &parts.ticket.enc_part)).is_ok());
}
