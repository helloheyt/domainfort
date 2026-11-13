//! Key lifecycle and secrets: D178 (krbtgt refused by the non-development
//! store), create / rotate / rotate_krbtgt (dual control) / retire_kvno,
//! set_secret / verify_secret (constant-time compare, throttling), and
//! entropy failure (fail closed). Sources: docs/10 §6, §7, §12; docs/33 §5,
//! §6.1; RFC 4120 3.2.3 (ticket decrypted with the kvno it names); AGENTS.md
//! §6. All values are constructed for these tests.

mod common;

use common::*;
use keyd::{
    AuditReason, AuthnError, DualControlToken, Error, InMemoryKeyStore, IssueError, KeyHandle,
    KeyPurpose, Keyd, Kvno, PrincipalBinding, PrincipalId,
};
use krb_crypto::EncType;
use krb_proto::constants::{KRB_NT_PRINCIPAL, KRB_NT_SRV_INST, KRB_NT_UNKNOWN};
use krb_proto::{EncTicketPart, PrincipalName};
use zeroize::Zeroizing;

fn z(s: &str) -> Zeroizing<String> {
    Zeroizing::new(s.to_owned())
}

const APPROVER_1: PrincipalId = PrincipalId::from_bytes([0x01; 16]);
const APPROVER_2: PrincipalId = PrincipalId::from_bytes([0x02; 16]);

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
        keyd.issue_as_rep(&KDC, &ALICE, &KRBTGT, &proof, None, &as_template(), &now()),
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
        .issue_tgs_rep(&KDC, &SERVICE, &ctx.ctx_id, &tgs_template(41), &now())
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
    // set_secret applies the same rules when it creates a key set.
    let carol = KeyHandle::new(
        PrincipalId::from_bytes([0xCA; 16]),
        KeyPurpose::PrincipalLongterm,
    );
    assert_eq!(
        f.keyd.set_secret(
            &DIRECTORY,
            &carol,
            &krbtgt_binding(),
            z("pw"),
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

/// set_secret cannot change the binding of an existing key set (no rename in
/// phase 1); a binding differing only in name-type is the same principal
/// (RFC 4120 6.2) and is accepted, the stored binding staying as created.
/// Source: docs/questions/Q-040 (A-19); RFC 4120 6.2.
#[test]
fn set_secret_cannot_rebind() {
    let mut f = Fixture::new();
    assert_eq!(
        f.keyd.set_secret(
            &DIRECTORY,
            &ALICE,
            &bob_binding(),
            z("pw2"),
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
            .issue_as_rep(&KDC, &ALICE, &KRBTGT, &proof, None, &t, &now()),
        Err(IssueError::Denied)
    );

    let mut same = alice_binding();
    same.name.name_type = KRB_NT_UNKNOWN;
    assert_eq!(
        f.keyd
            .set_secret(&DIRECTORY, &ALICE, &same, z("pw3"), ALICE_SALT, &now()),
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

    let approval = DualControlToken {
        approver_1: APPROVER_1,
        approver_2: APPROVER_2,
    };
    assert_eq!(
        f.keyd.rotate_krbtgt(&ADMIN, &KRBTGT, &approval, &now()),
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
    assert_eq!(
        f.keyd.retire_kvno(&ADMIN, &KRBTGT, Kvno::new(2), &now()),
        Err(Error::Denied)
    );
    assert_eq!(
        f.keyd.retire_kvno(&ADMIN, &KRBTGT, Kvno::new(7), &now()),
        Err(Error::Denied)
    );
    // Retire kvno 1: the old TGT is refused, the new one still works.
    assert_eq!(
        f.keyd.retire_kvno(&ADMIN, &KRBTGT, Kvno::new(1), &now()),
        Ok(())
    );
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
    assert_eq!(
        f.keyd.retire_kvno(&ADMIN, &KRBTGT, Kvno::new(1), &now()),
        Err(Error::Denied)
    );
}

/// A double rotation (compromise recovery) leaves the original kvno out of
/// the decryption set. Source: docs/33 §5 (D20); docs/10 §1.
#[test]
fn double_rotation_drops_original_key() {
    let mut f = Fixture::new();
    let old = obtain_tgt(&mut f, now(), &as_template());
    let approval = DualControlToken {
        approver_1: APPROVER_1,
        approver_2: APPROVER_2,
    };
    f.keyd
        .rotate_krbtgt(&ADMIN, &KRBTGT, &approval, &now())
        .unwrap();
    f.keyd
        .rotate_krbtgt(&ADMIN, &KRBTGT, &approval, &now())
        .unwrap();
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

/// Dual control needs two DISTINCT approvers (keyd checks distinctness only;
/// authenticity is the admin plane's — docs/43 D175). Source: docs/10 §7.
#[test]
fn rotate_krbtgt_requires_distinct_approvers() {
    let mut f = Fixture::new();
    let same = DualControlToken {
        approver_1: APPROVER_1,
        approver_2: APPROVER_1,
    };
    assert_eq!(
        f.keyd.rotate_krbtgt(&ADMIN, &KRBTGT, &same, &now()),
        Err(Error::Denied)
    );
    let last = f.records().last().unwrap();
    assert_eq!(last.reason, AuditReason::DualControlRejected);
    assert_eq!(last.approvers, Some([APPROVER_1, APPROVER_1]));
    // Nothing rotated: TGTs are still sealed under kvno 1.
    let tgt = obtain_tgt(&mut f, now(), &as_template());
    assert_eq!(tgt.parts.ticket.enc_part.kvno, Some(1));
}

/// rotate_key serves service keys (new service tickets use the new kvno);
/// the krbtgt is reachable only through rotate_krbtgt (I3). Source: docs/10
/// §7, §12 I3.
#[test]
fn rotate_service_key() {
    let mut f = Fixture::new();
    assert_eq!(
        f.keyd.rotate_key(&ADMIN, &KRBTGT, &now()),
        Err(Error::Denied)
    );
    assert_eq!(
        f.records().last().unwrap().reason,
        AuditReason::PurposeMismatch
    );
    assert_eq!(
        f.keyd.rotate_key(&ADMIN, &SERVICE, &now()),
        Ok(Kvno::new(2))
    );
    let tgt = obtain_tgt(&mut f, now(), &as_template());
    let ctx = open_tgt(&mut f, &tgt, 40, 40);
    let parts = f
        .keyd
        .issue_tgs_rep(&KDC, &SERVICE, &ctx.ctx_id, &tgs_template(40), &now())
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
        EncType::Aes256CtsHmacSha196,
        EncType::Aes128CtsHmacSha196,
        EncType::Aes128CtsHmacSha256128,
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

/// verify_secret: right password Ok; wrong password, unknown principal and
/// a random (non-password) key are the same uniform Denied. Source: docs/10
/// §6, §9 (uniform), §12 I6.
#[test]
fn verify_secret_outcomes() {
    let mut f = Fixture::new();
    assert_eq!(
        f.keyd
            .verify_secret(&DIRECTORY, &ALICE, z(ALICE_PASSWORD), &now()),
        Ok(())
    );
    assert_eq!(
        f.keyd.verify_secret(&DIRECTORY, &ALICE, z("guess"), &now()),
        Err(Error::Denied)
    );
    assert_eq!(
        f.records().last().unwrap().reason,
        AuditReason::SecretMismatch
    );
    let stranger = KeyHandle::new(
        PrincipalId::from_bytes([0xEE; 16]),
        KeyPurpose::PrincipalLongterm,
    );
    assert_eq!(
        f.keyd
            .verify_secret(&DIRECTORY, &stranger, z(ALICE_PASSWORD), &now()),
        Err(Error::Denied)
    );
    assert_eq!(f.records().last().unwrap().reason, AuditReason::KeyNotFound);
    assert_eq!(
        f.keyd
            .verify_secret(&DIRECTORY, &SERVICE, z(ALICE_PASSWORD), &now()),
        Err(Error::Denied)
    );
    assert_eq!(
        f.records().last().unwrap().reason,
        AuditReason::NoPasswordKey
    );
    // Bob's password does not verify for alice (salted per principal).
    assert_eq!(
        f.keyd
            .verify_secret(&DIRECTORY, &ALICE, z(BOB_PASSWORD), &now()),
        Err(Error::Denied)
    );
}

/// keyd chooses the kvno of set_secret (current + 1, or the initial kvno
/// for a new set); krbtgt is never password-derived.
/// Source: docs/10 §6, §12 I3; docs/questions/Q-115 (A-35); RFC 4120 5.2.9.
#[test]
fn set_secret_rules() {
    let mut f = Fixture::new();
    assert_eq!(
        f.keyd.set_secret(
            &DIRECTORY,
            &ALICE,
            &alice_binding(),
            z("x"),
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
    assert_eq!(
        f.keyd.set_secret(
            &DIRECTORY,
            &carol,
            &carol_binding,
            z("x"),
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
            z("x"),
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

/// verify_secret is throttled: after 5 failures within 5 minutes (default
/// policy) attempts are RateLimited — even with the right password — until
/// the window passes. Source: docs/10 §6 ("throttled"), §9 (RateLimited).
#[test]
fn verify_secret_throttled() {
    let mut f = Fixture::new();
    for _ in 0..5 {
        assert_eq!(
            f.keyd.verify_secret(&DIRECTORY, &ALICE, z("guess"), &now()),
            Err(Error::Denied)
        );
    }
    assert_eq!(
        f.keyd
            .verify_secret(&DIRECTORY, &ALICE, z(ALICE_PASSWORD), &now()),
        Err(Error::RateLimited)
    );
    assert_eq!(f.records().last().unwrap().reason, AuditReason::Throttled);
    // Other principals are unaffected.
    assert_eq!(
        f.keyd
            .verify_secret(&DIRECTORY, &BOB, z(BOB_PASSWORD), &now()),
        Ok(())
    );
    // After the window, the right password verifies again.
    assert_eq!(
        f.keyd
            .verify_secret(&DIRECTORY, &ALICE, z(ALICE_PASSWORD), &at(300)),
        Ok(())
    );
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
    assert_eq!(
        f.keyd.rotate_key(&ADMIN, &SERVICE, &now()),
        Err(Error::Unavailable)
    );
    assert_eq!(
        f.keyd
            .issue_as_rep(&KDC, &ALICE, &KRBTGT, &proof, None, &as_template(), &now()),
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
    assert_eq!(
        f.keyd
            .verify_secret(&DIRECTORY, &ALICE, z(ALICE_PASSWORD), &now()),
        Err(Error::Unavailable)
    );
    // Nothing was created or rotated.
    f.entropy.set_fail(false);
    let tgt = obtain_tgt(&mut f, now(), &as_template());
    let ctx = open_tgt(&mut f, &tgt, 50, 50);
    let parts = f
        .keyd
        .issue_tgs_rep(&KDC, &SERVICE, &ctx.ctx_id, &tgs_template(50), &now())
        .unwrap();
    assert!(EncTicketPart::decode(&open(&service_key(), 2, &parts.ticket.enc_part)).is_ok());
}
