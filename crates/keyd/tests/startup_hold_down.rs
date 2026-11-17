//! The startup hold-down: after keyd is built, every operation of the
//! Kerberos exchanges is refused as `Unavailable` until `now` is later than
//! the start time plus TWO `clock_skew_secs` intervals (A-62); Directory,
//! Admin, describe_config and ping are not held; a held request leaves no
//! state behind.
//!
//! The tests play the KDC and the client as the other keyd tests do. A
//! "donor" keyd that started a day earlier (the common fixture) issues the
//! tickets a client would present; the keyd under test holds the same keys
//! (the fixture creates them from the same scripted bytes) and starts at the
//! test's `now`. Every value is constructed by hand for these tests; no
//! vector comes from any other implementation.
//!
//! Sources: RFC 4120 §3.2.3 ("If a server loses track of authenticators
//! presented within the allowable clock skew, it MUST reject all requests
//! until the clock skew interval has passed"); docs/50 R50-6, §3.5;
//! docs/questions/Q-217, Q-222 (A-56), Q-240 items 1, 3 (A-62: two
//! intervals — an authenticator accepted just before a restart may carry a
//! client time up to one skew ahead and stays acceptable one skew after
//! that); docs/10 §9, §11, §12 I8.

mod common;

use common::*;
use keyd::authz::startup_hold_down_applies;
use keyd::{
    ArmorId, AuditOutcome, AuditReason, AuthnError, AuthnProof, CtxId, DecidedOperation, Error,
    ExchangeId, FastConversation, IssueError, KeyHandle, KeyPurpose, Kvno, Operation, PrincipalId,
};
use krb_proto::constants::FX_FAST_ARMOR_AP_REQUEST;
use krb_proto::{Checksum, EncryptedData, KerberosTime, KrbFastArmor, KrbFastArmoredReq};
use zeroize::Zeroizing;

/// The default clock skew (RFC 4120 §8.2: 5 minutes; `KeydConfig::new`).
const SKEW: i64 = 300;

/// The hold-down: two skew intervals (A-62).
const HOLD: i64 = 2 * SKEW;

/// A keyd that starts at the test's `now`: held until `now + HOLD`.
fn started_now() -> Fixture {
    Fixture::started(config(), &now())
}

/// The last audit record must be the hold-down refusal of `op`.
fn assert_held(f: &Fixture, op: Operation) {
    let last = f.records().last().unwrap();
    assert_eq!(last.op, op);
    assert_eq!(last.result, AuditOutcome::Unavailable, "{op:?}");
    assert_eq!(last.reason, AuditReason::StartupHoldDown, "{op:?}");
}

/// alice's PA-ENC-TIMESTAMP made at `when` (RFC 4120 5.2.7.2).
fn alice_timestamp(when: KerberosTime) -> krb_proto::PaData {
    pa_enc_timestamp(&alice_key(), Some(1), when)
}

/// The PA-TGS-REQ AP-REQ of alice's TGT with an authenticator made at
/// `ctime` (RFC 4120 5.5.1), and the request body it covers.
fn tgs_ap_req(tgt: &Tgt, ctime: KerberosTime, cusec: u32) -> (krb_proto::ApReq, Vec<u8>) {
    let (_, body) = tgs_req_body(0x7700 + cusec, service_name());
    let auth = authenticator(&tgt.session, &AuthenticatorSpec::new(ctime, cusec, &body));
    (ap_req(&tgt.parts.ticket, auth), body)
}

/// An armored request whose contents do not matter: the hold-down precedes
/// every check of it.
fn any_armored_req() -> KrbFastArmoredReq {
    KrbFastArmoredReq {
        armor: Some(KrbFastArmor {
            armor_type: FX_FAST_ARMOR_AP_REQUEST,
            armor_value: vec![0x30, 0x00],
        }),
        req_checksum: Checksum {
            cksumtype: 16,
            checksum: vec![0x33; 12],
        },
        enc_fast_req: EncryptedData {
            etype: 18,
            kvno: None,
            cipher: vec![0x44; 64],
        },
    }
}

/// Call every held operation at `when` with its permitted role, and check
/// each is refused as `Unavailable` with exactly one hold-down audit record.
/// Valid inputs for the authentication steps (a correct PA-ENC-TIMESTAMP, a
/// valid TGT and authenticator), arbitrary ones elsewhere.
fn every_held_operation_refused_at(f: &mut Fixture, tgt: &Tgt, when: KerberosTime) {
    let before = f.records().len();

    let r = f
        .keyd
        .verify_preauth(&KDC, &ALICE, &alice_timestamp(when), None, &when);
    assert_eq!(r.unwrap_err(), AuthnError::Unavailable);
    assert_held(f, Operation::VerifyPreauth);

    let proof = AuthnProof {
        exchange_id: ExchangeId::from_bytes([3; 16]),
        client: ALICE_ID,
        authtime: when,
    };
    let r = f
        .keyd
        .issue_as(&KDC, &ALICE, &KRBTGT, &proof, None, &as_template(), &when);
    assert_eq!(r.unwrap_err(), IssueError::Unavailable);
    assert_held(f, Operation::IssueAsRep);

    let (req, body) = tgs_ap_req(tgt, when, 1);
    let r = f
        .keyd
        .open_and_verify_tgt(&KDC, &KRBTGT, &req, &body, None, &when);
    assert_eq!(r.unwrap_err(), AuthnError::Unavailable);
    assert_held(f, Operation::OpenAndVerifyTgt);

    let r = f.keyd.issue_tgs(
        &KDC,
        &SERVICE,
        &CtxId::from_bytes([4; 16]),
        &tgs_template(1),
        &when,
    );
    assert_eq!(r.unwrap_err(), IssueError::Unavailable);
    assert_held(f, Operation::IssueTgsRep);

    let r = f
        .keyd
        .open_fast_armor(&KDC, &KRBTGT, &any_armored_req(), &[0x30, 0x00], &when);
    assert_eq!(r.unwrap_err(), AuthnError::Unavailable);
    assert_held(f, Operation::OpenFastArmor);

    let r = f.keyd.seal_fast_error(
        &KDC,
        &FastConversation::As(ArmorId::from_bytes([5; 16])),
        &fast_krb_error(25),
        &[],
        &when,
    );
    assert_eq!(r.unwrap_err(), Error::Unavailable);
    assert_held(f, Operation::SealFastError);

    let r = f
        .keyd
        .open_and_verify_service_ticket(&LDAP, &SERVICE.principal, &[0x30, 0x00], &when);
    assert_eq!(r.unwrap_err(), AuthnError::Unavailable);
    assert_held(f, Operation::OpenAndVerifyServiceTicket);

    // Q-523: the operation-bound verification shares the replay cache.
    let r = f.keyd.verify_operation_ticket(
        &LDAP,
        &SERVICE.principal,
        &keyd::OperationDigest::new([0x0D; 32]),
        &[0x30, 0x00],
        &when,
    );
    assert_eq!(r.unwrap_err(), AuthnError::Unavailable);
    assert_held(f, Operation::VerifyOperationTicket);

    // Task K3 (docs/53 §5.3): the change-password request enters the same
    // replay cache, and its context steps consume a context.
    let r = f.keyd.open_change_password_request(
        &LDAP,
        &SERVICE.principal,
        &[0x30, 0x00],
        &[0x30, 0x00],
        &keyd::HostAddr::ipv4([192, 0, 2, 10]),
        &keyd::HostAddr::ipv4([192, 0, 2, 1]),
        &when,
    );
    assert_eq!(r.unwrap_err(), AuthnError::Unavailable);
    assert_held(f, Operation::OpenChangePasswordRequest);
    let r = f.keyd.complete_change_password(
        &LDAP,
        &keyd::ChangePasswordCtxId::from_bytes([7; 16]),
        &ALICE,
        &when,
    );
    assert_eq!(r.unwrap_err(), Error::Unavailable);
    assert_held(f, Operation::CompleteChangePassword);
    let r = f.keyd.seal_change_password_error(
        &LDAP,
        &keyd::ChangePasswordCtxId::from_bytes([7; 16]),
        krb_proto::NonZeroResultCode::HardError,
        &when,
    );
    assert_eq!(r.unwrap_err(), Error::Unavailable);
    assert_held(f, Operation::SealChangePasswordError);

    // Exactly one record per call (I8), and every held operation was called.
    assert_eq!(f.records().len() - before, 11);
    for op in Operation::ALL {
        if startup_hold_down_applies(op) {
            assert!(
                f.records()[before..].iter().any(|r| r.op == op),
                "{op:?} not exercised"
            );
        }
    }
}

/// RFC 4120 §3.2.3 / docs/50 R50-6 / A-62: from the start time to the last
/// second of the second clock-skew interval, every operation of the Kerberos
/// exchanges — valid inputs included — is refused as `Unavailable`, audited
/// `StartupHoldDown`.
#[test]
fn every_held_operation_is_unavailable_inside_the_window() {
    let mut donor = Fixture::new();
    let tgt = obtain_tgt(&mut donor, now(), &as_template());
    let mut f = started_now();
    every_held_operation_refused_at(&mut f, &tgt, now());
    every_held_operation_refused_at(&mut f, &tgt, at(120));
    every_held_operation_refused_at(&mut f, &tgt, at(SKEW));
    every_held_operation_refused_at(&mut f, &tgt, at(SKEW + 1));
    every_held_operation_refused_at(&mut f, &tgt, at(HOLD));
}

/// The boundary is exact (A-62): `start + 2·skew` is still held — an
/// authenticator keyd accepted just before the start may carry a client time
/// up to `start + skew` and passes keyd's inclusive skew check until
/// `start + 2·skew` — and `start + 2·skew + 1` is served: the same valid
/// requests now succeed.
#[test]
fn the_boundary_is_exact() {
    let mut donor = Fixture::new();
    let tgt = obtain_tgt(&mut donor, now(), &as_template());
    let mut f = started_now();

    let held = at(HOLD);
    let served = at(HOLD + 1);
    assert_eq!(
        f.keyd
            .verify_preauth(&KDC, &ALICE, &alice_timestamp(held), None, &held)
            .unwrap_err(),
        AuthnError::Unavailable
    );
    assert!(f
        .keyd
        .verify_preauth(&KDC, &ALICE, &alice_timestamp(served), None, &served)
        .is_ok());

    let (req, body) = tgs_ap_req(&tgt, held, 2);
    assert_eq!(
        f.keyd
            .open_and_verify_tgt(&KDC, &KRBTGT, &req, &body, None, &held)
            .unwrap_err(),
        AuthnError::Unavailable
    );
    let (req, body) = tgs_ap_req(&tgt, served, 3);
    let ctx = f
        .keyd
        .open_and_verify_tgt(&KDC, &KRBTGT, &req, &body, None, &served)
        .unwrap();
    let template = keyd::TgsTicketTemplate {
        starttime: Some(served),
        ..tgs_template(0x7700 + 3)
    };
    assert!(f
        .keyd
        .issue_tgs(&KDC, &SERVICE, &ctx.ctx_id, &template, &served)
        .is_ok());
}

/// The window is two `clock_skew_secs` intervals of the configuration in
/// force (here one minute each), measured from the start time the caller
/// passed (A-62).
#[test]
fn the_window_is_twice_the_configured_clock_skew() {
    let mut c = config();
    c.clock_skew_secs = 60;
    let mut f = Fixture::started(c, &now());
    for (offset, held) in [
        (0, true),
        (60, true),
        (61, true),
        (119, true),
        (120, true),
        (121, false),
    ] {
        let when = at(offset);
        let r = f
            .keyd
            .verify_preauth(&KDC, &ALICE, &alice_timestamp(when), None, &when);
        assert_eq!(
            r.err() == Some(AuthnError::Unavailable),
            held,
            "offset {offset}"
        );
    }
    // Started at another time: the window moves with it.
    let mut f = Fixture::started(config(), &at(-1000));
    let when = at(-1000 + HOLD + 1);
    assert!(f
        .keyd
        .verify_preauth(&KDC, &ALICE, &alice_timestamp(when), None, &when)
        .is_ok());
}

/// A `now` before the start (a clock stepped back) is held: the elapsed time
/// cannot be established (fail closed, docs/CLEAN-ROOM.md).
#[test]
fn a_clock_before_the_start_is_held() {
    let mut f = started_now();
    let when = at(-1);
    assert_eq!(
        f.keyd
            .verify_preauth(&KDC, &ALICE, &alice_timestamp(when), None, &when)
            .unwrap_err(),
        AuthnError::Unavailable
    );
    assert_held(&f, Operation::VerifyPreauth);
}

/// A-56 ("decided before any secret-dependent work, so it is no oracle"): a
/// wrong and a right PA-ENC-TIMESTAMP get the same answer and the same audit
/// record, and held requests touch no state — six wrong passwords late in
/// the window do not count towards the failure throttle (A-34: five per
/// 300-second window, which would still be open right after the hold-down),
/// and an authenticator presented inside the window is not in the replay
/// cache afterwards.
#[test]
fn held_requests_are_decided_before_any_secret_and_leave_no_state() {
    let mut donor = Fixture::new();
    let tgt = obtain_tgt(&mut donor, now(), &as_template());
    let mut f = started_now();

    let wrong_key = password_key(
        krb_crypto::EncType::Aes256CtsHmacSha196,
        "not alice's password",
        ALICE_SALT,
    );
    let mut answers = Vec::new();
    for i in 0..6 {
        let when = at(HOLD - 50 + i);
        answers.push(f.keyd.verify_preauth(
            &KDC,
            &ALICE,
            &pa_enc_timestamp(&wrong_key, Some(1), when),
            None,
            &when,
        ));
        assert_held(&f, Operation::VerifyPreauth);
        let wrong_record = f.records().last().unwrap().clone();
        answers.push(
            f.keyd
                .verify_preauth(&KDC, &ALICE, &alice_timestamp(when), None, &when),
        );
        // The right password's record is the wrong one's, field for field.
        assert_eq!(f.records().last().unwrap(), &wrong_record);
    }
    assert!(answers.iter().all(|a| a == &Err(AuthnError::Unavailable)));

    // An authenticator made at +500 is presented inside the window.
    let (req, body) = tgs_ap_req(&tgt, at(HOLD - 100), 9);
    assert_eq!(
        f.keyd
            .open_and_verify_tgt(&KDC, &KRBTGT, &req, &body, None, &at(HOLD - 100))
            .unwrap_err(),
        AuthnError::Unavailable
    );

    // After the window: the throttle never counted the held failures ...
    let served = at(HOLD + 1);
    assert!(f
        .keyd
        .verify_preauth(&KDC, &ALICE, &alice_timestamp(served), None, &served)
        .is_ok());
    // ... and the held authenticator was never recorded: it is accepted
    // once (still within the skew of its ctime), then it is a replay.
    assert!(f
        .keyd
        .open_and_verify_tgt(&KDC, &KRBTGT, &req, &body, None, &served)
        .is_ok());
    assert_eq!(
        f.keyd
            .open_and_verify_tgt(&KDC, &KRBTGT, &req, &body, None, &at(HOLD + 2))
            .unwrap_err(),
        AuthnError::Replay
    );
}

/// docs/50 §3.5 ("Directory/Admin are not dependent on the replay cache and
/// are allowed") and Q-240 item 1 (describe_config, ping): inside the window
/// every Directory, Admin and daemon-support operation is served.
#[test]
fn directory_admin_and_daemon_support_operations_are_not_held() {
    let mut f = started_now();
    let n = now();
    let h = KeyHandle::new(PrincipalId::from_bytes([0x66; 16]), KeyPurpose::Service);
    let h_binding = bound(krb_proto::PrincipalName {
        name_type: krb_proto::constants::KRB_NT_PRINCIPAL,
        name_string: vec![kstr("svc-66")],
    });
    assert_eq!(
        f.keyd.create_key(&ADMIN, &h, &h_binding, &n),
        Ok(Kvno::new(1))
    );
    // A-102: the decisions dird registers, and their executions, are not
    // held either.
    let rotation = f
        .decide(DecidedOperation::RotateKey { handle: h }, &at(10))
        .unwrap();
    assert_eq!(
        f.keyd.rotate_key(&ADMIN, rotation, &at(10)),
        Ok(Kvno::new(2))
    );
    let retirement = f
        .decide(
            DecidedOperation::RetireKvno {
                handle: h,
                kvno: Kvno::new(1),
            },
            &at(20),
        )
        .unwrap();
    assert_eq!(f.keyd.retire_kvno(&ADMIN, retirement, &at(20)), Ok(()));
    let krbtgt_rotation = f
        .decide(DecidedOperation::RotateKrbtgt { krbtgt: KRBTGT }, &at(30))
        .unwrap();
    assert_eq!(
        f.keyd.rotate_krbtgt(&ADMIN, krbtgt_rotation, &at(30)),
        Ok(Kvno::new(2))
    );
    let destroy = f
        .decide(
            DecidedOperation::DestroyKeySet {
                principal: h.principal,
            },
            &at(40),
        )
        .unwrap();
    assert_eq!(f.keyd.destroy_key_set(&ADMIN, destroy, &at(40)), Ok(()));
    assert!(f.keyd.list_destroy_decisions(&ADMIN, None, &at(40)).is_ok());
    // The set_secret decision (task A15a) is not held either.
    assert_eq!(f.grant(&BOB, &bob_binding(), BOB_SALT, &at(50)), Ok(()));
    assert_eq!(
        f.keyd.set_secret(
            &DIRECTORY,
            &BOB,
            &bob_binding(),
            Zeroizing::new("Ginger-Hemlock-35-Jasper".to_owned()),
            BOB_SALT,
            &at(50),
        ),
        Ok(Kvno::new(2))
    );
    // The seal (A-102) is not held.
    assert_eq!(f.keyd.seal_ceremony(&ADMIN, &at(60)), Ok(()));
    assert!(f.keyd.describe_config(&KDC, &at(70)).is_ok());
    assert!(f.keyd.describe_config(&LDAP, &at(70)).is_ok());
    for caller in [KDC, DIRECTORY, ADMIN, LDAP] {
        assert_eq!(f.keyd.ping(&caller, &at(80)), Ok(()));
    }
    assert!(f
        .records()
        .iter()
        .all(|r| r.result == AuditOutcome::Success && r.reason == AuditReason::None));
}

/// The role and purpose checks come first (docs/10 §2, I2, I3): inside the
/// window an unauthorized call is still `Denied` for its own reason, not
/// `Unavailable`.
#[test]
fn authorization_precedes_the_hold_down() {
    let mut f = started_now();
    let n = now();
    assert_eq!(
        f.keyd
            .verify_preauth(&ADMIN, &ALICE, &alice_timestamp(n), None, &n)
            .unwrap_err(),
        AuthnError::Denied
    );
    assert_eq!(
        f.records().last().unwrap().reason,
        AuditReason::RoleNotPermitted
    );
    assert_eq!(
        f.keyd
            .verify_preauth(&KDC, &SERVICE, &alice_timestamp(n), None, &n)
            .unwrap_err(),
        AuthnError::Denied
    );
    assert_eq!(
        f.records().last().unwrap().reason,
        AuditReason::PurposeMismatch
    );
}
