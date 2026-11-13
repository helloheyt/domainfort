//! The KDC with keyd's `verify_preauth` failure throttle (decision A-34): a
//! throttled pre-authentication is KDC_ERR_PREAUTH_FAILED — the very same
//! KRB-ERROR as a wrong password — so nothing tells an unauthenticated
//! client that the account exists or is under attack; keyd's audit records
//! the throttle. The test acts as the client (RFC 4120 §3.1, §5.2.7.2); the
//! passwords and the policy are made up for these tests.

mod common;

use common::*;
use kdc::{AuditOutcome, AuditReason};
use keyd::ThrottlePolicy;
use krb_proto::constants::KDC_ERR_PREAUTH_FAILED;
use krb_proto::{AsRep, KerberosTime};

/// An AS-REQ for alice with a PA-ENC-TIMESTAMP under `password` at `when`;
/// the nonce varies so the KDC's retransmission cache never answers it.
fn as_req(password: &str, nonce: u32, when: KerberosTime) -> Vec<u8> {
    let mut spec = AsReqSpec::alice();
    spec.nonce = nonce;
    spec.padata = Some(vec![pa_enc_timestamp(
        &password_key(AES256, password, ALICE_SALT),
        when,
    )]);
    spec.encode()
}

/// Three wrong passwords throttle alice in keyd; the fourth request — with
/// the right password — gets KDC_ERR_PREAUTH_FAILED, a KRB-ERROR identical
/// to the wrong-password one; keyd audits `Throttled`. After the window the
/// right password is issued a TGT. The KDC audit event of the throttled
/// request is the same `PreauthDenied` as a wrong password: keyd reports the
/// throttle to the KDC as the uniform `Denied` (A-26), so the KDC cannot
/// audit it apart (docs/questions/Q-128). Source: decision A-34; RFC 4120
/// 3.1.3 (KDC_ERR_PREAUTH_FAILED); A-26.
#[test]
fn throttled_preauth_is_preauth_failed() {
    let mut setup = Setup::new();
    setup.keyd.preauth_throttle = ThrottlePolicy {
        max_failures: 3,
        window_secs: 60,
        capacity: 16,
    };
    let mut f = setup.build();

    let mut wrong_errors = Vec::new();
    for i in 0..3u32 {
        let reply = f.send(&as_req("not-alices-password", 100 + i, now()));
        wrong_errors.push(error_of(reply));
    }
    let throttled = error_of(f.send(&as_req(ALICE_PASSWORD, 200, now())));
    assert_eq!(throttled.error_code, KDC_ERR_PREAUTH_FAILED);
    // Indistinguishable from a wrong password (same request names, same
    // `now`): every field equal, no e-data, no e-text.
    assert_eq!(throttled, wrong_errors[0]);

    let events = f.events();
    assert_eq!(events.len(), 4);
    for event in events {
        assert_eq!(
            event.outcome,
            AuditOutcome::Refused {
                error_code: KDC_ERR_PREAUTH_FAILED
            }
        );
        assert_eq!(event.reason, AuditReason::PreauthDenied);
    }
    let keyd_record = f.keyd_records().last().unwrap();
    assert_eq!(keyd_record.reason, keyd::AuditReason::Throttled);
    assert_eq!(keyd_record.result, keyd::AuditOutcome::RateLimited);

    // After the window (60 s after the first failure): issued.
    let later = at(60);
    let reply = sent(f.send_at(
        &as_req(ALICE_PASSWORD, 300, later),
        kdc::Transport::Tcp,
        later,
    ));
    assert!(AsRep::decode(&reply).is_ok());
    assert_eq!(f.events().last().unwrap().reason, AuditReason::Issued);
}
