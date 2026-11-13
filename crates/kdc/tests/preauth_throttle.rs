//! The KDC with keyd's `verify_preauth` failure throttle (decision A-34): a
//! throttled pre-authentication is KDC_ERR_PREAUTH_FAILED — the very same
//! KRB-ERROR as a wrong password — so nothing tells the client that the
//! account exists or is under attack; keyd's audit records the throttle.
//!
//! alice is a user, so her guesses are armored encrypted challenges (FAST is
//! mandatory, docs/48 §7, P-10 interim), one armor per attempt (docs/48 §2.3:
//! one pre-authentication attempt per armor); the throttle counts challenge
//! failures exactly as PA-ENC-TIMESTAMP failures (docs/10 §5א, A-34). The
//! test acts as the client (RFC 4120 §3.1; RFC 6113 5.4.6); the passwords and
//! the policy are made up for these tests.

mod common;

use common::*;
use kdc::{AuditOutcome, AuditReason};
use keyd::ThrottlePolicy;
use krb_proto::constants::{KDC_ERR_PREAUTH_FAILED, PA_ETYPE_INFO2, PA_FX_COOKIE, PA_FX_ERROR};
use krb_proto::KerberosTime;

/// An armored AS-REQ for alice with an encrypted challenge under `password`
/// at `when`; the nonce varies so the KDC's retransmission cache never
/// answers it.
fn attempt(f: &mut Fixture, password: &str, nonce: u32, when: KerberosTime) -> FastSent {
    let mut spec = AsReqSpec::alice().with_challenge(&password_key(AES256, password, ALICE_SALT));
    spec.nonce = nonce;
    f.send_fast_at(&spec, kdc::Transport::Tcp, when)
}

/// Three wrong passwords throttle alice in keyd; the fourth request — with
/// the right password — gets KDC_ERR_PREAUTH_FAILED, an armored KRB-ERROR
/// whose content is identical to the wrong-password one (same outer fields,
/// same PA-FX-ERROR, same PA-ETYPE-INFO2 and cookie — only the sealing under
/// each request's own armor key differs); keyd audits `Throttled`. After the
/// window the right password is issued a TGT. The KDC audit event of the
/// throttled request is the same `PreauthDenied` as a wrong password: keyd
/// reports the throttle to the KDC as the uniform `Denied` (A-26), so the
/// KDC cannot audit it apart (docs/questions/Q-128). Source: decision A-34;
/// RFC 4120 3.1.3 (KDC_ERR_PREAUTH_FAILED); RFC 6113 5.4.6; A-26.
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
        let fast = attempt(&mut f, "not-alices-password", 100 + i, now());
        wrong_errors.push(open_fast_error(fast.reply, &fast.armor_key));
    }
    let fast = attempt(&mut f, ALICE_PASSWORD, 100, now());
    let throttled = open_fast_error(fast.reply, &fast.armor_key);
    assert_eq!(throttled.outer.error_code, KDC_ERR_PREAUTH_FAILED);
    // Indistinguishable from a wrong password (same request names, same
    // `now`, same nonce): every field equal but the sealed e-data.
    let reference = &wrong_errors[0];
    assert_eq!(throttled.inner, reference.inner);
    assert_eq!(
        throttled.padata_types(),
        vec![PA_ETYPE_INFO2, PA_FX_COOKIE, PA_FX_ERROR]
    );
    assert_eq!(throttled.response.padata, reference.response.padata);
    assert_eq!(throttled.response.nonce, reference.response.nonce);

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
    let verify = f
        .keyd_records()
        .iter()
        .rev()
        .find(|r| r.op == keyd::Operation::VerifyPreauth)
        .unwrap();
    assert_eq!(verify.reason, keyd::AuditReason::Throttled);
    assert_eq!(verify.result, keyd::AuditOutcome::RateLimited);

    // After the window (60 s after the first failure): issued.
    let later = at(60);
    let key = alice_key(AES256);
    let mut spec = AsReqSpec::alice().with_challenge(&key);
    spec.nonce = 300;
    let fast = f.send_fast_at(&spec, kdc::Transport::Tcp, later);
    let tgt = open_fast_as_rep(&sent(fast.reply), &fast.armor_key, &key);
    assert_eq!(tgt.part.0.nonce, 300);
    assert_eq!(f.events().last().unwrap().reason, AuditReason::Issued);
}
