//! The per-principal failure throttle of `verify_preauth` (decision A-34):
//! the `verify_secret` mechanism (bounded, self-expiring window, fail closed
//! when full) applied to the AS pre-authentication, checked before any
//! secret work, counting only failures of the cryptographic check, cleared
//! by a success, and surfacing as the uniform `AuthnError::Denied` (A-26).
//! The test acts as the client (PA-ENC-TIMESTAMP, RFC 4120 §5.2.7.2); the
//! passwords and policies are made up for these tests.

mod common;

use common::*;
use keyd::{AuditOutcome, AuditReason, AuthnError, KeydConfig, Operation, ThrottlePolicy};
use krb_crypto::EncType;
use krb_proto::{KerberosTime, PaData};

/// Three crypto failures per 60-second window; room for `capacity`
/// principals.
fn throttled_config(capacity: usize) -> KeydConfig {
    let mut c = config();
    c.preauth_throttle = ThrottlePolicy {
        max_failures: 3,
        window_secs: 60,
        capacity,
    };
    c
}

/// A PA-ENC-TIMESTAMP under a key derived from a wrong password: it does not
/// decrypt under alice's key (the counted failure).
fn wrong_timestamp(when: KerberosTime) -> PaData {
    let wrong = password_key(
        EncType::Aes256CtsHmacSha196,
        "not alice's password",
        ALICE_SALT,
    );
    pa_enc_timestamp(&wrong, Some(1), when)
}

fn alice_timestamp(when: KerberosTime) -> PaData {
    pa_enc_timestamp(&alice_key(), Some(1), when)
}

fn preauth(f: &mut Fixture, padata: &PaData, when: KerberosTime) -> Result<(), AuthnError> {
    f.keyd
        .verify_preauth(&KDC, &ALICE, padata, &when)
        .map(|_| ())
}

/// N wrong passwords throttle the principal: the next attempt — with the
/// CORRECT password — is refused as the uniform `Denied`, audited as
/// `Throttled`; after the window it is accepted. Source: decision A-34;
/// docs/10 §6 ("throttled"), §9; A-26 (a pre-chain refusal is uniform).
#[test]
fn wrong_passwords_throttle_even_the_right_one() {
    let mut f = Fixture::with_config(throttled_config(8));
    for i in 0..3 {
        assert_eq!(
            preauth(&mut f, &wrong_timestamp(at(i)), at(i)),
            Err(AuthnError::Denied)
        );
        assert_eq!(
            f.records().last().unwrap().reason,
            AuditReason::IntegrityFailure
        );
    }
    assert_eq!(
        preauth(&mut f, &alice_timestamp(at(10)), at(10)),
        Err(AuthnError::Denied)
    );
    let record = f.records().last().unwrap();
    assert_eq!(record.op, Operation::VerifyPreauth);
    assert_eq!(record.reason, AuditReason::Throttled);
    assert_eq!(record.result, AuditOutcome::RateLimited);
    // Decided before any secret work: no key version was resolved.
    assert_eq!(record.kvno, None);

    // The window ends 60 s after the first failure.
    assert_eq!(
        preauth(&mut f, &alice_timestamp(at(59)), at(59)),
        Err(AuthnError::Denied)
    );
    assert!(preauth(&mut f, &alice_timestamp(at(60)), at(60)).is_ok());
}

/// The throttle is per principal: alice's failures do not affect bob.
/// Source: decision A-34 ("per-principal"); docs/10 §6.
#[test]
fn throttle_is_per_principal() {
    let mut f = Fixture::with_config(throttled_config(8));
    for i in 0..3 {
        let _ = preauth(&mut f, &wrong_timestamp(at(i)), at(i));
    }
    let bob = pa_enc_timestamp(
        &password_key(EncType::Aes256CtsHmacSha196, BOB_PASSWORD, BOB_SALT),
        Some(1),
        at(5),
    );
    assert!(f.keyd.verify_preauth(&KDC, &BOB, &bob, &at(5)).is_ok());
    assert_eq!(
        preauth(&mut f, &alice_timestamp(at(5)), at(5)),
        Err(AuthnError::Denied)
    );
}

/// Bounded and fail closed: while the table is full of live windows, an
/// untracked principal is refused (even with the right password) rather
/// than escaping the throttle; once the windows expire there is room again.
/// Source: decision A-34 ("bounded table, fail closed when full");
/// AGENTS.md §6.
#[test]
fn full_throttle_table_fails_closed() {
    let mut f = Fixture::with_config(throttled_config(1));
    let _ = preauth(&mut f, &wrong_timestamp(now()), now());
    let bob = |when| {
        pa_enc_timestamp(
            &password_key(EncType::Aes256CtsHmacSha196, BOB_PASSWORD, BOB_SALT),
            Some(1),
            when,
        )
    };
    assert_eq!(
        f.keyd.verify_preauth(&KDC, &BOB, &bob(at(1)), &at(1)),
        Err(AuthnError::Denied)
    );
    assert_eq!(f.records().last().unwrap().reason, AuditReason::Throttled);
    assert!(f
        .keyd
        .verify_preauth(&KDC, &BOB, &bob(at(60)), &at(60))
        .is_ok());
}

/// Only failures of the cryptographic check count: skewed timestamps (which
/// decrypted), undecodable padata and an unknown kvno never throttle; and a
/// success clears the count, as in `verify_secret`. Source: decision A-34
/// ("count only failures decided by the crypto check"; success semantics of
/// verify_secret); A-26.
#[test]
fn only_crypto_failures_count_and_success_clears() {
    let mut f = Fixture::with_config(throttled_config(8));
    for i in 0..5 {
        assert_eq!(
            preauth(&mut f, &alice_timestamp(at(-400)), at(i)),
            Err(AuthnError::Skew)
        );
        let garbage = PaData {
            padata_type: 2,
            padata_value: vec![0x30, 0x00],
        };
        assert_eq!(preauth(&mut f, &garbage, at(i)), Err(AuthnError::Denied));
        let wrong_kvno = pa_enc_timestamp(&alice_key(), Some(9), at(i));
        assert_eq!(preauth(&mut f, &wrong_kvno, at(i)), Err(AuthnError::Denied));
    }
    assert!(preauth(&mut f, &alice_timestamp(at(6)), at(6)).is_ok());

    // Two failures, a success (clears), two more failures: still admitted.
    for i in 10..12 {
        let _ = preauth(&mut f, &wrong_timestamp(at(i)), at(i));
    }
    assert!(preauth(&mut f, &alice_timestamp(at(12)), at(12)).is_ok());
    for i in 13..15 {
        let _ = preauth(&mut f, &wrong_timestamp(at(i)), at(i));
    }
    assert!(preauth(&mut f, &alice_timestamp(at(15)), at(15)).is_ok());
}

/// The default policy throttles too (no configuration needed): after five
/// wrong passwords in five minutes the right one is refused. Source:
/// decision A-34; keyd `ThrottlePolicy::default` (5 failures / 300 s).
#[test]
fn default_policy_throttles() {
    let mut f = Fixture::new();
    for i in 0..5 {
        let _ = preauth(&mut f, &wrong_timestamp(at(i)), at(i));
    }
    assert_eq!(
        preauth(&mut f, &alice_timestamp(at(5)), at(5)),
        Err(AuthnError::Denied)
    );
    assert_eq!(f.records().last().unwrap().reason, AuditReason::Throttled);
}
