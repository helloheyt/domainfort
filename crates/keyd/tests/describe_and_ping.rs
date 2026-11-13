//! The daemon-support operations of docs/50 §3.4: `describe_config` (roles
//! Kdc and Ldap; the non-secret configuration, no key material) and `ping`
//! (every role) — each with exactly one audit record.
//!
//! Sources: docs/50 §3.4 (`DescribeConfig`: "realm, enctypes,
//! clock_skew_secs, token_lifetime_secs, ticket_policy"; `Ping`: "every
//! mapped Role"), §7.5; docs/47 §7.3 (R47-10: realm, enctypes, s2kparams
//! shared with the directory); docs/10 §2, §10, §12 I1, I2, I8;
//! docs/questions/Q-240 item 2. Every value is constructed by hand for these
//! tests; no vector comes from any other implementation.

mod common;

use common::*;
use keyd::{AuditOutcome, AuditReason, CallerId, ConfigDescription, EncTypeId, Error, Operation};

/// The last audit record: `op` by `caller`, with `result` / `reason`, and no
/// key reference (neither operation takes a handle).
fn assert_record(f: &Fixture, op: Operation, caller: &CallerId, result: AuditOutcome) {
    let last = f.records().last().unwrap();
    assert_eq!(last.op, op);
    assert_eq!(last.caller_role, caller.role);
    assert_eq!(last.caller_uid, caller.uid);
    assert_eq!(last.result, result);
    assert_eq!(last.principal, None);
    assert_eq!(last.purpose, None);
    assert_eq!(last.kvno, None);
    assert_eq!(last.secondary, None);
    assert_eq!(last.approvers, None);
    if result == AuditOutcome::Success {
        assert_eq!(last.reason, AuditReason::None);
    }
}

/// docs/50 §3.4: describe_config returns exactly the non-secret fields of the
/// configuration in force — the docs/50 list plus the string-to-key
/// parameters (Q-240 item 2) — to Kdc and Ldap, one audit record each.
#[test]
fn describe_config_returns_the_non_secret_configuration() {
    let mut c = config();
    c.enctypes = vec![
        EncTypeId::Aes256CtsHmacSha196,
        EncTypeId::Aes128CtsHmacSha196,
    ];
    c.clock_skew_secs = 240;
    c.token_lifetime_secs = 20;
    c.s2k_params = Some([0x00, 0x00, 0x80, 0x00]);
    c.ticket_policy.max_lifetime_secs = 10 * 60 * 60;
    let mut f = Fixture::with_config(c.clone());
    for caller in [KDC, LDAP] {
        let before = f.records().len();
        let d = f.keyd.describe_config(&caller, &now()).unwrap();
        assert_eq!(f.records().len(), before + 1);
        assert_record(
            &f,
            Operation::DescribeConfig,
            &caller,
            AuditOutcome::Success,
        );
        // Exhaustive destructuring: a field added to ConfigDescription does
        // not compile here until this test decides about it.
        let ConfigDescription {
            realm: d_realm,
            enctypes,
            clock_skew_secs,
            token_lifetime_secs,
            ticket_policy,
            s2k_params,
        } = d.clone();
        assert_eq!(d_realm, realm());
        assert_eq!(
            enctypes,
            [
                EncTypeId::Aes256CtsHmacSha196,
                EncTypeId::Aes128CtsHmacSha196
            ]
        );
        assert_eq!(clock_skew_secs, 240);
        assert_eq!(token_lifetime_secs, 20);
        assert_eq!(ticket_policy, c.ticket_policy);
        assert_eq!(s2k_params, Some([0x00, 0x00, 0x80, 0x00]));
        assert_eq!(d, c.description());
    }
}

/// docs/50 §3.4 / docs/10 §2 (I2): Directory and Admin may not call
/// describe_config — `Denied`, audited RoleNotPermitted, one record each.
#[test]
fn describe_config_is_refused_to_other_roles() {
    let mut f = Fixture::new();
    for caller in [DIRECTORY, ADMIN] {
        let before = f.records().len();
        assert_eq!(f.keyd.describe_config(&caller, &now()), Err(Error::Denied));
        assert_eq!(f.records().len(), before + 1);
        assert_record(&f, Operation::DescribeConfig, &caller, AuditOutcome::Denied);
        assert_eq!(
            f.records().last().unwrap().reason,
            AuditReason::RoleNotPermitted
        );
    }
}

/// docs/50 §3.4 ("every mapped Role"), §7.5: ping answers every role, one
/// audit record each.
#[test]
fn ping_answers_every_role() {
    let mut f = Fixture::new();
    for caller in [KDC, DIRECTORY, ADMIN, LDAP] {
        let before = f.records().len();
        assert_eq!(f.keyd.ping(&caller, &now()), Ok(()));
        assert_eq!(f.records().len(), before + 1);
        assert_record(&f, Operation::Ping, &caller, AuditOutcome::Success);
    }
}

/// docs/10 I1 ("no operation returns long-term key bytes"): the description
/// carries none of keyd's keys — the krbtgt and service keys, alice's
/// password-derived key — in any rendering of its Debug output.
#[test]
fn describe_config_carries_no_key_material() {
    let mut f = Fixture::new();
    let d = f.keyd.describe_config(&KDC, &now()).unwrap();
    let text = format!("{d:?}");
    let alice = alice_key();
    for secret in [&KRBTGT_KEY[..], &SERVICE_KEY[..], alice.octets()] {
        let head = &secret[..4];
        for rendering in [
            format!("{}, {}, {}, {}", head[0], head[1], head[2], head[3]),
            format!(
                "{:02x}{:02x}{:02x}{:02x}",
                head[0], head[1], head[2], head[3]
            ),
        ] {
            assert!(!text.contains(&rendering), "{rendering}");
        }
    }
}
