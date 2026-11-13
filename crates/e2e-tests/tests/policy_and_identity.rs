//! Task P12 scenarios 5 and 6 (docs/50 §9 tier 2 across all daemons).
//!
//! **5. Policy-version agreement** (docs/50 R50-2, §3.4, §7.2; A-68, A-69):
//! the kdc and dird load the same policy file and must agree on its
//! version — a kdc whose file is another version than the running dird's
//! does not start; dird restarted on another version under a running kdc
//! makes every request 29 (TCP) / silence (UDP) until it is back on the
//! kdc's version (no reload, Q-275 item 7).
//!
//! **6. Identity** (docs/50 R50-3, §3.2: a caller's identity comes only from
//! the peer credentials, through each server's `uid → Role` table):
//! a channel cross-wired at runtime is closed or refused, and the client is
//! never issued a ticket — a keyd that no longer gives the kdc's uid the
//! Kdc role is 29 like any keyd that does not serve, never 24 (Q-311, A-82)
//! — the Ldap role included (Q-351, A-87).
//! Every first request after a server was replaced is decided by the new
//! process (Q-312, A-82). Only what the per-daemon tests do not already
//! cover is added here — each server's refusal is seen **through the whole
//! chain, by the client** (the kdc's 29, ldap-front's notice), with the
//! other daemons running:
//!
//! | test | cross-wiring | seen by the client |
//! |---|---|---|
//! | `keyd_not_mapping_the_kdcs_uid_…` | keyd's map names another uid as Kdc | 29 / silence |
//! | `the_kdc_does_not_start_…` | keyd maps the kdc's uid to Directory, then to Ldap, at the kdc's start | the kdc refuses to start |
//! | `keyd_giving_the_kdcs_uid_another_role_…` | keyd maps the kdc's uid to Directory under a running kdc | 29 / silence, never 24; keyd's records: refused `DescribeConfig`s only (Q-311) |
//! | `keyd_giving_the_kdcs_uid_the_ldap_role_…` | the same with Ldap, which may call `DescribeConfig` | 29 / silence, never 24; keyd's records: `DescribeConfig`s of the Ldap caller only (Q-351) |
//! | `dird_kdc_channel_for_another_uid_…` | dird's kdc channel for another uid | 29 / silence; LDAP unaffected |
//! | `dird_ldap_channel_for_another_uid_…` | dird's LDAP channel for another uid | the notice, close; Kerberos unaffected |
//! | `auditd_not_mapping_the_senders_…` | auditd's map names another uid | 29 / silence, the notice; auditd's own record of the refused uid |
//!
//! Already covered per daemon (and not repeated): keyd closes an unmapped
//! uid with no reply and answers a wrong role keyd's uniform `Denied`
//! (crates/keyd-daemon tests/socket_server.rs); keyd, dird and the kdc
//! refuse an auditd of the wrong uid at start (socket_server.rs,
//! crates/directory-daemon tests/view_service.rs, crates/kdc-daemon
//! tests/listeners.rs); dird closes a peer that is not the kdc on
//! `dird-kdc.sock` (view_service.rs) and one that is not the front on
//! `dird-ldap.sock` (crates/directory-daemon tests/ldap_service.rs); auditd
//! closes an unmapped uid and records the summary (crates/audit-daemon
//! tests/tier2_socket.rs); the keyd, directory and LDAP clients refuse a
//! server of another uid (`PeerMismatch`: crates/ipc-keyd-server
//! tests/unix_socket.rs, crates/ipc-directory tests/client.rs, crates/
//! ipc-ldap tests/front.rs); ldap-front refuses to start without auditd or
//! dird (crates/ldap-front tests/front.rs).
//!
//! Sources: docs/50 R50-2, R50-3, R50-8, §3.2, §3.4, §3.7, §7.2, §7.5, §8.1;
//! docs/10 §2 (I2: keyd's capability table decides); RFC 4120 §7.5.9; RFC
//! 4511 §4.4.1; A-57, A-60, A-62, A-68, A-69, A-70; docs/questions/Q-311,
//! Q-312 (A-82), Q-351 (A-87). Every value is made here.

#[path = "../../kdc/tests/common/mod.rs"]
mod common;
mod support;

use audit_daemon::own_event::{AUDITD_EVENT_FORMAT, KIND_PEERS_REFUSED, PEERS_REFUSED_LEN};
use audit_log::Source;
use ipc_audit::{EventBody, KeydOperation, KeydOutcome, KeydReason, KeydRole};
use keyd::Role;
use keyd_daemon::CallerMap;
use krb_proto::constants::{KDC_ERR_PREAUTH_REQUIRED, KDC_ERR_SVC_UNAVAILABLE};
use parse_ldap::ResultCode;
use support::kdcd::{alice_probe, bootstrap};
use support::ldap_client::notice;
use support::probes::*;
use support::*;

const UNAVAILABLE: KdcAnswer = KdcAnswer::Error(KDC_ERR_SVC_UNAVAILABLE);
const PREAUTH_REQUIRED: KdcAnswer = KdcAnswer::Error(KDC_ERR_PREAUTH_REQUIRED);

/// A uid distinct from the test's (never 0).
fn another_uid(h: &Harness) -> u32 {
    support::auditd::other_uid(&[h.uid])
}

// ---- 5. policy-version agreement --------------------------------------------------

/// docs/50 R50-2 ("if the `policy_version` dird returned ≠ the version of
/// the kdc's `PolicySnapshot` ⇒ fail closed"), §7.2 (the same file), §7.5
/// (exit on any start-up failure); A-68, A-69: with auditd, keyd and dird
/// (policy version 7) running, a kdc whose policy file is version 8 does
/// not start; on version 7 it starts, ldap-front after it, and the
/// bootstrap is issued.
#[test]
fn a_kdc_on_another_policy_version_does_not_start() {
    within(TEST_BOUND, || {
        let Some(mut h) = Harness::fixtures() else {
            return;
        };
        h.start_auditd();
        h.start_keyd_serving().unwrap();
        h.start_dird().unwrap();
        let other = h.policy_file("policy-8.store", POLICY_VERSION + 1);
        let refused = h.start_kdc_with(&other).expect_err("refused to start");
        assert!(
            refused.contains("policy version mismatch") && refused.contains('8'),
            "{refused}"
        );
        assert!(h.kdcd.is_none());
        h.start_kdc().expect("the same version starts");
        h.start_front().unwrap();
        assert!(bootstrap_issued(&h, 1));
        h.stop_all();
    });
}

/// docs/50 R50-2, §3.4 (the version of every view), §3.7; Q-275 item 7 (no
/// reload); A-69: dird restarted on policy version 8 under the kdc on
/// version 7 ⇒ 29 over TCP and silence over UDP (the view's version is
/// refused, before keyd is asked); dird back on version 7 ⇒ served again.
#[test]
fn dird_on_another_policy_version_makes_the_kdc_answer_29() {
    within(TEST_BOUND, || {
        let Some(mut h) = Harness::start() else {
            return;
        };
        assert_eq!(kdc_tcp(&h, &alice_probe(1)), PREAUTH_REQUIRED);
        h.stop_dird();
        let other = h.policy_file("policy-8.store", POLICY_VERSION + 1);
        let uid = h.uid;
        h.start_dird_with(&other, uid, uid).unwrap();
        // The first request after each restart is decided by the dird now
        // running (docs/questions/Q-312; Q-311: the new connection's
        // `DescribeDomain` carries the policy version).
        assert_eq!(kdc_tcp(&h, &alice_probe(2)), UNAVAILABLE);
        assert_eq!(kdc_udp(&h, &alice_probe(3)), None, "silence over UDP");
        assert_eq!(kdc_tcp(&h, &bootstrap(4)), UNAVAILABLE);
        h.stop_dird();
        h.start_dird().unwrap();
        assert_eq!(
            kdc_tcp(&h, &alice_probe(5)),
            PREAUTH_REQUIRED,
            "the first request after dird is back on version 7"
        );
        assert!(bootstrap_issued(&h, 6));
        h.stop_all();
    });
}

// ---- 6. identity ------------------------------------------------------------------

/// docs/50 R50-3, §3.2 ("an unmapped uid ⇒ the connection is closed"), §3.7
/// (R50-8); RFC 4120 §7.5.9: keyd restarted with a map that names another
/// uid as the Kdc — the kdc's connection (the test's uid) is closed with no
/// reply, which the kdc answers 29 over TCP and silence over UDP; keyd
/// restarted with the right map ⇒ served again.
#[test]
fn keyd_not_mapping_the_kdcs_uid_is_closed_and_the_kdc_answers_29() {
    within(TEST_BOUND, || {
        let Some(mut h) = Harness::start() else {
            return;
        };
        assert!(bootstrap_issued(&h, 1));
        h.stop_keyd();
        let other = CallerMap::new(&[(another_uid(&h), Role::Kdc)]).unwrap();
        h.start_keyd(other, common::keyd_started()).unwrap();
        h.keyd_clock.set(common::now());
        assert_eq!(kdc_tcp(&h, &bootstrap(2)), UNAVAILABLE);
        assert_eq!(kdc_udp(&h, &bootstrap(3)), None, "silence over UDP");
        h.stop_keyd();
        h.start_keyd_serving().unwrap();
        // The first request after the restart (docs/questions/Q-312).
        assert!(bootstrap_issued(&h, 4), "served with the right map");
        h.stop_all();
    });
}

/// docs/50 R50-3, §3.2, §7.5 step 4 (`DescribeConfig` from keyd before the
/// listeners are served); docs/10 §2 (I2: keyd's capability table is the
/// PEP): keyd's map gives the kdc's uid the Directory role — the kdc's
/// `DescribeConfig` is refused and the kdc does not start.
#[test]
fn the_kdc_does_not_start_when_keyd_gives_its_uid_another_role() {
    within(TEST_BOUND, || {
        let Some(mut h) = Harness::fixtures() else {
            return;
        };
        h.start_auditd();
        let directory = CallerMap::new(&[(h.uid, Role::Directory)]).unwrap();
        h.start_keyd(directory, common::keyd_started()).unwrap();
        h.keyd_clock.set(common::now());
        h.start_dird().unwrap();
        let refused = h.start_kdc().expect_err("refused to start");
        assert!(refused.contains("keyd not verified"), "{refused}");
        // Q-351 (A-87): Ldap may call DescribeConfig, and keyd answers it —
        // naming the caller role Ldap, which the kdc's client refuses.
        h.stop_keyd();
        let ldap = CallerMap::new(&[(h.uid, Role::Ldap)]).unwrap();
        h.start_keyd(ldap, common::keyd_started()).unwrap();
        h.keyd_clock.set(common::now());
        let refused = h.start_kdc().expect_err("refused to start (Ldap)");
        assert!(refused.contains("keyd not verified"), "{refused}");
        h.stop_all();
    });
}

/// docs/50 R50-3, R50-8, §3.2, §3.4 (`DescribeConfig` — Kdc, Ldap), §3.7,
/// §7.5 step 4; docs/10 §2 (I2), §9; RFC 4120 §7.5.9; docs/questions/Q-311
/// (A-82): keyd restarted under the running kdc with the kdc's uid mapped
/// to the Directory role. The kdc's new keyd connection carries only its
/// `DescribeConfig` check, which keyd refuses, so the connection is dropped
/// and the bootstrap is answered KDC_ERR_SVC_UNAVAILABLE (29) over TCP and
/// with silence over UDP — never KDC_ERR_PREAUTH_FAILED (24), what a wrong
/// password looks like. keyd's own records of the attempts are refused
/// `DescribeConfig`s of the Directory caller (one per request: a new
/// connection each time), and keyd ran no operation of the exchange for
/// it. keyd back with the right map ⇒ the first request is issued.
#[test]
fn keyd_giving_the_kdcs_uid_another_role_at_runtime_is_29_not_24() {
    within(TEST_BOUND, || {
        let Some(mut h) = Harness::start() else {
            return;
        };
        assert!(bootstrap_issued(&h, 1));
        h.stop_keyd();
        let directory = CallerMap::new(&[(h.uid, Role::Directory)]).unwrap();
        h.start_keyd(directory, common::keyd_started()).unwrap();
        h.keyd_clock.set(common::now());
        assert_eq!(kdc_tcp(&h, &bootstrap(2)), UNAVAILABLE, "29, not 24");
        assert_eq!(kdc_udp(&h, &bootstrap(3)), None, "silence over UDP");
        assert_eq!(kdc_tcp(&h, &bootstrap(4)), UNAVAILABLE);
        h.stop_keyd();
        h.start_keyd_serving().unwrap();
        assert!(bootstrap_issued(&h, 5), "the right map: served at once");
        h.stop_all();

        let directory_records: Vec<_> = h
            .audit_events()
            .into_iter()
            .filter_map(|event| match event {
                EventBody::Keyd(record) if record.caller_role == KeydRole::Directory => {
                    Some(*record)
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            directory_records.len(),
            3,
            "one DescribeConfig per request: {directory_records:?}"
        );
        for record in &directory_records {
            assert_eq!(record.op, KeydOperation::DescribeConfig);
            assert_eq!(record.caller_uid, h.uid);
            assert_eq!(record.result, KeydOutcome::Denied);
            assert_eq!(record.reason, KeydReason::RoleNotPermitted);
        }
    });
}

/// docs/50 R50-3, R50-8, §3.2, §3.4 (`DescribeConfig` — Kdc, **Ldap**),
/// §3.7; docs/10 §2 (I2), §9; RFC 4120 §7.5.9; docs/questions/Q-351 (A-87:
/// keyd's `DescribeConfig` reply carries the caller's role as keyd resolved
/// it, and the kdc's client requires `Kdc`): keyd restarted under the
/// running kdc with the kdc's uid mapped to the **Ldap** role — the one
/// other role that may call `DescribeConfig`. keyd answers each new
/// connection's check, naming the caller role Ldap; the kdc's client drops
/// the connection, so the bootstrap is answered KDC_ERR_SVC_UNAVAILABLE (29)
/// over TCP and with silence over UDP — never the KDC_ERR_PREAUTH_FAILED
/// (24) that keyd's `Denied` of `verify_preauth` would have become. keyd's
/// own records of the attempts are `DescribeConfig`s of the Ldap caller
/// (one per request), and keyd ran no operation of the exchange. keyd back
/// with the right map ⇒ the first request is issued.
#[test]
fn keyd_giving_the_kdcs_uid_the_ldap_role_at_runtime_is_29_not_24() {
    within(TEST_BOUND, || {
        let Some(mut h) = Harness::start() else {
            return;
        };
        assert!(bootstrap_issued(&h, 1));
        h.stop_keyd();
        let ldap = CallerMap::new(&[(h.uid, Role::Ldap)]).unwrap();
        h.start_keyd(ldap, common::keyd_started()).unwrap();
        h.keyd_clock.set(common::now());
        assert_eq!(kdc_tcp(&h, &bootstrap(2)), UNAVAILABLE, "29, not 24");
        assert_eq!(kdc_udp(&h, &bootstrap(3)), None, "silence over UDP");
        assert_eq!(kdc_tcp(&h, &bootstrap(4)), UNAVAILABLE);
        h.stop_keyd();
        h.start_keyd_serving().unwrap();
        assert!(bootstrap_issued(&h, 5), "the right map: served at once");
        h.stop_all();

        let ldap_records: Vec<_> = h
            .audit_events()
            .into_iter()
            .filter_map(|event| match event {
                EventBody::Keyd(record) if record.caller_role == KeydRole::Ldap => Some(*record),
                _ => None,
            })
            .collect();
        assert_eq!(
            ldap_records.len(),
            3,
            "one DescribeConfig per request: {ldap_records:?}"
        );
        for record in &ldap_records {
            assert_eq!(record.op, KeydOperation::DescribeConfig);
            assert_eq!(record.caller_uid, h.uid);
            assert_eq!(record.result, KeydOutcome::Success);
        }
    });
}

/// docs/50 R50-3, §3.2 ("dird-kdc.sock ← the kdc's uid only"), §3.7: dird
/// restarted with its kdc channel for another uid — the kdc's view
/// connection is closed, which the kdc answers 29 over TCP and silence over
/// UDP; the LDAP channel (still the front's uid) keeps serving.
#[test]
fn dird_kdc_channel_for_another_uid_is_closed_and_the_kdc_answers_29() {
    within(TEST_BOUND, || {
        let Some(mut h) = Harness::start() else {
            return;
        };
        assert_eq!(kdc_tcp(&h, &alice_probe(1)), PREAUTH_REQUIRED);
        h.stop_dird();
        let (policy, uid, other) = (h.paths.policy.clone(), h.uid, another_uid(&h));
        h.start_dird_with(&policy, other, uid).unwrap();
        assert_eq!(kdc_tcp(&h, &alice_probe(2)), UNAVAILABLE);
        assert_eq!(kdc_udp(&h, &alice_probe(3)), None, "silence over UDP");
        assert!(
            matches!(ldaps_root_dse(&h), LdapAnswer::Served(r) if r.len() == 2),
            "the LDAP channel is unaffected"
        );
        h.stop_all();
    });
}

/// docs/50 R50-3, §3.2 ("dird-ldap.sock ← ldap-front"), §3.7 ("ldap-front
/// without dird ⇒ the connection is closed (no answer without a PEP)"); RFC
/// 4511 §4.4.1: dird restarted with its LDAP channel for another uid — the
/// front's dird connection is closed, so an LDAPS client gets the Notice of
/// Disconnection (unavailable) and is closed, and a new cleartext connection
/// too; the kdc (still the kdc's uid) keeps issuing.
#[test]
fn dird_ldap_channel_for_another_uid_is_closed_and_the_front_sends_its_notice() {
    within(TEST_BOUND, || {
        let Some(mut h) = Harness::start() else {
            return;
        };
        assert!(matches!(ldaps_root_dse(&h), LdapAnswer::Served(_)));
        h.stop_dird();
        let (policy, uid, other) = (h.paths.policy.clone(), h.uid, another_uid(&h));
        h.start_dird_with(&policy, uid, other).unwrap();
        let unavailable = notice(ResultCode::Unavailable);
        assert_eq!(
            ldaps_root_dse(&h),
            LdapAnswer::NoticeThenClosed(unavailable.clone())
        );
        assert_eq!(ldap_first_words(&h), Some(unavailable));
        // The kdc's first request since dird was replaced (Q-312).
        assert!(bootstrap_issued(&h, 1), "the kdc channel is unaffected");
        h.stop_all();
    });
}

/// docs/50 R50-3, §3.2 ("auditd: every service uid … an unmapped uid ⇒ the
/// connection is closed + an audit record"), §8.1; A-57 (no unaudited
/// issuance), A-70: auditd restarted with a map that names another uid —
/// every sender's connection is closed, so the kdc answers 29 over TCP and
/// silence over UDP and the front's clients get the notice; after
/// everything stopped, the log verifies and holds auditd's own summary of
/// the refused connections naming the test's uid.
#[test]
fn auditd_not_mapping_the_senders_is_closed_and_nothing_is_issued() {
    within(TEST_BOUND, || {
        let Some(mut h) = Harness::start() else {
            return;
        };
        assert!(bootstrap_issued(&h, 1));
        h.stop_auditd();
        let other = another_uid(&h);
        h.start_auditd_mapping(other);

        let mut nonce = 100u32;
        assert!(
            eventually(LONG, || {
                nonce += 1;
                kdc_tcp(&h, &bootstrap(nonce)) == UNAVAILABLE
            }),
            "the kdc's gate closed"
        );
        nonce += 1;
        assert_eq!(kdc_udp(&h, &bootstrap(nonce)), None, "silence over UDP");
        let unavailable = notice(ResultCode::Unavailable);
        assert!(
            eventually(LONG, || {
                ldaps_root_dse(&h) == LdapAnswer::NoticeThenClosed(unavailable.clone())
            }),
            "no LDAP operation"
        );
        h.stop_all();

        let (_, records) = h.verified_audit_log().expect("the log verifies");
        let refused = records.iter().any(|record| {
            let payload = &record.payload;
            record.source == Source::Auditd
                && payload.len() == PEERS_REFUSED_LEN
                && payload[0] == AUDITD_EVENT_FORMAT
                && payload[1] == KIND_PEERS_REFUSED
                && u64::from_be_bytes(payload[2..10].try_into().unwrap()) > 0
                && u32::from_be_bytes(payload[18..22].try_into().unwrap()) == h.uid
        });
        assert!(
            refused,
            "auditd recorded the refused connections of the test's uid"
        );
    });
}
