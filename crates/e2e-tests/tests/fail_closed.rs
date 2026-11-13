//! Task P12 scenario 4 (docs/50 §3.7 "keyd (or dird) down — fail closed",
//! R50-8; §9 tier 2 across all daemons): one daemon of the running
//! deployment is stopped, and every path through it fails closed; started
//! again, service resumes — for keyd only after its startup hold-down.
//!
//! * **keyd** stopped ⇒ the kdc answers KDC_ERR_SVC_UNAVAILABLE (29) over
//!   TCP and stays silent over UDP (never a "wrong password" code — A-56,
//!   A-62); keyd started again ⇒ still 29 / silence through its hold-down
//!   of two clock-skew intervals (RFC 4120 §3.2.3; R50-6; A-62), decided on
//!   **keyd's own injected clock** (R50-5): 29 at S and at S + 600 s, served
//!   at S + 601 s;
//! * **dird** stopped ⇒ the kdc answers 29 / silence; ldap-front answers an
//!   open session's next request with a Notice of Disconnection
//!   (unavailable, RFC 4511 §4.4.1) and closes, and a new connection gets
//!   the notice and is closed; dird started again ⇒ both serve again;
//! * **auditd** stopped ⇒ no ticket is issued (29 over TCP, silence over
//!   UDP — A-57: "no unaudited issuance") and no LDAP operation is
//!   performed (the notice, then close — A-70); auditd started again (its
//!   log verified at start) ⇒ both serve again, and the log still verifies
//!   as one chain.
//!
//! Sources: docs/50 R50-5, R50-6, R50-8, §3.5, §3.7, §4.3, §7.5, §8.1;
//! RFC 4120 §3.2.3, §7.2.1, §7.2.2, §7.5.9; RFC 4511 §4.4.1; A-56, A-57,
//! A-62, A-64, A-66, A-70. Every value is made here.

#[path = "../../kdc/tests/common/mod.rs"]
mod common;
mod support;

use common::at;
use krb_proto::constants::{KDC_ERR_PREAUTH_REQUIRED, KDC_ERR_SVC_UNAVAILABLE};
use parse_ldap::ResultCode;
use std::io::Write;
use support::kdcd::{alice_probe, bootstrap};
use support::ldap_client::{closed, notice, root_dse, tcp, tls_over, LdapReader};
use support::probes::*;
use support::*;

const UNAVAILABLE: KdcAnswer = KdcAnswer::Error(KDC_ERR_SVC_UNAVAILABLE);

/// docs/50 §3.7, R50-8; RFC 4120 §3.2.3, §7.5.9 (29); R50-5, R50-6; A-56,
/// A-62: keyd stopped under the running kdc ⇒ 29 over TCP, silence over
/// UDP; keyd started again with its clock at S = now − 600 s ⇒ 29 / silence
/// at S and at S + 600 s (the last second of 2 × 300 s), and the bootstrap
/// is issued at S + 601 s. The kdc's own clock reads `now` throughout — it
/// does not decide the hold-down.
#[test]
fn keyd_down_then_back_only_after_its_hold_down() {
    within(TEST_BOUND, || {
        let Some(mut h) = Harness::start() else {
            return;
        };
        assert!(bootstrap_issued(&h, 10), "served before the stop");

        h.stop_keyd();
        assert_eq!(kdc_tcp(&h, &bootstrap(11)), UNAVAILABLE);
        assert_eq!(kdc_udp(&h, &bootstrap(12)), None, "silence over UDP");

        let callers = h.kdc_callers();
        h.start_keyd(callers, at(-600)).expect("keyd starts again");
        // The first request after the restart is decided by the new keyd —
        // its hold-down — (docs/questions/Q-312: no stale connection is
        // ever reused).
        assert_eq!(kdc_tcp(&h, &bootstrap(13)), UNAVAILABLE, "hold-down at S");
        assert_eq!(kdc_udp(&h, &bootstrap(14)), None, "hold-down at S, UDP");
        h.keyd_clock.set(at(0));
        assert_eq!(
            kdc_tcp(&h, &bootstrap(15)),
            UNAVAILABLE,
            "hold-down at S + 2·skew"
        );
        h.keyd_clock.set(at(1));
        assert!(bootstrap_issued(&h, 16), "served after the hold-down");
        h.stop_all();
    });
}

/// docs/50 §3.7 ("dird down ⇒ `AccountSourceError`"; "ldap-front without
/// dird ⇒ the connection is closed (no answer without a PEP)"), R50-8; RFC
/// 4120 §7.5.9; RFC 4511 §4.4.1 (Notice of Disconnection, unavailable 52):
/// dird stopped ⇒ the kdc answers 29 / silence, an open LDAPS session's next
/// request gets the notice and is closed, and a new cleartext connection
/// gets the notice and is closed; dird started again (its own file, key and
/// policy file read again) ⇒ the kdc and the front serve again.
#[test]
fn dird_down_then_back() {
    within(TEST_BOUND, || {
        let Some(mut h) = Harness::start() else {
            return;
        };
        assert_eq!(
            kdc_tcp(&h, &alice_probe(20)),
            KdcAnswer::Error(KDC_ERR_PREAUTH_REQUIRED),
            "the directory answers before the stop"
        );
        let mut session = tls_over(tcp(h.front().ldaps), &h.tls_client).unwrap();
        session.write_all(&root_dse(1)).unwrap();
        let mut reader = LdapReader::default();
        let _entry = reader.next(&mut session).unwrap();
        let _done = reader.next(&mut session).unwrap();

        h.stop_dird();
        assert_eq!(kdc_tcp(&h, &alice_probe(21)), UNAVAILABLE);
        assert_eq!(kdc_udp(&h, &alice_probe(22)), None, "silence over UDP");

        let unavailable = notice(ResultCode::Unavailable);
        session.write_all(&root_dse(2)).unwrap();
        assert_eq!(reader.next(&mut session), Some(unavailable.clone()));
        assert_eq!(closed(&mut session), Ok(()), "closed after the notice");
        assert_eq!(
            ldap_first_words(&h),
            Some(unavailable),
            "a new connection: the notice"
        );

        h.start_dird().expect("dird starts again");
        assert_eq!(
            kdc_tcp(&h, &alice_probe(23)),
            KdcAnswer::Error(KDC_ERR_PREAUTH_REQUIRED),
            "the kdc reaches the directory again"
        );
        assert!(bootstrap_issued(&h, 24));
        assert!(matches!(ldaps_root_dse(&h), LdapAnswer::Served(r) if r.len() == 2));
        h.stop_all();
    });
}

/// docs/50 §8.1, R50-17; docs/questions/Q-218 (A-57: "no unaudited
/// issuance"), Q-252 item 8 (A-64), A-66, A-70: auditd stopped ⇒ once the
/// senders notice (their heartbeat), no ticket is issued — 29 over TCP,
/// silence over UDP — and no LDAP operation is performed (the notice, then
/// close); auditd started again on the same log (verified at start) ⇒ the
/// kdc issues and the front serves again, and after everything stopped the
/// log verifies as one chain from genesis across the restart.
#[test]
fn auditd_down_then_back() {
    within(TEST_BOUND, || {
        let Some(mut h) = Harness::start() else {
            return;
        };
        assert!(bootstrap_issued(&h, 30), "served before the stop");
        assert!(matches!(ldaps_root_dse(&h), LdapAnswer::Served(_)));
        h.stop_auditd();
        let records_before = {
            // The log as auditd left it (it is stopped): verified.
            h.verified_audit_log().expect("the log verifies").1.len()
        };

        let mut nonce = 100u32;
        assert!(
            eventually(LONG, || {
                nonce += 1;
                kdc_tcp(&h, &bootstrap(nonce)) == UNAVAILABLE
            }),
            "the kdc's gate closed"
        );
        for _ in 0..3 {
            nonce += 1;
            assert_eq!(kdc_tcp(&h, &bootstrap(nonce)), UNAVAILABLE);
            nonce += 1;
            assert_eq!(kdc_udp(&h, &bootstrap(nonce)), None, "silence over UDP");
        }
        let unavailable = notice(ResultCode::Unavailable);
        assert!(
            eventually(LONG, || {
                ldaps_root_dse(&h) == LdapAnswer::NoticeThenClosed(unavailable.clone())
            }),
            "no LDAP operation without auditd"
        );

        h.start_auditd();
        let mut nonce = 200u32;
        assert!(
            eventually(LONG, || {
                nonce += 1;
                bootstrap_issued(&h, nonce)
            }),
            "issued again once auditd is back"
        );
        assert!(
            eventually(LONG, || matches!(ldaps_root_dse(&h), LdapAnswer::Served(_))),
            "LDAP served again once auditd is back"
        );
        h.stop_all();
        let (_, records) = h
            .verified_audit_log()
            .expect("one chain across the restart");
        assert!(
            records.len() > records_before,
            "the restarted auditd appended"
        );
    });
}
