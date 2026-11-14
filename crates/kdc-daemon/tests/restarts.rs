//! Tier 2 (docs/50 §9: real sockets, the whole stack — the real keyd
//! daemon, the real dird, the kdc daemon): keyd or dird replaced under the
//! running kdc, the two defects of docs/questions/Q-311 and Q-312 (A-82).
//!
//! * **Q-312** — the kdc holds idle connections to keyd and dird; when the
//!   server is restarted while the kdc sends nothing, the **first** request
//!   afterwards is served by the new process (the clients check a held
//!   connection before reusing it and open a fresh one first).
//! * **Q-311** — keyd restarted with the kdc's uid mapped to another role:
//!   the kdc's new connection fails its `DescribeConfig` check, is dropped,
//!   and the request is answered KDC_ERR_SVC_UNAVAILABLE (29) over TCP and
//!   with silence over UDP — never KDC_ERR_PREAUTH_FAILED (24); no keyd
//!   operation runs for it.
//! * **Q-351** (A-87) — the same when that role is **Ldap**, which may call
//!   `DescribeConfig`: keyd answers it, naming the caller role Ldap, and the
//!   kdc's client refuses that answer.
//!
//! Sources: docs/50 R50-3, R50-6, R50-8, §3.2, §3.4, §3.6, §3.7, §7.5 step
//! 4; docs/10 §2; RFC 4120 §7.5.9 ("24 KDC_ERR_PREAUTH_FAILED", "29
//! KDC_ERR_SVC_UNAVAILABLE"); A-56, A-62; docs/questions/Q-311, Q-312
//! (A-82), Q-351 (A-87). Every value is hand-made.

#[path = "../../kdc/tests/common/mod.rs"]
mod common;
mod support;

use common::{machine_key, open_as_rep, AES256};
use core::time::Duration;
use ipc_audit::{EventBody, KeydOperation, KeydOutcome, KeydRole};
use keyd::Role;
use keyd_daemon::CallerMap;
use krb_proto::constants::{
    KDC_ERR_PREAUTH_FAILED, KDC_ERR_PREAUTH_REQUIRED, KDC_ERR_SVC_UNAVAILABLE,
};
use support::*;

const SHORT: Duration = Duration::from_millis(800);
const LONG: Duration = Duration::from_secs(10);

/// Start keyd again on the stack's socket with `callers`, past its
/// hold-down (started a day before `now`, its clock then moved to `now` —
/// R50-6, A-62 — as `Stack::start` does).
fn restart_keyd(stack: &mut Stack, callers: CallerMap) {
    let params = keyd_support::params(&stack.dir, callers, stack.uid);
    assert_eq!(params.keyd_socket, stack.keyd_socket);
    let clock = TestClock::at(common::keyd_started());
    let handles = stack.handles;
    let keyd = keyd_support::Daemon::start(params, clock.clone(), move |started| {
        directory_keyd(started, handles)
    })
    .unwrap();
    clock.set(common::now());
    stack.keyd = Some(keyd);
}

/// Start dird again on the stack's directory with policy version 7.
fn restart_dird(stack: &mut Stack) {
    stack.dird = Some(
        dird::Dird::start(
            support::stack_dird_params(&stack.dir, stack.uid),
            directory_daemon::test_seams::opened(std::sync::Arc::clone(&stack.directory.store)),
            shared_policy(7, vec![common::allow_kerberos()]),
        )
        .unwrap(),
    );
}

/// The computer's bootstrap over TCP was issued (its AS-REP opens with the
/// computer's key, RFC 4120 §3.1.5).
fn issued(stack: &Stack, nonce: u32) -> bool {
    match tcp_send(stack.kdcd().tcp, &bootstrap(nonce)) {
        TcpReply::Message(reply) if reply.first() == Some(&0x6B) => {
            let _ = open_as_rep(&reply, &machine_key(AES256));
            true
        }
        _ => false,
    }
}

/// keyd's records delivered to its auditd so far.
fn keyd_records(stack: &Stack) -> Vec<ipc_audit::KeydRecord> {
    stack
        .keyd_auditd
        .events()
        .into_iter()
        .filter_map(|event| match event {
            EventBody::Keyd(record) => Some(*record),
            _ => None,
        })
        .collect()
}

/// docs/50 §3.6, §3.7; Q-312 (A-82): keyd stopped and started again (past
/// its hold-down) while the kdc sent nothing — the kdc's connection to the
/// old keyd was idle — and the very first bootstrap afterwards is issued.
#[test]
fn the_first_request_after_keyd_is_restarted_is_served() {
    let Some(mut stack) = Stack::start(7, 7, |_| {}).unwrap() else {
        return;
    };
    assert!(issued(&stack, 1));
    stack.keyd.take().unwrap().stop().unwrap();
    let callers = CallerMap::new(&[(stack.uid, Role::Kdc)]).unwrap();
    restart_keyd(&mut stack, callers);
    assert!(issued(&stack, 2), "the first request after the restart");
    assert!(issued(&stack, 3));
    stack.stop();
}

/// docs/50 §3.6, §3.7; Q-312 (A-82): dird stopped and started again while
/// the kdc sent nothing; the very first request afterwards reaches the new
/// dird (alice's PREAUTH_REQUIRED, RFC 4120 §3.1.3), and the bootstrap is
/// issued.
#[test]
fn the_first_request_after_dird_is_restarted_is_served() {
    let Some(mut stack) = Stack::start(7, 7, |_| {}).unwrap() else {
        return;
    };
    let tcp = stack.kdcd().tcp;
    assert_eq!(
        error_code(&message(tcp_send(tcp, &alice_probe(1)))),
        KDC_ERR_PREAUTH_REQUIRED
    );
    stack.dird.take().unwrap().stop().unwrap();
    restart_dird(&mut stack);
    assert_eq!(
        error_code(&message(tcp_send(tcp, &alice_probe(2)))),
        KDC_ERR_PREAUTH_REQUIRED,
        "the first request after the restart"
    );
    assert!(issued(&stack, 3));
    stack.stop();
}

/// docs/50 R50-3, R50-8, §3.4 (`DescribeConfig` — Kdc, Ldap), §3.7, §7.5
/// step 4; docs/10 §2; RFC 4120 §7.5.9; Q-311 (A-82): keyd restarted under
/// the running kdc with the kdc's uid mapped to the Directory role. Each
/// request's new keyd connection carries only `DescribeConfig`, which keyd
/// refuses (Denied, for the Directory caller); the connection is dropped —
/// the next request opens another — and the client gets 29 over TCP and
/// silence over UDP, never 24; keyd ran no operation of the exchange. keyd
/// back with the right map ⇒ the first request is issued.
#[test]
fn keyd_restarted_with_the_kdcs_uid_in_another_role_answers_29_never_24() {
    keyd_restarted_with_the_kdcs_uid_as(Role::Directory, KeydRole::Directory, KeydOutcome::Denied);
}

/// docs/50 R50-3, R50-8, §3.2, §3.4 (`DescribeConfig` — Kdc, **Ldap**),
/// §3.7; docs/10 §2; RFC 4120 §7.5.9; Q-351 (A-87: "the kdc's client
/// requires Role::Kdc"): keyd restarted under the running kdc with the
/// kdc's uid mapped to the **Ldap** role, which may call `DescribeConfig`.
/// keyd answers each new connection's `DescribeConfig` (Success) naming the
/// caller role Ldap; the kdc's client refuses that answer and drops the
/// connection, so the client gets 29 over TCP and silence over UDP — never
/// the 24 that keyd's `Denied` of `verify_preauth` (Ldap may not call it)
/// would have become; keyd ran no operation of the exchange.
#[test]
fn keyd_restarted_with_the_kdcs_uid_as_ldap_answers_29_never_24() {
    keyd_restarted_with_the_kdcs_uid_as(Role::Ldap, KeydRole::Ldap, KeydOutcome::Success);
}

/// keyd restarted with the kdc's uid mapped to `role`; three bootstraps
/// (TCP, UDP, TCP) are 29 / silence / 29, keyd's records since the restart
/// are three `DescribeConfig`s of `recorded` with `outcome` and nothing
/// else; keyd back with the Kdc map ⇒ issued at once.
fn keyd_restarted_with_the_kdcs_uid_as(role: Role, recorded: KeydRole, outcome: KeydOutcome) {
    let Some(mut stack) = Stack::start(7, 7, |_| {}).unwrap() else {
        return;
    };
    assert!(issued(&stack, 1));
    stack.keyd.take().unwrap().stop().unwrap();
    let before = keyd_records(&stack).len();
    let cross_wired = CallerMap::new(&[(stack.uid, role)]).unwrap();
    restart_keyd(&mut stack, cross_wired);

    let tcp = message(tcp_send(stack.kdcd().tcp, &bootstrap(2)));
    assert_eq!(error_code(&tcp), KDC_ERR_SVC_UNAVAILABLE);
    assert!(!is_error(&tcp, KDC_ERR_PREAUTH_FAILED));
    assert_eq!(udp_send(stack.kdcd().udp, &bootstrap(3), SHORT), None);
    assert_eq!(
        error_code(&message(tcp_send(stack.kdcd().tcp, &bootstrap(4)))),
        KDC_ERR_SVC_UNAVAILABLE
    );

    // keyd's own records of the attempts: one DescribeConfig per request —
    // a new connection each time — and nothing else.
    let since = |stack: &Stack| keyd_records(stack).split_off(before);
    assert!(
        eventually(LONG, || since(&stack).len() >= 3),
        "keyd recorded the three DescribeConfigs"
    );
    std::thread::sleep(Duration::from_millis(300));
    let records = since(&stack);
    assert_eq!(records.len(), 3, "{records:?}");
    for record in &records {
        assert_eq!(record.op, KeydOperation::DescribeConfig);
        assert_eq!(record.caller_role, recorded);
        assert_eq!(record.caller_uid, stack.uid);
        assert_eq!(record.result, outcome);
    }

    stack.keyd.take().unwrap().stop().unwrap();
    let kdc = CallerMap::new(&[(stack.uid, Role::Kdc)]).unwrap();
    restart_keyd(&mut stack, kdc);
    assert!(issued(&stack, 5), "the right map: served at once");
    stack.stop();
}
