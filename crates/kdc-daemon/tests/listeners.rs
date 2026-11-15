//! Tier 2 (docs/50 §9: real sockets — UDP / TCP on loopback, Unix sockets
//! in a temporary directory): the kdc daemon's listeners, limits, queues,
//! dependencies and start-up checks, each against the whole stack (real
//! keyd daemon, real dird, the kdc daemon).
//!
//! Sources (each test names its own): RFC 4120 §3.1.2, §5.1.4, §7.2.1,
//! §7.2.2, §7.5.9 (codes 29, 52, 60, 61); docs/50 R50-2, R50-8, R50-9,
//! R50-16, §3.7, §4.1, §7.2, §7.5; docs/07 §1; docs/questions/Q-218 (A-57),
//! Q-223 (A-57), Q-252 item 8 (A-64), A-68. Every value is hand-made.

#[path = "../../kdc/tests/common/mod.rs"]
mod common;
mod support;

use common::{machine_key, open_as_rep, AES256};
use core::time::Duration;
use ipc_audit::EventBody;
use krb_proto::constants::{
    KDC_ERR_PREAUTH_REQUIRED, KDC_ERR_SVC_UNAVAILABLE, KRB_ERR_FIELD_TOOLONG,
    KRB_ERR_RESPONSE_TOO_BIG,
};
use support::*;

const SHORT: Duration = Duration::from_millis(800);
const LONG: Duration = Duration::from_secs(5);

/// RFC 4120 §7.2.2: a length with the reserved high bit set — "MUST return a
/// KRB-ERROR message with the error KRB_ERR_FIELD_TOOLONG and MUST close the
/// TCP stream"; a length above the KDC's bound — the same (§7.5.9 "Field is
/// too long for this implementation"); a record that stops short — closed
/// without a reply once the frame deadline passes (docs/50 §4.1); a
/// malformed but complete record — a KRB-ERROR, and the stream stays open
/// for the next request (§7.2.2: "MAY leave the stream open").
#[test]
fn tcp_framing_follows_rfc_4120_7_2_2() {
    let Some(stack) = Stack::start(7, 7, |_| {}).unwrap() else {
        return;
    };
    let kdc = stack.kdcd().tcp;

    let mut reserved = tcp_connect(kdc);
    tcp_raw(&mut reserved, &[0x80, 0, 0, 5, 1, 2, 3, 4, 5]);
    assert_eq!(
        error_code(&message(read_record(&mut reserved))),
        KRB_ERR_FIELD_TOOLONG
    );
    assert!(is_closed(&mut reserved, LONG));

    let mut oversize = tcp_connect(kdc);
    let length = u32::try_from(kdc::MAX_REQUEST_LEN + 1).unwrap();
    tcp_raw(&mut oversize, &length.to_be_bytes());
    assert_eq!(
        error_code(&message(read_record(&mut oversize))),
        KRB_ERR_FIELD_TOOLONG
    );
    assert!(is_closed(&mut oversize, LONG));

    let mut truncated = tcp_connect(kdc);
    tcp_raw(&mut truncated, &[0, 0, 0, 100, 0x6A, 0x62]);
    assert_eq!(read_record(&mut truncated), TcpReply::Closed);

    let mut half_prefix = tcp_connect(kdc);
    tcp_raw(&mut half_prefix, &[0, 0]);
    assert_eq!(read_record(&mut half_prefix), TcpReply::Closed);

    let mut malformed = tcp_connect(kdc);
    tcp_raw(
        &mut malformed,
        &kdc::tcp_encode_frame(&[0x6A, 0x00]).unwrap(),
    );
    let _code = error_code(&message(read_record(&mut malformed)));
    tcp_raw(
        &mut malformed,
        &kdc::tcp_encode_frame(&alice_probe(1)).unwrap(),
    );
    assert_eq!(
        error_code(&message(read_record(&mut malformed))),
        KDC_ERR_PREAUTH_REQUIRED
    );
    stack.stop();
}

/// RFC 4120 §5.1.4 ("KDCs SHOULD NOT respond to messages received with an
/// unknown tag over UDP"), extended by the kdc to every undecodable
/// datagram (crates/kdc: no reflector): arbitrary octets and a malformed
/// AS-REQ get silence; a well-formed request on the same listener is
/// answered.
#[test]
fn undecodable_udp_is_silent() {
    let Some(stack) = Stack::start(7, 7, |_| {}).unwrap() else {
        return;
    };
    let kdc = stack.kdcd().udp;
    assert_eq!(udp_send(kdc, &[0x00, 0x01, 0x02], SHORT), None);
    assert_eq!(udp_send(kdc, &[0x6A, 0x00], SHORT), None);
    assert_eq!(udp_send(kdc, &[0x6C, 0x03, 0x02, 0x01, 0x05], SHORT), None);
    let reply = udp_send(kdc, &alice_probe(2), LONG).expect("answered");
    assert_eq!(error_code(&reply), KDC_ERR_PREAUTH_REQUIRED);
    stack.stop();
}

/// RFC 4120 §7.2.1 ("If the response cannot be handled using UDP … the KDC
/// MUST return KRB_ERR_RESPONSE_TOO_BIG, forcing the client to retry the
/// request using the TCP transport") and §3.1.2 (the identical retry gets
/// the reply): with a small UDP limit the bootstrap AS-REP is replaced by
/// KRB_ERR_RESPONSE_TOO_BIG over UDP; the same request over TCP gets the
/// AS-REP, which opens under the computer's key.
#[test]
fn udp_too_big_then_the_tcp_retry_works() {
    let Some(stack) = Stack::start(7, 7, |p| p.udp_max_reply_len = 300).unwrap() else {
        return;
    };
    let request = bootstrap(3);
    let reply = udp_send(stack.kdcd().udp, &request, LONG).expect("answered");
    assert!(reply.len() <= 300);
    assert_eq!(error_code(&reply), KRB_ERR_RESPONSE_TOO_BIG);
    let rep = message(tcp_send(stack.kdcd().tcp, &request));
    let _tgt = open_as_rep(&rep, &machine_key(AES256));
    stack.stop();
}

/// docs/50 §4.1 ("a rate limiter per source", Q-223 option (a); "a counter
/// per source address" for TCP): a UDP source past its share in a window is
/// dropped (silence) and served again in the next window; a TCP source at
/// its connection bound gets its next connection closed at once, and a slot
/// freed admits a new one.
#[test]
fn per_source_limits() {
    let Some(stack) = Stack::start(7, 7, |p| {
        p.udp.per_source = 2;
        p.udp.window = Duration::from_secs(2);
        p.tcp.max_per_source = 1;
    })
    .unwrap() else {
        return;
    };
    let udp = stack.kdcd().udp;
    std::thread::sleep(Duration::from_secs(2));
    assert!(udp_send(udp, &alice_probe(10), LONG).is_some());
    assert!(udp_send(udp, &alice_probe(11), LONG).is_some());
    assert_eq!(
        udp_send(udp, &alice_probe(12), SHORT),
        None,
        "over the share"
    );
    std::thread::sleep(Duration::from_secs(2));
    assert!(
        udp_send(udp, &alice_probe(13), LONG).is_some(),
        "next window"
    );

    let tcp = stack.kdcd().tcp;
    let held = tcp_connect(tcp);
    let mut second = tcp_connect(tcp);
    assert!(is_closed(&mut second, LONG), "over the per-source bound");
    drop(held);
    assert!(
        eventually(LONG, || matches!(
            tcp_send(tcp, &alice_probe(14)),
            TcpReply::Message(_)
        )),
        "a freed slot admits a new connection"
    );
    stack.stop();
}

/// docs/50 R50-8, §3.7; RFC 4120 §7.5.9 ("29 A service is not available");
/// A-56: keyd stopped — the request is answered KDC_ERR_SVC_UNAVAILABLE over
/// TCP and with silence over UDP, never as a wrong password.
#[test]
fn keyd_down_is_29_over_tcp_and_silence_over_udp() {
    let Some(mut stack) = Stack::start(7, 7, |_| {}).unwrap() else {
        return;
    };
    let reply = message(tcp_send(stack.kdcd().tcp, &bootstrap(20)));
    let _tgt = open_as_rep(&reply, &machine_key(AES256));
    stack.keyd.take().unwrap().stop().unwrap();
    assert_eq!(
        error_code(&message(tcp_send(stack.kdcd().tcp, &bootstrap(21)))),
        KDC_ERR_SVC_UNAVAILABLE
    );
    assert_eq!(udp_send(stack.kdcd().udp, &bootstrap(22), SHORT), None);
    stack.stop();
}

/// docs/50 R50-8, §3.7 (dird down ⇒ `Unavailable`), R50-2 / §3.4 (the
/// policy version of every view; no reload — Q-275 item 7): dird stopped ⇒
/// 29 over TCP, silence over UDP; dird back with **another** policy version
/// ⇒ still 29 (the view's version is refused); dird back with the kdc's
/// version ⇒ served again.
#[test]
fn dird_down_or_on_another_policy_version_is_29() {
    let Some(mut stack) = Stack::start(7, 7, |_| {}).unwrap() else {
        return;
    };
    let tcp = stack.kdcd().tcp;
    assert_eq!(
        error_code(&message(tcp_send(tcp, &alice_probe(30)))),
        KDC_ERR_PREAUTH_REQUIRED
    );
    stack.dird.take().unwrap().stop().unwrap();
    assert_eq!(
        error_code(&message(tcp_send(tcp, &alice_probe(31)))),
        KDC_ERR_SVC_UNAVAILABLE
    );
    assert_eq!(udp_send(stack.kdcd().udp, &alice_probe(32), SHORT), None);

    let restart = |version: u64| {
        dird::Dird::start(
            support::stack_dird_params(&stack.dir, stack.uid),
            directory_daemon::test_seams::opened(std::sync::Arc::clone(&stack.directory.store)),
            shared_policy(version, vec![common::allow_kerberos()]),
        )
        .unwrap()
    };
    let other = restart(8);
    assert_eq!(
        error_code(&message(tcp_send(tcp, &alice_probe(33)))),
        KDC_ERR_SVC_UNAVAILABLE
    );
    other.stop().unwrap();
    stack.dird = Some(restart(7));
    assert_eq!(
        error_code(&message(tcp_send(tcp, &alice_probe(34)))),
        KDC_ERR_PREAUTH_REQUIRED
    );
    stack.stop();
}

/// docs/50 R50-2 ("if the `policy_version` dird returned ≠ the version of
/// the kdc's `PolicySnapshot` ⇒ fail closed"), §7.2 (the same file), §7.5
/// (exit on any start-up failure); A-68: a kdc whose policy file is another
/// version than dird's does not start.
#[test]
fn a_policy_version_mismatch_refuses_to_start() {
    let message = match Stack::start(8, 7, |_| {}) {
        Ok(None) => return,
        Ok(Some(_)) => panic!("the kdc started on another policy version"),
        Err(message) => message,
    };
    assert!(
        message.contains("policy version mismatch") && message.contains('8'),
        "{message}"
    );
}

/// docs/50 R50-16 ("a daemon does not bind a network port until its
/// dependencies are verified … audit"): without its auditd the kdc does not
/// start.
#[test]
fn no_auditd_refuses_to_start() {
    let Some(mut stack) = Stack::start(7, 7, |_| {}).unwrap() else {
        return;
    };
    stack.kdcd.take().unwrap().stop().unwrap();
    stack.kdc_auditd.stop();
    let result = Kdcd::start(
        kdc_params(&stack.dir.join("ka.sock"), stack.uid),
        shared_policy(7, vec![common::allow_kerberos()]),
        &stack.keyd_socket,
        &stack.dird_socket,
        HeldClock::at(common::now()),
    );
    assert!(
        matches!(&result, Err(m) if m.contains("auditd not verified")),
        "{:?}",
        result.as_ref().err()
    );
    stack.stop();
}

/// Attack — docs/50 R50-9 ("binding to internal interfaces only"), §4.1
/// (UDP: the same); docs/questions/Q-223 (A-57 (a)); task R15b
/// (docs/questions/Q-632; A-114's follow-up): a kdc whose UDP and TCP
/// listeners (127.0.0.1) lie outside every internal network of its zone
/// table does not start — refused first, before auditd is contacted (with
/// no auditd running the refusal is still the listener's) — and with a
/// table that holds the listener address the same start serves. The
/// table's match is crates/config's (`config::is_internal`).
#[test]
fn a_listener_outside_the_internal_networks_is_not_served() {
    let Some(mut stack) = Stack::start(7, 7, |_| {}).unwrap() else {
        return;
    };
    stack.kdcd.take().unwrap().stop().unwrap();
    let outside = |zones: Vec<config::Network>| {
        let mut params = kdc_params(&stack.dir.join("ka.sock"), stack.uid);
        params.zones = kdc_daemon::zones::ZoneTable::new(zones);
        Kdcd::start(
            params,
            shared_policy(7, vec![common::allow_kerberos()]),
            &stack.keyd_socket,
            &stack.dird_socket,
            HeldClock::at(common::now()),
        )
    };
    let ten = config::Network::new("10.0.0.0".parse().unwrap(), 8).unwrap();
    let v6_loopback = config::Network::new("::1".parse().unwrap(), 128).unwrap();
    for zones in [vec![ten], vec![v6_loopback], Vec::new()] {
        let result = outside(zones.clone());
        assert!(
            matches!(&result, Err(m) if m.contains("outside every configured internal network")),
            "{zones:?}: {:?}",
            result.as_ref().err()
        );
    }
    // Refused before auditd: with auditd gone the refusal is the same.
    stack.kdc_auditd.stop();
    let result = outside(vec![ten]);
    assert!(
        matches!(&result, Err(m) if m.contains("outside every configured internal network")),
        "{:?}",
        result.as_ref().err()
    );
    // Positive control: auditd back, the loopback network ⇒ served.
    stack.kdc_auditd =
        FakeAuditd::start_recording_as(&stack.dir.join("ka.sock"), ipc_audit::EventSource::Kdc);
    let loopback = config::Network::new("127.0.0.0".parse().unwrap(), 8).unwrap();
    let served = outside(vec![loopback]).unwrap();
    served.stop().unwrap();
    stack.stop();
}

/// Attack — task R9b (docs/questions/Q-512, Q-560; docs/50 §3.2: the source
/// is set from the uid): an auditd whose map gives the kdc's uid another
/// source is refused at its first `Pong`, before any event is sent; the kdc
/// does not start.
#[test]
fn an_auditd_recording_the_kdc_under_another_source_is_refused() {
    let Some(mut stack) = Stack::start(7, 7, |_| {}).unwrap() else {
        return;
    };
    stack.kdcd.take().unwrap().stop().unwrap();
    stack.kdc_auditd.stop();
    for other in ipc_audit::EventSource::ALL
        .into_iter()
        .filter(|s| *s != ipc_audit::EventSource::Kdc)
    {
        let mut cross_wired = FakeAuditd::start_recording_as(&stack.dir.join("ka.sock"), other);
        let result = Kdcd::start(
            kdc_params(&stack.dir.join("ka.sock"), stack.uid),
            shared_policy(7, vec![common::allow_kerberos()]),
            &stack.keyd_socket,
            &stack.dird_socket,
            HeldClock::at(common::now()),
        );
        assert!(
            matches!(&result, Err(m) if m.contains("another source")),
            "{other:?}: {:?}",
            result.as_ref().err()
        );
        assert!(cross_wired.events().is_empty(), "{other:?}: nothing sent");
        cross_wired.stop();
    }
    stack.stop();
}

/// docs/questions/Q-218 (A-57: "the kdc refuses every request that would
/// produce issuance"), Q-252 item 8 (a) (A-64): the kdc's auditd stopped —
/// requests are answered 29 over TCP and silence over UDP, and keyd is not
/// asked (no keyd record for them); auditd back — served again.
#[test]
fn the_kdc_does_not_serve_without_its_audit() {
    let Some(mut stack) = Stack::start(7, 7, |_| {}).unwrap() else {
        return;
    };
    let tcp = stack.kdcd().tcp;
    let _tgt = open_as_rep(
        &message(tcp_send(tcp, &bootstrap(40))),
        &machine_key(AES256),
    );
    let delivered = |stack: &Stack| {
        stack
            .kdc_auditd
            .events()
            .iter()
            .filter(|e| matches!(e, EventBody::Kdc(_)))
            .count()
    };
    assert!(eventually(LONG, || delivered(&stack) >= 1));

    stack.kdc_auditd.stop();
    let mut nonce = 41u32;
    assert!(
        eventually(Duration::from_secs(10), || {
            nonce += 1;
            matches!(
                tcp_send(tcp, &bootstrap(nonce)),
                TcpReply::Message(m) if is_error(&m, KDC_ERR_SVC_UNAVAILABLE)
            )
        }),
        "the gate closed"
    );
    let keyd_records = |stack: &Stack| {
        stack
            .keyd_auditd
            .events()
            .iter()
            .filter(|e| matches!(e, EventBody::Keyd(_)))
            .count()
    };
    std::thread::sleep(Duration::from_millis(300));
    let before = keyd_records(&stack);
    assert_eq!(
        error_code(&message(tcp_send(tcp, &bootstrap(100)))),
        KDC_ERR_SVC_UNAVAILABLE
    );
    assert_eq!(udp_send(stack.kdcd().udp, &bootstrap(101), SHORT), None);
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(keyd_records(&stack), before, "keyd was not asked");

    stack.kdc_auditd =
        FakeAuditd::start_recording_as(&stack.dir.join("ka.sock"), ipc_audit::EventSource::Kdc);
    let mut nonce = 200u32;
    assert!(
        eventually(Duration::from_secs(15), || {
            nonce += 1;
            matches!(tcp_send(tcp, &bootstrap(nonce)), TcpReply::Message(m) if m.first() == Some(&0x6B))
        }),
        "served again once auditd is back"
    );
    stack.stop();
}

/// docs/50 R50-9, §4.1 ("two bounded queues — AS and TGS … full queue ⇒ UDP
/// silence, TCP close"); docs/07 §1 (a flood of one kind does not starve the
/// other): with the engine held, the TGS queue full does not stop an AS
/// request from being queued, the AS queue full does not stop a TGS request,
/// each full queue closes the next connection of its kind, and once the
/// engine runs every queued request is answered.
#[test]
fn the_as_and_tgs_queues_are_separate() {
    let Some(stack) = Stack::start(7, 7, |p| {
        p.as_queue_capacity = 1;
        p.tgs_queue_capacity = 1;
    })
    .unwrap() else {
        return;
    };
    let tcp = stack.kdcd().tcp;
    let send = |octets: &[u8]| {
        let mut stream = tcp_connect(tcp);
        tcp_raw(&mut stream, &kdc::tcp_encode_frame(octets).unwrap());
        stream
    };
    // An AS-REQ-looking and a TGS-REQ-looking record (first octets 0x6A /
    // 0x6C, RFC 4120 §5.4.1): malformed, so each gets a KRB-ERROR.
    let as_like = [0x6A, 0x00];
    let tgs_like = [0x6C, 0x00];

    stack.clock.hold();
    let entered = stack.clock.entered();
    let mut first = send(&as_like);
    assert!(
        eventually(LONG, || stack.clock.entered() > entered),
        "engine held"
    );
    let mut tgs_queued = send(&tgs_like);
    let mut tgs_over = send(&tgs_like);
    assert!(is_closed(&mut tgs_over, LONG), "TGS queue full ⇒ closed");
    let mut as_queued = send(&as_like);
    let mut as_over = send(&as_like);
    assert!(is_closed(&mut as_over, LONG), "AS queue full ⇒ closed");
    stack.clock.release();

    for stream in [&mut first, &mut tgs_queued, &mut as_queued] {
        stream.set_read_timeout(Some(LONG)).unwrap();
        let reply = message(read_record(stream));
        let _ = error_code(&reply);
    }
    stack.stop();
}
