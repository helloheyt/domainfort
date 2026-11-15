//! dnsd serving: answers from the fetched image over UDP and TCP, the
//! staleness bound, the refresh by SERIAL, internal sources only, the rate
//! limits, the UDP size rules and the TCP framing bounds.
//!
//! Sources: RFC 1035 §2.3.4 ("UDP messages 512 octets or less"), §4.2.1,
//! §4.2.2 (the two-octet length; idle "on the order of two minutes"); RFC
//! 1034 §4.3.2 (authoritative answers, via dns-zone); docs/54 §3.3, §4.4
//! (refresh by SERIAL; "SERVFAIL to every query" past
//! `zone_image_max_age`), §4.7 (internal sources only), §6.5 (≤ 512 and ≤
//! k × the request, else TC = 1; errors ≤ the request), §6.7 (limits, TCP
//! bounds, one request in flight); A-114; A-124; A-154 item 6 (a).
//! Values: the RFC 2782 "Fictional example" zone and the RFC 1034 §3.7.1
//! addresses; hand-made IDs, limits and timeouts.

mod common;

use common::{
    closed_without_reply, eventually, host, parts, query, reply, serial, tcp_connect, tcp_exchange,
    tcp_read, tcp_write, transfer, udp_client, udp_exchange, Dnsd, World, SERIAL,
};
use config::Network;
use core::net::{IpAddr, Ipv4Addr};
use core::time::Duration;
use dns_daemon::clock::Clock;
use dns_daemon::Listeners;
use ipc_dns::{ImageTransfer, KpasswdService};
use parse_dns::{RData, Rcode, RrType, Transport};
use rate_limit::SourceLimits;
use std::io::Write;
use std::net::{TcpListener, UdpSocket};
use std::sync::Arc;

fn rfc2782() -> ImageTransfer {
    transfer(&parts(SERIAL, &[]))
}

/// RFC 1034 §4.3.2 via dns-zone (A-124): over UDP and TCP, a host's A record
/// comes from the image (AA, 172.30.79.13 — RFC 2782's `new-fast-box`), a
/// missing name is NXDOMAIN, a name outside the zone is REFUSED, and the
/// `_ldap._tcp` SRV names the DC on port 389 ([MS-ADTS] 6.3.2.3 via
/// dns-zone).
#[test]
fn answers_come_from_the_fetched_image() {
    let Some(world) = World::new(rfc2782()) else {
        return;
    };
    let dnsd = world.start(world.params());
    assert!(dnsd.serving());
    let client = udp_client();
    let a = reply(
        &udp_exchange(
            &client,
            dnsd.udp,
            &query(1, "new-fast-box.example.com", RrType::A),
        )
        .expect("udp answer"),
        Transport::Udp,
    );
    assert_eq!(a.header.id, 1);
    assert!(a.header.qr && a.header.aa && !a.header.ra);
    assert_eq!(a.header.rcode, Rcode::NOERROR);
    assert_eq!(
        a.answer
            .iter()
            .map(|rr| rr.rdata.clone())
            .collect::<Vec<_>>(),
        vec![RData::A(Ipv4Addr::new(172, 30, 79, 13))]
    );
    let tcp = reply(
        &tcp_exchange(dnsd.tcp, &query(2, "new-fast-box.example.com", RrType::A))
            .expect("tcp answer"),
        Transport::Tcp,
    );
    assert_eq!(tcp.answer, a.answer);
    let missing = reply(
        &udp_exchange(
            &client,
            dnsd.udp,
            &query(3, "no-such-box.example.com", RrType::A),
        )
        .expect("answer"),
        Transport::Udp,
    );
    assert_eq!(missing.header.rcode, Rcode::NXDOMAIN);
    let outside = reply(
        &udp_exchange(&client, dnsd.udp, &query(4, "www.example.org", RrType::A)).expect("answer"),
        Transport::Udp,
    );
    assert_eq!(outside.header.rcode, Rcode::REFUSED);
    let srv = reply(
        &tcp_exchange(dnsd.tcp, &query(5, "_ldap._tcp.example.com", RrType::SRV)).expect("answer"),
        Transport::Tcp,
    );
    match srv.answer.first().map(|rr| &rr.rdata) {
        Some(RData::Srv(record)) => {
            assert_eq!(record.port, 389);
            assert_eq!(record.target, common::name("server.example.com"));
        }
        other => panic!("expected an SRV record, got {other:?}"),
    }
    assert_eq!(dnsd.stop(), Ok(()));
}

/// docs/54 §4.4 (Q-616 item 6): when dird can no longer confirm the SERIAL,
/// the image ages; past `zone_image_max_age` every query is answered
/// SERVFAIL (fail closed) — and once a SERIAL check succeeds again, the
/// image is served again.
#[test]
fn a_stale_image_is_not_answered() {
    let Some(world) = World::new(rfc2782()) else {
        return;
    };
    let mut params = world.params();
    params.zone_image_max_age = Duration::from_secs(60);
    let dnsd = world.start(params);
    assert!(dnsd.serving());
    let client = udp_client();
    let request = query(10, "server.example.com", RrType::A);
    let fresh = reply(
        &udp_exchange(&client, dnsd.udp, &request).expect("answer"),
        Transport::Udp,
    );
    assert_eq!(fresh.header.rcode, Rcode::NOERROR);

    world.dird.state().refuse_images = true;
    // Let any check already under way finish before the clock moves.
    std::thread::sleep(Duration::from_millis(200));
    world.clock.advance(61);
    for transport in [Transport::Udp, Transport::Tcp] {
        let octets = match transport {
            Transport::Udp => udp_exchange(&client, dnsd.udp, &request),
            Transport::Tcp => tcp_exchange(dnsd.tcp, &request),
        };
        let stale = reply(&octets.expect("answered"), transport);
        assert_eq!(stale.header.rcode, Rcode::SERVFAIL, "{transport:?}");
        assert!(stale.answer.is_empty());
    }

    world.dird.state().refuse_images = false;
    assert!(eventually(Duration::from_secs(5), || {
        udp_exchange(&client, dnsd.udp, &request)
            .map(|octets| reply(&octets, Transport::Udp).header.rcode == Rcode::NOERROR)
            .unwrap_or(false)
    }));
    assert_eq!(dnsd.stop(), Ok(()));
}

/// docs/54 §4.4 (b): the periodic SERIAL check (`have: Some(SERIAL)`)
/// confirms an unchanged image and replaces a changed one whole — a host
/// added under a new SERIAL is answered after the next check.
#[test]
fn the_image_is_refreshed_by_serial() {
    let Some(world) = World::new(rfc2782()) else {
        return;
    };
    let dnsd = world.start(world.params());
    assert!(dnsd.serving());
    let client = udp_client();
    let joined = query(20, "joined-box.example.com", RrType::A);
    let before = reply(
        &udp_exchange(&client, dnsd.udp, &joined).expect("answer"),
        Transport::Udp,
    );
    assert_eq!(before.header.rcode, Rcode::NXDOMAIN);
    assert!(eventually(Duration::from_secs(5), || {
        world.dird.state().fetches.contains(&Some(serial(SERIAL)))
    }));
    world.dird.state().image =
        transfer(&parts(SERIAL + 1, &[host("joined-box", &[[10, 2, 0, 27]])]));
    assert!(eventually(Duration::from_secs(5), || {
        udp_exchange(&client, dnsd.udp, &joined)
            .map(|octets| reply(&octets, Transport::Udp).header.rcode == Rcode::NOERROR)
            .unwrap_or(false)
    }));
    assert_eq!(dnsd.stop(), Ok(()));
}

/// docs/54 §4.7 (A-114): a source outside `internal_networks` gets nothing —
/// UDP: dropped without a reply; TCP: closed before a byte. Needs a second
/// loopback address (127.0.0.2, present on Linux): dnsd listens there with
/// 127.0.0.2/32 as its only internal network, and the client's source is
/// 127.0.0.1. Where 127.0.0.2 cannot be bound the test is skipped (the
/// match itself is unit-tested in crate::source).
#[test]
fn sources_outside_the_internal_networks_are_dropped() {
    let Some(world) = World::new(rfc2782()) else {
        return;
    };
    let (Ok(udp), Ok(tcp)) = (
        UdpSocket::bind("127.0.0.2:0"),
        TcpListener::bind("127.0.0.2:0"),
    ) else {
        eprintln!("skipped: 127.0.0.2 cannot be bound on this host");
        return;
    };
    let addresses = (
        udp.local_addr().expect("udp"),
        tcp.local_addr().expect("tcp"),
    );
    let mut params = world.params();
    params.internal_networks =
        vec![Network::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 32).expect("network")];
    let clock: Arc<dyn Clock> = world.clock.clone();
    let dnsd = Dnsd::start_with(
        params,
        Listeners {
            udp: vec![udp],
            tcp: vec![tcp],
        },
        addresses,
        &world.connector,
        clock,
    );
    assert!(dnsd.serving());
    let client = udp_client(); // 127.0.0.1: outside 127.0.0.2/32
    assert_eq!(
        udp_exchange(
            &client,
            dnsd.udp,
            &query(30, "server.example.com", RrType::A)
        ),
        None
    );
    let mut stream = tcp_connect(dnsd.tcp);
    let _ = stream.write_all(&[0, 12]);
    assert!(closed_without_reply(&mut stream, Duration::from_secs(2)));
    assert_eq!(dnsd.stop(), Ok(()));
}

/// docs/54 §6.7 (A-154 item 6 (a): the shared limiter, per source and
/// global): past its share in the window a source gets no UDP reply; over
/// TCP, a message past the limit closes the connection.
#[test]
fn the_rate_limits_drop_the_excess() {
    let Some(world) = World::new(rfc2782()) else {
        return;
    };
    let mut params = world.params();
    params.udp = SourceLimits {
        per_source: 3,
        global: 100,
        window: Duration::from_secs(3600),
    };
    params.tcp_messages = SourceLimits {
        per_source: 2,
        global: 100,
        window: Duration::from_secs(3600),
    };
    let dnsd = world.start(params);
    assert!(dnsd.serving());
    let client = udp_client();
    for id in 0..3 {
        assert!(
            udp_exchange(
                &client,
                dnsd.udp,
                &query(40 + id, "server.example.com", RrType::A)
            )
            .is_some(),
            "query {id} within the share"
        );
    }
    assert_eq!(
        udp_exchange(
            &client,
            dnsd.udp,
            &query(43, "server.example.com", RrType::A)
        ),
        None,
        "past the per-source share"
    );
    let mut stream = tcp_connect(dnsd.tcp);
    for id in 0..2 {
        tcp_write(
            &mut stream,
            &query(50 + id, "server.example.com", RrType::A),
        );
        assert!(
            tcp_read(&mut stream).is_some(),
            "message {id} within the share"
        );
    }
    tcp_write(&mut stream, &query(52, "server.example.com", RrType::A));
    assert!(closed_without_reply(&mut stream, Duration::from_secs(2)));
    assert_eq!(dnsd.stop(), Ok(()));
}

/// RFC 1035 §2.3.4, §4.2.1; docs/54 §3.3, §6.5 (A-124): a datagram over 512
/// octets gets no reply; a UDP reply over k × the request is the TC = 1 form
/// (header + question, no record) while TCP carries the whole answer; an
/// error reply is never larger than the request. The zone: RFC 2782's, with
/// a DC of eight addresses (RFC 1034 §3.7.1's and hand-made) so the NS
/// answer's additional section is large.
#[test]
fn the_udp_size_rules_hold_on_the_wire() {
    let mut big = parts(SERIAL, &[]);
    big.kpasswd = KpasswdService::Absent;
    big.dc = host(
        "server",
        &[
            [172, 30, 79, 10],
            [10, 2, 0, 27],
            [128, 9, 0, 33],
            [10, 1, 0, 52],
            [128, 9, 0, 32],
            [172, 30, 79, 20],
            [172, 30, 79, 21],
            [172, 30, 79, 22],
        ],
    );
    let Some(world) = World::new(transfer(&big)) else {
        return;
    };
    let dnsd = world.start(world.params());
    assert!(dnsd.serving());
    let client = udp_client();

    let mut oversize = query(60, "server.example.com", RrType::A);
    oversize.resize(513, 0);
    assert_eq!(udp_exchange(&client, dnsd.udp, &oversize), None);

    let ns = query(61, "example.com", RrType::NS);
    let udp_octets = udp_exchange(&client, dnsd.udp, &ns).expect("udp answer");
    assert!(udp_octets.len() <= 4 * ns.len() && udp_octets.len() <= 512);
    let truncated = reply(&udp_octets, Transport::Udp);
    assert!(truncated.header.tc);
    assert!(truncated.answer.is_empty() && truncated.additional.is_empty());
    let full = reply(
        &tcp_exchange(dnsd.tcp, &ns).expect("tcp answer"),
        Transport::Tcp,
    );
    assert!(!full.header.tc);
    assert_eq!(full.answer.len(), 1);
    assert_eq!(full.additional.len(), 8);

    let refused = query(62, "www.example.org", RrType::A);
    let octets = udp_exchange(&client, dnsd.udp, &refused).expect("answer");
    assert!(octets.len() <= refused.len());
    assert_eq!(reply(&octets, Transport::Udp).header.rcode, Rcode::REFUSED);
    assert_eq!(dnsd.stop(), Ok(()));
}

/// RFC 1035 §4.2.2 (the two-octet length); docs/54 §6.6 ("malformed (TCP):
/// FORMERR if the header decoded, otherwise close"), §6.7 (first octet,
/// started frame, idle, messages per connection, connections per source;
/// one request in flight — replies in order).
#[test]
fn the_tcp_framing_is_bounded() {
    let Some(world) = World::new(rfc2782()) else {
        return;
    };
    let mut params = world.params();
    params.tcp.first_octet_timeout = Duration::from_millis(300);
    params.tcp.frame_timeout = Duration::from_millis(300);
    params.tcp.idle_timeout = Duration::from_millis(600);
    params.tcp.max_requests = 3;
    params.tcp.max_per_source = 2;
    let dnsd = world.start(params);
    assert!(dnsd.serving());
    let wait = Duration::from_secs(3);

    // A zero-length message and one shorter than a header: closed.
    let mut stream = tcp_connect(dnsd.tcp);
    stream.write_all(&[0, 0]).expect("write");
    assert!(closed_without_reply(&mut stream, wait));
    let mut stream = tcp_connect(dnsd.tcp);
    stream.write_all(&[0, 5, 1, 2, 3, 4, 5]).expect("write");
    assert!(closed_without_reply(&mut stream, wait));

    // Nothing sent: closed after the first-octet bound.
    let mut stream = tcp_connect(dnsd.tcp);
    assert!(closed_without_reply(&mut stream, wait));

    // A started message that never completes: closed after the frame bound.
    let mut stream = tcp_connect(dnsd.tcp);
    stream
        .write_all(&[0, 100, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
        .expect("write");
    assert!(closed_without_reply(&mut stream, wait));

    // Two messages written back to back: two replies, in order; a third
    // reaches the per-connection maximum and the connection closes.
    let mut stream = tcp_connect(dnsd.tcp);
    let mut both = Vec::new();
    for id in [70u16, 71] {
        let message = query(id, "server.example.com", RrType::A);
        both.extend_from_slice(&u16::try_from(message.len()).expect("fits").to_be_bytes());
        both.extend_from_slice(&message);
    }
    stream.write_all(&both).expect("write");
    for id in [70u16, 71] {
        let answer = reply(&tcp_read(&mut stream).expect("reply"), Transport::Tcp);
        assert_eq!(answer.header.id, id);
    }
    tcp_write(&mut stream, &query(72, "server.example.com", RrType::A));
    assert!(tcp_read(&mut stream).is_some());
    assert!(closed_without_reply(&mut stream, wait), "max messages");

    // Idle after a reply: closed after the idle bound.
    let mut stream = tcp_connect(dnsd.tcp);
    tcp_write(&mut stream, &query(73, "server.example.com", RrType::A));
    assert!(tcp_read(&mut stream).is_some());
    assert!(closed_without_reply(&mut stream, wait), "idle");

    // Connections per source: the third concurrent one is closed at once.
    let mut first = tcp_connect(dnsd.tcp);
    let mut second = tcp_connect(dnsd.tcp);
    tcp_write(&mut first, &query(74, "server.example.com", RrType::A));
    tcp_write(&mut second, &query(75, "server.example.com", RrType::A));
    assert!(tcp_read(&mut first).is_some());
    assert!(tcp_read(&mut second).is_some());
    let mut third = tcp_connect(dnsd.tcp);
    tcp_write(&mut third, &query(76, "server.example.com", RrType::A));
    assert!(closed_without_reply(&mut third, wait), "per-source bound");
    drop((first, second));
    assert_eq!(dnsd.stop(), Ok(()));
}

/// docs/54 §6.6 (dns-zone rows 3, 6): a response arriving (QR = 1) and a
/// datagram malformed past its header get no reply over UDP; over TCP a
/// malformed message with a readable header gets FORMERR.
#[test]
fn responses_and_malformed_datagrams_are_not_answered() {
    let Some(world) = World::new(rfc2782()) else {
        return;
    };
    let dnsd = world.start(world.params());
    assert!(dnsd.serving());
    let client = udp_client();
    let mut response = query(80, "server.example.com", RrType::A);
    response[2] |= 0x80; // QR = 1 (RFC 1035 §4.1.1)
    assert_eq!(udp_exchange(&client, dnsd.udp, &response), None);
    let mut malformed = query(81, "server.example.com", RrType::A);
    malformed.truncate(20); // the question cut short
    assert_eq!(udp_exchange(&client, dnsd.udp, &malformed), None);
    let formerr = reply(
        &tcp_exchange(dnsd.tcp, &malformed).expect("reply"),
        Transport::Tcp,
    );
    assert_eq!(formerr.header.rcode, Rcode::FORMERR);
    assert_eq!(formerr.header.id, 81);
    assert_eq!(dnsd.stop(), Ok(()));
}
