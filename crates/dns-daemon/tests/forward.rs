//! Forwarding signed UPDATE messages to dird and relaying its answer, over
//! the real channel to dird's real dispatcher (crates/ipc-dns-server).
//!
//! Sources: docs/54 §4.5 step 1 ("without TSIG ⇒ REFUSED in dnsd … dird never
//! sees an unsigned UPDATE"), §4.4 (a) (the new image fetched "before it
//! returns the answer to the client"), §4.6 (`Forward` / `Forwarded`;
//! "`None` ⇒ dnsd closes without a reply"; queue full ⇒ SERVFAIL), §6.6
//! (last row: dird unavailable ⇒ SERVFAIL), §6.7 (forwarding limits,
//! bounded queue (32)); A-140 / docs/research/r3-c-dns.md §4.1 (`Forward {
//! transport, peer, message }`); RFC 2136 §3.8 (the response on the
//! requestor's open TCP connection), §6.2, §6.4; RFC 8945 §5.5 ("MUST
//! forward the message unchanged including the TSIG"); docs/questions/
//! Q-671 (UPDATE over UDP ⇒ REFUSED, never forwarded — dns-zone row 7).
//! Values: the RFC 2782 "Fictional example" zone; hand-made IDs, keys, MACs
//! and SERIALs.

mod common;

use common::{
    closed_without_reply, host, parts, query, reply, serial, signed_update, tcp_connect,
    tcp_exchange, tcp_read, tcp_write, transfer, udp_client, udp_exchange, update, update_reply,
    World, SERIAL,
};
use core::net::{IpAddr, Ipv4Addr};
use core::time::Duration;
use ipc_dns::{Forwarded, FrontZone, PeerAddress};
use ipc_dns_server::Unserved;
use parse_dns::{Opcode, Rcode, RrType, Transport};
use rate_limit::SourceLimits;
use std::sync::mpsc;

fn world() -> Option<World> {
    World::new(transfer(&parts(SERIAL, &[])))
}

/// docs/54 §4.6, A-140, RFC 8945 §5.5: a signed UPDATE over TCP reaches dird
/// as the client's exact octets, with transport TCP and the source address
/// (127.0.0.1), on a connection of the internal zone; dird's reply is
/// written back on the same connection, unchanged (RFC 2136 §3.8), and the
/// connection goes on.
#[test]
fn a_signed_update_is_forwarded_and_the_reply_relayed() {
    let Some(world) = world() else {
        return;
    };
    world.dird.state().forward_answer = Ok(Forwarded {
        reply: Some(update_reply(0x2001, 0)),
        serial: serial(SERIAL),
    });
    let dnsd = world.start(world.params());
    assert!(dnsd.serving());
    let request = signed_update(0x2001);
    let mut stream = tcp_connect(dnsd.tcp);
    tcp_write(&mut stream, &request);
    let relayed = tcp_read(&mut stream).expect("relayed");
    assert_eq!(relayed, update_reply(0x2001, 0).as_bytes());
    {
        let state = world.dird.state();
        assert_eq!(state.forwards.len(), 1);
        let (zone, forwarded) = &state.forwards[0];
        assert_eq!(*zone, FrontZone::Internal);
        assert_eq!(forwarded.transport(), Transport::Tcp);
        assert_eq!(
            forwarded.peer(),
            PeerAddress::new(IpAddr::V4(Ipv4Addr::LOCALHOST))
        );
        assert_eq!(forwarded.message().as_bytes(), request.as_slice());
    }
    // The connection serves the next message.
    tcp_write(&mut stream, &query(0x2002, "server.example.com", RrType::A));
    let answer = reply(&tcp_read(&mut stream).expect("answer"), Transport::Tcp);
    assert_eq!(answer.header.id, 0x2002);
    assert_eq!(dnsd.stop(), Ok(()));
}

/// docs/54 §4.6 ("`None` ⇒ dnsd closes without a reply"; A-140).
#[test]
fn no_reply_from_dird_closes_the_connection() {
    let Some(world) = world() else {
        return;
    };
    world.dird.state().forward_answer = Ok(Forwarded {
        reply: None,
        serial: serial(SERIAL),
    });
    let dnsd = world.start(world.params());
    assert!(dnsd.serving());
    let mut stream = tcp_connect(dnsd.tcp);
    tcp_write(&mut stream, &signed_update(0x2101));
    assert!(closed_without_reply(&mut stream, Duration::from_secs(3)));
    assert_eq!(world.dird.state().forwards.len(), 1);
    assert_eq!(dnsd.stop(), Ok(()));
}

/// docs/54 §6.6 (last row: "dird queue full / dird unavailable ⇒ SERVFAIL"):
/// a dird refusal (`Busy`) reaches the client as dns-zone's SERVFAIL UPDATE
/// reply (ID copied, zero counts — RFC 2136 §3.8), and the next forward
/// reconnects, verifies and is served.
#[test]
fn a_dird_that_does_not_serve_means_servfail() {
    let Some(world) = world() else {
        return;
    };
    world.dird.state().forward_answer = Err(Unserved::Busy);
    let dnsd = world.start(world.params());
    assert!(dnsd.serving());
    let servfail = reply(
        &tcp_exchange(dnsd.tcp, &signed_update(0x2201)).expect("fallback"),
        Transport::Tcp,
    );
    assert_eq!(servfail.header.id, 0x2201);
    assert_eq!(servfail.header.opcode, Opcode::Update);
    assert_eq!(servfail.header.rcode, Rcode::SERVFAIL);
    assert!(servfail.question.is_none() && servfail.tsig.is_none());
    world.dird.state().forward_answer = Ok(Forwarded {
        reply: Some(update_reply(0x2202, 0)),
        serial: serial(SERIAL),
    });
    assert_eq!(
        tcp_exchange(dnsd.tcp, &signed_update(0x2202)).expect("relayed"),
        update_reply(0x2202, 0).as_bytes()
    );
    assert_eq!(dnsd.stop(), Ok(()));
}

/// docs/54 §4.5 step 1 (RFC 2136 §3.3.1): an unsigned UPDATE over TCP is
/// REFUSED by dnsd and never reaches dird; docs/questions/Q-671 (dns-zone
/// row 7): an UPDATE over UDP — signed or not — is REFUSED, header only,
/// never forwarded.
#[test]
fn unsigned_and_udp_updates_never_reach_dird() {
    let Some(world) = world() else {
        return;
    };
    let dnsd = world.start(world.params());
    assert!(dnsd.serving());
    let refused = reply(
        &tcp_exchange(dnsd.tcp, &update(0x2301, None)).expect("refused"),
        Transport::Tcp,
    );
    assert_eq!(refused.header.rcode, Rcode::REFUSED);
    let client = udp_client();
    for request in [update(0x2302, None), signed_update(0x2303)] {
        let octets = udp_exchange(&client, dnsd.udp, &request).expect("refused");
        assert!(octets.len() <= request.len());
        assert_eq!(reply(&octets, Transport::Udp).header.rcode, Rcode::REFUSED);
    }
    assert!(world.dird.state().forwards.is_empty());
    assert_eq!(dnsd.stop(), Ok(()));
}

/// docs/54 §4.4 (a); RFC 2136 §3.6 ("If the zone appears to change, the SOA
/// must appear to change as well"): when dird's answer names a new SERIAL,
/// the new image is fetched before the reply is relayed — a query sent right
/// after the reply sees the registered host. The periodic check is set far
/// away, so only the fetch the forward triggered can have brought it.
#[test]
fn the_new_image_is_fetched_before_the_reply() {
    let Some(world) = world() else {
        return;
    };
    {
        let mut state = world.dird.state();
        state.forward_answer = Ok(Forwarded {
            reply: Some(update_reply(0x2401, 0)),
            serial: serial(SERIAL + 1),
        });
        state.image_after_forward = Some(transfer(&parts(
            SERIAL + 1,
            &[host("joined-box", &[[10, 2, 0, 27]])],
        )));
    }
    let mut params = world.params();
    params.refresh_interval = Duration::from_secs(3600);
    let dnsd = world.start(params);
    assert!(dnsd.serving());
    let client = udp_client();
    let joined = query(0x2402, "joined-box.example.com", RrType::A);
    let before = reply(
        &udp_exchange(&client, dnsd.udp, &joined).expect("answer"),
        Transport::Udp,
    );
    assert_eq!(before.header.rcode, Rcode::NXDOMAIN);
    assert_eq!(
        tcp_exchange(dnsd.tcp, &signed_update(0x2401)).expect("relayed"),
        update_reply(0x2401, 0).as_bytes()
    );
    let after = reply(
        &udp_exchange(&client, dnsd.udp, &joined).expect("answer"),
        Transport::Udp,
    );
    assert_eq!(after.header.rcode, Rcode::NOERROR);
    assert_eq!(after.answer.len(), 1);
    assert!(world.dird.state().fetches.contains(&Some(serial(SERIAL))));
    assert_eq!(dnsd.stop(), Ok(()));
}

/// docs/54 §6.7 (forwarding limit per source; A-154 item 7): past its share
/// a source's signed UPDATE is answered SERVFAIL without reaching dird.
#[test]
fn the_forwarding_limit_keeps_the_excess_from_dird() {
    let Some(world) = world() else {
        return;
    };
    world.dird.state().forward_answer = Ok(Forwarded {
        reply: Some(update_reply(0x2501, 0)),
        serial: serial(SERIAL),
    });
    let mut params = world.params();
    params.forwards = SourceLimits {
        per_source: 1,
        global: 100,
        window: Duration::from_secs(3600),
    };
    let dnsd = world.start(params);
    assert!(dnsd.serving());
    assert!(tcp_exchange(dnsd.tcp, &signed_update(0x2501)).is_some());
    let limited = reply(
        &tcp_exchange(dnsd.tcp, &signed_update(0x2502)).expect("fallback"),
        Transport::Tcp,
    );
    assert_eq!(limited.header.rcode, Rcode::SERVFAIL);
    assert_eq!(world.dird.state().forwards.len(), 1);
    assert_eq!(dnsd.stop(), Ok(()));
}

/// docs/54 §6.7 ("bounded queue ⇒ SERVFAIL — a flood does not reach dird"):
/// while dird holds one forward and the queue (capacity 1 here) holds the
/// next, a third is answered SERVFAIL at once; once dird answers, the two
/// accepted ones are relayed.
#[test]
fn a_full_forwarding_queue_means_servfail() {
    let Some(world) = world() else {
        return;
    };
    let (release, gate) = mpsc::channel();
    {
        let mut state = world.dird.state();
        state.forward_answer = Ok(Forwarded {
            reply: Some(update_reply(0x2600, 0)),
            serial: serial(SERIAL),
        });
        state.forward_gate = Some(gate);
    }
    let mut params = world.params();
    params.forward_queue_capacity = 1;
    let dnsd = world.start(params);
    assert!(dnsd.serving());
    let mut held = tcp_connect(dnsd.tcp);
    tcp_write(&mut held, &signed_update(0x2601));
    // Wait until the forwarding thread holds the first one at dird.
    assert!(common::eventually(Duration::from_secs(5), || {
        world.dird.state().forward_gate.is_none()
    }));
    let mut queued = tcp_connect(dnsd.tcp);
    tcp_write(&mut queued, &signed_update(0x2602));
    std::thread::sleep(Duration::from_millis(200));
    let full = reply(
        &tcp_exchange(dnsd.tcp, &signed_update(0x2603)).expect("fallback"),
        Transport::Tcp,
    );
    assert_eq!(full.header.rcode, Rcode::SERVFAIL);
    assert_eq!(full.header.id, 0x2603);
    release.send(()).expect("release");
    assert!(tcp_read(&mut held).is_some());
    assert!(tcp_read(&mut queued).is_some());
    assert_eq!(world.dird.state().forwards.len(), 2);
    assert_eq!(dnsd.stop(), Ok(()));
}
