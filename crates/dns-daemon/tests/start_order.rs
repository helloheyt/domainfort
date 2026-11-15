//! dnsd's start order and its fail-closed refusals to start.
//!
//! Sources: docs/54 §4.8 ("configuration ⇒ bind ⇒ hardening ⇒ auditd
//! verified … ⇒ dird verified (`Ping` ⇒ `Pong` with the zone) ⇒
//! `FetchZoneImage` ⇒ **only then** serve. dird down at start ⇒ dnsd does
//! not come up"), as amended by A-152 / docs/questions/Q-922 (no
//! `DescribeZone`); docs/54 §4.6 (dnsd verifies dird's uid and the zone in
//! the `Pong` — C12), §4.7 (`serve` refuses a listener outside
//! `internal_networks`); docs/50 R50-16 (auditd first), §7.5 (fail closed);
//! docs/52 §3.12 (the audit source checked); docs/questions/Q-950 (dnsd's
//! own audit source does not exist yet: the product refuses to start).
//! Values: the RFC 2782 "Fictional example" zone; hand-made uids and IDs.

mod common;

use common::{parts, query, reply, transfer, udp_client, udp_exchange, Dnsd, World, SERIAL};
use config::Network;
use core::net::{IpAddr, Ipv4Addr};
use core::time::Duration;
use dns_daemon::audit::{AuditCheckError, AUDIT_SOURCE};
use dns_daemon::test_seams::DaemonParams as ServeParams;
use dns_daemon::{DaemonError, DaemonParams, DirdEndpoint, TcpLimits};
use ipc::Refused;
use ipc_audit::EventSource;
use ipc_audit_client::{AuditEndpoint, AuditLinkError};
use ipc_dns::{TransportError, Unserved};
use parse_dns::{Rcode, RrType, Transport};
use std::sync::atomic::Ordering;
use std::sync::mpsc;

/// docs/54 §4.8: nothing is answered before the first image is fetched —
/// while dird holds the first `FetchZoneImage`, dnsd does not serve and a
/// query gets no reply; once the image arrives, queries are answered from
/// it (AA, the RFC 2782 host `server` → 172.30.79.10).
#[test]
fn nothing_is_answered_before_the_image() {
    let Some(world) = World::new(transfer(&parts(SERIAL, &[]))) else {
        return;
    };
    let (release, gate) = mpsc::channel();
    world.dird.state().gate = Some(gate);
    let dnsd = world.start(world.params());
    let client = udp_client();
    let request = query(0x1001, "server.example.com", RrType::A);
    assert_eq!(udp_exchange(&client, dnsd.udp, &request), None);
    assert!(!dnsd.control.is_serving());
    release.send(()).expect("release");
    assert!(dnsd.serving());
    // A fresh client: the datagram sent before the image may also be
    // answered now (from the image), which this test does not rely on.
    let client = udp_client();
    let request = query(0x1002, "server.example.com", RrType::A);
    let answer = reply(
        &udp_exchange(&client, dnsd.udp, &request).expect("answered"),
        Transport::Udp,
    );
    assert_eq!(answer.header.rcode, Rcode::NOERROR);
    assert!(answer.header.aa);
    assert_eq!(answer.answer.len(), 1);
    assert_eq!(world.dird.state().fetches.first(), Some(&None));
    assert_eq!(dnsd.stop(), Ok(()));
}

/// docs/54 §4.8: "dird down at start ⇒ dnsd does not come up" — no
/// connection to dird ⇒ `serve` ends with the transport failure, nothing is
/// ever served, and the bound socket is closed with it.
#[test]
fn dird_down_at_start_means_no_start() {
    let Some(world) = World::new(transfer(&parts(SERIAL, &[]))) else {
        return;
    };
    world.connector.down.store(true, Ordering::SeqCst);
    let mut dnsd = world.start(world.params());
    assert_eq!(
        dnsd.join(),
        Err(DaemonError::Dird(Unserved::Transport(
            TransportError::Connect
        )))
    );
    assert!(!dnsd.control.is_serving());
    let client = udp_client();
    assert_eq!(
        udp_exchange(
            &client,
            dnsd.udp,
            &query(0x1003, "server.example.com", RrType::A)
        ),
        None
    );
}

/// docs/54 §4.8 (no image ⇒ no service); crates/ipc-dns-server: a host
/// refusal reaches dnsd as the shared `Refused{Unavailable}` — dnsd does not
/// start.
#[test]
fn no_image_at_start_means_no_start() {
    let Some(world) = World::new(transfer(&parts(SERIAL, &[]))) else {
        return;
    };
    world.dird.state().refuse_images = true;
    let mut dnsd = world.start(world.params());
    assert_eq!(
        dnsd.join(),
        Err(DaemonError::Dird(Unserved::Refused(Refused::Unavailable)))
    );
}

/// docs/54 §4.6 (C12): a peer whose uid is not dird's receives nothing — not
/// even the `Ping` — and dnsd does not start.
#[test]
fn a_peer_that_is_not_dird_gets_nothing() {
    let Some(mut world) = World::new(transfer(&parts(SERIAL, &[]))) else {
        return;
    };
    world.connector.uid = common::DIRD_UID + 1;
    let mut dnsd = world.start(world.params());
    assert_eq!(dnsd.join(), Err(DaemonError::Dird(Unserved::PeerMismatch)));
    assert!(world.dird.state().fetches.is_empty());
}

/// docs/50 R50-16 (auditd first), docs/52 §3.12 (the source auditd names is
/// checked): no auditd ⇒ no start, dird never contacted; an auditd that
/// would record dnsd under another source ⇒ no start.
#[test]
fn auditd_is_verified_first() {
    let Some(world) = World::new(transfer(&parts(SERIAL, &[]))) else {
        return;
    };
    let mut params = world.params();
    params.audit.socket = world.dir.path().join("absent.sock");
    let mut dnsd = world.start(params);
    assert_eq!(
        dnsd.join(),
        Err(DaemonError::Audit(AuditCheckError::Link(
            AuditLinkError::Connect
        )))
    );
    assert!(world.dird.state().fetches.is_empty(), "dird not contacted");

    let mut params = world.params();
    params.audit_source = Some(EventSource::Kdc);
    let mut dnsd = world.start(params);
    assert_eq!(
        dnsd.join(),
        Err(DaemonError::Audit(AuditCheckError::Link(
            AuditLinkError::SourceMismatch
        )))
    );
    assert!(world.dird.state().fetches.is_empty(), "dird not contacted");
}

/// docs/questions/Q-950: dnsd's own audit source (`dnsd`, docs/54 §9) is not
/// in ipc-audit's closed table yet (task DN12), and dnsd borrows no other
/// process's source — with the product's expectation the check refuses
/// before auditd is even contacted, and dnsd does not start.
#[test]
fn without_its_own_audit_source_dnsd_does_not_start() {
    assert_eq!(AUDIT_SOURCE, None);
    let Some(world) = World::new(transfer(&parts(SERIAL, &[]))) else {
        return;
    };
    let mut params = world.params();
    params.audit_source = AUDIT_SOURCE;
    let mut dnsd = world.start(params);
    assert_eq!(
        dnsd.join(),
        Err(DaemonError::Audit(AuditCheckError::SourceNotRegistered))
    );
    assert_eq!(world.auditd.pings(), 0, "auditd not contacted");
    assert!(world.dird.state().fetches.is_empty(), "dird not contacted");
}

/// docs/54 §4.7 (A-114): `serve` refuses a listener whose local address
/// lies outside `internal_networks` — before auditd or dird is contacted.
#[test]
fn a_listener_outside_the_internal_networks_means_no_start() {
    let Some(world) = World::new(transfer(&parts(SERIAL, &[]))) else {
        return;
    };
    let mut params = world.params();
    params.internal_networks =
        vec![Network::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8).expect("network")];
    let mut dnsd = world.start(params);
    assert_eq!(dnsd.join(), Err(DaemonError::ListenerNotInternal));
    assert_eq!(world.auditd.pings(), 0);
    assert!(world.dird.state().fetches.is_empty());
}

/// docs/52 C18 (task R15): a product dnsd runs with the configuration's
/// values and the daemon's constants only — the product audit source
/// (`None`, Q-950), the rate limits and queue of docs/questions/Q-951, the
/// refresh interval of docs/54 §4.4 (5 s), and the channel's one deadline
/// (crates/ipc-dns `DEFAULT_DEADLINE`, Q-920 item 9).
#[test]
fn a_product_dnsd_runs_with_the_constants() {
    let product = DaemonParams {
        dird: DirdEndpoint {
            socket: "/run/dird/dns/dird-dns.sock".into(),
            uid: 802,
        },
        audit: AuditEndpoint {
            socket: "/run/auditd/audit.sock".into(),
            uid: 805,
        },
        internal_networks: vec![common::loopback_network()],
        tcp: TcpLimits {
            max_connections: 512,
            max_per_source: 8,
            first_octet_timeout: Duration::from_secs(5),
            frame_timeout: Duration::from_secs(5),
            idle_timeout: Duration::from_secs(120),
            max_requests: 64,
        },
        zone_image_max_age: Duration::from_secs(60),
    };
    let serve = ServeParams::from(product);
    assert_eq!(serve.dird_uid, 802);
    assert_eq!(serve.audit_source, None);
    assert_eq!(serve.dird_deadline, ipc_dns::DEFAULT_DEADLINE);
    assert_eq!(serve.udp, dns_daemon::limits::UDP_LIMITS);
    assert_eq!(serve.tcp_messages, dns_daemon::limits::TCP_MESSAGE_LIMITS);
    assert_eq!(serve.forwards, dns_daemon::limits::FORWARD_LIMITS);
    assert_eq!(serve.forward_queue_capacity, 32);
    assert_eq!(serve.refresh_interval, Duration::from_secs(5));
    assert_eq!(serve.forwards.per_source, 2);
    assert_eq!(serve.forwards.window, Duration::from_secs(1));
}

/// A started dnsd stops cleanly: both dird threads end and are joined.
/// Spec: docs/54 §4.8; crates/dns-daemon `Stopped::join`.
#[test]
fn a_running_dnsd_stops_and_joins_its_threads() {
    let Some(world) = World::new(transfer(&parts(SERIAL, &[]))) else {
        return;
    };
    let dnsd: Dnsd = world.start(world.params());
    assert!(dnsd.serving());
    assert_eq!(dnsd.stop(), Ok(()));
}
