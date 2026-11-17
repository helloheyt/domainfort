//! Guard (task DN10d; decision A-178 on docs/questions/Q-1025 item 1;
//! docs/CLEAN-ROOM.md — the class "the zone advertises an endpoint no process
//! serves"): the zone's NS record and its SOA's MNAME name the DC as the
//! zone's name server (docs/54 §3.1), and the only port that server's
//! process — dnsd — may listen on is the one a name server is reached on.
//!
//! An NS record carries a name and nothing else (RFC 1035 §3.3.11: the RDATA
//! is NSDNAME, "a host which should be authoritative"), so no record of the
//! zone can name another port: clients go to port 53 ("name server access
//! using TCP … on server port 53 (decimal) as well as datagram access using
//! UDP … on UDP port 53 (decimal)", RFC 1035 §4.2). The port is crate
//! config's `StandardPort::Dns` — the one table the SRV records read too —
//! and dnsd's schema refuses any other (`NonStandardPort` at `listen`). This
//! guard ties the two: the synthesized NS and SOA name the DC, and dnsd's
//! schema accepts a listener on `StandardPort::Dns` and refuses every other
//! port of a sample (the other standard ports, the neighbours, a high port).
//!
//! Sources: RFC 1035 §3.3.11, §3.3.13 (MNAME "the name server that was the
//! original or primary source of data for this zone"), §4.2, §4.2.1,
//! §4.2.2; docs/54 §3.1, §3.3, §4.3; docs/questions/Q-1025 item 1 (A-178).
//! Zone values from RFC 2782's "Fictional example" (tests/common); the
//! configuration text is hand-made test data (192.0.2.0/24 addresses, fake
//! uids and paths). Test-only.

mod common;

use common::{name, query, rfc2782_zone, udp};
use config::{DnsdSettings, ErrorKind, StandardPort};
use core::net::SocketAddr;
use parse_dns::RData;

/// The QTYPE of NS. Spec: RFC 1035 §3.2.2 (NS, 2).
const T_NS: u16 = 2;
/// The QTYPE of SOA. Spec: RFC 1035 §3.2.2 (SOA, 6).
const T_SOA: u16 = 6;
/// The class IN. Spec: RFC 1035 §3.2.4 (IN, 1).
const C_IN: u16 = 1;

/// dnsd's file (crates/config's required keys) with one listener at
/// 192.0.2.53:`port`: the addresses its schema accepted, or the refusal's
/// (rule, key).
fn dnsd_with_listener(port: u16) -> Result<Vec<SocketAddr>, (ErrorKind, Option<&'static str>)> {
    let text = format!(
        "run_as_uid = 808\nrun_as_gid = 808\nlisten = 192.0.2.53:{port}\n\
         internal_networks = 192.0.2.0/24\n\
         dird_dns_socket = /run/dird/dns/dird-dns.sock\ndird_uid = 802\n\
         audit_socket = /run/auditd/audit.sock\nauditd_uid = 805\n"
    );
    DnsdSettings::parse(text.as_bytes())
        .map(|settings| settings.listen().to_vec())
        .map_err(|e| (e.kind(), e.key()))
}

/// docs/54 §3.1 (NS and MNAME: the DC); RFC 1035 §3.3.11, §3.3.13: the zone
/// advertises the DC as its name server — by name only, the NS RDATA having
/// no port.
#[test]
fn the_zone_names_the_dc_as_its_name_server() {
    let zone = rfc2782_zone();
    let ns = udp(&zone, &query(0x5301, "example.com", T_NS, C_IN, false));
    assert!(!ns.answer.is_empty(), "the zone advertises a name server");
    for record in &ns.answer {
        assert_eq!(record.rdata, RData::Ns(zone.dc_name().clone()));
    }
    assert_eq!(zone.dc_name(), &name("server.example.com"));
    let soa = udp(&zone, &query(0x5302, "example.com", T_SOA, C_IN, false));
    assert!(!soa.answer.is_empty(), "the zone has its SOA");
    for record in &soa.answer {
        match &record.rdata {
            RData::Soa(soa) => assert_eq!(&soa.mname, zone.dc_name()),
            other => panic!("not an SOA: {other:?}"),
        }
    }
}

/// Task DN10d (A-178 on docs/questions/Q-1025 item 1): the name server the
/// NS record names is reached on port 53 (RFC 1035 §4.2) — crate config's
/// `StandardPort::Dns` — and that is the only port dnsd's schema accepts:
/// any other port of the sample is `NonStandardPort` at `listen`.
#[test]
fn the_name_server_port_is_the_only_port_dnsd_accepts() {
    let port = StandardPort::Dns.number();
    assert_eq!(port, 53, "RFC 1035 §4.2: server port 53 (decimal)");
    assert_eq!(
        dnsd_with_listener(port),
        Ok(vec![SocketAddr::from(([192, 0, 2, 53], port))]),
        "its own port is accepted"
    );
    let others = StandardPort::ALL
        .into_iter()
        .map(StandardPort::number)
        .chain([port - 1, port + 1, 5353, 50_000])
        .filter(|other| *other != port);
    for other in others {
        assert_eq!(
            dnsd_with_listener(other),
            Err((ErrorKind::NonStandardPort, Some("listen"))),
            "port {other} must be refused"
        );
    }
}
