//! dnsd's configuration file (task DN11): a valid file parses into the typed
//! settings; every rule of the schema rejects what it must, with its typed
//! error, its line and its key; and no input derived from the sample makes
//! the parser panic or name a foreign key.
//!
//! The samples are written for these tests from the settings docs/54 and
//! docs/questions/Q-619 item 4 name for dnsd; the account ids (801..809) and
//! paths are arbitrary test values; the limits are the docs/54 §6.7 values
//! or tighter. Each test names its source. (The shared samples in `common`
//! are left as they are: this file is self-contained.)

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use core::time::Duration;

use config::{
    DnsdSettings, Error, ErrorKind, StandardPort, DNSD_MAX_REQUESTS_PER_TCP_CONNECTION_BOUND,
    DNSD_MAX_TCP_CONNECTIONS_BOUND, DNSD_MAX_TCP_CONNECTIONS_PER_SOURCE_BOUND,
    DNSD_TCP_FIRST_OCTET_TIMEOUT_SECS, DNSD_TCP_FRAME_TIMEOUT_SECS, DNSD_TCP_IDLE_TIMEOUT_SECS,
    ZONE_IMAGE_MAX_AGE_SECS,
};

/// dnsd, every key present. Spec: docs/54 §4.3, §4.4, §4.6, §4.7, §6.7;
/// docs/questions/Q-619 item 4; docs/50 §7.1.
const DNSD: &str = "\
# dnsd - docs/54 s4.3
run_as_uid = 808
run_as_gid = 808
listen = 192.0.2.53:53, [fd00:1234::35]:53
internal_networks = 192.0.2.0/24, fd00:1234::/32
dird_dns_socket = /run/dird/dns/dird-dns.sock
dird_uid = 802
audit_socket = /run/auditd/audit.sock
auditd_uid = 805
zone_image_max_age = 45s
max_tcp_connections = 256
max_tcp_connections_per_source = 4
tcp_first_octet_timeout = 3s
tcp_frame_timeout = 4s
tcp_idle_timeout = 90s
max_requests_per_tcp_connection = 32
";

/// dnsd, required keys only. Spec: docs/50 §7.1 (optional keys default).
const DNSD_MINIMAL: &str = "\
run_as_uid = 808
run_as_gid = 808
listen = 192.0.2.53:53
internal_networks = 192.0.2.0/24
dird_dns_socket = /run/dird/dns/dird-dns.sock
dird_uid = 802
audit_socket = /run/auditd/audit.sock
auditd_uid = 805
";

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

/// `text` with the line of `key` replaced by `key = value` (the key must be
/// present).
fn set(text: &str, key: &str, value: &str) -> String {
    let prefix = format!("{key} = ");
    let mut found = false;
    let out: Vec<String> = text
        .lines()
        .map(|line| {
            if line.starts_with(&prefix) {
                found = true;
                format!("{key} = {value}")
            } else {
                line.to_owned()
            }
        })
        .collect();
    assert!(found, "{key} not in the sample");
    out.join("\n") + "\n"
}

/// `text` without the line of `key`.
fn remove(text: &str, key: &str) -> String {
    let prefix = format!("{key} = ");
    let out: Vec<&str> = text
        .lines()
        .filter(|line| !line.starts_with(&prefix))
        .collect();
    out.join("\n") + "\n"
}

/// `text` with `line` appended.
fn append(text: &str, line: &str) -> String {
    format!("{text}{line}\n")
}

/// The 1-based line of `key` in `text`.
fn line_of(text: &str, key: &str) -> Option<u32> {
    let prefix = format!("{key} = ");
    text.lines()
        .position(|line| line.starts_with(&prefix))
        .and_then(|index| u32::try_from(index + 1).ok())
}

fn error(text: &str) -> Error {
    DnsdSettings::parse(text.as_bytes()).expect_err("the input must be rejected")
}

/// The sample with `key = value` is rejected with `kind`, at `key`'s line,
/// naming `key`.
fn rejects_value(key: &'static str, value: &str, kind: ErrorKind) {
    let text = set(DNSD, key, value);
    let err = error(&text);
    assert_eq!(err.kind(), kind, "{key} = {value}: {err}");
    assert_eq!(err.key(), Some(key), "{key} = {value}");
    assert_eq!(err.line(), line_of(&text, key), "{key} = {value}");
}

/// The sample with `key = value` is accepted.
fn accepts_value(key: &str, value: &str) {
    let text = set(DNSD, key, value);
    assert!(
        DnsdSettings::parse(text.as_bytes()).is_ok(),
        "{key} = {value}"
    );
}

// ---- samples ----------------------------------------------------------------

/// Spec: docs/54 §4.3 (the process row: UDP/TCP 53 on internal addresses,
/// talks to dird and auditd), §4.4 (`zone_image_max_age`), §4.6
/// (`dird-dns.sock`, dird's uid verified), §4.7 (`internal_networks`
/// mandatory), §6.7 (TCP limits); docs/questions/Q-619 item 4.
#[test]
fn dnsd_sample_parses() {
    let s = DnsdSettings::parse(DNSD.as_bytes()).expect("valid dnsd file");
    assert_eq!((s.run_as().uid(), s.run_as().gid()), (808, 808));
    assert_eq!(
        s.listen(),
        [
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53)), 53),
            SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0xfd00, 0x1234, 0, 0, 0, 0, 0, 0x35)),
                53
            ),
        ]
    );
    assert_eq!(s.internal_networks().len(), 2);
    assert_eq!(
        s.internal_networks()[0].address(),
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0))
    );
    assert_eq!(s.internal_networks()[1].prefix_len(), 32);
    assert_eq!(s.dird().socket().as_str(), "/run/dird/dns/dird-dns.sock");
    assert_eq!(s.dird().uid(), 802);
    assert_eq!(s.audit().socket().as_str(), "/run/auditd/audit.sock");
    assert_eq!(s.audit().uid(), 805);
    let l = s.limits();
    assert_eq!(l.zone_image_max_age(), secs(45));
    assert_eq!(l.max_tcp_connections(), 256);
    assert_eq!(l.max_tcp_connections_per_source(), 4);
    assert_eq!(l.tcp_first_octet_timeout(), secs(3));
    assert_eq!(l.tcp_frame_timeout(), secs(4));
    assert_eq!(l.tcp_idle_timeout(), secs(90));
    assert_eq!(l.max_requests_per_tcp_connection(), 32);
}

/// Absent limits take the docs/54 value (default and ceiling, Q-230 item 4):
/// 60 s staleness (docs/54 §4.4), 512 / 8 connections, 5 s / 5 s / 120 s,
/// 64 messages (docs/54 §6.7).
#[test]
fn dnsd_minimal_sample_takes_defaults() {
    let s = DnsdSettings::parse(DNSD_MINIMAL.as_bytes()).expect("valid dnsd file");
    let l = s.limits();
    assert_eq!(l.zone_image_max_age(), secs(60));
    assert_eq!(l.max_tcp_connections(), 512);
    assert_eq!(l.max_tcp_connections_per_source(), 8);
    assert_eq!(l.tcp_first_octet_timeout(), secs(5));
    assert_eq!(l.tcp_frame_timeout(), secs(5));
    assert_eq!(l.tcp_idle_timeout(), secs(120));
    assert_eq!(l.max_requests_per_tcp_connection(), 64);
}

/// The published bounds are the docs/54 values. Spec: docs/54 §4.4, §6.7;
/// docs/questions/Q-616 items 6, 10; Q-951 (the 30 s floor).
#[test]
fn dnsd_bounds_are_the_documented_values() {
    assert_eq!(
        (
            ZONE_IMAGE_MAX_AGE_SECS.min,
            ZONE_IMAGE_MAX_AGE_SECS.max,
            ZONE_IMAGE_MAX_AGE_SECS.default
        ),
        (30, 60, 60)
    );
    assert_eq!(DNSD_MAX_TCP_CONNECTIONS_BOUND.max, 512);
    assert_eq!(DNSD_MAX_TCP_CONNECTIONS_PER_SOURCE_BOUND.max, 8);
    assert_eq!(DNSD_TCP_FIRST_OCTET_TIMEOUT_SECS.max, 5);
    assert_eq!(DNSD_TCP_FRAME_TIMEOUT_SECS.max, 5);
    assert_eq!(DNSD_TCP_IDLE_TIMEOUT_SECS.max, 120);
    assert_eq!(DNSD_MAX_REQUESTS_PER_TCP_CONNECTION_BOUND.max, 64);
}

// ---- the closed key table and required keys --------------------------------

/// Spec: docs/50 R50-15 ("a closed key table per daemon"), §7.1 ("unknown
/// key ⇒ do not start"). dnsd has no keyd endpoint (docs/54 §4.3: not mapped
/// in keyd), no `dns_registrable_networks` (dird's rule, Q-951), no deadline
/// key (the channel's one value, Q-920 item 9).
#[test]
fn dnsd_keys_are_a_closed_table() {
    for line in [
        "keyd_socket = /run/keyd/keyd.sock",
        "keyd_uid = 801",
        "dns_registrable_networks = 192.0.2.0/24",
        "dird_deadline = 20s",
        "policy_store_path = /etc/domain/policy.store",
    ] {
        let err = error(&append(DNSD, line));
        assert_eq!(err.kind(), ErrorKind::UnknownKey, "{line}");
        assert_eq!(err.key(), None, "an unknown key is never echoed: {line}");
    }
    let err = error(&append(DNSD, "dird_uid = 802"));
    assert_eq!(err.kind(), ErrorKind::DuplicateKey);
}

/// Spec: docs/50 §7.1 ("missing-required ⇒ do not start"); docs/54 §4.7
/// (`internal_networks` mandatory), §4.6 (dird endpoint), §4.8 (auditd).
#[test]
fn dnsd_required_keys_are_required() {
    for key in [
        "run_as_uid",
        "run_as_gid",
        "listen",
        "internal_networks",
        "dird_dns_socket",
        "dird_uid",
        "audit_socket",
        "auditd_uid",
    ] {
        let err = error(&remove(DNSD_MINIMAL, key));
        assert_eq!(err.kind(), ErrorKind::MissingKey, "{key}");
        assert_eq!(err.key(), Some(key), "{key}");
    }
}

// ---- listeners ---------------------------------------------------------------

/// Every listener lies in an internal network (`ListenerNotInternal` at
/// `listen`), by the one match; a listener names one interface.
/// Spec: docs/54 §4.7 (A-114: "every listener address inside it, otherwise
/// the configuration is refused"); docs/50 §4.1; docs/questions/Q-230 item 7.
#[test]
fn dnsd_listeners_must_be_internal_interface_addresses() {
    rejects_value("listen", "198.51.100.53:53", ErrorKind::ListenerNotInternal);
    rejects_value(
        "listen",
        "192.0.2.53:53, [fd00:5678::35]:53",
        ErrorKind::ListenerNotInternal,
    );
    // An IPv4-mapped IPv6 listener is not rewritten into IPv4 (Q-275 item
    // 9): outside the IPv4 network.
    rejects_value(
        "listen",
        "[::ffff:192.0.2.53]:53",
        ErrorKind::ListenerNotInternal,
    );
    rejects_value("listen", "0.0.0.0:53", ErrorKind::NotAnInterfaceAddress);
    rejects_value("listen", "[::]:53", ErrorKind::NotAnInterfaceAddress);
    rejects_value("listen", "192.0.2.53:0", ErrorKind::InvalidSocketAddress);
    rejects_value(
        "listen",
        "192.0.2.53:53, 192.0.2.53:53",
        ErrorKind::DuplicateEntry,
    );
    rejects_value(
        "listen",
        "dc1.example.test:53",
        ErrorKind::InvalidSocketAddress,
    );
    accepts_value("listen", "192.0.2.54:53");
}

/// Task DN10d (A-178 on docs/questions/Q-1025 item 1): the zone's NS record
/// names the DC as its name server, reached on port 53 — the NS RDATA is a
/// name only (RFC 1035 §3.3.11) and "name server access using TCP … on
/// server port 53 (decimal) as well as datagram access using UDP … on UDP
/// port 53 (decimal)" (RFC 1035 §4.2). So every `listen` address is on
/// [`StandardPort::Dns`] (53) — any other port, also on one address of
/// several, is `NonStandardPort` at `listen`'s line, the value not echoed;
/// the rule runs before the zone-table rule; the addresses stay the
/// operator's. Addresses are the sample's test values (192.0.2.0/24,
/// fd00:1234::/32).
#[test]
fn dnsd_listeners_take_only_port_53() {
    assert_eq!(StandardPort::Dns.number(), 53);
    for value in [
        "192.0.2.53:5353",
        "192.0.2.53:52",
        "192.0.2.53:54",
        "192.0.2.53:88",
        "192.0.2.53:5300",
        "192.0.2.53:53, [fd00:1234::35]:5353",
        "[fd00:1234::35]:1053",
    ] {
        rejects_value("listen", value, ErrorKind::NonStandardPort);
        let err = error(&set(DNSD, "listen", value));
        assert!(!err.to_string().contains("192.0.2.53"), "no echo: {err}");
    }
    // Off the port and outside the zone table: the port rule speaks first.
    rejects_value("listen", "198.51.100.53:5353", ErrorKind::NonStandardPort);
    accepts_value("listen", "192.0.2.7:53, [fd00:1234::7]:53");
    let s = DnsdSettings::parse(DNSD.as_bytes()).expect("valid");
    assert!(s
        .listen()
        .iter()
        .all(|address| address.port() == StandardPort::Dns.number()));
}

/// Spec: docs/50 §4.1 (CIDR); docs/questions/Q-230 item 8.
#[test]
fn dnsd_internal_networks_are_canonical() {
    rejects_value(
        "internal_networks",
        "192.0.2.1/24, fd00:1234::/32",
        ErrorKind::NetworkHostBits,
    );
    rejects_value("internal_networks", "0.0.0.0/0", ErrorKind::NetworkTooBroad);
    rejects_value("internal_networks", "192.0.2.0", ErrorKind::InvalidNetwork);
}

// ---- accounts and endpoints ----------------------------------------------------

/// Spec: docs/50 R50-3 ("uid 0 is never mapped"), §2.4 (one account per
/// process), §3.1 (a socket per server and channel); docs/questions/Q-230
/// items 6, 16.
#[test]
fn dnsd_accounts_and_endpoints_are_distinct_and_never_root() {
    rejects_value("run_as_uid", "0", ErrorKind::ReservedId);
    rejects_value("dird_uid", "0", ErrorKind::ReservedId);
    rejects_value("auditd_uid", "4294967295", ErrorKind::ReservedId);
    rejects_value("auditd_uid", "802", ErrorKind::DuplicateId);
    rejects_value("dird_uid", "808", ErrorKind::DuplicateId);
    rejects_value(
        "audit_socket",
        "/run/dird/dns/dird-dns.sock",
        ErrorKind::DuplicatePath,
    );
    rejects_value("dird_dns_socket", "run/dird.sock", ErrorKind::InvalidPath);
    rejects_value(
        "dird_dns_socket",
        "$RUNTIME/dird.sock",
        ErrorKind::InvalidPath,
    );
}

// ---- limits -------------------------------------------------------------------

/// The staleness bound: 30 s ..= 60 s. Spec: docs/54 §4.4 ("for example
/// 60 s"); docs/questions/Q-616 item 6, Q-230 item 4, Q-951 (the floor).
#[test]
fn dnsd_zone_image_max_age_is_bounded() {
    rejects_value("zone_image_max_age", "61s", ErrorKind::OutOfRange);
    rejects_value("zone_image_max_age", "29s", ErrorKind::OutOfRange);
    rejects_value("zone_image_max_age", "0s", ErrorKind::OutOfRange);
    rejects_value("zone_image_max_age", "45", ErrorKind::InvalidDuration);
    accepts_value("zone_image_max_age", "30s");
    accepts_value("zone_image_max_age", "60s");
}

/// Every TCP limit stops at its docs/54 value (an operator may tighten,
/// never loosen — Q-230 item 4) and is at least 1.
/// Spec: docs/54 §6.7; RFC 1035 §4.2.2 (idle "on the order of two minutes").
#[test]
fn dnsd_tcp_limits_stop_at_the_documented_value() {
    for (key, above) in [
        ("max_tcp_connections", "513"),
        ("max_tcp_connections_per_source", "9"),
        ("tcp_first_octet_timeout", "6s"),
        ("tcp_frame_timeout", "6s"),
        ("tcp_idle_timeout", "121s"),
        ("max_requests_per_tcp_connection", "65"),
    ] {
        rejects_value(key, above, ErrorKind::OutOfRange);
    }
    for (key, zero) in [
        ("max_tcp_connections", "0"),
        ("max_tcp_connections_per_source", "0"),
        ("tcp_first_octet_timeout", "0s"),
        ("tcp_frame_timeout", "0s"),
        ("tcp_idle_timeout", "0s"),
        ("max_requests_per_tcp_connection", "0"),
    ] {
        rejects_value(key, zero, ErrorKind::OutOfRange);
    }
    accepts_value("max_tcp_connections", "512");
    accepts_value("tcp_idle_timeout", "120s");
}

/// The per-source bound never exceeds the global bound; reported at the
/// later key. Spec: docs/54 §6.7; docs/questions/Q-230 item 4.
#[test]
fn dnsd_connection_bounds_are_consistent() {
    let text = set(DNSD, "max_tcp_connections", "3");
    let err = error(&text);
    assert_eq!(err.kind(), ErrorKind::InconsistentLimits);
    assert_eq!(err.key(), Some("max_tcp_connections_per_source"));
    assert_eq!(err.line(), line_of(&text, "max_tcp_connections_per_source"));
    // Only the global bound given: the per-source default (8) is above it.
    let text = append(DNSD_MINIMAL, "max_tcp_connections = 2");
    let err = error(&text);
    assert_eq!(err.kind(), ErrorKind::InconsistentLimits);
    assert_eq!(err.key(), Some("max_tcp_connections"));
}

// ---- robustness ---------------------------------------------------------------

/// An error names, at most, a key of dnsd's own table, with a 1-based line.
fn check(input: &[u8]) {
    if let Err(err) = DnsdSettings::parse(input) {
        if let Some(key) = err.key() {
            assert!(DnsdSettings::KEYS.contains(&key), "foreign key {key}");
        }
        if let Some(line) = err.line() {
            assert!(line >= 1);
        }
        // The description never carries input text (A-60).
        let shown = err.to_string();
        assert!(!shown.contains("/run/dird"), "{shown}");
        assert!(!shown.contains("192.0.2"), "{shown}");
    }
}

/// Truncation and mutation sweep over the sample: no panic, every cut file
/// is refused, every error names only a key of dnsd's table and no input
/// text. (Arbitrary inputs are the fuzz target's job — docs/50 §9,
/// `config_file`; docs/54 §10.3 `config_dnsd`.)
/// Spec: docs/CLEAN-ROOM.md (strict, bounded parsers); docs/50 R50-15, §7.1.
#[test]
fn dnsd_sweep_never_panics() {
    const SUBSTITUTES: &[u8] = &[
        0x00, b'\t', b'\n', b'\r', b' ', b'#', b'=', b',', b':', b'/', b'.', b'0', b'9', b'a',
        b'$', b's', b'-', b'[', b']', 0x7F, 0xFF,
    ];
    let sample = DNSD.as_bytes();
    for cut in 0..sample.len() {
        let input = &sample[..cut];
        check(input);
        if !input.is_empty() && input.last() != Some(&b'\n') {
            assert!(DnsdSettings::parse(input).is_err(), "cut at {cut}");
        }
    }
    for at in 0..sample.len() {
        for &octet in SUBSTITUTES {
            let mut input = sample.to_vec();
            input[at] = octet;
            check(&input);
        }
        let mut input = sample.to_vec();
        input.remove(at);
        check(&input);
    }
}
