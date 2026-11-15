//! dird's DNS channel keys (task DN10a): `dird_dns_socket` + `dnsd_uid` —
//! both or neither, independent of the admin channel, a path and a uid
//! distinct from every other of the file — and the zone values its image
//! takes: `dns_registrable_networks` (IPv4 only), `dns_soa_rname` (a domain
//! name), the SOA's four times and the two TTLs (required, `<n>s`, 0 ..=
//! 2147483647), `dns_record_max_age` (optional, 1s ..= 604800s, default 7
//! days); every zone key refused without the channel.
//!
//! Sources: docs/54 §3.1 (the SOA row: "RNAME and REFRESH/RETRY/EXPIRE/
//! MINIMUM — dird configuration"), §4.3, §4.6 ("dird accepts only
//! `dnsd_uid`"), §5.2 ("e.g. 7 days"), §5.5; RFC 1035 §2.3.4 ("TTL positive
//! values of a signed 32 bit number"; labels ≤ 63, names ≤ 255 octets),
//! §3.2.1, §3.3.13, §5.3, §8; docs/50 R50-3, §3.2, §7.1; docs/questions/
//! Q-619 items 4-5, Q-230 items 4, 6, 16, Q-1001. Every value is this test's
//! own (obviously fake uids and paths, addresses from 192.0.2.0/24 and
//! 198.51.100.0/24); no vector comes from any other implementation.

mod common;

use common::*;
use config::limits::{DNS_RECORD_MAX_AGE_SECS, DNS_TIME_SECS};
use config::{DirdSettings, DnsdSettings, ErrorKind};
use core::net::{IpAddr, Ipv4Addr};

/// The DNS lines added to a dird sample (test data).
const DNS: &str = "\
dird_dns_socket = /run/dird/dns/dird-dns.sock
dnsd_uid = 809
dns_registrable_networks = 192.0.2.0/24, 198.51.100.0/24
dns_soa_rname = hostmaster.example.test
dns_soa_refresh = 7200s
dns_soa_retry = 600s
dns_soa_expire = 3600000s
dns_soa_minimum = 60s
dns_infrastructure_ttl = 3600s
dns_host_ttl = 600s
dns_record_max_age = 86400s
";

/// The minimal dird sample (no admin channel) with the DNS lines.
fn with_dns() -> String {
    format!("{DIRD_MINIMAL}{DNS}")
}

/// `text` with `key`'s line set to `value` (the key must be present).
fn set(text: &str, key: &str, value: &str) -> String {
    let prefix = format!("{key} = ");
    assert!(text.lines().any(|l| l.starts_with(&prefix)), "{key}");
    text.lines()
        .map(|l| {
            if l.starts_with(&prefix) {
                format!("{prefix}{value}\n")
            } else {
                format!("{l}\n")
            }
        })
        .collect()
}

fn parse_error(text: &str) -> config::Error {
    DirdSettings::parse(text.as_bytes()).expect_err("refused")
}

/// The 1-based line of `key` in `text`.
fn line_of(text: &str, key: &str) -> Option<u32> {
    let prefix = format!("{key} = ");
    text.lines()
        .position(|line| line.starts_with(&prefix))
        .and_then(|index| u32::try_from(index + 1).ok())
}

/// docs/54 §4.6; Q-619 item 5: the channel and every zone value are read —
/// beside the minimal sample's channels, with no admin channel (the zone
/// image needs neither keyd nor the write PEP — Q-1001 item 1).
#[test]
fn the_dns_service_is_read() {
    let s = DirdSettings::parse(with_dns().as_bytes()).expect("valid");
    assert!(s.admin_channel().is_none());
    let dns = s.dns_service().expect("configured");
    assert_eq!(
        dns.channel().socket().as_path(),
        std::path::Path::new("/run/dird/dns/dird-dns.sock")
    );
    assert_eq!(dns.channel().peer_uid(), 809);
    let networks: Vec<(IpAddr, u8)> = dns
        .registrable_networks()
        .iter()
        .map(|n| (n.address(), n.prefix_len()))
        .collect();
    assert_eq!(
        networks,
        vec![
            (IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)), 24),
            (IpAddr::V4(Ipv4Addr::new(198, 51, 100, 0)), 24),
        ]
    );
    assert_eq!(dns.soa().rname(), "hostmaster.example.test");
    assert_eq!(
        [
            dns.soa().refresh(),
            dns.soa().retry(),
            dns.soa().expire(),
            dns.soa().minimum()
        ],
        [7200, 600, 3_600_000, 60]
    );
    assert_eq!(dns.infrastructure_ttl(), 3600);
    assert_eq!(dns.host_ttl(), 600);
    assert_eq!(dns.record_max_age().as_secs(), 86_400);
    // Without the DNS lines: no DNS service.
    let s = DirdSettings::parse(DIRD_MINIMAL.as_bytes()).expect("valid without");
    assert!(s.dns_service().is_none());
    // The full sample (tests/common `DIRD`: admin and kpasswd channels) has
    // them too.
    let s = DirdSettings::parse(DIRD.as_bytes()).expect("valid with all");
    assert!(s.dns_service().is_some() && s.kpasswd_channel().is_some());
    assert_eq!(s.dns_service().unwrap().channel().peer_uid(), 809);
}

/// docs/54 §5.2 ("e.g. 7 days ⚠"), read as Q-230 item 4: the default and
/// the ceiling are 7 days, the floor 1 s.
#[test]
fn the_record_max_age_defaults_to_seven_days_and_never_more() {
    let text = remove(&with_dns(), "dns_record_max_age");
    let s = DirdSettings::parse(text.as_bytes()).expect("valid");
    assert_eq!(
        s.dns_service().unwrap().record_max_age().as_secs(),
        u64::from(DNS_RECORD_MAX_AGE_SECS.default)
    );
    assert_eq!(DNS_RECORD_MAX_AGE_SECS.default, 604_800);
    for (value, ok) in [
        ("1s", true),
        ("604800s", true),
        ("604801s", false),
        ("0s", false),
    ] {
        let text = set(&with_dns(), "dns_record_max_age", value);
        let parsed = DirdSettings::parse(text.as_bytes());
        assert_eq!(parsed.is_ok(), ok, "{value}");
        if !ok {
            assert_eq!(parsed.unwrap_err().kind(), ErrorKind::OutOfRange, "{value}");
        }
    }
}

/// docs/50 §3.2 (a channel is its socket and its one peer): one key alone is
/// refused at its own line (`IncompletePair`), never half-configured.
#[test]
fn the_dns_pair_is_both_or_neither() {
    for (missing, key) in [
        ("dnsd_uid", "dird_dns_socket"),
        ("dird_dns_socket", "dnsd_uid"),
    ] {
        let text = remove(&with_dns(), missing);
        let err = parse_error(&text);
        assert_eq!(err.kind(), ErrorKind::IncompletePair, "{key}");
        assert_eq!(err.key(), Some(key));
        assert_eq!(err.line(), line_of(&text, key));
    }
}

/// Fail closed (docs/50 §7.1; Q-1001 item 1): a zone key without the
/// channel is refused at its line, never ignored; with the channel, every
/// zone key but `dns_record_max_age` is required (no hidden default —
/// docs/54 §3.1 gives none).
#[test]
fn every_zone_key_needs_the_channel_and_the_channel_needs_them() {
    let zone_keys = [
        "dns_registrable_networks",
        "dns_soa_rname",
        "dns_soa_refresh",
        "dns_soa_retry",
        "dns_soa_expire",
        "dns_soa_minimum",
        "dns_infrastructure_ttl",
        "dns_host_ttl",
    ];
    let without_channel = remove(&remove(&with_dns(), "dird_dns_socket"), "dnsd_uid");
    let err = parse_error(&without_channel);
    assert_eq!(err.kind(), ErrorKind::IncompletePair);
    assert_eq!(err.key(), Some("dns_registrable_networks"));
    assert_eq!(
        err.line(),
        line_of(&without_channel, "dns_registrable_networks")
    );
    // Each zone key alone, without the channel, is refused.
    let mut alone = remove(&without_channel, "dns_record_max_age");
    for key in zone_keys {
        alone = remove(&alone, key);
    }
    DirdSettings::parse(alone.as_bytes()).expect("nothing of DNS: valid");
    for key in zone_keys.iter().chain(["dns_record_max_age"].iter()) {
        let line = DNS
            .lines()
            .find(|l| l.starts_with(&format!("{key} = ")))
            .unwrap();
        let text = format!("{alone}{line}\n");
        let err = parse_error(&text);
        assert_eq!(err.kind(), ErrorKind::IncompletePair, "{key}");
        assert_eq!(err.key(), Some(*key));
    }
    // With the channel, each required zone key missing is refused.
    for key in zone_keys {
        let err = parse_error(&remove(&with_dns(), key));
        assert_eq!(err.kind(), ErrorKind::MissingKey, "{key}");
        assert_eq!(err.key(), Some(key));
    }
}

/// docs/54 §3.1 (A only — AAAA waits for RFC 3596), §5.5; crates/
/// directory-admin `DnsRegistration::new`: an IPv6 registrable network is
/// refused (`NetworkFamily`); every network keeps the one network rule.
#[test]
fn the_registrable_networks_are_ipv4_networks() {
    for (value, kind) in [
        ("192.0.2.0/24, 2001:db8::/32", ErrorKind::NetworkFamily),
        ("2001:db8::/32", ErrorKind::NetworkFamily),
        ("192.0.2.1/24", ErrorKind::NetworkHostBits),
        ("0.0.0.0/0", ErrorKind::NetworkTooBroad),
        ("192.0.2.0/24, 192.0.2.0/24", ErrorKind::DuplicateEntry),
    ] {
        let err = parse_error(&set(&with_dns(), "dns_registrable_networks", value));
        assert_eq!(err.kind(), kind, "{value}");
        assert_eq!(err.key(), Some("dns_registrable_networks"));
    }
}

/// RFC 1035 §2.3.4, §3.1, §3.3.13 (RNAME "a <domain-name>"), §8: RNAME is
/// labels of 1..=63 octets of `A-Z a-z 0-9 -`, at most 253 octets of text; a
/// final dot, an empty label, an escape or a longer label is refused.
#[test]
fn the_rname_is_a_domain_name() {
    let label63 = "a".repeat(63);
    let ok = [
        "hostmaster.example.test".to_owned(),
        "Host-Master.Example.Test".to_owned(),
        format!("{label63}.example.test"),
        // 4 × 63 + 3 dots = 255 > 253: one shorter label to fit 253.
        format!("{label63}.{label63}.{label63}.{}", "a".repeat(61)),
    ];
    for value in ok {
        let s = DirdSettings::parse(set(&with_dns(), "dns_soa_rname", &value).as_bytes());
        assert!(s.is_ok(), "{value}");
    }
    let bad = [
        "hostmaster.example.test.".to_owned(),
        "hostmaster..example.test".to_owned(),
        "host\\.master.example.test".to_owned(),
        "host_master.example.test".to_owned(),
        format!("{}.example.test", "a".repeat(64)),
        format!("{label63}.{label63}.{label63}.{}", "a".repeat(62)),
    ];
    for value in bad {
        let err = parse_error(&set(&with_dns(), "dns_soa_rname", &value));
        assert_eq!(err.kind(), ErrorKind::InvalidDomainName, "{value}");
    }
}

/// RFC 1035 §2.3.4 ("TTL positive values of a signed 32 bit number"),
/// §3.2.1 ("Zero values are interpreted to mean that the RR can only be used
/// for the transaction in progress"), §3.3.13 ("All times are in units of
/// seconds"): every zone time value is `<n>s` within 0 ..= 2147483647.
#[test]
fn the_zone_times_are_bounded_seconds() {
    assert_eq!((DNS_TIME_SECS.min, DNS_TIME_SECS.max), (0, 2_147_483_647));
    for key in [
        "dns_soa_refresh",
        "dns_soa_retry",
        "dns_soa_expire",
        "dns_soa_minimum",
        "dns_infrastructure_ttl",
        "dns_host_ttl",
    ] {
        for value in ["0s", "2147483647s"] {
            let text = set(&with_dns(), key, value);
            assert!(
                DirdSettings::parse(text.as_bytes()).is_ok(),
                "{key} {value}"
            );
        }
        for (value, kind) in [
            ("2147483648s", ErrorKind::OutOfRange),
            ("60", ErrorKind::InvalidDuration),
            ("1m", ErrorKind::InvalidDuration),
            ("-1s", ErrorKind::InvalidDuration),
        ] {
            let err = parse_error(&set(&with_dns(), key, value));
            assert_eq!(err.kind(), kind, "{key} {value}");
            assert_eq!(err.key(), Some(key));
        }
    }
}

/// docs/50 §2.4, §3.1 (one account per process, a socket per channel);
/// Q-230 items 6, 16: dnsd's uid and the DNS socket are distinct from every
/// other uid and path of the file.
#[test]
fn the_dns_uid_and_socket_are_distinct_from_the_others() {
    let err = parse_error(&set(&with_dns(), "dnsd_uid", "803"));
    assert_eq!(err.kind(), ErrorKind::DuplicateId);
    let err = parse_error(&set(
        &with_dns(),
        "dird_dns_socket",
        "/run/dird/kdc/dird-kdc.sock",
    ));
    assert_eq!(err.kind(), ErrorKind::DuplicatePath);
    let err = parse_error(&set(&with_dns(), "dnsd_uid", "0"));
    assert_eq!(err.kind(), ErrorKind::ReservedId);
}

/// One spelling for the server's and the client's file (docs/54 §4.6;
/// crates/config schema `DIRD_DNS_SOCKET`): dird's key is dnsd's key.
#[test]
fn dird_and_dnsd_name_the_socket_with_one_key() {
    assert!(DirdSettings::KEYS.contains(&"dird_dns_socket"));
    assert!(DnsdSettings::KEYS.contains(&"dird_dns_socket"));
    assert!(DirdSettings::KEYS.contains(&"dnsd_uid"));
    for key in DirdSettings::KEYS {
        assert!(key.len() <= config::limits::MAX_KEY_OCTETS, "{key}");
    }
}
