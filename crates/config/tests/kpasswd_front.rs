//! kpasswd-front's configuration schema (`KpasswdFrontSettings`): the
//! sample, the defaults, the closed key table, the required keys, the
//! internal-listener rule, the limits and their bounds, the uid and path
//! rules, and no echo.
//!
//! Each test names its source: docs/53 R53-3 (TCP 464 only, inside
//! `internal_networks`), §3.3, §5.1 (the kdc's connection quotas; the first
//! frame within 10 s), §5.6, §5.7 (the realm of the KRB-ERROR); docs/50
//! R50-15, §3.2, §3.6, §4.1, §7.1; docs/52 R14; or the Q-230 interpretation
//! (A-60) the input exercises. The sample is constructed by hand for this
//! test (obviously fake uids, paths, and the TEST-NET-1 192.0.2.0/24 and
//! documentation 2001:db8::/32 ranges); no vector comes from any other
//! implementation.

use config::limits::MAX_LIST_ITEMS;
use config::{ErrorKind, KpasswdFrontSettings, StandardPort, DIRD_KPASSWD_DEADLINE_SECS};
use std::time::Duration;

/// A complete kpasswd-front file. Source: docs/53 R53-3, §3.3, §5.1, §5.7;
/// docs/50 §3.2, §3.6, §4.1, §7.1.
const SAMPLE: &str = "\
# kpasswd-front: RFC 3244 on TCP 464 (docs/53 K8)
run_as_uid = 4464
run_as_gid = 4464
listen = 192.0.2.5:464, [2001:db8::5]:464
internal_networks = 192.0.2.0/24, 2001:db8::/32
realm = EXAMPLE.TEST
dird_kpasswd_socket = /run/dird/kpasswd/dird-kpasswd.sock
dird_uid = 4402
audit_socket = /run/auditd/audit.sock
auditd_uid = 4405
max_tcp_connections = 256
max_tcp_connections_per_source = 4
tcp_first_frame_timeout = 5s
tcp_frame_timeout = 3s
dird_deadline = 15s
";

/// The optional keys of the sample (docs/50 §7.1: optional keys default).
const OPTIONAL: [&str; 5] = [
    "max_tcp_connections",
    "max_tcp_connections_per_source",
    "tcp_first_frame_timeout",
    "tcp_frame_timeout",
    "dird_deadline",
];

fn set(text: &str, key: &str, value: &str) -> String {
    let prefix = format!("{key} = ");
    text.lines()
        .map(|line| {
            if line.starts_with(&prefix) {
                format!("{prefix}{value}")
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

fn remove(text: &str, key: &str) -> String {
    let prefix = format!("{key} = ");
    text.lines()
        .filter(|line| !line.starts_with(&prefix))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

fn kind(text: &str) -> ErrorKind {
    KpasswdFrontSettings::parse(text.as_bytes())
        .expect_err("must be rejected")
        .kind()
}

/// docs/53 R53-3, §3.3, §5.1, §5.7; docs/50 §3.2, §3.6, §4.1: the sample is
/// accepted with its values.
#[test]
fn the_sample_is_accepted() {
    let s = KpasswdFrontSettings::parse(SAMPLE.as_bytes()).unwrap();
    assert_eq!((s.run_as().uid(), s.run_as().gid()), (4464, 4464));
    assert_eq!(s.listen().len(), 2);
    assert_eq!(s.listen()[0].to_string(), "192.0.2.5:464");
    assert_eq!(s.listen()[1].to_string(), "[2001:db8::5]:464");
    assert_eq!(s.internal_networks().len(), 2);
    assert_eq!(s.realm(), "EXAMPLE.TEST");
    assert_eq!(
        s.dird().socket().as_str(),
        "/run/dird/kpasswd/dird-kpasswd.sock"
    );
    assert_eq!(s.dird().uid(), 4402);
    assert_eq!(s.audit().socket().as_str(), "/run/auditd/audit.sock");
    assert_eq!(s.audit().uid(), 4405);
    let limits = s.limits();
    assert_eq!(limits.max_tcp_connections(), 256);
    assert_eq!(limits.max_tcp_connections_per_source(), 4);
    assert_eq!(limits.tcp_first_frame_timeout(), Duration::from_secs(5));
    assert_eq!(limits.tcp_frame_timeout(), Duration::from_secs(3));
    assert_eq!(limits.dird_deadline(), Duration::from_secs(15));
}

/// docs/50 §4.1 (1024 connections, 16 per source, the first frame and a
/// frame within 10 s), §3.6; docs/53 §5.1, §5.6 (crates/ipc-kpasswd
/// `DEFAULT_DEADLINE`, 25 s); Q-230 item 4 (the documented value is the
/// default and the ceiling): without the optional keys, the defaults.
#[test]
fn the_optional_keys_default() {
    let mut text = SAMPLE.to_owned();
    for key in OPTIONAL {
        text = remove(&text, key);
    }
    let limits = *KpasswdFrontSettings::parse(text.as_bytes())
        .unwrap()
        .limits();
    assert_eq!(limits.max_tcp_connections(), 1024);
    assert_eq!(limits.max_tcp_connections_per_source(), 16);
    assert_eq!(limits.tcp_first_frame_timeout(), Duration::from_secs(10));
    assert_eq!(limits.tcp_frame_timeout(), Duration::from_secs(10));
    assert_eq!(limits.dird_deadline(), Duration::from_secs(25));
    assert_eq!(DIRD_KPASSWD_DEADLINE_SECS.default, 25);
}

/// docs/50 R50-15 (closed key table, every required key present): each
/// required key, removed, is `MissingKey`; an unknown key — a UDP listener
/// key above all (A-117: no UDP code path) — is `UnknownKey`; a repeated
/// key is `DuplicateKey`.
#[test]
fn the_key_table_is_closed() {
    for key in KpasswdFrontSettings::KEYS {
        if OPTIONAL.contains(key) {
            continue;
        }
        assert_eq!(kind(&remove(SAMPLE, key)), ErrorKind::MissingKey, "{key}");
    }
    for unknown in [
        "udp_listen = 192.0.2.5:464",
        "listen_udp = 192.0.2.5:464",
        "tcp_idle_timeout = 5s",
        "keyd_socket = /run/keyd/keyd.sock",
    ] {
        assert_eq!(
            kind(&format!("{SAMPLE}{unknown}\n")),
            ErrorKind::UnknownKey,
            "{unknown}"
        );
    }
    assert_eq!(
        kind(&format!("{SAMPLE}realm = EXAMPLE.TEST\n")),
        ErrorKind::DuplicateKey
    );
}

/// docs/53 §3.3 ("every listen address inside them"); docs/52 R14: a
/// listener outside every internal network is `ListenerNotInternal`; the
/// zone table may not be the whole address space (`NetworkTooBroad`);
/// docs/50 §7.1 / Q-230 item 7: unspecified and port-0 listeners are
/// refused.
#[test]
fn listeners_must_be_internal_interfaces() {
    assert_eq!(
        kind(&set(SAMPLE, "listen", "198.51.100.5:464")),
        ErrorKind::ListenerNotInternal
    );
    assert_eq!(
        kind(&set(SAMPLE, "internal_networks", "192.0.2.0/24")),
        ErrorKind::ListenerNotInternal
    );
    assert_eq!(
        kind(&set(SAMPLE, "internal_networks", "0.0.0.0/0")),
        ErrorKind::NetworkTooBroad
    );
    assert_eq!(
        kind(&set(SAMPLE, "listen", "0.0.0.0:464")),
        ErrorKind::NotAnInterfaceAddress
    );
    assert_eq!(
        kind(&set(SAMPLE, "listen", "192.0.2.5:0")),
        ErrorKind::InvalidSocketAddress
    );
    assert_eq!(
        kind(&set(SAMPLE, "listen", "192.0.2.5:464, 192.0.2.5:464")),
        ErrorKind::DuplicateEntry
    );
    let many: Vec<String> = (0..=MAX_LIST_ITEMS)
        .map(|n| format!("192.0.2.5:{}", 1000 + n))
        .collect();
    assert_eq!(
        kind(&set(SAMPLE, "listen", &many.join(", "))),
        ErrorKind::TooManyItems
    );
}

/// Task DN10c (A-176 on docs/questions/Q-1016 item 4; Q-1024): the zone
/// advertises `_kpasswd._tcp` on port 464 ([MS-ADTS] §6.3.2.3: "Set to 464
/// for Kerberos Password Change service"; RFC 3244 §2), so every `listen`
/// address is on [`StandardPort::Kpasswd`] — any other port, also on one
/// address of several, is `NonStandardPort` at `listen`; the addresses stay
/// the operator's.
#[test]
fn listeners_take_only_port_464() {
    assert_eq!(StandardPort::Kpasswd.number(), 464);
    for value in [
        "192.0.2.5:465",
        "192.0.2.5:88",
        "192.0.2.5:1464",
        "192.0.2.5:464, [2001:db8::5]:4464",
    ] {
        let err = KpasswdFrontSettings::parse(set(SAMPLE, "listen", value).as_bytes())
            .expect_err("a port other than 464 is refused");
        assert_eq!(err.kind(), ErrorKind::NonStandardPort, "{value}");
        assert_eq!(err.key(), Some("listen"), "{value}");
    }
    let s = KpasswdFrontSettings::parse(
        set(SAMPLE, "listen", "192.0.2.9:464, [2001:db8::9]:464").as_bytes(),
    )
    .expect("any internal address on 464");
    assert_eq!(s.listen().len(), 2);
}

/// docs/50 §4.1, Q-230 item 4 (a limit within 1 ..= its documented value;
/// the per-source bound never above the global bound); docs/53 §5.1, §5.6
/// (the dird deadline 11 s ..= 25 s): out-of-range values are refused.
#[test]
fn limits_are_bounded() {
    for (key, value) in [
        ("max_tcp_connections", "0"),
        ("max_tcp_connections", "1025"),
        ("max_tcp_connections_per_source", "17"),
        ("max_tcp_connections_per_source", "0"),
    ] {
        assert_eq!(
            kind(&set(SAMPLE, key, value)),
            ErrorKind::OutOfRange,
            "{key} = {value}"
        );
    }
    for (key, value) in [
        ("tcp_first_frame_timeout", "11s"),
        ("tcp_first_frame_timeout", "0s"),
        ("tcp_frame_timeout", "11s"),
        ("dird_deadline", "10s"),
        ("dird_deadline", "26s"),
    ] {
        assert_eq!(
            kind(&set(SAMPLE, key, value)),
            ErrorKind::OutOfRange,
            "{key} = {value}"
        );
    }
    assert_eq!(
        kind(&set(SAMPLE, "tcp_frame_timeout", "3")),
        ErrorKind::InvalidDuration
    );
    let inconsistent = set(
        &set(SAMPLE, "max_tcp_connections", "4"),
        "max_tcp_connections_per_source",
        "8",
    );
    assert_eq!(kind(&inconsistent), ErrorKind::InconsistentLimits);
}

/// docs/50 R50-3, §3.2 (uid 0 never mapped; one account per process —
/// Q-230 item 6), §3.1 (a socket per server — item 16); docs/53 §5.7 (a
/// realm of `A-Z a-z 0-9 . -`, Q-230 item 15).
#[test]
fn ids_paths_and_the_realm_are_checked() {
    assert_eq!(kind(&set(SAMPLE, "dird_uid", "0")), ErrorKind::ReservedId);
    assert_eq!(kind(&set(SAMPLE, "run_as_uid", "0")), ErrorKind::ReservedId);
    assert_eq!(
        kind(&set(SAMPLE, "auditd_uid", "4402")),
        ErrorKind::DuplicateId
    );
    assert_eq!(
        kind(&set(SAMPLE, "run_as_uid", "4405")),
        ErrorKind::DuplicateId
    );
    assert_eq!(
        kind(&set(
            SAMPLE,
            "audit_socket",
            "/run/dird/kpasswd/dird-kpasswd.sock"
        )),
        ErrorKind::DuplicatePath
    );
    assert_eq!(
        kind(&set(SAMPLE, "dird_kpasswd_socket", "run/dird.sock")),
        ErrorKind::InvalidPath
    );
    for realm in ["EXAMPLE_TEST", "EXAMPLE TEST", "$REALM"] {
        assert_eq!(
            kind(&set(SAMPLE, "realm", realm)),
            ErrorKind::InvalidRealm,
            "{realm}"
        );
    }
}

/// docs/50 §7.1 (no environment interpolation, no secret in the file;
/// errors never echo input — A-60): a refused value never appears in the
/// error text.
#[test]
fn errors_do_not_echo_values() {
    for (key, value) in [
        ("realm", "s3cr3t$VALUE"),
        ("listen", "s3cr3t-host:464"),
        ("dird_kpasswd_socket", "/run/$s3cr3t"),
    ] {
        let error = KpasswdFrontSettings::parse(set(SAMPLE, key, value).as_bytes()).unwrap_err();
        let text = format!("{error} {error:?}");
        assert!(!text.contains("s3cr3t"), "{text}");
    }
}
