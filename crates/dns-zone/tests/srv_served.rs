//! Guard (task DN10b; docs/questions/Q-1004, decision A-172; AGENTS.md §6.1
//! — the class "the zone advertises an endpoint no process serves"): every
//! SRV record the zone can synthesize ([`SrvService::ALL`] — the one table of
//! the advertised set, crate::srv) names a transport its serving daemon
//! binds. A `_udp` record needs a UDP socket in the serving crate's product
//! source, a `_tcp` record a TCP listener; a Service label with no serving
//! crate below fails (fail closed: a service added to the table must say
//! who serves it).
//!
//! So the table and the daemons cannot drift apart unnoticed: putting a
//! `_kpasswd._udp` variant back while kpasswd-front binds no UDP socket
//! (A-117, A-158: "TCP 464 only") fails here, and so would a UDP listener
//! added to kpasswd-front without its record being decided.
//!
//! What a source scan cannot see — a listener *configured* away in another
//! daemon's file (an ldap-front with LDAPS listeners only; a non-standard
//! port), docs/questions/Q-1016 items 3–4 — is closed by task DN10c (A-176)
//! and guarded here and in crates/e2e-tests `tests/dns_zone.rs`:
//! [`every_srv_port_is_the_only_port_its_serving_daemon_accepts`] parses each
//! serving daemon's configuration with its listener on the record's port
//! (accepted) and on every other port of a sample (refused,
//! `NonStandardPort`), so a record's port and the port its daemon may listen
//! on cannot differ; the e2e test checks that every record a provisioned zone
//! advertises has a listener in the produced files (the StartTLS listener
//! ldap-front's own schema requires since task DN10d — Q-1016 item 3,
//! Q-1025 item 3). docs/questions/Q-1024. The NS record's name server
//! (dnsd, port 53) is guarded by `tests/ns_served.rs`.
//!
//! Scope of the scan: `crates/<serving crate>/src`, every `.rs` file except
//! directories named `tests` and files named `tests.rs` or `*_tests.rs`
//! (test code — the rule of crates/e2e-tests
//! `tests/no_test_seams_in_product.rs`), with
//! line comments (`//`, `///`, `//!`) removed — a comment saying "no UDP
//! socket" is not a socket. A positive control checks the scan finds the
//! KDC's UDP socket and TCP listener, so it cannot pass vacuously.
//!
//! Sources: docs/54 §3.1 (the record set); docs/questions/Q-1004 (A-172:
//! "one SRV record per service that exists"); PENDING-OWNER A-117, A-158;
//! docs/50 §2.4 (which process serves which port); RFC 2782 (the Proto
//! label `_udp` / `_tcp`); RFC 4120 §7.2.3.2; [MS-ADTS] v20261026
//! §6.3.2.3 (the Port field: 389, 88, 464); docs/questions/Q-1016 items
//! 3–4 (A-176), Q-1024. The configuration texts are hand-made test data
//! (documentation addresses 192.0.2.0/24, fake uids and paths). Test-only.

use config::{ErrorKind, KdcSettings, KpasswdFrontSettings, LdapFrontSettings, StandardPort};
use core::net::SocketAddr;
use dns_zone::{KpasswdService, SrvService};
use std::path::{Path, PathBuf};

/// The workspace's `crates/` directory.
fn crates_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/ directory")
        .to_path_buf()
}

/// The crate whose process serves each Service label (docs/50 §2.4: the KDC
/// on 88, ldap-front on 389, kpasswd-front on 464); `None` for a label no
/// serving crate is known for.
fn serving_crate(service: &[u8]) -> Option<&'static str> {
    match service {
        b"_kerberos" => Some("kdc-daemon"),
        b"_ldap" => Some("ldap-front"),
        b"_kpasswd" => Some("kpasswd-front"),
        _ => None,
    }
}

/// The socket type a Proto label needs in the serving crate (the tokio and
/// std type names alike).
fn socket_type(proto: &[u8]) -> Option<&'static str> {
    match proto {
        b"_udp" => Some("UdpSocket"),
        b"_tcp" => Some("TcpListener"),
        _ => None,
    }
}

/// Every product `.rs` file below `dir` (module documentation, "Scope").
fn sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .expect("readable source directory")
        .map(|e| e.expect("directory entry").path())
        .collect();
    entries.sort();
    for path in entries {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if path.is_dir() {
            if name != "tests" {
                sources(&path, out);
            }
        } else if name.ends_with(".rs") && name != "tests.rs" && !name.ends_with("_tests.rs") {
            out.push(path);
        }
    }
}

/// The product source of `krate`, without line comments.
fn product_code(krate: &str) -> String {
    let mut files = Vec::new();
    sources(&crates_dir().join(krate).join("src"), &mut files);
    assert!(!files.is_empty(), "{krate} has product source");
    let mut code = String::new();
    for file in files {
        let text = std::fs::read_to_string(&file).expect("readable source file");
        for line in text.lines() {
            code.push_str(line.split("//").next().unwrap_or(""));
            code.push('\n');
        }
    }
    code
}

/// docs/questions/Q-1004 (A-172): each synthesizable record's transport is
/// bound by its serving daemon.
#[test]
fn every_synthesizable_srv_record_names_a_transport_its_daemon_binds() {
    for service in SrvService::ALL {
        let krate = serving_crate(service.service_label())
            .unwrap_or_else(|| panic!("{service:?}: no serving crate is listed"));
        let socket = socket_type(service.proto_label())
            .unwrap_or_else(|| panic!("{service:?}: no socket type for its Proto label"));
        assert!(
            product_code(krate).contains(socket),
            "{service:?} is advertised, but {krate} binds no {socket}"
        );
    }
}

/// A-117, A-158 (kpasswd-front: TCP 464 only, no UDP socket) — the fact that
/// makes `_kpasswd._udp` unrepresentable; and with kpasswd present the zone
/// advertises exactly its TCP record.
#[test]
fn kpasswd_is_advertised_on_tcp_only_because_it_is_served_on_tcp_only() {
    let code = product_code("kpasswd-front");
    assert!(code.contains("TcpListener"));
    assert!(!code.contains("UdpSocket"));
    let kpasswd: Vec<SrvService> = SrvService::ALL
        .into_iter()
        .filter(|s| s.service_label() == b"_kpasswd")
        .collect();
    assert_eq!(kpasswd, vec![SrvService::KpasswdTcp]);
    assert!(SrvService::KpasswdTcp.synthesized_with(KpasswdService::Present));
    assert!(!SrvService::KpasswdTcp.synthesized_with(KpasswdService::Absent));
}

/// Positive control: the scan sees the KDC's UDP socket and TCP listener
/// (RFC 4120 §7.2.3.2: both `_kerberos._udp` and `_kerberos._tcp`), and a
/// comment is not code.
#[test]
fn the_scan_sees_the_kdc_sockets_and_ignores_comments() {
    let code = product_code("kdc-daemon");
    assert!(code.contains("UdpSocket") && code.contains("TcpListener"));
    let commented = "let a = 1; // UdpSocket\n";
    assert!(!commented
        .lines()
        .map(|l| l.split("//").next().unwrap_or(""))
        .any(|l| l.contains("UdpSocket")));
}

/// The key of the serving daemon's listener list for each Service label —
/// the list the zone's record for it advertises (the kdc's `listen` serves
/// UDP and TCP, ldap-front's `ldap_listen` StartTLS on TCP, kpasswd-front's
/// `listen` TCP); `None` for a label no serving configuration is known for.
fn listener_key(service: &[u8]) -> Option<&'static str> {
    match service {
        b"_kerberos" | b"_kpasswd" => Some("listen"),
        b"_ldap" => Some("ldap_listen"),
        _ => None,
    }
}

/// The serving daemon's file for `service` (docs/50 §7.1; crates/config's
/// test samples reduced to the required keys) with one listener at
/// 192.0.2.5:`port`: the addresses its schema accepted on that list, or the
/// refusal's (rule, key).
fn serving_configuration(
    service: &[u8],
    port: u16,
) -> Result<Vec<SocketAddr>, (ErrorKind, Option<&'static str>)> {
    let refusal = |e: config::Error| (e.kind(), e.key());
    let key = listener_key(service).expect("a listed Service label");
    let listener = format!("{key} = 192.0.2.5:{port}\n");
    let tail = "audit_socket = /run/auditd/audit.sock\nauditd_uid = 805\n";
    match service {
        b"_kerberos" => {
            let text = format!(
                "run_as_uid = 803\nrun_as_gid = 803\n{listener}\
                 internal_networks = 192.0.2.0/24\n\
                 keyd_socket = /run/keyd/keyd.sock\nkeyd_uid = 801\n\
                 dird_kdc_socket = /run/dird/kdc/dird-kdc.sock\ndird_uid = 802\n\
                 policy_store_path = /etc/domain/policy.store\n\
                 policy_store_format = unsigned-development\n{tail}"
            );
            KdcSettings::parse(text.as_bytes())
                .map(|s| s.listen().to_vec())
                .map_err(refusal)
        }
        b"_ldap" => {
            let text = format!(
                "run_as_uid = 804\nrun_as_gid = 804\n{listener}\
                 internal_networks = 192.0.2.0/24\n\
                 tls_certificate_path = /etc/ldap-front/dc-cert.der\n\
                 tls_private_key_path = /etc/ldap-front/dc-key.der\n\
                 dird_ldap_socket = /run/dird/ldap/dird-ldap.sock\ndird_uid = 802\n{tail}"
            );
            LdapFrontSettings::parse(text.as_bytes())
                .map(|s| s.ldap_listen().to_vec())
                .map_err(refusal)
        }
        b"_kpasswd" => {
            let text = format!(
                "run_as_uid = 4464\nrun_as_gid = 4464\n{listener}\
                 internal_networks = 192.0.2.0/24\nrealm = EXAMPLE.TEST\n\
                 dird_kpasswd_socket = /run/dird/kpasswd/dird-kpasswd.sock\n\
                 dird_uid = 4402\n{tail}"
            );
            KpasswdFrontSettings::parse(text.as_bytes())
                .map(|s| s.listen().to_vec())
                .map_err(refusal)
        }
        _ => unreachable!("listener_key lists the same labels"),
    }
}

/// Task DN10c (A-176 on docs/questions/Q-1016 item 4; Q-1024): for every
/// record the zone can synthesize, the serving daemon's schema accepts a
/// listener on the record's port and refuses it on any other port of the
/// sample — the other standard ports, the neighbours, a high port —
/// `NonStandardPort` at the listener's key. So the advertised port and the
/// only port a listener may have are one value. Fails closed for a Service
/// label with no serving configuration listed.
#[test]
fn every_srv_port_is_the_only_port_its_serving_daemon_accepts() {
    for service in SrvService::ALL {
        let label = service.service_label();
        let key = listener_key(label)
            .unwrap_or_else(|| panic!("{service:?}: no serving configuration is listed"));
        let port = service.port();
        assert_eq!(
            serving_configuration(label, port),
            Ok(vec![SocketAddr::from(([192, 0, 2, 5], port))]),
            "{service:?}: its own port is accepted"
        );
        let others = StandardPort::ALL
            .into_iter()
            .map(StandardPort::number)
            .chain([port - 1, port + 1, 1088, 50_000])
            .filter(|other| *other != port);
        for other in others {
            assert_eq!(
                serving_configuration(label, other),
                Err((ErrorKind::NonStandardPort, Some(key))),
                "{service:?}: port {other} must be refused"
            );
        }
    }
}

/// The one definition (task DN10c): each record's port is its
/// `standard_port` — crate config's — and the table uses exactly config's
/// standard ports but the name server's (RFC 4120 §7.2.3.2: 88 for both
/// Kerberos transports; [MS-ADTS] v20261026 §6.3.2.3: 389 for LDAP, 464 for
/// the Kerberos Password Change service). The name server's port (53,
/// `StandardPort::Dns`, task DN10d) is advertised by no SRV record: the NS
/// record names the server, and a name server is reached on port 53 (RFC
/// 1035 §3.3.11, §4.2) — `tests/ns_served.rs`. A new standard port fails
/// here until it says which record advertises it.
#[test]
fn the_srv_ports_are_config_s_standard_ports() {
    for service in SrvService::ALL {
        assert_eq!(service.port(), service.standard_port().number());
    }
    let mut used: Vec<StandardPort> = SrvService::ALL
        .into_iter()
        .map(SrvService::standard_port)
        .collect();
    used.dedup();
    let advertised_by_srv: Vec<StandardPort> = StandardPort::ALL
        .into_iter()
        .filter(|port| *port != StandardPort::Dns)
        .collect();
    assert_eq!(used, advertised_by_srv);
    assert!(!used.contains(&StandardPort::Dns));
    assert_eq!(SrvService::ALL.map(SrvService::port), [88, 88, 389, 464]);
}
