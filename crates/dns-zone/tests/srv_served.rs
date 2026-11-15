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
//! port) — is docs/questions/Q-1016.
//!
//! Scope of the scan: `crates/<serving crate>/src`, every `.rs` file except
//! directories named `tests` and files named `tests.rs` (test code), with
//! line comments (`//`, `///`, `//!`) removed — a comment saying "no UDP
//! socket" is not a socket. A positive control checks the scan finds the
//! KDC's UDP socket and TCP listener, so it cannot pass vacuously.
//!
//! Sources: docs/54 §3.1 (the record set); docs/questions/Q-1004 (A-172:
//! "one SRV record per service that exists"); PENDING-OWNER A-117, A-158;
//! docs/50 §2.4 (which process serves which port); RFC 2782 (the Proto
//! label `_udp` / `_tcp`); RFC 4120 §7.2.3.2. Test-only.

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
        } else if name.ends_with(".rs") && name != "tests.rs" {
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
