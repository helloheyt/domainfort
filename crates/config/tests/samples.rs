//! A valid file for each daemon parses into the typed settings docs/50 names.
//!
//! Each test names its source: the docs/50 section that lists the setting.
//! Samples are in `common` (test values written for these tests).

mod common;

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use core::time::Duration;

use common::{remove, set, Daemon, ALL};
use config::{
    AdmindSettings, AuditSource, AuditdSettings, DirdSettings, IntegrityKeySource, KdcSettings,
    KeyStoreKind, KeydSettings, LdapFrontSettings, PolicyStoreFormat, RoleName,
};

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

fn v4(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), port)
}

fn fd00_1234(last: u16, port: u16) -> SocketAddr {
    let ip = Ipv6Addr::new(0xfd00, 0x1234, 0, 0, 0, 0, 0, last);
    SocketAddr::new(IpAddr::V6(ip), port)
}

/// Spec: docs/50 §2.4 (keyd), R50-3 / §3.2 (the `uid → Role` map), R50-18 /
/// §7.3 (key store), §3.6 (limits), §7.1.
#[test]
fn keyd_sample_parses() {
    let s = KeydSettings::parse(common::KEYD.as_bytes()).expect("valid keyd file");
    assert_eq!((s.run_as().uid(), s.run_as().gid()), (801, 801));
    assert_eq!(s.realm(), "EXAMPLE.TEST");
    assert_eq!(s.keyd_socket().as_str(), "/run/keyd/keyd.sock");
    let roles: Vec<_> = s.uid_roles().iter().collect();
    assert_eq!(
        roles,
        [
            (803, RoleName::Kdc),
            (806, RoleName::Directory),
            (807, RoleName::Admin),
            (802, RoleName::Ldap),
        ]
    );
    assert_eq!(s.uid_roles().role_of(803), Some(RoleName::Kdc));
    assert_eq!(s.uid_roles().role_of(804), None, "unmapped uid has no role");
    assert_eq!(s.uid_roles().role_of(0), None, "uid 0 is never mapped");
    assert_eq!(s.uid_roles().len(), 4);
    assert!(!s.uid_roles().is_empty());
    assert_eq!(s.key_store(), KeyStoreKind::InsecureDevelopment);
    assert_eq!(s.audit().socket().as_str(), "/run/auditd/audit.sock");
    assert_eq!(s.audit().uid(), 805);
    assert_eq!(s.frame_timeout(), secs(4));
    assert_eq!(s.max_connections_per_uid(), 6);
}

/// Absent limits take the docs/50 value. Spec: docs/50 §3.6 (5 s frame
/// timeout; "kdc ≤ 8" connections per uid); docs/questions/Q-230 item 4.
#[test]
fn keyd_minimal_sample_takes_defaults() {
    let s = KeydSettings::parse(common::KEYD_MINIMAL.as_bytes()).expect("valid keyd file");
    assert_eq!(s.frame_timeout(), secs(5));
    assert_eq!(s.max_connections_per_uid(), 8);
    assert_eq!(
        s.uid_roles().iter().collect::<Vec<_>>(),
        [(803, RoleName::Kdc)]
    );
}

/// Spec: docs/50 §2.4 (dird), §3.2 (one peer uid per channel), §3.4 (view
/// lifetime), §4.2 (dird's zone table), §7.1 (realm, naming context), §7.2.
#[test]
fn dird_sample_parses() {
    let s = DirdSettings::parse(common::DIRD.as_bytes()).expect("valid dird file");
    assert_eq!((s.run_as().uid(), s.run_as().gid()), (802, 802));
    assert_eq!(s.realm(), "EXAMPLE.TEST");
    assert_eq!(s.naming_context().labels(), ["example", "test"]);
    assert_eq!(s.dns_host_name(), "dc1.example.test");
    assert_eq!(s.database_path().as_str(), "/var/lib/dird/directory.redb");
    assert_eq!(
        s.integrity_key_source(),
        IntegrityKeySource::InsecureDevelopmentFile
    );
    assert_eq!(s.integrity_key_path().as_str(), "/etc/dird/integrity.key");
    assert_eq!(s.policy_store_path().as_str(), "/etc/domain/policy.store");
    assert_eq!(
        s.policy_store_format(),
        PolicyStoreFormat::UnsignedDevelopment
    );
    assert_eq!(
        s.kdc_channel().socket().as_str(),
        "/run/dird/kdc/dird-kdc.sock"
    );
    assert_eq!(s.kdc_channel().peer_uid(), 803);
    assert_eq!(
        s.ldap_channel().socket().as_str(),
        "/run/dird/ldap/dird-ldap.sock"
    );
    assert_eq!(s.ldap_channel().peer_uid(), 804);
    let admin = s.admin_channel().expect("admin channel configured");
    assert_eq!(admin.socket().as_str(), "/run/dird/admin/dird-admin.sock");
    assert_eq!(admin.peer_uid(), 806);
    let keyd = s.keyd().expect("keyd endpoint configured");
    assert_eq!(keyd.socket().as_str(), "/run/keyd/keyd.sock");
    assert_eq!(keyd.uid(), 801);
    assert_eq!(
        s.node_id(),
        Some([
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x66, 0xff
        ])
    );
    let service = s.admin_service().expect("admin service configured");
    assert_eq!(service.ticket_age_max(), secs(600));
    assert_eq!(service.quorum(), 2);
    assert_eq!(
        service.provision_manifest().as_str(),
        "/etc/domain/provision.manifest"
    );
    assert_eq!(s.audit().uid(), 805);
    assert_eq!(s.frame_timeout(), secs(5));
    assert_eq!(s.view_lifetime(), secs(3));
}

/// Without the admin pair there is no admin channel. Spec: docs/50 §3.6 /
/// §3.4 defaults; docs/questions/Q-230 item 11.
#[test]
fn dird_minimal_sample_takes_defaults() {
    let s = DirdSettings::parse(common::DIRD_MINIMAL.as_bytes()).expect("valid dird file");
    assert!(s.admin_channel().is_none());
    assert!(s.admin_service().is_none());
    assert!(s.keyd().is_none());
    assert!(s.node_id().is_none());
    assert_eq!(s.frame_timeout(), secs(5));
    assert_eq!(s.view_lifetime(), secs(5));
}

/// Spec: docs/50 §2.4 (kdc), §3.2 (server uids), §3.6 (deadlines), §4.1
/// (listeners, zone table, TCP limits), §7.2.
#[test]
fn kdc_sample_parses() {
    let s = KdcSettings::parse(common::KDC.as_bytes()).expect("valid kdc file");
    assert_eq!((s.run_as().uid(), s.run_as().gid()), (803, 803));
    assert_eq!(s.listen(), [v4(10, 0, 0, 5, 88), fd00_1234(5, 88)]);
    assert_eq!(s.internal_networks().len(), 2);
    assert_eq!(s.keyd().socket().as_str(), "/run/keyd/keyd.sock");
    assert_eq!(s.keyd().uid(), 801);
    assert_eq!(s.dird().socket().as_str(), "/run/dird/kdc/dird-kdc.sock");
    assert_eq!(s.dird().uid(), 802);
    assert_eq!(s.policy_store_path().as_str(), "/etc/domain/policy.store");
    assert_eq!(
        s.policy_store_format(),
        PolicyStoreFormat::UnsignedDevelopment
    );
    assert_eq!(s.audit().uid(), 805);
    let l = s.limits();
    assert_eq!(l.max_tcp_connections(), 512);
    assert_eq!(l.max_tcp_connections_per_source(), 8);
    assert_eq!(l.tcp_first_frame_timeout(), secs(10));
    assert_eq!(l.tcp_frame_timeout(), secs(5));
    assert_eq!(l.tcp_idle_timeout(), secs(30));
    assert_eq!(l.max_requests_per_tcp_connection(), 32);
    assert_eq!(l.keyd_deadline(), secs(2));
    assert_eq!(l.dird_deadline(), secs(1));
}

/// Absent limits take the docs/50 §4.1 / §3.6 values: 1024, 16, 10 s, 10 s,
/// 30 s, 64, 2 s, 2 s. Spec: docs/50 §3.6, §4.1; Q-230 item 4.
#[test]
fn kdc_minimal_sample_takes_defaults() {
    let s = KdcSettings::parse(common::KDC_MINIMAL.as_bytes()).expect("valid kdc file");
    assert_eq!(s.listen(), [v4(127, 0, 0, 1, 88)]);
    assert_eq!(s.internal_networks().len(), 1);
    let l = s.limits();
    assert_eq!(l.max_tcp_connections(), 1024);
    assert_eq!(l.max_tcp_connections_per_source(), 16);
    assert_eq!(l.tcp_first_frame_timeout(), secs(10));
    assert_eq!(l.tcp_frame_timeout(), secs(10));
    assert_eq!(l.tcp_idle_timeout(), secs(30));
    assert_eq!(l.max_requests_per_tcp_connection(), 64);
    assert_eq!(l.keyd_deadline(), secs(2));
    assert_eq!(l.dird_deadline(), secs(2));
}

/// Spec: docs/50 §2.4 (ldap-front), §4.2 (389 / 636, the timeouts), §3.6
/// (dird-ldap deadline), R50-12 / §5.3 (certificate and key paths), §4.1
/// (the zone table — ldap-front's since docs/52 R14).
#[test]
fn ldap_front_sample_parses() {
    let s = LdapFrontSettings::parse(common::LDAP_FRONT.as_bytes()).expect("valid file");
    assert_eq!((s.run_as().uid(), s.run_as().gid()), (804, 804));
    assert_eq!(s.ldap_listen(), [v4(10, 0, 0, 5, 389)]);
    assert_eq!(s.ldaps_listen(), [v4(10, 0, 0, 5, 636), fd00_1234(5, 636)]);
    let networks: Vec<_> = s
        .internal_networks()
        .iter()
        .map(|n| (n.address(), n.prefix_len()))
        .collect();
    assert_eq!(
        networks,
        [
            (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8),
            (IpAddr::V4(Ipv4Addr::new(192, 168, 10, 0)), 24),
            (
                IpAddr::V6(Ipv6Addr::new(0xfd00, 0x1234, 0, 0, 0, 0, 0, 0)),
                32
            ),
        ]
    );
    assert_eq!(
        s.tls_certificate_path().as_str(),
        "/etc/ldap-front/dc-cert.der"
    );
    assert_eq!(
        s.tls_private_key_path().as_str(),
        "/etc/ldap-front/dc-key.der"
    );
    assert_eq!(
        s.tls_private_key_path().as_path(),
        std::path::Path::new("/etc/ldap-front/dc-key.der")
    );
    assert_eq!(s.dird().socket().as_str(), "/run/dird/ldap/dird-ldap.sock");
    assert_eq!(s.dird().uid(), 802);
    assert_eq!(s.audit().uid(), 805);
    let l = s.limits();
    assert_eq!(l.init_recv_timeout(), secs(20));
    assert_eq!(l.max_conn_idle_time(), secs(300));
    assert_eq!(l.tls_handshake_timeout(), secs(10));
    assert_eq!(l.dird_deadline(), secs(62));
}

/// LDAPS alone is a valid listener set; absent timeouts take the docs/50
/// values (30 s, 300 s, 10 s, 65 s). Spec: docs/50 §3.6, §4.2.
#[test]
fn ldap_front_minimal_sample_takes_defaults() {
    let s = LdapFrontSettings::parse(common::LDAP_FRONT_MINIMAL.as_bytes()).expect("valid");
    assert!(s.ldap_listen().is_empty());
    assert_eq!(s.ldaps_listen(), [v4(10, 0, 0, 5, 636)]);
    let l = s.limits();
    assert_eq!(l.init_recv_timeout(), secs(30));
    assert_eq!(l.max_conn_idle_time(), secs(300));
    assert_eq!(l.tls_handshake_timeout(), secs(10));
    assert_eq!(l.dird_deadline(), secs(65));
}

/// Spec: docs/50 §2.4 (auditd), §3.2 (source set from the uid), §8.1.
#[test]
fn auditd_sample_parses() {
    let s = AuditdSettings::parse(common::AUDITD.as_bytes()).expect("valid auditd file");
    assert_eq!((s.run_as().uid(), s.run_as().gid()), (805, 805));
    assert_eq!(s.audit_socket().as_str(), "/run/auditd/audit.sock");
    assert_eq!(
        s.audit_log_path().as_str(),
        "/var/log/audit/domain-audit.log"
    );
    assert_eq!(
        s.uid_sources().iter().collect::<Vec<_>>(),
        [
            (801, AuditSource::Keyd),
            (802, AuditSource::Dird),
            (803, AuditSource::Kdc),
            (804, AuditSource::LdapFront),
            (806, AuditSource::Admind),
        ]
    );
    assert_eq!(s.uid_sources().source_of(804), Some(AuditSource::LdapFront));
    assert_eq!(s.uid_sources().source_of(805), None);
    assert_eq!(s.uid_sources().source_of(0), None);
    assert_eq!(s.uid_sources().len(), 5);
    assert!(!s.uid_sources().is_empty());
    assert_eq!(s.frame_timeout(), secs(2));
}

/// Spec: docs/50 §3.6 (5 s frame timeout default).
#[test]
fn auditd_minimal_sample_takes_defaults() {
    let s = AuditdSettings::parse(common::AUDITD_MINIMAL.as_bytes()).expect("valid");
    assert_eq!(s.frame_timeout(), secs(5));
    assert_eq!(s.uid_sources().len(), 1);
}

/// Spec: docs/50 §2.4 (admind), §3.2, §3.6.
#[test]
fn admind_sample_parses() {
    let s = AdmindSettings::parse(common::ADMIND.as_bytes()).expect("valid admind file");
    assert_eq!((s.run_as().uid(), s.run_as().gid()), (806, 806));
    assert_eq!(s.admin_socket().as_str(), "/run/admind/admin.sock");
    assert_eq!(s.admin_socket_group(), 810);
    assert_eq!(s.min_password_length(), 14);
    assert_eq!(
        s.dird().socket().as_str(),
        "/run/dird/admin/dird-admin.sock"
    );
    assert_eq!(s.dird().uid(), 802);
    assert_eq!(s.keyd().socket().as_str(), "/run/keyd/keyd.sock");
    assert_eq!(s.keyd().uid(), 801);
    assert_eq!(s.audit().uid(), 805);
    assert_eq!(s.frame_timeout(), secs(5));
    assert_eq!(s.keyd_deadline(), secs(1));
}

/// Spec: docs/50 §3.6 (keyd channel deadline 2 s).
#[test]
fn admind_minimal_sample_takes_defaults() {
    let s = AdmindSettings::parse(common::ADMIND_MINIMAL.as_bytes()).expect("valid");
    assert_eq!(s.frame_timeout(), secs(5));
    assert_eq!(s.keyd_deadline(), secs(2));
    // Required, so the minimal sample carries it: the floor (A-79, P-24).
    assert_eq!(s.min_password_length(), 12);
}

/// Every key of every closed table appears in that daemon's full sample, so
/// the samples cover the whole schema. Spec: docs/50 R50-15 ("a closed key
/// table per daemon").
#[test]
fn full_samples_cover_every_key() {
    for &(daemon, full, _) in ALL {
        for key in daemon.keys() {
            let prefix = format!("{key} = ");
            assert!(
                full.lines().any(|line| line.starts_with(&prefix)),
                "{daemon:?} sample lacks {key}"
            );
        }
    }
}

/// Every key of every table is read and typed: an invalid value under it is
/// rejected and the error names exactly that key and its line. (A key in the
/// table that the parser ignored would let any value through.)
/// Spec: docs/50 R50-15, §7.1 ("every value typed").
#[test]
fn every_key_is_validated() {
    for &(daemon, full, _) in ALL {
        for &key in daemon.keys() {
            let input = set(full, key, "!");
            let err = daemon
                .parse(input.as_bytes())
                .expect_err("an invalid value is rejected");
            assert_eq!(err.key(), Some(key), "{daemon:?} {key}: {err}");
            let expected_line = input
                .lines()
                .position(|line| line.starts_with(&format!("{key} = ")))
                .and_then(|index| u32::try_from(index + 1).ok());
            assert_eq!(err.line(), expected_line, "{daemon:?} {key}");
        }
    }
}

/// Every key that a minimal sample has is required: removing it is
/// `MissingKey` naming it. Spec: docs/50 §7.1 ("missing-required ⇒ do not
/// start").
#[test]
fn every_minimal_key_is_required() {
    for &(daemon, _, minimal) in ALL {
        for line in minimal.lines() {
            let Some((key, _)) = line.split_once(" = ") else {
                continue;
            };
            // ldap-front needs one listener list or the other.
            if daemon == Daemon::LdapFront && key == "ldaps_listen" {
                continue;
            }
            let err = daemon
                .parse(remove(minimal, key).as_bytes())
                .expect_err("a required key cannot be omitted");
            assert_eq!(
                err.kind(),
                config::ErrorKind::MissingKey,
                "{daemon:?} {key}"
            );
            assert_eq!(err.key(), Some(key));
            assert_eq!(err.line(), None);
        }
    }
}

/// Key order, comments and empty lines carry no meaning.
/// Spec: docs/50 §7.1 ("`#` for a comment"); docs/questions/Q-230 item 2.
#[test]
fn order_comments_and_empty_lines_do_not_matter() {
    for &(daemon, full, _) in ALL {
        let mut lines: Vec<&str> = full.lines().collect();
        lines.reverse();
        let mut shuffled = String::from("\n# reversed\n\n");
        for line in lines {
            shuffled.push_str(line);
            shuffled.push_str("\n\n#\n");
        }
        assert_eq!(daemon.parse(shuffled.as_bytes()), Ok(()), "{daemon:?}");
    }
}

/// The zone table's match (docs/50 §4.1: CIDR → Internal, everything else
/// External; docs/questions/Q-230 item 8: host bits zero, prefix ≥ 1, an
/// empty table holds nothing; Q-275 item 9: within one address family, no
/// IPv4-mapped translation) — the one implementation ldap-front's listener
/// rule and its source check read (docs/52 R14). Every address is test data.
#[test]
fn network_containment() {
    let ten = config::Network::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8).unwrap();
    let ula =
        config::Network::new(IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0)), 16).unwrap();
    let table = [ten, ula];
    let inside = |ip| config::is_internal(&table, ip);
    assert!(inside(IpAddr::V4(Ipv4Addr::new(10, 200, 3, 4))));
    assert!(!inside(IpAddr::V4(Ipv4Addr::new(11, 0, 0, 1))));
    assert!(inside(IpAddr::V6(Ipv6Addr::new(
        0xfd00, 1, 2, 3, 4, 5, 6, 7
    ))));
    assert!(!inside(IpAddr::V6(Ipv6Addr::new(
        0xfd01, 0, 0, 0, 0, 0, 0, 1
    ))));
    let mapped = IpAddr::V6(Ipv4Addr::new(10, 1, 1, 1).to_ipv6_mapped());
    assert!(!inside(mapped));
    assert!(!config::is_internal(
        &[],
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
    ));
    let host = config::Network::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), 32).unwrap();
    assert!(host.contains(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))));
    assert!(!host.contains(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 6))));
    assert!(config::Network::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8).is_none());
    assert!(config::Network::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 0).is_none());
    assert!(config::Network::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 33).is_none());
    assert!(config::Network::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 129).is_none());
}
