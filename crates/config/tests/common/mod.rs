//! Sample configuration files, written for these tests from the settings
//! docs/50 names for each daemon (§2.4 process table, §3.2, §3.6, §4.1, §4.2,
//! §5.3, §7.1, §7.2, §8.1). The account ids (801..807) and paths are
//! arbitrary test values; the limits are the docs/50 values or tighter.

#![allow(dead_code)]

use config::{
    AdmindSettings, AuditdSettings, DirdSettings, Error, KdcSettings, KeydSettings,
    LdapFrontSettings,
};

/// keyd, every key present. Spec: docs/50 §2.4, R50-3, R50-18, §3.6, §7.1.
pub const KEYD: &str = "\
# keyd - docs/50 s2.4
run_as_uid = 801
run_as_gid = 801
realm = EXAMPLE.TEST
keyd_socket = /run/keyd/keyd.sock
uid_roles = 803:Kdc, 806:Directory, 807:Admin, 802:Ldap
key_store = insecure-development
audit_socket = /run/auditd/audit.sock
auditd_uid = 805
frame_timeout = 4s
max_connections_per_uid = 6
";

/// keyd, required keys only. Spec: docs/50 §7.1 (optional keys default).
pub const KEYD_MINIMAL: &str = "\
run_as_uid = 801
run_as_gid = 801
realm = EXAMPLE.TEST
keyd_socket = /run/keyd/keyd.sock
uid_roles = 803:Kdc
key_store = insecure-development
audit_socket = /run/auditd/audit.sock
auditd_uid = 805
";

/// dird, every key present. Spec: docs/50 §2.4, §3.2, §3.4, §4.2, §7.1, §7.2.
pub const DIRD: &str = "\
# dird - docs/50 s2.4

run_as_uid = 802
run_as_gid = 802
realm = EXAMPLE.TEST
naming_context = dc=example,dc=test
dns_host_name = dc1.example.test
database_path = /var/lib/dird/directory.redb
integrity_key_source = insecure-development-file
integrity_key_path = /etc/dird/integrity.key
policy_store_path = /etc/domain/policy.store
policy_store_format = unsigned-development
dird_kdc_socket = /run/dird/kdc/dird-kdc.sock
kdc_uid = 803
dird_ldap_socket = /run/dird/ldap/dird-ldap.sock
ldap_front_uid = 804
dird_admin_socket = /run/dird/admin/dird-admin.sock
admind_uid = 806
keyd_socket = /run/keyd/keyd.sock
keyd_uid = 801
node_id = 0123456789abcdef00112233445566ff
admin_ticket_age_max = 600s
admin_quorum = 2
provision_manifest = /etc/domain/provision.manifest
policy_next_path = /var/lib/dird/policy/policy.next
audit_socket = /run/auditd/audit.sock
auditd_uid = 805
frame_timeout = 5s
view_lifetime = 3s
";

/// dird, required keys only. Spec: docs/50 §7.1.
pub const DIRD_MINIMAL: &str = "\
run_as_uid = 802
run_as_gid = 802
realm = EXAMPLE.TEST
naming_context = dc=example,dc=test
dns_host_name = dc1.example.test
database_path = /var/lib/dird/directory.redb
integrity_key_source = insecure-development-file
integrity_key_path = /etc/dird/integrity.key
policy_store_path = /etc/domain/policy.store
policy_store_format = unsigned-development
dird_kdc_socket = /run/dird/kdc/dird-kdc.sock
kdc_uid = 803
dird_ldap_socket = /run/dird/ldap/dird-ldap.sock
ldap_front_uid = 804
audit_socket = /run/auditd/audit.sock
auditd_uid = 805
";

/// kdc, every key present. Spec: docs/50 §2.4, §3.6, §4.1, §7.1, §7.2.
pub const KDC: &str = "\
# kdc - docs/50 s2.4, s4.1
run_as_uid = 803
run_as_gid = 803
listen = 10.0.0.5:88, [fd00:1234::5]:88
internal_networks = 10.0.0.0/8
keyd_socket = /run/keyd/keyd.sock
keyd_uid = 801
dird_kdc_socket = /run/dird/kdc/dird-kdc.sock
dird_uid = 802
policy_store_path = /etc/domain/policy.store
policy_store_format = unsigned-development
audit_socket = /run/auditd/audit.sock
auditd_uid = 805
max_tcp_connections = 512
max_tcp_connections_per_source = 8
tcp_first_frame_timeout = 10s
tcp_frame_timeout = 5s
tcp_idle_timeout = 30s
max_requests_per_tcp_connection = 32
keyd_deadline = 2s
dird_deadline = 1s
";

/// kdc, required keys only. Spec: docs/50 §7.1.
pub const KDC_MINIMAL: &str = "\
run_as_uid = 803
run_as_gid = 803
listen = 127.0.0.1:88
keyd_socket = /run/keyd/keyd.sock
keyd_uid = 801
dird_kdc_socket = /run/dird/kdc/dird-kdc.sock
dird_uid = 802
policy_store_path = /etc/domain/policy.store
policy_store_format = unsigned-development
audit_socket = /run/auditd/audit.sock
auditd_uid = 805
";

/// ldap-front, every key present. Spec: docs/50 §2.4, §3.6, §4.1, §4.2,
/// §5.3; docs/52 R14 (the zone table, every listener inside it).
pub const LDAP_FRONT: &str = "\
# ldap-front - docs/50 s2.4, s4.2, s5.3
run_as_uid = 804
run_as_gid = 804
ldap_listen = 10.0.0.5:389
ldaps_listen = 10.0.0.5:636, [fd00:1234::5]:636
internal_networks = 10.0.0.0/8, 192.168.10.0/24, fd00:1234::/32
tls_certificate_path = /etc/ldap-front/dc-cert.der
tls_private_key_path = /etc/ldap-front/dc-key.der
dird_ldap_socket = /run/dird/ldap/dird-ldap.sock
dird_uid = 802
audit_socket = /run/auditd/audit.sock
auditd_uid = 805
init_recv_timeout = 20s
max_conn_idle_time = 300s
tls_handshake_timeout = 10s
dird_deadline = 62s
";

/// ldap-front, required keys only (LDAPS only). Spec: docs/50 §7.1, §4.2;
/// docs/52 R14 (`internal_networks` required).
pub const LDAP_FRONT_MINIMAL: &str = "\
run_as_uid = 804
run_as_gid = 804
ldaps_listen = 10.0.0.5:636
internal_networks = 10.0.0.0/8
tls_certificate_path = /etc/ldap-front/dc-cert.der
tls_private_key_path = /etc/ldap-front/dc-key.der
dird_ldap_socket = /run/dird/ldap/dird-ldap.sock
dird_uid = 802
audit_socket = /run/auditd/audit.sock
auditd_uid = 805
";

/// auditd, every key present. Spec: docs/50 §2.4, §3.2, §8.1.
pub const AUDITD: &str = "\
# auditd - docs/50 s2.4, s8.1
run_as_uid = 805
run_as_gid = 805
audit_socket = /run/auditd/audit.sock
audit_log_path = /var/log/audit/domain-audit.log
uid_sources = 801:keyd, 802:dird, 803:kdc, 804:ldap-front, 806:admind
frame_timeout = 2s
";

/// auditd, required keys only. Spec: docs/50 §7.1.
pub const AUDITD_MINIMAL: &str = "\
run_as_uid = 805
run_as_gid = 805
audit_socket = /run/auditd/audit.sock
audit_log_path = /var/log/audit/domain-audit.log
uid_sources = 801:keyd
";

/// admind, every key present. Spec: docs/50 §2.4, §3.2, §3.6.
pub const ADMIND: &str = "\
# admind - docs/50 s2.4 (blocked on Q-220)
run_as_uid = 806
run_as_gid = 806
admin_socket = /run/admind/admin.sock
admin_socket_group = 810
min_password_length = 14
dird_admin_socket = /run/dird/admin/dird-admin.sock
dird_uid = 802
keyd_socket = /run/keyd/keyd.sock
keyd_uid = 801
audit_socket = /run/auditd/audit.sock
auditd_uid = 805
frame_timeout = 5s
keyd_deadline = 1s
";

/// admind, required keys only. Spec: docs/50 §7.1.
pub const ADMIND_MINIMAL: &str = "\
run_as_uid = 806
run_as_gid = 806
admin_socket = /run/admind/admin.sock
admin_socket_group = 810
min_password_length = 12
dird_admin_socket = /run/dird/admin/dird-admin.sock
dird_uid = 802
keyd_socket = /run/keyd/keyd.sock
keyd_uid = 801
audit_socket = /run/auditd/audit.sock
auditd_uid = 805
";

/// The six daemons. Spec: docs/50 R50-1, §2.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Daemon {
    Keyd,
    Dird,
    Kdc,
    LdapFront,
    Auditd,
    Admind,
}

/// Every daemon with its full sample, its minimal sample and its key table.
pub const ALL: &[(Daemon, &str, &str)] = &[
    (Daemon::Keyd, KEYD, KEYD_MINIMAL),
    (Daemon::Dird, DIRD, DIRD_MINIMAL),
    (Daemon::Kdc, KDC, KDC_MINIMAL),
    (Daemon::LdapFront, LDAP_FRONT, LDAP_FRONT_MINIMAL),
    (Daemon::Auditd, AUDITD, AUDITD_MINIMAL),
    (Daemon::Admind, ADMIND, ADMIND_MINIMAL),
];

impl Daemon {
    /// The daemon's closed key table.
    pub fn keys(self) -> &'static [&'static str] {
        match self {
            Daemon::Keyd => KeydSettings::KEYS,
            Daemon::Dird => DirdSettings::KEYS,
            Daemon::Kdc => KdcSettings::KEYS,
            Daemon::LdapFront => LdapFrontSettings::KEYS,
            Daemon::Auditd => AuditdSettings::KEYS,
            Daemon::Admind => AdmindSettings::KEYS,
        }
    }

    /// Parses `input` with this daemon's schema, keeping only the error.
    pub fn parse(self, input: &[u8]) -> Result<(), Error> {
        match self {
            Daemon::Keyd => KeydSettings::parse(input).map(drop),
            Daemon::Dird => DirdSettings::parse(input).map(drop),
            Daemon::Kdc => KdcSettings::parse(input).map(drop),
            Daemon::LdapFront => LdapFrontSettings::parse(input).map(drop),
            Daemon::Auditd => AuditdSettings::parse(input).map(drop),
            Daemon::Admind => AdmindSettings::parse(input).map(drop),
        }
    }
}

/// Every daemon's parser on `input` (the sweep runs all six on every
/// mutation).
pub fn parse_all(input: &[u8]) -> Vec<Result<(), Error>> {
    ALL.iter().map(|(daemon, ..)| daemon.parse(input)).collect()
}

/// `sample` with the line of `key` replaced by `line` (which must end without
/// LF; one is added). Panics if `key` is absent — a test-construction bug.
pub fn replace(sample: &str, key: &str, line: &str) -> String {
    let prefix = format!("{key} = ");
    let mut found = false;
    let mut out = String::new();
    for existing in sample.lines() {
        if existing.starts_with(&prefix) {
            found = true;
            out.push_str(line);
        } else {
            out.push_str(existing);
        }
        out.push('\n');
    }
    assert!(found, "test sample has no `{key}` line");
    out
}

/// `sample` with the value of `key` set to `value`.
pub fn set(sample: &str, key: &str, value: &str) -> String {
    replace(sample, key, &format!("{key} = {value}"))
}

/// `sample` without the line of `key`.
pub fn remove(sample: &str, key: &str) -> String {
    let prefix = format!("{key} = ");
    let mut out = String::new();
    for existing in sample.lines() {
        if !existing.starts_with(&prefix) {
            out.push_str(existing);
            out.push('\n');
        }
    }
    out
}

/// `sample` with `line` appended (LF added).
pub fn append(sample: &str, line: &str) -> String {
    format!("{sample}{line}\n")
}
