//! The configuration files of step 7 (docs/51 §4.3): one per daemon plus
//! keyadm's, in the strict line format of docs/50 §7.1 — uids, gids, paths,
//! the realm, addresses; **no secret value** (A-60: "no setting can hold a
//! secret").
//!
//! Every generated file is parsed back by its own crates/config schema
//! before anything is written (one rule set: the daemon's). dird's file
//! carries the admin-channel keys task A8 adds to crates/config
//! concurrently (docs/51 §4.6, as A8 defined them — the main session's
//! coordination note): `keyd_socket` + `keyd_uid` (both or neither),
//! `node_id` (32 lower-case hex digits, not all zero), and — required with
//! the admin channel (`dird_admin_socket` + `admind_uid`), refused without
//! it — `admin_ticket_age_max` (60s ..= 3600s, no default),
//! `admin_quorum` (2 or 3) and `provision_manifest` (the manifest's
//! absolute path; dird reads it as root before its drop and requires its
//! realm, naming context and host name to match its own). dird's file —
//! these keys included ([`DIRD_ADMIN_CHANNEL_KEYS`]) — is parsed back with
//! dird's own schema (A-91); their values are also checked where they
//! appear elsewhere (keyd's socket and uid in keyd's own file; the
//! manifest's path among the targets, and its realm / naming context / host
//! name are dird's by construction), are generated here (the node id, the
//! CSPRNG's 16 octets), or are fixed in range ([`ADMIN_TICKET_AGE_MAX_SECS`],
//! [`ADMIN_QUORUM`]).
//!
//! Spec: docs/51 §4.3 step 7, §4.6, §5.5 (R51-10), §5.6 (R51-11); docs/50
//! R50-15, §2.4, §3.1, §3.2, §7.1, R50-18; A-60; A-68; A-73 (keyd's
//! `uid_roles`); P-22 (the quorum); Q-270 items 1-2; docs/questions/Q-378.

use config::{
    AdmindSettings, AuditdSettings, DirdSettings, KdcSettings, KeyadmSettings, KeydSettings,
    LdapFrontSettings,
};
use dirstore::NodeId;

use crate::input::{DomainInput, FilePath};

/// dird's admin-channel keys (docs/51 §4.6; A-91, docs/questions/Q-385),
/// emitted in dird's file whenever the admin channel is.
/// Spec: docs/51 §4.6; A-91.
pub const DIRD_ADMIN_CHANNEL_KEYS: [&str; 6] = [
    "keyd_socket",
    "keyd_uid",
    "node_id",
    "admin_ticket_age_max",
    "admin_quorum",
    "provision_manifest",
];

/// dird's `admin_ticket_age_max`, in seconds: ten minutes. A ticket whose
/// age (`now − authtime`) is above it is refused for an admin operation.
/// Project choice inside A8's range (60s ..= 3600s): docs/51 §5.5 (R51-10)
/// asks for a bounded `ticket_age` "(project choice ⚠, e.g. minutes)" so
/// that no standing authorization exists server-side; ten minutes leaves
/// an administrator time to obtain a fresh service ticket and an approver
/// time to act (P-22 dual control), while keyd's replay cache already makes
/// each AP-REQ single-use (docs/10 §5ב as cited in docs/51 §5.5).
/// docs/questions/Q-378 item 1.
pub const ADMIN_TICKET_AGE_MAX_SECS: u32 = 600;

/// dird's `admin_quorum`: the requester plus one other approver — the
/// smallest quorum, no single-administrator mode.
/// Spec: P-22 items 2-3 (Q-295); docs/51 §5.6 (R51-11); crates/directory-admin
/// `MIN_QUORUM`.
pub const ADMIN_QUORUM: usize = directory_admin::MIN_QUORUM;

/// admind's `min_password_length`: the hard floor of 12 characters (A-79 /
/// owner item P-24: "a required configuration key `min_password_length` in
/// admind, with a temporary hard floor of 12 characters"). admind's schema
/// requires the key (task A9), so every generated admind file carries it;
/// the operator raises it by editing the file. docs/questions/Q-378 item 3
/// (decided A-92: "provisioning must emit it (floor 12)").
/// Spec: A-79; P-24; A-92; [MS-SAMR] 3.1.1.7.2 item 3.2.1.
pub const MIN_PASSWORD_LENGTH: u32 = 12;

// The value provisioning writes is the schema's own floor.
const _: () = assert!(MIN_PASSWORD_LENGTH == config::limits::MIN_PASSWORD_LENGTH.min);

/// The process a configuration file belongs to.
/// Spec: docs/50 §2.4 (the process table).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Daemon {
    /// keyd.
    Keyd,
    /// dird.
    Dird,
    /// kdc.
    Kdc,
    /// ldap-front.
    LdapFront,
    /// auditd.
    Auditd,
    /// admind.
    Admind,
    /// keyadm (a tool, not a daemon).
    Keyadm,
}

impl Daemon {
    /// Every configuration file, in the order they are staged and installed.
    pub const ALL: [Daemon; 7] = [
        Daemon::Keyd,
        Daemon::Dird,
        Daemon::Kdc,
        Daemon::LdapFront,
        Daemon::Auditd,
        Daemon::Admind,
        Daemon::Keyadm,
    ];

    /// The process name (docs/50 §2.4), printable ASCII.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Daemon::Keyd => "keyd",
            Daemon::Dird => "dird",
            Daemon::Kdc => "kdc",
            Daemon::LdapFront => "ldap-front",
            Daemon::Auditd => "auditd",
            Daemon::Admind => "admind",
            Daemon::Keyadm => "keyadm",
        }
    }
}

/// One generated configuration file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigFile {
    /// Whose file.
    pub daemon: Daemon,
    /// Where it is installed.
    pub path: FilePath,
    /// The `key = value` lines, in file order.
    pub lines: Vec<(&'static str, String)>,
}

impl ConfigFile {
    /// The file's text: a comment line, then one `key = value` line each,
    /// every line LF-terminated (docs/50 §7.1).
    #[must_use]
    pub fn text(&self) -> String {
        self.render(|_| true)
    }

    /// The text without the lines `keep` refuses.
    fn render(&self, keep: impl Fn(&str) -> bool) -> String {
        let mut out = format!(
            "# {} configuration, written by provision domain (docs/51 4.3 step 7); no secret\n",
            self.daemon.name()
        );
        for (key, value) in self.lines.iter().filter(|(key, _)| keep(key)) {
            out.push_str(key);
            out.push_str(" = ");
            out.push_str(value);
            out.push('\n');
        }
        out
    }

    /// Parse the file back with its daemon's own schema (dird: the whole
    /// file, admin-channel keys included — A-91).
    ///
    /// # Errors
    /// The schema's `config::Error` (it names a line and a key, never the
    /// value).
    ///
    /// Spec: docs/50 R50-15, §7.1; module documentation.
    pub fn parse_back(&self) -> Result<(), config::Error> {
        match self.daemon {
            Daemon::Keyd => KeydSettings::parse(self.text().as_bytes()).map(drop),
            Daemon::Dird => DirdSettings::parse(self.text().as_bytes()).map(drop),
            Daemon::Kdc => KdcSettings::parse(self.text().as_bytes()).map(drop),
            Daemon::LdapFront => LdapFrontSettings::parse(self.text().as_bytes()).map(drop),
            Daemon::Auditd => AuditdSettings::parse(self.text().as_bytes()).map(drop),
            Daemon::Admind => AdmindSettings::parse(self.text().as_bytes()).map(drop),
            Daemon::Keyadm => KeyadmSettings::parse(self.text().as_bytes()).map(drop),
        }
    }
}

/// The lower-case hex form of a node id (docs/51 §4.6: "`node_id` (hex,
/// not secret)").
#[must_use]
pub fn node_id_text(node_id: &NodeId) -> String {
    node_id.0.iter().map(|b| format!("{b:02x}")).collect()
}

/// A path value.
fn path(p: &FilePath) -> String {
    p.as_str().to_owned()
}

/// An id value.
fn id(value: u32) -> String {
    value.to_string()
}

/// A `", "`-separated list (crates/config lists).
fn list(items: &[String]) -> String {
    items.join(", ")
}

/// Every configuration file of the domain (module documentation).
///
/// - keyd: `uid_roles` = kdc → Kdc, admind → Directory, keyadm → Admin,
///   dird → Ldap (A-73; docs/51 §4.3 step 7); `key_store =
///   insecure-development` (R50-18 — the only store until P-17).
/// - dird: the development integrity-key file and the unsigned development
///   policy, both named explicitly (Q-270 items 1-2); the admin channel
///   (`dird_admin_socket` + `admind_uid`) with A8's keys ([`DIRD_ADMIN_CHANNEL_KEYS`]:
///   keyd's socket and uid, the node id, `admin_ticket_age_max` =
///   [`ADMIN_TICKET_AGE_MAX_SECS`] s, `admin_quorum` = [`ADMIN_QUORUM`], and
///   `provision_manifest` = the manifest this run writes).
/// - kdc, ldap-front: their sockets, peers, policy (kdc), the operator's
///   certificate and key paths (ldap-front, R50-12).
/// - auditd: `uid_sources` = every daemon's uid with its source name
///   (docs/50 §3.2).
/// - admind: `admin_socket_group` (docs/51 §4.6), `min_password_length` =
///   [`MIN_PASSWORD_LENGTH`] (A-79 / P-24; required by admind's schema since
///   task A9). No `keyadm_uid`: admind forwards nothing for keyadm since
///   A-102 (docs/52 §4.6).
/// - keyadm: keyd's socket and uid — and nothing else: keyadm talks to keyd
///   only and runs dird's decisions by id (A-102; docs/51 §6, docs/52 §4.6);
///   the `admin_socket` + `admind_uid` pair of A-97 is gone.
///
/// Spec: docs/51 §4.3 step 7, §4.6, §6; docs/50 §2.4, §3.1, §3.2, §7.1;
/// A-60; A-68; A-73; A-97; docs/52 §4.6 (A-102).
#[must_use]
pub fn domain_configs(input: &DomainInput, node_id: &NodeId) -> Vec<ConfigFile> {
    let a = &input.accounts;
    let p = &input.paths;
    let n = &input.network;
    let nc = input
        .naming_context
        .iter()
        .map(|label| format!("dc={label}"))
        .collect::<Vec<_>>()
        .join(",");
    let keyd = vec![
        ("run_as_uid", id(a.keyd.uid)),
        ("run_as_gid", id(a.keyd.gid)),
        ("realm", input.realm.clone()),
        ("keyd_socket", path(&p.keyd_socket)),
        (
            "uid_roles",
            format!(
                "{}:Kdc, {}:Directory, {}:Admin, {}:Ldap",
                a.kdc.uid, a.admind.uid, a.keyadm_uid, a.dird.uid
            ),
        ),
        ("key_store", "insecure-development".to_owned()),
        ("audit_socket", path(&p.audit_socket)),
        ("auditd_uid", id(a.auditd.uid)),
    ];
    let mut dird = vec![
        ("run_as_uid", id(a.dird.uid)),
        ("run_as_gid", id(a.dird.gid)),
        ("realm", input.realm.clone()),
        ("naming_context", nc),
        ("dns_host_name", input.dc_fqdn.clone()),
        ("database_path", path(&p.database)),
        (
            "integrity_key_source",
            "insecure-development-file".to_owned(),
        ),
        ("integrity_key_path", path(&p.integrity_key)),
        ("policy_store_path", path(&p.policy)),
        ("policy_store_format", "unsigned-development".to_owned()),
        ("dird_kdc_socket", path(&p.dird_kdc_socket)),
        ("kdc_uid", id(a.kdc.uid)),
        ("dird_ldap_socket", path(&p.dird_ldap_socket)),
        ("ldap_front_uid", id(a.ldap_front.uid)),
        ("dird_admin_socket", path(&p.dird_admin_socket)),
        ("admind_uid", id(a.admind.uid)),
    ];
    if !n.internal_networks.is_empty() {
        dird.push(("internal_networks", list(&n.internal_networks)));
    }
    dird.extend([
        ("audit_socket", path(&p.audit_socket)),
        ("auditd_uid", id(a.auditd.uid)),
        // The admin channel's keys (A8): every one is required with
        // `dird_admin_socket` + `admind_uid`, which this file always has.
        ("keyd_socket", path(&p.keyd_socket)),
        ("keyd_uid", id(a.keyd.uid)),
        ("node_id", node_id_text(node_id)),
        (
            "admin_ticket_age_max",
            format!("{ADMIN_TICKET_AGE_MAX_SECS}s"),
        ),
        ("admin_quorum", ADMIN_QUORUM.to_string()),
        ("provision_manifest", path(&p.manifest)),
    ]);
    let mut kdc = vec![
        ("run_as_uid", id(a.kdc.uid)),
        ("run_as_gid", id(a.kdc.gid)),
        ("listen", list(&n.kdc_listen)),
    ];
    if !n.internal_networks.is_empty() {
        kdc.push(("internal_networks", list(&n.internal_networks)));
    }
    kdc.extend([
        ("keyd_socket", path(&p.keyd_socket)),
        ("keyd_uid", id(a.keyd.uid)),
        ("dird_kdc_socket", path(&p.dird_kdc_socket)),
        ("dird_uid", id(a.dird.uid)),
        ("policy_store_path", path(&p.policy)),
        ("policy_store_format", "unsigned-development".to_owned()),
        ("audit_socket", path(&p.audit_socket)),
        ("auditd_uid", id(a.auditd.uid)),
    ]);
    let mut ldap_front = vec![
        ("run_as_uid", id(a.ldap_front.uid)),
        ("run_as_gid", id(a.ldap_front.gid)),
    ];
    if !n.ldap_listen.is_empty() {
        ldap_front.push(("ldap_listen", list(&n.ldap_listen)));
    }
    if !n.ldaps_listen.is_empty() {
        ldap_front.push(("ldaps_listen", list(&n.ldaps_listen)));
    }
    ldap_front.extend([
        ("tls_certificate_path", path(&p.tls_certificate)),
        ("tls_private_key_path", path(&p.tls_private_key)),
        ("dird_ldap_socket", path(&p.dird_ldap_socket)),
        ("dird_uid", id(a.dird.uid)),
        ("audit_socket", path(&p.audit_socket)),
        ("auditd_uid", id(a.auditd.uid)),
    ]);
    let auditd = vec![
        ("run_as_uid", id(a.auditd.uid)),
        ("run_as_gid", id(a.auditd.gid)),
        ("audit_socket", path(&p.audit_socket)),
        ("audit_log_path", path(&p.audit_log)),
        (
            "uid_sources",
            format!(
                "{}:keyd, {}:dird, {}:kdc, {}:ldap-front, {}:admind",
                a.keyd.uid, a.dird.uid, a.kdc.uid, a.ldap_front.uid, a.admind.uid
            ),
        ),
    ];
    let admind = vec![
        ("run_as_uid", id(a.admind.uid)),
        ("run_as_gid", id(a.admind.gid)),
        ("admin_socket", path(&p.admin_socket)),
        ("admin_socket_group", id(a.admin_socket_group)),
        ("min_password_length", MIN_PASSWORD_LENGTH.to_string()),
        ("dird_admin_socket", path(&p.dird_admin_socket)),
        ("dird_uid", id(a.dird.uid)),
        ("keyd_socket", path(&p.keyd_socket)),
        ("keyd_uid", id(a.keyd.uid)),
        ("audit_socket", path(&p.audit_socket)),
        ("auditd_uid", id(a.auditd.uid)),
    ];
    // keyadm talks to keyd only (A-102; docs/51 §6, docs/52 §4.6): its
    // socket and the uid keyd must present (docs/50 R50-3).
    let keyadm = vec![
        ("keyd_socket", path(&p.keyd_socket)),
        ("keyd_uid", id(a.keyd.uid)),
    ];
    let file = |daemon, path: &FilePath, lines| ConfigFile {
        daemon,
        path: path.clone(),
        lines,
    };
    vec![
        file(Daemon::Keyd, &p.keyd_config, keyd),
        file(Daemon::Dird, &p.dird_config, dird),
        file(Daemon::Kdc, &p.kdc_config, kdc),
        file(Daemon::LdapFront, &p.ldap_front_config, ldap_front),
        file(Daemon::Auditd, &p.auditd_config, auditd),
        file(Daemon::Admind, &p.admind_config, admind),
        file(Daemon::Keyadm, &p.keyadm_config, keyadm),
    ]
}
