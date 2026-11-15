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
//! Task K9 adds the two network fronts' files — kpasswd-front's (docs/53
//! §3.3, §10 K8/K9) and dnsd's (docs/54 §4.3, §10 DN13, its front part) —,
//! dird's kpasswd channel (`dird_kpasswd_socket` + `kpasswd_front_uid`,
//! docs/53 §5.6 step 1; Q-955 item 13; Q-964 item 12) and the two fronts in
//! auditd's `uid_sources` (`kpasswd-front`, `dnsd` — A-160, Q-960 item 6).
//! Neither front is mapped in keyd (docs/53 R53-4: the front has no keyd
//! channel; docs/54 §4.3: dnsd is not mapped in keyd).
//!
//! Task DN10a adds dird's DNS channel — `dird_dns_socket` (the path dnsd's
//! file names) + `dnsd_uid` (dnsd's account), docs/54 §4.6 — and the zone
//! values of its image ([`DIRD_DNS_CHANNEL_KEYS`]; docs/questions/Q-619
//! item 5, Q-1001, Q-1003 item 1), so a provisioned dird serves the socket
//! a provisioned dnsd connects to (Q-973 item 6). The DC's own host record
//! is **not** written yet (it needs the provisioning session's zone — a
//! directory-admin change, docs/questions/Q-1003 item 2): until it is, the
//! zone cannot be projected and dird's DNS service reports it at start.
//!
//! Spec: docs/51 §4.3 step 7, §4.6, §5.5 (R51-10), §5.6 (R51-11); docs/50
//! R50-15, §2.4, §3.1, §3.2, §7.1, R50-18; docs/53 R53-3, R53-4, §3.3,
//! §5.6, §5.7, §9; docs/54 §4.3, §4.6, §4.7, §9; A-60; A-68; A-73 (keyd's
//! `uid_roles`); A-117; A-119; A-160; A-161; P-22 (the quorum); Q-270 items
//! 1-2; docs/questions/Q-378, Q-955 item 13, Q-960 item 6, Q-964 items 12-13,
//! Q-973.

use config::{
    AdmindSettings, AuditdSettings, DirdSettings, DnsdSettings, KdcSettings, KeyadmSettings,
    KeydSettings, KpasswdFrontSettings, LdapFrontSettings,
};
use dirstore::NodeId;

use crate::input::{DomainInput, FilePath};

/// dird's admin-channel keys (docs/51 §4.6; A-91, docs/questions/Q-385),
/// emitted in dird's file whenever the admin channel is.
/// Spec: docs/51 §4.6; A-91.
pub const DIRD_ADMIN_CHANNEL_KEYS: [&str; 7] = [
    "keyd_socket",
    "keyd_uid",
    "node_id",
    "admin_ticket_age_max",
    "admin_quorum",
    "provision_manifest",
    // Task A16: where dird writes `policy.next` (docs/51 §5.10).
    "policy_next_path",
];

/// dird's kpasswd-channel keys (task K7, docs/53 §5.6 step 1; Q-955 item
/// 13; Q-964 item 12), emitted in dird's file (task K9) — beside the admin
/// channel, which the kpasswd service shares (docs/53 §5.6 step 4).
/// Spec: docs/53 §5.6; docs/questions/Q-964 items 12-13.
pub const DIRD_KPASSWD_CHANNEL_KEYS: [&str; 2] = ["dird_kpasswd_socket", "kpasswd_front_uid"];

/// dird's DNS-channel keys (task DN10a, docs/54 §4.6; docs/questions/Q-619
/// item 5, Q-1001), emitted in dird's file whenever dnsd's is (always,
/// since task K9): the channel's pair — the same `dird-dns.sock` path dnsd's
/// file names and dnsd's uid — and the zone values the image takes that the
/// directory does not hold. `dns_record_max_age` keeps the schema's default
/// (docs/54 §5.2: 7 days, also the ceiling — Q-230 item 4), as the fronts'
/// limits keep theirs.
/// Spec: docs/54 §3.1, §4.3, §4.6, §5.5; docs/questions/Q-619 item 5,
/// Q-1001, Q-1003 item 1.
pub const DIRD_DNS_CHANNEL_KEYS: [&str; 10] = [
    "dird_dns_socket",
    "dnsd_uid",
    "dns_registrable_networks",
    "dns_soa_rname",
    "dns_soa_refresh",
    "dns_soa_retry",
    "dns_soa_expire",
    "dns_soa_minimum",
    "dns_infrastructure_ttl",
    "dns_host_ttl",
];

/// The local part of the SOA's RNAME, the mailbox of the person
/// responsible for the zone: `hostmaster`, prefaced to the zone's name as
/// one label — RNAME = `hostmaster.<zone>`. RFC 1035 §8 maps "the mailbox
/// HOSTMASTER@SRI-NIC.ARPA … into the domain name HOSTMASTER.SRI-NIC.ARPA";
/// the label is that example's. Project choice ⚠ (docs/54 §3.1: RNAME is
/// dird configuration with no value; the operator edits dird's file) —
/// docs/questions/Q-1003 item 1.
/// Spec: RFC 1035 §3.3.13, §8; docs/54 §3.1.
pub const DNS_SOA_RNAME_LOCAL_PART: &str = "hostmaster";

/// The SOA's REFRESH, RETRY, EXPIRE and MINIMUM, in seconds: the values of
/// RFC 1035 §5.3's master file example (`7200 ; REFRESH`, `600 ; RETRY`,
/// `3600000; EXPIRE`, `60) ; MINIMUM`). REFRESH, RETRY and EXPIRE matter to
/// secondary servers only, and there are none (OD-2); MINIMUM is the floor
/// of every TTL dnsd sends (RFC 1035 §3.3.13). Project choice ⚠ —
/// docs/questions/Q-1003 item 1.
/// Spec: RFC 1035 §3.3.13, §5.3; docs/54 §3.1.
pub const DNS_SOA_TIMERS: [u32; 4] = [7200, 600, 3_600_000, 60];

/// The TTL of the synthesized SOA, NS and SRV records: one hour — they
/// change only with dird's configuration or the DC (docs/54 §5.1). Project
/// choice ⚠ — docs/questions/Q-1003 item 1.
/// Spec: docs/54 §5.1; RFC 1035 §3.2.1.
pub const DNS_INFRASTRUCTURE_TTL_SECS: u32 = 3600;

/// The one zone-wide TTL of the hosts' A records: ten minutes — how long a
/// client may cache a host's address after the host changed or left it
/// (docs/54 §5.2; RFC 1035 §3.2.1). Project choice ⚠ — docs/questions/
/// Q-1003 item 1.
/// Spec: docs/questions/Q-991 item 4 (A-170: one TTL from dird's
/// configuration); RFC 2136 §7.12.
pub const DNS_HOST_TTL_SECS: u32 = 600;

// Every value is inside dird's schema bound for zone time values.
const _: () = assert!(DNS_INFRASTRUCTURE_TTL_SECS <= config::limits::DNS_TIME_SECS.max);
const _: () = assert!(DNS_HOST_TTL_SECS <= config::limits::DNS_TIME_SECS.max);
const _: () = assert!(DNS_SOA_TIMERS[0] <= config::limits::DNS_TIME_SECS.max);
const _: () = assert!(DNS_SOA_TIMERS[1] <= config::limits::DNS_TIME_SECS.max);
const _: () = assert!(DNS_SOA_TIMERS[2] <= config::limits::DNS_TIME_SECS.max);
const _: () = assert!(DNS_SOA_TIMERS[3] <= config::limits::DNS_TIME_SECS.max);

/// The IPv4 networks among `items` (crates/config's spelling
/// `<address>/<prefix>`): dird's `dns_registrable_networks` — Q-619 item 4's
/// default, the internal networks, restricted to IPv4 because phase 1
/// serves A records only (docs/54 §3.1). Every item is parsed back by dird's
/// schema before anything is written.
/// Spec: docs/54 §3.1, §5.5; docs/questions/Q-619 item 4, Q-1003 item 1.
#[must_use]
pub fn ipv4_networks(items: &[String]) -> Vec<String> {
    items
        .iter()
        .filter(|item| {
            item.split_once('/')
                .is_some_and(|(address, _)| address.parse::<core::net::Ipv4Addr>().is_ok())
        })
        .cloned()
        .collect()
}

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

/// admind's `min_password_length`: the floor of 8 characters — the owner's
/// minimum (docs/56 §7 P-24: "8+ characters", replacing A-79's temporary
/// floor of 12). admind's schema requires the key (task A9), so every
/// generated admind file carries it; the operator raises it by editing the
/// file. docs/questions/Q-378 item 3 (decided A-92: "provisioning must emit
/// it").
/// Spec: docs/56 §7 (P-24); A-79; A-92; [MS-SAMR] 3.1.1.7.2 item 3.2.1;
/// docs/questions/Q-910 item 2.
pub const MIN_PASSWORD_LENGTH: u32 = 8;

// The value provisioning writes is the schema's own floor ...
const _: () = assert!(MIN_PASSWORD_LENGTH == config::limits::MIN_PASSWORD_LENGTH.min);
// ... and the password-policy crate's floor (docs/56 §7 P-24): one value,
// pinned here because the config crate has no dependency.
const _: () = assert!(
    config::limits::MIN_PASSWORD_LENGTH.min == admin_password_policy::MIN_PASSWORD_CHARS_FLOOR
);

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
    /// kpasswd-front (task K9; docs/53 R53-4).
    KpasswdFront,
    /// dnsd (task K9 / DN13's front part; docs/54 §4.3).
    Dnsd,
}

impl Daemon {
    /// Every configuration file, in the order they are staged and installed.
    pub const ALL: [Daemon; 9] = [
        Daemon::Keyd,
        Daemon::Dird,
        Daemon::Kdc,
        Daemon::LdapFront,
        Daemon::Auditd,
        Daemon::Admind,
        Daemon::Keyadm,
        Daemon::KpasswdFront,
        Daemon::Dnsd,
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
            Daemon::KpasswdFront => "kpasswd-front",
            Daemon::Dnsd => "dnsd",
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
            Daemon::KpasswdFront => KpasswdFrontSettings::parse(self.text().as_bytes()).map(drop),
            Daemon::Dnsd => DnsdSettings::parse(self.text().as_bytes()).map(drop),
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
///   [`ADMIN_TICKET_AGE_MAX_SECS`] s, `admin_quorum` = [`ADMIN_QUORUM`],
///   `provision_manifest` = the manifest this run writes, and — task A16 —
///   `policy_next_path` = `--policy-next-path`).
/// - kdc, ldap-front: their sockets, peers, policy (kdc), the operator's
///   certificate and key paths (ldap-front, R50-12).
/// - dird (task K9): the kpasswd channel ([`DIRD_KPASSWD_CHANNEL_KEYS`]:
///   `dird_kpasswd_socket` + `kpasswd_front_uid`, the front's uid — docs/53
///   §5.6 step 1).
/// - dird (task DN10a): the DNS channel ([`DIRD_DNS_CHANNEL_KEYS`]:
///   `dird_dns_socket` — the path in dnsd's file — + `dnsd_uid`, dnsd's
///   uid; `dns_registrable_networks` = the IPv4 internal networks; the SOA's
///   RNAME `hostmaster.<zone>` and [`DNS_SOA_TIMERS`]; the TTLs
///   [`DNS_INFRASTRUCTURE_TTL_SECS`], [`DNS_HOST_TTL_SECS`] — docs/54 §3.1,
///   §4.6, §5.5; Q-1003 item 1).
/// - auditd: `uid_sources` = every daemon's uid with its source name
///   (docs/50 §3.2) — the two fronts too since task K9 (`kpasswd-front`,
///   `dnsd`; A-160, Q-960 item 6).
/// - kpasswd-front (task K9): its account, its TCP 464 listeners inside the
///   internal networks, the realm of its KRB-ERRORs, dird's
///   `dird-kpasswd.sock` and uid, auditd's socket and uid (docs/53 R53-3,
///   §3.3, §5.7); the limits keep the schema's defaults (docs/53 §5.1).
/// - dnsd (task K9 / DN13's front part): its account, its listeners inside
///   the internal networks, dird's `dird-dns.sock` and uid, auditd's socket
///   and uid (docs/54 §4.3, §4.6, §4.7); the limits keep the schema's
///   defaults (docs/54 §6.7).
/// - admind: `admin_socket_group` (docs/51 §4.6), `min_password_length` =
///   [`MIN_PASSWORD_LENGTH`] (A-79 / P-24; required by admind's schema since
///   task A9). No `keyadm_uid`: admind forwards nothing for keyadm since
///   A-102 (docs/52 §4.6).
/// - keyadm: keyd's socket and uid — and nothing else: keyadm talks to keyd
///   only and runs dird's decisions by id (A-102; docs/51 §6, docs/52 §4.6);
///   the `admin_socket` + `admind_uid` pair of A-97 is gone.
///
/// Spec: docs/51 §4.3 step 7, §4.6, §6; docs/50 §2.4, §3.1, §3.2, §7.1;
/// docs/53 R53-3, §3.3, §5.6, §5.7; docs/54 §4.3, §4.6, §4.7; A-60; A-68;
/// A-73; A-97; A-117; A-160; docs/52 §4.6 (A-102); docs/questions/Q-960
/// item 6, Q-964 items 12-13.
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
    // No `internal_networks` for dird: the LDAP zone is the front's, from
    // its peer uid (docs/52 R14).
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
        // Task A16: the online policy change's `policy.next` (dird prepares
        // its directory; root's activation reads this same key).
        ("policy_next_path", path(&p.policy_next)),
        // Task K9: the kpasswd channel (docs/53 §5.6 step 1: the peer on
        // `dird-kpasswd.sock` is the front's uid only) — beside the admin
        // channel, whose settings the kpasswd service shares (§5.6 step 4).
        ("dird_kpasswd_socket", path(&p.dird_kpasswd_socket)),
        ("kpasswd_front_uid", id(a.kpasswd_front.uid)),
        // Task DN10a: the DNS channel (docs/54 §4.6: the peer on
        // `dird-dns.sock` is dnsd's uid only) — the path dnsd's file names
        // — and the zone values ([`DIRD_DNS_CHANNEL_KEYS`]).
        ("dird_dns_socket", path(&p.dird_dns_socket)),
        ("dnsd_uid", id(a.dnsd.uid)),
        (
            "dns_registrable_networks",
            list(&ipv4_networks(&n.internal_networks)),
        ),
        (
            "dns_soa_rname",
            format!(
                "{DNS_SOA_RNAME_LOCAL_PART}.{}",
                input.naming_context.join(".")
            ),
        ),
        ("dns_soa_refresh", format!("{}s", DNS_SOA_TIMERS[0])),
        ("dns_soa_retry", format!("{}s", DNS_SOA_TIMERS[1])),
        ("dns_soa_expire", format!("{}s", DNS_SOA_TIMERS[2])),
        ("dns_soa_minimum", format!("{}s", DNS_SOA_TIMERS[3])),
        (
            "dns_infrastructure_ttl",
            format!("{DNS_INFRASTRUCTURE_TTL_SECS}s"),
        ),
        ("dns_host_ttl", format!("{DNS_HOST_TTL_SECS}s")),
    ]);
    let mut kdc = vec![
        ("run_as_uid", id(a.kdc.uid)),
        ("run_as_gid", id(a.kdc.gid)),
        ("listen", list(&n.kdc_listen)),
        // Required: the kdc binds to internal interfaces only — every
        // listener lies in an internal network (docs/50 R50-9; task R15b,
        // docs/questions/Q-632). The input check guarantees one entry.
        ("internal_networks", list(&n.internal_networks)),
    ];
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
    // Required: every LDAP listener lies in an internal network, and the
    // front serves only internal sources (docs/52 §7 R14; A-102 on
    // docs/questions/Q-469 (b)). The input check guarantees one entry.
    ldap_front.push(("internal_networks", list(&n.internal_networks)));
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
            // Task K9: the two fronts too — the source is set from the uid
            // only (docs/50 §3.2; A-160: `dnsd` = 7, `kpasswd-front` = 8).
            format!(
                "{}:keyd, {}:dird, {}:kdc, {}:ldap-front, {}:admind, {}:dnsd, {}:kpasswd-front",
                a.keyd.uid,
                a.dird.uid,
                a.kdc.uid,
                a.ldap_front.uid,
                a.admind.uid,
                a.dnsd.uid,
                a.kpasswd_front.uid
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
    // Task K9 — kpasswd-front: TCP 464 only, every listener inside the
    // internal networks (docs/53 R53-3, §3.3; A-117), the realm its
    // KRB-ERRORs name (docs/53 §5.7; dird's realm, Q-955 item 4), dird's
    // `dird-kpasswd.sock` and uid, auditd. No key, no keyd (R53-4).
    let kpasswd_front = vec![
        ("run_as_uid", id(a.kpasswd_front.uid)),
        ("run_as_gid", id(a.kpasswd_front.gid)),
        ("listen", list(&n.kpasswd_listen)),
        ("internal_networks", list(&n.internal_networks)),
        ("realm", input.realm.clone()),
        ("dird_kpasswd_socket", path(&p.dird_kpasswd_socket)),
        ("dird_uid", id(a.dird.uid)),
        ("audit_socket", path(&p.audit_socket)),
        ("auditd_uid", id(a.auditd.uid)),
    ];
    // Task K9 / DN13's front part — dnsd: every listener inside the internal
    // networks (docs/54 §4.7; A-114), dird's `dird-dns.sock` and uid (docs/54
    // §4.6 — dird serves it since task DN10a, its file naming the same path
    // and dnsd's uid), auditd. No key, not in keyd (docs/54 §4.3).
    let dnsd = vec![
        ("run_as_uid", id(a.dnsd.uid)),
        ("run_as_gid", id(a.dnsd.gid)),
        ("listen", list(&n.dnsd_listen)),
        ("internal_networks", list(&n.internal_networks)),
        ("dird_dns_socket", path(&p.dird_dns_socket)),
        ("dird_uid", id(a.dird.uid)),
        ("audit_socket", path(&p.audit_socket)),
        ("auditd_uid", id(a.auditd.uid)),
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
        file(Daemon::KpasswdFront, &p.kpasswd_front_config, kpasswd_front),
        file(Daemon::Dnsd, &p.dnsd_config, dnsd),
    ]
}
