//! dird's configuration file.
//!
//! dird is the sole owner of the redb file and runs the LDAP engine (docs/50
//! R50-1, R50-2). It serves up to five channels — `dird-kdc.sock`,
//! `dird-ldap.sock`, `dird-admin.sock`, (task K7) `dird-kpasswd.sock` and
//! (task DN10a) `dird-dns.sock`, with the zone values of its image (docs/54
//! §3.1, §4.4; docs/questions/Q-1001) —
//! each admitting exactly one peer uid (§3.2; docs/53 §5.6 step 1), loads the
//! signed policy store (which carries the TierMap, A-36) (§7.2). The kpasswd
//! channel's zone, like the LDAP channel's, is its front's, derived from the
//! peer uid (docs/53 §3.3). dird has **no zone table**: the zone of an LDAP client is the zone
//! of the front it came through, derived from the peer uid of the
//! `dird-ldap.sock` connection — phase 1 has one front, the internal one
//! (docs/52 §7 R14; A-102 on docs/questions/Q-469 (b)) — never from an address
//! the front reports, so `internal_networks` is not a dird key
//! (docs/questions/Q-580).
//!
//! **No secrets.** The dirstore `IntegrityKey` is never a setting (docs/50
//! §7.4: "never in a readable file next to the DB"). Q-213 → A-57 decided
//! that dird holds it, opened through the sealing mechanism of Q-212 (owner
//! item P-17, undecided). Until then the only source is the development
//! interim Q-213 names ("in development — a key from a development file"):
//! the operator must say so explicitly, `integrity_key_source =
//! insecure-development-file`, and `integrity_key_path` only **points to**
//! the root-only file (the key itself is never in this file). Likewise the
//! policy store: its signed format is Q-219 → A-57 and does not exist yet,
//! so the only accepted `policy_store_format` is `unsigned-development`
//! (docs/questions/Q-270 items 1-2). A production kind is added to each
//! table when its decision is implemented.
//!
//! **The attestation key** (task PN10; docs/59 §7.4; A-173 — docs/questions/
//! Q-1011 item 2): the key dird tags its name resolutions with is never a
//! setting either — `attestation_key_path` only **points to** dird's
//! root-only key file, which the provisioning tool writes (task PN12). The
//! key is **required** (task PN12; A-187 on docs/questions/Q-1048 item 1):
//! a dird file without it is refused here (`MissingKey`), so no dird can be
//! configured that cannot attest a name resolution — the start's own check
//! became this schema's (docs/questions/Q-1055).
//!
//! Spec: docs/50 R50-2, R50-15, §2.4, §3.2, §3.4, §4.2, §7.1, §7.2, §7.4;
//! docs/questions/Q-213, Q-219 (A-57), Q-270.

use core::time::Duration;

use crate::error::{Error, ErrorKind};
use crate::format::{Document, Located};
use crate::limits::{
    Bound, ADMIN_QUORUM, ADMIN_TICKET_AGE_MAX_SECS, DNS_RECORD_MAX_AGE_SECS, DNS_TIME_SECS,
    FRAME_TIMEOUT_SECS,
};
use crate::schema::{
    self, Account, Distinct, Endpoint, AUDITD_UID, AUDIT_SOCKET, DIRD_ADMIN_SOCKET,
    DIRD_DNS_SOCKET, DIRD_KDC_SOCKET, DIRD_KPASSWD_SOCKET, DIRD_LDAP_SOCKET, FRAME_TIMEOUT,
    KEYD_SOCKET, KEYD_UID, POLICY_STORE_PATH, RUN_AS_GID, RUN_AS_UID,
};
use crate::value::{self, AbsolutePath, NamingContextLabels, Network, NODE_ID_OCTETS};
use core::net::IpAddr;

/// Key: the realm. Spec: docs/50 §7.1; A-55 (must match the naming context).
const REALM: &str = "realm";
/// Key: the DN of the domain root. Spec: docs/50 §7.1 ("naming context
/// (A-53)").
const NAMING_CONTEXT: &str = "naming_context";
/// Key: the DC's DNS host name, reported by the LDAP engine's rootDSE
/// (dNSHostName). Spec: [MS-ADTS] 3.1.1.3.2.4; docs/49 §5.2;
/// docs/questions/Q-280 item 6.
const DNS_HOST_NAME: &str = "dns_host_name";
/// Key: the redb file dird alone opens. Spec: docs/50 R50-2, §2.4, §6.4.
const DATABASE_PATH: &str = "database_path";
/// Key: the only uid admitted on `dird-kdc.sock`. Spec: docs/50 §3.2.
const KDC_UID: &str = "kdc_uid";
/// Key: the only uid admitted on `dird-ldap.sock`. Spec: docs/50 §3.2.
const LDAP_FRONT_UID: &str = "ldap_front_uid";
/// Key: the only uid admitted on `dird-admin.sock`. Spec: docs/50 §3.2.
const ADMIND_UID: &str = "admind_uid";
/// Key: the only uid admitted on `dird-kpasswd.sock` — kpasswd-front's.
/// Spec: docs/53 §5.6 step 1 ("the peer on dird-kpasswd.sock = the front's
/// uid only (R50-3)"); docs/questions/Q-955 item 13.
const KPASSWD_FRONT_UID: &str = "kpasswd_front_uid";
/// Key: how long a `BeginView` snapshot stays pinned. Spec: docs/50 §3.4.
const VIEW_LIFETIME: &str = "view_lifetime";
/// Key: where the dirstore integrity key comes from. Spec: docs/50 §7.4;
/// Q-213 (A-57); docs/questions/Q-270 item 1.
const INTEGRITY_KEY_SOURCE: &str = "integrity_key_source";
/// Key: the development integrity-key file (a path, never the key). Spec:
/// docs/50 §7.1 ("only paths to protected files"), §7.4; Q-270 item 1.
const INTEGRITY_KEY_PATH: &str = "integrity_key_path";
/// Key: the format of the policy store file. Spec: docs/50 §7.2; Q-219
/// (A-57); docs/questions/Q-270 item 2.
pub(crate) const POLICY_STORE_FORMAT: &str = "policy_store_format";
/// Key: dird's name-resolution attestation-key file (a path, never the key;
/// required since task PN12).
/// Spec: docs/59 §7.4 (dird's key file, written by provision); docs/50 §7.1
/// ("only paths to protected files"); docs/questions/Q-1011 item 2 (A-173),
/// Q-1046 item 5, Q-1048 item 1 (A-187: required once provision writes it).
const ATTESTATION_KEY_PATH: &str = "attestation_key_path";
/// Key: this DC's node-id, the `Origin.origin_node` of every directory write
/// (32 lower-case hex digits, not secret). Spec: docs/51 §4.3 step 2, §4.6;
/// docs/29 §2 as cited there; docs/questions/Q-385 item 3.
const NODE_ID: &str = "node_id";
/// Key: the admin plane's ticket-age threshold. Spec: docs/51 §5.5 (R51-10);
/// docs/questions/Q-385 item 4.
const ADMIN_TICKET_AGE_MAX: &str = "admin_ticket_age_max";
/// Key: the dual-control quorum. Spec: docs/51 §5.6 (R51-11); P-22.
const ADMIN_QUORUM_KEY: &str = "admin_quorum";
/// Key: the non-secret provisioning manifest (root-owned), from which dird
/// takes the admin service object and the service objects it protects.
/// Spec: docs/51 §4.3 step 8, §5.2 row 9; A-73; docs/questions/Q-386.
const PROVISION_MANIFEST: &str = "provision_manifest";
/// Key: where dird writes `policy.next` — the tier-map change its admin
/// service decided under dual control, for root to activate (task A16). A
/// file in a directory of dird's own (dird prepares it as root before the
/// drop); root's activation reads the same key. Spec: docs/51 §5.10
/// (R51-21); A-80; docs/questions/Q-591.
const POLICY_NEXT_PATH: &str = "policy_next_path";
/// Key: the only uid admitted on `dird-dns.sock` — dnsd's (task DN10a).
/// Spec: docs/54 §4.3 ("dird gets another socket (`dird-dns.sock`, peer =
/// `dnsd_uid` only)"), §4.6; docs/questions/Q-619 item 5.
const DNSD_UID: &str = "dnsd_uid";
/// Key: the networks a host's registered address must lie in
/// (`dns_registrable_networks`), IPv4 only. Spec: docs/54 §4.4, §5.5;
/// docs/questions/Q-614 item 8, Q-619 item 4, Q-994 item 6 (e).
const DNS_REGISTRABLE_NETWORKS: &str = "dns_registrable_networks";
/// Key: `dns_record_max_age`. Spec: docs/54 §5.2; docs/questions/Q-614
/// item 7, Q-619 item 5.
const DNS_RECORD_MAX_AGE: &str = "dns_record_max_age";
/// Key: the SOA's RNAME. Spec: docs/54 §3.1 (SOA row); RFC 1035 §3.3.13;
/// docs/questions/Q-619 item 5.
const DNS_SOA_RNAME: &str = "dns_soa_rname";
/// Key: the SOA's REFRESH. Spec: docs/54 §3.1; RFC 1035 §3.3.13.
const DNS_SOA_REFRESH: &str = "dns_soa_refresh";
/// Key: the SOA's RETRY. Spec: docs/54 §3.1; RFC 1035 §3.3.13.
const DNS_SOA_RETRY: &str = "dns_soa_retry";
/// Key: the SOA's EXPIRE. Spec: docs/54 §3.1; RFC 1035 §3.3.13.
const DNS_SOA_EXPIRE: &str = "dns_soa_expire";
/// Key: the SOA's MINIMUM. Spec: docs/54 §3.1, §6.4; RFC 1035 §3.3.13.
const DNS_SOA_MINIMUM: &str = "dns_soa_minimum";
/// Key: the TTL of the synthesized SOA, NS and SRV records. Spec: docs/54
/// §5.1; docs/questions/Q-994 item 6 (e).
const DNS_INFRASTRUCTURE_TTL: &str = "dns_infrastructure_ttl";
/// Key: the one zone-wide TTL of every host's A records. Spec: docs/54
/// §3.1; RFC 2136 §7.12; docs/questions/Q-991 item 4 (A-170).
const DNS_HOST_TTL: &str = "dns_host_ttl";

/// The zone keys of dird's DNS service, besides the channel's pair: each
/// required with the channel, each refused without it.
/// Spec: docs/questions/Q-619 item 5, Q-1001 item 1.
const DNS_ZONE_KEYS: [&str; 9] = [
    DNS_REGISTRABLE_NETWORKS,
    DNS_RECORD_MAX_AGE,
    DNS_SOA_RNAME,
    DNS_SOA_REFRESH,
    DNS_SOA_RETRY,
    DNS_SOA_EXPIRE,
    DNS_SOA_MINIMUM,
    DNS_INFRASTRUCTURE_TTL,
    DNS_HOST_TTL,
];

/// Where dird's dirstore integrity key comes from.
///
/// Phase 1 has only the development interim of Q-213: a root-only file read
/// before the privilege drop. The sealed source of Q-212 (P-17) is added
/// here when the owner decides it.
///
/// Spec: docs/50 §7.4; docs/questions/Q-213 (A-57: dird holds the key),
/// Q-212 (P-17), Q-270 item 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegrityKeySource {
    /// A 32-octet key in a root-owned, mode-0400 file, read as root before
    /// the drop and wiped from the reading buffer after use — development
    /// only (Q-213: "in development — a key from a development file").
    InsecureDevelopmentFile,
}

/// The accepted spellings of [`IntegrityKeySource`]. Spec: Q-270 item 1.
const INTEGRITY_KEY_SOURCES: &[(&str, IntegrityKeySource)] = &[(
    "insecure-development-file",
    IntegrityKeySource::InsecureDevelopmentFile,
)];

/// The format of the policy store file dird loads.
///
/// The signed format of Q-219 (A-57) is not defined yet; until it is, the
/// only accepted format is a clearly marked, UNSIGNED development file, and
/// the operator must name it here (never trusted silently).
///
/// Spec: docs/50 §7.2; docs/questions/Q-219 (A-57), Q-270 item 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyStoreFormat {
    /// The unsigned development policy file (no signature is verified).
    UnsignedDevelopment,
}

/// The accepted spellings of [`PolicyStoreFormat`]. Spec: Q-270 item 2.
pub(crate) const POLICY_STORE_FORMATS: &[(&str, PolicyStoreFormat)] = &[(
    "unsigned-development",
    PolicyStoreFormat::UnsignedDevelopment,
)];

/// Lifetime of a view pinned by `BeginView`: at most 5 s.
/// Spec: docs/50 §3.4 ("expires after ≤ 5 s (project choice)").
pub const VIEW_LIFETIME_SECS: Bound = Bound::up_to(5);

/// A channel dird serves: its socket path and the one peer uid admitted on it.
///
/// Spec: docs/50 §3.1 (a socket per server and channel), §3.2 ("dird-kdc.sock
/// ← kdc's uid only; dird-ldap.sock ← ldap-front; dird-admin.sock ← admind").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Channel {
    socket: AbsolutePath,
    peer_uid: u32,
}

impl Channel {
    /// The path dird listens on for this channel.
    #[must_use]
    pub fn socket(&self) -> &AbsolutePath {
        &self.socket
    }

    /// The only peer uid admitted; every other uid is closed and audited.
    #[must_use]
    pub const fn peer_uid(&self) -> u32 {
        self.peer_uid
    }
}

/// The admin service's own settings: present exactly when the admin channel
/// (`dird_admin_socket` + `admind_uid`) is configured.
///
/// Spec: docs/51 §5.5, §5.6, §7; A-73; P-22; docs/questions/Q-385, Q-386.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminServiceSettings {
    ticket_age_max: Duration,
    quorum: u32,
    provision_manifest: AbsolutePath,
    policy_next: Option<AbsolutePath>,
}

impl AdminServiceSettings {
    /// The ticket-age threshold (60 s ..= 3600 s). Spec: docs/51 §5.5.
    #[must_use]
    pub const fn ticket_age_max(&self) -> Duration {
        self.ticket_age_max
    }

    /// The dual-control quorum (2 ..= 3). Spec: docs/51 §5.6; P-22.
    #[must_use]
    pub const fn quorum(&self) -> u32 {
        self.quorum
    }

    /// The provisioning manifest (root-owned, not group/other-writable — the
    /// daemon's checks). Spec: docs/51 §4.3 step 8.
    #[must_use]
    pub fn provision_manifest(&self) -> &AbsolutePath {
        &self.provision_manifest
    }

    /// Where dird writes `policy.next` (task A16), when configured; absent ⇒
    /// the online policy change is refused (`ChangePolicy` answered
    /// `Unavailable`) and policy changes are offline only (`provision
    /// policy`). Spec: docs/51 §5.10; A-80; docs/questions/Q-591.
    #[must_use]
    pub fn policy_next(&self) -> Option<&AbsolutePath> {
        self.policy_next.as_ref()
    }
}

/// The SOA fields dird's configuration sets (MNAME and SERIAL are not
/// configured: MNAME is the DC's name, SERIAL the zone counter — docs/54
/// §3.1). Times in seconds.
/// Spec: RFC 1035 §3.3.13; docs/54 §3.1 (SOA row); docs/questions/Q-619
/// item 5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SoaSettings {
    rname: String,
    refresh: u32,
    retry: u32,
    expire: u32,
    minimum: u32,
}

impl SoaSettings {
    /// RNAME, a domain name in text form (labels separated by dots, no final
    /// dot). Spec: RFC 1035 §3.3.13, §8.
    #[must_use]
    pub fn rname(&self) -> &str {
        &self.rname
    }

    /// REFRESH. Spec: RFC 1035 §3.3.13.
    #[must_use]
    pub const fn refresh(&self) -> u32 {
        self.refresh
    }

    /// RETRY. Spec: RFC 1035 §3.3.13.
    #[must_use]
    pub const fn retry(&self) -> u32 {
        self.retry
    }

    /// EXPIRE. Spec: RFC 1035 §3.3.13.
    #[must_use]
    pub const fn expire(&self) -> u32 {
        self.expire
    }

    /// MINIMUM — the floor of every TTL sent from the zone. Spec: RFC 1035
    /// §3.3.13.
    #[must_use]
    pub const fn minimum(&self) -> u32 {
        self.minimum
    }
}

/// dird's DNS service (task DN10a): present exactly when the channel
/// (`dird_dns_socket` + `dnsd_uid`) is configured, with the zone values
/// its image takes that the directory does not hold (docs/54 §3.1, §4.4,
/// §5.2, §5.5). Whether the `_kpasswd` SRV records are synthesized is not a
/// key: it is whether dird's kpasswd channel is configured
/// ([`DirdSettings::kpasswd_channel`]) — one fact, one place
/// (docs/questions/Q-1001 item 5).
/// Spec: docs/54 §3.1, §4.3, §4.4, §4.6, §5.2, §5.5; docs/questions/Q-619
/// item 5, Q-994 item 6 (e), Q-1001.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsServiceSettings {
    channel: Channel,
    registrable_networks: Vec<Network>,
    record_max_age: Duration,
    soa: SoaSettings,
    infrastructure_ttl: u32,
    host_ttl: u32,
}

impl DnsServiceSettings {
    /// `dird-dns.sock` and dnsd's uid — the only peer admitted.
    /// Spec: docs/54 §4.3, §4.6; docs/50 R50-3.
    #[must_use]
    pub fn channel(&self) -> &Channel {
        &self.channel
    }

    /// `dns_registrable_networks`: IPv4 networks, at least one.
    /// Spec: docs/54 §5.5; docs/questions/Q-614 item 8.
    #[must_use]
    pub fn registrable_networks(&self) -> &[Network] {
        &self.registrable_networks
    }

    /// `dns_record_max_age`. Spec: docs/54 §5.2.
    #[must_use]
    pub const fn record_max_age(&self) -> Duration {
        self.record_max_age
    }

    /// The configured SOA fields. Spec: docs/54 §3.1.
    #[must_use]
    pub fn soa(&self) -> &SoaSettings {
        &self.soa
    }

    /// The TTL of the synthesized SOA, NS and SRV records, in seconds.
    /// Spec: docs/54 §5.1.
    #[must_use]
    pub const fn infrastructure_ttl(&self) -> u32 {
        self.infrastructure_ttl
    }

    /// The TTL of every host's A records, in seconds. Spec: docs/questions/
    /// Q-991 item 4 (A-170).
    #[must_use]
    pub const fn host_ttl(&self) -> u32 {
        self.host_ttl
    }
}

/// A required zone time value `<seconds>s` within [`DNS_TIME_SECS`].
/// Spec: docs/50 §7.1 ("a duration with a unit"); RFC 1035 §2.3.4,
/// §3.3.13.
fn zone_time(doc: &Document<'_>, key: &'static str) -> Result<u32, Error> {
    Ok(doc
        .required(key, |text| value::duration_secs(text, DNS_TIME_SECS))?
        .value)
}

/// The IPv4 networks of `dns_registrable_networks`: a list of networks
/// (crates/config's one network rule), every one IPv4.
/// Spec: docs/54 §3.1, §5.5; docs/questions/Q-1001 item 3.
fn ipv4_networks(text: &str) -> Result<Vec<Network>, ErrorKind> {
    let networks = value::list(text, value::network)?;
    if networks
        .iter()
        .all(|network| matches!(network.address(), IpAddr::V4(_)))
    {
        Ok(networks)
    } else {
        Err(ErrorKind::NetworkFamily)
    }
}

/// dird's DNS service from the channel pair and the zone keys (module
/// documentation): both or neither of the pair (`IncompletePair`); with
/// it, every zone key but `dns_record_max_age` required (no hidden
/// default — docs/54 §3.1 gives no value; Q-1001 item 2); without it,
/// every zone key refused at its line (`IncompletePair`), never ignored.
/// Spec: docs/54 §3.1, §4.6, §5.2, §5.5; docs/50 §3.2, §7.1;
/// docs/questions/Q-619 item 5, Q-1001 item 1.
fn dns_service(
    doc: &Document<'_>,
    all: &mut Distinct,
) -> Result<Option<DnsServiceSettings>, Error> {
    let socket = doc.optional(DIRD_DNS_SOCKET, value::absolute_path)?;
    let uid = doc.optional(DNSD_UID, value::account_id)?;
    let channel = match (socket, uid) {
        (None, None) => None,
        (Some(socket), None) => {
            return Err(Error::at(
                socket.line,
                DIRD_DNS_SOCKET,
                ErrorKind::IncompletePair,
            ))
        }
        (None, Some(uid)) => return Err(Error::at(uid.line, DNSD_UID, ErrorKind::IncompletePair)),
        (Some(socket), Some(uid)) => {
            all.path(DIRD_DNS_SOCKET, &socket.value, socket.line)?;
            all.id(DNSD_UID, uid.value, uid.line)?;
            Some(Channel {
                socket: socket.value,
                peer_uid: uid.value,
            })
        }
    };
    let Some(channel) = channel else {
        // A zone setting of a service that is not configured is a mistake:
        // refused at its line, never silently ignored (fail closed).
        for key in DNS_ZONE_KEYS {
            if let Some(Located { line, .. }) = doc.optional(key, |_| Ok(()))? {
                return Err(Error::at(line, key, ErrorKind::IncompletePair));
            }
        }
        return Ok(None);
    };
    let registrable_networks = doc.required(DNS_REGISTRABLE_NETWORKS, ipv4_networks)?.value;
    let record_max_age = schema::duration(doc, DNS_RECORD_MAX_AGE, DNS_RECORD_MAX_AGE_SECS)?;
    let soa = SoaSettings {
        rname: doc.required(DNS_SOA_RNAME, value::domain_name)?.value,
        refresh: zone_time(doc, DNS_SOA_REFRESH)?,
        retry: zone_time(doc, DNS_SOA_RETRY)?,
        expire: zone_time(doc, DNS_SOA_EXPIRE)?,
        minimum: zone_time(doc, DNS_SOA_MINIMUM)?,
    };
    Ok(Some(DnsServiceSettings {
        channel,
        registrable_networks,
        record_max_age,
        soa,
        infrastructure_ttl: zone_time(doc, DNS_INFRASTRUCTURE_TTL)?,
        host_ttl: zone_time(doc, DNS_HOST_TTL)?,
    }))
}

/// dird's settings, as parsed and validated from its file.
///
/// Spec: docs/50 R50-15, §2.4, §7.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirdSettings {
    run_as: Account,
    realm: String,
    naming_context: NamingContextLabels,
    dns_host_name: String,
    database_path: AbsolutePath,
    integrity_key_source: IntegrityKeySource,
    integrity_key_path: AbsolutePath,
    attestation_key_path: AbsolutePath,
    policy_store_path: AbsolutePath,
    policy_store_format: PolicyStoreFormat,
    kdc_channel: Channel,
    ldap_channel: Channel,
    admin_channel: Option<Channel>,
    kpasswd_channel: Option<Channel>,
    dns_service: Option<DnsServiceSettings>,
    keyd: Option<Endpoint>,
    node_id: Option<[u8; NODE_ID_OCTETS]>,
    admin_service: Option<AdminServiceSettings>,
    audit: Endpoint,
    frame_timeout: Duration,
    view_lifetime: Duration,
}

/// A served channel from its socket key and peer-uid key.
fn channel(
    doc: &Document<'_>,
    all: &mut Distinct,
    socket_key: &'static str,
    uid_key: &'static str,
) -> Result<Channel, Error> {
    let socket = schema::path(doc, all, socket_key)?;
    let peer_uid = schema::id(doc, all, uid_key)?;
    Ok(Channel { socket, peer_uid })
}

impl DirdSettings {
    /// The closed key table of dird's file. Spec: docs/50 R50-15.
    pub const KEYS: &'static [&'static str] = &[
        RUN_AS_UID,
        RUN_AS_GID,
        REALM,
        NAMING_CONTEXT,
        DNS_HOST_NAME,
        DATABASE_PATH,
        INTEGRITY_KEY_SOURCE,
        INTEGRITY_KEY_PATH,
        ATTESTATION_KEY_PATH,
        POLICY_STORE_PATH,
        POLICY_STORE_FORMAT,
        DIRD_KDC_SOCKET,
        KDC_UID,
        DIRD_LDAP_SOCKET,
        LDAP_FRONT_UID,
        DIRD_ADMIN_SOCKET,
        ADMIND_UID,
        DIRD_KPASSWD_SOCKET,
        KPASSWD_FRONT_UID,
        DIRD_DNS_SOCKET,
        DNSD_UID,
        DNS_REGISTRABLE_NETWORKS,
        DNS_RECORD_MAX_AGE,
        DNS_SOA_RNAME,
        DNS_SOA_REFRESH,
        DNS_SOA_RETRY,
        DNS_SOA_EXPIRE,
        DNS_SOA_MINIMUM,
        DNS_INFRASTRUCTURE_TTL,
        DNS_HOST_TTL,
        KEYD_SOCKET,
        KEYD_UID,
        NODE_ID,
        ADMIN_TICKET_AGE_MAX,
        ADMIN_QUORUM_KEY,
        PROVISION_MANIFEST,
        POLICY_NEXT_PATH,
        AUDIT_SOCKET,
        AUDITD_UID,
        FRAME_TIMEOUT,
        VIEW_LIFETIME,
    ];

    /// Parses and validates dird's file. Required: `run_as_uid`,
    /// `run_as_gid`, `realm`, `naming_context`, `dns_host_name`,
    /// `database_path`,
    /// `integrity_key_source` (only `insecure-development-file`),
    /// `integrity_key_path`, `policy_store_path`, `policy_store_format`
    /// (only `unsigned-development`), `dird_kdc_socket` with `kdc_uid`,
    /// `attestation_key_path` (task PN10; required since task PN12, which
    /// writes the file — A-187 on docs/questions/Q-1048 item 1), distinct
    /// from every other path of the file,
    /// `dird_ldap_socket` with `ldap_front_uid`, `audit_socket`, `auditd_uid`.
    /// Optional: `dird_admin_socket` with `admind_uid` (both or neither);
    /// when they are present, `admin_ticket_age_max` (60s ..= 3600s),
    /// `admin_quorum` (2 ..= 3), `provision_manifest` and `node_id` are
    /// required, and without them the first three are refused
    /// (`IncompletePair`); with the admin channel, optionally
    /// `policy_next_path` (task A16 — refused without the channel) and
    /// `dird_kpasswd_socket` with `kpasswd_front_uid` (task K7 — both or
    /// neither, `IncompletePair`; refused without the admin channel, whose
    /// settings the kpasswd service shares — docs/53 §5.6 step 4; the socket
    /// path and the uid distinct from every other of the file);
    /// `dird_dns_socket` with `dnsd_uid` (task DN10a — both or neither,
    /// `IncompletePair`; independent of the admin channel), and with them
    /// `dns_registrable_networks` (IPv4 networks only — `NetworkFamily`),
    /// `dns_soa_rname` (a domain name), `dns_soa_refresh`, `dns_soa_retry`,
    /// `dns_soa_expire`, `dns_soa_minimum`, `dns_infrastructure_ttl`,
    /// `dns_host_ttl` (each `<n>s`, 0 ..= 2147483647 — required, no default)
    /// and optionally `dns_record_max_age` (1s ..= 604800s, default 604800s)
    /// — each zone key refused without the channel (`IncompletePair`);
    /// `keyd_socket` with `keyd_uid` (both or neither —
    /// without them dird's admin service does not start, the rest of dird
    /// runs); `node_id` (32 lower-case hex digits, not all zero);
    /// `frame_timeout` (5s), `view_lifetime` (5s). `internal_networks` is
    /// not a dird key (no zone table — docs/52 R14): it is refused as an
    /// unknown key.
    ///
    /// # Errors
    /// Any rule of the format or of this schema (see [`crate::ErrorKind`]).
    ///
    /// Spec: docs/50 R50-15, §3.2, §3.4, §4.2, §7.1, §7.2.
    pub fn parse(input: &[u8]) -> Result<Self, Error> {
        let doc = Document::parse(input, Self::KEYS)?;
        let mut all = Distinct::default();
        let run_as = schema::account(&doc, &mut all)?;
        let realm = doc.required(REALM, value::realm)?.value;
        let naming_context = doc.required(NAMING_CONTEXT, value::naming_context)?.value;
        let dns_host_name = doc.required(DNS_HOST_NAME, value::dns_host_name)?.value;
        let database_path = schema::path(&doc, &mut all, DATABASE_PATH)?;
        let integrity_key_source = doc
            .required(INTEGRITY_KEY_SOURCE, |text| {
                value::named(text, INTEGRITY_KEY_SOURCES)
            })?
            .value;
        let integrity_key_path = schema::path(&doc, &mut all, INTEGRITY_KEY_PATH)?;
        // Task PN10: dird's attestation-key file, a path distinct from every
        // other of the file (the integrity key's above all — two keys, two
        // files: docs/59 §7.4, "never the dirstore integrity key", A-129).
        // Required since task PN12 (provision writes the file and this line;
        // A-187 on docs/questions/Q-1048 item 1): missing ⇒ `MissingKey`.
        let attestation_key_path = schema::path(&doc, &mut all, ATTESTATION_KEY_PATH)?;
        let policy_store_path = schema::path(&doc, &mut all, POLICY_STORE_PATH)?;
        let policy_store_format = doc
            .required(POLICY_STORE_FORMAT, |text| {
                value::named(text, POLICY_STORE_FORMATS)
            })?
            .value;
        let kdc_channel = channel(&doc, &mut all, DIRD_KDC_SOCKET, KDC_UID)?;
        let ldap_channel = channel(&doc, &mut all, DIRD_LDAP_SOCKET, LDAP_FRONT_UID)?;
        let admin_socket = doc.optional(DIRD_ADMIN_SOCKET, value::absolute_path)?;
        let admin_uid = doc.optional(ADMIND_UID, value::account_id)?;
        let admin_channel = match (admin_socket, admin_uid) {
            (None, None) => None,
            (Some(socket), None) => {
                return Err(Error::at(
                    socket.line,
                    DIRD_ADMIN_SOCKET,
                    ErrorKind::IncompletePair,
                ))
            }
            (None, Some(uid)) => {
                return Err(Error::at(uid.line, ADMIND_UID, ErrorKind::IncompletePair))
            }
            (Some(socket), Some(uid)) => {
                all.path(DIRD_ADMIN_SOCKET, &socket.value, socket.line)?;
                all.id(ADMIND_UID, uid.value, uid.line)?;
                Some(Channel {
                    socket: socket.value,
                    peer_uid: uid.value,
                })
            }
        };
        // keyd, for the admin service's ticket verification (A-73): both or
        // neither (docs/51 §4.6).
        let keyd_socket = doc.optional(KEYD_SOCKET, value::absolute_path)?;
        let keyd_uid = doc.optional(KEYD_UID, value::account_id)?;
        let keyd = match (keyd_socket, keyd_uid) {
            (None, None) => None,
            (Some(socket), None) => {
                return Err(Error::at(
                    socket.line,
                    KEYD_SOCKET,
                    ErrorKind::IncompletePair,
                ))
            }
            (None, Some(uid)) => {
                return Err(Error::at(uid.line, KEYD_UID, ErrorKind::IncompletePair))
            }
            (Some(socket), Some(uid)) => {
                all.path(KEYD_SOCKET, &socket.value, socket.line)?;
                all.id(KEYD_UID, uid.value, uid.line)?;
                Some(Endpoint::from_parts(socket.value, uid.value))
            }
        };
        // The kpasswd channel (task K7; docs/53 §5.6 step 1): both or
        // neither, and only beside the admin channel — the kpasswd service
        // shares the admin service's ticket-age threshold, manifest, node-id
        // and keyd (docs/53 §5.6 step 4; R51-10: one threshold). A kpasswd
        // setting without the admin channel is refused, never ignored.
        let kpasswd_socket = doc.optional(DIRD_KPASSWD_SOCKET, value::absolute_path)?;
        let kpasswd_uid = doc.optional(KPASSWD_FRONT_UID, value::account_id)?;
        let kpasswd_channel = match (kpasswd_socket, kpasswd_uid) {
            (None, None) => None,
            (Some(socket), None) => {
                return Err(Error::at(
                    socket.line,
                    DIRD_KPASSWD_SOCKET,
                    ErrorKind::IncompletePair,
                ))
            }
            (None, Some(uid)) => {
                return Err(Error::at(
                    uid.line,
                    KPASSWD_FRONT_UID,
                    ErrorKind::IncompletePair,
                ))
            }
            (Some(socket), Some(uid)) => {
                if admin_channel.is_none() {
                    return Err(Error::at(
                        socket.line.min(uid.line),
                        if socket.line <= uid.line {
                            DIRD_KPASSWD_SOCKET
                        } else {
                            KPASSWD_FRONT_UID
                        },
                        ErrorKind::IncompletePair,
                    ));
                }
                all.path(DIRD_KPASSWD_SOCKET, &socket.value, socket.line)?;
                all.id(KPASSWD_FRONT_UID, uid.value, uid.line)?;
                Some(Channel {
                    socket: socket.value,
                    peer_uid: uid.value,
                })
            }
        };
        // The DNS channel (task DN10a; docs/54 §4.6): independent of the
        // admin channel — the zone image needs neither keyd nor the write
        // PEP (docs/questions/Q-1001 item 1).
        let dns_service = dns_service(&doc, &mut all)?;
        let node_id = doc.optional(NODE_ID, value::node_id)?;
        let ticket_age = doc.optional(ADMIN_TICKET_AGE_MAX, |text| {
            value::duration_secs(text, ADMIN_TICKET_AGE_MAX_SECS)
        })?;
        let quorum = doc.optional(ADMIN_QUORUM_KEY, |text| value::bounded(text, ADMIN_QUORUM))?;
        let manifest = doc.optional(PROVISION_MANIFEST, value::absolute_path)?;
        let policy_next = doc.optional(POLICY_NEXT_PATH, value::absolute_path)?;
        let admin_service = if admin_channel.is_some() {
            // The admin service's settings have no hidden default (docs/51
            // §5.5: the threshold is a configured value; P-22: the quorum).
            let ticket_age = ticket_age.ok_or(Error::missing(ADMIN_TICKET_AGE_MAX))?;
            let quorum = quorum.ok_or(Error::missing(ADMIN_QUORUM_KEY))?;
            let manifest = manifest.ok_or(Error::missing(PROVISION_MANIFEST))?;
            if node_id.is_none() {
                return Err(Error::missing(NODE_ID));
            }
            all.path(PROVISION_MANIFEST, &manifest.value, manifest.line)?;
            // Task A16: optional — without it the online policy change is
            // refused; distinct from every other path of the file.
            if let Some(located) = &policy_next {
                all.path(POLICY_NEXT_PATH, &located.value, located.line)?;
            }
            Some(AdminServiceSettings {
                ticket_age_max: value::seconds(ticket_age.value),
                quorum: quorum.value,
                provision_manifest: manifest.value,
                policy_next: policy_next.map(|located| located.value),
            })
        } else {
            // A setting of a service that is not configured is a mistake:
            // refused, never silently ignored (fail closed).
            if let Some(located) = ticket_age {
                return Err(Error::at(
                    located.line,
                    ADMIN_TICKET_AGE_MAX,
                    ErrorKind::IncompletePair,
                ));
            }
            if let Some(located) = quorum {
                return Err(Error::at(
                    located.line,
                    ADMIN_QUORUM_KEY,
                    ErrorKind::IncompletePair,
                ));
            }
            if let Some(located) = manifest {
                return Err(Error::at(
                    located.line,
                    PROVISION_MANIFEST,
                    ErrorKind::IncompletePair,
                ));
            }
            if let Some(located) = policy_next {
                return Err(Error::at(
                    located.line,
                    POLICY_NEXT_PATH,
                    ErrorKind::IncompletePair,
                ));
            }
            None
        };
        let audit = schema::endpoint(&doc, &mut all, AUDIT_SOCKET, AUDITD_UID)?;
        let frame_timeout = schema::duration(&doc, FRAME_TIMEOUT, FRAME_TIMEOUT_SECS)?;
        let view_lifetime = schema::duration(&doc, VIEW_LIFETIME, VIEW_LIFETIME_SECS)?;
        Ok(DirdSettings {
            run_as,
            realm,
            naming_context,
            dns_host_name,
            database_path,
            integrity_key_source,
            integrity_key_path,
            attestation_key_path,
            policy_store_path,
            policy_store_format,
            kdc_channel,
            ldap_channel,
            admin_channel,
            kpasswd_channel,
            dns_service,
            keyd,
            node_id: node_id.map(|located| located.value),
            admin_service,
            audit,
            frame_timeout,
            view_lifetime,
        })
    }

    /// The account dird drops to. Spec: docs/50 §6.1, §6.4.
    #[must_use]
    pub const fn run_as(&self) -> Account {
        self.run_as
    }

    /// The realm (checked against the naming context by crates/ldap, A-55).
    /// Spec: docs/50 §7.1.
    #[must_use]
    pub fn realm(&self) -> &str {
        &self.realm
    }

    /// The naming context's labels, for `directory_pip::NamingContext::new`.
    /// Spec: docs/50 §7.1; A-53.
    #[must_use]
    pub fn naming_context(&self) -> &NamingContextLabels {
        &self.naming_context
    }

    /// The DC's DNS host name (the rootDSE's dNSHostName).
    /// Spec: [MS-ADTS] 3.1.1.3.2.4; docs/49 §5.2.
    #[must_use]
    pub fn dns_host_name(&self) -> &str {
        &self.dns_host_name
    }

    /// The redb file. Spec: docs/50 R50-2, §6.4.
    #[must_use]
    pub fn database_path(&self) -> &AbsolutePath {
        &self.database_path
    }

    /// Where the dirstore integrity key comes from (the development interim
    /// only, until P-17). Spec: docs/50 §7.4; Q-213 (A-57); Q-270 item 1.
    #[must_use]
    pub const fn integrity_key_source(&self) -> IntegrityKeySource {
        self.integrity_key_source
    }

    /// The development integrity-key file (root-owned, mode 0400 — the
    /// daemon's checks). Spec: docs/50 §7.1, §7.4; Q-270 item 1.
    #[must_use]
    pub fn integrity_key_path(&self) -> &AbsolutePath {
        &self.integrity_key_path
    }

    /// dird's name-resolution attestation-key file (root-owned, mode 0400,
    /// exactly 32 octets — the daemon's checks; task PN10). Always present:
    /// the schema requires it (task PN12).
    /// Spec: docs/59 §7.4; docs/50 §7.1; docs/questions/Q-1011 item 2
    /// (A-173), Q-1046 item 5, Q-1048 item 1 (A-187).
    #[must_use]
    pub fn attestation_key_path(&self) -> &AbsolutePath {
        &self.attestation_key_path
    }

    /// The signed policy store (rules, anonymous allowlist, TierMap — A-36).
    /// Spec: docs/50 §7.2.
    #[must_use]
    pub fn policy_store_path(&self) -> &AbsolutePath {
        &self.policy_store_path
    }

    /// The policy store's format (unsigned development only, until Q-219's
    /// signed format exists). Spec: docs/50 §7.2; Q-270 item 2.
    #[must_use]
    pub const fn policy_store_format(&self) -> PolicyStoreFormat {
        self.policy_store_format
    }

    /// `dird-kdc.sock` and kdc's uid. Spec: docs/50 §3.2, §3.4.
    #[must_use]
    pub fn kdc_channel(&self) -> &Channel {
        &self.kdc_channel
    }

    /// `dird-ldap.sock` and ldap-front's uid. Spec: docs/50 §3.2, §4.2.
    #[must_use]
    pub fn ldap_channel(&self) -> &Channel {
        &self.ldap_channel
    }

    /// `dird-admin.sock` and admind's uid, when configured. Spec: docs/50
    /// §3.2; Q-220.
    #[must_use]
    pub fn admin_channel(&self) -> Option<&Channel> {
        self.admin_channel.as_ref()
    }

    /// `dird-kpasswd.sock` and kpasswd-front's uid, when configured (only
    /// beside the admin channel). Spec: docs/53 §5.6 step 1; docs/50 §3.2;
    /// docs/questions/Q-955 item 13.
    #[must_use]
    pub fn kpasswd_channel(&self) -> Option<&Channel> {
        self.kpasswd_channel.as_ref()
    }

    /// dird's DNS service — `dird-dns.sock`, dnsd's uid and the zone values
    /// — when configured (task DN10a). Spec: docs/54 §4.3, §4.6;
    /// docs/questions/Q-619 item 5, Q-1001.
    #[must_use]
    pub fn dns_service(&self) -> Option<&DnsServiceSettings> {
        self.dns_service.as_ref()
    }

    /// keyd's socket and uid, when configured: dird's admin service verifies
    /// the administrators' AP-REQs through keyd as Role::Ldap (A-73).
    /// Spec: docs/51 §4.6, §5.3 (option D), §7.4 step 1; A-73.
    #[must_use]
    pub fn keyd(&self) -> Option<&Endpoint> {
        self.keyd.as_ref()
    }

    /// This DC's node-id, when configured (required with the admin
    /// channel). Spec: docs/51 §4.6.
    #[must_use]
    pub const fn node_id(&self) -> Option<[u8; NODE_ID_OCTETS]> {
        self.node_id
    }

    /// The admin service's settings, present exactly when the admin channel
    /// is configured. Spec: docs/51 §5.5, §5.6, §7.
    #[must_use]
    pub fn admin_service(&self) -> Option<&AdminServiceSettings> {
        self.admin_service.as_ref()
    }

    /// auditd's socket and uid. Spec: docs/50 §2.4, R50-17.
    #[must_use]
    pub fn audit(&self) -> &Endpoint {
        &self.audit
    }

    /// How long a started frame may take to arrive. Spec: docs/50 §3.6.
    #[must_use]
    pub const fn frame_timeout(&self) -> Duration {
        self.frame_timeout
    }

    /// How long a pinned view lives. Spec: docs/50 §3.4.
    #[must_use]
    pub const fn view_lifetime(&self) -> Duration {
        self.view_lifetime
    }
}
