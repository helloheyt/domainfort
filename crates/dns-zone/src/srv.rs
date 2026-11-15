//! The phase-1 synthesized SRV set: a closed list, fixed names and ports.
//!
//! SRV records are never stored and have no write path (docs/54 §5.1): every
//! zone image synthesizes them from the apex and the DC's fully qualified name.
//! The set is closed — a service not listed here cannot appear in a reply.
//!
//! # One record per service that exists (task DN10b; docs/questions/Q-1004)
//!
//! **Class (AGENTS.md §6.1) — the zone advertises an endpoint no process
//! serves.** An SRV record tells a client where to go; one for a transport
//! nothing listens on sends it to a dead end (a delay, a fallback it may not
//! have). The phase-1 instance was `_kpasswd._udp`: kpasswd-front serves
//! TCP 464 only and has no UDP socket (A-117, A-158), yet the record was
//! synthesized whenever kpasswd existed.
//!
//! **The change: the advertised set is this one table, and the table holds
//! exactly the (service, transport) pairs a phase-1 process serves** — the
//! KDC on UDP and TCP (crates/kdc-daemon), ldap-front on TCP
//! (crates/ldap-front), kpasswd-front on TCP only (crates/kpasswd-front).
//! There is no `_kpasswd._udp` variant, so a UDP kpasswd record cannot be
//! represented, whatever an image's parameters say; a UDP kpasswd listener
//! added later adds its variant here with it. The guard
//! `tests/srv_served.rs` ties each variant to its serving crate's own
//! socket (a `_udp` record needs a UDP socket there, a `_tcp` record a TCP
//! listener), so the table and the daemons cannot drift apart unnoticed.
//! What this table cannot see — a listener *configured* away (an ldap-front
//! with LDAPS listeners only; a port other than the standard one) — is
//! recorded in docs/questions/Q-1016.
//!
//! Spec: docs/54 §3.1, §5.1; docs/questions/Q-618 item 1, Q-1004 (decision
//! A-172: option 2, "one SRV record per service that exists"), Q-1016; RFC
//! 2782 ("The format of the SRV RR", Applicability); RFC 4120 §7.2.3.2;
//! [MS-ADTS] v20261026 §6.3.2.3; PENDING-OWNER A-117, A-158 (kpasswd-front:
//! TCP 464 only).

/// One synthesized SRV RRset of phase 1 (one record each: a single DC, OD-2)
/// — one variant per (service, transport) a phase-1 process serves (module
/// documentation, "One record per service that exists").
///
/// Spec: docs/54 §3.1; docs/questions/Q-618 item 1, Q-1004 (A-172).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SrvService {
    /// `_kerberos._udp.<realm>`, port 88. Spec: RFC 4120 §7.2.3.2 ("The Service
    /// name for Kerberos is always "kerberos""; "both "udp" and "tcp" records
    /// MUST be specified"; port 88); [MS-ADTS] §6.3.2.3 (`_kerberos._udp.X`).
    KerberosUdp,
    /// `_kerberos._tcp.<realm>`, port 88. Spec: RFC 4120 §7.2.3.2; [MS-ADTS]
    /// §6.3.2.3 (`_kerberos._tcp.X`).
    KerberosTcp,
    /// `_ldap._tcp.<domain>`, port 389. Spec: [MS-ADTS] §6.3.2.3
    /// (`_ldap._tcp.X`; "Set to 389 for LDAP service").
    LdapTcp,
    /// `_kpasswd._tcp.<domain>`, port 464 — only when the kpasswd service
    /// exists. Spec: [MS-ADTS] §6.3.2.3 (`_kpasswd._tcp.X`; "Set to 464 for
    /// Kerberos Password Change service"); docs/54 §3.1; Q-618 item 1.
    KpasswdTcp,
    // No `_kpasswd._udp` variant: kpasswd-front serves TCP only (A-117,
    // A-158) — module documentation; docs/questions/Q-1004 (A-172).
}

/// Whether the zone synthesizes the `_kpasswd` SRV record.
///
/// Spec: docs/54 §3.1 ("synthesized only when kpasswd exists"); Q-618 item 1;
/// docs/questions/Q-1004 (A-172).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KpasswdService {
    /// No kpasswd service: no `_kpasswd` SRV record.
    Absent,
    /// The kpasswd service runs — kpasswd-front, on TCP only: the
    /// `_kpasswd._tcp` record (module documentation).
    Present,
}

/// The Proto label of the UDP records. Spec: RFC 2782 ("_TCP and _UDP are at
/// present the most useful values"; the underscore "prepended to prevent
/// collisions"); RFC 4120 §7.2.3.2.
const UDP_PROTO_LABEL: &[u8] = b"_udp";
/// The Proto label of the TCP records. Spec: RFC 2782; RFC 4120 §7.2.3.2.
const TCP_PROTO_LABEL: &[u8] = b"_tcp";

/// Priority of every synthesized record: one target only (OD-2), so the
/// lowest value. Spec: RFC 2782 (Priority: "lowest-numbered priority");
/// RFC 4120 §7.2.3.3 (the first KDC's records carry priority 0);
/// docs/questions/Q-670 item 4.
pub const SRV_PRIORITY: u16 = 0;

/// Weight of every synthesized record. Spec: RFC 2782 ("Domain administrators
/// SHOULD use Weight 0 when there isn't any server selection to do");
/// RFC 4120 §7.2.3.3 ("Weights are not used in these sample records");
/// docs/questions/Q-670 item 4.
pub const SRV_WEIGHT: u16 = 0;

impl SrvService {
    /// Every service, in the order the image lists them.
    pub const ALL: [SrvService; 4] = [
        SrvService::KerberosUdp,
        SrvService::KerberosTcp,
        SrvService::LdapTcp,
        SrvService::KpasswdTcp,
    ];

    /// The Service label (with its underscore). Spec: RFC 2782 ("An underscore
    /// (_) is prepended to the service identifier"); RFC 4120 §7.2.3.2;
    /// [MS-ADTS] §6.3.2.3.
    pub const fn service_label(self) -> &'static [u8] {
        match self {
            SrvService::KerberosUdp | SrvService::KerberosTcp => b"_kerberos",
            SrvService::LdapTcp => b"_ldap",
            SrvService::KpasswdTcp => b"_kpasswd",
        }
    }

    /// The Proto label (with its underscore). Spec: RFC 2782; RFC 4120
    /// §7.2.3.2; [MS-ADTS] §6.3.2.3.
    pub const fn proto_label(self) -> &'static [u8] {
        match self {
            SrvService::KerberosUdp => UDP_PROTO_LABEL,
            SrvService::KerberosTcp | SrvService::LdapTcp | SrvService::KpasswdTcp => {
                TCP_PROTO_LABEL
            }
        }
    }

    /// The Port. Spec: RFC 4120 §7.2.3.2 (88); [MS-ADTS] §6.3.2.3 ("Set to 389
    /// for LDAP service … Set to 88 for Kerberos KDC service. Set to 464 for
    /// Kerberos Password Change service").
    pub const fn port(self) -> u16 {
        match self {
            SrvService::KerberosUdp | SrvService::KerberosTcp => 88,
            SrvService::LdapTcp => 389,
            SrvService::KpasswdTcp => 464,
        }
    }

    /// Whether this record is synthesized when the kpasswd service is as
    /// given. Spec: docs/54 §3.1; Q-618 item 1; Q-1004 (A-172).
    pub const fn synthesized_with(self, kpasswd: KpasswdService) -> bool {
        match self {
            SrvService::KerberosUdp | SrvService::KerberosTcp | SrvService::LdapTcp => true,
            SrvService::KpasswdTcp => matches!(kpasswd, KpasswdService::Present),
        }
    }
}
