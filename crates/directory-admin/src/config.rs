//! The configuration of the write PEP, and the counter names and ranges the
//! provisioning tool (task A4) creates.
//!
//! Spec: docs/51 §5.5 (R51-10: `ticket_age` above a threshold is refused —
//! the threshold is the caller's, no default here), §5.6 (R51-11; quorum),
//! §8.3 (R51-16; the RID range), §7.4 step 5; decisions A-75 (Q-293), A-83
//! (Q-330), P-22 (Q-295).

use core::time::Duration;
use std::collections::BTreeSet;
use std::net::IpAddr;

use config::Network;
use directory_pip::NamingContext;
use dirstore::NodeId;
use dtyp::{Guid, Sid};
use ipc_audit::MAX_APPROVERS;
use krb_proto::Realm;
use principal_names::NameContext;

/// The zone serial counter (task DN6): its name and range, defined once in
/// crate directory-pip (the zone projection reads it) and created, like the
/// RID and change-seq counters, by the provisioning session only (A-83).
/// Spec: docs/54 §5.4; RFC 2136 §3.6, §7.11; A-75; A-83.
pub use directory_pip::{
    DNS_ZONE_SERIAL_COUNTER, DNS_ZONE_SERIAL_END_EXCLUSIVE, DNS_ZONE_SERIAL_FIRST,
};

/// The name of the RID counter. Created by `provision domain` only (A-83:
/// "counters created only by `provision domain`"), never by this crate.
/// Spec: docs/51 §8.3 (R51-16); A-75; A-83 (caller rules); dirstore
/// `MAX_COUNTER_NAME_LEN` (alphabet `a-z 0-9 . - _`).
pub const RID_COUNTER: &str = "rid";

/// The name of the change-seq counter (the originating write's
/// `Origin.origin_seq`). Created by `provision domain` only.
/// Spec: docs/51 §8.3 ("the same mechanism for change-seq"); docs/29 §2
/// (as cited in docs/51 §8.3: a monotonic counter per (node-id, epoch); one
/// epoch in phase 1); A-75; A-83.
pub const CHANGE_SEQ_COUNTER: &str = "change-seq";

/// First value of the RID range: the low 32 bits of the initial
/// `rIDAvailablePool` of a new domain, `4611686014132421709 =
/// 0x3FFFFFFF_0000044D` ⇒ 1101. Every predefined RID of [MS-SAMR] 2.2.1.14
/// (ADMINISTRATOR 0x1F4, GUEST 0x1F5, KRBTGT 0x1F6, the groups 0x201..0x220)
/// lies below it, so no RID this crate hands out is one of them (A-79: no
/// 500 / 501 / 512).
/// Spec: docs/51 §8.1, §8.3 (from [MS-ADTS] 6.1.5.3 and [MS-DRSR]
/// 4.1.10.5.12 as cited there); [MS-SAMR] 2.2.1.14, 3.1.1.9.2.2 item 1.1
/// (≥ 1000); A-75.
pub const RID_FIRST: u64 = 1101;

/// One past the last value of the RID range: the high 32 bits of the
/// initial `rIDAvailablePool`, `0x3FFFFFFF`. Exhaustion ⇒ refusal (fail
/// closed). Spec: docs/51 §8.1, §8.3; A-75.
pub const RID_END_EXCLUSIVE: u64 = 0x3FFF_FFFF;

/// The first value of the change-seq counter. Project choice (docs/29 §2
/// gives no origin; 0 is left meaning "no write"); its range ends at
/// `u64::MAX` (exclusive) — the change-seq is a u64 (dirstore
/// `Origin.origin_seq`). Created with it by the provisioning session only
/// (`crate::Provisioning`, A-83). Moved here from crate provision with the
/// counter's creation (docs/52 R13). docs/questions/Q-376 item 4.
pub const CHANGE_SEQ_FIRST: u64 = 1;

/// One past the last change-seq value. Spec: dirstore `CounterState`
/// (half-open range); docs/questions/Q-376 item 4.
pub const CHANGE_SEQ_END_EXCLUSIVE: u64 = u64::MAX;

/// The `principal-namespace` marker (task PN5): its name and one-value
/// range, defined once in crate directory-pip beside the namespace it marks
/// (dird refuses a store without it — `directory_pip::
/// principal_namespace_marked`, task PN10) and created, like the RID and
/// change-seq counters, by the provisioning session only (A-83). Re-exported
/// here under the same names (docs/questions/Q-1043 item 1, A-185).
/// Spec: docs/59 §5.2 (c), §5.5; docs/questions/Q-1008 item 5 (A-173),
/// Q-1029 item 6, Q-1043 item 1.
pub use directory_pip::{
    PRINCIPAL_NAMESPACE_COUNTER, PRINCIPAL_NAMESPACE_END_EXCLUSIVE, PRINCIPAL_NAMESPACE_FIRST,
};

/// The smallest dual-control quorum: the requester plus one other approver.
/// There is no "single administrator" mode — a weak option has no code path
/// (P-22 item 3, A-72 "no code path for the weak option").
/// Spec: docs/51 §5.6 (R51-11); Q-295 items 2-3 (P-22).
pub const MIN_QUORUM: usize = 2;

/// The largest quorum a request can reach: the requester plus the most
/// approvers an event names (crate ipc-audit `MAX_APPROVERS`, two — the
/// bound docs/51 §7.2 set when approvals were carried in the request; they
/// are a pending request's now, docs/questions/Q-882).
/// Spec: docs/51 §5.6, §7.2; crate ipc-audit `MAX_APPROVERS`.
pub const MAX_QUORUM: usize = 1 + MAX_APPROVERS;

/// The objects the admin plane must never delete or change beyond what is
/// listed for each operation, other than the structural ones this crate
/// recognises itself (the krbtgt account by RID 502, a DC account by
/// userAccountControl ST, the naming-context root, and every principal and
/// subtree the tier map names).
///
/// Spec: docs/51 §5.2 row 9 ("refusal for krbtgt / DC / service objects /
/// NC root / groups the policy references"), §4.3 step 5 (the LDAP and admin
/// service objects); A-18; A-19; A-35.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProtectedObjects {
    /// The objectGUIDs of the service objects (the LDAP service object and
    /// the admin service object of `provision domain`, from its manifest).
    pub service_objects: BTreeSet<Guid>,
    /// The objectSids of the principals the policy names outside the tier
    /// map: the FAST bootstrap group (`fast.bootstrap_group`, A-39 / A-44).
    pub policy_principals: BTreeSet<Sid>,
}

/// A configuration value was refused. Fail closed: no PEP is built.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConfigError {
    /// `ticket_age_max` is zero.
    TicketAgeMax,
    /// The quorum is outside [`MIN_QUORUM`]..=[`MAX_QUORUM`].
    Quorum,
    /// The realm is not the naming context's DNS name in upper case.
    Realm,
    /// The node id is all zero.
    NodeId,
    /// An attribute or class this crate needs is missing from the schema.
    Schema,
    /// The lifetime of a pending request is zero or above
    /// `MAX_REQUEST_LIFETIME` (task D2-c; it was the key requests', task
    /// A10).
    RequestLifetime,
    /// The per-requester cap of open pending requests is zero or above
    /// `MAX_REQUESTS_PER_REQUESTER` (task D2-c).
    RequesterCap,
    /// The DNS registration networks are empty, or one is not IPv4 (task
    /// DN6: a host record holds IPv4 addresses only — AAAA waits for RFC
    /// 3596, docs/54 §3.1).
    DnsNetworks,
    /// The naming context's DNS name is not usable as the principal
    /// namespace's realm alias (task PN5; crate principal-names
    /// `NameContext::new`: RFC 4120 §6.1 domain style, not "krbtgt").
    PrincipalNamespace,
}

impl core::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            ConfigError::TicketAgeMax => "ticket age threshold is zero",
            ConfigError::Quorum => "dual-control quorum is out of range",
            ConfigError::Realm => "realm is not the naming context's DNS name in upper case",
            ConfigError::NodeId => "node id is all zero",
            ConfigError::Schema => "schema lacks a definition the admin plane needs",
            ConfigError::RequestLifetime => "pending request lifetime is out of range",
            ConfigError::RequesterCap => "per-requester pending request cap is out of range",
            ConfigError::DnsNetworks => "DNS registration networks are empty or not IPv4",
            ConfigError::PrincipalNamespace => {
                "naming context's DNS name is not a valid principal namespace realm alias"
            }
        })
    }
}

/// What a host may register in its own DNS host record (task DN6): the
/// networks its addresses must lie in (`dns_registrable_networks`, docs/54
/// §5.5; Q-614 item 8 — dird's configuration, defaulting to its
/// `internal_networks`). Without it, the PEP refuses every self-update and
/// the write checker refuses every host address (fail closed).
/// Spec: docs/54 §5.5; docs/questions/Q-614 item 8; A-114.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRegistration {
    networks: Vec<Network>,
}

impl DnsRegistration {
    /// The registration rule over `networks`: at least one, all IPv4.
    ///
    /// # Errors
    /// [`ConfigError::DnsNetworks`].
    ///
    /// Spec: docs/54 §3.1 (A only; AAAA waits for RFC 3596), §5.5.
    pub fn new(networks: Vec<Network>) -> Result<DnsRegistration, ConfigError> {
        let ipv4 = |n: &Network| matches!(n.address(), IpAddr::V4(_));
        if networks.is_empty() || !networks.iter().all(ipv4) {
            return Err(ConfigError::DnsNetworks);
        }
        Ok(DnsRegistration { networks })
    }

    /// The registrable networks.
    #[must_use]
    pub fn networks(&self) -> &[Network] {
        &self.networks
    }
}

impl std::error::Error for ConfigError {}

/// The write PEP's configuration. Every value comes from the caller (dird's
/// configuration and the policy); nothing has a default here.
///
/// Spec: docs/51 §5.5 (R51-10), §5.6 (R51-11), §4.6 (`node_id`), §5.2 row 9;
/// A-75; P-22.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminConfig {
    ticket_age_max: Duration,
    quorum: usize,
    realm: Realm,
    naming_context: NamingContext,
    /// The principal namespace's realm context, derived from
    /// `naming_context` (task PN5; docs/59 §5.1: "`NameContext` reaches
    /// `Invariants` from `AdminConfig`").
    names: NameContext,
    node_id: NodeId,
    protected: ProtectedObjects,
    /// The DNS self-update rule (task DN6); `None` ⇒ none is accepted.
    dns: Option<DnsRegistration>,
}

impl AdminConfig {
    /// Check and build the configuration.
    ///
    /// - `ticket_age_max`: a ticket whose age (`now − authtime`) is above it
    ///   is refused (R51-10); zero is refused (it would refuse everything —
    ///   a misconfiguration, not a policy).
    /// - `quorum`: the requester plus approvers a dual-controlled operation
    ///   needs, [`MIN_QUORUM`]..=[`MAX_QUORUM`] (P-22: 2).
    /// - `realm`, `naming_context`: the domain; the realm must be the naming
    ///   context's DNS name in upper case (docs/47 §3.3 item 3; A-53). The
    ///   principal namespace's realm context is derived from the same naming
    ///   context (directory-pip `name_context_of`; its one alias is the NC's
    ///   DNS name — P-84 open), refused with
    ///   [`ConfigError::PrincipalNamespace`] if that name cannot be an alias.
    /// - `node_id`: this DC's node-id, the `Origin.origin_node` of every write
    ///   (docs/29 §2 as cited in docs/51 §4.6); all zero is refused.
    /// - `protected`: the service objects and policy principals.
    ///
    /// Spec: docs/51 §4.6, §5.5, §5.6, §5.2 row 9; P-22; A-53; docs/59 §4.2,
    /// §5.1 (task PN5).
    pub fn new(
        ticket_age_max: Duration,
        quorum: usize,
        realm: Realm,
        naming_context: NamingContext,
        node_id: NodeId,
        protected: ProtectedObjects,
    ) -> Result<AdminConfig, ConfigError> {
        if ticket_age_max.is_zero() {
            return Err(ConfigError::TicketAgeMax);
        }
        if !(MIN_QUORUM..=MAX_QUORUM).contains(&quorum) {
            return Err(ConfigError::Quorum);
        }
        if naming_context.dns_name().to_ascii_uppercase().as_bytes() != realm.as_bytes() {
            return Err(ConfigError::Realm);
        }
        let names = directory_pip::name_context_of(&naming_context)
            .map_err(|_| ConfigError::PrincipalNamespace)?;
        if node_id.0 == [0u8; 16] {
            return Err(ConfigError::NodeId);
        }
        Ok(AdminConfig {
            ticket_age_max,
            quorum,
            realm,
            naming_context,
            names,
            node_id,
            protected,
            dns: None,
        })
    }

    /// This configuration with DNS self-updates enabled under `dns` (task
    /// DN6; docs/54 §5.5). Without it, `DnsSelfUpdate` is refused and no
    /// host address can be written (fail closed).
    /// Spec: docs/54 §5.5; docs/questions/Q-614 item 8.
    #[must_use]
    pub fn with_dns_registration(mut self, dns: DnsRegistration) -> AdminConfig {
        self.dns = Some(dns);
        self
    }

    /// The DNS self-update rule, if enabled.
    #[must_use]
    pub fn dns_registration(&self) -> Option<&DnsRegistration> {
        self.dns.as_ref()
    }

    /// The ticket-age threshold (R51-10).
    #[must_use]
    pub fn ticket_age_max(&self) -> Duration {
        self.ticket_age_max
    }

    /// The dual-control quorum (P-22).
    #[must_use]
    pub fn quorum(&self) -> usize {
        self.quorum
    }

    /// The realm.
    #[must_use]
    pub fn realm(&self) -> &Realm {
        &self.realm
    }

    /// The naming context.
    #[must_use]
    pub fn naming_context(&self) -> &NamingContext {
        &self.naming_context
    }

    /// The principal namespace's realm context (task PN5): the alias set
    /// every key of the one checker and every `Lookup` probe is computed in.
    /// Spec: docs/59 §4.2 (`NameContext`), §5.1.
    pub(crate) fn name_context(&self) -> &NameContext {
        &self.names
    }

    /// This DC's node-id.
    #[must_use]
    pub fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// The protected service objects and policy principals.
    #[must_use]
    pub fn protected(&self) -> &ProtectedObjects {
        &self.protected
    }
}
