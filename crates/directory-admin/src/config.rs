//! The configuration of the write PEP, and the counter names and ranges the
//! provisioning tool (task A4) creates.
//!
//! Spec: docs/51 §5.5 (R51-10: `ticket_age` above a threshold is refused —
//! the threshold is the caller's, no default here), §5.6 (R51-11; quorum),
//! §8.3 (R51-16; the RID range), §7.4 step 5; decisions A-75 (Q-293), A-83
//! (Q-330), P-22 (Q-295).

use core::time::Duration;
use std::collections::BTreeSet;

use directory_pip::NamingContext;
use dirstore::NodeId;
use dtyp::{Guid, Sid};
use ipc_audit::MAX_APPROVERS;
use krb_proto::Realm;

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

/// The smallest dual-control quorum: the requester plus one other approver.
/// There is no "single administrator" mode — a weak option has no code path
/// (P-22 item 3, A-72 "no code path for the weak option").
/// Spec: docs/51 §5.6 (R51-11); Q-295 items 2-3 (P-22).
pub const MIN_QUORUM: usize = 2;

/// The largest quorum a request can reach: the requester plus the most
/// approvals a request carries (`approvals: seq<…, 2>`, docs/51 §7.2).
/// Spec: docs/51 §7.2; crate ipc-audit `MAX_APPROVERS`.
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
    /// The lifetime of a pending key-operation request is zero or above
    /// `MAX_KEY_REQUEST_LIFETIME` (task A10).
    KeyRequestLifetime,
}

impl core::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            ConfigError::TicketAgeMax => "ticket age threshold is zero",
            ConfigError::Quorum => "dual-control quorum is out of range",
            ConfigError::Realm => "realm is not the naming context's DNS name in upper case",
            ConfigError::NodeId => "node id is all zero",
            ConfigError::Schema => "schema lacks a definition the admin plane needs",
            ConfigError::KeyRequestLifetime => "key-operation request lifetime is out of range",
        })
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
    node_id: NodeId,
    protected: ProtectedObjects,
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
    ///   context's DNS name in upper case (docs/47 §3.3 item 3; A-53).
    /// - `node_id`: this DC's node-id, the `Origin.origin_node` of every write
    ///   (docs/29 §2 as cited in docs/51 §4.6); all zero is refused.
    /// - `protected`: the service objects and policy principals.
    ///
    /// Spec: docs/51 §4.6, §5.5, §5.6, §5.2 row 9; P-22; A-53.
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
        if node_id.0 == [0u8; 16] {
            return Err(ConfigError::NodeId);
        }
        Ok(AdminConfig {
            ticket_age_max,
            quorum,
            realm,
            naming_context,
            node_id,
            protected,
        })
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
