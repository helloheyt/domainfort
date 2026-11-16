//! The typed layer: the requests and replies of the admin channel as owned
//! Rust values, each passed through its strict decoder — text as UTF-8,
//! objectGUIDs as [MS-DTYP] 2.3.4.2 packets, SIDs through dtyp's [MS-DTYP]
//! 2.4.2.2 decoder, realms and salts through the KerberosString rules,
//! binding names through krb-proto's strict DER. Every value has exactly one
//! encoding, so `encode(decode(b)) == b` holds for everything that decodes
//! (an accountExpires of "never" is spelled only as `Never`, never as `At`
//! of the never value — the same rule as the audit shape, A-85).
//!
//! What the codec does **not** check — the semantic rules of docs/51 §11
//! (name characters and lengths, groupType values, accountExpires 0, …) —
//! is the write PEP's job in dird (crates/directory-admin), which records
//! every refusal in the audit trail.
//!
//! Spec: docs/51 §7.2, §7.3; docs/50 §3.3 ("Kerberos values … decoded in
//! `krb-proto`"; "a single encoding per value"; replies decoded with the
//! same strictness); A-85 (one spelling of "never").

use crate::channel::{codes, RefusalStatus, DIGEST_LEN};
use crate::plan::{plan_digest, EffectPlan};
use crate::wire::{
    AdminReply, AdminRequest, WireAuth, WireFact, WireKeyOperation, WireKeyRef, WireKeyTarget,
    WireLookupKey, WireOperation, WirePendingRequest, WirePolicyChange, WireRequestShown,
    WireRequestSummary,
};
use core::fmt;
use dtyp::{Guid, Sid};
use ipc::DerBlob;
use keyd_types::{KeyHandle, PrincipalBinding, PrincipalId};
use krb_proto::{KerberosString, PrincipalName};

/// The FILETIME meaning "never": the admin plane writes "never" as this
/// value only, so `At` of it is not a second spelling.
/// Spec: docs/47 §4.2 (R47-5b); [MS-SAMR] 3.1.1.8.1 item 1.2; crate
/// ipc-audit `AccountExpiresValue`.
pub const ACCOUNT_EXPIRES_NEVER: u64 = 0x7FFF_FFFF_FFFF_FFFF;

/// A value on the wire did not pass its strict decoder, or a reply does not
/// belong to the request. Carries no octet.
/// Spec: docs/50 §3.3, §8.2 ("IPC errors carry a code, not content").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConversionError {
    /// A text field is not UTF-8.
    Text,
    /// A SID packet did not decode ([MS-DTYP] 2.4.2.2).
    Sid,
    /// A realm or salt is not a valid KerberosString (RFC 4120 5.2.1).
    KerberosString,
    /// A `PrincipalName` DER did not decode strictly, or could not be
    /// encoded.
    PrincipalName,
    /// A value with a second spelling (accountExpires `At` the "never"
    /// value), or a key target of a purpose this channel cannot carry.
    NonCanonical,
    /// The reply is valid but answers another request.
    UnexpectedReply,
    /// A count that does not fit its one-octet field (approvals, quorum).
    Count,
    /// An effect plan does not decode, its digest is not the one it comes
    /// with, or a shown request's plan is not the one its `Commit` names
    /// (task MA2).
    Plan,
}

impl fmt::Display for ConversionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ConversionError::Text => "text field is not UTF-8",
            ConversionError::Sid => "invalid SID",
            ConversionError::KerberosString => "invalid KerberosString",
            ConversionError::PrincipalName => "invalid PrincipalName",
            ConversionError::NonCanonical => "value with a second spelling",
            ConversionError::UnexpectedReply => "reply does not answer the request",
            ConversionError::Count => "count does not fit its field",
            ConversionError::Plan => "effect plan does not match its digest",
        })
    }
}

impl std::error::Error for ConversionError {}

/// The authentication field (the requester's opaque AP-REQ; the in-request
/// approvals are retired — docs/questions/Q-882 item 6). Spec: docs/51 §7.2.
pub type Auth = WireAuth;

/// UTF-8 text from wire octets.
fn text(octets: &[u8]) -> Result<String, ConversionError> {
    String::from_utf8(octets.to_vec()).map_err(|_| ConversionError::Text)
}

/// Optional UTF-8 text.
fn opt_text(octets: Option<&Vec<u8>>) -> Result<Option<String>, ConversionError> {
    octets.map(|o| text(o)).transpose()
}

/// A GUID from its packet ([MS-DTYP] 2.3.4.2).
fn guid(packet: &[u8; 16]) -> Guid {
    Guid::from_packet(packet)
}

/// A SID through dtyp's strict decoder. Spec: [MS-DTYP] 2.4.2.2.
fn sid(octets: &[u8]) -> Result<Sid, ConversionError> {
    Sid::decode(octets).map_err(|_| ConversionError::Sid)
}

/// `accountExpires` of a `SetAccountExpires`.
/// Spec: docs/51 §5.2 row 7 (`never | filetime`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccountExpires {
    /// "Never".
    Never,
    /// A FILETIME (never [`ACCOUNT_EXPIRES_NEVER`]).
    At(u64),
}

/// How the keyd steps of a password set ended, as admind reports it.
/// Spec: docs/51 §7.3 (`CompletePasswordSet {target, outcome, kvnos}`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PasswordSetOutcome {
    /// Every `set_secret` succeeded.
    Completed,
    /// A `set_secret` failed.
    Failed,
}

/// The key of a `Lookup`. Spec: docs/51 §5.2 row 10; docs/questions/Q-358
/// item 5 (the DN as components).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupKey {
    /// A sAMAccountName.
    SamAccountName(String),
    /// A servicePrincipalName.
    ServicePrincipalName(String),
    /// A DN as `att=value` components, leaf first.
    Dn(Vec<String>),
}

/// Which key set a `retire_kvno` names. Spec: docs/51 §6; docs/10 §7.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyRef {
    /// The krbtgt key set (dird names it: the provisioning manifest's).
    Krbtgt,
    /// The `Service` key set of a service object (its objectGUID).
    Service(Guid),
}

/// The key operation of a pending request — the three Admin operations of
/// docs/51 §6 that need an approved request.
/// Spec: docs/51 §5.2 row 11, §5.6, §6; docs/10 §7.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyOperation {
    /// `rotate_krbtgt(DualControlToken)`.
    RotateKrbtgt,
    /// `rotate_key` of a service object's randomized `Service` key set.
    RotateKey {
        /// The service object's objectGUID.
        service: Guid,
    },
    /// `retire_kvno`.
    RetireKvno {
        /// The key set.
        key: KeyRef,
        /// The key version to retire.
        kvno: u32,
    },
}

impl KeyOperation {
    /// The typed operation of `wire` (every wire value has a typed form).
    #[must_use]
    pub fn from_wire(wire: &WireKeyOperation) -> KeyOperation {
        match wire {
            WireKeyOperation::RotateKrbtgt => KeyOperation::RotateKrbtgt,
            WireKeyOperation::RotateKey { service } => KeyOperation::RotateKey {
                service: guid(service),
            },
            WireKeyOperation::RetireKvno { key, kvno } => KeyOperation::RetireKvno {
                key: match key {
                    WireKeyRef::Krbtgt => KeyRef::Krbtgt,
                    WireKeyRef::Service(principal) => KeyRef::Service(guid(principal)),
                },
                kvno: *kvno,
            },
        }
    }

    /// The wire form.
    #[must_use]
    pub fn to_wire(&self) -> WireKeyOperation {
        match self {
            KeyOperation::RotateKrbtgt => WireKeyOperation::RotateKrbtgt,
            KeyOperation::RotateKey { service } => WireKeyOperation::RotateKey {
                service: service.to_packet(),
            },
            KeyOperation::RetireKvno { key, kvno } => WireKeyOperation::RetireKvno {
                key: match key {
                    KeyRef::Krbtgt => WireKeyRef::Krbtgt,
                    KeyRef::Service(principal) => WireKeyRef::Service(principal.to_packet()),
                },
                kvno: *kvno,
            },
        }
    }
}

/// A tier-map row's tier (task A16): `Untiered` is never a map row and has
/// no value here (crate policy-store refuses it; A-36).
/// Spec: docs/51 §5.10; A-36; crate::channel `codes::TIER_*`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PolicyTier {
    /// Tier 0.
    Tier0,
    /// Tier 1.
    Tier1,
    /// Tier 2.
    Tier2,
}

impl PolicyTier {
    /// Code → tier (the wire layer admits only these three codes).
    fn from_code(code: u8) -> PolicyTier {
        match code {
            codes::TIER_0 => PolicyTier::Tier0,
            codes::TIER_1 => PolicyTier::Tier1,
            _ => PolicyTier::Tier2,
        }
    }

    /// Tier → code.
    fn code(self) -> u8 {
        match self {
            PolicyTier::Tier0 => codes::TIER_0,
            PolicyTier::Tier1 => codes::TIER_1,
            PolicyTier::Tier2 => codes::TIER_2,
        }
    }
}

/// One tier-map change of a `ChangePolicy` (task A16) — the vocabulary of
/// the tier-map edit (crate policy-store `TierChange`, which dird converts
/// it to; this crate links no policy code). SIDs pass dtyp's strict decoder;
/// DN components are UTF-8 (the edit applies the format's own DN rules).
/// Spec: docs/51 §5.10; docs/questions/Q-592.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PolicyChange {
    /// Add `SID → tier`.
    AddPrincipal(Sid, PolicyTier),
    /// Remove the row of this SID.
    RemovePrincipal(Sid),
    /// Add `subtree → tier` (the DN's components, leaf first).
    AddSubtree(Vec<String>, PolicyTier),
    /// Remove the row of this subtree.
    RemoveSubtree(Vec<String>),
}

impl PolicyChange {
    /// The typed change of `wire`.
    ///
    /// # Errors
    /// [`ConversionError::Sid`], [`ConversionError::Text`].
    pub fn from_wire(wire: &WirePolicyChange) -> Result<PolicyChange, ConversionError> {
        let dn = |components: &[Vec<u8>]| {
            components
                .iter()
                .map(|c| text(c))
                .collect::<Result<Vec<_>, _>>()
        };
        Ok(match wire {
            WirePolicyChange::AddPrincipal { sid: s, tier } => {
                PolicyChange::AddPrincipal(sid(s)?, PolicyTier::from_code(*tier))
            }
            WirePolicyChange::RemovePrincipal { sid: s } => PolicyChange::RemovePrincipal(sid(s)?),
            WirePolicyChange::AddSubtree { dn: d, tier } => {
                PolicyChange::AddSubtree(dn(d)?, PolicyTier::from_code(*tier))
            }
            WirePolicyChange::RemoveSubtree { dn: d } => PolicyChange::RemoveSubtree(dn(d)?),
        })
    }

    /// The wire form.
    #[must_use]
    pub fn to_wire(&self) -> WirePolicyChange {
        let dn = |components: &[String]| components.iter().map(|c| c.as_bytes().to_vec()).collect();
        match self {
            PolicyChange::AddPrincipal(s, tier) => WirePolicyChange::AddPrincipal {
                sid: s.encode(),
                tier: tier.code(),
            },
            PolicyChange::RemovePrincipal(s) => {
                WirePolicyChange::RemovePrincipal { sid: s.encode() }
            }
            PolicyChange::AddSubtree(d, tier) => WirePolicyChange::AddSubtree {
                dn: dn(d),
                tier: tier.code(),
            },
            PolicyChange::RemoveSubtree(d) => WirePolicyChange::RemoveSubtree { dn: dn(d) },
        }
    }
}

/// One operation of the closed set (docs/51 §7.3), with exactly the fields
/// that table lists.
/// Spec: docs/51 §5.2, §7.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operation {
    /// `CreateUser {parent, sam, upn?, description?}`.
    CreateUser {
        /// The container.
        parent: Guid,
        /// The sAMAccountName.
        sam: String,
        /// The userPrincipalName.
        upn: Option<String>,
        /// The description.
        description: Option<String>,
    },
    /// `CreateComputer {parent, name, spn?}`. No dNSHostName: dird derives
    /// `<name>.<realm DNS name>` ([MS-ADTS] 3.1.1.5.3.1.1.2), so a client
    /// cannot name a host (task PN6b; docs/questions/Q-1036 item 1, A-182).
    CreateComputer {
        /// The container.
        parent: Guid,
        /// The computer name, without the trailing "$".
        name: String,
        /// The single servicePrincipalName (its host: the derived
        /// dNSHostName).
        spn: Option<String>,
    },
    /// `CreateGroup {parent, sam, group_type?}`.
    CreateGroup {
        /// The container.
        parent: Guid,
        /// The sAMAccountName.
        sam: String,
        /// The groupType bit pattern (absent: the default).
        group_type: Option<u32>,
    },
    /// `CreateOu {parent, name}`.
    CreateOu {
        /// The parent.
        parent: Guid,
        /// The RDN value.
        name: String,
    },
    /// `CreateContainer {parent, name}`.
    CreateContainer {
        /// The parent.
        parent: Guid,
        /// The RDN value.
        name: String,
    },
    /// `BeginPasswordSet {target}`.
    BeginPasswordSet {
        /// The account.
        target: Guid,
    },
    /// `CompletePasswordSet {target, outcome, kvnos}`.
    CompletePasswordSet {
        /// The account.
        target: Guid,
        /// The outcome admind reports.
        outcome: PasswordSetOutcome,
        /// The key versions keyd chose, in call order.
        kvnos: Vec<u32>,
    },
    /// `SetEnabled {target, value}`.
    SetEnabled {
        /// The account.
        target: Guid,
        /// Enable or disable.
        enabled: bool,
    },
    /// `SetAccountExpires {target, value}`.
    SetAccountExpires {
        /// The account.
        target: Guid,
        /// The value.
        value: AccountExpires,
    },
    /// `AddMember {group, member}`.
    AddMember {
        /// The group.
        group: Guid,
        /// The member.
        member: Guid,
    },
    /// `RemoveMember {group, member}`.
    RemoveMember {
        /// The group.
        group: Guid,
        /// The member.
        member: Guid,
    },
    /// `Delete {target}`.
    Delete {
        /// The object.
        target: Guid,
    },
    /// `Lookup {sam | spn | dn}`.
    Lookup(LookupKey),
    /// `ChangePolicy {changes}` (task A16): a tier-map edit under mandatory
    /// dual control, written by dird as `policy.next`.
    ChangePolicy {
        /// The changes, in order.
        changes: Vec<PolicyChange>,
    },
    /// A proposed key operation — only as the operation of a `Propose` (or
    /// of a `RequestShown`); never a request of its own (the codec refuses
    /// to send it alone).
    /// Spec: docs/51 §6; docs/questions/Q-882.
    KeyOperation(KeyOperation),
    /// `Propose {reason_ref?, operation}`: open a pending request for one
    /// dual-controlled operation (`request_kind::PROPOSABLE`).
    /// Spec: docs/questions/Q-882 items 1, 4.
    Propose {
        /// The requester's change identifier (unverified; the PEP admits
        /// printable ASCII of 1 to 64 characters).
        reason_ref: Option<String>,
        /// The operation the request is for.
        operation: Box<Operation>,
    },
    /// `Approve {id, digest}`.
    /// Spec: docs/questions/Q-882 item 1.
    Approve {
        /// The pending request's id.
        id: u64,
        /// The operation digest the approver was shown.
        digest: [u8; DIGEST_LEN],
    },
    /// `Reject {id, digest}`.
    /// Spec: docs/research/r5-a-admin-model.md §11 MA5.
    Reject {
        /// The pending request's id.
        id: u64,
        /// The operation digest the rejecting approver was shown.
        digest: [u8; DIGEST_LEN],
    },
    /// `Withdraw {id}`.
    /// Spec: docs/questions/Q-882 item 1.
    Withdraw {
        /// The pending request's id.
        id: u64,
    },
    /// `ListRequests {scope}`.
    /// Spec: docs/questions/Q-882 item 1; r5-a §11 MA5.
    ListRequests(ListScope),
    /// `ShowRequest {id}`.
    /// Spec: docs/questions/Q-882 item 1; r5-a §11 MA5.
    ShowRequest {
        /// The pending request's id.
        id: u64,
    },
    /// `PlanOperation {operation}` (task MA2): ask for the effect plan of a
    /// planned operation (`request_kind::PLANNED`).
    /// Spec: docs/research/r5-a-admin-model.md §3.3; docs/questions/Q-980.
    PlanOperation(Box<Operation>),
    /// `Commit {plan, operation}` (task MA2): a planned operation with the
    /// digest of the plan it commits to.
    /// Spec: docs/research/r5-a-admin-model.md §3.3; docs/questions/Q-980.
    Commit {
        /// The plan digest (crate::plan `plan_digest`).
        plan: [u8; DIGEST_LEN],
        /// The planned operation.
        operation: Box<Operation>,
    },
}

/// The scope of a `ListRequests`.
/// Spec: docs/questions/Q-882 item 1 (`List {mine | awaiting_me}`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ListScope {
    /// The caller's own pending requests.
    Mine,
    /// The pending requests the caller may approve and has not approved.
    AwaitingMe,
}

impl Operation {
    /// The typed operation of `wire`. Spec: module documentation.
    ///
    /// # Errors
    /// [`ConversionError`].
    pub fn from_wire(wire: &WireOperation) -> Result<Operation, ConversionError> {
        Ok(match wire {
            WireOperation::CreateUser {
                parent,
                sam,
                upn,
                description,
            } => Operation::CreateUser {
                parent: guid(parent),
                sam: text(sam)?,
                upn: opt_text(upn.as_ref())?,
                description: opt_text(description.as_ref())?,
            },
            WireOperation::CreateComputer { parent, name, spn } => Operation::CreateComputer {
                parent: guid(parent),
                name: text(name)?,
                spn: opt_text(spn.as_ref())?,
            },
            WireOperation::CreateGroup {
                parent,
                sam,
                group_type,
            } => Operation::CreateGroup {
                parent: guid(parent),
                sam: text(sam)?,
                group_type: *group_type,
            },
            WireOperation::CreateOu { parent, name } => Operation::CreateOu {
                parent: guid(parent),
                name: text(name)?,
            },
            WireOperation::CreateContainer { parent, name } => Operation::CreateContainer {
                parent: guid(parent),
                name: text(name)?,
            },
            WireOperation::BeginPasswordSet { target } => Operation::BeginPasswordSet {
                target: guid(target),
            },
            WireOperation::CompletePasswordSet {
                target,
                outcome,
                kvnos,
            } => Operation::CompletePasswordSet {
                target: guid(target),
                outcome: if *outcome == codes::OUTCOME_COMPLETED {
                    PasswordSetOutcome::Completed
                } else {
                    PasswordSetOutcome::Failed
                },
                kvnos: kvnos.clone(),
            },
            WireOperation::SetEnabled { target, enabled } => Operation::SetEnabled {
                target: guid(target),
                enabled: *enabled,
            },
            WireOperation::SetAccountExpires { target, filetime } => Operation::SetAccountExpires {
                target: guid(target),
                value: match filetime {
                    None => AccountExpires::Never,
                    Some(ACCOUNT_EXPIRES_NEVER) => return Err(ConversionError::NonCanonical),
                    Some(at) => AccountExpires::At(*at),
                },
            },
            WireOperation::AddMember { group, member } => Operation::AddMember {
                group: guid(group),
                member: guid(member),
            },
            WireOperation::RemoveMember { group, member } => Operation::RemoveMember {
                group: guid(group),
                member: guid(member),
            },
            WireOperation::Delete { target } => Operation::Delete {
                target: guid(target),
            },
            WireOperation::Lookup(key) => Operation::Lookup(match key {
                WireLookupKey::SamAccountName(sam) => LookupKey::SamAccountName(text(sam)?),
                WireLookupKey::ServicePrincipalName(spn) => {
                    LookupKey::ServicePrincipalName(text(spn)?)
                }
                WireLookupKey::Dn(dn) => {
                    LookupKey::Dn(dn.iter().map(|c| text(c)).collect::<Result<_, _>>()?)
                }
            }),
            WireOperation::ChangePolicy { changes } => Operation::ChangePolicy {
                changes: changes
                    .iter()
                    .map(PolicyChange::from_wire)
                    .collect::<Result<_, _>>()?,
            },
            WireOperation::KeyOperation { operation } => {
                Operation::KeyOperation(KeyOperation::from_wire(operation))
            }
            WireOperation::Propose {
                reason_ref,
                operation,
            } => Operation::Propose {
                reason_ref: opt_text(reason_ref.as_ref())?,
                operation: Box::new(Operation::from_wire(operation)?),
            },
            WireOperation::Approve { id, digest } => Operation::Approve {
                id: *id,
                digest: *digest,
            },
            WireOperation::Reject { id, digest } => Operation::Reject {
                id: *id,
                digest: *digest,
            },
            WireOperation::Withdraw { id } => Operation::Withdraw { id: *id },
            WireOperation::ListRequests { scope } => {
                Operation::ListRequests(if *scope == codes::LIST_MINE {
                    ListScope::Mine
                } else {
                    ListScope::AwaitingMe
                })
            }
            WireOperation::ShowRequest { id } => Operation::ShowRequest { id: *id },
            WireOperation::PlanOperation { operation } => {
                Operation::PlanOperation(Box::new(Operation::from_wire(operation)?))
            }
            WireOperation::Commit { plan, operation } => Operation::Commit {
                plan: *plan,
                operation: Box::new(Operation::from_wire(operation)?),
            },
        })
    }

    /// The wire form. Spec: module documentation.
    ///
    /// # Errors
    /// [`ConversionError::NonCanonical`] for `At` of the "never" value.
    pub fn to_wire(&self) -> Result<WireOperation, ConversionError> {
        let bytes = |s: &String| s.as_bytes().to_vec();
        let opt = |s: &Option<String>| s.as_ref().map(bytes);
        Ok(match self {
            Operation::CreateUser {
                parent,
                sam,
                upn,
                description,
            } => WireOperation::CreateUser {
                parent: parent.to_packet(),
                sam: bytes(sam),
                upn: opt(upn),
                description: opt(description),
            },
            Operation::CreateComputer { parent, name, spn } => WireOperation::CreateComputer {
                parent: parent.to_packet(),
                name: bytes(name),
                spn: opt(spn),
            },
            Operation::CreateGroup {
                parent,
                sam,
                group_type,
            } => WireOperation::CreateGroup {
                parent: parent.to_packet(),
                sam: bytes(sam),
                group_type: *group_type,
            },
            Operation::CreateOu { parent, name } => WireOperation::CreateOu {
                parent: parent.to_packet(),
                name: bytes(name),
            },
            Operation::CreateContainer { parent, name } => WireOperation::CreateContainer {
                parent: parent.to_packet(),
                name: bytes(name),
            },
            Operation::BeginPasswordSet { target } => WireOperation::BeginPasswordSet {
                target: target.to_packet(),
            },
            Operation::CompletePasswordSet {
                target,
                outcome,
                kvnos,
            } => WireOperation::CompletePasswordSet {
                target: target.to_packet(),
                outcome: match outcome {
                    PasswordSetOutcome::Completed => codes::OUTCOME_COMPLETED,
                    PasswordSetOutcome::Failed => codes::OUTCOME_FAILED,
                },
                kvnos: kvnos.clone(),
            },
            Operation::SetEnabled { target, enabled } => WireOperation::SetEnabled {
                target: target.to_packet(),
                enabled: *enabled,
            },
            Operation::SetAccountExpires { target, value } => WireOperation::SetAccountExpires {
                target: target.to_packet(),
                filetime: match value {
                    AccountExpires::Never => None,
                    AccountExpires::At(ACCOUNT_EXPIRES_NEVER) => {
                        return Err(ConversionError::NonCanonical)
                    }
                    AccountExpires::At(at) => Some(*at),
                },
            },
            Operation::AddMember { group, member } => WireOperation::AddMember {
                group: group.to_packet(),
                member: member.to_packet(),
            },
            Operation::RemoveMember { group, member } => WireOperation::RemoveMember {
                group: group.to_packet(),
                member: member.to_packet(),
            },
            Operation::Delete { target } => WireOperation::Delete {
                target: target.to_packet(),
            },
            Operation::Lookup(key) => WireOperation::Lookup(match key {
                LookupKey::SamAccountName(sam) => WireLookupKey::SamAccountName(bytes(sam)),
                LookupKey::ServicePrincipalName(spn) => {
                    WireLookupKey::ServicePrincipalName(bytes(spn))
                }
                LookupKey::Dn(dn) => WireLookupKey::Dn(dn.iter().map(bytes).collect()),
            }),
            Operation::ChangePolicy { changes } => WireOperation::ChangePolicy {
                changes: changes.iter().map(PolicyChange::to_wire).collect(),
            },
            Operation::KeyOperation(operation) => WireOperation::KeyOperation {
                operation: operation.to_wire(),
            },
            Operation::Propose {
                reason_ref,
                operation,
            } => WireOperation::Propose {
                reason_ref: opt(reason_ref),
                operation: Box::new(operation.to_wire()?),
            },
            Operation::Approve { id, digest } => WireOperation::Approve {
                id: *id,
                digest: *digest,
            },
            Operation::Reject { id, digest } => WireOperation::Reject {
                id: *id,
                digest: *digest,
            },
            Operation::Withdraw { id } => WireOperation::Withdraw { id: *id },
            Operation::ListRequests(scope) => WireOperation::ListRequests {
                scope: match scope {
                    ListScope::Mine => codes::LIST_MINE,
                    ListScope::AwaitingMe => codes::LIST_AWAITING_ME,
                },
            },
            Operation::ShowRequest { id } => WireOperation::ShowRequest { id: *id },
            Operation::PlanOperation(operation) => WireOperation::PlanOperation {
                operation: Box::new(operation.to_wire()?),
            },
            Operation::Commit { plan, operation } => WireOperation::Commit {
                plan: *plan,
                operation: Box::new(operation.to_wire()?),
            },
        })
    }
}

/// One typed request. Spec: docs/51 §7.2, §7.3; docs/50 §7.5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// An operation and the tickets that authenticate and approve it.
    Operation {
        /// The requester's and approvers' raw AP-REQs.
        auth: Auth,
        /// The operation.
        operation: Operation,
    },
    /// The health check.
    Ping,
}

impl Request {
    /// The typed request of `wire`.
    ///
    /// # Errors
    /// [`ConversionError`].
    pub fn from_wire(wire: &AdminRequest) -> Result<Request, ConversionError> {
        match wire {
            AdminRequest::Ping => Ok(Request::Ping),
            AdminRequest::Operation { auth, operation } => Ok(Request::Operation {
                auth: auth.clone(),
                operation: Operation::from_wire(operation)?,
            }),
        }
    }

    /// The wire form.
    ///
    /// # Errors
    /// [`ConversionError::NonCanonical`] (see [`Operation::to_wire`]).
    pub fn to_wire(&self) -> Result<AdminRequest, ConversionError> {
        match self {
            Request::Ping => Ok(AdminRequest::Ping),
            Request::Operation { auth, operation } => Ok(AdminRequest::Operation {
                auth: auth.clone(),
                operation: operation.to_wire()?,
            }),
        }
    }
}

/// The account kind of a `BeginPasswordSet` reply. Mirrors directory-pip's
/// `AccountKind` by name (this crate links no directory code).
/// Spec: docs/51 §7.3 (`kind` (User/Computer)).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccountKind {
    /// A user account.
    User,
    /// A computer account.
    Computer,
}

/// One key set admind passes to keyd `set_secret`: its handle and binding.
/// Spec: docs/47 §9.1; docs/51 §7.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyTarget {
    /// `(objectGUID, PrincipalLongterm | Service)`.
    pub handle: KeyHandle,
    /// The realm and principal name the key set is bound to (A-19).
    pub binding: PrincipalBinding,
}

/// The `BeginPasswordSet` reply. Spec: docs/51 §5.2 row 5, §7.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordSet {
    /// User or computer.
    pub kind: AccountKind,
    /// The key targets, `PrincipalLongterm` first.
    pub keys: Vec<KeyTarget>,
    /// The salt ([MS-KILE] 3.1.1.2 via `account_salt`, R47-4).
    pub salt: KerberosString,
}

/// The `Lookup` reply. Spec: docs/51 §5.2 row 10 (identifiers only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    /// The objectGUID.
    pub guid: Guid,
    /// The DN, leaf first.
    pub dn: Vec<String>,
    /// The lDAPDisplayName of the most specific class.
    pub class: String,
    /// The objectSid, for a security principal (or the NC root).
    pub sid: Option<Sid>,
}

/// The state of a pending request. Task D2-c.
/// Spec: docs/questions/Q-882 items 1-2; crate::channel `codes::REQUEST_*`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RequestState {
    /// Awaiting approvals.
    Pending,
    /// The quorum is reached: a directory or policy operation may be
    /// executed by its requester (the operation itself, sent again — dird
    /// re-evaluates everything then); a key operation's decision is
    /// registered in keyd for keyadm (A-102).
    Approved,
}

impl RequestState {
    /// Code → state (the wire layer admits only the two codes).
    fn from_code(code: u8) -> RequestState {
        if code == codes::REQUEST_APPROVED {
            RequestState::Approved
        } else {
            RequestState::Pending
        }
    }

    /// State → code.
    fn code(self) -> u8 {
        match self {
            RequestState::Pending => codes::REQUEST_PENDING,
            RequestState::Approved => codes::REQUEST_APPROVED,
        }
    }
}

/// A pending request's state, as dird answers `Propose` and `Approve`.
/// Spec: docs/questions/Q-882 item 1 (`{id, digest, quorum, expires}`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingRequestState {
    /// The id (64 bits from dird's CSPRNG).
    pub id: u64,
    /// The operation digest of the request's operation — the fingerprint the
    /// requester saw, the approver compares and the audit trail carries
    /// (docs/questions/Q-888).
    pub digest: [u8; DIGEST_LEN],
    /// The state.
    pub state: RequestState,
    /// Approvals recorded so far (the requester not counted).
    pub approvals: u8,
    /// The quorum, the requester included (`admin_quorum`, P-22).
    pub quorum: u8,
    /// The expiry: seconds since 1970-01-01T00:00:00Z.
    pub expires: u64,
}

impl PendingRequestState {
    fn from_wire(wire: &WirePendingRequest) -> PendingRequestState {
        PendingRequestState {
            id: wire.id,
            digest: wire.digest,
            state: RequestState::from_code(wire.state),
            approvals: wire.approvals,
            quorum: wire.quorum,
            expires: wire.expires,
        }
    }

    fn to_wire(&self) -> WirePendingRequest {
        WirePendingRequest {
            id: self.id,
            digest: self.digest,
            state: self.state.code(),
            approvals: self.approvals,
            quorum: self.quorum,
            expires: self.expires,
        }
    }
}

/// One entry of a `ListRequests` answer.
/// Spec: docs/research/r5-a-admin-model.md §11 MA5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestSummary {
    /// The id.
    pub id: u64,
    /// The operation digest.
    pub digest: [u8; DIGEST_LEN],
    /// The state.
    pub state: RequestState,
    /// The kind of the operation (`request_kind::PROPOSABLE`).
    pub operation: u8,
    /// The requester's objectSid, as dird verified it.
    pub requester: Sid,
    /// Approvals recorded so far.
    pub approvals: u8,
    /// The quorum.
    pub quorum: u8,
    /// The expiry (seconds since 1970).
    pub expires: u64,
}

impl RequestSummary {
    fn from_wire(wire: &WireRequestSummary) -> Result<RequestSummary, ConversionError> {
        Ok(RequestSummary {
            id: wire.id,
            digest: wire.digest,
            state: RequestState::from_code(wire.state),
            operation: wire.operation,
            requester: sid(&wire.requester)?,
            approvals: wire.approvals,
            quorum: wire.quorum,
            expires: wire.expires,
        })
    }

    fn to_wire(&self) -> WireRequestSummary {
        WireRequestSummary {
            id: self.id,
            digest: self.digest,
            state: self.state.code(),
            operation: self.operation,
            requester: self.requester.encode(),
            approvals: self.approvals,
            quorum: self.quorum,
            expires: self.expires,
        }
    }
}

/// The explicit tier of a fact: what the tier map or a structural rule
/// makes it — or `Unclassified` (Tier0 for writes by A-36, yet needing no
/// approver: P-22).
/// Spec: docs/47 §6.3; A-36; P-22; docs/questions/Q-887 item 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FactTier {
    /// Explicitly Tier 0.
    Tier0,
    /// Tier 1.
    Tier1,
    /// Tier 2.
    Tier2,
    /// No explicit classification.
    Unclassified,
}

impl FactTier {
    fn from_code(code: u8) -> FactTier {
        match code {
            codes::TIER_0 => FactTier::Tier0,
            codes::TIER_1 => FactTier::Tier1,
            codes::TIER_2 => FactTier::Tier2,
            _ => FactTier::Unclassified,
        }
    }

    fn code(self) -> u8 {
        match self {
            FactTier::Tier0 => codes::TIER_0,
            FactTier::Tier1 => codes::TIER_1,
            FactTier::Tier2 => codes::TIER_2,
            FactTier::Unclassified => codes::FACT_UNCLASSIFIED,
        }
    }
}

/// One fact dird resolved for an object a pending operation names.
/// Spec: docs/questions/Q-882 item 1, Q-887 items 2-3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fact {
    /// The objectGUID.
    pub guid: Guid,
    /// The DN, leaf first.
    pub dn: Vec<String>,
    /// The most specific class's lDAPDisplayName.
    pub class: String,
    /// The objectSid, if any.
    pub sid: Option<Sid>,
    /// The explicit tier.
    pub tier: FactTier,
}

impl Fact {
    fn from_wire(wire: &WireFact) -> Result<Fact, ConversionError> {
        Ok(Fact {
            guid: guid(&wire.guid),
            dn: wire.dn.iter().map(|c| text(c)).collect::<Result<_, _>>()?,
            class: text(&wire.class)?,
            sid: wire.sid.as_deref().map(sid).transpose()?,
            tier: FactTier::from_code(wire.tier),
        })
    }

    fn to_wire(&self) -> WireFact {
        WireFact {
            guid: self.guid.to_packet(),
            dn: self.dn.iter().map(|c| c.as_bytes().to_vec()).collect(),
            class: self.class.as_bytes().to_vec(),
            sid: self.sid.as_ref().map(Sid::encode),
            tier: self.tier.code(),
        }
    }
}

/// A pending request as dird holds it — the answer to `ShowRequest`: the
/// operation from dird's own copy (never requester text), the requester and
/// approvers dird verified, and the facts dird resolved.
/// Spec: docs/questions/Q-882 item 1, Q-887 item 3; docs/research/
/// r5-b-cli.md §7.4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestShown {
    /// The id.
    pub id: u64,
    /// The operation digest.
    pub digest: [u8; DIGEST_LEN],
    /// The state.
    pub state: RequestState,
    /// The requester's objectSid.
    pub requester: Sid,
    /// The approvers' objectSids, in approval order.
    pub approvers: Vec<Sid>,
    /// The quorum.
    pub quorum: u8,
    /// The expiry (seconds since 1970).
    pub expires: u64,
    /// The requester's change identifier (unverified).
    pub reason_ref: Option<String>,
    /// The operation.
    pub operation: Operation,
    /// The facts.
    pub facts: Vec<Fact>,
    /// The effect plan dird holds, for a `Commit` (task MA2): decoded from
    /// dird's canonical bytes, and checked against the `Commit`'s plan
    /// digest when converted (a client renders exactly what is bound).
    pub plan: Option<EffectPlan>,
}

/// The plan of a shown request must be the one its operation names: `Some`
/// exactly for a `Commit`, whose `plan` is that plan's digest.
/// Spec: docs/questions/Q-874 item 1, Q-980 (the plan rendered from the
/// server's bytes is the plan whose digest is signed).
fn plan_matches(operation: &Operation, plan: Option<&[u8]>) -> Result<(), ConversionError> {
    match (operation, plan) {
        (Operation::Commit { plan: digest, .. }, Some(octets))
            if plan_digest(octets) == *digest =>
        {
            Ok(())
        }
        (Operation::Commit { .. }, _) | (_, Some(_)) => Err(ConversionError::Plan),
        (_, None) => Ok(()),
    }
}

impl RequestShown {
    fn from_wire(wire: &WireRequestShown) -> Result<RequestShown, ConversionError> {
        let operation = Operation::from_wire(&wire.operation)?;
        plan_matches(&operation, wire.plan.as_deref())?;
        let plan = wire
            .plan
            .as_deref()
            .map(EffectPlan::decode)
            .transpose()
            .map_err(|_| ConversionError::Plan)?;
        Ok(RequestShown {
            id: wire.id,
            digest: wire.digest,
            state: RequestState::from_code(wire.state),
            requester: sid(&wire.requester)?,
            approvers: wire
                .approvers
                .iter()
                .map(|a| sid(a))
                .collect::<Result<_, _>>()?,
            quorum: wire.quorum,
            expires: wire.expires,
            reason_ref: opt_text(wire.reason_ref.as_ref())?,
            operation,
            facts: wire
                .facts
                .iter()
                .map(Fact::from_wire)
                .collect::<Result<_, _>>()?,
            plan,
        })
    }

    fn to_wire(&self) -> Result<WireRequestShown, ConversionError> {
        Ok(WireRequestShown {
            id: self.id,
            digest: self.digest,
            state: self.state.code(),
            requester: self.requester.encode(),
            approvers: self.approvers.iter().map(Sid::encode).collect(),
            quorum: self.quorum,
            expires: self.expires,
            reason_ref: self.reason_ref.as_ref().map(|r| r.as_bytes().to_vec()),
            operation: self.operation.to_wire()?,
            facts: self.facts.iter().map(Fact::to_wire).collect(),
            plan: {
                let octets = self
                    .plan
                    .as_ref()
                    .map(EffectPlan::encode)
                    .transpose()
                    .map_err(|_| ConversionError::Plan)?;
                plan_matches(&self.operation, octets.as_deref())?;
                octets
            },
        })
    }
}

/// One typed reply. Spec: docs/51 §7.3; docs/50 §7.5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    /// A create.
    Created {
        /// The objectGUID.
        guid: Guid,
        /// The objectSid (user, computer, group).
        sid: Option<Sid>,
    },
    /// `BeginPasswordSet`.
    PasswordSet(PasswordSet),
    /// `()`.
    Done,
    /// `Lookup` of a visible object.
    Found(Found),
    /// Refused or failed (the reason is in the audit trail).
    Refused(RefusalStatus),
    /// `Ping` answered.
    Pong,
    /// `ChangePolicy` written as `policy.next` (task A16): the version root's
    /// activation installs (`provision policy --activate-next`).
    PolicyNext {
        /// The `policy_version` of `policy.next`.
        version: u64,
    },
    /// `Propose` / `Approve`: the pending request's state. For a key
    /// operation the request's id is also the id of the decision dird
    /// registers in keyd when an `Approve` completes the quorum (A-102,
    /// docs/52 §4.3) — what the operator gives keyadm.
    PendingRequest(PendingRequestState),
    /// `ListRequests`: the requests in the scope.
    RequestList(Vec<RequestSummary>),
    /// `ShowRequest`: the request as dird holds it.
    RequestShown(Box<RequestShown>),
    /// `PlanOperation`: the effect plan (task MA2) — decoded from its
    /// canonical bytes, whose digest is `digest` (checked when converted).
    Plan {
        /// The plan.
        plan: EffectPlan,
        /// Its digest: the value a `Commit` names.
        digest: [u8; DIGEST_LEN],
    },
}

impl Reply {
    /// The typed reply of `wire`.
    ///
    /// # Errors
    /// [`ConversionError`].
    pub fn from_wire(wire: &AdminReply) -> Result<Reply, ConversionError> {
        Ok(match wire {
            AdminReply::Created { guid: g, sid: s } => Reply::Created {
                guid: guid(g),
                sid: s.as_deref().map(sid).transpose()?,
            },
            AdminReply::PasswordSet { kind, keys, salt } => Reply::PasswordSet(PasswordSet {
                kind: if *kind == codes::KIND_USER {
                    AccountKind::User
                } else {
                    AccountKind::Computer
                },
                keys: keys.iter().map(key_target).collect::<Result<Vec<_>, _>>()?,
                salt: KerberosString::from_bytes(salt)
                    .map_err(|_| ConversionError::KerberosString)?,
            }),
            AdminReply::Done => Reply::Done,
            AdminReply::Found {
                guid: g,
                dn,
                class,
                sid: s,
            } => Reply::Found(Found {
                guid: guid(g),
                dn: dn.iter().map(|c| text(c)).collect::<Result<_, _>>()?,
                class: text(class)?,
                sid: s.as_deref().map(sid).transpose()?,
            }),
            AdminReply::Refused(status) => Reply::Refused(*status),
            AdminReply::Pong => Reply::Pong,
            AdminReply::PolicyNext { version } => Reply::PolicyNext { version: *version },
            AdminReply::PendingRequest(request) => {
                Reply::PendingRequest(PendingRequestState::from_wire(request))
            }
            AdminReply::RequestList { entries } => Reply::RequestList(
                entries
                    .iter()
                    .map(RequestSummary::from_wire)
                    .collect::<Result<_, _>>()?,
            ),
            AdminReply::RequestShown(shown) => {
                Reply::RequestShown(Box::new(RequestShown::from_wire(shown)?))
            }
            AdminReply::Plan { plan, digest } => {
                if plan_digest(plan) != *digest {
                    return Err(ConversionError::Plan);
                }
                Reply::Plan {
                    plan: EffectPlan::decode(plan).map_err(|_| ConversionError::Plan)?,
                    digest: *digest,
                }
            }
        })
    }

    /// The wire form.
    ///
    /// # Errors
    /// [`ConversionError::PrincipalName`] if a binding name cannot be
    /// encoded; [`ConversionError::NonCanonical`] for a `Krbtgt` key target.
    pub fn to_wire(&self) -> Result<AdminReply, ConversionError> {
        Ok(match self {
            Reply::Created { guid, sid } => AdminReply::Created {
                guid: guid.to_packet(),
                sid: sid.as_ref().map(Sid::encode),
            },
            Reply::PasswordSet(set) => AdminReply::PasswordSet {
                kind: match set.kind {
                    AccountKind::User => codes::KIND_USER,
                    AccountKind::Computer => codes::KIND_COMPUTER,
                },
                keys: set
                    .keys
                    .iter()
                    .map(wire_key_target)
                    .collect::<Result<Vec<_>, _>>()?,
                salt: set.salt.as_bytes().to_vec(),
            },
            Reply::Done => AdminReply::Done,
            Reply::Found(found) => AdminReply::Found {
                guid: found.guid.to_packet(),
                dn: found.dn.iter().map(|c| c.as_bytes().to_vec()).collect(),
                class: found.class.as_bytes().to_vec(),
                sid: found.sid.as_ref().map(Sid::encode),
            },
            Reply::Refused(status) => AdminReply::Refused(*status),
            Reply::Pong => AdminReply::Pong,
            Reply::PolicyNext { version } => AdminReply::PolicyNext { version: *version },
            Reply::PendingRequest(request) => AdminReply::PendingRequest(request.to_wire()),
            Reply::RequestList(entries) => AdminReply::RequestList {
                entries: entries.iter().map(RequestSummary::to_wire).collect(),
            },
            Reply::RequestShown(shown) => AdminReply::RequestShown(Box::new(shown.to_wire()?)),
            Reply::Plan { plan, digest } => {
                let octets = plan.encode().map_err(|_| ConversionError::Plan)?;
                if plan_digest(&octets) != *digest {
                    return Err(ConversionError::Plan);
                }
                AdminReply::Plan {
                    plan: octets,
                    digest: *digest,
                }
            }
        })
    }
}

/// A key target from the wire. Spec: docs/50 §3.3; RFC 4120 5.2.1, 5.2.2.
fn key_target(wire: &WireKeyTarget) -> Result<KeyTarget, ConversionError> {
    let realm =
        KerberosString::from_bytes(&wire.realm).map_err(|_| ConversionError::KerberosString)?;
    let name =
        PrincipalName::decode(wire.name.as_der()).map_err(|_| ConversionError::PrincipalName)?;
    Ok(KeyTarget {
        handle: KeyHandle::new(PrincipalId::from_bytes(wire.principal), wire.purpose),
        binding: PrincipalBinding::new(realm, name),
    })
}

/// A key target on the wire. Spec: docs/50 §3.3.
fn wire_key_target(target: &KeyTarget) -> Result<WireKeyTarget, ConversionError> {
    if matches!(
        target.handle.purpose,
        keyd_types::KeyPurpose::Krbtgt
            | keyd_types::KeyPurpose::AdminService
            | keyd_types::KeyPurpose::ChangePasswordService
    ) {
        return Err(ConversionError::NonCanonical);
    }
    let name = target
        .binding
        .name
        .encode()
        .map_err(|_| ConversionError::PrincipalName)?;
    Ok(WireKeyTarget {
        principal: *target.handle.principal.as_bytes(),
        purpose: target.handle.purpose,
        realm: target.binding.realm.as_bytes().to_vec(),
        name: DerBlob::new(name),
    })
}
