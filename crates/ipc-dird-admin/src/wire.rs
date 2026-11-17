//! The wire layer: every message of the admin channel as fixed-order fields
//! over `ipc` (lengths, markers, closed enumeration tables, no trailing
//! octet). Text, SIDs and Kerberos values stay opaque octets here; the typed
//! layer ([`crate::typed`]) passes each through its strict decoder (UTF-8,
//! dtyp, krb-proto).
//!
//! | field | encoding |
//! |---|---|
//! | `auth` | `requester: bytes<64 KiB>` (a raw AP-REQ) ‖ `approvals: seq<_, 0>` (retired by Q-882: always empty) |
//! | object | 16-octet objectGUID packet ([MS-DTYP] 2.3.4.2) |
//! | name, UPN, SPN, description | `bytes<max>` (UTF-8 in the typed layer) — no request carries a dNSHostName since task PN6b (dird derives it) |
//! | DN | `seq<bytes<128>, 64>` of `att=value` components, leaf first |
//! | SID | `bytes<68>` holding the [MS-DTYP] 2.4.2.2 packet |
//! | `KeyHandle` | 16-octet `PrincipalId` ‖ purpose `u8` (closed table) |
//! | binding | realm `bytes<255>` ‖ name `bytes<4096>` holding the `PrincipalName` DER |
//! | outcome, expiry, lookup key, account kind, status | `u8` from a closed table |
//! | `KeyOperation` | `u8 1 RotateKrbtgt` / `u8 2 RotateKey ‖ service:[16]` / `u8 3 RetireKvno ‖ KeyRef ‖ kvno:u32` |
//! | `KeyRef` | `u8 1 Krbtgt` / `u8 2 Service ‖ principal:[16]` |
//! | `PolicyChange` | `u8 1 AddPrincipal ‖ sid ‖ tier:u8` / `u8 2 RemovePrincipal ‖ sid` / `u8 3 AddSubtree ‖ dn:seq<bytes<128>,16> ‖ tier` / `u8 4 RemoveSubtree ‖ dn` (task A16) |
//! | digest | 32 octets (a SHA-256 output: an operation digest, crate::digest) |
//! | proposed operation | `kind:u8` from `request_kind::PROPOSABLE` ‖ that kind's fields (a planned operation: `COMMIT` ‖ its fields) |
//! | planned operation | `kind:u8` from `request_kind::PLANNED` ‖ that kind's fields (a key operation: `KEY_OPERATION` ‖ `KeyOperation`) — inside `PlanOperation` / `Commit` only (task MA2) |
//! | effect plan | `bytes<24 KiB>` holding the plan's canonical encoding (crate::plan) |
//! | request state, list scope, fact tier | `u8` from a closed table (`codes::REQUEST_*`, `codes::LIST_*`, `codes::TIER_*` / `FACT_UNCLASSIFIED`) |
//! | time of a request's expiry | `u64` seconds since 1970-01-01T00:00:00Z (the PDP's `Instant`, docs/11 P9) |
//!
//! Every request but `Ping` carries `auth`. keyadm's former requests
//! (`FetchApproved`, `Complete`, `ListPendingDestruction` — the only ones
//! without `auth`) were retired by A-102 (docs/52 §4.6; docs/questions/
//! Q-460): keyadm talks to keyd only.
//!
//! Spec: docs/51 §7.1 (the `crates/ipc` codec), §7.2 (`auth`), §7.3 (the
//! fields of each operation and reply), §5.6, §6 (the key operations);
//! docs/50 §3.3 (primitives; "Kerberos values … as `bytes<max>` containing
//! DER"; "`KeyHandle` = 16 octets `PrincipalId` + `u8` purpose").

use crate::channel::{
    codes, reply_kind, request_kind, RefusalStatus, DIGEST_LEN, MAX_AP_REQ, MAX_BINDING_NAME,
    MAX_CLASS_NAME, MAX_DESCRIPTION, MAX_DN_COMPONENT, MAX_DN_COMPONENTS, MAX_FACTS,
    MAX_KEY_TARGETS, MAX_KVNOS, MAX_LISTED_REQUESTS, MAX_NAME, MAX_PLAN, MAX_POLICY_CHANGES,
    MAX_POLICY_DN_COMPONENTS, MAX_PRINCIPAL_NAME, MAX_REALM, MAX_REASON_REF, MAX_SALT,
    MAX_SHOWN_APPROVERS, MAX_SID, RETIRED_APPROVALS,
};
use ipc::{DerBlob, Error, MessageSet, Payload, Reader, Result, Writer};
use keyd_types::KeyPurpose;

/// A 16-octet objectGUID packet.
pub type GuidPacket = [u8; 16];

/// The plan bound as a field bound (24 KiB fits a `u32`).
const MAX_PLAN_U32: u32 = MAX_PLAN as u32;

/// An owned byte string of at most `max` octets.
fn read_owned(reader: &mut Reader<'_>, max: u32) -> Result<Vec<u8>> {
    reader.read_bytes(max).map(<[u8]>::to_vec)
}

/// An optional byte string of at most `max` octets.
fn read_opt_owned(reader: &mut Reader<'_>, max: u32) -> Result<Option<Vec<u8>>> {
    reader.read_option(|r| read_owned(r, max))
}

/// Spec: docs/50 §3.3 (`Option<T>`, `bytes<max>`).
fn write_opt_bytes(writer: &mut Writer, value: Option<&Vec<u8>>, max: u32) -> Result<()> {
    writer.write_option(value, |w, v| w.write_bytes(v, max))
}

/// A DN as components. Spec: docs/51 §7.3 (`dn`); docs/questions/Q-358
/// item 5.
fn read_dn(reader: &mut Reader<'_>) -> Result<Vec<Vec<u8>>> {
    reader.read_seq(MAX_DN_COMPONENTS, |r| read_owned(r, MAX_DN_COMPONENT))
}

/// Spec: docs/51 §7.3; docs/questions/Q-358 item 5.
fn write_dn(writer: &mut Writer, dn: &[Vec<u8>]) -> Result<()> {
    writer.write_seq(dn, MAX_DN_COMPONENTS, |w, c| {
        w.write_bytes(c, MAX_DN_COMPONENT)
    })
}

// ===========================================================================
// Requests.
// ===========================================================================

/// The authentication field of every operation: the requester's raw AP-REQ.
/// There is **no** field in which admind could claim a name, a SID, a tier
/// or "approved" — dird learns who asks only from keyd's verification of
/// this ticket.
///
/// **No approvals.** The in-request approvals of docs/51 §7.2 (`approvals:
/// seq<bytes<64 KiB>, 2>`) are retired (docs/questions/Q-882 item 6, A-148):
/// the type has no field for them, and the wire keeps only the sequence's
/// count — always written 0, and read with the bound
/// [`RETIRED_APPROVALS`] (0), so a request that still carries one is refused
/// by the codec (`ipc::Error::CountOverBound`) before anything is decoded
/// further. Every approval is an `Approve {id, digest}` of a pending request
/// dird holds.
/// Spec: docs/51 §7.2; A-70 (precedent: the front cannot claim an identity);
/// A-73; docs/questions/Q-882, Q-935.
#[derive(Clone, PartialEq, Eq)]
pub struct WireAuth {
    /// The requester's `KRB_AP_REQ` DER, as admind received it.
    pub requester: Vec<u8>,
}

impl WireAuth {
    /// The `auth` of a request: `requester`'s AP-REQ.
    #[must_use]
    pub fn of(requester: Vec<u8>) -> WireAuth {
        WireAuth { requester }
    }
}

impl core::fmt::Debug for WireAuth {
    /// Lengths only: AP-REQ octets are never printed (docs/50 §8.2).
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WireAuth")
            .field("requester_len", &self.requester.len())
            .finish()
    }
}

impl Payload for WireAuth {
    /// The requester, then the retired approvals' count (0).
    /// Spec: docs/51 §7.2; docs/questions/Q-882 item 6.
    fn write_fields(&self, writer: &mut Writer) -> Result<()> {
        writer.write_bytes(&self.requester, MAX_AP_REQ)?;
        writer.write_seq::<Vec<u8>>(&[], RETIRED_APPROVALS, |w, a| w.write_bytes(a, MAX_AP_REQ))
    }

    /// Spec: docs/51 §7.2; docs/questions/Q-882 item 6 (a non-empty
    /// sequence is over its bound of 0 and refused here).
    fn read_fields(reader: &mut Reader<'_>) -> Result<WireAuth> {
        let requester = read_owned(reader, MAX_AP_REQ)?;
        let retired = reader.read_seq(RETIRED_APPROVALS, |r| read_owned(r, MAX_AP_REQ))?;
        if !retired.is_empty() {
            // Cannot happen: the bound is 0.
            return Err(Error::CountOverBound);
        }
        Ok(WireAuth { requester })
    }
}

/// The key of a `Lookup`. Spec: docs/51 §5.2 row 10 (`sam | spn | dn`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireLookupKey {
    /// A sAMAccountName.
    SamAccountName(Vec<u8>),
    /// A servicePrincipalName.
    ServicePrincipalName(Vec<u8>),
    /// A DN as components, leaf first.
    Dn(Vec<Vec<u8>>),
}

/// Which key set a `retire_kvno` names.
/// Spec: docs/51 §6 (`retire-kvno`: after a rotation); docs/10 §7.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireKeyRef {
    /// The krbtgt key set (dird names it).
    Krbtgt,
    /// A service object's `Service` key set (its objectGUID packet).
    Service(GuidPacket),
}

impl WireKeyRef {
    /// Spec: crate::channel `codes::KEY_REF_*`.
    fn write(&self, writer: &mut Writer) -> Result<()> {
        match self {
            WireKeyRef::Krbtgt => writer.write_enum(codes::KEY_REF_KRBTGT),
            WireKeyRef::Service(principal) => {
                writer.write_enum(codes::KEY_REF_SERVICE)?;
                writer.write_array(principal)
            }
        }
    }

    /// Spec: crate::channel `codes::KEY_REF_*`.
    fn read(reader: &mut Reader<'_>) -> Result<WireKeyRef> {
        match reader.read_enum(|c| {
            matches!(c, codes::KEY_REF_KRBTGT | codes::KEY_REF_SERVICE).then_some(c)
        })? {
            codes::KEY_REF_SERVICE => Ok(WireKeyRef::Service(reader.read_array()?)),
            _ => Ok(WireKeyRef::Krbtgt),
        }
    }
}

/// The key operation of a pending request: exactly the three Admin
/// operations that need dual control (docs/51 §6 table — `rotate-key`,
/// `rotate-krbtgt`, `retire-kvno`).
/// Spec: docs/51 §5.2 row 11, §5.6, §6; docs/10 §7.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireKeyOperation {
    /// `rotate_krbtgt` (the krbtgt key set; dird names it).
    RotateKrbtgt,
    /// `rotate_key` of a service object's `Service` key set.
    RotateKey {
        /// The service object's objectGUID packet.
        service: GuidPacket,
    },
    /// `retire_kvno`.
    RetireKvno {
        /// The key set.
        key: WireKeyRef,
        /// The key version to retire.
        kvno: u32,
    },
}

impl WireKeyOperation {
    /// Spec: crate::channel `codes::KEY_OP_*`.
    fn write(&self, writer: &mut Writer) -> Result<()> {
        match self {
            WireKeyOperation::RotateKrbtgt => writer.write_enum(codes::KEY_OP_ROTATE_KRBTGT),
            WireKeyOperation::RotateKey { service } => {
                writer.write_enum(codes::KEY_OP_ROTATE_KEY)?;
                writer.write_array(service)
            }
            WireKeyOperation::RetireKvno { key, kvno } => {
                writer.write_enum(codes::KEY_OP_RETIRE_KVNO)?;
                key.write(writer)?;
                writer.write_u32(*kvno)
            }
        }
    }

    /// Spec: crate::channel `codes::KEY_OP_*`.
    fn read(reader: &mut Reader<'_>) -> Result<WireKeyOperation> {
        let tag = reader.read_enum(|c| {
            matches!(
                c,
                codes::KEY_OP_ROTATE_KRBTGT | codes::KEY_OP_ROTATE_KEY | codes::KEY_OP_RETIRE_KVNO
            )
            .then_some(c)
        })?;
        Ok(match tag {
            codes::KEY_OP_ROTATE_KEY => WireKeyOperation::RotateKey {
                service: reader.read_array()?,
            },
            codes::KEY_OP_RETIRE_KVNO => WireKeyOperation::RetireKvno {
                key: WireKeyRef::read(reader)?,
                kvno: reader.read_u32()?,
            },
            _ => WireKeyOperation::RotateKrbtgt,
        })
    }
}

/// A tier-map subtree DN of a `ChangePolicy` (task A16): at most
/// [`MAX_POLICY_DN_COMPONENTS`] components of at most [`MAX_DN_COMPONENT`]
/// octets, leaf first.
/// Spec: docs/51 §5.10; crate::channel `MAX_POLICY_DN_COMPONENTS`.
fn read_policy_dn(reader: &mut Reader<'_>) -> Result<Vec<Vec<u8>>> {
    reader.read_seq(MAX_POLICY_DN_COMPONENTS, |r| {
        read_owned(r, MAX_DN_COMPONENT)
    })
}

/// Spec: docs/51 §5.10.
fn write_policy_dn(writer: &mut Writer, dn: &[Vec<u8>]) -> Result<()> {
    writer.write_seq(dn, MAX_POLICY_DN_COMPONENTS, |w, c| {
        w.write_bytes(c, MAX_DN_COMPONENT)
    })
}

/// A tier-map row's tier code (closed table: `Untiered` has none).
/// Spec: crate::channel `codes::TIER_*`.
fn read_tier(reader: &mut Reader<'_>) -> Result<u8> {
    reader.read_enum(|c| matches!(c, codes::TIER_0 | codes::TIER_1 | codes::TIER_2).then_some(c))
}

/// One tier-map change of a `ChangePolicy` (task A16): the vocabulary of the
/// tier-map edit (crate policy-store `TierChange`; `provision policy`).
///
/// `PolicyChange := u8 1 AddPrincipal ‖ sid:bytes<68> ‖ tier:u8 | u8 2
/// RemovePrincipal ‖ sid | u8 3 AddSubtree ‖ dn:seq<bytes<128>, 16> ‖ tier |
/// u8 4 RemoveSubtree ‖ dn`, `tier := 0 Tier0 | 1 Tier1 | 2 Tier2`.
/// Spec: docs/51 §5.10 ("add / remove rows of the map"); docs/questions/
/// Q-592.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WirePolicyChange {
    /// Add `SID → tier`.
    AddPrincipal {
        /// The SID packet ([MS-DTYP] 2.4.2.2).
        sid: Vec<u8>,
        /// The tier code.
        tier: u8,
    },
    /// Remove the row of a SID.
    RemovePrincipal {
        /// The SID packet.
        sid: Vec<u8>,
    },
    /// Add `subtree → tier`.
    AddSubtree {
        /// The subtree's DN components, leaf first.
        dn: Vec<Vec<u8>>,
        /// The tier code.
        tier: u8,
    },
    /// Remove the row of a subtree.
    RemoveSubtree {
        /// The subtree's DN components, leaf first.
        dn: Vec<Vec<u8>>,
    },
}

impl WirePolicyChange {
    /// Spec: crate::channel `codes::POLICY_*`.
    fn write(&self, writer: &mut Writer) -> Result<()> {
        match self {
            WirePolicyChange::AddPrincipal { sid, tier } => {
                writer.write_enum(codes::POLICY_ADD_PRINCIPAL)?;
                writer.write_bytes(sid, MAX_SID)?;
                writer.write_enum(*tier)
            }
            WirePolicyChange::RemovePrincipal { sid } => {
                writer.write_enum(codes::POLICY_REMOVE_PRINCIPAL)?;
                writer.write_bytes(sid, MAX_SID)
            }
            WirePolicyChange::AddSubtree { dn, tier } => {
                writer.write_enum(codes::POLICY_ADD_SUBTREE)?;
                write_policy_dn(writer, dn)?;
                writer.write_enum(*tier)
            }
            WirePolicyChange::RemoveSubtree { dn } => {
                writer.write_enum(codes::POLICY_REMOVE_SUBTREE)?;
                write_policy_dn(writer, dn)
            }
        }
    }

    /// Spec: crate::channel `codes::POLICY_*`, `codes::TIER_*`.
    fn read(reader: &mut Reader<'_>) -> Result<WirePolicyChange> {
        let tag = reader.read_enum(|c| {
            matches!(
                c,
                codes::POLICY_ADD_PRINCIPAL
                    | codes::POLICY_REMOVE_PRINCIPAL
                    | codes::POLICY_ADD_SUBTREE
                    | codes::POLICY_REMOVE_SUBTREE
            )
            .then_some(c)
        })?;
        Ok(match tag {
            codes::POLICY_ADD_PRINCIPAL => WirePolicyChange::AddPrincipal {
                sid: read_owned(reader, MAX_SID)?,
                tier: read_tier(reader)?,
            },
            codes::POLICY_REMOVE_PRINCIPAL => WirePolicyChange::RemovePrincipal {
                sid: read_owned(reader, MAX_SID)?,
            },
            codes::POLICY_ADD_SUBTREE => WirePolicyChange::AddSubtree {
                dn: read_policy_dn(reader)?,
                tier: read_tier(reader)?,
            },
            _ => WirePolicyChange::RemoveSubtree {
                dn: read_policy_dn(reader)?,
            },
        })
    }
}

/// The fields of one operation after `auth`.
/// Spec: docs/51 §7.3 (the request column).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireOperation {
    /// `CreateUser {parent, sam, upn?, description?}`.
    CreateUser {
        /// The container.
        parent: GuidPacket,
        /// The sAMAccountName.
        sam: Vec<u8>,
        /// The userPrincipalName.
        upn: Option<Vec<u8>>,
        /// The description.
        description: Option<Vec<u8>>,
    },
    /// `CreateComputer {parent, name, spn?}` — no dNSHostName: dird derives
    /// it from the name (task PN6b; docs/questions/Q-1036 item 1, A-182).
    CreateComputer {
        /// The container.
        parent: GuidPacket,
        /// The computer name (without "$").
        name: Vec<u8>,
        /// The single SPN.
        spn: Option<Vec<u8>>,
    },
    /// `CreateGroup {parent, sam, group_type?}` (absent: the default).
    CreateGroup {
        /// The container.
        parent: GuidPacket,
        /// The sAMAccountName.
        sam: Vec<u8>,
        /// The groupType bit pattern.
        group_type: Option<u32>,
    },
    /// `CreateOu {parent, name}`.
    CreateOu {
        /// The parent.
        parent: GuidPacket,
        /// The RDN value.
        name: Vec<u8>,
    },
    /// `CreateContainer {parent, name}`.
    CreateContainer {
        /// The parent.
        parent: GuidPacket,
        /// The RDN value.
        name: Vec<u8>,
    },
    /// `BeginPasswordSet {target}`.
    BeginPasswordSet {
        /// The account.
        target: GuidPacket,
    },
    /// `CompletePasswordSet {target, outcome, kvnos}`.
    CompletePasswordSet {
        /// The account.
        target: GuidPacket,
        /// [`codes::OUTCOME_COMPLETED`] or [`codes::OUTCOME_FAILED`].
        outcome: u8,
        /// The key versions keyd chose.
        kvnos: Vec<u32>,
    },
    /// `SetEnabled {target, value}`.
    SetEnabled {
        /// The account.
        target: GuidPacket,
        /// Enable (`true`) or disable.
        enabled: bool,
    },
    /// `SetAccountExpires {target, never | filetime}`.
    SetAccountExpires {
        /// The account.
        target: GuidPacket,
        /// `None` = never; `Some(filetime)`.
        filetime: Option<u64>,
    },
    /// `AddMember {group, member}`.
    AddMember {
        /// The group.
        group: GuidPacket,
        /// The member.
        member: GuidPacket,
    },
    /// `RemoveMember {group, member}`.
    RemoveMember {
        /// The group.
        group: GuidPacket,
        /// The member.
        member: GuidPacket,
    },
    /// `Delete {target}`.
    Delete {
        /// The object.
        target: GuidPacket,
    },
    /// `Lookup {sam | spn | dn}`.
    Lookup(WireLookupKey),
    /// `ChangePolicy {changes}` (task A16): the tier-map edit, 1 to
    /// [`MAX_POLICY_CHANGES`] changes (the count's lower bound is the
    /// edit's own rule, applied in dird).
    ChangePolicy {
        /// The changes, in order.
        changes: Vec<WirePolicyChange>,
    },
    /// A proposed key operation (kind `KEY_OPERATION`): valid only as the
    /// operation of a [`WireOperation::Propose`] (and in a
    /// `RequestShown`); never a request of its own.
    /// Spec: docs/51 §6; docs/questions/Q-882.
    KeyOperation {
        /// The key operation.
        operation: WireKeyOperation,
    },
    /// `Propose {reason_ref?, operation}` (task D2-c): open a pending
    /// request for `operation`, one of `request_kind::PROPOSABLE`.
    /// Spec: docs/questions/Q-882 items 1, 4.
    Propose {
        /// The requester's change identifier, at most [`MAX_REASON_REF`]
        /// octets (printable ASCII — the PEP checks it); shown to approvers
        /// as unverified.
        reason_ref: Option<Vec<u8>>,
        /// The operation the request is for (never a `Propose`).
        operation: Box<WireOperation>,
    },
    /// `Approve {id, digest}`: approve the pending request `id`, whose
    /// operation digest the approver was shown.
    /// Spec: docs/questions/Q-882 item 1.
    Approve {
        /// The pending request's id.
        id: u64,
        /// The operation digest the approver was shown.
        digest: [u8; DIGEST_LEN],
    },
    /// `Reject {id, digest}`: end the pending request `id` (an eligible
    /// approver).
    /// Spec: docs/research/r5-a-admin-model.md §11 MA5.
    Reject {
        /// The pending request's id.
        id: u64,
        /// The operation digest the rejecting approver was shown.
        digest: [u8; DIGEST_LEN],
    },
    /// `Withdraw {id}`: end the pending request `id` (its requester).
    /// Spec: docs/questions/Q-882 item 1.
    Withdraw {
        /// The pending request's id.
        id: u64,
    },
    /// `ListRequests {scope}`: [`codes::LIST_MINE`] or
    /// [`codes::LIST_AWAITING_ME`].
    /// Spec: docs/questions/Q-882 item 1; r5-a §11 MA5.
    ListRequests {
        /// The scope code.
        scope: u8,
    },
    /// `ShowRequest {id}`.
    /// Spec: docs/questions/Q-882 item 1; r5-a §11 MA5.
    ShowRequest {
        /// The pending request's id.
        id: u64,
    },
    /// `PlanOperation {operation}` (task MA2): the effect plan of one of
    /// `request_kind::PLANNED`.
    /// Spec: docs/research/r5-a-admin-model.md §3.3; docs/questions/Q-980.
    PlanOperation {
        /// The planned operation.
        operation: Box<WireOperation>,
    },
    /// `Commit {plan, operation}` (task MA2): one of `request_kind::PLANNED`
    /// with the digest of the plan it commits to (crate::plan).
    /// Spec: docs/research/r5-a-admin-model.md §3.3; docs/questions/Q-980.
    Commit {
        /// The plan digest.
        plan: [u8; DIGEST_LEN],
        /// The planned operation.
        operation: Box<WireOperation>,
    },
}

impl WireOperation {
    /// The request kind. Spec: crate::channel `request_kind`.
    #[must_use]
    pub fn kind(&self) -> u8 {
        match self {
            WireOperation::CreateUser { .. } => request_kind::CREATE_USER,
            WireOperation::CreateComputer { .. } => request_kind::CREATE_COMPUTER,
            WireOperation::CreateGroup { .. } => request_kind::CREATE_GROUP,
            WireOperation::CreateOu { .. } => request_kind::CREATE_OU,
            WireOperation::CreateContainer { .. } => request_kind::CREATE_CONTAINER,
            WireOperation::BeginPasswordSet { .. } => request_kind::BEGIN_PASSWORD_SET,
            WireOperation::CompletePasswordSet { .. } => request_kind::COMPLETE_PASSWORD_SET,
            WireOperation::SetEnabled { .. } => request_kind::SET_ENABLED,
            WireOperation::SetAccountExpires { .. } => request_kind::SET_ACCOUNT_EXPIRES,
            WireOperation::AddMember { .. } => request_kind::ADD_MEMBER,
            WireOperation::RemoveMember { .. } => request_kind::REMOVE_MEMBER,
            WireOperation::Delete { .. } => request_kind::DELETE,
            WireOperation::Lookup(_) => request_kind::LOOKUP,
            WireOperation::ChangePolicy { .. } => request_kind::CHANGE_POLICY,
            WireOperation::KeyOperation { .. } => request_kind::KEY_OPERATION,
            WireOperation::Propose { .. } => request_kind::PROPOSE,
            WireOperation::Approve { .. } => request_kind::APPROVE,
            WireOperation::Reject { .. } => request_kind::REJECT,
            WireOperation::Withdraw { .. } => request_kind::WITHDRAW,
            WireOperation::ListRequests { .. } => request_kind::LIST_REQUESTS,
            WireOperation::ShowRequest { .. } => request_kind::SHOW_REQUEST,
            WireOperation::PlanOperation { .. } => request_kind::PLAN_OPERATION,
            WireOperation::Commit { .. } => request_kind::COMMIT,
        }
    }

    /// Whether this is a `Commit` of a key operation — valid only inside a
    /// `Propose` (a key operation is executed by keyadm in keyd, A-102).
    /// Spec: docs/51 §6; docs/questions/Q-980.
    fn commits_key_operation(&self) -> bool {
        matches!(
            self,
            WireOperation::Commit { operation, .. }
                if matches!(**operation, WireOperation::KeyOperation { .. })
        )
    }

    /// The fields after `auth`, in the docs/51 §7.3 order.
    /// Spec: docs/51 §7.3.
    pub(crate) fn write_fields(&self, writer: &mut Writer) -> Result<()> {
        match self {
            WireOperation::CreateUser {
                parent,
                sam,
                upn,
                description,
            } => {
                writer.write_array(parent)?;
                writer.write_bytes(sam, MAX_NAME)?;
                write_opt_bytes(writer, upn.as_ref(), MAX_PRINCIPAL_NAME)?;
                write_opt_bytes(writer, description.as_ref(), MAX_DESCRIPTION)
            }
            WireOperation::CreateComputer { parent, name, spn } => {
                writer.write_array(parent)?;
                writer.write_bytes(name, MAX_NAME)?;
                write_opt_bytes(writer, spn.as_ref(), MAX_PRINCIPAL_NAME)
            }
            WireOperation::CreateGroup {
                parent,
                sam,
                group_type,
            } => {
                writer.write_array(parent)?;
                writer.write_bytes(sam, MAX_NAME)?;
                writer.write_option(group_type.as_ref(), |w, t| w.write_u32(*t))
            }
            WireOperation::CreateOu { parent, name }
            | WireOperation::CreateContainer { parent, name } => {
                writer.write_array(parent)?;
                writer.write_bytes(name, MAX_NAME)
            }
            WireOperation::BeginPasswordSet { target } | WireOperation::Delete { target } => {
                writer.write_array(target)
            }
            WireOperation::CompletePasswordSet {
                target,
                outcome,
                kvnos,
            } => {
                writer.write_array(target)?;
                writer.write_enum(*outcome)?;
                writer.write_seq(kvnos, MAX_KVNOS, |w, k| w.write_u32(*k))
            }
            WireOperation::SetEnabled { target, enabled } => {
                writer.write_array(target)?;
                writer.write_bool(*enabled)
            }
            WireOperation::SetAccountExpires { target, filetime } => {
                writer.write_array(target)?;
                match filetime {
                    None => writer.write_enum(codes::EXPIRES_NEVER),
                    Some(at) => {
                        writer.write_enum(codes::EXPIRES_AT)?;
                        writer.write_u64(*at)
                    }
                }
            }
            WireOperation::AddMember { group, member }
            | WireOperation::RemoveMember { group, member } => {
                writer.write_array(group)?;
                writer.write_array(member)
            }
            WireOperation::Lookup(key) => match key {
                WireLookupKey::SamAccountName(sam) => {
                    writer.write_enum(codes::LOOKUP_SAM)?;
                    writer.write_bytes(sam, MAX_NAME)
                }
                WireLookupKey::ServicePrincipalName(spn) => {
                    writer.write_enum(codes::LOOKUP_SPN)?;
                    writer.write_bytes(spn, MAX_PRINCIPAL_NAME)
                }
                WireLookupKey::Dn(dn) => {
                    writer.write_enum(codes::LOOKUP_DN)?;
                    write_dn(writer, dn)
                }
            },
            WireOperation::ChangePolicy { changes } => {
                writer.write_seq(changes, MAX_POLICY_CHANGES, |w, c| c.write(w))
            }
            WireOperation::KeyOperation { operation } => operation.write(writer),
            WireOperation::Propose {
                reason_ref,
                operation,
            } => {
                write_opt_bytes(writer, reason_ref.as_ref(), MAX_REASON_REF)?;
                operation.write_proposed(writer)
            }
            WireOperation::Approve { id, digest } | WireOperation::Reject { id, digest } => {
                writer.write_u64(*id)?;
                writer.write_array(digest)
            }
            WireOperation::Withdraw { id } | WireOperation::ShowRequest { id } => {
                writer.write_u64(*id)
            }
            WireOperation::ListRequests { scope } => writer.write_enum(*scope),
            WireOperation::PlanOperation { operation } => operation.write_planned(writer),
            WireOperation::Commit { plan, operation } => {
                writer.write_array(plan)?;
                operation.write_planned(writer)
            }
        }
    }

    /// A planned operation: `kind:u8 ‖ fields`, the kind one of
    /// `request_kind::PLANNED` (anything else is refused).
    /// Spec: docs/questions/Q-980, Q-982.
    pub(crate) fn write_planned(&self, writer: &mut Writer) -> Result<()> {
        let kind = self.kind();
        if !request_kind::PLANNED.contains(&kind) {
            return Err(Error::UnknownKind);
        }
        writer.write_enum(kind)?;
        self.write_fields(writer)
    }

    /// A planned operation (see [`WireOperation::write_planned`]).
    /// Spec: docs/questions/Q-980.
    fn read_planned(reader: &mut Reader<'_>) -> Result<WireOperation> {
        let kind = reader.read_enum(|c| request_kind::PLANNED.contains(&c).then_some(c))?;
        WireOperation::read_fields(kind, reader)
    }

    /// A proposed operation: `kind:u8 ‖ fields`, the kind one of
    /// `request_kind::PROPOSABLE` (anything else is refused: no `Propose`
    /// inside a `Propose`, no read, no queue step).
    /// Spec: docs/questions/Q-882 item 1.
    pub(crate) fn write_proposed(&self, writer: &mut Writer) -> Result<()> {
        let kind = self.kind();
        if !request_kind::PROPOSABLE.contains(&kind) {
            return Err(Error::UnknownKind);
        }
        writer.write_enum(kind)?;
        self.write_fields(writer)
    }

    /// A proposed operation (see [`WireOperation::write_proposed`]).
    /// Spec: docs/questions/Q-882 item 1.
    fn read_proposed(reader: &mut Reader<'_>) -> Result<WireOperation> {
        let kind = reader.read_enum(|c| request_kind::PROPOSABLE.contains(&c).then_some(c))?;
        WireOperation::read_fields(kind, reader)
    }

    /// The fields of a frame of kind `kind`. Spec: docs/51 §7.3.
    fn read_fields(kind: u8, reader: &mut Reader<'_>) -> Result<WireOperation> {
        Ok(match kind {
            request_kind::CREATE_USER => WireOperation::CreateUser {
                parent: reader.read_array()?,
                sam: read_owned(reader, MAX_NAME)?,
                upn: read_opt_owned(reader, MAX_PRINCIPAL_NAME)?,
                description: read_opt_owned(reader, MAX_DESCRIPTION)?,
            },
            // Task PN6b: `parent ‖ name ‖ spn?` — the dNSHostName left the
            // layout (docs/questions/Q-1045 item 1).
            request_kind::CREATE_COMPUTER => WireOperation::CreateComputer {
                parent: reader.read_array()?,
                name: read_owned(reader, MAX_NAME)?,
                spn: read_opt_owned(reader, MAX_PRINCIPAL_NAME)?,
            },
            request_kind::CREATE_GROUP => WireOperation::CreateGroup {
                parent: reader.read_array()?,
                sam: read_owned(reader, MAX_NAME)?,
                group_type: reader.read_option(Reader::read_u32)?,
            },
            request_kind::CREATE_OU => WireOperation::CreateOu {
                parent: reader.read_array()?,
                name: read_owned(reader, MAX_NAME)?,
            },
            request_kind::CREATE_CONTAINER => WireOperation::CreateContainer {
                parent: reader.read_array()?,
                name: read_owned(reader, MAX_NAME)?,
            },
            request_kind::BEGIN_PASSWORD_SET => WireOperation::BeginPasswordSet {
                target: reader.read_array()?,
            },
            request_kind::COMPLETE_PASSWORD_SET => WireOperation::CompletePasswordSet {
                target: reader.read_array()?,
                outcome: reader.read_enum(|c| {
                    matches!(c, codes::OUTCOME_COMPLETED | codes::OUTCOME_FAILED).then_some(c)
                })?,
                kvnos: reader.read_seq(MAX_KVNOS, Reader::read_u32)?,
            },
            request_kind::SET_ENABLED => WireOperation::SetEnabled {
                target: reader.read_array()?,
                enabled: reader.read_bool()?,
            },
            request_kind::SET_ACCOUNT_EXPIRES => {
                let target = reader.read_array()?;
                let filetime = match reader.read_enum(|c| {
                    matches!(c, codes::EXPIRES_NEVER | codes::EXPIRES_AT).then_some(c)
                })? {
                    codes::EXPIRES_AT => Some(reader.read_u64()?),
                    _ => None,
                };
                WireOperation::SetAccountExpires { target, filetime }
            }
            request_kind::ADD_MEMBER => WireOperation::AddMember {
                group: reader.read_array()?,
                member: reader.read_array()?,
            },
            request_kind::REMOVE_MEMBER => WireOperation::RemoveMember {
                group: reader.read_array()?,
                member: reader.read_array()?,
            },
            request_kind::DELETE => WireOperation::Delete {
                target: reader.read_array()?,
            },
            request_kind::LOOKUP => {
                let tag = reader.read_enum(|c| {
                    matches!(c, codes::LOOKUP_SAM | codes::LOOKUP_SPN | codes::LOOKUP_DN)
                        .then_some(c)
                })?;
                WireOperation::Lookup(match tag {
                    codes::LOOKUP_SAM => {
                        WireLookupKey::SamAccountName(read_owned(reader, MAX_NAME)?)
                    }
                    codes::LOOKUP_SPN => {
                        WireLookupKey::ServicePrincipalName(read_owned(reader, MAX_PRINCIPAL_NAME)?)
                    }
                    _ => WireLookupKey::Dn(read_dn(reader)?),
                })
            }
            request_kind::CHANGE_POLICY => WireOperation::ChangePolicy {
                changes: reader.read_seq(MAX_POLICY_CHANGES, WirePolicyChange::read)?,
            },
            // Reached only through `read_proposed` (the kind is not in
            // `request_kind::ALL`, which `read_payload` checks first).
            request_kind::KEY_OPERATION => WireOperation::KeyOperation {
                operation: WireKeyOperation::read(reader)?,
            },
            request_kind::PROPOSE => WireOperation::Propose {
                reason_ref: read_opt_owned(reader, MAX_REASON_REF)?,
                operation: Box::new(WireOperation::read_proposed(reader)?),
            },
            request_kind::APPROVE => WireOperation::Approve {
                id: reader.read_u64()?,
                digest: reader.read_array()?,
            },
            request_kind::REJECT => WireOperation::Reject {
                id: reader.read_u64()?,
                digest: reader.read_array()?,
            },
            request_kind::WITHDRAW => WireOperation::Withdraw {
                id: reader.read_u64()?,
            },
            request_kind::LIST_REQUESTS => WireOperation::ListRequests {
                scope: reader.read_enum(|c| {
                    matches!(c, codes::LIST_MINE | codes::LIST_AWAITING_ME).then_some(c)
                })?,
            },
            request_kind::SHOW_REQUEST => WireOperation::ShowRequest {
                id: reader.read_u64()?,
            },
            request_kind::PLAN_OPERATION => WireOperation::PlanOperation {
                operation: Box::new(WireOperation::read_planned(reader)?),
            },
            request_kind::COMMIT => WireOperation::Commit {
                plan: reader.read_array()?,
                operation: Box::new(WireOperation::read_planned(reader)?),
            },
            _ => return Err(Error::UnknownKind),
        })
    }
}

/// One request of the admin channel.
/// Spec: docs/51 §7.2, §7.3; docs/50 §7.5 (`Ping`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminRequest {
    /// An operation: `auth` then the operation's fields.
    Operation {
        /// The tickets.
        auth: WireAuth,
        /// The operation.
        operation: WireOperation,
    },
    /// The health check (no `auth`, no field).
    Ping,
}

impl MessageSet for AdminRequest {
    const KINDS: &'static [u8] = request_kind::ALL;

    fn kind(&self) -> u8 {
        match self {
            AdminRequest::Operation { operation, .. } => operation.kind(),
            AdminRequest::Ping => request_kind::PING,
        }
    }

    /// Spec: docs/51 §7.2 (`auth` on every operation), §7.3; a `Commit` of
    /// a key operation is never a request of its own (docs/questions/Q-980).
    fn write_payload(&self, writer: &mut Writer) -> Result<()> {
        match self {
            AdminRequest::Operation { auth, operation } => {
                if operation.commits_key_operation() {
                    return Err(Error::UnknownKind);
                }
                auth.write_fields(writer)?;
                operation.write_fields(writer)
            }
            AdminRequest::Ping => Ok(()),
        }
    }

    /// Spec: docs/51 §7.2, §7.3; docs/52 §4.6 (the retired kinds are not
    /// in the closed table).
    fn read_payload(kind: u8, reader: &mut Reader<'_>) -> Result<AdminRequest> {
        if kind == request_kind::PING {
            return Ok(AdminRequest::Ping);
        }
        if !request_kind::ALL.contains(&kind) {
            return Err(Error::UnknownKind);
        }
        let auth = WireAuth::read_fields(reader)?;
        let operation = WireOperation::read_fields(kind, reader)?;
        // A key operation executes only from keyd's decision (A-102): its
        // `Commit` is valid inside a `Propose` only (task MA2).
        if operation.commits_key_operation() {
            return Err(Error::UnknownKind);
        }
        Ok(AdminRequest::Operation { auth, operation })
    }
}

// ===========================================================================
// Replies.
// ===========================================================================

/// One key set of a `BeginPasswordSet` reply: its handle and its binding.
/// Spec: docs/51 §7.3 (`handles (1 or 2), bindings`); docs/47 §9.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireKeyTarget {
    /// The objectGUID packet (`PrincipalId`).
    pub principal: GuidPacket,
    /// `PrincipalLongterm` or `Service` (never `Krbtgt`).
    pub purpose: KeyPurpose,
    /// The binding's realm (KerberosString octets).
    pub realm: Vec<u8>,
    /// The binding's `PrincipalName` DER.
    pub name: DerBlob,
}

/// `KeyPurpose` → code; `Krbtgt` has none on this channel.
/// Spec: crate::channel `codes`.
fn purpose_code(purpose: KeyPurpose) -> Result<u8> {
    match purpose {
        KeyPurpose::PrincipalLongterm => Ok(codes::PURPOSE_PRINCIPAL_LONGTERM),
        KeyPurpose::Service => Ok(codes::PURPOSE_SERVICE),
        // Never a password-set target: the krbtgt key, the admin service
        // key (R2) and the change-password service key (task K3, docs/53
        // §4.5) are keyd-drawn only.
        KeyPurpose::Krbtgt | KeyPurpose::AdminService | KeyPurpose::ChangePasswordService => {
            Err(Error::UnknownCode)
        }
    }
}

/// Code → `KeyPurpose` (closed table).
fn purpose_from(code: u8) -> Option<KeyPurpose> {
    match code {
        codes::PURPOSE_PRINCIPAL_LONGTERM => Some(KeyPurpose::PrincipalLongterm),
        codes::PURPOSE_SERVICE => Some(KeyPurpose::Service),
        _ => None,
    }
}

impl Payload for WireKeyTarget {
    /// Spec: docs/50 §3.3 (`KeyHandle`, binding `{ realm, name: DER }`).
    fn write_fields(&self, writer: &mut Writer) -> Result<()> {
        writer.write_array(&self.principal)?;
        writer.write_enum(purpose_code(self.purpose)?)?;
        writer.write_bytes(&self.realm, MAX_REALM)?;
        writer.write_der(&self.name, MAX_BINDING_NAME)
    }

    /// Spec: docs/50 §3.3.
    fn read_fields(reader: &mut Reader<'_>) -> Result<WireKeyTarget> {
        let principal = reader.read_array()?;
        let purpose = reader.read_enum(purpose_from)?;
        let realm = read_owned(reader, MAX_REALM)?;
        let name = reader.read_der(MAX_BINDING_NAME)?;
        Ok(WireKeyTarget {
            principal,
            purpose,
            realm,
            name,
        })
    }
}

/// A request state code (closed table).
/// Spec: crate::channel `codes::REQUEST_*`.
fn read_state(reader: &mut Reader<'_>) -> Result<u8> {
    reader.read_enum(|c| matches!(c, codes::REQUEST_PENDING | codes::REQUEST_APPROVED).then_some(c))
}

/// The state of a pending request, shown back to the requester and to every
/// approver: the answer to `Propose` and `Approve` (task D2-c).
///
/// `id:u64 ‖ digest:[32] ‖ state:u8 ‖ approvals:u8 ‖ quorum:u8 ‖
/// expires:u64`.
/// Spec: docs/questions/Q-882 item 1 (`{id, digest, quorum, expires}`);
/// docs/51 §5.6.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WirePendingRequest {
    /// The id (64 bits from dird's CSPRNG, Q-882 item 3).
    pub id: u64,
    /// The operation digest of the request's operation (crate::digest).
    pub digest: [u8; DIGEST_LEN],
    /// [`codes::REQUEST_PENDING`] or [`codes::REQUEST_APPROVED`].
    pub state: u8,
    /// Approvals recorded so far (the requester not counted).
    pub approvals: u8,
    /// The quorum, the requester included (`admin_quorum`, P-22).
    pub quorum: u8,
    /// The expiry: seconds since 1970-01-01T00:00:00Z.
    pub expires: u64,
}

impl WirePendingRequest {
    /// Spec: docs/questions/Q-882 item 1.
    fn write(&self, writer: &mut Writer) -> Result<()> {
        writer.write_u64(self.id)?;
        writer.write_array(&self.digest)?;
        writer.write_enum(self.state)?;
        writer.write_u8(self.approvals)?;
        writer.write_u8(self.quorum)?;
        writer.write_u64(self.expires)
    }

    /// Spec: docs/questions/Q-882 item 1.
    fn read(reader: &mut Reader<'_>) -> Result<WirePendingRequest> {
        Ok(WirePendingRequest {
            id: reader.read_u64()?,
            digest: reader.read_array()?,
            state: read_state(reader)?,
            approvals: reader.read_u8()?,
            quorum: reader.read_u8()?,
            expires: reader.read_u64()?,
        })
    }
}

/// One entry of a `RequestList` (task D2-c).
///
/// `id ‖ digest ‖ state:u8 ‖ operation:u8 (a PROPOSABLE kind) ‖
/// requester:bytes<68> (objectSid) ‖ approvals:u8 ‖ quorum:u8 ‖
/// expires:u64`.
/// Spec: docs/research/r5-a-admin-model.md §11 MA5; docs/questions/Q-882
/// item 1 (`List`); docs/research/r5-b-cli.md §7.4 ("the requester … verified
/// by the directory").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireRequestSummary {
    /// The id.
    pub id: u64,
    /// The operation digest.
    pub digest: [u8; DIGEST_LEN],
    /// The state code.
    pub state: u8,
    /// The kind of the operation the request is for.
    pub operation: u8,
    /// The requester's objectSid packet ([MS-DTYP] 2.4.2.2), as dird
    /// verified it.
    pub requester: Vec<u8>,
    /// Approvals recorded so far.
    pub approvals: u8,
    /// The quorum.
    pub quorum: u8,
    /// The expiry (seconds since 1970).
    pub expires: u64,
}

impl WireRequestSummary {
    /// Spec: r5-a §11 MA5.
    fn write(&self, writer: &mut Writer) -> Result<()> {
        writer.write_u64(self.id)?;
        writer.write_array(&self.digest)?;
        writer.write_enum(self.state)?;
        if !request_kind::REQUEST_OPERATIONS.contains(&self.operation) {
            return Err(Error::UnknownCode);
        }
        writer.write_enum(self.operation)?;
        writer.write_bytes(&self.requester, MAX_SID)?;
        writer.write_u8(self.approvals)?;
        writer.write_u8(self.quorum)?;
        writer.write_u64(self.expires)
    }

    /// Spec: r5-a §11 MA5.
    fn read(reader: &mut Reader<'_>) -> Result<WireRequestSummary> {
        Ok(WireRequestSummary {
            id: reader.read_u64()?,
            digest: reader.read_array()?,
            state: read_state(reader)?,
            operation: reader
                .read_enum(|c| request_kind::REQUEST_OPERATIONS.contains(&c).then_some(c))?,
            requester: read_owned(reader, MAX_SID)?,
            approvals: reader.read_u8()?,
            quorum: reader.read_u8()?,
            expires: reader.read_u64()?,
        })
    }
}

/// One fact dird resolved for an object a pending operation names (task
/// D2-c): what the approver is shown beside the operation — "directory
/// says", never the requester's words.
///
/// `guid:[16] ‖ dn:seq<bytes<128>,64> ‖ class:bytes<64> ‖
/// sid:Option<bytes<68>> ‖ tier:u8` (`codes::TIER_0..2`, or
/// `codes::FACT_UNCLASSIFIED`).
/// Spec: docs/questions/Q-882 item 1 ("facts dird resolved: DN / class /
/// SID / tier for every GUID"), Q-887 items 2-3; docs/research/r5-b-cli.md
/// §7.4 rule 2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireFact {
    /// The objectGUID packet.
    pub guid: GuidPacket,
    /// The DN, leaf first.
    pub dn: Vec<Vec<u8>>,
    /// The most specific class's lDAPDisplayName.
    pub class: Vec<u8>,
    /// The objectSid packet, if any.
    pub sid: Option<Vec<u8>>,
    /// The explicit tier code.
    pub tier: u8,
}

impl WireFact {
    /// Spec: docs/questions/Q-887 item 2.
    fn write(&self, writer: &mut Writer) -> Result<()> {
        writer.write_array(&self.guid)?;
        write_dn(writer, &self.dn)?;
        writer.write_bytes(&self.class, MAX_CLASS_NAME)?;
        write_opt_bytes(writer, self.sid.as_ref(), MAX_SID)?;
        writer.write_enum(self.tier)
    }

    /// Spec: docs/questions/Q-887 item 2.
    fn read(reader: &mut Reader<'_>) -> Result<WireFact> {
        Ok(WireFact {
            guid: reader.read_array()?,
            dn: read_dn(reader)?,
            class: read_owned(reader, MAX_CLASS_NAME)?,
            sid: read_opt_owned(reader, MAX_SID)?,
            tier: reader.read_enum(|c| {
                matches!(
                    c,
                    codes::TIER_0 | codes::TIER_1 | codes::TIER_2 | codes::FACT_UNCLASSIFIED
                )
                .then_some(c)
            })?,
        })
    }
}

/// A pending request as dird holds it: the answer to `ShowRequest` (task
/// D2-c). The operation is dird's own copy of the fields it will execute —
/// never text the requester wrote (docs/research/r5-b-cli.md §7.4 rule 1;
/// class C44) — and the facts are what dird resolved for the objects it
/// names, through the caller's visibility gate.
///
/// `id ‖ digest ‖ state:u8 ‖ requester:bytes<68> ‖ approvers:seq<bytes<68>,
/// 2> ‖ quorum:u8 ‖ expires:u64 ‖ reason_ref:Option<bytes<64>> ‖ operation
/// (a PROPOSABLE kind ‖ its fields) ‖ facts:seq<Fact, 2> ‖
/// plan:Option<bytes<24 KiB>>` — `plan` appended by task MA2: the canonical
/// encoding of the effect plan dird holds for a `Commit` (its digest is the
/// `Commit`'s `plan`), rendered from dird's own bytes, never from requester
/// text (docs/questions/Q-874, Q-980).
/// Spec: docs/questions/Q-882 item 1 (`Show {id}`), Q-887 item 3;
/// docs/research/r5-a-admin-model.md §11 MA5; docs/research/r5-b-cli.md
/// §7.4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireRequestShown {
    /// The id.
    pub id: u64,
    /// The operation digest.
    pub digest: [u8; DIGEST_LEN],
    /// The state code.
    pub state: u8,
    /// The requester's objectSid packet, as dird verified it.
    pub requester: Vec<u8>,
    /// The approvers' objectSid packets, in approval order.
    pub approvers: Vec<Vec<u8>>,
    /// The quorum.
    pub quorum: u8,
    /// The expiry (seconds since 1970).
    pub expires: u64,
    /// The requester's change identifier (unverified).
    pub reason_ref: Option<Vec<u8>>,
    /// The operation (a PROPOSABLE kind).
    pub operation: WireOperation,
    /// The facts, at most [`MAX_FACTS`].
    pub facts: Vec<WireFact>,
    /// The effect plan's canonical encoding, for a `Commit` (task MA2).
    pub plan: Option<Vec<u8>>,
}

impl WireRequestShown {
    /// Spec: docs/questions/Q-882 item 1.
    fn write(&self, writer: &mut Writer) -> Result<()> {
        writer.write_u64(self.id)?;
        writer.write_array(&self.digest)?;
        writer.write_enum(self.state)?;
        writer.write_bytes(&self.requester, MAX_SID)?;
        writer.write_seq(&self.approvers, MAX_SHOWN_APPROVERS, |w, a| {
            w.write_bytes(a, MAX_SID)
        })?;
        writer.write_u8(self.quorum)?;
        writer.write_u64(self.expires)?;
        write_opt_bytes(writer, self.reason_ref.as_ref(), MAX_REASON_REF)?;
        self.operation.write_proposed(writer)?;
        writer.write_seq(&self.facts, MAX_FACTS, |w, f| f.write(w))?;
        write_opt_bytes(writer, self.plan.as_ref(), MAX_PLAN_U32)
    }

    /// Spec: docs/questions/Q-882 item 1.
    fn read(reader: &mut Reader<'_>) -> Result<WireRequestShown> {
        Ok(WireRequestShown {
            id: reader.read_u64()?,
            digest: reader.read_array()?,
            state: read_state(reader)?,
            requester: read_owned(reader, MAX_SID)?,
            approvers: reader.read_seq(MAX_SHOWN_APPROVERS, |r| read_owned(r, MAX_SID))?,
            quorum: reader.read_u8()?,
            expires: reader.read_u64()?,
            reason_ref: read_opt_owned(reader, MAX_REASON_REF)?,
            operation: WireOperation::read_proposed(reader)?,
            facts: reader.read_seq(MAX_FACTS, WireFact::read)?,
            plan: read_opt_owned(reader, MAX_PLAN_U32)?,
        })
    }
}

/// One reply of the admin channel (the shared `Refused` travels separately,
/// `ipc::Reply::Refused`).
/// Spec: docs/51 §7.3 (the reply column); docs/50 §7.5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminReply {
    /// A create: the new objectGUID and, for a security principal, its SID.
    Created {
        /// The objectGUID packet.
        guid: GuidPacket,
        /// The objectSid packet.
        sid: Option<Vec<u8>>,
    },
    /// `BeginPasswordSet`: account kind, key targets, salt.
    PasswordSet {
        /// [`codes::KIND_USER`] or [`codes::KIND_COMPUTER`].
        kind: u8,
        /// The key targets, `PrincipalLongterm` first.
        keys: Vec<WireKeyTarget>,
        /// The salt (KerberosString octets).
        salt: Vec<u8>,
    },
    /// `()`.
    Done,
    /// `Lookup` of a visible object.
    Found {
        /// The objectGUID packet.
        guid: GuidPacket,
        /// The DN, leaf first.
        dn: Vec<Vec<u8>>,
        /// The most specific class's lDAPDisplayName.
        class: Vec<u8>,
        /// The objectSid packet, if any.
        sid: Option<Vec<u8>>,
    },
    /// The operation was refused or failed.
    Refused(RefusalStatus),
    /// `Ping` answered.
    Pong,
    /// `ChangePolicy` written as `policy.next` (task A16): its version.
    PolicyNext {
        /// The `policy_version` of the file dird wrote (the loaded one + 1).
        version: u64,
    },
    /// `Propose` / `Approve`: the pending request's state (task D2-c).
    PendingRequest(WirePendingRequest),
    /// `ListRequests`: the requests in the scope.
    RequestList {
        /// One entry per request, at most [`MAX_LISTED_REQUESTS`].
        entries: Vec<WireRequestSummary>,
    },
    /// `ShowRequest`: the request as dird holds it.
    RequestShown(Box<WireRequestShown>),
    /// `PlanOperation`: the effect plan's canonical encoding and its digest
    /// (task MA2).
    Plan {
        /// The canonical encoding (crate::plan), at most 24 KiB.
        plan: Vec<u8>,
        /// Its digest (crate::plan `plan_digest`).
        digest: [u8; DIGEST_LEN],
    },
}

impl MessageSet for AdminReply {
    const KINDS: &'static [u8] = reply_kind::ALL;

    fn kind(&self) -> u8 {
        match self {
            AdminReply::Created { .. } => reply_kind::CREATED,
            AdminReply::PasswordSet { .. } => reply_kind::PASSWORD_SET,
            AdminReply::Done => reply_kind::DONE,
            AdminReply::Found { .. } => reply_kind::FOUND,
            AdminReply::Refused(_) => reply_kind::REFUSED,
            AdminReply::Pong => reply_kind::PONG,
            AdminReply::PolicyNext { .. } => reply_kind::POLICY_NEXT,
            AdminReply::PendingRequest(_) => reply_kind::PENDING_REQUEST,
            AdminReply::RequestList { .. } => reply_kind::REQUEST_LIST,
            AdminReply::RequestShown(_) => reply_kind::REQUEST_SHOWN,
            AdminReply::Plan { .. } => reply_kind::PLAN,
        }
    }

    /// Spec: docs/51 §7.3.
    fn write_payload(&self, writer: &mut Writer) -> Result<()> {
        match self {
            AdminReply::Created { guid, sid } => {
                writer.write_array(guid)?;
                write_opt_bytes(writer, sid.as_ref(), MAX_SID)
            }
            AdminReply::PasswordSet { kind, keys, salt } => {
                writer.write_enum(*kind)?;
                writer.write_seq(keys, MAX_KEY_TARGETS, |w, k| k.write_fields(w))?;
                writer.write_bytes(salt, MAX_SALT)
            }
            AdminReply::Found {
                guid,
                dn,
                class,
                sid,
            } => {
                writer.write_array(guid)?;
                write_dn(writer, dn)?;
                writer.write_bytes(class, MAX_CLASS_NAME)?;
                write_opt_bytes(writer, sid.as_ref(), MAX_SID)
            }
            AdminReply::Refused(status) => writer.write_enum(status.code()),
            AdminReply::Done | AdminReply::Pong => Ok(()),
            AdminReply::PolicyNext { version } => writer.write_u64(*version),
            AdminReply::PendingRequest(request) => request.write(writer),
            AdminReply::RequestList { entries } => {
                writer.write_seq(entries, MAX_LISTED_REQUESTS, |w, e| e.write(w))
            }
            AdminReply::RequestShown(shown) => shown.write(writer),
            AdminReply::Plan { plan, digest } => {
                writer.write_bytes(plan, MAX_PLAN_U32)?;
                writer.write_array(digest)
            }
        }
    }

    /// Spec: docs/51 §7.3; docs/50 §3.3 ("replies are decoded with the same
    /// strictness").
    fn read_payload(kind: u8, reader: &mut Reader<'_>) -> Result<AdminReply> {
        Ok(match kind {
            reply_kind::CREATED => AdminReply::Created {
                guid: reader.read_array()?,
                sid: read_opt_owned(reader, MAX_SID)?,
            },
            reply_kind::PASSWORD_SET => AdminReply::PasswordSet {
                kind: reader.read_enum(|c| {
                    matches!(c, codes::KIND_USER | codes::KIND_COMPUTER).then_some(c)
                })?,
                keys: reader.read_seq(MAX_KEY_TARGETS, WireKeyTarget::read_fields)?,
                salt: read_owned(reader, MAX_SALT)?,
            },
            reply_kind::DONE => AdminReply::Done,
            reply_kind::FOUND => AdminReply::Found {
                guid: reader.read_array()?,
                dn: read_dn(reader)?,
                class: read_owned(reader, MAX_CLASS_NAME)?,
                sid: read_opt_owned(reader, MAX_SID)?,
            },
            reply_kind::REFUSED => AdminReply::Refused(reader.read_enum(RefusalStatus::from_code)?),
            reply_kind::PONG => AdminReply::Pong,
            reply_kind::POLICY_NEXT => AdminReply::PolicyNext {
                version: reader.read_u64()?,
            },
            reply_kind::PENDING_REQUEST => {
                AdminReply::PendingRequest(WirePendingRequest::read(reader)?)
            }
            reply_kind::REQUEST_LIST => AdminReply::RequestList {
                entries: reader.read_seq(MAX_LISTED_REQUESTS, WireRequestSummary::read)?,
            },
            reply_kind::REQUEST_SHOWN => {
                AdminReply::RequestShown(Box::new(WireRequestShown::read(reader)?))
            }
            reply_kind::PLAN => AdminReply::Plan {
                plan: read_owned(reader, MAX_PLAN_U32)?,
                digest: reader.read_array()?,
            },
            _ => return Err(Error::UnknownKind),
        })
    }
}
