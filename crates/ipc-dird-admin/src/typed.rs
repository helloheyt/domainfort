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
use crate::wire::{
    AdminReply, AdminRequest, WireAuth, WireKeyOperation, WireKeyRef, WireKeyRequest,
    WireKeyTarget, WireLookupKey, WireOperation,
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
        })
    }
}

impl std::error::Error for ConversionError {}

/// The authentication field (opaque AP-REQs). Spec: docs/51 §7.2.
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
    /// `CreateComputer {parent, name, dns_host_name, spn?}`.
    CreateComputer {
        /// The container.
        parent: Guid,
        /// The computer name, without the trailing "$".
        name: String,
        /// The dNSHostName.
        dns_host_name: String,
        /// The single servicePrincipalName.
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
    /// `RequestKeyOperation {operation}`.
    RequestKeyOperation {
        /// The key operation asked for.
        operation: KeyOperation,
    },
    /// `Approve {id, operation}`.
    Approve {
        /// The pending request's id.
        id: u64,
        /// The exact operation the approver approves.
        operation: KeyOperation,
    },
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
            WireOperation::CreateComputer {
                parent,
                name,
                dns_host_name,
                spn,
            } => Operation::CreateComputer {
                parent: guid(parent),
                name: text(name)?,
                dns_host_name: text(dns_host_name)?,
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
            WireOperation::RequestKeyOperation { operation } => Operation::RequestKeyOperation {
                operation: KeyOperation::from_wire(operation),
            },
            WireOperation::Approve { id, operation } => Operation::Approve {
                id: *id,
                operation: KeyOperation::from_wire(operation),
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
            Operation::CreateComputer {
                parent,
                name,
                dns_host_name,
                spn,
            } => WireOperation::CreateComputer {
                parent: parent.to_packet(),
                name: bytes(name),
                dns_host_name: bytes(dns_host_name),
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
            Operation::RequestKeyOperation { operation } => WireOperation::RequestKeyOperation {
                operation: operation.to_wire(),
            },
            Operation::Approve { id, operation } => WireOperation::Approve {
                id: *id,
                operation: operation.to_wire(),
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

/// The pending key-operation request as dird holds it — the answer to
/// `RequestKeyOperation` and to `Approve`, so the requester and every
/// approver see the exact operation and its digest.
/// Spec: docs/51 §5.6, §7.3 (`id / state`); docs/24 §6 (principle).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRequestState {
    /// The request's id.
    pub id: u64,
    /// The operation digest (docs/questions/Q-420).
    pub digest: [u8; DIGEST_LEN],
    /// The operation.
    pub operation: KeyOperation,
    /// Approvals recorded so far.
    pub approvals: u8,
    /// The quorum, the requester included (`admin_quorum`, P-22).
    pub quorum: u8,
}

impl KeyRequestState {
    /// Whether the approvals reach the quorum.
    #[must_use]
    pub fn approved(&self) -> bool {
        u16::from(self.approvals) + 1 >= u16::from(self.quorum)
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
    /// `RequestKeyOperation` / `Approve`. The request's id is also the id
    /// of the decision dird registers in keyd when an `Approve` completes
    /// the quorum (A-102, docs/52 §4.3) — what the operator gives keyadm.
    KeyRequest(KeyRequestState),
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
            AdminReply::KeyRequest(request) => Reply::KeyRequest(KeyRequestState {
                id: request.id,
                digest: request.digest,
                operation: KeyOperation::from_wire(&request.operation),
                approvals: request.approvals,
                quorum: request.quorum,
            }),
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
            Reply::KeyRequest(request) => AdminReply::KeyRequest(WireKeyRequest {
                id: request.id,
                digest: request.digest,
                operation: request.operation.to_wire(),
                approvals: request.approvals,
                quorum: request.quorum,
            }),
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
        keyd_types::KeyPurpose::Krbtgt | keyd_types::KeyPurpose::AdminService
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
