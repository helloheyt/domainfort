//! The wire layer: every message of the admin channel as fixed-order fields
//! over `ipc` (lengths, markers, closed enumeration tables, no trailing
//! octet). Text, SIDs and Kerberos values stay opaque octets here; the typed
//! layer ([`crate::typed`]) passes each through its strict decoder (UTF-8,
//! dtyp, krb-proto).
//!
//! | field | encoding |
//! |---|---|
//! | `auth` | `requester: bytes<64 KiB>` ‖ `approvals: seq<bytes<64 KiB>, 2>` (raw AP-REQs) |
//! | object | 16-octet objectGUID packet ([MS-DTYP] 2.3.4.2) |
//! | name, UPN, SPN, dNSHostName, description | `bytes<max>` (UTF-8 in the typed layer) |
//! | DN | `seq<bytes<128>, 64>` of `att=value` components, leaf first |
//! | SID | `bytes<68>` holding the [MS-DTYP] 2.4.2.2 packet |
//! | `KeyHandle` | 16-octet `PrincipalId` ‖ purpose `u8` (closed table) |
//! | binding | realm `bytes<255>` ‖ name `bytes<4096>` holding the `PrincipalName` DER |
//! | outcome, expiry, lookup key, account kind, status | `u8` from a closed table |
//!
//! Spec: docs/51 §7.1 (the `crates/ipc` codec), §7.2 (`auth`), §7.3 (the
//! fields of each operation and reply); docs/50 §3.3 (primitives; "Kerberos
//! values … as `bytes<max>` containing DER"; "`KeyHandle` = 16 octets
//! `PrincipalId` + `u8` purpose").

use crate::channel::{
    codes, reply_kind, request_kind, RefusalStatus, MAX_APPROVALS, MAX_AP_REQ, MAX_BINDING_NAME,
    MAX_CLASS_NAME, MAX_DESCRIPTION, MAX_DNS_HOST_NAME, MAX_DN_COMPONENT, MAX_DN_COMPONENTS,
    MAX_KEY_TARGETS, MAX_KVNOS, MAX_NAME, MAX_PRINCIPAL_NAME, MAX_REALM, MAX_SALT, MAX_SID,
};
use ipc::{DerBlob, Error, MessageSet, Payload, Reader, Result, Writer};
use keyd_types::KeyPurpose;

/// A 16-octet objectGUID packet.
pub type GuidPacket = [u8; 16];

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

/// The authentication field of every operation: the requester's raw AP-REQ
/// and the approvers' (at most two). There is **no** field in which admind
/// could claim a name, a SID, a tier or "approved" — dird learns who asks
/// only from keyd's verification of these tickets.
/// Spec: docs/51 §7.2; A-70 (precedent: the front cannot claim an identity);
/// A-73.
#[derive(Clone, PartialEq, Eq)]
pub struct WireAuth {
    /// The requester's `KRB_AP_REQ` DER, as admind received it.
    pub requester: Vec<u8>,
    /// The approvers' `KRB_AP_REQ` DERs.
    pub approvals: Vec<Vec<u8>>,
}

impl core::fmt::Debug for WireAuth {
    /// Lengths only: AP-REQ octets are never printed (docs/50 §8.2).
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WireAuth")
            .field("requester_len", &self.requester.len())
            .field("approvals", &self.approvals.len())
            .finish()
    }
}

impl Payload for WireAuth {
    /// Spec: docs/51 §7.2.
    fn write_fields(&self, writer: &mut Writer) -> Result<()> {
        writer.write_bytes(&self.requester, MAX_AP_REQ)?;
        writer.write_seq(&self.approvals, MAX_APPROVALS, |w, a| {
            w.write_bytes(a, MAX_AP_REQ)
        })
    }

    /// Spec: docs/51 §7.2.
    fn read_fields(reader: &mut Reader<'_>) -> Result<WireAuth> {
        let requester = read_owned(reader, MAX_AP_REQ)?;
        let approvals = reader.read_seq(MAX_APPROVALS, |r| read_owned(r, MAX_AP_REQ))?;
        Ok(WireAuth {
            requester,
            approvals,
        })
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
    /// `CreateComputer {parent, name, dns_host_name, spn?}`.
    CreateComputer {
        /// The container.
        parent: GuidPacket,
        /// The computer name (without "$").
        name: Vec<u8>,
        /// The dNSHostName.
        dns_host_name: Vec<u8>,
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
        }
    }

    /// The fields after `auth`, in the docs/51 §7.3 order.
    /// Spec: docs/51 §7.3.
    fn write_fields(&self, writer: &mut Writer) -> Result<()> {
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
            WireOperation::CreateComputer {
                parent,
                name,
                dns_host_name,
                spn,
            } => {
                writer.write_array(parent)?;
                writer.write_bytes(name, MAX_NAME)?;
                writer.write_bytes(dns_host_name, MAX_DNS_HOST_NAME)?;
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
        }
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
            request_kind::CREATE_COMPUTER => WireOperation::CreateComputer {
                parent: reader.read_array()?,
                name: read_owned(reader, MAX_NAME)?,
                dns_host_name: read_owned(reader, MAX_DNS_HOST_NAME)?,
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

    /// Spec: docs/51 §7.2 (`auth` on every operation), §7.3.
    fn write_payload(&self, writer: &mut Writer) -> Result<()> {
        match self {
            AdminRequest::Operation { auth, operation } => {
                auth.write_fields(writer)?;
                operation.write_fields(writer)
            }
            AdminRequest::Ping => Ok(()),
        }
    }

    /// Spec: docs/51 §7.2, §7.3.
    fn read_payload(kind: u8, reader: &mut Reader<'_>) -> Result<AdminRequest> {
        if kind == request_kind::PING {
            return Ok(AdminRequest::Ping);
        }
        if !request_kind::ALL.contains(&kind) {
            return Err(Error::UnknownKind);
        }
        let auth = WireAuth::read_fields(reader)?;
        let operation = WireOperation::read_fields(kind, reader)?;
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
        KeyPurpose::Krbtgt => Err(Error::UnknownCode),
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
            _ => return Err(Error::UnknownKind),
        })
    }
}
