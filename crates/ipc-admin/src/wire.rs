//! The wire layer: every message of the administrators' channel as
//! fixed-order fields over `ipc`.
//!
//! * A **forwarded operation** is written and read by crate ipc-dird-admin's
//!   own message set (`ipc_dird_admin::AdminRequest`): `auth` then the
//!   operation's fields, exactly dird's layout — admind passes `auth` on
//!   untouched (docs/51 §7.6: "the same operations").
//! * **`SetPassword`**:
//!   `auth ‖ completion: bytes<64 KiB> ‖ target: [16] ‖ password: secret bytes<1024>`
//!   — `auth` is dird's field (the requester's AP-REQ and ≤ 2 approvals, for
//!   `BeginPasswordSet`); `completion` is one more AP-REQ of the requester,
//!   for `CompletePasswordSet` (keyd's replay cache makes each AP-REQ
//!   single-use — docs/questions/Q-400); the password is an `ipc::Secret`
//!   (zeroizing buffer, no `Debug` content, no `Clone`).
//! * keyadm's former requests (`FetchApproved`, `Complete`,
//!   `ListPendingDestruction`, the only ones without `auth`) are retired by
//!   A-102 (docs/52 §4.6; docs/questions/Q-460): their kinds are not in the
//!   closed table, so admind refuses them like any unknown kind.
//! * The replies `Created`, `Done`, `Found`, `Pong`, `KeyRequest` are
//!   dird's (read and written by
//!   `ipc_dird_admin::AdminReply`); `Refused` carries this channel's status
//!   table; `PasswordChanged` is `kvnos: seq<u32, 2> ‖ completion_recorded:
//!   bool`.
//!
//! Spec: docs/51 §7.1-§7.3, §7.6; docs/50 §3.3 (primitives; "`bool` = `00` /
//! `01` only"; secret-bearing bodies read into `Zeroizing`); A-59.

use crate::channel::{
    reply_kind, request_kind, RefusalStatus, MAX_COMPLETION_AP_REQ, MAX_KVNOS, MAX_PASSWORD,
};
use core::fmt;
use ipc::{Error, MessageSet, Payload, Reader, Result, Secret, Writer};
use ipc_dird_admin::wire::{AdminReply as DirdReply, AdminRequest as DirdRequest};
use ipc_dird_admin::{WireAuth, WireKeyRequest, WireOperation};

/// A 16-octet objectGUID packet.
pub type GuidPacket = [u8; 16];

/// The fields of a `SetPassword` request.
/// Spec: docs/51 §7.6; docs/questions/Q-400.
pub struct WireSetPassword {
    /// The requester's and approvers' raw AP-REQs, forwarded untouched to
    /// dird's `BeginPasswordSet`.
    pub auth: WireAuth,
    /// The requester's second raw AP-REQ, forwarded untouched to dird's
    /// `CompletePasswordSet` (with no approvals).
    pub completion: Vec<u8>,
    /// The account's objectGUID packet.
    pub target: GuidPacket,
    /// The password (UTF-8 in the typed layer), in a zeroizing buffer.
    pub password: Secret,
}

impl fmt::Debug for WireSetPassword {
    /// Lengths and the target only: neither AP-REQ octets nor anything of
    /// the password (not even its length) is printed (docs/50 §8.2;
    /// AGENTS.md §6).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WireSetPassword")
            .field("auth", &self.auth)
            .field("completion_len", &self.completion.len())
            .field("target", &self.target)
            .field("password", &self.password)
            .finish()
    }
}

impl Payload for WireSetPassword {
    /// Spec: docs/51 §7.2, §7.6.
    fn write_fields(&self, writer: &mut Writer) -> Result<()> {
        self.auth.write_fields(writer)?;
        writer.write_bytes(&self.completion, MAX_COMPLETION_AP_REQ)?;
        writer.write_array(&self.target)?;
        writer.write_secret(&self.password, MAX_PASSWORD)
    }

    /// Spec: docs/51 §7.2, §7.6; docs/50 §3.3 (the secret read into a
    /// zeroizing buffer).
    fn read_fields(reader: &mut Reader<'_>) -> Result<WireSetPassword> {
        let auth = WireAuth::read_fields(reader)?;
        let completion = reader.read_bytes(MAX_COMPLETION_AP_REQ)?.to_vec();
        let target = reader.read_array()?;
        let password = reader.read_secret(MAX_PASSWORD)?;
        Ok(WireSetPassword {
            auth,
            completion,
            target,
            password,
        })
    }
}

/// One request of the administrators' channel. No `Clone` and no
/// `PartialEq`: `SetPassword` holds a secret (docs/10 I6 — no
/// variable-time comparison of secret material; no silent second copy).
/// Spec: docs/51 §7.6; docs/50 §7.5 (`Ping`).
#[derive(Debug)]
pub enum AdminRequest {
    /// An operation admind forwards to dird: dird's `auth` and fields.
    /// Never dird's `BeginPasswordSet` / `CompletePasswordSet` (their kinds
    /// are not in this channel's table, so such a value does not encode).
    Forward {
        /// The tickets, forwarded untouched.
        auth: WireAuth,
        /// The operation's fields (dird's layout).
        operation: WireOperation,
    },
    /// `SetPassword`.
    SetPassword(WireSetPassword),
    /// admind's health check (no `auth`, no field).
    Ping,
}

impl MessageSet for AdminRequest {
    const KINDS: &'static [u8] = request_kind::ALL;

    fn kind(&self) -> u8 {
        match self {
            AdminRequest::Forward { operation, .. } => operation.kind(),
            AdminRequest::SetPassword(_) => request_kind::SET_PASSWORD,
            AdminRequest::Ping => request_kind::PING,
        }
    }

    /// Spec: docs/51 §7.2, §7.6.
    fn write_payload(&self, writer: &mut Writer) -> Result<()> {
        match self {
            AdminRequest::Forward { auth, operation } => {
                if !request_kind::FORWARDED.contains(&operation.kind()) {
                    return Err(Error::UnknownKind);
                }
                // dird's message set writes `auth` then the fields — the one
                // layout of these operations (encoding side only: a client).
                DirdRequest::Operation {
                    auth: auth.clone(),
                    operation: operation.clone(),
                }
                .write_payload(writer)
            }
            AdminRequest::SetPassword(set) => set.write_fields(writer),
            AdminRequest::Ping => Ok(()),
        }
    }

    /// Spec: docs/51 §7.2, §7.6.
    fn read_payload(kind: u8, reader: &mut Reader<'_>) -> Result<AdminRequest> {
        match kind {
            request_kind::PING => Ok(AdminRequest::Ping),
            request_kind::SET_PASSWORD => Ok(AdminRequest::SetPassword(
                WireSetPassword::read_fields(reader)?,
            )),
            _ if request_kind::FORWARDED.contains(&kind) => {
                match DirdRequest::read_payload(kind, reader)? {
                    DirdRequest::Operation { auth, operation } => {
                        Ok(AdminRequest::Forward { auth, operation })
                    }
                    // A forwarded kind is never dird's `Ping` (matched
                    // above).
                    DirdRequest::Ping => Err(Error::UnknownKind),
                }
            }
            _ => Err(Error::UnknownKind),
        }
    }
}

// ===========================================================================
// Replies.
// ===========================================================================

/// One reply of the administrators' channel (the shared `Refused` travels
/// separately, `ipc::Reply::Refused`).
/// Spec: docs/51 §7.3 (the reply column), §7.6; docs/50 §7.5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminReply {
    /// A create: the new objectGUID and, for a security principal, its SID.
    Created {
        /// The objectGUID packet.
        guid: GuidPacket,
        /// The objectSid packet.
        sid: Option<Vec<u8>>,
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
    /// `SetPassword`: every `set_secret` succeeded.
    PasswordChanged {
        /// The key versions keyd chose, in call order (`PrincipalLongterm`,
        /// then `Service` for a computer).
        kvnos: Vec<u32>,
        /// Whether dird accepted the `CompletePasswordSet` report.
        completion_recorded: bool,
    },
    /// dird's `KeyRequest` (dird's layout).
    KeyRequest(WireKeyRequest),
}

impl MessageSet for AdminReply {
    const KINDS: &'static [u8] = reply_kind::ALL;

    fn kind(&self) -> u8 {
        match self {
            AdminReply::Created { .. } => reply_kind::CREATED,
            AdminReply::Done => reply_kind::DONE,
            AdminReply::Found { .. } => reply_kind::FOUND,
            AdminReply::Refused(_) => reply_kind::REFUSED,
            AdminReply::Pong => reply_kind::PONG,
            AdminReply::PasswordChanged { .. } => reply_kind::PASSWORD_CHANGED,
            AdminReply::KeyRequest(_) => reply_kind::KEY_REQUEST,
        }
    }

    /// Spec: docs/51 §7.3, §7.6.
    fn write_payload(&self, writer: &mut Writer) -> Result<()> {
        match self {
            AdminReply::Created { guid, sid } => DirdReply::Created {
                guid: *guid,
                sid: sid.clone(),
            }
            .write_payload(writer),
            AdminReply::Found {
                guid,
                dn,
                class,
                sid,
            } => DirdReply::Found {
                guid: *guid,
                dn: dn.clone(),
                class: class.clone(),
                sid: sid.clone(),
            }
            .write_payload(writer),
            AdminReply::Refused(status) => writer.write_enum(status.code()),
            AdminReply::PasswordChanged {
                kvnos,
                completion_recorded,
            } => {
                writer.write_seq(kvnos, MAX_KVNOS, |w, k| w.write_u32(*k))?;
                writer.write_bool(*completion_recorded)
            }
            AdminReply::Done | AdminReply::Pong => Ok(()),
            AdminReply::KeyRequest(request) => {
                DirdReply::KeyRequest(request.clone()).write_payload(writer)
            }
        }
    }

    /// Spec: docs/51 §7.3, §7.6; docs/50 §3.3 ("replies are decoded with the
    /// same strictness").
    fn read_payload(kind: u8, reader: &mut Reader<'_>) -> Result<AdminReply> {
        Ok(match kind {
            reply_kind::CREATED => match DirdReply::read_payload(kind, reader)? {
                DirdReply::Created { guid, sid } => AdminReply::Created { guid, sid },
                _ => return Err(Error::UnknownKind),
            },
            reply_kind::FOUND => match DirdReply::read_payload(kind, reader)? {
                DirdReply::Found {
                    guid,
                    dn,
                    class,
                    sid,
                } => AdminReply::Found {
                    guid,
                    dn,
                    class,
                    sid,
                },
                _ => return Err(Error::UnknownKind),
            },
            reply_kind::DONE => AdminReply::Done,
            reply_kind::PONG => AdminReply::Pong,
            reply_kind::REFUSED => AdminReply::Refused(reader.read_enum(RefusalStatus::from_code)?),
            reply_kind::PASSWORD_CHANGED => AdminReply::PasswordChanged {
                kvnos: reader.read_seq(MAX_KVNOS, Reader::read_u32)?,
                completion_recorded: reader.read_bool()?,
            },
            reply_kind::KEY_REQUEST => match DirdReply::read_payload(kind, reader)? {
                DirdReply::KeyRequest(request) => AdminReply::KeyRequest(request),
                _ => return Err(Error::UnknownKind),
            },
            _ => return Err(Error::UnknownKind),
        })
    }
}
