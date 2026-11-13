//! The wire layer: every message of the directory-view channel as fixed-order
//! fields over `ipc` (lengths, markers, closed enumeration tables, no
//! trailing octet). Kerberos values and SIDs stay opaque octets here; the
//! typed layer ([`crate::typed`]) passes each through its strict decoder
//! (krb-proto, dtyp).
//!
//! | field | encoding |
//! |---|---|
//! | view id, policy version | `u64` |
//! | realm, salt | `bytes<max>` holding KerberosString octets |
//! | name | `bytes<MAX_NAME>` holding the `PrincipalName` DER |
//! | SID | `bytes<MAX_SID>` holding the [MS-DTYP] 2.4.2.2 packet |
//! | `KeyHandle` | 16-octet `PrincipalId` ‖ purpose `u8` (closed table) |
//! | `KerberosTime` | `year:u16 ‖ month ‖ day ‖ hour ‖ minute ‖ second` (A-63 item 1) |
//! | etype | `i32` as four octets, big-endian |
//! | `Tier`, `AccountKind`, `ArmorPolicy`, failures | `u8` from a closed table |
//!
//! Spec: docs/50 §3.3 (primitives, "Kerberos values … as `bytes<max>`
//! containing DER", "KeyHandle = 16 octets PrincipalId + u8 purpose"), §3.4;
//! docs/questions/Q-245 item 1 (A-63: KerberosTime as six fixed fields).

use crate::channel::{
    codes, reply_kind, request_kind, ViewFailure, MAX_ENCTYPES, MAX_GROUPS, MAX_NAME, MAX_NC_LABEL,
    MAX_NC_LABELS, MAX_REALM, MAX_S2KPARAMS, MAX_SALT, MAX_SID,
};
use ipc::{DerBlob, Error, MessageSet, Payload, Reader, Result, Writer};
use kdc::{AccountKind, AccountSourceError, ArmorPolicy};
use keyd_types::{KeyHandle, PrincipalId};
use pdp::{PipError, Tier};

/// `KeyHandle` = `PrincipalId` (16 octets) ‖ purpose (`u8`).
/// Spec: docs/50 §3.3.
fn write_handle(writer: &mut Writer, handle: &KeyHandle) -> Result<()> {
    writer.write_array(handle.principal.as_bytes())?;
    writer.write_enum(codes::key_purpose(handle.purpose))
}

/// Spec: docs/50 §3.3.
fn read_handle(reader: &mut Reader<'_>) -> Result<KeyHandle> {
    let principal = PrincipalId::from_bytes(reader.read_array::<16>()?);
    let purpose = reader.read_enum(codes::key_purpose_from)?;
    Ok(KeyHandle::new(principal, purpose))
}

/// A signed 32-bit etype number as four octets, big-endian (RFC 3961 §8:
/// encryption type numbers are signed 32-bit).
fn write_etype(writer: &mut Writer, etype: i32) -> Result<()> {
    writer.write_array(&etype.to_be_bytes())
}

/// Spec: RFC 3961 §8.
fn read_etype(reader: &mut Reader<'_>) -> Result<i32> {
    Ok(i32::from_be_bytes(reader.read_array::<4>()?))
}

/// A SID packet as `bytes<MAX_SID>`. Spec: docs/50 §3.4; [MS-DTYP] 2.4.2.2.
fn write_sid(writer: &mut Writer, sid: &[u8]) -> Result<()> {
    writer.write_bytes(sid, MAX_SID)
}

/// Spec: docs/50 §3.4; [MS-DTYP] 2.4.2.2.
fn read_sid(reader: &mut Reader<'_>) -> Result<Vec<u8>> {
    Ok(reader.read_bytes(MAX_SID)?.to_vec())
}

/// A `KerberosTime` as six fixed-width calendar fields (checked by
/// `KerberosTime::new` in the typed layer).
/// Spec: docs/50 §3.3; RFC 4120 5.2.3; docs/questions/Q-245 item 1 (A-63).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireTime {
    /// Year.
    pub year: u16,
    /// Month.
    pub month: u8,
    /// Day of the month.
    pub day: u8,
    /// Hour.
    pub hour: u8,
    /// Minute.
    pub minute: u8,
    /// Second.
    pub second: u8,
}

impl Payload for WireTime {
    /// Spec: docs/50 §3.3; RFC 4120 5.2.3.
    fn write_fields(&self, writer: &mut Writer) -> Result<()> {
        writer.write_u16(self.year)?;
        writer.write_u8(self.month)?;
        writer.write_u8(self.day)?;
        writer.write_u8(self.hour)?;
        writer.write_u8(self.minute)?;
        writer.write_u8(self.second)
    }

    /// Spec: docs/50 §3.3; RFC 4120 5.2.3.
    fn read_fields(reader: &mut Reader<'_>) -> Result<WireTime> {
        let year = reader.read_u16()?;
        let month = reader.read_u8()?;
        let day = reader.read_u8()?;
        let hour = reader.read_u8()?;
        let minute = reader.read_u8()?;
        let second = reader.read_u8()?;
        Ok(WireTime {
            year,
            month,
            day,
            hour,
            minute,
            second,
        })
    }
}

/// `AccountState`: `enabled: bool ‖ locked: bool ‖ expires: Option<time> ‖
/// revoked_before: Option<time>`.
/// Spec: crates/kdc accounts.rs (`AccountState`); docs/47 §4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireState {
    /// Enabled.
    pub enabled: bool,
    /// Locked.
    pub locked: bool,
    /// Expiry.
    pub expires: Option<WireTime>,
    /// The hot-list cut (RFC 4120 3.3.3.1).
    pub revoked_before: Option<WireTime>,
}

impl Payload for WireState {
    /// Spec: crates/kdc accounts.rs; docs/50 §3.3.
    fn write_fields(&self, writer: &mut Writer) -> Result<()> {
        writer.write_bool(self.enabled)?;
        writer.write_bool(self.locked)?;
        writer.write_option(self.expires.as_ref(), |w, t| t.write_fields(w))?;
        writer.write_option(self.revoked_before.as_ref(), |w, t| t.write_fields(w))
    }

    /// Spec: crates/kdc accounts.rs; docs/50 §3.3.
    fn read_fields(reader: &mut Reader<'_>) -> Result<WireState> {
        let enabled = reader.read_bool()?;
        let locked = reader.read_bool()?;
        let expires = reader.read_option(WireTime::read_fields)?;
        let revoked_before = reader.read_option(WireTime::read_fields)?;
        Ok(WireState {
            enabled,
            locked,
            expires,
            revoked_before,
        })
    }
}

/// One ETYPE-INFO2 entry: `etype ‖ salt: Option<bytes<MAX_SALT>> ‖
/// s2kparams: Option<bytes<MAX_S2KPARAMS>>` (public string-to-key hints).
/// Spec: RFC 4120 5.2.7.5; crates/kdc accounts.rs (`etype_info`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireEtypeInfo {
    /// The encryption type number.
    pub etype: i32,
    /// The salt's KerberosString octets.
    pub salt: Option<Vec<u8>>,
    /// The string-to-key parameters.
    pub s2kparams: Option<Vec<u8>>,
}

impl Payload for WireEtypeInfo {
    /// Spec: RFC 4120 5.2.7.5; docs/50 §3.3.
    fn write_fields(&self, writer: &mut Writer) -> Result<()> {
        write_etype(writer, self.etype)?;
        writer.write_option(self.salt.as_ref(), |w, s| w.write_bytes(s, MAX_SALT))?;
        writer.write_option(self.s2kparams.as_ref(), |w, p| {
            w.write_bytes(p, MAX_S2KPARAMS)
        })
    }

    /// Spec: RFC 4120 5.2.7.5; docs/50 §3.3.
    fn read_fields(reader: &mut Reader<'_>) -> Result<WireEtypeInfo> {
        let etype = read_etype(reader)?;
        let salt = reader.read_option(|r| Ok(r.read_bytes(MAX_SALT)?.to_vec()))?;
        let s2kparams = reader.read_option(|r| Ok(r.read_bytes(MAX_S2KPARAMS)?.to_vec()))?;
        Ok(WireEtypeInfo {
            etype,
            salt,
            s2kparams,
        })
    }
}

/// A client record (`kdc::ClientAccount`, non-secret: a key handle, never a
/// key; salts are public).
/// Spec: docs/50 §3.4 (`Option<ClientAccount>` — key, sid, groups, tier,
/// state, etype_info, kind, armor_policy); crates/kdc accounts.rs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireClient {
    /// The keyd handle of the long-term key set.
    pub key: KeyHandle,
    /// The account SID packet.
    pub sid: Vec<u8>,
    /// The expanded group SID packets, in ascending SID order.
    pub groups: Vec<Vec<u8>>,
    /// The tier.
    pub tier: Tier,
    /// The account state.
    pub state: WireState,
    /// The ETYPE-INFO2 entries.
    pub etype_info: Vec<WireEtypeInfo>,
    /// User or computer.
    pub kind: AccountKind,
    /// The FAST armor policy.
    pub armor_policy: ArmorPolicy,
}

impl Payload for WireClient {
    /// Spec: docs/50 §3.4; crates/kdc accounts.rs.
    fn write_fields(&self, writer: &mut Writer) -> Result<()> {
        write_handle(writer, &self.key)?;
        write_sid(writer, &self.sid)?;
        writer.write_seq(&self.groups, MAX_GROUPS, |w, g| write_sid(w, g))?;
        writer.write_enum(codes::tier(self.tier))?;
        self.state.write_fields(writer)?;
        writer.write_seq(&self.etype_info, MAX_ENCTYPES, |w, e| e.write_fields(w))?;
        writer.write_enum(codes::account_kind(self.kind))?;
        writer.write_enum(codes::armor_policy(self.armor_policy))
    }

    /// Spec: docs/50 §3.4; crates/kdc accounts.rs.
    fn read_fields(reader: &mut Reader<'_>) -> Result<WireClient> {
        let key = read_handle(reader)?;
        let sid = read_sid(reader)?;
        let groups = reader.read_seq(MAX_GROUPS, read_sid)?;
        let tier = reader.read_enum(codes::tier_from)?;
        let state = WireState::read_fields(reader)?;
        let etype_info = reader.read_seq(MAX_ENCTYPES, WireEtypeInfo::read_fields)?;
        let kind = reader.read_enum(codes::account_kind_from)?;
        let armor_policy = reader.read_enum(codes::armor_policy_from)?;
        Ok(WireClient {
            key,
            sid,
            groups,
            tier,
            state,
            etype_info,
            kind,
            armor_policy,
        })
    }
}

/// A service record (`kdc::ServiceAccount`).
/// Spec: docs/50 §3.4 (`Option<ServiceAccount>`); crates/kdc accounts.rs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireService {
    /// The keyd handle of the service key set.
    pub key: KeyHandle,
    /// The account state.
    pub state: WireState,
    /// The encryption types the service accepts.
    pub enctypes: Vec<i32>,
}

impl Payload for WireService {
    /// Spec: docs/50 §3.4; crates/kdc accounts.rs.
    fn write_fields(&self, writer: &mut Writer) -> Result<()> {
        write_handle(writer, &self.key)?;
        self.state.write_fields(writer)?;
        writer.write_seq(&self.enctypes, MAX_ENCTYPES, |w, e| write_etype(w, *e))
    }

    /// Spec: docs/50 §3.4; crates/kdc accounts.rs.
    fn read_fields(reader: &mut Reader<'_>) -> Result<WireService> {
        let key = read_handle(reader)?;
        let state = WireState::read_fields(reader)?;
        let enctypes = reader.read_seq(MAX_ENCTYPES, read_etype)?;
        Ok(WireService {
            key,
            state,
            enctypes,
        })
    }
}

/// A request of the directory-view channel (client → dird).
///
/// No message carries a role, a uid or a `now`: the caller is the
/// connection's peer (docs/50 §3.2), and the view lifetime runs on dird's
/// own monotonic clock.
///
/// Spec: docs/50 §3.4 (the dird-kdc table), §7.5 (`Ping`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectoryRequest {
    /// `BeginView` (no field).
    BeginView,
    /// `Client { view, realm, name: DER }`.
    Client {
        /// The pinned view.
        view: u64,
        /// The realm's KerberosString octets.
        realm: Vec<u8>,
        /// The `PrincipalName` DER.
        name: DerBlob,
    },
    /// `Service { view, realm, name: DER }`.
    Service {
        /// The pinned view.
        view: u64,
        /// The realm's KerberosString octets.
        realm: Vec<u8>,
        /// The `PrincipalName` DER.
        name: DerBlob,
    },
    /// `ExpandGroups { view, sid }`.
    ExpandGroups {
        /// The pinned view.
        view: u64,
        /// The principal's SID packet.
        sid: Vec<u8>,
    },
    /// `TierOf { view, sid, groups: seq<Sid> }`.
    TierOf {
        /// The pinned view.
        view: u64,
        /// The principal's SID packet.
        sid: Vec<u8>,
        /// The group SID packets, in ascending SID order.
        groups: Vec<Vec<u8>>,
    },
    /// `EndView { view }`.
    EndView {
        /// The view to release.
        view: u64,
    },
    /// `DescribeDomain` (no field).
    DescribeDomain,
    /// `Ping` (no field).
    Ping,
}

impl MessageSet for DirectoryRequest {
    const KINDS: &'static [u8] = request_kind::ALL;

    fn kind(&self) -> u8 {
        match self {
            DirectoryRequest::BeginView => request_kind::BEGIN_VIEW,
            DirectoryRequest::Client { .. } => request_kind::CLIENT,
            DirectoryRequest::Service { .. } => request_kind::SERVICE,
            DirectoryRequest::ExpandGroups { .. } => request_kind::EXPAND_GROUPS,
            DirectoryRequest::TierOf { .. } => request_kind::TIER_OF,
            DirectoryRequest::EndView { .. } => request_kind::END_VIEW,
            DirectoryRequest::DescribeDomain => request_kind::DESCRIBE_DOMAIN,
            DirectoryRequest::Ping => request_kind::PING,
        }
    }

    /// Spec: docs/50 §3.4.
    fn write_payload(&self, writer: &mut Writer) -> Result<()> {
        match self {
            DirectoryRequest::BeginView
            | DirectoryRequest::DescribeDomain
            | DirectoryRequest::Ping => Ok(()),
            DirectoryRequest::Client { view, realm, name }
            | DirectoryRequest::Service { view, realm, name } => {
                writer.write_u64(*view)?;
                writer.write_bytes(realm, MAX_REALM)?;
                writer.write_der(name, MAX_NAME)
            }
            DirectoryRequest::ExpandGroups { view, sid } => {
                writer.write_u64(*view)?;
                write_sid(writer, sid)
            }
            DirectoryRequest::TierOf { view, sid, groups } => {
                writer.write_u64(*view)?;
                write_sid(writer, sid)?;
                writer.write_seq(groups, MAX_GROUPS, |w, g| write_sid(w, g))
            }
            DirectoryRequest::EndView { view } => writer.write_u64(*view),
        }
    }

    /// Spec: docs/50 §3.4.
    fn read_payload(kind: u8, reader: &mut Reader<'_>) -> Result<DirectoryRequest> {
        match kind {
            request_kind::BEGIN_VIEW => Ok(DirectoryRequest::BeginView),
            request_kind::CLIENT | request_kind::SERVICE => {
                let view = reader.read_u64()?;
                let realm = reader.read_bytes(MAX_REALM)?.to_vec();
                let name = reader.read_der(MAX_NAME)?;
                Ok(if kind == request_kind::CLIENT {
                    DirectoryRequest::Client { view, realm, name }
                } else {
                    DirectoryRequest::Service { view, realm, name }
                })
            }
            request_kind::EXPAND_GROUPS => {
                let view = reader.read_u64()?;
                let sid = read_sid(reader)?;
                Ok(DirectoryRequest::ExpandGroups { view, sid })
            }
            request_kind::TIER_OF => {
                let view = reader.read_u64()?;
                let sid = read_sid(reader)?;
                let groups = reader.read_seq(MAX_GROUPS, read_sid)?;
                Ok(DirectoryRequest::TierOf { view, sid, groups })
            }
            request_kind::END_VIEW => {
                let view = reader.read_u64()?;
                Ok(DirectoryRequest::EndView { view })
            }
            request_kind::DESCRIBE_DOMAIN => Ok(DirectoryRequest::DescribeDomain),
            request_kind::PING => Ok(DirectoryRequest::Ping),
            _ => Err(Error::UnknownKind),
        }
    }
}

/// A reply of the directory-view channel (dird → client). The shared
/// `ipc::Refused` travels beside it with `ipc::REFUSED_KIND` (A-59).
///
/// Spec: docs/50 §3.4; A-59.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectoryReply {
    /// `ViewBegun { view, policy_version }`.
    ViewBegun {
        /// The id of the view pinned to this connection.
        view: u64,
        /// The version of dird's policy (tier map) the view carries.
        policy_version: u64,
    },
    /// `Option<ClientAccount>`.
    Client(Option<WireClient>),
    /// `Option<ServiceAccount>`.
    Service(Option<WireService>),
    /// The expanded group SID packets, in ascending SID order.
    Groups(Vec<Vec<u8>>),
    /// The tier.
    Tier(Tier),
    /// `EndView` done.
    ViewEnded,
    /// The domain description.
    Domain {
        /// The realm's KerberosString octets.
        realm: Vec<u8>,
        /// The naming context's labels n1 … nk (leaf first).
        naming_context: Vec<Vec<u8>>,
        /// keyd's handle of the krbtgt key set.
        krbtgt: KeyHandle,
        /// The version of dird's policy.
        policy_version: u64,
    },
    /// `Ping` answered.
    Pong,
    /// The view's `AccountSourceError` for a `Client` / `Service` query.
    AccountFailure(AccountSourceError),
    /// The view's `PipError` for an `ExpandGroups` / `TierOf` query.
    PipFailure(PipError),
    /// The view protocol refused the request.
    ViewFailure(ViewFailure),
}

impl MessageSet for DirectoryReply {
    const KINDS: &'static [u8] = reply_kind::ALL;

    fn kind(&self) -> u8 {
        match self {
            DirectoryReply::ViewBegun { .. } => reply_kind::VIEW_BEGUN,
            DirectoryReply::Client(_) => reply_kind::CLIENT,
            DirectoryReply::Service(_) => reply_kind::SERVICE,
            DirectoryReply::Groups(_) => reply_kind::GROUPS,
            DirectoryReply::Tier(_) => reply_kind::TIER,
            DirectoryReply::ViewEnded => reply_kind::VIEW_ENDED,
            DirectoryReply::Domain { .. } => reply_kind::DOMAIN,
            DirectoryReply::Pong => reply_kind::PONG,
            DirectoryReply::AccountFailure(_) => reply_kind::ACCOUNT_FAILURE,
            DirectoryReply::PipFailure(_) => reply_kind::PIP_FAILURE,
            DirectoryReply::ViewFailure(_) => reply_kind::VIEW_FAILURE,
        }
    }

    /// Spec: docs/50 §3.4.
    fn write_payload(&self, writer: &mut Writer) -> Result<()> {
        match self {
            DirectoryReply::ViewBegun {
                view,
                policy_version,
            } => {
                writer.write_u64(*view)?;
                writer.write_u64(*policy_version)
            }
            DirectoryReply::Client(record) => {
                writer.write_option(record.as_ref(), |w, r| r.write_fields(w))
            }
            DirectoryReply::Service(record) => {
                writer.write_option(record.as_ref(), |w, r| r.write_fields(w))
            }
            DirectoryReply::Groups(groups) => {
                writer.write_seq(groups, MAX_GROUPS, |w, g| write_sid(w, g))
            }
            DirectoryReply::Tier(tier) => writer.write_enum(codes::tier(*tier)),
            DirectoryReply::ViewEnded | DirectoryReply::Pong => Ok(()),
            DirectoryReply::Domain {
                realm,
                naming_context,
                krbtgt,
                policy_version,
            } => {
                writer.write_bytes(realm, MAX_REALM)?;
                writer.write_seq(naming_context, MAX_NC_LABELS, |w, l| {
                    w.write_bytes(l, MAX_NC_LABEL)
                })?;
                write_handle(writer, krbtgt)?;
                writer.write_u64(*policy_version)
            }
            DirectoryReply::AccountFailure(error) => {
                writer.write_enum(codes::account_error(*error))
            }
            DirectoryReply::PipFailure(error) => writer.write_enum(codes::pip_error(*error)),
            DirectoryReply::ViewFailure(failure) => {
                writer.write_enum(codes::view_failure(*failure))
            }
        }
    }

    /// Spec: docs/50 §3.4.
    fn read_payload(kind: u8, reader: &mut Reader<'_>) -> Result<DirectoryReply> {
        match kind {
            reply_kind::VIEW_BEGUN => {
                let view = reader.read_u64()?;
                let policy_version = reader.read_u64()?;
                Ok(DirectoryReply::ViewBegun {
                    view,
                    policy_version,
                })
            }
            reply_kind::CLIENT => Ok(DirectoryReply::Client(
                reader.read_option(WireClient::read_fields)?,
            )),
            reply_kind::SERVICE => Ok(DirectoryReply::Service(
                reader.read_option(WireService::read_fields)?,
            )),
            reply_kind::GROUPS => Ok(DirectoryReply::Groups(
                reader.read_seq(MAX_GROUPS, read_sid)?,
            )),
            reply_kind::TIER => Ok(DirectoryReply::Tier(reader.read_enum(codes::tier_from)?)),
            reply_kind::VIEW_ENDED => Ok(DirectoryReply::ViewEnded),
            reply_kind::DOMAIN => {
                let realm = reader.read_bytes(MAX_REALM)?.to_vec();
                let naming_context =
                    reader.read_seq(MAX_NC_LABELS, |r| Ok(r.read_bytes(MAX_NC_LABEL)?.to_vec()))?;
                let krbtgt = read_handle(reader)?;
                let policy_version = reader.read_u64()?;
                Ok(DirectoryReply::Domain {
                    realm,
                    naming_context,
                    krbtgt,
                    policy_version,
                })
            }
            reply_kind::PONG => Ok(DirectoryReply::Pong),
            reply_kind::ACCOUNT_FAILURE => Ok(DirectoryReply::AccountFailure(
                reader.read_enum(codes::account_error_from)?,
            )),
            reply_kind::PIP_FAILURE => Ok(DirectoryReply::PipFailure(
                reader.read_enum(codes::pip_error_from)?,
            )),
            reply_kind::VIEW_FAILURE => Ok(DirectoryReply::ViewFailure(
                reader.read_enum(codes::view_failure_from)?,
            )),
            _ => Err(Error::UnknownKind),
        }
    }
}
