//! The event encoding: what a sender puts in each event of an `Append`, and
//! what the log keeps as a record's payload.
//!
//! ```text
//! Event := event_format:u8 (= 1) ‖ shape:u8 ‖ the shape's fields
//! shape := 1 Kdc | 2 Keyd | 3 Ldap | 4 WindowSummary | 5 DirAdmin | 6 Admind
//!        | 7 ZoneSerial
//! ```
//!
//! Each shape carries exactly the non-secret fields its source crate's
//! audit type already exposes (crates/kdc `AuditEvent`, crates/keyd
//! `AuditRecord`, crates/ldap `AuditEvent`), in their declared order, with
//! the `ipc` field primitives (one encoding per value, docs/50 §3.3). The
//! admin-plane shapes `DirAdmin` (dird) and `Admind` (admind) have no source
//! audit type yet; their fields are this crate's (crate::admin, docs/51
//! §5.7, task A7) — as are those of `ZoneSerial` (dird's serial-only zone
//! write, crate::zone; task DN10b, docs/questions/Q-1013).
//! **No field can hold a key, a password, a ticket, a PAC, a plaintext, a
//! ciphertext, a free attribute value or any request octet string** (the
//! `DirAdmin` request values are closed codes, Q-340 item 5): the types
//! are fixed-width integers, codes from closed tables, SIDs/GUIDs/principal
//! ids, bounded counts, and client strings kept only as printable ASCII of at
//! most 256 octets (else a marker). The sources' own audit types were built
//! the same way (crates/kdc audit.rs: "There is no field that could hold a
//! key, a password, a plaintext, a ticket or any other octet string from the
//! request"; crates/keyd audit.rs, I8; crates/ldap audit.rs).
//!
//! The source of an event (which process sent it) is **not** in the event:
//! auditd sets it from the connection's peer uid (docs/50 §3.2). Each shape
//! keeps the caller-supplied time its source recorded; the record keeps
//! auditd's own clock beside it.
//!
//! The largest encoding of every shape fits [`MAX_EVENT_OCTETS`] (tested),
//! so encoding an event built from this crate's types does not fail on
//! size.
//!
//! Spec: docs/50 §3.3, §8.1, §8.2; docs/37 §2 ("only identifiers and
//! metadata"); docs/10 I8; docs/49 §10.1; docs/questions/Q-252; docs/51
//! §5.7; docs/questions/Q-340.

use crate::admin::{AdmindEvent, DirAdminEvent};
use crate::codes::{
    BindMechanismCode, EventShape, IpZone, KdcExchange, KdcOutcomeCode, KdcReason, KdcTransport,
    KeyPurposeCode, KeydOperation, KeydOutcome, KeydReason, KeydRole, LdapAction,
    LdapOperationCode, LdapReason, LdapTargetCode, LdapTransport, SearchScope, UnsupportedOpCode,
};
use crate::error::EventError;
use crate::values::{
    read_opt, read_seq, write_opt, write_seq, AuditText, CalendarTime, CodecError, PdpReason,
    Principal, ReportedAddress, SidValue,
};
use crate::zone::ZoneSerialEvent;
use core::fmt;
use ipc::{FrameLimit, Reader, Writer};

/// Largest encoded event: 8 KiB. Spec: docs/50 §3.3 ("audit ≤ 8 KiB per
/// event").
pub const MAX_EVENT_OCTETS: u32 = 8 * 1024;

/// The one event format this build writes and reads (exact match).
/// Spec: docs/50 §3.3 (exact versions, no negotiation); docs/questions/Q-252
/// item 3.
pub const EVENT_FORMAT: u8 = 1;

/// Most filter attribute names a [`LdapSearch`] keeps (the rest are counted
/// as truncated). Project choice (bounds the event size;
/// docs/questions/Q-252 item 5).
pub const MAX_FILTER_ATTRS: usize = 16;

/// The bound handed to the `ipc` writer.
const EVENT_LIMIT: FrameLimit = match FrameLimit::new(MAX_EVENT_OCTETS) {
    Some(limit) => limit,
    None => panic!("MAX_EVENT_OCTETS is a valid ipc bound"),
};

// ---- kdc ----------------------------------------------------------------------

/// What the KDC did with a request: `kdc::AuditOutcome`.
/// Spec: crates/kdc audit.rs; RFC 4120 7.5.9 (the error code sent).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KdcOutcome {
    /// An AS-REP or TGS-REP was sent.
    Issued,
    /// A KRB-ERROR with this error code was sent.
    Refused {
        /// The error code sent.
        error_code: i32,
    },
    /// Nothing was sent.
    Dropped,
}

/// One KDC audit event: `kdc::AuditEvent`, field for field.
/// Spec: crates/kdc audit.rs (main-session decision 14; docs/48 §2.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KdcEvent {
    /// The caller-supplied time of the request.
    pub time: CalendarTime,
    /// The transport.
    pub transport: KdcTransport,
    /// The exchange, when the request decoded.
    pub exchange: Option<KdcExchange>,
    /// The client principal.
    pub client: Option<Principal>,
    /// The service principal.
    pub service: Option<Principal>,
    /// The FAST armor principal (`ArmorAudit::principal`).
    pub armor_principal: Option<Principal>,
    /// Whether the reply sent was armored (`ArmorAudit::reply_armored`).
    pub reply_armored: bool,
    /// The outcome.
    pub outcome: KdcOutcome,
    /// The internal reason.
    pub reason: KdcReason,
    /// The PDP reason, for [`KdcReason::PolicyDenied`].
    pub policy_reason: Option<PdpReason>,
}

impl KdcEvent {
    fn write(&self, writer: &mut Writer) -> Result<(), EventError> {
        self.time.write(writer)?;
        writer.write_enum(self.transport.code())?;
        write_opt(writer, self.exchange.as_ref(), |e, w| {
            Ok(w.write_enum(e.code())?)
        })?;
        write_opt(writer, self.client.as_ref(), Principal::write)?;
        write_opt(writer, self.service.as_ref(), Principal::write)?;
        write_opt(writer, self.armor_principal.as_ref(), Principal::write)?;
        writer.write_bool(self.reply_armored)?;
        match self.outcome {
            KdcOutcome::Issued => writer.write_enum(KdcOutcomeCode::Issued.code())?,
            KdcOutcome::Refused { error_code } => {
                writer.write_enum(KdcOutcomeCode::Refused.code())?;
                writer.write_u32(u32::from_be_bytes(error_code.to_be_bytes()))?;
            }
            KdcOutcome::Dropped => writer.write_enum(KdcOutcomeCode::Dropped.code())?,
        }
        writer.write_enum(self.reason.code())?;
        write_opt(writer, self.policy_reason.as_ref(), PdpReason::write)
    }

    fn read(reader: &mut Reader<'_>) -> Result<KdcEvent, EventError> {
        let time = CalendarTime::read(reader)?;
        let transport = reader.read_enum(KdcTransport::from_code)?;
        let exchange = read_opt(reader, |r| Ok(r.read_enum(KdcExchange::from_code)?))?;
        let client = read_opt(reader, Principal::read)?;
        let service = read_opt(reader, Principal::read)?;
        let armor_principal = read_opt(reader, Principal::read)?;
        let reply_armored = reader.read_bool()?;
        let outcome = match reader.read_enum(KdcOutcomeCode::from_code)? {
            KdcOutcomeCode::Issued => KdcOutcome::Issued,
            KdcOutcomeCode::Refused => KdcOutcome::Refused {
                error_code: i32::from_be_bytes(reader.read_u32()?.to_be_bytes()),
            },
            KdcOutcomeCode::Dropped => KdcOutcome::Dropped,
        };
        let reason = reader.read_enum(KdcReason::from_code)?;
        let policy_reason = read_opt(reader, PdpReason::read)?;
        Ok(KdcEvent {
            time,
            transport,
            exchange,
            client,
            service,
            armor_principal,
            reply_armored,
            outcome,
            reason,
            policy_reason,
        })
    }
}

// ---- keyd ---------------------------------------------------------------------

/// A key referenced by a keyd operation: `keyd::AuditKeyRef` (no key
/// material). Spec: docs/10 §10.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyRef {
    /// The key set's principal id (16 octets).
    pub principal: [u8; 16],
    /// The key set's purpose.
    pub purpose: KeyPurposeCode,
    /// The key version, when resolved.
    pub kvno: Option<u32>,
}

impl KeyRef {
    fn write(&self, writer: &mut Writer) -> Result<(), EventError> {
        writer.write_array(&self.principal)?;
        writer.write_enum(self.purpose.code())?;
        write_opt(writer, self.kvno.as_ref(), |k, w| Ok(w.write_u32(*k)?))
    }

    fn read(reader: &mut Reader<'_>) -> Result<KeyRef, EventError> {
        let principal = reader.read_array::<16>()?;
        let purpose = reader.read_enum(KeyPurposeCode::from_code)?;
        let kvno = read_opt(reader, |r| Ok(r.read_u32()?))?;
        Ok(KeyRef {
            principal,
            purpose,
            kvno,
        })
    }
}

/// One keyd audit record: `keyd::AuditRecord`, field for field
/// (docs/10 §10: `{ ts, caller_role, caller_uid, op, principal, purpose,
/// kvno, result }` + reason, secondary, approvers, and — appended by A-102,
/// docs/52 §4.5 — the `decision` a Directory / Admin state change
/// registered or ran: the field a detection rule matches against dird's
/// `DirAdmin` event).
///
/// **Phase records** (decision A-86): around an operation that changes
/// keyd's key state, keyd-daemon also writes, with the same layout, the
/// record of the intent (`result` = [`KeydOutcome::Intent`]) before keyd
/// runs it and — only if that intent was not acknowledged in time — a
/// [`KeydOutcome::NotPerformed`] outcome. Field use there: `ts`, the caller,
/// `op`, the handle's `principal` / `purpose` as in keyd's record; `kvno`
/// only for `RetireKvno` (the version named); `approvers` and `decision`
/// from keyd's decision (A-102: never from the request); `secondary` for a
/// computer's second set-secret target or a destroyed account's `Service`
/// key set; `reason` = `None`. As for the other
/// shapes, the codec checks the encoding, not the field use
/// (docs/questions/Q-252 item 4); the layout is unchanged — the two phases
/// are codes 6 and 7 of the closed outcome table.
///
/// Spec: crates/keyd audit.rs; docs/10 §10, I8; docs/questions/Q-346
/// (A-86), Q-365.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeydRecord {
    /// The caller-supplied time of the operation.
    pub ts: CalendarTime,
    /// The caller's role.
    pub caller_role: KeydRole,
    /// The caller's uid (as keyd recorded it).
    pub caller_uid: u32,
    /// The operation.
    pub op: KeydOperation,
    /// The primary handle's principal id.
    pub principal: Option<[u8; 16]>,
    /// The primary handle's purpose.
    pub purpose: Option<KeyPurposeCode>,
    /// The key version used or produced.
    pub kvno: Option<u32>,
    /// A second key used by the operation.
    pub secondary: Option<KeyRef>,
    /// Dual-control approvers.
    pub approvers: Option<[[u8; 16]; 2]>,
    /// The outcome.
    pub result: KeydOutcome,
    /// The internal reason.
    pub reason: KeydReason,
    /// The decision id the operation registered or ran (A-102).
    pub decision: Option<u64>,
}

impl KeydRecord {
    fn write(&self, writer: &mut Writer) -> Result<(), EventError> {
        self.ts.write(writer)?;
        writer.write_enum(self.caller_role.code())?;
        writer.write_u32(self.caller_uid)?;
        writer.write_enum(self.op.code())?;
        write_opt(
            writer,
            self.principal.as_ref(),
            |p, w| Ok(w.write_array(p)?),
        )?;
        write_opt(writer, self.purpose.as_ref(), |p, w| {
            Ok(w.write_enum(p.code())?)
        })?;
        write_opt(writer, self.kvno.as_ref(), |k, w| Ok(w.write_u32(*k)?))?;
        write_opt(writer, self.secondary.as_ref(), KeyRef::write)?;
        write_opt(writer, self.approvers.as_ref(), |[a, b], w| {
            w.write_array(a)?;
            Ok(w.write_array(b)?)
        })?;
        writer.write_enum(self.result.code())?;
        writer.write_enum(self.reason.code())?;
        write_opt(writer, self.decision.as_ref(), |d, w| Ok(w.write_u64(*d)?))
    }

    fn read(reader: &mut Reader<'_>) -> Result<KeydRecord, EventError> {
        let ts = CalendarTime::read(reader)?;
        let caller_role = reader.read_enum(KeydRole::from_code)?;
        let caller_uid = reader.read_u32()?;
        let op = reader.read_enum(KeydOperation::from_code)?;
        let principal = read_opt(reader, |r| Ok(r.read_array::<16>()?))?;
        let purpose = read_opt(reader, |r| Ok(r.read_enum(KeyPurposeCode::from_code)?))?;
        let kvno = read_opt(reader, |r| Ok(r.read_u32()?))?;
        let secondary = read_opt(reader, KeyRef::read)?;
        let approvers = read_opt(reader, |r| {
            Ok([r.read_array::<16>()?, r.read_array::<16>()?])
        })?;
        let result = reader.read_enum(KeydOutcome::from_code)?;
        let reason = reader.read_enum(KeydReason::from_code)?;
        let decision = read_opt(reader, |r| Ok(r.read_u64()?))?;
        Ok(KeydRecord {
            ts,
            caller_role,
            caller_uid,
            op,
            principal,
            purpose,
            kvno,
            secondary,
            approvers,
            result,
            reason,
            decision,
        })
    }
}

// ---- ldap ---------------------------------------------------------------------

/// The transport security the engine attributed: `pdp::TransportSec`.
/// Spec: docs/49 §4.3, §10.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TransportSecurity {
    /// Encrypted (TLS established with an AEAD suite).
    pub encrypted: bool,
    /// Sealed (SASL layer).
    pub sealed: bool,
    /// Channel-bound.
    pub channel_bound: bool,
}

/// The LDAP operation: `ldap::AuditOperation`.
/// Spec: crates/ldap audit.rs; RFC 4511 §4.1.1 (as cited there).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(missing_docs)]
pub enum LdapOperation {
    Bind,
    Unbind,
    Search,
    Abandon,
    StartTls,
    Extended,
    /// A recognised operation not performed in phase 1 (A-48).
    NotSupported(UnsupportedOpCode),
    Malformed,
    NotDecoded,
}

impl LdapOperation {
    fn code(self) -> LdapOperationCode {
        match self {
            LdapOperation::Bind => LdapOperationCode::Bind,
            LdapOperation::Unbind => LdapOperationCode::Unbind,
            LdapOperation::Search => LdapOperationCode::Search,
            LdapOperation::Abandon => LdapOperationCode::Abandon,
            LdapOperation::StartTls => LdapOperationCode::StartTls,
            LdapOperation::Extended => LdapOperationCode::Extended,
            LdapOperation::NotSupported(_) => LdapOperationCode::NotSupported,
            LdapOperation::Malformed => LdapOperationCode::Malformed,
            LdapOperation::NotDecoded => LdapOperationCode::NotDecoded,
        }
    }

    fn write(&self, writer: &mut Writer) -> Result<(), EventError> {
        writer.write_enum(self.code().code())?;
        if let LdapOperation::NotSupported(op) = self {
            writer.write_enum(op.code())?;
        }
        Ok(())
    }

    fn read(reader: &mut Reader<'_>) -> Result<LdapOperation, EventError> {
        Ok(match reader.read_enum(LdapOperationCode::from_code)? {
            LdapOperationCode::Bind => LdapOperation::Bind,
            LdapOperationCode::Unbind => LdapOperation::Unbind,
            LdapOperationCode::Search => LdapOperation::Search,
            LdapOperationCode::Abandon => LdapOperation::Abandon,
            LdapOperationCode::StartTls => LdapOperation::StartTls,
            LdapOperationCode::Extended => LdapOperation::Extended,
            LdapOperationCode::NotSupported => {
                LdapOperation::NotSupported(reader.read_enum(UnsupportedOpCode::from_code)?)
            }
            LdapOperationCode::Malformed => LdapOperation::Malformed,
            LdapOperationCode::NotDecoded => LdapOperation::NotDecoded,
        })
    }
}

/// The bind mechanism: `ldap::BindMechanism`. Never a credential.
/// Spec: crates/ldap audit.rs; RFC 4513 §5.1, §5.2 (as cited there).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BindMechanism {
    /// Simple, empty name and password.
    SimpleAnonymous,
    /// Simple, a name and an empty password.
    SimpleUnauthenticated,
    /// Simple with a password (refused; the password never reaches the
    /// engine, A-52).
    SimplePassword,
    /// SASL, with the mechanism name the client sent.
    Sasl {
        /// The mechanism name.
        mechanism: AuditText,
    },
    /// An AuthenticationChoice with no code path.
    Unrecognized {
        /// The context-specific tag number.
        tag_number: u8,
    },
}

impl BindMechanism {
    fn write(&self, writer: &mut Writer) -> Result<(), EventError> {
        match self {
            BindMechanism::SimpleAnonymous => {
                writer.write_enum(BindMechanismCode::SimpleAnonymous.code())?;
            }
            BindMechanism::SimpleUnauthenticated => {
                writer.write_enum(BindMechanismCode::SimpleUnauthenticated.code())?;
            }
            BindMechanism::SimplePassword => {
                writer.write_enum(BindMechanismCode::SimplePassword.code())?;
            }
            BindMechanism::Sasl { mechanism } => {
                writer.write_enum(BindMechanismCode::Sasl.code())?;
                mechanism.write(writer)?;
            }
            BindMechanism::Unrecognized { tag_number } => {
                writer.write_enum(BindMechanismCode::Unrecognized.code())?;
                writer.write_u8(*tag_number)?;
            }
        }
        Ok(())
    }

    fn read(reader: &mut Reader<'_>) -> Result<BindMechanism, EventError> {
        Ok(match reader.read_enum(BindMechanismCode::from_code)? {
            BindMechanismCode::SimpleAnonymous => BindMechanism::SimpleAnonymous,
            BindMechanismCode::SimpleUnauthenticated => BindMechanism::SimpleUnauthenticated,
            BindMechanismCode::SimplePassword => BindMechanism::SimplePassword,
            BindMechanismCode::Sasl => BindMechanism::Sasl {
                mechanism: AuditText::read(reader)?,
            },
            BindMechanismCode::Unrecognized => BindMechanism::Unrecognized {
                tag_number: reader.read_u8()?,
            },
        })
    }
}

/// The bind facts: `ldap::BindAudit`. Spec: docs/49 §10.1.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LdapBind {
    /// The LDAP version asked for.
    pub version: u8,
    /// The mechanism.
    pub mechanism: BindMechanism,
    /// The bind name, when not empty (trace only, RFC 4513 §5.1.2).
    pub name: Option<AuditText>,
}

impl LdapBind {
    fn write(&self, writer: &mut Writer) -> Result<(), EventError> {
        writer.write_u8(self.version)?;
        self.mechanism.write(writer)?;
        write_opt(writer, self.name.as_ref(), AuditText::write)
    }

    fn read(reader: &mut Reader<'_>) -> Result<LdapBind, EventError> {
        let version = reader.read_u8()?;
        let mechanism = BindMechanism::read(reader)?;
        let name = read_opt(reader, AuditText::read)?;
        Ok(LdapBind {
            version,
            mechanism,
            name,
        })
    }
}

/// What a request was about, once resolved: `ldap::AuditTarget`.
/// Spec: docs/49 §10.1 (`target: Option<Guid>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LdapTarget {
    /// The rootDSE.
    RootDse,
    /// A directory object, by its objectGUID (16 octets, packet order).
    DirObject([u8; 16]),
}

impl LdapTarget {
    fn write(&self, writer: &mut Writer) -> Result<(), EventError> {
        match self {
            LdapTarget::RootDse => writer.write_enum(LdapTargetCode::RootDse.code())?,
            LdapTarget::DirObject(guid) => {
                writer.write_enum(LdapTargetCode::DirObject.code())?;
                writer.write_array(guid)?;
            }
        }
        Ok(())
    }

    fn read(reader: &mut Reader<'_>) -> Result<LdapTarget, EventError> {
        Ok(match reader.read_enum(LdapTargetCode::from_code)? {
            LdapTargetCode::RootDse => LdapTarget::RootDse,
            LdapTargetCode::DirObject => LdapTarget::DirObject(reader.read_array::<16>()?),
        })
    }
}

/// The search facts: `ldap::SearchAudit` — counts and schema names only.
/// At most [`MAX_FILTER_ATTRS`] attribute names are kept;
/// [`LdapSearch::filter_attrs_truncated`] says whether more were named.
/// Spec: docs/49 §10.1.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LdapSearch {
    /// The requested scope.
    pub scope: SearchScope,
    /// SearchResultEntry messages sent.
    pub entries_returned: u32,
    /// Candidate objects read and evaluated.
    pub candidates_visited: u32,
    /// Containers not descended into.
    pub pruned_subtrees: u32,
    filter_attrs: Vec<AuditText>,
    filter_attrs_truncated: bool,
}

impl LdapSearch {
    /// Search facts; `filter_attrs` beyond [`MAX_FILTER_ATTRS`] are dropped
    /// and marked as truncated.
    #[must_use]
    pub fn new(
        scope: SearchScope,
        entries_returned: u32,
        candidates_visited: u32,
        pruned_subtrees: u32,
        mut filter_attrs: Vec<AuditText>,
    ) -> LdapSearch {
        let filter_attrs_truncated = filter_attrs.len() > MAX_FILTER_ATTRS;
        filter_attrs.truncate(MAX_FILTER_ATTRS);
        LdapSearch {
            scope,
            entries_returned,
            candidates_visited,
            pruned_subtrees,
            filter_attrs,
            filter_attrs_truncated,
        }
    }

    /// The filter's attribute names kept.
    #[must_use]
    pub fn filter_attrs(&self) -> &[AuditText] {
        &self.filter_attrs
    }

    /// Whether the filter named more attributes than were kept.
    #[must_use]
    pub fn filter_attrs_truncated(&self) -> bool {
        self.filter_attrs_truncated
    }

    fn write(&self, writer: &mut Writer) -> Result<(), EventError> {
        writer.write_enum(self.scope.code())?;
        writer.write_u32(self.entries_returned)?;
        writer.write_u32(self.candidates_visited)?;
        writer.write_u32(self.pruned_subtrees)?;
        write_seq(
            writer,
            &self.filter_attrs,
            MAX_FILTER_ATTRS,
            AuditText::write,
        )?;
        Ok(writer.write_bool(self.filter_attrs_truncated)?)
    }

    fn read(reader: &mut Reader<'_>) -> Result<LdapSearch, EventError> {
        let scope = reader.read_enum(SearchScope::from_code)?;
        let entries_returned = reader.read_u32()?;
        let candidates_visited = reader.read_u32()?;
        let pruned_subtrees = reader.read_u32()?;
        let filter_attrs = read_seq(reader, MAX_FILTER_ATTRS, AuditText::read)?;
        let filter_attrs_truncated = reader.read_bool()?;
        Ok(LdapSearch {
            scope,
            entries_returned,
            candidates_visited,
            pruned_subtrees,
            filter_attrs,
            filter_attrs_truncated,
        })
    }
}

/// One LDAP audit event: `ldap::AuditEvent`, field for field, plus the
/// client address ldap-front reported, which dird adds (the engine never
/// sees it — docs/52 R14).
/// Spec: crates/ldap audit.rs; docs/49 §10.1 (R49-14); docs/52 §7 R14.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdapEvent {
    /// The caller-supplied time.
    pub time: CalendarTime,
    /// The engine's connection identifier.
    pub connection_id: u64,
    /// The source zone the decision was made under: the zone of the front
    /// the client came through, derived by dird from the front's peer uid
    /// (docs/52 R14) — not from [`LdapEvent::reported_peer`].
    pub source_zone: IpZone,
    /// The client address **as ldap-front reported it** — an unverified
    /// observation (the front owns the TCP socket), kept for the
    /// investigator; no decision was derived from it.
    /// Spec: docs/52 §7 R14; docs/questions/Q-581.
    pub reported_peer: ReportedAddress,
    /// How the connection is carried.
    pub transport: LdapTransport,
    /// The transport security attributed to the request.
    pub transport_sec: TransportSecurity,
    /// The operation.
    pub operation: LdapOperation,
    /// The MessageID, once decoded.
    pub message_id: Option<u32>,
    /// The requester's SID (`None` = anonymous).
    pub principal: Option<SidValue>,
    /// The bind facts.
    pub bind: Option<LdapBind>,
    /// The resolved target.
    pub target: Option<LdapTarget>,
    /// The search facts.
    pub search: Option<LdapSearch>,
    /// The resultCode sent (RFC 4511 §4.1.9 value).
    pub result_code: Option<u8>,
    /// The resultCode of the Notice of Disconnection sent.
    pub notice: Option<u8>,
    /// The connection action.
    pub action: LdapAction,
    /// The internal reason.
    pub reason: LdapReason,
    /// The PDP reason, for [`LdapReason::PolicyDenied`].
    pub policy_reason: Option<PdpReason>,
    /// The codec error, for [`LdapReason::Malformed`].
    pub codec_error: Option<CodecError>,
}

impl LdapEvent {
    fn write(&self, writer: &mut Writer) -> Result<(), EventError> {
        self.time.write(writer)?;
        writer.write_u64(self.connection_id)?;
        writer.write_enum(self.source_zone.code())?;
        self.reported_peer.write(writer)?;
        writer.write_enum(self.transport.code())?;
        writer.write_bool(self.transport_sec.encrypted)?;
        writer.write_bool(self.transport_sec.sealed)?;
        writer.write_bool(self.transport_sec.channel_bound)?;
        self.operation.write(writer)?;
        write_opt(writer, self.message_id.as_ref(), |id, w| {
            Ok(w.write_u32(*id)?)
        })?;
        write_opt(writer, self.principal.as_ref(), SidValue::write)?;
        write_opt(writer, self.bind.as_ref(), LdapBind::write)?;
        write_opt(writer, self.target.as_ref(), LdapTarget::write)?;
        write_opt(writer, self.search.as_ref(), LdapSearch::write)?;
        write_opt(
            writer,
            self.result_code.as_ref(),
            |c, w| Ok(w.write_u8(*c)?),
        )?;
        write_opt(writer, self.notice.as_ref(), |c, w| Ok(w.write_u8(*c)?))?;
        writer.write_enum(self.action.code())?;
        writer.write_enum(self.reason.code())?;
        write_opt(writer, self.policy_reason.as_ref(), PdpReason::write)?;
        write_opt(writer, self.codec_error.as_ref(), CodecError::write)
    }

    fn read(reader: &mut Reader<'_>) -> Result<LdapEvent, EventError> {
        let time = CalendarTime::read(reader)?;
        let connection_id = reader.read_u64()?;
        let source_zone = reader.read_enum(IpZone::from_code)?;
        let reported_peer = ReportedAddress::read(reader)?;
        let transport = reader.read_enum(LdapTransport::from_code)?;
        let transport_sec = TransportSecurity {
            encrypted: reader.read_bool()?,
            sealed: reader.read_bool()?,
            channel_bound: reader.read_bool()?,
        };
        let operation = LdapOperation::read(reader)?;
        let message_id = read_opt(reader, |r| Ok(r.read_u32()?))?;
        let principal = read_opt(reader, SidValue::read)?;
        let bind = read_opt(reader, LdapBind::read)?;
        let target = read_opt(reader, LdapTarget::read)?;
        let search = read_opt(reader, LdapSearch::read)?;
        let result_code = read_opt(reader, |r| Ok(r.read_u8()?))?;
        let notice = read_opt(reader, |r| Ok(r.read_u8()?))?;
        let action = reader.read_enum(LdapAction::from_code)?;
        let reason = reader.read_enum(LdapReason::from_code)?;
        let policy_reason = read_opt(reader, PdpReason::read)?;
        let codec_error = read_opt(reader, CodecError::read)?;
        Ok(LdapEvent {
            time,
            connection_id,
            source_zone,
            reported_peer,
            transport,
            transport_sec,
            operation,
            message_id,
            principal,
            bind,
            target,
            search,
            result_code,
            notice,
            action,
            reason,
            policy_reason,
            codec_error,
        })
    }
}

// ---- the window summary ------------------------------------------------------

/// What a sender's window could not record one by one since its last
/// summary: unauthenticated noise counted instead of queued,
/// issuance-gating operations refused because the window was full, and
/// outcome records that could not be put into the window although their
/// operation's intent or decision was already recorded (keyd-daemon's
/// key-state changes, A-86; dird's admin writes, A-85) — the log then holds
/// that intent or decision without the outcome that should follow it.
///
/// ```text
/// WindowSummary := suppressed_noise:u64 ‖ refused_gating:u64
///                  ‖ unrecorded_outcomes:u64
/// ```
///
/// Three fixed-width counters, every value valid, so each summary has
/// exactly one encoding (24 octets after the format and shape octets) and
/// any other length is refused (docs/50 §3.3). The third counter was
/// appended by task F4 (decision A-88; docs/questions/Q-366 option (a),
/// Q-395): before it, a lost outcome could only be noted on stderr, and
/// counting it as `refused_gating` would have told a reader the operation
/// was refused — not done — when it may well have been done. A sender with
/// no two-record operations (kdc-daemon; dird's LDAP events) leaves it 0.
///
/// Spec: docs/questions/Q-218 option (a), decided A-57 ("unauthenticated
/// noise events … are summarised in counters and rate-limited"; "no
/// unaudited issuance"); docs/37 §5 (the visibility gap is itself a
/// signal); docs/questions/Q-366 (A-88), Q-395.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WindowSummary {
    /// Noise events counted, not queued.
    pub suppressed_noise: u64,
    /// Gating reservations refused (window full).
    pub refused_gating: u64,
    /// Outcome records that could not be committed after their intent or
    /// decision was recorded: each is an intent (keyd-daemon, A-86) or a
    /// decision (dird, A-85) in the log with no outcome after it. Not a
    /// refusal (A-88).
    pub unrecorded_outcomes: u64,
}

impl WindowSummary {
    /// Spec: this type's layout; docs/50 §3.3 (fixed width, big-endian).
    fn write(&self, writer: &mut Writer) -> Result<(), EventError> {
        writer.write_u64(self.suppressed_noise)?;
        writer.write_u64(self.refused_gating)?;
        Ok(writer.write_u64(self.unrecorded_outcomes)?)
    }

    /// Spec: this type's layout; docs/50 §3.3 (strict; the caller refuses
    /// trailing octets).
    fn read(reader: &mut Reader<'_>) -> Result<WindowSummary, EventError> {
        Ok(WindowSummary {
            suppressed_noise: reader.read_u64()?,
            refused_gating: reader.read_u64()?,
            unrecorded_outcomes: reader.read_u64()?,
        })
    }
}

// ---- the envelope --------------------------------------------------------------

/// One audit event, of one of the shapes.
///
/// Spec: docs/50 §8.1; docs/questions/Q-252 item 3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventBody {
    /// A KDC event.
    Kdc(Box<KdcEvent>),
    /// A keyd record.
    Keyd(Box<KeydRecord>),
    /// An LDAP event (written by dird, R49-14).
    Ldap(Box<LdapEvent>),
    /// A sender window's summary (A-57).
    WindowSummary(WindowSummary),
    /// An admin-plane decision or outcome (written by dird, docs/51 §5.7).
    DirAdmin(Box<DirAdminEvent>),
    /// An admind event (docs/51 §5.7 item 3).
    Admind(Box<AdmindEvent>),
    /// dird's serial-only zone write: a decision or outcome (task DN10b;
    /// docs/questions/Q-1002, Q-1013).
    ZoneSerial(Box<ZoneSerialEvent>),
}

impl EventBody {
    /// The shape tag.
    #[must_use]
    pub fn shape(&self) -> EventShape {
        match self {
            EventBody::Kdc(_) => EventShape::Kdc,
            EventBody::Keyd(_) => EventShape::Keyd,
            EventBody::Ldap(_) => EventShape::Ldap,
            EventBody::WindowSummary(_) => EventShape::WindowSummary,
            EventBody::DirAdmin(_) => EventShape::DirAdmin,
            EventBody::Admind(_) => EventShape::Admind,
            EventBody::ZoneSerial(_) => EventShape::ZoneSerial,
        }
    }
}

/// One encoded event: 1 to [`MAX_EVENT_OCTETS`] octets. What an `Append`
/// carries and what the log keeps as a record's payload; opaque to auditd.
///
/// Not secret (docs/37 §2), so `Debug` shows only the length — the octets
/// are for the log, not for operational output (docs/50 §8.2).
///
/// Spec: docs/50 §3.3, §8.1.
#[derive(Clone, PartialEq, Eq)]
pub struct EventBytes(Vec<u8>);

impl fmt::Debug for EventBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventBytes")
            .field("len", &self.0.len())
            .finish()
    }
}

impl EventBytes {
    /// Wrap encoded octets, or `None` if empty or over
    /// [`MAX_EVENT_OCTETS`].
    #[must_use]
    pub fn new(octets: Vec<u8>) -> Option<EventBytes> {
        let len = u32::try_from(octets.len()).ok()?;
        (1..=MAX_EVENT_OCTETS)
            .contains(&len)
            .then_some(EventBytes(octets))
    }

    /// The octets.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The octets, by value.
    #[must_use]
    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }

    /// Octets in the event.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Always `false`.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Encode an event.
///
/// # Errors
/// [`EventError::Codec`] if the encoding would exceed [`MAX_EVENT_OCTETS`]
/// (cannot happen for an event built from this crate's types — every
/// shape's largest encoding fits, which the tests check).
///
/// Spec: docs/50 §3.3, §8.1.
pub fn encode_event(event: &EventBody) -> Result<EventBytes, EventError> {
    let mut writer = Writer::new(EVENT_LIMIT);
    writer.write_u8(EVENT_FORMAT)?;
    writer.write_enum(event.shape().code())?;
    match event {
        EventBody::Kdc(kdc) => kdc.write(&mut writer)?,
        EventBody::Keyd(keyd) => keyd.write(&mut writer)?,
        EventBody::Ldap(ldap) => ldap.write(&mut writer)?,
        EventBody::WindowSummary(summary) => summary.write(&mut writer)?,
        EventBody::DirAdmin(admin) => admin.write(&mut writer)?,
        EventBody::Admind(admind) => admind.write(&mut writer)?,
        EventBody::ZoneSerial(zone) => zone.write(&mut writer)?,
    }
    // The payload holds no secret (docs/37 §2); the zeroizing buffer of the
    // ipc writer is simply copied out.
    let octets = writer.into_payload().to_vec();
    EventBytes::new(octets).ok_or(EventError::Codec(ipc::Error::BodyOverBound))
}

/// Decode an event: exact format version, closed shape and code tables,
/// every bound, and no octet after the last field.
///
/// # Errors
/// [`EventError`].
///
/// Spec: docs/50 §3.3 (strict decoding; "no trailing byte").
pub fn decode_event(octets: &[u8]) -> Result<EventBody, EventError> {
    if octets.len() > MAX_EVENT_OCTETS as usize {
        return Err(EventError::Codec(ipc::Error::LengthOverBound));
    }
    let mut reader = Reader::new(octets);
    if reader.read_u8()? != EVENT_FORMAT {
        return Err(EventError::UnsupportedFormat);
    }
    let event = match reader.read_enum(EventShape::from_code)? {
        EventShape::Kdc => EventBody::Kdc(Box::new(KdcEvent::read(&mut reader)?)),
        EventShape::Keyd => EventBody::Keyd(Box::new(KeydRecord::read(&mut reader)?)),
        EventShape::Ldap => EventBody::Ldap(Box::new(LdapEvent::read(&mut reader)?)),
        EventShape::WindowSummary => EventBody::WindowSummary(WindowSummary::read(&mut reader)?),
        EventShape::DirAdmin => EventBody::DirAdmin(Box::new(DirAdminEvent::read(&mut reader)?)),
        EventShape::Admind => EventBody::Admind(Box::new(AdmindEvent::read(&mut reader)?)),
        EventShape::ZoneSerial => {
            EventBody::ZoneSerial(Box::new(ZoneSerialEvent::read(&mut reader)?))
        }
    };
    reader.finish()?;
    Ok(event)
}

/// The shape an encoded event declares — its first two octets only — or
/// `None` if the format octet is not [`EVENT_FORMAT`] or the shape code is
/// outside the closed table. **Nothing else is checked**: this is not a
/// decoder, and `Some` does not mean the event decodes.
///
/// auditd uses it to refuse a shape from a source that may not send it
/// (crate audit-daemon; docs/questions/Q-341) while keeping the payloads
/// opaque, so no event parser is added to auditd (AGENTS.md §6).
///
/// Spec: docs/50 §3.2 (the source comes from the transport), §3.3, §8.1;
/// docs/51 §5.7; docs/questions/Q-341.
#[must_use]
pub fn peek_shape(octets: &[u8]) -> Option<EventShape> {
    match octets {
        [format, shape, ..] if *format == EVENT_FORMAT => EventShape::from_code(*shape),
        _ => None,
    }
}

/// The canonical round trip for one event: decode, encode, compare.
/// `Err` — refused (not a property failure); `Ok(false)` — a codec bug.
///
/// Spec: docs/50 §3.3 ("every decoder checks `encode(decode(b)) == b`").
pub fn event_round_trip_is_canonical(octets: &[u8]) -> Result<bool, EventError> {
    let event = decode_event(octets)?;
    Ok(encode_event(&event)?.as_bytes() == octets)
}
