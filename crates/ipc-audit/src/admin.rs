//! The admin-plane event shapes: `DirAdmin` (sent by dird) and `Admind`
//! (sent by admind).
//!
//! # Who sends what (docs/51 §5.7, R51-12, decided A-72)
//!
//! * **dird is the source of the admin write events** — the decision is
//!   made there (§7.4). Every admin operation produces a [`DirAdminEvent`]
//!   with [`DirAdminStage::Decision`] after `decide`; for an operation that
//!   writes the directory, that event is **acknowledged by auditd before the
//!   commit**, and a second event with [`DirAdminStage::Outcome`] follows the
//!   commit. auditd unavailable ⇒ the operation is refused before the commit
//!   (§5.7 item 2). An operation that commits nothing to the directory
//!   (`Lookup`, `CompletePasswordSet`, the pending key-operation requests)
//!   has its `Decision` event only, sent before the reply (Q-340 item 1).
//! * **admind** sends its own [`AdmindEvent`]s: a refused connection, a
//!   malformed frame, a `SetPassword` completed or failed (§5.7 item 3), and
//!   the keyadm-only requests it forwarded or refused (§6).
//! * keyd keeps its own key-operation records ([`crate::KeydRecord`], §5.7
//!   item 4); they correlate with these events by the target's GUID (= the
//!   key set's principal id, docs/51 §5.8).
//!
//! The source of an event is **not** in it: auditd sets it from the
//! connection's peer uid (docs/50 §3.2, §8.1), and refuses a `DirAdmin` event
//! from any source but dird and an `Admind` event from any source but admind
//! (crate audit-daemon; docs/questions/Q-341).
//!
//! # What may be in them (docs/37 §2: "only identifiers and metadata")
//!
//! GUIDs, SIDs, RIDs, uids, key version numbers, request numbers, codes from
//! closed tables, the names of the objects acted on — each name only as an
//! [`AuditText`] (printable ASCII ≤ 256 octets, else a fixed marker) — and
//! three request values recorded as metadata from closed forms (decided on
//! Q-340 item 5): the direction of `SetEnabled`, the value of
//! `SetAccountExpires` (never, or a FILETIME), and the groupType of
//! `CreateGroup` (one of six codes). **No other attribute value** (no
//! description, no free value) and **never a password, a key, a ticket or an
//! AP-REQ**: no field has a type that could hold one.
//!
//! # The noise rule (A-57; docs/questions/Q-218 (a), Q-252 item 8)
//!
//! Every `DirAdmin` event is **gating**: dird decodes the request before it
//! records anything, as the LDAP engine and the KDC do for theirs (A-64,
//! A-69: decoded requests are gating, undecoded ones are noise). An
//! `Admind` event is **noise** exactly when it records a connection refused
//! or a frame that did not decode ([`AdmindEvent::is_noise`]) — nothing was
//! asked of dird or keyd — and is offered with
//! [`crate::SendWindow::offer_noise`]: queued within the window's noise share,
//! otherwise counted into a [`crate::WindowSummary`]. A flood of refused
//! connections or malformed frames therefore never takes a slot a gating
//! event needs and never stops admind.
//!
//! Spec: docs/51 §5.2, §5.6, §5.7, §6, §7.3, §7.4, §7.6, §8.3, §9, §11;
//! docs/50 §3.2, §3.3, §8.1, §8.2; docs/37 §2; Q-218 (A-57), Q-252 (A-64);
//! docs/questions/Q-340.

use crate::codes::{
    AccountExpiresCode, AdminFailure, AdminNameKind, AdminPhase, AdminRefusal, AdmindActivityCode,
    ConnectionRefusal, DecisionResultCode, DirAdminOperation, EnableDirection, ForwardDecision,
    FrameErrorCode, GroupTypeCode, KeyPurposeCode, KeyadmOperation, KeydOperation,
    OutcomeResultCode, PasswordFailure, PasswordResultCode, PasswordStepCode,
};
use crate::error::EventError;
use crate::values::{
    read_opt, write_opt, AuditText, BoundedSeq, CalendarTime, PdpReason, SidValue,
};
use ipc::{Reader, Writer};

/// Most approvers a `DirAdmin` event names. Spec: docs/51 §7.2
/// (`approvals: seq<bytes<64 KiB>, 2>`), §5.6.
pub const MAX_APPROVERS: usize = 2;

/// Most names a `DirAdmin` event keeps. `CreateComputer` names three (name,
/// DNS host name, SPN), the most of any operation (docs/51 §7.3). Project
/// choice (docs/questions/Q-340 item 4).
pub const MAX_TARGET_NAMES: usize = 4;

/// Most key version numbers one event reports: two, for a computer's
/// `PrincipalLongterm` and `Service` key sets (docs/51 §5.2 row 5, §7.3
/// `CompletePasswordSet {kvnos}`).
pub const MAX_REPORTED_KVNOS: usize = 2;

// ---- dird: DirAdmin ------------------------------------------------------------

/// The object a committed create allocated: its objectGUID and, for a
/// security principal (user, computer, group), its RID.
/// Spec: docs/51 R51-16, R51-17, §7.4 step 5, §8.3 ("RIDs only for user /
/// computer / group").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Allocation {
    /// The new objectGUID (16 octets, as dirstore keeps it).
    pub guid: [u8; 16],
    /// The RID, for a security principal.
    pub rid: Option<u32>,
}

impl Allocation {
    fn write(&self, writer: &mut Writer) -> Result<(), EventError> {
        writer.write_array(&self.guid)?;
        write_opt(writer, self.rid.as_ref(), |rid, w| Ok(w.write_u32(*rid)?))
    }

    fn read(reader: &mut Reader<'_>) -> Result<Allocation, EventError> {
        let guid = reader.read_array::<16>()?;
        let rid = read_opt(reader, |r| Ok(r.read_u32()?))?;
        Ok(Allocation { guid, rid })
    }
}

/// What a `Decision` event says.
/// Spec: docs/51 §5.7 item 2, §7.4 steps 1-5.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DecisionResult {
    /// Allowed: dird proceeds (to the commit, or — for an operation that
    /// commits nothing — to the reply).
    Proceed,
    /// Refused before the commit; nothing is written.
    Refused(AdminRefusal),
    /// Failed before a decision could be made; nothing is written.
    Failed(AdminFailure),
}

/// What an `Outcome` event says.
/// Spec: docs/51 §5.7 item 2, §7.4 steps 5-6.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OutcomeResult {
    /// The `WriteTxn` committed; a create names the object it allocated.
    Committed {
        /// The created object, for a create.
        allocated: Option<Allocation>,
    },
    /// Refused at the commit (for example a unique value taken); nothing is
    /// written.
    Refused(AdminRefusal),
    /// The commit failed.
    Failed(AdminFailure),
}

/// The phase of a `DirAdmin` event and its result. A result that does not
/// belong to its phase (a `Decision` that "committed", an `Outcome` that
/// "proceeds") cannot be built or decoded: each phase has its own closed
/// result table.
/// Spec: docs/51 §5.7 item 2; docs/50 §3.3 (one encoding per value).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DirAdminStage {
    /// After `decide`, before the commit.
    Decision(DecisionResult),
    /// After the commit (or its failure).
    Outcome(OutcomeResult),
}

impl DirAdminStage {
    /// The phase.
    #[must_use]
    pub fn phase(&self) -> AdminPhase {
        match self {
            DirAdminStage::Decision(_) => AdminPhase::Decision,
            DirAdminStage::Outcome(_) => AdminPhase::Outcome,
        }
    }

    /// `phase:u8 ‖ result:u8 ‖ detail` (refusal or failure code, or the
    /// optional allocation of `Committed`).
    fn write(&self, writer: &mut Writer) -> Result<(), EventError> {
        writer.write_enum(self.phase().code())?;
        match self {
            DirAdminStage::Decision(result) => match result {
                DecisionResult::Proceed => writer.write_enum(DecisionResultCode::Proceed.code())?,
                DecisionResult::Refused(refusal) => {
                    writer.write_enum(DecisionResultCode::Refused.code())?;
                    writer.write_enum(refusal.code())?;
                }
                DecisionResult::Failed(failure) => {
                    writer.write_enum(DecisionResultCode::Failed.code())?;
                    writer.write_enum(failure.code())?;
                }
            },
            DirAdminStage::Outcome(result) => match result {
                OutcomeResult::Committed { allocated } => {
                    writer.write_enum(OutcomeResultCode::Committed.code())?;
                    write_opt(writer, allocated.as_ref(), Allocation::write)?;
                }
                OutcomeResult::Refused(refusal) => {
                    writer.write_enum(OutcomeResultCode::Refused.code())?;
                    writer.write_enum(refusal.code())?;
                }
                OutcomeResult::Failed(failure) => {
                    writer.write_enum(OutcomeResultCode::Failed.code())?;
                    writer.write_enum(failure.code())?;
                }
            },
        }
        Ok(())
    }

    fn read(reader: &mut Reader<'_>) -> Result<DirAdminStage, EventError> {
        Ok(match reader.read_enum(AdminPhase::from_code)? {
            AdminPhase::Decision => {
                DirAdminStage::Decision(match reader.read_enum(DecisionResultCode::from_code)? {
                    DecisionResultCode::Proceed => DecisionResult::Proceed,
                    DecisionResultCode::Refused => {
                        DecisionResult::Refused(reader.read_enum(AdminRefusal::from_code)?)
                    }
                    DecisionResultCode::Failed => {
                        DecisionResult::Failed(reader.read_enum(AdminFailure::from_code)?)
                    }
                })
            }
            AdminPhase::Outcome => {
                DirAdminStage::Outcome(match reader.read_enum(OutcomeResultCode::from_code)? {
                    OutcomeResultCode::Committed => OutcomeResult::Committed {
                        allocated: read_opt(reader, Allocation::read)?,
                    },
                    OutcomeResultCode::Refused => {
                        OutcomeResult::Refused(reader.read_enum(AdminRefusal::from_code)?)
                    }
                    OutcomeResultCode::Failed => {
                        OutcomeResult::Failed(reader.read_enum(AdminFailure::from_code)?)
                    }
                })
            }
        })
    }
}

/// One name of an object acted on, kept by the [`AuditText`] rule.
/// Spec: docs/51 §5.7 item 1 ("names only as `AuditText`"), §7.3;
/// docs/50 §8.2.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TargetName {
    /// Which name it is.
    pub kind: AdminNameKind,
    /// The name (or the marker).
    pub text: AuditText,
}

impl TargetName {
    fn write(&self, writer: &mut Writer) -> Result<(), EventError> {
        writer.write_enum(self.kind.code())?;
        self.text.write(writer)
    }

    fn read(reader: &mut Reader<'_>) -> Result<TargetName, EventError> {
        let kind = reader.read_enum(AdminNameKind::from_code)?;
        let text = AuditText::read(reader)?;
        Ok(TargetName { kind, text })
    }
}

/// The value of a `SetAccountExpires` request: "never", or the FILETIME
/// (100-ns intervals since 1601-01-01 UTC) the request named, recorded
/// verbatim — also when dird refuses it (`0` is refused, docs/51 §5.2 row 7).
///
/// One encoding per meaning: "never" is the value `0x7FFFFFFFFFFFFFFF`
/// (the only spelling the admin plane writes, docs/47 R47-5b), so
/// [`AccountExpiresValue::at`] of that value **is** [`AccountExpiresValue::NEVER`]
/// and is encoded as `Never`; a decoded `At` holding it is refused.
///
/// Wire: `1 Never | 2 At ‖ filetime:u64`.
///
/// Spec: docs/51 §5.2 row 7, §7.3; docs/47 §4.2 ([MS-SAMR] 2.2.6.1 and
/// [MS-DTYP] 2.3.3 as quoted there; R47-5b); docs/50 §3.3; docs/questions/
/// Q-340 item 5.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AccountExpiresValue {
    filetime: u64,
}

impl AccountExpiresValue {
    /// The accountExpires value meaning "never". Spec: docs/47 §4.2 (R47-5b:
    /// "the admin plane writes 'never' as `0x7FFFFFFFFFFFFFFF` only").
    const NEVER_FILETIME: u64 = 0x7FFF_FFFF_FFFF_FFFF;

    /// "Never expires".
    pub const NEVER: AccountExpiresValue = AccountExpiresValue {
        filetime: Self::NEVER_FILETIME,
    };

    /// The request's FILETIME (`0x7FFFFFFFFFFFFFFF` is "never").
    #[must_use]
    pub const fn at(filetime: u64) -> AccountExpiresValue {
        AccountExpiresValue { filetime }
    }

    /// Whether this is "never".
    #[must_use]
    pub const fn is_never(self) -> bool {
        self.filetime == Self::NEVER_FILETIME
    }

    /// The FILETIME, or `None` for "never".
    #[must_use]
    pub const fn filetime(self) -> Option<u64> {
        if self.is_never() {
            None
        } else {
            Some(self.filetime)
        }
    }

    fn write(&self, writer: &mut Writer) -> Result<(), EventError> {
        match self.filetime() {
            None => writer.write_enum(AccountExpiresCode::Never.code())?,
            Some(filetime) => {
                writer.write_enum(AccountExpiresCode::At.code())?;
                writer.write_u64(filetime)?;
            }
        }
        Ok(())
    }

    fn read(reader: &mut Reader<'_>) -> Result<AccountExpiresValue, EventError> {
        Ok(match reader.read_enum(AccountExpiresCode::from_code)? {
            AccountExpiresCode::Never => AccountExpiresValue::NEVER,
            AccountExpiresCode::At => {
                let filetime = reader.read_u64()?;
                // "never" has one spelling (`Never`); the same meaning as
                // `At` would be a second encoding (docs/50 §3.3).
                if filetime == Self::NEVER_FILETIME {
                    return Err(EventError::Codec(ipc::Error::UnknownCode));
                }
                AccountExpiresValue::at(filetime)
            }
        })
    }
}

/// One dird admin-plane audit event.
///
/// Field use per operation (docs/51 §7.3; not enforced by the codec — dird
/// is attributed by uid either way, docs/questions/Q-252 item 4):
///
/// * `target` — the existing object acted on (`BeginPasswordSet`,
///   `SetEnabled`, `Delete`, the group of `AddMember`, the object `Lookup`
///   found, the key's account of `RequestKeyOperation`, …); `None` for a
///   create (its object is `Committed { allocated }`), a `Lookup` that found
///   nothing, and `ListPendingDestruction`.
/// * `parent` — the container of a create. `member` — the member of
///   `AddMember` / `RemoveMember`.
/// * `requester` — the objectSid of the principal whose AP-REQ dird
///   verified (§5.3); `None` when it did not verify or could not be resolved.
///   `approvers` — the objectSids of the verified approvers (§5.6).
/// * `pdp` — the requester's PDP decision (`Allowed` or the deny reason, with
///   the rule id for `CoarseDeny`); `None` when the PDP was not reached.
/// * `names` — the request's name fields (`sam`, `upn`, `name`,
///   `dns_host_name`, `spn`; the key of a `Lookup`).
/// * `enable` — the direction of `SetEnabled`; `account_expires` — the
///   value of `SetAccountExpires`; `group_type` — the groupType of
///   `CreateGroup` (absent when the request named none of the six). `None`
///   for every other operation (Q-340 item 5).
/// * `key_request` — the pending key-operation request's id (§5.6, §6);
///   `key_operation` — the key operation it asks for (`RotateKey`,
///   `RotateKrbtgt`, `RetireKvno`, …, docs/51 §6).
/// * `reported_kvnos` — key versions reported to dird: by admind in
///   `CompletePasswordSet`, by keyadm in `Complete` (dird does not verify
///   them; keyd's own records do).
///
/// Spec: docs/51 §5.3, §5.6, §5.7 item 1, §6, §7.3, §7.4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirAdminEvent {
    /// dird's clock when it recorded the event.
    pub time: CalendarTime,
    /// dird's number for the operation: the `Decision` and `Outcome` events
    /// of one operation carry the same number (Q-340 item 1).
    pub operation_id: u64,
    /// The operation.
    pub operation: DirAdminOperation,
    /// Decision or outcome, and its result.
    pub stage: DirAdminStage,
    /// The existing object acted on (objectGUID).
    pub target: Option<[u8; 16]>,
    /// The parent of a create (objectGUID).
    pub parent: Option<[u8; 16]>,
    /// The member of a membership change (objectGUID).
    pub member: Option<[u8; 16]>,
    /// The verified requester's objectSid.
    pub requester: Option<SidValue>,
    /// The verified approvers' objectSids (0 to [`MAX_APPROVERS`]).
    pub approvers: BoundedSeq<SidValue, MAX_APPROVERS>,
    /// The requester's PDP decision and reason.
    pub pdp: Option<PdpReason>,
    /// The names of the objects acted on (0 to [`MAX_TARGET_NAMES`]).
    pub names: BoundedSeq<TargetName, MAX_TARGET_NAMES>,
    /// `SetEnabled`: enable or disable.
    pub enable: Option<EnableDirection>,
    /// `SetAccountExpires`: never, or the FILETIME.
    pub account_expires: Option<AccountExpiresValue>,
    /// `CreateGroup`: the groupType (one of the six phase-1 values).
    pub group_type: Option<GroupTypeCode>,
    /// The pending key-operation request's id.
    pub key_request: Option<u64>,
    /// The key operation a pending request asks for.
    pub key_operation: Option<KeydOperation>,
    /// Key versions reported to dird (0 to [`MAX_REPORTED_KVNOS`]).
    pub reported_kvnos: BoundedSeq<u32, MAX_REPORTED_KVNOS>,
}

impl DirAdminEvent {
    /// The fields in declaration order.
    /// Spec: docs/50 §3.3 (positional fields, one encoding per value).
    pub(crate) fn write(&self, writer: &mut Writer) -> Result<(), EventError> {
        self.time.write(writer)?;
        writer.write_u64(self.operation_id)?;
        writer.write_enum(self.operation.code())?;
        self.stage.write(writer)?;
        write_opt(writer, self.target.as_ref(), |g, w| Ok(w.write_array(g)?))?;
        write_opt(writer, self.parent.as_ref(), |g, w| Ok(w.write_array(g)?))?;
        write_opt(writer, self.member.as_ref(), |g, w| Ok(w.write_array(g)?))?;
        write_opt(writer, self.requester.as_ref(), SidValue::write)?;
        self.approvers.write(writer, SidValue::write)?;
        write_opt(writer, self.pdp.as_ref(), PdpReason::write)?;
        self.names.write(writer, TargetName::write)?;
        write_opt(writer, self.enable.as_ref(), |e, w| {
            Ok(w.write_enum(e.code())?)
        })?;
        write_opt(
            writer,
            self.account_expires.as_ref(),
            AccountExpiresValue::write,
        )?;
        write_opt(writer, self.group_type.as_ref(), |g, w| {
            Ok(w.write_enum(g.code())?)
        })?;
        write_opt(writer, self.key_request.as_ref(), |id, w| {
            Ok(w.write_u64(*id)?)
        })?;
        write_opt(writer, self.key_operation.as_ref(), |op, w| {
            Ok(w.write_enum(op.code())?)
        })?;
        self.reported_kvnos
            .write(writer, |kvno, w| Ok(w.write_u32(*kvno)?))
    }

    pub(crate) fn read(reader: &mut Reader<'_>) -> Result<DirAdminEvent, EventError> {
        let time = CalendarTime::read(reader)?;
        let operation_id = reader.read_u64()?;
        let operation = reader.read_enum(DirAdminOperation::from_code)?;
        let stage = DirAdminStage::read(reader)?;
        let target = read_opt(reader, |r| Ok(r.read_array::<16>()?))?;
        let parent = read_opt(reader, |r| Ok(r.read_array::<16>()?))?;
        let member = read_opt(reader, |r| Ok(r.read_array::<16>()?))?;
        let requester = read_opt(reader, SidValue::read)?;
        let approvers = BoundedSeq::read(reader, SidValue::read)?;
        let pdp = read_opt(reader, PdpReason::read)?;
        let names = BoundedSeq::read(reader, TargetName::read)?;
        let enable = read_opt(reader, |r| Ok(r.read_enum(EnableDirection::from_code)?))?;
        let account_expires = read_opt(reader, AccountExpiresValue::read)?;
        let group_type = read_opt(reader, |r| Ok(r.read_enum(GroupTypeCode::from_code)?))?;
        let key_request = read_opt(reader, |r| Ok(r.read_u64()?))?;
        let key_operation = read_opt(reader, |r| Ok(r.read_enum(KeydOperation::from_code)?))?;
        let reported_kvnos = BoundedSeq::read(reader, |r| Ok(r.read_u32()?))?;
        Ok(DirAdminEvent {
            time,
            operation_id,
            operation,
            stage,
            target,
            parent,
            member,
            requester,
            approvers,
            pdp,
            names,
            enable,
            account_expires,
            group_type,
            key_request,
            key_operation,
            reported_kvnos,
        })
    }
}

// ---- admind: Admind ------------------------------------------------------------

/// The step of a `SetPassword` that failed.
/// Spec: docs/51 §7.6 (`BeginPasswordSet` ⇒ `set_secret` ×1 / ×2 ⇒
/// `CompletePasswordSet`), §5.2 row 5, §9.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PasswordStep {
    /// admind's own check of the request, before dird is asked.
    Validation,
    /// dird's `BeginPasswordSet`.
    BeginPasswordSet,
    /// keyd's `set_secret` for the key set of this purpose.
    SetSecret(KeyPurposeCode),
    /// dird's `CompletePasswordSet`.
    CompletePasswordSet,
}

impl PasswordStep {
    fn code(self) -> PasswordStepCode {
        match self {
            PasswordStep::Validation => PasswordStepCode::Validation,
            PasswordStep::BeginPasswordSet => PasswordStepCode::BeginPasswordSet,
            PasswordStep::SetSecret(_) => PasswordStepCode::SetSecret,
            PasswordStep::CompletePasswordSet => PasswordStepCode::CompletePasswordSet,
        }
    }

    fn write(&self, writer: &mut Writer) -> Result<(), EventError> {
        writer.write_enum(self.code().code())?;
        if let PasswordStep::SetSecret(purpose) = self {
            writer.write_enum(purpose.code())?;
        }
        Ok(())
    }

    fn read(reader: &mut Reader<'_>) -> Result<PasswordStep, EventError> {
        Ok(match reader.read_enum(PasswordStepCode::from_code)? {
            PasswordStepCode::Validation => PasswordStep::Validation,
            PasswordStepCode::BeginPasswordSet => PasswordStep::BeginPasswordSet,
            PasswordStepCode::SetSecret => {
                PasswordStep::SetSecret(reader.read_enum(KeyPurposeCode::from_code)?)
            }
            PasswordStepCode::CompletePasswordSet => PasswordStep::CompletePasswordSet,
        })
    }
}

/// How a `SetPassword` ended.
/// Spec: docs/51 §5.7 item 3, §7.6.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PasswordResult {
    /// Every step succeeded.
    Completed,
    /// A step failed.
    Failed {
        /// The step.
        step: PasswordStep,
        /// The failure class.
        cause: PasswordFailure,
    },
}

impl PasswordResult {
    fn write(&self, writer: &mut Writer) -> Result<(), EventError> {
        match self {
            PasswordResult::Completed => writer.write_enum(PasswordResultCode::Completed.code())?,
            PasswordResult::Failed { step, cause } => {
                writer.write_enum(PasswordResultCode::Failed.code())?;
                step.write(writer)?;
                writer.write_enum(cause.code())?;
            }
        }
        Ok(())
    }

    fn read(reader: &mut Reader<'_>) -> Result<PasswordResult, EventError> {
        Ok(match reader.read_enum(PasswordResultCode::from_code)? {
            PasswordResultCode::Completed => PasswordResult::Completed,
            PasswordResultCode::Failed => {
                let step = PasswordStep::read(reader)?;
                let cause = reader.read_enum(PasswordFailure::from_code)?;
                PasswordResult::Failed { step, cause }
            }
        })
    }
}

/// What admind recorded.
/// Spec: docs/51 §5.7 item 3, §6, §7.3, §7.6.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmindActivity {
    /// An `admin.sock` connection was refused. Noise.
    ConnectionRefused {
        /// Why.
        reason: ConnectionRefusal,
    },
    /// An `admin.sock` frame did not decode; the connection was closed.
    /// Noise.
    MalformedFrame {
        /// The rule it broke (never its octets).
        error: FrameErrorCode,
    },
    /// A `SetPassword` ended. The password is never recorded (docs/51
    /// §7.6: it does not even reach dird).
    SetPassword {
        /// The account's objectGUID (= the principal id of its key sets).
        target: [u8; 16],
        /// The key versions keyd chose, in call order (`PrincipalLongterm`,
        /// then `Service` for a computer — docs/51 §5.2 row 5): one per
        /// `set_secret` that succeeded.
        kvnos: BoundedSeq<u32, MAX_REPORTED_KVNOS>,
        /// Completed, or the step that failed and why.
        result: PasswordResult,
    },
    /// A keyadm-only request: forwarded to dird, or refused because the
    /// peer uid is not `keyadm_uid`.
    KeyadmForward {
        /// The request.
        operation: KeyadmOperation,
        /// Forwarded or refused.
        decision: ForwardDecision,
    },
}

impl AdmindActivity {
    fn code(&self) -> AdmindActivityCode {
        match self {
            AdmindActivity::ConnectionRefused { .. } => AdmindActivityCode::ConnectionRefused,
            AdmindActivity::MalformedFrame { .. } => AdmindActivityCode::MalformedFrame,
            AdmindActivity::SetPassword { .. } => AdmindActivityCode::SetPassword,
            AdmindActivity::KeyadmForward { .. } => AdmindActivityCode::KeyadmForward,
        }
    }

    fn write(&self, writer: &mut Writer) -> Result<(), EventError> {
        writer.write_enum(self.code().code())?;
        match self {
            AdmindActivity::ConnectionRefused { reason } => writer.write_enum(reason.code())?,
            AdmindActivity::MalformedFrame { error } => writer.write_enum(error.code())?,
            AdmindActivity::SetPassword {
                target,
                kvnos,
                result,
            } => {
                writer.write_array(target)?;
                kvnos.write(writer, |kvno, w| Ok(w.write_u32(*kvno)?))?;
                result.write(writer)?;
            }
            AdmindActivity::KeyadmForward {
                operation,
                decision,
            } => {
                writer.write_enum(operation.code())?;
                writer.write_enum(decision.code())?;
            }
        }
        Ok(())
    }

    fn read(reader: &mut Reader<'_>) -> Result<AdmindActivity, EventError> {
        Ok(match reader.read_enum(AdmindActivityCode::from_code)? {
            AdmindActivityCode::ConnectionRefused => AdmindActivity::ConnectionRefused {
                reason: reader.read_enum(ConnectionRefusal::from_code)?,
            },
            AdmindActivityCode::MalformedFrame => AdmindActivity::MalformedFrame {
                error: reader.read_enum(FrameErrorCode::from_code)?,
            },
            AdmindActivityCode::SetPassword => {
                let target = reader.read_array::<16>()?;
                let kvnos = BoundedSeq::read(reader, |r| Ok(r.read_u32()?))?;
                let result = PasswordResult::read(reader)?;
                AdmindActivity::SetPassword {
                    target,
                    kvnos,
                    result,
                }
            }
            AdmindActivityCode::KeyadmForward => AdmindActivity::KeyadmForward {
                operation: reader.read_enum(KeyadmOperation::from_code)?,
                decision: reader.read_enum(ForwardDecision::from_code)?,
            },
        })
    }
}

/// One admind audit event.
/// Spec: docs/51 §5.7 item 3, §6; docs/50 §3.2 (the peer uid comes from the
/// peer credentials, never from a message).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmindEvent {
    /// admind's clock when it recorded the event.
    pub time: CalendarTime,
    /// The `admin.sock` peer's uid, from its peer credentials; `None` when
    /// they could not be read. Metadata only — never the Subject of an
    /// operation (docs/51 §5.1).
    pub peer_uid: Option<u32>,
    /// What happened.
    pub activity: AdmindActivity,
}

impl AdmindEvent {
    /// Whether this event is noise under the A-57 rule: a refused
    /// connection or a frame that did not decode — nothing was asked of dird
    /// or keyd. Offer it with [`crate::SendWindow::offer_noise`] (queued
    /// within the noise share, otherwise counted into a
    /// [`crate::WindowSummary`]), so a flood of them never takes the slots
    /// gating events need and never stops admind. Every other admind event
    /// is gating: reserve its slot ([`crate::SendWindow::reserve`]) before
    /// the operation, and a full window answers `Busy` (A-64).
    ///
    /// Spec: docs/questions/Q-218 (a) (A-57: "unauthenticated noise events
    /// (… malformed frame) summarised in counters and rate-limited"), Q-252
    /// item 8 (A-64); docs/51 §5.7.
    #[must_use]
    pub fn is_noise(&self) -> bool {
        matches!(
            self.activity,
            AdmindActivity::ConnectionRefused { .. } | AdmindActivity::MalformedFrame { .. }
        )
    }

    /// The fields in declaration order.
    /// Spec: docs/50 §3.3.
    pub(crate) fn write(&self, writer: &mut Writer) -> Result<(), EventError> {
        self.time.write(writer)?;
        write_opt(writer, self.peer_uid.as_ref(), |uid, w| {
            Ok(w.write_u32(*uid)?)
        })?;
        self.activity.write(writer)
    }

    pub(crate) fn read(reader: &mut Reader<'_>) -> Result<AdmindEvent, EventError> {
        let time = CalendarTime::read(reader)?;
        let peer_uid = read_opt(reader, |r| Ok(r.read_u32()?))?;
        let activity = AdmindActivity::read(reader)?;
        Ok(AdmindEvent {
            time,
            peer_uid,
            activity,
        })
    }
}
