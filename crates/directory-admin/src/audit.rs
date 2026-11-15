//! The `DirAdmin` audit events this crate plans, and the refusals it
//! returns.
//!
//! This crate **plans** the events (A-85): `prepare` returns the `Decision`
//! event — `Proceed`, or the refusal / failure that stopped it — and `apply`
//! returns the `Outcome` event. The caller sends them: the decision event
//! acknowledged by auditd **before** the commit, the outcome event after it
//! (docs/51 §5.7 item 2). Events carry only identifiers and metadata
//! (docs/37 §2 as cited in docs/51 §5.7): GUIDs, SIDs, the RID, closed
//! codes, the request's names as `AuditText`, and the three request values
//! A-85 allows (enable direction, accountExpires value, groupType code) —
//! never a description, a password, a key or a ticket.
//!
//! The client-visible answer is a coarse [`RefusalStatus`]; the precise
//! reason is in the event only (A-26: uniform `Denied`; docs/11 §1b: reason
//! codes are for audit only). In particular an object the requester cannot
//! read is answered exactly like an absent one, `NotFound` (A-55: no
//! existence oracle), while the event keeps `NotVisible` apart from
//! `NotFound`.
//!
//! Spec: docs/51 §5.7 (R51-12), §7.4 steps 5-6; A-85 (crate ipc-audit
//! admin.rs, Q-340); A-26; A-55; docs/11 §1b, §8; docs/questions/Q-358
//! items 2, 10 (the codes this crate uses, the approvers it lists).

use dtyp::{Guid, Sid};
use ipc_audit::{
    AccountExpiresValue, AdminFailure, AdminNameKind, AdminRefusal, Allocation, AuditText,
    BoundedSeq, CalendarTime, DecisionResult, DirAdminEvent, DirAdminOperation, DirAdminStage,
    EnableDirection, GroupTypeCode, KeydOperation, OutcomeResult, PdpReason, PdpReasonCode,
    SidValue, TargetName, MAX_APPROVERS, MAX_REPORTED_KVNOS, MAX_TARGET_NAMES,
};
use keyd_types::OperationDigest;
use krb_proto::KerberosTime;

use crate::operation::{LookupKey, Operation};
use crate::time;

/// What the client is told about a refused or failed operation. The reason
/// itself is in the audit event only.
/// Spec: A-26 (uniform `Denied`); A-55 (no existence oracle); docs/11 §1b.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RefusalStatus {
    /// Not permitted: the requester did not authenticate or is not allowed,
    /// an approval is not acceptable, the target is protected, or the
    /// self-lockout guard applies.
    Denied,
    /// Dual control applies and the approvals do not reach the quorum.
    ApprovalRequired,
    /// The object does not exist **or** the requester cannot read it.
    NotFound,
    /// A request value breaks a rule (name, value, membership).
    Invalid,
    /// The directory holds a conflicting value or state.
    Conflict,
    /// The operation could not be carried out (store, RID range,
    /// randomness); retrying later may succeed.
    Unavailable,
}

/// Why an operation stopped, before it is turned into an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Stop {
    /// A check refused it.
    Refused(AdminRefusal),
    /// Something failed; nothing was decided against the requester.
    Failed(AdminFailure),
}

impl Stop {
    /// The client-visible status. Spec: module documentation.
    pub(crate) fn status(self) -> RefusalStatus {
        match self {
            Stop::Refused(refusal) => match refusal {
                // A key operation fetched before its approvals reach the
                // quorum (task A10).
                AdminRefusal::ApprovalRequired | AdminRefusal::NotApproved => {
                    RefusalStatus::ApprovalRequired
                }
                // An unknown or expired pending key-operation request is
                // "not found" too (task A10, docs/questions/Q-421).
                AdminRefusal::NotFound | AdminRefusal::NotVisible | AdminRefusal::PendingUnknown => {
                    RefusalStatus::NotFound
                }
                AdminRefusal::AccountNameInvalid
                | AdminRefusal::ValueInvalid
                | AdminRefusal::MembershipInvalid
                | AdminRefusal::OperationMismatch
                // A proposal for an operation that needs no approver: send
                // the operation itself (task D2-c, docs/questions/Q-938).
                | AdminRefusal::ApprovalNotNeeded => RefusalStatus::Invalid,
                // The state a pending request was judged on changed (task
                // D2-c, class C43): the request is dropped; propose again.
                AdminRefusal::Conflict | AdminRefusal::RequestStale => RefusalStatus::Conflict,
                // The bounded pending table is full, or the requester holds
                // its cap of open requests: retrying later (after a request
                // expires or completes) may succeed (task A10; task D2-c).
                AdminRefusal::RidExhausted
                | AdminRefusal::PendingLimit
                | AdminRefusal::RequesterLimit => RefusalStatus::Unavailable,
                AdminRefusal::Unauthenticated
                | AdminRefusal::TicketAge
                | AdminRefusal::PolicyDenied
                | AdminRefusal::ApproverUnauthenticated
                | AdminRefusal::ApproverNotDistinct
                | AdminRefusal::ApproverDenied
                | AdminRefusal::TargetProtected
                | AdminRefusal::SelfLockout
                // Recorded in a `Complete`'s outcome event only; never a
                // refusal of a request (task A10).
                | AdminRefusal::KeyOperationRefused
                // Not planned by this crate: dird refuses an obligation it
                // cannot honour after `prepare`, answering `Denied` as for a
                // PDP deny (docs/questions/Q-388 item 2, Q-397; A-91).
                | AdminRefusal::ObligationRefused => RefusalStatus::Denied,
            },
            Stop::Failed(_) => RefusalStatus::Unavailable,
        }
    }
}

/// A refused or failed operation: the event to send and what the client is
/// told. From `prepare` the event is a `Decision` (nothing was written);
/// from `apply` it is an `Outcome` (the caller must abort the transaction).
/// Spec: docs/51 §5.7 item 2, §7.4; A-85.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    event: Box<DirAdminEvent>,
    status: RefusalStatus,
}

impl Refusal {
    /// The audit event to send (acknowledged before the reply).
    #[must_use]
    pub fn event(&self) -> &DirAdminEvent {
        &self.event
    }

    /// The client-visible status.
    #[must_use]
    pub fn status(&self) -> RefusalStatus {
        self.status
    }

    /// The audit event, by value.
    #[must_use]
    pub fn into_event(self) -> DirAdminEvent {
        *self.event
    }
}

/// The SID in audit form. A `dtyp::Sid` has at most 15 sub-authorities
/// ([MS-DTYP] 2.4.2.2), as many as `SidValue` keeps, so this never fails in
/// practice; a failure leaves the field empty.
pub(crate) fn sid_value(sid: &Sid) -> Option<SidValue> {
    SidValue::new(sid.identifier_authority(), sid.sub_authority().to_vec())
}

/// `pdp::ReasonCode` → its audit form (the rule id for `CoarseDeny`).
/// Spec: crate pdp model.rs; crate ipc-audit `PdpReasonCode`.
pub(crate) fn pdp_reason(code: pdp::ReasonCode) -> PdpReason {
    use pdp::ReasonCode as R;
    let (code, rule) = match code {
        R::Allowed => (PdpReasonCode::Allowed, None),
        R::InvalidRequest => (PdpReasonCode::InvalidRequest, None),
        R::Unauthenticated => (PdpReasonCode::Unauthenticated, None),
        R::WeakTransport => (PdpReasonCode::WeakTransport, None),
        R::PipFailure => (PdpReasonCode::PipFailure, None),
        R::SubjectMismatch => (PdpReasonCode::SubjectMismatch, None),
        R::CoarseDeny(id) => (PdpReasonCode::CoarseDeny, Some(id.0)),
        R::NoGrant => (PdpReasonCode::NoGrant, None),
        R::TierViolation => (PdpReasonCode::TierViolation, None),
        R::Acl => (PdpReasonCode::Acl, None),
        R::NoSuchPath => (PdpReasonCode::NoSuchPath, None),
        R::Sensitive => (PdpReasonCode::Sensitive, None),
    };
    PdpReason { code, rule }
}

/// The fields one operation's `Decision` and `Outcome` events share, filled
/// in as `prepare` learns them.
/// Spec: crate ipc-audit `DirAdminEvent` (field use per operation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EventBase {
    pub(crate) operation_id: u64,
    pub(crate) operation: DirAdminOperation,
    pub(crate) target: Option<Guid>,
    pub(crate) parent: Option<Guid>,
    pub(crate) member: Option<Guid>,
    pub(crate) requester: Option<SidValue>,
    pub(crate) approvers: Vec<SidValue>,
    pub(crate) pdp: Option<PdpReason>,
    names: Vec<TargetName>,
    enable: Option<EnableDirection>,
    account_expires: Option<AccountExpiresValue>,
    group_type: Option<GroupTypeCode>,
    pub(crate) pending_request: Option<u64>,
    pub(crate) key_operation: Option<KeydOperation>,
    pub(crate) reported_kvnos: Vec<u32>,
    /// The operation's fingerprint (docs/questions/Q-888): the digest dird
    /// computed from the request it decoded — or, on a step of a pending
    /// request, the request's operation digest.
    pub(crate) operation_digest: OperationDigest,
    /// The operation a pending directory / policy request is for.
    pub(crate) proposed: Option<DirAdminOperation>,
    /// A pending request's `reason_ref` (unverified).
    pub(crate) reason_ref: Option<AuditText>,
}

/// One name of the request, kept by the `AuditText` rule.
fn name(kind: AdminNameKind, text: &str) -> TargetName {
    TargetName {
        kind,
        text: AuditText::from_client(text),
    }
}

impl EventBase {
    /// The fields the request itself determines: the operation, the objects
    /// it names (`target` / `parent` / `member` by GUID), its name fields,
    /// the three request values A-85 records, and its digest (Q-888).
    /// Spec: crate ipc-audit `DirAdminEvent` field list; Q-340 items 4-5;
    /// docs/questions/Q-888.
    pub(crate) fn of_request(
        operation_id: u64,
        op: &Operation,
        digest: &OperationDigest,
    ) -> EventBase {
        let mut base = EventBase::bare(operation_id, op.code(), digest);
        match op {
            Operation::CreateUser(c) => {
                base.parent = Some(c.parent);
                base.names.push(name(AdminNameKind::SamAccountName, &c.sam));
                if let Some(upn) = &c.upn {
                    base.names.push(name(AdminNameKind::UserPrincipalName, upn));
                }
            }
            Operation::CreateComputer(c) => {
                base.parent = Some(c.parent);
                base.names.push(name(AdminNameKind::Name, &c.name));
                base.names
                    .push(name(AdminNameKind::DnsHostName, &c.dns_host_name));
                if let Some(spn) = &c.spn {
                    base.names
                        .push(name(AdminNameKind::ServicePrincipalName, spn));
                }
            }
            Operation::CreateGroup(c) => {
                base.parent = Some(c.parent);
                base.names.push(name(AdminNameKind::SamAccountName, &c.sam));
                base.group_type = c
                    .group_type
                    .map_or(Some(GroupTypeCode::SecurityAccountGroup), |value| {
                        GroupTypeCode::from_group_type(value)
                    });
            }
            Operation::CreateOu(c) | Operation::CreateContainer(c) => {
                base.parent = Some(c.parent);
                base.names.push(name(AdminNameKind::Name, &c.name));
            }
            Operation::BeginPasswordSet { target } | Operation::Delete { target } => {
                base.target = Some(*target);
            }
            Operation::CompletePasswordSet(c) => {
                base.target = Some(c.target);
                base.reported_kvnos = c.kvnos.clone();
            }
            Operation::SetEnabled(s) => {
                base.target = Some(s.target);
                base.enable = Some(if s.enabled {
                    EnableDirection::Enable
                } else {
                    EnableDirection::Disable
                });
            }
            Operation::SetAccountExpires(s) => {
                base.target = Some(s.target);
                base.account_expires = Some(s.value);
            }
            Operation::AddMember(m) | Operation::RemoveMember(m) => {
                base.target = Some(m.group);
                base.member = Some(m.member);
            }
            Operation::Lookup(key) => {
                let entry = match key {
                    LookupKey::SamAccountName(sam) => name(AdminNameKind::SamAccountName, sam),
                    LookupKey::ServicePrincipalName(spn) => {
                        name(AdminNameKind::ServicePrincipalName, spn)
                    }
                    LookupKey::Dn(dn) => {
                        name(AdminNameKind::DistinguishedName, &dn.rdns().join(","))
                    }
                };
                base.names.push(entry);
            }
        }
        base
    }

    /// The fields a `ChangePolicy` request determines (task A16): the
    /// operation, and each tier-map change as a name of kind `PolicyChange`
    /// in the edit's command-line spelling (crate policy-store `TierChange`'s
    /// `Display`) — SIDs and DNs, not secret (docs/47 §2.3). A change whose
    /// spelling is not kept by the `AuditText` rule (over 256 octets) is the
    /// marker.
    /// Spec: docs/51 §5.7 item 1, §5.10; crate ipc-audit
    /// `AdminNameKind::PolicyChange`; docs/questions/Q-592.
    pub(crate) fn of_policy_change(
        operation_id: u64,
        changes: &[policy_store::TierChange],
        digest: &OperationDigest,
    ) -> EventBase {
        let mut base = EventBase::bare(operation_id, DirAdminOperation::ChangePolicy, digest);
        base.names = changes
            .iter()
            .map(|change| name(AdminNameKind::PolicyChange, &change.to_string()))
            .collect();
        base
    }

    /// An event base with only the operation number, code and digest (every
    /// other field empty): a step of a pending request fills its own fields
    /// (crate::requests).
    /// Spec: crate ipc-audit `DirAdminEvent` field list.
    pub(crate) fn bare(
        operation_id: u64,
        operation: DirAdminOperation,
        digest: &OperationDigest,
    ) -> EventBase {
        EventBase {
            operation_id,
            operation,
            target: None,
            parent: None,
            member: None,
            requester: None,
            approvers: Vec::new(),
            pdp: None,
            names: Vec::new(),
            enable: None,
            account_expires: None,
            group_type: None,
            pending_request: None,
            key_operation: None,
            reported_kvnos: Vec::new(),
            operation_digest: *digest,
            proposed: None,
            reason_ref: None,
        }
    }

    /// The request-derived fields of a pending request's operation, for an
    /// event of the step `step` on it: the objects and names a directory
    /// operation names, a policy change's changes, a key operation's code,
    /// the operation's code as `proposed`, its digest and its `reason_ref`
    /// (task D2-c).
    /// Spec: crate ipc-audit `DirAdminEvent` field list (`pending_request`,
    /// `proposed`, `reason_ref`, `operation_digest`); docs/questions/Q-882,
    /// Q-888.
    pub(crate) fn of_proposed(
        operation_id: u64,
        step: DirAdminOperation,
        operation: &crate::requests::ProposedOperation,
        digest: &OperationDigest,
        reason_ref: Option<&str>,
    ) -> EventBase {
        use crate::requests::ProposedOperation;
        let mut base = match operation {
            ProposedOperation::Directory(op) => EventBase::of_request(operation_id, op, digest),
            ProposedOperation::Policy(changes) => {
                EventBase::of_policy_change(operation_id, changes, digest)
            }
            ProposedOperation::Key(op) => {
                let mut base = EventBase::bare(operation_id, step, digest);
                base.key_operation = Some(op.keyd_operation());
                base
            }
        };
        base.proposed = operation.code();
        base.operation = step;
        base.reason_ref = reason_ref.map(AuditText::from_client);
        base
    }

    /// Build the event of `stage`, recorded at `now`. A bounded field that
    /// would overflow its bound (never, by construction) is left empty.
    fn event(&self, now: &KerberosTime, stage: DirAdminStage) -> DirAdminEvent {
        let time: CalendarTime = time::calendar(now);
        let packet = |g: &Option<Guid>| g.map(|g| g.to_packet());
        let mut approvers = self.approvers.clone();
        approvers.truncate(MAX_APPROVERS);
        let mut names = self.names.clone();
        names.truncate(MAX_TARGET_NAMES);
        let mut kvnos = self.reported_kvnos.clone();
        kvnos.truncate(MAX_REPORTED_KVNOS);
        let digest: [u8; 32] = *self.operation_digest.as_bytes();
        DirAdminEvent {
            time,
            operation_id: self.operation_id,
            operation: self.operation,
            stage,
            target: packet(&self.target),
            parent: packet(&self.parent),
            member: packet(&self.member),
            requester: self.requester.clone(),
            approvers: BoundedSeq::new(approvers).unwrap_or_default(),
            pdp: self.pdp,
            names: BoundedSeq::new(names).unwrap_or_default(),
            enable: self.enable,
            account_expires: self.account_expires,
            group_type: self.group_type,
            pending_request: self.pending_request,
            key_operation: self.key_operation,
            reported_kvnos: BoundedSeq::new(kvnos).unwrap_or_default(),
            operation_digest: digest,
            proposed: self.proposed,
            reason_ref: self.reason_ref.clone(),
        }
    }

    /// The `Decision` event: proceed.
    pub(crate) fn proceed(&self, now: &KerberosTime) -> DirAdminEvent {
        self.event(now, DirAdminStage::Decision(DecisionResult::Proceed))
    }

    /// The event of an explicit `stage` (a `Complete`'s `Outcome`, task
    /// A10).
    pub(crate) fn staged(&self, now: &KerberosTime, stage: DirAdminStage) -> DirAdminEvent {
        self.event(now, stage)
    }

    /// The refusal of `prepare`: a `Decision` event.
    pub(crate) fn decision_refusal(&self, now: &KerberosTime, stop: Stop) -> Refusal {
        let result = match stop {
            Stop::Refused(r) => DecisionResult::Refused(r),
            Stop::Failed(f) => DecisionResult::Failed(f),
        };
        Refusal {
            event: Box::new(self.event(now, DirAdminStage::Decision(result))),
            status: stop.status(),
        }
    }

    /// The `Outcome` event of a committed write.
    pub(crate) fn committed(
        &self,
        now: &KerberosTime,
        allocated: Option<Allocation>,
    ) -> DirAdminEvent {
        self.event(
            now,
            DirAdminStage::Outcome(OutcomeResult::Committed { allocated }),
        )
    }

    /// The refusal of `apply`: an `Outcome` event.
    pub(crate) fn outcome_refusal(&self, now: &KerberosTime, stop: Stop) -> Refusal {
        let result = match stop {
            Stop::Refused(r) => OutcomeResult::Refused(r),
            Stop::Failed(f) => OutcomeResult::Failed(f),
        };
        Refusal {
            event: Box::new(self.event(now, DirAdminStage::Outcome(result))),
            status: stop.status(),
        }
    }
}
