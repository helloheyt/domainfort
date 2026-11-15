//! **One dual-control mechanism** (task D2-c; docs/questions/Q-882, A-148):
//! the pending requests dird holds for every dual-controlled operation, and
//! the steps on them — `Propose`, `Approve`, `Reject`, `Withdraw`,
//! `ListRequests`, `ShowRequest` (docs/research/r5-a-admin-model.md §11
//! MA5) — and the consumption of an approved request by the operation's
//! execution.
//!
//! # The class this closes (AGENTS.md §6.1)
//!
//! Before this module there were **two** mechanisms for one control
//! (docs/research/r5-b-cli.md §7.1): directory writes and `ChangePolicy`
//! carried the approvers' AP-REQs *inside* the request (both people online
//! within the clock skew, an "approval token" passed between people, the
//! approver judging what the requester showed it), while key operations
//! used a pending request in dird. Two rule sets for one decision can
//! diverge (docs/52 **C14**). Now there is one: the in-request approvals
//! have no field on the wire (crate ipc-dird-admin: a non-empty sequence is
//! refused by the codec), the key-only steps are retired, and every
//! approval is an `Approve` of a request held here — a type the rest of the
//! PEP can only reach through [`PendingRequests`].
//!
//! # The lifecycle
//!
//! | state | entered by | left by |
//! |---|---|---|
//! | `Pending` | `Propose` (the requester's AP-REQ; the operation's checks pass as a dry run and its rule needs an approver) | `Approve` reaching the quorum ⇒ `Approved`; `Reject`, `Withdraw`, expiry, or a stale basis ⇒ gone |
//! | `Approved` | the quorum (the requester plus `admin_quorum − 1` approvers, P-22) | a directory / policy operation: its **execution** by the requester (the operation itself, sent again with a fresh AP-REQ: [`DirectoryAdmin::consume_approved`]), `Reject`, `Withdraw`, expiry ⇒ gone; a key operation: its decision is registered in keyd for keyadm at the quorum (A-102) and the record stays, for `ListRequests` / `ShowRequest`, until expiry — `Reject` / `Withdraw` of it are a `Conflict` (keyd's decision would not be revoked) |
//!
//! Gone requests leave no trace here (the audit trail keeps every step); a
//! dird restart drops every request (memory only — fail closed, docs/51
//! §5.6).
//!
//! # What a request holds — and what is re-checked (class C43)
//!
//! A request holds the **exact operation** (the PEP's typed fields) and its
//! **operation digest** (computed by the caller from the decoded octets,
//! crate ipc-dird-admin `operation_digest`: the fingerprint the requester
//! saw, the approver compares, and the execution's AP-REQ is bound to —
//! docs/questions/Q-888), the requester (objectGUID, objectSid and its
//! verified ticket's facts), the approvers (the same), the expiry, the
//! Action and Resource every approver must be allowed (the operation's own
//! — P-22 item 2), and its **basis**: the policy version and a SHA-256 of
//! every object record the operation depends on, as the dry run at
//! `Propose` read them.
//!
//! At every `Approve` and at the execution, everything an approval was
//! judged on is evaluated again against the current view, and any change
//! drops the request (`RequestStale`): the requester's account must still
//! resolve to the same principal, be usable and not have its ticket revoked
//! (docs/47 §4.5); the operation's checks must pass again for it with the
//! same classification and the same basis — an object it names changed in
//! any attribute, or the policy changed ⇒ stale; every earlier approver
//! must still resolve, be usable and be allowed. At the execution the
//! requester is the fresh AP-REQ's (every check of `prepare`, ticket age
//! included).
//!
//! # The bounds (classes C47, C9)
//!
//! At most [`MAX_PENDING_REQUESTS`] requests; at most `per_requester` open
//! requests per requester (interim [`REQUESTS_PER_REQUESTER`] while owner
//! item P-78 / Q-878 is open — docs/questions/Q-940); one open request per
//! (requester, operation digest); the lifetime ([`REQUEST_LIFETIME`], at
//! most [`MAX_REQUEST_LIFETIME`] — docs/questions/Q-939); a `Propose` for an
//! operation whose rule needs no approver is refused (`ApprovalNotNeeded`:
//! no human is asked to judge what needs no judgment); every `Approve`
//! names one request and its digest — there is no step that approves more
//! than one. Ids are 64 bits from the CSPRNG (never a counter a restart
//! resets: a replayed approval cannot meet a new request with an old id —
//! docs/questions/Q-882 item 3).
//!
//! # Who sees a request
//!
//! Its requester, and every account the PDP allows the request's Action on
//! its Resource (an eligible approver). Anyone else is answered exactly as
//! for an unknown id (`NotFound`; the event keeps `NotVisible` — the rule
//! of A-55). `ShowRequest` returns the operation from the request's own
//! fields (never requester text — class C44), the requester and approvers
//! dird verified, and the facts dird resolves for each object the operation
//! names — through the viewer's visibility gate (docs/52 R10).
//!
//! # Audit (A-85; docs/questions/Q-888)
//!
//! Every step has one `DirAdmin` `Decision` event; an `Approve` that
//! completes a key request's quorum has, after its `Decision` (which auditd
//! must acknowledge first — [`QuorumStep`], docs/52 R6), the `Outcome`
//! event of its registration in keyd. Every event carries the request's id
//! (`pending_request`), the operation it is for (`proposed` /
//! `key_operation`, with the operation's own target / names fields), its
//! `reason_ref` and its **operation digest**; the execution's events carry
//! the same digest and id. keyd's own records carry the decision id — the
//! request's id (docs/52 §4.5).
//!
//! Spec: docs/questions/Q-882 (A-148), Q-888, Q-887 item 3; docs/research/
//! r5-b-cli.md §7, §12; docs/research/r5-a-admin-model.md §5, §8.2, §11
//! MA5; docs/51 §5.6, §5.7, §6; docs/52 §3.11 R6, §4.3 (A-102), C14, C43,
//! C44, C47; P-22; FIPS 180-4 (SHA-256, the approved `sha2`).

use core::time::Duration;
use std::collections::BTreeMap;

use directory_pip::{DirectoryView, GateFault, Visibility};
use dirstore::{AttrStamp, Object};
use dtyp::{Guid, Sid};
use ipc_audit::{
    AdminFailure, AdminRefusal, DirAdminEvent, DirAdminOperation, DirAdminStage, EventBody,
    OutcomeResult, MAX_APPROVERS,
};
use ipc_audit_client::IntentRecord;
use keyd_types::{KeyHandle, OperationDigest};
use krb_proto::KerberosTime;
use pdp::{
    Action, Dn, Effect, Obligation, PolicyScope, PolicySnapshot, PolicyVersion, Resource, Tier,
};
use policy_store::{check_tier_map_successor, edit_tier_map, DevelopmentPolicy, TierChange};
use sha2::{Digest, Sha256};

use crate::admin::{subject_of, DirectoryAdmin, Dual, OpCx, Plan, VerificationFailure};
use crate::audit::{pdp_reason, sid_value, EventBase, Refusal, Stop};
use crate::checks::{local_ipc_security, malformed, Cx, Resolved};
use crate::config::ConfigError;
use crate::key_requests::{
    key_request, KeyDecision, KeyOperation, KeyTargets, RegistrationOutcome,
};
use crate::operation::Operation;
use crate::policy_change::{PendingPolicy, MAX_POLICY_CHANGES, POLICY_CHANGE_SCOPE};
use crate::random::RandomSource;
use crate::record;
use crate::subject::{AdminSubject, SubjectError, VerifiedTicket};

/// Most pending requests dird holds at once (approved ones included, until
/// they are executed or expire). Project choice: dual-controlled operations
/// are rare and human-paced; [`MAX_REQUESTS_PER_REQUESTER`] × a few
/// administrators. Spec: docs/51 §5.6 ("bounded in number"); AGENTS.md §6;
/// docs/questions/Q-940.
pub const MAX_PENDING_REQUESTS: usize = 32;

/// The default lifetime of a pending request: 60 minutes — the value
/// docs/questions/Q-882 proposes ("TTL default (proposed 60 min)"): an
/// asynchronous approval must reach a second person, and a longer window
/// does not widen class C43, since the basis and every party are evaluated
/// again at each approval and at the execution. Project choice — a light
/// product decision recorded in docs/questions/Q-939.
/// Spec: docs/51 §5.6 ("bounded in time"); docs/questions/Q-882 ("the gap"),
/// Q-939.
pub const REQUEST_LIFETIME: Duration = Duration::from_secs(60 * 60);

/// The longest lifetime accepted: one hour — keyd's ceiling for a key
/// decision's lifetime (`keyd_types::MAX_KEY_DECISION_SECS`), and the
/// ceiling of `admin_ticket_age_max` (docs/questions/Q-385 item 4).
/// Spec: docs/51 §5.6; AGENTS.md §6; docs/questions/Q-939.
pub const MAX_REQUEST_LIFETIME: Duration = Duration::from_secs(60 * 60);

/// The default cap of open pending requests per requester: 4 — **interim**,
/// at most docs/questions/Q-878 item 2's recommendation (5) while owner item
/// P-78 is open (class C47: a requester cannot flood the approvers). Project
/// choice (docs/questions/Q-940).
/// Spec: docs/research/r5-a-admin-model.md §8.2 item 4, §11 MA5;
/// docs/questions/Q-878 item 2, Q-940.
pub const REQUESTS_PER_REQUESTER: usize = 4;

/// The largest per-requester cap accepted. Spec: docs/questions/Q-940;
/// AGENTS.md §6.
pub const MAX_REQUESTS_PER_REQUESTER: usize = 8;

/// The longest `reason_ref`: 64 printable ASCII characters ("a change
/// identifier"). Spec: docs/questions/Q-882 item 4.
pub const MAX_REASON_REF_CHARS: usize = 64;

/// Most facts a `ShowRequest` answers: one per object the operation names —
/// at most two. Spec: docs/questions/Q-882 item 1; crate ipc-dird-admin
/// `MAX_FACTS` (pinned in crates/directory-daemon).
pub const MAX_FACTS: usize = 2;

/// How many times a fresh id is drawn before the proposal fails (a zero or
/// a colliding draw is redrawn). Project choice.
const ID_DRAWS: usize = 4;

/// The domain-separation label of an object record's state digest (the
/// basis). Project choice: no other digest of this project starts with it.
const BASIS_LABEL: &[u8] = b"dird pending-request object state, layout 1";

/// The operation a pending request is for.
/// Spec: docs/questions/Q-882 item 1 ("every dual-controlled operation").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProposedOperation {
    /// A directory write (one of the operations whose rule can require an
    /// approver; never `Lookup` or `CompletePasswordSet`).
    Directory(Operation),
    /// A tier-map change (`ChangePolicy`).
    Policy(Vec<TierChange>),
    /// A key operation (registered in keyd at the quorum, A-102).
    Key(KeyOperation),
}

impl ProposedOperation {
    /// The audit code of a directory or policy operation (`proposed`); a key
    /// operation's is its `key_operation`.
    /// Spec: crate ipc-audit `DirAdminEvent::proposed`.
    #[must_use]
    pub fn code(&self) -> Option<DirAdminOperation> {
        match self {
            ProposedOperation::Directory(op) => Some(op.code()),
            ProposedOperation::Policy(_) => Some(DirAdminOperation::ChangePolicy),
            ProposedOperation::Key(_) => None,
        }
    }

    /// Whether it may be proposed at all: not a read, not an audit-only
    /// report. Spec: crate ipc-dird-admin `request_kind::PROPOSABLE`.
    fn proposable(&self) -> bool {
        match self {
            ProposedOperation::Directory(op) => op.writes(),
            ProposedOperation::Policy(_) | ProposedOperation::Key(_) => true,
        }
    }
}

/// A pending request's state. Spec: module documentation (the lifecycle).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RequestState {
    /// Awaiting approvals.
    Pending,
    /// The quorum is reached.
    Approved,
}

/// The scope of a `ListRequests`. Spec: docs/questions/Q-882 item 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ListScope {
    /// The caller's own requests.
    Mine,
    /// Pending requests the caller may approve and has not approved.
    AwaitingMe,
}

/// What a request's approvals were judged on: the policy version and the
/// state digest of every object record the operation depends on (module
/// documentation, class C43).
/// Spec: docs/questions/Q-882 item 2, Q-887 item 1 (a precondition on the
/// object's state); docs/51 §7.4 step 5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Basis {
    policy: PolicyVersion,
    objects: Vec<(Guid, [u8; 32])>,
}

impl Basis {
    /// The basis of a directory operation's plan: every object it read.
    /// Spec: docs/51 §7.4 step 5 ("every object the write depends on").
    pub(crate) fn of_plan(cx: &Cx<'_, '_, '_>, plan: &Plan) -> Result<Basis, Stop> {
        let objects = match plan {
            Plan::Write(write) => write
                .seen
                .iter()
                .map(|(guid, obj)| (*guid, object_state(obj)))
                .collect(),
            Plan::Read(_) => Vec::new(),
        };
        Ok(Basis {
            policy: cx.policy.version(),
            objects,
        })
    }

    /// The basis of a policy change: the policy version (it names no
    /// object).
    /// Spec: docs/51 §5.10.
    pub(crate) fn of_policy(cx: &Cx<'_, '_, '_>) -> Basis {
        Basis {
            policy: cx.policy.version(),
            objects: Vec::new(),
        }
    }

    /// The objects named, without repetition, in plan order.
    fn named(&self) -> Vec<Guid> {
        let mut named = Vec::new();
        for (guid, _) in &self.objects {
            if !named.contains(guid) {
                named.push(*guid);
            }
        }
        named
    }
}

/// The state digest of an object record: SHA-256 over a label and a
/// length-prefixed, fixed-order encoding of every field of the record —
/// GUID, parent, RDN, classes, every attribute value with its attr-stamp,
/// the tombstone marker — so any change of the record changes it (the same
/// comparison `apply` makes of whole records, docs/51 §7.4 step 5).
/// Spec: docs/32 §2 (the record), docs/29 §2 (attr-stamps); FIPS 180-4
/// §6.2 via the approved `sha2` (`Digest` API, docs.rs sha2 0.11.1 as
/// crates/audit-log cites it).
fn object_state(obj: &Object) -> [u8; 32] {
    fn stamp(hasher: &mut Sha256, s: &AttrStamp) {
        hasher.update(s.version.to_be_bytes());
        hasher.update(s.wall_clock.0.to_be_bytes());
        hasher.update(s.origin_node.0);
        hasher.update(s.origin_seq.to_be_bytes());
    }
    fn len(hasher: &mut Sha256, n: usize) {
        hasher.update(u64::try_from(n).unwrap_or(u64::MAX).to_be_bytes());
    }
    let mut hasher = Sha256::new();
    hasher.update(BASIS_LABEL);
    hasher.update(obj.guid.to_packet());
    match obj.parent {
        Some(parent) => {
            hasher.update([1u8]);
            hasher.update(parent.to_packet());
        }
        None => hasher.update([0u8]),
    }
    len(&mut hasher, obj.rdn.len());
    hasher.update(&obj.rdn);
    len(&mut hasher, obj.classes.len());
    for class in &obj.classes {
        hasher.update(class.0.to_be_bytes());
    }
    len(&mut hasher, obj.attributes.len());
    for attribute in &obj.attributes {
        hasher.update(attribute.id.0.to_be_bytes());
        len(&mut hasher, attribute.values.len());
        for value in &attribute.values {
            len(&mut hasher, value.value.len());
            hasher.update(&value.value);
            stamp(&mut hasher, &value.stamp);
        }
    }
    match &obj.tombstone {
        Some(marker) => {
            hasher.update([1u8]);
            stamp(&mut hasher, marker);
        }
        None => hasher.update([0u8]),
    }
    <[u8; 32]>::from(hasher.finalize())
}

/// A principal of a pending request: its objectGUID (keyd's token), its
/// objectSid (the audit event) and its verified ticket's facts (to resolve
/// it again — never a ticket to present again).
/// Spec: docs/51 §5.3; docs/questions/Q-882 item 2.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Party {
    guid: Guid,
    sid: Sid,
    ticket: VerifiedTicket,
}

impl Party {
    fn of(subject: &AdminSubject, ticket: &VerifiedTicket) -> Party {
        Party {
            guid: subject.guid(),
            sid: *subject.sid(),
            ticket: ticket.clone(),
        }
    }

    fn is(&self, subject: &AdminSubject) -> bool {
        self.guid == subject.guid() || self.sid == *subject.sid()
    }
}

/// One pending request (module documentation).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Record {
    operation: ProposedOperation,
    digest: OperationDigest,
    reason_ref: Option<String>,
    requester: Party,
    approvals: Vec<Party>,
    expires: u64,
    state: RequestState,
    basis: Basis,
    action: Action,
    resource: Resource,
    key_handle: Option<KeyHandle>,
}

/// The pending requests (module documentation). In dird's memory only.
/// Spec: docs/51 §5.6; docs/questions/Q-882.
#[derive(Debug, Clone)]
pub struct PendingRequests {
    records: BTreeMap<u64, Record>,
    lifetime: u64,
    per_requester: usize,
    targets: KeyTargets,
}

impl PendingRequests {
    /// An empty table. `lifetime` must be 1 s ..= [`MAX_REQUEST_LIFETIME`];
    /// `per_requester` 1 ..= [`MAX_REQUESTS_PER_REQUESTER`]; `targets` are
    /// the key sets a key operation may name.
    ///
    /// # Errors
    /// [`ConfigError::RequestLifetime`], [`ConfigError::RequesterCap`].
    ///
    /// Spec: docs/51 §5.6; docs/questions/Q-939, Q-940.
    pub fn new(
        targets: KeyTargets,
        lifetime: Duration,
        per_requester: usize,
    ) -> Result<PendingRequests, ConfigError> {
        if lifetime.as_secs() == 0 || lifetime > MAX_REQUEST_LIFETIME {
            return Err(ConfigError::RequestLifetime);
        }
        if per_requester == 0 || per_requester > MAX_REQUESTS_PER_REQUESTER {
            return Err(ConfigError::RequesterCap);
        }
        Ok(PendingRequests {
            records: BTreeMap::new(),
            lifetime: lifetime.as_secs(),
            per_requester,
            targets,
        })
    }

    /// The requests held (expired ones included until the next step drops
    /// them).
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether no request is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Drop every request whose expiry is at or before `now` (seconds since
    /// 1970).
    fn purge(&mut self, now: u64) {
        self.records.retain(|_, record| record.expires > now);
    }

    /// Revert the approval that completed `decision`'s quorum, after the
    /// decision could not be recorded or registered in keyd: the request's
    /// last approval is removed when it is that decision's last approver,
    /// and the request is `Pending` again, so the approver may approve
    /// again. `true` if one was removed. keyd accepts the same decision
    /// again unchanged (an identical re-registration — keyd decision.rs), so
    /// a second `Approve` after "outcome unknown" is harmless.
    /// Spec: docs/52 §4.3 ("failure to register ⇒ dird answers
    /// `Unavailable`"); A-85 / docs/questions/Q-453 item 1 (fail closed).
    pub fn revert_approval(&mut self, decision: &KeyDecision) -> bool {
        let Some(record) = self.records.get_mut(&decision.id.get()) else {
            return false;
        };
        let last = record
            .approvals
            .last()
            .map(|p| keyd_types::PrincipalId::from_bytes(p.guid.to_packet()));
        if last.is_some() && last == decision.approvers.last().copied() {
            record.approvals.pop();
            record.state = RequestState::Pending;
            true
        } else {
            false
        }
    }

    /// Drop the request `id` — the caller could not record the step that
    /// created it (no request outlives an unrecorded proposal; fail closed).
    /// `true` if it was held.
    pub fn discard(&mut self, id: u64) -> bool {
        self.records.remove(&id).is_some()
    }
}

/// A pending request's state, shown back to the requester and the
/// approvers (the answer to `Propose` and `Approve`).
/// Spec: docs/questions/Q-882 item 1 (`{id, digest, quorum, expires}`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestView {
    /// The id.
    pub id: u64,
    /// The operation digest (the fingerprint).
    pub digest: OperationDigest,
    /// The state.
    pub state: RequestState,
    /// Approvals recorded so far (the requester not counted).
    pub approvals: usize,
    /// The quorum, the requester included.
    pub quorum: usize,
    /// The expiry (seconds since 1970).
    pub expires: u64,
}

/// One entry of a `ListRequests` answer.
/// Spec: docs/research/r5-a-admin-model.md §11 MA5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestSummary {
    /// The id.
    pub id: u64,
    /// The operation digest.
    pub digest: OperationDigest,
    /// The state.
    pub state: RequestState,
    /// The operation (the caller names its kind).
    pub operation: ProposedOperation,
    /// The requester's objectSid, as dird verified it.
    pub requester: Sid,
    /// Approvals recorded so far.
    pub approvals: usize,
    /// The quorum.
    pub quorum: usize,
    /// The expiry (seconds since 1970).
    pub expires: u64,
}

/// One fact dird resolved for an object a pending operation names.
/// Spec: docs/questions/Q-882 item 1, Q-887 item 2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestFact {
    /// The objectGUID.
    pub guid: Guid,
    /// The DN in the directory's canonical form.
    pub dn: Dn,
    /// The lDAPDisplayName of the most specific class.
    pub class: &'static str,
    /// The objectSid, for a security principal.
    pub sid: Option<Sid>,
    /// The explicit tier (`None`: unclassified — A-36, P-22).
    pub tier: Option<Tier>,
}

/// A pending request as dird holds it (the answer to `ShowRequest`).
/// Spec: docs/questions/Q-882 item 1, Q-887 item 3; docs/research/
/// r5-b-cli.md §7.4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestDetail {
    /// The id.
    pub id: u64,
    /// The operation digest.
    pub digest: OperationDigest,
    /// The state.
    pub state: RequestState,
    /// The requester's objectSid.
    pub requester: Sid,
    /// The approvers' objectSids, in approval order.
    pub approvers: Vec<Sid>,
    /// The quorum.
    pub quorum: usize,
    /// The expiry (seconds since 1970).
    pub expires: u64,
    /// The requester's change identifier (unverified).
    pub reason_ref: Option<String>,
    /// The operation — the request's own fields.
    pub operation: ProposedOperation,
    /// The facts (through the viewer's visibility gate).
    pub facts: Vec<RequestFact>,
}

/// The reply of a step.
/// Spec: crate ipc-dird-admin reply table (D2-c rows).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepReply {
    /// `Approve`: the request's state.
    Request(RequestView),
    /// `Reject` / `Withdraw`.
    Done,
    /// `ListRequests`.
    List(Vec<RequestSummary>),
    /// `ShowRequest`.
    Shown(Box<RequestDetail>),
}

/// The inputs of a `Propose`, after the caller verified the requester's
/// AP-REQ through keyd.
/// Spec: docs/questions/Q-882 item 1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposeRequest {
    /// dird's number for the step.
    pub operation_id: u64,
    /// The operation the request is for.
    pub operation: ProposedOperation,
    /// The operation's digest as sent on its own (crate ipc-dird-admin
    /// `operation_digest` of the proposed operation): the request's
    /// fingerprint.
    pub operation_digest: OperationDigest,
    /// The digest of the `Propose` request itself — what the requester's
    /// AP-REQ is bound to (R2; it covers `reason_ref` and the operation).
    pub request_digest: OperationDigest,
    /// The requester's change identifier.
    pub reason_ref: Option<String>,
    /// The requester's verified ticket.
    pub requester: VerifiedTicket,
}

/// One step on the pending requests (other than `Propose`).
/// Spec: docs/questions/Q-882 item 1; r5-a §11 MA5.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestStep {
    /// `Approve {id, digest}`.
    Approve {
        /// The request.
        id: u64,
        /// The digest the approver was shown.
        digest: OperationDigest,
    },
    /// `Reject {id, digest}`.
    Reject {
        /// The request.
        id: u64,
        /// The digest the rejecting approver was shown.
        digest: OperationDigest,
    },
    /// `Withdraw {id}`.
    Withdraw {
        /// The request.
        id: u64,
    },
    /// `ListRequests {scope}`.
    List(ListScope),
    /// `ShowRequest {id}`.
    Show {
        /// The request.
        id: u64,
    },
}

impl RequestStep {
    /// The audit code. Spec: crate ipc-audit `DirAdminOperation`.
    #[must_use]
    pub fn code(&self) -> DirAdminOperation {
        match self {
            RequestStep::Approve { .. } => DirAdminOperation::Approve,
            RequestStep::Reject { .. } => DirAdminOperation::Reject,
            RequestStep::Withdraw { .. } => DirAdminOperation::Withdraw,
            RequestStep::List(_) => DirAdminOperation::ListRequests,
            RequestStep::Show { .. } => DirAdminOperation::ShowRequest,
        }
    }

    /// The `DirAdmin` events it may record: two for `Approve` (its decision
    /// and, when it completes a key request's quorum, the outcome of the
    /// decision's registration in keyd — the second slot is released
    /// otherwise), one for the others.
    /// Spec: module documentation (audit); docs/52 §4.3 (A-102).
    #[must_use]
    pub fn audit_events(&self) -> usize {
        match self {
            RequestStep::Approve { .. } => 2,
            _ => 1,
        }
    }

    /// Whether the caller acts as an approver (its unverified ticket is an
    /// approver's).
    fn by_approver(&self) -> bool {
        matches!(
            self,
            RequestStep::Approve { .. } | RequestStep::Reject { .. }
        )
    }

    /// The digest the event of this step starts with: the one an `Approve`
    /// / `Reject` names (the fingerprint its approver saw), else the step
    /// request's own (replaced by the request's once it is found).
    fn digest(&self, request_digest: &OperationDigest) -> OperationDigest {
        match self {
            RequestStep::Approve { digest, .. } | RequestStep::Reject { digest, .. } => *digest,
            _ => *request_digest,
        }
    }
}

/// The place of an approver's signature in the approval step — owner item
/// P-30 (decided: both options, the administrator chooses; by default the
/// approvers sign) and docs/questions/Q-882 item 5 ("P-30 (b) signatures in
/// the same approval step"). **Uninhabited:** the signature algorithm and
/// key custody are not decided (docs/questions/Q-864, owner item P-20), and
/// no scheme is invented here — so no value of this type exists, and an
/// approval cannot carry one until the scheme is defined and this type gets
/// its fields (task D2-c; docs/questions/Q-941).
/// Spec: P-30; docs/questions/Q-882 item 5, Q-864; docs/research/
/// r5-b-cli.md §7.6.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApproverSignature {}

/// The inputs of a step, after the caller verified the caller's AP-REQ
/// through keyd.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepRequest {
    /// dird's number for the step.
    pub operation_id: u64,
    /// The step.
    pub step: RequestStep,
    /// The digest of the step's request (what the AP-REQ is bound to, R2).
    pub request_digest: OperationDigest,
    /// The caller's verified ticket.
    pub caller: VerifiedTicket,
    /// An `Approve`'s approver signature (P-30 (b)): always `None` — its
    /// type has no value yet ([`ApproverSignature`]).
    pub signature: Option<ApproverSignature>,
}

/// The loaded policy and whether a `policy.next` waits — needed to propose
/// a `ChangePolicy` (its dry run builds the candidate).
/// Spec: docs/51 §5.10; crate::policy_change.
#[derive(Debug, Clone, Copy)]
pub struct PolicyFile<'a> {
    /// The loaded policy (of the version the PDP snapshot is of).
    pub installed: &'a DevelopmentPolicy,
    /// Whether a `policy.next` waits for root.
    pub pending: PendingPolicy,
}

/// A `Propose` that succeeded: the request's id, its state, the `Decision`
/// event to commit before the reply.
/// Spec: module documentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposed {
    id: u64,
    reply: RequestView,
    event: DirAdminEvent,
}

impl Proposed {
    /// The new request's id (to [`PendingRequests::discard`] it if its event
    /// cannot be recorded).
    #[must_use]
    pub fn id(&self) -> u64 {
        self.id
    }

    /// The reply.
    #[must_use]
    pub fn reply(&self) -> &RequestView {
        &self.reply
    }

    /// The `Decision` event.
    #[must_use]
    pub fn event(&self) -> &DirAdminEvent {
        &self.event
    }
}

/// A step that succeeded: its reply, its `Decision` event, and — for an
/// `Approve` that completed a key request's quorum — the decision to
/// register in keyd.
/// Spec: module documentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stepped {
    reply: StepReply,
    event: DirAdminEvent,
    decision: Option<KeyDecision>,
    base: EventBase,
    now: KerberosTime,
}

impl Stepped {
    /// The reply.
    #[must_use]
    pub fn reply(&self) -> &StepReply {
        &self.reply
    }

    /// The `Decision` event to commit before the reply.
    #[must_use]
    pub fn event(&self) -> &DirAdminEvent {
        &self.event
    }

    /// The decision to register in keyd: `Some` only for an `Approve` that
    /// completed a key request's quorum (A-102).
    #[must_use]
    pub fn decision(&self) -> Option<&KeyDecision> {
        self.decision.as_ref()
    }

    /// The `Approve` that completed a key request's quorum, as a
    /// [`QuorumStep`], or the step back.
    /// Spec: docs/52 §4.3 (A-102), §3.11 R6 (a).
    ///
    /// # Errors
    /// The step back (boxed: it is large) when it is not such an `Approve`.
    pub fn into_quorum(self) -> Result<QuorumStep, Box<Stepped>> {
        match self.decision.clone() {
            Some(decision) => Ok(QuorumStep {
                event: self.event.clone(),
                decision,
                step: self,
            }),
            None => Err(Box::new(self)),
        }
    }
}

/// The `Approve` that completed a key request's quorum (A-102, docs/52
/// §4.3): its `Decision` event — its [`IntentRecord`], which auditd must
/// acknowledge before dird registers the decision in keyd (A-85: no
/// loosening of keyd without the PDP's decision durably recorded) — and the
/// [`KeyDecision`]. dird's registration takes it only as an
/// `ipc_audit_client::AckedIntent<QuorumStep>` (docs/52 §3.11 R6 (a)). Not
/// `Clone`.
/// Spec: docs/52 §4.3, §3.11 R6 (a); docs/51 §5.6, §5.7 item 2; A-85.
#[derive(Debug, PartialEq, Eq)]
pub struct QuorumStep {
    event: DirAdminEvent,
    decision: KeyDecision,
    step: Stepped,
}

impl QuorumStep {
    /// The decision to register in keyd.
    #[must_use]
    pub fn decision(&self) -> &KeyDecision {
        &self.decision
    }

    /// The reply.
    #[must_use]
    pub fn reply(&self) -> &StepReply {
        &self.step.reply
    }

    /// The `Outcome` event of the registration: `Committed` when keyd
    /// registered it, else the codes of docs/questions/Q-421 item 7, reused
    /// for the registration.
    /// Spec: docs/52 §4.3, §4.5; docs/51 §5.7 item 2 (decision ⇒ change ⇒
    /// outcome); A-85.
    #[must_use]
    pub fn registration_event(&self, outcome: RegistrationOutcome) -> DirAdminEvent {
        let stage = match outcome {
            RegistrationOutcome::Registered => {
                DirAdminStage::Outcome(OutcomeResult::Committed { allocated: None })
            }
            RegistrationOutcome::Refused => {
                DirAdminStage::Outcome(OutcomeResult::Refused(AdminRefusal::KeyOperationRefused))
            }
            RegistrationOutcome::NotPerformed => DirAdminStage::Outcome(OutcomeResult::Failed(
                AdminFailure::KeyOperationNotPerformed,
            )),
            RegistrationOutcome::OutcomeUnknown => DirAdminStage::Outcome(OutcomeResult::Failed(
                AdminFailure::KeyOperationOutcomeUnknown,
            )),
        };
        self.step.base.staged(&self.step.now, stage)
    }
}

impl IntentRecord for QuorumStep {
    /// The `Approve`'s `Decision` event.
    /// Spec: docs/51 §5.7 item 2; docs/52 §4.3.
    fn intent_event(&self) -> EventBody {
        EventBody::DirAdmin(Box::new(self.event.clone()))
    }
}

/// What the dry run of a proposed operation found.
struct Evaluation {
    dual: Dual,
    obligations: Vec<Obligation>,
    basis: Basis,
    key_handle: Option<KeyHandle>,
}

/// The obligations of an Allow other than the audit record this crate
/// plans (the caller honours them, docs/11 §2).
fn caller_obligations(obligations: &[Obligation]) -> Vec<Obligation> {
    obligations
        .iter()
        .filter(|o| !matches!(o, Obligation::Audit))
        .cloned()
        .collect()
}

/// Whether `reason_ref` is 1 to 64 printable ASCII characters (an empty one
/// would be a second spelling of none).
/// Spec: docs/questions/Q-882 item 4 ("printable ASCII ≤ 64").
fn reason_ref_ok(reason_ref: &str) -> bool {
    !reason_ref.is_empty()
        && reason_ref.len() <= MAX_REASON_REF_CHARS
        && reason_ref.bytes().all(|b| (0x20..=0x7E).contains(&b))
}

/// The fields a step's event takes from the request `id` it acts on
/// (module documentation, audit): the request's operation, digest, id,
/// `reason_ref`, requester and approvers; the PDP reason recorded so far is
/// kept.
fn describe(base: &mut EventBase, id: u64, record: &Record) {
    let mut described = EventBase::of_proposed(
        base.operation_id,
        base.operation,
        &record.operation,
        &record.digest,
        record.reason_ref.as_deref(),
    );
    described.pending_request = Some(id);
    if let Some(handle) = &record.key_handle {
        described.target = Some(Guid::from_packet(handle.principal.as_bytes()));
    }
    described.requester = sid_value(&record.requester.sid);
    described.approvers = record
        .approvals
        .iter()
        .filter_map(|p| sid_value(&p.sid))
        .collect();
    described.pdp = base.pdp;
    *base = described;
}

/// Record the acting approver of an `Approve` / `Reject` last among the
/// event's approvers (the oldest dropped if the event's bound is reached).
fn push_actor(base: &mut EventBase, actor: &Sid) {
    if let Some(sid) = sid_value(actor) {
        if base.approvers.len() >= MAX_APPROVERS {
            base.approvers.remove(0);
        }
        base.approvers.push(sid);
    }
}

/// `Withdraw` / `Reject` of an **approved key request** is a `Conflict`: its
/// decision is already registered in keyd for keyadm (A-102) and lives
/// there for the request's remaining lifetime (Q-460); removing the record
/// here would not revoke it, so a "done" answer would claim a cancellation
/// that did not happen — two holders of one fact diverging (class C14).
/// No step revokes a registered key decision (no such keyd call exists);
/// the residual is recorded in docs/questions/Q-937 item 6. An approved
/// directory or policy request may still be withdrawn or rejected: its
/// execution then finds no approval (`ApprovalRequired`).
/// Spec: docs/52 §4.3 (A-102); docs/questions/Q-460, Q-937; class C14.
fn refuse_handed_over(record: &Record) -> Result<(), Stop> {
    if record.state == RequestState::Approved
        && matches!(record.operation, ProposedOperation::Key(_))
    {
        return Err(Stop::Refused(AdminRefusal::Conflict));
    }
    Ok(())
}

/// A refusal that means "the request's basis changed" — the request can
/// never run as approved (module documentation; class C43). A failure stays
/// a failure.
fn stale(stop: Stop) -> Stop {
    match stop {
        Stop::Refused(_) => Stop::Refused(AdminRefusal::RequestStale),
        failed @ Stop::Failed(_) => failed,
    }
}

impl<R: RandomSource> DirectoryAdmin<R> {
    /// The refusal of a `Propose` whose AP-REQ keyd did not verify (or could
    /// not be asked): its `Decision` event and the uniform `Denied` /
    /// `Unavailable`.
    /// Spec: docs/51 §7.4 step 1; A-26; A-56.
    #[must_use]
    pub fn refuse_unverified_proposal(
        &self,
        operation_id: u64,
        operation: &ProposedOperation,
        operation_digest: &OperationDigest,
        reason_ref: Option<&str>,
        failure: VerificationFailure,
        now: &KerberosTime,
    ) -> Refusal {
        let stop = match failure {
            VerificationFailure::KeydUnavailable => Stop::Failed(AdminFailure::KeydUnavailable),
            VerificationFailure::Requester | VerificationFailure::Approver => {
                Stop::Refused(AdminRefusal::Unauthenticated)
            }
        };
        EventBase::of_proposed(
            operation_id,
            DirAdminOperation::Propose,
            operation,
            operation_digest,
            reason_ref,
        )
        .decision_refusal(now, stop)
    }

    /// The refusal of a `Propose` that failed before any check ran (the view
    /// could not be taken, a policy change cannot be proposed here, …).
    /// Spec: docs/51 §7.4; A-91 (`ViewUnavailable`).
    #[must_use]
    pub fn refuse_failed_proposal(
        &self,
        operation_id: u64,
        operation: &ProposedOperation,
        operation_digest: &OperationDigest,
        reason_ref: Option<&str>,
        failure: AdminFailure,
        now: &KerberosTime,
    ) -> Refusal {
        EventBase::of_proposed(
            operation_id,
            DirAdminOperation::Propose,
            operation,
            operation_digest,
            reason_ref,
        )
        .decision_refusal(now, Stop::Failed(failure))
    }

    /// The refusal of a step whose AP-REQ keyd did not verify (or could not
    /// be asked). The ticket of an `Approve` / `Reject` is an approver's
    /// (`ApproverUnauthenticated`).
    /// Spec: docs/51 §7.4 step 1; A-26; A-56.
    #[must_use]
    pub fn refuse_unverified_step(
        &self,
        operation_id: u64,
        step: &RequestStep,
        request_digest: &OperationDigest,
        failure: VerificationFailure,
        now: &KerberosTime,
    ) -> Refusal {
        let stop = match failure {
            VerificationFailure::KeydUnavailable => Stop::Failed(AdminFailure::KeydUnavailable),
            _ if step.by_approver() => Stop::Refused(AdminRefusal::ApproverUnauthenticated),
            _ => Stop::Refused(AdminRefusal::Unauthenticated),
        };
        EventBase::bare(operation_id, step.code(), &step.digest(request_digest))
            .decision_refusal(now, stop)
    }

    /// The refusal of a step that failed before any check ran.
    /// Spec: docs/51 §7.4; A-91.
    #[must_use]
    pub fn refuse_failed_step(
        &self,
        operation_id: u64,
        step: &RequestStep,
        request_digest: &OperationDigest,
        failure: AdminFailure,
        now: &KerberosTime,
    ) -> Refusal {
        EventBase::bare(operation_id, step.code(), &step.digest(request_digest))
            .decision_refusal(now, Stop::Failed(failure))
    }

    /// `Propose` (module documentation): the requester's Subject and ticket
    /// age, the `reason_ref`, the operation's every check as a dry run
    /// against ONE view (it must need an approver), the requester's
    /// obligations (`honour` is asked before the table changes), the table's
    /// bounds — then a new request.
    ///
    /// `Err` carries the `Decision` event of the refusal and the
    /// client-visible status.
    ///
    /// Spec: docs/questions/Q-882 items 1, 3, 4; docs/51 §5.6, §7.4;
    /// docs/11 §2; r5-a §8.2 items 1, 4.
    #[allow(clippy::too_many_arguments)]
    pub fn propose(
        &mut self,
        requests: &mut PendingRequests,
        request: &ProposeRequest,
        view: &DirectoryView<'_>,
        policy: &PolicySnapshot,
        policy_file: Option<PolicyFile<'_>>,
        now: &KerberosTime,
        honour: &mut dyn FnMut(&[Obligation]) -> bool,
    ) -> Result<Proposed, Refusal> {
        let mut base = EventBase::of_proposed(
            request.operation_id,
            DirAdminOperation::Propose,
            &request.operation,
            &request.operation_digest,
            request.reason_ref.as_deref(),
        );
        let checked = self.proposal_checked(
            requests,
            request,
            view,
            policy,
            policy_file,
            now,
            honour,
            &mut base,
        );
        let (requester, evaluation, action, resource, instant) = match checked {
            Ok(checked) => checked,
            Err(stop) => return Err(base.decision_refusal(now, stop)),
        };
        // The table, after the PDP (no oracle): its bound, the requester's
        // cap, one open request per (requester, operation).
        requests.purge(instant);
        let open = |r: &&Record| r.requester.guid == requester.guid;
        let stop = if requests.records.len() >= MAX_PENDING_REQUESTS {
            Some(AdminRefusal::PendingLimit)
        } else if requests.records.values().filter(open).count() >= requests.per_requester {
            Some(AdminRefusal::RequesterLimit)
        } else if requests
            .records
            .values()
            .filter(open)
            .any(|r| r.digest == request.operation_digest)
        {
            Some(AdminRefusal::Conflict)
        } else {
            None
        };
        if let Some(refusal) = stop {
            return Err(base.decision_refusal(now, Stop::Refused(refusal)));
        }
        let id = match self.draw_id(requests) {
            Ok(id) => id,
            Err(stop) => return Err(base.decision_refusal(now, stop)),
        };
        let Some(expires) = instant.checked_add(requests.lifetime) else {
            return Err(base.decision_refusal(now, Stop::Failed(AdminFailure::InternalFailure)));
        };
        let record = Record {
            operation: request.operation.clone(),
            digest: request.operation_digest,
            reason_ref: request.reason_ref.clone(),
            requester,
            approvals: Vec::new(),
            expires,
            state: RequestState::Pending,
            basis: evaluation.basis,
            action,
            resource,
            key_handle: evaluation.key_handle,
        };
        let reply = self.view_of(id, &record);
        requests.records.insert(id, record);
        base.pending_request = Some(id);
        Ok(Proposed {
            id,
            reply,
            event: base.proceed(now),
        })
    }

    /// The checks of a `Propose`, in order (module documentation).
    #[allow(clippy::too_many_arguments, clippy::type_complexity)]
    fn proposal_checked(
        &self,
        requests: &PendingRequests,
        request: &ProposeRequest,
        view: &DirectoryView<'_>,
        policy: &PolicySnapshot,
        policy_file: Option<PolicyFile<'_>>,
        now: &KerberosTime,
        honour: &mut dyn FnMut(&[Obligation]) -> bool,
        base: &mut EventBase,
    ) -> Result<(Party, Evaluation, Action, Resource, u64), Stop> {
        self.same_domain(view)?;
        // R2: bound only if keyd verified the requester's ticket bound to
        // this very `Propose` (its reason and its operation).
        let cx = Cx::new(
            &self.config,
            &self.ids,
            view,
            policy,
            now,
            local_ipc_security(request.requester.bound_to(&request.request_digest)),
        )?;
        let requester = subject_of(&cx, &request.requester).map_err(|e| match e {
            SubjectError::NotUsable => Stop::Refused(AdminRefusal::Unauthenticated),
            SubjectError::Unavailable => Stop::Failed(AdminFailure::StoreFailure),
        })?;
        base.requester = sid_value(requester.sid());
        if requester.ticket_age() > self.config.ticket_age_max() {
            return Err(Stop::Refused(AdminRefusal::TicketAge));
        }
        if request
            .reason_ref
            .as_deref()
            .is_some_and(|r| !reason_ref_ok(r))
            || !request.operation.proposable()
        {
            return Err(Stop::Refused(AdminRefusal::ValueInvalid));
        }
        let evaluation = self.evaluate_proposed(
            &cx,
            &requester,
            &request.operation,
            &requests.targets,
            policy_file,
            true,
            base,
        )?;
        let Dual::Required { action, resource } = evaluation.dual.clone() else {
            return Err(Stop::Refused(AdminRefusal::ApprovalNotNeeded));
        };
        if !honour(&caller_obligations(&evaluation.obligations)) {
            return Err(Stop::Refused(AdminRefusal::ObligationRefused));
        }
        Ok((
            Party::of(&requester, &request.requester),
            evaluation,
            action,
            resource,
            cx.instant.0,
        ))
    }

    /// A fresh request id: 64 bits from the CSPRNG, never 0, never one held.
    /// Spec: docs/questions/Q-882 item 3; A-15.
    fn draw_id(&mut self, requests: &PendingRequests) -> Result<u64, Stop> {
        for _ in 0..ID_DRAWS {
            let mut octets = [0u8; 8];
            self.rng
                .fill(&mut octets)
                .map_err(|_| Stop::Failed(AdminFailure::InternalFailure))?;
            let id = u64::from_be_bytes(octets);
            if id != 0 && !requests.records.contains_key(&id) {
                return Ok(id);
            }
        }
        Err(Stop::Failed(AdminFailure::InternalFailure))
    }

    /// The view must be of this PEP's domain (fail closed on a misassembled
    /// caller).
    fn same_domain(&self, view: &DirectoryView<'_>) -> Result<(), Stop> {
        if view.context().realm() != self.config.realm()
            || view.context().naming_context() != self.config.naming_context()
        {
            return Err(Stop::Failed(AdminFailure::InternalFailure));
        }
        Ok(())
    }

    /// The dry run of `operation` for `requester` against `cx`'s view: the
    /// same checks its execution runs (crate::admin `evaluate`, the policy
    /// change's, the key operation's), committing nothing; its dual-control
    /// classification and its basis. `full` builds a policy change's
    /// candidate (at `Propose`); a re-evaluation needs only its basis (the
    /// policy version).
    /// Spec: module documentation; docs/52 C14 (one implementation of each
    /// rule).
    #[allow(clippy::too_many_arguments)]
    fn evaluate_proposed(
        &self,
        cx: &Cx<'_, '_, '_>,
        requester: &AdminSubject,
        operation: &ProposedOperation,
        targets: &KeyTargets,
        policy_file: Option<PolicyFile<'_>>,
        full: bool,
        base: &mut EventBase,
    ) -> Result<Evaluation, Stop> {
        let ctx = OpCx { cx, requester };
        match operation {
            ProposedOperation::Directory(op) => {
                let handled = self.evaluate(&ctx, base, op)?;
                let basis = Basis::of_plan(cx, &handled.plan)?;
                Ok(Evaluation {
                    dual: handled.dual,
                    obligations: handled.obligations,
                    basis,
                    key_handle: None,
                })
            }
            ProposedOperation::Policy(changes) => {
                if changes.is_empty() || changes.len() > MAX_POLICY_CHANGES {
                    return Err(Stop::Refused(AdminRefusal::ValueInvalid));
                }
                let action = Action::PolicyAdmin;
                let resource = Resource::Policy {
                    scope: PolicyScope(String::from(POLICY_CHANGE_SCOPE)),
                };
                let obligations = self.authorize(&ctx, base, &action, &resource)?;
                if full {
                    let Some(file) = policy_file else {
                        return Err(Stop::Failed(AdminFailure::InternalFailure));
                    };
                    if cx.policy.version() != file.installed.version {
                        return Err(Stop::Failed(AdminFailure::InternalFailure));
                    }
                    if file.pending == PendingPolicy::Present {
                        return Err(Stop::Refused(AdminRefusal::PendingLimit));
                    }
                    let (next, encoded) = edit_tier_map(file.installed, changes)
                        .map_err(|_| Stop::Refused(AdminRefusal::ValueInvalid))?;
                    let reread = DevelopmentPolicy::decode(&encoded)
                        .map_err(|_| Stop::Failed(AdminFailure::InternalFailure))?;
                    if reread != next || check_tier_map_successor(file.installed, &reread).is_err()
                    {
                        return Err(Stop::Failed(AdminFailure::InternalFailure));
                    }
                }
                Ok(Evaluation {
                    dual: Dual::Required { action, resource },
                    obligations,
                    basis: Basis::of_policy(cx),
                    key_handle: None,
                })
            }
            ProposedOperation::Key(op) => {
                let (action, resource) = key_request();
                let decision = cx.decide(requester.subject(), action.clone(), resource.clone());
                base.pdp = Some(pdp_reason(decision.reason));
                if decision.effect != Effect::Allow {
                    return Err(Stop::Refused(AdminRefusal::PolicyDenied));
                }
                let (handle, target) = self.key_target(cx, targets, op)?;
                base.target = Some(target.guid);
                Ok(Evaluation {
                    dual: Dual::Required { action, resource },
                    obligations: decision.obligations,
                    basis: Basis {
                        policy: cx.policy.version(),
                        objects: vec![(target.guid, object_state(&target.obj))],
                    },
                    key_handle: Some(handle),
                })
            }
        }
    }

    /// The standing of a party judged earlier — an approver of a request —
    /// against `cx`'s view: its account resolves to the same principal, is
    /// usable and has not revoked the ticket it approved with (docs/47
    /// §4.5), and the PDP still allows it `action` on `resource`. Otherwise
    /// `RequestStale`.
    /// Spec: docs/questions/Q-882 item 2 ("re-evaluates the requester and
    /// the approvers"); docs/51 §5.3, §5.6; class C43.
    fn still_allowed(
        &self,
        cx: &Cx<'_, '_, '_>,
        party: &Party,
        action: &Action,
        resource: &Resource,
    ) -> Result<(), Stop> {
        let subject = subject_of(cx, &party.ticket).map_err(|e| match e {
            SubjectError::NotUsable => Stop::Refused(AdminRefusal::RequestStale),
            SubjectError::Unavailable => Stop::Failed(AdminFailure::StoreFailure),
        })?;
        if subject.guid() != party.guid || *subject.sid() != party.sid {
            return Err(Stop::Refused(AdminRefusal::RequestStale));
        }
        let decision = cx.decide(subject.subject(), action.clone(), resource.clone());
        if decision.effect != Effect::Allow {
            return Err(Stop::Refused(AdminRefusal::RequestStale));
        }
        Ok(())
    }

    /// Everything the request's approvals were judged on, against `cx`'s
    /// view (module documentation): the requester resolves to the same
    /// principal and is usable, the operation passes its checks for it with
    /// the same classification and the same basis, and every approver so
    /// far is still allowed. Any change ⇒ `RequestStale`.
    /// Spec: docs/questions/Q-882 item 2; class C43.
    fn reevaluate(
        &self,
        cx: &Cx<'_, '_, '_>,
        record: &Record,
        targets: &KeyTargets,
    ) -> Result<(), Stop> {
        let requester = subject_of(cx, &record.requester.ticket).map_err(|e| match e {
            SubjectError::NotUsable => Stop::Refused(AdminRefusal::RequestStale),
            SubjectError::Unavailable => Stop::Failed(AdminFailure::StoreFailure),
        })?;
        if requester.guid() != record.requester.guid || *requester.sid() != record.requester.sid {
            return Err(Stop::Refused(AdminRefusal::RequestStale));
        }
        // The dry run's own reasons are not this step's: a scratch event.
        let mut scratch = EventBase::bare(0, DirAdminOperation::Approve, &record.digest);
        let evaluation = self
            .evaluate_proposed(
                cx,
                &requester,
                &record.operation,
                targets,
                None,
                false,
                &mut scratch,
            )
            .map_err(stale)?;
        let same = matches!(
            &evaluation.dual,
            Dual::Required { action, resource }
                if *action == record.action && *resource == record.resource
        );
        if !same || evaluation.basis != record.basis || evaluation.key_handle != record.key_handle {
            return Err(Stop::Refused(AdminRefusal::RequestStale));
        }
        for approver in &record.approvals {
            self.still_allowed(cx, approver, &record.action, &record.resource)?;
        }
        Ok(())
    }

    /// The execution of a dual-controlled directory or policy operation
    /// (module documentation): the approved request for exactly
    /// `operation` (its fields and its digest) proposed by `requester` is
    /// consumed — removed now, whatever follows (one approval, one execution
    /// attempt; fail closed) — after its basis (`basis`, what this
    /// execution's own checks read) and every approver's standing for
    /// `action` on `resource` are confirmed against `cx`'s view. None ⇒
    /// `ApprovalRequired`; any change ⇒ `RequestStale`. The request's id,
    /// approvers and `reason_ref` go to the execution's events.
    /// Spec: docs/questions/Q-882 item 2; docs/51 §5.6 (P-22 items 1-2);
    /// class C43, C14.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn consume_approved(
        &self,
        cx: &Cx<'_, '_, '_>,
        requests: &mut PendingRequests,
        requester: &AdminSubject,
        operation: &ProposedOperation,
        digest: &OperationDigest,
        action: &Action,
        resource: &Resource,
        basis: &Basis,
        base: &mut EventBase,
    ) -> Result<u64, Stop> {
        requests.purge(cx.instant.0);
        let found = requests
            .records
            .iter()
            .find(|(_, r)| {
                r.state == RequestState::Approved
                    && r.digest == *digest
                    && r.operation == *operation
                    && r.requester.guid == requester.guid()
                    && r.requester.sid == *requester.sid()
            })
            .map(|(id, _)| *id);
        let Some(id) = found else {
            return Err(Stop::Refused(AdminRefusal::ApprovalRequired));
        };
        let Some(record) = requests.records.remove(&id) else {
            return Err(Stop::Failed(AdminFailure::InternalFailure));
        };
        base.pending_request = Some(id);
        base.approvers = record
            .approvals
            .iter()
            .filter_map(|p| sid_value(&p.sid))
            .collect();
        base.reason_ref = record
            .reason_ref
            .as_deref()
            .map(ipc_audit::AuditText::from_client);
        if record.basis != *basis || record.action != *action || record.resource != *resource {
            return Err(Stop::Refused(AdminRefusal::RequestStale));
        }
        let mut parties: Vec<&Party> = vec![&record.requester];
        for approver in &record.approvals {
            if parties
                .iter()
                .any(|p| p.guid == approver.guid || p.sid == approver.sid)
            {
                return Err(Stop::Refused(AdminRefusal::ApproverNotDistinct));
            }
            parties.push(approver);
            self.still_allowed(cx, approver, action, resource)?;
        }
        if parties.len() < self.config.quorum() {
            return Err(Stop::Refused(AdminRefusal::ApprovalRequired));
        }
        Ok(id)
    }

    /// The shown-back state of a request.
    fn view_of(&self, id: u64, record: &Record) -> RequestView {
        RequestView {
            id,
            digest: record.digest,
            state: record.state,
            approvals: record.approvals.len(),
            quorum: self.config.quorum(),
            expires: record.expires,
        }
    }

    /// Whether `subject` may see `record`: its requester, or an eligible
    /// approver (the PDP allows it the request's Action on its Resource).
    /// The decision's reason goes to the event.
    fn sees(
        cx: &Cx<'_, '_, '_>,
        subject: &AdminSubject,
        record: &Record,
        base: &mut EventBase,
    ) -> Option<pdp::Decision> {
        if record.requester.is(subject) {
            return None;
        }
        let decision = cx.decide(
            subject.subject(),
            record.action.clone(),
            record.resource.clone(),
        );
        base.pdp = Some(pdp_reason(decision.reason));
        Some(decision)
    }

    /// Serve one step (module documentation) against `requests` and ONE view
    /// of the policy version `policy` belongs to. `honour` is asked whether
    /// the caller can honour the obligations of an approver's Allow before
    /// the table changes (docs/11 §2).
    ///
    /// `Err` carries the `Decision` event of the refusal and the
    /// client-visible status.
    ///
    /// Spec: docs/questions/Q-882 items 1-2; r5-a §11 MA5; docs/51 §5.6,
    /// §7.4; docs/52 §4.3 (A-102).
    pub fn step(
        &self,
        requests: &mut PendingRequests,
        request: &StepRequest,
        view: &DirectoryView<'_>,
        policy: &PolicySnapshot,
        now: &KerberosTime,
        honour: &mut dyn FnMut(&[Obligation]) -> bool,
    ) -> Result<Stepped, Refusal> {
        let mut base = EventBase::bare(
            request.operation_id,
            request.step.code(),
            &request.step.digest(&request.request_digest),
        );
        match self.step_checked(requests, request, view, policy, now, honour, &mut base) {
            Ok((reply, decision)) => Ok(Stepped {
                reply,
                event: base.proceed(now),
                decision,
                base,
                now: *now,
            }),
            Err(stop) => Err(base.decision_refusal(now, stop)),
        }
    }

    /// The checks of one step.
    #[allow(clippy::too_many_arguments)]
    fn step_checked(
        &self,
        requests: &mut PendingRequests,
        request: &StepRequest,
        view: &DirectoryView<'_>,
        policy: &PolicySnapshot,
        now: &KerberosTime,
        honour: &mut dyn FnMut(&[Obligation]) -> bool,
        base: &mut EventBase,
    ) -> Result<(StepReply, Option<KeyDecision>), Stop> {
        self.same_domain(view)?;
        let cx = Cx::new(
            &self.config,
            &self.ids,
            view,
            policy,
            now,
            local_ipc_security(request.caller.bound_to(&request.request_digest)),
        )?;
        let by_approver = request.step.by_approver();
        let unusable = if by_approver {
            AdminRefusal::ApproverUnauthenticated
        } else {
            AdminRefusal::Unauthenticated
        };
        let caller = subject_of(&cx, &request.caller).map_err(|e| match e {
            SubjectError::NotUsable => Stop::Refused(unusable),
            SubjectError::Unavailable => Stop::Failed(AdminFailure::StoreFailure),
        })?;
        if caller.ticket_age() > self.config.ticket_age_max() {
            return Err(Stop::Refused(if by_approver {
                AdminRefusal::ApproverUnauthenticated
            } else {
                AdminRefusal::TicketAge
            }));
        }
        requests.purge(cx.instant.0);
        match request.step {
            RequestStep::List(scope) => {
                base.requester = sid_value(caller.sid());
                Ok((
                    StepReply::List(self.list(&cx, requests, &caller, scope)),
                    None,
                ))
            }
            RequestStep::Show { id } => {
                let record = requests
                    .records
                    .get(&id)
                    .ok_or(Stop::Refused(AdminRefusal::PendingUnknown))?;
                describe(base, id, record);
                base.requester = sid_value(caller.sid());
                base.approvers.clear();
                if let Some(decision) = Self::sees(&cx, &caller, record, base) {
                    if decision.effect != Effect::Allow {
                        return Err(Stop::Refused(AdminRefusal::NotVisible));
                    }
                }
                let detail = RequestDetail {
                    id,
                    digest: record.digest,
                    state: record.state,
                    requester: record.requester.sid,
                    approvers: record.approvals.iter().map(|p| p.sid).collect(),
                    quorum: self.config.quorum(),
                    expires: record.expires,
                    reason_ref: record.reason_ref.clone(),
                    operation: record.operation.clone(),
                    facts: self.facts(&cx, &caller, record)?,
                };
                Ok((StepReply::Shown(Box::new(detail)), None))
            }
            RequestStep::Withdraw { id } => {
                let record = requests
                    .records
                    .get(&id)
                    .ok_or(Stop::Refused(AdminRefusal::PendingUnknown))?;
                describe(base, id, record);
                if !(record.requester.guid == caller.guid()
                    && record.requester.sid == *caller.sid())
                {
                    return Err(Stop::Refused(AdminRefusal::NotVisible));
                }
                refuse_handed_over(record)?;
                requests.records.remove(&id);
                Ok((StepReply::Done, None))
            }
            RequestStep::Reject { id, digest } => {
                let record = requests
                    .records
                    .get(&id)
                    .ok_or(Stop::Refused(AdminRefusal::PendingUnknown))?;
                describe(base, id, record);
                push_actor(base, caller.sid());
                match Self::sees(&cx, &caller, record, base) {
                    // The requester withdraws; it does not reject.
                    None => return Err(Stop::Refused(AdminRefusal::ApproverNotDistinct)),
                    Some(decision) if decision.effect != Effect::Allow => {
                        return Err(Stop::Refused(AdminRefusal::NotVisible))
                    }
                    Some(_) => {}
                }
                if digest != record.digest {
                    return Err(Stop::Refused(AdminRefusal::OperationMismatch));
                }
                refuse_handed_over(record)?;
                requests.records.remove(&id);
                Ok((StepReply::Done, None))
            }
            RequestStep::Approve { id, digest } => {
                // P-30 (b): the signature's place — no value can be here
                // until its scheme exists (Q-864, P-20).
                if let Some(signature) = request.signature {
                    match signature {}
                }
                self.approve(&cx, requests, request, &caller, id, digest, honour, base)
            }
        }
    }

    /// `Approve` (module documentation): the approver may see the request
    /// and is distinct from its requester and earlier approvers; the digest
    /// it names is the request's; the request is pending; everything the
    /// request was judged on holds again (else it is dropped); the
    /// approver's obligations are honoured; the approval is recorded, and at
    /// the quorum the request is approved — for a key operation, with the
    /// decision to register in keyd.
    /// Spec: docs/questions/Q-882 items 1-2; docs/51 §5.6 (P-22 items 1-2);
    /// docs/52 §4.3 (A-102); class C43.
    #[allow(clippy::too_many_arguments)]
    fn approve(
        &self,
        cx: &Cx<'_, '_, '_>,
        requests: &mut PendingRequests,
        request: &StepRequest,
        approver: &AdminSubject,
        id: u64,
        digest: OperationDigest,
        honour: &mut dyn FnMut(&[Obligation]) -> bool,
        base: &mut EventBase,
    ) -> Result<(StepReply, Option<KeyDecision>), Stop> {
        let record = requests
            .records
            .get(&id)
            .cloned()
            .ok_or(Stop::Refused(AdminRefusal::PendingUnknown))?;
        describe(base, id, &record);
        push_actor(base, approver.sid());
        let decision = match Self::sees(cx, approver, &record, base) {
            None => return Err(Stop::Refused(AdminRefusal::ApproverNotDistinct)),
            Some(decision) if decision.effect != Effect::Allow => {
                return Err(Stop::Refused(AdminRefusal::NotVisible))
            }
            Some(decision) => decision,
        };
        if digest != record.digest {
            return Err(Stop::Refused(AdminRefusal::OperationMismatch));
        }
        if record.state != RequestState::Pending {
            return Err(Stop::Refused(AdminRefusal::Conflict));
        }
        if record.approvals.iter().any(|p| p.is(approver)) {
            return Err(Stop::Refused(AdminRefusal::ApproverNotDistinct));
        }
        // Class C43: what the request was judged on must hold now; else it
        // can never run as approved — dropped.
        if let Err(stop) = self.reevaluate(cx, &record, &requests.targets) {
            if matches!(stop, Stop::Refused(_)) {
                requests.records.remove(&id);
            }
            return Err(stop);
        }
        if !honour(&caller_obligations(&decision.obligations)) {
            return Err(Stop::Refused(AdminRefusal::ObligationRefused));
        }
        let quorum = self.config.quorum();
        let Some(entry) = requests.records.get_mut(&id) else {
            return Err(Stop::Failed(AdminFailure::InternalFailure));
        };
        entry.approvals.push(Party::of(approver, &request.caller));
        let mut key_decision = None;
        if entry.approvals.len() + 1 >= quorum {
            entry.state = RequestState::Approved;
            if let (ProposedOperation::Key(op), Some(handle)) = (&entry.operation, entry.key_handle)
            {
                key_decision = Some(KeyDecision::of_request(
                    id,
                    op,
                    handle,
                    core::iter::once(entry.requester.guid)
                        .chain(entry.approvals.iter().map(|p| p.guid)),
                    entry.expires,
                    cx.instant.0,
                ));
            }
        }
        let entry = entry.clone();
        Ok((StepReply::Request(self.view_of(id, &entry)), key_decision))
    }

    /// `ListRequests`: the caller's own requests, or the pending ones it may
    /// approve (it is not the requester, has not approved, and the PDP
    /// allows it the request's Action on its Resource).
    /// Spec: docs/questions/Q-882 item 1 (`List {mine | awaiting_me}` "under
    /// PDP"); r5-a §11 MA5.
    fn list(
        &self,
        cx: &Cx<'_, '_, '_>,
        requests: &PendingRequests,
        caller: &AdminSubject,
        scope: ListScope,
    ) -> Vec<RequestSummary> {
        requests
            .records
            .iter()
            .filter(|(_, record)| match scope {
                ListScope::Mine => {
                    record.requester.guid == caller.guid() && record.requester.sid == *caller.sid()
                }
                ListScope::AwaitingMe => {
                    record.state == RequestState::Pending
                        && !record.requester.is(caller)
                        && !record.approvals.iter().any(|p| p.is(caller))
                        && cx
                            .decide(
                                caller.subject(),
                                record.action.clone(),
                                record.resource.clone(),
                            )
                            .effect
                            == Effect::Allow
                }
            })
            .map(|(id, record)| RequestSummary {
                id: *id,
                digest: record.digest,
                state: record.state,
                operation: record.operation.clone(),
                requester: record.requester.sid,
                approvals: record.approvals.len(),
                quorum: self.config.quorum(),
                expires: record.expires,
            })
            .collect()
    }

    /// The facts of the objects `record`'s operation names, as `viewer` may
    /// see them now: a directory operation's through `viewer`'s visibility
    /// gate (an object it may not see is left out — docs/52 R10, A-55), a key
    /// operation's target as the key path reads it (after `PolicyAdmin` on
    /// `keys`, which an eligible viewer holds); a policy change names no
    /// object.
    /// Spec: docs/questions/Q-882 item 1, Q-887 items 2-3; docs/52 R10.
    fn facts(
        &self,
        cx: &Cx<'_, '_, '_>,
        viewer: &AdminSubject,
        record: &Record,
    ) -> Result<Vec<RequestFact>, Stop> {
        let mut facts = Vec::new();
        for guid in record.basis.named().into_iter().take(MAX_FACTS) {
            let found = match &record.operation {
                ProposedOperation::Policy(_) => None,
                ProposedOperation::Key(_) => match cx.resolve(guid) {
                    Ok(target) => Some((target.guid, target.obj, target.dn, target.class)),
                    Err(Stop::Refused(_)) => None,
                    Err(failed) => return Err(failed),
                },
                ProposedOperation::Directory(_) => match cx.gate(viewer.subject()).visible(guid) {
                    Ok(Visibility::Visible { object, .. }) => {
                        let resolved = Resolved::from_visible(cx, object)?;
                        Some((resolved.guid, resolved.obj, resolved.dn, resolved.class))
                    }
                    Ok(Visibility::NotFound(_) | Visibility::Refused(_)) => None,
                    Err(GateFault::Store(e)) => return Err(crate::checks::store_failure(&e)),
                    Err(GateFault::Name | GateFault::TooDeep) => {
                        return Err(Stop::Failed(AdminFailure::StoreFailure))
                    }
                },
            };
            if let Some((guid, obj, dn, class)) = found {
                let class = self
                    .ids
                    .class(class)
                    .ok_or(Stop::Failed(AdminFailure::IntegrityFailure))?
                    .name;
                let sid = record::sid(&obj, self.ids.object_sid).map_err(malformed)?;
                let tier = cx.explicit_tier(&dn)?;
                facts.push(RequestFact {
                    guid,
                    dn,
                    class,
                    sid,
                    tier,
                });
            }
        }
        Ok(facts)
    }
}
