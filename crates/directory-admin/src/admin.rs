//! The write PEP: `prepare` (every check, against ONE view; it plans the
//! decision event and everything `apply` needs).
//!
//! # The steps of `prepare` (docs/51 §7.4 steps 2-4)
//!
//! 1. The requester's Subject from its verified ticket (§5.3); an unknown
//!    or unusable account ⇒ `Unauthenticated`; `ticket_age` above the
//!    configured threshold ⇒ `TicketAge` (R51-10).
//! 2. The request's own values (names, groupType, accountExpires, …), which
//!    reveal nothing about the directory (§11).
//! 3. The objects the request names, through the visibility gate
//!    (`directory_pip::VisibilityGate`, docs/52 R10) — the only source of a
//!    [`Resolved`]: absent ⇒ `NotFound`; not visible to the requester
//!    (`DirList` on the parent, [MS-ADTS] 5.1.3.3.6) or not readable by it
//!    (`DirRead`, docs/11 §7) ⇒ `NotVisible` — one verdict, the client is
//!    told `NotFound` either way (A-55; docs/questions/Q-485).
//! 4. `decide` for the requester on the operation's Action and Resource
//!    (§5.2) ⇒ `PolicyDenied`.
//! 5. The semantic checks of §11 and §5.2 (protected objects, classes,
//!    membership rules, the cycle refusal, the member limit, values already
//!    taken, the new object's descriptor) and the counters' presence.
//! 6. The self-lockout guard (Q-295 item 4).
//! 7. Dual control (§5.6, P-22) — **one mechanism** (task D2-c;
//!    docs/questions/Q-882, A-148): each handler only *classifies* the
//!    operation ([`Dual`]: whether its rule needs an approver, and the
//!    Action and Resource every approver must be allowed). When it does,
//!    the operation runs only by consuming an **approved pending request**
//!    dird holds for exactly this operation (its digest and its fields) and
//!    this requester (crate::requests): every approver and every object the
//!    operation depends on are re-evaluated against this view first (class
//!    C43), and the request is consumed. Without one ⇒ `ApprovalRequired`.
//!    There are no approvals inside a request (the field is retired).
//!
//! Spec: docs/51 §5.2-§5.7, §7.4, §8, §9, §10, §11; A-72..A-79, A-83..A-85,
//! P-22; docs/questions/Q-882.

use dirstore::{AttrId, CounterState, Object};
use dtyp::{Guid, Sid};
use ipc_audit::{AdminFailure, AdminRefusal, DirAdminEvent, EventBody};
use ipc_audit_client::IntentRecord;
use keyd_types::{
    KeyHandle, KeyPurpose, OperationDigest, PrincipalBinding, PrincipalId, ServiceKeyHandle,
};
use krb_proto::constants::{KRB_NT_PRINCIPAL, KRB_NT_SRV_HST};
use krb_proto::{KerberosString, KerberosTime, PrincipalName};
use pdp::{
    Action, AttrId as PdpAttrId, ControlRightId, Decision, Effect, ObjClass, Obligation,
    PolicySnapshot, Resource, Tier,
};

use ad_schema::flags::group_type::{
    ALLOWED_VALUES, GROUP_TYPE_ACCOUNT_GROUP, GROUP_TYPE_SECURITY_ENABLED,
};
use ad_schema::flags::user_account_control::{
    ADS_UF_ACCOUNT_DISABLE, ADS_UF_NORMAL_ACCOUNT, ADS_UF_WORKSTATION_TRUST_ACCOUNT,
};
use ad_schema::Phase1Schema;
use directory_pip::{
    account_salt, AccountKind, DirectoryView, GateFault, UnseenCause, Visibility, MAX_DN_DEPTH,
};

use crate::audit::{pdp_reason, sid_value, EventBase, Refusal, Stop};
use crate::checks::{
    domain_sid, local_ipc_security, malformed, store_failure, Cx, LockoutChange, Resolved,
};
use crate::config::{AdminConfig, ConfigError, CHANGE_SEQ_COUNTER, RID_COUNTER};
use crate::descriptor::new_object_sd;
use crate::ids::{ClassIds, Ids};
use crate::invariants::{End, Invariants, LinkProof};
use crate::names;
use crate::operation::{
    CompletePasswordSet, CreateComputer, CreateContainerLike, CreateGroup, CreateUser, LookupKey,
    Membership, Operation, PasswordSetOutcome, SetAccountExpires, SetEnabled,
};
use crate::random::RandomSource;
use crate::record;
use crate::reply::{KeyTarget, LookupResult, PasswordChangeTarget, PasswordSetReply, Reply};
use crate::requests::{Basis, PendingRequests, ProposedOperation};
use crate::subject::{AdminSubject, SubjectError, VerifiedTicket};
use crate::time;

/// The control access right User-Force-Change-Password: rightsGuid
/// `00299570-246d-11d0-a768-00aa006e0529`, its printed groups mapped to the
/// GUID members as the project decided for every schema GUID (A-31: group 1
/// = Data1, group 2 = Data2, group 3 = Data3, groups 4-5 = the eight Data4
/// bytes in order).
/// Spec: [MS-ADTS] v20261026 6.1.1.2.7.53; docs/47 §9.2 step 1; docs/51
/// §5.2 row 5; A-31.
pub const USER_FORCE_CHANGE_PASSWORD: Guid = Guid {
    data1: 0x0029_9570,
    data2: 0x246d,
    data3: 0x11d0,
    data4: [0xa7, 0x68, 0x00, 0xaa, 0x00, 0x6e, 0x05, 0x29],
};

/// accountExpires "never". Spec: [MS-SAMR] 3.1.1.8.1 item 1.2
/// ("0x7FFFFFFF FFFFFFFF (default value)"); docs/47 §4.2 (R47-5b: the admin
/// plane writes "never" as this value only).
pub const ACCOUNT_EXPIRES_NEVER: i64 = i64::MAX;

/// One admin request, after the caller verified its AP-REQ through keyd.
/// There are no approvals in it: dual control is a pending request dird
/// holds (crate::requests; docs/questions/Q-882 — the in-request approvals
/// of docs/51 §7.2 are retired).
/// Spec: docs/51 §7.2 (`auth`), §7.3; docs/52 §5 item 4 (the operation
/// digest); docs/questions/Q-882.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// dird's number for the operation: its `Decision` and `Outcome`
    /// events carry it (Q-340 item 1).
    pub operation_id: u64,
    /// The operation.
    pub operation: Operation,
    /// The operation digest dird computed from the request it decoded
    /// (crate ipc-dird-admin `operation_digest`) and had keyd verify the
    /// AP-REQ against — the operation's fingerprint (docs/questions/Q-888):
    /// every event of the operation carries it, and an approved pending
    /// request is matched by it. The PEP reports `channel_bound` to the PDP
    /// only when the ticket below carries exactly this digest (R2).
    /// Spec: docs/52 §5 items 1, 4; RFC 4120 §5.5.1.
    pub operation_digest: OperationDigest,
    /// The requester's verified ticket.
    pub requester: VerifiedTicket,
}

/// Which AP-REQ keyd did not verify — for the refusal the caller records
/// without calling `prepare` (docs/51 §7.4 step 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VerificationFailure {
    /// The requester's AP-REQ did not verify (`Unauthenticated`).
    Requester,
    /// An approver's AP-REQ (of an `Approve` / `Reject`) did not verify
    /// (`ApproverUnauthenticated`).
    Approver,
    /// keyd did not answer (`Failed(KeydUnavailable)`, A-56).
    KeydUnavailable,
}

/// How an operation's rule classifies it for dual control (docs/51 §5.6,
/// P-22 item 1): whether it needs an approver, and the Action and Resource
/// every approver must be allowed — the requester's own (P-22 item 2: "the
/// same Action and Resource"). Each handler computes it; crate::requests
/// alone acts on it (one mechanism — docs/52 C14; docs/questions/Q-882).
/// Spec: docs/51 §5.6 (R51-11); P-22; docs/questions/Q-882.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Dual {
    /// No approver is needed.
    NotRequired,
    /// An approver is needed; each must be allowed `action` on `resource`.
    Required {
        /// The operation's Action.
        action: Action,
        /// The operation's Resource.
        resource: Resource,
    },
}

impl Dual {
    /// The classification of an operation whose rule `required` holds.
    pub(crate) fn of(required: bool, action: &Action, resource: &Resource) -> Dual {
        if required {
            Dual::Required {
                action: action.clone(),
                resource: resource.clone(),
            }
        } else {
            Dual::NotRequired
        }
    }
}

/// What one operation's checks produced: the plan, the obligations of the
/// requester's Allow, and the dual-control classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Handled {
    pub(crate) plan: Plan,
    pub(crate) obligations: Vec<Obligation>,
    pub(crate) dual: Dual,
}

/// What `apply` will write, with the state `prepare` decided on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WritePlan {
    /// The change-seq counter as `prepare` saw it.
    pub(crate) change_seq: CounterState,
    /// Every object the write depends on, as `prepare` read it.
    pub(crate) seen: Vec<(Guid, Object)>,
    /// The write.
    pub(crate) kind: WriteKind,
}

/// The new object of a create.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CreatePlan {
    pub(crate) parent: Guid,
    pub(crate) class: ClassIds,
    /// For a security principal: the NC root, whose objectSid is the domain
    /// SID the new objectSid extends.
    pub(crate) domain_root: Option<Guid>,
    /// The values the request determines (cn / ou, sAMAccountName,
    /// userAccountControl, accountExpires, groupType, …).
    pub(crate) attributes: Vec<(AttrId, Vec<Vec<u8>>)>,
}

/// What a password write hands back once committed: the key sets of an
/// administrator's `BeginPasswordSet` (admind's `set_secret`, on a
/// `SetSecret` decision), or the one key set of a user's own `ChangePassword`
/// (keyd's `complete_change_password`, on a `ChangePassword` decision —
/// docs/questions/Q-662: the decision names its executor). The write itself
/// is the same for both (`pwdLastSet = now`, crate::apply): one write path,
/// two replies.
/// Spec: docs/51 §5.2 row 5; docs/53 §4.4 (R53-5), §5.6 step 5; A-126.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PasswordWrite {
    /// `BeginPasswordSet`.
    Set(PasswordSetReply),
    /// `ChangePassword` (task K6).
    Change(PasswordChangeTarget),
}

/// The write of one operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WriteKind {
    Create(CreatePlan),
    PasswordSet {
        target: Guid,
        reply: PasswordWrite,
    },
    SetUac {
        target: Guid,
        uac: u32,
    },
    SetAccountExpires {
        target: Guid,
        value: i64,
    },
    SetMembers {
        group: Guid,
        members: Vec<Guid>,
        /// For an `AddMember`: the write invariants' proof of the link walks
        /// against `prepare`'s snapshot (crate::invariants, "Links checked
        /// once"); `None` for a removal.
        proof: Option<LinkProof>,
    },
    Delete {
        target: Guid,
    },
}

/// What `prepare` produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Plan {
    /// An operation that commits nothing (`Lookup`, `CompletePasswordSet`):
    /// its reply, available at once.
    Read(Reply),
    /// A write for `apply`.
    Write(WritePlan),
}

/// A prepared operation: the decision event to send (and have acknowledged)
/// before anything is committed, and everything `apply` needs.
///
/// **Not `Clone`** (docs/52 N5, R6): its decision event is its
/// [`IntentRecord`]; `apply` takes it only as an
/// `ipc_audit_client::AckedIntent<Prepared>` — which only the caller's
/// `ipc_audit_client::AuditGate` produces, after auditd acknowledged **this**
/// prepared operation's decision event — so a write cannot be applied before
/// the acknowledgement, and one acknowledgement applies one write.
///
/// Spec: docs/51 §5.7 item 2, §7.4 step 5; A-85; docs/52 §2 row 38 (N5),
/// §3.11 R6 (a).
#[derive(Debug, PartialEq, Eq)]
pub struct Prepared {
    pub(crate) base: EventBase,
    decision: DirAdminEvent,
    obligations: Vec<Obligation>,
    pub(crate) requester: Sid,
    pub(crate) plan: Plan,
}

impl Prepared {
    /// The `Decision` event (`Proceed`). For a write, the caller sends it
    /// and waits for auditd's acknowledgement before it begins the commit
    /// (docs/51 §5.7 item 2).
    #[must_use]
    pub fn decision_event(&self) -> &DirAdminEvent {
        &self.decision
    }

    /// The obligations of the requester's Allow decision other than the
    /// audit record this crate plans (`RateLimit`, `Constrain`), which the
    /// caller must honour (docs/11 §2: "the PEP must honour obligations").
    #[must_use]
    pub fn obligations(&self) -> &[Obligation] {
        &self.obligations
    }

    /// `true` if the operation commits a write (call `apply`); `false` for
    /// `Lookup` and `CompletePasswordSet`, whose reply is [`Prepared::reply`].
    #[must_use]
    pub fn writes(&self) -> bool {
        matches!(self.plan, Plan::Write(_))
    }

    /// The reply of an operation that commits nothing; `None` for a write.
    #[must_use]
    pub fn reply(&self) -> Option<&Reply> {
        match &self.plan {
            Plan::Read(reply) => Some(reply),
            Plan::Write(_) => None,
        }
    }
}

impl Prepared {
    /// A prepared operation from its parts: the `Decision` event
    /// (`Proceed`, at `now`) of `base`, the obligations of the requester's
    /// Allow other than the audit record, the requester's objectSid and the
    /// plan — for `prepare` and `prepare_change_password` alike (task K6).
    /// Spec: docs/51 §5.7 item 2, §7.4 step 5; A-85.
    pub(crate) fn planned(
        base: EventBase,
        now: &KerberosTime,
        obligations: Vec<Obligation>,
        requester: Sid,
        plan: Plan,
    ) -> Prepared {
        Prepared {
            decision: base.proceed(now),
            base,
            obligations: obligations
                .into_iter()
                .filter(|o| !matches!(o, Obligation::Audit))
                .collect(),
            requester,
            plan,
        }
    }
}

impl IntentRecord for Prepared {
    /// The `Decision` event (`Proceed`): what auditd must acknowledge before
    /// `apply` (A-85).
    /// Spec: docs/51 §5.7 item 2; docs/52 §3.11 R6 (a).
    fn intent_event(&self) -> EventBody {
        EventBody::DirAdmin(Box::new(self.decision.clone()))
    }
}

/// The write PEP: its configuration, the schema identifiers, the write
/// invariants every write passes (docs/52 R13), and the random source for
/// objectGUIDs. Spec: docs/51 §12 task A3.
pub struct DirectoryAdmin<R: RandomSource> {
    pub(crate) config: AdminConfig,
    pub(crate) ids: Ids,
    pub(crate) invariants: Invariants,
    pub(crate) rng: R,
}

impl<R: RandomSource> DirectoryAdmin<R> {
    /// Build the PEP. Fails closed if the schema lacks an attribute or
    /// class it needs. `rng` must be [`crate::OsRandom`] outside tests
    /// (A-15).
    pub fn new(
        config: AdminConfig,
        schema: &Phase1Schema,
        rng: R,
    ) -> Result<DirectoryAdmin<R>, ConfigError> {
        let invariants = Invariants::new(schema, config.protected().service_objects.clone())?;
        Ok(DirectoryAdmin {
            config,
            ids: Ids::resolve(schema)?,
            invariants,
            rng,
        })
    }

    /// The configuration.
    #[must_use]
    pub fn config(&self) -> &AdminConfig {
        &self.config
    }

    /// The refusal of a request whose AP-REQ keyd did not verify: the
    /// `Decision` event to record (no requester SID — none was verified;
    /// the operation's digest, `operation_digest`, as dird computed it) and
    /// the uniform `Denied` (or `Unavailable` when keyd is down).
    /// Spec: docs/51 §7.4 step 1 ("failure ⇒ `Denied` uniform (A-26), keyd
    /// down ⇒ `Unavailable` (A-56)"); docs/questions/Q-888.
    #[must_use]
    pub fn refuse_unverified(
        &self,
        operation_id: u64,
        operation: &Operation,
        operation_digest: &OperationDigest,
        failure: VerificationFailure,
        now: &KerberosTime,
    ) -> Refusal {
        let base = EventBase::of_request(operation_id, operation, operation_digest);
        let stop = match failure {
            VerificationFailure::Requester => Stop::Refused(AdminRefusal::Unauthenticated),
            VerificationFailure::Approver => Stop::Refused(AdminRefusal::ApproverUnauthenticated),
            VerificationFailure::KeydUnavailable => Stop::Failed(AdminFailure::KeydUnavailable),
        };
        base.decision_refusal(now, stop)
    }

    /// Run every check of the request against ONE view (module
    /// documentation) and plan the operation. `view` and `policy` must be of
    /// the same policy version (docs/47 §8.1); for a write the caller should
    /// begin its `WriteTxn` before taking `view`, so that the view is the
    /// transaction's starting state (`apply` refuses otherwise — see
    /// `DirectoryAdmin::apply`).
    ///
    /// An operation whose rule needs an approver consumes the approved
    /// pending request `requests` holds for it (module documentation, step
    /// 7) — at the decision: an approval allows one execution attempt,
    /// whatever happens after `prepare` (fail closed).
    ///
    /// `Err` carries the `Decision` event of the refusal (send it) and the
    /// client-visible status. Spec: docs/51 §7.4 steps 2-4; A-85;
    /// docs/questions/Q-882 item 2.
    pub fn prepare(
        &self,
        request: &Request,
        requests: &mut PendingRequests,
        view: &DirectoryView<'_>,
        policy: &PolicySnapshot,
        now: &KerberosTime,
    ) -> Result<Prepared, Refusal> {
        let mut base = EventBase::of_request(
            request.operation_id,
            &request.operation,
            &request.operation_digest,
        );
        match self.checked(request, requests, view, policy, now, &mut base) {
            Ok((plan, obligations, requester)) => {
                Ok(Prepared::planned(base, now, obligations, requester, plan))
            }
            Err(stop) => Err(base.decision_refusal(now, stop)),
        }
    }

    /// The checks, in order (module documentation).
    fn checked(
        &self,
        request: &Request,
        requests: &mut PendingRequests,
        view: &DirectoryView<'_>,
        policy: &PolicySnapshot,
        now: &KerberosTime,
        base: &mut EventBase,
    ) -> Result<(Plan, Vec<Obligation>, Sid), Stop> {
        // The view must be of this PEP's domain (fail closed on a
        // misassembled caller).
        if view.context().realm() != self.config.realm()
            || view.context().naming_context() != self.config.naming_context()
        {
            return Err(Stop::Failed(AdminFailure::InternalFailure));
        }
        // R2 (docs/52 §5 item 4): the channel is bound only if keyd verified
        // the request's ticket bound to this very operation.
        let bound = request.requester.bound_to(&request.operation_digest);
        let cx = Cx::new(
            &self.config,
            &self.ids,
            view,
            policy,
            now,
            local_ipc_security(bound),
        )?;
        // Step 1 — the requester (docs/51 §5.3, §5.5; A-73; R51-10).
        let requester = subject_of(&cx, &request.requester).map_err(|e| match e {
            SubjectError::NotUsable => Stop::Refused(AdminRefusal::Unauthenticated),
            SubjectError::Unavailable => Stop::Failed(AdminFailure::StoreFailure),
        })?;
        base.requester = sid_value(requester.sid());
        if requester.ticket_age() > self.config.ticket_age_max() {
            return Err(Stop::Refused(AdminRefusal::TicketAge));
        }
        let ctx = OpCx {
            cx: &cx,
            requester: &requester,
        };
        let handled = self.evaluate(&ctx, base, &request.operation)?;
        // Step 7 — dual control, by the one mechanism (crate::requests).
        if let Dual::Required { action, resource } = &handled.dual {
            let basis = Basis::of_plan(&cx, &handled.plan)?;
            self.consume_approved(
                &cx,
                requests,
                &requester,
                &ProposedOperation::Directory(request.operation.clone()),
                &request.operation_digest,
                action,
                resource,
                &basis,
                base,
            )?;
        }
        Ok((handled.plan, handled.obligations, *requester.sid()))
    }

    /// The checks of one directory operation for `ctx.requester` against
    /// `ctx`'s view (module documentation, steps 2-6, and step 7's
    /// classification), committing nothing — the same code for a direct
    /// execution, a proposal and the re-evaluation of a pending request
    /// (crate::requests; docs/52 C14).
    /// Spec: docs/51 §5.2, §5.6, §7.4 steps 2-4, §11.
    pub(crate) fn evaluate(
        &self,
        ctx: &OpCx<'_, '_, '_, '_>,
        base: &mut EventBase,
        operation: &Operation,
    ) -> Result<Handled, Stop> {
        Ok(match operation {
            Operation::CreateUser(c) => self.create(ctx, base, NewObject::User(c))?,
            Operation::CreateComputer(c) => self.create(ctx, base, NewObject::Computer(c))?,
            Operation::CreateGroup(c) => self.create(ctx, base, NewObject::Group(c))?,
            Operation::CreateOu(c) => self.create(ctx, base, NewObject::Ou(c))?,
            Operation::CreateContainer(c) => self.create(ctx, base, NewObject::Container(c))?,
            Operation::BeginPasswordSet { target } => {
                self.begin_password_set(ctx, base, *target)?
            }
            Operation::CompletePasswordSet(c) => self.complete_password_set(ctx, base, c)?,
            Operation::SetEnabled(s) => self.set_enabled(ctx, base, s)?,
            Operation::SetAccountExpires(s) => self.set_account_expires(ctx, base, s)?,
            Operation::AddMember(m) => self.membership(ctx, base, m, true)?,
            Operation::RemoveMember(m) => self.membership(ctx, base, m, false)?,
            Operation::Delete { target } => self.delete(ctx, base, *target)?,
            Operation::Lookup(key) => self.lookup(ctx, base, key)?,
        })
    }
}

/// The Subject of a verified ticket. Spec: docs/51 §5.3.
pub(crate) fn subject_of(
    cx: &Cx<'_, '_, '_>,
    ticket: &VerifiedTicket,
) -> Result<AdminSubject, SubjectError> {
    subject_of_facts(cx, &ticket.crealm, &ticket.cname, &ticket.authtime)
}

/// The Subject of the client a ticket keyd verified names — the admin
/// plane's `VerifiedTicket`, or a kpasswd request's `ChangePasswordTicket`
/// (task K6): one construction for both (docs/53 §4.4: "the same
/// function").
/// Spec: docs/51 §5.3; docs/53 §5.6 step 4.
pub(crate) fn subject_of_facts(
    cx: &Cx<'_, '_, '_>,
    crealm: &krb_proto::Realm,
    cname: &PrincipalName,
    authtime: &KerberosTime,
) -> Result<AdminSubject, SubjectError> {
    AdminSubject::from_verified_ticket(cx.pep.accounts(), crealm, cname, authtime, &cx.now)
}

/// The per-request part every operation handler reads.
pub(crate) struct OpCx<'o, 'c, 'v, 'a> {
    pub(crate) cx: &'o Cx<'c, 'v, 'a>,
    pub(crate) requester: &'o AdminSubject,
}

/// The object a create makes.
#[derive(Clone, Copy)]
enum NewObject<'r> {
    User(&'r CreateUser),
    Computer(&'r CreateComputer),
    Group(&'r CreateGroup),
    Ou(&'r CreateContainerLike),
    Container(&'r CreateContainerLike),
}

/// The values a create determines from the request alone.
struct NewValues {
    class: ClassIds,
    /// The RDN value (cn / ou), for the name check under the parent.
    rdn: String,
    attributes: Vec<(AttrId, Vec<Vec<u8>>)>,
    /// (attribute, value) pairs the unique index must not already hold.
    uniques: Vec<(AttrId, String)>,
    /// A security principal: gets a RID and an objectSid.
    principal: bool,
}

impl<R: RandomSource> DirectoryAdmin<R> {
    /// The requester's decision on `action` / `resource`; the reason goes to
    /// the event. Deny ⇒ `PolicyDenied`. Spec: docs/51 §7.4 step 3; docs/11
    /// §4.
    pub(crate) fn authorize(
        &self,
        ctx: &OpCx<'_, '_, '_, '_>,
        base: &mut EventBase,
        action: &Action,
        resource: &Resource,
    ) -> Result<Vec<Obligation>, Stop> {
        let decision = ctx
            .cx
            .decide(ctx.requester.subject(), action.clone(), resource.clone());
        base.pdp = Some(pdp_reason(decision.reason));
        if decision.effect != Effect::Allow {
            return Err(Stop::Refused(AdminRefusal::PolicyDenied));
        }
        Ok(decision.obligations)
    }

    /// The object `guid` a request names, through the visibility gate —
    /// the only way to a [`Resolved`]: absent ⇒ `NotFound`; present but its
    /// parent not listable ([MS-ADTS] 5.1.3.3.6) or the object not readable
    /// by the requester ⇒ `NotVisible`, the PDP's reason in the event — one
    /// verdict, told to the client as `NotFound` either way
    /// (A-55) — for every object a request names, not only for `Lookup`
    /// (docs/questions/Q-358 item 3). Also returned: the decision that made
    /// the object visible (`Lookup`'s authorising decision).
    /// Spec: [MS-ADTS] 5.1.3.3.6; docs/11 §7 as cited in docs/51 §5.2 row
    /// 10; docs/52 R10; A-55; docs/questions/Q-485.
    fn named<'v>(
        &self,
        ctx: &OpCx<'_, '_, 'v, '_>,
        base: &mut EventBase,
        guid: Guid,
    ) -> Result<(Resolved<'v>, Decision), Stop> {
        let cx = ctx.cx;
        match cx.gate(ctx.requester.subject()).visible(guid) {
            Ok(Visibility::Visible { object, decision }) => {
                Ok((Resolved::from_visible(cx, object)?, decision))
            }
            Ok(Visibility::NotFound(unseen)) => match unseen.audit_cause() {
                UnseenCause::Absent => Err(Stop::Refused(AdminRefusal::NotFound)),
                UnseenCause::Hidden(reason) => {
                    base.pdp = Some(pdp_reason(reason));
                    Err(Stop::Refused(AdminRefusal::NotVisible))
                }
            },
            // Any denial of a named object is `NotVisible` on the admin
            // plane (A-55: the client hears `NotFound`).
            Ok(Visibility::Refused(decision)) => {
                base.pdp = Some(pdp_reason(decision.reason));
                Err(Stop::Refused(AdminRefusal::NotVisible))
            }
            Err(GateFault::Store(e)) => Err(store_failure(&e)),
            Err(GateFault::Name | GateFault::TooDeep) => {
                Err(Stop::Failed(AdminFailure::StoreFailure))
            }
        }
    }

    /// The self-lockout guard: refuse a change that would leave fewer
    /// enabled Tier-0 administrators than the quorum. A change that does not
    /// lower the count is never refused (a store already below the quorum
    /// stays manageable for everything else).
    /// Spec: Q-295 item 4 (P-22); docs/51 §5.6; docs/questions/Q-357 items
    /// 6-8.
    fn lockout_guard(&self, cx: &Cx<'_, '_, '_>, change: LockoutChange) -> Result<(), Stop> {
        let before = cx.enabled_tier0_admins(None)?;
        let after = cx.enabled_tier0_admins(Some(&change))?;
        if after < self.config.quorum() && after < before {
            return Err(Stop::Refused(AdminRefusal::SelfLockout));
        }
        Ok(())
    }

    /// The change-seq counter must exist and not be exhausted (A-83: never
    /// created here; missing ⇒ refusal).
    /// Spec: docs/51 §8.3; A-75; A-83.
    pub(crate) fn change_seq(&self, cx: &Cx<'_, '_, '_>) -> Result<CounterState, Stop> {
        let state = cx
            .counter(CHANGE_SEQ_COUNTER)?
            .ok_or(Stop::Failed(AdminFailure::StoreFailure))?;
        if state.is_exhausted() {
            return Err(Stop::Failed(AdminFailure::StoreFailure));
        }
        Ok(state)
    }

    /// The RID counter must exist and not be exhausted.
    /// Spec: docs/51 §8.3 ("exhaustion ⇒ refusal (fail closed)"); A-75;
    /// A-83.
    fn rid_available(&self, cx: &Cx<'_, '_, '_>) -> Result<(), Stop> {
        let state = cx
            .counter(RID_COUNTER)?
            .ok_or(Stop::Failed(AdminFailure::StoreFailure))?;
        if state.is_exhausted() {
            return Err(Stop::Refused(AdminRefusal::RidExhausted));
        }
        Ok(())
    }

    /// The values of a new object (docs/51 §5.2 rows 1-4, §11).
    fn new_values(&self, new: NewObject<'_>) -> Result<NewValues, Stop> {
        let ids = &self.ids;
        let invalid_name = Stop::Refused(AdminRefusal::AccountNameInvalid);
        let invalid_value = Stop::Refused(AdminRefusal::ValueInvalid);
        let text = |s: &str| vec![s.as_bytes().to_vec()];
        Ok(match new {
            // CreateUser: cn = sAMAccountName = sam; UAC = N|D (never NR —
            // A-79, R46-6; [MS-SAMR] 3.1.1.8.1 item 1.5 adds PASSWD_NOTREQD,
            // refused here); accountExpires "never" (3.1.1.8.1 item 1.2);
            // no pwdLastSet (docs/51 §5.2 row 1: set by BeginPasswordSet).
            NewObject::User(c) => {
                if !names::user_sam_ok(&c.sam) {
                    return Err(invalid_name);
                }
                let mut attributes = vec![
                    (ids.cn, text(&c.sam)),
                    (ids.sam_account_name, text(&c.sam)),
                    (
                        ids.user_account_control,
                        vec![record::encode_flags(
                            ADS_UF_NORMAL_ACCOUNT | ADS_UF_ACCOUNT_DISABLE,
                        )],
                    ),
                    (
                        ids.account_expires,
                        vec![record::encode_int64(ACCOUNT_EXPIRES_NEVER)],
                    ),
                ];
                let mut uniques = vec![(ids.sam_account_name, c.sam.clone())];
                if let Some(upn) = &c.upn {
                    if !names::upn_ok(upn) {
                        return Err(invalid_value);
                    }
                    attributes.push((ids.user_principal_name, text(upn)));
                    uniques.push((ids.user_principal_name, upn.clone()));
                }
                if let Some(description) = &c.description {
                    if !names::description_ok(description) {
                        return Err(invalid_value);
                    }
                    attributes.push((ids.description, text(description)));
                }
                NewValues {
                    class: ids.user.clone(),
                    rdn: c.sam.clone(),
                    attributes,
                    uniques,
                    principal: true,
                }
            }
            // CreateComputer: sAMAccountName = name ‖ "$", UAC = WT|D (ST is
            // never set here — A-79), one SPN with a lower-case host,
            // accountExpires "never" ([MS-SAMR] 3.1.1.8.1 item 1.2: computer
            // derives from user).
            NewObject::Computer(c) => {
                if !names::computer_name_ok(&c.name) {
                    return Err(invalid_name);
                }
                if !names::dns_host_name_ok(&c.dns_host_name) {
                    return Err(invalid_value);
                }
                let sam = names::computer_sam(&c.name);
                let mut attributes = vec![
                    (ids.cn, text(&c.name)),
                    (ids.sam_account_name, text(&sam)),
                    (
                        ids.user_account_control,
                        vec![record::encode_flags(
                            ADS_UF_WORKSTATION_TRUST_ACCOUNT | ADS_UF_ACCOUNT_DISABLE,
                        )],
                    ),
                    (
                        ids.account_expires,
                        vec![record::encode_int64(ACCOUNT_EXPIRES_NEVER)],
                    ),
                    (ids.dns_host_name, text(&c.dns_host_name)),
                ];
                let mut uniques = vec![(ids.sam_account_name, sam)];
                if let Some(spn) = &c.spn {
                    if !names::spn_ok(spn, &c.dns_host_name) {
                        return Err(invalid_value);
                    }
                    attributes.push((ids.service_principal_name, text(spn)));
                    uniques.push((ids.service_principal_name, spn.clone()));
                }
                NewValues {
                    class: ids.computer.clone(),
                    rdn: c.name.clone(),
                    attributes,
                    uniques,
                    principal: true,
                }
            }
            // CreateGroup: groupType one of the six phase-1 values, default
            // GROUP_TYPE_SECURITY_ACCOUNT ([MS-SAMR] 3.1.1.8.1 item 2.2;
            // docs/46 §8.2).
            NewObject::Group(c) => {
                if !names::group_sam_ok(&c.sam) {
                    return Err(invalid_name);
                }
                let group_type = c
                    .group_type
                    .unwrap_or(GROUP_TYPE_SECURITY_ENABLED | GROUP_TYPE_ACCOUNT_GROUP);
                if !ALLOWED_VALUES
                    .iter()
                    .any(|v| u32::from_be_bytes(v.to_be_bytes()) == group_type)
                {
                    return Err(invalid_value);
                }
                NewValues {
                    class: ids.group.clone(),
                    rdn: c.sam.clone(),
                    attributes: vec![
                        (ids.cn, text(&c.sam)),
                        (ids.sam_account_name, text(&c.sam)),
                        (ids.group_type, vec![record::encode_flags(group_type)]),
                    ],
                    uniques: vec![(ids.sam_account_name, c.sam.clone())],
                    principal: true,
                }
            }
            NewObject::Ou(c) => {
                if !names::rdn_value_ok(&c.name) {
                    return Err(invalid_value);
                }
                NewValues {
                    class: ids.organizational_unit.clone(),
                    rdn: c.name.clone(),
                    attributes: vec![(ids.ou, text(&c.name))],
                    uniques: Vec::new(),
                    principal: false,
                }
            }
            NewObject::Container(c) => {
                if !names::rdn_value_ok(&c.name) {
                    return Err(invalid_value);
                }
                NewValues {
                    class: ids.container.clone(),
                    rdn: c.name.clone(),
                    attributes: vec![(ids.cn, text(&c.name))],
                    uniques: Vec::new(),
                    principal: false,
                }
            }
        })
    }

    /// `CreateUser` / `CreateComputer` / `CreateGroup` / `CreateOu` /
    /// `CreateContainer`: `DirAddChild(class)` on the parent; dual control
    /// when the parent lies in a subtree the tier map explicitly makes
    /// Tier0. Spec: docs/51 §5.2 rows 1-4, §5.6, §7.4, §10, §11.
    fn create(
        &self,
        ctx: &OpCx<'_, '_, '_, '_>,
        base: &mut EventBase,
        new: NewObject<'_>,
    ) -> Result<Handled, Stop> {
        let cx = ctx.cx;
        let values = self.new_values(new)?;
        let parent_guid = match new {
            NewObject::User(c) => c.parent,
            NewObject::Computer(c) => c.parent,
            NewObject::Group(c) => c.parent,
            NewObject::Ou(c) | NewObject::Container(c) => c.parent,
        };
        let (parent, _) = self.named(ctx, base, parent_guid)?;
        let action = Action::DirAddChild(ObjClass(values.class.guid));
        let resource = Resource::DirObject {
            dn: parent.dn.clone(),
            attr: None,
        };
        let obligations = self.authorize(ctx, base, &action, &resource)?;
        // The parent's class must be a possible superior of the new class
        // (docs/46 §4.4, §8.3 item 2; dirstore refuses it too).
        let schema = cx.pep.context().schema().schema();
        let definition = schema
            .class(values.class.id)
            .ok_or(Stop::Failed(AdminFailure::InternalFailure))?;
        if !definition.poss_superiors.contains(&parent.class) {
            return Err(Stop::Refused(AdminRefusal::ValueInvalid));
        }
        // A live child of the parent with the same RDN (docs/46 §8.3 item
        // 3; dirstore `NameExists`).
        cx.name_free(parent.guid, &values.rdn)?;
        // A value the unique index already holds ([MS-SAMR] 3.1.1.8.4 item
        // 2; docs/46 §8.5).
        for (attr, value) in &values.uniques {
            cx.unique_free(*attr, value)?;
        }
        // The new object's descriptor must have a DACL ([MS-ADTS] 6.1.3
        // item 7; A-84).
        new_object_sd(
            &self.ids,
            &parent.obj,
            values.class.guid,
            ctx.requester.sid(),
        )?;
        let mut seen = vec![(parent.guid, parent.obj.clone())];
        let domain_root = if values.principal {
            let (guid, root) = cx.domain_root()?;
            domain_sid(&self.ids, &root)?;
            seen.push((guid, root));
            self.rid_available(cx)?;
            Some(guid)
        } else {
            None
        };
        let change_seq = self.change_seq(cx)?;
        // P-22 item 1: "create inside an explicitly Tier0 subtree of the
        // tier map".
        let required = cx.tier_map().subtree_tier(&parent.dn) == Some(Tier::Tier0);
        Ok(Handled {
            plan: Plan::Write(WritePlan {
                change_seq,
                seen,
                kind: WriteKind::Create(CreatePlan {
                    parent: parent.guid,
                    class: values.class,
                    domain_root,
                    attributes: values.attributes,
                }),
            }),
            obligations,
            dual: Dual::of(required, &action, &resource),
        })
    }

    /// The account a password operation names, and the key sets admind
    /// passes to keyd: a user or computer, never krbtgt, a DC account or a
    /// service object (their keys come from `create_key`, or — the DC in
    /// phase 1 — do not exist).
    /// Spec: docs/51 §5.2 row 5, §7.3; docs/47 §9.1 (the table), §3.3
    /// (R47-4); RFC 4120 §6.2 (NT-PRINCIPAL "for users"; NT-SRV-HST
    /// "Service with host name as instance"); docs/47 §1.4 (krbtgt is
    /// never password-derived: its password set is replaced with a random
    /// value, [MS-SAMR] 3.1.1.8.5 item 3 as cited there).
    ///
    /// The account is given by its parts — a [`Resolved`]'s (the admin
    /// plane), or the requester's own account of a kpasswd change (task K6,
    /// crate::change_password) — so both reach the key sets through this one
    /// derivation (docs/52 C14).
    pub(crate) fn password_targets(
        &self,
        cx: &Cx<'_, '_, '_>,
        guid: Guid,
        obj: &Object,
        class: dirstore::ClassId,
    ) -> Result<PasswordSetReply, Stop> {
        if !cx.is_account(class) {
            return Err(Stop::Refused(AdminRefusal::ValueInvalid));
        }
        if cx.is_structural_object(guid, obj, class)? {
            return Err(Stop::Refused(AdminRefusal::TargetProtected));
        }
        let ids = &self.ids;
        let internal = || Stop::Failed(AdminFailure::InternalFailure);
        let sam = record::text(obj, ids.sam_account_name)
            .map_err(malformed)?
            .ok_or(Stop::Failed(AdminFailure::IntegrityFailure))?;
        let kind = if class == ids.computer.id {
            AccountKind::Computer
        } else {
            AccountKind::User
        };
        let principal = PrincipalId::from_bytes(guid.to_packet());
        let realm = self.config.realm().clone();
        let mut keys = vec![KeyTarget {
            handle: KeyHandle::new(principal, KeyPurpose::PrincipalLongterm),
            binding: PrincipalBinding::new(
                realm.clone(),
                PrincipalName {
                    name_type: KRB_NT_PRINCIPAL,
                    name_string: vec![KerberosString::new(sam).map_err(|_| internal())?],
                },
            ),
        }];
        if kind == AccountKind::Computer {
            if let Some(spn) = record::text(obj, ids.service_principal_name).map_err(malformed)? {
                let name_string = names::spn_components(spn)
                    .into_iter()
                    .map(|c| KerberosString::new(c).map_err(|_| internal()))
                    .collect::<Result<Vec<_>, Stop>>()?;
                let name = PrincipalName {
                    name_type: KRB_NT_SRV_HST,
                    name_string,
                };
                // The service key set's purpose is derived from its name —
                // the one derivation the KDC's account source uses (docs/52
                // R2b). A name that derives the admin service's key set is
                // never a password-set target: that key set is keyd-drawn
                // only (no `set_secret` may name it — docs/questions/Q-491
                // item 3), so the request is refused here rather than at
                // keyd.
                let service = ServiceKeyHandle::of_service(principal, &name);
                if service.purpose() != KeyPurpose::Service {
                    return Err(Stop::Refused(AdminRefusal::TargetProtected));
                }
                keys.push(KeyTarget {
                    handle: service.handle(),
                    binding: PrincipalBinding::new(realm.clone(), name),
                });
            }
        }
        let salt = account_salt(&realm, kind, sam).map_err(|_| internal())?;
        Ok(PasswordSetReply { kind, keys, salt })
    }

    /// `BeginPasswordSet`: `DirControlRight(User-Force-Change-Password)` on
    /// the account; dual control when the account is explicitly Tier0; the
    /// write is `pwdLastSet = now` (A-79: always "now"; docs/47 §9.2 step
    /// 2: before `set_secret`).
    /// Spec: docs/51 §5.2 row 5, §5.6, §7.3, §9; docs/47 §9.2.
    fn begin_password_set(
        &self,
        ctx: &OpCx<'_, '_, '_, '_>,
        base: &mut EventBase,
        target: Guid,
    ) -> Result<Handled, Stop> {
        let cx = ctx.cx;
        let (t, _) = self.named(ctx, base, target)?;
        let (action, resource) = password_request(&t);
        let obligations = self.authorize(ctx, base, &action, &resource)?;
        let reply = self.password_targets(cx, t.guid, &t.obj, t.class)?;
        let change_seq = self.change_seq(cx)?;
        let required = cx.explicit_tier(&t.dn)? == Some(Tier::Tier0);
        Ok(Handled {
            plan: Plan::Write(WritePlan {
                change_seq,
                seen: vec![(t.guid, t.obj)],
                kind: WriteKind::PasswordSet {
                    target,
                    reply: PasswordWrite::Set(reply),
                },
            }),
            obligations,
            dual: Dual::of(required, &action, &resource),
        })
    }

    /// `CompletePasswordSet`: audit only. The same decision as
    /// `BeginPasswordSet` (only who may set the password reports its
    /// completion); the reported key versions must fit the account's key
    /// sets (a completed set reports one per key set).
    /// Spec: docs/51 §7.3 ("audit only, no state"), §9; Q-340 item 1;
    /// docs/questions/Q-358 item 4.
    fn complete_password_set(
        &self,
        ctx: &OpCx<'_, '_, '_, '_>,
        base: &mut EventBase,
        c: &CompletePasswordSet,
    ) -> Result<Handled, Stop> {
        let cx = ctx.cx;
        let (t, _) = self.named(ctx, base, c.target)?;
        let (action, resource) = password_request(&t);
        let obligations = self.authorize(ctx, base, &action, &resource)?;
        let reply = self.password_targets(cx, t.guid, &t.obj, t.class)?;
        let fits = match c.outcome {
            PasswordSetOutcome::Completed => c.kvnos.len() == reply.keys.len(),
            PasswordSetOutcome::Failed => c.kvnos.len() < reply.keys.len(),
        };
        if !fits {
            return Err(Stop::Refused(AdminRefusal::ValueInvalid));
        }
        // Audit only, never dual-controlled (docs/51 §7.3).
        let _ = (action, resource);
        Ok(Handled {
            plan: Plan::Read(Reply::Done),
            obligations,
            dual: Dual::NotRequired,
        })
    }

    /// An account a `SetEnabled` / `SetAccountExpires` names: a user or
    /// computer, never krbtgt (its D bit is forbidden — [MS-SAMR] 3.1.1.6
    /// item 22), a DC account or a service object.
    /// Spec: docs/51 §5.2 rows 6-7; A-18, A-19, A-35.
    fn account_target(&self, cx: &Cx<'_, '_, '_>, t: &Resolved) -> Result<(), Stop> {
        if !cx.is_account(t.class) {
            return Err(Stop::Refused(AdminRefusal::ValueInvalid));
        }
        if cx.is_structural(t)? {
            return Err(Stop::Refused(AdminRefusal::TargetProtected));
        }
        Ok(())
    }

    /// `SetEnabled`: `DirWrite(userAccountControl)`; only the D bit changes
    /// (docs/51 §5.2 row 6), so ST / NR can never be set here (A-79); dual
    /// control when the account is explicitly Tier0; a disable passes the
    /// self-lockout guard.
    /// Spec: docs/51 §5.2 row 6, §5.6; [MS-SAMR] 3.1.1.6 items 20-22; P-22.
    fn set_enabled(
        &self,
        ctx: &OpCx<'_, '_, '_, '_>,
        base: &mut EventBase,
        s: &SetEnabled,
    ) -> Result<Handled, Stop> {
        let cx = ctx.cx;
        let (t, _) = self.named(ctx, base, s.target)?;
        let action = Action::DirWrite;
        let resource = attr_resource(&t, self.ids.uac_guid);
        let obligations = self.authorize(ctx, base, &action, &resource)?;
        self.account_target(cx, &t)?;
        let uac = record::flags(&t.obj, self.ids.user_account_control)
            .map_err(malformed)?
            .ok_or(Stop::Refused(AdminRefusal::ValueInvalid))?;
        let uac = if s.enabled {
            uac & !ADS_UF_ACCOUNT_DISABLE
        } else {
            uac | ADS_UF_ACCOUNT_DISABLE
        };
        let change_seq = self.change_seq(cx)?;
        let required = cx.explicit_tier(&t.dn)? == Some(Tier::Tier0);
        if !s.enabled {
            self.lockout_guard(cx, LockoutChange::Unusable(t.guid))?;
        }
        Ok(Handled {
            plan: Plan::Write(WritePlan {
                change_seq,
                seen: vec![(t.guid, t.obj)],
                kind: WriteKind::SetUac {
                    target: s.target,
                    uac,
                },
            }),
            obligations,
            dual: Dual::of(required, &action, &resource),
        })
    }

    /// `SetAccountExpires`: `DirWrite(accountExpires)`; "never" is written
    /// as `0x7FFFFFFFFFFFFFFF` only and `0` is refused (R47-5b, Q-113);
    /// dual control when the account is explicitly Tier0; an expiry that
    /// takes effect at once passes the self-lockout guard (it disables the
    /// account as surely as `SetEnabled`, docs/questions/Q-357 item 7).
    /// Spec: docs/51 §5.2 row 7, §5.6; docs/47 §4.2; P-22.
    fn set_account_expires(
        &self,
        ctx: &OpCx<'_, '_, '_, '_>,
        base: &mut EventBase,
        s: &SetAccountExpires,
    ) -> Result<Handled, Stop> {
        let cx = ctx.cx;
        let value = match s.value.filetime() {
            None => ACCOUNT_EXPIRES_NEVER,
            Some(0) => return Err(Stop::Refused(AdminRefusal::ValueInvalid)),
            Some(filetime) => {
                i64::try_from(filetime).map_err(|_| Stop::Refused(AdminRefusal::ValueInvalid))?
            }
        };
        let (t, _) = self.named(ctx, base, s.target)?;
        let action = Action::DirWrite;
        let resource = attr_resource(&t, self.ids.account_expires_guid);
        let obligations = self.authorize(ctx, base, &action, &resource)?;
        self.account_target(cx, &t)?;
        let change_seq = self.change_seq(cx)?;
        let required = cx.explicit_tier(&t.dn)? == Some(Tier::Tier0);
        let now_filetime =
            time::filetime(&cx.now).ok_or(Stop::Failed(AdminFailure::InternalFailure))?;
        if value <= now_filetime {
            self.lockout_guard(cx, LockoutChange::Unusable(t.guid))?;
        }
        Ok(Handled {
            plan: Plan::Write(WritePlan {
                change_seq,
                seen: vec![(t.guid, t.obj)],
                kind: WriteKind::SetAccountExpires {
                    target: s.target,
                    value,
                },
            }),
            obligations,
            dual: Dual::of(required, &action, &resource),
        })
    }

    /// `AddMember` / `RemoveMember`: `DirWrite(member)` on the group; the
    /// membership rules of [MS-SAMR] 3.1.1.8.9 (native mode), the cycle
    /// refusal, at most 4096 members, and no closure group expansion could
    /// not compute — no nesting chain deeper than 16 levels and no closure
    /// of more than 1024 groups (`Cx::expansion_allowed`); never krbtgt,
    /// a DC account, a service object or the NC root as the member; dual
    /// control when the group is explicitly Tier0; a removal passes the
    /// self-lockout guard. Adding a present member or removing an absent one
    /// is refused, not a no-op (docs/questions/Q-356 items 2-5, Q-416).
    /// Spec: docs/51 §5.2 row 8, §5.6, §11; docs/46 §2.3 item 5; docs/47
    /// §5.3 items 1, 3-4; A-79; A-89; P-22.
    fn membership(
        &self,
        ctx: &OpCx<'_, '_, '_, '_>,
        base: &mut EventBase,
        m: &Membership,
        add: bool,
    ) -> Result<Handled, Stop> {
        let cx = ctx.cx;
        let (group, _) = self.named(ctx, base, m.group)?;
        let (member, _) = self.named(ctx, base, m.member)?;
        let action = Action::DirWrite;
        let resource = attr_resource(&group, self.ids.member_guid);
        let obligations = self.authorize(ctx, base, &action, &resource)?;
        if group.class != self.ids.group.id {
            return Err(Stop::Refused(AdminRefusal::ValueInvalid));
        }
        if cx.is_structural(&member)? {
            return Err(Stop::Refused(AdminRefusal::TargetProtected));
        }
        let mut members = record::refs(&group.obj, self.ids.member).map_err(malformed)?;
        let present = members.contains(&member.guid);
        let mut proof = None;
        if add {
            let group_type = record::flags(&group.obj, self.ids.group_type)
                .map_err(malformed)?
                .ok_or(Stop::Failed(AdminFailure::IntegrityFailure))?;
            if present {
                return Err(Stop::Refused(AdminRefusal::MembershipInvalid));
            }
            // The membership rule of the group's type, the member limit,
            // the cycle and the expansion bounds: the write invariants'
            // link check (crate::invariants, docs/52 R13), in that order.
            let checked = cx.check_link(
                &self.invariants,
                End {
                    guid: group.guid,
                    obj: &group.obj,
                },
                group_type,
                End {
                    guid: member.guid,
                    obj: &member.obj,
                },
                member.class,
                members.len(),
            )?;
            proof = Some(checked.ok_or(Stop::Refused(AdminRefusal::MembershipInvalid))?);
            members.push(member.guid);
        } else {
            if !present {
                return Err(Stop::Refused(AdminRefusal::MembershipInvalid));
            }
            members.retain(|g| *g != member.guid);
        }
        let change_seq = self.change_seq(cx)?;
        let required = cx.explicit_tier(&group.dn)? == Some(Tier::Tier0);
        if !add {
            self.lockout_guard(
                cx,
                LockoutChange::EdgeRemoved {
                    group: group.guid,
                    member: member.guid,
                },
            )?;
        }
        Ok(Handled {
            plan: Plan::Write(WritePlan {
                change_seq,
                seen: vec![(group.guid, group.obj), (member.guid, member.obj)],
                kind: WriteKind::SetMembers {
                    group: m.group,
                    members,
                    proof,
                },
            }),
            obligations,
            dual: Dual::of(required, &action, &resource),
        })
    }

    /// `Delete`: `DirDelete`; never krbtgt, a DC account, a service object,
    /// the NC root, or an object the policy names (tier-map principals and
    /// subtree bases, the bootstrap group); a container must be empty;
    /// dual control when the object is explicitly Tier0 (any object, not
    /// only a principal — docs/questions/Q-357 item 2); the self-lockout
    /// guard. The write is a tombstone (A-18) whose references dirstore
    /// removes in the same transaction (docs/46 §8.4). A container with
    /// children ⇒ `Conflict` (Q-356 item 6).
    /// Spec: docs/51 §5.2 row 9, §5.6, §9; A-18, A-19, A-35; P-22.
    fn delete(
        &self,
        ctx: &OpCx<'_, '_, '_, '_>,
        base: &mut EventBase,
        target: Guid,
    ) -> Result<Handled, Stop> {
        let cx = ctx.cx;
        let (t, _) = self.named(ctx, base, target)?;
        let action = Action::DirDelete;
        let resource = Resource::DirObject {
            dn: t.dn.clone(),
            attr: None,
        };
        let obligations = self.authorize(ctx, base, &action, &resource)?;
        if cx.is_structural(&t)? || cx.is_policy_named(&t)? {
            return Err(Stop::Refused(AdminRefusal::TargetProtected));
        }
        if cx.has_children(t.guid)? {
            return Err(Stop::Refused(AdminRefusal::Conflict));
        }
        let change_seq = self.change_seq(cx)?;
        let required = cx.explicit_tier(&t.dn)? == Some(Tier::Tier0);
        self.lockout_guard(cx, LockoutChange::Deleted(t.guid))?;
        Ok(Handled {
            plan: Plan::Write(WritePlan {
                change_seq,
                seen: vec![(t.guid, t.obj)],
                kind: WriteKind::Delete { target },
            }),
            obligations,
            dual: Dual::of(required, &action, &resource),
        })
    }

    /// `Lookup`: the object the key names, if the requester may see it
    /// (`DirList` on its parent, [MS-ADTS] 5.1.3.3.6) and read it
    /// (`DirRead`) — the visibility gate's verdict; otherwise — and when
    /// nothing has the key — the same `NotFound` (A-55: no existence
    /// oracle). The `DirRead` decision authorises the reply (its
    /// obligations are the operation's).
    /// Spec: docs/51 §5.2 row 10, §7.3; docs/11 §7; [MS-ADTS] 5.1.3.3.6;
    /// docs/52 R10; A-55; docs/questions/Q-485.
    fn lookup(
        &self,
        ctx: &OpCx<'_, '_, '_, '_>,
        base: &mut EventBase,
        key: &LookupKey,
    ) -> Result<Handled, Stop> {
        let cx = ctx.cx;
        let guid = self
            .find(cx, key)?
            .ok_or(Stop::Refused(AdminRefusal::NotFound))?;
        base.target = Some(guid);
        let (found, decision) = self.named(ctx, base, guid)?;
        base.pdp = Some(pdp_reason(decision.reason));
        let class = self
            .ids
            .class(found.class)
            .ok_or(Stop::Failed(AdminFailure::IntegrityFailure))?
            .name;
        let sid = record::sid(&found.obj, self.ids.object_sid).map_err(malformed)?;
        Ok(Handled {
            plan: Plan::Read(Reply::Found(LookupResult {
                guid,
                dn: found.dn,
                class,
                sid,
            })),
            obligations: decision.obligations,
            dual: Dual::NotRequired,
        })
    }

    /// The object a `Lookup` key names, if any: a sAMAccountName or SPN
    /// through the unique index and then compared octet for octet (A-27, as
    /// the account source does — `Cx::locate_exact`), a DN through the PEP
    /// view's `lookup_dn`. A key that cannot name anything (not printable
    /// ASCII, too long) names nothing. Only a GUID: the object reaches the
    /// reply only through the gate (docs/52 R-a).
    /// Spec: docs/47 §1.3 steps 3-4 (R47-1); docs/49 §7 (R49-11, DN
    /// resolution); docs/46 §5.4 (bounds).
    fn find(&self, cx: &Cx<'_, '_, '_>, key: &LookupKey) -> Result<Option<Guid>, Stop> {
        match key {
            LookupKey::SamAccountName(sam) => {
                cx.locate_exact(self.ids.sam_account_name, sam, names::MAX_GROUP_SAM_CHARS)
            }
            LookupKey::ServicePrincipalName(spn) => cx.locate_exact(
                self.ids.service_principal_name,
                spn,
                names::MAX_PRINCIPAL_NAME_CHARS,
            ),
            LookupKey::Dn(dn) => {
                if dn.rdns().len() > MAX_DN_DEPTH {
                    return Ok(None);
                }
                let mut rdns = Vec::with_capacity(dn.rdns().len());
                for component in dn.rdns() {
                    match component.split_once('=') {
                        Some(pair) => rdns.push(pair),
                        None => return Ok(None),
                    }
                }
                cx.pep
                    .lookup_dn(&rdns)
                    .map_err(|_| Stop::Failed(AdminFailure::StoreFailure))
            }
        }
    }
}

/// The Action and Resource of a password set: the control access right
/// User-Force-Change-Password on the account (whole object).
/// Spec: docs/51 §5.2 row 5; docs/47 §9.2 step 1; [MS-ADTS] 6.1.1.2.7.53.
fn password_request(t: &Resolved) -> (Action, Resource) {
    (
        Action::DirControlRight(ControlRightId(USER_FORCE_CHANGE_PASSWORD)),
        Resource::DirObject {
            dn: t.dn.clone(),
            attr: None,
        },
    )
}

/// `DirObject { dn, attr }` for one attribute (named by its schemaIDGUID).
/// Spec: docs/11 §1; [MS-ADTS] 5.1.3.3.3 as cited in crate pdp.
fn attr_resource(t: &Resolved, attr_guid: Guid) -> Resource {
    Resource::DirObject {
        dn: t.dn.clone(),
        attr: Some(PdpAttrId(attr_guid)),
    }
}
