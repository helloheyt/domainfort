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
//! 3. The objects the request names, read from the view; absent ⇒
//!    `NotFound`; not readable by the requester (`DirRead`, docs/11 §7) ⇒
//!    `NotVisible` — the client is told `NotFound` either way (A-55).
//! 4. `decide` for the requester on the operation's Action and Resource
//!    (§5.2) ⇒ `PolicyDenied`.
//! 5. The semantic checks of §11 and §5.2 (protected objects, classes,
//!    membership rules, the cycle refusal, the member limit, values already
//!    taken, the new object's descriptor) and the counters' presence.
//! 6. Dual control (§5.6, P-22): every supplied approval is checked
//!    (Subject, ticket age, distinct from the requester and from the other
//!    approvers, `decide` = Allow for the same Action and Resource); when
//!    the operation needs it, too few approvals ⇒ `ApprovalRequired`.
//! 7. The self-lockout guard (Q-295 item 4).
//!
//! Spec: docs/51 §5.2-§5.7, §7.4, §8, §9, §10, §11; A-72..A-79, A-83..A-85,
//! P-22.

use dirstore::{AttrId, CounterState, Object, MAX_VALUES_PER_ATTRIBUTE};
use dtyp::{Guid, Sid};
use ipc_audit::{AdminFailure, AdminRefusal, DirAdminEvent, MAX_APPROVERS};
use keyd_types::{KeyHandle, KeyPurpose, PrincipalBinding, PrincipalId};
use krb_proto::constants::{KRB_NT_PRINCIPAL, KRB_NT_SRV_HST};
use krb_proto::{KerberosString, KerberosTime, PrincipalName};
use pdp::{
    Action, AttrId as PdpAttrId, ControlRightId, Effect, ObjClass, Obligation, PolicySnapshot,
    Resource, Tier,
};

use ad_schema::flags::group_type::{
    ALLOWED_VALUES, GROUP_TYPE_ACCOUNT_GROUP, GROUP_TYPE_SECURITY_ENABLED,
};
use ad_schema::flags::user_account_control::{
    ADS_UF_ACCOUNT_DISABLE, ADS_UF_NORMAL_ACCOUNT, ADS_UF_WORKSTATION_TRUST_ACCOUNT,
};
use ad_schema::Phase1Schema;
use directory_pip::{account_salt, AccountKind, DirectoryView, MAX_DN_DEPTH};

use crate::audit::{pdp_reason, sid_value, EventBase, Refusal, Stop};
use crate::checks::{domain_sid, malformed, store_failure, Cx, LockoutChange, Resolved};
use crate::config::{AdminConfig, ConfigError, CHANGE_SEQ_COUNTER, RID_COUNTER};
use crate::descriptor::new_object_sd;
use crate::ids::{ClassIds, Ids};
use crate::names;
use crate::operation::{
    CompletePasswordSet, CreateComputer, CreateContainerLike, CreateGroup, CreateUser, LookupKey,
    Membership, Operation, PasswordSetOutcome, SetAccountExpires, SetEnabled,
};
use crate::random::RandomSource;
use crate::record;
use crate::reply::{KeyTarget, LookupResult, PasswordSetReply, Reply};
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

/// One admin request, after the caller verified every AP-REQ through keyd.
/// Spec: docs/51 §7.2 (`auth := requester ‖ approvals`), §7.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// dird's number for the operation: its `Decision` and `Outcome`
    /// events carry it (Q-340 item 1).
    pub operation_id: u64,
    /// The operation.
    pub operation: Operation,
    /// The requester's verified ticket.
    pub requester: VerifiedTicket,
    /// The approvers' verified tickets (at most two, docs/51 §7.2).
    pub approvals: Vec<VerifiedTicket>,
}

/// Which AP-REQ keyd did not verify — for the refusal the caller records
/// without calling `prepare` (docs/51 §7.4 step 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VerificationFailure {
    /// The requester's AP-REQ did not verify (`Unauthenticated`).
    Requester,
    /// An approver's AP-REQ did not verify (`ApproverUnauthenticated`).
    Approver,
    /// keyd did not answer (`Failed(KeydUnavailable)`, A-56).
    KeydUnavailable,
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

/// The write of one operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WriteKind {
    Create(CreatePlan),
    PasswordSet {
        target: Guid,
        reply: PasswordSetReply,
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
/// Spec: docs/51 §5.7 item 2, §7.4 step 5; A-85.
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// The write PEP: its configuration, the schema identifiers, and the random
/// source for objectGUIDs. Spec: docs/51 §12 task A3.
pub struct DirectoryAdmin<R: RandomSource> {
    pub(crate) config: AdminConfig,
    pub(crate) ids: Ids,
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
        Ok(DirectoryAdmin {
            config,
            ids: Ids::resolve(schema)?,
            rng,
        })
    }

    /// The configuration.
    #[must_use]
    pub fn config(&self) -> &AdminConfig {
        &self.config
    }

    /// The refusal of a request whose AP-REQ keyd did not verify: the
    /// `Decision` event to record (no requester SID — none was verified)
    /// and the uniform `Denied` (or `Unavailable` when keyd is down).
    /// Spec: docs/51 §7.4 step 1 ("failure ⇒ `Denied` uniform (A-26), keyd
    /// down ⇒ `Unavailable` (A-56)").
    #[must_use]
    pub fn refuse_unverified(
        &self,
        operation_id: u64,
        operation: &Operation,
        failure: VerificationFailure,
        now: &KerberosTime,
    ) -> Refusal {
        let base = EventBase::of_request(operation_id, operation);
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
    /// `Err` carries the `Decision` event of the refusal (send it) and the
    /// client-visible status. Spec: docs/51 §7.4 steps 2-4; A-85.
    pub fn prepare(
        &self,
        request: &Request,
        view: &DirectoryView<'_>,
        policy: &PolicySnapshot,
        now: &KerberosTime,
    ) -> Result<Prepared, Refusal> {
        let mut base = EventBase::of_request(request.operation_id, &request.operation);
        match self.checked(request, view, policy, now, &mut base) {
            Ok((plan, obligations, requester)) => Ok(Prepared {
                decision: base.proceed(now),
                base,
                obligations,
                requester,
                plan,
            }),
            Err(stop) => Err(base.decision_refusal(now, stop)),
        }
    }

    /// The checks, in order (module documentation).
    fn checked(
        &self,
        request: &Request,
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
        let cx = Cx {
            config: &self.config,
            ids: &self.ids,
            view,
            policy,
            now: *now,
            instant: time::instant(now).ok_or(Stop::Failed(AdminFailure::InternalFailure))?,
        };
        // Step 1 — the requester (docs/51 §5.3, §5.5; A-73; R51-10).
        let requester = subject_of(&cx, &request.requester).map_err(|e| match e {
            SubjectError::NotUsable => Stop::Refused(AdminRefusal::Unauthenticated),
            SubjectError::Unavailable => Stop::Failed(AdminFailure::StoreFailure),
        })?;
        base.requester = sid_value(requester.sid());
        if requester.ticket_age() > self.config.ticket_age_max() {
            return Err(Stop::Refused(AdminRefusal::TicketAge));
        }
        if request.approvals.len() > MAX_APPROVERS {
            return Err(Stop::Refused(AdminRefusal::ValueInvalid));
        }
        let ctx = OpCx {
            cx: &cx,
            requester: &requester,
            approvals: &request.approvals,
        };
        let (plan, obligations) = match &request.operation {
            Operation::CreateUser(c) => self.create(&ctx, base, NewObject::User(c))?,
            Operation::CreateComputer(c) => self.create(&ctx, base, NewObject::Computer(c))?,
            Operation::CreateGroup(c) => self.create(&ctx, base, NewObject::Group(c))?,
            Operation::CreateOu(c) => self.create(&ctx, base, NewObject::Ou(c))?,
            Operation::CreateContainer(c) => self.create(&ctx, base, NewObject::Container(c))?,
            Operation::BeginPasswordSet { target } => {
                self.begin_password_set(&ctx, base, *target)?
            }
            Operation::CompletePasswordSet(c) => self.complete_password_set(&ctx, base, c)?,
            Operation::SetEnabled(s) => self.set_enabled(&ctx, base, s)?,
            Operation::SetAccountExpires(s) => self.set_account_expires(&ctx, base, s)?,
            Operation::AddMember(m) => self.membership(&ctx, base, m, true)?,
            Operation::RemoveMember(m) => self.membership(&ctx, base, m, false)?,
            Operation::Delete { target } => self.delete(&ctx, base, *target)?,
            Operation::Lookup(key) => self.lookup(&ctx, base, key)?,
        };
        let obligations = obligations
            .into_iter()
            .filter(|o| !matches!(o, Obligation::Audit))
            .collect();
        Ok((plan, obligations, *requester.sid()))
    }
}

/// The Subject of a verified ticket. Spec: docs/51 §5.3.
pub(crate) fn subject_of(
    cx: &Cx<'_, '_, '_>,
    ticket: &VerifiedTicket,
) -> Result<AdminSubject, SubjectError> {
    AdminSubject::from_verified_ticket(
        cx.view,
        &ticket.crealm,
        &ticket.cname,
        &ticket.authtime,
        &cx.now,
    )
}

/// The per-request part every operation handler reads.
struct OpCx<'o, 'c, 'v, 'a> {
    cx: &'o Cx<'c, 'v, 'a>,
    requester: &'o AdminSubject,
    approvals: &'o [VerifiedTicket],
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
    fn authorize(
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

    /// `r` must be readable by the requester; otherwise `NotVisible` (told
    /// to the client as `NotFound`, A-55) — for every object a request
    /// names, not only for `Lookup` (docs/questions/Q-358 item 3).
    /// Spec: docs/11 §7 as cited in docs/51 §5.2 row 10; A-55.
    fn visible(
        &self,
        ctx: &OpCx<'_, '_, '_, '_>,
        base: &mut EventBase,
        r: &Resolved,
    ) -> Result<(), Stop> {
        let decision = ctx.cx.read_decision(ctx.requester.subject(), r);
        if decision.effect != Effect::Allow {
            base.pdp = Some(pdp_reason(decision.reason));
            return Err(Stop::Refused(AdminRefusal::NotVisible));
        }
        Ok(())
    }

    /// Dual control (docs/51 §5.6, R51-11; P-22 items 1-2): every supplied
    /// approval must come from a usable account with a fresh enough ticket,
    /// be distinct from the requester and from every other approver, and get
    /// `decide` = Allow for the same Action and Resource; when `required`,
    /// the requester plus the approvals must reach the quorum. Approvals
    /// supplied when dual control does not apply are checked all the same
    /// (docs/questions/Q-357 items 3-4).
    fn dual_control(
        &self,
        ctx: &OpCx<'_, '_, '_, '_>,
        base: &mut EventBase,
        required: bool,
        action: &Action,
        resource: &Resource,
    ) -> Result<(), Stop> {
        let mut principals: Vec<Sid> = vec![*ctx.requester.sid()];
        for ticket in ctx.approvals {
            let approver = subject_of(ctx.cx, ticket).map_err(|e| match e {
                SubjectError::NotUsable => Stop::Refused(AdminRefusal::ApproverUnauthenticated),
                SubjectError::Unavailable => Stop::Failed(AdminFailure::StoreFailure),
            })?;
            if let Some(sid) = sid_value(approver.sid()) {
                base.approvers.push(sid);
            }
            if approver.ticket_age() > self.config.ticket_age_max() {
                return Err(Stop::Refused(AdminRefusal::ApproverUnauthenticated));
            }
            if principals.contains(approver.sid()) {
                return Err(Stop::Refused(AdminRefusal::ApproverNotDistinct));
            }
            principals.push(*approver.sid());
            let decision = ctx
                .cx
                .decide(approver.subject(), action.clone(), resource.clone());
            if decision.effect != Effect::Allow {
                return Err(Stop::Refused(AdminRefusal::ApproverDenied));
            }
        }
        if required && principals.len() < self.config.quorum() {
            return Err(Stop::Refused(AdminRefusal::ApprovalRequired));
        }
        Ok(())
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
    fn change_seq(&self, cx: &Cx<'_, '_, '_>) -> Result<CounterState, Stop> {
        let state = cx
            .view
            .snapshot()
            .counter(CHANGE_SEQ_COUNTER)
            .map_err(|e| store_failure(&e))?
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
            .view
            .snapshot()
            .counter(RID_COUNTER)
            .map_err(|e| store_failure(&e))?
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
    ) -> Result<(Plan, Vec<Obligation>), Stop> {
        let cx = ctx.cx;
        let values = self.new_values(new)?;
        let parent_guid = match new {
            NewObject::User(c) => c.parent,
            NewObject::Computer(c) => c.parent,
            NewObject::Group(c) => c.parent,
            NewObject::Ou(c) | NewObject::Container(c) => c.parent,
        };
        let parent = cx.resolve(parent_guid)?;
        self.visible(ctx, base, &parent)?;
        let action = Action::DirAddChild(ObjClass(values.class.guid));
        let resource = Resource::DirObject {
            dn: parent.dn.clone(),
            attr: None,
        };
        let obligations = self.authorize(ctx, base, &action, &resource)?;
        // The parent's class must be a possible superior of the new class
        // (docs/46 §4.4, §8.3 item 2; dirstore refuses it too).
        let schema = cx.view.context().schema().schema();
        let definition = schema
            .class(values.class.id)
            .ok_or(Stop::Failed(AdminFailure::InternalFailure))?;
        if !definition.poss_superiors.contains(&parent.class) {
            return Err(Stop::Refused(AdminRefusal::ValueInvalid));
        }
        let snapshot = cx.view.snapshot();
        // A live child of the parent with the same RDN (docs/46 §8.3 item
        // 3; dirstore `NameExists`).
        match snapshot.lookup_child(Some(parent.guid), values.rdn.as_bytes()) {
            Ok(None) => {}
            Ok(Some(_)) => return Err(Stop::Refused(AdminRefusal::Conflict)),
            Err(dirstore::Error::Rejected(_)) => {
                return Err(Stop::Refused(AdminRefusal::ValueInvalid))
            }
            Err(e) => return Err(store_failure(&e)),
        }
        // A value the unique index already holds ([MS-SAMR] 3.1.1.8.4 item
        // 2; docs/46 §8.5).
        for (attr, value) in &values.uniques {
            match snapshot.lookup_unique(*attr, value.as_bytes()) {
                Ok(None) => {}
                Ok(Some(_)) => return Err(Stop::Refused(AdminRefusal::Conflict)),
                Err(dirstore::Error::Rejected(_)) => {
                    return Err(Stop::Refused(AdminRefusal::ValueInvalid))
                }
                Err(e) => return Err(store_failure(&e)),
            }
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
            let (guid, root) = self.domain_root(cx)?;
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
        let required = cx.view.tier_map().subtree_tier(&parent.dn) == Some(Tier::Tier0);
        self.dual_control(ctx, base, required, &action, &resource)?;
        Ok((
            Plan::Write(WritePlan {
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
        ))
    }

    /// The NC root: the object the naming context's DN names.
    /// Spec: A-53; docs/47 §8.2; docs/51 §8.3.
    fn domain_root(&self, cx: &Cx<'_, '_, '_>) -> Result<(Guid, Object), Stop> {
        let labels = self.config.naming_context().labels();
        let rdns: Vec<(&str, &str)> = labels
            .iter()
            .map(|l| (directory_pip::NC_RDN_ATTRIBUTE, l.as_str()))
            .collect();
        let guid = cx
            .view
            .lookup_dn(&rdns)
            .map_err(|_| Stop::Failed(AdminFailure::StoreFailure))?
            .ok_or(Stop::Failed(AdminFailure::StoreFailure))?;
        let root = cx
            .view
            .snapshot()
            .get_object(guid)
            .map_err(|e| store_failure(&e))?
            .ok_or(Stop::Failed(AdminFailure::StoreFailure))?;
        Ok((guid, root))
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
    fn password_targets(
        &self,
        cx: &Cx<'_, '_, '_>,
        t: &Resolved,
    ) -> Result<PasswordSetReply, Stop> {
        if !cx.is_account(t.class) {
            return Err(Stop::Refused(AdminRefusal::ValueInvalid));
        }
        if cx.is_structural(t)? {
            return Err(Stop::Refused(AdminRefusal::TargetProtected));
        }
        let ids = &self.ids;
        let internal = || Stop::Failed(AdminFailure::InternalFailure);
        let sam = record::text(&t.obj, ids.sam_account_name)
            .map_err(malformed)?
            .ok_or(Stop::Failed(AdminFailure::IntegrityFailure))?;
        let kind = if t.class == ids.computer.id {
            AccountKind::Computer
        } else {
            AccountKind::User
        };
        let principal = PrincipalId::from_bytes(t.guid.to_packet());
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
            if let Some(spn) =
                record::text(&t.obj, ids.service_principal_name).map_err(malformed)?
            {
                let name_string = names::spn_components(spn)
                    .into_iter()
                    .map(|c| KerberosString::new(c).map_err(|_| internal()))
                    .collect::<Result<Vec<_>, Stop>>()?;
                keys.push(KeyTarget {
                    handle: KeyHandle::new(principal, KeyPurpose::Service),
                    binding: PrincipalBinding::new(
                        realm.clone(),
                        PrincipalName {
                            name_type: KRB_NT_SRV_HST,
                            name_string,
                        },
                    ),
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
    ) -> Result<(Plan, Vec<Obligation>), Stop> {
        let cx = ctx.cx;
        let t = cx.resolve(target)?;
        self.visible(ctx, base, &t)?;
        let (action, resource) = password_request(&t);
        let obligations = self.authorize(ctx, base, &action, &resource)?;
        let reply = self.password_targets(cx, &t)?;
        let change_seq = self.change_seq(cx)?;
        let required = cx.explicit_tier(&t.dn)? == Some(Tier::Tier0);
        self.dual_control(ctx, base, required, &action, &resource)?;
        Ok((
            Plan::Write(WritePlan {
                change_seq,
                seen: vec![(t.guid, t.obj)],
                kind: WriteKind::PasswordSet { target, reply },
            }),
            obligations,
        ))
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
    ) -> Result<(Plan, Vec<Obligation>), Stop> {
        let cx = ctx.cx;
        let t = cx.resolve(c.target)?;
        self.visible(ctx, base, &t)?;
        let (action, resource) = password_request(&t);
        let obligations = self.authorize(ctx, base, &action, &resource)?;
        let reply = self.password_targets(cx, &t)?;
        let fits = match c.outcome {
            PasswordSetOutcome::Completed => c.kvnos.len() == reply.keys.len(),
            PasswordSetOutcome::Failed => c.kvnos.len() < reply.keys.len(),
        };
        if !fits {
            return Err(Stop::Refused(AdminRefusal::ValueInvalid));
        }
        self.dual_control(ctx, base, false, &action, &resource)?;
        Ok((Plan::Read(Reply::Done), obligations))
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
    ) -> Result<(Plan, Vec<Obligation>), Stop> {
        let cx = ctx.cx;
        let t = cx.resolve(s.target)?;
        self.visible(ctx, base, &t)?;
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
        self.dual_control(ctx, base, required, &action, &resource)?;
        if !s.enabled {
            self.lockout_guard(cx, LockoutChange::Unusable(t.guid))?;
        }
        Ok((
            Plan::Write(WritePlan {
                change_seq,
                seen: vec![(t.guid, t.obj)],
                kind: WriteKind::SetUac {
                    target: s.target,
                    uac,
                },
            }),
            obligations,
        ))
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
    ) -> Result<(Plan, Vec<Obligation>), Stop> {
        let cx = ctx.cx;
        let value = match s.value.filetime() {
            None => ACCOUNT_EXPIRES_NEVER,
            Some(0) => return Err(Stop::Refused(AdminRefusal::ValueInvalid)),
            Some(filetime) => {
                i64::try_from(filetime).map_err(|_| Stop::Refused(AdminRefusal::ValueInvalid))?
            }
        };
        let t = cx.resolve(s.target)?;
        self.visible(ctx, base, &t)?;
        let action = Action::DirWrite;
        let resource = attr_resource(&t, self.ids.account_expires_guid);
        let obligations = self.authorize(ctx, base, &action, &resource)?;
        self.account_target(cx, &t)?;
        let change_seq = self.change_seq(cx)?;
        let required = cx.explicit_tier(&t.dn)? == Some(Tier::Tier0);
        self.dual_control(ctx, base, required, &action, &resource)?;
        let now_filetime =
            time::filetime(&cx.now).ok_or(Stop::Failed(AdminFailure::InternalFailure))?;
        if value <= now_filetime {
            self.lockout_guard(cx, LockoutChange::Unusable(t.guid))?;
        }
        Ok((
            Plan::Write(WritePlan {
                change_seq,
                seen: vec![(t.guid, t.obj)],
                kind: WriteKind::SetAccountExpires {
                    target: s.target,
                    value,
                },
            }),
            obligations,
        ))
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
    ) -> Result<(Plan, Vec<Obligation>), Stop> {
        let cx = ctx.cx;
        let group = cx.resolve(m.group)?;
        self.visible(ctx, base, &group)?;
        let member = cx.resolve(m.member)?;
        self.visible(ctx, base, &member)?;
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
        if add {
            let group_type = record::flags(&group.obj, self.ids.group_type)
                .map_err(malformed)?
                .ok_or(Stop::Failed(AdminFailure::IntegrityFailure))?;
            if present
                || !cx.member_allowed(group_type, &member)?
                || members.len() >= MAX_VALUES_PER_ATTRIBUTE
                || cx.closes_cycle(group.guid, member.guid)?
                || !cx.expansion_allowed(&group, &member)?
            {
                return Err(Stop::Refused(AdminRefusal::MembershipInvalid));
            }
            members.push(member.guid);
        } else {
            if !present {
                return Err(Stop::Refused(AdminRefusal::MembershipInvalid));
            }
            members.retain(|g| *g != member.guid);
        }
        let change_seq = self.change_seq(cx)?;
        let required = cx.explicit_tier(&group.dn)? == Some(Tier::Tier0);
        self.dual_control(ctx, base, required, &action, &resource)?;
        if !add {
            self.lockout_guard(
                cx,
                LockoutChange::EdgeRemoved {
                    group: group.guid,
                    member: member.guid,
                },
            )?;
        }
        Ok((
            Plan::Write(WritePlan {
                change_seq,
                seen: vec![(group.guid, group.obj), (member.guid, member.obj)],
                kind: WriteKind::SetMembers {
                    group: m.group,
                    members,
                },
            }),
            obligations,
        ))
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
    ) -> Result<(Plan, Vec<Obligation>), Stop> {
        let cx = ctx.cx;
        let t = cx.resolve(target)?;
        self.visible(ctx, base, &t)?;
        let action = Action::DirDelete;
        let resource = Resource::DirObject {
            dn: t.dn.clone(),
            attr: None,
        };
        let obligations = self.authorize(ctx, base, &action, &resource)?;
        if cx.is_structural(&t)? || cx.is_policy_named(&t)? {
            return Err(Stop::Refused(AdminRefusal::TargetProtected));
        }
        let children = cx
            .view
            .snapshot()
            .children(Some(t.guid), None, 1)
            .map_err(|e| store_failure(&e))?;
        if !children.children.is_empty() {
            return Err(Stop::Refused(AdminRefusal::Conflict));
        }
        let change_seq = self.change_seq(cx)?;
        let required = cx.explicit_tier(&t.dn)? == Some(Tier::Tier0);
        self.dual_control(ctx, base, required, &action, &resource)?;
        self.lockout_guard(cx, LockoutChange::Deleted(t.guid))?;
        Ok((
            Plan::Write(WritePlan {
                change_seq,
                seen: vec![(t.guid, t.obj)],
                kind: WriteKind::Delete { target },
            }),
            obligations,
        ))
    }

    /// `Lookup`: the object the key names, if the requester may read it
    /// (`DirRead`); otherwise — and when nothing has the key — the same
    /// `NotFound` (A-55: no existence oracle).
    /// Spec: docs/51 §5.2 row 10, §7.3; docs/11 §7; A-55.
    fn lookup(
        &self,
        ctx: &OpCx<'_, '_, '_, '_>,
        base: &mut EventBase,
        key: &LookupKey,
    ) -> Result<(Plan, Vec<Obligation>), Stop> {
        let cx = ctx.cx;
        let guid = self
            .find(cx, key)?
            .ok_or(Stop::Refused(AdminRefusal::NotFound))?;
        base.target = Some(guid);
        let found = cx.resolve(guid)?;
        let decision = cx.read_decision(ctx.requester.subject(), &found);
        base.pdp = Some(pdp_reason(decision.reason));
        if decision.effect != Effect::Allow {
            return Err(Stop::Refused(AdminRefusal::NotVisible));
        }
        let class = self
            .ids
            .class(found.class)
            .ok_or(Stop::Failed(AdminFailure::IntegrityFailure))?
            .name;
        let sid = record::sid(&found.obj, self.ids.object_sid).map_err(malformed)?;
        let resource = Resource::DirObject {
            dn: found.dn.clone(),
            attr: None,
        };
        self.dual_control(ctx, base, false, &Action::DirRead, &resource)?;
        Ok((
            Plan::Read(Reply::Found(LookupResult {
                guid,
                dn: found.dn,
                class,
                sid,
            })),
            decision.obligations,
        ))
    }

    /// The object a `Lookup` key names, if any: a sAMAccountName or SPN
    /// through the unique index and then compared octet for octet (A-27, as
    /// the account source does), a DN through `lookup_dn`. A key that cannot
    /// name anything (not printable ASCII, too long) names nothing.
    /// Spec: docs/47 §1.3 steps 3-4 (R47-1); docs/49 §7 (R49-11, DN
    /// resolution); docs/46 §5.4 (bounds).
    fn find(&self, cx: &Cx<'_, '_, '_>, key: &LookupKey) -> Result<Option<Guid>, Stop> {
        let snapshot = cx.view.snapshot();
        let exact = |attr: AttrId, value: &str, max: usize| -> Result<Option<Guid>, Stop> {
            if value.is_empty()
                || value.len() > max
                || !value.bytes().all(|b| (0x20..=0x7E).contains(&b))
            {
                return Ok(None);
            }
            let guid = match snapshot.lookup_unique(attr, value.as_bytes()) {
                Ok(Some(guid)) => guid,
                Ok(None) | Err(dirstore::Error::Rejected(_)) => return Ok(None),
                Err(e) => return Err(store_failure(&e)),
            };
            let Some(obj) = snapshot.get_object(guid).map_err(|e| store_failure(&e))? else {
                return Ok(None);
            };
            let stored = record::text(&obj, attr).map_err(malformed)?;
            Ok((stored == Some(value)).then_some(guid))
        };
        match key {
            LookupKey::SamAccountName(sam) => {
                exact(self.ids.sam_account_name, sam, names::MAX_GROUP_SAM_CHARS)
            }
            LookupKey::ServicePrincipalName(spn) => exact(
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
                cx.view
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
