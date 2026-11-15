//! `PolicyAdmin` online (task A16; docs/51 §5.10, R51-21; decision A-80 on
//! docs/questions/Q-299 option (b)): an approved tier-map change becomes the
//! candidate dird writes as `policy.next`; activating it stays root's.
//!
//! # What this module decides
//!
//! [`DirectoryAdmin::prepare_policy_change`] runs, against ONE view and the
//! policy snapshot of the loaded version, the checks of a `ChangePolicy`
//! request — with **the same code** the directory writes use:
//!
//! 1. the requester's Subject from its verified ticket and its ticket age
//!    (docs/51 §5.3, §5.5);
//! 2. the request's own values: 1 to [`MAX_POLICY_CHANGES`] changes;
//! 3. `decide` for `PolicyAdmin` on the policy scope
//!    [`POLICY_CHANGE_SCOPE`] — the requester's Allow, through the PEP's one
//!    `authorize` ("a policy change = `POLICY_ADMIN`, the most privileged
//!    operation, tier-0, always controlled", docs/06 §9; the object tier of
//!    a policy scope is Tier0, so a subject below Tier0 is denied by the
//!    PDP's tier layer whatever the rules say);
//! 4. **mandatory dual control** (docs/51 §5.2 row 13: "always"; P-22):
//!    the PEP's one `dual_control`, with `required` always true — every
//!    approval a verified, fresh, distinct, Tier0-allowed AP-REQ bound to
//!    this very request's digest, and the requester plus the approvals at
//!    least the configured quorum (2 under P-22). There is no second
//!    implementation of the approval rule (docs/52 C14 — one rule, one
//!    implementation);
//! 5. **one pending change at a time**: a `policy.next` dird already wrote
//!    and root has not activated refuses a new change (`PendingLimit`) —
//!    checked after the PDP and dual control, so an account that may not
//!    change the policy learns nothing of a pending one (the rule of A-55);
//! 6. the candidate: the loaded policy edited by **the one tier-map edit**
//!    (crate policy-store `edit_tier_map`, the edit `provision policy` uses
//!    offline), version + 1; then — fail closed — its encoding decoded again
//!    by the policy format's own decoder and checked to be exactly the
//!    candidate and a tier-map successor of the loaded policy
//!    (`check_tier_map_successor`, the rule root's activation applies).
//!    An edit the edit refuses is `ValueInvalid`.
//!
//! The result is a [`PreparedPolicyChange`]: the `Decision` event (its
//! `ipc_audit_client::IntentRecord`) and the candidate, which leaves the type only
//! through [`PolicyCandidate::from_acknowledged`] — from an
//! `ipc_audit_client::AckedIntent<PreparedPolicyChange>`, which only the caller's
//! audit gate produces after auditd acknowledged the decision event (docs/52
//! R6: "decision acknowledged ⇒ commit" as a type). dird writes the file
//! from the [`PolicyCandidate`] and records the `Outcome` event it plans.
//!
//! # What this module does not do
//!
//! No file is touched here (a library, no I/O): dird observes whether
//! `policy.next` exists ([`PendingPolicy`]) and writes it. Signing: the
//! candidate is the **unsigned development format** (Q-219's algorithm and
//! key custody are not defined — A-57); where a signature must attach is
//! docs/questions/Q-593.
//!
//! Spec: docs/51 §5.2 row 13, §5.3, §5.5, §5.6, §5.7, §5.10; docs/06 §9;
//! docs/11 §4 (layer 4: `is_write(PolicyAdmin)`, object tier); docs/52 §3.11
//! (R6), §3.14 (C14); A-36; A-55; A-80; P-22; docs/questions/Q-299, Q-590,
//! Q-592, Q-593.

use directory_pip::DirectoryView;
use ipc_audit::{
    AdminFailure, AdminRefusal, DirAdminEvent, DirAdminStage, EventBody, OutcomeResult,
    MAX_APPROVERS, MAX_TARGET_NAMES,
};
use ipc_audit_client::{AckedIntent, IntentRecord};
use keyd_types::OperationDigest;
use krb_proto::KerberosTime;
use pdp::{Action, Obligation, PolicyScope, PolicySnapshot, PolicyVersion, Resource};
use policy_store::{check_tier_map_successor, edit_tier_map, DevelopmentPolicy, TierChange};

use crate::admin::{subject_of, DirectoryAdmin, OpCx, VerificationFailure};
use crate::audit::{sid_value, EventBase, Refusal, Stop};
use crate::checks::{local_ipc_security, Cx};
use crate::random::RandomSource;
use crate::subject::{all_bound, SubjectError, VerifiedTicket};

/// The policy scope of a tier-map change: `PolicyAdmin` on `Policy {scope:
/// "tier-map"}`. The rule `provision domain` writes for the Tier-0 group
/// (`scope: None`, every scope) covers it; a narrower grant can name it.
/// Spec: docs/51 §5.2 row 13 (`PolicyAdmin`), §5.10; docs/06 §9; crates/pdp
/// policy.rs (`ResourceMatch::Policy`); docs/questions/Q-592.
pub const POLICY_CHANGE_SCOPE: &str = "tier-map";

/// Most tier-map changes one request carries: every change is named in the
/// request's events, which keep at most `ipc_audit::MAX_TARGET_NAMES` names
/// (crate ipc-dird-admin's `MAX_POLICY_CHANGES` equals it — pinned in
/// crates/directory-daemon).
/// Spec: docs/51 §5.7 item 1; docs/questions/Q-592.
pub const MAX_POLICY_CHANGES: usize = MAX_TARGET_NAMES;

/// Whether dird holds a `policy.next` root has not activated yet — what dird
/// observed of its own file just before the request was decided.
/// Spec: docs/51 §5.10 (`policy.next`); docs/questions/Q-591 ("one pending
/// change at a time").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PendingPolicy {
    /// No `policy.next`: a change may be decided.
    Absent,
    /// A `policy.next` waits for root's activation: a new change is
    /// refused.
    Present,
}

/// One `ChangePolicy` request, after the caller verified every AP-REQ
/// through keyd — each bound to `operation_digest`, the digest of the
/// request dird decoded (R2).
/// Spec: docs/51 §7.2, §7.3; docs/52 §5 items 1, 4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyChangeRequest {
    /// dird's number for the operation (its `Decision` and `Outcome` events
    /// carry it, Q-340 item 1).
    pub operation_id: u64,
    /// The changes, in order (the tier-map edit's vocabulary).
    pub changes: Vec<TierChange>,
    /// The operation digest every ticket below must carry (R2).
    pub operation_digest: OperationDigest,
    /// The requester's verified ticket.
    pub requester: VerifiedTicket,
    /// The approvers' verified tickets (at most two, docs/51 §7.2).
    pub approvals: Vec<VerifiedTicket>,
}

/// A decided tier-map change: the `Decision` event to have acknowledged and
/// the candidate `policy.next`, reachable only through the acknowledgement
/// ([`PolicyCandidate::from_acknowledged`]). Not `Clone` (docs/52 N5, R6):
/// one acknowledgement, one write.
/// Spec: docs/51 §5.7 item 2, §5.10; docs/52 §3.11 R6 (a); A-85.
#[derive(Debug, PartialEq, Eq)]
pub struct PreparedPolicyChange {
    base: EventBase,
    decision: DirAdminEvent,
    obligations: Vec<Obligation>,
    version: PolicyVersion,
    file: Vec<u8>,
}

impl PreparedPolicyChange {
    /// The `Decision` event (`Proceed`): the caller commits it and waits for
    /// auditd's acknowledgement before anything is written.
    #[must_use]
    pub fn decision_event(&self) -> &DirAdminEvent {
        &self.decision
    }

    /// The obligations of the requester's Allow other than the audit record
    /// planned here (`RateLimit`, `Constrain`), which the caller must honour
    /// (docs/11 §2) before the decision event is committed.
    #[must_use]
    pub fn obligations(&self) -> &[Obligation] {
        &self.obligations
    }

    /// The version the candidate carries (the loaded version + 1).
    #[must_use]
    pub fn version(&self) -> PolicyVersion {
        self.version
    }
}

impl IntentRecord for PreparedPolicyChange {
    /// The `Decision` event (`Proceed`): what auditd must acknowledge before
    /// `policy.next` is written (A-85).
    /// Spec: docs/51 §5.7 item 2; docs/52 §3.11 R6 (a).
    fn intent_event(&self) -> EventBody {
        EventBody::DirAdmin(Box::new(self.decision.clone()))
    }
}

/// The candidate `policy.next` of an acknowledged decision: its encoding
/// (decoded and re-checked by `prepare_policy_change`), its version, and the
/// `Outcome` events of its write. Built only from the proof (module
/// documentation). Not `Clone`.
/// Spec: docs/51 §5.7 item 2, §5.10; docs/52 §3.11 R6 (a).
#[derive(Debug, PartialEq, Eq)]
pub struct PolicyCandidate {
    base: EventBase,
    version: PolicyVersion,
    file: Vec<u8>,
}

impl PolicyCandidate {
    /// The candidate of a decision auditd acknowledged.
    /// Spec: docs/52 §3.11 R6 (a) (the mutation entry point consumes the
    /// proof).
    #[must_use]
    pub fn from_acknowledged(acked: AckedIntent<PreparedPolicyChange>) -> PolicyCandidate {
        let prepared = acked.into_inner();
        PolicyCandidate {
            base: prepared.base,
            version: prepared.version,
            file: prepared.file,
        }
    }

    /// The file's octets: the unsigned development format (crate
    /// policy-store), version + 1.
    #[must_use]
    pub fn file(&self) -> &[u8] {
        &self.file
    }

    /// The version the file carries.
    #[must_use]
    pub fn version(&self) -> PolicyVersion {
        self.version
    }

    /// The `Outcome` event of a `policy.next` written and made durable.
    /// Spec: docs/51 §5.7 item 2 (decision ⇒ change ⇒ outcome).
    #[must_use]
    pub fn written_event(&self, now: &KerberosTime) -> DirAdminEvent {
        self.base.committed(now, None)
    }

    /// The `Outcome` event of a write refused because a `policy.next`
    /// appeared after the decision (one pending change at a time).
    /// Spec: docs/51 §5.10; docs/questions/Q-591.
    #[must_use]
    pub fn pending_event(&self, now: &KerberosTime) -> DirAdminEvent {
        self.base.staged(
            now,
            DirAdminStage::Outcome(OutcomeResult::Refused(AdminRefusal::PendingLimit)),
        )
    }

    /// The `Outcome` event of a write that failed (nothing is pending: the
    /// partial file is never renamed into place).
    /// Spec: docs/51 §5.7 item 2.
    #[must_use]
    pub fn failed_event(&self, now: &KerberosTime) -> DirAdminEvent {
        self.base.staged(
            now,
            DirAdminStage::Outcome(OutcomeResult::Failed(AdminFailure::StoreFailure)),
        )
    }
}

/// The checks' result: the candidate and the caller's obligations.
struct Decided {
    version: PolicyVersion,
    file: Vec<u8>,
    obligations: Vec<Obligation>,
}

impl<R: RandomSource> DirectoryAdmin<R> {
    /// The refusal of a `ChangePolicy` whose AP-REQ keyd did not verify (or
    /// could not be asked): its `Decision` event and the uniform `Denied` /
    /// `Unavailable`.
    /// Spec: docs/51 §7.4 step 1; A-26; A-56.
    #[must_use]
    pub fn refuse_unverified_policy_change(
        &self,
        operation_id: u64,
        changes: &[TierChange],
        failure: VerificationFailure,
        now: &KerberosTime,
    ) -> Refusal {
        let stop = match failure {
            VerificationFailure::Requester => Stop::Refused(AdminRefusal::Unauthenticated),
            VerificationFailure::Approver => Stop::Refused(AdminRefusal::ApproverUnauthenticated),
            VerificationFailure::KeydUnavailable => Stop::Failed(AdminFailure::KeydUnavailable),
        };
        EventBase::of_policy_change(operation_id, changes).decision_refusal(now, stop)
    }

    /// The refusal of a `ChangePolicy` that failed before any check ran (the
    /// view could not be taken, dird could not tell whether `policy.next`
    /// exists): its `Decision(Failed(failure))`.
    /// Spec: docs/51 §7.4; A-91 (`ViewUnavailable`).
    #[must_use]
    pub fn refuse_failed_policy_change(
        &self,
        operation_id: u64,
        changes: &[TierChange],
        failure: AdminFailure,
        now: &KerberosTime,
    ) -> Refusal {
        EventBase::of_policy_change(operation_id, changes)
            .decision_refusal(now, Stop::Failed(failure))
    }

    /// Decide a `ChangePolicy` against ONE view, the PDP snapshot of the
    /// loaded policy, the loaded policy itself (`installed`, of the same
    /// version) and what dird observed of `policy.next` (module
    /// documentation, steps 1-6).
    ///
    /// `Err` carries the `Decision` event of the refusal (send it) and the
    /// client-visible status.
    ///
    /// Spec: module documentation; docs/51 §5.10, §7.4 steps 2-4; A-85.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_policy_change(
        &self,
        request: &PolicyChangeRequest,
        view: &DirectoryView<'_>,
        policy: &PolicySnapshot,
        installed: &DevelopmentPolicy,
        pending: PendingPolicy,
        now: &KerberosTime,
    ) -> Result<PreparedPolicyChange, Refusal> {
        let mut base = EventBase::of_policy_change(request.operation_id, &request.changes);
        match self.policy_checked(request, view, policy, installed, pending, now, &mut base) {
            Ok(decided) => Ok(PreparedPolicyChange {
                decision: base.proceed(now),
                base,
                obligations: decided.obligations,
                version: decided.version,
                file: decided.file,
            }),
            Err(stop) => Err(base.decision_refusal(now, stop)),
        }
    }

    /// The checks, in order (module documentation).
    #[allow(clippy::too_many_arguments)]
    fn policy_checked(
        &self,
        request: &PolicyChangeRequest,
        view: &DirectoryView<'_>,
        policy: &PolicySnapshot,
        installed: &DevelopmentPolicy,
        pending: PendingPolicy,
        now: &KerberosTime,
        base: &mut EventBase,
    ) -> Result<Decided, Stop> {
        // The view must be of this PEP's domain, and the snapshot of the
        // loaded policy (fail closed on a misassembled caller).
        if view.context().realm() != self.config.realm()
            || view.context().naming_context() != self.config.naming_context()
            || policy.version() != installed.version
        {
            return Err(Stop::Failed(AdminFailure::InternalFailure));
        }
        // R2 (docs/52 §5 item 4): bound only if keyd verified every ticket
        // bound to this very request.
        let bound = all_bound(
            &request.operation_digest,
            core::iter::once(&request.requester).chain(&request.approvals),
        );
        let cx = Cx::new(
            &self.config,
            &self.ids,
            view,
            policy,
            now,
            local_ipc_security(bound),
        )?;
        // Step 1 — the requester (docs/51 §5.3, §5.5; R51-10).
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
        // Step 2 — the request's own values (they reveal nothing).
        if request.changes.is_empty() || request.changes.len() > MAX_POLICY_CHANGES {
            return Err(Stop::Refused(AdminRefusal::ValueInvalid));
        }
        let ctx = OpCx {
            cx: &cx,
            requester: &requester,
            approvals: &request.approvals,
        };
        // Step 3 — `PolicyAdmin` on the tier-map scope (docs/06 §9).
        let action = Action::PolicyAdmin;
        let resource = Resource::Policy {
            scope: PolicyScope(String::from(POLICY_CHANGE_SCOPE)),
        };
        let obligations = self.authorize(&ctx, base, &action, &resource)?;
        // Step 4 — dual control, always (docs/51 §5.2 row 13; P-22).
        self.dual_control(&ctx, base, true, &action, &resource)?;
        // Step 5 — one pending change at a time (after the PDP: no oracle).
        if pending == PendingPolicy::Present {
            return Err(Stop::Refused(AdminRefusal::PendingLimit));
        }
        // Step 6 — the candidate, by the one edit; then parse what will be
        // written, and require it to be exactly the candidate and a
        // tier-map successor of the loaded policy (fail closed).
        let (next, file) = edit_tier_map(installed, &request.changes)
            .map_err(|_| Stop::Refused(AdminRefusal::ValueInvalid))?;
        let reread = DevelopmentPolicy::decode(&file)
            .map_err(|_| Stop::Failed(AdminFailure::InternalFailure))?;
        if reread != next || check_tier_map_successor(installed, &reread).is_err() {
            return Err(Stop::Failed(AdminFailure::InternalFailure));
        }
        let obligations = obligations
            .into_iter()
            .filter(|o| !matches!(o, Obligation::Audit))
            .collect();
        Ok(Decided {
            version: next.version,
            file,
            obligations,
        })
    }
}
