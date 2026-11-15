//! `PolicyAdmin` online (task A16): the write PEP's decision on a tier-map
//! change — the requester's `PolicyAdmin` on the `tier-map` scope, mandatory
//! dual control by the one mechanism (task D2-c, docs/questions/Q-882: an
//! approved pending request for exactly these changes, consumed by the
//! execution), one pending change at a time, the candidate built by the one tier-map edit (version + 1) and
//! re-read by the policy format's own decoder, released only by the
//! acknowledgement of the decision event.
//!
//! Sources: docs/51 §5.2 row 13 ("`PolicyAdmin`, always dual"), §5.6, §5.7,
//! §5.10 (R51-21); docs/06 §9 ("a policy change = `POLICY_ADMIN`, the most
//! privileged operation, tier-0, always controlled"); docs/11 §4 (layer 4:
//! a policy scope is Tier0); P-22 (quorum 2); A-55 (no oracle); A-80;
//! docs/52 §3.11 (R6), §5 (R2); docs/questions/Q-590..Q-592. Fixtures:
//! tests/common (two Tier-0 administrators, a Tier-1 helper, quorum 2); the
//! policy below is hand-made for these tests. No vector comes from any other
//! implementation.

mod common;

use std::collections::BTreeMap;

use common::*;
use directory_admin::{
    PendingPolicy, PolicyCandidate, PolicyChangeRequest, PreparedPolicyChange, ProposedOperation,
    RefusalStatus, RequestStep, VerificationFailure, MAX_POLICY_CHANGES,
};
use ipc_audit::{
    AdminFailure, AdminNameKind, AdminRefusal, DecisionResult, DirAdminOperation, DirAdminStage,
    OutcomeResult, PdpReasonCode, SidValue,
};
use ipc_audit_client::AckedIntent;
use pdp::{
    ActionMatch, AuthMatch, ContextMatch, Effect, Match, PolicyVersion, ResourceMatch, Rule,
    RuleId, SubjectMatch, SubtreeBase, Tier,
};
use policy_store::{DevelopmentPolicy, MandatoryFast, TierChange};

/// The loaded policy of the test domain (version 1): the tier map of
/// tests/common, the directory rules of tests/common, and `PolicyAdmin` on
/// every policy scope for the Tier-0 group (the rule `provision domain`
/// writes, docs/51 §4.3 step 6).
fn installed() -> DevelopmentPolicy {
    let rule = |id: u32, action: ActionMatch, resource: ResourceMatch, subject| Rule {
        id: RuleId(id),
        effect: Effect::Allow,
        when: Match {
            action,
            resource,
            subject,
            context: ContextMatch::ANY,
            auth: AuthMatch::ANY,
        },
        obligations: vec![],
    };
    let subtree = || ResourceMatch::DirSubtree {
        base: SubtreeBase::new(nc_dn()).unwrap(),
    };
    DevelopmentPolicy {
        version: PolicyVersion(1),
        principals: BTreeMap::from([
            (sid_of(TIER0_GROUP), Tier::Tier0),
            (sid_of(HELPDESK), Tier::Tier1),
        ]),
        subtrees: vec![
            (ou_dn("Tier0"), Tier::Tier0),
            (ou_dn("Managed"), Tier::Tier1),
        ],
        mandatory_fast: MandatoryFast {
            bootstrap_group: sid_of(BOOTSTRAP),
            first_rule_id: RuleId(100),
        },
        rules: vec![
            rule(
                1,
                ActionMatch::Class(pdp::ActionClass::Directory),
                subtree(),
                SubjectMatch::MemberOf(sid_of(TIER0_GROUP)),
            ),
            rule(
                2,
                ActionMatch::Class(pdp::ActionClass::Directory),
                subtree(),
                SubjectMatch::MemberOf(sid_of(HELPDESK)),
            ),
            rule(
                4,
                ActionMatch::Exact(pdp::Action::PolicyAdmin),
                ResourceMatch::Policy { scope: None },
                SubjectMatch::MemberOf(sid_of(TIER0_GROUP)),
            ),
            // The helpdesk group is allowed `PolicyAdmin` by a rule too, so
            // that only the tier layer can deny the Tier-1 helper.
            rule(
                5,
                ActionMatch::Exact(pdp::Action::PolicyAdmin),
                ResourceMatch::Policy { scope: None },
                SubjectMatch::MemberOf(sid_of(HELPDESK)),
            ),
        ],
        anonymous: vec![],
    }
}

fn add_staff_tier2() -> TierChange {
    TierChange::AddSubtree(ou_dn("Staff"), Tier::Tier2)
}

fn sid_value(id: u32) -> SidValue {
    SidValue::new(dtyp::SECURITY_NT_AUTHORITY, vec![21, 1, 2, 3, rid(id)]).unwrap()
}

/// A `ChangePolicy` executed by `requester`, the ticket bound to the
/// request's digest (R2) — the changes' fingerprint.
fn request(changes: Vec<TierChange>, requester: &str) -> PolicyChangeRequest {
    let digest = fingerprint(&changes);
    PolicyChangeRequest {
        operation_id: 7,
        changes,
        operation_digest: digest,
        // Task MA2: the plan is checked after `PolicyAdmin` and dual control
        // classification; this file's own tests of the plan set it with
        // `planned_request`.
        plan: Some([0xEE; 32]),
        requester: ticket_bound_to(requester, Some(digest)),
    }
}

/// [`request`] committing to the plan `d` computes for `changes` (task MA2).
fn planned_request(d: &Domain, changes: Vec<TierChange>, requester: &str) -> PolicyChangeRequest {
    let mut request = request(changes.clone(), requester);
    request.plan = Some(d.committed_plan(&ProposedOperation::Policy(changes), requester));
    request
}

/// The domain under `installed`: its PDP snapshot, and the file a proposal
/// builds its candidate on.
fn load(d: &mut Domain, installed: &DevelopmentPolicy) {
    d.policy = installed.snapshot().unwrap();
    d.policy_file = Some(installed.clone());
}

/// The one dual-control mechanism (task D2-c): `requester` proposes the
/// change, each of `approvers` approves it; then the execution by
/// `requester` against the domain with `installed` and `pending`.
fn decide(
    d: &mut Domain,
    installed: &DevelopmentPolicy,
    changes: Vec<TierChange>,
    requester: &str,
    approvers: &[&str],
    pending: PendingPolicy,
) -> Result<PreparedPolicyChange, directory_admin::Refusal> {
    load(d, installed);
    if !approvers.is_empty() {
        let proposed = d.propose(ProposedOperation::Policy(changes.clone()), requester, None)?;
        let (id, digest) = (proposed.reply().id, proposed.reply().digest);
        for approver in approvers {
            d.approve(id, digest, approver)?;
        }
    }
    let request = planned_request(d, changes, requester);
    execute(d, installed, &request, pending)
}

/// The execution of `request` against the domain with `installed`.
fn execute(
    d: &mut Domain,
    installed: &DevelopmentPolicy,
    request: &PolicyChangeRequest,
    pending: PendingPolicy,
) -> Result<PreparedPolicyChange, directory_admin::Refusal> {
    let snapshot = installed.snapshot().unwrap();
    let view = d.ctx.view(&d.store, &d.tiers).unwrap();
    d.admin.prepare_policy_change(
        request,
        &mut d.requests,
        &view,
        &snapshot,
        installed,
        pending,
        &now(),
    )
}

/// Play auditd for one decision (as tests/common `acknowledged` does for a
/// directory write): the proof, obtained only through the gate the real
/// audit client is attached to, from a fake auditd's `Ack` (task R15b,
/// docs/questions/Q-630 — nothing else can acknowledge).
fn acknowledged(prepared: PreparedPolicyChange) -> AckedIntent<PreparedPolicyChange> {
    linked::acknowledged(prepared)
}

fn refusal_code(r: &directory_admin::Refusal) -> DecisionResult {
    match r.event().stage {
        DirAdminStage::Decision(result) => result,
        other => panic!("not a decision: {other:?}"),
    }
}

/// docs/51 §5.10, §5.6 (P-22): a Tier-0 administrator's change approved by
/// a second one is decided; the candidate is the loaded policy with the
/// edit applied, version 1 → 2, its encoding decoded by the policy format
/// itself; the decision event names the operation, the requester, the
/// approver and the change in the edit's spelling; the candidate leaves the
/// prepared value only through the acknowledgement, with its outcome events.
#[test]
fn an_approved_change_yields_the_next_version() {
    let mut d = Domain::new("pc-approved");
    let installed = installed();
    let prepared = decide(
        &mut d,
        &installed,
        vec![add_staff_tier2()],
        "admin1",
        &["admin2"],
        PendingPolicy::Absent,
    )
    .unwrap();
    assert_eq!(prepared.version(), PolicyVersion(2));
    let decision = prepared.decision_event().clone();
    assert_eq!(decision.operation, DirAdminOperation::ChangePolicy);
    assert_eq!(
        decision.stage,
        DirAdminStage::Decision(DecisionResult::Proceed)
    );
    assert_eq!(decision.operation_id, 7);
    assert_eq!(decision.requester, Some(sid_value(ADMIN1)));
    assert_eq!(decision.approvers.as_slice(), &[sid_value(ADMIN2)]);
    // The approved request it consumed, and the fingerprint (Q-888).
    assert!(decision.pending_request.is_some());
    assert_eq!(
        decision.operation_digest,
        *fingerprint(&vec![add_staff_tier2()]).as_bytes()
    );
    assert!(d.requests.is_empty(), "consumed");
    let names = decision.names.as_slice();
    assert_eq!(names.len(), 1);
    assert_eq!(names[0].kind, AdminNameKind::PolicyChange);
    assert_eq!(
        names[0].text.as_text(),
        Some("--add-subtree Tier2 ou=Staff dc=example dc=test")
    );
    assert_eq!(decision.pdp.map(|p| p.code), Some(PdpReasonCode::Allowed));

    let candidate = PolicyCandidate::from_acknowledged(acknowledged(prepared));
    let written = DevelopmentPolicy::decode(candidate.file()).unwrap();
    let (expected, _) = policy_store::edit_tier_map(&installed, &[add_staff_tier2()]).unwrap();
    assert_eq!(written, expected);
    assert_eq!(written.version, PolicyVersion(2));
    assert_eq!(candidate.version(), PolicyVersion(2));
    assert!(matches!(
        candidate.written_event(&now()).stage,
        DirAdminStage::Outcome(OutcomeResult::Committed { allocated: None })
    ));
    assert_eq!(
        candidate.pending_event(&now()).stage,
        DirAdminStage::Outcome(OutcomeResult::Refused(AdminRefusal::PendingLimit))
    );
    assert_eq!(
        candidate.failed_event(&now()).stage,
        DirAdminStage::Outcome(OutcomeResult::Failed(AdminFailure::StoreFailure))
    );
    assert_eq!(candidate.written_event(&now()).operation_id, 7);
}

/// docs/51 §5.2 row 13 ("always dual"), P-22: one administrator alone cannot
/// change the policy — not alone, and not by approving his own request.
#[test]
fn a_single_administrator_cannot_complete_it() {
    let mut d = Domain::new("pc-single");
    let installed = installed();
    let alone = decide(
        &mut d,
        &installed,
        vec![add_staff_tier2()],
        "admin1",
        &[],
        PendingPolicy::Absent,
    )
    .unwrap_err();
    assert_eq!(
        refusal_code(&alone),
        DecisionResult::Refused(AdminRefusal::ApprovalRequired)
    );
    assert_eq!(alone.status(), RefusalStatus::ApprovalRequired);
    let self_approved = decide(
        &mut d,
        &installed,
        vec![add_staff_tier2()],
        "admin1",
        &["admin1"],
        PendingPolicy::Absent,
    )
    .unwrap_err();
    assert_eq!(
        refusal_code(&self_approved),
        DecisionResult::Refused(AdminRefusal::ApproverNotDistinct)
    );
    assert_eq!(self_approved.status(), RefusalStatus::Denied);
}

/// docs/06 §9, docs/11 §4 (layer 4): a policy scope is Tier0, so the Tier-1
/// helper is denied by the PDP even with a rule granting his group
/// `PolicyAdmin` (his proposal is refused); and a Tier-1 account cannot
/// approve a Tier-0 requester's change (the approver's own decision — it
/// may not even see the request: `NotVisible`, told `NotFound`, the rule of
/// A-55; task D2-c).
#[test]
fn a_non_tier0_administrator_is_denied_by_the_pdp() {
    let mut d = Domain::new("pc-tier1");
    let installed = installed();
    let denied = decide(
        &mut d,
        &installed,
        vec![add_staff_tier2()],
        "helper",
        &["admin2"],
        PendingPolicy::Absent,
    )
    .unwrap_err();
    assert_eq!(
        refusal_code(&denied),
        DecisionResult::Refused(AdminRefusal::PolicyDenied)
    );
    assert_eq!(denied.status(), RefusalStatus::Denied);
    assert_eq!(
        denied.event().pdp.map(|p| p.code),
        Some(PdpReasonCode::TierViolation)
    );
    let approver = decide(
        &mut d,
        &installed,
        vec![add_staff_tier2()],
        "admin1",
        &["helper"],
        PendingPolicy::Absent,
    )
    .unwrap_err();
    assert_eq!(
        refusal_code(&approver),
        DecisionResult::Refused(AdminRefusal::NotVisible)
    );
    assert_eq!(approver.status(), RefusalStatus::NotFound);
}

/// docs/51 §5.10 ("one pending change at a time", docs/questions/Q-591):
/// while a `policy.next` waits for root, a new change is refused — and only
/// after the PDP and dual control, so an account that may not change the
/// policy is told it may not, not that a change is pending (A-55).
#[test]
fn a_second_pending_change_is_refused_after_the_pdp() {
    let mut d = Domain::new("pc-pending");
    let installed = installed();
    let pending = decide(
        &mut d,
        &installed,
        vec![add_staff_tier2()],
        "admin1",
        &["admin2"],
        PendingPolicy::Present,
    )
    .unwrap_err();
    assert_eq!(
        refusal_code(&pending),
        DecisionResult::Refused(AdminRefusal::PendingLimit)
    );
    assert_eq!(pending.status(), RefusalStatus::Unavailable);
    let no_oracle = execute(
        &mut d,
        &installed,
        &request(vec![add_staff_tier2()], "helper"),
        PendingPolicy::Present,
    )
    .unwrap_err();
    assert_eq!(
        refusal_code(&no_oracle),
        DecisionResult::Refused(AdminRefusal::PolicyDenied)
    );
    let unapproved = decide(
        &mut d,
        &installed,
        vec![add_staff_tier2()],
        "admin1",
        &[],
        PendingPolicy::Present,
    )
    .unwrap_err();
    assert_eq!(
        refusal_code(&unapproved),
        DecisionResult::Refused(AdminRefusal::ApprovalRequired)
    );
}

/// docs/51 §5.10; docs/questions/Q-379, Q-590: the edit's own refusals
/// (removing the last Tier0 principal, adding a row already present), no
/// change, and more changes than the audit event can name are
/// `ValueInvalid` — already at the proposal (its dry run builds the
/// candidate: no approver is asked to judge an edit that cannot be made —
/// task D2-c, class C47).
#[test]
fn an_edit_the_edit_refuses_is_invalid() {
    let mut d = Domain::new("pc-invalid");
    let installed = installed();
    let staff = |n: u32| TierChange::AddSubtree(ou_dn(&format!("S{n}")), Tier::Tier2);
    for changes in [
        vec![TierChange::RemovePrincipal(sid_of(TIER0_GROUP))],
        vec![TierChange::AddPrincipal(sid_of(HELPDESK), Tier::Tier2)],
        vec![TierChange::AddPrincipal(sid_of(BOB), Tier::Untiered)],
        vec![],
        (0..=MAX_POLICY_CHANGES as u32).map(staff).collect(),
    ] {
        let refused = decide(
            &mut d,
            &installed,
            changes.clone(),
            "admin1",
            &["admin2"],
            PendingPolicy::Absent,
        )
        .unwrap_err();
        assert_eq!(refused.event().operation, DirAdminOperation::Propose);
        assert_eq!(
            refusal_code(&refused),
            DecisionResult::Refused(AdminRefusal::ValueInvalid),
            "{changes:?}"
        );
        assert_eq!(refused.status(), RefusalStatus::Invalid);
    }
    // At the bound it is decided.
    decide(
        &mut d,
        &installed,
        (0..MAX_POLICY_CHANGES as u32).map(staff).collect(),
        "admin1",
        &["admin2"],
        PendingPolicy::Absent,
    )
    .unwrap();
}

/// R2 (docs/52 §5 item 4): an `Approve` whose AP-REQ keyd verified for
/// another digest leaves the channel unbound — `PolicyAdmin` is a write, so
/// the PDP denies the approver (`WeakTransport`) and the request stays
/// invisible to it; no approval is recorded, and the change still needs one.
#[test]
fn an_approval_bound_to_another_operation_is_not_channel_bound() {
    let mut d = Domain::new("pc-unbound");
    let installed = installed();
    load(&mut d, &installed);
    let proposed = d
        .propose(
            ProposedOperation::Policy(vec![add_staff_tier2()]),
            "admin1",
            None,
        )
        .unwrap();
    let refused = d
        .step_at(
            RequestStep::Approve {
                id: proposed.reply().id,
                digest: proposed.reply().digest,
            },
            ticket_bound_to("admin2", Some(keyd_types::OperationDigest::new([0xEE; 32]))),
            &now(),
        )
        .unwrap_err();
    assert_eq!(
        refusal_code(&refused),
        DecisionResult::Refused(AdminRefusal::NotVisible)
    );
    assert_eq!(
        refused.event().pdp.map(|p| p.code),
        Some(PdpReasonCode::WeakTransport)
    );
    let unapproved = execute(
        &mut d,
        &installed,
        &request(vec![add_staff_tier2()], "admin1"),
        PendingPolicy::Absent,
    )
    .unwrap_err();
    assert_eq!(
        refusal_code(&unapproved),
        DecisionResult::Refused(AdminRefusal::ApprovalRequired)
    );
}

/// Fail closed on a misassembled caller: a PDP snapshot of another version
/// than the loaded policy is `InternalFailure`; an unverified ticket is the
/// uniform refusal; keyd down is a failure.
#[test]
fn misassembled_inputs_and_unverified_tickets_fail_closed() {
    let mut d = Domain::new("pc-misassembled");
    let installed = installed();
    let mut newer = installed.clone();
    newer.version = PolicyVersion(2);
    let snapshot = installed.snapshot().unwrap();
    let view = d.ctx.view(&d.store, &d.tiers).unwrap();
    let refused = d
        .admin
        .prepare_policy_change(
            &request(vec![add_staff_tier2()], "admin1"),
            &mut d.requests,
            &view,
            &snapshot,
            &newer,
            PendingPolicy::Absent,
            &now(),
        )
        .unwrap_err();
    drop(view);
    assert_eq!(
        refusal_code(&refused),
        DecisionResult::Failed(AdminFailure::InternalFailure)
    );
    let changes = [add_staff_tier2()];
    for (failure, expected) in [
        (
            VerificationFailure::Requester,
            DecisionResult::Refused(AdminRefusal::Unauthenticated),
        ),
        (
            VerificationFailure::Approver,
            DecisionResult::Refused(AdminRefusal::ApproverUnauthenticated),
        ),
        (
            VerificationFailure::KeydUnavailable,
            DecisionResult::Failed(AdminFailure::KeydUnavailable),
        ),
    ] {
        let r = d.admin.refuse_unverified_policy_change(
            9,
            &changes,
            &fingerprint(&changes.to_vec()),
            failure,
            &now(),
        );
        assert_eq!(refusal_code(&r), expected);
        assert_eq!(r.event().operation, DirAdminOperation::ChangePolicy);
        assert_eq!(r.event().names.len(), 1);
    }
}

/// The plan of a policy change (task MA3; r5-a §8.2: "`ChangePolicy` ⇒
/// everyone whose tier changes"), read through the PIP's tier functions
/// under the candidate map the one tier-map edit builds: classifying
/// `readers` Tier 2 moves the group and its members bob, disabled and alice
/// from Untiered to Tier 2 (subject) and from unclassified to Tier 2
/// (object); helper, also in the Tier-1 helpdesk, keeps Tier 1 — not in the
/// plan. Classifying ou=Staff Tier 2 changes object tiers only (a subtree is
/// no subject tier). The execution recomputes the same plan, and its
/// decision records the plan's digest.
#[test]
fn a_policy_change_plans_who_changes_tier() {
    use ipc_dird_admin::{Effect, PlanTier};
    let mut d = Domain::new("pc-plan");
    let installed = installed();
    load(&mut d, &installed);
    let readers = vec![TierChange::AddPrincipal(sid_of(READERS), Tier::Tier2)];
    let planned = d
        .plan_operation(ProposedOperation::Policy(readers.clone()), "admin1")
        .unwrap();
    let moved: std::collections::BTreeSet<dtyp::Sid> = [READERS, BOB, DISABLED, ALICE]
        .iter()
        .map(|id| sid_of(*id))
        .collect();
    assert_eq!(
        planned.plan().effects(),
        &[Effect::TierDelta {
            subject: (PlanTier::None, PlanTier::Tier2),
            object: (PlanTier::None, PlanTier::Tier2),
            principals: moved,
        }]
    );
    assert!(planned.plan().principal(&sid_of(HELPER)).is_none());

    let staff = d
        .plan_operation(ProposedOperation::Policy(vec![add_staff_tier2()]), "admin1")
        .unwrap();
    for effect in staff.plan().effects() {
        match effect {
            Effect::TierDelta {
                subject, object, ..
            } => {
                assert_eq!(subject.0, subject.1, "a subtree is no subject tier");
                assert_eq!(object.1, PlanTier::Tier2);
            }
            other => panic!("{other:?}"),
        }
    }
    assert!(staff
        .plan()
        .effects()
        .iter()
        .any(|e| e.principals().contains(&sid_of(ALICE))));

    let prepared = decide(
        &mut d,
        &installed,
        readers,
        "admin1",
        &["admin2"],
        PendingPolicy::Absent,
    )
    .unwrap();
    assert_eq!(
        prepared.decision_event().plan_digest,
        Some(planned.digest())
    );
}
