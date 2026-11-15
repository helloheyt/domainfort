//! `PolicyAdmin` online (task A16): the write PEP's decision on a tier-map
//! change — the requester's `PolicyAdmin` on the `tier-map` scope, mandatory
//! dual control with the PEP's one approval rule, one pending change at a
//! time, the candidate built by the one tier-map edit (version + 1) and
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
    PendingPolicy, PolicyCandidate, PolicyChangeRequest, PreparedPolicyChange, RefusalStatus,
    VerificationFailure, MAX_POLICY_CHANGES,
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

/// A `ChangePolicy` by `requester` with `approvers`, every ticket bound to
/// the request's digest (R2).
fn request(changes: Vec<TierChange>, requester: &str, approvers: &[&str]) -> PolicyChangeRequest {
    PolicyChangeRequest {
        operation_id: 7,
        changes,
        operation_digest: TEST_DIGEST,
        requester: ticket(requester),
        approvals: approvers.iter().map(|a| ticket(a)).collect(),
    }
}

/// Decide `request` against the domain with `installed` and `pending`.
fn decide(
    d: &Domain,
    installed: &DevelopmentPolicy,
    request: &PolicyChangeRequest,
    pending: PendingPolicy,
) -> Result<PreparedPolicyChange, directory_admin::Refusal> {
    let snapshot = installed.snapshot().unwrap();
    d.admin
        .prepare_policy_change(request, &d.view(), &snapshot, installed, pending, &now())
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
    let d = Domain::new("pc-approved");
    let installed = installed();
    let prepared = decide(
        &d,
        &installed,
        &request(vec![add_staff_tier2()], "admin1", &["admin2"]),
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
    let d = Domain::new("pc-single");
    let installed = installed();
    let alone = decide(
        &d,
        &installed,
        &request(vec![add_staff_tier2()], "admin1", &[]),
        PendingPolicy::Absent,
    )
    .unwrap_err();
    assert_eq!(
        refusal_code(&alone),
        DecisionResult::Refused(AdminRefusal::ApprovalRequired)
    );
    assert_eq!(alone.status(), RefusalStatus::ApprovalRequired);
    let self_approved = decide(
        &d,
        &installed,
        &request(vec![add_staff_tier2()], "admin1", &["admin1"]),
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
/// `PolicyAdmin` and a Tier-0 approver; and a Tier-1 approval does not count
/// for a Tier-0 requester (the approver's own decision).
#[test]
fn a_non_tier0_administrator_is_denied_by_the_pdp() {
    let d = Domain::new("pc-tier1");
    let installed = installed();
    let denied = decide(
        &d,
        &installed,
        &request(vec![add_staff_tier2()], "helper", &["admin2"]),
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
        &d,
        &installed,
        &request(vec![add_staff_tier2()], "admin1", &["helper"]),
        PendingPolicy::Absent,
    )
    .unwrap_err();
    assert_eq!(
        refusal_code(&approver),
        DecisionResult::Refused(AdminRefusal::ApproverDenied)
    );
}

/// docs/51 §5.10 ("one pending change at a time", docs/questions/Q-591):
/// while a `policy.next` waits for root, a new change is refused — and only
/// after the PDP and dual control, so an account that may not change the
/// policy is told it may not, not that a change is pending (A-55).
#[test]
fn a_second_pending_change_is_refused_after_the_pdp() {
    let d = Domain::new("pc-pending");
    let installed = installed();
    let pending = decide(
        &d,
        &installed,
        &request(vec![add_staff_tier2()], "admin1", &["admin2"]),
        PendingPolicy::Present,
    )
    .unwrap_err();
    assert_eq!(
        refusal_code(&pending),
        DecisionResult::Refused(AdminRefusal::PendingLimit)
    );
    assert_eq!(pending.status(), RefusalStatus::Unavailable);
    let no_oracle = decide(
        &d,
        &installed,
        &request(vec![add_staff_tier2()], "helper", &["admin2"]),
        PendingPolicy::Present,
    )
    .unwrap_err();
    assert_eq!(
        refusal_code(&no_oracle),
        DecisionResult::Refused(AdminRefusal::PolicyDenied)
    );
    let unapproved = decide(
        &d,
        &installed,
        &request(vec![add_staff_tier2()], "admin1", &[]),
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
/// `ValueInvalid`.
#[test]
fn an_edit_the_edit_refuses_is_invalid() {
    let d = Domain::new("pc-invalid");
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
            &d,
            &installed,
            &request(changes.clone(), "admin1", &["admin2"]),
            PendingPolicy::Absent,
        )
        .unwrap_err();
        assert_eq!(
            refusal_code(&refused),
            DecisionResult::Refused(AdminRefusal::ValueInvalid),
            "{changes:?}"
        );
        assert_eq!(refused.status(), RefusalStatus::Invalid);
    }
    // At the bound it is decided.
    decide(
        &d,
        &installed,
        &request(
            (0..MAX_POLICY_CHANGES as u32).map(staff).collect(),
            "admin1",
            &["admin2"],
        ),
        PendingPolicy::Absent,
    )
    .unwrap();
}

/// R2 (docs/52 §5 item 4): an approval not bound to this request's digest
/// leaves the channel unbound — `PolicyAdmin` is a write, so the PDP denies
/// it (`WeakTransport`).
#[test]
fn an_approval_bound_to_another_operation_is_not_channel_bound() {
    let d = Domain::new("pc-unbound");
    let installed = installed();
    let mut unbound = request(vec![add_staff_tier2()], "admin1", &[]);
    unbound.approvals = vec![ticket_bound_to(
        "admin2",
        Some(keyd_types::OperationDigest::new([0xEE; 32])),
    )];
    let refused = decide(&d, &installed, &unbound, PendingPolicy::Absent).unwrap_err();
    assert_eq!(
        refusal_code(&refused),
        DecisionResult::Refused(AdminRefusal::PolicyDenied)
    );
    assert_eq!(
        refused.event().pdp.map(|p| p.code),
        Some(PdpReasonCode::WeakTransport)
    );
}

/// Fail closed on a misassembled caller: a PDP snapshot of another version
/// than the loaded policy is `InternalFailure`; an unverified ticket is the
/// uniform refusal; keyd down is a failure.
#[test]
fn misassembled_inputs_and_unverified_tickets_fail_closed() {
    let d = Domain::new("pc-misassembled");
    let installed = installed();
    let mut newer = installed.clone();
    newer.version = PolicyVersion(2);
    let snapshot = installed.snapshot().unwrap();
    let refused = d
        .admin
        .prepare_policy_change(
            &request(vec![add_staff_tier2()], "admin1", &["admin2"]),
            &d.view(),
            &snapshot,
            &newer,
            PendingPolicy::Absent,
            &now(),
        )
        .unwrap_err();
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
        let r = d
            .admin
            .refuse_unverified_policy_change(9, &changes, failure, &now());
        assert_eq!(refusal_code(&r), expected);
        assert_eq!(r.event().operation, DirAdminOperation::ChangePolicy);
        assert_eq!(r.event().names.len(), 1);
    }
}
