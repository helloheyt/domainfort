//! Plan → Commit and the effect-plan builders (tasks MA2 + MA3) through the
//! write PEP: the plan names the effect closure, is computed by the
//! functions that enforce, is part of what the requester and the approvers
//! bind, and is recomputed at every `Approve` and at the execution — a
//! different closure refuses (`PlanChanged`).
//!
//! Sources (all project documents, opened in this session):
//! docs/research/r5-a-admin-model.md §3.3 (`EffectPlan`, the effect kinds,
//! "Commit recomputes", the order against the PDP), §8.1 U4 (the forty-member
//! group added to a Tier-0 group), U17, U18 (TOCTOU between plan and
//! execution), §8.3 (C46); docs/questions/Q-874 items 1-4, 7; PENDING-OWNER
//! A-147 (the finding: "adding a 40-member group to a tier-0 group raises 40
//! people to tier 0, and the approver sees only AddMember"); Q-941 item 1
//! (the basis: the records the operation reads), item 4 (one approval, one
//! execution attempt); P-68 (an administrator's reset loses the user's
//! protected secrets); A-162 (`revoked_before`); the test domain of
//! tests/common (its own fixtures — no other implementation's test vectors).

mod common;

use common::*;
use directory_admin::{
    CreateGroup, CreateUser, Membership, Operation, ProposedOperation, Reply, RequestStep,
    SetEnabled, StepReply,
};
use dtyp::{Guid, Sid};
use ipc_audit::{AdminRefusal, DecisionResult, DirAdminOperation, DirAdminStage};
use ipc_dird_admin::{
    Effect, EffectPlan, PlanPrincipalKind, PlanTier, PolicyReferenceKind, RevocationKind,
};
use std::collections::BTreeSet;

fn refusal_code(r: &directory_admin::Refusal) -> AdminRefusal {
    match r.event().stage {
        DirAdminStage::Decision(DecisionResult::Refused(code)) => code,
        other => panic!("not a decision refusal: {other:?}"),
    }
}

/// The objectGUID and objectSid of a create's reply.
fn created(reply: &Reply) -> (Guid, Sid) {
    match reply {
        Reply::Created {
            guid,
            sid: Some(sid),
        } => (*guid, *sid),
        other => panic!("not a principal's create: {other:?}"),
    }
}

/// `admin1` creates the user `sam` in ou=Staff (unclassified: one Tier-0
/// administrator suffices, P-22).
fn user(d: &mut Domain, sam: &str) -> (Guid, Sid) {
    let op = Operation::CreateUser(CreateUser {
        parent: guid(STAFF_OU),
        sam: sam.into(),
        upn: None,
        description: None,
    });
    let (_, applied) = d.run(op, "admin1", &[]).applied();
    created(applied.reply())
}

/// `admin1` creates the global security group `sam` under `parent`.
fn group(d: &mut Domain, parent: u32, sam: &str) -> (Guid, Sid) {
    let op = Operation::CreateGroup(CreateGroup {
        parent: guid(parent),
        sam: sam.into(),
        group_type: None,
    });
    let (_, applied) = d.run(op, "admin1", &[]).applied();
    created(applied.reply())
}

/// `admin1` adds `member` to the (unclassified or Tier-1) group `group` —
/// planned and committed by the helpers (task MA2).
fn add(d: &mut Domain, group: Guid, member: Guid) {
    let op = Operation::AddMember(Membership { group, member });
    let _ = d.run(op, "admin1", &[]).applied();
}

fn add_to_tier0(member: Guid) -> Operation {
    Operation::AddMember(Membership {
        group: guid(TIER0_GROUP),
        member,
    })
}

/// The plan `requester` gets for `op`.
fn plan_of(d: &Domain, op: &Operation, requester: &str) -> (EffectPlan, [u8; 32]) {
    let planned = d
        .plan_operation(ProposedOperation::Directory(op.clone()), requester)
        .unwrap();
    (planned.plan().clone(), planned.digest())
}

/// A pending request's fingerprint as the channel computes it covers the
/// plan: these PEP tests run without the codec, so the fingerprint of a
/// `Commit` is the made-up digest of the operation and its plan digest.
fn commit_fingerprint(op: &Operation, plan: [u8; 32]) -> keyd_types::OperationDigest {
    fingerprint(&(op, plan))
}

/// `Propose` of the `Commit {plan, op}` by `requester`.
fn propose_commit(
    d: &mut Domain,
    op: &Operation,
    plan: Option<[u8; 32]>,
    requester: &str,
) -> Result<directory_admin::Proposed, directory_admin::Refusal> {
    let digest = plan.map_or_else(|| fingerprint(op), |p| commit_fingerprint(op, p));
    let request = directory_admin::ProposeRequest {
        operation_id: d.next_id(),
        operation: ProposedOperation::Directory(op.clone()),
        operation_digest: digest,
        request_digest: TEST_DIGEST,
        reason_ref: None,
        plan,
        requester: ticket(requester),
    };
    d.propose_request(&request)
}

/// The execution of `Commit {plan, op}` by `requester` (its AP-REQ bound to
/// the commit's fingerprint).
fn commit(d: &mut Domain, op: &Operation, plan: [u8; 32], requester: &str) -> Ran {
    let digest = commit_fingerprint(op, plan);
    let request = directory_admin::Request {
        operation_id: d.next_id(),
        operation: op.clone(),
        operation_digest: digest,
        plan: Some(plan),
        requester: ticket_bound_to(requester, Some(digest)),
    };
    d.run_request(&request)
}

/// The effects of `kind` (by tag) in `plan`.
fn membership_deltas(plan: &EffectPlan) -> Vec<&Effect> {
    plan.effects()
        .iter()
        .filter(|e| matches!(e, Effect::MembershipDelta { .. }))
        .collect()
}

/// The principals `plan` shows entering Tier 0 as Subjects.
fn entering_tier0(plan: &EffectPlan) -> BTreeSet<Sid> {
    plan.effects()
        .iter()
        .filter_map(|e| match e {
            Effect::TierDelta {
                subject,
                principals,
                ..
            } if subject.1 == PlanTier::Tier0 && subject.0 != PlanTier::Tier0 => {
                Some(principals.clone())
            }
            _ => None,
        })
        .flatten()
        .collect()
}

/// A-147's finding, closed (r5-a U4): H has forty members; "AddMember(H,
/// tier0)" shows exactly those forty people entering Tier 0 (and the group H
/// itself), each by SID and canonical name; every one of them gains the
/// Tier-0 group; the plan names the tier-map row that makes the group
/// Tier 0 — and the digest the approver approves is the digest of exactly
/// this closure: the request the approver sees carries it, and the
/// execution's decision event records it.
#[test]
fn forty_members_entering_tier0_are_in_the_plan_the_approver_approves() {
    let mut d = Domain::new("plan-forty");
    let (h, h_sid) = group(&mut d, STAFF_OU, "project-h");
    let mut members = BTreeSet::new();
    for i in 0..40 {
        let (g, sid) = user(&mut d, &format!("member{i:02}"));
        add(&mut d, h, g);
        members.insert(sid);
    }
    let op = add_to_tier0(h);
    let (plan, digest) = plan_of(&d, &op, "admin1");

    // TierDelta: the forty users (and H) go from Untiered to Tier 0.
    let entering = entering_tier0(&plan);
    let people: BTreeSet<Sid> = entering
        .iter()
        .filter(|s| plan.principal(s).unwrap().kind == PlanPrincipalKind::User)
        .copied()
        .collect();
    assert_eq!(people, members, "the forty people entering Tier 0");
    assert!(entering.contains(&h_sid));
    assert_eq!(entering.len(), 41);
    // Every named principal carries its canonical name (R5A-10).
    for sid in &members {
        let principal = plan.principal(sid).unwrap();
        assert!(principal.name.starts_with("member"), "{principal:?}");
    }
    // MembershipDelta: all 41 gain the Tier-0 group, nothing is lost.
    let deltas = membership_deltas(&plan);
    assert_eq!(deltas.len(), 1);
    match deltas[0] {
        Effect::MembershipDelta {
            gained,
            lost,
            principals,
        } => {
            assert_eq!(gained, &BTreeSet::from([sid_of(TIER0_GROUP)]));
            assert!(lost.is_empty());
            assert_eq!(principals.len(), 41);
        }
        other => panic!("{other:?}"),
    }
    // PolicyReference: the tier map names the group it reaches (Tier 0).
    assert!(plan.effects().iter().any(|e| matches!(
        e,
        Effect::PolicyReference { reference: PolicyReferenceKind::TierMap(PlanTier::Tier0), principals }
            if principals.contains(&sid_of(TIER0_GROUP))
    )));
    // The plan is canonical: it decodes from its own bytes, same digest.
    let bytes = plan.encode().unwrap();
    assert_eq!(EffectPlan::decode(&bytes).unwrap(), plan);
    assert_eq!(ipc_dird_admin::plan_digest(&bytes), digest);

    // Dual control (tier0 is explicitly Tier 0): the request holds the plan;
    // the approver is shown the plan from dird's record and approves the
    // fingerprint of the Commit — which covers the plan digest.
    let proposed = propose_commit(&mut d, &op, Some(digest), "admin1").unwrap();
    let fingerprint = proposed.reply().digest;
    assert_eq!(fingerprint, commit_fingerprint(&op, digest));
    assert_eq!(proposed.event().plan_digest, Some(digest));
    let shown = d
        .step(
            RequestStep::Show {
                id: proposed.reply().id,
            },
            "admin2",
        )
        .unwrap();
    match shown.reply() {
        StepReply::Shown(detail) => assert_eq!(detail.plan.as_ref(), Some(&plan)),
        other => panic!("{other:?}"),
    }
    d.approve(proposed.reply().id, fingerprint, "admin2")
        .unwrap();
    let (decision, applied) = commit(&mut d, &op, digest, "admin1").applied();
    assert_eq!(decision.plan_digest, Some(digest));
    assert_eq!(decision.pending_request, Some(proposed.reply().id));
    assert_eq!(applied.outcome_event().plan_digest, Some(digest));
    // A commit of another plan would have been another fingerprint: the
    // approval covers this closure only.
    assert_ne!(commit_fingerprint(&op, [0; 32]), fingerprint);
}

/// C46 beyond the basis (r5-a U18; Q-941 item 1): the request's basis is
/// the records the operation reads — the Tier-0 group and H. A user added
/// to H2, nested in H, changes neither record, yet adds one more person to
/// the closure: the approval of the old plan is refused at the execution
/// (`PlanChanged`, nothing written) — the approval was consumed by this
/// attempt (Q-941 item 4).
#[test]
fn a_nested_membership_change_after_the_approval_is_plan_changed() {
    let mut d = Domain::new("plan-nested");
    let (h, _) = group(&mut d, STAFF_OU, "project-h");
    let (h2, _) = group(&mut d, STAFF_OU, "project-h2");
    let (u1, _) = user(&mut d, "carol");
    add(&mut d, h, h2);
    add(&mut d, h2, u1);
    let op = add_to_tier0(h);
    let (plan, digest) = plan_of(&d, &op, "admin1");
    assert_eq!(entering_tier0(&plan).len(), 3, "h, h2, carol");
    let proposed = propose_commit(&mut d, &op, Some(digest), "admin1").unwrap();
    d.approve(proposed.reply().id, proposed.reply().digest, "admin2")
        .unwrap();

    // Between the approval and the execution: dave joins H2.
    let (dave, dave_sid) = user(&mut d, "dave");
    add(&mut d, h2, dave);
    let (new_plan, new_digest) = plan_of(&d, &op, "admin1");
    assert!(entering_tier0(&new_plan).contains(&dave_sid));
    assert_ne!(new_digest, digest);

    let r = commit(&mut d, &op, digest, "admin1").refused();
    assert_eq!(refusal_code(&r), AdminRefusal::PlanChanged);
    assert_eq!(r.status(), directory_admin::RefusalStatus::Conflict);
    assert_eq!(r.event().plan_digest, Some(new_digest));
    assert_eq!(r.event().pending_request, Some(proposed.reply().id));
    assert!(!d
        .object(guid(TIER0_GROUP))
        .unwrap()
        .attribute(d.attr("member"))
        .unwrap()
        .values
        .iter()
        .any(|v| v.value == h.to_packet().to_vec()));
    // One approval, one attempt: the request is gone.
    assert!(d.requests.is_empty());
}

/// The same change between the `Propose` and the `Approve`: the approval
/// recomputes the plan and drops the request (`PlanChanged`) — nobody
/// approves a closure other than the one proposed.
#[test]
fn a_change_before_the_approval_drops_the_request() {
    let mut d = Domain::new("plan-before-approve");
    let (h, _) = group(&mut d, STAFF_OU, "project-h");
    let (h2, _) = group(&mut d, STAFF_OU, "project-h2");
    add(&mut d, h, h2);
    let op = add_to_tier0(h);
    let (_, digest) = plan_of(&d, &op, "admin1");
    let proposed = propose_commit(&mut d, &op, Some(digest), "admin1").unwrap();
    let (eve, _) = user(&mut d, "eve");
    add(&mut d, h2, eve);
    let r = d
        .approve(proposed.reply().id, proposed.reply().digest, "admin2")
        .unwrap_err();
    assert_eq!(refusal_code(&r), AdminRefusal::PlanChanged);
    assert!(d.requests.is_empty());
}

/// The direct path (no approver: an unclassified group, P-22): the commit
/// of a stale plan is `PlanChanged`; the commit of the current plan runs.
#[test]
fn the_direct_path_recomputes_the_plan_too() {
    let mut d = Domain::new("plan-direct");
    let (h, _) = group(&mut d, STAFF_OU, "project-h");
    let (outer, _) = group(&mut d, STAFF_OU, "outer");
    let op = Operation::AddMember(Membership {
        group: outer,
        member: h,
    });
    let (_, stale) = plan_of(&d, &op, "admin1");
    let (frank, _) = user(&mut d, "frank");
    add(&mut d, h, frank);
    let r = commit(&mut d, &op, stale, "admin1").refused();
    assert_eq!(refusal_code(&r), AdminRefusal::PlanChanged);
    let (_, current) = plan_of(&d, &op, "admin1");
    let (decision, _) = commit(&mut d, &op, current, "admin1").applied();
    assert_eq!(decision.plan_digest, Some(current));
}

/// No second path (r5-a §3.3): an operation that requires a plan, sent
/// without one, is refused `PlanRequired` before anything is held or
/// written; a plan for an operation that takes none is `ValueInvalid`; a
/// proposal of a planned operation without its plan is refused and nothing
/// is queued; a proposal naming another plan is `PlanChanged`.
#[test]
fn a_planned_operation_without_its_plan_is_refused() {
    let mut d = Domain::new("plan-required");
    let disable = Operation::SetEnabled(SetEnabled {
        target: guid(BOB),
        enabled: false,
    });
    let request = d.request_with_plan(disable.clone(), "admin1", None);
    let r = d.run_request(&request).refused();
    assert_eq!(refusal_code(&r), AdminRefusal::PlanRequired);
    assert_eq!(r.status(), directory_admin::RefusalStatus::Invalid);

    let create = Operation::CreateUser(CreateUser {
        parent: guid(STAFF_OU),
        sam: "gina".into(),
        upn: None,
        description: None,
    });
    let request = d.request_with_plan(create, "admin1", Some([1; 32]));
    let r = d.run_request(&request).refused();
    assert_eq!(refusal_code(&r), AdminRefusal::ValueInvalid);

    let op = add_to_tier0(guid(ALICE));
    let r = propose_commit(&mut d, &op, None, "admin1").unwrap_err();
    assert_eq!(refusal_code(&r), AdminRefusal::PlanRequired);
    let r = propose_commit(&mut d, &op, Some([2; 32]), "admin1").unwrap_err();
    assert_eq!(refusal_code(&r), AdminRefusal::PlanChanged);
    assert!(d.requests.is_empty());
}

/// The plan is computed only after the PDP's Allow (no oracle, r5-a §3.3,
/// U17): bob may not write, and his `PlanOperation` gets the same refusal as
/// his write would (`PolicyDenied`), never a plan.
#[test]
fn no_plan_before_the_pdp_allows() {
    let d = Domain::new("plan-pdp");
    let r = d
        .plan_operation(
            ProposedOperation::Directory(add_to_tier0(guid(ALICE))),
            "bob",
        )
        .unwrap_err();
    assert_eq!(refusal_code(&r), AdminRefusal::PolicyDenied);
    assert_eq!(r.event().operation, DirAdminOperation::PlanOperation);
    assert_eq!(r.event().plan_digest, None);
}

/// Q-874 item 4 (Q-983): whoever cannot see the results of an operation
/// does not perform it. `team` (ou=Managed, Tier 1) holds `secret`, whose
/// ou=Hidden only the Tier-0 group may read; helper (Tier 1) may write
/// ou=Managed, but its plan of "AddMember(crew, team)" names `secret` ⇒
/// `PlanNotVisible`; admin1, who may see `secret`, gets the plan.
#[test]
fn an_effect_the_requester_cannot_see_is_plan_not_visible() {
    let mut d = Domain::new("plan-visibility");
    let (team, _) = group(&mut d, MANAGED_OU, "team");
    let (crew, _) = group(&mut d, MANAGED_OU, "crew");
    add(&mut d, team, guid(SECRET));
    let op = Operation::AddMember(Membership {
        group: crew,
        member: team,
    });
    let r = d
        .plan_operation(ProposedOperation::Directory(op.clone()), "helper")
        .unwrap_err();
    assert_eq!(refusal_code(&r), AdminRefusal::PlanNotVisible);
    assert_eq!(r.status(), directory_admin::RefusalStatus::Denied);
    let (plan, _) = plan_of(&d, &op, "admin1");
    assert!(plan.principal(&sid_of(SECRET)).is_some());
}

/// The account effects (r5-a §3.3, §8.2): a password set revokes the
/// account's tickets for good (A-162) and loses a user's protected secrets
/// (P-68); a disable revokes them while the account stays unusable (D53);
/// an enable has no effect beyond its target.
#[test]
fn account_effects_come_from_the_kdc_account_state() {
    let d = Domain::new("plan-accounts");
    let (set, _) = plan_of(
        &d,
        &Operation::BeginPasswordSet { target: guid(BOB) },
        "admin1",
    );
    assert!(set.effects().iter().any(|e| matches!(
        e,
        Effect::TicketsRevoked { kind: RevocationKind::PasswordSet, principals }
            if principals.contains(&sid_of(BOB))
    )));
    assert!(set.effects().iter().any(|e| matches!(
        e,
        Effect::ProtectedDataLoss { principals } if principals.contains(&sid_of(BOB))
    )));
    let disable = Operation::SetEnabled(SetEnabled {
        target: guid(BOB),
        enabled: false,
    });
    let (off, _) = plan_of(&d, &disable, "admin1");
    assert_eq!(
        off.effects(),
        &[Effect::TicketsRevoked {
            kind: RevocationKind::AccountUnusable,
            principals: BTreeSet::from([sid_of(BOB)]),
        }]
    );
    let enable = Operation::SetEnabled(SetEnabled {
        target: guid(DISABLED),
        enabled: true,
    });
    let (on, _) = plan_of(&d, &enable, "admin1");
    assert!(on.effects().is_empty());
    // A computer's password set loses no user secret.
    let (ws, _) = plan_of(
        &d,
        &Operation::BeginPasswordSet { target: guid(WS01) },
        "admin1",
    );
    assert!(!ws
        .effects()
        .iter()
        .any(|e| matches!(e, Effect::ProtectedDataLoss { .. })));
}

/// A `Delete` (r5-a §8.2: "Delete ⇒ removal from groups + key set
/// destruction after a decision"): a user's tickets end and its key sets are
/// destroyed by dird's decision (A-105); a group's members lose it.
#[test]
fn delete_effects() {
    let mut d = Domain::new("plan-delete");
    let (plan, _) = plan_of(&d, &Operation::Delete { target: guid(BOB) }, "admin1");
    assert!(plan.effects().iter().any(|e| matches!(
        e,
        Effect::KeyDestruction { kvno: None, principals } if principals.contains(&sid_of(BOB))
    )));
    assert!(plan.effects().iter().any(|e| matches!(
        e,
        Effect::TicketsRevoked { kind: RevocationKind::AccountUnusable, principals }
            if principals.contains(&sid_of(BOB))
    )));
    let (club, club_sid) = group(&mut d, STAFF_OU, "club");
    add(&mut d, club, guid(ALICE));
    let (plan, _) = plan_of(&d, &Operation::Delete { target: club }, "admin1");
    assert!(plan.effects().iter().any(|e| matches!(
        e,
        Effect::MembershipDelta { lost, principals, .. }
            if lost.contains(&club_sid) && principals.contains(&sid_of(ALICE))
    )));
}

/// A removal: the members leave the Tier-0 group and drop out of Tier 0
/// (the inverse of U4).
#[test]
fn a_removal_shows_who_leaves_tier0() {
    let mut d = Domain::new("plan-remove");
    let (h, h_sid) = group(&mut d, STAFF_OU, "project-h");
    let op = add_to_tier0(h);
    let _ = d.run(op, "admin1", &["admin2"]).applied();
    let remove = Operation::RemoveMember(Membership {
        group: guid(TIER0_GROUP),
        member: h,
    });
    let (plan, _) = plan_of(&d, &remove, "admin1");
    assert!(plan.effects().iter().any(|e| matches!(
        e,
        Effect::TierDelta { subject: (PlanTier::Tier0, PlanTier::None), principals, .. }
            if principals.contains(&h_sid)
    )));
}
