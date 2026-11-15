//! The one dual-control mechanism at the write PEP (task D2-c;
//! docs/questions/Q-882, A-148; r5-a MA5): pending requests held in dird for
//! every dual-controlled operation — `Propose` (a dry run of the operation's
//! checks; its exact fields and digest held), `ShowRequest` (the operation
//! from the request's own fields, the facts dird resolved),
//! `Approve {id, digest}` (everything the request was judged on evaluated
//! again), `Reject`, `Withdraw`, `ListRequests`, expiry, the per-requester
//! cap, and the execution that consumes the approved request.
//!
//! Sources: docs/questions/Q-882 items 1-4 ("`Propose {operation,
//! reason_ref?}` ⇒ `{id, digest, quorum, expires}`; `Show {id}`; `Approve
//! {id, digest}`; `Withdraw {id}`; `List {mine | awaiting_me}`; at the
//! quorum dird re-evaluates the requester and the approvers … on the current
//! snapshot; ids from the CSPRNG; `reason_ref` printable ASCII ≤ 64"),
//! Q-888 (the digest in every event); docs/research/r5-a-admin-model.md §8.2
//! items 3-4, §11 MA5 ("`ListRequests` / `ShowRequest` / `Reject` /
//! `Withdraw`, TTL, per-requester quota, no multi-approve"); docs/51 §5.6
//! (P-22); docs/52 classes C14, C43, C44, C47; A-55 (no oracle). Fixtures:
//! tests/common (two Tier-0 administrators, quorum 2). No vector comes from
//! any other implementation.

mod common;

use core::time::Duration;

use common::*;
use directory_admin::{
    ConfigError, CreateUser, ListScope, Membership, Operation, PendingRequests, ProposedOperation,
    RefusalStatus, RequestState, RequestStep, SetEnabled, StepReply, MAX_REQUESTS_PER_REQUESTER,
    MAX_REQUEST_LIFETIME, REQUESTS_PER_REQUESTER, REQUEST_LIFETIME,
};
use ipc_audit::{AdminRefusal, DecisionResult, DirAdminOperation, DirAdminStage, SidValue};
use pdp::Tier;

fn refusal_code(r: &directory_admin::Refusal) -> AdminRefusal {
    match r.event().stage {
        DirAdminStage::Decision(DecisionResult::Refused(code)) => code,
        other => panic!("not a decision refusal: {other:?}"),
    }
}

fn sid_value(id: u32) -> SidValue {
    SidValue::new(dtyp::SECURITY_NT_AUTHORITY, vec![21, 1, 2, 3, rid(id)]).unwrap()
}

/// The Tier-0 membership change P-22 puts under dual control.
fn alice_to_tier0() -> Operation {
    Operation::AddMember(Membership {
        group: guid(TIER0_GROUP),
        member: guid(ALICE),
    })
}

fn create_user(parent: u32, sam: &str) -> Operation {
    Operation::CreateUser(CreateUser {
        parent: guid(parent),
        sam: sam.to_owned(),
        upn: None,
        description: None,
    })
}

/// admin1 proposes `op` with `reason`; its id and digest.
fn propose(
    d: &mut Domain,
    op: Operation,
    reason: Option<&str>,
) -> (u64, keyd_types::OperationDigest) {
    let proposed = d
        .propose(ProposedOperation::Directory(op), "admin1", reason)
        .unwrap();
    (proposed.reply().id, proposed.reply().digest)
}

/// Q-882 items 1-2, Q-888; docs/51 §5.6 (P-22): the two-person flow end to
/// end at the PEP — admin1 proposes (the `Decision` event names the step,
/// the proposed operation, its fingerprint, the `reason_ref`, the request),
/// admin2 is shown the operation from the request's own fields with the
/// facts dird resolved, approves it by id and digest, and admin1's
/// execution of the very operation consumes the approved request: applied,
/// its events carry the same fingerprint, the request's id and the
/// approver; the request is gone (one approval, one execution).
#[test]
fn the_two_person_flow_end_to_end() {
    let mut d = Domain::new("rq-flow");
    let proposed = d
        .propose(
            ProposedOperation::Directory(alice_to_tier0()),
            "admin1",
            Some("CHG-1182"),
        )
        .unwrap();
    let view = proposed.reply().clone();
    assert_eq!(view.state, RequestState::Pending);
    assert_eq!((view.approvals, view.quorum), (0, QUORUM));
    assert_eq!(view.digest, fingerprint(&alice_to_tier0()));
    assert_ne!(view.id, 0);
    let event = proposed.event();
    assert_eq!(event.operation, DirAdminOperation::Propose);
    assert_eq!(event.proposed, Some(DirAdminOperation::AddMember));
    assert_eq!(event.operation_digest, *view.digest.as_bytes());
    assert_eq!(event.pending_request, Some(view.id));
    assert_eq!(
        event.reason_ref.as_ref().and_then(|r| r.as_text()),
        Some("CHG-1182")
    );
    assert_eq!(event.requester, Some(sid_value(ADMIN1)));
    assert_eq!(event.target, Some(guid(TIER0_GROUP).to_packet()));
    assert_eq!(event.member, Some(guid(ALICE).to_packet()));

    // admin2 is shown it: the operation is the request's own copy; the
    // facts are dird's (DN, class, SID, explicit tier).
    let shown = d.step(RequestStep::Show { id: view.id }, "admin2").unwrap();
    let StepReply::Shown(detail) = shown.reply() else {
        panic!("{:?}", shown.reply());
    };
    assert_eq!(
        detail.operation,
        ProposedOperation::Directory(alice_to_tier0())
    );
    assert_eq!(detail.digest, view.digest);
    assert_eq!(detail.requester, sid_of(ADMIN1));
    assert_eq!(detail.reason_ref.as_deref(), Some("CHG-1182"));
    assert_eq!(detail.facts.len(), 2);
    assert_eq!(detail.facts[0].guid, guid(TIER0_GROUP));
    assert_eq!(detail.facts[0].class, "group");
    assert_eq!(detail.facts[0].tier, Some(Tier::Tier0));
    assert_eq!(detail.facts[0].sid, Some(sid_of(TIER0_GROUP)));
    assert_eq!(detail.facts[1].guid, guid(ALICE));
    assert_eq!(detail.facts[1].class, "user");
    assert_eq!(detail.facts[1].tier, None, "alice is unclassified");
    assert_eq!(shown.event().operation, DirAdminOperation::ShowRequest);
    assert_eq!(shown.event().operation_digest, *view.digest.as_bytes());

    let approved = d.approve(view.id, view.digest, "admin2").unwrap();
    let approved_view = request_view(&approved);
    assert_eq!(approved_view.state, RequestState::Approved);
    assert_eq!(approved_view.approvals, 1);
    assert!(approved.decision().is_none(), "not a key operation");
    assert_eq!(approved.event().operation, DirAdminOperation::Approve);
    assert_eq!(approved.event().approvers.as_slice(), &[sid_value(ADMIN2)]);
    assert_eq!(approved.event().operation_digest, *view.digest.as_bytes());

    // The execution: the same operation, admin1's fresh ticket.
    let request = d.request(alice_to_tier0(), "admin1");
    let (decision, applied) = d.run_request(&request).applied();
    assert_eq!(decision.operation, DirAdminOperation::AddMember);
    assert_eq!(decision.pending_request, Some(view.id));
    assert_eq!(decision.operation_digest, *view.digest.as_bytes());
    assert_eq!(decision.approvers.as_slice(), &[sid_value(ADMIN2)]);
    assert_eq!(
        decision.reason_ref.as_ref().and_then(|r| r.as_text()),
        Some("CHG-1182")
    );
    assert_eq!(
        applied.outcome_event().operation_digest,
        *view.digest.as_bytes()
    );
    assert!(d.requests.is_empty(), "consumed");
    // A second execution needs a new approval.
    let again = d.run_request(&d.request(alice_to_tier0(), "admin1"));
    assert!(matches!(again, Ran::Refused(_)));
}

/// P-22 item 2; Q-882 item 1 ("approver ≠ requester"): the requester cannot
/// approve its own request, nor reject it (it withdraws it).
#[test]
fn the_requester_cannot_approve_or_reject_its_own_request() {
    let mut d = Domain::new("rq-self");
    let (id, digest) = propose(&mut d, alice_to_tier0(), None);
    let r = d.approve(id, digest, "admin1").unwrap_err();
    assert_eq!(refusal_code(&r), AdminRefusal::ApproverNotDistinct);
    assert_eq!(r.status(), RefusalStatus::Denied);
    let r = d
        .step(RequestStep::Reject { id, digest }, "admin1")
        .unwrap_err();
    assert_eq!(refusal_code(&r), AdminRefusal::ApproverNotDistinct);
    let r = d.run(alice_to_tier0(), "admin1", &[]).refused();
    assert_eq!(refusal_code(&r), AdminRefusal::ApprovalRequired);
}

/// Class C43; Q-882 item 2 ("re-evaluates … and the semantic checks on the
/// current snapshot"): an object the approved operation depends on changes
/// between the approval and the execution (alice is disabled by a write
/// that needs no approver) — the execution is refused `RequestStale`
/// (`Conflict`), nothing is written, and the request is dropped.
#[test]
fn a_change_of_the_target_between_approve_and_execute_is_refused() {
    let mut d = Domain::new("rq-stale-exec");
    let (id, digest) = propose(&mut d, alice_to_tier0(), None);
    d.approve(id, digest, "admin2").unwrap();
    d.run(
        Operation::SetEnabled(SetEnabled {
            target: guid(ALICE),
            enabled: false,
        }),
        "admin1",
        &[],
    )
    .applied();
    let r = d.run(alice_to_tier0(), "admin1", &[]).refused();
    assert_eq!(refusal_code(&r), AdminRefusal::RequestStale);
    assert_eq!(r.status(), RefusalStatus::Conflict);
    assert_eq!(r.event().pending_request, Some(id));
    assert!(d.requests.is_empty(), "dropped");
    let group = d.object(guid(TIER0_GROUP)).unwrap();
    let member = d.attr("member");
    let members = group
        .attributes
        .iter()
        .find(|a| a.id == member)
        .map(|a| a.values.len())
        .unwrap_or(0);
    assert_eq!(members, 2, "alice was not added");
}

/// Class C43: a change between the proposal and the approval — the approver
/// would judge facts that are no longer true — refuses the approval
/// `RequestStale` and drops the request.
#[test]
fn a_change_of_the_target_between_propose_and_approve_is_refused() {
    let mut d = Domain::new("rq-stale-approve");
    let (id, digest) = propose(&mut d, alice_to_tier0(), None);
    d.run(
        Operation::SetEnabled(SetEnabled {
            target: guid(ALICE),
            enabled: false,
        }),
        "admin1",
        &[],
    )
    .applied();
    let r = d.approve(id, digest, "admin2").unwrap_err();
    assert_eq!(refusal_code(&r), AdminRefusal::RequestStale);
    assert!(d.requests.is_empty());
}

/// Q-882 item 2 ("re-evaluates the requester and the approvers"): the
/// requester's standing is evaluated again at each approval — admin1's
/// password is set (through the mechanism itself) after it proposed, which
/// revokes the ticket it proposed with (docs/47 §4.5) — so admin2's
/// approval of admin1's request is refused `RequestStale`.
#[test]
fn the_requester_is_evaluated_again_at_the_approval() {
    let mut d = Domain::new("rq-requester");
    let (id, digest) = propose(&mut d, alice_to_tier0(), None);
    // admin2 has admin1's password set (admin1 approves it).
    let password = Operation::BeginPasswordSet {
        target: guid(ADMIN1),
    };
    let proposed = d
        .propose(
            ProposedOperation::Directory(password.clone()),
            "admin2",
            None,
        )
        .unwrap();
    d.approve(proposed.reply().id, proposed.reply().digest, "admin1")
        .unwrap();
    d.run(password, "admin2", &[]).applied();
    let r = d.approve(id, digest, "admin2").unwrap_err();
    assert_eq!(refusal_code(&r), AdminRefusal::RequestStale);
    assert!(d.requests.is_empty());
}

/// Q-882 item 2: every approver's standing is evaluated again at the
/// execution — admin2 approved, then its own password was set (revoking the
/// ticket it approved with) — so admin1's execution is refused
/// `RequestStale`.
#[test]
fn the_approvers_are_evaluated_again_at_the_execution() {
    let mut d = Domain::new("rq-approver");
    let (id, digest) = propose(&mut d, alice_to_tier0(), None);
    d.approve(id, digest, "admin2").unwrap();
    d.run(
        Operation::BeginPasswordSet {
            target: guid(ADMIN2),
        },
        "admin1",
        &["admin2"],
    )
    .applied();
    let r = d.run(alice_to_tier0(), "admin1", &[]).refused();
    assert_eq!(refusal_code(&r), AdminRefusal::RequestStale);
    assert_eq!(r.event().pending_request, Some(id));
}

/// Q-882 ("TTL"), r5-a MA5: a request expires — after its lifetime it is
/// unknown (`PendingUnknown`, told `NotFound`) to an approval, and its
/// execution needs a new one.
#[test]
fn an_expired_request_is_unknown() {
    let mut d = Domain::new("rq-expired");
    let (id, digest) = propose(&mut d, alice_to_tier0(), None);
    let later = kt(2026, 11, 13, 11, 0, 1); // now + 60 min + 1 s
    let mut fresh = ticket("admin2");
    fresh.authtime = kt(2026, 11, 13, 10, 59, 0);
    let r = d
        .step_at(RequestStep::Approve { id, digest }, fresh, &later)
        .unwrap_err();
    assert_eq!(refusal_code(&r), AdminRefusal::PendingUnknown);
    assert_eq!(r.status(), RefusalStatus::NotFound);
    assert!(d.requests.is_empty(), "purged");
    assert_eq!(REQUEST_LIFETIME, Duration::from_secs(60 * 60));
}

/// Q-882 item 1 (`Withdraw {id}` — the requester only): a withdrawn request
/// is gone; another account's withdrawal is answered as for an unknown id.
#[test]
fn a_withdrawn_request_is_gone() {
    let mut d = Domain::new("rq-withdraw");
    let (id, digest) = propose(&mut d, alice_to_tier0(), None);
    let r = d.step(RequestStep::Withdraw { id }, "admin2").unwrap_err();
    assert_eq!(refusal_code(&r), AdminRefusal::NotVisible);
    assert_eq!(r.status(), RefusalStatus::NotFound);
    let withdrawn = d.step(RequestStep::Withdraw { id }, "admin1").unwrap();
    assert_eq!(withdrawn.reply(), &StepReply::Done);
    assert_eq!(withdrawn.event().operation, DirAdminOperation::Withdraw);
    assert_eq!(withdrawn.event().pending_request, Some(id));
    let r = d.approve(id, digest, "admin2").unwrap_err();
    assert_eq!(refusal_code(&r), AdminRefusal::PendingUnknown);
    let r = d.run(alice_to_tier0(), "admin1", &[]).refused();
    assert_eq!(refusal_code(&r), AdminRefusal::ApprovalRequired);
}

/// r5-a MA5 (`Reject`): an eligible approver ends the request, naming the
/// digest it was shown (another digest is `OperationMismatch`); an account
/// that may not approve cannot see it.
#[test]
fn a_rejected_request_is_gone() {
    let mut d = Domain::new("rq-reject");
    let (id, digest) = propose(&mut d, alice_to_tier0(), None);
    let r = d
        .step(
            RequestStep::Reject {
                id,
                digest: fingerprint(&"another"),
            },
            "admin2",
        )
        .unwrap_err();
    assert_eq!(refusal_code(&r), AdminRefusal::OperationMismatch);
    let r = d
        .step(RequestStep::Reject { id, digest }, "bob")
        .unwrap_err();
    assert_eq!(refusal_code(&r), AdminRefusal::NotVisible);
    let rejected = d
        .step(RequestStep::Reject { id, digest }, "admin2")
        .unwrap();
    assert_eq!(rejected.reply(), &StepReply::Done);
    assert_eq!(rejected.event().operation, DirAdminOperation::Reject);
    assert_eq!(rejected.event().approvers.as_slice(), &[sid_value(ADMIN2)]);
    let r = d.approve(id, digest, "admin2").unwrap_err();
    assert_eq!(refusal_code(&r), AdminRefusal::PendingUnknown);
}

/// Class C47; r5-a §8.2 item 4, MA5; Q-878 item 2 (interim, P-78 open): a
/// requester holds at most `REQUESTS_PER_REQUESTER` open requests — one
/// more is refused `RequesterLimit` (told `Unavailable`) — and at most one
/// per operation (`Conflict`); withdrawing one frees a place.
#[test]
fn the_per_requester_cap_holds() {
    let mut d = Domain::new("rq-cap");
    let ops: Vec<Operation> = (0..=REQUESTS_PER_REQUESTER)
        .map(|n| create_user(TIER0_OU, &format!("t0user{n}")))
        .collect();
    let mut ids = Vec::new();
    for op in &ops[..REQUESTS_PER_REQUESTER] {
        ids.push(propose(&mut d, op.clone(), None).0);
    }
    let r = d
        .propose(
            ProposedOperation::Directory(ops[REQUESTS_PER_REQUESTER].clone()),
            "admin1",
            None,
        )
        .unwrap_err();
    assert_eq!(refusal_code(&r), AdminRefusal::RequesterLimit);
    assert_eq!(r.status(), RefusalStatus::Unavailable);
    // Another requester is not affected.
    d.propose(
        ProposedOperation::Directory(ops[REQUESTS_PER_REQUESTER].clone()),
        "admin2",
        None,
    )
    .unwrap();
    d.step(RequestStep::Withdraw { id: ids[0] }, "admin1")
        .unwrap();
    // The same operation twice: one open request per operation.
    let r = d
        .propose(ProposedOperation::Directory(ops[1].clone()), "admin1", None)
        .unwrap_err();
    assert_eq!(refusal_code(&r), AdminRefusal::Conflict);
    propose(&mut d, ops[0].clone(), None);
    // Distinct ids from the random source, never 0.
    let mut all = ids.clone();
    all.sort_unstable();
    all.dedup();
    assert_eq!(all.len(), ids.len());
    assert!(ids.iter().all(|id| *id != 0));
}

/// Class C47 (r5-a §8.2 item 1: "fewer approvals, not faster ones"): a
/// proposal of an operation whose rule needs no approver is refused
/// `ApprovalNotNeeded` (told `Invalid`) — nobody is asked to judge it; a
/// read or an audit-only report cannot be proposed (`ValueInvalid`); an
/// operation its checks refuse is refused at the proposal with their reason.
#[test]
fn only_operations_that_need_an_approver_are_queued() {
    let mut d = Domain::new("rq-needless");
    let r = d
        .propose(
            ProposedOperation::Directory(create_user(STAFF_OU, "carol")),
            "admin1",
            None,
        )
        .unwrap_err();
    assert_eq!(refusal_code(&r), AdminRefusal::ApprovalNotNeeded);
    assert_eq!(r.status(), RefusalStatus::Invalid);
    let r = d
        .propose(
            ProposedOperation::Directory(Operation::Lookup(
                directory_admin::LookupKey::SamAccountName("alice".into()),
            )),
            "admin1",
            None,
        )
        .unwrap_err();
    assert_eq!(refusal_code(&r), AdminRefusal::ValueInvalid);
    let r = d
        .propose(
            ProposedOperation::Directory(create_user(TIER0_OU, "admin1")),
            "admin1",
            None,
        )
        .unwrap_err();
    assert_eq!(
        refusal_code(&r),
        AdminRefusal::Conflict,
        "the name is taken"
    );
    assert!(d.requests.is_empty());
}

/// Q-882 item 4: `reason_ref` is 1 to 64 printable ASCII characters; anything
/// else is `ValueInvalid`.
#[test]
fn the_reason_ref_is_short_printable_ascii() {
    let mut d = Domain::new("rq-reason");
    let long = "x".repeat(65);
    for bad in ["", "tab\there", "naïve", long.as_str()] {
        let r = d
            .propose(
                ProposedOperation::Directory(alice_to_tier0()),
                "admin1",
                Some(bad),
            )
            .unwrap_err();
        assert_eq!(refusal_code(&r), AdminRefusal::ValueInvalid, "{bad:?}");
    }
    propose(&mut d, alice_to_tier0(), Some(&"y".repeat(64)));
}

/// Q-882 item 1 (`List {mine | awaiting_me}` under the PDP; `Show` to the
/// requester and eligible approvers only — A-55): admin1 lists its request;
/// admin2 sees it awaiting its approval until it approved; bob (who may not
/// approve it) sees nothing and is told `NotFound` when asking for it.
#[test]
fn list_and_show_follow_the_pdp() {
    let mut d = Domain::new("rq-list");
    let (id, digest) = propose(&mut d, alice_to_tier0(), None);
    let list = |d: &mut Domain, scope: ListScope, who: &str| match d
        .step(RequestStep::List(scope), who)
        .unwrap()
        .reply()
        .clone()
    {
        StepReply::List(entries) => entries,
        other => panic!("{other:?}"),
    };
    let mine = list(&mut d, ListScope::Mine, "admin1");
    assert_eq!(mine.len(), 1);
    assert_eq!(mine[0].id, id);
    assert_eq!(mine[0].requester, sid_of(ADMIN1));
    assert_eq!(
        mine[0].operation,
        ProposedOperation::Directory(alice_to_tier0())
    );
    assert!(list(&mut d, ListScope::AwaitingMe, "admin1").is_empty());
    assert_eq!(list(&mut d, ListScope::AwaitingMe, "admin2").len(), 1);
    assert!(list(&mut d, ListScope::Mine, "admin2").is_empty());
    assert!(list(&mut d, ListScope::AwaitingMe, "bob").is_empty());
    let r = d.step(RequestStep::Show { id }, "bob").unwrap_err();
    assert_eq!(refusal_code(&r), AdminRefusal::NotVisible);
    assert_eq!(r.status(), RefusalStatus::NotFound);
    let r = d
        .step(RequestStep::Show { id: id ^ 1 }, "admin2")
        .unwrap_err();
    assert_eq!(refusal_code(&r), AdminRefusal::PendingUnknown);
    assert_eq!(r.status(), RefusalStatus::NotFound);
    d.approve(id, digest, "admin2").unwrap();
    assert!(list(&mut d, ListScope::AwaitingMe, "admin2").is_empty());
    let mine = list(&mut d, ListScope::Mine, "admin1");
    assert_eq!(mine[0].state, RequestState::Approved);
}

/// docs/51 §5.6 ("bounded in number and in time"); Q-939, Q-940: the
/// lifetime is 1 s ..= one hour, the per-requester cap 1 ..= 8.
#[test]
fn the_table_bounds_are_checked() {
    for lifetime in [
        Duration::ZERO,
        MAX_REQUEST_LIFETIME + Duration::from_secs(1),
    ] {
        assert_eq!(
            PendingRequests::new(domain_targets(), lifetime, 1).unwrap_err(),
            ConfigError::RequestLifetime
        );
    }
    for cap in [0, MAX_REQUESTS_PER_REQUESTER + 1] {
        assert_eq!(
            PendingRequests::new(domain_targets(), REQUEST_LIFETIME, cap).unwrap_err(),
            ConfigError::RequesterCap
        );
    }
    let table = PendingRequests::new(
        domain_targets(),
        Duration::from_secs(1),
        MAX_REQUESTS_PER_REQUESTER,
    )
    .unwrap();
    assert!(table.is_empty());
    assert_eq!(table.len(), 0);
}
