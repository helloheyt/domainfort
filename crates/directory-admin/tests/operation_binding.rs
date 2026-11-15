//! R2 at the write PEP (docs/52 §3.2, §5 item 4; decision A-102): the PEP
//! reports `channel_bound` to the PDP only when keyd verified every ticket
//! the request relies on bound to the request's own operation digest — and
//! the PDP (docs/11 §4, no `LocalIpc` exemption any more) refuses a write
//! without it (`WeakTransport`). These tests run the PEP without keyd: the
//! tickets carry the binding keyd would have reported.
//!
//! Sources: docs/52 §3.2 (C2), §5 item 4; docs/11 §1, §4; docs/51 §5.4,
//! §5.6, §7.4. Fixtures: tests/common; the digests are made-up values.

mod common;

use common::*;
use directory_admin::{
    CreateUser, KeyOperation, LookupKey, Membership, Operation, ProposedOperation, RefusalStatus,
    RequestStep,
};
use ipc_audit::{AdminRefusal, DecisionResult, DirAdminStage, PdpReasonCode};
use keyd_types::OperationDigest;

/// Another operation's digest.
const OTHER: OperationDigest = OperationDigest::new([0xEE; 32]);

fn create_user(parent: u32, sam: &str) -> Operation {
    Operation::CreateUser(CreateUser {
        parent: guid(parent),
        sam: sam.to_owned(),
        upn: None,
        description: None,
    })
}

fn refusal_code(r: &directory_admin::Refusal) -> AdminRefusal {
    match r.event().stage {
        DirAdminStage::Decision(DecisionResult::Refused(code)) => code,
        other => panic!("not a decision refusal: {other:?}"),
    }
}

/// A write whose requester's ticket keyd verified bound to another
/// operation — or reported unbound — is refused by the PDP at layer 2
/// (`WeakTransport`), and nothing is written; the same request bound to its
/// own digest is applied.
#[test]
fn a_write_by_a_ticket_bound_elsewhere_is_weak_transport() {
    let mut d = Domain::new("bind-write");
    for bound in [Some(OTHER), None] {
        let mut request = d.request(create_user(STAFF_OU, "carol"), "admin1");
        request.requester = ticket_bound_to("admin1", bound);
        let r = d.run_request(&request).refused();
        assert_eq!(refusal_code(&r), AdminRefusal::PolicyDenied, "{bound:?}");
        assert_eq!(r.status(), RefusalStatus::Denied);
        assert_eq!(r.event().pdp.unwrap().code, PdpReasonCode::WeakTransport);
        assert!(d.object(drawn_guid(1)).is_none());
    }
    let (_, applied) = d
        .run(create_user(STAFF_OU, "carol"), "admin1", &[])
        .applied();
    assert!(matches!(
        applied.reply(),
        directory_admin::Reply::Created { .. }
    ));
}

/// An approval bound to another operation does not bind this one (task
/// D2-c: an approval is an `Approve` of a pending request): admin2's
/// `Approve` whose AP-REQ keyd verified for another digest leaves the
/// channel unbound, so the PDP denies admin2 the request's Action at layer 2
/// (`WeakTransport`) — the request stays invisible to it (`NotVisible`) and
/// unapproved, and the Tier-0 membership change is refused
/// `ApprovalRequired`; approved with a bound ticket, it is applied.
#[test]
fn an_approval_bound_to_another_operation_is_refused() {
    let mut d = Domain::new("bind-approval");
    let op = || {
        Operation::AddMember(Membership {
            group: guid(TIER0_GROUP),
            member: guid(ALICE),
        })
    };
    let proposed = d
        .propose(ProposedOperation::Directory(op()), "admin1", None)
        .unwrap();
    let (id, digest) = (proposed.reply().id, proposed.reply().digest);
    let r = d
        .step_at(
            RequestStep::Approve { id, digest },
            ticket_bound_to("admin2", Some(OTHER)),
            &now(),
        )
        .unwrap_err();
    assert_eq!(refusal_code(&r), AdminRefusal::NotVisible);
    assert_eq!(r.event().pdp.unwrap().code, PdpReasonCode::WeakTransport);
    let request = d.request(op(), "admin1");
    let r = d.run_request(&request).refused();
    assert_eq!(refusal_code(&r), AdminRefusal::ApprovalRequired);
    d.approve(id, digest, "admin2").unwrap();
    d.run(op(), "admin1", &[]).applied();
}

/// A read needs no channel binding (docs/11 §4: "authenticated read →
/// {encrypted}"): a `Lookup` is answered whatever the binding keyd reported.
#[test]
fn a_read_needs_no_binding() {
    let mut d = Domain::new("bind-read");
    let mut request = d.request(
        Operation::Lookup(LookupKey::SamAccountName("alice".into())),
        "admin1",
    );
    request.requester = ticket_bound_to("admin1", None);
    let prepared = d.run_request(&request).read();
    assert!(prepared.reply().is_some());
}

/// The key plane (docs/51 §5.6), through the one mechanism (task D2-c):
/// `PolicyAdmin` is a write, so a `Propose` of a key operation whose ticket
/// keyd verified for another digest — or reported unbound — is refused at
/// layer 2, and nothing is held.
#[test]
fn key_steps_need_the_steps_own_binding() {
    let mut d = Domain::new("bind-key");
    with_policy_admin(&mut d);
    for bound in [Some(OTHER), None] {
        let request = directory_admin::ProposeRequest {
            operation_id: 1,
            operation: ProposedOperation::Key(KeyOperation::RotateKrbtgt),
            operation_digest: fingerprint(&KeyOperation::RotateKrbtgt),
            request_digest: TEST_DIGEST,
            reason_ref: None,
            // Task MA2: refused at the PDP, before the plan is compared.
            plan: Some([0xEE; 32]),
            requester: ticket_bound_to("admin1", bound),
        };
        let r = d.propose_request(&request).unwrap_err();
        assert_eq!(refusal_code(&r), AdminRefusal::PolicyDenied, "{bound:?}");
        assert_eq!(r.event().pdp.unwrap().code, PdpReasonCode::WeakTransport);
    }
    assert!(d.requests.is_empty());
}
