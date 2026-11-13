//! Dual control and the self-lockout guard.
//!
//! Sources: docs/51 §5.6 (R51-11); docs/questions/Q-295 as decided by the
//! owner item P-22 ("proceed with the recommendation"): item 1 — the scope
//! (membership change of a Tier0 group; password / enable / delete /
//! accountExpires of a Tier0 principal; create inside an **explicitly**
//! Tier0 subtree; a write that is Tier0 only because it is unclassified
//! needs no approver), item 2 — the requester plus one other, distinct
//! approver, each with `decide` = Allow for the same Action and Resource,
//! item 4 — refuse a disable, delete or removal from the Tier-0 group that
//! leaves fewer enabled Tier-0 administrators than the quorum. Fixtures:
//! tests/common (two administrators, quorum 2).

mod common;

use common::*;
use directory_admin::{
    CreateUser, Membership, Operation, RefusalStatus, SetAccountExpires, SetEnabled,
    VerificationFailure,
};
use ipc_audit::{
    AccountExpiresValue, AdminFailure, AdminRefusal, DecisionResult, DirAdminStage, SidValue,
};

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

fn sid_value(id: u32) -> SidValue {
    SidValue::new(dtyp::SECURITY_NT_AUTHORITY, vec![21, 1, 2, 3, rid(id)]).unwrap()
}

/// P-22 item 1: creating inside the tier map's explicit Tier0 subtree
/// (ou=Tier0) needs an approver; with admin2's approval it is applied, and
/// the decision event names the approver (A-85).
#[test]
fn a_create_in_an_explicit_tier0_subtree_needs_an_approver() {
    let mut d = Domain::new("dc-create");
    let r = d
        .run(create_user(TIER0_OU, "admin3"), "admin1", &[])
        .refused();
    assert_eq!(refusal_code(&r), AdminRefusal::ApprovalRequired);
    assert_eq!(r.status(), RefusalStatus::ApprovalRequired);
    let (decision, _) = d
        .run(create_user(TIER0_OU, "admin3"), "admin1", &["admin2"])
        .applied();
    assert_eq!(decision.approvers.as_slice(), &[sid_value(ADMIN2)]);
    assert_eq!(decision.requester, Some(sid_value(ADMIN1)));
}

/// P-22 item 1, last sentence: a write that is Tier0 only because it is
/// unclassified (ou=Staff, A-36) needs no approver — one Tier-0
/// administrator is enough.
#[test]
fn an_unclassified_tier0_write_needs_no_approver() {
    let mut d = Domain::new("dc-unclassified");
    d.run(create_user(STAFF_OU, "carol"), "admin1", &[])
        .applied();
    d.run(
        Operation::SetEnabled(SetEnabled {
            target: guid(BOB),
            enabled: false,
        }),
        "admin1",
        &[],
    )
    .applied();
}

/// P-22 item 1: a membership change of a group whose tier is Tier0 (the
/// tier map's Tier0 group), and password / enable / accountExpires / delete
/// of a Tier0 principal (admin2, a member of it), need an approver.
#[test]
fn tier0_principals_and_groups_need_an_approver() {
    let mut d = Domain::new("dc-scope");
    let ops = [
        Operation::AddMember(Membership {
            group: guid(TIER0_GROUP),
            member: guid(ALICE),
        }),
        Operation::BeginPasswordSet {
            target: guid(ADMIN2),
        },
        Operation::SetEnabled(SetEnabled {
            target: guid(ADMIN2),
            enabled: true,
        }),
        Operation::SetAccountExpires(SetAccountExpires {
            target: guid(ADMIN2),
            value: AccountExpiresValue::NEVER,
        }),
        Operation::Delete {
            target: guid(ADMIN2),
        },
    ];
    for op in ops {
        let r = d.run(op.clone(), "admin1", &[]).refused();
        assert_eq!(refusal_code(&r), AdminRefusal::ApprovalRequired, "{op:?}");
    }
    // Satisfied: the Tier0 group gains alice with admin2's approval.
    d.run(
        Operation::AddMember(Membership {
            group: guid(TIER0_GROUP),
            member: guid(ALICE),
        }),
        "admin1",
        &["admin2"],
    )
    .applied();
}

/// P-22 item 2: the approver must differ from the requester and from every
/// other approver.
#[test]
fn approvers_must_be_distinct() {
    let mut d = Domain::new("dc-distinct");
    let r = d
        .run(create_user(TIER0_OU, "admin3"), "admin1", &["admin1"])
        .refused();
    assert_eq!(refusal_code(&r), AdminRefusal::ApproverNotDistinct);
    assert_eq!(r.status(), RefusalStatus::Denied);
    let r = d
        .run(
            create_user(TIER0_OU, "admin3"),
            "admin1",
            &["admin2", "admin2"],
        )
        .refused();
    assert_eq!(refusal_code(&r), AdminRefusal::ApproverNotDistinct);
}

/// P-22 item 2: each approval needs `decide` = Allow for the same Action
/// and Resource — bob may read but not create ⇒ `ApproverDenied`; helper is
/// Tier1, so creating in a Tier0 subtree is denied to him (layer 4).
#[test]
fn an_approver_the_pdp_denies_is_refused() {
    let mut d = Domain::new("dc-denied");
    for approver in ["bob", "helper"] {
        let r = d
            .run(create_user(TIER0_OU, "admin3"), "admin1", &[approver])
            .refused();
        assert_eq!(refusal_code(&r), AdminRefusal::ApproverDenied, "{approver}");
        assert_eq!(r.status(), RefusalStatus::Denied);
    }
}

/// docs/51 §5.6 ("each a verified AP-REQ", §5.3): an approver whose account
/// is unknown or unusable, or whose ticket is older than the threshold
/// (R51-10), is refused.
#[test]
fn an_unusable_approver_is_refused() {
    let mut d = Domain::new("dc-unusable");
    for approver in ["disabled", "nobody"] {
        let r = d
            .run(create_user(TIER0_OU, "admin3"), "admin1", &[approver])
            .refused();
        assert_eq!(
            refusal_code(&r),
            AdminRefusal::ApproverUnauthenticated,
            "{approver}"
        );
    }
    let mut request = d.request(create_user(TIER0_OU, "admin3"), "admin1", &["admin2"]);
    request.approvals[0].authtime = kt(2026, 11, 13, 9, 49, 59);
    let r = d.run_request(&request).refused();
    assert_eq!(refusal_code(&r), AdminRefusal::ApproverUnauthenticated);
}

/// docs/51 §7.2: at most two approvals per request.
#[test]
fn more_than_two_approvals_are_refused() {
    let mut d = Domain::new("dc-many");
    let r = d
        .run(
            create_user(TIER0_OU, "admin3"),
            "admin1",
            &["admin2", "alice", "bob"],
        )
        .refused();
    assert_eq!(refusal_code(&r), AdminRefusal::ValueInvalid);
}

/// A quorum of three needs two distinct approvers (P-22 allows the
/// configured quorum; MIN_QUORUM = 2, MAX_QUORUM = 3).
#[test]
fn a_quorum_of_three_needs_two_approvers() {
    let mut d = Domain::with_quorum("dc-quorum3", 3);
    // Give the Tier0 group a third administrator first (needs two
    // approvers already): impossible with only admin2 ⇒ ApprovalRequired.
    let add = Operation::AddMember(Membership {
        group: guid(TIER0_GROUP),
        member: guid(ALICE),
    });
    let r = d.run(add, "admin1", &["admin2"]).refused();
    assert_eq!(refusal_code(&r), AdminRefusal::ApprovalRequired);
}

/// docs/51 §7.4 step 1: an AP-REQ keyd did not verify is refused before
/// `prepare` — uniform `Denied`, or `Unavailable` when keyd is down
/// (A-26, A-56) — with no requester recorded.
#[test]
fn unverified_ap_reqs_are_refused_uniformly() {
    let d = Domain::new("dc-unverified");
    let op = create_user(STAFF_OU, "carol");
    for (failure, stage, status) in [
        (
            VerificationFailure::Requester,
            DirAdminStage::Decision(DecisionResult::Refused(AdminRefusal::Unauthenticated)),
            RefusalStatus::Denied,
        ),
        (
            VerificationFailure::Approver,
            DirAdminStage::Decision(DecisionResult::Refused(
                AdminRefusal::ApproverUnauthenticated,
            )),
            RefusalStatus::Denied,
        ),
        (
            VerificationFailure::KeydUnavailable,
            DirAdminStage::Decision(DecisionResult::Failed(AdminFailure::KeydUnavailable)),
            RefusalStatus::Unavailable,
        ),
    ] {
        let r = d.admin.refuse_unverified(7, &op, failure, &now());
        assert_eq!(r.event().stage, stage);
        assert_eq!(r.status(), status);
        assert_eq!(r.event().operation_id, 7);
        assert_eq!(r.event().requester, None);
        assert_eq!(r.event().parent, Some(guid(STAFF_OU).to_packet()));
    }
}

/// Q-295 item 4 (P-22): with two enabled Tier-0 administrators and a quorum
/// of two, disabling one, removing one from the Tier-0 group, deleting one
/// or making one expire now is refused even with an approval — it would
/// leave fewer than the quorum.
#[test]
fn the_self_lockout_guard_refuses_dropping_below_the_quorum() {
    let mut d = Domain::new("lockout");
    let ops = [
        Operation::SetEnabled(SetEnabled {
            target: guid(ADMIN2),
            enabled: false,
        }),
        Operation::RemoveMember(Membership {
            group: guid(TIER0_GROUP),
            member: guid(ADMIN2),
        }),
        Operation::Delete {
            target: guid(ADMIN2),
        },
        Operation::SetAccountExpires(SetAccountExpires {
            target: guid(ADMIN2),
            value: AccountExpiresValue::at(u64::try_from(NOW_FILETIME).unwrap()),
        }),
    ];
    for op in ops {
        let r = d.run(op.clone(), "admin1", &["admin2"]).refused();
        assert_eq!(refusal_code(&r), AdminRefusal::SelfLockout, "{op:?}");
        assert_eq!(r.status(), RefusalStatus::Denied);
    }
    // An expiry in the future does not lock anyone out now.
    // 2027-01-01T00:00:00Z as FILETIME (derived in tests/operations.rs).
    let op = Operation::SetAccountExpires(SetAccountExpires {
        target: guid(ADMIN2),
        value: AccountExpiresValue::at(134_432_352_000_000_000),
    });
    d.run(op, "admin1", &["admin2"]).applied();
}

/// Q-295 item 4: with a third enabled administrator (alice joins the Tier-0
/// group, approved), disabling admin2 leaves two — the quorum — and is
/// applied; disabling a second one is then refused.
#[test]
fn the_guard_allows_what_keeps_the_quorum() {
    let mut d = Domain::new("lockout-three");
    d.run(
        Operation::AddMember(Membership {
            group: guid(TIER0_GROUP),
            member: guid(ALICE),
        }),
        "admin1",
        &["admin2"],
    )
    .applied();
    d.run(
        Operation::SetEnabled(SetEnabled {
            target: guid(ADMIN2),
            enabled: false,
        }),
        "admin1",
        &["alice"],
    )
    .applied();
    let r = d
        .run(
            Operation::SetEnabled(SetEnabled {
                target: guid(ALICE),
                enabled: false,
            }),
            "admin1",
            &["alice"],
        )
        .refused();
    assert_eq!(refusal_code(&r), AdminRefusal::SelfLockout);
}

/// Q-295 item 4 through nesting: an administrator who is Tier0 only through
/// a security group nested in the Tier-0 group counts; deleting that group
/// (the removal of its members from the Tier-0 group) is weighed too.
#[test]
fn the_guard_follows_nested_security_groups() {
    let mut d = Domain::new("lockout-nested");
    let (_, applied) = d
        .run(
            Operation::CreateGroup(directory_admin::CreateGroup {
                parent: guid(TIER0_OU),
                sam: "ops".into(),
                group_type: None,
            }),
            "admin1",
            &["admin2"],
        )
        .applied();
    let ops = match applied.reply() {
        directory_admin::Reply::Created { guid, .. } => *guid,
        other => panic!("{other:?}"),
    };
    d.run(
        Operation::AddMember(Membership {
            group: ops,
            member: guid(ALICE),
        }),
        "admin1",
        &["admin2"],
    )
    .applied();
    d.run(
        Operation::AddMember(Membership {
            group: guid(TIER0_GROUP),
            member: ops,
        }),
        "admin1",
        &["admin2"],
    )
    .applied();
    // Three administrators: disabling admin2 is fine.
    d.run(
        Operation::SetEnabled(SetEnabled {
            target: guid(ADMIN2),
            enabled: false,
        }),
        "admin1",
        &["alice"],
    )
    .applied();
    // Two left (admin1, alice via ops): deleting ops would leave one.
    let r = d
        .run(Operation::Delete { target: ops }, "admin1", &["alice"])
        .refused();
    assert_eq!(refusal_code(&r), AdminRefusal::SelfLockout);
}
