//! Every operation of the closed set, table-driven: allowed (a Tier-1
//! subject inside its Tier-1 subtree), denied by the PDP (a reader), and
//! denied for tier (the Tier-1 subject on an unclassified — hence Tier0 for
//! writes — object); plus the member limit and missing counters.
//!
//! Sources: docs/51 §5.2 (each operation's Action and Resource; every write
//! Action passes the tier layer), §7.3, §7.4 step 3, §11 row "≤ 4096
//! members" (docs/46 §2.3 item 5); docs/11 §4 layers 3-4 (NoGrant,
//! TierViolation; P5); A-36 (unclassified ⇒ Tier0 for writes); A-83 (a
//! missing counter ⇒ refusal, never re-created). Fixtures: tests/common
//! (helper is Tier1 through the helpdesk group; ou=Managed is a Tier1
//! subtree; bob may only read).

mod common;

use common::*;
use directory_admin::{
    CompletePasswordSet, CreateComputer, CreateContainerLike, CreateGroup, CreateUser, LookupKey,
    Membership, Operation, PasswordSetOutcome, RefusalStatus, Reply, SetAccountExpires, SetEnabled,
};
use ipc_audit::{
    AccountExpiresValue, AdminFailure, AdminRefusal, DecisionResult, DirAdminStage, PdpReasonCode,
};

fn decision_refusal(r: &directory_admin::Refusal) -> AdminRefusal {
    match r.event().stage {
        DirAdminStage::Decision(DecisionResult::Refused(code)) => code,
        other => panic!("not a decision refusal: {other:?}"),
    }
}

/// Every write operation on `parent` (creates) or on the `user`, `group`
/// and `member` objects (the rest).
fn every_write(
    parent: dtyp::Guid,
    user: dtyp::Guid,
    group: dtyp::Guid,
    member: dtyp::Guid,
) -> Vec<Operation> {
    vec![
        Operation::CreateUser(CreateUser {
            parent,
            sam: "newuser".into(),
            upn: None,
            description: None,
        }),
        Operation::CreateComputer(CreateComputer {
            parent,
            name: "newpc".into(),
            spn: None,
        }),
        Operation::CreateGroup(CreateGroup {
            parent,
            sam: "newgroup".into(),
            group_type: None,
        }),
        Operation::CreateOu(CreateContainerLike {
            parent,
            name: "NewOu".into(),
        }),
        Operation::CreateContainer(CreateContainerLike {
            parent,
            name: "NewContainer".into(),
        }),
        Operation::BeginPasswordSet { target: user },
        Operation::CompletePasswordSet(CompletePasswordSet {
            target: user,
            outcome: PasswordSetOutcome::Completed,
            kvnos: vec![1],
        }),
        Operation::SetEnabled(SetEnabled {
            target: user,
            enabled: false,
        }),
        Operation::SetAccountExpires(SetAccountExpires {
            target: user,
            value: AccountExpiresValue::NEVER,
        }),
        Operation::AddMember(Membership {
            group,
            member: user,
        }),
        Operation::RemoveMember(Membership { group, member }),
        Operation::Delete { target: user },
    ]
}

/// docs/11 §4 layer 3: bob holds only read rules — every write is refused
/// with `PolicyDenied` / NoGrant, uniformly `Denied` to him.
#[test]
fn every_write_is_denied_by_the_pdp_without_a_grant() {
    let mut d = Domain::new("every-pdp");
    for op in every_write(guid(STAFF_OU), guid(ALICE), guid(READERS), guid(BOB)) {
        let r = d.run(op.clone(), "bob", &[]).refused();
        assert_eq!(decision_refusal(&r), AdminRefusal::PolicyDenied, "{op:?}");
        assert_eq!(
            r.event().pdp.unwrap().code,
            PdpReasonCode::NoGrant,
            "{op:?}"
        );
        assert_eq!(r.status(), RefusalStatus::Denied, "{op:?}");
    }
}

/// docs/11 §4 layer 4 (P5) and A-36: helper (Tier1, with a write rule on
/// the whole domain) is refused every write on ou=Staff's unclassified
/// objects — they are Tier0 for writes — with `TierViolation`.
#[test]
fn every_write_is_denied_for_tier_above_the_subject() {
    let mut d = Domain::new("every-tier");
    for op in every_write(guid(STAFF_OU), guid(ALICE), guid(READERS), guid(BOB)) {
        let r = d.run(op.clone(), "helper", &[]).refused();
        assert_eq!(decision_refusal(&r), AdminRefusal::PolicyDenied, "{op:?}");
        assert_eq!(
            r.event().pdp.unwrap().code,
            PdpReasonCode::TierViolation,
            "{op:?}"
        );
    }
}

/// The same operations by the same Tier-1 subject inside its Tier-1
/// subtree (ou=Managed) are allowed: a user and a group are created there,
/// then every other operation is applied to them.
#[test]
fn every_operation_is_allowed_inside_the_subjects_tier() {
    let mut d = Domain::new("every-allowed");
    let new = |reply: &Reply| match reply {
        Reply::Created { guid, .. } => *guid,
        other => panic!("{other:?}"),
    };
    let ops = every_write(guid(MANAGED_OU), guid(0), guid(0), guid(0));
    let mut created = Vec::new();
    for op in ops.iter().take(5) {
        let (_, applied) = d.run(op.clone(), "helper", &[]).applied();
        created.push(new(applied.reply()));
    }
    let (user, computer, group) = (created[0], created[1], created[2]);
    // Membership first (AddMember, then RemoveMember of the computer).
    d.run(
        Operation::AddMember(Membership {
            group,
            member: computer,
        }),
        "helper",
        &[],
    )
    .applied();
    for op in every_write(guid(MANAGED_OU), user, group, computer)
        .into_iter()
        .skip(5)
    {
        match d.run(op.clone(), "helper", &[]) {
            Ran::Applied { .. } | Ran::Read(_) => {}
            other => panic!("{op:?}: {other:?}"),
        }
    }
    assert!(d.object(user).is_none(), "deleted last");
    // Lookup: the Tier-1 subject reads the group it made.
    let prepared = d
        .run(
            Operation::Lookup(LookupKey::SamAccountName("newgroup".into())),
            "helper",
            &[],
        )
        .read();
    assert!(matches!(prepared.reply(), Some(Reply::Found(_))));
}

/// docs/46 §2.3 item 5 / docs/51 §11: a group holds at most 4096 members
/// (dirstore `MAX_VALUES_PER_ATTRIBUTE`); adding the 4097th is refused
/// before anything is written.
#[test]
fn a_group_holds_at_most_4096_members() {
    let mut d = Domain::new("member-limit");
    let user_class = d.p1.class_by_name("user").unwrap();
    let group_class = d.p1.class_by_name("group").unwrap();
    let sd = child_sd(&root_sd(), d.class_guid("user")).encode().unwrap();
    let big = guid(100_000);
    {
        let mut txn = d.store.begin_write().unwrap();
        let origin = || dirstore::Origin {
            wall_clock: directory_admin::wall_clock(&now()).unwrap(),
            origin_node: NODE_ID,
            origin_seq: 0,
        };
        let mut members = Vec::new();
        for i in 0..4096u32 {
            let id = 200_000 + i;
            let name = format!("m{i}");
            txn.create_object(
                dirstore::NewObject {
                    guid: guid(id),
                    parent: Some(guid(MANAGED_OU)),
                    classes: d.p1.class(user_class).unwrap().object_class.clone(),
                    attributes: vec![
                        (d.attr("cn"), vec![name.as_bytes().to_vec()]),
                        (d.attr("sAMAccountName"), vec![name.as_bytes().to_vec()]),
                        (d.attr("objectSid"), vec![account_sid(50_000 + i).encode()]),
                        (d.attr("nTSecurityDescriptor"), vec![sd.clone()]),
                    ],
                },
                &origin(),
            )
            .unwrap();
            members.push(ref_to(id));
        }
        txn.create_object(
            dirstore::NewObject {
                guid: big,
                parent: Some(guid(MANAGED_OU)),
                classes: d.p1.class(group_class).unwrap().object_class.clone(),
                attributes: vec![
                    (d.attr("cn"), vec![b"big".to_vec()]),
                    (d.attr("sAMAccountName"), vec![b"big".to_vec()]),
                    (d.attr("objectSid"), vec![account_sid(49_999).encode()]),
                    (d.attr("groupType"), vec![flags(0x8000_0002)]),
                    (d.attr("member"), members),
                    (d.attr("nTSecurityDescriptor"), vec![sd.clone()]),
                ],
            },
            &origin(),
        )
        .unwrap();
        txn.commit().unwrap();
    }
    let r = d
        .run(
            Operation::AddMember(Membership {
                group: big,
                member: guid(ALICE),
            }),
            "admin1",
            &[],
        )
        .refused();
    assert_eq!(decision_refusal(&r), AdminRefusal::MembershipInvalid);
}

/// A-83: without the counters `provision domain` creates, every write is
/// refused before anything is written (`Failed(StoreFailure)`), and the
/// counters are not created; a `Lookup` still works.
#[test]
fn missing_counters_refuse_writes() {
    let mut d = Domain::without_counters("no-counters");
    for op in [
        Operation::CreateUser(CreateUser {
            parent: guid(STAFF_OU),
            sam: "carol".into(),
            upn: None,
            description: None,
        }),
        Operation::CreateOu(CreateContainerLike {
            parent: guid(STAFF_OU),
            name: "Lab".into(),
        }),
        Operation::SetEnabled(SetEnabled {
            target: guid(BOB),
            enabled: false,
        }),
    ] {
        let r = d.run(op.clone(), "admin1", &[]).refused();
        assert_eq!(
            r.event().stage,
            DirAdminStage::Decision(DecisionResult::Failed(AdminFailure::StoreFailure)),
            "{op:?}"
        );
        assert_eq!(r.status(), RefusalStatus::Unavailable);
    }
    assert!(d
        .store
        .snapshot()
        .unwrap()
        .counter(directory_admin::RID_COUNTER)
        .unwrap()
        .is_none());
    d.run(
        Operation::Lookup(LookupKey::SamAccountName("bob".into())),
        "admin1",
        &[],
    )
    .read();
}
