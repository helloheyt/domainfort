//! The closure-size refusal of `AddMember` (the A-89 residual of Q-356 item
//! 5, task F5; docs/questions/Q-416): a link that would make some closure
//! group expansion computes hold more than 1024 groups is refused at write
//! time, as `MembershipInvalid` (told as `Invalid`), instead of leaving the
//! account to fail closed at login.
//!
//! Sources: docs/47 §5.3 items 1, 3 (R47-8: the closure climbs through
//! security-enabled groups only; `MAX_EXPANDED_GROUPS = 1024`; exceeding it
//! is an error, never a partial set); crate directory-pip
//! `MAX_EXPANDED_GROUPS` ("most groups one expansion may return") and
//! `groups::expand`, against which the bound is checked here end to end;
//! crate directory-admin `MAX_WALK_STEPS` (16,384 references, Q-356 items
//! 4-5, Q-357 item 8). Fixtures: tests/common (alice and bob are each a
//! member of `readers` — one group — before every test); the large group
//! sets are this project's own test groups, written beneath the PEP in one
//! transaction.

mod common;

use common::*;
use directory_admin::{CreateGroup, Membership, Operation, RefusalStatus, Reply};
use directory_pip::TicketSubjects;
use ipc_audit::{AdminRefusal, DecisionResult, DirAdminStage};

/// groupType of a global security group and of a global distribution group
/// ([MS-ADTS] 2.2.12: GROUP_TYPE_ACCOUNT_GROUP 0x2, GROUP_TYPE_SECURITY_ENABLED
/// 0x80000000).
const GLOBAL_SECURITY: u32 = 0x8000_0002;
const GLOBAL_DISTRIBUTION: u32 = 0x0000_0002;

fn refusal_code(r: &directory_admin::Refusal) -> AdminRefusal {
    match r.event().stage {
        DirAdminStage::Decision(DecisionResult::Refused(code)) => code,
        other => panic!("not a decision refusal: {other:?}"),
    }
}

/// A security-enabled global group created through the admin plane.
fn new_group(d: &mut Domain, sam: &str) -> dtyp::Guid {
    let (_, applied) = d
        .run(
            Operation::CreateGroup(CreateGroup {
                parent: guid(STAFF_OU),
                sam: sam.into(),
                group_type: None,
            }),
            "admin1",
            &[],
        )
        .applied();
    match applied.reply() {
        Reply::Created { guid, .. } => *guid,
        other => panic!("{other:?}"),
    }
}

fn add(group: dtyp::Guid, member: dtyp::Guid) -> Operation {
    Operation::AddMember(Membership { group, member })
}

/// Whether directory-pip's ticket-subject lookup (its closure — the one
/// expansion the KDC's account records carry too, R47-8) resolves the
/// account — i.e. it can be a Subject (task PN10b: no account source, no
/// signer).
fn resolves(d: &Domain, sam: &str) -> bool {
    d.view()
        .ticket_subject(&realm(), &ticket(sam).cname)
        .is_ok()
}

/// The number of groups in the account's closure, as directory-pip computes
/// it.
fn closure_size(d: &Domain, sam: &str) -> usize {
    d.view()
        .ticket_subject(&realm(), &ticket(sam).cname)
        .unwrap()
        .unwrap()
        .groups
        .len()
}

/// One group written beneath the PEP: its number (GUID and RID), groupType
/// and members.
struct Planned {
    id: u32,
    group_type: u32,
    members: Vec<dtyp::Guid>,
}

fn planned(id: u32, group_type: u32, members: &[dtyp::Guid]) -> Planned {
    Planned {
        id,
        group_type,
        members: members.to_vec(),
    }
}

fn origin() -> dirstore::Origin {
    dirstore::Origin {
        wall_clock: directory_admin::wall_clock(&now()).unwrap(),
        origin_node: NODE_ID,
        origin_seq: 0,
    }
}

/// Writes `groups` under ou=Managed directly in the store, in order (a
/// member before the groups holding it), in one transaction.
fn write_groups(d: &Domain, groups: &[Planned]) {
    let group_class = d.p1.class_by_name("group").unwrap();
    let classes = d.p1.class(group_class).unwrap().object_class.clone();
    let sd = child_sd(&root_sd(), d.class_guid("group"))
        .encode()
        .unwrap();
    let mut txn = d.store.begin_write().unwrap();
    for g in groups {
        let name = format!("c{}", g.id);
        let mut attributes = vec![
            (d.attr("cn"), vec![name.as_bytes().to_vec()]),
            (d.attr("sAMAccountName"), vec![name.as_bytes().to_vec()]),
            (d.attr("objectSid"), vec![account_sid(g.id).encode()]),
            (d.attr("groupType"), vec![flags(g.group_type)]),
            (d.attr("nTSecurityDescriptor"), vec![sd.clone()]),
        ];
        if !g.members.is_empty() {
            attributes.push((
                d.attr("member"),
                g.members.iter().map(|m| m.to_packet().to_vec()).collect(),
            ));
        }
        txn.create_object(
            dirstore::NewObject {
                guid: guid(g.id),
                parent: Some(guid(MANAGED_OU)),
                classes: classes.clone(),
                attributes,
            },
            &origin(),
        )
        .unwrap();
    }
    txn.commit().unwrap();
}

/// Forces `member` into the empty `group` beneath the PEP (a write the
/// admin plane refused), to show directory-pip's expansion then fails.
fn force_member(d: &Domain, group: dtyp::Guid, member: dtyp::Guid) {
    let mut txn = d.store.begin_write().unwrap();
    txn.modify_object(
        group,
        vec![dirstore::AttributeChange::Replace {
            id: d.attr("member"),
            values: vec![member.to_packet().to_vec()],
        }],
        &origin(),
    )
    .unwrap();
    txn.commit().unwrap();
}

/// Adding a member under a large tree. `t` is held by 1022 security groups
/// and by three distribution groups (not counted — expansion does not enter
/// them); `t2` by the same groups and one more security group. alice
/// (already in `readers`) added to `t`: readers + t + 1022 = exactly 1024 —
/// allowed, and directory-pip still resolves her. bob (also in `readers`)
/// added to `t2`: readers + t2 + 1023 = 1025 — refused (`MembershipInvalid`,
/// told as `Invalid`), nothing written. A group added to `t2` reaches
/// exactly 1024 itself: allowed while nothing is below it, refused when an
/// account is (ws01$, in no group: it would hold 1025), and no account can
/// join it afterwards. Last, bob's refused link forced in beneath the PEP
/// makes directory-pip fail for bob, so the PEP's bound is exactly the
/// closure's.
#[test]
fn a_member_added_under_a_large_tree_is_refused_at_1025() {
    let mut d = Domain::new("closure-under-tree");
    let t = new_group(&mut d, "t");
    let t2 = new_group(&mut d, "t2");
    let mut groups: Vec<Planned> = (0..1022)
        .map(|i| planned(500_000 + i, GLOBAL_SECURITY, &[t, t2]))
        .collect();
    groups.push(planned(501_022, GLOBAL_SECURITY, &[t2]));
    for i in 0..3 {
        groups.push(planned(501_100 + i, GLOBAL_DISTRIBUTION, &[t, t2]));
    }
    write_groups(&d, &groups);

    // The link check allows exactly 1024; the write stops only at its
    // effect plan, which would name 1023 new groups — beyond the plan's
    // bounds (`PlanTooLarge`, task MA2; docs/questions/Q-981) — so the link
    // is written beneath the PEP.
    let r = d.run(add(t, guid(ALICE)), "admin1", &[]).refused();
    assert_eq!(refusal_code(&r), AdminRefusal::PlanTooLarge);
    force_member(&d, t, guid(ALICE));
    assert!(resolves(&d, "alice"));
    assert_eq!(closure_size(&d, "alice"), 1024);

    let r = d.run(add(t2, guid(BOB)), "admin1", &[]).refused();
    assert_eq!(refusal_code(&r), AdminRefusal::MembershipInvalid);
    assert_eq!(r.status(), RefusalStatus::Invalid);
    assert!(d.object(t2).unwrap().attribute(d.attr("member")).is_none());
    assert!(resolves(&d, "bob"));

    let empty = new_group(&mut d, "empty");
    let r = d.run(add(t2, empty), "admin1", &[]).refused();
    assert_eq!(refusal_code(&r), AdminRefusal::PlanTooLarge);
    force_member(&d, t2, empty);
    let r = d.run(add(empty, guid(WS01)), "admin1", &[]).refused();
    assert_eq!(refusal_code(&r), AdminRefusal::MembershipInvalid);
    let full = new_group(&mut d, "full");
    d.run(add(full, guid(WS01)), "admin1", &[]).applied();
    let r = d.run(add(t2, full), "admin1", &[]).refused();
    assert_eq!(refusal_code(&r), AdminRefusal::MembershipInvalid);

    force_member(&d, t2, guid(BOB));
    assert!(!resolves(&d, "bob"));
}

/// Adding a group above an account with a large closure. bob is in
/// `readers`, in 1021 further security groups and in `k`: 1023 groups.
/// `k` added to a new, empty group `h1`: bob's closure becomes exactly 1024
/// — allowed, and directory-pip resolves him. `k` added to another new group
/// `h2`: 1025 — refused, nothing written; forced in beneath the PEP,
/// directory-pip fails for bob.
#[test]
fn a_group_added_above_a_large_closure_is_refused_at_1025() {
    let mut d = Domain::new("closure-above-account");
    let groups: Vec<Planned> = (0..1021)
        .map(|i| planned(600_000 + i, GLOBAL_SECURITY, &[guid(BOB)]))
        .collect();
    write_groups(&d, &groups);
    let k = new_group(&mut d, "k");
    d.run(add(k, guid(BOB)), "admin1", &[]).applied();
    assert_eq!(closure_size(&d, "bob"), 1023);

    let h1 = new_group(&mut d, "h1");
    d.run(add(h1, k), "admin1", &[]).applied();
    assert!(resolves(&d, "bob"));
    assert_eq!(closure_size(&d, "bob"), 1024);

    let h2 = new_group(&mut d, "h2");
    let r = d.run(add(h2, k), "admin1", &[]).refused();
    assert_eq!(refusal_code(&r), AdminRefusal::MembershipInvalid);
    assert_eq!(r.status(), RefusalStatus::Invalid);
    assert!(d.object(h2).unwrap().attribute(d.attr("member")).is_none());
    assert!(resolves(&d, "bob"));
    force_member(&d, h2, k);
    assert!(!resolves(&d, "bob"));
}

/// Each account below the new link is measured on its own, not the sum of
/// all of them: `w` holds alice and bob; alice is in 600 security groups of
/// her own, bob in 600 others. Adding `w` to a new group `h` gives each of
/// them readers + 600 + w + h = 603 groups (allowed), although the groups
/// above both together number 1203.
#[test]
fn accounts_below_the_link_are_measured_one_by_one() {
    let mut d = Domain::new("closure-per-account");
    let mut groups: Vec<Planned> = (0..600)
        .map(|i| planned(700_000 + i, GLOBAL_SECURITY, &[guid(ALICE)]))
        .collect();
    groups.extend((0..600).map(|i| planned(701_000 + i, GLOBAL_SECURITY, &[guid(BOB)])));
    write_groups(&d, &groups);
    let w = new_group(&mut d, "w");
    d.run(add(w, guid(ALICE)), "admin1", &[]).applied();
    d.run(add(w, guid(BOB)), "admin1", &[]).applied();
    let h = new_group(&mut d, "h");
    d.run(add(h, w), "admin1", &[]).applied();
    assert_eq!(closure_size(&d, "alice"), 603);
    assert_eq!(closure_size(&d, "bob"), 603);
}

/// The closure walk is bounded (16,384 references followed, the bound of
/// the other membership walks) and fails closed. Under ou=Managed: 130 empty
/// security groups `c`, each held by the same 130 security groups, by a
/// holder `a` (all 130) and by a holder `b` (the first 120). Every closure
/// stays small (at most 133 groups after either link) and every chain
/// short, but measuring the starts below `a` follows 120 · 132 + 10 · 131 =
/// 17,150 memberOf references (each `c` names `a`, perhaps `b`, and the 130)
/// — adding `a` to a new group is refused. Below `b` it is 120 · 132 =
/// 15,840 references: adding `b` to a new group is allowed.
#[test]
fn a_closure_walk_over_its_bound_is_refused() {
    let mut d = Domain::new("closure-bound");
    let first = 800_000;
    let starts: Vec<dtyp::Guid> = (0..130).map(|i| guid(first + i)).collect();
    let mut groups: Vec<Planned> = (0..130)
        .map(|i| planned(first + i, GLOBAL_SECURITY, &[]))
        .collect();
    groups.extend((0..130).map(|i| planned(first + 200 + i, GLOBAL_SECURITY, &starts)));
    groups.push(planned(first + 400, GLOBAL_SECURITY, &starts));
    groups.push(planned(first + 401, GLOBAL_SECURITY, &starts[..120]));
    write_groups(&d, &groups);
    let (a, b) = (guid(first + 400), guid(first + 401));

    let h = new_group(&mut d, "h");
    let r = d.run(add(h, a), "admin1", &[]).refused();
    assert_eq!(refusal_code(&r), AdminRefusal::MembershipInvalid);
    assert_eq!(r.status(), RefusalStatus::Invalid);
    let h2 = new_group(&mut d, "h2");
    d.run(add(h2, b), "admin1", &[]).applied();
}
