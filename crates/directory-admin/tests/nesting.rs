//! The nesting-depth refusal of `AddMember` (Q-356 item 5, decided by the
//! main session in the A3 review: refuse at write time).
//!
//! Sources: docs/47 §5.3 items 1, 3 (R47-8: the closure climbs through
//! security-enabled groups only; `MAX_NESTING_DEPTH = 16`; exceeding it is an
//! error, never a partial set); crate directory-pip `MAX_NESTING_DEPTH`
//! ("most levels of group nesting on any path from the start: a direct
//! membership is level 1") and `groups::expand`, against which the bound is
//! checked here end to end; docs/51 §11 (membership rules refused at the
//! write). Fixtures: tests/common; chains of this project's own test groups.

mod common;

use common::*;
use directory_admin::{CreateGroup, Membership, Operation, RefusalStatus, Reply};
use ipc_audit::{AdminRefusal, DecisionResult, DirAdminStage};
use kdc::AccountSource;

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

/// Whether the account source (directory-pip's closure) still resolves the
/// account — i.e. it can still log in.
fn resolves(d: &Domain, sam: &str) -> bool {
    d.view().client(&realm(), &ticket(sam).cname).is_ok()
}

/// alice ∈ g1 ∈ g2 ∈ … ∈ g`n`, built link by link through the admin plane:
/// alice's chain is `n` levels.
fn chain_above_alice(d: &mut Domain, n: usize) -> Vec<dtyp::Guid> {
    let groups: Vec<dtyp::Guid> = (1..=n).map(|i| new_group(d, &format!("g{i}"))).collect();
    d.run(add(groups[0], guid(ALICE)), "admin1", &[]).applied();
    for pair in groups.windows(2) {
        d.run(add(pair[1], pair[0]), "admin1", &[]).applied();
    }
    groups
}

/// A chain of exactly 16 levels (the bound) is allowed, and directory-pip's
/// closure still resolves the account at the bottom of it.
#[test]
fn a_chain_of_sixteen_levels_is_allowed() {
    let mut d = Domain::new("nest-16");
    let groups = chain_above_alice(&mut d, 16);
    let alice = d
        .view()
        .client(&realm(), &ticket("alice").cname)
        .unwrap()
        .unwrap();
    let top = account_sid(FIRST_ADMIN_RID + 15);
    assert!(alice.groups.contains(&top));
    assert_eq!(groups.len(), 16);
}

/// Adding a 17th level on top of a 16-level chain is refused
/// (`MembershipInvalid`, told as `Invalid`), and nothing is written. The
/// same link written directly into the store (bypassing the PEP) makes
/// directory-pip's closure fail for alice — the PEP's bound is exactly the
/// closure's.
#[test]
fn a_seventeenth_level_on_top_is_refused() {
    let mut d = Domain::new("nest-17-top");
    let groups = chain_above_alice(&mut d, 16);
    let g17 = new_group(&mut d, "g17");
    let r = d.run(add(g17, groups[15]), "admin1", &[]).refused();
    assert_eq!(refusal_code(&r), AdminRefusal::MembershipInvalid);
    assert_eq!(r.status(), RefusalStatus::Invalid);
    assert!(d.object(g17).unwrap().attribute(d.attr("member")).is_none());
    assert!(resolves(&d, "alice"));
    // The refused link, forced in beneath the PEP: alice can no longer be
    // resolved (directory-pip `MAX_NESTING_DEPTH`).
    {
        let mut txn = d.store.begin_write().unwrap();
        txn.modify_object(
            g17,
            vec![dirstore::AttributeChange::Replace {
                id: d.attr("member"),
                values: vec![groups[15].to_packet().to_vec()],
            }],
            &dirstore::Origin {
                wall_clock: directory_admin::wall_clock(&now()).unwrap(),
                origin_node: NODE_ID,
                origin_seq: 0,
            },
        )
        .unwrap();
        txn.commit().unwrap();
    }
    assert!(!resolves(&d, "alice"));
}

/// Adding at the bottom: h1 ∈ h2 ∈ … ∈ h17 is a 16-level chain from h1
/// (allowed); putting bob into h1 would make bob's chain 17 levels —
/// refused; putting bob into h2 makes it 16 — allowed.
#[test]
fn a_seventeenth_level_at_the_bottom_is_refused() {
    let mut d = Domain::new("nest-17-bottom");
    let groups: Vec<dtyp::Guid> = (1..=17)
        .map(|i| new_group(&mut d, &format!("h{i}")))
        .collect();
    for pair in groups.windows(2) {
        d.run(add(pair[1], pair[0]), "admin1", &[]).applied();
    }
    let r = d.run(add(groups[0], guid(BOB)), "admin1", &[]).refused();
    assert_eq!(refusal_code(&r), AdminRefusal::MembershipInvalid);
    d.run(add(groups[1], guid(BOB)), "admin1", &[]).applied();
    assert!(resolves(&d, "bob"));
}

/// Writes `layers` layers of `width` security groups above `g`, under
/// ou=Managed, directly in the store: every group of layer 1 holds `g`, and
/// every group of layer k > 1 holds every group of layer k − 1. `g` sits
/// `layers` levels below the top layer, and climbing above it follows
/// `width + (layers − 1) · width²` memberOf references.
fn layers_above(d: &Domain, g: dtyp::Guid, width: u32, layers: u32, first: u32) {
    let group_class = d.p1.class_by_name("group").unwrap();
    let sd = child_sd(&root_sd(), d.class_guid("group"))
        .encode()
        .unwrap();
    let mut txn = d.store.begin_write().unwrap();
    let origin = || dirstore::Origin {
        wall_clock: directory_admin::wall_clock(&now()).unwrap(),
        origin_node: NODE_ID,
        origin_seq: 0,
    };
    let mut lower = vec![g.to_packet().to_vec()];
    for layer in 0..layers {
        let mut this = Vec::new();
        for i in 0..width {
            let id = first + layer * width + i;
            let name = format!("l{id}");
            txn.create_object(
                dirstore::NewObject {
                    guid: guid(id),
                    parent: Some(guid(MANAGED_OU)),
                    classes: d.p1.class(group_class).unwrap().object_class.clone(),
                    attributes: vec![
                        (d.attr("cn"), vec![name.as_bytes().to_vec()]),
                        (d.attr("sAMAccountName"), vec![name.as_bytes().to_vec()]),
                        (d.attr("objectSid"), vec![account_sid(id).encode()]),
                        (d.attr("groupType"), vec![flags(0x8000_0002)]),
                        (d.attr("member"), lower.clone()),
                        (d.attr("nTSecurityDescriptor"), vec![sd.clone()]),
                    ],
                },
                &origin(),
            )
            .unwrap();
            this.push(ref_to(id));
        }
        lower = this;
    }
    txn.commit().unwrap();
}

/// The walk is bounded (16,384 references followed, the same bound as the
/// lockout count). 15 layers of 35 groups above a group are within the
/// depth (alice → group → 15 layers = 16 levels) but take 35 + 14 · 35² =
/// 17,185 references to climb: adding a member is refused (fail closed).
/// 15 layers of 30 groups (30 + 14 · 30² = 12,630 references) pass the
/// walk — a chain of exactly 16 levels again: the link check allows it, and
/// the write stops only at its effect plan, which would name bob's 451 new
/// groups — beyond the plan's bounds, so not performed (`PlanTooLarge`, task
/// MA2; docs/questions/Q-981: an effect that cannot be shown is not
/// performed). Written beneath the PEP, directory-pip resolves the member.
#[test]
fn a_depth_walk_over_its_bound_is_refused() {
    let mut d = Domain::new("nest-bound");
    let wide = new_group(&mut d, "wide");
    layers_above(&d, wide, 35, 15, 300_000);
    let r = d.run(add(wide, guid(ALICE)), "admin1", &[]).refused();
    assert_eq!(refusal_code(&r), AdminRefusal::MembershipInvalid);
    assert_eq!(r.status(), RefusalStatus::Invalid);
    let narrower = new_group(&mut d, "narrower");
    layers_above(&d, narrower, 30, 15, 400_000);
    let r = d.run(add(narrower, guid(BOB)), "admin1", &[]).refused();
    assert_eq!(refusal_code(&r), AdminRefusal::PlanTooLarge);
    force_member(&d, narrower, guid(BOB));
    assert!(resolves(&d, "bob"));
}

/// `member` into the empty `group`, beneath the PEP (task MA2: a link the
/// write path allows but cannot plan within the plan's bounds).
fn force_member(d: &Domain, group: dtyp::Guid, member: dtyp::Guid) {
    let mut txn = d.store.begin_write().unwrap();
    txn.modify_object(
        group,
        vec![dirstore::AttributeChange::Replace {
            id: d.attr("member"),
            values: vec![member.to_packet().to_vec()],
        }],
        &dirstore::Origin {
            wall_clock: directory_admin::wall_clock(&now()).unwrap(),
            origin_node: NODE_ID,
            origin_seq: 0,
        },
    )
    .unwrap();
    txn.commit().unwrap();
}
