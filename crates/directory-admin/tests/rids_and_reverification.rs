//! RID allocation (contiguous, never reused, nothing consumed by an aborted
//! transaction, exhaustion refused) and what `apply` re-verifies.
//!
//! Sources: docs/51 §8.3 (R51-16; decided A-75 / Q-293: the dirstore counter,
//! range `[1101, 0x3FFFFFFF)`, taken in the same `WriteTxn` as the create;
//! exhaustion ⇒ refusal); A-83 / Q-330 (caller rules: counters created only
//! by provisioning; abort when the create is refused); [MS-SAMR] v20260427
//! 3.1.1.9.2 ("unique for all time and space"), 3.1.1.9.2.1 item 1.2 (a
//! committed value "MUST NOT ever be used again"); docs/51 §7.4 step 5 (the
//! write after the acknowledged decision). Fixtures: tests/common.

mod common;

use common::*;
use directory_admin::{
    CreateContainerLike, CreateUser, Operation, RefusalStatus, Reply, SetEnabled,
};
use ipc_audit::{AdminRefusal, DecisionResult, DirAdminStage, OutcomeResult};

fn create_user(sam: &str) -> Operation {
    Operation::CreateUser(CreateUser {
        parent: guid(STAFF_OU),
        sam: sam.to_owned(),
        upn: None,
        description: None,
    })
}

fn rid_of(reply: &Reply) -> u32 {
    match reply {
        Reply::Created { sid: Some(sid), .. } => *sid.sub_authority().last().unwrap(),
        other => panic!("{other:?}"),
    }
}

/// A-75: consecutive creates take consecutive RIDs from the counter,
/// starting after the ones provisioning took; the outcome event records
/// each allocation (A-85).
#[test]
fn rids_are_contiguous() {
    let mut d = Domain::new("rid-contiguous");
    for (i, sam) in ["u1", "u2", "u3"].iter().enumerate() {
        let (_, applied) = d.run(create_user(sam), "admin1", &[]).applied();
        let expected = FIRST_ADMIN_RID + u32::try_from(i).unwrap();
        assert_eq!(rid_of(applied.reply()), expected);
        match applied.outcome_event().stage {
            DirAdminStage::Outcome(OutcomeResult::Committed {
                allocated: Some(allocation),
            }) => assert_eq!(allocation.rid, Some(expected)),
            other => panic!("{other:?}"),
        }
    }
}

/// [MS-SAMR] 3.1.1.9.2.1 item 1.2: the RID of a deleted principal is never
/// handed out again (A-18: a tombstone keeps no objectSid, so only the
/// counter guards this).
#[test]
fn rids_are_not_reused_after_a_delete() {
    let mut d = Domain::new("rid-delete");
    let (_, applied) = d.run(create_user("u1"), "admin1", &[]).applied();
    let first = rid_of(applied.reply());
    let Reply::Created { guid: g, .. } = applied.reply() else {
        panic!();
    };
    d.run(Operation::Delete { target: *g }, "admin1", &[])
        .applied();
    let (_, applied) = d.run(create_user("u1"), "admin1", &[]).applied();
    assert_eq!(rid_of(applied.reply()), first + 1);
}

/// A-83 / Q-330 item 5: an aborted transaction consumes nothing — the RID
/// and the change-seq a refused or abandoned write took return with the
/// rollback, and the next create gets the same RID.
#[test]
fn an_aborted_transaction_consumes_nothing() {
    let mut d = Domain::new("rid-abort");
    let rid_before = d.counter_next(directory_admin::RID_COUNTER);
    let seq_before = d.counter_next(directory_admin::CHANGE_SEQ_COUNTER);
    let request = d.request(create_user("u1"), "admin1", &[]);
    {
        let mut txn = d.store.begin_write().unwrap();
        let view = d.ctx.view(&d.store, &d.tiers).unwrap();
        let prepared = d.admin.prepare(&request, &view, &d.policy, &now()).unwrap();
        drop(view);
        let applied = d.admin.apply(prepared, &mut txn, &now()).unwrap();
        assert_eq!(rid_of(applied.reply()), FIRST_ADMIN_RID);
        txn.abort().unwrap();
    }
    assert_eq!(d.counter_next(directory_admin::RID_COUNTER), rid_before);
    assert_eq!(
        d.counter_next(directory_admin::CHANGE_SEQ_COUNTER),
        seq_before
    );
    assert!(d.object(drawn_guid(1)).is_none());
    let (_, applied) = d.run(create_user("u1"), "admin1", &[]).applied();
    assert_eq!(rid_of(applied.reply()), FIRST_ADMIN_RID);
}

/// docs/51 §8.3 ("exhaustion ⇒ refusal (fail closed)"): with the RID range
/// used up, a principal create is refused before anything is written
/// (`RidExhausted`, told as `Unavailable`), while an OU — no RID — is still
/// created.
#[test]
fn an_exhausted_rid_range_refuses_principals_only() {
    let mut d = Domain::with_rid_end("rid-exhausted", FIRST_ADMIN_RID);
    let r = d.run(create_user("u1"), "admin1", &[]).refused();
    assert_eq!(
        r.event().stage,
        DirAdminStage::Decision(DecisionResult::Refused(AdminRefusal::RidExhausted))
    );
    assert_eq!(r.status(), RefusalStatus::Unavailable);
    let ou = Operation::CreateOu(CreateContainerLike {
        parent: guid(STAFF_OU),
        name: "Lab".into(),
    });
    d.run(ou, "admin1", &[]).applied();
}

/// docs/51 §7.4 step 5 and the `apply` contract: if a write committed
/// between `prepare`'s snapshot and the transaction (the caller took the
/// view first), the change-seq counter moved and `apply` refuses with an
/// `Outcome` `Conflict` — nothing is written.
#[test]
fn apply_refuses_a_write_prepared_against_a_stale_view() {
    let mut d = Domain::new("stale");
    let stale = d.request(create_user("u1"), "admin1", &[]);
    let prepared = {
        let view = d.ctx.view(&d.store, &d.tiers).unwrap();
        d.admin.prepare(&stale, &view, &d.policy, &now()).unwrap()
    };
    // Another write commits in between.
    d.run(
        Operation::SetEnabled(SetEnabled {
            target: guid(BOB),
            enabled: false,
        }),
        "admin1",
        &[],
    )
    .applied();
    let mut txn = d.store.begin_write().unwrap();
    let r = d.admin.apply(prepared, &mut txn, &now()).unwrap_err();
    txn.abort().unwrap();
    assert_eq!(
        r.event().stage,
        DirAdminStage::Outcome(OutcomeResult::Refused(AdminRefusal::Conflict))
    );
    assert_eq!(r.status(), RefusalStatus::Conflict);
    assert_eq!(r.event().operation_id, stale.operation_id);
    assert!(d.object(drawn_guid(1)).is_none());
}

/// The second guard of `apply` (whole-record comparison) does not depend on
/// the change-seq convention: a write that bypasses the counter (here a
/// direct dirstore modify of the target with a hand-made origin, as no
/// admin-plane writer would do) is still caught.
#[test]
fn apply_compares_the_records_it_depends_on() {
    let mut d = Domain::new("stale-record");
    let request = d.request(
        Operation::SetEnabled(SetEnabled {
            target: guid(BOB),
            enabled: false,
        }),
        "admin1",
        &[],
    );
    let mut txn = d.store.begin_write().unwrap();
    let prepared = {
        let view = d.ctx.view(&d.store, &d.tiers).unwrap();
        d.admin.prepare(&request, &view, &d.policy, &now()).unwrap()
    };
    // Change bob inside the same transaction without taking a change-seq.
    txn.modify_object(
        guid(BOB),
        vec![dirstore::AttributeChange::Replace {
            id: d.attr("description"),
            values: vec![b"changed".to_vec()],
        }],
        &dirstore::Origin {
            wall_clock: directory_admin::wall_clock(&now()).unwrap(),
            origin_node: NODE_ID,
            origin_seq: 0,
        },
    )
    .unwrap();
    let r = d.admin.apply(prepared, &mut txn, &now()).unwrap_err();
    txn.abort().unwrap();
    assert_eq!(
        r.event().stage,
        DirAdminStage::Outcome(OutcomeResult::Refused(AdminRefusal::Conflict))
    );
}

/// A prepared operation that commits nothing has nothing to apply: `apply`
/// refuses it (a caller error), with an outcome failure event.
#[test]
fn a_read_only_operation_has_nothing_to_apply() {
    let mut d = Domain::new("apply-read");
    let request = d.request(
        Operation::Lookup(directory_admin::LookupKey::SamAccountName("alice".into())),
        "admin1",
        &[],
    );
    let prepared = {
        let view = d.ctx.view(&d.store, &d.tiers).unwrap();
        d.admin.prepare(&request, &view, &d.policy, &now()).unwrap()
    };
    assert!(!prepared.writes());
    let mut txn = d.store.begin_write().unwrap();
    let r = d.admin.apply(prepared, &mut txn, &now()).unwrap_err();
    txn.abort().unwrap();
    assert!(matches!(
        r.event().stage,
        DirAdminStage::Outcome(OutcomeResult::Failed(_))
    ));
}
