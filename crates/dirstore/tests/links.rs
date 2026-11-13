//! Forward links, the reverse-link index and referential integrity.
//!
//! Source: docs/46 §2.3 (DN-valued attributes stored as the target GUID;
//! target must be live; back links derived from a reverse index maintained in
//! the same transaction; on delete every forward reference to the deleted
//! object is removed in the same transaction), §8.4 (the reverse-link table,
//! its maintenance, the back-link query); docs/32 §7 (D136: one atomic
//! transaction); [MS-ADTS] v20261026 §3.1.1.1.6 (a reference to a missing or
//! tombstoned object fails with noSuchObject; "When an object o is expunged
//! or transformed into a tombstone ..., any forward link reference to o is
//! removed"; a forward link may exist without a back link). Test data is
//! hand-made (tests/common).

mod common;

use common::*;
use dirstore::{AttrId, AttributeChange, Error, Store, Timestamp, Violation};

fn members(store: &Store, group: u32) -> Vec<Vec<u8>> {
    store
        .snapshot()
        .unwrap()
        .get_object(guid(group))
        .unwrap()
        .unwrap()
        .attribute(ATTR_MEMBER)
        .map(|a| a.values.iter().map(|v| v.value.clone()).collect())
        .unwrap_or_default()
}

fn member_of(store: &Store, target: u32) -> Vec<dtyp::Guid> {
    store
        .snapshot()
        .unwrap()
        .back_links(guid(target), ATTR_MEMBER_OF)
        .unwrap()
}

fn set_members(store: &Store, group: u32, refs: Vec<Vec<u8>>, seq: u64) {
    let mut txn = store.begin_write().unwrap();
    txn.modify_object(
        guid(group),
        vec![AttributeChange::Replace {
            id: ATTR_MEMBER,
            values: refs,
        }],
        &origin(NODE_1, 100 + seq, seq),
    )
    .unwrap();
    txn.commit().unwrap();
}

/// root(1); alice(2), bob(3); group g1(4) = {alice, bob}; g2(5) = {alice}.
fn groups(test: &str) -> (TempDir, Store) {
    let dir = TempDir::new(test);
    let store = open_store(&dir);
    create_all(
        &store,
        vec![
            root(1, "root"),
            principal(2, guid(1), "alice"),
            principal(3, guid(1), "bob"),
            principal_with(
                4,
                guid(1),
                "g1",
                vec![(ATTR_MEMBER, vec![ref_to(2), ref_to(3)])],
            ),
            principal_with(5, guid(1), "g2", vec![(ATTR_MEMBER, vec![ref_to(2)])]),
        ],
    );
    (dir, store)
}

#[test]
fn back_links_follow_forward_values() {
    // Source: docs/46 §8.4 — the reverse index is maintained in the same
    // transaction as every forward add / remove; the back link (e.g.
    // memberOf) is answered from it.
    let (_dir, store) = groups("links-maintain");
    assert_eq!(member_of(&store, 2), vec![guid(4), guid(5)]);
    assert_eq!(member_of(&store, 3), vec![guid(4)]);
    assert_eq!(member_of(&store, 4), vec![]);

    let old = store.snapshot().unwrap();
    // Remove alice from g1.
    set_members(&store, 4, vec![ref_to(3)], 10);
    assert_eq!(member_of(&store, 2), vec![guid(5)]);
    assert_eq!(member_of(&store, 3), vec![guid(4)]);
    // Swap: add alice back, drop bob — one modify.
    set_members(&store, 4, vec![ref_to(2)], 11);
    assert_eq!(member_of(&store, 2), vec![guid(4), guid(5)]);
    assert_eq!(member_of(&store, 3), vec![]);
    // Empty g2.
    set_members(&store, 5, vec![], 12);
    assert_eq!(member_of(&store, 2), vec![guid(4)]);
    // A snapshot taken earlier still sees the earlier index, whole (D39).
    assert_eq!(
        old.back_links(guid(2), ATTR_MEMBER_OF).unwrap(),
        vec![guid(4), guid(5)]
    );
    assert_eq!(
        old.back_links(guid(3), ATTR_MEMBER_OF).unwrap(),
        vec![guid(4)]
    );

    // A write transaction sees its own index changes; dropping it undoes
    // them (D136).
    {
        let mut txn = store.begin_write().unwrap();
        txn.modify_object(
            guid(5),
            vec![AttributeChange::Replace {
                id: ATTR_MEMBER,
                values: vec![ref_to(3)],
            }],
            &origin(NODE_1, 200, 20),
        )
        .unwrap();
        assert_eq!(
            txn.back_links(guid(3), ATTR_MEMBER_OF).unwrap(),
            vec![guid(5)]
        );
    }
    assert_eq!(member_of(&store, 3), vec![]);
}

#[test]
fn back_link_query_arguments() {
    // Source: docs/46 §8.4 (the query names a back link); [MS-ADTS]
    // 3.1.1.1.6 (a back link is defined only through its forward link).
    let (_dir, store) = groups("links-query-args");
    let snap = store.snapshot().unwrap();
    assert!(matches!(
        snap.back_links(guid(2), ATTR_MEMBER),
        Err(Error::Rejected(Violation::NotBackLink(ATTR_MEMBER)))
    ));
    assert!(matches!(
        snap.back_links(guid(2), AttrId(999)),
        Err(Error::Rejected(Violation::UnknownAttribute(AttrId(999))))
    ));
    assert!(matches!(
        snap.back_links(guid(99), ATTR_MEMBER_OF),
        Err(Error::NoSuchObject)
    ));
}

#[test]
fn reference_to_missing_or_tombstoned_target_is_refused() {
    // Source: docs/46 §2.3 item 4 / §8.4 — writing an ObjectRef whose target
    // is not a live object is refused; [MS-ADTS] 3.1.1.1.6 — "If no such
    // object exists, including the case where the object has been deleted
    // and exists as a tombstone ..., the request fails with error
    // noSuchObject".
    let (_dir, store) = groups("links-target");
    let mut txn = store.begin_write().unwrap();
    txn.delete_object(guid(3), &origin(NODE_1, 50, 1)).unwrap();
    // Missing target, on create.
    assert!(matches!(
        txn.create_object(
            principal_with(6, guid(1), "g3", vec![(ATTR_MEMBER, vec![ref_to(99)])]),
            &origin(NODE_1, 51, 2)
        ),
        Err(Error::NoSuchTarget(ATTR_MEMBER))
    ));
    // Tombstoned target, on create and on modify.
    assert!(matches!(
        txn.create_object(
            principal_with(6, guid(1), "g3", vec![(ATTR_MEMBER, vec![ref_to(3)])]),
            &origin(NODE_1, 51, 3)
        ),
        Err(Error::NoSuchTarget(ATTR_MEMBER))
    ));
    assert!(matches!(
        txn.modify_object(
            guid(5),
            vec![AttributeChange::Replace {
                id: ATTR_MEMBER,
                values: vec![ref_to(2), ref_to(3)],
            }],
            &origin(NODE_1, 52, 4)
        ),
        Err(Error::NoSuchTarget(ATTR_MEMBER))
    ));
    // A forward link with no back link attribute follows the same rule.
    assert!(matches!(
        txn.modify_object(
            guid(5),
            vec![AttributeChange::Replace {
                id: ATTR_SEE_ALSO,
                values: vec![ref_to(98)],
            }],
            &origin(NODE_1, 52, 5)
        ),
        Err(Error::NoSuchTarget(ATTR_SEE_ALSO))
    ));
    // An object cannot reference itself while it does not exist yet.
    assert!(matches!(
        txn.create_object(
            principal_with(7, guid(1), "self", vec![(ATTR_MEMBER, vec![ref_to(7)])]),
            &origin(NODE_1, 53, 6)
        ),
        Err(Error::NoSuchTarget(ATTR_MEMBER))
    ));
    txn.commit().unwrap();
    // None of the refusals changed anything.
    assert_eq!(members(&store, 5), vec![ref_to(2)]);
    assert_eq!(store.snapshot().unwrap().get_object(guid(6)).unwrap(), None);
}

#[test]
fn delete_removes_every_forward_reference_atomically() {
    // Source: docs/46 §2.3 item 4 / §8.4 — on delete, in the same
    // transaction, the deleted object's GUID is removed from every forward
    // attribute that references it, and the reverse entries go; [MS-ADTS]
    // 3.1.1.1.6. Abort leaves everything intact (D136).
    let (_dir, store) = groups("links-delete");
    // see(6) references alice through a forward link with no back link.
    create_all(
        &store,
        vec![principal_with(
            6,
            guid(1),
            "see",
            vec![(ATTR_SEE_ALSO, vec![ref_to(2)])],
        )],
    );
    let g1_before = store.snapshot().unwrap().get_object(guid(4)).unwrap();
    let bob_stamp = g1_before
        .as_ref()
        .unwrap()
        .attribute(ATTR_MEMBER)
        .unwrap()
        .values
        .iter()
        .find(|v| v.value == ref_to(3))
        .unwrap()
        .stamp;

    // Inside the transaction: alice is gone from every referrer.
    {
        let mut txn = store.begin_write().unwrap();
        txn.delete_object(guid(2), &origin(NODE_2, 500, 1)).unwrap();
        let g1 = txn.get_object(guid(4)).unwrap().unwrap();
        assert_eq!(
            g1.attribute(ATTR_MEMBER)
                .unwrap()
                .values
                .iter()
                .map(|v| v.value.clone())
                .collect::<Vec<_>>(),
            vec![ref_to(3)]
        );
        assert!(txn
            .get_object(guid(5))
            .unwrap()
            .unwrap()
            .attribute(ATTR_MEMBER)
            .is_none());
        assert!(txn
            .get_object(guid(6))
            .unwrap()
            .unwrap()
            .attribute(ATTR_SEE_ALSO)
            .is_none());
        txn.abort().unwrap();
    }
    // Aborted: everything as before.
    assert_eq!(
        store.snapshot().unwrap().get_object(guid(4)).unwrap(),
        g1_before
    );
    assert_eq!(members(&store, 5), vec![ref_to(2)]);
    assert_eq!(member_of(&store, 2), vec![guid(4), guid(5)]);
    assert!(store
        .snapshot()
        .unwrap()
        .get_object(guid(2))
        .unwrap()
        .is_some());

    // Committed: same result, durable.
    let mut txn = store.begin_write().unwrap();
    txn.delete_object(guid(2), &origin(NODE_2, 600, 2)).unwrap();
    txn.commit().unwrap();
    let snap = store.snapshot().unwrap();
    let g1 = snap.get_object(guid(4)).unwrap().unwrap();
    let left = &g1.attribute(ATTR_MEMBER).unwrap().values;
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].value, ref_to(3));
    // The value left behind keeps its stamp; the removal leaves none (A-20).
    assert_eq!(left[0].stamp, bob_stamp);
    assert!(snap
        .get_object(guid(5))
        .unwrap()
        .unwrap()
        .attribute(ATTR_MEMBER)
        .is_none());
    assert!(snap
        .get_object(guid(6))
        .unwrap()
        .unwrap()
        .attribute(ATTR_SEE_ALSO)
        .is_none());
    assert_eq!(
        snap.back_links(guid(3), ATTR_MEMBER_OF).unwrap(),
        vec![guid(4)]
    );
    drop(snap);
    // No reverse entry targets the tombstone: it can be purged (a purge
    // refuses while one does).
    let mut txn = store.begin_write().unwrap();
    assert_eq!(txn.purge_tombstones(Timestamp(u64::MAX), 0).unwrap(), 1);
    txn.commit().unwrap();
}

#[test]
fn deleting_a_source_removes_its_own_reverse_entries() {
    // Source: docs/46 §2.3 item 4 — "the outgoing links of the deleted object
    // disappear anyway, because A-18 drops all its values — and their index
    // rows are deleted with them".
    let (_dir, store) = groups("links-delete-source");
    let mut txn = store.begin_write().unwrap();
    txn.delete_object(guid(4), &origin(NODE_1, 70, 1)).unwrap();
    txn.commit().unwrap();
    assert_eq!(member_of(&store, 2), vec![guid(5)]);
    assert_eq!(member_of(&store, 3), vec![]);
    // bob can now be deleted and purged with nothing left behind.
    let mut txn = store.begin_write().unwrap();
    txn.delete_object(guid(3), &origin(NODE_1, 71, 2)).unwrap();
    assert_eq!(txn.purge_tombstones(Timestamp(u64::MAX), 0).unwrap(), 2);
    txn.commit().unwrap();
}

#[test]
fn self_reference_is_allowed_on_a_live_object_and_deletes_cleanly() {
    // Source: docs/46 §2.3 item 4 — no prohibition of self-reference was
    // found in the sections opened; the target only has to be live.
    let (_dir, store) = groups("links-self");
    set_members(&store, 4, vec![ref_to(2), ref_to(3), ref_to(4)], 30);
    assert_eq!(member_of(&store, 4), vec![guid(4)]);
    let mut txn = store.begin_write().unwrap();
    txn.delete_object(guid(4), &origin(NODE_1, 80, 1)).unwrap();
    txn.commit().unwrap();
    assert_eq!(member_of(&store, 2), vec![guid(5)]);
    let mut txn = store.begin_write().unwrap();
    assert_eq!(txn.purge_tombstones(Timestamp(u64::MAX), 0).unwrap(), 1);
    txn.commit().unwrap();
}
