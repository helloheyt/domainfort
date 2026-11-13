//! Transaction atomicity and snapshot isolation.
//!
//! Source: docs/32 §7 (value + stamp + indexes + MAC in one atomic
//! transaction, D136), §6 (point-in-time snapshot; no half-updated read,
//! D39). Test data is hand-made (tests/common).

mod common;

use common::*;
use dirstore::AttributeChange;

#[test]
fn dropped_write_leaves_no_trace() {
    // Source: D136 — dropping an uncommitted transaction leaves nothing.
    let dir = TempDir::new("drop");
    let store = open_store(&dir);
    create_all(&store, vec![root(1, "root")]);
    {
        let mut txn = store.begin_write().unwrap();
        txn.create_object(principal(2, guid(1), "alice"), &origin(NODE_1, 1, 1))
            .unwrap();
        txn.create_object(principal(3, guid(1), "bob"), &origin(NODE_1, 1, 2))
            .unwrap();
        txn.modify_object(
            guid(1),
            vec![AttributeChange::Replace {
                id: ATTR_NOTE,
                values: vec![b"changed".to_vec()],
            }],
            &origin(NODE_1, 1, 3),
        )
        .unwrap();
        // dropped here without commit
    }
    let snap = store.snapshot().unwrap();
    assert_eq!(snap.get_object(guid(2)).unwrap(), None);
    assert_eq!(snap.get_object(guid(3)).unwrap(), None);
    assert_eq!(snap.lookup_child(Some(guid(1)), b"alice").unwrap(), None);
    assert!(snap
        .get_object(guid(1))
        .unwrap()
        .unwrap()
        .attribute(ATTR_NOTE)
        .is_none());
    drop(snap);

    // The parent's child count was not touched either: it is deletable.
    let mut txn = store.begin_write().unwrap();
    txn.delete_object(guid(1), &origin(NODE_1, 2, 4)).unwrap();
    txn.commit().unwrap();
}

#[test]
fn aborted_write_leaves_no_trace_even_after_reopen() {
    // Source: D136.
    let dir = TempDir::new("abort");
    {
        let store = open_store(&dir);
        let mut txn = store.begin_write().unwrap();
        txn.create_object(root(1, "root"), &origin(NODE_1, 1, 1))
            .unwrap();
        txn.abort().unwrap();
    }
    let store = open_store(&dir);
    let snap = store.snapshot().unwrap();
    assert_eq!(snap.get_object(guid(1)).unwrap(), None);
    assert_eq!(snap.lookup_child(None, b"root").unwrap(), None);
}

#[test]
fn several_operations_commit_together() {
    // Source: D136 — all-or-nothing across operations of one transaction.
    let dir = TempDir::new("together");
    let store = open_store(&dir);
    let mut txn = store.begin_write().unwrap();
    txn.create_object(root(1, "root"), &origin(NODE_1, 1, 1))
        .unwrap();
    txn.create_object(principal(2, guid(1), "alice"), &origin(NODE_1, 1, 2))
        .unwrap();
    // A snapshot taken mid-transaction sees nothing of it.
    let before = store.snapshot().unwrap();
    txn.commit().unwrap();
    assert_eq!(before.get_object(guid(1)).unwrap(), None);
    assert_eq!(before.get_object(guid(2)).unwrap(), None);
    let after = store.snapshot().unwrap();
    assert!(after.get_object(guid(1)).unwrap().is_some());
    assert!(after.get_object(guid(2)).unwrap().is_some());
}

#[test]
fn snapshot_does_not_see_later_commits() {
    // Source: docs/32 §6 (D39) — a reader opened before a write never sees it,
    // neither the value nor the index.
    let dir = TempDir::new("isolation");
    let store = open_store(&dir);
    create_all(&store, vec![root(1, "root")]);

    let old = store.snapshot().unwrap();

    let mut txn = store.begin_write().unwrap();
    txn.create_object(principal(2, guid(1), "alice"), &origin(NODE_1, 5, 1))
        .unwrap();
    txn.modify_object(
        guid(1),
        vec![AttributeChange::Replace {
            id: ATTR_NOTE,
            values: vec![b"new note".to_vec()],
        }],
        &origin(NODE_1, 5, 2),
    )
    .unwrap();

    // While the write is open (uncommitted): invisible.
    assert_eq!(old.get_object(guid(2)).unwrap(), None);
    let during = store.snapshot().unwrap();
    assert_eq!(during.get_object(guid(2)).unwrap(), None);
    assert_eq!(during.lookup_child(Some(guid(1)), b"alice").unwrap(), None);

    txn.commit().unwrap();

    // After commit: the old snapshots still show the earlier state, whole.
    for snap in [&old, &during] {
        assert_eq!(snap.get_object(guid(2)).unwrap(), None);
        assert_eq!(snap.lookup_child(Some(guid(1)), b"alice").unwrap(), None);
        assert!(snap
            .get_object(guid(1))
            .unwrap()
            .unwrap()
            .attribute(ATTR_NOTE)
            .is_none());
    }
    // A new snapshot shows the new state, whole.
    let new = store.snapshot().unwrap();
    assert!(new.get_object(guid(2)).unwrap().is_some());
    assert_eq!(
        new.lookup_child(Some(guid(1)), b"alice").unwrap(),
        Some(guid(2))
    );
    assert_eq!(
        new.get_object(guid(1))
            .unwrap()
            .unwrap()
            .attribute(ATTR_NOTE)
            .unwrap()
            .values[0]
            .value,
        b"new note"
    );
}

#[test]
fn snapshot_keeps_seeing_a_deleted_object() {
    // Source: docs/32 §6 (D39) with docs/29 §5.
    let dir = TempDir::new("isolation-delete");
    let store = open_store(&dir);
    create_all(&store, vec![root(1, "root")]);
    let old = store.snapshot().unwrap();
    let mut txn = store.begin_write().unwrap();
    txn.delete_object(guid(1), &origin(NODE_1, 9, 1)).unwrap();
    txn.commit().unwrap();
    assert!(old.get_object(guid(1)).unwrap().is_some());
    assert_eq!(store.snapshot().unwrap().get_object(guid(1)).unwrap(), None);
}
