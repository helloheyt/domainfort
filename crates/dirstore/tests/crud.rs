//! Create / read / update / delete, and the `(parent, RDN key)` name index.
//!
//! Source: docs/32 §2 (objects keyed by stable GUID, name as secondary index,
//! D134), §4 (validated writes), §7 (atomic write); docs/29 §5 (tombstones
//! invisible to reads, D121). Test data is hand-made (tests/common).

mod common;

use common::*;
use dirstore::{AttributeChange, Error, NewObject};

#[test]
fn create_read_update_delete() {
    let dir = TempDir::new("crud");
    let store = open_store(&dir);
    create_all(
        &store,
        vec![container(1, None, "root"), principal(2, guid(1), "alice")],
    );

    // Read back through a snapshot. Source: docs/32 §2, §6.
    let snap = store.snapshot().unwrap();
    let alice = snap.get_object(guid(2)).unwrap().expect("alice exists");
    assert_eq!(alice.guid, guid(2));
    assert_eq!(alice.parent, Some(guid(1)));
    assert_eq!(alice.rdn, b"alice");
    assert_eq!(alice.classes, vec![CLASS_PRINCIPAL]);
    assert!(!alice.is_tombstone());
    let name = alice.attribute(ATTR_NAME).unwrap();
    assert_eq!(name.values.len(), 1);
    assert_eq!(name.values[0].value, b"alice");
    assert_eq!(
        alice.attribute(ATTR_SID).unwrap().values[0].value,
        sid_value(1002)
    );
    assert_eq!(
        snap.lookup_child(Some(guid(1)), b"alice").unwrap(),
        Some(guid(2))
    );
    assert_eq!(snap.lookup_child(None, b"root").unwrap(), Some(guid(1)));
    assert_eq!(snap.lookup_child(Some(guid(1)), b"bob").unwrap(), None);
    drop(snap);

    // Update. Source: docs/32 §4, §7.
    let mut txn = store.begin_write().unwrap();
    txn.modify_object(
        guid(2),
        vec![
            AttributeChange::Replace {
                id: ATTR_NOTE,
                values: vec![b"second".to_vec(), b"first".to_vec()],
            },
            AttributeChange::Replace {
                id: ATTR_MEMBER,
                values: vec![guid(1).to_packet().to_vec()],
            },
            AttributeChange::Replace {
                id: ATTR_SD,
                values: vec![sd_value()],
            },
            AttributeChange::Replace {
                id: ATTR_FLAG,
                values: vec![vec![0x01]],
            },
            AttributeChange::Replace {
                id: ATTR_COUNTER,
                values: vec![42i64.to_be_bytes().to_vec()],
            },
            AttributeChange::Replace {
                id: ATTR_PHONE,
                values: vec![b"+1 555".to_vec()],
            },
        ],
        &origin(NODE_1, 2000, 10),
    )
    .unwrap();
    txn.commit().unwrap();

    let snap = store.snapshot().unwrap();
    let alice = snap.get_object(guid(2)).unwrap().unwrap();
    let notes: Vec<&[u8]> = alice
        .attribute(ATTR_NOTE)
        .unwrap()
        .values
        .iter()
        .map(|v| v.value.as_slice())
        .collect();
    // Values are a set kept in ascending byte order (record codec rule).
    assert_eq!(notes, vec![b"first".as_slice(), b"second".as_slice()]);
    assert_eq!(
        alice.attribute(ATTR_SD).unwrap().values[0].value,
        sd_value()
    );
    assert_eq!(alice.attribute(ATTR_FLAG).unwrap().values[0].value, vec![1]);
    drop(snap);

    // Remove an attribute with an empty replace.
    let mut txn = store.begin_write().unwrap();
    txn.modify_object(
        guid(2),
        vec![AttributeChange::Replace {
            id: ATTR_NOTE,
            values: vec![],
        }],
        &origin(NODE_1, 2100, 11),
    )
    .unwrap();
    txn.commit().unwrap();
    let snap = store.snapshot().unwrap();
    assert!(snap
        .get_object(guid(2))
        .unwrap()
        .unwrap()
        .attribute(ATTR_NOTE)
        .is_none());
    drop(snap);

    // Delete: a tombstone, invisible to normal reads. Source: docs/29 §5.
    let mut txn = store.begin_write().unwrap();
    txn.delete_object(guid(2), &origin(NODE_1, 3000, 12))
        .unwrap();
    txn.commit().unwrap();
    let snap = store.snapshot().unwrap();
    assert_eq!(snap.get_object(guid(2)).unwrap(), None);
    assert_eq!(snap.lookup_child(Some(guid(1)), b"alice").unwrap(), None);
    assert!(snap.get_tombstone(guid(2)).unwrap().is_some());
}

#[test]
fn data_survives_reopen() {
    // Source: docs/32 §7 (committed writes are durable state).
    let dir = TempDir::new("reopen");
    {
        let store = open_store(&dir);
        create_all(&store, vec![container(1, None, "root")]);
    }
    let store = open_store(&dir);
    let snap = store.snapshot().unwrap();
    let root = snap.get_object(guid(1)).unwrap().expect("persisted");
    assert_eq!(root.rdn, b"root");
    assert_eq!(snap.lookup_child(None, b"root").unwrap(), Some(guid(1)));
}

#[test]
fn modify_and_delete_of_missing_object() {
    // Source: docs/32 §2; docs/29 §5.
    let dir = TempDir::new("missing");
    let store = open_store(&dir);
    let mut txn = store.begin_write().unwrap();
    assert!(matches!(
        txn.modify_object(
            guid(9),
            vec![AttributeChange::Replace {
                id: ATTR_NOTE,
                values: vec![b"x".to_vec()]
            }],
            &origin(NODE_1, 1, 1)
        ),
        Err(Error::NoSuchObject)
    ));
    assert!(matches!(
        txn.delete_object(guid(9), &origin(NODE_1, 1, 2)),
        Err(Error::NoSuchObject)
    ));
    assert_eq!(txn.get_object(guid(9)).unwrap(), None);
}

#[test]
fn name_uniqueness_under_one_parent() {
    // Source: docs/32 §2 — unique (parent GUID, RDN key) among live objects.
    let dir = TempDir::new("names");
    let store = open_store(&dir);
    create_all(
        &store,
        vec![
            container(1, None, "root"),
            container(2, Some(guid(1)), "ou-a"),
            container(3, Some(guid(1)), "ou-b"),
            principal(4, guid(2), "alice"),
        ],
    );

    let mut txn = store.begin_write().unwrap();
    // Same RDN key, same parent -> refused.
    assert!(matches!(
        txn.create_object(principal(5, guid(2), "alice"), &origin(NODE_1, 1, 1)),
        Err(Error::NameExists)
    ));
    // Same RDN key at the root -> refused.
    assert!(matches!(
        txn.create_object(container(6, None, "root"), &origin(NODE_1, 1, 2)),
        Err(Error::NameExists)
    ));
    // Same RDN key under another parent -> fine.
    txn.create_object(principal(7, guid(3), "alice"), &origin(NODE_1, 1, 3))
        .unwrap();
    // A refusal does not poison the transaction: the good write commits.
    txn.commit().unwrap();

    let snap = store.snapshot().unwrap();
    assert_eq!(
        snap.lookup_child(Some(guid(2)), b"alice").unwrap(),
        Some(guid(4))
    );
    assert_eq!(
        snap.lookup_child(Some(guid(3)), b"alice").unwrap(),
        Some(guid(7))
    );
    assert_eq!(snap.get_object(guid(5)).unwrap(), None);
    assert_eq!(snap.get_object(guid(6)).unwrap(), None);
}

#[test]
fn rdn_key_is_opaque_bytes() {
    // Source: task scope / docs/32 §2 — the RDN key is an opaque,
    // caller-normalized byte string; dirstore applies no matching rule, so
    // keys differing only in letter case are distinct names.
    let dir = TempDir::new("opaque");
    let store = open_store(&dir);
    create_all(
        &store,
        vec![container(1, None, "root"), principal(2, guid(1), "Alice")],
    );
    let mut txn = store.begin_write().unwrap();
    txn.create_object(principal(3, guid(1), "alice"), &origin(NODE_1, 1, 1))
        .unwrap();
    txn.commit().unwrap();
    let snap = store.snapshot().unwrap();
    assert_eq!(
        snap.lookup_child(Some(guid(1)), b"Alice").unwrap(),
        Some(guid(2))
    );
    assert_eq!(
        snap.lookup_child(Some(guid(1)), b"alice").unwrap(),
        Some(guid(3))
    );
}

#[test]
fn tree_rules() {
    // Source: docs/32 §2 (DIT): the parent must be live; a live object's
    // parent stays live; a GUID held by any record cannot be reused.
    let dir = TempDir::new("tree");
    let store = open_store(&dir);
    create_all(
        &store,
        vec![
            container(1, None, "root"),
            container(2, Some(guid(1)), "ou"),
            principal(3, guid(2), "alice"),
        ],
    );
    let mut txn = store.begin_write().unwrap();
    assert!(matches!(
        txn.create_object(principal(4, guid(99), "bob"), &origin(NODE_1, 1, 1)),
        Err(Error::NoSuchParent)
    ));
    assert!(matches!(
        txn.delete_object(guid(2), &origin(NODE_1, 1, 2)),
        Err(Error::HasChildren)
    ));
    assert!(matches!(
        txn.create_object(principal(3, guid(1), "other-name"), &origin(NODE_1, 1, 3)),
        Err(Error::ObjectExists)
    ));
    // Delete bottom-up; the parent becomes deletable.
    txn.delete_object(guid(3), &origin(NODE_1, 1, 4)).unwrap();
    txn.delete_object(guid(2), &origin(NODE_1, 1, 5)).unwrap();
    // Creating under a tombstone is refused: it is not a live parent.
    assert!(matches!(
        txn.create_object(principal(5, guid(2), "carol"), &origin(NODE_1, 1, 6)),
        Err(Error::NoSuchParent)
    ));
    // The GUID of a tombstone is still taken.
    assert!(matches!(
        txn.create_object(container(2, Some(guid(1)), "ou2"), &origin(NODE_1, 1, 7)),
        Err(Error::ObjectExists)
    ));
    txn.commit().unwrap();
}

#[test]
fn deleted_name_is_released() {
    // Source: docs/29 §5 (tombstones invisible to normal reads) with docs/32
    // §2 (names unique among live objects) — see docs/questions/Q-062.
    let dir = TempDir::new("release");
    let store = open_store(&dir);
    create_all(
        &store,
        vec![container(1, None, "root"), principal(2, guid(1), "alice")],
    );
    let mut txn = store.begin_write().unwrap();
    txn.delete_object(guid(2), &origin(NODE_1, 5, 1)).unwrap();
    let again = NewObject {
        guid: guid(3),
        ..principal(2, guid(1), "alice")
    };
    txn.create_object(again, &origin(NODE_1, 6, 2)).unwrap();
    txn.commit().unwrap();
    let snap = store.snapshot().unwrap();
    assert_eq!(
        snap.lookup_child(Some(guid(1)), b"alice").unwrap(),
        Some(guid(3))
    );
    assert!(snap.get_tombstone(guid(2)).unwrap().is_some());
}

#[test]
fn write_transaction_reads_its_own_writes() {
    // Source: docs/32 §7 (one transaction).
    let dir = TempDir::new("own-writes");
    let store = open_store(&dir);
    let mut txn = store.begin_write().unwrap();
    txn.create_object(container(1, None, "root"), &origin(NODE_1, 1, 1))
        .unwrap();
    assert!(txn.get_object(guid(1)).unwrap().is_some());
    assert_eq!(txn.lookup_child(None, b"root").unwrap(), Some(guid(1)));
    txn.delete_object(guid(1), &origin(NODE_1, 2, 2)).unwrap();
    assert_eq!(txn.get_object(guid(1)).unwrap(), None);
    assert!(txn.get_tombstone(guid(1)).unwrap().is_some());
    txn.commit().unwrap();
}
