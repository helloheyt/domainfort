//! Tombstones (invisible to reads, purged by lifetime) and attr-stamps
//! (preserved, version rises per change).
//!
//! Source: docs/29 §2 (attr-stamp `(version, wall-clock, origin-node,
//! origin-seq)` per attribute value; version rises on every change of the
//! attribute, D119), §5 (deletion = tombstone with attr-stamp, kept for a
//! tombstone lifetime then collected, D121); docs/32 §2 (attr-stamp on every
//! value, D134). Times and node ids are caller-supplied (tests/common).

mod common;

use common::*;
use dirstore::{AttrStamp, AttributeChange, Error, Timestamp, Tombstone};
use redb::{ReadableDatabase, TableDefinition};

fn stamp(version: u64, node: dirstore::NodeId, wall_clock: u64, seq: u64) -> AttrStamp {
    AttrStamp {
        version,
        wall_clock: Timestamp(wall_clock),
        origin_node: node,
        origin_seq: seq,
    }
}

#[test]
fn create_stamps_every_value_with_version_one() {
    // Source: docs/29 §2.
    let dir = TempDir::new("stamps-create");
    let store = open_store(&dir);
    let mut txn = store.begin_write().unwrap();
    txn.create_object(root(1, "root"), &origin(NODE_1, 100, 7))
        .unwrap();
    txn.commit().unwrap();
    let root = store
        .snapshot()
        .unwrap()
        .get_object(guid(1))
        .unwrap()
        .unwrap();
    assert_eq!(
        root.attribute(ATTR_NAME).unwrap().values[0].stamp,
        stamp(1, NODE_1, 100, 7)
    );
}

#[test]
fn stamps_preserved_and_versions_rise() {
    // Source: docs/29 §2 — the stamp travels per attribute value; changing
    // one attribute leaves the others' stamps untouched; version rises on
    // every change of the same attribute.
    let dir = TempDir::new("stamps-modify");
    let store = open_store(&dir);
    let mut txn = store.begin_write().unwrap();
    txn.create_object(root(1, "root"), &origin(NODE_1, 100, 1))
        .unwrap();
    txn.create_object(
        principal_with(
            2,
            guid(1),
            "alice",
            vec![(ATTR_COUNTER, vec![1i64.to_be_bytes().to_vec()])],
        ),
        &origin(NODE_1, 100, 2),
    )
    .unwrap();
    txn.modify_object(
        guid(2),
        vec![AttributeChange::Replace {
            id: ATTR_NOTE,
            values: vec![b"a".to_vec(), b"b".to_vec()],
        }],
        &origin(NODE_1, 110, 3),
    )
    .unwrap();
    txn.commit().unwrap();

    // Second change, from another node: keep "a", drop "b", add "c".
    let mut txn = store.begin_write().unwrap();
    txn.modify_object(
        guid(2),
        vec![AttributeChange::Replace {
            id: ATTR_NOTE,
            values: vec![b"c".to_vec(), b"a".to_vec()],
        }],
        &origin(NODE_2, 200, 50),
    )
    .unwrap();
    txn.commit().unwrap();

    let alice = store
        .snapshot()
        .unwrap()
        .get_object(guid(2))
        .unwrap()
        .unwrap();
    let note = alice.attribute(ATTR_NOTE).unwrap();
    assert_eq!(note.values.len(), 2);
    assert_eq!(note.values[0].value, b"a");
    assert_eq!(note.values[0].stamp, stamp(1, NODE_1, 110, 3)); // kept
    assert_eq!(note.values[1].value, b"c");
    assert_eq!(note.values[1].stamp, stamp(2, NODE_2, 200, 50)); // new
                                                                 // Untouched attributes keep their creation stamps.
    assert_eq!(
        alice.attribute(ATTR_NAME).unwrap().values[0].stamp,
        stamp(1, NODE_1, 100, 2)
    );
    assert_eq!(
        alice.attribute(ATTR_SID).unwrap().values[0].stamp,
        stamp(1, NODE_1, 100, 2)
    );

    // Single-valued replace: the new value gets version 2. (The RDN
    // attribute itself cannot be modified — [MS-ADTS] 3.1.1.5.3.2 — so a
    // non-naming single-valued attribute is used.)
    let mut txn = store.begin_write().unwrap();
    txn.modify_object(
        guid(2),
        vec![AttributeChange::Replace {
            id: ATTR_COUNTER,
            values: vec![2i64.to_be_bytes().to_vec()],
        }],
        &origin(NODE_2, 300, 51),
    )
    .unwrap();
    txn.commit().unwrap();

    // Preserved across close / reopen.
    drop(store);
    let store = open_store(&dir);
    let alice = store
        .snapshot()
        .unwrap()
        .get_object(guid(2))
        .unwrap()
        .unwrap();
    assert_eq!(
        alice.attribute(ATTR_COUNTER).unwrap().values[0].stamp,
        stamp(2, NODE_2, 300, 51)
    );
    assert_eq!(
        alice.attribute(ATTR_NAME).unwrap().values[0].stamp,
        stamp(1, NODE_1, 100, 2)
    );
    assert_eq!(
        alice.attribute(ATTR_NOTE).unwrap().values[1].stamp,
        stamp(2, NODE_2, 200, 50)
    );
}

#[test]
fn unchanged_replace_writes_nothing() {
    // Source: docs/29 §2 — version rises on a *change*; replacing a value set
    // with itself is no change.
    let dir = TempDir::new("stamps-noop");
    let store = open_store(&dir);
    create_all(
        &store,
        vec![
            root(1, "root"),
            principal_with(
                2,
                guid(1),
                "p",
                vec![(ATTR_COUNTER, vec![5i64.to_be_bytes().to_vec()])],
            ),
        ],
    );
    let before = store.snapshot().unwrap().get_object(guid(2)).unwrap();
    let mut txn = store.begin_write().unwrap();
    txn.modify_object(
        guid(2),
        vec![
            AttributeChange::Replace {
                id: ATTR_COUNTER,
                values: vec![5i64.to_be_bytes().to_vec()],
            },
            AttributeChange::Replace {
                id: ATTR_NOTE,
                values: vec![],
            },
        ],
        &origin(NODE_2, 999, 999),
    )
    .unwrap();
    txn.commit().unwrap();
    assert_eq!(
        store.snapshot().unwrap().get_object(guid(2)).unwrap(),
        before
    );
}

#[test]
fn tombstone_is_invisible_and_reduced_to_identity() {
    // Source: docs/29 §5 — a tombstone is a deletion marker with an
    // attr-stamp, not physically removed, invisible to normal reads; its only
    // job is to stop the object coming back, so it keeps only the GUID, the
    // classes and the deletion stamp (docs/25 §5 "state"; Q-062 / A-18).
    let dir = TempDir::new("tombstone");
    let store = open_store(&dir);
    create_all(
        &store,
        vec![root(1, "root"), principal(2, guid(1), "alice")],
    );

    let mut txn = store.begin_write().unwrap();
    txn.delete_object(guid(2), &origin(NODE_2, 5000, 77))
        .unwrap();
    txn.commit().unwrap();

    let snap = store.snapshot().unwrap();
    assert_eq!(snap.get_object(guid(2)).unwrap(), None);
    assert_eq!(snap.lookup_child(Some(guid(1)), b"alice").unwrap(), None);
    let ts = snap
        .get_tombstone(guid(2))
        .unwrap()
        .expect("tombstone kept");
    assert_eq!(
        ts,
        Tombstone {
            guid: guid(2),
            classes: PRINCIPAL_CHAIN.to_vec(),
            deletion: stamp(1, NODE_2, 5000, 77),
        }
    );
    // A live object is not a tombstone.
    assert_eq!(snap.get_tombstone(guid(1)).unwrap(), None);
    drop(snap);

    // Writes treat the tombstone as absent.
    let mut txn = store.begin_write().unwrap();
    assert!(matches!(
        txn.delete_object(guid(2), &origin(NODE_1, 1, 1)),
        Err(Error::NoSuchObject)
    ));
    assert!(matches!(
        txn.modify_object(
            guid(2),
            vec![AttributeChange::Replace {
                id: ATTR_NOTE,
                values: vec![b"x".to_vec()]
            }],
            &origin(NODE_1, 1, 2)
        ),
        Err(Error::NoSuchObject)
    ));
    // The parent has no live children left.
    txn.delete_object(guid(1), &origin(NODE_1, 6000, 3))
        .unwrap();
    txn.commit().unwrap();
}

#[test]
fn tombstone_has_its_own_validation_path() {
    // Source: Q-062 / A-18; docs/32 §4; docs/14 D60. A tombstone of
    // CLASS_PRINCIPAL has none of that class's must-attributes and still
    // reads back (must / may do not apply); but its classes must be known to
    // the schema given at open, else it is refused, never returned.
    let dir = TempDir::new("tombstone-validate");
    {
        let store = open_store(&dir);
        create_all(
            &store,
            vec![root(1, "root"), principal(2, guid(1), "alice")],
        );
        let mut txn = store.begin_write().unwrap();
        txn.delete_object(guid(2), &origin(NODE_1, 10, 1)).unwrap();
        txn.commit().unwrap();
        assert!(store
            .snapshot()
            .unwrap()
            .get_tombstone(guid(2))
            .unwrap()
            .is_some());
    }
    // CLASS_FLAGGED is a subclass of CLASS_PRINCIPAL, so it goes too.
    let without_principal: Vec<_> = class_definitions()
        .into_iter()
        .filter(|c| c.id != CLASS_PRINCIPAL && c.id != CLASS_FLAGGED)
        .collect();
    let schema = dirstore::Schema::new(
        attribute_definitions(dirstore::AttrClass::Secret),
        without_principal,
    )
    .unwrap();
    let store = dirstore::Store::open(dir.db_path(), key_a(), schema).unwrap();
    assert!(matches!(
        store.snapshot().unwrap().get_tombstone(guid(2)),
        Err(Error::StoredObjectRejected(
            dirstore::Violation::UnknownClass(CLASS_PRINCIPAL)
        ))
    ));
}

#[test]
fn stored_tombstone_record_holds_none_of_the_deleted_values() {
    // Source: docs/29 §5 + docs/25 §5 ("state"), Q-062 / A-18 — the tombstone
    // record keeps no attribute value, no RDN key and no parent. Checked on
    // the raw stored record itself (read through redb's public API with the
    // store closed), not on the whole file: redb is copy-on-write, so freed
    // pages may still hold old bytes — the documented residual of Q-062.
    const NOTE: &[u8] = b"DELETED-NOTE-VALUE-9c41e7";
    const RDN: &[u8] = b"rdn-qz8x-distinct";
    let dir = TempDir::new("tombstone-raw");
    {
        let store = open_store(&dir);
        // The RDN key is computed from ATTR_NAME (lower-case already, so the
        // folded key has the same bytes).
        let mut obj = principal(2, guid(1), "unused");
        obj.attributes = vec![
            (ATTR_NAME, vec![RDN.to_vec()]),
            (ATTR_SID, vec![sid_value(4242)]),
            (ATTR_NOTE, vec![NOTE.to_vec()]),
        ];
        create_all(&store, vec![root(1, "root"), obj]);
        let mut txn = store.begin_write().unwrap();
        txn.delete_object(guid(2), &origin(NODE_2, 7000, 5))
            .unwrap();
        txn.commit().unwrap();
    }
    let db = redb::Database::create(dir.db_path()).unwrap();
    let txn = db.begin_read().unwrap();
    let def: TableDefinition<&'static [u8], &'static [u8]> =
        TableDefinition::new("dirstore.objects");
    let objects = txn.open_table(def).unwrap();
    let stored = objects
        .get(guid(2).to_packet().as_slice())
        .unwrap()
        .expect("tombstone record present")
        .value()
        .to_vec();
    let contains = |needle: &[u8]| stored.windows(needle.len()).any(|w| w == needle);
    assert!(!contains(NOTE), "deleted attribute value still stored");
    assert!(!contains(RDN), "RDN key / name value still stored");
    assert!(
        !contains(&sid_value(4242)),
        "deleted SID value still stored"
    );
    assert!(!contains(&guid(1).to_packet()), "parent GUID still stored");
    // Body = format, flags, rdn_len, deletion stamp, class count + the three
    // classes of the principal chain, attribute count; then the 32-byte tag
    // (src/record.rs layout).
    assert_eq!(
        stored.len(),
        1 + 1 + 2 + 40 + 2 + 4 * PRINCIPAL_CHAIN.len() + 2 + dirstore::MAC_LEN
    );
}

#[test]
fn purge_by_lifetime() {
    // Source: docs/29 §5 (D121) — kept for the lifetime, then collected.
    // Rule (src/store.rs): purged iff tombstone time + lifetime < now.
    let dir = TempDir::new("purge");
    let store = open_store(&dir);
    create_all(
        &store,
        vec![
            root(1, "root"),
            principal(2, guid(1), "old"),
            principal(3, guid(1), "recent"),
            principal(4, guid(1), "live"),
        ],
    );
    let mut txn = store.begin_write().unwrap();
    txn.delete_object(guid(2), &origin(NODE_1, 1000, 10))
        .unwrap();
    txn.delete_object(guid(3), &origin(NODE_1, 5000, 11))
        .unwrap();
    txn.commit().unwrap();

    const LIFETIME: u64 = 3000;
    // At now = 4000: 1000 + 3000 is not < 4000 -> nothing purged yet.
    let mut txn = store.begin_write().unwrap();
    assert_eq!(txn.purge_tombstones(Timestamp(4000), LIFETIME).unwrap(), 0);
    txn.commit().unwrap();
    assert!(store
        .snapshot()
        .unwrap()
        .get_tombstone(guid(2))
        .unwrap()
        .is_some());

    // At now = 4001: the old tombstone is purged, the recent one stays.
    let mut txn = store.begin_write().unwrap();
    assert_eq!(txn.purge_tombstones(Timestamp(4001), LIFETIME).unwrap(), 1);
    txn.commit().unwrap();
    let snap = store.snapshot().unwrap();
    assert_eq!(snap.get_tombstone(guid(2)).unwrap(), None);
    assert!(snap.get_tombstone(guid(3)).unwrap().is_some());
    assert!(snap.get_object(guid(4)).unwrap().is_some());
    assert!(snap.get_object(guid(1)).unwrap().is_some());
    drop(snap);

    // A purge that is dropped uncommitted removes nothing.
    {
        let mut txn = store.begin_write().unwrap();
        assert_eq!(txn.purge_tombstones(Timestamp(u64::MAX), 0).unwrap(), 1);
    }
    assert!(store
        .snapshot()
        .unwrap()
        .get_tombstone(guid(3))
        .unwrap()
        .is_some());

    // A clock behind the tombstone time, or an overflowing lifetime, keeps it.
    let mut txn = store.begin_write().unwrap();
    assert_eq!(txn.purge_tombstones(Timestamp(10), 0).unwrap(), 0);
    assert_eq!(
        txn.purge_tombstones(Timestamp(u64::MAX), u64::MAX).unwrap(),
        0
    );
    // Live objects are never purged, whatever the arguments.
    assert_eq!(txn.purge_tombstones(Timestamp(u64::MAX), 0).unwrap(), 1);
    txn.commit().unwrap();
    let snap = store.snapshot().unwrap();
    assert_eq!(snap.get_tombstone(guid(3)).unwrap(), None);
    assert!(snap.get_object(guid(4)).unwrap().is_some());
}
