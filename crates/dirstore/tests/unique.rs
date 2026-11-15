//! Unique attributes and the unique index.
//!
//! Source: docs/46 §8.5 (an integrity-tagged index from the comparison key to
//! the GUID for every `unique` attribute; create / modify that would
//! duplicate a value is refused; maintained in the same transaction; removed
//! on delete; no code path disables it — docs/CLEAN-ROOM.md); Q-080 (phase-1
//! comparison key for String(Unicode): printable ASCII, A–Z folded; raw bytes
//! for other syntaxes); [MS-ADTS] v20261026 §3.1.1.5.1.3 (UPN / SPN "MUST be
//! unique"). Test data is hand-made (tests/common).

mod common;

use common::*;
use dirstore::{AttrId, AttributeChange, Error, Store, Violation};

fn login(name: &str) -> (AttrId, Vec<Vec<u8>>) {
    (ATTR_LOGIN, vec![name.as_bytes().to_vec()])
}

fn spns(names: &[&str]) -> (AttrId, Vec<Vec<u8>>) {
    (
        ATTR_SPN,
        names.iter().map(|n| n.as_bytes().to_vec()).collect(),
    )
}

fn replace(
    store: &Store,
    id: u32,
    change: (AttrId, Vec<Vec<u8>>),
    seq: u64,
) -> dirstore::Result<()> {
    let mut txn = store.begin_write().unwrap();
    txn.modify_object(
        guid(id),
        vec![AttributeChange::Replace {
            id: change.0,
            values: change.1,
        }],
        &origin(NODE_1, 100 + seq, seq),
    )?;
    txn.commit()
}

fn create(store: &Store, obj: dirstore::NewObject, seq: u64) -> dirstore::Result<()> {
    let mut txn = store.begin_write().unwrap();
    txn.create_object(obj, &origin(NODE_1, 100 + seq, seq))?;
    txn.commit()
}

/// root(1); alice(2) with login "Alice" and SPNs HOST/a, HOST/b.
fn populated(test: &str) -> (TempDir, Store) {
    let dir = TempDir::new(test);
    let store = open_store(&dir);
    create_all(
        &store,
        vec![
            root(1, "root"),
            principal_with(
                2,
                guid(1),
                "alice",
                vec![login("Alice"), spns(&["HOST/a", "HOST/b"])],
            ),
        ],
    );
    (dir, store)
}

#[test]
fn duplicate_under_case_fold_is_refused_on_create() {
    // Source: docs/46 §8.5 with the Q-080 comparison key.
    let (_dir, store) = populated("unique-create");
    for (i, (extra, attr)) in [
        (vec![login("alice")], ATTR_LOGIN),
        (vec![login("ALICE")], ATTR_LOGIN),
        (vec![spns(&["host/B"])], ATTR_SPN),
        (vec![spns(&["HOST/c", "Host/A"])], ATTR_SPN),
    ]
    .into_iter()
    .enumerate()
    {
        let seq = u64::try_from(i).unwrap() + 1;
        assert!(
            matches!(
                create(&store, principal_with(3, guid(1), "bob", extra), seq),
                Err(Error::ValueNotUnique(x)) if x == attr
            ),
            "case {i}"
        );
    }
    // Raw bytes for a non-string syntax: the same SID is a duplicate.
    let same_sid = dirstore::NewObject {
        attributes: vec![
            (ATTR_NAME, vec![b"bob".to_vec()]),
            (ATTR_SID, vec![sid_value(1002)]),
        ],
        ..principal(3, guid(1), "bob")
    };
    assert!(matches!(
        create(&store, same_sid, 9),
        Err(Error::ValueNotUnique(ATTR_SID))
    ));
    assert_eq!(store.snapshot().unwrap().get_object(guid(3)).unwrap(), None);
}

#[test]
fn values_of_one_object_must_have_distinct_keys() {
    // Source: docs/46 §8.5 — two values of one object with the same
    // comparison key would share one index entry; refused as a duplicate.
    let (_dir, store) = populated("unique-within");
    assert!(matches!(
        create(
            &store,
            principal_with(3, guid(1), "bob", vec![spns(&["HOST/x", "host/X"])]),
            1
        ),
        Err(Error::Rejected(Violation::DuplicateValue(ATTR_SPN)))
    ));
}

#[test]
fn non_ascii_unique_string_is_refused() {
    // Source: Q-080 item 1 — no phase-1 comparison key exists for a
    // non-ASCII String(Unicode) value; refused, never folded by a guess.
    let (_dir, store) = populated("unique-ascii");
    assert!(matches!(
        create(
            &store,
            principal_with(3, guid(1), "bob", vec![login("b\u{f6}b")]),
            1
        ),
        Err(Error::Rejected(Violation::ComparisonKeyNotAscii(
            ATTR_LOGIN
        )))
    ));
}

#[test]
fn duplicate_is_refused_on_modify_and_freed_by_modify() {
    // Source: docs/46 §8.5 — modify that would duplicate a value is refused;
    // the index follows the change in the same transaction.
    let (_dir, store) = populated("unique-modify");
    create(
        &store,
        principal_with(3, guid(1), "bob", vec![login("bob")]),
        1,
    )
    .unwrap();
    assert!(matches!(
        replace(&store, 3, login("aLiCe"), 2),
        Err(Error::ValueNotUnique(ATTR_LOGIN))
    ));
    assert!(matches!(
        replace(&store, 3, spns(&["HOST/z", "HOST/A"]), 3),
        Err(Error::ValueNotUnique(ATTR_SPN))
    ));
    // A case-only change of one's own value keeps the same key.
    replace(&store, 2, login("ALICE"), 4).unwrap();
    // Alice gives up "Alice" and HOST/a; bob can take both.
    replace(&store, 2, login("carol"), 5).unwrap();
    replace(&store, 2, spns(&["HOST/b", "HOST/c"]), 6).unwrap();
    replace(&store, 3, login("Alice"), 7).unwrap();
    replace(&store, 3, spns(&["host/a"]), 8).unwrap();
    // ... but not what alice still holds.
    assert!(matches!(
        replace(&store, 3, login("Carol"), 9),
        Err(Error::ValueNotUnique(ATTR_LOGIN))
    ));
    assert!(matches!(
        replace(&store, 3, spns(&["host/a", "HOST/C"]), 10),
        Err(Error::ValueNotUnique(ATTR_SPN))
    ));
    let snap = store.snapshot().unwrap();
    assert_eq!(
        snap.lookup_unique(ATTR_LOGIN, b"alice").unwrap(),
        Some(guid(3))
    );
    assert_eq!(
        snap.lookup_unique(ATTR_LOGIN, b"CAROL").unwrap(),
        Some(guid(2))
    );
    assert_eq!(
        snap.lookup_unique(ATTR_SPN, b"HOST/A").unwrap(),
        Some(guid(3))
    );
    assert_eq!(
        snap.lookup_unique(ATTR_SPN, b"host/c").unwrap(),
        Some(guid(2))
    );
}

#[test]
fn value_is_freed_on_delete() {
    // Source: docs/46 §8.5 — removed on delete (the A-18 tombstone keeps no
    // values, so it keeps no unique entry either).
    let (_dir, store) = populated("unique-delete");
    let mut txn = store.begin_write().unwrap();
    txn.delete_object(guid(2), &origin(NODE_1, 50, 1)).unwrap();
    // Same transaction: the value is already free.
    txn.create_object(
        principal_with(3, guid(1), "bob", vec![login("alice"), spns(&["host/a"])]),
        &origin(NODE_1, 51, 2),
    )
    .unwrap();
    // The deleted object's SID is free too.
    txn.create_object(
        dirstore::NewObject {
            attributes: vec![
                (ATTR_NAME, vec![b"carol".to_vec()]),
                (ATTR_SID, vec![sid_value(1002)]),
            ],
            ..principal(4, guid(1), "carol")
        },
        &origin(NODE_1, 52, 3),
    )
    .unwrap();
    txn.commit().unwrap();
    let snap = store.snapshot().unwrap();
    assert_eq!(
        snap.lookup_unique(ATTR_LOGIN, b"Alice").unwrap(),
        Some(guid(3))
    );
    assert_eq!(
        snap.lookup_unique(ATTR_SID, &sid_value(1002)).unwrap(),
        Some(guid(4))
    );
    assert_eq!(snap.lookup_unique(ATTR_SPN, b"HOST/b").unwrap(), None);
}

#[test]
fn aborted_write_takes_no_value() {
    // Source: D136 — index entries commit with the object or not at all.
    let (_dir, store) = populated("unique-abort");
    {
        let mut txn = store.begin_write().unwrap();
        txn.create_object(
            principal_with(3, guid(1), "bob", vec![login("dave")]),
            &origin(NODE_1, 60, 1),
        )
        .unwrap();
        assert_eq!(
            txn.lookup_unique(ATTR_LOGIN, b"DAVE").unwrap(),
            Some(guid(3))
        );
        // dropped: aborted
    }
    assert_eq!(
        store
            .snapshot()
            .unwrap()
            .lookup_unique(ATTR_LOGIN, b"dave")
            .unwrap(),
        None
    );
    create(
        &store,
        principal_with(4, guid(1), "erin", vec![login("Dave")]),
        2,
    )
    .unwrap();
}

#[test]
fn lookup_unique_arguments() {
    // Source: docs/46 §8.5 (the index exists only for unique attributes);
    // docs/32 §8 (bounded input).
    let (_dir, store) = populated("unique-lookup-args");
    let snap = store.snapshot().unwrap();
    assert!(matches!(
        snap.lookup_unique(ATTR_NOTE, b"x"),
        Err(Error::Rejected(Violation::NotUnique(ATTR_NOTE)))
    ));
    assert!(matches!(
        snap.lookup_unique(AttrId(999), b"x"),
        Err(Error::Rejected(Violation::UnknownAttribute(AttrId(999))))
    ));
    assert!(matches!(
        snap.lookup_unique(ATTR_LOGIN, &[b'a'; 769]),
        Err(Error::Rejected(Violation::ValueTooLarge(ATTR_LOGIN)))
    ));
    assert!(matches!(
        snap.lookup_unique(ATTR_LOGIN, "\u{e9}".as_bytes()),
        Err(Error::Rejected(Violation::ComparisonKeyNotAscii(
            ATTR_LOGIN
        )))
    ));
    assert_eq!(snap.lookup_unique(ATTR_LOGIN, b"nobody").unwrap(), None);
}
