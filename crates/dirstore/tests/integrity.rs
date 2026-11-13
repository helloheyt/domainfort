//! At-rest integrity: records edited beneath the engine are detected.
//!
//! Source: docs/32 §3 (every record carries a MAC; direct edits of the KV
//! beneath our interface are detected and not accepted as ground truth —
//! e.g. a DB admin editing records directly, D135), §8 (tag first, then
//! bounded parse). The "edit beneath the engine" is done here exactly as that
//! threat describes: the store is closed and the redb file is opened directly
//! through redb's public API, bypassing dirstore. Table names and key layout
//! are dirstore's documented on-disk layout (src/store.rs module docs). The
//! reverse-link and unique-index tables (docs/46 §8.4, §8.5) are held to the
//! same properties: tag bound to table and key (tamper → `Tamper`), entries
//! cross-checked against the object they name (stale → `Inconsistent`), and
//! a delete or purge that meets a bad record changes nothing.

mod common;

use common::*;
use dirstore::record::{back_link_key, unique_index_key};
use dirstore::{AttributeChange, Error, IntegrityKey, RecordKind, Store, Timestamp};
use redb::{ReadableTable, TableDefinition};

type RawTable<'t> = redb::Table<'t, &'static [u8], &'static [u8]>;

const OBJECTS: &str = "dirstore.objects";
const NAME_INDEX: &str = "dirstore.name_index";
const CHILD_COUNT: &str = "dirstore.child_count";
const META: &str = "dirstore.meta";
const BACK_LINKS: &str = "dirstore.back_links";
const UNIQUE_INDEX: &str = "dirstore.unique_index";

/// Open the closed store's redb file directly and edit one table.
fn edit_beneath(dir: &TempDir, table: &str, edit: impl FnOnce(&mut RawTable<'_>)) {
    let db = redb::Database::create(dir.db_path()).expect("open raw database");
    let txn = db.begin_write().expect("raw write");
    {
        let def: TableDefinition<&'static [u8], &'static [u8]> = TableDefinition::new(table);
        let mut t = txn.open_table(def).expect("raw table");
        edit(&mut t);
    }
    txn.commit().expect("raw commit");
}

fn raw_value(t: &RawTable<'_>, key: &[u8]) -> Vec<u8> {
    t.get(key)
        .expect("raw get")
        .expect("record present")
        .value()
        .to_vec()
}

fn name_key_child(parent: dtyp::Guid, rdn: &[u8]) -> Vec<u8> {
    dirstore::record::name_index_key(Some(parent), rdn)
}

/// A store with root(1) / alice(2), bob(3); closed on return.
fn populated(test: &str) -> TempDir {
    let dir = TempDir::new(test);
    let store = open_store(&dir);
    create_all(
        &store,
        vec![
            root(1, "root"),
            principal(2, guid(1), "alice"),
            principal(3, guid(1), "bob"),
        ],
    );
    dir
}

#[test]
fn flipped_byte_in_object_body_is_tamper() {
    // Source: docs/32 §3 — a direct KV edit is detected; the record is never
    // returned or used.
    let dir = populated("flip-body");
    edit_beneath(&dir, OBJECTS, |t| {
        let key = guid(2).to_packet();
        let mut v = raw_value(t, &key);
        // Flip a byte inside the body (the RDN key area), not the tag.
        v[22] ^= 0x01;
        t.insert(key.as_slice(), v.as_slice()).unwrap();
    });
    let store = open_store(&dir);
    let snap = store.snapshot().unwrap();
    assert!(matches!(
        snap.get_object(guid(2)),
        Err(Error::Tamper(RecordKind::Object))
    ));
    // The name lookup also refuses: it authenticates the target object.
    assert!(matches!(
        snap.lookup_child(Some(guid(1)), b"alice"),
        Err(Error::Tamper(RecordKind::Object))
    ));
    // Untouched records still read fine.
    assert!(snap.get_object(guid(3)).unwrap().is_some());
    drop(snap);

    // No write may build on the tampered record.
    let mut txn = store.begin_write().unwrap();
    assert!(matches!(
        txn.modify_object(
            guid(2),
            vec![AttributeChange::Replace {
                id: ATTR_NOTE,
                values: vec![b"x".to_vec()]
            }],
            &origin(NODE_1, 1, 1)
        ),
        Err(Error::Tamper(RecordKind::Object))
    ));
    assert!(matches!(
        txn.delete_object(guid(2), &origin(NODE_1, 1, 2)),
        Err(Error::Tamper(RecordKind::Object))
    ));
    assert!(matches!(
        txn.purge_tombstones(Timestamp(u64::MAX), 0),
        Err(Error::Tamper(RecordKind::Object))
    ));
}

#[test]
fn flipped_byte_in_tag_is_tamper() {
    // Source: docs/32 §3; D135.
    let dir = populated("flip-tag");
    edit_beneath(&dir, OBJECTS, |t| {
        let key = guid(2).to_packet();
        let mut v = raw_value(t, &key);
        let last = v.len() - 1;
        v[last] ^= 0x80;
        t.insert(key.as_slice(), v.as_slice()).unwrap();
    });
    let store = open_store(&dir);
    assert!(matches!(
        store.snapshot().unwrap().get_object(guid(2)),
        Err(Error::Tamper(RecordKind::Object))
    ));
}

#[test]
fn truncated_and_empty_records_are_tamper() {
    // Source: docs/32 §3, §8 — a value that cannot carry a tag is tampered.
    let dir = populated("truncate");
    edit_beneath(&dir, OBJECTS, |t| {
        let k2 = guid(2).to_packet();
        let v = raw_value(t, &k2);
        t.insert(k2.as_slice(), &v[..10]).unwrap();
        let k3 = guid(3).to_packet();
        t.insert(k3.as_slice(), &[][..]).unwrap();
    });
    let store = open_store(&dir);
    let snap = store.snapshot().unwrap();
    assert!(matches!(
        snap.get_object(guid(2)),
        Err(Error::Tamper(RecordKind::Object))
    ));
    assert!(matches!(
        snap.get_object(guid(3)),
        Err(Error::Tamper(RecordKind::Object))
    ));
}

#[test]
fn record_moved_to_another_key_is_tamper() {
    // Source: docs/32 §3 — the tag binds the record to its key, so a valid
    // record copied under another object's GUID is refused.
    let dir = populated("swap");
    edit_beneath(&dir, OBJECTS, |t| {
        let alice = raw_value(t, &guid(2).to_packet());
        let k3 = guid(3).to_packet();
        t.insert(k3.as_slice(), alice.as_slice()).unwrap();
    });
    let store = open_store(&dir);
    assert!(matches!(
        store.snapshot().unwrap().get_object(guid(3)),
        Err(Error::Tamper(RecordKind::Object))
    ));
}

#[test]
fn redirected_name_index_entry_is_tamper() {
    // Source: docs/32 §3 — redirecting a name to another object (a
    // name-confusion attack, docs/32 §2 D64) by copying another entry's valid
    // record is refused: the tag binds the entry to its own key.
    let dir = populated("redirect");
    edit_beneath(&dir, NAME_INDEX, |t| {
        let bob = raw_value(t, &name_key_child(guid(1), b"bob"));
        let alice_key = name_key_child(guid(1), b"alice");
        t.insert(alice_key.as_slice(), bob.as_slice()).unwrap();
    });
    let store = open_store(&dir);
    assert!(matches!(
        store
            .snapshot()
            .unwrap()
            .lookup_child(Some(guid(1)), b"alice"),
        Err(Error::Tamper(RecordKind::NameIndex))
    ));
}

#[test]
fn replayed_name_index_entry_is_inconsistent() {
    // Source: docs/32 §3. A validly tagged but stale entry (saved before the
    // object was deleted, then put back beneath the engine) is caught by the
    // cross-check against the object's own record. (Replay of an older
    // version of a single record in general is NOT detectable by a
    // per-record tag — docs/questions/Q-060.)
    let dir = populated("replay");
    let mut saved = Vec::new();
    edit_beneath(&dir, NAME_INDEX, |t| {
        saved = raw_value(t, &name_key_child(guid(1), b"alice"));
    });
    {
        let store = open_store(&dir);
        let mut txn = store.begin_write().unwrap();
        txn.delete_object(guid(2), &origin(NODE_1, 50, 1)).unwrap();
        txn.commit().unwrap();
    }
    edit_beneath(&dir, NAME_INDEX, |t| {
        let key = name_key_child(guid(1), b"alice");
        t.insert(key.as_slice(), saved.as_slice()).unwrap();
    });
    let store = open_store(&dir);
    assert!(matches!(
        store
            .snapshot()
            .unwrap()
            .lookup_child(Some(guid(1)), b"alice"),
        Err(Error::Inconsistent(RecordKind::NameIndex))
    ));
    let mut txn = store.begin_write().unwrap();
    assert!(matches!(
        txn.create_object(principal(9, guid(1), "alice"), &origin(NODE_1, 60, 2)),
        Err(Error::Inconsistent(RecordKind::NameIndex))
    ));
}

#[test]
fn tampered_child_count_is_tamper() {
    // Source: docs/32 §3 — index records are tagged like objects (D136: the
    // MAC is part of every write).
    let dir = populated("count");
    edit_beneath(&dir, CHILD_COUNT, |t| {
        let key = guid(1).to_packet();
        let mut v = raw_value(t, &key);
        v[8] ^= 0x01; // inside the count
        t.insert(key.as_slice(), v.as_slice()).unwrap();
    });
    let store = open_store(&dir);
    let mut txn = store.begin_write().unwrap();
    assert!(matches!(
        txn.delete_object(guid(1), &origin(NODE_1, 1, 1)),
        Err(Error::Tamper(RecordKind::ChildCount))
    ));
    assert!(matches!(
        txn.create_object(principal(4, guid(1), "carol"), &origin(NODE_1, 1, 2)),
        Err(Error::Tamper(RecordKind::ChildCount))
    ));
}

#[test]
fn removed_child_count_is_inconsistent() {
    // Source: docs/32 §3 — a removed index record is caught where it is
    // relied on: deleting a child must decrement an existing count.
    let dir = populated("count-removed");
    edit_beneath(&dir, CHILD_COUNT, |t| {
        t.remove(guid(1).to_packet().as_slice()).unwrap();
    });
    let store = open_store(&dir);
    let mut txn = store.begin_write().unwrap();
    assert!(matches!(
        txn.delete_object(guid(2), &origin(NODE_1, 1, 1)),
        Err(Error::Inconsistent(RecordKind::ChildCount))
    ));
}

#[test]
fn foreign_record_in_object_table_is_tamper() {
    // Source: docs/32 §3 — a record the engine never wrote (here under a key
    // that is not a GUID) is refused when encountered.
    let dir = populated("foreign");
    edit_beneath(&dir, OBJECTS, |t| {
        t.insert(
            &b"abc"[..],
            &b"not a record at all, but long enough to hold a tag"[..],
        )
        .unwrap();
    });
    let store = open_store(&dir);
    let mut txn = store.begin_write().unwrap();
    assert!(matches!(
        txn.purge_tombstones(Timestamp(0), 0),
        Err(Error::Tamper(RecordKind::Object))
    ));
}

#[test]
fn wrong_integrity_key_is_tamper() {
    // Source: D135 — the tag is keyed by the injected key; another key
    // verifies nothing. Detected at open, on the meta record.
    let dir = populated("wrong-key");
    let result = Store::open(
        dir.db_path(),
        IntegrityKey::from_bytes(&KEY_B),
        test_schema(),
    );
    assert!(matches!(result, Err(Error::Tamper(RecordKind::Meta))));
    // The right key still opens it: nothing was changed by the failed open.
    let store = open_store(&dir);
    assert!(store
        .snapshot()
        .unwrap()
        .get_object(guid(2))
        .unwrap()
        .is_some());
}

#[test]
fn wrong_key_also_fails_on_every_record() {
    // Source: D135. Even with the meta check bypassed (meta record replaced
    // beneath the engine by one tagged with the wrong key), object records
    // still fail verification.
    let dir = populated("wrong-key-records");
    // Produce a meta record valid for KEY_B by creating an empty store with
    // KEY_B elsewhere and copying its meta record over.
    let other = TempDir::new("wrong-key-records-donor");
    drop(
        Store::open(
            other.db_path(),
            IntegrityKey::from_bytes(&KEY_B),
            test_schema(),
        )
        .unwrap(),
    );
    let mut meta_b = Vec::new();
    edit_beneath(&other, META, |t| meta_b = raw_value(t, b"store"));
    edit_beneath(&dir, META, |t| {
        t.insert(&b"store"[..], meta_b.as_slice()).unwrap();
    });
    let store = Store::open(
        dir.db_path(),
        IntegrityKey::from_bytes(&KEY_B),
        test_schema(),
    )
    .expect("meta now verifies under KEY_B");
    let snap = store.snapshot().unwrap();
    assert!(matches!(
        snap.get_object(guid(1)),
        Err(Error::Tamper(RecordKind::Object))
    ));
    assert!(matches!(
        snap.lookup_child(None, b"root"),
        Err(Error::Tamper(RecordKind::NameIndex))
    ));
}

#[test]
fn removed_meta_record_with_data_is_tamper() {
    // Source: docs/32 §3 — a populated store whose meta record vanished is
    // never silently adopted.
    let dir = populated("meta-removed");
    edit_beneath(&dir, META, |t| {
        t.remove(&b"store"[..]).unwrap();
    });
    assert!(matches!(
        Store::open(dir.db_path(), key_a(), test_schema()),
        Err(Error::Tamper(RecordKind::Meta))
    ));
}

// ------------------------------------- reverse links and unique index (§8) --

/// Back link id of ATTR_MEMBER (forward link id + 1, [MS-ADTS] 3.1.1.2.3).
const MEMBER_BACK: u32 = MEMBER_LINK + 1;

/// root(1); alice(2) with login "Alice"; bob(3); g1(4) = {alice, bob};
/// g2(5) = {alice}. Closed on return.
fn linked(test: &str) -> TempDir {
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
                vec![(ATTR_LOGIN, vec![b"Alice".to_vec()])],
            ),
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
    dir
}

/// The reverse-link key "member of `group`" for `target`.
fn link_key(target: u32, group: u32) -> Vec<u8> {
    back_link_key(guid(target), MEMBER_BACK, guid(group)).to_vec()
}

fn set_members(store: &Store, group: u32, refs: Vec<Vec<u8>>) {
    let mut txn = store.begin_write().unwrap();
    txn.modify_object(
        guid(group),
        vec![AttributeChange::Replace {
            id: ATTR_MEMBER,
            values: refs,
        }],
        &origin(NODE_1, 700, 70),
    )
    .unwrap();
    txn.commit().unwrap();
}

/// The store's objects 1..=5 as read now (to prove a refused write changed
/// nothing).
fn all_objects(store: &Store) -> Vec<Option<dirstore::Object>> {
    let snap = store.snapshot().unwrap();
    (1..=5).map(|i| snap.get_object(guid(i)).unwrap()).collect()
}

#[test]
fn tampered_back_link_entry_is_tamper_and_blocks_writes() {
    // Source: docs/46 §8.4 (the reverse-link table is HMAC-tagged with its own
    // kind); docs/32 §3. A flipped byte is caught on the query and by every
    // write that relies on the entry; a delete that meets it changes nothing.
    let dir = linked("bl-flip");
    edit_beneath(&dir, BACK_LINKS, |t| {
        let key = link_key(2, 4);
        let mut v = raw_value(t, &key);
        v[0] ^= 0x01; // the format byte
        t.insert(key.as_slice(), v.as_slice()).unwrap();
    });
    let store = open_store(&dir);
    let before = all_objects(&store);
    assert!(matches!(
        store
            .snapshot()
            .unwrap()
            .back_links(guid(2), ATTR_MEMBER_OF),
        Err(Error::Tamper(RecordKind::BackLink))
    ));
    let mut txn = store.begin_write().unwrap();
    // Delete of the target scans its reverse entries.
    assert!(matches!(
        txn.delete_object(guid(2), &origin(NODE_1, 1, 1)),
        Err(Error::Tamper(RecordKind::BackLink))
    ));
    // Delete of the source removes its own entries.
    assert!(matches!(
        txn.delete_object(guid(4), &origin(NODE_1, 1, 2)),
        Err(Error::Tamper(RecordKind::BackLink))
    ));
    // Modify that removes the value removes the entry.
    assert!(matches!(
        txn.modify_object(
            guid(4),
            vec![AttributeChange::Replace {
                id: ATTR_MEMBER,
                values: vec![ref_to(3)]
            }],
            &origin(NODE_1, 1, 3)
        ),
        Err(Error::Tamper(RecordKind::BackLink))
    ));
    txn.commit().unwrap();
    assert_eq!(all_objects(&store), before);
}

#[test]
fn back_link_entry_moved_to_another_key_is_tamper() {
    // Source: docs/46 §8.4; docs/32 §3 — the tag binds the entry to its key
    // (target, back link id, source): a valid entry copied under a forged key
    // ("bob is a member of g2") is refused.
    let dir = linked("bl-move");
    edit_beneath(&dir, BACK_LINKS, |t| {
        let v = raw_value(t, &link_key(2, 5));
        let forged = link_key(3, 5);
        t.insert(forged.as_slice(), v.as_slice()).unwrap();
    });
    let store = open_store(&dir);
    assert!(matches!(
        store
            .snapshot()
            .unwrap()
            .back_links(guid(3), ATTR_MEMBER_OF),
        Err(Error::Tamper(RecordKind::BackLink))
    ));
}

#[test]
fn replayed_back_link_entry_is_inconsistent() {
    // Source: docs/46 §8.4; docs/32 §3; Q-060. An entry saved while alice was
    // in g2, put back after she was removed, is validly tagged but stale: the
    // cross-check against g2's own record catches it — on the query, on a
    // delete of the target (which changes nothing), and on a purge.
    let dir = linked("bl-replay");
    let mut saved = Vec::new();
    edit_beneath(&dir, BACK_LINKS, |t| saved = raw_value(t, &link_key(2, 5)));
    {
        let store = open_store(&dir);
        set_members(&store, 5, vec![]);
    }
    edit_beneath(&dir, BACK_LINKS, |t| {
        t.insert(link_key(2, 5).as_slice(), saved.as_slice())
            .unwrap();
    });
    let store = open_store(&dir);
    let before = all_objects(&store);
    assert!(matches!(
        store
            .snapshot()
            .unwrap()
            .back_links(guid(2), ATTR_MEMBER_OF),
        Err(Error::Inconsistent(RecordKind::BackLink))
    ));
    let mut txn = store.begin_write().unwrap();
    assert!(matches!(
        txn.delete_object(guid(2), &origin(NODE_1, 1, 1)),
        Err(Error::Inconsistent(RecordKind::BackLink))
    ));
    txn.commit().unwrap();
    assert_eq!(all_objects(&store), before);
}

#[test]
fn stale_back_link_to_a_tombstone_blocks_purge() {
    // Source: docs/46 §8.4 (a deleted object's references are all removed);
    // docs/29 §5 (purge). An entry saved before bob's delete and put back
    // targets a tombstone; a purge meeting it removes nothing.
    let dir = linked("bl-purge");
    let mut saved = Vec::new();
    edit_beneath(&dir, BACK_LINKS, |t| saved = raw_value(t, &link_key(3, 4)));
    {
        let store = open_store(&dir);
        let mut txn = store.begin_write().unwrap();
        txn.delete_object(guid(3), &origin(NODE_1, 10, 1)).unwrap();
        txn.commit().unwrap();
    }
    edit_beneath(&dir, BACK_LINKS, |t| {
        t.insert(link_key(3, 4).as_slice(), saved.as_slice())
            .unwrap();
    });
    let store = open_store(&dir);
    let mut txn = store.begin_write().unwrap();
    assert!(matches!(
        txn.purge_tombstones(Timestamp(u64::MAX), 0),
        Err(Error::Inconsistent(RecordKind::BackLink))
    ));
    txn.commit().unwrap();
    assert!(store
        .snapshot()
        .unwrap()
        .get_tombstone(guid(3))
        .unwrap()
        .is_some());
}

#[test]
fn removed_back_link_entry_is_inconsistent_where_relied_on() {
    // Source: docs/46 §8.4; docs/32 §3; Q-060 — a removed entry is caught
    // where the engine relies on it: removing the forward value, or deleting
    // its source, must remove an existing entry.
    let dir = linked("bl-removed");
    edit_beneath(&dir, BACK_LINKS, |t| {
        t.remove(link_key(3, 4).as_slice()).unwrap();
    });
    let store = open_store(&dir);
    let before = all_objects(&store);
    let mut txn = store.begin_write().unwrap();
    assert!(matches!(
        txn.modify_object(
            guid(4),
            vec![AttributeChange::Replace {
                id: ATTR_MEMBER,
                values: vec![ref_to(2)]
            }],
            &origin(NODE_1, 1, 1)
        ),
        Err(Error::Inconsistent(RecordKind::BackLink))
    ));
    assert!(matches!(
        txn.delete_object(guid(4), &origin(NODE_1, 1, 2)),
        Err(Error::Inconsistent(RecordKind::BackLink))
    ));
    txn.commit().unwrap();
    assert_eq!(all_objects(&store), before);
}

#[test]
fn tampered_unique_entry_is_tamper_and_blocks_writes() {
    // Source: docs/46 §8.5 (integrity-tagged index); docs/32 §3. A delete
    // that meets the bad entry changes nothing.
    let dir = linked("uq-flip");
    let key = unique_index_key(ATTR_LOGIN, b"alice");
    edit_beneath(&dir, UNIQUE_INDEX, |t| {
        let mut v = raw_value(t, &key);
        v[5] ^= 0x01; // inside the owner GUID
        t.insert(key.as_slice(), v.as_slice()).unwrap();
    });
    let store = open_store(&dir);
    let before = all_objects(&store);
    assert!(matches!(
        store
            .snapshot()
            .unwrap()
            .lookup_unique(ATTR_LOGIN, b"ALICE"),
        Err(Error::Tamper(RecordKind::UniqueIndex))
    ));
    let mut txn = store.begin_write().unwrap();
    assert!(matches!(
        txn.create_object(
            principal_with(
                9,
                guid(1),
                "mallory",
                vec![(ATTR_LOGIN, vec![b"alice".to_vec()])]
            ),
            &origin(NODE_1, 1, 1)
        ),
        Err(Error::Tamper(RecordKind::UniqueIndex))
    ));
    assert!(matches!(
        txn.delete_object(guid(2), &origin(NODE_1, 1, 2)),
        Err(Error::Tamper(RecordKind::UniqueIndex))
    ));
    txn.commit().unwrap();
    assert_eq!(all_objects(&store), before);
}

#[test]
fn unique_entry_moved_to_another_key_is_tamper() {
    // Source: docs/46 §8.5; docs/32 §3 — the tag binds the entry to
    // (attribute, comparison key): alice's entry copied under the key of
    // another value is refused.
    let dir = linked("uq-move");
    edit_beneath(&dir, UNIQUE_INDEX, |t| {
        let v = raw_value(t, &unique_index_key(ATTR_LOGIN, b"alice"));
        let forged = unique_index_key(ATTR_LOGIN, b"root-admin");
        t.insert(forged.as_slice(), v.as_slice()).unwrap();
    });
    let store = open_store(&dir);
    assert!(matches!(
        store
            .snapshot()
            .unwrap()
            .lookup_unique(ATTR_LOGIN, b"root-admin"),
        Err(Error::Tamper(RecordKind::UniqueIndex))
    ));
}

#[test]
fn replayed_unique_entry_is_inconsistent() {
    // Source: docs/46 §8.5; docs/32 §3; Q-060. Alice's entry, saved before
    // she changed her login, is validly tagged but stale once put back: the
    // cross-check against her record catches it on lookup and on a create
    // that would take the value.
    let dir = linked("uq-replay");
    let key = unique_index_key(ATTR_LOGIN, b"alice");
    let mut saved = Vec::new();
    edit_beneath(&dir, UNIQUE_INDEX, |t| saved = raw_value(t, &key));
    {
        let store = open_store(&dir);
        let mut txn = store.begin_write().unwrap();
        txn.modify_object(
            guid(2),
            vec![AttributeChange::Replace {
                id: ATTR_LOGIN,
                values: vec![b"carol".to_vec()],
            }],
            &origin(NODE_1, 20, 1),
        )
        .unwrap();
        txn.commit().unwrap();
    }
    edit_beneath(&dir, UNIQUE_INDEX, |t| {
        t.insert(key.as_slice(), saved.as_slice()).unwrap();
    });
    let store = open_store(&dir);
    assert!(matches!(
        store
            .snapshot()
            .unwrap()
            .lookup_unique(ATTR_LOGIN, b"alice"),
        Err(Error::Inconsistent(RecordKind::UniqueIndex))
    ));
    let mut txn = store.begin_write().unwrap();
    assert!(matches!(
        txn.create_object(
            principal_with(
                9,
                guid(1),
                "mallory",
                vec![(ATTR_LOGIN, vec![b"Alice".to_vec()])]
            ),
            &origin(NODE_1, 21, 2)
        ),
        Err(Error::Inconsistent(RecordKind::UniqueIndex))
    ));
}

#[test]
fn removed_unique_entry_is_inconsistent_on_delete() {
    // Source: docs/46 §8.5; docs/32 §3; Q-060 — a removed entry is caught
    // where it is relied on: deleting the owner must remove an existing entry
    // naming it; the refused delete changes nothing.
    let dir = linked("uq-removed");
    edit_beneath(&dir, UNIQUE_INDEX, |t| {
        t.remove(unique_index_key(ATTR_SID, &sid_value(1003)).as_slice())
            .unwrap();
    });
    let store = open_store(&dir);
    let before = all_objects(&store);
    let mut txn = store.begin_write().unwrap();
    assert!(matches!(
        txn.delete_object(guid(3), &origin(NODE_1, 1, 1)),
        Err(Error::Inconsistent(RecordKind::UniqueIndex))
    ));
    txn.commit().unwrap();
    assert_eq!(all_objects(&store), before);
}

#[test]
fn removed_meta_record_with_only_index_records_is_tamper() {
    // Source: docs/32 §3 — a store whose meta record vanished is never
    // silently adopted, whichever tables still hold records.
    let dir = linked("meta-removed-index");
    edit_beneath(&dir, OBJECTS, |t| {
        let keys: Vec<Vec<u8>> = t
            .iter()
            .unwrap()
            .map(|e| e.unwrap().0.value().to_vec())
            .collect();
        for k in keys {
            t.remove(k.as_slice()).unwrap();
        }
    });
    for table in [NAME_INDEX, CHILD_COUNT] {
        edit_beneath(&dir, table, |t| {
            let keys: Vec<Vec<u8>> = t
                .iter()
                .unwrap()
                .map(|e| e.unwrap().0.value().to_vec())
                .collect();
            for k in keys {
                t.remove(k.as_slice()).unwrap();
            }
        });
    }
    edit_beneath(&dir, META, |t| {
        t.remove(&b"store"[..]).unwrap();
    });
    assert!(matches!(
        Store::open(dir.db_path(), key_a(), test_schema()),
        Err(Error::Tamper(RecordKind::Meta))
    ));
}
