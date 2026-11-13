//! Named counters (task A1): the persistent counter behind RIDs and the
//! change-seq.
//!
//! Source: docs/51 §8.3 (R51-16) and owner decision A-75 / Q-293 — one named
//! counter in dirstore, read and advanced in the same write transaction as
//! the object creation (only a commit consumes a value), never decreasing,
//! refusing when exhausted, the same mechanism for the RID and the change-seq
//! counter (docs/29 §2); docs/51 §4.3 step 5 (counters created at
//! provisioning, in the same transaction as the domain objects); [MS-SAMR]
//! v20260427 3.1.1.9.2 ("maintain a counter and increment the counter"),
//! 3.1.1.9.2.1 item 1.2 and 3.1.1.9.2.2 item 1.2 (a value "successfully
//! committed in a transaction MUST NOT ever be used again"), 3.1.1.9.2.2
//! item 2 (refuse when no value can be generated) — opened in-session from
//! the pinned copy; docs/32 §3 (D135: an edit beneath the engine is
//! detected), §7 (D136: one atomic transaction).
//!
//! Test data is hand-made (tests/common). The RID bounds `[1101,
//! 0x3FFFFFFF)` are those of docs/51 §8.3 (derived there from [MS-ADTS]
//! 6.1.5.3 and [MS-DRSR] 4.1.10.5.12); dirstore itself does not know them
//! (R46-1). Edits "beneath the engine" open the closed store's redb file
//! through redb's public API, as tests/integrity.rs does; the key layout is
//! dirstore's documented on-disk layout (src/store.rs, src/record.rs).

mod common;

use common::*;
use dirstore::record::counter_key;
use dirstore::{CounterState, Error, NewObject, RecordKind, Violation, MAC_LEN};
use dtyp::Guid;
use redb::{ReadableTable, TableDefinition};

type RawTable<'t> = redb::Table<'t, &'static [u8], &'static [u8]>;

const META: &str = "dirstore.meta";
const RID: &str = "rid";
const CHANGE_SEQ: &str = "change-seq";
/// docs/51 §8.3: the RID range.
const RID_FIRST: u64 = 1101;
const RID_END: u64 = 0x3FFF_FFFF;

/// Open the closed store's redb file directly and edit the meta table.
fn edit_meta(dir: &TempDir, edit: impl FnOnce(&mut RawTable<'_>)) {
    let db = redb::Database::create(dir.db_path()).expect("open raw database");
    let txn = db.begin_write().expect("raw write");
    {
        let def: TableDefinition<&'static [u8], &'static [u8]> = TableDefinition::new(META);
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

fn key_of(name: &str) -> Vec<u8> {
    counter_key(name).expect("valid counter name")
}

fn state(first_value: u64, next_value: u64, end_exclusive: u64) -> CounterState {
    CounterState {
        first_value,
        next_value,
        end_exclusive,
    }
}

/// A principal under `parent` whose objectSid is S-1-5-21-1-2-3-`rid`.
fn principal_with_rid(id: u32, parent: Guid, name: &str, rid: u64) -> NewObject {
    NewObject {
        guid: guid(id),
        parent: Some(parent),
        classes: PRINCIPAL_CHAIN.to_vec(),
        attributes: vec![
            (ATTR_NAME, vec![name.as_bytes().to_vec()]),
            (
                ATTR_SID,
                vec![sid_value(u32::try_from(rid).expect("RID fits 32 bits"))],
            ),
        ],
    }
}

/// A store holding the RID counter with 1101 already taken (next = 1102);
/// closed on return.
fn rid_counter_store(test: &str) -> TempDir {
    let dir = TempDir::new(test);
    let store = open_store(&dir);
    let mut txn = store.begin_write().unwrap();
    txn.create_counter(RID, RID_FIRST, RID_END).unwrap();
    assert_eq!(txn.take_counter_value(RID).unwrap(), RID_FIRST);
    txn.commit().unwrap();
    dir
}

#[test]
fn values_rise_across_commits_and_reopen() {
    // Source: docs/51 §8.3 / A-75 (never decreases, persistent); [MS-SAMR]
    // 3.1.1.9.2.1 item 1.2 (a committed value is never used again).
    let dir = TempDir::new("counter-monotonic");
    {
        let store = open_store(&dir);
        let mut txn = store.begin_write().unwrap();
        txn.create_counter(RID, RID_FIRST, RID_END).unwrap();
        assert_eq!(
            txn.counter(RID).unwrap(),
            Some(state(RID_FIRST, RID_FIRST, RID_END))
        );
        assert_eq!(txn.take_counter_value(RID).unwrap(), 1101);
        txn.commit().unwrap();

        let mut txn = store.begin_write().unwrap();
        assert_eq!(txn.take_counter_value(RID).unwrap(), 1102);
        assert_eq!(txn.take_counter_value(RID).unwrap(), 1103);
        txn.commit().unwrap();
    }
    let store = open_store(&dir);
    assert_eq!(
        store.snapshot().unwrap().counter(RID).unwrap(),
        Some(state(RID_FIRST, 1104, RID_END))
    );
    let mut txn = store.begin_write().unwrap();
    assert_eq!(txn.take_counter_value(RID).unwrap(), 1104);
    txn.commit().unwrap();
    drop(store);
    let store = open_store(&dir);
    let mut txn = store.begin_write().unwrap();
    assert_eq!(txn.take_counter_value(RID).unwrap(), 1105);
}

#[test]
fn aborted_or_dropped_take_is_not_consumed() {
    // Source: A-75 ("only a commit consumes a value"); D136 (abort / drop
    // leave no trace); [MS-SAMR] 3.1.1.9.2.1 item 1.2 binds only values
    // "successfully committed in a transaction".
    let dir = TempDir::new("counter-abort");
    {
        let store = open_store(&dir);
        let mut txn = store.begin_write().unwrap();
        txn.create_counter(RID, RID_FIRST, RID_END).unwrap();
        txn.commit().unwrap();

        let mut txn = store.begin_write().unwrap();
        assert_eq!(txn.take_counter_value(RID).unwrap(), 1101);
        assert_eq!(txn.take_counter_value(RID).unwrap(), 1102);
        txn.abort().unwrap();

        {
            let mut txn = store.begin_write().unwrap();
            assert_eq!(txn.take_counter_value(RID).unwrap(), 1101);
            // dropped without commit
        }
        assert_eq!(
            store.snapshot().unwrap().counter(RID).unwrap(),
            Some(state(RID_FIRST, RID_FIRST, RID_END))
        );
    }
    let store = open_store(&dir);
    let mut txn = store.begin_write().unwrap();
    assert_eq!(txn.take_counter_value(RID).unwrap(), 1101);
    txn.commit().unwrap();
    let mut txn = store.begin_write().unwrap();
    assert_eq!(txn.take_counter_value(RID).unwrap(), 1102);
}

#[test]
fn exhaustion_refuses_and_changes_nothing() {
    // Source: A-75 ("exhaustion ⇒ refusal", fail closed); [MS-SAMR]
    // 3.1.1.9.2.2 item 2 (no value can be generated ⇒ error).
    let dir = TempDir::new("counter-exhausted");
    let store = open_store(&dir);
    let mut txn = store.begin_write().unwrap();
    txn.create_counter("small", 5, 8).unwrap();
    txn.commit().unwrap();

    let mut txn = store.begin_write().unwrap();
    assert_eq!(txn.take_counter_value("small").unwrap(), 5);
    assert_eq!(txn.take_counter_value("small").unwrap(), 6);
    // The last value is end_exclusive - 1 ...
    assert_eq!(txn.take_counter_value("small").unwrap(), 7);
    // ... and then the counter refuses, with no change.
    assert!(matches!(
        txn.take_counter_value("small"),
        Err(Error::CounterExhausted)
    ));
    let s = txn.counter("small").unwrap().unwrap();
    assert_eq!(s, state(5, 8, 8));
    assert!(s.is_exhausted());
    assert_eq!(s.remaining(), 0);
    // The refusal did not poison the transaction.
    txn.commit().unwrap();

    let mut txn = store.begin_write().unwrap();
    assert!(matches!(
        txn.take_counter_value("small"),
        Err(Error::CounterExhausted)
    ));
    assert_eq!(txn.counter("small").unwrap(), Some(state(5, 8, 8)));
    drop(txn);

    // The RID range ends below 0x3FFFFFFF: 0x3FFFFFFE is the last RID.
    let mut txn = store.begin_write().unwrap();
    txn.create_counter("rid-top", RID_END - 1, RID_END).unwrap();
    assert_eq!(txn.take_counter_value("rid-top").unwrap(), RID_END - 1);
    assert!(matches!(
        txn.take_counter_value("rid-top"),
        Err(Error::CounterExhausted)
    ));

    // At the top of u64 the advance is checked: no wrap, no panic.
    txn.create_counter("u64-top", u64::MAX - 2, u64::MAX)
        .unwrap();
    assert_eq!(txn.take_counter_value("u64-top").unwrap(), u64::MAX - 2);
    assert_eq!(txn.take_counter_value("u64-top").unwrap(), u64::MAX - 1);
    assert!(matches!(
        txn.take_counter_value("u64-top"),
        Err(Error::CounterExhausted)
    ));
    assert_eq!(
        txn.counter("u64-top").unwrap(),
        Some(state(u64::MAX - 2, u64::MAX, u64::MAX))
    );

    // A one-value range.
    txn.create_counter("one", 0, 1).unwrap();
    assert_eq!(txn.take_counter_value("one").unwrap(), 0);
    assert!(matches!(
        txn.take_counter_value("one"),
        Err(Error::CounterExhausted)
    ));
    txn.commit().unwrap();
}

#[test]
fn duplicate_create_is_refused_and_never_resets() {
    // Source: A-75 (never decreases — so never re-created or reset).
    let dir = TempDir::new("counter-duplicate");
    let store = open_store(&dir);
    let mut txn = store.begin_write().unwrap();
    txn.create_counter(RID, RID_FIRST, RID_END).unwrap();
    assert!(matches!(
        txn.create_counter(RID, RID_FIRST, RID_END),
        Err(Error::CounterExists)
    ));
    assert_eq!(txn.take_counter_value(RID).unwrap(), 1101);
    assert_eq!(txn.take_counter_value(RID).unwrap(), 1102);
    txn.commit().unwrap();

    let mut txn = store.begin_write().unwrap();
    for (first, end) in [(RID_FIRST, RID_END), (1, 2), (0, u64::MAX)] {
        assert!(matches!(
            txn.create_counter(RID, first, end),
            Err(Error::CounterExists)
        ));
    }
    // Still usable, and the counter kept its place.
    assert_eq!(
        txn.counter(RID).unwrap(),
        Some(state(RID_FIRST, 1103, RID_END))
    );
    assert_eq!(txn.take_counter_value(RID).unwrap(), 1103);
    txn.commit().unwrap();
}

#[test]
fn empty_or_inverted_range_is_refused() {
    // Source: A-75 (create refused if the bounds are empty or inverted).
    let dir = TempDir::new("counter-range");
    let store = open_store(&dir);
    let mut txn = store.begin_write().unwrap();
    for (first, end) in [
        (5, 5),
        (6, 5),
        (0, 0),
        (u64::MAX, u64::MAX),
        (u64::MAX, 0),
        (RID_END, RID_FIRST),
    ] {
        assert!(matches!(
            txn.create_counter(RID, first, end),
            Err(Error::Rejected(Violation::EmptyCounterRange))
        ));
        assert_eq!(txn.counter(RID).unwrap(), None);
    }
    // Nothing was written and the transaction is still usable.
    txn.create_counter(RID, RID_FIRST, RID_END).unwrap();
    txn.commit().unwrap();
    assert_eq!(
        store.snapshot().unwrap().counter(RID).unwrap(),
        Some(state(RID_FIRST, RID_FIRST, RID_END))
    );
}

#[test]
fn invalid_names_are_refused_everywhere() {
    // Source: MAX_COUNTER_NAME_LEN documentation (bounded, validated
    // identifier; docs/32 §8; Q-330 item 2).
    let dir = TempDir::new("counter-names");
    let store = open_store(&dir);
    let long = "a".repeat(dirstore::MAX_COUNTER_NAME_LEN + 1);
    let mut txn = store.begin_write().unwrap();
    for bad in [
        "",
        "RID",
        "change seq",
        "a/b",
        "counter:rid",
        "caf\u{e9}",
        long.as_str(),
    ] {
        assert!(matches!(
            txn.create_counter(bad, 1, 2),
            Err(Error::Rejected(Violation::InvalidCounterName))
        ));
        assert!(matches!(
            txn.take_counter_value(bad),
            Err(Error::Rejected(Violation::InvalidCounterName))
        ));
        assert!(matches!(
            txn.counter(bad),
            Err(Error::Rejected(Violation::InvalidCounterName))
        ));
        assert!(matches!(
            store.snapshot().unwrap().counter(bad),
            Err(Error::Rejected(Violation::InvalidCounterName))
        ));
    }
    let longest = "a".repeat(dirstore::MAX_COUNTER_NAME_LEN);
    for good in [RID, CHANGE_SEQ, "a.b_c-9", "store", longest.as_str()] {
        txn.create_counter(good, 1, 2).unwrap();
        assert_eq!(txn.take_counter_value(good).unwrap(), 1);
    }
    txn.commit().unwrap();
    // A counter named "store" never touches the store record: the store
    // still opens under its key.
    drop(store);
    let store = open_store(&dir);
    assert_eq!(
        store.snapshot().unwrap().counter("store").unwrap(),
        Some(state(1, 2, 2))
    );
}

#[test]
fn unknown_name_is_refused_and_never_created_implicitly() {
    // Source: A-75 (take on a missing counter is an error, no change);
    // docs/51 §4.3 step 5 (counters are created at provisioning only).
    let dir = TempDir::new("counter-unknown");
    let store = open_store(&dir);
    let mut txn = store.begin_write().unwrap();
    assert!(matches!(
        txn.take_counter_value(RID),
        Err(Error::NoSuchCounter)
    ));
    assert_eq!(txn.counter(RID).unwrap(), None);
    assert_eq!(store.snapshot().unwrap().counter(RID).unwrap(), None);
    // Still usable.
    txn.create_counter(CHANGE_SEQ, 1, u64::MAX).unwrap();
    txn.commit().unwrap();
    let snap = store.snapshot().unwrap();
    assert_eq!(snap.counter(RID).unwrap(), None);
    assert!(snap.counter(CHANGE_SEQ).unwrap().is_some());
}

#[test]
fn altered_counter_value_is_tamper_and_never_reset() {
    // Source: docs/32 §3 (D135) — a direct edit beneath the engine is
    // detected; A-75 (no silent reset). The "rollback in place" here lowers
    // the stored next value (1102 -> 1101) without the integrity key.
    for (case, offset, new_byte) in [
        ("counter-lowered", 16usize, Some(0x4Du8)), // 1102 = 0x044E -> 0x044D
        ("counter-raised", 16, Some(0xFF)),
        ("counter-end", 24, Some(0x00)),
        ("counter-flip-tag", 25 + MAC_LEN - 1, None),
    ] {
        let dir = rid_counter_store(case);
        edit_meta(&dir, |t| {
            let key = key_of(RID);
            let mut v = raw_value(t, &key);
            assert_eq!(v.len(), 25 + MAC_LEN);
            match new_byte {
                Some(b) => {
                    assert_ne!(v[offset], b);
                    v[offset] = b;
                }
                None => v[offset] ^= 0x01,
            }
            t.insert(key.as_slice(), v.as_slice()).unwrap();
        });
        let store = open_store(&dir);
        assert!(matches!(
            store.snapshot().unwrap().counter(RID),
            Err(Error::Tamper(RecordKind::Counter))
        ));
        let mut txn = store.begin_write().unwrap();
        assert!(matches!(
            txn.take_counter_value(RID),
            Err(Error::Tamper(RecordKind::Counter))
        ));
        assert!(matches!(
            txn.counter(RID),
            Err(Error::Tamper(RecordKind::Counter))
        ));
        // A tampered record is never overwritten by a fresh counter.
        assert!(matches!(
            txn.create_counter(RID, RID_FIRST, RID_END),
            Err(Error::Tamper(RecordKind::Counter))
        ));
    }
}

#[test]
fn truncated_or_empty_counter_record_is_tamper() {
    // Source: docs/32 §3, §8 — a value that cannot carry a tag is tampered.
    for (case, len) in [
        ("counter-trunc-body", 25 + MAC_LEN - 1),
        ("counter-trunc-tag", MAC_LEN),
        ("counter-empty", 0),
    ] {
        let dir = rid_counter_store(case);
        edit_meta(&dir, |t| {
            let key = key_of(RID);
            let v = raw_value(t, &key);
            t.insert(key.as_slice(), &v[..len]).unwrap();
        });
        let store = open_store(&dir);
        let mut txn = store.begin_write().unwrap();
        assert!(matches!(
            txn.take_counter_value(RID),
            Err(Error::Tamper(RecordKind::Counter))
        ));
    }
}

#[test]
fn counter_record_moved_or_swapped_is_tamper() {
    // Source: D135 — the tag binds the record to its key and its kind: one
    // counter's record cannot be moved to another name, and the store record
    // and a counter record (same table, distinct kinds) cannot stand in for
    // each other.
    let dir = rid_counter_store("counter-moved");
    edit_meta(&dir, |t| {
        let v = raw_value(t, &key_of(RID));
        t.insert(key_of(CHANGE_SEQ).as_slice(), v.as_slice())
            .unwrap();
    });
    let store = open_store(&dir);
    let mut txn = store.begin_write().unwrap();
    assert!(matches!(
        txn.take_counter_value(CHANGE_SEQ),
        Err(Error::Tamper(RecordKind::Counter))
    ));
    // The genuine record is unaffected.
    assert_eq!(txn.take_counter_value(RID).unwrap(), 1102);
    drop(txn);
    drop(store);

    let dir = rid_counter_store("counter-swapped");
    edit_meta(&dir, |t| {
        let store_record = raw_value(t, b"store");
        t.insert(key_of(RID).as_slice(), store_record.as_slice())
            .unwrap();
    });
    let store = open_store(&dir);
    let mut txn = store.begin_write().unwrap();
    assert!(matches!(
        txn.take_counter_value(RID),
        Err(Error::Tamper(RecordKind::Counter))
    ));
    drop(txn);
    drop(store);

    let dir = rid_counter_store("counter-as-store");
    edit_meta(&dir, |t| {
        let counter_record = raw_value(t, &key_of(RID));
        t.insert(b"store".as_slice(), counter_record.as_slice())
            .unwrap();
    });
    assert!(matches!(
        dirstore::Store::open(dir.db_path(), key_a(), test_schema()),
        Err(Error::Tamper(RecordKind::Meta))
    ));
}

#[test]
fn removed_counter_record_is_refused_not_recreated() {
    // Source: A-75 (no silent reset: a take never creates a counter);
    // docs/32 §3. Removal itself is not detectable by a per-record tag
    // (Q-060 / P-7; Q-330 item 3): the caller must not answer
    // `NoSuchCounter` at run time by creating the counter again.
    let dir = rid_counter_store("counter-removed");
    edit_meta(&dir, |t| {
        t.remove(key_of(RID).as_slice()).unwrap();
    });
    let store = open_store(&dir);
    let mut txn = store.begin_write().unwrap();
    assert!(matches!(
        txn.take_counter_value(RID),
        Err(Error::NoSuchCounter)
    ));
    assert_eq!(txn.counter(RID).unwrap(), None);
}

#[test]
fn removed_store_record_with_only_counters_is_tamper() {
    // Source: D135 — a database whose meta record is gone while it still
    // holds records (here only a counter, in the meta table itself) was
    // edited beneath us; it is never adopted under a new key.
    let dir = TempDir::new("counter-no-store-record");
    {
        let store = open_store(&dir);
        let mut txn = store.begin_write().unwrap();
        txn.create_counter(RID, RID_FIRST, RID_END).unwrap();
        txn.commit().unwrap();
    }
    edit_meta(&dir, |t| {
        t.remove(b"store".as_slice()).unwrap();
    });
    assert!(matches!(
        dirstore::Store::open(dir.db_path(), key_a(), test_schema()),
        Err(Error::Tamper(RecordKind::Meta))
    ));
}

#[test]
fn wrong_integrity_key_never_reaches_a_counter() {
    // Source: D135 — the store record is checked at open under the given key.
    let dir = rid_counter_store("counter-wrong-key");
    let other = dirstore::IntegrityKey::from_bytes(&KEY_B);
    assert!(matches!(
        dirstore::Store::open(dir.db_path(), other, test_schema()),
        Err(Error::Tamper(RecordKind::Meta))
    ));
}

#[test]
fn replayed_counter_record_is_the_known_limit_and_objectsid_stays_unique() {
    // Source: Q-060 / P-7 (a per-record tag cannot detect an older, validly
    // tagged version put back) and docs/51 §8.3 (the objectSid unique index
    // is a second guard for live objects; docs/46 §8.5). This test documents
    // the limit (Q-330 item 3): the replayed counter re-issues a RID, and the
    // unique index refuses the duplicate SID while its holder is live.
    let dir = TempDir::new("counter-replayed");
    {
        let store = open_store(&dir);
        create_all(&store, vec![root(1, "root")]);
        let mut txn = store.begin_write().unwrap();
        txn.create_counter(RID, RID_FIRST, RID_END).unwrap();
        txn.commit().unwrap();
    }
    let mut old_record = Vec::new();
    edit_meta(&dir, |t| old_record = raw_value(t, &key_of(RID)));
    {
        let store = open_store(&dir);
        let mut txn = store.begin_write().unwrap();
        let rid = txn.take_counter_value(RID).unwrap();
        txn.create_object(
            principal_with_rid(2, guid(1), "alice", rid),
            &origin(NODE_1, 10, 1),
        )
        .unwrap();
        txn.commit().unwrap();
    }
    edit_meta(&dir, |t| {
        t.insert(key_of(RID).as_slice(), old_record.as_slice())
            .unwrap();
    });
    let store = open_store(&dir);
    let mut txn = store.begin_write().unwrap();
    let rid = txn.take_counter_value(RID).unwrap();
    assert_eq!(rid, RID_FIRST, "replay is not detectable by the tag (P-7)");
    assert!(matches!(
        txn.create_object(
            principal_with_rid(3, guid(1), "bob", rid),
            &origin(NODE_1, 11, 2)
        ),
        Err(Error::ValueNotUnique(ATTR_SID))
    ));
}

#[test]
fn two_counters_are_independent() {
    // Source: A-75 — one mechanism serves the RID counter and the change-seq
    // counter (docs/29 §2), each with its own state.
    let dir = TempDir::new("counter-independent");
    let store = open_store(&dir);
    let mut txn = store.begin_write().unwrap();
    txn.create_counter(RID, RID_FIRST, RID_END).unwrap();
    txn.create_counter(CHANGE_SEQ, 1, u64::MAX).unwrap();
    assert_eq!(txn.take_counter_value(CHANGE_SEQ).unwrap(), 1);
    assert_eq!(txn.take_counter_value(RID).unwrap(), 1101);
    assert_eq!(txn.take_counter_value(CHANGE_SEQ).unwrap(), 2);
    assert_eq!(txn.take_counter_value(CHANGE_SEQ).unwrap(), 3);
    assert_eq!(txn.take_counter_value(RID).unwrap(), 1102);
    txn.commit().unwrap();

    // Exhausting one leaves the other untouched.
    let mut txn = store.begin_write().unwrap();
    txn.create_counter("tiny", 7, 8).unwrap();
    assert_eq!(txn.take_counter_value("tiny").unwrap(), 7);
    assert!(matches!(
        txn.take_counter_value("tiny"),
        Err(Error::CounterExhausted)
    ));
    assert_eq!(txn.take_counter_value(RID).unwrap(), 1103);
    txn.commit().unwrap();

    let snap = store.snapshot().unwrap();
    assert_eq!(
        snap.counter(RID).unwrap(),
        Some(state(RID_FIRST, 1104, RID_END))
    );
    assert_eq!(
        snap.counter(CHANGE_SEQ).unwrap(),
        Some(state(1, 4, u64::MAX))
    );
    assert_eq!(snap.counter("tiny").unwrap(), Some(state(7, 8, 8)));
}

#[test]
fn many_takes_are_strictly_increasing_and_contiguous() {
    // Source: [MS-SAMR] 3.1.1.9.2 (a counter incremented for each value
    // issued; committed values never reused, 3.1.1.9.2.1 item 1.2) and A-75
    // (only a commit consumes). Property-style: rounds of 1..=7 takes, every
    // third round aborted (alternately dropped), with a reopen half-way;
    // the committed values must be exactly first, first+1, ... in order, and
    // an aborted round's values must be issued again.
    let dir = TempDir::new("counter-property");
    let mut committed: Vec<u64> = Vec::new();
    let mut store = open_store(&dir);
    {
        let mut txn = store.begin_write().unwrap();
        txn.create_counter(RID, RID_FIRST, RID_END).unwrap();
        txn.commit().unwrap();
    }
    let mut expected_next = RID_FIRST;
    for round in 0u64..120 {
        if round == 60 {
            drop(store);
            store = open_store(&dir);
        }
        let takes = (round % 7) + 1;
        let mut txn = store.begin_write().unwrap();
        let mut taken = Vec::new();
        for _ in 0..takes {
            taken.push(txn.take_counter_value(RID).unwrap());
        }
        // Inside a transaction: contiguous from the committed position.
        let want: Vec<u64> = (expected_next..expected_next + takes).collect();
        assert_eq!(taken, want);
        match round % 3 {
            0 if round % 2 == 0 => txn.abort().unwrap(),
            0 => drop(txn),
            _ => {
                txn.commit().unwrap();
                committed.extend(&taken);
                expected_next += takes;
            }
        }
        assert_eq!(
            store.snapshot().unwrap().counter(RID).unwrap(),
            Some(state(RID_FIRST, expected_next, RID_END))
        );
    }
    assert!(committed.windows(2).all(|w| w[0] < w[1]));
    let n = u64::try_from(committed.len()).unwrap();
    assert_eq!(committed, (RID_FIRST..RID_FIRST + n).collect::<Vec<_>>());
}

#[test]
fn a_take_and_the_object_using_it_commit_together() {
    // Source: docs/51 §8.3 (read and advanced in the creation's own
    // WriteTxn; objectSid = domain SID || RID) and §4.3 step 5; A-75; D136
    // (one atomic transaction). The change-seq counter supplies the
    // Origin's origin_seq in the same transaction (docs/29 §2).
    let dir = TempDir::new("counter-with-object");
    let store = open_store(&dir);
    {
        // Provisioning shape: the root and both counters in one transaction.
        let mut txn = store.begin_write().unwrap();
        txn.create_counter(RID, RID_FIRST, RID_END).unwrap();
        txn.create_counter(CHANGE_SEQ, 1, u64::MAX).unwrap();
        let seq = txn.take_counter_value(CHANGE_SEQ).unwrap();
        txn.create_object(root(1, "root"), &origin(NODE_1, 1, seq))
            .unwrap();
        txn.commit().unwrap();
    }

    // Neither: the object and the values go with an aborted transaction.
    let mut txn = store.begin_write().unwrap();
    let rid = txn.take_counter_value(RID).unwrap();
    let seq = txn.take_counter_value(CHANGE_SEQ).unwrap();
    assert_eq!((rid, seq), (1101, 2));
    txn.create_object(
        principal_with_rid(2, guid(1), "alice", rid),
        &origin(NODE_1, 2, seq),
    )
    .unwrap();
    txn.abort().unwrap();
    let snap = store.snapshot().unwrap();
    assert_eq!(snap.get_object(guid(2)).unwrap(), None);
    assert_eq!(
        snap.lookup_unique(ATTR_SID, &sid_value(1101)).unwrap(),
        None
    );
    assert_eq!(
        snap.counter(RID).unwrap(),
        Some(state(RID_FIRST, 1101, RID_END))
    );
    assert_eq!(
        snap.counter(CHANGE_SEQ).unwrap(),
        Some(state(1, 2, u64::MAX))
    );
    drop(snap);

    // Both: the same values are issued again and commit with the object.
    let mut txn = store.begin_write().unwrap();
    let rid = txn.take_counter_value(RID).unwrap();
    let seq = txn.take_counter_value(CHANGE_SEQ).unwrap();
    assert_eq!((rid, seq), (1101, 2));
    txn.create_object(
        principal_with_rid(2, guid(1), "alice", rid),
        &origin(NODE_1, 2, seq),
    )
    .unwrap();
    // A snapshot during the open transaction sees neither.
    let during = store.snapshot().unwrap();
    txn.commit().unwrap();
    assert_eq!(during.get_object(guid(2)).unwrap(), None);
    assert_eq!(
        during.counter(RID).unwrap(),
        Some(state(RID_FIRST, 1101, RID_END))
    );
    let snap = store.snapshot().unwrap();
    let alice = snap.get_object(guid(2)).unwrap().unwrap();
    let sid = alice.attribute(ATTR_SID).unwrap();
    assert_eq!(sid.values[0].value, sid_value(1101));
    assert_eq!(sid.values[0].stamp.origin_seq, 2);
    assert_eq!(
        snap.lookup_unique(ATTR_SID, &sid_value(1101)).unwrap(),
        Some(guid(2))
    );
    assert_eq!(
        snap.counter(RID).unwrap(),
        Some(state(RID_FIRST, 1102, RID_END))
    );
    drop(snap);

    // A refused creation after a take: the caller aborts, nothing consumed.
    let mut txn = store.begin_write().unwrap();
    let rid = txn.take_counter_value(RID).unwrap();
    assert_eq!(rid, 1102);
    assert!(matches!(
        txn.create_object(
            principal_with_rid(3, guid(1), "alice", rid),
            &origin(NODE_1, 3, 3)
        ),
        Err(Error::NameExists)
    ));
    txn.abort().unwrap();
    assert_eq!(
        store.snapshot().unwrap().counter(RID).unwrap(),
        Some(state(RID_FIRST, 1102, RID_END))
    );
}
