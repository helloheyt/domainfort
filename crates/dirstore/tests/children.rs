//! Children listings: `Snapshot::children` / `WriteTxn::children`.
//!
//! Source: docs/49 §6.1 item 3 (R49-9: a bounded range scan over the
//! `(parent, …)` prefix of the name index, every entry tag-checked and
//! cross-checked like a lookup, `after` / `limit` paging, name-index order),
//! §12 (task L3); docs/32 §2 (name index keyed by `(parent, RDN key)`; the
//! NC roots), §3 (edits beneath the engine are detected, D135), §6 (snapshot
//! isolation, D39), §8 (bounds); docs/29 §5 (tombstones are invisible); A-30
//! (removed index entries). The "edit beneath the engine" is done as in
//! tests/integrity.rs: the store is closed and the redb file is opened
//! through redb's public API, bypassing dirstore; table names and key layout
//! are dirstore's documented on-disk layout (src/store.rs, src/record.rs).
//! Test data is hand-made (tests/common).

mod common;

use common::*;
use dirstore::record::name_index_key;
use dirstore::{
    ChildCursor, ChildPage, Error, RecordKind, Result, Store, Timestamp, Violation,
    MAX_CHILDREN_PER_PAGE,
};
use dtyp::Guid;
use redb::{ReadableTable, TableDefinition};

type RawTable<'t> = redb::Table<'t, &'static [u8], &'static [u8]>;

const OBJECTS: &str = "dirstore.objects";
const NAME_INDEX: &str = "dirstore.name_index";

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

/// Page through a whole listing with `limit`, checking the paging rules on
/// every page: a page that has a successor is full (`limit`, capped), and
/// the last page has no cursor. Returns the concatenated children.
fn list_all(
    limit: usize,
    mut page: impl FnMut(Option<&ChildCursor>, usize) -> Result<ChildPage>,
) -> Vec<Guid> {
    let mut all = Vec::new();
    let mut cursor: Option<ChildCursor> = None;
    loop {
        let p = page(cursor.as_ref(), limit).expect("page");
        assert!(p.children.len() <= limit.min(MAX_CHILDREN_PER_PAGE));
        all.extend(p.children.iter().copied());
        match p.next {
            Some(next) => {
                assert_eq!(p.children.len(), limit.min(MAX_CHILDREN_PER_PAGE));
                cursor = Some(next);
            }
            None => return all,
        }
    }
}

/// Every child of `parent` in one snapshot, paged by `limit`.
fn snapshot_children(store: &Store, parent: Option<Guid>, limit: usize) -> Vec<Guid> {
    let snap = store.snapshot().unwrap();
    list_all(limit, |after, l| snap.children(parent, after, l))
}

/// root(1) with containers carol(2), alice(3), bob(4), dave(5), eve(6)
/// (mixed case), and a grandchild under alice(3).
fn family(store: &Store) {
    create_all(
        store,
        vec![
            root(1, "root"),
            container(2, guid(1), "Carol"),
            container(3, guid(1), "alice"),
            container(4, guid(1), "Bob"),
            container(5, guid(1), "dave"),
            container(6, guid(1), "Eve"),
            container(7, guid(3), "grandchild"),
        ],
    );
}

/// The children of root(1) in `family`, in RDN-key order: the keys are the
/// A–Z-folded names (Q-080), so "alice" < "bob" < "carol" < "dave" < "eve".
fn family_order() -> Vec<Guid> {
    vec![guid(3), guid(4), guid(2), guid(5), guid(6)]
}

// ------------------------------------------------------------- listings --

#[test]
fn parent_with_no_children_lists_nothing() {
    // Source: docs/49 §6.1 item 3; docs/32 §2 — a parent without children
    // (and a GUID that names nothing) has an empty, complete listing.
    let dir = TempDir::new("children-none");
    let store = open_store(&dir);
    create_all(&store, vec![root(1, "root")]);
    let snap = store.snapshot().unwrap();
    for parent in [guid(1), guid(99)] {
        let page = snap.children(Some(parent), None, 10).unwrap();
        assert!(page.children.is_empty());
        assert_eq!(page.next, None);
    }
}

#[test]
fn parent_with_one_child_lists_it() {
    // Source: docs/49 §6.1 item 3; docs/32 §2.
    let dir = TempDir::new("children-one");
    let store = open_store(&dir);
    create_all(&store, vec![root(1, "root"), container(2, guid(1), "only")]);
    let page = store
        .snapshot()
        .unwrap()
        .children(Some(guid(1)), None, 10)
        .unwrap();
    assert_eq!(page.children, vec![guid(2)]);
    assert_eq!(page.next, None);
}

#[test]
fn many_children_are_listed_in_rdn_key_order() {
    // Source: docs/32 §2 (name index keyed by `(parent, RDN key)`); docs/49
    // §6.1 item 3 ("name-index order — deterministic"); Q-080 (the RDN key is
    // the A–Z-folded value). Only the parent's own children are listed: not
    // grandchildren, not the children of a sibling.
    let dir = TempDir::new("children-many");
    let store = open_store(&dir);
    family(&store);
    let page = store
        .snapshot()
        .unwrap()
        .children(Some(guid(1)), None, 100)
        .unwrap();
    assert_eq!(page.children, family_order());
    assert_eq!(page.next, None);
    assert_eq!(snapshot_children(&store, Some(guid(3)), 100), vec![guid(7)]);
    assert!(snapshot_children(&store, Some(guid(4)), 100).is_empty());
}

#[test]
fn no_parent_lists_the_naming_context_roots() {
    // Source: docs/32 §2 (naming contexts; a root has no parent — its own
    // name-index key space, src/record.rs); docs/49 §6.1 item 3.
    let dir = TempDir::new("children-roots");
    let store = open_store(&dir);
    create_all(
        &store,
        vec![
            root(1, "beta"),
            root(2, "Alpha"),
            container(3, guid(1), "a-child"),
            container(4, guid(2), "b-child"),
        ],
    );
    assert_eq!(snapshot_children(&store, None, 100), vec![guid(2), guid(1)]);
    assert_eq!(snapshot_children(&store, None, 1), vec![guid(2), guid(1)]);
}

// --------------------------------------------------------------- paging --

#[test]
fn paging_is_complete_and_non_overlapping() {
    // Source: docs/49 §6.1 item 3 (`after`, `limit`); docs/32 §8 (bounded
    // pages). Every page size gives the same listing, with no child twice.
    let dir = TempDir::new("children-paging");
    let store = open_store(&dir);
    let mut objects = vec![root(1, "root")];
    let names = ["g", "c", "a", "f", "b", "e", "d"];
    for (i, name) in (10u32..).zip(names) {
        objects.push(container(i, guid(1), name));
    }
    create_all(&store, objects);
    let whole = snapshot_children(&store, Some(guid(1)), 100);
    assert_eq!(
        whole,
        vec![
            guid(12),
            guid(14),
            guid(11),
            guid(16),
            guid(15),
            guid(13),
            guid(10)
        ]
    );
    for limit in 1..=8 {
        let paged = snapshot_children(&store, Some(guid(1)), limit);
        assert_eq!(paged, whole, "limit {limit}");
    }
    // A page that ends exactly at the last child has no cursor.
    let snap = store.snapshot().unwrap();
    assert_eq!(snap.children(Some(guid(1)), None, 7).unwrap().next, None);
    let first = snap.children(Some(guid(1)), None, 4).unwrap();
    let second = snap
        .children(Some(guid(1)), first.next.as_ref(), 3)
        .unwrap();
    assert_eq!(second.children.len(), 3);
    assert_eq!(second.next, None);
}

#[test]
fn limit_is_capped_by_the_constant() {
    // Source: docs/32 §8 (bounds), docs/49 §6.1 item 3; lib.rs
    // MAX_CHILDREN_PER_PAGE — a larger limit returns at most the cap.
    let dir = TempDir::new("children-cap");
    let store = open_store(&dir);
    let extra = 3u32;
    let total = u32::try_from(MAX_CHILDREN_PER_PAGE).unwrap() + extra;
    let mut objects = vec![root(1, "root")];
    for i in 0..total {
        objects.push(container(10 + i, guid(1), &format!("c{i:05}")));
    }
    create_all(&store, objects);
    let snap = store.snapshot().unwrap();
    for limit in [MAX_CHILDREN_PER_PAGE + 1, usize::MAX] {
        let first = snap.children(Some(guid(1)), None, limit).unwrap();
        assert_eq!(first.children.len(), MAX_CHILDREN_PER_PAGE);
        assert_eq!(first.children.first(), Some(&guid(10)));
        let second = snap
            .children(Some(guid(1)), first.next.as_ref(), limit)
            .unwrap();
        assert_eq!(second.children.len(), usize::try_from(extra).unwrap());
        assert_eq!(second.children.last(), Some(&guid(10 + total - 1)));
        assert_eq!(second.next, None);
    }
    let all = list_all(usize::MAX, |after, l| {
        snap.children(Some(guid(1)), after, l)
    });
    assert_eq!(all.len(), usize::try_from(total).unwrap());
}

#[test]
fn zero_limit_is_refused() {
    // Source: docs/32 §8; docs/49 §6.1 item 3 — a page of nothing could never
    // advance a listing.
    let dir = TempDir::new("children-zero");
    let store = open_store(&dir);
    create_all(&store, vec![root(1, "root"), container(2, guid(1), "a")]);
    assert!(matches!(
        store.snapshot().unwrap().children(Some(guid(1)), None, 0),
        Err(Error::Rejected(Violation::PageLimitZero))
    ));
    let txn = store.begin_write().unwrap();
    assert!(matches!(
        txn.children(None, None, 0),
        Err(Error::Rejected(Violation::PageLimitZero))
    ));
}

#[test]
fn cursor_of_another_parent_is_refused() {
    // Source: docs/49 §6.1 item 3 (`after` resumes one parent's listing);
    // docs/32 §2.
    let dir = TempDir::new("children-cursor");
    let store = open_store(&dir);
    family(&store);
    create_all(&store, vec![container(8, guid(3), "another")]);
    let snap = store.snapshot().unwrap();
    let page = snap.children(Some(guid(1)), None, 1).unwrap();
    let cursor = page.next.expect("more children follow");
    for other in [Some(guid(3)), None] {
        assert!(matches!(
            snap.children(other, Some(&cursor), 10),
            Err(Error::Rejected(Violation::CursorParentMismatch))
        ));
    }
}

// ---------------------------------------------------- views and deletes --

#[test]
fn snapshot_does_not_list_children_written_later() {
    // Source: docs/32 §6 (D39) — a snapshot lists the children of its own
    // moment, also when a listing is paged across a later commit.
    let dir = TempDir::new("children-isolation");
    let store = open_store(&dir);
    family(&store);
    let old = store.snapshot().unwrap();
    let first = old.children(Some(guid(1)), None, 2).unwrap();
    {
        let mut txn = store.begin_write().unwrap();
        txn.create_object(container(20, guid(1), "aaa"), &origin(NODE_1, 50, 1))
            .unwrap();
        txn.create_object(container(21, guid(1), "zzz"), &origin(NODE_1, 50, 2))
            .unwrap();
        txn.delete_object(guid(5), &origin(NODE_1, 50, 3)).unwrap();
        txn.commit().unwrap();
    }
    // The old snapshot: the paged listing finishes on the old state, and its
    // count check holds against the old count. (`list_all` starts with no
    // cursor; the first call resumes from the page read before the commit.)
    let mut rest = list_all(2, |after, l| {
        old.children(Some(guid(1)), after.or(first.next.as_ref()), l)
    });
    let mut paged = first.children.clone();
    paged.append(&mut rest);
    assert_eq!(paged, family_order());
    assert_eq!(
        list_all(100, |after, l| old.children(Some(guid(1)), after, l)),
        family_order()
    );
    // A new snapshot lists the new state.
    assert_eq!(
        snapshot_children(&store, Some(guid(1)), 2),
        vec![guid(20), guid(3), guid(4), guid(2), guid(6), guid(21)]
    );
}

#[test]
fn write_txn_lists_its_own_uncommitted_children() {
    // Source: docs/32 §6, §7 (D39, D136) — the write transaction sees its own
    // writes; a snapshot taken meanwhile does not.
    let dir = TempDir::new("children-own-writes");
    let store = open_store(&dir);
    create_all(&store, vec![root(1, "root"), container(2, guid(1), "b")]);
    let mut txn = store.begin_write().unwrap();
    txn.create_object(container(3, guid(1), "a"), &origin(NODE_1, 5, 1))
        .unwrap();
    txn.create_object(container(4, guid(1), "c"), &origin(NODE_1, 5, 2))
        .unwrap();
    assert_eq!(
        list_all(1, |after, l| txn.children(Some(guid(1)), after, l)),
        vec![guid(3), guid(2), guid(4)]
    );
    assert_eq!(snapshot_children(&store, Some(guid(1)), 10), vec![guid(2)]);
    txn.commit().unwrap();
    assert_eq!(
        snapshot_children(&store, Some(guid(1)), 10),
        vec![guid(3), guid(2), guid(4)]
    );
}

#[test]
fn tombstoned_children_are_not_listed() {
    // Source: docs/29 §5 (tombstones are invisible to normal reads); Q-062 /
    // A-18 (the name is released on delete); docs/32 §2.
    let dir = TempDir::new("children-tombstones");
    let store = open_store(&dir);
    family(&store);
    {
        let mut txn = store.begin_write().unwrap();
        txn.delete_object(guid(4), &origin(NODE_1, 9, 1)).unwrap();
        txn.delete_object(guid(6), &origin(NODE_1, 9, 2)).unwrap();
        assert_eq!(
            list_all(1, |after, l| txn.children(Some(guid(1)), after, l)),
            vec![guid(3), guid(2), guid(5)]
        );
        txn.commit().unwrap();
    }
    for limit in [1, 2, 100] {
        assert_eq!(
            snapshot_children(&store, Some(guid(1)), limit),
            vec![guid(3), guid(2), guid(5)]
        );
    }
    // Deleting the last child leaves a complete, empty listing.
    let mut txn = store.begin_write().unwrap();
    txn.delete_object(guid(7), &origin(NODE_1, 10, 3)).unwrap();
    txn.commit().unwrap();
    assert!(snapshot_children(&store, Some(guid(3)), 10).is_empty());
}

// ------------------------------------------------- integrity (docs/32 §3) --

/// A closed store holding `family`.
fn closed_family(test: &str) -> TempDir {
    let dir = TempDir::new(test);
    let store = open_store(&dir);
    family(&store);
    dir
}

#[test]
fn flipped_name_entry_is_tamper() {
    // Source: docs/32 §3 (D135) — a name-index entry edited beneath the engine
    // fails its tag; the listing that meets it fails whole (nothing partial),
    // and so does the write transaction's listing. A page that ends before
    // the bad entry reads only its own entries.
    let dir = closed_family("children-flip");
    edit_beneath(&dir, NAME_INDEX, |t| {
        let key = name_index_key(Some(guid(1)), b"dave");
        let mut v = raw_value(t, &key);
        v[3] ^= 0x01; // inside the child GUID
        t.insert(key.as_slice(), v.as_slice()).unwrap();
    });
    let store = open_store(&dir);
    let snap = store.snapshot().unwrap();
    assert!(matches!(
        snap.children(Some(guid(1)), None, 100),
        Err(Error::Tamper(RecordKind::NameIndex))
    ));
    let first = snap.children(Some(guid(1)), None, 3).unwrap();
    assert_eq!(first.children, vec![guid(3), guid(4), guid(2)]);
    assert!(matches!(
        snap.children(Some(guid(1)), first.next.as_ref(), 3),
        Err(Error::Tamper(RecordKind::NameIndex))
    ));
    drop(snap);
    let txn = store.begin_write().unwrap();
    assert!(matches!(
        txn.children(Some(guid(1)), None, 100),
        Err(Error::Tamper(RecordKind::NameIndex))
    ));
}

#[test]
fn name_entry_copied_to_another_key_is_tamper() {
    // Source: docs/32 §3 — the tag binds an entry to its key, so a valid
    // entry copied under another name (here: a new name under the parent) is
    // refused; so is a foreign record under the parent's prefix.
    let dir = closed_family("children-copy");
    edit_beneath(&dir, NAME_INDEX, |t| {
        let bob = raw_value(t, &name_index_key(Some(guid(1)), b"bob"));
        let forged = name_index_key(Some(guid(1)), b"bobby");
        t.insert(forged.as_slice(), bob.as_slice()).unwrap();
    });
    {
        let store = open_store(&dir);
        assert!(matches!(
            store.snapshot().unwrap().children(Some(guid(1)), None, 100),
            Err(Error::Tamper(RecordKind::NameIndex))
        ));
    }
    let dir = closed_family("children-foreign");
    edit_beneath(&dir, NAME_INDEX, |t| {
        let key = name_index_key(Some(guid(1)), b"mallory");
        t.insert(
            key.as_slice(),
            &b"not a record at all, but long enough to hold a tag"[..],
        )
        .unwrap();
    });
    let store = open_store(&dir);
    assert!(matches!(
        store.snapshot().unwrap().children(Some(guid(1)), None, 100),
        Err(Error::Tamper(RecordKind::NameIndex))
    ));
}

#[test]
fn tampered_child_record_is_tamper() {
    // Source: docs/32 §3 — the listing authenticates the object each entry
    // names before believing the entry.
    let dir = closed_family("children-object");
    edit_beneath(&dir, OBJECTS, |t| {
        let key = guid(5).to_packet();
        let mut v = raw_value(t, &key);
        let last = v.len() - 1;
        v[last] ^= 0x80;
        t.insert(key.as_slice(), v.as_slice()).unwrap();
    });
    let store = open_store(&dir);
    assert!(matches!(
        store.snapshot().unwrap().children(Some(guid(1)), None, 100),
        Err(Error::Tamper(RecordKind::Object))
    ));
}

#[test]
fn replayed_name_entry_is_inconsistent() {
    // Source: docs/32 §3; Q-060. An entry saved before its object was
    // deleted, put back beneath the engine, is validly tagged but stale: the
    // cross-check against the object's own record (a tombstone) catches it.
    let dir = closed_family("children-replay");
    let key = name_index_key(Some(guid(1)), b"bob");
    let mut saved = Vec::new();
    edit_beneath(&dir, NAME_INDEX, |t| saved = raw_value(t, &key));
    {
        let store = open_store(&dir);
        let mut txn = store.begin_write().unwrap();
        txn.delete_object(guid(4), &origin(NODE_1, 50, 1)).unwrap();
        txn.commit().unwrap();
    }
    edit_beneath(&dir, NAME_INDEX, |t| {
        t.insert(key.as_slice(), saved.as_slice()).unwrap();
    });
    let store = open_store(&dir);
    let snap = store.snapshot().unwrap();
    assert!(matches!(
        snap.children(Some(guid(1)), None, 100),
        Err(Error::Inconsistent(RecordKind::NameIndex))
    ));
    // The same rule as a lookup.
    assert!(matches!(
        snap.lookup_child(Some(guid(1)), b"bob"),
        Err(Error::Inconsistent(RecordKind::NameIndex))
    ));
}

/// Save the validly tagged entry `(old parent, "x") -> guid(30)`, then
/// delete and purge guid(30) and recreate the same GUID as `recreated`, and
/// put the saved entry back beneath the engine. root(1) has containers
/// p1(10) and p2(20); guid(30) starts as "x" under p2.
fn stale_entry_for_recreated_object(test: &str, recreated: dirstore::NewObject) -> TempDir {
    let dir = TempDir::new(test);
    {
        let store = open_store(&dir);
        create_all(
            &store,
            vec![
                root(1, "root"),
                container(10, guid(1), "p1"),
                container(20, guid(1), "p2"),
                container(30, guid(20), "x"),
            ],
        );
    }
    let key = name_index_key(Some(guid(20)), b"x");
    let mut saved = Vec::new();
    edit_beneath(&dir, NAME_INDEX, |t| saved = raw_value(t, &key));
    {
        let store = open_store(&dir);
        let mut txn = store.begin_write().unwrap();
        txn.delete_object(guid(30), &origin(NODE_1, 50, 1)).unwrap();
        assert_eq!(txn.purge_tombstones(Timestamp(1000), 0).unwrap(), 1);
        txn.create_object(recreated, &origin(NODE_1, 60, 2))
            .unwrap();
        txn.commit().unwrap();
    }
    edit_beneath(&dir, NAME_INDEX, |t| {
        t.insert(key.as_slice(), saved.as_slice()).unwrap();
    });
    dir
}

#[test]
fn entry_naming_a_child_of_another_parent_is_inconsistent() {
    // Source: docs/32 §2 (the entry `(parent, RDN key)` names a child of that
    // parent), §3. The stale entry `(p2, "x")` names a live object whose own
    // record says its parent is p1: refused under p2, while p1's own listing
    // is sound.
    let dir =
        stale_entry_for_recreated_object("children-other-parent", container(30, guid(10), "x"));
    let store = open_store(&dir);
    let snap = store.snapshot().unwrap();
    assert!(matches!(
        snap.children(Some(guid(20)), None, 100),
        Err(Error::Inconsistent(RecordKind::NameIndex))
    ));
    assert_eq!(
        snap.children(Some(guid(10)), None, 100).unwrap().children,
        vec![guid(30)]
    );
}

#[test]
fn entry_naming_a_child_under_another_name_is_inconsistent() {
    // Source: docs/32 §2, §3. The stale entry `(p2, "x")` names a live child
    // of p2 whose own record carries the RDN key "y": refused.
    let dir = stale_entry_for_recreated_object("children-other-name", container(30, guid(20), "y"));
    let store = open_store(&dir);
    assert!(matches!(
        store
            .snapshot()
            .unwrap()
            .children(Some(guid(20)), None, 100),
        Err(Error::Inconsistent(RecordKind::NameIndex))
    ));
}

#[test]
fn removed_name_entry_fails_the_count_check() {
    // Source: docs/32 §2 (live-child count), §3; A-30 (an index entry removed
    // beneath the engine is caught where it is relied on). A listing relies
    // on the name index being complete: its final page compares the number
    // listed with the parent's count — also when the listing is paged.
    let dir = closed_family("children-removed");
    edit_beneath(&dir, NAME_INDEX, |t| {
        t.remove(name_index_key(Some(guid(1)), b"carol").as_slice())
            .unwrap();
    });
    let store = open_store(&dir);
    let snap = store.snapshot().unwrap();
    assert!(matches!(
        snap.children(Some(guid(1)), None, 100),
        Err(Error::Inconsistent(RecordKind::ChildCount))
    ));
    // alice, bob | dave, eve: the second page is the final one, and fails.
    let first = snap.children(Some(guid(1)), None, 2).unwrap();
    assert_eq!(first.children, vec![guid(3), guid(4)]);
    assert!(matches!(
        snap.children(Some(guid(1)), first.next.as_ref(), 2),
        Err(Error::Inconsistent(RecordKind::ChildCount))
    ));
    // The object itself is untouched and still readable by GUID.
    assert!(snap.get_object(guid(2)).unwrap().is_some());
}
