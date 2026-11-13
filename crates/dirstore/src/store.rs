//! The store: tables over redb, write transactions and snapshots.
//!
//! # On-disk layout (all tables `&[u8] -> &[u8]`)
//!
//! | table | key | value |
//! |---|---|---|
//! | `dirstore.meta` | `"store"` | meta body + tag |
//! | `dirstore.objects` | 16-byte GUID packet | object body + tag |
//! | `dirstore.name_index` | [`record::name_index_key`] | name-index body + tag |
//! | `dirstore.child_count` | 16-byte parent GUID packet | count body + tag |
//!
//! Bodies are defined in [`record`]; tags in the integrity module (D135).
//!
//! # Write discipline
//!
//! Every operation first *plans*: it validates the request against the schema
//! and bounds, reads and authenticates every record it depends on, and builds
//! every new record (body + tag). Only then does it *apply* the planned
//! inserts and removals. A refusal during planning changes nothing, and the
//! transaction stays usable. A failure while applying poisons the
//! transaction: it can then only be aborted (commit refuses and aborts), so a
//! half-applied operation can never be committed. Spec: docs/32 §7, D136.
//!
//! Spec: docs/32 §2 (D134), §3 (D135), §6 (D39), §7 (D136); docs/29 §5 (D121).

use crate::error::{Error, RecordKind, Result, Violation};
use crate::integrity::{self, IntegrityKey};
use crate::record;
use crate::schema::Schema;
use crate::types::{
    AttrId, Attribute, AttributeChange, NewObject, Object, Origin, StampedValue, Timestamp,
    Tombstone,
};
use crate::{
    MAX_ATTRIBUTES_PER_OBJECT, MAX_CLASSES_PER_OBJECT, MAX_RDN_KEY_LEN, MAX_RECORD_BODY_LEN,
    MAX_VALUES_PER_ATTRIBUTE, MAX_VALUE_LEN,
};
use core::num::NonZeroU64;
use dtyp::Guid;
use redb::{
    Database, ReadTransaction, ReadableDatabase, ReadableTable, ReadableTableMetadata,
    TableDefinition, WriteTransaction,
};
use std::collections::BTreeSet;
use std::path::Path;

/// Raw byte keys and values: the codec and the tag are ours, the KV engine
/// only stores bytes. Spec: docs/32 §1 (D5: the KV is a replaceable engine).
type Raw = &'static [u8];

/// Store metadata: format version, and a key check at open. Spec: D135.
const META_TABLE: TableDefinition<'static, Raw, Raw> = TableDefinition::new("dirstore.meta");
/// Objects by GUID. Spec: docs/32 §2, D134.
const OBJECT_TABLE: TableDefinition<'static, Raw, Raw> = TableDefinition::new("dirstore.objects");
/// `(parent, RDN key) -> GUID` for live objects. Spec: docs/32 §2.
const NAME_INDEX_TABLE: TableDefinition<'static, Raw, Raw> =
    TableDefinition::new("dirstore.name_index");
/// Live-child count per parent GUID. Spec: docs/32 §2 (DIT shape).
const CHILD_COUNT_TABLE: TableDefinition<'static, Raw, Raw> =
    TableDefinition::new("dirstore.child_count");
/// The single key of the meta table.
const META_KEY: &[u8] = b"store";

/// Which table a planned write targets.
#[derive(Debug, Clone, Copy)]
enum TableId {
    Objects,
    NameIndex,
    ChildCount,
}

/// One planned insert (`value: Some`) or removal (`value: None`).
/// Spec: docs/32 §7 (all parts of one write in one transaction).
struct Write {
    table: TableId,
    key: Vec<u8>,
    value: Option<Vec<u8>>,
}

/// The directory store: a redb database, the injected integrity key, and the
/// schema every write is validated against.
///
/// Spec: docs/32 §1 (our interface over the approved KV, D5), §3 (D135),
/// §4 (schema as data).
pub struct Store {
    db: Database,
    key: IntegrityKey,
    schema: Schema,
}

impl Store {
    /// Open (or create) the store at `path`.
    ///
    /// On a new database this creates the tables and a tagged meta record. On
    /// an existing one it verifies the meta record's tag first: a wrong
    /// `key` is reported here as [`Error::Tamper`]`(`[`RecordKind::Meta`]`)`,
    /// as is a missing meta record in a database that holds other records.
    /// Spec: docs/32 §3 (D135); docs/10 D34 (format version).
    pub fn open(path: impl AsRef<Path>, key: IntegrityKey, schema: Schema) -> Result<Store> {
        let db = Database::create(path)?;
        let txn = db.begin_write()?;
        match init_tables(&txn, &key) {
            Ok(()) => txn.commit()?,
            Err(e) => {
                // Nothing of a failed open is kept. Spec: D136.
                let _ = txn.abort();
                return Err(e);
            }
        }
        Ok(Store { db, key, schema })
    }

    /// The schema writes are validated against. Spec: docs/32 §4.
    #[must_use]
    pub fn schema(&self) -> &Schema {
        &self.schema
    }

    /// Begin a write transaction (waits while another one is open).
    /// Spec: docs/32 §7, D136.
    pub fn begin_write(&self) -> Result<WriteTxn<'_>> {
        Ok(WriteTxn {
            store: self,
            txn: Some(self.db.begin_write()?),
            poisoned: false,
        })
    }

    /// Take a point-in-time snapshot for reading. Spec: docs/32 §6, D39.
    pub fn snapshot(&self) -> Result<Snapshot<'_>> {
        Ok(Snapshot {
            store: self,
            txn: self.db.begin_read()?,
        })
    }
}

/// Create the tables and the meta record, or authenticate the existing meta
/// record. Spec: D135; docs/10 D34.
fn init_tables(txn: &WriteTransaction, key: &IntegrityKey) -> Result<()> {
    let mut meta = txn.open_table(META_TABLE)?;
    let objects = txn.open_table(OBJECT_TABLE)?;
    let names = txn.open_table(NAME_INDEX_TABLE)?;
    let counts = txn.open_table(CHILD_COUNT_TABLE)?;
    match raw_get(&meta, META_KEY)? {
        Some(stored) => {
            let body = integrity::open(key, RecordKind::Meta, META_KEY, &stored)?;
            record::decode_meta_body(body)
                .map_err(|e| Error::RecordMalformed(RecordKind::Meta, e))?;
        }
        None => {
            // A database with records but no meta record has been edited
            // beneath us; never silently adopt it under a new key.
            if !objects.is_empty()? || !names.is_empty()? || !counts.is_empty()? {
                return Err(Error::Tamper(RecordKind::Meta));
            }
            let sealed =
                integrity::seal(key, RecordKind::Meta, META_KEY, record::encode_meta_body())?;
            meta.insert(META_KEY, sealed.as_slice())?;
        }
    }
    Ok(())
}

/// A consistent, read-only, point-in-time view of the store: a redb read
/// transaction. Writes committed after it was taken are not visible, and an
/// uncommitted write is never visible. Spec: docs/32 §6 (D39; against
/// read-while-write TOCTOU).
pub struct Snapshot<'s> {
    store: &'s Store,
    txn: ReadTransaction,
}

impl Snapshot<'_> {
    /// The live object with this GUID; `None` if absent or a tombstone.
    /// The record is authenticated, decoded and re-validated against the
    /// schema before it is returned. Spec: docs/32 §3; docs/29 §5; D60.
    pub fn get_object(&self, guid: Guid) -> Result<Option<Object>> {
        let objects = self.txn.open_table(OBJECT_TABLE)?;
        get_live(&objects, self.store, guid)
    }

    /// The tombstone with this GUID — its GUID, classes and deletion stamp
    /// only; `None` if absent or live. An explicit, separate read
    /// (replication / audit / purge tooling), never part of a normal read.
    /// Spec: docs/29 §5; Q-062 / A-18.
    pub fn get_tombstone(&self, guid: Guid) -> Result<Option<Tombstone>> {
        let objects = self.txn.open_table(OBJECT_TABLE)?;
        get_tombstone(&objects, self.store, guid)
    }

    /// The GUID of the live child of `parent` (or the root, for `None`) named
    /// by the opaque `rdn` key. The index entry is authenticated and
    /// cross-checked against the object it names. Spec: docs/32 §2.
    pub fn lookup_child(&self, parent: Option<Guid>, rdn: &[u8]) -> Result<Option<Guid>> {
        let names = self.txn.open_table(NAME_INDEX_TABLE)?;
        let objects = self.txn.open_table(OBJECT_TABLE)?;
        resolve_name(&names, &objects, &self.store.key, parent, rdn)
    }
}

/// A write transaction. Every change made through it — values, stamps, name
/// index, child counts and integrity tags — commits together or not at all;
/// dropping it without [`WriteTxn::commit`] aborts it.
/// Spec: docs/32 §7, D136.
pub struct WriteTxn<'s> {
    store: &'s Store,
    /// `None` only after commit / abort, which consume `self`.
    txn: Option<WriteTransaction>,
    /// Set when applying planned writes failed part-way. Spec: D136.
    poisoned: bool,
}

impl WriteTxn<'_> {
    /// The open redb transaction, unless this one is poisoned.
    fn txn(&self) -> Result<&WriteTransaction> {
        if self.poisoned {
            return Err(Error::TransactionPoisoned);
        }
        self.txn.as_ref().ok_or(Error::TransactionPoisoned)
    }

    /// Apply planned writes; a failure poisons the transaction. Spec: D136.
    fn apply(&mut self, writes: Vec<Write>) -> Result<()> {
        if writes.is_empty() {
            return Ok(());
        }
        let result = apply_writes(self.txn()?, &writes);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    /// Create an object.
    ///
    /// Refused (nothing written) if the request breaks the schema or a bound
    /// ([`Error::Rejected`] — including any Secret attribute, D44), if a
    /// record already holds the GUID ([`Error::ObjectExists`]), if the parent
    /// is not a live object ([`Error::NoSuchParent`]), or if a live child of
    /// the parent already has the RDN key ([`Error::NameExists`]). Every value
    /// is stamped `version` 1 with `origin`.
    /// Spec: docs/32 §2, §4, §7; docs/29 §2; docs/12 D44.
    pub fn create_object(&mut self, new: NewObject, origin: &Origin) -> Result<()> {
        let writes = plan_create(self.txn()?, self.store, new, origin)?;
        self.apply(writes)
    }

    /// Apply attribute changes to a live object (see
    /// [`AttributeChange::Replace`] for stamping). The resulting object is
    /// validated as a whole. Naming a Secret attribute in any change — even to
    /// remove it — is refused. A change that leaves every value as it was
    /// writes nothing. Spec: docs/32 §4, §7; docs/29 §2; docs/12 D44.
    pub fn modify_object(
        &mut self,
        guid: Guid,
        changes: Vec<AttributeChange>,
        origin: &Origin,
    ) -> Result<()> {
        let writes = plan_modify(self.txn()?, self.store, guid, changes, origin)?;
        self.apply(writes)
    }

    /// Delete a live object by replacing its record with a tombstone that
    /// keeps only its GUID, its classes and a deletion stamp (`version` 1,
    /// `origin`). The parent, the RDN key and every attribute value with its
    /// stamp are dropped; its name is released; it disappears from normal
    /// reads. Refused while it has live children ([`Error::HasChildren`]).
    ///
    /// Residual — no physical erasure guarantee: redb stores data in
    /// copy-on-write B-trees (redb crate docs), so the bytes of the replaced
    /// live record (the deleted values) can remain in the file's free pages
    /// until those pages are reused. The engine removes them from every
    /// reachable record, not from the disk. Q-062.
    ///
    /// Spec: docs/29 §5 (D121); docs/32 §2; docs/25 §5 ("state"); Q-062 /
    /// A-18.
    pub fn delete_object(&mut self, guid: Guid, origin: &Origin) -> Result<()> {
        let writes = plan_delete(self.txn()?, self.store, guid, origin)?;
        self.apply(writes)
    }

    /// Physically remove every tombstone older than `lifetime`, i.e. whose
    /// tombstone time `t` (its deletion stamp's wall-clock) satisfies
    /// `t + lifetime < now`. A sum that overflows is treated as "not yet
    /// expired" (keep). Every record is authenticated first; any tampered
    /// record aborts the purge with nothing removed. Returns the number of
    /// tombstones removed. Spec: docs/29 §5 (D121: tombstones are kept for a
    /// lifetime, then collected).
    pub fn purge_tombstones(&mut self, now: Timestamp, lifetime: u64) -> Result<usize> {
        let writes = plan_purge(self.txn()?, self.store, now, lifetime)?;
        let count = writes.len();
        self.apply(writes)?;
        Ok(count)
    }

    /// [`Snapshot::get_object`], seeing this transaction's own writes.
    pub fn get_object(&self, guid: Guid) -> Result<Option<Object>> {
        let objects = self.txn()?.open_table(OBJECT_TABLE)?;
        get_live(&objects, self.store, guid)
    }

    /// [`Snapshot::get_tombstone`], seeing this transaction's own writes.
    pub fn get_tombstone(&self, guid: Guid) -> Result<Option<Tombstone>> {
        let objects = self.txn()?.open_table(OBJECT_TABLE)?;
        get_tombstone(&objects, self.store, guid)
    }

    /// [`Snapshot::lookup_child`], seeing this transaction's own writes.
    pub fn lookup_child(&self, parent: Option<Guid>, rdn: &[u8]) -> Result<Option<Guid>> {
        let txn = self.txn()?;
        let names = txn.open_table(NAME_INDEX_TABLE)?;
        let objects = txn.open_table(OBJECT_TABLE)?;
        resolve_name(&names, &objects, &self.store.key, parent, rdn)
    }

    /// Commit every write of this transaction atomically. A poisoned
    /// transaction is aborted instead and reports
    /// [`Error::TransactionPoisoned`]. Spec: docs/32 §7, D136.
    pub fn commit(mut self) -> Result<()> {
        let txn = self.txn.take().ok_or(Error::TransactionPoisoned)?;
        if self.poisoned {
            let _ = txn.abort();
            return Err(Error::TransactionPoisoned);
        }
        txn.commit()?;
        Ok(())
    }

    /// Roll back every write of this transaction. Spec: D136.
    pub fn abort(mut self) -> Result<()> {
        if let Some(txn) = self.txn.take() {
            txn.abort()?;
        }
        Ok(())
    }
}

impl Drop for WriteTxn<'_> {
    /// An uncommitted transaction is rolled back explicitly, so a dropped
    /// write leaves no trace. `drop` has no way to return a rollback error.
    /// Spec: D136.
    fn drop(&mut self) {
        if let Some(txn) = self.txn.take() {
            let _ = txn.abort();
        }
    }
}

// ------------------------------------------------------------ read helpers --

/// Copy out the raw stored value under `key`.
fn raw_get<T: ReadableTable<Raw, Raw>>(table: &T, key: &[u8]) -> Result<Option<Vec<u8>>> {
    Ok(table.get(key)?.map(|guard| guard.value().to_vec()))
}

/// Load an object record (live or tombstone): tag first, then the bounded
/// decoder. No schema check (internal structural use).
/// Spec: docs/32 §3 (D135), §8 (D138).
fn load_object<T: ReadableTable<Raw, Raw>>(
    objects: &T,
    key: &IntegrityKey,
    guid: Guid,
) -> Result<Option<Object>> {
    let record_key = guid.to_packet();
    let Some(stored) = raw_get(objects, &record_key)? else {
        return Ok(None);
    };
    let body = integrity::open(key, RecordKind::Object, &record_key, &stored)?;
    record::decode_object_body(guid, body)
        .map(Some)
        .map_err(|e| Error::RecordMalformed(RecordKind::Object, e))
}

/// Load a name-index entry: the GUID it names. Spec: docs/32 §2, §3.
fn load_name<T: ReadableTable<Raw, Raw>>(
    names: &T,
    key: &IntegrityKey,
    name_key: &[u8],
) -> Result<Option<Guid>> {
    let Some(stored) = raw_get(names, name_key)? else {
        return Ok(None);
    };
    let body = integrity::open(key, RecordKind::NameIndex, name_key, &stored)?;
    record::decode_name_index_body(body)
        .map(Some)
        .map_err(|e| Error::RecordMalformed(RecordKind::NameIndex, e))
}

/// Load a parent's live-child count (0 when no record).
/// Spec: docs/32 §2, §3.
fn load_child_count<T: ReadableTable<Raw, Raw>>(
    counts: &T,
    key: &IntegrityKey,
    parent: Guid,
) -> Result<u64> {
    let record_key = parent.to_packet();
    let Some(stored) = raw_get(counts, &record_key)? else {
        return Ok(0);
    };
    let body = integrity::open(key, RecordKind::ChildCount, &record_key, &stored)?;
    record::decode_child_count_body(body)
        .map(NonZeroU64::get)
        .map_err(|e| Error::RecordMalformed(RecordKind::ChildCount, e))
}

/// RDN key bounds. Spec: docs/32 §2, §8.
fn check_rdn(rdn: &[u8]) -> core::result::Result<(), Violation> {
    if rdn.is_empty() {
        return Err(Violation::RdnKeyEmpty);
    }
    if rdn.len() > MAX_RDN_KEY_LEN {
        return Err(Violation::RdnKeyTooLong);
    }
    Ok(())
}

/// Resolve `(parent, rdn)` to a live object. The entry must name a live
/// object whose own (tagged) record carries the same parent and RDN key;
/// anything else is [`Error::Inconsistent`] — e.g. a replayed index entry of
/// a deleted object. Spec: docs/32 §2, §3.
fn resolve_name<N: ReadableTable<Raw, Raw>, O: ReadableTable<Raw, Raw>>(
    names: &N,
    objects: &O,
    key: &IntegrityKey,
    parent: Option<Guid>,
    rdn: &[u8],
) -> Result<Option<Guid>> {
    check_rdn(rdn).map_err(Error::Rejected)?;
    let name_key = record::name_index_key(parent, rdn);
    let Some(child) = load_name(names, key, &name_key)? else {
        return Ok(None);
    };
    match load_object(objects, key, child)? {
        Some(obj) if !obj.is_tombstone() && obj.parent == parent && obj.rdn == rdn => {
            Ok(Some(child))
        }
        _ => Err(Error::Inconsistent(RecordKind::NameIndex)),
    }
}

/// A live object, re-validated against the schema before it is handed out.
/// Spec: docs/29 §5 (tombstones invisible); docs/14 D60; docs/12 D44.
fn get_live<T: ReadableTable<Raw, Raw>>(
    objects: &T,
    store: &Store,
    guid: Guid,
) -> Result<Option<Object>> {
    match load_object(objects, &store.key, guid)? {
        Some(obj) if !obj.is_tombstone() => {
            store
                .schema
                .validate_object(&obj)
                .map_err(Error::StoredObjectRejected)?;
            Ok(Some(obj))
        }
        _ => Ok(None),
    }
}

/// A tombstone, checked on the tombstone validation path (never the
/// live-object one) before it is handed out as a [`Tombstone`].
/// Spec: docs/29 §5; docs/14 D60; Q-062 / A-18.
fn get_tombstone<T: ReadableTable<Raw, Raw>>(
    objects: &T,
    store: &Store,
    guid: Guid,
) -> Result<Option<Tombstone>> {
    let Some(obj) = load_object(objects, &store.key, guid)? else {
        return Ok(None);
    };
    let Some(deletion) = obj.tombstone else {
        return Ok(None);
    };
    store
        .schema
        .validate_tombstone(&obj)
        .map_err(Error::StoredObjectRejected)?;
    Ok(Some(Tombstone {
        guid: obj.guid,
        classes: obj.classes,
        deletion,
    }))
}

// ----------------------------------------------------------------- planning --

/// Sort a value set and check its bounds; reject byte-equal duplicates.
/// Bounds are checked before any sorting work. Spec: docs/32 §8; docs/29 §4
/// (values are a set).
fn normalize_values(
    id: AttrId,
    mut values: Vec<Vec<u8>>,
) -> core::result::Result<Vec<Vec<u8>>, Violation> {
    if values.len() > MAX_VALUES_PER_ATTRIBUTE {
        return Err(Violation::TooManyValues(id));
    }
    if values.iter().any(|v| v.len() > MAX_VALUE_LEN) {
        return Err(Violation::ValueTooLarge(id));
    }
    values.sort_unstable();
    if values
        .iter()
        .zip(values.iter().skip(1))
        .any(|(a, b)| a == b)
    {
        return Err(Violation::DuplicateValue(id));
    }
    Ok(values)
}

/// The first repeated item of an ascending sequence.
fn first_repeat<T: PartialEq + Copy, I: Iterator<Item = T>>(sorted: I) -> Option<T> {
    let mut previous = None;
    for item in sorted {
        if previous == Some(item) {
            return Some(item);
        }
        previous = Some(item);
    }
    None
}

/// Build the canonical object of a creation request; every value is stamped
/// `version` 1. Spec: docs/32 §2, §4; docs/29 §2.
fn build_new_object(new: NewObject, origin: &Origin) -> core::result::Result<Object, Violation> {
    check_rdn(&new.rdn)?;
    if new.classes.len() > MAX_CLASSES_PER_OBJECT {
        return Err(Violation::TooManyClasses);
    }
    let mut classes = new.classes;
    classes.sort_unstable();
    if let Some(dup) = first_repeat(classes.iter().copied()) {
        return Err(Violation::DuplicateClass(dup));
    }
    if new.attributes.len() > MAX_ATTRIBUTES_PER_OBJECT {
        return Err(Violation::TooManyAttributes);
    }
    let stamp = origin.stamp(1);
    let mut attributes = Vec::new();
    for (id, values) in new.attributes {
        let values = normalize_values(id, values)?;
        if values.is_empty() {
            return Err(Violation::EmptyAttribute(id));
        }
        attributes.push(Attribute {
            id,
            values: values
                .into_iter()
                .map(|value| StampedValue { value, stamp })
                .collect(),
        });
    }
    attributes.sort_unstable_by_key(|a| a.id);
    if let Some(dup) = first_repeat(attributes.iter().map(|a| a.id)) {
        return Err(Violation::DuplicateAttribute(dup));
    }
    Ok(Object {
        guid: new.guid,
        parent: new.parent,
        rdn: new.rdn,
        classes,
        attributes,
        tombstone: None,
    })
}

/// Encode a live object's body, keeping room for the deletion stamp so that
/// every object that could be written can also be deleted.
/// Spec: docs/32 §8; docs/29 §5.
fn encode_live_body(obj: &Object) -> Result<Vec<u8>> {
    let body = record::encode_object_body(obj).map_err(Error::Rejected)?;
    if body.len() > MAX_RECORD_BODY_LEN - record::STAMP_LEN {
        return Err(Error::Rejected(Violation::RecordTooLarge));
    }
    Ok(body)
}

/// Plan a creation. Spec: docs/32 §2, §4, §7; docs/12 D44.
fn plan_create(
    txn: &WriteTransaction,
    store: &Store,
    new: NewObject,
    origin: &Origin,
) -> Result<Vec<Write>> {
    // Validate the request before touching storage. A Secret attribute is
    // refused before anything else about it is examined. Spec: D44.
    if new.attributes.len() > MAX_ATTRIBUTES_PER_OBJECT {
        return Err(Error::Rejected(Violation::TooManyAttributes));
    }
    for (id, _) in &new.attributes {
        store.schema.check_writable(*id).map_err(Error::Rejected)?;
    }
    let obj = build_new_object(new, origin).map_err(Error::Rejected)?;
    store
        .schema
        .validate_object(&obj)
        .map_err(Error::Rejected)?;
    let body = encode_live_body(&obj)?;

    let objects = txn.open_table(OBJECT_TABLE)?;
    let names = txn.open_table(NAME_INDEX_TABLE)?;
    let counts = txn.open_table(CHILD_COUNT_TABLE)?;

    // The GUID is free: no live object and no tombstone holds it.
    let object_key = obj.guid.to_packet();
    if raw_get(&objects, &object_key)?.is_some() {
        return Err(Error::ObjectExists);
    }
    // The parent is a live object. Spec: docs/32 §2 (DIT).
    if let Some(parent) = obj.parent {
        match load_object(&objects, &store.key, parent)? {
            Some(p) if !p.is_tombstone() => {}
            _ => return Err(Error::NoSuchParent),
        }
    }
    // The name is free under the parent. Spec: docs/32 §2.
    if resolve_name(&names, &objects, &store.key, obj.parent, &obj.rdn)?.is_some() {
        return Err(Error::NameExists);
    }

    let name_key = record::name_index_key(obj.parent, &obj.rdn);
    let mut writes = vec![
        Write {
            table: TableId::Objects,
            key: object_key.to_vec(),
            value: Some(integrity::seal(
                &store.key,
                RecordKind::Object,
                &object_key,
                body,
            )?),
        },
        Write {
            table: TableId::NameIndex,
            value: Some(integrity::seal(
                &store.key,
                RecordKind::NameIndex,
                &name_key,
                record::encode_name_index_body(obj.guid),
            )?),
            key: name_key,
        },
    ];
    if let Some(parent) = obj.parent {
        let count = load_child_count(&counts, &store.key, parent)?;
        let next = count
            .checked_add(1)
            .and_then(NonZeroU64::new)
            .ok_or(Error::Inconsistent(RecordKind::ChildCount))?;
        let count_key = parent.to_packet();
        writes.push(Write {
            table: TableId::ChildCount,
            key: count_key.to_vec(),
            value: Some(integrity::seal(
                &store.key,
                RecordKind::ChildCount,
                &count_key,
                record::encode_child_count_body(next),
            )?),
        });
    }
    Ok(writes)
}

/// Replace one attribute's value set inside `obj`. Kept values keep their
/// stamps; new values get `version` = (highest version among the
/// attribute's current values) + 1. Spec: docs/29 §2 (D119).
fn replace_values(
    obj: &mut Object,
    id: AttrId,
    values: Vec<Vec<u8>>,
    origin: &Origin,
) -> Result<()> {
    if values.is_empty() {
        obj.attributes.retain(|a| a.id != id);
        return Ok(());
    }
    let old: &[StampedValue] = obj.attribute(id).map_or(&[], |a| a.values.as_slice());
    let next_version = old
        .iter()
        .map(|v| v.stamp.version)
        .max()
        .unwrap_or(0)
        .checked_add(1)
        .ok_or(Error::VersionOverflow)?;
    let mut new_values = Vec::new();
    for value in values {
        let kept = old
            .binary_search_by(|o| o.value.as_slice().cmp(value.as_slice()))
            .ok()
            .and_then(|i| old.get(i));
        match kept {
            Some(k) => new_values.push(k.clone()),
            None => new_values.push(StampedValue {
                value,
                stamp: origin.stamp(next_version),
            }),
        }
    }
    obj.attributes.retain(|a| a.id != id);
    obj.attributes.push(Attribute {
        id,
        values: new_values,
    });
    obj.attributes.sort_unstable_by_key(|a| a.id);
    Ok(())
}

/// Plan a modification. Spec: docs/32 §4, §7; docs/29 §2; docs/12 D44.
fn plan_modify(
    txn: &WriteTransaction,
    store: &Store,
    guid: Guid,
    changes: Vec<AttributeChange>,
    origin: &Origin,
) -> Result<Vec<Write>> {
    if changes.len() > MAX_ATTRIBUTES_PER_OBJECT {
        return Err(Error::Rejected(Violation::TooManyAttributes));
    }
    let mut named = BTreeSet::new();
    for change in &changes {
        let AttributeChange::Replace { id, .. } = change;
        store.schema.check_writable(*id).map_err(Error::Rejected)?;
        if !named.insert(*id) {
            return Err(Error::Rejected(Violation::DuplicateAttribute(*id)));
        }
    }

    let objects = txn.open_table(OBJECT_TABLE)?;
    let original = match load_object(&objects, &store.key, guid)? {
        Some(o) if !o.is_tombstone() => o,
        _ => return Err(Error::NoSuchObject),
    };
    store
        .schema
        .validate_object(&original)
        .map_err(Error::StoredObjectRejected)?;

    let mut obj = original.clone();
    for change in changes {
        let AttributeChange::Replace { id, values } = change;
        let values = normalize_values(id, values).map_err(Error::Rejected)?;
        replace_values(&mut obj, id, values, origin)?;
    }
    if obj == original {
        return Ok(Vec::new());
    }
    store
        .schema
        .validate_object(&obj)
        .map_err(Error::Rejected)?;
    let body = encode_live_body(&obj)?;
    let object_key = guid.to_packet();
    Ok(vec![Write {
        table: TableId::Objects,
        key: object_key.to_vec(),
        value: Some(integrity::seal(
            &store.key,
            RecordKind::Object,
            &object_key,
            body,
        )?),
    }])
}

/// Plan a deletion (tombstone). Spec: docs/29 §5 (D121); docs/32 §2.
fn plan_delete(
    txn: &WriteTransaction,
    store: &Store,
    guid: Guid,
    origin: &Origin,
) -> Result<Vec<Write>> {
    let objects = txn.open_table(OBJECT_TABLE)?;
    let names = txn.open_table(NAME_INDEX_TABLE)?;
    let counts = txn.open_table(CHILD_COUNT_TABLE)?;

    let obj = match load_object(&objects, &store.key, guid)? {
        Some(o) if !o.is_tombstone() => o,
        _ => return Err(Error::NoSuchObject),
    };
    // A live object's parent is always live. Spec: docs/32 §2 (DIT).
    if load_child_count(&counts, &store.key, guid)? > 0 {
        return Err(Error::HasChildren);
    }
    // Release the name: the index entry must name exactly this object.
    let name_key = record::name_index_key(obj.parent, &obj.rdn);
    if load_name(&names, &store.key, &name_key)? != Some(guid) {
        return Err(Error::Inconsistent(RecordKind::NameIndex));
    }
    let mut writes = vec![Write {
        table: TableId::NameIndex,
        key: name_key,
        value: None,
    }];
    if let Some(parent) = obj.parent {
        let remaining = load_child_count(&counts, &store.key, parent)?
            .checked_sub(1)
            .ok_or(Error::Inconsistent(RecordKind::ChildCount))?;
        let count_key = parent.to_packet();
        let value = match NonZeroU64::new(remaining) {
            Some(n) => Some(integrity::seal(
                &store.key,
                RecordKind::ChildCount,
                &count_key,
                record::encode_child_count_body(n),
            )?),
            None => None,
        };
        writes.push(Write {
            table: TableId::ChildCount,
            key: count_key.to_vec(),
            value,
        });
    }
    // The reduced tombstone, built fresh (the live object is not mutated):
    // identity (GUID = record key, classes) + deletion marker only. Parent,
    // RDN key and every attribute value with its stamp are dropped.
    // Spec: docs/29 §5 ("tombstone = deletion marker with attr-stamp");
    // docs/25 §5 ("state", D104); Q-062 / A-18.
    let tombstone = Object {
        guid,
        parent: None,
        rdn: Vec::new(),
        classes: obj.classes.clone(),
        attributes: Vec::new(),
        tombstone: Some(origin.stamp(1)),
    };
    let body = record::encode_object_body(&tombstone).map_err(Error::Rejected)?;
    let object_key = guid.to_packet();
    writes.push(Write {
        table: TableId::Objects,
        key: object_key.to_vec(),
        value: Some(integrity::seal(
            &store.key,
            RecordKind::Object,
            &object_key,
            body,
        )?),
    });
    Ok(writes)
}

/// `true` if a tombstone of time `t` is older than `lifetime` at `now`
/// (`t + lifetime < now`); an overflowing sum keeps the tombstone.
/// Spec: docs/29 §5 (D121).
fn tombstone_expired(t: Timestamp, now: Timestamp, lifetime: u64) -> bool {
    t.0.checked_add(lifetime)
        .is_some_and(|deadline| deadline < now.0)
}

/// Plan a purge: authenticate every object record, collect expired
/// tombstones. Spec: docs/29 §5 (D121); docs/32 §3.
fn plan_purge(
    txn: &WriteTransaction,
    store: &Store,
    now: Timestamp,
    lifetime: u64,
) -> Result<Vec<Write>> {
    let objects = txn.open_table(OBJECT_TABLE)?;
    let mut writes = Vec::new();
    for entry in objects.iter()? {
        let (k, v) = entry?;
        let record_key = k.value();
        let guid = Guid::decode(record_key).map_err(|_| Error::Tamper(RecordKind::Object))?;
        let body = integrity::open(&store.key, RecordKind::Object, record_key, v.value())?;
        let obj = record::decode_object_body(guid, body)
            .map_err(|e| Error::RecordMalformed(RecordKind::Object, e))?;
        if let Some(stamp) = obj.tombstone {
            if tombstone_expired(stamp.wall_clock, now, lifetime) {
                writes.push(Write {
                    table: TableId::Objects,
                    key: record_key.to_vec(),
                    value: None,
                });
            }
        }
    }
    Ok(writes)
}

/// Apply planned writes inside the redb transaction. Spec: D136.
fn apply_writes(txn: &WriteTransaction, writes: &[Write]) -> Result<()> {
    let mut objects = txn.open_table(OBJECT_TABLE)?;
    let mut names = txn.open_table(NAME_INDEX_TABLE)?;
    let mut counts = txn.open_table(CHILD_COUNT_TABLE)?;
    for w in writes {
        let table = match w.table {
            TableId::Objects => &mut objects,
            TableId::NameIndex => &mut names,
            TableId::ChildCount => &mut counts,
        };
        match &w.value {
            Some(value) => {
                table.insert(w.key.as_slice(), value.as_slice())?;
            }
            None => {
                table.remove(w.key.as_slice())?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Source: docs/29 §5 — kept for the lifetime, then collected; boundary and
    // overflow behaviour as documented on `purge_tombstones`.
    #[test]
    fn tombstone_expiry_rule() {
        assert!(!tombstone_expired(Timestamp(100), Timestamp(150), 50));
        assert!(tombstone_expired(Timestamp(100), Timestamp(151), 50));
        assert!(!tombstone_expired(Timestamp(100), Timestamp(50), 0));
        assert!(!tombstone_expired(
            Timestamp(u64::MAX),
            Timestamp(u64::MAX),
            1
        ));
    }
}
