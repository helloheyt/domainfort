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
//! | `dirstore.back_links` | [`record::back_link_key`] | reverse-link body + tag |
//! | `dirstore.unique_index` | [`record::unique_index_key`] | unique-index body + tag |
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
//! # Cross-checks
//!
//! Every index entry is authenticated (tag) and then checked against the
//! object it names before it is believed: a name entry must name a live
//! object with that parent and RDN key; a reverse-link entry
//! `(target, back id, source)` must name a live `source` that holds `target`
//! in the forward link `back id − 1`; a unique entry must name a live object
//! that holds a value with that comparison key. Anything else is
//! [`Error::Inconsistent`] — a replayed or stale record (docs/32 §3; Q-060).
//!
//! Spec: docs/32 §2 (D134), §3 (D135), §6 (D39), §7 (D136); docs/29 §5
//! (D121); docs/46 §8.3-§8.5.

use crate::comparison;
use crate::error::{Error, RecordKind, Result, Violation};
use crate::integrity::{self, IntegrityKey};
use crate::record;
use crate::schema::{AttributeDefinition, Link, Schema};
use crate::types::{
    AttrId, Attribute, AttributeChange, ClassId, NewObject, Object, Origin, StampedValue,
    Timestamp, Tombstone,
};
use crate::{
    MAX_ATTRIBUTES_PER_OBJECT, MAX_CLASSES_PER_OBJECT, MAX_RDN_KEY_LEN, MAX_RECORD_BODY_LEN,
    MAX_VALUES_PER_ATTRIBUTE, MAX_VALUE_LEN,
};
use core::num::NonZeroU64;
use dtyp::{Guid, GUID_PACKET_LEN};
use redb::{
    Database, ReadTransaction, ReadableDatabase, ReadableTable, ReadableTableMetadata,
    TableDefinition, WriteTransaction,
};
use std::collections::{BTreeMap, BTreeSet};
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
/// `(target, back link id, source)` for every forward-link value.
/// Spec: docs/46 §8.4.
const BACK_LINK_TABLE: TableDefinition<'static, Raw, Raw> =
    TableDefinition::new("dirstore.back_links");
/// `(attribute, comparison key) -> GUID` for every value of a unique
/// attribute. Spec: docs/46 §8.5.
const UNIQUE_INDEX_TABLE: TableDefinition<'static, Raw, Raw> =
    TableDefinition::new("dirstore.unique_index");
/// The single key of the meta table.
const META_KEY: &[u8] = b"store";

/// Which table a planned write targets.
#[derive(Debug, Clone, Copy)]
enum TableId {
    Objects,
    NameIndex,
    ChildCount,
    BackLinks,
    UniqueIndex,
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
    let links = txn.open_table(BACK_LINK_TABLE)?;
    let uniques = txn.open_table(UNIQUE_INDEX_TABLE)?;
    match raw_get(&meta, META_KEY)? {
        Some(stored) => {
            let body = integrity::open(key, RecordKind::Meta, META_KEY, &stored)?;
            record::decode_meta_body(body)
                .map_err(|e| Error::RecordMalformed(RecordKind::Meta, e))?;
        }
        None => {
            // A database with records but no meta record has been edited
            // beneath us; never silently adopt it under a new key.
            if !objects.is_empty()?
                || !names.is_empty()?
                || !counts.is_empty()?
                || !links.is_empty()?
                || !uniques.is_empty()?
            {
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

    /// The GUID of the live child of `parent` (or the root, for `None`) whose
    /// RDN value is `rdn_value`. The RDN key is computed from the value by the
    /// same rule as on create (printable ASCII, A–Z folded — Q-080 interim),
    /// so `"Alice"` finds the child named `"alice"`. The index entry is
    /// authenticated and cross-checked against the object it names.
    /// Spec: docs/32 §2; docs/46 §8.3 item 3.
    pub fn lookup_child(&self, parent: Option<Guid>, rdn_value: &[u8]) -> Result<Option<Guid>> {
        let names = self.txn.open_table(NAME_INDEX_TABLE)?;
        let objects = self.txn.open_table(OBJECT_TABLE)?;
        lookup_child(&names, &objects, &self.store.key, parent, rdn_value)
    }

    /// The sources of the back link `back_attr` on the live object `target`:
    /// every live object that holds `target` in the corresponding forward
    /// link (e.g. the groups an object is a member of), ascending by GUID
    /// packet. Each reverse-link entry is authenticated and cross-checked
    /// against its source. Refused if `back_attr` is not a Back link
    /// ([`Violation::NotBackLink`]); [`Error::NoSuchObject`] if `target` is
    /// not live. Spec: docs/46 §2.3 item 3, §8.4; [MS-ADTS] 3.1.1.1.6.
    pub fn back_links(&self, target: Guid, back_attr: AttrId) -> Result<Vec<Guid>> {
        let links = self.txn.open_table(BACK_LINK_TABLE)?;
        let objects = self.txn.open_table(OBJECT_TABLE)?;
        back_links_of(&links, &objects, self.store, target, back_attr)
    }

    /// The live object that holds `value` (compared by its comparison key)
    /// in the `unique` attribute `attr` — e.g. resolving a SID to a GUID
    /// (docs/46 §2.3 item 1, §8.5). The entry is authenticated and
    /// cross-checked against the object it names.
    /// Spec: docs/46 §8.5.
    pub fn lookup_unique(&self, attr: AttrId, value: &[u8]) -> Result<Option<Guid>> {
        let uniques = self.txn.open_table(UNIQUE_INDEX_TABLE)?;
        let objects = self.txn.open_table(OBJECT_TABLE)?;
        lookup_unique(&uniques, &objects, self.store, attr, value)
    }
}

/// A write transaction. Every change made through it — values, stamps, name
/// index, child counts, reverse links, unique entries and integrity tags —
/// commits together or not at all; dropping it without [`WriteTxn::commit`]
/// aborts it. Spec: docs/32 §7, D136.
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
    /// The RDN key is computed from the RDN attribute of the most specific
    /// class. Refused (nothing written) if the request breaks the schema or a
    /// bound ([`Error::Rejected`] — including any Secret or Derived
    /// attribute, a broken class chain, a parent class that is not a possible
    /// superior, or an RDN value that breaks the naming rules), if a record
    /// already holds the GUID ([`Error::ObjectExists`]), if the parent is not
    /// a live object ([`Error::NoSuchParent`]), if a live child of the parent
    /// already has the RDN key ([`Error::NameExists`]), if an ObjectRef value
    /// names no live object ([`Error::NoSuchTarget`]), or if a unique value is
    /// already held by another object ([`Error::ValueNotUnique`]). Every
    /// value is stamped `version` 1 with `origin`.
    /// Spec: docs/32 §2, §4, §7; docs/29 §2; docs/12 D44; docs/46 §8.2-§8.5.
    pub fn create_object(&mut self, new: NewObject, origin: &Origin) -> Result<()> {
        let writes = plan_create(self.txn()?, self.store, new, origin)?;
        self.apply(writes)
    }

    /// Apply attribute changes to a live object (see
    /// [`AttributeChange::Replace`] for stamping). The resulting object is
    /// validated as a whole. Naming a Secret or Derived attribute in any
    /// change — even to remove it — is refused, as is naming the object's
    /// RDN attribute (renaming is a separate operation). Reverse-link and
    /// unique entries follow the change in the same transaction. A change
    /// that leaves every value as it was writes nothing.
    /// Spec: docs/32 §4, §7; docs/29 §2; docs/12 D44; docs/46 §8.2-§8.5;
    /// [MS-ADTS] 3.1.1.5.3.2.
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
    /// stamp are dropped; its name and unique values are released; its own
    /// reverse-link entries go; it disappears from normal reads. Refused
    /// while it has live children ([`Error::HasChildren`]).
    ///
    /// **Referential integrity** (docs/46 §2.3 item 4, §8.4; [MS-ADTS]
    /// 3.1.1.1.6: "When an object o is … transformed into a tombstone …, any
    /// forward link reference to o is removed"): in the same transaction, the
    /// deleted object's GUID is removed from every forward-link attribute of
    /// every live object that references it, with those reverse-link entries.
    /// Values left behind keep their stamps; a removal leaves no stamp (as
    /// for any value removal, A-20).
    ///
    /// Residual — cost: deleting an object referenced from N objects (e.g. a
    /// member of N groups) reads and rewrites N object records, and N is
    /// bounded only by the store's contents. Deletion is a privileged
    /// operation (the PDP gates it); treat it as expensive (docs/46 §8.4).
    ///
    /// Residual — a reverse-link entry removed beneath the engine is not
    /// noticed here: its referrer keeps a reference to the tombstone. Stale
    /// entries are caught (cross-check); removed ones need the store root of
    /// P-7 (Q-060; Q-091 item 11).
    ///
    /// Residual — no physical erasure guarantee: redb stores data in
    /// copy-on-write B-trees (redb crate docs), so the bytes of the replaced
    /// live record (the deleted values) can remain in the file's free pages
    /// until those pages are reused. The engine removes them from every
    /// reachable record, not from the disk. Q-062.
    ///
    /// Spec: docs/29 §5 (D121); docs/32 §2; docs/25 §5 ("state"); Q-062 /
    /// A-18; docs/46 §8.4-§8.5.
    pub fn delete_object(&mut self, guid: Guid, origin: &Origin) -> Result<()> {
        let writes = plan_delete(self.txn()?, self.store, guid, origin)?;
        self.apply(writes)
    }

    /// Physically remove every tombstone older than `lifetime`, i.e. whose
    /// tombstone time `t` (its deletion stamp's wall-clock) satisfies
    /// `t + lifetime < now`. A sum that overflows is treated as "not yet
    /// expired" (keep). Every object record is authenticated first, and no
    /// reverse-link entry may still target an expiring tombstone (any such
    /// entry is authenticated, then reported as [`Error::Inconsistent`]); any
    /// failure aborts the purge with nothing removed. Returns the number of
    /// tombstones removed. Spec: docs/29 §5 (D121: tombstones are kept for a
    /// lifetime, then collected); docs/46 §8.4.
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
    pub fn lookup_child(&self, parent: Option<Guid>, rdn_value: &[u8]) -> Result<Option<Guid>> {
        let txn = self.txn()?;
        let names = txn.open_table(NAME_INDEX_TABLE)?;
        let objects = txn.open_table(OBJECT_TABLE)?;
        lookup_child(&names, &objects, &self.store.key, parent, rdn_value)
    }

    /// [`Snapshot::back_links`], seeing this transaction's own writes.
    pub fn back_links(&self, target: Guid, back_attr: AttrId) -> Result<Vec<Guid>> {
        let txn = self.txn()?;
        let links = txn.open_table(BACK_LINK_TABLE)?;
        let objects = txn.open_table(OBJECT_TABLE)?;
        back_links_of(&links, &objects, self.store, target, back_attr)
    }

    /// [`Snapshot::lookup_unique`], seeing this transaction's own writes.
    pub fn lookup_unique(&self, attr: AttrId, value: &[u8]) -> Result<Option<Guid>> {
        let txn = self.txn()?;
        let uniques = txn.open_table(UNIQUE_INDEX_TABLE)?;
        let objects = txn.open_table(OBJECT_TABLE)?;
        lookup_unique(&uniques, &objects, self.store, attr, value)
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

/// Load a live object record (tombstones and absent records are `None`).
fn load_live<T: ReadableTable<Raw, Raw>>(
    objects: &T,
    key: &IntegrityKey,
    guid: Guid,
) -> Result<Option<Object>> {
    Ok(load_object(objects, key, guid)?.filter(|o| !o.is_tombstone()))
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

/// `true` if an authentic reverse-link entry exists under `record_key`.
/// Spec: docs/46 §8.4; docs/32 §3.
fn load_back_link<T: ReadableTable<Raw, Raw>>(
    links: &T,
    key: &IntegrityKey,
    record_key: &[u8],
) -> Result<bool> {
    let Some(stored) = raw_get(links, record_key)? else {
        return Ok(false);
    };
    let body = integrity::open(key, RecordKind::BackLink, record_key, &stored)?;
    record::decode_back_link_body(body)
        .map_err(|e| Error::RecordMalformed(RecordKind::BackLink, e))?;
    Ok(true)
}

/// Load a unique-index entry: the GUID it names. Spec: docs/46 §8.5;
/// docs/32 §3.
fn load_unique<T: ReadableTable<Raw, Raw>>(
    uniques: &T,
    key: &IntegrityKey,
    record_key: &[u8],
) -> Result<Option<Guid>> {
    let Some(stored) = raw_get(uniques, record_key)? else {
        return Ok(None);
    };
    let body = integrity::open(key, RecordKind::UniqueIndex, record_key, &stored)?;
    record::decode_unique_index_body(body)
        .map(Some)
        .map_err(|e| Error::RecordMalformed(RecordKind::UniqueIndex, e))
}

/// Every authentic reverse-link entry whose key starts with `prefix`, as
/// `(target, back link id, source)`, in key order. Each entry is
/// authenticated before its key is parsed; one bad entry fails the scan.
/// Spec: docs/46 §8.4 (prefix scan); docs/32 §3.
fn scan_back_links<T: ReadableTable<Raw, Raw>>(
    links: &T,
    key: &IntegrityKey,
    prefix: &[u8],
) -> Result<Vec<(Guid, u32, Guid)>> {
    let mut out = Vec::new();
    for entry in links.range::<&[u8]>(prefix..)? {
        let (k, v) = entry?;
        let record_key = k.value();
        if !record_key.starts_with(prefix) {
            break;
        }
        let body = integrity::open(key, RecordKind::BackLink, record_key, v.value())?;
        record::decode_back_link_body(body)
            .map_err(|e| Error::RecordMalformed(RecordKind::BackLink, e))?;
        out.push(
            record::decode_back_link_key(record_key)
                .map_err(|e| Error::RecordMalformed(RecordKind::BackLink, e))?,
        );
    }
    Ok(out)
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

/// Resolve `(parent, rdn key)` to a live object. The entry must name a live
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

/// Look a child up by its RDN value: compute the key, then resolve it.
/// Spec: docs/32 §2; docs/46 §8.3 item 3; Q-080.
fn lookup_child<N: ReadableTable<Raw, Raw>, O: ReadableTable<Raw, Raw>>(
    names: &N,
    objects: &O,
    key: &IntegrityKey,
    parent: Option<Guid>,
    rdn_value: &[u8],
) -> Result<Option<Guid>> {
    let rdn = comparison::lookup_rdn_key(rdn_value).map_err(Error::Rejected)?;
    resolve_name(names, objects, key, parent, &rdn)
}

/// The packet bytes of an ObjectRef value, as a GUID (the value passed the
/// ObjectRef syntax, so it is 16 bytes). Spec: docs/46 §8.1.
fn ref_target(id: AttrId, value: &[u8]) -> Result<Guid> {
    Guid::decode(value).map_err(|_| Error::Rejected(Violation::InvalidValueSyntax(id)))
}

/// The targets of an attribute's ObjectRef values, ascending by packet.
fn ref_targets(obj: &Object, id: AttrId) -> Result<BTreeSet<[u8; GUID_PACKET_LEN]>> {
    let mut out = BTreeSet::new();
    if let Some(attr) = obj.attribute(id) {
        for v in &attr.values {
            out.insert(ref_target(id, &v.value)?.to_packet());
        }
    }
    Ok(out)
}

/// `true` if `obj` holds `target` among the values of attribute `id`.
/// Spec: docs/46 §8.4 (cross-check of a reverse-link entry).
fn holds_ref(obj: &Object, id: AttrId, target: Guid) -> bool {
    let packet = target.to_packet();
    obj.attribute(id).is_some_and(|a| {
        a.values
            .binary_search_by(|v| v.value.as_slice().cmp(packet.as_slice()))
            .is_ok()
    })
}

/// The back link id that pairs with an (even) forward link id: forward + 1,
/// written as setting bit 0 (cannot overflow). Spec: [MS-ADTS] 3.1.1.2.3.
fn back_id(forward_link_id: u32) -> u32 {
    forward_link_id | 1
}

/// Comparison keys of a unique attribute's values on `obj`.
/// Spec: docs/46 §8.5.
fn unique_keys(obj: &Object, def: &AttributeDefinition) -> Result<BTreeSet<Vec<u8>>> {
    let mut out = BTreeSet::new();
    if let Some(attr) = obj.attribute(def.id) {
        for v in &attr.values {
            let k =
                comparison::unique_key(def.id, def.syntax, &v.value).map_err(Error::Rejected)?;
            if !out.insert(k) {
                return Err(Error::Rejected(Violation::DuplicateValue(def.id)));
            }
        }
    }
    Ok(out)
}

/// `true` if `obj` holds a value of the unique attribute `def` whose
/// comparison key is `ckey`. Spec: docs/46 §8.5 (cross-check).
fn holds_unique_key(obj: &Object, def: &AttributeDefinition, ckey: &[u8]) -> bool {
    obj.attribute(def.id).is_some_and(|a| {
        a.values
            .iter()
            .any(|v| comparison::unique_key(def.id, def.syntax, &v.value).is_ok_and(|k| k == ckey))
    })
}

/// Resolve a unique-index entry to the live object holding the value; a
/// stale entry is [`Error::Inconsistent`]. Spec: docs/46 §8.5; docs/32 §3.
fn resolve_unique<U: ReadableTable<Raw, Raw>, O: ReadableTable<Raw, Raw>>(
    uniques: &U,
    objects: &O,
    key: &IntegrityKey,
    def: &AttributeDefinition,
    ckey: &[u8],
) -> Result<Option<Guid>> {
    let record_key = record::unique_index_key(def.id, ckey);
    let Some(owner) = load_unique(uniques, key, &record_key)? else {
        return Ok(None);
    };
    match load_live(objects, key, owner)? {
        Some(obj) if holds_unique_key(&obj, def, ckey) => Ok(Some(owner)),
        _ => Err(Error::Inconsistent(RecordKind::UniqueIndex)),
    }
}

/// [`Snapshot::lookup_unique`]. Spec: docs/46 §8.5.
fn lookup_unique<U: ReadableTable<Raw, Raw>, O: ReadableTable<Raw, Raw>>(
    uniques: &U,
    objects: &O,
    store: &Store,
    attr: AttrId,
    value: &[u8],
) -> Result<Option<Guid>> {
    let def = store
        .schema
        .attribute(attr)
        .ok_or(Error::Rejected(Violation::UnknownAttribute(attr)))?;
    if !def.unique {
        return Err(Error::Rejected(Violation::NotUnique(attr)));
    }
    // Bound the input before any work. Spec: docs/32 §8.
    if value.len() > def.max_value_len {
        return Err(Error::Rejected(Violation::ValueTooLarge(attr)));
    }
    let ckey = comparison::unique_key(attr, def.syntax, value).map_err(Error::Rejected)?;
    resolve_unique(uniques, objects, &store.key, def, &ckey)
}

/// [`Snapshot::back_links`]. Spec: docs/46 §8.4.
fn back_links_of<L: ReadableTable<Raw, Raw>, O: ReadableTable<Raw, Raw>>(
    links: &L,
    objects: &O,
    store: &Store,
    target: Guid,
    back_attr: AttrId,
) -> Result<Vec<Guid>> {
    let def = store
        .schema
        .attribute(back_attr)
        .ok_or(Error::Rejected(Violation::UnknownAttribute(back_attr)))?;
    let Some(Link::Back { link_id }) = def.link else {
        return Err(Error::Rejected(Violation::NotBackLink(back_attr)));
    };
    let forward = store
        .schema
        .forward_link_for_back_id(link_id)
        .ok_or(Error::Rejected(Violation::NotBackLink(back_attr)))?;
    if load_live(objects, &store.key, target)?.is_none() {
        return Err(Error::NoSuchObject);
    }
    let prefix = record::back_link_prefix(target, Some(link_id));
    let mut sources = Vec::new();
    for (_, _, source) in scan_back_links(links, &store.key, &prefix)? {
        match load_live(objects, &store.key, source)? {
            Some(obj) if holds_ref(&obj, forward, target) => sources.push(source),
            _ => return Err(Error::Inconsistent(RecordKind::BackLink)),
        }
    }
    Ok(sources)
}

/// A live object, re-validated against the schema before it is handed out.
/// Spec: docs/29 §5 (tombstones invisible); docs/14 D60; docs/12 D44.
fn get_live<T: ReadableTable<Raw, Raw>>(
    objects: &T,
    store: &Store,
    guid: Guid,
) -> Result<Option<Object>> {
    match load_live(objects, &store.key, guid)? {
        Some(obj) => {
            store
                .schema
                .validate_object(&obj)
                .map_err(Error::StoredObjectRejected)?;
            Ok(Some(obj))
        }
        None => Ok(None),
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

/// Build and validate the canonical object of a creation request: every
/// value stamped `version` 1, the RDN key computed from the RDN value.
/// Returns the object and its most specific class.
/// Spec: docs/32 §2, §4; docs/29 §2; docs/46 §8.3; [MS-ADTS] 3.1.1.1.3.
fn build_new_object(
    schema: &Schema,
    new: NewObject,
    origin: &Origin,
) -> core::result::Result<(Object, ClassId), Violation> {
    // "No actual object has objectGUID equal to the NULL GUID".
    // Spec: [MS-ADTS] 3.1.1.1.3; Q-091 item 6.
    if new.guid.to_packet() == [0u8; GUID_PACKET_LEN] {
        return Err(Violation::NullGuid);
    }
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
    let mut obj = Object {
        guid: new.guid,
        parent: new.parent,
        rdn: Vec::new(),
        classes,
        attributes,
        tombstone: None,
    };
    // The RDN key is computed here, in one place. Spec: docs/46 §8.3 item 3.
    let (most_specific, rdn) = schema.check_object(&obj)?;
    obj.rdn = rdn;
    Ok((obj, most_specific))
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

/// A planned insert of a tagged record.
fn seal_write(
    store: &Store,
    table: TableId,
    kind: RecordKind,
    key: Vec<u8>,
    body: Vec<u8>,
) -> Result<Write> {
    let value = integrity::seal(&store.key, kind, &key, body)?;
    Ok(Write {
        table,
        key,
        value: Some(value),
    })
}

/// A planned removal.
fn remove_write(table: TableId, key: Vec<u8>) -> Write {
    Write {
        table,
        key,
        value: None,
    }
}

/// A planned (re)write of a live object record.
fn object_write(store: &Store, obj: &Object) -> Result<Write> {
    let body = encode_live_body(obj)?;
    seal_write(
        store,
        TableId::Objects,
        RecordKind::Object,
        obj.guid.to_packet().to_vec(),
        body,
    )
}

/// A planned insert of the reverse-link entry `(target, back id, source)`.
/// Spec: docs/46 §8.4.
fn back_link_insert(store: &Store, target: Guid, back: u32, source: Guid) -> Result<Write> {
    seal_write(
        store,
        TableId::BackLinks,
        RecordKind::BackLink,
        record::back_link_key(target, back, source).to_vec(),
        record::encode_back_link_body(),
    )
}

/// A planned removal of the reverse-link entry `(target, back id, source)`,
/// which must exist and be authentic — a missing entry is
/// [`Error::Inconsistent`]. Spec: docs/46 §8.4; docs/32 §3.
fn back_link_removal<L: ReadableTable<Raw, Raw>>(
    links: &L,
    store: &Store,
    target: Guid,
    back: u32,
    source: Guid,
) -> Result<Write> {
    let key = record::back_link_key(target, back, source).to_vec();
    if !load_back_link(links, &store.key, &key)? {
        return Err(Error::Inconsistent(RecordKind::BackLink));
    }
    Ok(remove_write(TableId::BackLinks, key))
}

/// A planned removal of a unique entry, which must name `owner` — anything
/// else is [`Error::Inconsistent`]. Spec: docs/46 §8.5; docs/32 §3.
fn unique_removal<U: ReadableTable<Raw, Raw>>(
    uniques: &U,
    store: &Store,
    attr: AttrId,
    ckey: &[u8],
    owner: Guid,
) -> Result<Write> {
    let key = record::unique_index_key(attr, ckey);
    if load_unique(uniques, &store.key, &key)? != Some(owner) {
        return Err(Error::Inconsistent(RecordKind::UniqueIndex));
    }
    Ok(remove_write(TableId::UniqueIndex, key))
}

/// The live target of a new ObjectRef value, else [`Error::NoSuchTarget`].
/// Spec: docs/46 §2.3 item 4, §8.4; [MS-ADTS] 3.1.1.1.6 (noSuchObject, also
/// for a tombstone).
fn require_live_target<O: ReadableTable<Raw, Raw>>(
    objects: &O,
    store: &Store,
    attr: AttrId,
    target: Guid,
) -> Result<()> {
    match load_live(objects, &store.key, target)? {
        Some(_) => Ok(()),
        None => Err(Error::NoSuchTarget(attr)),
    }
}

/// The parent's most specific class must be a possible superior of the new
/// object's class. Spec: docs/46 §8.3 item 2; [MS-ADTS] 3.1.1.5.2.2.
fn check_parent_class(store: &Store, parent: &Object, child_class: ClassId) -> Result<()> {
    let parent_class = store
        .schema
        .most_specific_class(&parent.classes)
        .ok_or(Error::StoredObjectRejected(Violation::InvalidClassChain))?;
    let child = store
        .schema
        .class(child_class)
        .ok_or(Error::Rejected(Violation::UnknownClass(child_class)))?;
    if !child.poss_superiors.contains(&parent_class) {
        return Err(Error::Rejected(Violation::ParentClassNotAllowed(
            parent_class,
        )));
    }
    Ok(())
}

/// Plan a creation. Spec: docs/32 §2, §4, §7; docs/12 D44; docs/46 §8.3-§8.5.
fn plan_create(
    txn: &WriteTransaction,
    store: &Store,
    new: NewObject,
    origin: &Origin,
) -> Result<Vec<Write>> {
    // Validate the request before touching storage. A Secret attribute is
    // refused before anything else about it is examined, then a Derived one.
    // Spec: D44; docs/46 §8.2.
    if new.attributes.len() > MAX_ATTRIBUTES_PER_OBJECT {
        return Err(Error::Rejected(Violation::TooManyAttributes));
    }
    for (id, _) in &new.attributes {
        store.schema.check_writable(*id).map_err(Error::Rejected)?;
    }
    let (obj, most_specific) =
        build_new_object(&store.schema, new, origin).map_err(Error::Rejected)?;
    let object = object_write(store, &obj)?;

    let objects = txn.open_table(OBJECT_TABLE)?;
    let names = txn.open_table(NAME_INDEX_TABLE)?;
    let counts = txn.open_table(CHILD_COUNT_TABLE)?;
    let uniques = txn.open_table(UNIQUE_INDEX_TABLE)?;

    // The GUID is free: no live object and no tombstone holds it.
    if raw_get(&objects, &obj.guid.to_packet())?.is_some() {
        return Err(Error::ObjectExists);
    }
    // The parent is a live object of an allowed class. Spec: docs/32 §2
    // (DIT); docs/46 §8.3 item 2.
    if let Some(parent) = obj.parent {
        let Some(p) = load_live(&objects, &store.key, parent)? else {
            return Err(Error::NoSuchParent);
        };
        check_parent_class(store, &p, most_specific)?;
    }
    // The name is free under the parent. Spec: docs/32 §2.
    if resolve_name(&names, &objects, &store.key, obj.parent, &obj.rdn)?.is_some() {
        return Err(Error::NameExists);
    }

    let name_key = record::name_index_key(obj.parent, &obj.rdn);
    let mut writes = vec![
        object,
        seal_write(
            store,
            TableId::NameIndex,
            RecordKind::NameIndex,
            name_key,
            record::encode_name_index_body(obj.guid),
        )?,
    ];
    if let Some(parent) = obj.parent {
        let count = load_child_count(&counts, &store.key, parent)?;
        let next = count
            .checked_add(1)
            .and_then(NonZeroU64::new)
            .ok_or(Error::Inconsistent(RecordKind::ChildCount))?;
        writes.push(seal_write(
            store,
            TableId::ChildCount,
            RecordKind::ChildCount,
            parent.to_packet().to_vec(),
            record::encode_child_count_body(next),
        )?);
    }

    for attr in &obj.attributes {
        let Some(def) = store.schema.attribute(attr.id) else {
            return Err(Error::Rejected(Violation::UnknownAttribute(attr.id)));
        };
        // Forward links: live targets, one reverse-link entry per value.
        // Spec: docs/46 §8.4.
        if let Some(link_id) = def.forward_link_id() {
            for v in &attr.values {
                let target = ref_target(attr.id, &v.value)?;
                require_live_target(&objects, store, attr.id, target)?;
                writes.push(back_link_insert(store, target, back_id(link_id), obj.guid)?);
            }
        }
        // Unique values: free, one entry per comparison key. Spec: §8.5.
        if def.unique {
            for ckey in unique_keys(&obj, def)? {
                if resolve_unique(&uniques, &objects, &store.key, def, &ckey)?.is_some() {
                    return Err(Error::ValueNotUnique(attr.id));
                }
                writes.push(seal_write(
                    store,
                    TableId::UniqueIndex,
                    RecordKind::UniqueIndex,
                    record::unique_index_key(attr.id, &ckey),
                    record::encode_unique_index_body(obj.guid),
                )?);
            }
        }
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

/// Plan a modification. Spec: docs/32 §4, §7; docs/29 §2; docs/12 D44;
/// docs/46 §8.2-§8.5; [MS-ADTS] 3.1.1.5.3.2.
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
    let links = txn.open_table(BACK_LINK_TABLE)?;
    let uniques = txn.open_table(UNIQUE_INDEX_TABLE)?;
    let Some(original) = load_live(&objects, &store.key, guid)? else {
        return Err(Error::NoSuchObject);
    };
    store
        .schema
        .validate_object(&original)
        .map_err(Error::StoredObjectRejected)?;
    // The RDN attribute is changed only by a rename. Spec: [MS-ADTS]
    // 3.1.1.5.3.2 ("Updates to … the object's naming attribute … are
    // disallowed"); docs/46 §8.3 item 3; Q-091 item 5.
    let rdn_attr = store
        .schema
        .most_specific_class(&original.classes)
        .and_then(|c| store.schema.class(c))
        .map(|c| c.rdn_attr)
        .ok_or(Error::StoredObjectRejected(Violation::InvalidClassChain))?;
    if named.contains(&rdn_attr) {
        return Err(Error::Rejected(Violation::RdnAttributeNotModifiable(
            rdn_attr,
        )));
    }

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
    let mut writes = vec![object_write(store, &obj)?];

    for id in &named {
        let Some(def) = store.schema.attribute(*id) else {
            return Err(Error::Rejected(Violation::UnknownAttribute(*id)));
        };
        // Reverse links follow the forward values. Spec: docs/46 §8.4.
        if let Some(link_id) = def.forward_link_id() {
            let before = ref_targets(&original, *id)?;
            let after = ref_targets(&obj, *id)?;
            for gone in before.difference(&after) {
                let target = Guid::from_packet(gone);
                writes.push(back_link_removal(
                    &links,
                    store,
                    target,
                    back_id(link_id),
                    guid,
                )?);
            }
            for added in after.difference(&before) {
                let target = Guid::from_packet(added);
                require_live_target(&objects, store, *id, target)?;
                writes.push(back_link_insert(store, target, back_id(link_id), guid)?);
            }
        }
        // Unique entries follow the comparison keys. Spec: docs/46 §8.5.
        if def.unique {
            let before = unique_keys(&original, def)?;
            let after = unique_keys(&obj, def)?;
            for gone in before.difference(&after) {
                writes.push(unique_removal(&uniques, store, *id, gone, guid)?);
            }
            for added in after.difference(&before) {
                if resolve_unique(&uniques, &objects, &store.key, def, added)?.is_some() {
                    return Err(Error::ValueNotUnique(*id));
                }
                writes.push(seal_write(
                    store,
                    TableId::UniqueIndex,
                    RecordKind::UniqueIndex,
                    record::unique_index_key(*id, added),
                    record::encode_unique_index_body(guid),
                )?);
            }
        }
    }
    Ok(writes)
}

/// Plan a deletion (tombstone), with referential integrity.
/// Spec: docs/29 §5 (D121); docs/32 §2; docs/46 §2.3 item 4, §8.4-§8.5;
/// [MS-ADTS] 3.1.1.1.6.
fn plan_delete(
    txn: &WriteTransaction,
    store: &Store,
    guid: Guid,
    origin: &Origin,
) -> Result<Vec<Write>> {
    let objects = txn.open_table(OBJECT_TABLE)?;
    let names = txn.open_table(NAME_INDEX_TABLE)?;
    let counts = txn.open_table(CHILD_COUNT_TABLE)?;
    let links = txn.open_table(BACK_LINK_TABLE)?;
    let uniques = txn.open_table(UNIQUE_INDEX_TABLE)?;

    let Some(obj) = load_live(&objects, &store.key, guid)? else {
        return Err(Error::NoSuchObject);
    };
    // The object's links and unique values are read through the schema, so
    // the object must satisfy it (fail closed). Spec: docs/14 D60; Q-091
    // item 8.
    store
        .schema
        .validate_object(&obj)
        .map_err(Error::StoredObjectRejected)?;
    // A live object's parent is always live. Spec: docs/32 §2 (DIT).
    if load_child_count(&counts, &store.key, guid)? > 0 {
        return Err(Error::HasChildren);
    }
    // Release the name: the index entry must name exactly this object.
    let name_key = record::name_index_key(obj.parent, &obj.rdn);
    if load_name(&names, &store.key, &name_key)? != Some(guid) {
        return Err(Error::Inconsistent(RecordKind::NameIndex));
    }
    let mut writes = vec![remove_write(TableId::NameIndex, name_key)];
    if let Some(parent) = obj.parent {
        let remaining = load_child_count(&counts, &store.key, parent)?
            .checked_sub(1)
            .ok_or(Error::Inconsistent(RecordKind::ChildCount))?;
        let count_key = parent.to_packet().to_vec();
        writes.push(match NonZeroU64::new(remaining) {
            Some(n) => seal_write(
                store,
                TableId::ChildCount,
                RecordKind::ChildCount,
                count_key,
                record::encode_child_count_body(n),
            )?,
            None => remove_write(TableId::ChildCount, count_key),
        });
    }

    // The object's own forward values and unique values go with the
    // tombstone (A-18), and so do their index entries. Spec: docs/46 §2.3
    // item 4, §8.4, §8.5.
    let mut own_links = BTreeSet::new();
    for attr in &obj.attributes {
        let Some(def) = store.schema.attribute(attr.id) else {
            return Err(Error::StoredObjectRejected(Violation::UnknownAttribute(
                attr.id,
            )));
        };
        if let Some(link_id) = def.forward_link_id() {
            for v in &attr.values {
                let target = ref_target(attr.id, &v.value)?;
                writes.push(back_link_removal(
                    &links,
                    store,
                    target,
                    back_id(link_id),
                    guid,
                )?);
                own_links.insert((target.to_packet(), back_id(link_id)));
            }
        }
        if def.unique {
            for ckey in unique_keys(&obj, def)? {
                writes.push(unique_removal(&uniques, store, attr.id, &ckey, guid)?);
            }
        }
    }

    // Referential integrity: remove this object's GUID from every forward
    // link that references it. Spec: [MS-ADTS] 3.1.1.1.6 ("any forward link
    // reference to o is removed"); docs/46 §8.4.
    let mut referrers: BTreeMap<[u8; GUID_PACKET_LEN], Object> = BTreeMap::new();
    for (_, back, source) in
        scan_back_links(&links, &store.key, &record::back_link_prefix(guid, None))?
    {
        if source == guid {
            // A self-reference: removed above with the object's own values.
            if !own_links.contains(&(guid.to_packet(), back)) {
                return Err(Error::Inconsistent(RecordKind::BackLink));
            }
            continue;
        }
        let forward = store
            .schema
            .forward_link_for_back_id(back)
            .ok_or(Error::Inconsistent(RecordKind::BackLink))?;
        let referrer = match referrers.entry(source.to_packet()) {
            std::collections::btree_map::Entry::Occupied(e) => e.into_mut(),
            std::collections::btree_map::Entry::Vacant(e) => {
                let Some(r) = load_live(&objects, &store.key, source)? else {
                    return Err(Error::Inconsistent(RecordKind::BackLink));
                };
                store
                    .schema
                    .validate_object(&r)
                    .map_err(Error::StoredObjectRejected)?;
                e.insert(r)
            }
        };
        if !holds_ref(referrer, forward, guid) {
            return Err(Error::Inconsistent(RecordKind::BackLink));
        }
        let packet = guid.to_packet();
        for attr in &mut referrer.attributes {
            if attr.id == forward {
                attr.values
                    .retain(|v| v.value.as_slice() != packet.as_slice());
            }
        }
        referrer.attributes.retain(|a| !a.values.is_empty());
        writes.push(remove_write(
            TableId::BackLinks,
            record::back_link_key(guid, back, source).to_vec(),
        ));
    }
    for referrer in referrers.values() {
        store
            .schema
            .validate_object(referrer)
            .map_err(Error::Rejected)?;
        writes.push(object_write(store, referrer)?);
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
    writes.push(seal_write(
        store,
        TableId::Objects,
        RecordKind::Object,
        guid.to_packet().to_vec(),
        body,
    )?);
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
/// tombstones; no reverse-link entry may target one. Spec: docs/29 §5
/// (D121); docs/32 §3; docs/46 §8.4.
fn plan_purge(
    txn: &WriteTransaction,
    store: &Store,
    now: Timestamp,
    lifetime: u64,
) -> Result<Vec<Write>> {
    let objects = txn.open_table(OBJECT_TABLE)?;
    let links = txn.open_table(BACK_LINK_TABLE)?;
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
                // A tombstone is referenced by nothing (its delete removed
                // every reference). Spec: docs/46 §8.4.
                let prefix = record::back_link_prefix(guid, None);
                if !scan_back_links(&links, &store.key, &prefix)?.is_empty() {
                    return Err(Error::Inconsistent(RecordKind::BackLink));
                }
                writes.push(remove_write(TableId::Objects, record_key.to_vec()));
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
    let mut links = txn.open_table(BACK_LINK_TABLE)?;
    let mut uniques = txn.open_table(UNIQUE_INDEX_TABLE)?;
    for w in writes {
        let table = match w.table {
            TableId::Objects => &mut objects,
            TableId::NameIndex => &mut names,
            TableId::ChildCount => &mut counts,
            TableId::BackLinks => &mut links,
            TableId::UniqueIndex => &mut uniques,
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

    // Source: [MS-ADTS] 3.1.1.2.3 — back link id = forward link id + 1.
    #[test]
    fn back_id_is_forward_plus_one() {
        assert_eq!(back_id(2), 3);
        assert_eq!(back_id(u32::MAX - 1), u32::MAX);
    }
}
