//! The data model: identifiers, attr-stamps, attributes and objects.
//!
//! Spec: docs/32 §2 (DIT → KV by stable object GUID, name as a secondary
//! index, attr-stamp on every attribute value, D134); docs/29 §2 (the
//! attr-stamp tuple, D119) and §5 (tombstone = deletion marker with an
//! attr-stamp, D121); docs/11 §6 (`AttrId`).

use dtyp::Guid;

/// Identifier of an attribute definition in the [`crate::Schema`].
///
/// Opaque number to this crate: the mapping to directory attribute names /
/// OIDs belongs to the AD schema content (`ad-schema`, docs/46 R46-1), which
/// uses the ATTRTYP of [MS-DRSR] 5.16.4 (docs/46 §3.3, R46-3). Every value,
/// **including 0**, is a valid id — `AttrId(0)` is objectClass there — and
/// this crate never uses any value as a sentinel. Spec: docs/32 §4 (schema as
/// data); docs/11 §6 (`AttrId`); docs/46 §8.6.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AttrId(pub u32);

/// Identifier of a class definition in the [`crate::Schema`]. Like
/// [`AttrId`], every value including 0 is valid; none is a sentinel.
/// Spec: docs/32 §4 (classes as schema data); docs/46 §3.3, §8.6.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClassId(pub u32);

/// The node-id of the DC that originated a write: a stable, unique identifier
/// per DC (bound to its certificate — that binding is not this crate's job).
/// Carried as 16 opaque bytes. Spec: docs/29 §2 ("node-id").
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId(pub [u8; 16]);

/// A caller-supplied wall-clock reading. The unit is the caller's (one unit
/// for all calls); the engine never reads a clock and only compares and adds
/// these values. Spec: docs/29 §2 ("wall-clock"); task rule "times are
/// supplied by the caller".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(pub u64);

/// The attr-stamp carried by every stored attribute value, and by a
/// tombstone's deletion marker.
///
/// Spec: docs/29 §2 — `(version, wall-clock, origin-node, origin-seq)`;
/// `version` rises on every change of the same attribute, `wall-clock` breaks
/// ties (D119). docs/32 §2 — the same structure serves replication and
/// tamper-evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AttrStamp {
    /// Change counter of the attribute. Spec: docs/29 §2 ("version").
    pub version: u64,
    /// Wall-clock of the originating write. Spec: docs/29 §2 ("wall-clock").
    pub wall_clock: Timestamp,
    /// Node that originated the write. Spec: docs/29 §2 ("origin-node").
    pub origin_node: NodeId,
    /// The originating node's change-seq for that write. Spec: docs/29 §2
    /// ("origin-seq", "change-seq").
    pub origin_seq: u64,
}

/// The caller-supplied context of one originating write: everything of the
/// attr-stamp except `version`, which the engine derives.
///
/// Spec: docs/29 §2 (wall-clock, origin-node, origin-seq); the engine reads no
/// clock and invents no node id (task scope).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Origin {
    /// Wall-clock of this write. Spec: docs/29 §2.
    pub wall_clock: Timestamp,
    /// This DC's node-id. Spec: docs/29 §2.
    pub origin_node: NodeId,
    /// This DC's change-seq for this write. Spec: docs/29 §2.
    pub origin_seq: u64,
}

impl Origin {
    /// The attr-stamp of this write for an attribute at `version`.
    /// Spec: docs/29 §2.
    #[must_use]
    pub(crate) fn stamp(&self, version: u64) -> AttrStamp {
        AttrStamp {
            version,
            wall_clock: self.wall_clock,
            origin_node: self.origin_node,
            origin_seq: self.origin_seq,
        }
    }
}

/// One attribute value with its attr-stamp. Spec: docs/32 §2 ("every
/// attribute value carries an attr-stamp"); docs/29 §2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StampedValue {
    /// The value bytes, in the canonical form of the attribute's
    /// [`crate::ValueSyntax`].
    pub value: Vec<u8>,
    /// When / where this value was written. Spec: docs/29 §2.
    pub stamp: AttrStamp,
}

/// One attribute of an object: its id and its values (a set — no two values
/// are byte-equal; kept in ascending byte order, which is the canonical
/// order of the record codec). Spec: docs/32 §2, §4; docs/29 §4 (multi-valued
/// attributes are sets).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    /// Schema id. Spec: docs/32 §4.
    pub id: AttrId,
    /// At least one value. Spec: docs/32 §4.
    pub values: Vec<StampedValue>,
}

/// A directory object record as stored (the record codec's model).
///
/// A tombstone record (`tombstone: Some`) keeps only `guid`, `classes` and
/// the deletion stamp: its `parent` is `None`, its `rdn` and `attributes`
/// are empty (Q-062 / A-18). The read API hands tombstones out as
/// [`Tombstone`], never as an `Object`.
///
/// Spec: docs/32 §2 (object keyed by stable GUID; name = secondary index,
/// D134); docs/29 §5 (tombstone, D121); docs/25 §5 ("state").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Object {
    /// Stable object GUID — the primary key. Spec: docs/32 §2, D134.
    pub guid: Guid,
    /// GUID of the parent object; `None` for a naming-context root (and in a
    /// tombstone). Spec: docs/32 §2 (DIT).
    pub parent: Option<Guid>,
    /// RDN key, unique among the live children of `parent` (empty in a
    /// tombstone). **Computed by this crate** from the single value of the
    /// RDN attribute of the most specific class (ASCII, A–Z folded — Q-080
    /// interim), stored for the name-index cross-check and re-checked against
    /// the value on every read. Spec: docs/32 §2 (name as secondary index);
    /// docs/46 §8.3 item 3; docs/14 D60.
    pub rdn: Vec<u8>,
    /// Object classes, ascending, no duplicates: the full superclass chain of
    /// the most specific class (docs/46 §8.3 item 1). The ascending order is
    /// the codec's canonical order, not the objectClass order of
    /// [MS-ADTS] 3.1.1.2.4.3 (top first, most specific last), which the layer
    /// above derives from the schema. Spec: docs/32 §4; docs/46 §5.4.
    pub classes: Vec<ClassId>,
    /// Attributes, ascending by id, no duplicates (empty in a tombstone).
    /// Spec: docs/32 §2, §4.
    pub attributes: Vec<Attribute>,
    /// The deletion marker, if the object is a tombstone. Its `wall_clock` is
    /// the tombstone time used by purge. Spec: docs/29 §5, D121.
    pub tombstone: Option<AttrStamp>,
}

/// What remains of a deleted object: its identity and its deletion marker —
/// all that docs/29 §5 needs to stop the object from coming back, and nothing
/// more (minimal state, docs/25 §5 "state" row, D104; Q-062 / A-18).
/// Spec: docs/29 §5 (D121).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tombstone {
    /// The deleted object's GUID (the record key). Spec: docs/32 §2.
    pub guid: Guid,
    /// The deleted object's classes, ascending. Spec: docs/32 §4.
    pub classes: Vec<ClassId>,
    /// The deletion marker; its `wall_clock` is the tombstone time used by
    /// purge. Spec: docs/29 §5 ("deletion marker with attr-stamp").
    pub deletion: AttrStamp,
}

impl Object {
    /// The attribute with this id, if present.
    #[must_use]
    pub fn attribute(&self, id: AttrId) -> Option<&Attribute> {
        self.attributes
            .binary_search_by_key(&id, |a| a.id)
            .ok()
            .and_then(|i| self.attributes.get(i))
    }

    /// `true` if the object has been deleted (is a tombstone).
    /// Spec: docs/29 §5.
    #[must_use]
    pub fn is_tombstone(&self) -> bool {
        self.tombstone.is_some()
    }
}

/// Where a children listing resumes: after the RDN key of the last child of
/// the previous page, under the same parent. It also carries how many
/// children the earlier pages of the listing returned, for the completeness
/// check on the final page.
///
/// Opaque, and made only by [`crate::Snapshot::children`] /
/// [`crate::WriteTxn::children`]: its RDN key is one read from an
/// authenticated, cross-checked name-index entry, so it is bounded. A cursor
/// continues a listing in the view that made it (the same snapshot, or the
/// same write transaction with no write under the parent in between); see
/// [`crate::Snapshot::children`].
///
/// Spec: docs/49 §6.1 item 3 (`after: Option<RdnKey>`); docs/32 §2 (name
/// index keyed by `(parent, RDN key)`), §8 (bounded paging).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildCursor {
    /// The parent whose children are listed (`None`: the roots).
    pub(crate) parent: Option<Guid>,
    /// RDN key of the last child returned so far.
    pub(crate) after: Vec<u8>,
    /// Children returned by the pages before this cursor.
    pub(crate) listed: u64,
}

/// One page of a children listing.
/// Spec: docs/49 §6.1 item 3 (R49-9); docs/32 §8.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildPage {
    /// GUIDs of live children, in name-index key order (ascending RDN key
    /// bytes, i.e. the A–Z-folded RDN value — Q-080 interim). Spec: docs/32
    /// §2; docs/49 §6.1 item 3 ("name-index order — deterministic").
    pub children: Vec<Guid>,
    /// `Some` when more children follow: pass it as `after` to read the next
    /// page. `None` when the listing is complete.
    pub next: Option<ChildCursor>,
}

/// A new object to create. Values are raw bytes; the engine sorts them,
/// rejects duplicates and stamps each with `version` 1. There is no RDN key
/// field: the engine computes it from the value of the RDN attribute of the
/// most specific class (docs/46 §8.3 item 3).
/// Spec: docs/32 §2, §4; docs/29 §2; docs/46 §8.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewObject {
    /// Stable object GUID, chosen by the caller; never the NULL GUID
    /// ([MS-ADTS] 3.1.1.1.3). Creation is refused while any record — live or
    /// tombstone — holds this GUID. Spec: docs/32 §2 (the GUID is the stable
    /// key), docs/29 §5 (a tombstone still holds it).
    pub guid: Guid,
    /// Parent GUID, or `None` for a naming-context root. Spec: docs/32 §2;
    /// docs/46 §8.3 item 2.
    pub parent: Option<Guid>,
    /// Object classes (any order, no duplicates): the full superclass chain
    /// of exactly one instantiable class. Spec: docs/32 §4; docs/46 §8.3.
    pub classes: Vec<ClassId>,
    /// Attributes with their values (any order, no duplicate ids).
    pub attributes: Vec<(AttrId, Vec<Vec<u8>>)>,
}

/// The state of one named counter: the half-open range
/// `[first_value, end_exclusive)` it was created with, and `next_value`, the
/// value the next take returns.
///
/// Invariant, checked by the record codec on every write and every read:
/// `first_value < end_exclusive` and
/// `first_value <= next_value <= end_exclusive`. `next_value ==
/// end_exclusive` means every value of the range has been taken: the counter
/// is exhausted and refuses further takes (fail closed). `next_value` never
/// decreases — no operation sets, lowers, resets or removes a counter.
///
/// Values are `u64` because the change-seq of docs/29 §2 is
/// ([`Origin::origin_seq`]); a caller whose values are narrower (a 32-bit
/// RID, [MS-SAMR] 3.1.1.9.2) creates the counter with a range that fits.
///
/// Spec: docs/51 §8.3 (R51-16; A-75 / Q-293); [MS-SAMR] 3.1.1.9.2 ("maintain
/// a counter and increment the counter for each RID that is issued"),
/// 3.1.1.9.2.2 item 2 (refuse when no value can be generated).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CounterState {
    /// First value of the range (the first value ever taken).
    pub first_value: u64,
    /// The value the next take returns; `end_exclusive` once exhausted.
    pub next_value: u64,
    /// One past the last value of the range.
    pub end_exclusive: u64,
}

impl CounterState {
    /// `true` if every value of the range has been taken. Spec: A-75
    /// ("exhaustion ⇒ refusal").
    #[must_use]
    pub fn is_exhausted(&self) -> bool {
        self.next_value >= self.end_exclusive
    }

    /// How many values can still be taken. Spec: docs/51 §8.3 (diagnostics).
    #[must_use]
    pub fn remaining(&self) -> u64 {
        self.end_exclusive.saturating_sub(self.next_value)
    }
}

/// One change to an existing object's attributes.
/// Spec: docs/32 §4 (every write validated), §7 (one atomic write).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttributeChange {
    /// Make `values` the attribute's complete value set; an empty set removes
    /// the attribute. Values already present keep their attr-stamp; values
    /// not present before are stamped with the attribute's next version.
    /// Spec: docs/29 §2 (version rises on every change of the attribute).
    Replace {
        /// Attribute to change.
        id: AttrId,
        /// New value set (any order, no duplicates).
        values: Vec<Vec<u8>>,
    },
}
