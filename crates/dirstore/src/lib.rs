#![forbid(unsafe_code)]
//! `dirstore`: the directory storage engine — our interface over the approved
//! embedded KV engine (redb, OD-4), holding every piece of directory logic
//! itself (D5; docs/32 §1).
//!
//! # What it stores
//!
//! - **Objects keyed by a stable object GUID** ([`dtyp::Guid`]); the name is a
//!   secondary index (docs/32 §2, D134). DN strings are *not* parsed here: the
//!   LDAP layer owns DN parsing. The **RDN key is computed here**, in one
//!   place, from the value of the RDN attribute of the object's most specific
//!   class (docs/46 §8.3 item 3; D64): ASCII only, A–Z folded to a–z (the
//!   Q-080 interim rule, PENDING-OWNER P-9). Children are indexed by
//!   `(parent GUID, RDN key)` and that pair is unique among live objects.
//!   The same index lists the live children of a parent, or the
//!   naming-context roots, in bounded pages in RDN-key order
//!   ([`Snapshot::children`]; the candidate source of LDAP one-level and
//!   subtree searches, docs/49 §6.1 item 3, R49-9).
//! - **Class chains and the tree shape** (docs/46 §8.3): an object lists the
//!   full superclass chain of exactly one instantiable class; its parent's
//!   most specific class must be one of that class's possible superiors; an
//!   NC root has no parent.
//! - **Object references** ([`ValueSyntax::ObjectRef`], docs/46 §2.3, §8.4):
//!   a forward-link value is the GUID of a live target. A reverse-link index
//!   `(target, back link id, source)` is maintained in the same transaction,
//!   answers back-link queries ([`Snapshot::back_links`]) and lets a delete
//!   remove every forward reference to the deleted object (referential
//!   integrity, [MS-ADTS] 3.1.1.1.6).
//! - **Unique attributes** (docs/46 §8.5): for every attribute the schema
//!   marks `unique`, an index from the value's comparison key to the owning
//!   GUID refuses duplicates. No code path disables it (AGENTS.md §6).
//! - **Per-value attr-stamps** `(version, wall-clock, origin-node,
//!   origin-seq)` (docs/29 §2, D119). Every time and node id is supplied by the
//!   caller ([`Origin`]); the engine reads no clock. The engine computes
//!   `version` itself so that it rises on every change of an attribute.
//! - **Tombstones** (docs/29 §5, D121): deleting an object replaces it by a
//!   [`Tombstone`] that keeps only its GUID, its classes and a deletion stamp
//!   — every attribute value, the parent and the name are dropped (minimal
//!   state, docs/25 §5; Q-062 / A-18). It is invisible to normal reads, and
//!   [`WriteTxn::purge_tombstones`] removes tombstones older than a
//!   caller-given lifetime.
//! - **Schema as data** (docs/32 §4): attribute and class definitions
//!   ([`Schema`]) validate every write. An attribute whose class is
//!   [`AttrClass::Secret`] can never be written — secret material lives in
//!   keyd, never in the readable store (D44; docs/25 §5 "state"). An attribute
//!   whose storage is [`Storage::Derived`] is never stored and every write
//!   naming it is refused (docs/46 §5.4, §8.2). This crate holds **no AD
//!   schema content** — no attribute names, OIDs or GUIDs (docs/46 §8, R46-1);
//!   that content is data handed in by the caller.
//!
//! # Guarantees
//!
//! - **Atomic writes** (D136; docs/32 §7): value, stamp, name index, child
//!   count, reverse-link and unique-index entries, the forward references a
//!   delete removes from other objects, and the integrity tags of one change
//!   are written in one redb write transaction ([`WriteTxn`]). Dropping or
//!   aborting it leaves no trace.
//! - **Snapshots** (D39; docs/32 §6): a [`Snapshot`] is a redb read
//!   transaction — a consistent point-in-time view that never shows a
//!   half-applied write.
//! - **At-rest integrity** (D135; docs/32 §3): every stored record carries an
//!   HMAC-SHA-256 tag over a domain label, its table, its key and its body,
//!   keyed by a caller-injected [`IntegrityKey`]. On read the tag is verified
//!   first (constant-time, by the `hmac` crate); a mismatch is
//!   [`Error::Tamper`] and the record is never decoded, returned or used.
//!   Index entries (name, reverse link, unique) are also cross-checked
//!   against the object they name; a mismatch is [`Error::Inconsistent`].
//!   A children listing cross-checks every entry it returns the same way,
//!   and its final page checks the number of children listed against the
//!   parent's live-child count, so a name entry removed beneath the engine
//!   cannot silently hide a child from a listing (residuals on
//!   [`Snapshot::children`]).
//! - **Bounded, canonical codec** (docs/10 D34; docs/32 §8, D138): records use
//!   this crate's own length-prefixed encoding ([`record`]), not a general
//!   serializer. The decoder is bounded and fail-closed; bytes read back from
//!   disk are untrusted (tag first, then bounded parse).
//!
//! # Resource bounds
//!
//! Enforced on every write (as [`Error::Rejected`]) and on every read (as
//! [`Error::RecordMalformed`] from the decoder, or
//! [`Error::StoredObjectRejected`] from schema re-validation). The values are
//! this project's provisional choices — docs/32 §8 requires bounds but fixes no
//! numbers; they are constants so a later owner decision changes one line.
//!
//! | bound | constant |
//! |---|---|
//! | bytes in one attribute value | [`MAX_VALUE_LEN`] |
//! | values in one attribute | [`MAX_VALUES_PER_ATTRIBUTE`] |
//! | attributes in one object | [`MAX_ATTRIBUTES_PER_OBJECT`] |
//! | object classes of one object | [`MAX_CLASSES_PER_OBJECT`] |
//! | bytes in an RDN key | [`MAX_RDN_KEY_LEN`] |
//! | bytes in one encoded record body | [`MAX_RECORD_BODY_LEN`] |
//! | children in one listing page (a read bound: larger limits are capped) | [`MAX_CHILDREN_PER_PAGE`] |
//!
//! # Out of scope
//!
//! Replication protocol (docs/29, phase 4), the visibility index (needs the
//! PDP, D137), the LDAP front-end, DN string parsing, the AD schema content
//! (a separate `ad-schema` crate, docs/46 R46-1), computing derived
//! attributes for reads (objectClass, name, distinguishedName, … — the layer
//! above does that from the stored state), schema storage and signed schema
//! change (docs/32 §4, tier-0), rename/move, references that cross a naming
//! context (phase 1 has one domain NC).
//!
//! # Provenance
//!
//! Written only from this project's design documents, opened in-session:
//! docs/32 (all sections), docs/29 §2 and §5, docs/46 (§1, §2.3, §5.4, §8,
//! §10 / A-29), docs/12 §3 (D44), docs/25 §5, docs/10 §3 (D34), docs/11 §6
//! (`AttrClass` = Normal | Sensitive | Secret), docs/14 §6 (D60), Q-080,
//! Q-062 / A-18, docs/49 §6.1 and §12 (the children listing, task L3; A-30,
//! P-7); and the pinned [MS-ADTS] v20261026 and [MS-DRSR] v20260309
//! sections cited on each item (opened in-session from
//! `tools/spec-pin/cache/`). GUID / SID / security-descriptor handling is delegated
//! to our own `dtyp` crate (its public API and docs, read in-session); the redb,
//! hmac and sha2 public API docs on docs.rs (PENDING-OWNER P-2). No other
//! implementation was consulted or recalled (AGENTS.md §1-3).
//!
//! Spec: docs/32 §1-§8 (D134-D136, D138); docs/29 §2 (D119), §5 (D121);
//! docs/46 §8; docs/12 D44; docs/11 §6; docs/10 D34; docs/49 §6.1 (R49-9).

mod comparison;
mod error;
mod integrity;
pub mod record;
mod schema;
mod store;
mod types;

pub use error::{DecodeError, Error, RecordKind, Result, SchemaDefect, Violation};
pub use integrity::{IntegrityKey, INTEGRITY_KEY_LEN, MAC_LEN};
pub use schema::{
    AttrClass, AttributeDefinition, ClassDefinition, Link, Multiplicity, Schema, Storage,
    ValueConstraint, ValueRange, ValueSyntax,
};
pub use store::{Snapshot, Store, WriteTxn};
pub use types::{
    AttrId, AttrStamp, Attribute, AttributeChange, ChildCursor, ChildPage, ClassId, NewObject,
    NodeId, Object, Origin, StampedValue, Timestamp, Tombstone,
};

/// Largest attribute value, in bytes. A schema attribute's own bound may only
/// be smaller. Kept at 64 KiB in phase 1 although [MS-ADA3] gives
/// nTSecurityDescriptor a rangeUpper of 132096 — a deliberate, stricter
/// deviation (docs/46 §8.6, R46-7). Spec: docs/32 §8 (allocation ceiling);
/// docs/46 §8.6.
pub const MAX_VALUE_LEN: usize = 64 * 1024;

/// Most values one attribute may hold. Spec: docs/32 §8; project choice.
pub const MAX_VALUES_PER_ATTRIBUTE: usize = 4096;

/// Most attributes one object may hold. Spec: docs/32 §8; project choice.
pub const MAX_ATTRIBUTES_PER_OBJECT: usize = 256;

/// Most object classes one object may list. Spec: docs/32 §8; project choice.
pub const MAX_CLASSES_PER_OBJECT: usize = 16;

/// Longest RDN key, in bytes (at least one byte is required) — the bound of
/// the record codec and of lookup input. A key computed from an RDN value is
/// always far shorter: the RDN is under 255 characters and ASCII-only in
/// phase 1 (docs/46 §8.6). Spec: docs/32 §2 (name as secondary index), §8;
/// project choice.
pub const MAX_RDN_KEY_LEN: usize = 1024;

/// The RDN size limit: "The RDN size MUST be less than 255 characters", read
/// strictly as the whole `att=val` string (docs/46 §8.3 item 3; Q-090).
/// Spec: [MS-ADTS] 3.1.1.5.1.2; docs/46 §8.3.
pub const RDN_SIZE_LIMIT: usize = 255;

/// Largest `rdn_att_len` an attribute definition may declare: `att`, `=` and
/// at least one value character must fit under [`RDN_SIZE_LIMIT`].
/// Spec: [MS-ADTS] 3.1.1.1.4 (RDN = "att=val"), 3.1.1.5.1.2; Q-090.
pub const MAX_RDN_ATT_LEN: usize = RDN_SIZE_LIMIT - 3;

/// Largest encoded record body, in bytes (the stored value is this plus the
/// [`MAC_LEN`]-byte tag). Caps one object's total size whatever the other
/// bounds allow. Spec: docs/32 §8 (allocation ceiling); project choice.
pub const MAX_RECORD_BODY_LEN: usize = 16 * 1024 * 1024;

/// Most children one page of [`Snapshot::children`] / [`WriteTxn::children`]
/// returns; a larger `limit` is capped to this. One page therefore reads at
/// most this many object records plus one more name-index key, and a caller
/// pages through a large container instead of holding it whole. It is well
/// under the search visit budget of docs/49 §6.1 item 3 (10,000 candidates),
/// which the caller enforces across pages. Spec: docs/32 §8 (bounds; no
/// number fixed there), docs/49 §6.1 item 3; project choice.
pub const MAX_CHILDREN_PER_PAGE: usize = 1000;
