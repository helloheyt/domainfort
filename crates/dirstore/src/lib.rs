#![forbid(unsafe_code)]
//! `dirstore`: the directory storage engine — our interface over the approved
//! embedded KV engine (redb, OD-4), holding every piece of directory logic
//! itself (D5; docs/32 §1).
//!
//! # What it stores
//!
//! - **Objects keyed by a stable object GUID** ([`dtyp::Guid`]); the name is a
//!   secondary index (docs/32 §2, D134). DN strings are *not* parsed here: the
//!   LDAP layer owns DN parsing and matching rules, and hands this crate an
//!   opaque, already-normalized RDN key. Children are indexed by
//!   `(parent GUID, RDN key)` and that pair is unique among live objects.
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
//!   keyd, never in the readable store (D44; docs/25 §5 "state").
//!
//! # Guarantees
//!
//! - **Atomic writes** (D136; docs/32 §7): value, stamp, name index, child
//!   count and integrity tag of one change are written in one redb write
//!   transaction ([`WriteTxn`]). Dropping or aborting it leaves no trace.
//! - **Snapshots** (D39; docs/32 §6): a [`Snapshot`] is a redb read
//!   transaction — a consistent point-in-time view that never shows a
//!   half-applied write.
//! - **At-rest integrity** (D135; docs/32 §3): every stored record carries an
//!   HMAC-SHA-256 tag over a domain label, its table, its key and its body,
//!   keyed by a caller-injected [`IntegrityKey`]. On read the tag is verified
//!   first (constant-time, by the `hmac` crate); a mismatch is
//!   [`Error::Tamper`] and the record is never decoded, returned or used.
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
//!
//! # Out of scope
//!
//! Replication protocol (docs/29, phase 4), the visibility index (needs the
//! PDP, D137), the LDAP front-end, DN string parsing, the AD schema content
//! ([MS-ADSC]/[MS-ADA*] are not pinned yet), schema storage and signed schema
//! change (docs/32 §4, tier-0), rename/move.
//!
//! # Provenance
//!
//! Written only from this project's design documents, opened in-session:
//! docs/32 (all sections), docs/29 §2 and §5, docs/12 §3 (D44), docs/25 §5,
//! docs/10 §3 (D34), docs/11 §6 (`AttrClass` = Normal | Sensitive | Secret),
//! docs/14 §6 (D60); GUID / SID / security-descriptor handling is delegated
//! to our own `dtyp` crate (its public API and docs, read in-session); the redb,
//! hmac and sha2 public API docs on docs.rs (PENDING-OWNER P-2). No other
//! implementation was consulted or recalled (AGENTS.md §1-3).
//!
//! Spec: docs/32 §1-§8 (D134-D136, D138); docs/29 §2 (D119), §5 (D121);
//! docs/12 D44; docs/11 §6; docs/10 D34.

mod error;
mod integrity;
pub mod record;
mod schema;
mod store;
mod types;

pub use error::{DecodeError, Error, RecordKind, Result, SchemaDefect, Violation};
pub use integrity::{IntegrityKey, INTEGRITY_KEY_LEN, MAC_LEN};
pub use schema::{
    AttrClass, AttributeDefinition, ClassDefinition, Multiplicity, Schema, ValueSyntax,
};
pub use store::{Snapshot, Store, WriteTxn};
pub use types::{
    AttrId, AttrStamp, Attribute, AttributeChange, ClassId, NewObject, NodeId, Object, Origin,
    StampedValue, Timestamp, Tombstone,
};

/// Largest attribute value, in bytes. A schema attribute's own bound may only
/// be smaller. Spec: docs/32 §8 (allocation ceiling); project choice.
pub const MAX_VALUE_LEN: usize = 64 * 1024;

/// Most values one attribute may hold. Spec: docs/32 §8; project choice.
pub const MAX_VALUES_PER_ATTRIBUTE: usize = 4096;

/// Most attributes one object may hold. Spec: docs/32 §8; project choice.
pub const MAX_ATTRIBUTES_PER_OBJECT: usize = 256;

/// Most object classes one object may list. Spec: docs/32 §8; project choice.
pub const MAX_CLASSES_PER_OBJECT: usize = 16;

/// Longest RDN key, in bytes (at least one byte is required). Spec: docs/32
/// §2 (name as secondary index), §8; project choice.
pub const MAX_RDN_KEY_LEN: usize = 1024;

/// Largest encoded record body, in bytes (the stored value is this plus the
/// [`MAC_LEN`]-byte tag). Caps one object's total size whatever the other
/// bounds allow. Spec: docs/32 §8 (allocation ceiling); project choice.
pub const MAX_RECORD_BODY_LEN: usize = 16 * 1024 * 1024;
