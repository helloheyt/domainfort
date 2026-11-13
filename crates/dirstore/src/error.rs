//! Error types.
//!
//! Hand-rolled (AGENTS.md §7; docs/45 §4 style). Fail closed: every broken
//! rule is a distinct variant, never a panic and never a silent repair
//! (AGENTS.md §6; docs/32 §8).
//!
//! Security: no variant carries attribute values, record bytes or key
//! material — only identifiers and which rule failed (AGENTS.md §6
//! "secrets never appear in error messages").

use crate::types::{AttrId, ClassId};
use core::fmt;

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Which kind of stored record an integrity or decode failure concerns.
/// Spec: docs/32 §3 (every record is integrity-checked), §7 (object, index).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordKind {
    /// The store's own format/key-check record.
    Meta,
    /// An object record (keyed by object GUID). Spec: docs/32 §2.
    Object,
    /// A name-index record `(parent, RDN key) -> GUID`. Spec: docs/32 §2.
    NameIndex,
    /// A per-parent live-child count. Spec: docs/32 §2 (DIT shape).
    ChildCount,
}

/// A rule of the record codec that a stored body broke. Raised only after the
/// integrity tag verified (tag first, then bounded parse).
/// Spec: docs/32 §8 (bounded, fail-closed parser), D138; docs/10 D34.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DecodeError {
    /// The body ended before a field.
    Truncated,
    /// Bytes remained after the last field (strict framing).
    TrailingData,
    /// The format byte is not one this crate writes.
    UnsupportedFormat,
    /// A flags byte had a bit this format does not define.
    UndefinedFlags,
    /// A live object's RDN key length was 0 or above
    /// [`crate::MAX_RDN_KEY_LEN`].
    RdnKeyLength,
    /// A tombstone body carried a parent, an RDN key or attributes; a
    /// tombstone keeps only its classes and deletion stamp (Q-062 / A-18).
    /// Spec: docs/29 §5; docs/25 §5 ("state").
    TombstoneContent,
    /// Class count was 0 or above [`crate::MAX_CLASSES_PER_OBJECT`].
    ClassCount,
    /// Class ids were not strictly ascending (canonical order, no duplicates).
    ClassOrder,
    /// Attribute count was above [`crate::MAX_ATTRIBUTES_PER_OBJECT`].
    AttributeCount,
    /// Attribute ids were not strictly ascending.
    AttributeOrder,
    /// Value count was 0 or above [`crate::MAX_VALUES_PER_ATTRIBUTE`].
    ValueCount,
    /// A value length was above [`crate::MAX_VALUE_LEN`].
    ValueLength,
    /// Values of one attribute were not strictly ascending by bytes.
    ValueOrder,
    /// The body was longer than [`crate::MAX_RECORD_BODY_LEN`].
    RecordTooLarge,
    /// A child-count record held zero (absent is the only encoding of zero).
    ZeroChildCount,
}

/// A rule an object (or a requested change) breaks: schema rules
/// (docs/32 §4) and resource bounds (docs/32 §8).
///
/// Returned as [`Error::Rejected`] for a write and as
/// [`Error::StoredObjectRejected`] when a stored object fails re-validation on
/// read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Violation {
    // ---- schema (docs/32 §4: "type, must, singularity") ----
    /// The object lists no object class. Spec: docs/32 §4.
    NoObjectClass,
    /// A class id is not defined in the schema. Spec: docs/32 §4.
    UnknownClass(ClassId),
    /// A class is listed twice. Spec: docs/32 §4.
    DuplicateClass(ClassId),
    /// An attribute id is not defined in the schema. Spec: docs/32 §4.
    UnknownAttribute(AttrId),
    /// The attribute's class is Secret: secret material is never written to
    /// the readable store. Spec: docs/12 D44; docs/32 §1; docs/11 §6 / P6.
    SecretAttribute(AttrId),
    /// No class of the object allows the attribute (neither must nor may).
    /// Spec: docs/32 §4.
    AttributeNotAllowed(AttrId),
    /// A must-attribute of one of the object's classes is absent.
    /// Spec: docs/32 §4 ("must").
    MissingMustAttribute(AttrId),
    /// The same attribute id appears twice in one request. Spec: docs/32 §4.
    DuplicateAttribute(AttrId),
    /// An attribute was given with no values on creation. Spec: docs/32 §4.
    EmptyAttribute(AttrId),
    /// A single-valued attribute was given more than one value.
    /// Spec: docs/32 §4 ("singularity").
    MultipleValuesOnSingleValued(AttrId),
    /// A value is longer than the attribute's schema bound (itself at most
    /// [`crate::MAX_VALUE_LEN`]). Spec: docs/32 §4, §8.
    ValueTooLarge(AttrId),
    /// A value is not in the canonical form of the attribute's syntax.
    /// Spec: docs/32 §4 ("type"); docs/14 D60 (strict validation of what is
    /// stored).
    InvalidValueSyntax(AttrId),
    /// Two byte-equal values in one attribute. Spec: docs/29 §4 (values form a
    /// set).
    DuplicateValue(AttrId),

    // ---- resource bounds (docs/32 §8) ----
    /// More than [`crate::MAX_CLASSES_PER_OBJECT`] classes.
    TooManyClasses,
    /// More than [`crate::MAX_ATTRIBUTES_PER_OBJECT`] attributes.
    TooManyAttributes,
    /// More than [`crate::MAX_VALUES_PER_ATTRIBUTE`] values in one attribute.
    TooManyValues(AttrId),
    /// The RDN key is empty.
    RdnKeyEmpty,
    /// The RDN key is longer than [`crate::MAX_RDN_KEY_LEN`].
    RdnKeyTooLong,
    /// The encoded record would exceed [`crate::MAX_RECORD_BODY_LEN`].
    RecordTooLarge,

    // ---- codec invariant ----
    /// Encoder input was not in canonical order (classes, attributes or
    /// values not strictly ascending). Spec: docs/10 D34 (canonical codec).
    NotCanonical,
    /// A tombstone carried a parent, an RDN key or attributes; it may keep
    /// only its GUID, classes and deletion stamp (Q-062 / A-18).
    /// Spec: docs/29 §5; docs/25 §5 ("state").
    TombstoneCarriesContent,
}

/// A defect in a schema definition, found when the [`crate::Schema`] is built.
/// Spec: docs/32 §4 (schema is data — and data is validated).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SchemaDefect {
    /// Two attribute definitions share an id.
    DuplicateAttributeDefinition(AttrId),
    /// Two class definitions share an id.
    DuplicateClassDefinition(ClassId),
    /// An attribute's value-size bound is 0 or above [`crate::MAX_VALUE_LEN`].
    ValueBoundOutOfRange(AttrId),
    /// A class names an attribute that is not defined.
    UndefinedAttributeInClass(ClassId, AttrId),
    /// A class names the same attribute twice (within or across must / may).
    DuplicateAttributeInClass(ClassId, AttrId),
    /// A class requires a Secret attribute, which could never be written
    /// (docs/12 D44).
    SecretMustAttribute(ClassId, AttrId),
    /// A class lists more attributes than an object may hold.
    TooManyAttributesInClass(ClassId),
}

/// Any failure of the storage engine.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// A stored record failed integrity verification (wrong tag, wrong key, or
    /// a value too short / too long to carry a tag). The record was not
    /// decoded and is never returned or used. Spec: docs/32 §3, D135.
    Tamper(RecordKind),
    /// A record's tag verified but its body broke the codec rules. Only a bug
    /// or a compromised integrity key can produce this.
    /// Spec: docs/32 §8, D138.
    RecordMalformed(RecordKind, DecodeError),
    /// Records that each verified are mutually inconsistent (e.g. the name
    /// index points at an object whose name differs, or a child count does not
    /// match) — a replayed or removed record. Fail closed.
    /// Spec: docs/32 §3 (direct KV edits are not accepted as ground truth).
    Inconsistent(RecordKind),
    /// A write was refused by the schema or a resource bound; nothing was
    /// written. Spec: docs/32 §4, §8.
    Rejected(Violation),
    /// A stored object does not satisfy the schema / bounds given at open, so
    /// it is not returned. Spec: docs/14 D60 (no stored value reaches a
    /// decision without re-validation); docs/12 D44.
    StoredObjectRejected(Violation),
    /// The schema definition is invalid. Spec: docs/32 §4.
    InvalidSchema(SchemaDefect),
    /// A record (live or tombstone) already holds this object GUID.
    /// Spec: docs/32 §2 (stable GUID key).
    ObjectExists,
    /// No live object has this GUID. Spec: docs/29 §5 (tombstones are
    /// invisible).
    NoSuchObject,
    /// The parent GUID names no live object. Spec: docs/32 §2 (DIT).
    NoSuchParent,
    /// A live child of the parent already has this RDN key.
    /// Spec: docs/32 §2 (name index, unique `(parent, RDN key)`).
    NameExists,
    /// The object still has live children; delete them first.
    /// Spec: docs/32 §2 (DIT: a live object's parent is live).
    HasChildren,
    /// An attribute's version counter cannot be incremented.
    /// Spec: docs/29 §2 (version rises on every change).
    VersionOverflow,
    /// A step of this write transaction failed after it had started changing
    /// tables; the transaction can only be aborted. Spec: D136.
    TransactionPoisoned,
    /// The integrity key could not be used by the MAC implementation.
    IntegrityKeyUnusable,
    /// The KV engine reported an error. Spec: docs/32 §10 (redb, OD-4).
    Storage(redb::Error),
}

impl fmt::Display for RecordKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            RecordKind::Meta => "store metadata",
            RecordKind::Object => "object",
            RecordKind::NameIndex => "name index",
            RecordKind::ChildCount => "child count",
        })
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            DecodeError::Truncated => "record body truncated",
            DecodeError::TrailingData => "trailing bytes after record body",
            DecodeError::UnsupportedFormat => "unsupported record format",
            DecodeError::UndefinedFlags => "undefined flag bit",
            DecodeError::RdnKeyLength => "RDN key length out of bounds",
            DecodeError::TombstoneContent => "tombstone carries more than its identity",
            DecodeError::ClassCount => "class count out of bounds",
            DecodeError::ClassOrder => "classes not strictly ascending",
            DecodeError::AttributeCount => "attribute count out of bounds",
            DecodeError::AttributeOrder => "attributes not strictly ascending",
            DecodeError::ValueCount => "value count out of bounds",
            DecodeError::ValueLength => "value length out of bounds",
            DecodeError::ValueOrder => "values not strictly ascending",
            DecodeError::RecordTooLarge => "record body too large",
            DecodeError::ZeroChildCount => "child count record holds zero",
        })
    }
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Violation::NoObjectClass => f.write_str("object has no class"),
            Violation::UnknownClass(c) => write!(f, "class {} is not defined", c.0),
            Violation::DuplicateClass(c) => write!(f, "class {} listed twice", c.0),
            Violation::UnknownAttribute(a) => write!(f, "attribute {} is not defined", a.0),
            Violation::SecretAttribute(a) => {
                write!(f, "attribute {} is secret and never stored here", a.0)
            }
            Violation::AttributeNotAllowed(a) => {
                write!(
                    f,
                    "attribute {} is not allowed by the object's classes",
                    a.0
                )
            }
            Violation::MissingMustAttribute(a) => write!(f, "must-attribute {} is absent", a.0),
            Violation::DuplicateAttribute(a) => write!(f, "attribute {} given twice", a.0),
            Violation::EmptyAttribute(a) => write!(f, "attribute {} has no values", a.0),
            Violation::MultipleValuesOnSingleValued(a) => {
                write!(f, "single-valued attribute {} given several values", a.0)
            }
            Violation::ValueTooLarge(a) => write!(f, "value of attribute {} too large", a.0),
            Violation::InvalidValueSyntax(a) => {
                write!(f, "value of attribute {} does not match its syntax", a.0)
            }
            Violation::DuplicateValue(a) => write!(f, "attribute {} has a duplicate value", a.0),
            Violation::TooManyClasses => f.write_str("too many object classes"),
            Violation::TooManyAttributes => f.write_str("too many attributes"),
            Violation::TooManyValues(a) => write!(f, "attribute {} has too many values", a.0),
            Violation::RdnKeyEmpty => f.write_str("RDN key is empty"),
            Violation::RdnKeyTooLong => f.write_str("RDN key too long"),
            Violation::RecordTooLarge => f.write_str("encoded object too large"),
            Violation::NotCanonical => f.write_str("object not in canonical order"),
            Violation::TombstoneCarriesContent => {
                f.write_str("tombstone carries more than its identity")
            }
        }
    }
}

impl fmt::Display for SchemaDefect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SchemaDefect::DuplicateAttributeDefinition(a) => {
                write!(f, "attribute {} defined twice", a.0)
            }
            SchemaDefect::DuplicateClassDefinition(c) => write!(f, "class {} defined twice", c.0),
            SchemaDefect::ValueBoundOutOfRange(a) => {
                write!(f, "attribute {} value bound out of range", a.0)
            }
            SchemaDefect::UndefinedAttributeInClass(c, a) => {
                write!(f, "class {} names undefined attribute {}", c.0, a.0)
            }
            SchemaDefect::DuplicateAttributeInClass(c, a) => {
                write!(f, "class {} names attribute {} twice", c.0, a.0)
            }
            SchemaDefect::SecretMustAttribute(c, a) => {
                write!(f, "class {} requires secret attribute {}", c.0, a.0)
            }
            SchemaDefect::TooManyAttributesInClass(c) => {
                write!(f, "class {} lists too many attributes", c.0)
            }
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Tamper(k) => write!(f, "integrity check failed for a {k} record"),
            Error::RecordMalformed(k, e) => write!(f, "malformed {k} record: {e}"),
            Error::Inconsistent(k) => write!(f, "inconsistent {k} record"),
            Error::Rejected(v) => write!(f, "write rejected: {v}"),
            Error::StoredObjectRejected(v) => write!(f, "stored object rejected: {v}"),
            Error::InvalidSchema(d) => write!(f, "invalid schema: {d}"),
            Error::ObjectExists => f.write_str("object GUID already in use"),
            Error::NoSuchObject => f.write_str("no such object"),
            Error::NoSuchParent => f.write_str("no such parent object"),
            Error::NameExists => f.write_str("name already in use under this parent"),
            Error::HasChildren => f.write_str("object has live children"),
            Error::VersionOverflow => f.write_str("attribute version overflow"),
            Error::TransactionPoisoned => f.write_str("write transaction poisoned"),
            Error::IntegrityKeyUnusable => f.write_str("integrity key unusable"),
            Error::Storage(e) => write!(f, "storage engine error: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Storage(e) => Some(e),
            _ => None,
        }
    }
}

// Every redb error type converts into `redb::Error` (redb API docs); wrap it.
// Spec: docs/32 §10 (the KV is only a storage engine behind our interface).
macro_rules! from_redb {
    ($($t:ty),*) => {
        $(impl From<$t> for Error {
            fn from(e: $t) -> Error {
                Error::Storage(redb::Error::from(e))
            }
        })*
    };
}
from_redb!(
    redb::DatabaseError,
    redb::TransactionError,
    redb::TableError,
    redb::StorageError,
    redb::CommitError
);

impl From<redb::Error> for Error {
    fn from(e: redb::Error) -> Error {
        Error::Storage(e)
    }
}
