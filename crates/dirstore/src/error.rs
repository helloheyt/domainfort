//! Error types.
//!
//! Hand-rolled (docs/CLEAN-ROOM.md; docs/45 §4 style). Fail closed: every broken
//! rule is a distinct variant, never a panic and never a silent repair
//! (docs/CLEAN-ROOM.md; docs/32 §8).
//!
//! Security: no variant carries attribute values, record bytes or key
//! material — only identifiers and which rule failed (docs/CLEAN-ROOM.md
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
    /// A reverse-link entry `(target, back link id, source)`.
    /// Spec: docs/46 §8.4; docs/32 §7 (D136).
    BackLink,
    /// A unique-index entry `(attribute, comparison key) -> GUID`.
    /// Spec: docs/46 §8.5.
    UniqueIndex,
    /// A named counter, stored in the meta table under its own key and MAC
    /// domain. Spec: docs/51 §8.3 (A-75); docs/32 §3 (D135).
    Counter,
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
    /// An index key read back from disk does not have its table's layout.
    /// Spec: docs/46 §8.4 (reverse-link key layout); docs/32 §8.
    KeyLength,
    /// A counter record's values break `first_value < end_exclusive` and
    /// `first_value <= next_value <= end_exclusive`.
    /// Spec: docs/51 §8.3 (A-75: within its bounds, never decreasing).
    CounterState,
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
    /// Two byte-equal values in one attribute — or, for a `unique`
    /// attribute, two values with the same comparison key. Spec: docs/29 §4
    /// (values form a set); docs/46 §8.5.
    DuplicateValue(AttrId),

    // ---- derived attributes and value rules (docs/46 §8.2) ----
    /// The attribute is Derived: it is never stored, and every write naming
    /// it is refused. Spec: docs/46 §5.4, §8.2; [MS-ADTS] 3.1.1.1.6 (servers
    /// MUST reject writes to a back link), 3.1.1.5.3.2 (constructed
    /// attributes cannot be modified).
    DerivedAttribute(AttrId),
    /// A value is outside the attribute's range (value range for integers
    /// and times, UTF-16 length for Utf8String, byte length otherwise).
    /// Spec: docs/46 §8.2; [MS-ADTS] 3.1.1.2.3 (rangeLower / rangeUpper).
    ValueOutOfRange(AttrId),
    /// An Integer32 value sets a bit outside the attribute's allowed bits.
    /// Spec: docs/46 §8.2 (`AllowedBits`, R46-6).
    DisallowedBits(AttrId),
    /// An Integer32 value is not one of the attribute's allowed values.
    /// Spec: docs/46 §8.2 (`AllowedValues`, R46-6).
    ValueNotAllowed(AttrId),
    /// A value of a `unique` Utf8String attribute is not printable ASCII, so
    /// it has no comparison key in phase 1. Spec: docs/46 §8.5; Q-080
    /// (interim: ASCII + A–Z fold, P-9).
    ComparisonKeyNotAscii(AttrId),
    /// A value of an attribute constrained to printable ASCII
    /// ([`crate::ValueConstraint::AsciiPrintable`]) has a byte outside
    /// `0x20..=0x7E`. Spec: Q-091 item 10; Q-080 item 1.
    ValueNotAsciiPrintable(AttrId),

    // ---- class chain and tree shape (docs/46 §8.3 items 1-2) ----
    /// The classes are not `SUPCLASSES(c) ∪ {c}` for exactly one class `c`.
    /// Spec: docs/46 §8.3 item 1; [MS-ADTS] 3.1.1.5.2.2 ("a single, most
    /// specific structural objectClass"), 3.1.1.2.4.3, 3.1.1.4.2.
    InvalidClassChain,
    /// The most specific class is not instantiable. Spec: docs/46 §8.3 item 1;
    /// [MS-ADTS] 3.1.1.5.2.2 (objectClassCategory 0 or 1 only).
    ClassNotInstantiable(ClassId),
    /// An object of an NC-root class has a parent. Spec: docs/46 §8.3 item 2.
    NcRootHasParent,
    /// An object of a class that is not an NC root has no parent.
    /// Spec: docs/46 §8.3 item 2.
    ParentRequired,
    /// The parent's most specific class (named) is not a possible superior
    /// of the new object's class. Spec: docs/46 §8.3 item 2; [MS-ADTS]
    /// 3.1.1.5.2.2 (possSuperiors), 3.1.1.2.4.4.
    ParentClassNotAllowed(ClassId),

    // ---- RDN (docs/46 §8.3 item 3) ----
    /// The RDN attribute of the most specific class is absent.
    /// Spec: docs/46 §8.3 item 3; [MS-ADTS] 3.1.1.1.4.
    RdnAttributeMissing(AttrId),
    /// The RDN attribute holds more than one value ("the RDN attribute of an
    /// object always has exactly one value"). Spec: [MS-ADTS] 3.1.1.1.4,
    /// 3.1.1.3.1.2.1.
    RdnAttributeMultiValued(AttrId),
    /// The RDN value contains a character 0x00 or 0x0A.
    /// Spec: [MS-ADTS] 3.1.1.5.1.2.
    RdnForbiddenCharacter,
    /// The RDN value is not printable ASCII (0x20..=0x7E), so it has no
    /// phase-1 RDN key. Spec: Q-080 (interim, P-9); docs/46 §8.3 item 3.
    RdnNotAscii,
    /// The RDN (`att=val`) is not under [`crate::RDN_SIZE_LIMIT`] characters.
    /// Spec: [MS-ADTS] 3.1.1.5.1.2; docs/46 §8.3 (strict reading); Q-090.
    RdnTooLong,
    /// A stored object's RDN key is not the key computed from its RDN value
    /// (re-validation on read). Spec: docs/46 §8.3 item 3; docs/14 D60.
    RdnKeyMismatch,
    /// A modify names the object's RDN attribute; renaming is a separate
    /// operation (out of scope). Spec: [MS-ADTS] 3.1.1.5.3.2
    /// (notAllowedOnRDN).
    RdnAttributeNotModifiable(AttrId),

    // ---- identity ----
    /// The object GUID is the NULL GUID: "No actual object has objectGUID
    /// equal to the NULL GUID". Spec: [MS-ADTS] 3.1.1.1.3.
    NullGuid,

    // ---- query arguments ----
    /// A back-link query named an attribute that is not a Back link.
    /// Spec: docs/46 §8.4.
    NotBackLink(AttrId),
    /// A unique-index lookup named an attribute that is not `unique`.
    /// Spec: docs/46 §8.5.
    NotUnique(AttrId),
    /// A children listing asked for a page of zero entries (such a page
    /// could never advance). Spec: docs/49 §6.1 item 3; docs/32 §8.
    PageLimitZero,
    /// A children listing was given a cursor made by a listing of another
    /// parent. Spec: docs/49 §6.1 item 3 (`after`); docs/32 §2.
    CursorParentMismatch,

    // ---- named counters (docs/51 §8.3, A-75) ----
    /// A counter name is empty, longer than [`crate::MAX_COUNTER_NAME_LEN`],
    /// or has a byte outside `a`–`z`, `0`–`9`, `.`, `-`, `_`.
    /// Spec: docs/32 §8; Q-330 item 2.
    InvalidCounterName,
    /// A counter range `[first_value, end_exclusive)` is empty or inverted
    /// (`first_value >= end_exclusive`). Spec: A-75.
    EmptyCounterRange,
    /// A counter state breaks `first_value <= next_value <= end_exclusive`
    /// (encoder input). Spec: A-75 (within its bounds).
    InvalidCounterState,

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

    // ---- attribute definition rules (docs/46 §8.2) ----
    /// A link id is zero ("not a link"), or its parity does not match the
    /// link kind (even = forward, odd = back). Spec: [MS-ADTS] 3.1.1.2.3
    /// (linkID); docs/46 §8.2.
    InvalidLinkId(AttrId),
    /// Two forward (or two back) links share a link id. Spec: [MS-ADTS]
    /// 3.1.1.2.3 ("the linkID value is unique").
    DuplicateLinkId(AttrId),
    /// A forward link that is not a Stored attribute of syntax ObjectRef.
    /// Spec: docs/46 §2.3 item 2, §8.2.
    InvalidForwardLink(AttrId),
    /// A back link whose forward link (link id − 1) is not defined.
    /// Spec: [MS-ADTS] 3.1.1.1.6 ("A forward link attribute can exist with no
    /// corresponding back link attribute, but not vice versa"), 3.1.1.2.3.
    BackLinkWithoutForward(AttrId),
    /// A back link that is not Derived. Spec: docs/46 §2.3 item 3, §8.2;
    /// [MS-ADTS] 3.1.1.1.6 (a back link is constructed).
    BackLinkNotDerived(AttrId),
    /// A Stored ObjectRef attribute that is not a forward link (phase 1:
    /// ObjectRef ⇔ Forward). Spec: docs/46 §2.3 item 2, §8.2.
    ObjectRefWithoutForwardLink(AttrId),
    /// A range with lower > upper, or that no value of the syntax (within the
    /// attribute's byte bound) can satisfy. Spec: docs/46 §8.2.
    InvalidRange(AttrId),
    /// A range on a syntax it cannot apply to: "rangeLower does not affect
    /// the allowed values for syntax Boolean and Object(DS-DN)".
    /// Spec: [MS-ADTS] 3.1.1.2.3; docs/46 §8.2.
    RangeNotApplicable(AttrId),
    /// An Integer32 value constraint on another syntax, an empty
    /// allowed-value list, or `AsciiPrintable` on a syntax other than
    /// Utf8String. Spec: docs/46 §8.2; Q-091 item 10.
    InvalidConstraint(AttrId),
    /// A Derived attribute carries a rule that only applies to stored values
    /// (range, constraint, unique, or an RDN label). Spec: docs/46 §8.2.
    DerivedAttributeRule(AttrId),
    /// `unique` on an attribute that is never stored (Secret) or on a link.
    /// Spec: docs/46 §8.5; docs/12 D44.
    UniqueNotApplicable(AttrId),
    /// An RDN label length of 0 or above [`crate::MAX_RDN_ATT_LEN`].
    /// Spec: [MS-ADTS] 3.1.1.1.4, 3.1.1.5.1.2; Q-090.
    InvalidRdnAttLen(AttrId),

    // ---- class definition rules (docs/46 §8.2-§8.3) ----
    /// A class requires a Derived attribute, which can never be written.
    /// Spec: docs/46 §8.2 ("forbidden in must").
    DerivedMustAttribute(ClassId, AttrId),
    /// A class requires a forward link: deleting the last target would leave
    /// the referencing object without a must-attribute. Spec: docs/46 §8.4;
    /// [MS-ADTS] 3.1.1.1.6 (references to a deleted object are removed).
    LinkMustAttribute(ClassId, AttrId),
    /// A class names a superclass that is not defined. Spec: docs/46 §8.3.
    UnknownSuperclass(ClassId, ClassId),
    /// A class's superclass chain is cyclic or longer than
    /// [`crate::MAX_CLASSES_PER_OBJECT`]. Spec: [MS-ADTS] 3.1.1.4.2
    /// (SUPCLASSES); docs/32 §8.
    InvalidClassChain(ClassId),
    /// A class's RDN attribute is not defined. Spec: docs/46 §8.3.
    UndefinedRdnAttribute(ClassId, AttrId),
    /// A class's RDN attribute is not a Stored, non-Secret Utf8String
    /// attribute with an RDN label length. Spec: [MS-ADTS] 3.1.1.3.1.2.1
    /// ("MUST be of String(Unicode) syntax"), 3.1.1.2.4.7; Q-090.
    InvalidRdnAttribute(ClassId, AttrId),
    /// An instantiable class whose chain allows neither must nor may of its
    /// RDN attribute. Spec: docs/46 §8.3 item 3; [MS-ADTS] 3.1.1.4.2
    /// (CLASSATTS).
    RdnAttributeNotAllowed(ClassId, AttrId),
    /// A class names a possible superior that is not defined.
    /// Spec: docs/46 §8.3.
    UnknownPossSuperior(ClassId, ClassId),
    /// A class names the same possible superior twice. Spec: docs/32 §4.
    DuplicatePossSuperior(ClassId, ClassId),
    /// An NC-root class that is not instantiable or lists possible superiors
    /// (an NC root has no parent). Spec: docs/46 §8.3 item 2.
    InvalidNcRoot(ClassId),
    /// An instantiable class that is not an NC root has no possible superior,
    /// so no object of it could be created. Spec: docs/46 §8.3 item 2.
    NoPossSuperiors(ClassId),
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
    /// An ObjectRef value of this attribute names no live object (absent or a
    /// tombstone). Spec: docs/46 §2.3 item 4, §8.4; [MS-ADTS] 3.1.1.1.6
    /// (noSuchObject).
    NoSuchTarget(AttrId),
    /// Another live object already holds a value of this `unique` attribute
    /// with the same comparison key. Spec: docs/46 §8.5.
    ValueNotUnique(AttrId),
    /// An attribute's version counter cannot be incremented.
    /// Spec: docs/29 §2 (version rises on every change).
    VersionOverflow,
    /// A counter with this name already exists; it is never re-created or
    /// reset. Spec: A-75 (never decreases); docs/51 §4.3 step 5.
    CounterExists,
    /// No counter has this name. A counter is never created implicitly.
    /// Spec: A-75; docs/51 §4.3 step 5 (counters are created at provisioning).
    NoSuchCounter,
    /// Every value of the counter's range has been taken. Nothing changed.
    /// Spec: A-75 ("exhaustion ⇒ refusal"); [MS-SAMR] 3.1.1.9.2.2 item 2.
    CounterExhausted,
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
            RecordKind::BackLink => "reverse link",
            RecordKind::UniqueIndex => "unique index",
            RecordKind::Counter => "counter",
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
            DecodeError::KeyLength => "index key has the wrong length",
            DecodeError::CounterState => "counter state outside its bounds",
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
            Violation::DerivedAttribute(a) => {
                write!(f, "attribute {} is derived and never written", a.0)
            }
            Violation::ValueOutOfRange(a) => write!(f, "value of attribute {} out of range", a.0),
            Violation::DisallowedBits(a) => {
                write!(f, "value of attribute {} sets a disallowed bit", a.0)
            }
            Violation::ValueNotAllowed(a) => {
                write!(f, "value of attribute {} is not an allowed value", a.0)
            }
            Violation::ComparisonKeyNotAscii(a) => {
                write!(
                    f,
                    "value of unique attribute {} is not printable ASCII",
                    a.0
                )
            }
            Violation::ValueNotAsciiPrintable(a) => {
                write!(f, "value of attribute {} is not printable ASCII", a.0)
            }
            Violation::InvalidClassChain => {
                f.write_str("classes are not the chain of one most specific class")
            }
            Violation::ClassNotInstantiable(c) => write!(f, "class {} is not instantiable", c.0),
            Violation::NcRootHasParent => f.write_str("naming-context root has a parent"),
            Violation::ParentRequired => f.write_str("object requires a parent"),
            Violation::ParentClassNotAllowed(c) => {
                write!(f, "parent class {} is not a possible superior", c.0)
            }
            Violation::RdnAttributeMissing(a) => write!(f, "RDN attribute {} is absent", a.0),
            Violation::RdnAttributeMultiValued(a) => {
                write!(f, "RDN attribute {} has more than one value", a.0)
            }
            Violation::RdnForbiddenCharacter => f.write_str("RDN contains 0x00 or 0x0A"),
            Violation::RdnNotAscii => f.write_str("RDN is not printable ASCII"),
            Violation::RdnTooLong => f.write_str("RDN is not under the size limit"),
            Violation::RdnKeyMismatch => f.write_str("stored RDN key does not match RDN value"),
            Violation::RdnAttributeNotModifiable(a) => {
                write!(f, "RDN attribute {} cannot be modified", a.0)
            }
            Violation::NullGuid => f.write_str("object GUID is the NULL GUID"),
            Violation::NotBackLink(a) => write!(f, "attribute {} is not a back link", a.0),
            Violation::NotUnique(a) => write!(f, "attribute {} is not unique", a.0),
            Violation::PageLimitZero => f.write_str("listing page limit is zero"),
            Violation::CursorParentMismatch => {
                f.write_str("listing cursor belongs to another parent")
            }
            Violation::InvalidCounterName => f.write_str("counter name is not a valid identifier"),
            Violation::EmptyCounterRange => f.write_str("counter range is empty"),
            Violation::InvalidCounterState => f.write_str("counter state outside its range"),
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
            SchemaDefect::InvalidLinkId(a) => write!(f, "attribute {} has an invalid link id", a.0),
            SchemaDefect::DuplicateLinkId(a) => {
                write!(f, "attribute {} reuses a link id", a.0)
            }
            SchemaDefect::InvalidForwardLink(a) => {
                write!(f, "forward link {} is not a stored object reference", a.0)
            }
            SchemaDefect::BackLinkWithoutForward(a) => {
                write!(f, "back link {} has no forward link", a.0)
            }
            SchemaDefect::BackLinkNotDerived(a) => {
                write!(f, "back link {} is not derived", a.0)
            }
            SchemaDefect::ObjectRefWithoutForwardLink(a) => {
                write!(f, "stored object reference {} is not a forward link", a.0)
            }
            SchemaDefect::InvalidRange(a) => write!(f, "attribute {} has an invalid range", a.0),
            SchemaDefect::RangeNotApplicable(a) => {
                write!(f, "attribute {} cannot carry a range", a.0)
            }
            SchemaDefect::InvalidConstraint(a) => {
                write!(f, "attribute {} has an invalid value constraint", a.0)
            }
            SchemaDefect::DerivedAttributeRule(a) => {
                write!(f, "derived attribute {} carries a stored-value rule", a.0)
            }
            SchemaDefect::UniqueNotApplicable(a) => {
                write!(f, "attribute {} cannot be unique", a.0)
            }
            SchemaDefect::InvalidRdnAttLen(a) => {
                write!(f, "attribute {} has an invalid RDN label length", a.0)
            }
            SchemaDefect::DerivedMustAttribute(c, a) => {
                write!(f, "class {} requires derived attribute {}", c.0, a.0)
            }
            SchemaDefect::LinkMustAttribute(c, a) => {
                write!(f, "class {} requires link attribute {}", c.0, a.0)
            }
            SchemaDefect::UnknownSuperclass(c, s) => {
                write!(f, "class {} names undefined superclass {}", c.0, s.0)
            }
            SchemaDefect::InvalidClassChain(c) => {
                write!(f, "class {} has a cyclic or too long superclass chain", c.0)
            }
            SchemaDefect::UndefinedRdnAttribute(c, a) => {
                write!(f, "class {} names undefined RDN attribute {}", c.0, a.0)
            }
            SchemaDefect::InvalidRdnAttribute(c, a) => {
                write!(f, "class {} has unusable RDN attribute {}", c.0, a.0)
            }
            SchemaDefect::RdnAttributeNotAllowed(c, a) => {
                write!(f, "class {} does not allow its RDN attribute {}", c.0, a.0)
            }
            SchemaDefect::UnknownPossSuperior(c, p) => {
                write!(f, "class {} names undefined possible superior {}", c.0, p.0)
            }
            SchemaDefect::DuplicatePossSuperior(c, p) => {
                write!(f, "class {} names possible superior {} twice", c.0, p.0)
            }
            SchemaDefect::InvalidNcRoot(c) => {
                write!(f, "naming-context root class {} is inconsistent", c.0)
            }
            SchemaDefect::NoPossSuperiors(c) => {
                write!(f, "class {} has no possible superior", c.0)
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
            Error::NoSuchTarget(a) => {
                write!(f, "a reference in attribute {} names no live object", a.0)
            }
            Error::ValueNotUnique(a) => {
                write!(f, "a value of unique attribute {} is already in use", a.0)
            }
            Error::VersionOverflow => f.write_str("attribute version overflow"),
            Error::CounterExists => f.write_str("counter already exists"),
            Error::NoSuchCounter => f.write_str("no such counter"),
            Error::CounterExhausted => f.write_str("counter exhausted"),
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
