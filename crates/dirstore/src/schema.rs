//! Schema as data: attribute and class definitions, and object validation.
//!
//! Spec: docs/32 §4 — the schema is *data* (classes / attributes), not code,
//! and every write is validated against it ("type, must, singularity");
//! docs/11 §6 — the attribute class `Normal | Sensitive | Secret`; docs/12 D44
//! and docs/32 §1 — secret material is never in the readable store, so an
//! attribute of class Secret is never written here; docs/14 D60 — strict
//! validation of what is stored; docs/46 §8.1-§8.3 — the value syntaxes,
//! attribute fields (storage, link, range, constraint, unique) and class
//! fields (superclass, instantiable, RDN attribute, possible superiors, NC
//! root) this module validates.
//!
//! The AD schema *content* ([MS-ADSC] / [MS-ADA1-3]) is out of scope: this
//! module is the mechanism only (docs/46 §8, R46-1). No attribute or class id,
//! name or OID is hard-coded here.

use crate::comparison;
use crate::error::{Error, Result, SchemaDefect, Violation};
use crate::types::{AttrId, ClassId, Object};
use crate::{
    MAX_ATTRIBUTES_PER_OBJECT, MAX_CLASSES_PER_OBJECT, MAX_RDN_ATT_LEN, MAX_RDN_KEY_LEN,
    MAX_VALUES_PER_ATTRIBUTE, MAX_VALUE_LEN,
};
use std::collections::{BTreeMap, BTreeSet};

/// The protection class of an attribute.
///
/// Spec: docs/11 §6 (`AttrClass` = Normal | Sensitive | Secret), §4 layer 5
/// (Sensitive needs a control right to read; Secret has no read path, P6);
/// docs/12 D44 / D46.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AttrClass {
    /// Ordinary attribute.
    Normal,
    /// Stored here; reading it needs a dedicated right, enforced by the PDP
    /// (not by this crate). Spec: docs/11 §4 layer 5.
    Sensitive,
    /// Secret material: belongs to keyd, never to this store. Any write naming
    /// it is rejected. Spec: docs/12 D44; docs/11 P6.
    Secret,
}

/// The value syntax of an attribute: which byte strings are valid values, in
/// their single canonical form. Spec: docs/32 §4 ("type"); docs/14 D60;
/// docs/46 §1 (one canonical internal form per syntax, D60), §8.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValueSyntax {
    /// Any bytes.
    OctetString,
    /// Well-formed UTF-8 text (as decided by `core::str::from_utf8`).
    Utf8String,
    /// A signed 64-bit integer: exactly 8 bytes, two's complement, big-endian
    /// (this crate's canonical internal form).
    Integer,
    /// A signed 32-bit integer: exactly 4 bytes, two's complement, big-endian
    /// (this crate's canonical internal form). Spec: docs/46 §1, §8.1;
    /// [MS-ADTS] 3.1.1.2.2.2 note * ("restricted to 32-bit integers");
    /// [MS-DRSR] 5.16.3.2 (valLen 4).
    Integer32,
    /// A DSTIME — "the number of seconds since January 1, 1601, 12:00:00
    /// A.M." ([MS-DRSR] 5.51) — as exactly 8 bytes, signed big-endian, and
    /// never negative (this crate's canonical internal form; the wire form of
    /// [MS-DRSR] 5.16.3.9 is little-endian). Spec: docs/46 §1, §8.1;
    /// [MS-DRSR] 5.51, 5.16.3.9; [MS-ADTS] 3.1.1.2.2.2 note ††††† (1-second
    /// granularity).
    DsTime,
    /// Exactly one byte, `0x00` (false) or `0x01` (true) (this crate's
    /// canonical internal form).
    Boolean,
    /// A GUID in the 16-byte packet form of our `dtyp` crate
    /// (`dtyp::GUID_PACKET_LEN`, `dtyp::Guid::to_packet`).
    Guid,
    /// A reference to another object: the target's object GUID in the 16-byte
    /// packet form of our `dtyp` crate, never the NULL GUID ("No actual object
    /// has objectGUID equal to the NULL GUID"). That the target exists and is
    /// live is enforced by the store, not by the syntax. In phase 1 only a
    /// forward-link attribute has this syntax. Spec: docs/46 §1, §2.3, §8.1;
    /// [MS-ADTS] 3.1.1.1.3, 3.1.1.1.6; [MS-DRSR] 5.16.2.1.
    ObjectRef,
    /// A SID packet that our `dtyp` crate decodes (`dtyp::Sid::decode`) and
    /// re-encodes to the same bytes. The SID rules are dtyp's (see its docs).
    Sid,
    /// A self-relative security descriptor that our `dtyp` crate decodes
    /// (`dtyp::SecurityDescriptor::decode`) and re-encodes to the same bytes
    /// (canonical form only). The descriptor rules are dtyp's (see its docs);
    /// docs/11 §5: the PDP reads this descriptor.
    SecurityDescriptor,
}

impl ValueSyntax {
    /// `true` if `value` is a canonical value of this syntax.
    /// Spec: docs/32 §4 ("type"); docs/14 D60; docs/46 §8.1.
    #[must_use]
    pub fn accepts(self, value: &[u8]) -> bool {
        match self {
            ValueSyntax::OctetString => true,
            ValueSyntax::Utf8String => core::str::from_utf8(value).is_ok(),
            ValueSyntax::Integer => value.len() == 8,
            // Spec: docs/46 §8.1 (`len == 4`).
            ValueSyntax::Integer32 => value.len() == 4,
            // Spec: docs/46 §8.1 (`len == 8 && i64::from_be_bytes(v) >= 0`).
            ValueSyntax::DsTime => be_i64(value).is_some_and(|t| t >= 0),
            ValueSyntax::Boolean => matches!(value, [0x00] | [0x01]),
            ValueSyntax::Guid => value.len() == dtyp::GUID_PACKET_LEN,
            // Spec: docs/46 §8.1 (`len == GUID_PACKET_LEN && v != [0; 16]`).
            ValueSyntax::ObjectRef => {
                value.len() == dtyp::GUID_PACKET_LEN && value.iter().any(|b| *b != 0)
            }
            ValueSyntax::Sid => dtyp::Sid::decode(value).is_ok_and(|s| s.encode() == value),
            ValueSyntax::SecurityDescriptor => dtyp::SecurityDescriptor::decode(value)
                .and_then(|sd| sd.encode())
                .is_ok_and(|bytes| bytes == value),
        }
    }
}

/// An 8-byte big-endian signed integer, if `value` is exactly 8 bytes.
fn be_i64(value: &[u8]) -> Option<i64> {
    <[u8; 8]>::try_from(value).ok().map(i64::from_be_bytes)
}

/// A 4-byte big-endian signed integer, if `value` is exactly 4 bytes.
fn be_i32(value: &[u8]) -> Option<i32> {
    <[u8; 4]>::try_from(value).ok().map(i32::from_be_bytes)
}

/// Whether an attribute holds one value or a set. Spec: docs/32 §4
/// ("singularity"); docs/29 §4 (single- vs multi-valued).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Multiplicity {
    /// Exactly one value when present.
    SingleValued,
    /// One or more values (a set).
    MultiValued,
}

/// Whether an attribute's values are stored, or derived from stored state by
/// the layer above (objectClass, name, distinguishedName, back links, …).
/// Spec: docs/46 §5.4 ("Derived = never stored; computed on read; every write
/// naming it is refused"), §8.2; [MS-ADTS] 3.1.1.1.4 (constructed attributes
/// contribute no state).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Storage {
    /// Values are stored in the object record.
    Stored,
    /// Never stored; every write naming the attribute is refused, and a class
    /// may not require it. For a Derived attribute only `id`, `class` and a
    /// `Back` link mean anything to this crate.
    Derived,
}

/// The link role of an attribute. Spec: [MS-ADTS] 3.1.1.2.3 (linkID: "If
/// linkID is even, the attribute is a forward link attribute; otherwise it is
/// a back link attribute. The linkID for back link attribute equals to the
/// linkID of the corresponding forward link attribute plus one"); docs/46
/// §2.3, §8.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Link {
    /// A forward link: a Stored attribute of syntax ObjectRef. `link_id` is
    /// even and not zero ("If present, and not zero, this is a link
    /// attribute").
    Forward {
        /// Even, non-zero, unique among forward links.
        link_id: u32,
    },
    /// A back link: Derived, `link_id` odd, equal to its forward link's
    /// `link_id + 1`. Its values are answered from the reverse-link index
    /// ([`crate::Snapshot::back_links`]).
    Back {
        /// Odd; the forward link `link_id - 1` must be defined.
        link_id: u32,
    },
}

/// An inclusive range, interpreted by syntax: the value for
/// Integer / Integer32 / DsTime; the length in UTF-16 code units for
/// Utf8String; the length in bytes for OctetString, Guid, Sid and
/// SecurityDescriptor. Not allowed on Boolean or ObjectRef.
/// Spec: docs/46 §8.2; [MS-ADTS] 3.1.1.2.3 (rangeLower / rangeUpper: value
/// for Integer / LargeInteger / time syntaxes, "length in characters" for
/// String(Unicode), no effect for Boolean and Object(DS-DN), bytes for all
/// other syntaxes); Q-080 item 4 (characters = UTF-16 code units).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ValueRange {
    /// Smallest allowed value / length (inclusive).
    pub lower: i64,
    /// Largest allowed value / length (inclusive).
    pub upper: i64,
}

/// A constraint on the values of an attribute: `AllowedBits` and
/// `AllowedValues` for Integer32 (the value read as its two's-complement bit
/// pattern for `AllowedBits`), `AsciiPrintable` for Utf8String. Any other
/// pairing is refused by [`Schema::new`]. Spec: docs/46 §8.2 (R46-6);
/// Q-091 item 10 (A-30).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ValueConstraint {
    /// Integer32: every set bit of the value must be set in this mask.
    AllowedBits(u32),
    /// Integer32: the value must be one of these (at least one).
    AllowedValues(Vec<i32>),
    /// Utf8String: every byte of the value is printable ASCII,
    /// `0x20..=0x7E` — the phase-1 rule for names that are not an RDN or a
    /// `unique` value (e.g. dNSHostName). Spec: Q-091 item 10 (A-30); Q-080
    /// item 1 (interim ASCII-only names, P-9).
    AsciiPrintable,
}

/// One attribute definition. Spec: docs/32 §4; docs/46 §8.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributeDefinition {
    /// Attribute id. Spec: docs/32 §4; docs/11 §6.
    pub id: AttrId,
    /// Value syntax. Spec: docs/32 §4 ("type").
    pub syntax: ValueSyntax,
    /// Single- or multi-valued. Spec: docs/32 §4 ("singularity").
    pub multiplicity: Multiplicity,
    /// Largest value, in bytes: `1..=MAX_VALUE_LEN`. Spec: docs/32 §8.
    pub max_value_len: usize,
    /// Protection class. Spec: docs/11 §6; docs/12 D44.
    pub class: AttrClass,
    /// Stored or Derived. Spec: docs/46 §8.2.
    pub storage: Storage,
    /// Forward / back link role, if any. Spec: docs/46 §8.2.
    pub link: Option<Link>,
    /// Allowed range of values (see [`ValueRange`]). Spec: docs/46 §8.2.
    pub range: Option<ValueRange>,
    /// Allowed values or bits (Integer32), or printable ASCII (Utf8String).
    /// Spec: docs/46 §8.2; Q-091 item 10.
    pub constraint: Option<ValueConstraint>,
    /// No two live objects may hold values with the same comparison key
    /// (docs/46 §8.5). Honoured always; nothing can switch it off at run time
    /// (docs/CLEAN-ROOM.md).
    pub unique: bool,
    /// For an attribute that can name objects (a class's RDN attribute): the
    /// length in characters of `att` in the RDN form `att=val`, i.e. of the
    /// attribute's lDAPDisplayName — needed for the "RDN size MUST be less
    /// than 255 characters" rule without putting names in this crate
    /// (`1..=MAX_RDN_ATT_LEN`). Spec: [MS-ADTS] 3.1.1.1.4, 3.1.1.5.1.2;
    /// docs/46 §8.3 item 3; Q-090.
    pub rdn_att_len: Option<usize>,
}

impl AttributeDefinition {
    /// A Stored attribute with no link, range, constraint, uniqueness or RDN
    /// label; set those fields directly when needed. Spec: docs/46 §8.2.
    #[must_use]
    pub fn new(
        id: AttrId,
        syntax: ValueSyntax,
        multiplicity: Multiplicity,
        max_value_len: usize,
        class: AttrClass,
    ) -> AttributeDefinition {
        AttributeDefinition {
            id,
            syntax,
            multiplicity,
            max_value_len,
            class,
            storage: Storage::Stored,
            link: None,
            range: None,
            constraint: None,
            unique: false,
            rdn_att_len: None,
        }
    }

    /// The forward link id, if this is a forward link. Spec: docs/46 §8.4.
    pub(crate) fn forward_link_id(&self) -> Option<u32> {
        match self.link {
            Some(Link::Forward { link_id }) => Some(link_id),
            _ => None,
        }
    }
}

/// One class definition. Spec: docs/32 §4 ("must"); docs/46 §8.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassDefinition {
    /// Class id. Spec: docs/32 §4.
    pub id: ClassId,
    /// The superclass (subClassOf); `None` for the root of a chain.
    /// Spec: docs/46 §8.3; [MS-ADTS] 3.1.1.4.2 (SUPCLASSES).
    pub superclass: Option<ClassId>,
    /// Whether an object may have this class as its most specific class.
    /// Spec: docs/46 §8.3; [MS-ADTS] 3.1.1.5.2.2 (objectClassCategory 0 / 1).
    pub instantiable: bool,
    /// The RDN attribute (rDNAttID), already resolved through the superclass
    /// chain by the schema's author. Spec: docs/46 §8.3; [MS-ADTS]
    /// 3.1.1.2.4.7, 3.1.1.3.1.2.1.
    pub rdn_attr: AttrId,
    /// The classes a parent's most specific class may be — flattened
    /// (POSSSUPERIORS of [MS-ADTS] 3.1.1.4.2, computed by the schema's
    /// author). Spec: docs/46 §4.4, §8.3.
    pub poss_superiors: Vec<ClassId>,
    /// An object of this class is the root of a naming context and has no
    /// parent. Spec: docs/46 §8.3 item 2; [MS-ADTS] 3.1.1.1.5.
    pub nc_root: bool,
    /// Attributes every object of this class must hold.
    pub must: Vec<AttrId>,
    /// Further attributes an object of this class may hold.
    pub may: Vec<AttrId>,
}

/// A validated schema. Spec: docs/32 §4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Schema {
    attributes: BTreeMap<AttrId, AttributeDefinition>,
    classes: BTreeMap<ClassId, ClassDefinition>,
    /// `SUPCLASSES(c) ∪ {c}` per class, ascending (the codec's canonical
    /// class order). Spec: [MS-ADTS] 3.1.1.4.2; docs/46 §8.3 item 1.
    chains: BTreeMap<ClassId, Vec<ClassId>>,
    /// Forward link id → the forward-link attribute. Spec: docs/46 §8.4.
    forward_links: BTreeMap<u32, AttrId>,
}

/// Fail with a schema defect.
fn defect<T>(d: SchemaDefect) -> Result<T> {
    Err(Error::InvalidSchema(d))
}

/// The rules of one attribute definition on its own. Spec: docs/32 §4, §8;
/// docs/46 §8.2; [MS-ADTS] 3.1.1.2.3.
fn check_attribute_definition(def: &AttributeDefinition) -> Result<()> {
    let id = def.id;
    if def.max_value_len == 0 || def.max_value_len > MAX_VALUE_LEN {
        return defect(SchemaDefect::ValueBoundOutOfRange(id));
    }
    if let Some(n) = def.rdn_att_len {
        if n == 0 || n > MAX_RDN_ATT_LEN {
            return defect(SchemaDefect::InvalidRdnAttLen(id));
        }
    }
    // A Derived attribute is never stored, so stored-value rules on it would
    // be dead data. Spec: docs/46 §8.2.
    if def.storage == Storage::Derived
        && (def.range.is_some()
            || def.constraint.is_some()
            || def.unique
            || def.rdn_att_len.is_some())
    {
        return defect(SchemaDefect::DerivedAttributeRule(id));
    }
    // Links. Spec: [MS-ADTS] 3.1.1.2.3 (linkID parity, zero = no link);
    // docs/46 §2.3, §8.2.
    match def.link {
        Some(Link::Forward { link_id }) => {
            if link_id == 0 || !link_id.is_multiple_of(2) {
                return defect(SchemaDefect::InvalidLinkId(id));
            }
            if def.storage != Storage::Stored || def.syntax != ValueSyntax::ObjectRef {
                return defect(SchemaDefect::InvalidForwardLink(id));
            }
        }
        Some(Link::Back { link_id }) => {
            if link_id.is_multiple_of(2) {
                return defect(SchemaDefect::InvalidLinkId(id));
            }
            if def.storage != Storage::Derived {
                return defect(SchemaDefect::BackLinkNotDerived(id));
            }
        }
        None => {}
    }
    // Phase 1: a stored ObjectRef is always a forward link (the rule covers
    // stored values; a Derived attribute's syntax is not checked — Q-091
    // item 1). Spec: docs/46 §2.3 item 2, §8.2.
    if def.storage == Storage::Stored
        && def.syntax == ValueSyntax::ObjectRef
        && def.forward_link_id().is_none()
    {
        return defect(SchemaDefect::ObjectRefWithoutForwardLink(id));
    }
    if let Some(r) = def.range {
        check_range(def, r)?;
    }
    // Spec: docs/46 §8.2 (Integer32 constraints); Q-091 item 10
    // (AsciiPrintable on Utf8String only).
    if let Some(c) = &def.constraint {
        let usable = match c {
            ValueConstraint::AllowedBits(_) => def.syntax == ValueSyntax::Integer32,
            ValueConstraint::AllowedValues(v) => {
                def.syntax == ValueSyntax::Integer32 && !v.is_empty()
            }
            ValueConstraint::AsciiPrintable => def.syntax == ValueSyntax::Utf8String,
        };
        if !usable {
            return defect(SchemaDefect::InvalidConstraint(id));
        }
    }
    // Uniqueness applies to stored, non-secret, non-link values.
    // Spec: docs/46 §8.5; docs/12 D44; Q-091 item 3.
    if def.unique && (def.class == AttrClass::Secret || def.link.is_some()) {
        return defect(SchemaDefect::UniqueNotApplicable(id));
    }
    Ok(())
}

/// A range must be ordered and satisfiable by some value of the syntax.
/// Spec: docs/46 §8.2; [MS-ADTS] 3.1.1.2.3.
fn check_range(def: &AttributeDefinition, r: ValueRange) -> Result<()> {
    let id = def.id;
    if r.lower > r.upper {
        return defect(SchemaDefect::InvalidRange(id));
    }
    // A byte bound of at most MAX_VALUE_LEN always fits in i64.
    let max_len = i64::try_from(def.max_value_len).unwrap_or(i64::MAX);
    let satisfiable = match def.syntax {
        // Spec: [MS-ADTS] 3.1.1.2.3 — no effect for Boolean and
        // Object(DS-DN); refused rather than ignored (Q-091 item 4).
        ValueSyntax::Boolean | ValueSyntax::ObjectRef => {
            return defect(SchemaDefect::RangeNotApplicable(id));
        }
        ValueSyntax::Integer => true,
        ValueSyntax::Integer32 => r.upper >= i64::from(i32::MIN) && r.lower <= i64::from(i32::MAX),
        ValueSyntax::DsTime => r.upper >= 0,
        // Lengths: UTF-16 units (each at least one UTF-8 byte) or bytes.
        ValueSyntax::Utf8String
        | ValueSyntax::OctetString
        | ValueSyntax::Guid
        | ValueSyntax::Sid
        | ValueSyntax::SecurityDescriptor => r.lower >= 0 && r.lower <= max_len,
    };
    if satisfiable {
        Ok(())
    } else {
        defect(SchemaDefect::InvalidRange(id))
    }
}

/// The measure a range is compared with, or `None` if the value cannot be
/// measured (not of the syntax). Spec: docs/46 §8.2; [MS-ADTS] 3.1.1.2.3;
/// Q-080 item 4.
fn range_measure(syntax: ValueSyntax, value: &[u8]) -> Option<i64> {
    match syntax {
        ValueSyntax::Integer | ValueSyntax::DsTime => be_i64(value),
        ValueSyntax::Integer32 => be_i32(value).map(i64::from),
        ValueSyntax::Utf8String => core::str::from_utf8(value).ok().and_then(|s| {
            // Characters counted in UTF-16 code units (Q-080 item 4).
            let units: usize = s.chars().map(char::len_utf16).sum();
            i64::try_from(units).ok()
        }),
        ValueSyntax::Boolean | ValueSyntax::ObjectRef => None,
        ValueSyntax::OctetString
        | ValueSyntax::Guid
        | ValueSyntax::Sid
        | ValueSyntax::SecurityDescriptor => i64::try_from(value.len()).ok(),
    }
}

impl Schema {
    /// Build a schema, rejecting a defective definition: duplicate ids,
    /// out-of-range bounds, classes that name undefined or repeated
    /// attributes, classes that require a Secret, Derived or forward-link
    /// attribute, bad links / ranges / constraints / uniqueness, unknown or
    /// cyclic superclasses, unusable RDN attributes, unknown possible
    /// superiors, and inconsistent NC-root classes.
    /// Spec: docs/32 §4; docs/12 D44; docs/46 §8.2-§8.3.
    pub fn new(
        attributes: Vec<AttributeDefinition>,
        classes: Vec<ClassDefinition>,
    ) -> Result<Schema> {
        // ---- attributes ----
        let mut attr_map = BTreeMap::new();
        for def in attributes {
            check_attribute_definition(&def)?;
            let id = def.id;
            if attr_map.insert(id, def).is_some() {
                return defect(SchemaDefect::DuplicateAttributeDefinition(id));
            }
        }
        // Link ids are unique; a back link has its forward link.
        // Spec: [MS-ADTS] 3.1.1.2.3, 3.1.1.1.6; docs/46 §8.2.
        let mut forward_links = BTreeMap::new();
        for def in attr_map.values() {
            if let Some(link_id) = def.forward_link_id() {
                if forward_links.insert(link_id, def.id).is_some() {
                    return defect(SchemaDefect::DuplicateLinkId(def.id));
                }
            }
        }
        let mut back_links = BTreeSet::new();
        for def in attr_map.values() {
            if let Some(Link::Back { link_id }) = def.link {
                let forward = link_id.checked_sub(1);
                if !forward.is_some_and(|f| forward_links.contains_key(&f)) {
                    return defect(SchemaDefect::BackLinkWithoutForward(def.id));
                }
                if !back_links.insert(link_id) {
                    return defect(SchemaDefect::DuplicateLinkId(def.id));
                }
            }
        }

        // ---- classes, each on its own ----
        let mut class_map = BTreeMap::new();
        for def in classes {
            if def.must.len().saturating_add(def.may.len()) > MAX_ATTRIBUTES_PER_OBJECT {
                return defect(SchemaDefect::TooManyAttributesInClass(def.id));
            }
            let mut seen = BTreeSet::new();
            for (attr, required) in def
                .must
                .iter()
                .map(|a| (*a, true))
                .chain(def.may.iter().map(|a| (*a, false)))
            {
                let Some(attr_def) = attr_map.get(&attr) else {
                    return defect(SchemaDefect::UndefinedAttributeInClass(def.id, attr));
                };
                if !seen.insert(attr) {
                    return defect(SchemaDefect::DuplicateAttributeInClass(def.id, attr));
                }
                if required {
                    if attr_def.class == AttrClass::Secret {
                        return defect(SchemaDefect::SecretMustAttribute(def.id, attr));
                    }
                    // Spec: docs/46 §8.2 (Derived forbidden in must).
                    if attr_def.storage == Storage::Derived {
                        return defect(SchemaDefect::DerivedMustAttribute(def.id, attr));
                    }
                    // Spec: docs/46 §8.4; [MS-ADTS] 3.1.1.1.6; Q-091
                    // item 3.
                    if attr_def.forward_link_id().is_some() {
                        return defect(SchemaDefect::LinkMustAttribute(def.id, attr));
                    }
                }
            }
            let mut superiors = BTreeSet::new();
            for p in &def.poss_superiors {
                if !superiors.insert(*p) {
                    return defect(SchemaDefect::DuplicatePossSuperior(def.id, *p));
                }
            }
            let id = def.id;
            if class_map.insert(id, def).is_some() {
                return defect(SchemaDefect::DuplicateClassDefinition(id));
            }
        }

        // ---- classes against each other ----
        for def in class_map.values() {
            if let Some(s) = def.superclass {
                if !class_map.contains_key(&s) {
                    return defect(SchemaDefect::UnknownSuperclass(def.id, s));
                }
            }
            for p in &def.poss_superiors {
                if !class_map.contains_key(p) {
                    return defect(SchemaDefect::UnknownPossSuperior(def.id, *p));
                }
            }
        }
        let mut chains = BTreeMap::new();
        for def in class_map.values() {
            let chain = superclass_chain(&class_map, def)?;
            check_class_naming(&attr_map, &class_map, def, &chain)?;
            chains.insert(def.id, chain);
        }
        Ok(Schema {
            attributes: attr_map,
            classes: class_map,
            chains,
            forward_links,
        })
    }

    /// The definition of an attribute.
    #[must_use]
    pub fn attribute(&self, id: AttrId) -> Option<&AttributeDefinition> {
        self.attributes.get(&id)
    }

    /// The definition of a class.
    #[must_use]
    pub fn class(&self, id: ClassId) -> Option<&ClassDefinition> {
        self.classes.get(&id)
    }

    /// The protection class of an attribute (the PIP query of docs/11 §6).
    #[must_use]
    pub fn attr_class(&self, id: AttrId) -> Option<AttrClass> {
        self.attributes.get(&id).map(|d| d.class)
    }

    /// The most specific class of a canonical (ascending) class list: the one
    /// class `c` with `SUPCLASSES(c) ∪ {c}` equal to the list, or `None` if no
    /// class has exactly this chain. Instantiability is not checked here.
    /// Spec: docs/46 §8.3 item 1; [MS-ADTS] 3.1.1.4.2, 3.1.1.2.4.3; Q-081
    /// (the PDP's object class is the most specific class).
    #[must_use]
    pub fn most_specific_class(&self, classes: &[ClassId]) -> Option<ClassId> {
        classes
            .iter()
            .copied()
            .find(|c| self.chains.get(c).is_some_and(|chain| chain == classes))
    }

    /// The forward-link attribute whose back link id is `back_link_id`
    /// (forward link id + 1). Spec: docs/46 §8.4; [MS-ADTS] 3.1.1.2.3.
    pub(crate) fn forward_link_for_back_id(&self, back_link_id: u32) -> Option<AttrId> {
        if back_link_id.is_multiple_of(2) {
            return None;
        }
        self.forward_links
            .get(&back_link_id.checked_sub(1)?)
            .copied()
    }

    /// Check that a change may name `id` at all: the attribute is defined, is
    /// not Secret and is not Derived. Used for every attribute a write names —
    /// including a removal, since writing a Secret or Derived attribute in any
    /// way is refused. Spec: docs/32 §4; docs/12 D44; docs/46 §8.2.
    pub(crate) fn check_writable(&self, id: AttrId) -> core::result::Result<(), Violation> {
        match self.attributes.get(&id) {
            None => Err(Violation::UnknownAttribute(id)),
            Some(d) if d.class == AttrClass::Secret => Err(Violation::SecretAttribute(id)),
            Some(d) if d.storage == Storage::Derived => Err(Violation::DerivedAttribute(id)),
            Some(_) => Ok(()),
        }
    }

    /// Validate a tombstone record — the tombstone path, separate from
    /// [`Schema::validate_object`], which is never applied to a tombstone.
    ///
    /// A tombstone must carry no parent, no RDN key and no attributes (its
    /// identity and deletion stamp only), and list 1..=MAX classes, ascending,
    /// each known to this schema, forming the chain of one class. Must / may
    /// rules do not apply: a tombstone has no attributes to check them
    /// against. Spec: docs/29 §5; docs/32 §4; docs/25 §5 ("state"); docs/14
    /// D60; Q-062 / A-18; docs/46 §8.3 item 1.
    pub(crate) fn validate_tombstone(&self, obj: &Object) -> core::result::Result<(), Violation> {
        if obj.tombstone.is_none()
            || obj.parent.is_some()
            || !obj.rdn.is_empty()
            || !obj.attributes.is_empty()
        {
            return Err(Violation::TombstoneCarriesContent);
        }
        self.check_classes(&obj.classes)?;
        if self.most_specific_class(&obj.classes).is_none() {
            return Err(Violation::InvalidClassChain);
        }
        Ok(())
    }

    /// Classes: at least one, bounded, ascending (no duplicates), defined.
    /// Spec: docs/32 §4, §8.
    fn check_classes(&self, classes: &[ClassId]) -> core::result::Result<(), Violation> {
        if classes.is_empty() {
            return Err(Violation::NoObjectClass);
        }
        if classes.len() > MAX_CLASSES_PER_OBJECT {
            return Err(Violation::TooManyClasses);
        }
        let mut previous: Option<ClassId> = None;
        for class_id in classes {
            if previous.is_some_and(|p| p >= *class_id) {
                return Err(Violation::DuplicateClass(*class_id));
            }
            previous = Some(*class_id);
            if !self.classes.contains_key(class_id) {
                return Err(Violation::UnknownClass(*class_id));
            }
        }
        Ok(())
    }

    /// Validate a whole live object against this schema and the resource
    /// bounds, and return its most specific class and the RDN key computed
    /// from its RDN value. The object's own `rdn` field is not looked at
    /// (see [`Schema::validate_object`]).
    ///
    /// Order: classes and chain (docs/46 §8.3 item 1); parent presence (item
    /// 2 — the parent's class is checked by the store, which can read it);
    /// attributes (Secret, Derived, allowed, values, syntax, range,
    /// constraint — §8.2); must; RDN (item 3).
    /// Spec: docs/32 §4, §8; docs/12 D44; docs/14 D60; docs/46 §8.2-§8.3.
    pub(crate) fn check_object(
        &self,
        obj: &Object,
    ) -> core::result::Result<(ClassId, Vec<u8>), Violation> {
        // Classes: the full chain of exactly one instantiable class.
        // Spec: docs/46 §8.3 item 1; [MS-ADTS] 3.1.1.5.2.2, 3.1.1.2.4.3.
        self.check_classes(&obj.classes)?;
        let most_specific = self
            .most_specific_class(&obj.classes)
            .ok_or(Violation::InvalidClassChain)?;
        let class = self
            .classes
            .get(&most_specific)
            .ok_or(Violation::UnknownClass(most_specific))?;
        if !class.instantiable {
            return Err(Violation::ClassNotInstantiable(most_specific));
        }
        // An NC root has no parent; every other object has one.
        // Spec: docs/46 §8.3 item 2.
        match (class.nc_root, obj.parent.is_some()) {
            (true, true) => return Err(Violation::NcRootHasParent),
            (false, false) => return Err(Violation::ParentRequired),
            _ => {}
        }
        let mut allowed = BTreeSet::new();
        for class_id in &obj.classes {
            if let Some(c) = self.classes.get(class_id) {
                allowed.extend(c.must.iter().copied());
                allowed.extend(c.may.iter().copied());
            }
        }

        // Attributes. Spec: docs/32 §4 ("type, must, singularity"), §8;
        // docs/46 §8.2.
        if obj.attributes.len() > MAX_ATTRIBUTES_PER_OBJECT {
            return Err(Violation::TooManyAttributes);
        }
        let mut previous: Option<AttrId> = None;
        for attr in &obj.attributes {
            if previous.is_some_and(|p| p >= attr.id) {
                return Err(Violation::DuplicateAttribute(attr.id));
            }
            previous = Some(attr.id);
            let def = self
                .attributes
                .get(&attr.id)
                .ok_or(Violation::UnknownAttribute(attr.id))?;
            // Secret before anything else about the attribute. Spec: D44.
            if def.class == AttrClass::Secret {
                return Err(Violation::SecretAttribute(attr.id));
            }
            // A Derived attribute has no stored values. Spec: docs/46 §8.2.
            if def.storage == Storage::Derived {
                return Err(Violation::DerivedAttribute(attr.id));
            }
            if !allowed.contains(&attr.id) {
                return Err(Violation::AttributeNotAllowed(attr.id));
            }
            if attr.values.is_empty() {
                return Err(Violation::EmptyAttribute(attr.id));
            }
            if attr.values.len() > MAX_VALUES_PER_ATTRIBUTE {
                return Err(Violation::TooManyValues(attr.id));
            }
            if def.multiplicity == Multiplicity::SingleValued && attr.values.len() > 1 {
                return Err(Violation::MultipleValuesOnSingleValued(attr.id));
            }
            let mut previous_value: Option<&[u8]> = None;
            for v in &attr.values {
                if v.value.len() > def.max_value_len {
                    return Err(Violation::ValueTooLarge(attr.id));
                }
                if !def.syntax.accepts(&v.value) {
                    return Err(Violation::InvalidValueSyntax(attr.id));
                }
                if previous_value.is_some_and(|p| p >= v.value.as_slice()) {
                    return Err(Violation::DuplicateValue(attr.id));
                }
                previous_value = Some(&v.value);
                check_value_rules(def, &v.value)?;
            }
            // A unique attribute's values have comparison keys (printable
            // ASCII for Utf8String) and no two of them share one.
            // Spec: docs/46 §8.5; Q-080.
            if def.unique {
                let mut keys = BTreeSet::new();
                for v in &attr.values {
                    if !keys.insert(comparison::unique_key(attr.id, def.syntax, &v.value)?) {
                        return Err(Violation::DuplicateValue(attr.id));
                    }
                }
            }
        }

        // Every must-attribute of every class is present. Spec: docs/32 §4.
        for class_id in &obj.classes {
            if let Some(c) = self.classes.get(class_id) {
                for must in &c.must {
                    if obj.attribute(*must).is_none() {
                        return Err(Violation::MissingMustAttribute(*must));
                    }
                }
            }
        }

        // RDN: exactly one value of the most specific class's RDN attribute;
        // the key is computed from it. Spec: docs/46 §8.3 item 3; [MS-ADTS]
        // 3.1.1.1.4, 3.1.1.3.1.2.1, 3.1.1.5.1.2; Q-080.
        let rdn_attr = class.rdn_attr;
        let att_len = self
            .attributes
            .get(&rdn_attr)
            .and_then(|d| d.rdn_att_len)
            .ok_or(Violation::RdnAttributeMissing(rdn_attr))?;
        let value = match obj.attribute(rdn_attr).map(|a| a.values.as_slice()) {
            None | Some([]) => return Err(Violation::RdnAttributeMissing(rdn_attr)),
            Some([only]) => only,
            Some(_) => return Err(Violation::RdnAttributeMultiValued(rdn_attr)),
        };
        let key = comparison::rdn_key(&value.value, att_len)?;
        Ok((most_specific, key))
    }

    /// Validate a whole live object against this schema and the resource
    /// bounds, including that its stored RDN key is the key computed from
    /// its RDN value. Never applied to a tombstone (see
    /// [`Schema::validate_tombstone`]).
    ///
    /// Used on every write (the object as it will be stored) and on every read
    /// that returns an object (re-validation, D60), so the store never hands
    /// out an object this schema would refuse — in particular never a Secret
    /// or Derived attribute. Spec: docs/32 §4, §8; docs/12 D44; docs/14 D60;
    /// docs/46 §8.3.
    pub(crate) fn validate_object(&self, obj: &Object) -> core::result::Result<(), Violation> {
        // RDN key bounds. Spec: docs/32 §2, §8.
        if obj.rdn.is_empty() {
            return Err(Violation::RdnKeyEmpty);
        }
        if obj.rdn.len() > MAX_RDN_KEY_LEN {
            return Err(Violation::RdnKeyTooLong);
        }
        let (_, key) = self.check_object(obj)?;
        if key != obj.rdn {
            return Err(Violation::RdnKeyMismatch);
        }
        Ok(())
    }
}

/// Range and constraint of one (syntax-valid) value. Spec: docs/46 §8.2;
/// [MS-ADTS] 3.1.1.2.3.
fn check_value_rules(
    def: &AttributeDefinition,
    value: &[u8],
) -> core::result::Result<(), Violation> {
    let id = def.id;
    if let Some(r) = def.range {
        let in_range =
            range_measure(def.syntax, value).is_some_and(|m| m >= r.lower && m <= r.upper);
        if !in_range {
            return Err(Violation::ValueOutOfRange(id));
        }
    }
    match &def.constraint {
        None => {}
        Some(ValueConstraint::AllowedBits(mask)) => {
            let v = be_i32(value).ok_or(Violation::InvalidValueSyntax(id))?;
            // The two's-complement bit pattern of the value.
            let bits = u32::from_be_bytes(v.to_be_bytes());
            if bits & !mask != 0 {
                return Err(Violation::DisallowedBits(id));
            }
        }
        Some(ValueConstraint::AllowedValues(allowed)) => {
            let v = be_i32(value).ok_or(Violation::InvalidValueSyntax(id))?;
            if !allowed.contains(&v) {
                return Err(Violation::ValueNotAllowed(id));
            }
        }
        // Spec: Q-091 item 10; Q-080 item 1.
        Some(ValueConstraint::AsciiPrintable)
            if !value.iter().copied().all(comparison::printable_ascii) =>
        {
            return Err(Violation::ValueNotAsciiPrintable(id));
        }
        Some(ValueConstraint::AsciiPrintable) => {}
    }
    Ok(())
}

/// `SUPCLASSES(c) ∪ {c}`, ascending; a cyclic or over-long chain is a defect.
/// Every superclass is known (checked before). Spec: [MS-ADTS] 3.1.1.4.2;
/// docs/32 §8 (MAX_CLASSES_PER_OBJECT).
fn superclass_chain(
    classes: &BTreeMap<ClassId, ClassDefinition>,
    def: &ClassDefinition,
) -> Result<Vec<ClassId>> {
    let mut chain = vec![def.id];
    let mut next = def.superclass;
    while let Some(s) = next {
        if chain.len() >= MAX_CLASSES_PER_OBJECT || chain.contains(&s) {
            return defect(SchemaDefect::InvalidClassChain(def.id));
        }
        chain.push(s);
        next = classes.get(&s).and_then(|c| c.superclass);
    }
    chain.sort_unstable();
    Ok(chain)
}

/// The RDN attribute and NC-root rules of one class.
/// Spec: docs/46 §8.3; [MS-ADTS] 3.1.1.3.1.2.1, 3.1.1.2.4.7, 3.1.1.4.2.
fn check_class_naming(
    attributes: &BTreeMap<AttrId, AttributeDefinition>,
    classes: &BTreeMap<ClassId, ClassDefinition>,
    def: &ClassDefinition,
    chain: &[ClassId],
) -> Result<()> {
    let Some(rdn) = attributes.get(&def.rdn_attr) else {
        return defect(SchemaDefect::UndefinedRdnAttribute(def.id, def.rdn_attr));
    };
    // "the AttributeType used MUST be of String(Unicode) syntax".
    // Spec: [MS-ADTS] 3.1.1.3.1.2.1; Q-090 (label length needed).
    if rdn.syntax != ValueSyntax::Utf8String
        || rdn.storage != Storage::Stored
        || rdn.class == AttrClass::Secret
        || rdn.rdn_att_len.is_none()
    {
        return defect(SchemaDefect::InvalidRdnAttribute(def.id, def.rdn_attr));
    }
    if def.nc_root && (!def.instantiable || !def.poss_superiors.is_empty()) {
        return defect(SchemaDefect::InvalidNcRoot(def.id));
    }
    if def.instantiable {
        if !def.nc_root && def.poss_superiors.is_empty() {
            return defect(SchemaDefect::NoPossSuperiors(def.id));
        }
        // The chain (CLASSATTS) must allow the RDN attribute.
        let allowed = chain
            .iter()
            .filter_map(|c| classes.get(c))
            .any(|c| c.must.contains(&def.rdn_attr) || c.may.contains(&def.rdn_attr));
        if !allowed {
            return defect(SchemaDefect::RdnAttributeNotAllowed(def.id, def.rdn_attr));
        }
    }
    Ok(())
}
