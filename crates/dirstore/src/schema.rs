//! Schema as data: attribute and class definitions, and object validation.
//!
//! Spec: docs/32 §4 — the schema is *data* (classes / attributes), not code,
//! and every write is validated against it ("type, must, singularity");
//! docs/11 §6 — the attribute class `Normal | Sensitive | Secret`; docs/12 D44
//! and docs/32 §1 — secret material is never in the readable store, so an
//! attribute of class Secret is never written here; docs/14 D60 — strict
//! validation of what is stored.
//!
//! The AD schema *content* ([MS-ADSC] / [MS-ADA1-3]) is out of scope: this
//! module is the mechanism only.

use crate::error::{Error, Result, SchemaDefect, Violation};
use crate::types::{AttrId, ClassId, Object};
use crate::{
    MAX_ATTRIBUTES_PER_OBJECT, MAX_CLASSES_PER_OBJECT, MAX_RDN_KEY_LEN, MAX_VALUES_PER_ATTRIBUTE,
    MAX_VALUE_LEN,
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
/// their single canonical form. Spec: docs/32 §4 ("type"); docs/14 D60.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValueSyntax {
    /// Any bytes.
    OctetString,
    /// Well-formed UTF-8 text (as decided by `core::str::from_utf8`).
    Utf8String,
    /// A signed 64-bit integer: exactly 8 bytes, two's complement, big-endian
    /// (this crate's canonical internal form).
    Integer,
    /// Exactly one byte, `0x00` (false) or `0x01` (true) (this crate's
    /// canonical internal form).
    Boolean,
    /// A GUID in the 16-byte packet form of our `dtyp` crate
    /// (`dtyp::GUID_PACKET_LEN`, `dtyp::Guid::to_packet`).
    Guid,
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
    /// Spec: docs/32 §4 ("type"); docs/14 D60.
    #[must_use]
    pub fn accepts(self, value: &[u8]) -> bool {
        match self {
            ValueSyntax::OctetString => true,
            ValueSyntax::Utf8String => core::str::from_utf8(value).is_ok(),
            ValueSyntax::Integer => value.len() == 8,
            ValueSyntax::Boolean => matches!(value, [0x00] | [0x01]),
            ValueSyntax::Guid => value.len() == dtyp::GUID_PACKET_LEN,
            ValueSyntax::Sid => dtyp::Sid::decode(value).is_ok_and(|s| s.encode() == value),
            ValueSyntax::SecurityDescriptor => dtyp::SecurityDescriptor::decode(value)
                .and_then(|sd| sd.encode())
                .is_ok_and(|bytes| bytes == value),
        }
    }
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

/// One attribute definition. Spec: docs/32 §4.
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
}

/// One class definition: the attributes an object of the class must and may
/// hold. Spec: docs/32 §4 ("must").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassDefinition {
    /// Class id. Spec: docs/32 §4.
    pub id: ClassId,
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
}

impl Schema {
    /// Build a schema, rejecting a defective definition (duplicate ids,
    /// out-of-range bounds, classes that name undefined or repeated
    /// attributes, classes that require a Secret attribute).
    /// Spec: docs/32 §4; docs/12 D44.
    pub fn new(
        attributes: Vec<AttributeDefinition>,
        classes: Vec<ClassDefinition>,
    ) -> Result<Schema> {
        let mut attr_map = BTreeMap::new();
        for def in attributes {
            if def.max_value_len == 0 || def.max_value_len > MAX_VALUE_LEN {
                return Err(Error::InvalidSchema(SchemaDefect::ValueBoundOutOfRange(
                    def.id,
                )));
            }
            let id = def.id;
            if attr_map.insert(id, def).is_some() {
                return Err(Error::InvalidSchema(
                    SchemaDefect::DuplicateAttributeDefinition(id),
                ));
            }
        }
        let mut class_map = BTreeMap::new();
        for def in classes {
            if def.must.len().saturating_add(def.may.len()) > MAX_ATTRIBUTES_PER_OBJECT {
                return Err(Error::InvalidSchema(
                    SchemaDefect::TooManyAttributesInClass(def.id),
                ));
            }
            let mut seen = BTreeSet::new();
            for (attr, required) in def
                .must
                .iter()
                .map(|a| (*a, true))
                .chain(def.may.iter().map(|a| (*a, false)))
            {
                let attr_def = attr_map.get(&attr).ok_or(Error::InvalidSchema(
                    SchemaDefect::UndefinedAttributeInClass(def.id, attr),
                ))?;
                if !seen.insert(attr) {
                    return Err(Error::InvalidSchema(
                        SchemaDefect::DuplicateAttributeInClass(def.id, attr),
                    ));
                }
                if required && attr_def.class == AttrClass::Secret {
                    return Err(Error::InvalidSchema(SchemaDefect::SecretMustAttribute(
                        def.id, attr,
                    )));
                }
            }
            let id = def.id;
            if class_map.insert(id, def).is_some() {
                return Err(Error::InvalidSchema(
                    SchemaDefect::DuplicateClassDefinition(id),
                ));
            }
        }
        Ok(Schema {
            attributes: attr_map,
            classes: class_map,
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

    /// Check that a change may name `id` at all: the attribute is defined and
    /// is not Secret. Used for every attribute a write names — including a
    /// removal, since writing a Secret attribute in any way is refused.
    /// Spec: docs/32 §4; docs/12 D44.
    pub(crate) fn check_writable(&self, id: AttrId) -> core::result::Result<(), Violation> {
        match self.attributes.get(&id) {
            None => Err(Violation::UnknownAttribute(id)),
            Some(d) if d.class == AttrClass::Secret => Err(Violation::SecretAttribute(id)),
            Some(_) => Ok(()),
        }
    }

    /// Validate a tombstone record — the tombstone path, separate from
    /// [`Schema::validate_object`], which is never applied to a tombstone.
    ///
    /// A tombstone must carry no parent, no RDN key and no attributes (its
    /// identity and deletion stamp only), and list 1..=MAX classes, ascending,
    /// each known to this schema. Must / may rules do not apply: a tombstone
    /// has no attributes to check them against.
    /// Spec: docs/29 §5; docs/32 §4; docs/25 §5 ("state"); docs/14 D60;
    /// Q-062 / A-18.
    pub(crate) fn validate_tombstone(&self, obj: &Object) -> core::result::Result<(), Violation> {
        if obj.tombstone.is_none()
            || obj.parent.is_some()
            || !obj.rdn.is_empty()
            || !obj.attributes.is_empty()
        {
            return Err(Violation::TombstoneCarriesContent);
        }
        if obj.classes.is_empty() {
            return Err(Violation::NoObjectClass);
        }
        if obj.classes.len() > MAX_CLASSES_PER_OBJECT {
            return Err(Violation::TooManyClasses);
        }
        let mut previous: Option<ClassId> = None;
        for class_id in &obj.classes {
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
    /// bounds. Never applied to a tombstone (see
    /// [`Schema::validate_tombstone`]).
    ///
    /// Used on every write (the object as it will be stored) and on every read
    /// that returns an object (re-validation, D60), so the store never hands
    /// out an object this schema would refuse — in particular never a Secret
    /// attribute. Spec: docs/32 §4, §8; docs/12 D44; docs/14 D60.
    pub(crate) fn validate_object(&self, obj: &Object) -> core::result::Result<(), Violation> {
        // RDN key bounds. Spec: docs/32 §2, §8.
        if obj.rdn.is_empty() {
            return Err(Violation::RdnKeyEmpty);
        }
        if obj.rdn.len() > MAX_RDN_KEY_LEN {
            return Err(Violation::RdnKeyTooLong);
        }

        // Classes: at least one, bounded, defined, no duplicates (ascending).
        // Spec: docs/32 §4, §8.
        if obj.classes.is_empty() {
            return Err(Violation::NoObjectClass);
        }
        if obj.classes.len() > MAX_CLASSES_PER_OBJECT {
            return Err(Violation::TooManyClasses);
        }
        let mut allowed = BTreeSet::new();
        let mut previous: Option<ClassId> = None;
        for class_id in &obj.classes {
            if previous.is_some_and(|p| p >= *class_id) {
                return Err(Violation::DuplicateClass(*class_id));
            }
            previous = Some(*class_id);
            let class = self
                .classes
                .get(class_id)
                .ok_or(Violation::UnknownClass(*class_id))?;
            allowed.extend(class.must.iter().copied());
            allowed.extend(class.may.iter().copied());
        }

        // Attributes. Spec: docs/32 §4 ("type, must, singularity"), §8.
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
            }
        }

        // Every must-attribute of every class is present. Spec: docs/32 §4.
        for class_id in &obj.classes {
            if let Some(class) = self.classes.get(class_id) {
                for must in &class.must {
                    if obj.attribute(*must).is_none() {
                        return Err(Violation::MissingMustAttribute(*must));
                    }
                }
            }
        }
        Ok(())
    }
}
