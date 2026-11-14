//! Building the phase-1 schema from the tables, and the lookups over it.
//!
//! Everything that can be computed is computed here, never set per row
//! (docs/46 §3.3, §6, §7; A-28):
//!
//! - `AttrId` / `ClassId` = `MakeAttid(NewPrefixTable(), attributeID |
//!   governsID)` (R46-3);
//! - the dirstore value syntax, from the AD syntax (docs/46 §1);
//! - the `AttrClass`: Secret for the [MS-ADTS] 3.1.1.1.4 set, Sensitive for
//!   fCONFIDENTIAL, Normal otherwise (docs/46 §6);
//! - the link role, from linkID parity ([MS-ADTS] 3.1.1.2.3);
//! - `rdn_att_len`, from the lDAPDisplayName of every attribute some class
//!   names as rDNAttID (Q-090);
//! - `instantiable`, from objectClassCategory (docs/46 §4.1);
//! - a property set's `is_attribute_guid`, from the whole attribute table
//!   (A-28);
//! - the objectClass chain and CLASSATTS of every class ([MS-ADTS]
//!   3.1.1.4.2, 3.1.1.2.4.3).
//!
//! Spec: docs/46 §3-§8 (decided, A-29); [MS-ADTS] v20261026 3.1.1.1.4,
//! 3.1.1.2.3, 3.1.1.2.3.3, 3.1.1.2.4.3, 3.1.1.4.2; [MS-DRSR] v20260309
//! 5.16.4; Q-080, Q-081 / A-28, Q-090, Q-091.

use crate::attid::make_attid;
use crate::attributes::{dirstore_syntax, AttributeEntry, Constraint, Form, SECRET_ATTRIBUTES};
use crate::classes::{ClassEntry, STRUCTURAL_CLASS};
use crate::error::{Error, LookupError};
use crate::flags::search_flags::F_CONFIDENTIAL;
use crate::{ATTRIBUTES, CLASSES};
use dirstore::{
    AttrClass, AttrId, AttributeDefinition, ClassDefinition, ClassId, Link, Schema, Storage,
    ValueConstraint, ValueSyntax,
};
use dtyp::Guid;
use std::collections::{BTreeMap, BTreeSet};

/// A property set an attribute belongs to.
/// Spec: [MS-ADTS] 3.1.1.2.3.3 ("the property set is identified by the
/// property set GUID, which is the attributeSecurityGUID value"); A-28
/// (Q-081) item 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PropertySet {
    /// The property set GUID (the attribute's attributeSecurityGUID).
    pub guid: Guid,
    /// `true` if `guid` is also the schemaIDGUID of some attribute in the
    /// phase-1 table, so the GUID labels two nodes of the object type tree
    /// (in phase 1: dNSHostName, [MS-ADA1] 2.185). Computed from the whole
    /// attribute table. Spec: A-28; Q-081 item 2.
    pub is_attribute_guid: bool,
}

/// One phase-1 attribute, with everything computed from its table row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributeInfo {
    /// The table row (attributeSchema values and dirstore form).
    pub entry: &'static AttributeEntry,
    /// The ATTRTYP, `MakeAttid(NewPrefixTable(), attributeID)`.
    /// Spec: [MS-DRSR] 5.16.4; docs/46 §3.3.
    pub id: AttrId,
    /// schemaIDGUID. Spec: [MS-ADTS] 3.1.1.2.3.
    pub schema_id_guid: Guid,
    /// The property set, if the entry has an attributeSecurityGUID.
    pub property_set: Option<PropertySet>,
    /// The protection class. Spec: docs/46 §6.
    pub attr_class: AttrClass,
}

/// One phase-1 class, with everything computed from its table row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassInfo {
    /// The table row (classSchema values and dirstore definition).
    pub entry: &'static ClassEntry,
    /// The ATTRTYP, `MakeAttid(NewPrefixTable(), governsID)`.
    /// Spec: [MS-DRSR] 5.16.4; docs/46 §3.3.
    pub id: ClassId,
    /// schemaIDGUID. Spec: [MS-ADTS] 3.1.1.2.4.8.
    pub schema_id_guid: Guid,
    /// subClassOf; `None` for top. Spec: [MS-ADTS] 3.1.1.4.2.
    pub superclass: Option<ClassId>,
    /// Whether phase 1 lets an object have this as its most specific class
    /// (structural classes only). Spec: docs/46 §4.1.
    pub instantiable: bool,
    /// The class defaultObjectCategory names — the value of the derived
    /// objectCategory on objects of this class (R46-5). Spec: docs/46 §4.2,
    /// §5.4.
    pub default_object_category: ClassId,
    /// The objectClass value of an object of this class:
    /// `SUPCLASSES(c) ∪ {c}`, top first, this class last.
    /// Spec: [MS-ADTS] 3.1.1.2.4.3.
    pub object_class: Vec<ClassId>,
    /// CLASSATTS(c) cut to the 35 phase-1 attributes, ascending — every
    /// attribute (stored, derived or secret) an object of this class can
    /// have, the second and third levels of its object type tree.
    /// Spec: [MS-ADTS] 3.1.1.4.2, 5.1.3.3.3; docs/46 §7.
    pub class_attributes: Vec<AttrId>,
}

/// One class of a [`ClassChain`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChainClass {
    /// The ClassId (ATTRTYP).
    pub id: ClassId,
    /// Its schemaIDGUID (the PDP's object class identifier).
    pub schema_id_guid: Guid,
}

/// The classes of an object: its most specific class and the rest of its
/// superclass chain. Spec: [MS-ADTS] 3.1.1.2.4.3; A-28 (Q-081) item 1 (the
/// root of the object type tree is the most specific class).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ClassChain {
    /// The most specific class (the last objectClass value).
    pub most_specific: ChainClass,
    /// top up to the direct superclass of `most_specific`, in objectClass
    /// order (top first).
    pub superclasses: Vec<ChainClass>,
}

/// The phase-1 AD schema: the validated `dirstore::Schema` and the metadata
/// and lookup tables of docs/46 §7.
#[derive(Debug, Clone)]
pub struct Phase1Schema {
    schema: Schema,
    attributes: BTreeMap<AttrId, AttributeInfo>,
    classes: BTreeMap<ClassId, ClassInfo>,
    attribute_names: BTreeMap<String, AttrId>,
    class_names: BTreeMap<String, ClassId>,
    /// Longest lDAPDisplayName in the tables; a longer name cannot match.
    max_name_len: usize,
}

/// lDAPDisplayName of the class at the root of every chain.
/// Spec: [MS-ADTS] 3.1.1.4.2; [MS-ADSC] 2.266.
const TOP: &str = "top";

/// The lookup key of an lDAPDisplayName: ASCII with A–Z folded to a–z;
/// `None` if not ASCII. Spec: Q-080 (interim ASCII + A–Z fold, P-9), as the
/// task applies it to lDAPDisplayName (case-insensitive); [MS-ADTS]
/// 3.1.1.2.3 ("Unique" name).
fn name_key(name: &str) -> Option<String> {
    name.is_ascii().then(|| name.to_ascii_lowercase())
}

/// Insert `name → id` into a name map, refusing duplicates and non-ASCII.
fn insert_name<T: Copy>(
    map: &mut BTreeMap<String, T>,
    name: &'static str,
    id: T,
) -> Result<(), Error> {
    let key = name_key(name).ok_or(Error::DuplicateOrInvalidName(name))?;
    if map.insert(key, id).is_some() {
        return Err(Error::DuplicateOrInvalidName(name));
    }
    Ok(())
}

/// A table GUID string (the lower-case `8-4-4-4-12` form [MS-ADSC] /
/// [MS-ADA*] print), parsed by dtyp's one GUID text mapping — the A-31
/// route, moved there from this crate (A-86 follow-up).
/// Spec: [MS-DTYP] 2.3.4.1, 2.3.4.2, 2.5.1.1; [MS-DRSR] 5.16.3.16; A-31.
fn parse_guid(s: &str) -> Option<Guid> {
    Guid::parse_text(s).ok()
}

/// Parse a table GUID string.
fn guid(name: &'static str, s: &str) -> Result<Guid, Error> {
    parse_guid(s).ok_or(Error::MalformedGuid(name))
}

/// The ATTRTYP of a table OID.
fn attrtyp(name: &'static str, oid: &str) -> Result<u32, Error> {
    make_attid(oid).map_err(|error| Error::Attrtyp { name, error })
}

/// The protection class of a row: Secret for a secret row, Sensitive for
/// fCONFIDENTIAL, Normal otherwise. Spec: docs/46 §6; [MS-ADTS] 2.2.9
/// (fCONFIDENTIAL), 3.1.1.1.4 (the secret set).
fn attr_class_of(entry: &AttributeEntry) -> AttrClass {
    if entry.form == Form::Secret {
        AttrClass::Secret
    } else if entry.search_flags & F_CONFIDENTIAL != 0 {
        AttrClass::Sensitive
    } else {
        AttrClass::Normal
    }
}

/// The dirstore constraint of a table constraint.
fn value_constraint(c: Constraint) -> ValueConstraint {
    match c {
        Constraint::AllowedBits(mask) => ValueConstraint::AllowedBits(mask),
        Constraint::AllowedValues(values) => ValueConstraint::AllowedValues(values.to_vec()),
        Constraint::AsciiPrintable => ValueConstraint::AsciiPrintable,
    }
}

/// The dirstore definition of one attribute row. Spec: docs/46 §5.4, §8.2;
/// [MS-ADTS] 3.1.1.2.3 (linkID parity); Q-090 (`rdn_att_len`); Q-091 item 1
/// (a Derived attribute's syntax is not checked).
fn attribute_definition(
    entry: &'static AttributeEntry,
    id: AttrId,
    class: AttrClass,
    rdn_attribute: bool,
) -> Result<AttributeDefinition, Error> {
    let name = entry.ldap_display_name;
    let multiplicity = if entry.is_single_valued {
        dirstore::Multiplicity::SingleValued
    } else {
        dirstore::Multiplicity::MultiValued
    };
    // Link role by parity: even = forward, odd = back. A wrong pairing with
    // the storage is refused by Schema::new. Spec: [MS-ADTS] 3.1.1.2.3.
    let link = entry.link_id.map(|link_id| {
        if link_id % 2 == 0 {
            Link::Forward { link_id }
        } else {
            Link::Back { link_id }
        }
    });
    let def = match entry.form {
        Form::Stored(s) => {
            let syntax = dirstore_syntax(entry).ok_or(Error::UnmappedSyntax(name))?;
            AttributeDefinition {
                range: s.range,
                constraint: s.constraint.map(value_constraint),
                unique: s.unique,
                link,
                // Spec: Q-090 — the length of `att` in "att=val" (ASCII).
                rdn_att_len: rdn_attribute.then_some(name.len()),
                ..AttributeDefinition::new(id, syntax, s.multiplicity, s.max_value_len, class)
            }
        }
        Form::Derived { max_value_len } => {
            // String(Object-Identifier) (objectClass) has no phase-1
            // variant; a Derived syntax is never read (Q-091 item 1).
            let syntax = dirstore_syntax(entry).unwrap_or(ValueSyntax::OctetString);
            AttributeDefinition {
                storage: Storage::Derived,
                link,
                ..AttributeDefinition::new(id, syntax, multiplicity, max_value_len, class)
            }
        }
        Form::Secret => {
            let syntax = dirstore_syntax(entry).ok_or(Error::UnmappedSyntax(name))?;
            AttributeDefinition {
                link,
                ..AttributeDefinition::new(id, syntax, multiplicity, dirstore::MAX_VALUE_LEN, class)
            }
        }
    };
    Ok(def)
}

/// Resolve lDAPDisplayNames named by a class row.
fn resolve<T: Copy>(
    map: &BTreeMap<String, T>,
    entry: &'static str,
    names: &[&'static str],
) -> Result<Vec<T>, Error> {
    names
        .iter()
        .map(|name| {
            name_key(name)
                .and_then(|k| map.get(&k).copied())
                .ok_or(Error::UnknownName { entry, name })
        })
        .collect()
}

/// Build the phase-1 schema. Fails closed on any table defect and if
/// `dirstore::Schema::new` refuses the result.
///
/// Spec: docs/46 §3-§8 (A-29); see the module docs.
pub fn phase1() -> Result<Phase1Schema, Error> {
    let mut attribute_names = BTreeMap::new();
    let mut class_names = BTreeMap::new();
    let mut attrtyps = BTreeSet::new();
    let mut schema_guids = BTreeSet::new();
    let mut max_name_len = 0;

    // ---- attribute identities ----
    let mut attr_ids = Vec::with_capacity(ATTRIBUTES.len());
    for entry in ATTRIBUTES.iter() {
        let name = entry.ldap_display_name;
        let raw = attrtyp(name, entry.attribute_id)?;
        let schema_id_guid = guid(name, entry.schema_id_guid)?;
        if !attrtyps.insert(raw) {
            return Err(Error::DuplicateAttrtyp(name));
        }
        if !schema_guids.insert(schema_id_guid) {
            return Err(Error::DuplicateSchemaIdGuid(name));
        }
        insert_name(&mut attribute_names, name, AttrId(raw))?;
        max_name_len = max_name_len.max(name.len());
        attr_ids.push((entry, AttrId(raw), schema_id_guid));
    }
    // The secret rows are exactly the [MS-ADTS] 3.1.1.1.4 set.
    for entry in ATTRIBUTES.iter() {
        let listed = SECRET_ATTRIBUTES.contains(&entry.ldap_display_name);
        if listed != (entry.form == Form::Secret) {
            return Err(Error::SecretSetMismatch(entry.ldap_display_name));
        }
    }

    // ---- class identities ----
    let mut class_ids = Vec::with_capacity(CLASSES.len());
    let mut class_by_cn = BTreeMap::new();
    for entry in CLASSES.iter() {
        let name = entry.ldap_display_name;
        let raw = attrtyp(name, entry.governs_id)?;
        let schema_id_guid = guid(name, entry.schema_id_guid)?;
        // One ATTRTYP space for attributes and classes. Spec: [MS-ADTS]
        // 3.1.1.2.6 (an OID names the attributeSchema or classSchema object
        // with that attributeID or governsID).
        if !attrtyps.insert(raw) {
            return Err(Error::DuplicateAttrtyp(name));
        }
        if !schema_guids.insert(schema_id_guid) {
            return Err(Error::DuplicateSchemaIdGuid(name));
        }
        insert_name(&mut class_names, name, ClassId(raw))?;
        insert_name(&mut class_by_cn, entry.cn, ClassId(raw))?;
        max_name_len = max_name_len.max(name.len());
        class_ids.push((entry, ClassId(raw), schema_id_guid));
    }

    // ---- dirstore definitions ----
    // RDN attributes: every rDNAttID some class names. Spec: Q-090.
    let mut rdn_attributes = BTreeSet::new();
    for (entry, _, _) in &class_ids {
        rdn_attributes.extend(resolve(
            &attribute_names,
            entry.ldap_display_name,
            &[entry.rdn_att_id],
        )?);
    }
    let mut definitions = Vec::with_capacity(attr_ids.len());
    for (entry, id, _) in &attr_ids {
        let class = attr_class_of(entry);
        let rdn = rdn_attributes.contains(id);
        definitions.push(attribute_definition(entry, *id, class, rdn)?);
    }
    let mut class_definitions = Vec::with_capacity(class_ids.len());
    let mut superclasses = BTreeMap::new();
    for (entry, id, _) in &class_ids {
        let name = entry.ldap_display_name;
        // Only top ends a chain (its subClassOf is itself); any other class
        // naming itself is a cycle that Schema::new refuses. Spec: [MS-ADTS]
        // 3.1.1.4.2 ("Let SUPCLASSES (top) be the empty set").
        let superclass = if name == TOP && entry.sub_class_of == TOP {
            None
        } else {
            resolve(&class_names, name, &[entry.sub_class_of])?
                .first()
                .copied()
        };
        superclasses.insert(*id, superclass);
        let rdn_attr = resolve(&attribute_names, name, &[entry.rdn_att_id])?
            .first()
            .copied()
            .ok_or(Error::UnknownName {
                entry: name,
                name: entry.rdn_att_id,
            })?;
        class_definitions.push(ClassDefinition {
            id: *id,
            superclass,
            instantiable: entry.object_class_category == STRUCTURAL_CLASS,
            rdn_attr,
            poss_superiors: resolve(&class_names, name, entry.poss_superiors)?,
            nc_root: entry.nc_root,
            must: resolve(&attribute_names, name, entry.must)?,
            may: resolve(&attribute_names, name, entry.may)?,
        });
    }
    let schema = Schema::new(definitions, class_definitions).map_err(Error::Schema)?;

    // ---- attribute metadata: property sets (A-28) ----
    let mut attributes = BTreeMap::new();
    for (entry, id, schema_id_guid) in attr_ids {
        let property_set = match entry.attribute_security_guid {
            None => None,
            Some(s) => {
                let g = guid(entry.ldap_display_name, s)?;
                Some(PropertySet {
                    guid: g,
                    // Computed from the whole table, never per row (A-28).
                    is_attribute_guid: ATTRIBUTES
                        .iter()
                        .any(|other| parse_guid(other.schema_id_guid) == Some(g)),
                })
            }
        };
        attributes.insert(
            id,
            AttributeInfo {
                entry,
                id,
                schema_id_guid,
                property_set,
                attr_class: attr_class_of(entry),
            },
        );
    }

    // ---- class metadata: chains and CLASSATTS ----
    let mut own_attributes = BTreeMap::new();
    for (entry, id, _) in &class_ids {
        let names = resolve(
            &attribute_names,
            entry.ldap_display_name,
            entry.spec_attributes,
        )?;
        own_attributes.insert(*id, names);
    }
    let mut classes = BTreeMap::new();
    for (entry, id, schema_id_guid) in class_ids {
        let name = entry.ldap_display_name;
        // SUPCLASSES(c) ∪ {c}, walked up to top, then reversed (top first).
        // Bounded by the class count (the chain was checked acyclic by
        // Schema::new). Spec: [MS-ADTS] 3.1.1.4.2, 3.1.1.2.4.3.
        let mut object_class = vec![id];
        let mut next = superclasses.get(&id).copied().flatten();
        while let Some(s) = next {
            if object_class.len() > CLASSES.len() || object_class.contains(&s) {
                // Unreachable after Schema::new; kept fail-closed.
                return Err(Error::Schema(dirstore::Error::InvalidSchema(
                    dirstore::SchemaDefect::InvalidClassChain(id),
                )));
            }
            object_class.push(s);
            next = superclasses.get(&s).copied().flatten();
        }
        object_class.reverse();
        // CLASSATTS(c) = own (with static auxiliaries) over the chain.
        // Spec: [MS-ADTS] 3.1.1.4.2.
        let class_attributes: BTreeSet<AttrId> = object_class
            .iter()
            .filter_map(|c| own_attributes.get(c))
            .flatten()
            .copied()
            .collect();
        let default_object_category =
            resolve(&class_by_cn, name, &[entry.default_object_category])?
                .first()
                .copied()
                .ok_or(Error::UnknownName {
                    entry: name,
                    name: entry.default_object_category,
                })?;
        classes.insert(
            id,
            ClassInfo {
                entry,
                id,
                schema_id_guid,
                superclass: superclasses.get(&id).copied().flatten(),
                instantiable: entry.object_class_category == STRUCTURAL_CLASS,
                default_object_category,
                object_class,
                class_attributes: class_attributes.into_iter().collect(),
            },
        );
    }

    Ok(Phase1Schema {
        schema,
        attributes,
        classes,
        attribute_names,
        class_names,
        max_name_len,
    })
}

impl Phase1Schema {
    /// The validated dirstore schema (pass a clone to `dirstore::Store::open`).
    #[must_use]
    pub fn schema(&self) -> &Schema {
        &self.schema
    }

    /// Every phase-1 attribute, ascending by AttrId.
    pub fn attributes(&self) -> impl Iterator<Item = &AttributeInfo> {
        self.attributes.values()
    }

    /// Every phase-1 class, ascending by ClassId.
    pub fn classes(&self) -> impl Iterator<Item = &ClassInfo> {
        self.classes.values()
    }

    /// The attribute with this id.
    #[must_use]
    pub fn attribute(&self, id: AttrId) -> Option<&AttributeInfo> {
        self.attributes.get(&id)
    }

    /// The class with this id.
    #[must_use]
    pub fn class(&self, id: ClassId) -> Option<&ClassInfo> {
        self.classes.get(&id)
    }

    /// The schemaIDGUID of an attribute — the PDP's attribute identifier
    /// (docs/46 §7). Spec: [MS-ADTS] 3.1.1.2.3, 5.1.3.3.3.
    pub fn attribute_schema_id_guid(&self, id: AttrId) -> Result<Guid, LookupError> {
        self.attribute(id)
            .map(|a| a.schema_id_guid)
            .ok_or(LookupError::UnknownAttribute(id))
    }

    /// The schemaIDGUID of a class — the PDP's object class identifier and
    /// the ObjectType of a create-child / delete-child ACE (docs/46 §7).
    /// Spec: [MS-ADTS] 3.1.1.2.4.8, 5.1.3.3.3.
    pub fn class_schema_id_guid(&self, id: ClassId) -> Result<Guid, LookupError> {
        self.class(id)
            .map(|c| c.schema_id_guid)
            .ok_or(LookupError::UnknownClass(id))
    }

    /// The property set of an attribute (`None` if it has no
    /// attributeSecurityGUID), with A-28's `is_attribute_guid`. An unknown
    /// id is an error (the PDP denies). Spec: [MS-ADTS] 3.1.1.2.3.3; A-28;
    /// docs/46 §7 (`Pip::property_set`).
    pub fn property_set(&self, id: AttrId) -> Result<Option<PropertySet>, LookupError> {
        self.attribute(id)
            .map(|a| a.property_set)
            .ok_or(LookupError::UnknownAttribute(id))
    }

    /// The protection class of an attribute. Spec: docs/46 §6, §7
    /// (`Pip::attr_class`).
    pub fn attr_class(&self, id: AttrId) -> Result<AttrClass, LookupError> {
        self.attribute(id)
            .map(|a| a.attr_class)
            .ok_or(LookupError::UnknownAttribute(id))
    }

    /// CLASSATTS of a class, cut to the phase-1 attributes, ascending.
    /// Spec: [MS-ADTS] 3.1.1.4.2, 5.1.3.3.3; docs/46 §7.
    pub fn class_attributes(&self, id: ClassId) -> Result<&[AttrId], LookupError> {
        self.class(id)
            .map(|c| c.class_attributes.as_slice())
            .ok_or(LookupError::UnknownClass(id))
    }

    /// The class chain of an object whose classes are `classes` (any order):
    /// they must be exactly `SUPCLASSES(c) ∪ {c}` of one class `c`, with no
    /// repeats; anything else is [`LookupError::InvalidClassChain`].
    /// Spec: [MS-ADTS] 3.1.1.4.2, 3.1.1.2.4.3; A-28 (Q-081) item 1; docs/46
    /// §7 (`Pip::object_classes`).
    pub fn class_chain(&self, classes: &[ClassId]) -> Result<ClassChain, LookupError> {
        let mut sorted = classes.to_vec();
        sorted.sort_unstable();
        let before = sorted.len();
        sorted.dedup();
        if sorted.len() != before {
            return Err(LookupError::InvalidClassChain);
        }
        let most_specific = self
            .schema
            .most_specific_class(&sorted)
            .ok_or(LookupError::InvalidClassChain)?;
        let info = self
            .class(most_specific)
            .ok_or(LookupError::UnknownClass(most_specific))?;
        let chain_class = |id: ClassId| -> Result<ChainClass, LookupError> {
            Ok(ChainClass {
                id,
                schema_id_guid: self.class_schema_id_guid(id)?,
            })
        };
        let superclasses = info
            .object_class
            .iter()
            .filter(|c| **c != most_specific)
            .map(|c| chain_class(*c))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ClassChain {
            most_specific: chain_class(most_specific)?,
            superclasses,
        })
    }

    /// The attribute with this lDAPDisplayName (ASCII, case-insensitive);
    /// `None` if unknown or not ASCII. Spec: Q-080 (ASCII, A–Z fold);
    /// [MS-ADTS] 3.1.1.2.3.
    #[must_use]
    pub fn attribute_by_name(&self, name: &str) -> Option<AttrId> {
        if name.len() > self.max_name_len {
            return None;
        }
        self.attribute_names.get(&name_key(name)?).copied()
    }

    /// The class with this lDAPDisplayName (ASCII, case-insensitive);
    /// `None` if unknown or not ASCII. Spec: Q-080; [MS-ADTS] 3.1.1.2.4.8.
    #[must_use]
    pub fn class_by_name(&self, name: &str) -> Option<ClassId> {
        if name.len() > self.max_name_len {
            return None;
        }
        self.class_names.get(&name_key(name)?).copied()
    }
}
