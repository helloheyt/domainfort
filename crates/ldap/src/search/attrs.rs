//! Attribute descriptions: which phase-1 attribute a client's description
//! names, and how its values are obtained.
//!
//! # Recognising a description
//!
//! "attributedescription = attributetype options; attributetype = oid"
//! (RFC 4512 §2.5). The attribute type is recognised as an lDAPDisplayName,
//! ASCII case-insensitively (`ad-schema::attribute_by_name`; RFC 4512 §2.5:
//! "case insensitive"), or as the attribute's attributeID OID, compared
//! exactly ([MS-ADTS] 3.1.1.3.1.3.6: "The server supports specifying the
//! attributes to be returned by their numeric OIDs in searches that do not
//! use the rootDSE as the search base"). Any option (`;binary`, `;range=…`)
//! makes the description unrecognised: "Servers SHALL treat an attribute
//! description with an unrecognized attribute option as unrecognized" (RFC
//! 4512 §2.5; docs/49 §6.3 — range retrieval is avoided by construction).
//!
//! # Kinds (docs/46 §5.4, R46-4; docs/49 §6.4, §6.5)
//!
//! - **Never**: the eleven Secret attributes ([MS-ADTS] 3.1.1.1.4; "Access is
//!   never granted", 3.1.1.4.4) and nTSecurityDescriptor (R49-9: never
//!   returned and not in a filter until the PDP's 3.1.1.4.4 rule and
//!   SD_FLAGS exist — A-48, A-51). They "do not exist" for every requester,
//!   and the PDP is not even asked about them (docs/11 P6).
//! - **Stored**: values from the object record, in dirstore's canonical form
//!   of the attribute's syntax (docs/46 §1).
//! - **Derived**, computed at read time (docs/46 §5.4): objectClass,
//!   objectCategory, instanceType, objectGUID, name, distinguishedName, and
//!   the back link memberOf.
//!
//! Spec: RFC 4512 §2.5; [MS-ADTS] v20261026 3.1.1.1.4, 3.1.1.3.1.3.6,
//! 3.1.1.4.4, 3.1.1.4.5; docs/46 §1, §5.4, §6; docs/49 §6.3-§6.5.

use ad_schema::{dirstore_syntax, AttributeInfo, Form, Phase1Schema};
use dirstore::{AttrClass, AttrId, ValueSyntax};
use dtyp::Guid;

/// The attribute option separator. Spec: RFC 4512 §2.5 (`options = *( SEMI
/// option )`), §1.4 (SEMI).
const SEMI: char = ';';

/// The derived and specially treated attributes of phase 1, by AttrId.
/// Spec: docs/46 §5.4; docs/49 §6.4, §6.5.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Known {
    pub(crate) object_class: AttrId,
    pub(crate) object_category: AttrId,
    pub(crate) instance_type: AttrId,
    pub(crate) object_guid: AttrId,
    pub(crate) name: AttrId,
    pub(crate) distinguished_name: AttrId,
    pub(crate) member_of: AttrId,
    pub(crate) nt_security_descriptor: AttrId,
}

impl Known {
    /// Resolve the identifiers by lDAPDisplayName (docs/46 §5.2). `None` if
    /// the schema lacks one (fail closed).
    pub(crate) fn resolve(p1: &Phase1Schema) -> Option<Known> {
        Some(Known {
            object_class: p1.attribute_by_name("objectClass")?,
            object_category: p1.attribute_by_name("objectCategory")?,
            instance_type: p1.attribute_by_name("instanceType")?,
            object_guid: p1.attribute_by_name("objectGUID")?,
            name: p1.attribute_by_name("name")?,
            distinguished_name: p1.attribute_by_name("distinguishedName")?,
            member_of: p1.attribute_by_name("memberOf")?,
            nt_security_descriptor: p1.attribute_by_name("nTSecurityDescriptor")?,
        })
    }
}

/// How an attribute's values are obtained (module documentation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    /// Secret or nTSecurityDescriptor: never exists for any requester.
    Never,
    /// Stored, in dirstore's canonical form of this syntax.
    Stored(ValueSyntax),
    /// objectClass: the class chain, top first ([MS-ADTS] 3.1.1.2.4.3).
    ObjectClass,
    /// objectCategory: the defaultObjectCategory of the most specific class
    /// (docs/46 R46-5).
    ObjectCategory,
    /// instanceType: 4, or 5 for the NC root (docs/46 §5.4).
    InstanceType,
    /// objectGUID: the record key (16 octets).
    ObjectGuid,
    /// name: the RDN attribute's value ([MS-ADTS] 3.1.1.1.4).
    Name,
    /// distinguishedName: the object's DN ([MS-ADTS] 3.1.1.1.4).
    DistinguishedName,
    /// memberOf: the back link of member (docs/46 R46-2), constructed
    /// ([MS-ADTS] 3.1.1.4.5).
    MemberOf,
}

/// A recognised phase-1 attribute. Spec: docs/46 §5.2, §5.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Attr {
    /// The ATTRTYP (dirstore's identifier).
    pub(crate) id: AttrId,
    /// The lDAPDisplayName: the description of a returned attribute (RFC
    /// 4511 §4.5.2: "the server SHOULD use one of those names").
    pub(crate) name: &'static str,
    /// The schemaIDGUID: the PDP's attribute identifier (docs/46 §7).
    pub(crate) guid: Guid,
    /// How its values are obtained.
    pub(crate) kind: Kind,
}

/// The [`Attr`] of a phase-1 attribute. Spec: module documentation.
pub(crate) fn attr(info: &AttributeInfo, known: &Known) -> Attr {
    Attr {
        id: info.id,
        name: info.entry.ldap_display_name,
        guid: info.schema_id_guid,
        kind: kind(info, known),
    }
}

/// The kind of an attribute (module documentation). Anything this function
/// does not recognise is `Never` (fail closed).
fn kind(info: &AttributeInfo, known: &Known) -> Kind {
    if info.attr_class == AttrClass::Secret || info.id == known.nt_security_descriptor {
        return Kind::Never;
    }
    match info.entry.form {
        Form::Secret => Kind::Never,
        Form::Stored(_) => match dirstore_syntax(info.entry) {
            // A descriptor is never returned (R49-9).
            Some(ValueSyntax::SecurityDescriptor) | None => Kind::Never,
            Some(syntax) => Kind::Stored(syntax),
        },
        Form::Derived { .. } => {
            let id = info.id;
            if id == known.object_class {
                Kind::ObjectClass
            } else if id == known.object_category {
                Kind::ObjectCategory
            } else if id == known.instance_type {
                Kind::InstanceType
            } else if id == known.object_guid {
                Kind::ObjectGuid
            } else if id == known.name {
                Kind::Name
            } else if id == known.distinguished_name {
                Kind::DistinguishedName
            } else if id == known.member_of {
                Kind::MemberOf
            } else {
                Kind::Never
            }
        }
    }
}

/// The attribute a client's description names, or `None` if unrecognised
/// (module documentation).
/// Spec: RFC 4512 §2.5; [MS-ADTS] 3.1.1.3.1.3.6; docs/49 §6.3.
pub(crate) fn describe(p1: &Phase1Schema, known: &Known, description: &str) -> Option<Attr> {
    if description.contains(SEMI) {
        return None;
    }
    let id = if description.as_bytes().first()?.is_ascii_digit() {
        p1.attributes()
            .find(|a| a.entry.attribute_id == description)?
            .id
    } else {
        p1.attribute_by_name(description)?
    };
    p1.attribute(id).map(|info| attr(info, known))
}
