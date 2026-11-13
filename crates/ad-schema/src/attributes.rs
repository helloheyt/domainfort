//! The 35 phase-1 attribute definitions: 17 stored, 7 derived, 11 secret.
//!
//! Each row carries the attributeSchema values of its [MS-ADA1-3] entry
//! (named in `source`) and the dirstore mapping decided in docs/46 §5.4
//! (`form`). Identifiers are **not** in the table: the ATTRTYP is computed
//! from `attribute_id` with [`crate::make_attid`] (R46-3), and the dirstore
//! value syntax from the AD syntax with [`dirstore_syntax`] (docs/46 §1).
//! The AttrClass, the link role and the RDN label length are computed too
//! (see `crate::schema`), never set per row.
//!
//! Spec: docs/46 §5.1-§5.4, §6, §8.2 (decided, A-29: R46-4, R46-6, R46-7,
//! R46-8); [MS-ADA1] v20180912, [MS-ADA2] v20240423, [MS-ADA3] v20180912
//! (the entry in each row's `source`); [MS-ADTS] v20261026 2.2.9, 2.2.10,
//! 3.1.1.2.2.2, 3.1.1.2.3.

use crate::flags::search_flags::{F_ANR, F_ATTINDEX, F_COPY, F_PRESERVEONDELETE};
use crate::flags::system_flags::{
    FLAG_ATTR_IS_OPERATIONAL, FLAG_ATTR_NOT_REPLICATED, FLAG_ATTR_REQ_PARTIAL_SET_MEMBER,
    FLAG_SCHEMA_BASE_OBJECT,
};
use crate::flags::{group_type, user_account_control};
use dirstore::Multiplicity::{self, MultiValued, SingleValued};
use dirstore::{ValueRange, ValueSyntax, MAX_VALUE_LEN};

/// A value constraint, in a form that fits a static table; converted to
/// [`dirstore::ValueConstraint`] when the schema is built.
/// Spec: docs/46 §8.2 (R46-6); Q-091 item 10.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Constraint {
    /// Integer32: allowed bits.
    AllowedBits(u32),
    /// Integer32: allowed values.
    AllowedValues(&'static [i32]),
    /// Utf8String: printable ASCII only.
    AsciiPrintable,
}

/// The dirstore rules of a stored attribute. Spec: docs/46 §5.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stored {
    /// Single- or multi-valued in dirstore (differs from isSingleValued only
    /// for `ou` and `description`, R46-8).
    pub multiplicity: Multiplicity,
    /// Largest value in bytes (3 × rangeUpper for strings, docs/46 §5.4).
    pub max_value_len: usize,
    /// dirstore range (value, or UTF-16 length for strings).
    pub range: Option<ValueRange>,
    /// dirstore value constraint.
    pub constraint: Option<Constraint>,
    /// Unique among live objects (docs/46 §8.5).
    pub unique: bool,
}

/// How an attribute is represented in dirstore. Spec: docs/46 §5.4 (R46-4),
/// §6.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Form {
    /// Stored in the object record.
    Stored(Stored),
    /// Never stored; computed on read by the layer above; every write is
    /// refused. `max_value_len` only satisfies the dirstore definition (a
    /// Derived attribute's values are never checked, Q-091 item 1).
    Derived {
        /// Bound of the computed value, in bytes.
        max_value_len: usize,
    },
    /// One of the [MS-ADTS] 3.1.1.1.4 secret attributes: AttrClass::Secret,
    /// never stored, every write refused (D44).
    Secret,
}

/// One phase-1 attribute: its attributeSchema values and its dirstore form.
/// Spec: [MS-ADTS] 3.1.1.2.3 (the attributeSchema attributes); docs/46 §5.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttributeEntry {
    /// lDAPDisplayName.
    pub ldap_display_name: &'static str,
    /// attributeID (OID).
    pub attribute_id: &'static str,
    /// schemaIDGUID, as printed.
    pub schema_id_guid: &'static str,
    /// attributeSecurityGUID (property set), as printed; `None` if absent.
    pub attribute_security_guid: Option<&'static str>,
    /// attributeSyntax.
    pub attribute_syntax: &'static str,
    /// oMSyntax.
    pub om_syntax: u32,
    /// oMObjectClass (dotted form), if the syntax uses one.
    pub om_object_class: Option<&'static str>,
    /// isSingleValued, as printed (not the dirstore multiplicity).
    pub is_single_valued: bool,
    /// rangeLower, as printed (not the dirstore range).
    pub range_lower: Option<i64>,
    /// rangeUpper, as printed (not the dirstore range).
    pub range_upper: Option<i64>,
    /// searchFlags ([MS-ADTS] 2.2.9).
    pub search_flags: u32,
    /// systemFlags ([MS-ADTS] 2.2.10).
    pub system_flags: u32,
    /// systemOnly.
    pub system_only: bool,
    /// linkID, if a link attribute.
    pub link_id: Option<u32>,
    /// The entry the values were read from.
    pub source: &'static str,
    /// The dirstore representation (docs/46 §5.4).
    pub form: Form,
}

/// The dirstore value syntax of an AD syntax — the docs/46 §1 table. `None`
/// for a syntax with no phase-1 path: String(Object-Identifier) has no
/// variant in phase 1 (only the derived objectClass uses it), and every
/// syntax docs/46 §1 does not map (D104).
/// Spec: docs/46 §1; [MS-ADTS] 3.1.1.2.2.2 (attributeSyntax / oMSyntax /
/// oMObjectClass identify the syntax).
#[must_use]
pub fn dirstore_syntax(entry: &AttributeEntry) -> Option<ValueSyntax> {
    match (
        entry.attribute_syntax,
        entry.om_syntax,
        entry.om_object_class,
    ) {
        // Integer → Integer32. Spec: docs/46 §1.
        ("2.5.5.9", 2, None) => Some(ValueSyntax::Integer32),
        // LargeInteger → Integer. Spec: docs/46 §1.
        ("2.5.5.16", 65, None) => Some(ValueSyntax::Integer),
        // String(Unicode) → Utf8String. Spec: docs/46 §1.
        ("2.5.5.12", 64, None) => Some(ValueSyntax::Utf8String),
        // String(Octet) → OctetString. Spec: docs/46 §1.
        ("2.5.5.10", 4, None) => Some(ValueSyntax::OctetString),
        // String(Sid) → Sid. Spec: docs/46 §1.
        ("2.5.5.17", 4, None) => Some(ValueSyntax::Sid),
        // String(NT-Sec-Desc) → SecurityDescriptor. Spec: docs/46 §1.
        ("2.5.5.15", 66, None) => Some(ValueSyntax::SecurityDescriptor),
        // String(Generalized-Time) → DsTime. Spec: docs/46 §1.
        ("2.5.5.11", 24, None) => Some(ValueSyntax::DsTime),
        // Object(DS-DN) → ObjectRef. Spec: docs/46 §1, §2.3.
        ("2.5.5.1", 127, Some(OBJECT_DS_DN)) => Some(ValueSyntax::ObjectRef),
        _ => None,
    }
}

/// oMObjectClass of Object(DS-DN), dotted form. Spec: [MS-ADTS]
/// 3.1.1.2.2.2 ("Object(DS-DN) 2.5.5.1 127 ... (1.3.12.2.1011.28.0.714)").
const OBJECT_DS_DN: &str = "1.3.12.2.1011.28.0.714";

/// BS | PS — the systemFlags most phase-1 attributes carry.
/// Spec: [MS-ADTS] 2.2.10.
const BASE_PAS: u32 = FLAG_SCHEMA_BASE_OBJECT | FLAG_ATTR_REQ_PARTIAL_SET_MEMBER;

/// A stored attribute with no range, constraint or uniqueness.
const fn stored(multiplicity: Multiplicity, max_value_len: usize) -> Form {
    Form::Stored(Stored {
        multiplicity,
        max_value_len,
        range: None,
        constraint: None,
        unique: false,
    })
}

/// `lower..=upper`.
const fn range(lower: i64, upper: i64) -> Option<ValueRange> {
    Some(ValueRange { lower, upper })
}

/// A secret attribute's row: only these values differ between the eleven.
/// Spec: [MS-ADA1] / [MS-ADA3] (each entry: searchFlags 0, systemFlags
/// FLAG_SCHEMA_BASE_OBJECT, systemOnly FALSE); docs/46 §5.4, §6.
#[allow(clippy::too_many_arguments)]
const fn secret(
    ldap_display_name: &'static str,
    attribute_id: &'static str,
    schema_id_guid: &'static str,
    attribute_syntax: &'static str,
    om_syntax: u32,
    is_single_valued: bool,
    range_upper: Option<i64>,
    source: &'static str,
) -> AttributeEntry {
    AttributeEntry {
        ldap_display_name,
        attribute_id,
        schema_id_guid,
        attribute_security_guid: None,
        attribute_syntax,
        om_syntax,
        om_object_class: None,
        is_single_valued,
        range_lower: if range_upper.is_some() { Some(0) } else { None },
        range_upper,
        search_flags: 0,
        system_flags: FLAG_SCHEMA_BASE_OBJECT,
        system_only: false,
        link_id: None,
        source,
        form: Form::Secret,
    }
}

/// Public Information. Spec: [MS-ADTS] 3.1.1.2.3.3 (table); the value as
/// printed in each [MS-ADA*] entry that names it.
const PS_PUBLIC_INFORMATION: Option<&str> = Some("e48d0154-bcf8-11d1-8702-00c04fb96050");
/// General Information. Spec: [MS-ADTS] 3.1.1.2.3.3; [MS-ADA3] 2.222, 2.45.
const PS_GENERAL_INFORMATION: Option<&str> = Some("59ba2f42-79a2-11d0-9020-00c04fc2d3cf");
/// Account Restrictions. Spec: [MS-ADTS] 3.1.1.2.3.3; [MS-ADA3] 2.342,
/// 2.175; [MS-ADA1] 2.1.
const PS_ACCOUNT_RESTRICTIONS: Option<&str> = Some("4c164200-20c0-11d0-a768-00aa006e0529");
/// Group Membership. Spec: [MS-ADTS] 3.1.1.2.3.3; [MS-ADA2] 2.43, 2.45.
const PS_GROUP_MEMBERSHIP: Option<&str> = Some("bc0ac240-79a9-11d0-9020-00c04fc2d4cf");

/// The 35 phase-1 attributes, in docs/46 §5.2 order.
pub static ATTRIBUTES: [AttributeEntry; 35] = [
    // ---- must, transitively (docs/46 §5.1) ----
    // Spec: [MS-ADA3] 2.40 objectClass; docs/46 §5.4 (derived from
    // Object.classes; String(Object-Identifier) has no phase-1 variant —
    // 4 bytes = an ATTRTYP, [MS-DRSR] 5.16.3.8 valLen 4).
    AttributeEntry {
        ldap_display_name: "objectClass",
        attribute_id: "2.5.4.0",
        schema_id_guid: "bf9679e5-0de6-11d0-a285-00aa003049e2",
        attribute_security_guid: PS_PUBLIC_INFORMATION,
        attribute_syntax: "2.5.5.2",
        om_syntax: 6,
        om_object_class: None,
        is_single_valued: false,
        range_lower: None,
        range_upper: None,
        search_flags: F_ATTINDEX | F_PRESERVEONDELETE,
        system_flags: BASE_PAS,
        system_only: true,
        link_id: None,
        source: "[MS-ADA3] 2.40",
        form: Form::Derived { max_value_len: 4 },
    },
    // Spec: [MS-ADA3] 2.39 objectCategory; docs/46 §5.4 (derived =
    // defaultObjectCategory, R46-5).
    AttributeEntry {
        ldap_display_name: "objectCategory",
        attribute_id: "1.2.840.113556.1.4.782",
        schema_id_guid: "26d97369-6070-11d1-a9c6-0000f80367c1",
        attribute_security_guid: PS_PUBLIC_INFORMATION,
        attribute_syntax: "2.5.5.1",
        om_syntax: 127,
        om_object_class: Some(OBJECT_DS_DN),
        is_single_valued: true,
        range_lower: None,
        range_upper: None,
        search_flags: F_ATTINDEX,
        system_flags: BASE_PAS,
        system_only: false,
        link_id: None,
        source: "[MS-ADA3] 2.39",
        form: Form::Derived {
            max_value_len: dtyp::GUID_PACKET_LEN,
        },
    },
    // Spec: [MS-ADA3] 2.37 nTSecurityDescriptor; docs/46 §5.4, §8.6 (R46-7:
    // capped at MAX_VALUE_LEN = 65536, stricter than rangeUpper 132096).
    AttributeEntry {
        ldap_display_name: "nTSecurityDescriptor",
        attribute_id: "1.2.840.113556.1.2.281",
        schema_id_guid: "bf9679e3-0de6-11d0-a285-00aa003049e2",
        attribute_security_guid: None,
        attribute_syntax: "2.5.5.15",
        om_syntax: 66,
        om_object_class: None,
        is_single_valued: true,
        range_lower: Some(0),
        range_upper: Some(132_096),
        search_flags: F_PRESERVEONDELETE,
        system_flags: FLAG_SCHEMA_BASE_OBJECT
            | FLAG_ATTR_IS_OPERATIONAL
            | FLAG_ATTR_REQ_PARTIAL_SET_MEMBER,
        system_only: false,
        link_id: None,
        source: "[MS-ADA3] 2.37",
        form: stored(SingleValued, MAX_VALUE_LEN),
    },
    // Spec: [MS-ADA1] 2.309 instanceType; docs/46 §5.4 (derived: 0x4, | 0x1
    // for an NC root).
    AttributeEntry {
        ldap_display_name: "instanceType",
        attribute_id: "1.2.840.113556.1.2.1",
        schema_id_guid: "bf96798c-0de6-11d0-a285-00aa003049e2",
        attribute_security_guid: None,
        attribute_syntax: "2.5.5.9",
        om_syntax: 2,
        om_object_class: None,
        is_single_valued: true,
        range_lower: None,
        range_upper: None,
        search_flags: F_PRESERVEONDELETE,
        system_flags: BASE_PAS,
        system_only: true,
        link_id: None,
        source: "[MS-ADA1] 2.309",
        form: Form::Derived { max_value_len: 4 },
    },
    // Spec: [MS-ADA1] 2.110 cn; docs/46 §5.4 (192 = 3 × 64, 1..64 chars);
    // Q-080 item 1 (naming attribute: printable ASCII).
    AttributeEntry {
        ldap_display_name: "cn",
        attribute_id: "2.5.4.3",
        schema_id_guid: "bf96793f-0de6-11d0-a285-00aa003049e2",
        attribute_security_guid: PS_PUBLIC_INFORMATION,
        attribute_syntax: "2.5.5.12",
        om_syntax: 64,
        om_object_class: None,
        is_single_valued: true,
        range_lower: Some(1),
        range_upper: Some(64),
        search_flags: F_ATTINDEX,
        system_flags: BASE_PAS,
        system_only: false,
        link_id: None,
        source: "[MS-ADA1] 2.110",
        form: Form::Stored(Stored {
            multiplicity: SingleValued,
            max_value_len: 192,
            range: range(1, 64),
            constraint: Some(Constraint::AsciiPrintable),
            unique: false,
        }),
    },
    // Spec: [MS-ADA1] 2.142 dc; docs/46 §5.4 (765 = 3 × 255, 1..255 chars);
    // Q-080 item 1.
    AttributeEntry {
        ldap_display_name: "dc",
        attribute_id: "0.9.2342.19200300.100.1.25",
        schema_id_guid: "19195a55-6da0-11d0-afd3-00c04fd930c9",
        attribute_security_guid: None,
        attribute_syntax: "2.5.5.12",
        om_syntax: 64,
        om_object_class: None,
        is_single_valued: true,
        range_lower: Some(1),
        range_upper: Some(255),
        search_flags: 0,
        system_flags: BASE_PAS,
        system_only: false,
        link_id: None,
        source: "[MS-ADA1] 2.142",
        form: Form::Stored(Stored {
            multiplicity: SingleValued,
            max_value_len: 765,
            range: range(1, 255),
            constraint: Some(Constraint::AsciiPrintable),
            unique: false,
        }),
    },
    // Spec: [MS-ADA3] 2.73 ou; docs/46 §5.4 (R46-8: single-valued in phase
    // 1, although multi-valued in the spec); Q-080 item 1.
    AttributeEntry {
        ldap_display_name: "ou",
        attribute_id: "2.5.4.11",
        schema_id_guid: "bf9679f0-0de6-11d0-a285-00aa003049e2",
        attribute_security_guid: PS_PUBLIC_INFORMATION,
        attribute_syntax: "2.5.5.12",
        om_syntax: 64,
        om_object_class: None,
        is_single_valued: false,
        range_lower: Some(1),
        range_upper: Some(64),
        search_flags: F_ATTINDEX,
        system_flags: BASE_PAS,
        system_only: false,
        link_id: None,
        source: "[MS-ADA3] 2.73",
        form: Form::Stored(Stored {
            multiplicity: SingleValued,
            max_value_len: 192,
            range: range(1, 64),
            constraint: Some(Constraint::AsciiPrintable),
            unique: false,
        }),
    },
    // Spec: [MS-ADA3] 2.222 sAMAccountName; docs/46 §5.4 (R46-8: rangeLower
    // 1, the spec has 0), §8.5 (unique); Q-080 item 1 (ASCII).
    AttributeEntry {
        ldap_display_name: "sAMAccountName",
        attribute_id: "1.2.840.113556.1.4.221",
        schema_id_guid: "3e0abfd0-126a-11d0-a060-00aa006c33ed",
        attribute_security_guid: PS_GENERAL_INFORMATION,
        attribute_syntax: "2.5.5.12",
        om_syntax: 64,
        om_object_class: None,
        is_single_valued: true,
        range_lower: Some(0),
        range_upper: Some(256),
        search_flags: F_PRESERVEONDELETE | F_ANR | F_ATTINDEX,
        system_flags: BASE_PAS,
        system_only: false,
        link_id: None,
        source: "[MS-ADA3] 2.222",
        form: Form::Stored(Stored {
            multiplicity: SingleValued,
            max_value_len: 768,
            range: range(1, 256),
            constraint: Some(Constraint::AsciiPrintable),
            unique: true,
        }),
    },
    // Spec: [MS-ADA3] 2.45 objectSid; docs/46 §5.4 (28 bytes = rangeUpper),
    // §8.5 (unique).
    AttributeEntry {
        ldap_display_name: "objectSid",
        attribute_id: "1.2.840.113556.1.4.146",
        schema_id_guid: "bf9679e8-0de6-11d0-a285-00aa003049e2",
        attribute_security_guid: PS_GENERAL_INFORMATION,
        attribute_syntax: "2.5.5.17",
        om_syntax: 4,
        om_object_class: None,
        is_single_valued: true,
        range_lower: Some(0),
        range_upper: Some(28),
        search_flags: F_PRESERVEONDELETE | F_ATTINDEX,
        system_flags: BASE_PAS,
        system_only: true,
        link_id: None,
        source: "[MS-ADA3] 2.45",
        form: Form::Stored(Stored {
            multiplicity: SingleValued,
            max_value_len: 28,
            range: None,
            constraint: None,
            unique: true,
        }),
    },
    // Spec: [MS-ADA1] 2.288 groupType; docs/46 §5.4, §8.2 (the six values,
    // [MS-ADTS] 2.2.12).
    AttributeEntry {
        ldap_display_name: "groupType",
        attribute_id: "1.2.840.113556.1.4.750",
        schema_id_guid: "9a9a021e-4a5b-11d1-a9c3-0000f80367c1",
        attribute_security_guid: None,
        attribute_syntax: "2.5.5.9",
        om_syntax: 2,
        om_object_class: None,
        is_single_valued: true,
        range_lower: None,
        range_upper: None,
        search_flags: F_PRESERVEONDELETE | F_ATTINDEX,
        system_flags: BASE_PAS,
        system_only: false,
        link_id: None,
        source: "[MS-ADA1] 2.288",
        form: Form::Stored(Stored {
            multiplicity: SingleValued,
            max_value_len: 4,
            range: None,
            constraint: Some(Constraint::AllowedValues(&group_type::ALLOWED_VALUES)),
            unique: false,
        }),
    },
    // ---- identity and name, derived (docs/46 §5.1, §5.4) ----
    // Spec: [MS-ADA3] 2.44 objectGUID; docs/46 §5.4 (derived = record key).
    AttributeEntry {
        ldap_display_name: "objectGUID",
        attribute_id: "1.2.840.113556.1.4.2",
        schema_id_guid: "bf9679e7-0de6-11d0-a285-00aa003049e2",
        attribute_security_guid: PS_PUBLIC_INFORMATION,
        attribute_syntax: "2.5.5.10",
        om_syntax: 4,
        om_object_class: None,
        is_single_valued: true,
        range_lower: Some(16),
        range_upper: Some(16),
        search_flags: F_PRESERVEONDELETE | F_ATTINDEX,
        system_flags: BASE_PAS | FLAG_ATTR_NOT_REPLICATED,
        system_only: true,
        link_id: None,
        source: "[MS-ADA3] 2.44",
        form: Form::Derived {
            max_value_len: dtyp::GUID_PACKET_LEN,
        },
    },
    // Spec: [MS-ADA3] 2.1 name; docs/46 §5.4 (derived = the RDN value;
    // 765 = 3 × 255).
    AttributeEntry {
        ldap_display_name: "name",
        attribute_id: "1.2.840.113556.1.4.1",
        schema_id_guid: "bf967a0e-0de6-11d0-a285-00aa003049e2",
        attribute_security_guid: PS_PUBLIC_INFORMATION,
        attribute_syntax: "2.5.5.12",
        om_syntax: 64,
        om_object_class: None,
        is_single_valued: true,
        range_lower: Some(1),
        range_upper: Some(255),
        search_flags: F_PRESERVEONDELETE | F_ANR | F_ATTINDEX,
        system_flags: BASE_PAS,
        system_only: true,
        link_id: None,
        source: "[MS-ADA3] 2.1",
        form: Form::Derived { max_value_len: 765 },
    },
    // Spec: [MS-ADA1] 2.177 distinguishedName; docs/46 §5.4 (derived from
    // the parent chain).
    AttributeEntry {
        ldap_display_name: "distinguishedName",
        attribute_id: "2.5.4.49",
        schema_id_guid: "bf9679e4-0de6-11d0-a285-00aa003049e2",
        attribute_security_guid: PS_PUBLIC_INFORMATION,
        attribute_syntax: "2.5.5.1",
        om_syntax: 127,
        om_object_class: Some(OBJECT_DS_DN),
        is_single_valued: true,
        range_lower: None,
        range_upper: None,
        search_flags: F_PRESERVEONDELETE,
        system_flags: BASE_PAS | FLAG_ATTR_NOT_REPLICATED,
        system_only: true,
        link_id: None,
        source: "[MS-ADA1] 2.177",
        form: Form::Derived {
            max_value_len: dtyp::GUID_PACKET_LEN,
        },
    },
    // ---- justified may (docs/46 §5.1) ----
    // Spec: [MS-ADA3] 2.349 userPrincipalName; docs/46 §5.4 (rangeLower 1 =
    // project choice, R46-8; 3072 = 3 × 1024), §8.5 (unique); Q-080 / P-6
    // (ASCII).
    AttributeEntry {
        ldap_display_name: "userPrincipalName",
        attribute_id: "1.2.840.113556.1.4.656",
        schema_id_guid: "28630ebb-41d5-11d1-a9c1-0000f80367c1",
        attribute_security_guid: PS_PUBLIC_INFORMATION,
        attribute_syntax: "2.5.5.12",
        om_syntax: 64,
        om_object_class: None,
        is_single_valued: true,
        range_lower: None,
        range_upper: Some(1024),
        search_flags: F_ATTINDEX,
        system_flags: BASE_PAS,
        system_only: false,
        link_id: None,
        source: "[MS-ADA3] 2.349",
        form: Form::Stored(Stored {
            multiplicity: SingleValued,
            max_value_len: 3072,
            range: range(1, 1024),
            constraint: Some(Constraint::AsciiPrintable),
            unique: true,
        }),
    },
    // Spec: [MS-ADA3] 2.253 servicePrincipalName; docs/46 §5.4 (1..1024 =
    // project choice, R46-8: the entry has no range), §8.5 (unique); Q-080
    // (ASCII).
    AttributeEntry {
        ldap_display_name: "servicePrincipalName",
        attribute_id: "1.2.840.113556.1.4.771",
        schema_id_guid: "f3a64788-5306-11d1-a9c5-0000f80367c1",
        attribute_security_guid: PS_PUBLIC_INFORMATION,
        attribute_syntax: "2.5.5.12",
        om_syntax: 64,
        om_object_class: None,
        is_single_valued: false,
        range_lower: None,
        range_upper: None,
        search_flags: F_ATTINDEX,
        system_flags: BASE_PAS,
        system_only: false,
        link_id: None,
        source: "[MS-ADA3] 2.253",
        form: Form::Stored(Stored {
            multiplicity: MultiValued,
            max_value_len: 3072,
            range: range(1, 1024),
            constraint: Some(Constraint::AsciiPrintable),
            unique: true,
        }),
    },
    // Spec: [MS-ADA1] 2.185 dNSHostName (attributeSecurityGuid = its own
    // schemaIdGuid — Q-081 / A-28); docs/46 §5.4 (6144 = 3 × 2048, 0..2048
    // chars); Q-080 item 1, Q-091 item 10 (printable ASCII).
    AttributeEntry {
        ldap_display_name: "dNSHostName",
        attribute_id: "1.2.840.113556.1.4.619",
        schema_id_guid: "72e39547-7b18-11d1-adef-00c04fd8d5cd",
        attribute_security_guid: Some("72e39547-7b18-11d1-adef-00c04fd8d5cd"),
        attribute_syntax: "2.5.5.12",
        om_syntax: 64,
        om_object_class: None,
        is_single_valued: true,
        range_lower: Some(0),
        range_upper: Some(2048),
        search_flags: 0,
        system_flags: FLAG_SCHEMA_BASE_OBJECT,
        system_only: false,
        link_id: None,
        source: "[MS-ADA1] 2.185",
        form: Form::Stored(Stored {
            multiplicity: SingleValued,
            max_value_len: 6144,
            range: range(0, 2048),
            constraint: Some(Constraint::AsciiPrintable),
            unique: false,
        }),
    },
    // Spec: [MS-ADA3] 2.342 userAccountControl; docs/46 §5.4, §8.2 (allowed
    // bits, R46-6 / A-29; [MS-ADTS] 2.2.16).
    AttributeEntry {
        ldap_display_name: "userAccountControl",
        attribute_id: "1.2.840.113556.1.4.8",
        schema_id_guid: "bf967a68-0de6-11d0-a285-00aa003049e2",
        attribute_security_guid: PS_ACCOUNT_RESTRICTIONS,
        attribute_syntax: "2.5.5.9",
        om_syntax: 2,
        om_object_class: None,
        is_single_valued: true,
        range_lower: None,
        range_upper: None,
        search_flags: F_COPY | F_PRESERVEONDELETE | F_ATTINDEX,
        system_flags: BASE_PAS,
        system_only: false,
        link_id: None,
        source: "[MS-ADA3] 2.342",
        form: Form::Stored(Stored {
            multiplicity: SingleValued,
            max_value_len: 4,
            range: None,
            constraint: Some(Constraint::AllowedBits(user_account_control::ALLOWED)),
            unique: false,
        }),
    },
    // Spec: [MS-ADA1] 2.1 accountExpires; docs/46 §5.4 (0..i64::MAX =
    // project choice: "100-nanosecond intervals since January 1, 1601").
    AttributeEntry {
        ldap_display_name: "accountExpires",
        attribute_id: "1.2.840.113556.1.4.159",
        schema_id_guid: "bf967915-0de6-11d0-a285-00aa003049e2",
        attribute_security_guid: PS_ACCOUNT_RESTRICTIONS,
        attribute_syntax: "2.5.5.16",
        om_syntax: 65,
        om_object_class: None,
        is_single_valued: true,
        range_lower: None,
        range_upper: None,
        search_flags: F_COPY,
        system_flags: FLAG_SCHEMA_BASE_OBJECT,
        system_only: false,
        link_id: None,
        source: "[MS-ADA1] 2.1",
        form: Form::Stored(Stored {
            multiplicity: SingleValued,
            max_value_len: 8,
            range: range(0, i64::MAX),
            constraint: None,
            unique: false,
        }),
    },
    // Spec: [MS-ADA3] 2.175 pwdLastSet; docs/46 §5.4 (0..i64::MAX, as
    // accountExpires).
    AttributeEntry {
        ldap_display_name: "pwdLastSet",
        attribute_id: "1.2.840.113556.1.4.96",
        schema_id_guid: "bf967a0a-0de6-11d0-a285-00aa003049e2",
        attribute_security_guid: PS_ACCOUNT_RESTRICTIONS,
        attribute_syntax: "2.5.5.16",
        om_syntax: 65,
        om_object_class: None,
        is_single_valued: true,
        range_lower: None,
        range_upper: None,
        search_flags: 0,
        system_flags: FLAG_SCHEMA_BASE_OBJECT,
        system_only: false,
        link_id: None,
        source: "[MS-ADA3] 2.175",
        form: Form::Stored(Stored {
            multiplicity: SingleValued,
            max_value_len: 8,
            range: range(0, i64::MAX),
            constraint: None,
            unique: false,
        }),
    },
    // Spec: [MS-ADA2] 2.43 member (linkID 2: forward link); docs/46 §2.3,
    // §5.4 (ObjectRef, 16 bytes).
    AttributeEntry {
        ldap_display_name: "member",
        attribute_id: "2.5.4.31",
        schema_id_guid: "bf9679c0-0de6-11d0-a285-00aa003049e2",
        attribute_security_guid: PS_GROUP_MEMBERSHIP,
        attribute_syntax: "2.5.5.1",
        om_syntax: 127,
        om_object_class: Some(OBJECT_DS_DN),
        is_single_valued: false,
        range_lower: None,
        range_upper: None,
        search_flags: 0,
        system_flags: BASE_PAS,
        system_only: false,
        link_id: Some(2),
        source: "[MS-ADA2] 2.43",
        form: stored(MultiValued, dtyp::GUID_PACKET_LEN),
    },
    // Spec: [MS-ADA2] 2.45 memberOf (linkID 3: back link of member);
    // docs/46 §2.3 item 3, §5.4 (derived from the reverse-link index).
    AttributeEntry {
        ldap_display_name: "memberOf",
        attribute_id: "1.2.840.113556.1.2.102",
        schema_id_guid: "bf967991-0de6-11d0-a285-00aa003049e2",
        attribute_security_guid: PS_GROUP_MEMBERSHIP,
        attribute_syntax: "2.5.5.1",
        om_syntax: 127,
        om_object_class: Some(OBJECT_DS_DN),
        is_single_valued: false,
        range_lower: None,
        range_upper: None,
        search_flags: F_COPY,
        system_flags: FLAG_SCHEMA_BASE_OBJECT | FLAG_ATTR_NOT_REPLICATED,
        system_only: true,
        link_id: Some(3),
        source: "[MS-ADA2] 2.45",
        form: Form::Derived {
            max_value_len: dtyp::GUID_PACKET_LEN,
        },
    },
    // Spec: [MS-ADA3] 2.371 whenCreated; docs/46 §5.4 (DsTime, set by the
    // system on create).
    AttributeEntry {
        ldap_display_name: "whenCreated",
        attribute_id: "1.2.840.113556.1.2.2",
        schema_id_guid: "bf967a78-0de6-11d0-a285-00aa003049e2",
        attribute_security_guid: None,
        attribute_syntax: "2.5.5.11",
        om_syntax: 24,
        om_object_class: None,
        is_single_valued: true,
        range_lower: None,
        range_upper: None,
        search_flags: 0,
        system_flags: BASE_PAS,
        system_only: true,
        link_id: None,
        source: "[MS-ADA3] 2.371",
        form: stored(SingleValued, 8),
    },
    // Spec: [MS-ADA3] 2.370 whenChanged; docs/46 §5.4 (DsTime, set by the
    // system on every originating write).
    AttributeEntry {
        ldap_display_name: "whenChanged",
        attribute_id: "1.2.840.113556.1.2.3",
        schema_id_guid: "bf967a77-0de6-11d0-a285-00aa003049e2",
        attribute_security_guid: None,
        attribute_syntax: "2.5.5.11",
        om_syntax: 24,
        om_object_class: None,
        is_single_valued: true,
        range_lower: None,
        range_upper: None,
        search_flags: 0,
        system_flags: BASE_PAS | FLAG_ATTR_NOT_REPLICATED,
        system_only: true,
        link_id: None,
        source: "[MS-ADA3] 2.370",
        form: stored(SingleValued, 8),
    },
    // Spec: [MS-ADA1] 2.153 description; docs/46 §5.4 (R46-8: single-valued
    // in phase 1; 3072 = 3 × 1024); Q-080 item 3 (free text: any UTF-8).
    AttributeEntry {
        ldap_display_name: "description",
        attribute_id: "2.5.4.13",
        schema_id_guid: "bf967950-0de6-11d0-a285-00aa003049e2",
        attribute_security_guid: PS_PUBLIC_INFORMATION,
        attribute_syntax: "2.5.5.12",
        om_syntax: 64,
        om_object_class: None,
        is_single_valued: false,
        range_lower: Some(0),
        range_upper: Some(1024),
        search_flags: 0,
        system_flags: FLAG_SCHEMA_BASE_OBJECT,
        system_only: false,
        link_id: None,
        source: "[MS-ADA1] 2.153",
        form: Form::Stored(Stored {
            multiplicity: SingleValued,
            max_value_len: 3072,
            range: range(0, 1024),
            constraint: None,
            unique: false,
        }),
    },
    // ---- the eleven [MS-ADTS] 3.1.1.1.4 secret attributes (docs/46 §6) ----
    // Spec: [MS-ADA1] 2.139 currentValue.
    secret(
        "currentValue",
        "1.2.840.113556.1.4.27",
        "bf967947-0de6-11d0-a285-00aa003049e2",
        "2.5.5.10",
        4,
        true,
        None,
        "[MS-ADA1] 2.139",
    ),
    // Spec: [MS-ADA1] 2.141 dBCSPwd.
    secret(
        "dBCSPwd",
        "1.2.840.113556.1.4.55",
        "bf96799c-0de6-11d0-a285-00aa003049e2",
        "2.5.5.10",
        4,
        true,
        None,
        "[MS-ADA1] 2.141",
    ),
    // Spec: [MS-ADA1] 2.305 initialAuthIncoming.
    secret(
        "initialAuthIncoming",
        "1.2.840.113556.1.4.539",
        "52458023-ca6a-11d0-afff-0000f80367c1",
        "2.5.5.12",
        64,
        true,
        None,
        "[MS-ADA1] 2.305",
    ),
    // Spec: [MS-ADA1] 2.306 initialAuthOutgoing.
    secret(
        "initialAuthOutgoing",
        "1.2.840.113556.1.4.540",
        "52458024-ca6a-11d0-afff-0000f80367c1",
        "2.5.5.12",
        64,
        true,
        None,
        "[MS-ADA1] 2.306",
    ),
    // Spec: [MS-ADA1] 2.363 lmPwdHistory.
    secret(
        "lmPwdHistory",
        "1.2.840.113556.1.4.160",
        "bf96799d-0de6-11d0-a285-00aa003049e2",
        "2.5.5.10",
        4,
        false,
        None,
        "[MS-ADA1] 2.363",
    ),
    // Spec: [MS-ADA3] 2.36 ntPwdHistory.
    secret(
        "ntPwdHistory",
        "1.2.840.113556.1.4.94",
        "bf9679e2-0de6-11d0-a285-00aa003049e2",
        "2.5.5.10",
        4,
        false,
        None,
        "[MS-ADA3] 2.36",
    ),
    // Spec: [MS-ADA3] 2.160 priorValue.
    secret(
        "priorValue",
        "1.2.840.113556.1.4.100",
        "bf967a02-0de6-11d0-a285-00aa003049e2",
        "2.5.5.10",
        4,
        true,
        None,
        "[MS-ADA3] 2.160",
    ),
    // Spec: [MS-ADA3] 2.287 supplementalCredentials.
    secret(
        "supplementalCredentials",
        "1.2.840.113556.1.4.125",
        "bf967a3f-0de6-11d0-a285-00aa003049e2",
        "2.5.5.10",
        4,
        false,
        None,
        "[MS-ADA3] 2.287",
    ),
    // Spec: [MS-ADA3] 2.321 trustAuthIncoming (rangeLower 0, rangeUpper
    // 32767).
    secret(
        "trustAuthIncoming",
        "1.2.840.113556.1.4.129",
        "bf967a59-0de6-11d0-a285-00aa003049e2",
        "2.5.5.10",
        4,
        true,
        Some(32_767),
        "[MS-ADA3] 2.321",
    ),
    // Spec: [MS-ADA3] 2.322 trustAuthOutgoing (rangeLower 0, rangeUpper
    // 32767).
    secret(
        "trustAuthOutgoing",
        "1.2.840.113556.1.4.135",
        "bf967a5f-0de6-11d0-a285-00aa003049e2",
        "2.5.5.10",
        4,
        true,
        Some(32_767),
        "[MS-ADA3] 2.322",
    ),
    // Spec: [MS-ADA3] 2.332 unicodePwd.
    secret(
        "unicodePwd",
        "1.2.840.113556.1.4.90",
        "bf9679e1-0de6-11d0-a285-00aa003049e2",
        "2.5.5.10",
        4,
        true,
        None,
        "[MS-ADA3] 2.332",
    ),
];

/// The secret attributes: "A secret attribute is any attribute from the
/// following set: currentValue, dBCSPwd, initialAuthIncoming,
/// initialAuthOutgoing, lmPwdHistory, ntPwdHistory, priorValue,
/// supplementalCredentials, trustAuthIncoming, trustAuthOutgoing, and
/// unicodePwd." The rows with [`Form::Secret`] must be exactly these (checked
/// when the schema is built). Spec: [MS-ADTS] v20261026 3.1.1.1.4; docs/46
/// §6.
pub const SECRET_ATTRIBUTES: [&str; 11] = [
    "currentValue",
    "dBCSPwd",
    "initialAuthIncoming",
    "initialAuthOutgoing",
    "lmPwdHistory",
    "ntPwdHistory",
    "priorValue",
    "supplementalCredentials",
    "trustAuthIncoming",
    "trustAuthOutgoing",
    "unicodePwd",
];
