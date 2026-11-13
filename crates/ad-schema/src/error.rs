//! Error types. Hand-rolled (AGENTS.md §7). Every failure names the table
//! entry (a static lDAPDisplayName) and the rule; nothing else is carried.
//! Building the schema fails closed on any of them (docs/46 §3.3, R46-3).

use crate::attid::OidError;
use core::fmt;
use dirstore::{AttrId, ClassId};

/// Why [`crate::phase1`] refused to build the phase-1 schema.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// An attributeID / governsID could not be mapped to an ATTRTYP.
    /// Spec: [MS-DRSR] 5.16.4; docs/46 §3.3 (R46-3).
    Attrtyp {
        /// The entry's lDAPDisplayName.
        name: &'static str,
        /// Why.
        error: OidError,
    },
    /// A schemaIDGUID / attributeSecurityGUID string is malformed.
    MalformedGuid(&'static str),
    /// Two entries share an lDAPDisplayName (ASCII, case-insensitive), or a
    /// name is not ASCII. Spec: [MS-ADTS] 3.1.1.2.3 ("Unique" name); Q-080.
    DuplicateOrInvalidName(&'static str),
    /// Two entries share an ATTRTYP (attributes and classes share one
    /// space). Spec: [MS-ADTS] 3.1.1.2.6; docs/46 §3.3.
    DuplicateAttrtyp(&'static str),
    /// Two entries share a schemaIDGUID. Spec: [MS-ADTS] 3.1.1.2.3
    /// ("Unique" GUID).
    DuplicateSchemaIdGuid(&'static str),
    /// A class names an attribute or class that is not in the tables.
    UnknownName {
        /// The class entry.
        entry: &'static str,
        /// The unknown name.
        name: &'static str,
    },
    /// A stored or secret attribute has an AD syntax with no phase-1 mapping.
    /// Spec: docs/46 §1 (D104).
    UnmappedSyntax(&'static str),
    /// The secret rows are not exactly the [MS-ADTS] 3.1.1.1.4 set.
    SecretSetMismatch(&'static str),
    /// dirstore refused the schema (fail closed). Spec: docs/46 §8.
    Schema(dirstore::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Attrtyp { name, error } => {
                write!(f, "{name}: OID not mappable to an ATTRTYP ({error:?})")
            }
            Error::MalformedGuid(name) => write!(f, "{name}: malformed GUID string"),
            Error::DuplicateOrInvalidName(name) => {
                write!(f, "{name}: duplicate or non-ASCII lDAPDisplayName")
            }
            Error::DuplicateAttrtyp(name) => write!(f, "{name}: ATTRTYP already in use"),
            Error::DuplicateSchemaIdGuid(name) => {
                write!(f, "{name}: schemaIDGUID already in use")
            }
            Error::UnknownName { entry, name } => {
                write!(f, "{entry}: names unknown schema entry {name}")
            }
            Error::UnmappedSyntax(name) => write!(f, "{name}: AD syntax has no phase-1 mapping"),
            Error::SecretSetMismatch(name) => {
                write!(f, "{name}: secret rows differ from the specified set")
            }
            Error::Schema(e) => write!(f, "dirstore refused the schema: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Schema(e) => Some(e),
            _ => None,
        }
    }
}

/// A lookup of an unknown id, or of a class set that is not one class
/// chain. A PIP answers these with NotFound, so the PDP denies (D40).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum LookupError {
    /// No phase-1 attribute has this id.
    UnknownAttribute(AttrId),
    /// No phase-1 class has this id.
    UnknownClass(ClassId),
    /// The classes are not `SUPCLASSES(c) ∪ {c}` for exactly one class `c`.
    /// Spec: [MS-ADTS] 3.1.1.4.2, 3.1.1.2.4.3.
    InvalidClassChain,
}

impl fmt::Display for LookupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LookupError::UnknownAttribute(a) => write!(f, "attribute {} is not defined", a.0),
            LookupError::UnknownClass(c) => write!(f, "class {} is not defined", c.0),
            LookupError::InvalidClassChain => {
                f.write_str("classes are not the chain of one most specific class")
            }
        }
    }
}

impl std::error::Error for LookupError {}
