#![forbid(unsafe_code)]
//! `ad-schema`: the phase-1 Active Directory schema **content**, as data
//! (docs/46, decided as A-29; R46-1 — `dirstore` stays the mechanism).
//!
//! # What it holds
//!
//! - **35 attribute definitions** ([`ATTRIBUTES`]): 17 stored, 7 derived
//!   (objectClass, objectCategory, instanceType, objectGUID, name,
//!   distinguishedName, memberOf), 11 secret (the [MS-ADTS] 3.1.1.1.4 set) —
//!   with their attributeSchema values from [MS-ADA1-3] and the dirstore
//!   mapping of docs/46 §5.4 (R46-4, R46-6, R46-7, R46-8) and docs/47 R47-13
//!   (servicePrincipalName single-valued, and allowed on computer only, in
//!   phase 1).
//! - **10 class definitions** ([`CLASSES`]): top, domain, domainDNS (NC root
//!   only), organizationalUnit, container, person, organizationalPerson,
//!   user, computer, group — with their classSchema values from [MS-ADSC]
//!   and the dirstore definitions of docs/46 §4.4 (R46-9).
//! - **Identifiers computed, not tabled**: `AttrId` / `ClassId` =
//!   [`make_attid`]`(attributeID | governsID)` — `MakeAttid` over
//!   `NewPrefixTable()` exactly as [MS-DRSR] 5.16.4 defines them; an OID
//!   whose prefix is not in that table is refused (R46-3).
//!   `objectClass` is `AttrId(0)`.
//!
//! # What it gives
//!
//! [`phase1`] builds the [`Phase1Schema`]: the validated
//! [`dirstore::Schema`] (it fails closed if `Schema::new` refuses) and the
//! lookups the PDP and the LDAP layer need (docs/46 §7): schemaIDGUID per
//! AttrId / ClassId, the property set per AttrId with A-28's
//! `is_attribute_guid` computed from the whole table, the class chain of a
//! class set, CLASSATTS per class, AttrId / ClassId by lDAPDisplayName
//! (ASCII, case-insensitive). Plain data: no pdp dependency — a future
//! directory PIP adapts it.
//!
//! # Provenance
//!
//! Written only from this project's documents (docs/46 in full, Q-080,
//! Q-081 / A-28, Q-090, Q-091 / A-30, PENDING-OWNER A-18, A-29, P-9) and
//! the pinned specifications opened in-session from `tools/spec-pin/cache/`
//! (SHA-256 verified against `tools/spec-pin/manifest.json`): [MS-DRSR]
//! v20260309 5.16.3.8, 5.16.3.16, 5.16.4; [MS-ADSC] v20240423 (the phase-1
//! classes and their auxiliary classes); [MS-ADA1] v20180912, [MS-ADA2]
//! v20240423, [MS-ADA3] v20180912 (the 35 attribute entries); [MS-ADTS]
//! v20261026 2.2.9, 2.2.10, 2.2.12, 2.2.16, 3.1.1.1.4, 3.1.1.2.2.2,
//! 3.1.1.2.3, 3.1.1.2.3.3, 3.1.1.2.4.3, 3.1.1.2.4.6, 3.1.1.2.4.8, 3.1.1.2.6,
//! 3.1.1.4.2; [MS-DTYP] v20241119 2.3.4.1, 2.3.4.2, 2.5.1.1; ITU-T X.690
//! (02/2021) 8.19. No other implementation was consulted or recalled
//! (AGENTS.md §1-3).
//!
//! Spec: docs/46 §3-§8; [MS-DRSR] 5.16.4; [MS-ADSC]; [MS-ADA1-3];
//! [MS-ADTS] 3.1.1.1.4, 3.1.1.4.2.

mod attid;
mod attributes;
mod classes;
mod error;
pub mod flags;
mod guid;
mod schema;

pub use attid::{make_attid, OidError, MAX_OID_LEN};
pub use attributes::{
    dirstore_syntax, AttributeEntry, Constraint, Form, Stored, ATTRIBUTES, SECRET_ATTRIBUTES,
};
pub use classes::{ClassEntry, CLASSES, STRUCTURAL_CLASS};
pub use error::{Error, LookupError};
pub use schema::{
    phase1, AttributeInfo, ChainClass, ClassChain, ClassInfo, Phase1Schema, PropertySet,
};
