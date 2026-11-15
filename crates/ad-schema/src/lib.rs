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
//! - **Two internal attributes** (module `internal`), stored by dirstore
//!   with ATTRTYPs from the range [MS-ADTS] 3.1.1.2.6 reserves "for internal
//!   use (never appear on the wire)" — in none of the AD tables or lookups,
//!   so no LDAP request, PDP resource or wire format can name one:
//!   [`HOST_ADDRESS`] (task DN6), a computer's DNS host addresses (docs/54
//!   §5.2), allowed on computer (docs/questions/Q-614 item 1 (b), Q-992);
//!   and [`PRINCIPAL_NAME_KEY`] (task PN2), the keys of the one principal
//!   namespace, **unique** — so the store refuses a key another live object
//!   holds, whichever name it was cut from — allowed on user, computer and
//!   group (docs/59 §4.6; docs/questions/Q-1008 item 1, A-173).
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
//! (02/2021) 8.19. The principal-name key (task PN2) also from docs/59
//! §4.1-§4.6, docs/questions/Q-1008 (A-173), [MS-SAMR] v20260427 3.1.1.8.4
//! and RFC 4120 §6.2. No other implementation was consulted or recalled
//! (AGENTS.md §1-3).
//!
//! Spec: docs/46 §3-§8; [MS-DRSR] 5.16.4; [MS-ADSC]; [MS-ADA1-3];
//! [MS-ADTS] 3.1.1.1.4, 3.1.1.4.2.

mod attid;
mod attributes;
mod classes;
mod error;
pub mod flags;
mod internal;
mod schema;

pub use attid::{make_attid, OidError, MAX_OID_LEN};
pub use attributes::{
    dirstore_syntax, AttributeEntry, Constraint, Form, Stored, ATTRIBUTES, SECRET_ATTRIBUTES,
};
pub use classes::{ClassEntry, CLASSES, STRUCTURAL_CLASS};
pub use error::{Error, LookupError};
// The internal attributes: host addresses (task DN6; docs/questions/Q-992)
// and principal-name keys (task PN2; docs/59 §4.6, docs/questions/Q-1008).
pub use internal::{
    host_address_definition, principal_name_key_definition, HOST_ADDRESS, HOST_ADDRESS_HOLDERS,
    HOST_ADDRESS_OCTETS, INTERNAL_ATTRTYP_FIRST, PRINCIPAL_NAME_KEY, PRINCIPAL_NAME_KEY_HOLDERS,
    PRINCIPAL_NAME_KEY_MAX_OCTETS,
};
pub use schema::{
    phase1, AttributeInfo, ChainClass, ClassChain, ClassInfo, Phase1Schema, PropertySet,
};
