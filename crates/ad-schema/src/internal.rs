//! The internal attributes: stored by dirstore on an object, defined in its
//! schema, and **outside** the Active Directory model — no attributeID, no
//! lDAPDisplayName, no schemaIDGUID, so no LDAP request, no PDP resource
//! and no wire format can name one ("never appear on the wire").
//!
//! # The first: the host addresses (task DN6; docs/questions/Q-614 item 1, Q-992)
//!
//! A member host's dynamic DNS addresses are an attribute of its own
//! computer object (docs/54 §5.2; Q-614 — the record dies with its owner in
//! the same transaction, A-18). The AD attribute with that meaning is
//! `ipHostNumber` ([MS-ADSC] v20240423 2.21: computer has `auxiliaryClass:
//! ipHost`; 2.67: ipHost `mayContain: … ipHostNumber …`; [MS-ADA1]
//! v20180912 2.315: "the IP address as a dotted decimal", attributeId
//! `1.3.6.1.1.1.1.19`). Its OID's prefix (`1.3.6.1.1.1.1`) is not in
//! `NewPrefixTable()` ([MS-DRSR] 5.16.4), and the decided identifier rule
//! refuses such an OID (docs/46 §3.3 R46-3, A-29 — it names the ipHost
//! family by name). Q-614's accepted plan gives the fallback for exactly
//! this case: "(b) a dirstore facet attached to the object, not
//! LDAP-visible … no AD attribute". This module is (b), built with the
//! store's existing attribute mechanism (values, stamps, integrity tag,
//! deletion with the object) and an ATTRTYP from the range [MS-ADTS]
//! 3.1.1.2.6 reserves "for internal use (never appear on the wire)" — no new
//! dirstore mechanism. Q-992 asks the main session to confirm (b) or amend
//! R46-3 for (a); the choice is confined to this module and the one codec
//! of crates/directory-admin `host_record`.
//!
//! # The second: the principal-name keys (task PN2; docs/59 §4.6, Q-1008)
//!
//! Every principal name of an account — its sAMAccountName, a computer's
//! base name, the local part of its userPrincipalName, its
//! servicePrincipalNames, a computer's dNSHostName, the krbtgt's realm
//! aliases — is one **key** of one namespace (docs/59 §4.1, decided as
//! A-173): "no two names can be the same" (RFC 4120 §6.2), and [MS-SAMR]
//! 3.1.1.8.4 item 2 already judges a sAMAccountName against "the union of
//! all sAMAccountName and msDS-AdditionalSamAccountName attribute values
//! for all other objects". The keys of an object are the values of one
//! internal attribute, [`PRINCIPAL_NAME_KEY`], marked `unique`: the store's
//! existing unique index then refuses, at every commit, a key that another
//! live object holds — whichever name each key was cut from — so
//! uniqueness holds **over the union** without a new dirstore mechanism and
//! without name rules in the storage engine (Q-1008 item 1). This crate
//! only declares the attribute; the keys are computed by crate
//! `principal-names` and written only by the one write checker (crates/
//! directory-admin `invariants`, task PN5 — docs/59 §5.1, N7), which also
//! refuses the attribute in a caller's input. Like [`HOST_ADDRESS`] it is in
//! none of the AD tables, so no LDAP request and no PDP resource can name
//! it.
//!
//! Spec: [MS-ADTS] v20261026 3.1.1.2.6 (ATTRTYP ranges); docs/54 §4.4,
//! §5.2; docs/questions/Q-614 items 1-2, Q-992; RFC 1035 §3.4.1 (ADDRESS: "A
//! 32 bit Internet address"), §2.3.2 (octet order); docs/59 §4.1, §4.4 N1,
//! §4.6; docs/questions/Q-1008 items 1-2, 6 (A-173); RFC 4120 §6.2;
//! [MS-SAMR] v20260427 3.1.1.8.4 item 2.

use dirstore::{AttrClass, AttrId, AttributeDefinition, Multiplicity, ValueRange, ValueSyntax};

/// The first ATTRTYP of the range [MS-ADTS] 3.1.1.2.6 reserves for internal
/// use: `[0xFFFF0000 .. 0xFFFFFFFF]` "Reserved for internal use (never
/// appear on the wire)". No `MakeAttid` value reaches it (those are below
/// `0x80000000`, the prefix-table range), so it cannot collide with an AD
/// attribute or class.
/// Spec: [MS-ADTS] v20261026 3.1.1.2.6.
pub const INTERNAL_ATTRTYP_FIRST: u32 = 0xFFFF_0000;

/// The host addresses of a computer's DNS host record (docs/54 §5.2): one
/// value per IPv4 address of the host's A records, multi-valued (a set).
/// The ATTRTYP is the first of the internal range (project choice inside
/// the spec's range — docs/questions/Q-992).
/// Spec: [MS-ADTS] 3.1.1.2.6; docs/54 §4.4 ("≤ 8 IPv4 addresses"), §5.2;
/// RFC 1035 §3.4.1.
pub const HOST_ADDRESS: AttrId = AttrId(INTERNAL_ATTRTYP_FIRST);

/// Octets of one [`HOST_ADDRESS`] value: the 32-bit Internet address in
/// network (transmission) order — exactly the A RDATA. One spelling per
/// address, so the store's value set is the address set.
/// Spec: RFC 1035 §3.4.1 ("ADDRESS A 32 bit Internet address"), §2.3.2
/// ("the normal order in which they are read in English").
pub const HOST_ADDRESS_OCTETS: usize = 4;

/// The classes whose objects may hold [`HOST_ADDRESS`] values, by
/// lDAPDisplayName: computer only — the class of a host's account (docs/54
/// §5.2; the AD counterpart is reachable on computer through its auxiliary
/// class ipHost, [MS-ADSC] 2.21 / 2.67). Which computer may hold one is the
/// write checker's rule (crates/directory-admin `invariants`).
/// Spec: docs/54 §5.2, §5.3; [MS-ADSC] v20240423 2.21, 2.67.
pub const HOST_ADDRESS_HOLDERS: [&str; 1] = ["computer"];

/// The dirstore definition of [`HOST_ADDRESS`]: OctetString, multi-valued,
/// exactly [`HOST_ADDRESS_OCTETS`] octets per value (the store refuses any
/// other length itself), Normal (it is no secret — zone content is visible
/// to every client of the internal network, docs/54 §4.4 "privacy"; and the
/// PDP never sees it), stored, no link, not unique (two hosts may announce
/// one address — docs/54 §8 row 1 residual).
/// Spec: docs/46 §8.2 (the definition fields); RFC 1035 §3.4.1; docs/54
/// §4.4, §5.2.
#[must_use]
pub fn host_address_definition() -> AttributeDefinition {
    // A byte bound of 4 always fits in i64.
    let octets = HOST_ADDRESS_OCTETS as i64;
    AttributeDefinition {
        range: Some(ValueRange {
            lower: octets,
            upper: octets,
        }),
        ..AttributeDefinition::new(
            HOST_ADDRESS,
            ValueSyntax::OctetString,
            Multiplicity::MultiValued,
            HOST_ADDRESS_OCTETS,
            AttrClass::Normal,
        )
    }
}

/// The principal-name keys of an account (docs/59 §4.6): one value per key
/// of the one principal namespace — each the folded form of one of the
/// object's names (docs/59 §4.1-§4.3) — multi-valued (a set: one object
/// may hold one key through two names, docs/59 §4.1, and the writer stores
/// it once). The ATTRTYP is the second of the internal range, after
/// [`HOST_ADDRESS`] (project choice inside the spec's range — docs/59
/// §4.6, docs/questions/Q-1008 item 1).
/// Spec: [MS-ADTS] v20261026 3.1.1.2.6 ("[0xFFFF0000.. 0xFFFFFFFF] Reserved
/// for internal use (never appear on the wire)"); docs/59 §4.6;
/// docs/questions/Q-1008 item 1 (A-173).
pub const PRINCIPAL_NAME_KEY: AttrId = AttrId(INTERNAL_ATTRTYP_FIRST + 1);

/// Largest octets of one [`PRINCIPAL_NAME_KEY`] value: 2048. A key is a
/// folded copy of (a part of) one name, never longer than it, and the
/// longest stored name a key is cut from is a dNSHostName (rangeUpper 2048
/// characters; sAMAccountName 256, userPrincipalName and
/// servicePrincipalName 1024 — docs/46 §5.4); names are printable ASCII in
/// phase 1 (docs/questions/Q-080), so a character is one octet. A longer
/// key (e.g. a realm alias from configuration, docs/59 §4.2) is refused by
/// the store — fail closed.
/// Spec: docs/46 §5.4; docs/questions/Q-1008 item 2 (A-173: "a value ≤
/// 2048 octets"), Q-080 item 1.
pub const PRINCIPAL_NAME_KEY_MAX_OCTETS: usize = 2048;

/// The classes whose objects may hold [`PRINCIPAL_NAME_KEY`] values, by
/// lDAPDisplayName: user (the krbtgt account is a user), computer and group —
/// every class docs/59 §4.3 gives keys (a group only for its
/// sAMAccountName, which it still occupies). computer is listed although it
/// also inherits user's `may` (docs/46 §4.4): the list names every holder of
/// docs/59 §4.3 explicitly, and the store judges an object against the
/// union of its chain's `must` / `may`, so the repetition changes nothing it
/// allows. domainDNS, organizationalUnit and container have no keys. Which
/// keys an object holds is the write checker's rule (crates/directory-admin
/// `invariants`, docs/59 §5.1).
/// Spec: docs/59 §4.3, §4.6; docs/questions/Q-1008 item 1 (A-173).
pub const PRINCIPAL_NAME_KEY_HOLDERS: [&str; 3] = ["user", "computer", "group"];

/// The dirstore definition of [`PRINCIPAL_NAME_KEY`]: OctetString (the
/// store's comparison key is then the octets themselves — the writer has
/// already folded them, docs/59 §4.2, Q-1008 item 4), multi-valued,
/// 1..=[`PRINCIPAL_NAME_KEY_MAX_OCTETS`] octets per value (an empty key is
/// unrepresentable — no principal name is empty, docs/59 §4.2, §4.4 N3-N4;
/// as for sAMAccountName's rangeLower 1, docs/46 §5.4), Normal (names are
/// no secret — docs/59 §4.6), stored, no link, and **unique**: no two live
/// objects may hold the same key, whichever name each was cut from
/// (docs/59 §4.4 N1; dirstore enforces it at every write and releases a
/// key with its object's tombstone — Q-1008 item 1).
/// Spec: docs/46 §8.2 (the definition fields), §8.5 (unique); docs/59 §4.4
/// N1, §4.6; docs/questions/Q-1008 items 1-2 (A-173).
#[must_use]
pub fn principal_name_key_definition() -> AttributeDefinition {
    // A byte bound of 2048 always fits in i64.
    let upper = PRINCIPAL_NAME_KEY_MAX_OCTETS as i64;
    AttributeDefinition {
        range: Some(ValueRange { lower: 1, upper }),
        unique: true,
        ..AttributeDefinition::new(
            PRINCIPAL_NAME_KEY,
            ValueSyntax::OctetString,
            Multiplicity::MultiValued,
            PRINCIPAL_NAME_KEY_MAX_OCTETS,
            AttrClass::Normal,
        )
    }
}

/// One internal attribute as the schema builder installs it (crate::schema):
/// its dirstore definition, the classes whose `may` lists it (by
/// lDAPDisplayName), and a label for errors — it has no lDAPDisplayName.
pub(crate) struct InternalAttribute {
    /// The label an [`Error`](crate::Error) names it by.
    pub(crate) label: &'static str,
    /// The dirstore definition.
    pub(crate) definition: AttributeDefinition,
    /// The classes whose `may` lists it.
    pub(crate) holders: &'static [&'static str],
}

/// Every internal attribute, ascending by ATTRTYP.
/// Spec: [MS-ADTS] 3.1.1.2.6; docs/questions/Q-992, Q-1008 item 1.
pub(crate) fn internal_attributes() -> [InternalAttribute; 2] {
    [
        InternalAttribute {
            label: "(internal) host address",
            definition: host_address_definition(),
            holders: &HOST_ADDRESS_HOLDERS,
        },
        InternalAttribute {
            label: "(internal) principal name key",
            definition: principal_name_key_definition(),
            holders: &PRINCIPAL_NAME_KEY_HOLDERS,
        },
    ]
}
