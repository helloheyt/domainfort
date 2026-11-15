//! The internal attributes: stored by dirstore on an object, defined in its
//! schema, and **outside** the Active Directory model — no attributeID, no
//! lDAPDisplayName, no schemaIDGUID, so no LDAP request, no PDP resource
//! and no wire format can name one ("never appear on the wire").
//!
//! # Why one exists (task DN6; docs/questions/Q-614 item 1, Q-992)
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
//! Spec: [MS-ADTS] v20261026 3.1.1.2.6 (ATTRTYP ranges); docs/54 §4.4,
//! §5.2; docs/questions/Q-614 items 1-2, Q-992; RFC 1035 §3.4.1 (ADDRESS: "A
//! 32 bit Internet address"), §2.3.2 (octet order).

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
