//! Access rights for Active Directory objects, and the generic mapping.
//!
//! Spec: [MS-ADTS] 5.1.3.2 (the access-rights diagram and the value of each
//! right; "X: Ignored. These bits are ignored in Active Directory DACLs";
//! the mapping of the four generic rights), 6.1.3 item 5.6 (the same
//! `GenericMapping` table, "used for all Active Directory SD operations").
//! The values agree with [MS-DTYP] 2.4.3 / 2.4.4.3 / 2.5.1.1 as carried by
//! `dtyp::AccessMask` (checked by a test).
//!
//! Diagram of 5.1.3.2 (position 0 = most significant bit): GR GW GX GA, then
//! eight X (ignored), WO WD RC DE, then seven X (ignored), CR LO DT WP RP VW LC
//! DC CC.

/// CC — RIGHT_DS_CREATE_CHILD. Spec: [MS-ADTS] 5.1.3.2 ("0x00000001").
pub const RIGHT_DS_CREATE_CHILD: u32 = 0x0000_0001;
/// DC — RIGHT_DS_DELETE_CHILD. Spec: [MS-ADTS] 5.1.3.2 ("0x00000002").
pub const RIGHT_DS_DELETE_CHILD: u32 = 0x0000_0002;
/// LC — RIGHT_DS_LIST_CONTENTS. Spec: [MS-ADTS] 5.1.3.2 ("0x00000004").
pub const RIGHT_DS_LIST_CONTENTS: u32 = 0x0000_0004;
/// VW — RIGHT_DS_WRITE_PROPERTY_EXTENDED. Spec: [MS-ADTS] 5.1.3.2
/// ("0x00000008").
pub const RIGHT_DS_WRITE_PROPERTY_EXTENDED: u32 = 0x0000_0008;
/// RP — RIGHT_DS_READ_PROPERTY. Spec: [MS-ADTS] 5.1.3.2 ("0x00000010").
pub const RIGHT_DS_READ_PROPERTY: u32 = 0x0000_0010;
/// WP — RIGHT_DS_WRITE_PROPERTY. Spec: [MS-ADTS] 5.1.3.2 ("0x00000020").
pub const RIGHT_DS_WRITE_PROPERTY: u32 = 0x0000_0020;
/// DT — RIGHT_DS_DELETE_TREE. Spec: [MS-ADTS] 5.1.3.2 ("0x00000040").
pub const RIGHT_DS_DELETE_TREE: u32 = 0x0000_0040;
/// LO — RIGHT_DS_LIST_OBJECT. Spec: [MS-ADTS] 5.1.3.2 ("0x00000080").
pub const RIGHT_DS_LIST_OBJECT: u32 = 0x0000_0080;
/// CR — RIGHT_DS_CONTROL_ACCESS. Spec: [MS-ADTS] 5.1.3.2 ("0x00000100").
pub const RIGHT_DS_CONTROL_ACCESS: u32 = 0x0000_0100;
/// DE — RIGHT_DELETE. Spec: [MS-ADTS] 5.1.3.2 ("0x00010000").
pub const RIGHT_DELETE: u32 = 0x0001_0000;
/// RC — RIGHT_READ_CONTROL. Spec: [MS-ADTS] 5.1.3.2 ("0x00020000").
pub const RIGHT_READ_CONTROL: u32 = 0x0002_0000;
/// WD — RIGHT_WRITE_DAC. Spec: [MS-ADTS] 5.1.3.2 ("0x00040000").
pub const RIGHT_WRITE_DAC: u32 = 0x0004_0000;
/// WO — RIGHT_WRITE_OWNER. Spec: [MS-ADTS] 5.1.3.2 ("0x00080000").
pub const RIGHT_WRITE_OWNER: u32 = 0x0008_0000;
/// GA — RIGHT_GENERIC_ALL. Spec: [MS-ADTS] 5.1.3.2 ("0x10000000").
pub const RIGHT_GENERIC_ALL: u32 = 0x1000_0000;
/// GX — RIGHT_GENERIC_EXECUTE. Spec: [MS-ADTS] 5.1.3.2 ("0x20000000").
pub const RIGHT_GENERIC_EXECUTE: u32 = 0x2000_0000;
/// GW — RIGHT_GENERIC_WRITE. Spec: [MS-ADTS] 5.1.3.2 ("0x40000000").
pub const RIGHT_GENERIC_WRITE: u32 = 0x4000_0000;
/// GR — RIGHT_GENERIC_READ. Spec: [MS-ADTS] 5.1.3.2 ("0x80000000").
pub const RIGHT_GENERIC_READ: u32 = 0x8000_0000;

/// ACCESS_SYSTEM_SECURITY — requestable, never meaningful in a DACL ACE.
/// Spec: [MS-DTYP] 2.4.3 (value 0x01000000); 2.5.3.2 (needs
/// SeSecurityPrivilege). In AD DACLs this position is an ignored X bit
/// ([MS-ADTS] 5.1.3.2).
pub const ACCESS_SYSTEM_SECURITY: u32 = 0x0100_0000;
/// MAXIMUM_ALLOWED — requestable only. Spec: [MS-DTYP] 2.4.3 (value
/// 0x02000000); 2.5.3.2 (MaxAllowedMode, not supported here).
pub const MAXIMUM_ALLOWED: u32 = 0x0200_0000;

/// The rights an owner holds implicitly: READ_CONTROL only.
///
/// DELIBERATE DEVIATION (project decision A-21, Q-050 resolved): [MS-DTYP]
/// 2.5.3.2 grants the owner "READ_CONTROL and WRITE_DAC", [MS-ADTS] 5.1.3.3.2
/// step 3 "RC, WD and WO". [MS-ADTS] 5.1.3.3.1 and 6.1.3.4 define a supported
/// mode, BlockOwnerImplicitRights, in which the implicit WRITE_DAC "MUST be
/// ignored"; that blocked behaviour is hard-wired here for every requester
/// (no Domain / Enterprise Admins exemption — the PDP has no such notion;
/// administrators get WRITE_DAC through explicit ACEs), closing the
/// owner → WRITE_DAC escalation path (AGENTS.md §6: fail closed). WRITE_OWNER
/// is never implicit ([MS-DTYP] 2.5.3.2 / [MS-ADTS] 5.1.3.3.1: only with
/// SeTakeOwnershipPrivilege, which this model has no notion of).
pub const OWNER_IMPLICIT_RIGHTS: u32 = RIGHT_READ_CONTROL;

/// GR = (RC | LC | RP | LO). Spec: [MS-ADTS] 5.1.3.2; 6.1.3
/// (GENERIC_READ_MAPPING).
pub const GENERIC_READ_MAPPING: u32 =
    RIGHT_READ_CONTROL | RIGHT_DS_LIST_CONTENTS | RIGHT_DS_READ_PROPERTY | RIGHT_DS_LIST_OBJECT;
/// GW = (RC | WP | VW). Spec: [MS-ADTS] 5.1.3.2; 6.1.3
/// (GENERIC_WRITE_MAPPING).
pub const GENERIC_WRITE_MAPPING: u32 =
    RIGHT_READ_CONTROL | RIGHT_DS_WRITE_PROPERTY | RIGHT_DS_WRITE_PROPERTY_EXTENDED;
/// GX = (RC | LC). Spec: [MS-ADTS] 5.1.3.2; 6.1.3 (GENERIC_EXECUTE_MAPPING).
pub const GENERIC_EXECUTE_MAPPING: u32 = RIGHT_READ_CONTROL | RIGHT_DS_LIST_CONTENTS;
/// GA = (DE | RC | WD | WO | CC | DC | DT | RP | WP | LC | LO | CR | VW).
/// Spec: [MS-ADTS] 5.1.3.2; 6.1.3 (GENERIC_ALL_MAPPING).
pub const GENERIC_ALL_MAPPING: u32 = RIGHT_DELETE
    | RIGHT_READ_CONTROL
    | RIGHT_WRITE_DAC
    | RIGHT_WRITE_OWNER
    | RIGHT_DS_CREATE_CHILD
    | RIGHT_DS_DELETE_CHILD
    | RIGHT_DS_DELETE_TREE
    | RIGHT_DS_READ_PROPERTY
    | RIGHT_DS_WRITE_PROPERTY
    | RIGHT_DS_LIST_CONTENTS
    | RIGHT_DS_LIST_OBJECT
    | RIGHT_DS_CONTROL_ACCESS
    | RIGHT_DS_WRITE_PROPERTY_EXTENDED;

/// Every specific (non-generic, non-X) right position of the 5.1.3.2
/// diagram: WO WD RC DE and CR LO DT WP RP VW LC DC CC. A request may only
/// name these; every other bit of an ACE mask is either a generic right
/// (mapped) or an X bit (ignored). Spec: [MS-ADTS] 5.1.3.2.
pub const DIRECTORY_RIGHTS: u32 = RIGHT_WRITE_OWNER
    | RIGHT_WRITE_DAC
    | RIGHT_READ_CONTROL
    | RIGHT_DELETE
    | RIGHT_DS_CONTROL_ACCESS
    | RIGHT_DS_LIST_OBJECT
    | RIGHT_DS_DELETE_TREE
    | RIGHT_DS_WRITE_PROPERTY
    | RIGHT_DS_READ_PROPERTY
    | RIGHT_DS_WRITE_PROPERTY_EXTENDED
    | RIGHT_DS_LIST_CONTENTS
    | RIGHT_DS_DELETE_CHILD
    | RIGHT_DS_CREATE_CHILD;

/// The effective rights of an ACE mask in an AD DACL: each generic right is
/// replaced by the specific rights it represents, and the X bits are dropped.
///
/// Spec: [MS-ADTS] 5.1.3.2 ("The mapping for access to objects in Active
/// Directory is as follows: GR = ..., GW = ..., GX = ..., GA = ..."; "X:
/// Ignored. These bits are ignored in Active Directory DACLs"); 6.1.3 item
/// 5.6. (5.1.3.2 also notes that generic bits are mapped before an SD value
/// is stored, so a stored value should not carry them; mapping them here
/// keeps the meaning the spec assigns if one ever does.)
#[must_use]
pub fn effective_ace_rights(mask: u32) -> u32 {
    let mut rights = mask;
    if mask & RIGHT_GENERIC_READ != 0 {
        rights |= GENERIC_READ_MAPPING;
    }
    if mask & RIGHT_GENERIC_WRITE != 0 {
        rights |= GENERIC_WRITE_MAPPING;
    }
    if mask & RIGHT_GENERIC_EXECUTE != 0 {
        rights |= GENERIC_EXECUTE_MAPPING;
    }
    if mask & RIGHT_GENERIC_ALL != 0 {
        rights |= GENERIC_ALL_MAPPING;
    }
    rights & DIRECTORY_RIGHTS
}
