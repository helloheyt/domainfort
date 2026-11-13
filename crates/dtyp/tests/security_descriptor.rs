//! Self-relative SECURITY_DESCRIPTOR tests.
//!
//! Every vector names its source: the 176-byte worked example of
//! [MS-DTYP] v20241119 2.5.1.4, pieces of it rearranged as [MS-DTYP] 2.4.6
//! permits, or byte sequences hand-derived from [MS-DTYP] 2.4.6. No vector
//! comes from any other implementation.

use dtyp::{
    ace_type, AccessMask, Ace, Acl, Control, Error, MaskSidAce, SecurityDescriptor, Sid,
    UnsupportedAce, ACL_REVISION, SD_FIXED_LEN,
};

/// [MS-DTYP] 2.5.1.4: the self-relative encoding of
/// "O:BAG:BAD:P(A;CIOI;GRGX;;;BU)(A;CIOI;GA;;;BA)(A;CIOI;GA;;;SY)(A;CIOI;GA;;;CO)S:P(AU;FA;GR;;;WD)".
const EXAMPLE: [u8; 0xb0] = [
    0x01, 0x00, 0x14, 0xb0, 0x90, 0x00, 0x00, 0x00, 0xa0, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00,
    0x30, 0x00, 0x00, 0x00, 0x02, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x80, 0x14, 0x00,
    0x00, 0x00, 0x00, 0x80, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x60, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x03, 0x18, 0x00, 0x00, 0x00, 0x00, 0xa0,
    0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x20, 0x00, 0x00, 0x00, 0x21, 0x02, 0x00, 0x00,
    0x00, 0x03, 0x18, 0x00, 0x00, 0x00, 0x00, 0x10, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
    0x20, 0x00, 0x00, 0x00, 0x20, 0x02, 0x00, 0x00, 0x00, 0x03, 0x14, 0x00, 0x00, 0x00, 0x00, 0x10,
    0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x12, 0x00, 0x00, 0x00, 0x00, 0x03, 0x14, 0x00,
    0x00, 0x00, 0x00, 0x10, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x20, 0x00, 0x00, 0x00, 0x20, 0x02, 0x00, 0x00,
    0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x20, 0x00, 0x00, 0x00, 0x20, 0x02, 0x00, 0x00,
];

// Component ranges inside EXAMPLE ([MS-DTYP] 2.5.1.4 offsets).
const SACL: core::ops::Range<usize> = 0x14..0x30;
const DACL: core::ops::Range<usize> = 0x30..0x90;
const OWNER: core::ops::Range<usize> = 0x90..0xa0;
const GROUP: core::ops::Range<usize> = 0xa0..0xb0;

fn sid(text: &str) -> Sid {
    Sid::parse_sid_string(text).unwrap()
}

/// Assemble a descriptor: fixed portion ([MS-DTYP] 2.4.6) followed by `body`.
fn sd_bytes(control: u16, offsets: [u32; 4], body: &[u8]) -> Vec<u8> {
    let [owner, group, sacl, dacl] = offsets;
    let mut out = vec![1u8, 0];
    out.extend_from_slice(&control.to_le_bytes());
    for offset in [owner, group, sacl, dacl] {
        out.extend_from_slice(&offset.to_le_bytes());
    }
    out.extend_from_slice(body);
    out
}

const SR: u16 = Control::SELF_RELATIVE;
const OD_GD: u16 = Control::OWNER_DEFAULTED | Control::GROUP_DEFAULTED;

#[test]
fn worked_example_decodes_and_reencodes_exactly() {
    // Source: [MS-DTYP] 2.5.1.4 — revision 1, Control 0xB014, OffsetOwner
    // 0x90, OffsetGroup 0xA0, OffsetSacl 0x14, OffsetDacl 0x30.
    let sd = SecurityDescriptor::decode(&EXAMPLE).unwrap();
    assert_eq!(sd.sbz1, 0);
    assert_eq!(sd.control, Control(0xb014));
    // The bit table of 2.5.1.4: SR, PS, PD, SP, DP set; all others clear.
    for bit in [
        Control::SELF_RELATIVE,
        Control::SACL_PROTECTED,
        Control::DACL_PROTECTED,
        Control::SACL_PRESENT,
        Control::DACL_PRESENT,
    ] {
        assert!(sd.control.contains(bit));
    }
    for bit in [
        Control::RM_CONTROL_VALID,
        Control::SACL_AUTO_INHERITED,
        Control::DACL_AUTO_INHERITED,
        Control::SACL_COMPUTED_INHERITANCE_REQUIRED,
        Control::DACL_COMPUTED_INHERITANCE_REQUIRED,
        Control::SERVER_SECURITY,
        Control::DACL_TRUSTED,
        Control::SACL_DEFAULTED,
        Control::DACL_DEFAULTED,
        Control::GROUP_DEFAULTED,
        Control::OWNER_DEFAULTED,
    ] {
        assert!(!sd.control.contains(bit));
    }
    // Owner and group are "BA".
    assert_eq!(sd.owner_sid, Some(sid("S-1-5-32-544")));
    assert_eq!(sd.group_sid, Some(sid("S-1-5-32-544")));
    let sacl = sd.sacl.as_ref().unwrap();
    assert_eq!(sacl.aces.len(), 1);
    assert_eq!(
        sacl.aces[0],
        Ace::SystemAudit(MaskSidAce {
            ace_flags: 0x80,
            mask: AccessMask(AccessMask::GENERIC_READ),
            sid: sid("S-1-1-0"),
        })
    );
    assert_eq!(sd.dacl.as_ref().unwrap().aces.len(), 4);
    // Canonical order is the example's order, so the round trip is exact.
    assert_eq!(sd.encode().unwrap(), EXAMPLE);
    assert_eq!(sd.encoded_len().unwrap(), EXAMPLE.len());
}

#[test]
fn any_component_order_decodes_and_canonicalises() {
    // Source: [MS-DTYP] 2.4.6 — "The order of appearance of pointer target
    // fields is not required to be in any particular order". Hand-derived from
    // the 2.5.1.4 pieces laid out as Owner, Group, Dacl, Sacl.
    let mut body = Vec::new();
    body.extend_from_slice(&EXAMPLE[OWNER]); // at 0x14
    body.extend_from_slice(&EXAMPLE[GROUP]); // at 0x24
    body.extend_from_slice(&EXAMPLE[DACL]); // at 0x34
    body.extend_from_slice(&EXAMPLE[SACL]); // at 0x94
    let bytes = sd_bytes(0xb014, [0x14, 0x24, 0x94, 0x34], &body);
    assert_eq!(bytes.len(), EXAMPLE.len());
    let reordered = SecurityDescriptor::decode(&bytes).unwrap();
    assert_eq!(reordered, SecurityDescriptor::decode(&EXAMPLE).unwrap());
    assert_eq!(reordered.encode().unwrap(), EXAMPLE);
}

#[test]
fn fixed_portion_only() {
    // Source: [MS-DTYP] 2.4.6 — all offsets zero: no field present. OffsetOwner
    // / OffsetGroup must be valid only when OD / GD are clear, so both are set;
    // SP and DP are clear, so OffsetSacl / OffsetDacl MUST be zero.
    let bytes = sd_bytes(SR | OD_GD, [0; 4], &[]);
    assert_eq!(bytes.len(), SD_FIXED_LEN);
    let sd = SecurityDescriptor::decode(&bytes).unwrap();
    assert_eq!(sd.owner_sid, None);
    assert_eq!(sd.group_sid, None);
    assert_eq!(sd.sacl, None);
    assert_eq!(sd.dacl, None);
    assert_eq!(sd.encode().unwrap(), bytes);
}

#[test]
fn empty_dacl_and_rm_control_bits() {
    // Source: [MS-DTYP] 2.4.6 (DP with a present, empty DACL; Sbz1 carried as
    // resource manager control bits when RM is set) and 2.4.5 (8-byte ACL
    // header). Hand-derived.
    let sd = SecurityDescriptor {
        sbz1: 0x5A,
        control: Control(SR | Control::RM_CONTROL_VALID | Control::DACL_PRESENT | OD_GD),
        owner_sid: None,
        group_sid: None,
        sacl: None,
        dacl: Some(Acl {
            acl_revision: ACL_REVISION,
            aces: Vec::new(),
        }),
    };
    let bytes = sd.encode().unwrap();
    let mut expected = sd_bytes(
        SR | Control::RM_CONTROL_VALID | Control::DACL_PRESENT | OD_GD,
        [0, 0, 0, 20],
        &[0x02, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00],
    );
    expected[1] = 0x5A; // Sbz1
    assert_eq!(bytes, expected);
    assert_eq!(SecurityDescriptor::decode(&bytes).unwrap(), sd);
}

#[test]
fn reject_fixed_portion_rules() {
    // Source: [MS-DTYP] 2.4.6, rule by rule.
    for cut in 0..SD_FIXED_LEN {
        assert_eq!(
            SecurityDescriptor::decode(&EXAMPLE[..cut]),
            Err(Error::SdTruncated),
            "cut {cut}"
        );
    }
    // Revision MUST be one.
    let mut b = EXAMPLE;
    b[0] = 2;
    assert_eq!(SecurityDescriptor::decode(&b), Err(Error::SdRevision));
    // SR MUST be set in self-relative form.
    let mut b = EXAMPLE;
    b[3] &= 0x7F;
    assert_eq!(
        SecurityDescriptor::decode(&b),
        Err(Error::SdNotSelfRelative)
    );
}

#[test]
fn reject_present_flag_and_offset_disagreement() {
    // Source: [MS-DTYP] 2.4.6 — OffsetSacl / OffsetDacl "MUST be set to zero"
    // when SP / DP is clear; Sacl / Dacl "MUST be present" when SP / DP is set.
    let mut b = EXAMPLE;
    b[2] &= !0x10; // clear SP, keep OffsetSacl 0x14
    assert_eq!(
        SecurityDescriptor::decode(&b),
        Err(Error::SaclOffsetWithoutPresentFlag)
    );
    let mut b = EXAMPLE;
    b[2] &= !0x04; // clear DP, keep OffsetDacl 0x30
    assert_eq!(
        SecurityDescriptor::decode(&b),
        Err(Error::DaclOffsetWithoutPresentFlag)
    );
    // SP / DP set with a zero offset.
    let bytes = sd_bytes(SR | OD_GD | Control::SACL_PRESENT, [0; 4], &[]);
    assert_eq!(
        SecurityDescriptor::decode(&bytes),
        Err(Error::SaclPresentWithoutOffset)
    );
    let bytes = sd_bytes(SR | OD_GD | Control::DACL_PRESENT, [0; 4], &[]);
    assert_eq!(
        SecurityDescriptor::decode(&bytes),
        Err(Error::DaclPresentWithoutOffset)
    );
}

#[test]
fn reject_absent_owner_or_group_without_defaulted_flag() {
    // Source: [MS-DTYP] 2.4.6 — OffsetOwner / OffsetGroup "must be a valid
    // offset if the OD / GD flag is not set". Zero then is unresolved (Q-023),
    // so it is rejected.
    let bytes = sd_bytes(SR | Control::GROUP_DEFAULTED, [0; 4], &[]);
    assert_eq!(
        SecurityDescriptor::decode(&bytes),
        Err(Error::OwnerAbsentNotDefaulted)
    );
    let bytes = sd_bytes(SR | Control::OWNER_DEFAULTED, [0; 4], &[]);
    assert_eq!(
        SecurityDescriptor::decode(&bytes),
        Err(Error::GroupAbsentNotDefaulted)
    );
}

#[test]
fn reject_bad_offsets() {
    // Source: [MS-DTYP] 2.4.6 — each non-zero offset must be "a valid offset":
    // after the fixed portion, inside the buffer, with the whole field inside.
    let owner = &EXAMPLE[OWNER];
    // Offset into the fixed portion.
    let bytes = sd_bytes(SR | Control::GROUP_DEFAULTED, [4, 0, 0, 0], owner);
    assert_eq!(
        SecurityDescriptor::decode(&bytes),
        Err(Error::OffsetIntoHeader)
    );
    // Offset at the end of the buffer.
    let bytes = sd_bytes(SR | Control::GROUP_DEFAULTED, [36, 0, 0, 0], owner);
    assert_eq!(
        SecurityDescriptor::decode(&bytes),
        Err(Error::OffsetOutOfRange)
    );
    // Offset far beyond the buffer (and beyond 16 bits).
    let bytes = sd_bytes(SR | Control::GROUP_DEFAULTED, [0xFFFF_FFF0, 0, 0, 0], owner);
    assert_eq!(
        SecurityDescriptor::decode(&bytes),
        Err(Error::OffsetOutOfRange)
    );
    // The owner SID runs past the end of the buffer.
    let bytes = sd_bytes(SR | Control::GROUP_DEFAULTED, [20, 0, 0, 0], &owner[..12]);
    assert_eq!(SecurityDescriptor::decode(&bytes), Err(Error::SidTruncated));
    // The DACL's AclSize runs past the end of the buffer.
    let bytes = sd_bytes(
        SR | OD_GD | Control::DACL_PRESENT,
        [0, 0, 0, 20],
        &EXAMPLE[DACL.start..DACL.end - 4],
    );
    assert_eq!(SecurityDescriptor::decode(&bytes), Err(Error::AclTruncated));
}

#[test]
fn reject_overlap_and_unreferenced_bytes() {
    // Source: [MS-DTYP] 2.4.6 context; overlap / gap / trailing rules are the
    // project's strictness choice recorded in Q-024. Hand-derived.
    let owner = &EXAMPLE[OWNER];
    // Owner and group share the same bytes.
    let bytes = sd_bytes(SR, [20, 20, 0, 0], owner);
    assert_eq!(
        SecurityDescriptor::decode(&bytes),
        Err(Error::ComponentsOverlap)
    );
    // Group starts inside the owner. Owner S-1-5-1-16777216 ends with the
    // bytes 01 00 00 00 00 00 00 01, which also parse as a SID (S-1-1 with no
    // SubAuthority, 2.4.2.2), so both parse and only the overlap rule fails.
    let body = [1u8, 2, 0, 0, 0, 0, 0, 5, 1, 0, 0, 0, 0, 0, 0, 1];
    let bytes = sd_bytes(SR, [20, 28, 0, 0], &body);
    assert_eq!(
        SecurityDescriptor::decode(&bytes),
        Err(Error::ComponentsOverlap)
    );
    // A 4-byte gap between the fixed portion and the owner.
    let mut body = vec![0u8; 4];
    body.extend_from_slice(owner);
    let bytes = sd_bytes(SR | Control::GROUP_DEFAULTED, [24, 0, 0, 0], &body);
    assert_eq!(
        SecurityDescriptor::decode(&bytes),
        Err(Error::UnreferencedBytes)
    );
    // Trailing bytes after the last component.
    let mut body = owner.to_vec();
    body.extend_from_slice(&[0u8; 4]);
    let bytes = sd_bytes(SR | Control::GROUP_DEFAULTED, [20, 0, 0, 0], &body);
    assert_eq!(
        SecurityDescriptor::decode(&bytes),
        Err(Error::UnreferencedBytes)
    );
    // Trailing bytes with no component at all.
    let mut bytes = sd_bytes(SR | OD_GD, [0; 4], &[]);
    bytes.extend_from_slice(&[0u8; 4]);
    assert_eq!(
        SecurityDescriptor::decode(&bytes),
        Err(Error::UnreferencedBytes)
    );
    // Trailing bytes after the worked example.
    let mut bytes = EXAMPLE.to_vec();
    bytes.extend_from_slice(&[0u8; 4]);
    assert_eq!(
        SecurityDescriptor::decode(&bytes),
        Err(Error::UnreferencedBytes)
    );
}

#[test]
fn reject_acl_role_violations() {
    // Source: [MS-DTYP] 2.4.5 — SACL / DACL ACE-type rules; 2.4.3 —
    // ACCESS_SYSTEM_SECURITY MUST NOT be set in a DACL ACE. Hand-derived by
    // swapping the 2.5.1.4 SACL and DACL offsets.
    let mut swapped = EXAMPLE;
    swapped[12..16].copy_from_slice(&0x30u32.to_le_bytes()); // OffsetSacl -> DACL bytes
    swapped[16..20].copy_from_slice(&0x14u32.to_le_bytes()); // OffsetDacl -> SACL bytes
    assert_eq!(
        SecurityDescriptor::decode(&swapped),
        Err(Error::AceTypeNotValidInSacl)
    );
    // Only the DACL position, holding the audit ACL.
    let mut b = sd_bytes(
        SR | OD_GD | Control::DACL_PRESENT,
        [0, 0, 0, 20],
        &EXAMPLE[SACL],
    );
    assert_eq!(
        SecurityDescriptor::decode(&b),
        Err(Error::AceTypeNotValidInDacl)
    );
    // A DACL allow ACE with ACCESS_SYSTEM_SECURITY (mask byte 3 |= 0x01).
    let mut dacl = EXAMPLE[DACL].to_vec();
    dacl[8 + 7] |= 0x01;
    b = sd_bytes(SR | OD_GD | Control::DACL_PRESENT, [0, 0, 0, 20], &dacl);
    assert_eq!(
        SecurityDescriptor::decode(&b),
        Err(Error::AccessSystemSecurityInDacl)
    );
}

#[test]
fn encoder_applies_the_same_rules() {
    // Source: [MS-DTYP] 2.4.6 / 2.4.5 — the canonical encoder refuses what the
    // decoder rejects.
    let base = SecurityDescriptor::decode(&EXAMPLE).unwrap();

    let mut sd = base.clone();
    sd.control = Control(sd.control.0 & !Control::SELF_RELATIVE);
    assert_eq!(sd.encode(), Err(Error::SdNotSelfRelative));

    let mut sd = base.clone();
    sd.dacl = None; // DP still set
    assert_eq!(sd.encode(), Err(Error::DaclPresentWithoutOffset));

    let mut sd = base.clone();
    sd.control = Control(sd.control.0 & !Control::SACL_PRESENT); // SACL kept
    assert_eq!(sd.encode(), Err(Error::SaclOffsetWithoutPresentFlag));

    let mut sd = base.clone();
    sd.owner_sid = None; // OD clear
    assert_eq!(sd.encode(), Err(Error::OwnerAbsentNotDefaulted));

    let mut sd = base.clone();
    if let Some(dacl) = sd.dacl.as_mut() {
        dacl.aces.push(Ace::SystemAudit(MaskSidAce {
            ace_flags: 0,
            mask: AccessMask(0),
            sid: sid("S-1-1-0"),
        }));
    }
    assert_eq!(sd.encode(), Err(Error::AceTypeNotValidInDacl));

    let mut sd = base;
    if let Some(sacl) = sd.sacl.as_mut() {
        sacl.aces[0] = Ace::AccessAllowed(MaskSidAce {
            ace_flags: 0,
            mask: AccessMask(0),
            sid: sid("S-1-1-0"),
        });
    }
    assert_eq!(sd.encode(), Err(Error::AceTypeNotValidInSacl));
}

#[test]
fn unsupported_ace_survives_in_a_sacl() {
    // Source: [MS-DTYP] 2.4.5 (a SACL MAY contain a label ACE; 0x11 is
    // permitted by ACL_REVISION) and 2.4.4.13 (Header, Mask, Sid).
    // Hand-derived: SACL with one mandatory-label ACE for S-1-16-12288.
    let label = Ace::Unsupported(UnsupportedAce {
        ace_type: ace_type::SYSTEM_MANDATORY_LABEL_ACE_TYPE,
        ace_flags: 0,
        body: vec![
            1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0x10, 0x00, 0x30, 0x00, 0x00,
        ],
    });
    let sd = SecurityDescriptor {
        sbz1: 0,
        control: Control(SR | OD_GD | Control::SACL_PRESENT),
        owner_sid: None,
        group_sid: None,
        sacl: Some(Acl {
            acl_revision: ACL_REVISION,
            aces: vec![label.clone()],
        }),
        dacl: None,
    };
    let bytes = sd.encode().unwrap();
    let back = SecurityDescriptor::decode(&bytes).unwrap();
    assert_eq!(back, sd);
    assert_eq!(back.sacl.unwrap().aces[0], label);
}

#[test]
fn revision_ds_dacl_mixing_basic_and_object_aces() {
    // Source: [MS-DTYP] 2.4.5 — ACL_REVISION_DS adds the object ACE types to
    // the ACL_REVISION set (Q-022); 2.4.6 layout. Hand-derived: the 2.5.1.4
    // owner/group with a revision-4 DACL holding an ACCESS_DENIED_OBJECT ACE
    // and an ACCESS_ALLOWED ACE.
    let dacl = Acl {
        acl_revision: dtyp::ACL_REVISION_DS,
        aces: vec![
            Ace::AccessDeniedObject(dtyp::ObjectAce {
                ace_flags: 0,
                mask: AccessMask(AccessMask::ADS_RIGHT_DS_WRITE_PROP),
                object_type: Some(dtyp::Guid::from_packet(&[0x42; 16])),
                inherited_object_type: None,
                sid: sid("S-1-1-0"),
            }),
            Ace::AccessAllowed(MaskSidAce {
                ace_flags: 0,
                mask: AccessMask(AccessMask::READ_CONTROL),
                sid: sid("S-1-5-11"),
            }),
        ],
    };
    let sd = SecurityDescriptor {
        sbz1: 0,
        control: Control(SR | Control::DACL_PRESENT),
        owner_sid: Some(sid("S-1-5-32-544")),
        group_sid: Some(sid("S-1-5-32-544")),
        sacl: None,
        dacl: Some(dacl),
    };
    let bytes = sd.encode().unwrap();
    // DACL first (no SACL), then owner, then group (canonical order).
    assert_eq!(&bytes[16..20], &20u32.to_le_bytes()); // OffsetDacl
    assert_eq!(bytes[20], dtyp::ACL_REVISION_DS);
    let back = SecurityDescriptor::decode(&bytes).unwrap();
    assert_eq!(back, sd);
    assert_eq!(back.encode().unwrap(), bytes);
}
