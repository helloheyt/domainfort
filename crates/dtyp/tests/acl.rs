//! ACL tests.
//!
//! Every vector names its source: the SACL and DACL of the worked example in
//! [MS-DTYP] v20241119 2.5.1.4, or byte sequences hand-derived from
//! [MS-DTYP] 2.4.5 (little-endian per 2.4.6). No vector comes from any other
//! implementation.

use dtyp::{
    ace_type, acl_revision_permits, AccessMask, Ace, Acl, Error, MaskSidAce, ObjectAce, Sid,
    UnsupportedAce, ACL_REVISION, ACL_REVISION_DS,
};

/// The DACL of [MS-DTYP] 2.5.1.4 (bytes 0x30..0x90 of the example):
/// "(A;CIOI;GRGX;;;BU)(A;CIOI;GA;;;BA)(A;CIOI;GA;;;SY)(A;CIOI;GA;;;CO)".
const EXAMPLE_DACL: [u8; 0x60] = [
    0x02, 0x00, 0x60, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x03, 0x18, 0x00, 0x00, 0x00, 0x00, 0xa0,
    0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x20, 0x00, 0x00, 0x00, 0x21, 0x02, 0x00, 0x00,
    0x00, 0x03, 0x18, 0x00, 0x00, 0x00, 0x00, 0x10, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
    0x20, 0x00, 0x00, 0x00, 0x20, 0x02, 0x00, 0x00, 0x00, 0x03, 0x14, 0x00, 0x00, 0x00, 0x00, 0x10,
    0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x12, 0x00, 0x00, 0x00, 0x00, 0x03, 0x14, 0x00,
    0x00, 0x00, 0x00, 0x10, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
];

/// The SACL of [MS-DTYP] 2.5.1.4 (bytes 0x14..0x30): "(AU;FA;GR;;;WD)".
const EXAMPLE_SACL: [u8; 0x1c] = [
    0x02, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x80, 0x14, 0x00, 0x00, 0x00, 0x00, 0x80,
    0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
];

fn sid(text: &str) -> Sid {
    Sid::parse_sid_string(text).unwrap()
}

fn allowed(mask: u32, trustee: &str) -> Ace {
    Ace::AccessAllowed(MaskSidAce {
        ace_flags: 0,
        mask: AccessMask(mask),
        sid: sid(trustee),
    })
}

/// Build ACL bytes from a header and ACE bytes ([MS-DTYP] 2.4.5 layout).
fn acl_bytes(revision: u8, sbz1: u8, size: u16, count: u16, sbz2: u16, aces: &[u8]) -> Vec<u8> {
    let mut out = vec![revision, sbz1];
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&sbz2.to_le_bytes());
    out.extend_from_slice(aces);
    out
}

/// One 20-byte ACCESS_ALLOWED ACE for S-1-1-0 ([MS-DTYP] 2.4.4.2).
const ALLOW_EVERYONE: [u8; 20] = [
    0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x10, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00,
];

#[test]
fn dacl_from_the_worked_example() {
    // Source: [MS-DTYP] 2.5.1.4 — ACL header "02 00 60 00 04 00 00 00"
    // (AclRevision 0x02, AclSize 0x0060, AceCount 0x0004) and four ACEs.
    let acl = Acl::decode(&EXAMPLE_DACL).unwrap();
    assert_eq!(acl.acl_revision, ACL_REVISION);
    assert_eq!(acl.aces.len(), 4);
    let ga = AccessMask::GENERIC_ALL;
    let grgx = AccessMask::GENERIC_READ | AccessMask::GENERIC_EXECUTE;
    let trustees = [
        (grgx, "S-1-5-32-545"),
        (ga, "S-1-5-32-544"),
        (ga, "S-1-5-18"),
        (ga, "S-1-3-0"),
    ];
    for (ace, (mask, trustee)) in acl.aces.iter().zip(trustees) {
        match ace {
            Ace::AccessAllowed(a) => {
                assert_eq!(a.ace_flags, 0x03, "CIOI");
                assert_eq!(a.mask, AccessMask(mask));
                assert_eq!(a.sid, sid(trustee));
            }
            other => panic!("unexpected ACE {other:?}"),
        }
    }
    acl.check_dacl().unwrap();
    assert_eq!(acl.encode().unwrap(), EXAMPLE_DACL);
    assert_eq!(acl.encoded_len().unwrap(), EXAMPLE_DACL.len());
}

#[test]
fn sacl_from_the_worked_example() {
    // Source: [MS-DTYP] 2.5.1.4 — SACL "S:P(AU;FA;GR;;;WD)" at offset 0x14.
    let acl = Acl::decode(&EXAMPLE_SACL).unwrap();
    assert_eq!(acl.aces.len(), 1);
    assert_eq!(acl.aces[0].ace_type(), ace_type::SYSTEM_AUDIT_ACE_TYPE);
    acl.check_sacl().unwrap();
    assert_eq!(acl.encode().unwrap(), EXAMPLE_SACL);
}

#[test]
fn empty_acl() {
    // Source: [MS-DTYP] 2.4.5 — AclSize counts the 8-byte header; AceCount 0.
    // (2.5.3.2 names "an empty DACL" as a valid configuration.)
    let bytes = acl_bytes(ACL_REVISION, 0, 8, 0, 0, &[]);
    let acl = Acl::decode(&bytes).unwrap();
    assert!(acl.aces.is_empty());
    assert_eq!(acl.encode().unwrap(), bytes);
}

#[test]
fn revision_ds_acl_with_object_and_label_aces() {
    // Source: [MS-DTYP] 2.4.5 — ACL_REVISION_DS allows AceTypes 0x05, 0x06,
    // 0x07, 0x08 and 0x11. Hand-derived values.
    let acl = Acl {
        acl_revision: ACL_REVISION_DS,
        aces: vec![
            Ace::AccessDeniedObject(ObjectAce {
                ace_flags: 0,
                mask: AccessMask(AccessMask::ADS_RIGHT_DS_WRITE_PROP),
                object_type: None,
                inherited_object_type: None,
                sid: sid("S-1-1-0"),
            }),
            Ace::AccessAllowedObject(ObjectAce {
                ace_flags: 0,
                mask: AccessMask(AccessMask::ADS_RIGHT_DS_READ_PROP),
                object_type: None,
                inherited_object_type: None,
                sid: sid("S-1-5-11"),
            }),
            Ace::Unsupported(UnsupportedAce {
                ace_type: ace_type::SYSTEM_MANDATORY_LABEL_ACE_TYPE,
                ace_flags: 0,
                body: vec![
                    1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0x10, 0x00, 0x30, 0x00, 0x00,
                ],
            }),
        ],
    };
    let bytes = acl.encode().unwrap();
    assert_eq!(bytes[0], ACL_REVISION_DS);
    assert_eq!(
        usize::from(u16::from_le_bytes([bytes[2], bytes[3]])),
        bytes.len()
    );
    assert_eq!(u16::from_le_bytes([bytes[4], bytes[5]]), 3);
    assert_eq!(Acl::decode(&bytes).unwrap(), acl);
}

#[test]
fn revision_type_table() {
    // Source: [MS-DTYP] 2.4.5 AclRevision table. ACL_REVISION: "only" 0x00,
    // 0x01, 0x02, 0x03, 0x11, 0x12, 0x13. ACL_REVISION_DS: 0x05, 0x06, 0x07,
    // 0x08 and 0x11 "are allowed" (no "only") in addition to those (Q-022).
    let revision_2 = [0x00u8, 0x01, 0x02, 0x03, 0x11, 0x12, 0x13];
    let revision_4 = [
        0x00u8, 0x01, 0x02, 0x03, 0x05, 0x06, 0x07, 0x08, 0x11, 0x12, 0x13,
    ];
    for t in 0u8..=0xFF {
        assert_eq!(
            acl_revision_permits(ACL_REVISION, t),
            revision_2.contains(&t),
            "rev 2, type {t:#04x}"
        );
        assert_eq!(
            acl_revision_permits(ACL_REVISION_DS, t),
            revision_4.contains(&t),
            "rev 4, type {t:#04x}"
        );
        // Any other revision permits nothing.
        assert!(!acl_revision_permits(3, t));
    }
}

#[test]
fn revision_ds_dacl_mixing_basic_and_object_aces() {
    // Source: [MS-DTYP] 2.4.5 — ACL_REVISION_DS adds the object ACE types to
    // the ACL_REVISION set (Q-022), so a revision-4 DACL may mix
    // ACCESS_ALLOWED (2.4.4.2) and ACCESS_ALLOWED_OBJECT (2.4.4.3) ACEs.
    // Hand-derived bytes.
    let object_packet = [0x10u8; 16];
    let mut aces = ALLOW_EVERYONE.to_vec(); // ACCESS_ALLOWED, S-1-1-0
    aces.extend_from_slice(&[0x05, 0x02, 0x28, 0x00]); // object ACE header, CI, size 40
    aces.extend_from_slice(&0x0000_0010u32.to_le_bytes()); // ADS_RIGHT_DS_READ_PROP
    aces.extend_from_slice(&1u32.to_le_bytes()); // ACE_OBJECT_TYPE_PRESENT
    aces.extend_from_slice(&object_packet); // ObjectType
    aces.extend_from_slice(&[1, 1, 0, 0, 0, 0, 0, 5, 0x0B, 0, 0, 0]); // S-1-5-11
    let bytes = acl_bytes(ACL_REVISION_DS, 0, (8 + aces.len()) as u16, 2, 0, &aces);
    let acl = Acl::decode(&bytes).unwrap();
    assert_eq!(acl.acl_revision, ACL_REVISION_DS);
    assert_eq!(
        acl.aces,
        vec![
            allowed(AccessMask::GENERIC_ALL, "S-1-1-0"),
            Ace::AccessAllowedObject(ObjectAce {
                ace_flags: 0x02,
                mask: AccessMask(AccessMask::ADS_RIGHT_DS_READ_PROP),
                object_type: Some(dtyp::Guid::from_packet(&object_packet)),
                inherited_object_type: None,
                sid: sid("S-1-5-11"),
            }),
        ]
    );
    acl.check_dacl().unwrap();
    assert_eq!(acl.encode().unwrap(), bytes);
}

#[test]
fn reject_header_rules() {
    // Source: [MS-DTYP] 2.4.5, rule by rule (hand-derived around one ACE).
    let good = acl_bytes(ACL_REVISION, 0, 28, 1, 0, &ALLOW_EVERYONE);
    assert!(Acl::decode(&good).is_ok());

    // Fewer than the 8 header bytes.
    for cut in 0..8 {
        assert_eq!(
            Acl::decode(&good[..cut]),
            Err(Error::AclTruncated),
            "cut {cut}"
        );
    }
    // AclSize beyond the input.
    assert_eq!(Acl::decode(&good[..27]), Err(Error::AclTruncated));
    // AclRevision MUST be 0x02 or 0x04.
    for revision in [0u8, 1, 3, 5, 0xFF] {
        let bytes = acl_bytes(revision, 0, 28, 1, 0, &ALLOW_EVERYONE);
        assert_eq!(
            Acl::decode(&bytes),
            Err(Error::AclRevision),
            "rev {revision}"
        );
    }
    // Sbz1 and Sbz2 MUST be zero.
    let bytes = acl_bytes(ACL_REVISION, 1, 28, 1, 0, &ALLOW_EVERYONE);
    assert_eq!(Acl::decode(&bytes), Err(Error::AclSbz1NonZero));
    let bytes = acl_bytes(ACL_REVISION, 0, 28, 1, 1, &ALLOW_EVERYONE);
    assert_eq!(Acl::decode(&bytes), Err(Error::AclSbz2NonZero));
    // AclSize below the header size.
    let bytes = acl_bytes(ACL_REVISION, 0, 4, 0, 0, &[]);
    assert_eq!(Acl::decode(&bytes), Err(Error::AclSizeTooSmall));
    // Strict framing for a stand-alone ACL.
    let mut trailing = good.clone();
    trailing.extend_from_slice(&[0; 4]);
    assert_eq!(Acl::decode(&trailing), Err(Error::TrailingData));
}

#[test]
fn reject_count_and_size_rules() {
    // Source: [MS-DTYP] 2.4.5 — ACEs are located with AclSize and AceCount,
    // and AclSize is the size of the complete ACL including all ACEs.

    // AceCount larger than AclSize can hold (checked before any allocation).
    let bytes = acl_bytes(ACL_REVISION, 0, 28, 0xFFFF, 0, &ALLOW_EVERYONE);
    assert_eq!(Acl::decode(&bytes), Err(Error::AceCountExceedsAclSize));
    // Two ACEs claimed, room for one and a bit: the second runs past AclSize.
    let mut aces = ALLOW_EVERYONE.to_vec();
    aces.extend_from_slice(&ALLOW_EVERYONE[..8]);
    let bytes = acl_bytes(ACL_REVISION, 0, 36, 2, 0, &aces);
    assert_eq!(Acl::decode(&bytes), Err(Error::AceCountExceedsAclSize));
    // One ACE, but AclSize leaves 4 unaccounted bytes inside the ACL.
    let mut slack = ALLOW_EVERYONE.to_vec();
    slack.extend_from_slice(&[0; 4]);
    let bytes = acl_bytes(ACL_REVISION, 0, 32, 1, 0, &slack);
    assert_eq!(Acl::decode(&bytes), Err(Error::AclSizeMismatch));
    // AceCount 0 with ACE bytes inside AclSize.
    let bytes = acl_bytes(ACL_REVISION, 0, 28, 0, 0, &ALLOW_EVERYONE);
    assert_eq!(Acl::decode(&bytes), Err(Error::AclSizeMismatch));
}

#[test]
fn reject_type_not_permitted_by_revision() {
    // Source: [MS-DTYP] 2.4.5 — under ACL_REVISION "only AceTypes 0x00, 0x01,
    // 0x02, 0x03, 0x11, 0x12, and 0x13 can be present".
    let object = Ace::AccessAllowedObject(ObjectAce {
        ace_flags: 0,
        mask: AccessMask(AccessMask::ADS_RIGHT_DS_READ_PROP),
        object_type: None,
        inherited_object_type: None,
        sid: sid("S-1-1-0"),
    })
    .encode()
    .unwrap();
    let bytes = acl_bytes(ACL_REVISION, 0, (8 + object.len()) as u16, 1, 0, &object);
    assert_eq!(
        Acl::decode(&bytes),
        Err(Error::AceTypeNotPermittedByAclRevision)
    );
    // A callback ACE (0x09) is not in the ACL_REVISION list either.
    let mut callback = ALLOW_EVERYONE;
    callback[0] = ace_type::ACCESS_ALLOWED_CALLBACK_ACE_TYPE;
    let bytes = acl_bytes(ACL_REVISION, 0, 28, 1, 0, &callback);
    assert_eq!(
        Acl::decode(&bytes),
        Err(Error::AceTypeNotPermittedByAclRevision)
    );
    // Nor in the ACL_REVISION_DS set (Q-022).
    let bytes = acl_bytes(ACL_REVISION_DS, 0, 28, 1, 0, &callback);
    assert_eq!(
        Acl::decode(&bytes),
        Err(Error::AceTypeNotPermittedByAclRevision)
    );
    // The encoder applies the same rules: an object ACE under ACL_REVISION.
    let acl = Acl {
        acl_revision: ACL_REVISION,
        aces: vec![Ace::decode(&object).unwrap()],
    };
    assert_eq!(acl.encode(), Err(Error::AceTypeNotPermittedByAclRevision));
    let acl = Acl {
        acl_revision: 3,
        aces: Vec::new(),
    };
    assert_eq!(acl.encode(), Err(Error::AclRevision));
}

#[test]
fn sacl_and_dacl_type_rules() {
    // Source: [MS-DTYP] 2.4.5 — the only valid SACL ACE types are 0x02, 0x07,
    // 0x0D, 0x0F, 0x11, 0x12, 0x13; the DACL MUST NOT contain those; 2.4.3 —
    // ACCESS_SYSTEM_SECURITY MUST NOT be set in a DACL ACE.
    let dacl_like = Acl::decode(&EXAMPLE_DACL).unwrap();
    assert_eq!(dacl_like.check_sacl(), Err(Error::AceTypeNotValidInSacl));
    let sacl_like = Acl::decode(&EXAMPLE_SACL).unwrap();
    assert_eq!(sacl_like.check_dacl(), Err(Error::AceTypeNotValidInDacl));
    let with_as = Acl {
        acl_revision: ACL_REVISION,
        aces: vec![allowed(AccessMask::ACCESS_SYSTEM_SECURITY, "S-1-1-0")],
    };
    assert_eq!(with_as.check_dacl(), Err(Error::AccessSystemSecurityInDacl));
    // In a SACL audit ACE, ACCESS_SYSTEM_SECURITY is meaningful (2.4.3).
    let audit_as = Acl {
        acl_revision: ACL_REVISION,
        aces: vec![Ace::SystemAudit(MaskSidAce {
            ace_flags: 0x80,
            mask: AccessMask(AccessMask::ACCESS_SYSTEM_SECURITY),
            sid: sid("S-1-1-0"),
        })],
    };
    assert_eq!(audit_as.check_sacl(), Ok(()));
}

#[test]
fn encoder_refuses_oversized_acl() {
    // Source: [MS-DTYP] 2.4.5 — AclSize is an unsigned 16-bit integer.
    // 3277 ACEs of 20 bytes = 65548 bytes including the header.
    let acl = Acl {
        acl_revision: ACL_REVISION,
        aces: vec![allowed(AccessMask::READ_CONTROL, "S-1-1-0"); 3277],
    };
    assert_eq!(acl.encode(), Err(Error::AclTooLarge));
    // 3276 ACEs = 65528 bytes: fits.
    let acl = Acl {
        acl_revision: ACL_REVISION,
        aces: vec![allowed(AccessMask::READ_CONTROL, "S-1-1-0"); 3276],
    };
    let bytes = acl.encode().unwrap();
    assert_eq!(bytes.len(), 65528);
    assert_eq!(Acl::decode(&bytes).unwrap(), acl);
}
