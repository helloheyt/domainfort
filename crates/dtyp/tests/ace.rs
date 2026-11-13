//! ACE tests.
//!
//! Every vector names its source: ACE bytes from the worked example in
//! [MS-DTYP] v20241119 2.5.1.4, or byte sequences hand-derived from the named
//! clause of [MS-DTYP] 2.4.4.x (little-endian per 2.4.6). No vector comes from
//! any other implementation.

use dtyp::{
    ace_flags, ace_type, AccessMask, Ace, Error, Guid, MaskSidAce, ObjectAce, Sid, UnsupportedAce,
    MAX_ACE_SIZE,
};

fn sid(text: &str) -> Sid {
    Sid::parse_sid_string(text).unwrap()
}

/// Decode, compare, and re-encode to the same bytes.
fn assert_round_trip(bytes: &[u8], expected: &Ace) {
    let decoded = Ace::decode(bytes).expect("vector must decode");
    assert_eq!(&decoded, expected);
    assert_eq!(expected.encode().unwrap(), bytes);
    assert_eq!(expected.encoded_len().unwrap(), bytes.len());
}

/// GUID with distinct bytes, for hand-derived object ACEs ([MS-DTYP] 2.3.4.2).
fn guid_a() -> (Guid, [u8; 16]) {
    let packet = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F,
    ];
    (Guid::from_packet(&packet), packet)
}

fn guid_b() -> (Guid, [u8; 16]) {
    let packet = [
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E,
        0x2F,
    ];
    (Guid::from_packet(&packet), packet)
}

/// S-1-1-0 as a packet ([MS-DTYP] 2.5.1.4, SACL trustee "WD").
const EVERYONE: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];

#[test]
fn access_allowed_ace_from_the_worked_example() {
    // Source: [MS-DTYP] 2.5.1.4 — "(A;CIOI;GRGX;;;BU)" maps to
    //   00 03 18 00 00 00 00 a0 01 02 00 00 00 00 00 05 20 00 00 00 21 02 00 00
    let bytes = [
        0x00, 0x03, 0x18, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x05, 0x20, 0x00, 0x00, 0x00, 0x21, 0x02, 0x00, 0x00,
    ];
    let expected = Ace::AccessAllowed(MaskSidAce {
        ace_flags: ace_flags::OBJECT_INHERIT_ACE | ace_flags::CONTAINER_INHERIT_ACE,
        mask: AccessMask(AccessMask::GENERIC_READ | AccessMask::GENERIC_EXECUTE),
        sid: sid("S-1-5-32-545"),
    });
    assert_round_trip(&bytes, &expected);
    assert_eq!(expected.ace_type(), ace_type::ACCESS_ALLOWED_ACE_TYPE);
}

#[test]
fn system_audit_ace_from_the_worked_example() {
    // Source: [MS-DTYP] 2.5.1.4 — SACL "(AU;FA;GR;;;WD)" at offset 0x1c:
    //   02 80 14 00 00 00 00 80 01 01 00 00 00 00 00 01 00 00 00 00
    let bytes = [
        0x02, 0x80, 0x14, 0x00, 0x00, 0x00, 0x00, 0x80, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00,
    ];
    let expected = Ace::SystemAudit(MaskSidAce {
        ace_flags: ace_flags::FAILED_ACCESS_ACE_FLAG,
        mask: AccessMask(AccessMask::GENERIC_READ),
        sid: sid("S-1-1-0"),
    });
    assert_round_trip(&bytes, &expected);
}

#[test]
fn access_denied_ace() {
    // Source: [MS-DTYP] 2.4.4.4 (Header, Mask, Sid), hand-derived:
    // type 0x01, flags INHERITED_ACE, size 0x14, mask WRITE_DACL, Sid S-1-1-0.
    let mut bytes = vec![0x01, 0x10, 0x14, 0x00, 0x00, 0x00, 0x04, 0x00];
    bytes.extend_from_slice(&EVERYONE);
    let expected = Ace::AccessDenied(MaskSidAce {
        ace_flags: ace_flags::INHERITED_ACE,
        mask: AccessMask(AccessMask::WRITE_DACL),
        sid: sid("S-1-1-0"),
    });
    assert_round_trip(&bytes, &expected);
}

#[test]
fn object_ace_presence_flags() {
    // Source: [MS-DTYP] 2.4.4.3 — Flags bit 0x1 = ObjectType present, 0x2 =
    // InheritedObjectType present; each field "is present only if" its bit is
    // set, so the Sid follows whatever is present. Hand-derived for all four
    // Flags values, mask ADS_RIGHT_DS_READ_PROP.
    let (ga, pa) = guid_a();
    let (gb, pb) = guid_b();
    let cases: [(u32, Option<Guid>, Option<Guid>); 4] = [
        (0, None, None),
        (1, Some(ga), None),
        (2, None, Some(gb)),
        (3, Some(ga), Some(gb)),
    ];
    for (flags, object_type, inherited_object_type) in cases {
        let mut body = Vec::new();
        body.extend_from_slice(&0x0000_0010u32.to_le_bytes()); // Mask
        body.extend_from_slice(&flags.to_le_bytes()); // Flags
        if object_type.is_some() {
            body.extend_from_slice(&pa);
        }
        if inherited_object_type.is_some() {
            body.extend_from_slice(&pb);
        }
        body.extend_from_slice(&EVERYONE);
        let size = 4 + body.len();
        let mut bytes = vec![
            ace_type::ACCESS_ALLOWED_OBJECT_ACE_TYPE,
            ace_flags::CONTAINER_INHERIT_ACE,
        ];
        bytes.extend_from_slice(&(size as u16).to_le_bytes());
        bytes.extend_from_slice(&body);
        let expected = Ace::AccessAllowedObject(ObjectAce {
            ace_flags: ace_flags::CONTAINER_INHERIT_ACE,
            mask: AccessMask(AccessMask::ADS_RIGHT_DS_READ_PROP),
            object_type,
            inherited_object_type,
            sid: sid("S-1-1-0"),
        });
        assert_round_trip(&bytes, &expected);
        assert_eq!(size, 12 + 16 * (flags.count_ones() as usize) + 12);
    }
}

#[test]
fn access_denied_object_ace() {
    // Source: [MS-DTYP] 2.4.4.5, hand-derived: ObjectType only, mask
    // ADS_RIGHT_DS_CONTROL_ACCESS, Sid S-1-5-18.
    let (ga, pa) = guid_a();
    let mut bytes = vec![0x06, 0x00, 0x28, 0x00];
    bytes.extend_from_slice(&0x0000_0100u32.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&pa);
    bytes.extend_from_slice(&[1, 1, 0, 0, 0, 0, 0, 5, 0x12, 0, 0, 0]);
    let expected = Ace::AccessDeniedObject(ObjectAce {
        ace_flags: 0,
        mask: AccessMask(AccessMask::ADS_RIGHT_DS_CONTROL_ACCESS),
        object_type: Some(ga),
        inherited_object_type: None,
        sid: sid("S-1-5-18"),
    });
    assert_round_trip(&bytes, &expected);
}

#[test]
fn system_audit_object_ace_keeps_application_data() {
    // Source: [MS-DTYP] 2.4.4.11 — ApplicationData "determined by the AceSize
    // field". Hand-derived: no GUIDs, Sid S-1-1-0, 4 bytes of data.
    let mut bytes = vec![0x07, 0x40, 0x1C, 0x00];
    bytes.extend_from_slice(&0x0000_0020u32.to_le_bytes()); // Mask
    bytes.extend_from_slice(&0u32.to_le_bytes()); // Flags
    bytes.extend_from_slice(&EVERYONE);
    bytes.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
    let expected = Ace::SystemAuditObject {
        ace: ObjectAce {
            ace_flags: ace_flags::SUCCESSFUL_ACCESS_ACE_FLAG,
            mask: AccessMask(AccessMask::ADS_RIGHT_DS_WRITE_PROP),
            object_type: None,
            inherited_object_type: None,
            sid: sid("S-1-1-0"),
        },
        application_data: vec![0xAA, 0xBB, 0xCC, 0xDD],
    };
    assert_round_trip(&bytes, &expected);
}

#[test]
fn unsupported_types_are_preserved_whole() {
    // Source: [MS-DTYP] 2.4.4.1 AceType table. Hand-derived:
    //  - 0x11 SYSTEM_MANDATORY_LABEL_ACE (2.4.4.13: Header, Mask, Sid) with
    //    Sid S-1-16-12288 (ML_HIGH, 2.4.2.4);
    //  - 0x09 ACCESS_ALLOWED_CALLBACK_ACE (2.4.4.6) with 4 ApplicationData bytes;
    //  - 0x03 SYSTEM_ALARM_ACE_TYPE ("reserved for future use"), empty body.
    let label_body: Vec<u8> = [
        &[0x01, 0x00, 0x00, 0x00][..],
        &[1, 1, 0, 0, 0, 0, 0, 0x10, 0x00, 0x30, 0x00, 0x00][..],
    ]
    .concat();
    let callback_body: Vec<u8> = [
        &[0x00, 0x00, 0x00, 0x10][..],
        &EVERYONE[..],
        &[0x61, 0x72, 0x74, 0x78][..],
    ]
    .concat();
    let cases: [(u8, u8, Vec<u8>); 3] = [
        (ace_type::SYSTEM_MANDATORY_LABEL_ACE_TYPE, 0x00, label_body),
        (
            ace_type::ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
            0x03,
            callback_body,
        ),
        (ace_type::SYSTEM_ALARM_ACE_TYPE, 0x00, Vec::new()),
    ];
    for (t, f, body) in cases {
        let mut bytes = vec![t, f];
        bytes.extend_from_slice(&((4 + body.len()) as u16).to_le_bytes());
        bytes.extend_from_slice(&body);
        let expected = Ace::Unsupported(UnsupportedAce {
            ace_type: t,
            ace_flags: f,
            body,
        });
        assert_round_trip(&bytes, &expected);
        assert_eq!(
            expected.mask(),
            None,
            "unsupported ACE bytes are not interpreted"
        );
    }
}

#[test]
fn padding_inside_ace_size_is_ignored_and_canonicalised() {
    // Source: [MS-DTYP] 2.4.4.1 — AceSize "can be greater than the sum of the
    // individual fields"; that additional data "is not interpreted and MUST be
    // ignored". Hand-derived from the 2.5.1.4 ACE with AceSize 0x1C and four
    // extra bytes.
    let minimal = [
        0x00, 0x03, 0x18, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x05, 0x20, 0x00, 0x00, 0x00, 0x21, 0x02, 0x00, 0x00,
    ];
    let mut padded = minimal.to_vec();
    padded[2] = 0x1C;
    padded.extend_from_slice(&[0xEE; 4]);
    let a = Ace::decode(&padded).unwrap();
    assert_eq!(a, Ace::decode(&minimal).unwrap());
    assert_eq!(a.encode().unwrap(), minimal);
}

#[test]
fn reject_header_rules() {
    // Source: [MS-DTYP] 2.4.4.1, rule by rule (hand-derived).
    let mut good = vec![0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x10];
    good.extend_from_slice(&EVERYONE);
    assert!(Ace::decode(&good).is_ok());

    // Fewer than the 4 header bytes.
    assert_eq!(Ace::decode(&good[..3]), Err(Error::AceTruncated));
    // AceSize beyond the input.
    assert_eq!(Ace::decode(&good[..19]), Err(Error::AceTruncated));
    // AceType outside the table (0x14 is the first undefined value).
    let mut t = good.clone();
    t[0] = 0x14;
    assert_eq!(Ace::decode(&t), Err(Error::AceTypeUndefined));
    t[0] = 0xFF;
    assert_eq!(Ace::decode(&t), Err(Error::AceTypeUndefined));
    // AceFlags bit 0x20 is not in the flag table.
    let mut f = good.clone();
    f[1] = 0x20;
    assert_eq!(Ace::decode(&f), Err(Error::AceFlagsUndefined));
    // AceSize smaller than its own header.
    let mut s = good.clone();
    s[2] = 0x00;
    assert_eq!(Ace::decode(&s), Err(Error::AceSizeTooSmall));
    // AceSize MUST be a multiple of 4.
    let mut m = good.clone();
    m[2] = 0x13;
    assert_eq!(Ace::decode(&m), Err(Error::AceSizeNotMultipleOf4));
    // Strict framing for a stand-alone ACE.
    let mut trailing = good.clone();
    trailing.extend_from_slice(&[0, 0, 0, 0]);
    assert_eq!(Ace::decode(&trailing), Err(Error::TrailingData));
}

#[test]
fn reject_body_rules() {
    // Source: [MS-DTYP] 2.4.4.2 — Header, Mask, Sid must fit in AceSize.
    // AceSize 8 leaves room for the Mask but not the Sid.
    assert_eq!(
        Ace::decode(&[0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x10]),
        Err(Error::AceSizeTooSmall)
    );
    // AceSize 0x10 cuts the 12-byte Sid short.
    let mut cut = vec![0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x10];
    cut.extend_from_slice(&EVERYONE[..8]);
    assert_eq!(Ace::decode(&cut), Err(Error::AceSizeTooSmall));
    // Source: [MS-DTYP] 2.4.2.2 — the trustee Sid's Revision MUST be 1.
    let mut bad_sid = vec![0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x10];
    bad_sid.extend_from_slice(&EVERYONE);
    bad_sid[8] = 0x02;
    assert_eq!(Ace::decode(&bad_sid), Err(Error::SidRevision));

    // Source: [MS-DTYP] 2.4.4.3 — Flags is one or more of 0x1 / 0x2.
    let mut flags = vec![
        0x05, 0x00, 0x18, 0x00, 0x10, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
    ];
    flags.extend_from_slice(&EVERYONE);
    assert_eq!(Ace::decode(&flags), Err(Error::ObjectAceFlagsUndefined));
    // ObjectType flagged present but AceSize leaves no room for 16 bytes.
    let mut short = vec![
        0x05, 0x00, 0x18, 0x00, 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    ];
    short.extend_from_slice(&EVERYONE);
    assert_eq!(Ace::decode(&short), Err(Error::AceSizeTooSmall));
}

#[test]
fn encoder_refuses_non_canonical_values() {
    // Source: [MS-DTYP] 2.4.4.1 (defined AceType / AceFlags; AceSize a 16-bit
    // multiple of 4) and the one-encoding-per-value rule of this crate.
    let typed_as_unsupported = Ace::Unsupported(UnsupportedAce {
        ace_type: ace_type::ACCESS_ALLOWED_ACE_TYPE,
        ace_flags: 0,
        body: vec![0; 16],
    });
    assert_eq!(
        typed_as_unsupported.encode(),
        Err(Error::UnsupportedAceHasSupportedType)
    );
    let undefined = Ace::Unsupported(UnsupportedAce {
        ace_type: 0x14,
        ace_flags: 0,
        body: Vec::new(),
    });
    assert_eq!(undefined.encode(), Err(Error::AceTypeUndefined));
    let unaligned = Ace::Unsupported(UnsupportedAce {
        ace_type: ace_type::SYSTEM_ALARM_ACE_TYPE,
        ace_flags: 0,
        body: vec![0; 3],
    });
    assert_eq!(unaligned.encode(), Err(Error::AceSizeNotMultipleOf4));
    let huge = Ace::Unsupported(UnsupportedAce {
        ace_type: ace_type::SYSTEM_ALARM_ACE_TYPE,
        ace_flags: 0,
        body: vec![0; MAX_ACE_SIZE],
    });
    assert_eq!(huge.encode(), Err(Error::AceTooLarge));
    let bad_flags = Ace::AccessAllowed(MaskSidAce {
        ace_flags: 0x20,
        mask: AccessMask(0),
        sid: sid("S-1-1-0"),
    });
    assert_eq!(bad_flags.encode(), Err(Error::AceFlagsUndefined));
    let odd_data = Ace::SystemAuditObject {
        ace: ObjectAce {
            ace_flags: 0,
            mask: AccessMask(0),
            object_type: None,
            inherited_object_type: None,
            sid: sid("S-1-1-0"),
        },
        application_data: vec![1, 2],
    };
    assert_eq!(odd_data.encode(), Err(Error::AceSizeNotMultipleOf4));
    // On error nothing is appended.
    let mut out = vec![0xAB];
    assert!(huge.encode_into(&mut out).is_err());
    assert_eq!(out, vec![0xAB]);
}

#[test]
fn access_mask_bit_values() {
    // Source: [MS-DTYP] 2.4.3 Figure 2 (position 0 = most significant bit,
    // per 2.1) and value table; 2.5.1.1 rights tables ("GW" = 0x40000000);
    // 2.4.4.3 ADS_RIGHT_DS_* table.
    assert_eq!(AccessMask::GENERIC_READ, 1 << 31); // position 0
    assert_eq!(AccessMask::GENERIC_WRITE, 1 << 30); // position 1
    assert_eq!(AccessMask::GENERIC_EXECUTE, 1 << 29); // position 2
    assert_eq!(AccessMask::GENERIC_ALL, 1 << 28); // position 3
    assert_eq!(AccessMask::MAXIMUM_ALLOWED, 1 << 25); // position 6
    assert_eq!(AccessMask::ACCESS_SYSTEM_SECURITY, 1 << 24); // position 7
    assert_eq!(AccessMask::SYNCHRONIZE, 1 << 20); // position 11
    assert_eq!(AccessMask::WRITE_OWNER, 1 << 19); // position 12
    assert_eq!(AccessMask::WRITE_DACL, 1 << 18); // position 13
    assert_eq!(AccessMask::READ_CONTROL, 1 << 17); // position 14
    assert_eq!(AccessMask::DELETE, 1 << 16); // position 15
    assert_eq!(AccessMask::ADS_RIGHT_DS_CREATE_CHILD, 0x01);
    assert_eq!(AccessMask::ADS_RIGHT_DS_DELETE_CHILD, 0x02);
    assert_eq!(AccessMask::DIRECTORY_OBJECT_LIST_CHILDREN, 0x04);
    assert_eq!(AccessMask::ADS_RIGHT_DS_SELF, 0x08);
    assert_eq!(AccessMask::ADS_RIGHT_DS_READ_PROP, 0x10);
    assert_eq!(AccessMask::ADS_RIGHT_DS_WRITE_PROP, 0x20);
    assert_eq!(AccessMask::DIRECTORY_OBJECT_DELETE_TREE, 0x40);
    assert_eq!(AccessMask::DIRECTORY_OBJECT_LIST_OBJECT, 0x80);
    assert_eq!(AccessMask::ADS_RIGHT_DS_CONTROL_ACCESS, 0x100);
    // The 2.5.1.4 example ACE mask "GRGX" is 0xA0000000.
    assert!(AccessMask(0xA000_0000).contains(AccessMask::GENERIC_READ));
    assert!(AccessMask(0xA000_0000).contains(AccessMask::GENERIC_EXECUTE));
    assert!(!AccessMask(0xA000_0000).contains(AccessMask::GENERIC_WRITE));
}
