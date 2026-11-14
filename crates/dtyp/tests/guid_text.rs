//! The GUID text form ([`dtyp::Guid::parse_text`], [`dtyp::Guid::to_text`]).
//!
//! The vectors are the ones crates/ad-schema (`guid.rs`, A-31) and
//! crates/provision-manifest (Q-345 item 5) used before the mapping moved
//! here (A-86 follow-up, task F7); each test names its source.

use dtyp::{Error, Guid, GUID_TEXT_LEN};

/// The packet of the [MS-DRSR] 5.16.3.16 example.
const DRSR_PACKET: [u8; 16] = [
    0x53, 0x1a, 0x72, 0xab, 0x2f, 0x1e, 0xd0, 0x11, 0x98, 0x19, 0x00, 0xaa, 0x00, 0x40, 0x52, 0x9b,
];

/// The text of the [MS-DRSR] 5.16.3.16 example.
const DRSR_TEXT: &str = "ab721a53-1e2f-11d0-9819-00aa0040529b";

// Source: [MS-DRSR] v20260309 5.16.3.16 (String(NT-Sec-Desc)) — the printed
// example: "Object Ace Type: Change Password-
// ab721a53-1e2f-11d0-9819-00aa0040529b", whose bytes in the printed payload
// are 53 1a 72 ab 2f 1e d0 11 98 19 00 aa 00 40 52 9b ([MS-DTYP] 2.3.4.2:
// Data1-Data3 little-endian, Data4 in array order).
#[test]
fn drsr_example_text_to_packet_and_back() {
    let guid = Guid::parse_text(DRSR_TEXT).unwrap();
    assert_eq!(guid.to_packet(), DRSR_PACKET);
    assert_eq!(guid.data1, 0xab72_1a53);
    assert_eq!(guid.data2, 0x1e2f);
    assert_eq!(guid.data3, 0x11d0);
    assert_eq!(guid.data4, [0x98, 0x19, 0x00, 0xaa, 0x00, 0x40, 0x52, 0x9b]);
    assert_eq!(Guid::from_packet(&DRSR_PACKET).to_text(), DRSR_TEXT);
}

// Source: [MS-DTYP] 2.5.1.1 (the `guid` production: exactly 8-4-4-4-12 hex
// digits); lower case only (one spelling per value, A-31). The cases are
// crates/ad-schema's `malformed_strings_are_refused` and crates/provision-
// manifest's GUID rejections.
#[test]
fn malformed_text_is_refused() {
    for bad in [
        "",
        "ab721a53-1e2f-11d0-9819-00aa0040529",
        "ab721a53-1e2f-11d0-9819-00aa0040529b0",
        "ab721a53x1e2f-11d0-9819-00aa0040529b",
        "ab721a531-e2f-11d0-9819-00aa0040529b",
        "AB721A53-1E2F-11D0-9819-00AA0040529B",
        "ab721a53-1e2f-11d0-9819-00aa0040529B",
        "{b721a53-1e2f-11d0-9819-00aa0040529b",
        "+b721a53-1e2f-11d0-9819-00aa0040529b",
        "ab721a53-1e2f-11d0-9819-00aa0040529\u{e9}",
        "ab721a53-1e2f-11d0-9819+00aa0040529b",
        "ab721a53-1e2f-11d0-98190-0aa0040529b",
        "g0000000-0000-0000-0000-000000000001",
    ] {
        assert_eq!(Guid::parse_text(bad), Err(Error::GuidTextSyntax), "{bad:?}");
    }
}

// Source: [MS-DTYP] 2.5.1.1 (8 + 4 + 4 + 4 + 12 digits and four "-").
#[test]
fn the_text_is_36_octets() {
    assert_eq!(GUID_TEXT_LEN, 36);
    assert_eq!(DRSR_TEXT.len(), GUID_TEXT_LEN);
}

// Source: [MS-DTYP] 2.3.4.2 (any 16 octets are a GUID packet) — the text
// form is a bijection on GUIDs: to_text then parse_text is the identity,
// and the text is always lower case and 36 octets. The NULL GUID is a GUID
// (refusing it is the caller's rule).
#[test]
fn every_guid_round_trips() {
    for packet in [
        [0u8; 16],
        [0xff; 16],
        DRSR_PACKET,
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
    ] {
        let guid = Guid::from_packet(&packet);
        let text = guid.to_text();
        assert_eq!(text.len(), GUID_TEXT_LEN);
        assert!(!text.bytes().any(|b| b.is_ascii_uppercase()), "{text}");
        assert_eq!(Guid::parse_text(&text), Ok(guid));
    }
    assert_eq!(
        Guid::from_packet(&[0u8; 16]).to_text(),
        "00000000-0000-0000-0000-000000000000"
    );
}
