//! GUID packet tests.
//!
//! Source: byte sequences hand-derived from [MS-DTYP] v20241119 2.3.4.1 /
//! 2.3.4.2 (Data1, Data2, Data3 little-endian; Data4 eight bytes in array
//! order). No vector comes from any other implementation.

use dtyp::{Error, Guid, GUID_PACKET_LEN};

#[test]
fn packet_field_order_and_byte_order() {
    // Source: [MS-DTYP] 2.3.4.2, hand-derived with distinct byte values.
    let packet: [u8; GUID_PACKET_LEN] = [
        0x00, 0x01, 0x02, 0x03, // Data1, little-endian
        0x04, 0x05, // Data2, little-endian
        0x06, 0x07, // Data3, little-endian
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, // Data4
    ];
    let guid = Guid::from_packet(&packet);
    assert_eq!(
        guid,
        Guid {
            data1: 0x0302_0100,
            data2: 0x0504,
            data3: 0x0706,
            data4: [0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F],
        }
    );
    assert_eq!(guid.to_packet(), packet);
    assert_eq!(Guid::decode(&packet).unwrap(), guid);
}

#[test]
fn round_trip_from_fields() {
    // Source: [MS-DTYP] 2.3.4.2 — encode then decode is the identity.
    let guid = Guid {
        data1: 0xDEAD_BEEF,
        data2: 0x1234,
        data3: 0xABCD,
        data4: [1, 2, 3, 4, 5, 6, 7, 8],
    };
    let packet = guid.to_packet();
    assert_eq!(&packet[0..4], &[0xEF, 0xBE, 0xAD, 0xDE]);
    assert_eq!(&packet[4..6], &[0x34, 0x12]);
    assert_eq!(&packet[6..8], &[0xCD, 0xAB]);
    assert_eq!(&packet[8..16], &[1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(Guid::from_packet(&packet), guid);
}

#[test]
fn reject_wrong_length() {
    // Source: [MS-DTYP] 2.3.4 — "a 16-byte structure".
    assert_eq!(Guid::decode(&[0u8; 15]), Err(Error::GuidLength));
    assert_eq!(Guid::decode(&[0u8; 17]), Err(Error::GuidLength));
    assert_eq!(Guid::decode(&[]), Err(Error::GuidLength));
}
