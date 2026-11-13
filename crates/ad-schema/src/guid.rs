//! The GUID strings of the schema tables → [`dtyp::Guid`].
//!
//! [MS-ADSC] / [MS-ADA1-3] print schemaIdGuid and attributeSecurityGuid as
//! `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`. Our `dtyp` crate deliberately has
//! no string form: [MS-DTYP] 2.3.4.3 defines its curly-braced form only by
//! reference to RFC 4122, which is not an allowed source. This helper is
//! derived from allowed text only:
//!
//! - the layout: [MS-DTYP] 2.5.1.1, SDDL ABNF `guid = 8HEXDIG "-" 4HEXDIG
//!   "-" 4HEXDIG "-" 4HEXDIG "-" 12HEXDIG`;
//! - the fields: [MS-DTYP] 2.3.4.1 (Data1 `unsigned long`, Data2 / Data3
//!   `unsigned short`, Data4 `byte[8]`) and 2.3.4.2 (packet: Data1, Data2,
//!   Data3 little-endian, then Data4 in array order);
//! - which group is which field: the printed example of [MS-DRSR] 5.16.3.16
//!   (String(NT-Sec-Desc)), where the object ACE type
//!   `ab721a53-1e2f-11d0-9819-00aa0040529b` is the packet
//!   `53 1a 72 ab 2f 1e d0 11 98 19 00 aa 00 40 52 9b` — so group 1 is
//!   Data1, group 2 Data2, group 3 Data3 (each the hexadecimal value of the
//!   member), and groups 4 + 5 are the eight Data4 bytes in array order.
//!
//! Only the lowercase form the tables carry (as printed in [MS-ADSC] /
//! [MS-ADA*]) is accepted. Recorded for review in Q-100.

use dtyp::Guid;

/// Length of the string form. Spec: [MS-DTYP] 2.5.1.1 (8+4+4+4+12 hex digits
/// and four "-").
const GUID_STRING_LEN: usize = 36;

/// Byte offsets of the four "-". Spec: [MS-DTYP] 2.5.1.1.
const DASHES: [usize; 4] = [8, 13, 18, 23];

/// Byte offsets of the eight two-digit Data4 bytes (groups 4 and 5).
/// Spec: [MS-DTYP] 2.5.1.1; [MS-DRSR] 5.16.3.16 example.
const DATA4_AT: [usize; 8] = [19, 21, 24, 26, 28, 30, 32, 34];

/// The hexadecimal value of `s[start..end]` (already checked to be hex).
fn hex(s: &str, start: usize, end: usize) -> Option<u32> {
    u32::from_str_radix(s.get(start..end)?, 16).ok()
}

/// Parse a schema-table GUID string; `None` if it is not exactly the
/// lowercase `8-4-4-4-12` hex form. Spec: see the module docs.
pub(crate) fn parse_guid(s: &str) -> Option<Guid> {
    if s.len() != GUID_STRING_LEN {
        return None;
    }
    for (i, c) in s.bytes().enumerate() {
        let well_formed = if DASHES.contains(&i) {
            c == b'-'
        } else {
            matches!(c, b'0'..=b'9' | b'a'..=b'f')
        };
        if !well_formed {
            return None;
        }
    }
    let mut data4 = [0u8; 8];
    for (byte, at) in data4.iter_mut().zip(DATA4_AT) {
        *byte = u8::try_from(hex(s, at, at + 2)?).ok()?;
    }
    Some(Guid {
        data1: hex(s, 0, 8)?,
        data2: u16::try_from(hex(s, 9, 13)?).ok()?,
        data3: u16::try_from(hex(s, 14, 18)?).ok()?,
        data4,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Source: [MS-DRSR] v20260309 5.16.3.16 (String(NT-Sec-Desc)) — the
    // printed example: "Object Ace Type: Change Password-
    // ab721a53-1e2f-11d0-9819-00aa0040529b", whose bytes in the printed
    // payload are 53 1a 72 ab 2f 1e d0 11 98 19 00 aa 00 40 52 9b.
    #[test]
    fn drsr_example_string_to_packet() {
        let g = parse_guid("ab721a53-1e2f-11d0-9819-00aa0040529b").unwrap();
        assert_eq!(
            g.to_packet(),
            [
                0x53, 0x1a, 0x72, 0xab, 0x2f, 0x1e, 0xd0, 0x11, 0x98, 0x19, 0x00, 0xaa, 0x00, 0x40,
                0x52, 0x9b
            ]
        );
    }

    // Source: [MS-DTYP] 2.5.1.1 (the `guid` production: exactly 8-4-4-4-12
    // hex digits); lowercase only (module docs).
    #[test]
    fn malformed_strings_are_refused() {
        for bad in [
            "",
            "ab721a53-1e2f-11d0-9819-00aa0040529",
            "ab721a53-1e2f-11d0-9819-00aa0040529b0",
            "ab721a53x1e2f-11d0-9819-00aa0040529b",
            "ab721a531-e2f-11d0-9819-00aa0040529b",
            "AB721A53-1E2F-11D0-9819-00AA0040529B",
            "{b721a53-1e2f-11d0-9819-00aa0040529b",
            "+b721a53-1e2f-11d0-9819-00aa0040529b",
            "ab721a53-1e2f-11d0-9819-00aa0040529\u{e9}",
        ] {
            assert_eq!(parse_guid(bad), None, "{bad}");
        }
    }
}
