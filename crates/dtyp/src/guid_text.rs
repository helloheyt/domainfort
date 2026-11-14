//! GUID — the lower-case `8-4-4-4-12` text form.
//!
//! [MS-DTYP] 2.3.4.3 defines the curly-braced GUID string only by reference
//! to RFC 4122, which is not an allowed source (specs/SOURCES.md), so this
//! crate has no curly-braced form. The text form here is derived from
//! allowed text only — the route decision A-31 accepted (docs/questions/Q-100
//! item 1) and Q-345 item 5 re-derived; one copy for the whole workspace
//! (A-86 follow-up: crates/ad-schema and crates/provision-manifest each had
//! their own):
//!
//! * the layout: [MS-DTYP] 2.5.1.1, the SDDL ABNF production
//!   `guid = "" / 8HEXDIG "-" 4HEXDIG "-" 4HEXDIG "-" 4HEXDIG "-" 12HEXDIG`
//!   ("the GUID of the object in the form XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
//!   Where each "X" is a Hex digit") — its second option;
//! * the fields: [MS-DTYP] 2.3.4.1 (Data1 `unsigned long`, Data2 / Data3
//!   `unsigned short`, Data4 `byte[8]`) and 2.3.4.2 (the packet: Data1,
//!   Data2, Data3 little-endian, then Data4 in array order);
//! * which group is which field: the printed example of [MS-DRSR] 5.16.3.16
//!   (String(NT-Sec-Desc)), where the object ACE type printed as
//!   `ab721a53-1e2f-11d0-9819-00aa0040529b` is carried in the payload as the
//!   packet `53 1a 72 ab 2f 1e d0 11 98 19 00 aa 00 40 52 9b` — so group 1 is
//!   the hexadecimal value of Data1, group 2 of Data2, group 3 of Data3, and
//!   groups 4 and 5 are the eight Data4 octets in array order.
//!
//! Only lower-case hexadecimal digits are accepted and produced: one
//! spelling per value (the [MS-DRSR] example and the [MS-ADSC] / [MS-ADA*]
//! tables print lower case). The NULL GUID is a valid text here; a caller
//! that refuses it (an objectGUID "MUST NOT be the NULL GUID") checks that
//! itself.
//!
//! Spec: [MS-DTYP] 2.3.4.1, 2.3.4.2, 2.5.1.1; [MS-DRSR] 5.16.3.16;
//! PENDING-OWNER A-31, A-86.

use crate::error::{Error, Result};
use crate::guid::Guid;

/// Length of the text form: 8 + 4 + 4 + 4 + 12 hexadecimal digits and four
/// "-". Spec: [MS-DTYP] 2.5.1.1 (the `guid` production).
pub const GUID_TEXT_LEN: usize = 36;

/// Offsets of the four "-". Spec: [MS-DTYP] 2.5.1.1.
const DASHES: [usize; 4] = [8, 13, 18, 23];

/// Offsets of the eight two-digit Data4 octets (groups 4 and 5).
/// Spec: [MS-DTYP] 2.5.1.1; [MS-DRSR] 5.16.3.16 (the printed example).
const DATA4_AT: [usize; 8] = [19, 21, 24, 26, 28, 30, 32, 34];

/// Whether `c` is a lower-case hexadecimal digit (the one spelling
/// accepted; module documentation).
const fn is_lower_hex(c: u8) -> bool {
    matches!(c, b'0'..=b'9' | b'a'..=b'f')
}

/// The value of the hexadecimal digits `text[start..end]` (already checked
/// to be lower-case hexadecimal digits).
fn hex(text: &str, start: usize, end: usize) -> Result<u32> {
    let digits = text.get(start..end).ok_or(Error::GuidTextSyntax)?;
    u32::from_str_radix(digits, 16).map_err(|_| Error::GuidTextSyntax)
}

impl Guid {
    /// Parse the lower-case `8-4-4-4-12` text form (module documentation).
    ///
    /// # Errors
    /// [`Error::GuidTextSyntax`] unless `text` is exactly 36 octets: four
    /// "-" at offsets 8, 13, 18 and 23, and a lower-case hexadecimal digit
    /// everywhere else.
    ///
    /// Spec: [MS-DTYP] 2.3.4.1, 2.3.4.2, 2.5.1.1; [MS-DRSR] 5.16.3.16; A-31.
    pub fn parse_text(text: &str) -> Result<Guid> {
        let octets = text.as_bytes();
        if octets.len() != GUID_TEXT_LEN {
            return Err(Error::GuidTextSyntax);
        }
        let shaped = octets.iter().enumerate().all(|(at, &c)| {
            if DASHES.contains(&at) {
                c == b'-'
            } else {
                is_lower_hex(c)
            }
        });
        if !shaped {
            return Err(Error::GuidTextSyntax);
        }
        let mut data4 = [0u8; 8];
        for (slot, &at) in data4.iter_mut().zip(DATA4_AT.iter()) {
            *slot = u8::try_from(hex(text, at, at + 2)?).map_err(|_| Error::GuidTextSyntax)?;
        }
        Ok(Guid {
            // Group 1: Data1. Spec: [MS-DRSR] 5.16.3.16 example.
            data1: hex(text, 0, 8)?,
            // Group 2: Data2. Spec: [MS-DRSR] 5.16.3.16 example.
            data2: u16::try_from(hex(text, 9, 13)?).map_err(|_| Error::GuidTextSyntax)?,
            // Group 3: Data3. Spec: [MS-DRSR] 5.16.3.16 example.
            data3: u16::try_from(hex(text, 14, 18)?).map_err(|_| Error::GuidTextSyntax)?,
            // Groups 4 and 5: Data4 in array order. Spec: [MS-DTYP] 2.3.4.1;
            // [MS-DRSR] 5.16.3.16 example.
            data4,
        })
    }

    /// The lower-case `8-4-4-4-12` text form: the inverse of
    /// [`Guid::parse_text`].
    ///
    /// Spec: [MS-DTYP] 2.5.1.1; [MS-DRSR] 5.16.3.16; A-31.
    #[must_use]
    pub fn to_text(&self) -> String {
        let d = self.data4;
        format!(
            "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            self.data1, self.data2, self.data3, d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]
        )
    }
}
