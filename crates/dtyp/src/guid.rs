//! GUID — packet representation.
//!
//! Spec: [MS-DTYP] 2.3.4 (GUID is a 16-byte structure), 2.3.4.1 (members
//! Data1 `unsigned long`, Data2 / Data3 `unsigned short`, Data4 `byte[8]`),
//! 2.3.4.2 (packet representation: Data1, Data2 and Data3 each in
//! little-endian byte order, then the eight Data4 bytes).
//!
//! Data4 is an array of single bytes (2.3.4.1), so it has no multi-byte
//! integer to reorder: its elements are carried in array order, exactly as the
//! six-byte array SID_IDENTIFIER_AUTHORITY is carried in array order in the
//! [MS-DTYP] 2.5.1.4 example.
//!
//! The curly-braced string form (2.3.4.3) is out of scope: it is defined by
//! reference to RFC 4122, which is not an allowed source (specs/SOURCES.md).
//! The lower-case `8-4-4-4-12` text form derived from allowed text only is
//! in the module `guid_text` ([`Guid::parse_text`], [`Guid::to_text`]).

use crate::error::{Error, Result};

/// Size of the GUID packet. Spec: [MS-DTYP] 2.3.4 ("a 16-byte structure").
pub const GUID_PACKET_LEN: usize = 16;

/// A GUID, with the members named as in [MS-DTYP] 2.3.4.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Guid {
    /// Data1. Spec: [MS-DTYP] 2.3.4.1.
    pub data1: u32,
    /// Data2. Spec: [MS-DTYP] 2.3.4.1.
    pub data2: u16,
    /// Data3. Spec: [MS-DTYP] 2.3.4.1.
    pub data3: u16,
    /// Data4. Spec: [MS-DTYP] 2.3.4.1.
    pub data4: [u8; 8],
}

impl Guid {
    /// Decode the 16-byte packet representation.
    ///
    /// Spec: [MS-DTYP] 2.3.4.2.
    #[must_use]
    pub fn from_packet(bytes: &[u8; GUID_PACKET_LEN]) -> Guid {
        let mut data4 = [0u8; 8];
        data4.copy_from_slice(&bytes[8..16]);
        Guid {
            // Data1 (4 bytes), little-endian. Spec: [MS-DTYP] 2.3.4.2.
            data1: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            // Data2 (2 bytes), little-endian. Spec: [MS-DTYP] 2.3.4.2.
            data2: u16::from_le_bytes([bytes[4], bytes[5]]),
            // Data3 (2 bytes), little-endian. Spec: [MS-DTYP] 2.3.4.2.
            data3: u16::from_le_bytes([bytes[6], bytes[7]]),
            // Data4 (8 bytes), array order. Spec: [MS-DTYP] 2.3.4.1, 2.3.4.2.
            data4,
        }
    }

    /// Decode a GUID packet from a slice that must be exactly 16 bytes.
    ///
    /// Spec: [MS-DTYP] 2.3.4.2.
    pub fn decode(bytes: &[u8]) -> Result<Guid> {
        let array: &[u8; GUID_PACKET_LEN] = bytes.try_into().map_err(|_| Error::GuidLength)?;
        Ok(Guid::from_packet(array))
    }

    /// Encode the 16-byte packet representation.
    ///
    /// Spec: [MS-DTYP] 2.3.4.2.
    #[must_use]
    pub fn to_packet(&self) -> [u8; GUID_PACKET_LEN] {
        let mut out = [0u8; GUID_PACKET_LEN];
        out[0..4].copy_from_slice(&self.data1.to_le_bytes());
        out[4..6].copy_from_slice(&self.data2.to_le_bytes());
        out[6..8].copy_from_slice(&self.data3.to_le_bytes());
        out[8..16].copy_from_slice(&self.data4);
        out
    }
}
