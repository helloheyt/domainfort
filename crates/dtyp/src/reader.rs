//! Bounded forward reader for little-endian packet fields.
//!
//! Every read is checked against the remaining input before any slice is
//! taken, so no length or count from the input is ever used to index or
//! allocate without a bound (AGENTS.md §6; docs/32 §8). Each caller names the
//! structure-specific error to return when the input is too short.
//!
//! Byte order: a self-relative security descriptor "is sent in little-endian
//! format" (Spec: [MS-DTYP] 2.4.6), and the SID, ACL and ACE packets this crate
//! handles are the ones embedded in it, so multi-byte integers are read
//! little-endian. The worked example in [MS-DTYP] 2.5.1.4 shows the same
//! (e.g. SubAuthority 545 as `21 02 00 00`).

use crate::error::{Error, Result};

/// A cursor over a byte slice that never reads past its end.
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    /// Bytes consumed so far.
    pub(crate) fn position(&self) -> usize {
        self.pos
    }

    /// Bytes not yet consumed.
    pub(crate) fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Take the next `n` bytes, or return `short` if fewer remain.
    pub(crate) fn take(&mut self, n: usize, short: Error) -> Result<&'a [u8]> {
        if n > self.remaining() {
            return Err(short);
        }
        let slice = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    /// Take exactly `N` bytes as an array.
    pub(crate) fn array<const N: usize>(&mut self, short: Error) -> Result<[u8; N]> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N, short)?);
        Ok(out)
    }

    pub(crate) fn u8(&mut self, short: Error) -> Result<u8> {
        Ok(self.array::<1>(short)?[0])
    }

    /// Little-endian 16-bit unsigned. Spec: [MS-DTYP] 2.4.6 (little-endian).
    pub(crate) fn u16_le(&mut self, short: Error) -> Result<u16> {
        Ok(u16::from_le_bytes(self.array::<2>(short)?))
    }

    /// Little-endian 32-bit unsigned. Spec: [MS-DTYP] 2.4.6 (little-endian).
    pub(crate) fn u32_le(&mut self, short: Error) -> Result<u32> {
        Ok(u32::from_le_bytes(self.array::<4>(short)?))
    }
}
