//! The field decoder: reads the canonical fixed-order fields of one payload.
//!
//! Each primitive accepts exactly the one encoding the [`crate::Writer`]
//! produces for its value, so a payload that decodes re-encodes to the same
//! octets (docs/50 §3.3: "canonicity: a single encoding per value"). The reader
//! borrows its input, allocates only for the owned values it returns (never
//! more than the octets present), and never panics: every shortfall, bad
//! marker, over-bound length or count and leftover octet is a typed
//! [`Error`].

use crate::error::{Error, Result};
use crate::limits::{to_usize, MAX_NESTING};
use crate::values::{DerBlob, Secret};
use core::fmt;

/// Marker octet of an absent optional field. Spec: docs/50 §3.3
/// ("`Option<T>` = `00` | `01 T`").
pub(crate) const OPTION_ABSENT: u8 = 0x00;
/// Marker octet of a present optional field. Spec: docs/50 §3.3.
pub(crate) const OPTION_PRESENT: u8 = 0x01;
/// The boolean `false`. Spec: docs/50 §3.3 ("`bool` = `00`/`01` only").
pub(crate) const BOOL_FALSE: u8 = 0x00;
/// The boolean `true`. Spec: docs/50 §3.3.
pub(crate) const BOOL_TRUE: u8 = 0x01;

/// Decoder over the payload octets of one frame (or of one standalone
/// payload).
///
/// Read the fields in their fixed order, then call [`Reader::finish`], which
/// refuses any octet left over.
///
/// `Debug` shows only how many octets remain: the payload may carry a
/// secret (docs/50 §8.2).
///
/// Spec: docs/50 §3.3 ("positional fields in a fixed order for each kind;
/// after the last field — exactly the end of the body"); R50-4.
pub struct Reader<'a> {
    rest: &'a [u8],
    depth: usize,
}

impl fmt::Debug for Reader<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Reader")
            .field("remaining", &self.rest.len())
            .field("depth", &self.depth)
            .finish()
    }
}

impl<'a> Reader<'a> {
    /// Start reading `input` from its first octet.
    #[must_use]
    pub fn new(input: &'a [u8]) -> Reader<'a> {
        Reader {
            rest: input,
            depth: 0,
        }
    }

    /// Octets not yet consumed.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.rest.len()
    }

    /// End of the payload: [`Error::TrailingBytes`] if any octet is left.
    ///
    /// Spec: docs/50 §3.3 ("no trailing byte … otherwise `Malformed` +
    /// close"); R50-4.
    pub fn finish(self) -> Result<()> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(Error::TrailingBytes)
        }
    }

    /// Consume exactly `count` octets.
    fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        let (head, tail) = self.rest.split_at_checked(count).ok_or(Error::Truncated)?;
        self.rest = tail;
        Ok(head)
    }

    /// A fixed-length octet string of `N` octets (for example a 16-octet
    /// `PrincipalId` or a token of `TOKEN_ID_LENGTH` octets). No length prefix:
    /// the width is fixed by the field.
    ///
    /// Spec: docs/50 §3.3 (keyd types row: fixed-length octet fields).
    pub fn read_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let (head, tail) = self.rest.split_first_chunk::<N>().ok_or(Error::Truncated)?;
        self.rest = tail;
        Ok(*head)
    }

    /// An unsigned 8-bit integer. Spec: docs/50 §3.3 ("`u8/u16/u32/u64`
    /// fixed width, big-endian").
    pub fn read_u8(&mut self) -> Result<u8> {
        self.read_array().map(u8::from_be_bytes)
    }

    /// An unsigned 16-bit integer, big-endian. Spec: docs/50 §3.3.
    pub fn read_u16(&mut self) -> Result<u16> {
        self.read_array().map(u16::from_be_bytes)
    }

    /// An unsigned 32-bit integer, big-endian. Spec: docs/50 §3.3.
    pub fn read_u32(&mut self) -> Result<u32> {
        self.read_array().map(u32::from_be_bytes)
    }

    /// An unsigned 64-bit integer, big-endian. Spec: docs/50 §3.3.
    pub fn read_u64(&mut self) -> Result<u64> {
        self.read_array().map(u64::from_be_bytes)
    }

    /// A boolean: `00` is false, `01` is true, any other octet is
    /// [`Error::InvalidBoolean`].
    ///
    /// Spec: docs/50 §3.3 ("`bool` = `00`/`01` only").
    pub fn read_bool(&mut self) -> Result<bool> {
        match self.read_u8()? {
            BOOL_FALSE => Ok(false),
            BOOL_TRUE => Ok(true),
            _ => Err(Error::InvalidBoolean),
        }
    }

    /// The `u32` length of a byte string, checked against the field bound
    /// before the octets are looked at.
    fn read_length(&mut self, max: u32) -> Result<usize> {
        let length = self.read_u32()?;
        if length > max {
            return Err(Error::LengthOverBound);
        }
        Ok(to_usize(length))
    }

    /// A length-prefixed byte string of at most `max` octets, borrowed from
    /// the input.
    ///
    /// Spec: docs/50 §3.3 ("`bytes<max>` = `u32` length ≤ max + octets").
    pub fn read_bytes(&mut self, max: u32) -> Result<&'a [u8]> {
        let length = self.read_length(max)?;
        self.take(length)
    }

    /// A DER blob of at most `max` octets: a byte string whose contents this
    /// crate does not interpret (`krb-proto` decodes it later).
    ///
    /// Spec: docs/50 §3.3 (Kerberos values as `bytes<max>` holding DER).
    pub fn read_der(&mut self, max: u32) -> Result<DerBlob> {
        self.read_bytes(max).map(DerBlob::from_slice)
    }

    /// A secret byte string of at most `max` octets, copied into a zeroizing
    /// buffer. (The frame buffer it came from must be wiped by its owner —
    /// [`crate::FrameReader`] does.)
    ///
    /// Spec: docs/50 §3.3 (secret-bearing buffers zeroized); R50-4; docs/10 I7.
    pub fn read_secret(&mut self, max: u32) -> Result<Secret> {
        self.read_bytes(max).map(Secret::from_slice)
    }

    /// An optional field: marker `00` (absent) or `01` followed by the value
    /// read by `read_value`. Any other marker is
    /// [`Error::InvalidOptionMarker`].
    ///
    /// Spec: docs/50 §3.3 ("`Option<T>` = `00` | `01 T`").
    pub fn read_option<T>(
        &mut self,
        read_value: impl FnOnce(&mut Reader<'a>) -> Result<T>,
    ) -> Result<Option<T>> {
        match self.read_u8()? {
            OPTION_ABSENT => Ok(None),
            OPTION_PRESENT => self.nested(read_value).map(Some),
            _ => Err(Error::InvalidOptionMarker),
        }
    }

    /// A bounded sequence: a `u32` count of at most `max`, then that many
    /// items, each read by `read_item`.
    ///
    /// Nothing is reserved from the attacker-supplied count: the vector grows
    /// only as items actually decode, so allocation never exceeds what the
    /// octets present can produce.
    ///
    /// Spec: docs/50 §3.3 ("`seq<T,max>` = `u32` count ≤ max + items");
    /// docs/CLEAN-ROOM.md (no unbounded allocation from attacker-supplied lengths).
    pub fn read_seq<T>(
        &mut self,
        max: u32,
        mut read_item: impl FnMut(&mut Reader<'a>) -> Result<T>,
    ) -> Result<Vec<T>> {
        let count = self.read_u32()?;
        if count > max {
            return Err(Error::CountOverBound);
        }
        self.nested(|reader| {
            let mut items = Vec::new();
            for _ in 0..count {
                items.push(read_item(reader)?);
            }
            Ok(items)
        })
    }

    /// An enumeration: one `u8` code, mapped by `from_code` from the field's
    /// closed table; a code outside it is [`Error::UnknownCode`].
    ///
    /// Spec: docs/50 §3.3 ("enum = `u8` from a closed table").
    pub fn read_enum<T>(&mut self, from_code: impl FnOnce(u8) -> Option<T>) -> Result<T> {
        from_code(self.read_u8()?).ok_or(Error::UnknownCode)
    }

    /// Run `read` one nesting level deeper, refusing to pass
    /// [`MAX_NESTING`].
    ///
    /// Spec: docs/CLEAN-ROOM.md (recursion-depth limits); docs/questions/Q-225 item 5.
    fn nested<T>(&mut self, read: impl FnOnce(&mut Reader<'a>) -> Result<T>) -> Result<T> {
        if self.depth >= MAX_NESTING {
            return Err(Error::NestingTooDeep);
        }
        self.depth += 1;
        let result = read(self);
        self.depth -= 1;
        result
    }
}
