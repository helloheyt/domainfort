//! The field encoder: writes the single canonical form of each field.
//!
//! Every primitive has exactly one encoding (docs/50 §3.3), and the writer
//! enforces the same bounds the [`crate::Reader`] enforces — field bounds,
//! the nesting limit and the channel's body bound — so it never produces
//! octets the peer would refuse.
//!
//! The output buffer is zeroizing and is never reallocated in place: when it
//! must grow, a larger zeroizing buffer is allocated, the octets are moved
//! across and the old buffer is wiped as it drops. The `zeroize` docs warn
//! that a plain reallocation can leave copies on the heap that cannot be
//! wiped; this growth step leaves none (R50-4: secret-bearing buffers
//! zeroized).

use crate::error::{Error, Result};
use crate::limits::{FrameLimit, LENGTH_PREFIX_LEN, MAX_NESTING};
use crate::reader::{BOOL_FALSE, BOOL_TRUE, OPTION_ABSENT, OPTION_PRESENT};
use crate::values::{DerBlob, Secret};
use core::fmt;
use zeroize::Zeroizing;

/// First capacity reserved when the buffer must grow (a small payload fits
/// without a second step). Project choice.
const INITIAL_CAPACITY: usize = 64;

/// Encoder of one payload (or, inside [`crate::encode_frame`], of one whole
/// frame).
///
/// Write the fields in their fixed order. Each primitive write checks the
/// field bound and the body bound first and writes nothing on error; a
/// composite write (optional, sequence) may stop part-way, so after any error
/// the writer is discarded ([`crate::encode_frame`] does).
///
/// `Debug` shows only lengths: the buffer may hold a secret (docs/50 §8.2).
///
/// Spec: docs/50 §3.3 (canonical positional fields; a bound per channel and
/// direction); R50-4.
pub struct Writer {
    buffer: Zeroizing<Vec<u8>>,
    /// Octets before the body (the frame length prefix), not counted against
    /// the body bound.
    body_start: usize,
    /// The body bound, in octets.
    limit: usize,
    depth: usize,
}

impl fmt::Debug for Writer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Writer")
            .field("body_len", &self.body_len())
            .field("limit", &self.limit)
            .field("depth", &self.depth)
            .finish()
    }
}

impl Writer {
    /// A writer for a standalone payload of at most `limit` octets.
    /// Spec: docs/50 §3.3.
    #[must_use]
    pub fn new(limit: FrameLimit) -> Writer {
        Writer {
            buffer: Zeroizing::new(Vec::new()),
            body_start: 0,
            limit: limit.max_body_len(),
            depth: 0,
        }
    }

    /// A writer for a whole frame: room for the length prefix, then a body of
    /// at most `limit` octets. Spec: docs/50 §3.3
    /// (`Frame := length:u32 ‖ body[length]`).
    pub(crate) fn for_frame(limit: FrameLimit) -> Writer {
        let mut buffer = Zeroizing::new(Vec::with_capacity(LENGTH_PREFIX_LEN + INITIAL_CAPACITY));
        // Placeholder, patched by `into_frame_octets` once the body length is known.
        buffer.extend_from_slice(&[0; LENGTH_PREFIX_LEN]);
        Writer {
            buffer,
            body_start: LENGTH_PREFIX_LEN,
            limit: limit.max_body_len(),
            depth: 0,
        }
    }

    /// Octets of body written so far.
    #[must_use]
    pub fn body_len(&self) -> usize {
        self.buffer.len().saturating_sub(self.body_start)
    }

    /// The encoded payload of a standalone writer, in a zeroizing buffer.
    /// Spec: docs/50 §3.3; R50-4.
    #[must_use]
    pub fn into_payload(self) -> Zeroizing<Vec<u8>> {
        self.buffer
    }

    /// The whole frame: patch the length prefix with the body length.
    /// Spec: docs/50 §3.3 ("length:u32 (big-endian)").
    pub(crate) fn into_frame_octets(self) -> Result<Zeroizing<Vec<u8>>> {
        let body_len = u32::try_from(self.body_len()).map_err(|_| Error::BodyOverBound)?;
        let mut buffer = self.buffer;
        let prefix = buffer
            .first_chunk_mut::<LENGTH_PREFIX_LEN>()
            .ok_or(Error::BodyOverBound)?;
        *prefix = body_len.to_be_bytes();
        Ok(buffer)
    }

    /// Append `octets` to the body, refusing to pass the body bound.
    fn put(&mut self, octets: &[u8]) -> Result<()> {
        let new_body_len = self
            .body_len()
            .checked_add(octets.len())
            .ok_or(Error::BodyOverBound)?;
        if new_body_len > self.limit {
            return Err(Error::BodyOverBound);
        }
        self.reserve(octets.len());
        self.buffer.extend_from_slice(octets);
        Ok(())
    }

    /// Make room for `additional` octets without an in-place reallocation:
    /// a larger zeroizing buffer replaces the old one, which is wiped as it
    /// drops. Callers have already checked the body bound, so the sizes here
    /// stay within `body_start + limit`.
    fn reserve(&mut self, additional: usize) {
        let needed = self.buffer.len().saturating_add(additional);
        if needed <= self.buffer.capacity() {
            return;
        }
        let ceiling = self.body_start.saturating_add(self.limit);
        let doubled = self
            .buffer
            .capacity()
            .saturating_mul(2)
            .max(INITIAL_CAPACITY);
        let capacity = doubled.min(ceiling).max(needed);
        let mut grown = Zeroizing::new(Vec::with_capacity(capacity));
        // Within the reserved capacity: no reallocation.
        grown.extend_from_slice(&self.buffer);
        // The previous buffer drops here and is zeroized.
        self.buffer = grown;
    }

    /// A fixed-length octet string of `N` octets, without a length prefix.
    /// Spec: docs/50 §3.3 (keyd types row: fixed-length octet fields).
    pub fn write_array<const N: usize>(&mut self, octets: &[u8; N]) -> Result<()> {
        self.put(octets)
    }

    /// An unsigned 8-bit integer. Spec: docs/50 §3.3 ("fixed width,
    /// big-endian").
    pub fn write_u8(&mut self, value: u8) -> Result<()> {
        self.put(&value.to_be_bytes())
    }

    /// An unsigned 16-bit integer, big-endian. Spec: docs/50 §3.3.
    pub fn write_u16(&mut self, value: u16) -> Result<()> {
        self.put(&value.to_be_bytes())
    }

    /// An unsigned 32-bit integer, big-endian. Spec: docs/50 §3.3.
    pub fn write_u32(&mut self, value: u32) -> Result<()> {
        self.put(&value.to_be_bytes())
    }

    /// An unsigned 64-bit integer, big-endian. Spec: docs/50 §3.3.
    pub fn write_u64(&mut self, value: u64) -> Result<()> {
        self.put(&value.to_be_bytes())
    }

    /// A boolean: `00` or `01`. Spec: docs/50 §3.3 ("`bool` = `00`/`01`
    /// only").
    pub fn write_bool(&mut self, value: bool) -> Result<()> {
        self.write_u8(if value { BOOL_TRUE } else { BOOL_FALSE })
    }

    /// A length-prefixed byte string of at most `max` octets.
    /// Spec: docs/50 §3.3 ("`bytes<max>` = `u32` length ≤ max + octets").
    pub fn write_bytes(&mut self, octets: &[u8], max: u32) -> Result<()> {
        let length = u32::try_from(octets.len()).map_err(|_| Error::LengthOverBound)?;
        if length > max {
            return Err(Error::LengthOverBound);
        }
        // Check the whole field against the body bound before writing any
        // part of it, so an error leaves the body unchanged.
        let field_len = octets.len().saturating_add(4);
        if self.body_len().saturating_add(field_len) > self.limit {
            return Err(Error::BodyOverBound);
        }
        self.write_u32(length)?;
        self.put(octets)
    }

    /// A DER blob of at most `max` octets (a byte string).
    /// Spec: docs/50 §3.3 (Kerberos values as `bytes<max>` holding DER).
    pub fn write_der(&mut self, der: &DerBlob, max: u32) -> Result<()> {
        self.write_bytes(der.as_der(), max)
    }

    /// A secret byte string of at most `max` octets; the octets land only in
    /// this writer's zeroizing buffer.
    /// Spec: docs/50 §3.3; R50-4; docs/10 I7.
    pub fn write_secret(&mut self, secret: &Secret, max: u32) -> Result<()> {
        self.write_bytes(secret.expose(), max)
    }

    /// An optional field: `00` when `value` is `None`, else `01` followed by
    /// the value written by `write_value`.
    /// Spec: docs/50 §3.3 ("`Option<T>` = `00` | `01 T`").
    pub fn write_option<T>(
        &mut self,
        value: Option<&T>,
        write_value: impl FnOnce(&mut Writer, &T) -> Result<()>,
    ) -> Result<()> {
        match value {
            None => self.write_u8(OPTION_ABSENT),
            Some(value) => {
                // The same nesting rule as the reader, checked before the marker.
                if self.depth >= MAX_NESTING {
                    return Err(Error::NestingTooDeep);
                }
                self.write_u8(OPTION_PRESENT)?;
                self.nested(|writer| write_value(writer, value))
            }
        }
    }

    /// A bounded sequence: a `u32` count of at most `max`, then each item
    /// written by `write_item`.
    /// Spec: docs/50 §3.3 ("`seq<T,max>` = `u32` count ≤ max + items").
    pub fn write_seq<T>(
        &mut self,
        items: &[T],
        max: u32,
        mut write_item: impl FnMut(&mut Writer, &T) -> Result<()>,
    ) -> Result<()> {
        let count = u32::try_from(items.len()).map_err(|_| Error::CountOverBound)?;
        if count > max {
            return Err(Error::CountOverBound);
        }
        if self.depth >= MAX_NESTING {
            return Err(Error::NestingTooDeep);
        }
        self.write_u32(count)?;
        self.nested(|writer| {
            for item in items {
                write_item(writer, item)?;
            }
            Ok(())
        })
    }

    /// An enumeration code from the field's closed table.
    /// Spec: docs/50 §3.3 ("enum = `u8` from a closed table").
    pub fn write_enum(&mut self, code: u8) -> Result<()> {
        self.write_u8(code)
    }

    /// Run `write` one nesting level deeper (the depth was checked by the
    /// caller, mirroring [`crate::Reader`]).
    fn nested(&mut self, write: impl FnOnce(&mut Writer) -> Result<()>) -> Result<()> {
        self.depth += 1;
        let result = write(self);
        self.depth -= 1;
        result
    }
}
