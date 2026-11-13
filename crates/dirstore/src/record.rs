//! The record codec: this crate's own minimal, length-prefixed, canonical
//! encoding of stored record bodies.
//!
//! Not serde, not any general serializer: a hand-defined codec, as docs/10
//! D34 requires between components and docs/32 §8 requires for every stored
//! structure ("no general deserialization"). The integrity tag that follows
//! each body is added and checked by the store, never here — a body reaches
//! [`decode_object_body`] from disk only after its tag verified (docs/32 §3).
//!
//! # Rules
//!
//! - Integers are unsigned and big-endian.
//! - Every variable-length field has a length or count prefix that is checked
//!   against its bound ([`crate::MAX_RDN_KEY_LEN`],
//!   [`crate::MAX_CLASSES_PER_OBJECT`], [`crate::MAX_ATTRIBUTES_PER_OBJECT`],
//!   [`crate::MAX_VALUES_PER_ATTRIBUTE`], [`crate::MAX_VALUE_LEN`]) and
//!   against the remaining input before it is used. Nothing is allocated from
//!   a count: containers grow one parsed element at a time, and every element
//!   consumes input, so memory stays proportional to the (bounded) input.
//! - Canonical: classes, attributes and values are strictly ascending (which
//!   also forbids duplicates), flags have no undefined bits, and no bytes
//!   follow the last field. The encoder refuses non-canonical input, so
//!   `decode(encode(o)) == o`, and every body the decoder accepts satisfies
//!   `encode(decode(b)) == b`.
//! - No recursion.
//!
//! # Object record body (stored under the 16-byte GUID packet)
//!
//! ```text
//! u8      format            = RECORD_FORMAT_V1
//! u8      flags             bit 0 HAS_PARENT, bit 1 TOMBSTONE, others 0
//!                           (never both: a tombstone has no parent)
//! [16]    parent GUID       if HAS_PARENT (`dtyp::Guid::to_packet` form)
//! u16     rdn_len           live: 1..=MAX_RDN_KEY_LEN; tombstone: 0
//! [..]    rdn key           (absent in a tombstone)
//! [40]    deletion stamp    if TOMBSTONE
//! u16     class_count       1..=MAX_CLASSES_PER_OBJECT
//! u32 x n class ids         strictly ascending
//! u16     attribute_count   live: 0..=MAX_ATTRIBUTES_PER_OBJECT; tombstone: 0
//! per attribute (ids strictly ascending):
//!   u32   attribute id
//!   u16   value_count       1..=MAX_VALUES_PER_ATTRIBUTE
//!   per value (bytes strictly ascending):
//!     [40]  attr-stamp
//!     u32   value_len       0..=MAX_VALUE_LEN
//!     [..]  value
//! ```
//!
//! A **tombstone** body is therefore exactly: format, flags = TOMBSTONE,
//! rdn_len = 0, deletion stamp, classes, attribute_count = 0. It keeps the
//! object's identity (the GUID is the record key, plus its classes) and the
//! deletion stamp — the only things docs/29 §5 needs to stop a deleted object
//! from coming back — and nothing else (minimal state: docs/25 §5 "state"
//! row, D104; owner decision Q-062 / A-18). The decoder rejects a tombstone
//! body that carries a parent, an RDN key or any attribute
//! ([`DecodeError::TombstoneContent`]).
//!
//! An attr-stamp is `u64 version, u64 wall-clock, [16] origin-node,
//! u64 origin-seq` (docs/29 §2). The whole body is at most
//! [`crate::MAX_RECORD_BODY_LEN`] bytes.
//!
//! # Name-index body, child-count body, meta body
//!
//! ```text
//! name index  (key: 0x00 || rdn            for a root,
//!              key: 0x01 || parent || rdn  for a child)
//!   u8 format, [16] child GUID
//! child count (key: 16-byte parent GUID)
//!   u8 format, u64 live-child count (>= 1; zero is never stored)
//! meta        (key: "store")
//!   u8 format
//! ```
//!
//! Spec: docs/10 D34; docs/32 §2 (object / name index, D134), §8 (bounded
//! parser, D138); docs/29 §2 (attr-stamp), §5 (tombstone).

use crate::error::{DecodeError, Violation};
use crate::types::{
    AttrId, AttrStamp, Attribute, ClassId, NodeId, Object, StampedValue, Timestamp,
};
use crate::{
    MAX_ATTRIBUTES_PER_OBJECT, MAX_CLASSES_PER_OBJECT, MAX_RDN_KEY_LEN, MAX_RECORD_BODY_LEN,
    MAX_VALUES_PER_ATTRIBUTE, MAX_VALUE_LEN,
};
use core::num::NonZeroU64;
use dtyp::{Guid, GUID_PACKET_LEN};

/// The only record format this crate writes or reads. Spec: docs/10 D34
/// ("version-aware codec").
pub const RECORD_FORMAT_V1: u8 = 0x01;

/// Object flags bit: a parent GUID follows. Spec: docs/32 §2 (DIT).
const FLAG_HAS_PARENT: u8 = 0x01;
/// Object flags bit: the object is a tombstone; a deletion stamp follows.
/// Spec: docs/29 §5.
const FLAG_TOMBSTONE: u8 = 0x02;
/// Every defined object flag bit.
const DEFINED_FLAGS: u8 = FLAG_HAS_PARENT | FLAG_TOMBSTONE;

/// Encoded size of an attr-stamp. Spec: docs/29 §2.
pub(crate) const STAMP_LEN: usize = 8 + 8 + 16 + 8;

/// Name-index key prefix for a naming-context root (no parent).
const NAME_KEY_ROOT: u8 = 0x00;
/// Name-index key prefix for a child (a parent GUID follows).
const NAME_KEY_CHILD: u8 = 0x01;

// ---------------------------------------------------------------- writing --

/// Growing output buffer that refuses to pass the record-size bound.
struct Writer {
    out: Vec<u8>,
}

impl Writer {
    fn new() -> Writer {
        Writer { out: Vec::new() }
    }

    /// Append bytes, failing once the body would exceed the bound.
    /// Spec: docs/32 §8 (allocation ceiling).
    fn bytes(&mut self, b: &[u8]) -> Result<(), Violation> {
        if self.out.len().saturating_add(b.len()) > MAX_RECORD_BODY_LEN {
            return Err(Violation::RecordTooLarge);
        }
        self.out.extend_from_slice(b);
        Ok(())
    }

    fn u8(&mut self, v: u8) -> Result<(), Violation> {
        self.bytes(&[v])
    }

    fn u16(&mut self, v: u16) -> Result<(), Violation> {
        self.bytes(&v.to_be_bytes())
    }

    fn u32(&mut self, v: u32) -> Result<(), Violation> {
        self.bytes(&v.to_be_bytes())
    }

    fn u64(&mut self, v: u64) -> Result<(), Violation> {
        self.bytes(&v.to_be_bytes())
    }

    /// attr-stamp. Spec: docs/29 §2.
    fn stamp(&mut self, s: &AttrStamp) -> Result<(), Violation> {
        self.u64(s.version)?;
        self.u64(s.wall_clock.0)?;
        self.bytes(&s.origin_node.0)?;
        self.u64(s.origin_seq)
    }
}

/// A count or length as `u16`, given that it is already within a bound that
/// fits; refuse rather than truncate.
fn len_u16(n: usize, err: Violation) -> Result<u16, Violation> {
    u16::try_from(n).map_err(|_| err)
}

/// Encode an object record body (the object's GUID is the record key and is
/// not repeated in the body).
///
/// Refuses anything the decoder would reject: out-of-bound counts or lengths
/// ([`Violation`] bound variants), non-canonical order
/// ([`Violation::NotCanonical`]), and a tombstone that carries a parent, an
/// RDN key or attributes ([`Violation::TombstoneCarriesContent`]).
/// Spec: docs/10 D34; docs/32 §8; docs/29 §5 (Q-062 / A-18).
pub fn encode_object_body(obj: &Object) -> Result<Vec<u8>, Violation> {
    // A tombstone keeps only identity + deletion stamp. Spec: docs/29 §5;
    // docs/25 §5 ("state"); Q-062 / A-18.
    if obj.tombstone.is_some()
        && (obj.parent.is_some() || !obj.rdn.is_empty() || !obj.attributes.is_empty())
    {
        return Err(Violation::TombstoneCarriesContent);
    }
    let mut w = Writer::new();
    w.u8(RECORD_FORMAT_V1)?;
    let mut flags = 0u8;
    if obj.parent.is_some() {
        flags |= FLAG_HAS_PARENT;
    }
    if obj.tombstone.is_some() {
        flags |= FLAG_TOMBSTONE;
    }
    w.u8(flags)?;
    if let Some(parent) = &obj.parent {
        w.bytes(&parent.to_packet())?;
    }

    // RDN key: 1..=MAX for a live object, absent (length 0) in a tombstone.
    // Spec: docs/32 §2, §8; docs/29 §5.
    if obj.tombstone.is_none() {
        if obj.rdn.is_empty() {
            return Err(Violation::RdnKeyEmpty);
        }
        if obj.rdn.len() > MAX_RDN_KEY_LEN {
            return Err(Violation::RdnKeyTooLong);
        }
    }
    w.u16(len_u16(obj.rdn.len(), Violation::RdnKeyTooLong)?)?;
    w.bytes(&obj.rdn)?;

    // Deletion marker. Spec: docs/29 §5.
    if let Some(stamp) = &obj.tombstone {
        w.stamp(stamp)?;
    }

    // Classes. Spec: docs/32 §4.
    if obj.classes.is_empty() {
        return Err(Violation::NoObjectClass);
    }
    if obj.classes.len() > MAX_CLASSES_PER_OBJECT {
        return Err(Violation::TooManyClasses);
    }
    if !strictly_ascending(obj.classes.iter()) {
        return Err(Violation::NotCanonical);
    }
    w.u16(len_u16(obj.classes.len(), Violation::TooManyClasses)?)?;
    for c in &obj.classes {
        w.u32(c.0)?;
    }

    // Attributes. Spec: docs/32 §2, §4; docs/29 §2.
    if obj.attributes.len() > MAX_ATTRIBUTES_PER_OBJECT {
        return Err(Violation::TooManyAttributes);
    }
    if !strictly_ascending(obj.attributes.iter().map(|a| a.id)) {
        return Err(Violation::NotCanonical);
    }
    w.u16(len_u16(obj.attributes.len(), Violation::TooManyAttributes)?)?;
    for attr in &obj.attributes {
        w.u32(attr.id.0)?;
        if attr.values.is_empty() {
            return Err(Violation::EmptyAttribute(attr.id));
        }
        if attr.values.len() > MAX_VALUES_PER_ATTRIBUTE {
            return Err(Violation::TooManyValues(attr.id));
        }
        if !strictly_ascending(attr.values.iter().map(|v| v.value.as_slice())) {
            return Err(Violation::NotCanonical);
        }
        w.u16(len_u16(
            attr.values.len(),
            Violation::TooManyValues(attr.id),
        )?)?;
        for v in &attr.values {
            if v.value.len() > MAX_VALUE_LEN {
                return Err(Violation::ValueTooLarge(attr.id));
            }
            w.stamp(&v.stamp)?;
            let len =
                u32::try_from(v.value.len()).map_err(|_| Violation::ValueTooLarge(attr.id))?;
            w.u32(len)?;
            w.bytes(&v.value)?;
        }
    }
    Ok(w.out)
}

/// `true` if every item is strictly greater than the one before it.
fn strictly_ascending<T: PartialOrd, I: Iterator<Item = T>>(mut items: I) -> bool {
    let Some(mut previous) = items.next() else {
        return true;
    };
    for item in items {
        if item <= previous {
            return false;
        }
        previous = item;
    }
    true
}

// ---------------------------------------------------------------- reading --

/// Bounded forward reader: every read is checked against the remaining input
/// before a slice is taken. Spec: docs/32 §8 (bounded parser), D138.
struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Reader<'a> {
        Reader { buf }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        let (head, tail) = self.buf.split_at_checked(n).ok_or(DecodeError::Truncated)?;
        self.buf = tail;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(u8::from_be_bytes(self.array::<1>()?))
    }

    fn u16(&mut self) -> Result<u16, DecodeError> {
        Ok(u16::from_be_bytes(self.array::<2>()?))
    }

    fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_be_bytes(self.array::<4>()?))
    }

    fn u64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_be_bytes(self.array::<8>()?))
    }

    fn guid(&mut self) -> Result<Guid, DecodeError> {
        Ok(Guid::from_packet(&self.array::<GUID_PACKET_LEN>()?))
    }

    /// attr-stamp. Spec: docs/29 §2.
    fn stamp(&mut self) -> Result<AttrStamp, DecodeError> {
        Ok(AttrStamp {
            version: self.u64()?,
            wall_clock: Timestamp(self.u64()?),
            origin_node: NodeId(self.array::<16>()?),
            origin_seq: self.u64()?,
        })
    }

    /// Fail unless the input is fully consumed (strict framing).
    fn finish(&self) -> Result<(), DecodeError> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(DecodeError::TrailingData)
        }
    }
}

/// Decode an object record body stored under `guid`.
///
/// Bounded and fail-closed: every count and length is checked against its
/// bound and the remaining input before use, order must be canonical, and no
/// bytes may follow. Never panics. Spec: docs/32 §8, D138; docs/10 D34.
pub fn decode_object_body(guid: Guid, body: &[u8]) -> Result<Object, DecodeError> {
    if body.len() > MAX_RECORD_BODY_LEN {
        return Err(DecodeError::RecordTooLarge);
    }
    let mut r = Reader::new(body);
    if r.u8()? != RECORD_FORMAT_V1 {
        return Err(DecodeError::UnsupportedFormat);
    }
    let flags = r.u8()?;
    if flags & !DEFINED_FLAGS != 0 {
        return Err(DecodeError::UndefinedFlags);
    }
    let is_tombstone = flags & FLAG_TOMBSTONE != 0;
    // A tombstone has no parent. Spec: docs/29 §5; Q-062 / A-18.
    if is_tombstone && flags & FLAG_HAS_PARENT != 0 {
        return Err(DecodeError::TombstoneContent);
    }
    let parent = if flags & FLAG_HAS_PARENT != 0 {
        Some(r.guid()?)
    } else {
        None
    };

    // RDN key: 1..=MAX for a live object, length 0 in a tombstone.
    // Spec: docs/32 §2, §8; docs/29 §5 (Q-062 / A-18).
    let rdn_len = usize::from(r.u16()?);
    if is_tombstone {
        if rdn_len != 0 {
            return Err(DecodeError::TombstoneContent);
        }
    } else if rdn_len == 0 || rdn_len > MAX_RDN_KEY_LEN {
        return Err(DecodeError::RdnKeyLength);
    }
    let rdn = r.take(rdn_len)?.to_vec();

    // Deletion marker. Spec: docs/29 §5.
    let tombstone = if is_tombstone { Some(r.stamp()?) } else { None };

    // Classes. Spec: docs/32 §4.
    let class_count = usize::from(r.u16()?);
    if class_count == 0 || class_count > MAX_CLASSES_PER_OBJECT {
        return Err(DecodeError::ClassCount);
    }
    let mut classes: Vec<ClassId> = Vec::new();
    for _ in 0..class_count {
        let id = ClassId(r.u32()?);
        if classes.last().is_some_and(|p| *p >= id) {
            return Err(DecodeError::ClassOrder);
        }
        classes.push(id);
    }

    // Attributes. Spec: docs/32 §2, §4; docs/29 §2.
    let attribute_count = usize::from(r.u16()?);
    // A tombstone keeps no attribute values. Spec: docs/29 §5; Q-062 / A-18.
    if is_tombstone && attribute_count != 0 {
        return Err(DecodeError::TombstoneContent);
    }
    if attribute_count > MAX_ATTRIBUTES_PER_OBJECT {
        return Err(DecodeError::AttributeCount);
    }
    let mut attributes: Vec<Attribute> = Vec::new();
    for _ in 0..attribute_count {
        let id = AttrId(r.u32()?);
        if attributes.last().is_some_and(|p| p.id >= id) {
            return Err(DecodeError::AttributeOrder);
        }
        let value_count = usize::from(r.u16()?);
        if value_count == 0 || value_count > MAX_VALUES_PER_ATTRIBUTE {
            return Err(DecodeError::ValueCount);
        }
        let mut values: Vec<StampedValue> = Vec::new();
        for _ in 0..value_count {
            let stamp = r.stamp()?;
            let len = usize::try_from(r.u32()?).map_err(|_| DecodeError::ValueLength)?;
            if len > MAX_VALUE_LEN {
                return Err(DecodeError::ValueLength);
            }
            let bytes = r.take(len)?;
            if values.last().is_some_and(|p| p.value.as_slice() >= bytes) {
                return Err(DecodeError::ValueOrder);
            }
            values.push(StampedValue {
                value: bytes.to_vec(),
                stamp,
            });
        }
        attributes.push(Attribute { id, values });
    }
    r.finish()?;
    Ok(Object {
        guid,
        parent,
        rdn,
        classes,
        attributes,
        tombstone,
    })
}

/// The name-index key of `(parent, rdn)`: `0x00 || rdn` for a root,
/// `0x01 || parent GUID packet || rdn` for a child. The prefix byte keeps the
/// two key spaces apart without reserving any GUID value.
/// Spec: docs/32 §2 (name as secondary index; unique `(parent, RDN key)`).
#[must_use]
pub fn name_index_key(parent: Option<Guid>, rdn: &[u8]) -> Vec<u8> {
    // No capacity arithmetic on the caller's length (callers bound the RDN
    // key first; this keeps the function total on its own).
    let mut key = Vec::new();
    match parent {
        None => key.push(NAME_KEY_ROOT),
        Some(p) => {
            key.push(NAME_KEY_CHILD);
            key.extend_from_slice(&p.to_packet());
        }
    }
    key.extend_from_slice(rdn);
    key
}

/// Encode a name-index body naming `child`. Spec: docs/32 §2.
#[must_use]
pub fn encode_name_index_body(child: Guid) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + GUID_PACKET_LEN);
    out.push(RECORD_FORMAT_V1);
    out.extend_from_slice(&child.to_packet());
    out
}

/// Decode a name-index body. Spec: docs/32 §2, §8.
pub fn decode_name_index_body(body: &[u8]) -> Result<Guid, DecodeError> {
    let mut r = Reader::new(body);
    if r.u8()? != RECORD_FORMAT_V1 {
        return Err(DecodeError::UnsupportedFormat);
    }
    let child = r.guid()?;
    r.finish()?;
    Ok(child)
}

/// Encode a child-count body. The count is never zero (zero is stored as "no
/// record"), so there is exactly one encoding of every count.
/// Spec: docs/32 §2 (DIT shape), §8.
#[must_use]
pub fn encode_child_count_body(count: NonZeroU64) -> Vec<u8> {
    let mut out = Vec::with_capacity(9);
    out.push(RECORD_FORMAT_V1);
    out.extend_from_slice(&count.get().to_be_bytes());
    out
}

/// Decode a child-count body (count >= 1). Spec: docs/32 §2, §8.
pub fn decode_child_count_body(body: &[u8]) -> Result<NonZeroU64, DecodeError> {
    let mut r = Reader::new(body);
    if r.u8()? != RECORD_FORMAT_V1 {
        return Err(DecodeError::UnsupportedFormat);
    }
    let count = r.u64()?;
    r.finish()?;
    NonZeroU64::new(count).ok_or(DecodeError::ZeroChildCount)
}

/// Encode the store's meta body. Spec: docs/10 D34 (version-aware codec).
#[must_use]
pub fn encode_meta_body() -> Vec<u8> {
    vec![RECORD_FORMAT_V1]
}

/// Decode the store's meta body. Spec: docs/10 D34.
pub fn decode_meta_body(body: &[u8]) -> Result<(), DecodeError> {
    let mut r = Reader::new(body);
    if r.u8()? != RECORD_FORMAT_V1 {
        return Err(DecodeError::UnsupportedFormat);
    }
    r.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Source: the layout table in this module's documentation (our own codec;
    // no external vector exists).
    #[test]
    fn stamp_len_matches_layout() {
        let mut w = Writer::new();
        w.stamp(&AttrStamp {
            version: 1,
            wall_clock: Timestamp(2),
            origin_node: NodeId([3; 16]),
            origin_seq: 4,
        })
        .unwrap();
        assert_eq!(w.out.len(), STAMP_LEN);
    }

    #[test]
    fn strictly_ascending_rules() {
        assert!(strictly_ascending([1, 2, 3].iter()));
        assert!(strictly_ascending(core::iter::empty::<u8>()));
        assert!(!strictly_ascending([1, 1].iter()));
        assert!(!strictly_ascending([2, 1].iter()));
    }
}
