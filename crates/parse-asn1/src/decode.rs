//! Strict DER decoder for the Kerberos ASN.1 subset.
//!
//! Only the Distinguished Encoding Rules are accepted: definite lengths encoded
//! in the minimum octets, canonical SET OF ordering, primitive encodings where
//! DER requires them, and no trailing data. Anything else is a distinct `Err`
//! (fail closed — AGENTS.md §6; docs/32 §8). The decoder is bounded: every
//! length is checked against the remaining input before use (so nothing is
//! allocated from an attacker-controlled length without a bound), and nesting is
//! capped at [`crate::MAX_DEPTH`].
//!
//! Spec basis: ITU-T X.690 (02/2021) clauses 8, 10, 11; ITU-T X.680 (02/2021)
//! Table 1; type set per RFC 4120 §5 (docs/45 §3).

use crate::error::{Error, Result};
use crate::types::{
    set_of_cmp, Tag, TagClass, Value, MAX_DEPTH, TAG_BIT_STRING, TAG_BOOLEAN, TAG_ENUMERATED,
    TAG_GENERALIZED_TIME, TAG_GENERAL_STRING, TAG_INTEGER, TAG_OBJECT_IDENTIFIER, TAG_OCTET_STRING,
    TAG_SEQUENCE, TAG_SET,
};
use core::cmp::Ordering;

/// Decode exactly one DER value from `input`.
///
/// Returns [`Error::TrailingData`] if any octet remains after the value.
/// Spec: X.690 8 (a single encoding); strict framing.
pub fn decode(input: &[u8]) -> Result<Value> {
    let mut cursor = Cursor::new(input);
    let value = cursor.read_value(0)?;
    if !cursor.at_end() {
        return Err(Error::TrailingData);
    }
    Ok(value)
}

/// A bounded forward cursor over a byte slice.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

/// One decoded tag-length-value unit.
struct Tlv<'a> {
    tag: Tag,
    /// The contents octets only. Spec: X.690 8.1.4.
    contents: &'a [u8],
    /// The complete encoding (identifier + length + contents). Used to verify
    /// SET OF ordering on the wire. Spec: X.690 11.6.
    element: &'a [u8],
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Cursor { buf, pos: 0 }
    }

    fn at_end(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn remaining(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }

    /// Take the next `n` octets, or [`Error::Truncated`].
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or(Error::LengthOverflow)?;
        if end > self.buf.len() {
            return Err(Error::Truncated);
        }
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn read_byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    /// Read the identifier octets. Spec: X.690 8.1.2.
    fn read_tag(&mut self) -> Result<Tag> {
        let first = self.read_byte()?;
        // Bits 8-7: class. Spec: X.690 8.1.2.2 a), Table 1.
        let class = match first >> 6 {
            0 => TagClass::Universal,
            1 => TagClass::Application,
            2 => TagClass::ContextSpecific,
            _ => TagClass::Private,
        };
        // Bit 6: primitive/constructed. Spec: X.690 8.1.2.5.
        let constructed = first & 0x20 != 0;
        // Bits 5-1: tag number (low form) or 0x1F escape to the high form.
        // Spec: X.690 8.1.2.2 c), 8.1.2.4.
        let low = first & 0x1F;
        let number = if low != 0x1F {
            u32::from(low)
        } else {
            self.read_high_tag_number()?
        };
        Ok(Tag {
            class,
            constructed,
            number,
        })
    }

    /// Read the high-tag-number form. Spec: X.690 8.1.2.4.
    fn read_high_tag_number(&mut self) -> Result<u32> {
        let mut number: u32 = 0;
        let mut first = true;
        loop {
            let octet = self.read_byte()?;
            // 8.1.2.4.2 c): bits 7-1 of the first subsequent octet are not all
            // zero (that would be a non-minimal leading octet).
            if first && (octet & 0x7F) == 0 {
                return Err(Error::NonMinimalTagNumber);
            }
            first = false;
            // Accumulate 7 bits per octet. `checked_mul` (not `checked_shl`,
            // which only guards the shift amount) detects value overflow.
            number = number
                .checked_mul(0x80)
                .and_then(|n| n.checked_add(u32::from(octet & 0x7F)))
                .ok_or(Error::TagNumberOverflow)?;
            // Bit 8 clear marks the last octet. Spec: X.690 8.1.2.4.2 a).
            if octet & 0x80 == 0 {
                break;
            }
        }
        // The high form must only be used for numbers >= 31. Spec: X.690 8.1.2.2.
        if number < 0x1F {
            return Err(Error::NonMinimalTagNumber);
        }
        Ok(number)
    }

    /// Read the length octets in strict DER form. Spec: X.690 8.1.3, 10.1.
    fn read_length(&mut self) -> Result<usize> {
        let first = self.read_byte()?;
        // Short form: bit 8 zero. Spec: X.690 8.1.3.4.
        if first & 0x80 == 0 {
            return Ok(usize::from(first));
        }
        // 0x80 is the indefinite form, forbidden in DER. Spec: 8.1.3.6; 10.1.
        if first == 0x80 {
            return Err(Error::IndefiniteLength);
        }
        // 0xFF is reserved. Spec: X.690 8.1.3.5 c).
        if first == 0xFF {
            return Err(Error::ReservedLengthOctet);
        }
        // Long form: low 7 bits give the number of subsequent octets.
        // Spec: X.690 8.1.3.5.
        let count = usize::from(first & 0x7F);
        let octets = self.take(count)?;
        // A leading zero octet would be a non-minimal length. Spec: X.690 10.1.
        if octets[0] == 0 {
            return Err(Error::NonMinimalLength);
        }
        let mut length: usize = 0;
        for &octet in octets {
            // `checked_mul` (not `checked_shl`, which only guards the shift
            // amount) detects a length that overflows a machine word.
            length = length
                .checked_mul(0x100)
                .and_then(|l| l.checked_add(usize::from(octet)))
                .ok_or(Error::LengthOverflow)?;
        }
        // The long form must not be used when the short form would fit.
        // Spec: X.690 10.1 (minimum number of octets).
        if length <= 0x7F {
            return Err(Error::NonMinimalLength);
        }
        Ok(length)
    }

    /// Read one tag-length-value unit, bounding the length against the input.
    fn read_tlv(&mut self) -> Result<Tlv<'a>> {
        let start = self.pos;
        let tag = self.read_tag()?;
        let length = self.read_length()?;
        // Bound the declared length against what is actually present before
        // slicing. Spec: X.690 8.1.3.3; AGENTS.md §6 (no unbounded reads).
        if length > self.remaining().len() {
            return Err(Error::LengthExceedsInput);
        }
        let contents = self.take(length)?;
        let element = &self.buf[start..self.pos];
        Ok(Tlv {
            tag,
            contents,
            element,
        })
    }

    /// Read one complete value, dispatching on its tag.
    fn read_value(&mut self, depth: usize) -> Result<Value> {
        if depth > MAX_DEPTH {
            return Err(Error::DepthExceeded);
        }
        let tlv = self.read_tlv()?;
        match tlv.tag.class {
            TagClass::Universal => self.decode_universal(&tlv, depth),
            TagClass::ContextSpecific => {
                // Kerberos tags EXPLICIT, so a context tag is constructed and
                // wraps exactly one value. Spec: X.690 8.14.3; RFC 4120 §5.
                let inner = decode_explicit_inner(&tlv, depth)?;
                Ok(Value::ContextTag {
                    number: tlv.tag.number,
                    inner: Box::new(inner),
                })
            }
            TagClass::Application => {
                let inner = decode_explicit_inner(&tlv, depth)?;
                Ok(Value::Application {
                    number: tlv.tag.number,
                    inner: Box::new(inner),
                })
            }
            TagClass::Private => Err(Error::UnsupportedTag),
        }
    }

    /// Decode a universal-class value. Spec: X.680 Table 1; X.690 clause 8.
    fn decode_universal(&self, tlv: &Tlv<'a>, depth: usize) -> Result<Value> {
        match tlv.tag.number {
            TAG_BOOLEAN => {
                require_primitive(tlv)?;
                Ok(Value::Boolean(decode_boolean(tlv.contents)?))
            }
            TAG_INTEGER => {
                require_primitive(tlv)?;
                validate_integer(tlv.contents)?;
                Ok(Value::Integer(tlv.contents.to_vec()))
            }
            TAG_ENUMERATED => {
                require_primitive(tlv)?;
                validate_integer(tlv.contents)?;
                Ok(Value::Enumerated(tlv.contents.to_vec()))
            }
            TAG_BIT_STRING => {
                // DER forbids the constructed form. Spec: X.690 10.2.
                require_primitive(tlv)?;
                decode_bit_string(tlv.contents)
            }
            TAG_OCTET_STRING => {
                require_primitive(tlv)?; // X.690 10.2
                Ok(Value::OctetString(tlv.contents.to_vec()))
            }
            TAG_OBJECT_IDENTIFIER => {
                require_primitive(tlv)?;
                decode_oid(tlv.contents)
            }
            TAG_GENERALIZED_TIME => {
                require_primitive(tlv)?; // X.690 10.2 (VisibleString-based)
                validate_generalized_time(tlv.contents)?;
                Ok(Value::GeneralizedTime(tlv.contents.to_vec()))
            }
            TAG_GENERAL_STRING => {
                require_primitive(tlv)?; // X.690 10.2
                Ok(Value::GeneralString(tlv.contents.to_vec()))
            }
            TAG_SEQUENCE => {
                require_constructed(tlv)?; // X.690 8.9.1
                Ok(Value::Sequence(decode_children(tlv.contents, depth)?))
            }
            TAG_SET => {
                require_constructed(tlv)?; // X.690 8.11.1
                Ok(Value::SetOf(decode_set_of(tlv.contents, depth)?))
            }
            _ => Err(Error::UnsupportedTag),
        }
    }
}

/// Require a primitive encoding. Spec: X.690 8.1.2.5; per-type clauses in 8.
fn require_primitive(tlv: &Tlv<'_>) -> Result<()> {
    if tlv.tag.constructed {
        Err(Error::PrimitiveConstructedMismatch)
    } else {
        Ok(())
    }
}

/// Require a constructed encoding. Spec: X.690 8.9.1/8.11.1/8.14.3.
fn require_constructed(tlv: &Tlv<'_>) -> Result<()> {
    if tlv.tag.constructed {
        Ok(())
    } else {
        Err(Error::PrimitiveConstructedMismatch)
    }
}

/// Decode the single inner value of an explicit tag; reject trailing octets.
/// Spec: X.690 8.14.3 (contents are exactly the complete base encoding).
fn decode_explicit_inner(tlv: &Tlv<'_>, depth: usize) -> Result<Value> {
    require_constructed(tlv)?;
    let mut inner = Cursor::new(tlv.contents);
    let value = inner.read_value(depth + 1)?;
    if !inner.at_end() {
        return Err(Error::TrailingData);
    }
    Ok(value)
}

/// Decode the children of a SEQUENCE / SEQUENCE OF, in order.
/// Spec: X.690 8.9.2, 8.10.
fn decode_children(contents: &[u8], depth: usize) -> Result<Vec<Value>> {
    let mut cursor = Cursor::new(contents);
    let mut out = Vec::new();
    while !cursor.at_end() {
        out.push(cursor.read_value(depth + 1)?);
    }
    Ok(out)
}

/// Decode a SET OF, verifying canonical ascending order on the wire.
/// Spec: X.690 8.12; 11.6 (ascending, compared as octet strings with the
/// shorter padded by trailing zero octets for the comparison only).
fn decode_set_of(contents: &[u8], depth: usize) -> Result<Vec<Value>> {
    let mut cursor = Cursor::new(contents);
    let mut out = Vec::new();
    let mut previous: Option<&[u8]> = None;
    while !cursor.at_end() {
        let tlv = cursor.read_tlv()?;
        if let Some(prev) = previous {
            // 11.6: elements appear in ascending order (equal encodings, i.e.
            // duplicate values, are permitted and remain canonical).
            if set_of_cmp(prev, tlv.element) == Ordering::Greater {
                return Err(Error::SetOfNotCanonical);
            }
        }
        previous = Some(tlv.element);
        // Decode the element itself (bounded, from its own contents).
        let mut element_cursor = Cursor::new(tlv.element);
        out.push(element_cursor.read_value(depth + 1)?);
    }
    Ok(out)
}

/// Decode a BOOLEAN. Spec: X.690 8.2 (single octet); 11.1 (DER: TRUE == 0xFF).
fn decode_boolean(contents: &[u8]) -> Result<bool> {
    match contents {
        [0x00] => Ok(false),
        [0xFF] => Ok(true),
        _ => Err(Error::InvalidBoolean),
    }
}

/// Validate minimal two's-complement INTEGER contents. Spec: X.690 8.3.1/8.3.2.
pub(crate) fn validate_integer(contents: &[u8]) -> Result<()> {
    if contents.is_empty() {
        return Err(Error::EmptyInteger); // 8.3.1: one or more octets
    }
    if contents.len() >= 2 {
        let first = contents[0];
        let second_top_set = contents[1] & 0x80 != 0;
        // 8.3.2: the first octet and bit 8 of the second are not all ones and
        // not all zeros (otherwise the leading octet is redundant).
        if (first == 0x00 && !second_top_set) || (first == 0xFF && second_top_set) {
            return Err(Error::NonMinimalInteger);
        }
    }
    Ok(())
}

/// Decode a BIT STRING (primitive). Spec: X.690 8.6.2; 11.2.1.
fn decode_bit_string(contents: &[u8]) -> Result<Value> {
    let (&unused, data) = contents.split_first().ok_or(Error::BitStringEmpty)?; // 8.6.2: initial octet is present
    validate_bit_string(unused, data)?;
    Ok(Value::BitString {
        unused_bits: unused,
        bytes: data.to_vec(),
    })
}

/// Check the DER constraints on a BIT STRING's unused-bits count and data.
///
/// Spec: X.690 8.6.2.2 (0..=7 unused bits), 8.6.2.3 (empty string → zero
/// initial octet), 11.2.1 (unused bits are zero). Shared by the decoder and the
/// encoder so both enforce the same canonical form.
pub(crate) fn validate_bit_string(unused: u8, data: &[u8]) -> Result<()> {
    if unused > 7 {
        return Err(Error::BitStringUnusedBits); // 8.6.2.2
    }
    match data.last() {
        None => {
            // 8.6.2.3: an empty bit string has a zero initial octet.
            if unused != 0 {
                return Err(Error::BitStringNonZeroUnused);
            }
        }
        Some(&last) => {
            if unused > 0 {
                // 11.2.1: each unused bit in the final octet is zero.
                let mask = (1u8 << unused) - 1;
                if last & mask != 0 {
                    return Err(Error::BitStringNonZeroUnused);
                }
            }
        }
    }
    Ok(())
}

/// Decode an OBJECT IDENTIFIER. Spec: X.690 8.19.
fn decode_oid(contents: &[u8]) -> Result<Value> {
    if contents.is_empty() {
        return Err(Error::EmptyOid); // 8.19 needs at least one contents octet
    }
    let mut arcs: Vec<u64> = Vec::new();
    let mut index = 0usize;
    let mut first_subid = true;
    while index < contents.len() {
        let mut subid: u64 = 0;
        let subid_start = index;
        loop {
            let octet = contents[index];
            // 8.19.2: a subidentifier is encoded in the fewest octets, so its
            // leading octet is never 0x80.
            if index == subid_start && octet == 0x80 {
                return Err(Error::NonMinimalSubidentifier);
            }
            // `checked_mul` (not `checked_shl`, which only guards the shift
            // amount) detects a subidentifier that overflows u64.
            subid = subid
                .checked_mul(0x80)
                .and_then(|s| s.checked_add(u64::from(octet & 0x7F)))
                .ok_or(Error::InvalidOid)?;
            index += 1;
            if octet & 0x80 == 0 {
                break; // bit 8 clear: last octet of this subidentifier
            }
            if index >= contents.len() {
                // 8.19.2: the final octet must have bit 8 clear.
                return Err(Error::OidTruncatedSubidentifier);
            }
        }
        if first_subid {
            // 8.19.4: first subidentifier == X*40 + Y, X in {0,1,2}.
            let (x, y) = if subid < 40 {
                (0u64, subid)
            } else if subid < 80 {
                (1u64, subid - 40)
            } else {
                (2u64, subid - 80)
            };
            arcs.push(x);
            arcs.push(y);
            first_subid = false;
        } else {
            arcs.push(subid);
        }
    }
    Ok(Value::ObjectIdentifier(arcs))
}

/// Validate GeneralizedTime contents in DER form.
///
/// Spec: X.690 11.7 (terminating "Z"; seconds always present; fractional
/// seconds omit trailing zeros, and the "." is omitted entirely when there is
/// no fraction); X.680 46.3 (`YYYYMMDDHHMMSS` basic format). RFC 4120 5.2.3
/// uses this with no fractional seconds, e.g. `19851106210627Z`.
pub(crate) fn validate_generalized_time(contents: &[u8]) -> Result<()> {
    // Minimum is 14 date-time digits plus the "Z". Spec: X.680 46.3; X.690 11.7.2.
    if contents.len() < 15 {
        return Err(Error::InvalidGeneralizedTime);
    }
    for &c in &contents[0..14] {
        if !c.is_ascii_digit() {
            return Err(Error::InvalidGeneralizedTime);
        }
    }
    let last_index = contents.len() - 1;
    // 11.7.1: the encoding terminates with "Z".
    if contents[last_index] != b'Z' {
        return Err(Error::InvalidGeneralizedTime);
    }
    if contents.len() == 15 {
        return Ok(()); // YYYYMMDDHHMMSSZ
    }
    // 11.7.4: the fractional part, if present, starts with ".".
    if contents[14] != b'.' {
        return Err(Error::InvalidGeneralizedTime);
    }
    let fraction = &contents[15..last_index];
    if fraction.is_empty() {
        return Err(Error::InvalidGeneralizedTime); // a point with no digits
    }
    for &c in fraction {
        if !c.is_ascii_digit() {
            return Err(Error::InvalidGeneralizedTime);
        }
    }
    // 11.7.3: fractional seconds omit all trailing zeros.
    if let Some(&last_digit) = fraction.last() {
        if last_digit == b'0' {
            return Err(Error::InvalidGeneralizedTime);
        }
    }
    Ok(())
}
