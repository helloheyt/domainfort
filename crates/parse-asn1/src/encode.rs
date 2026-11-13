//! Canonical DER encoder for the Kerberos ASN.1 subset.
//!
//! Produces exactly the Distinguished Encoding Rules form: definite lengths in
//! the minimum octets (X.690 10.1), primitive string encodings (10.2), SET OF
//! components sorted into canonical order (11.6), and BOOLEAN TRUE as 0xFF
//! (11.1). The encoder refuses to emit a non-canonical [`Value`] (e.g. a
//! non-minimal INTEGER): it returns an `Err` instead, so that decode→encode is a
//! true round trip and encode→decode always re-reads.
//!
//! Spec basis: ITU-T X.690 (02/2021) clauses 8, 10, 11; ITU-T X.680 (02/2021)
//! Table 1.

use crate::decode::{validate_bit_string, validate_generalized_time, validate_integer};
use crate::error::{Error, Result};
use crate::types::{
    set_of_cmp, Tag, TagClass, Value, TAG_BIT_STRING, TAG_BOOLEAN, TAG_ENUMERATED,
    TAG_GENERALIZED_TIME, TAG_GENERAL_STRING, TAG_INTEGER, TAG_OBJECT_IDENTIFIER, TAG_OCTET_STRING,
    TAG_SEQUENCE, TAG_SET,
};

/// Encode one [`Value`] as canonical DER.
///
/// Returns an `Err` if the value is not in canonical form (so the output is
/// always valid DER). Spec: X.690 clause 10 (DER).
pub fn encode(value: &Value) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    encode_into(value, &mut out)?;
    Ok(out)
}

/// Encode one element at the tag-length-value level: the identifier octets
/// for `tag`, the definite length of `contents` in the minimum number of
/// octets, then `contents` unchanged. The contents are the caller's: this
/// function writes canonical identifier and length octets only, so it can
/// build structures outside the [`Value`] model (implicitly tagged types,
/// restricted character string types, UTCTime) whose contents the caller has
/// already put in DER form.
///
/// Spec: X.690 8.1.2 (identifier octets), 8.1.3.4 / 8.1.3.5 (definite
/// length), 10.1 (DER: minimum number of length octets).
#[must_use]
pub fn encode_element(tag: Tag, contents: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(contents.len().saturating_add(16));
    write_tlv(tag.class, tag.constructed, tag.number, contents, &mut out);
    out
}

/// Append the canonical DER encoding of `value` to `out`.
fn encode_into(value: &Value, out: &mut Vec<u8>) -> Result<()> {
    match value {
        Value::Boolean(b) => {
            // 11.1: TRUE is 0xFF; 8.2.1: single octet, primitive.
            let octet = if *b { 0xFF } else { 0x00 };
            write_tlv(TagClass::Universal, false, TAG_BOOLEAN, &[octet], out);
        }
        Value::Integer(bytes) => {
            validate_integer(bytes)?; // 8.3.2 minimal form
            write_tlv(TagClass::Universal, false, TAG_INTEGER, bytes, out);
        }
        Value::Enumerated(bytes) => {
            validate_integer(bytes)?; // 8.4 (as INTEGER)
            write_tlv(TagClass::Universal, false, TAG_ENUMERATED, bytes, out);
        }
        Value::BitString { unused_bits, bytes } => {
            validate_bit_string(*unused_bits, bytes)?; // 8.6.2.2, 11.2.1
            let mut contents = Vec::with_capacity(bytes.len() + 1);
            contents.push(*unused_bits); // 8.6.2.2 initial octet
            contents.extend_from_slice(bytes);
            // 10.2: primitive encoding in DER.
            write_tlv(TagClass::Universal, false, TAG_BIT_STRING, &contents, out);
        }
        Value::OctetString(bytes) => {
            write_tlv(TagClass::Universal, false, TAG_OCTET_STRING, bytes, out);
        }
        Value::GeneralString(bytes) => {
            write_tlv(TagClass::Universal, false, TAG_GENERAL_STRING, bytes, out);
        }
        Value::GeneralizedTime(bytes) => {
            validate_generalized_time(bytes)?; // 11.7
            write_tlv(TagClass::Universal, false, TAG_GENERALIZED_TIME, bytes, out);
        }
        Value::ObjectIdentifier(arcs) => {
            let contents = encode_oid(arcs)?;
            write_tlv(
                TagClass::Universal,
                false,
                TAG_OBJECT_IDENTIFIER,
                &contents,
                out,
            );
        }
        Value::Sequence(children) => {
            // 8.9/8.10: constructed; components in order.
            let mut contents = Vec::new();
            for child in children {
                encode_into(child, &mut contents)?;
            }
            write_tlv(TagClass::Universal, true, TAG_SEQUENCE, &contents, out);
        }
        Value::SetOf(children) => {
            // 8.12/11.6: constructed; components sorted into canonical order.
            let mut encoded: Vec<Vec<u8>> = Vec::with_capacity(children.len());
            for child in children {
                encoded.push(encode(child)?);
            }
            encoded.sort_by(|a, b| set_of_cmp(a, b));
            let mut contents = Vec::new();
            for element in &encoded {
                contents.extend_from_slice(element);
            }
            write_tlv(TagClass::Universal, true, TAG_SET, &contents, out);
        }
        Value::ContextTag { number, inner } => {
            // 8.14.3: explicit tag — constructed, contents = complete base encoding.
            let contents = encode(inner)?;
            write_tlv(TagClass::ContextSpecific, true, *number, &contents, out);
        }
        Value::Application { number, inner } => {
            let contents = encode(inner)?;
            write_tlv(TagClass::Application, true, *number, &contents, out);
        }
    }
    Ok(())
}

/// Write a complete tag-length-value unit. Spec: X.690 8.1.
fn write_tlv(class: TagClass, constructed: bool, number: u32, contents: &[u8], out: &mut Vec<u8>) {
    write_identifier(class, constructed, number, out);
    write_length(contents.len(), out);
    out.extend_from_slice(contents);
}

/// Write the identifier octets. Spec: X.690 8.1.2.
fn write_identifier(class: TagClass, constructed: bool, number: u32, out: &mut Vec<u8>) {
    // Bits 8-7: class. Spec: X.690 8.1.2.2 a), Table 1.
    let class_bits: u8 = match class {
        TagClass::Universal => 0x00,
        TagClass::Application => 0x40,
        TagClass::ContextSpecific => 0x80,
        TagClass::Private => 0xC0,
    };
    // Bit 6: constructed. Spec: X.690 8.1.2.5.
    let constructed_bit: u8 = if constructed { 0x20 } else { 0x00 };
    if number <= 30 {
        // Low-tag-number form. Spec: X.690 8.1.2.2.
        out.push(class_bits | constructed_bit | (number as u8));
    } else {
        // High-tag-number form. Spec: X.690 8.1.2.4.
        out.push(class_bits | constructed_bit | 0x1F);
        write_base128(number, out);
    }
}

/// Write a tag number in base-128 with continuation bits (high-tag form).
/// Spec: X.690 8.1.2.4.2 (bit 8 set on all but the last octet; minimal).
fn write_base128(mut number: u32, out: &mut Vec<u8>) {
    // Build the 7-bit groups most-significant first.
    let mut groups = [0u8; 5]; // u32 needs at most 5 groups of 7 bits
    let mut count = 0usize;
    loop {
        groups[count] = (number & 0x7F) as u8;
        count += 1;
        number >>= 7;
        if number == 0 {
            break;
        }
    }
    // Emit most-significant first; every octet but the last sets bit 8.
    for i in (0..count).rev() {
        let last = i == 0;
        let continuation = if last { 0x00 } else { 0x80 };
        out.push(continuation | groups[i]);
    }
}

/// Write definite-form length octets in the minimum number of octets.
/// Spec: X.690 8.1.3.4 (short form), 8.1.3.5 (long form), 10.1 (minimal).
fn write_length(length: usize, out: &mut Vec<u8>) {
    if length <= 0x7F {
        out.push(length as u8); // short form
        return;
    }
    // Long form: big-endian length with no leading zero octets.
    let bytes = length.to_be_bytes();
    let first_significant = bytes
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(bytes.len() - 1);
    let significant = &bytes[first_significant..];
    // Initial octet: bit 8 set, low 7 bits = number of subsequent octets.
    out.push(0x80 | (significant.len() as u8));
    out.extend_from_slice(significant);
}

/// Encode an OBJECT IDENTIFIER's arcs into contents octets. Spec: X.690 8.19.
fn encode_oid(arcs: &[u64]) -> Result<Vec<u8>> {
    // 8.19.3/8.19.4: the first two arcs combine into one subidentifier, so at
    // least two arcs are required.
    if arcs.len() < 2 {
        return Err(Error::InvalidOid);
    }
    let first = arcs[0];
    let second = arcs[1];
    // 8.19.4: first arc is 0, 1 or 2; for 0 and 1 the second arc is < 40.
    if first > 2 || (first < 2 && second >= 40) {
        return Err(Error::InvalidOid);
    }
    let first_subid = first
        .checked_mul(40)
        .and_then(|v| v.checked_add(second))
        .ok_or(Error::InvalidOid)?;
    let mut out = Vec::new();
    write_subidentifier(first_subid, &mut out);
    for &arc in &arcs[2..] {
        write_subidentifier(arc, &mut out);
    }
    Ok(out)
}

/// Write one OID subidentifier in base-128, fewest octets. Spec: X.690 8.19.2.
fn write_subidentifier(mut subid: u64, out: &mut Vec<u8>) {
    let mut groups = [0u8; 10]; // u64 needs at most 10 groups of 7 bits
    let mut count = 0usize;
    loop {
        groups[count] = (subid & 0x7F) as u8;
        count += 1;
        subid >>= 7;
        if subid == 0 {
            break;
        }
    }
    for i in (0..count).rev() {
        let last = i == 0;
        let continuation = if last { 0x00 } else { 0x80 };
        out.push(continuation | groups[i]);
    }
}
