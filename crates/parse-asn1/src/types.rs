//! Tag model, value model, and subset constants.
//!
//! Terminology follows the specifications (docs/CLEAN-ROOM.md): tag "class" and
//! "number", "primitive"/"constructed", and the ASN.1 type names from
//! ITU-T X.680 (02/2021) and RFC 4120 §5. No naming is mirrored from any
//! existing implementation.

use crate::error::{Error, Result};
use core::cmp::Ordering;

/// Maximum nesting depth of constructed values the decoder will descend.
///
/// This is a resource bound to stop stack exhaustion from attacker-supplied
/// nesting, not an encoding rule (docs/CLEAN-ROOM.md; docs/32 §8 "recursion-depth
/// limit"). Chosen well above the depth any RFC 4120 §5 structure reaches.
pub const MAX_DEPTH: usize = 64;

/// Tag class.
///
/// Spec: X.690 8.1.2.2, Table 1 (bits 8 and 7 of the identifier octet).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagClass {
    /// Universal (bits 8,7 = 00).
    Universal,
    /// Application (bits 8,7 = 01).
    Application,
    /// Context-specific (bits 8,7 = 10).
    ContextSpecific,
    /// Private (bits 8,7 = 11).
    Private,
}

/// A decoded ASN.1 tag: class, primitive/constructed flag, and number.
///
/// Spec: X.690 8.1.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tag {
    /// The tag class. Spec: X.690 8.1.2.2.
    pub class: TagClass,
    /// `true` for a constructed encoding, `false` for primitive.
    /// Spec: X.690 8.1.2.5.
    pub constructed: bool,
    /// The tag number. Spec: X.690 8.1.2.2 / 8.1.2.4.
    pub number: u32,
}

// Universal-class tag numbers used by the Kerberos subset.
// Spec: X.680 Table 1 (Universal class tag assignments).

/// BOOLEAN. Spec: X.680 Table 1 (UNIVERSAL 1).
pub const TAG_BOOLEAN: u32 = 1;
/// INTEGER. Spec: X.680 Table 1 (UNIVERSAL 2).
pub const TAG_INTEGER: u32 = 2;
/// BIT STRING. Spec: X.680 Table 1 (UNIVERSAL 3).
pub const TAG_BIT_STRING: u32 = 3;
/// OCTET STRING. Spec: X.680 Table 1 (UNIVERSAL 4).
pub const TAG_OCTET_STRING: u32 = 4;
/// OBJECT IDENTIFIER. Spec: X.680 Table 1 (UNIVERSAL 6).
pub const TAG_OBJECT_IDENTIFIER: u32 = 6;
/// ENUMERATED. Spec: X.680 Table 1 (UNIVERSAL 10).
pub const TAG_ENUMERATED: u32 = 10;
/// SEQUENCE and SEQUENCE OF. Spec: X.680 Table 1 (UNIVERSAL 16).
pub const TAG_SEQUENCE: u32 = 16;
/// SET and SET OF. Spec: X.680 Table 1 (UNIVERSAL 17).
pub const TAG_SET: u32 = 17;
/// GeneralizedTime. Spec: X.680 Table 1 / 46.3 (UNIVERSAL 24).
pub const TAG_GENERALIZED_TIME: u32 = 24;
/// GeneralString. Spec: X.680 Table 1 (UNIVERSAL 27).
pub const TAG_GENERAL_STRING: u32 = 27;

/// A decoded value from the Kerberos DER subset (docs/45 §3; RFC 4120 §5).
///
/// Each variant maps to one ASN.1 type. `INTEGER`/`ENUMERATED` keep their raw
/// minimal two's-complement contents octets (X.690 8.3) so that a decoded value
/// re-encodes to exactly the same bytes; use [`Value::integer`] /
/// [`Value::as_i64`] for numeric access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// BOOLEAN. Spec: X.690 8.2, 11.1.
    Boolean(bool),
    /// INTEGER, as minimal two's-complement contents octets. Spec: X.690 8.3.
    Integer(Vec<u8>),
    /// ENUMERATED, as minimal two's-complement contents octets. Spec: X.690 8.4.
    Enumerated(Vec<u8>),
    /// BIT STRING: number of unused trailing bits (0..=7) and the data octets.
    /// Spec: X.690 8.6, 10.2, 11.2.
    BitString {
        /// Unused bits in the final data octet (0..=7). Spec: X.690 8.6.2.2.
        unused_bits: u8,
        /// The data octets (without the leading unused-bits octet).
        bytes: Vec<u8>,
    },
    /// OCTET STRING. Spec: X.690 8.7, 10.2.
    OctetString(Vec<u8>),
    /// OBJECT IDENTIFIER as its sequence of arcs (at least two). Spec: X.690 8.19.
    ObjectIdentifier(Vec<u64>),
    /// GeneralizedTime contents octets (ASCII), e.g. `19851106210627Z`.
    /// Spec: X.690 8.26 / 11.7; X.680 46.3; RFC 4120 5.2.3.
    GeneralizedTime(Vec<u8>),
    /// GeneralString contents octets. Spec: X.690 8.23; X.680 Table 1 (27).
    GeneralString(Vec<u8>),
    /// SEQUENCE / SEQUENCE OF: ordered components. Spec: X.690 8.9, 8.10.
    Sequence(Vec<Value>),
    /// SET OF: components in canonical ascending order. Spec: X.690 8.12, 11.6.
    SetOf(Vec<Value>),
    /// An explicit context-specific tag `[n]` wrapping one value.
    /// Spec: X.690 8.14.3 (explicit tagging); RFC 4120 §5 (EXPLICIT TAGS).
    ContextTag {
        /// The context tag number `n`.
        number: u32,
        /// The single wrapped value.
        inner: Box<Value>,
    },
    /// An explicit `[APPLICATION n]` tag wrapping one value.
    /// Spec: X.690 8.14.3; RFC 4120 §5 (e.g. Ticket is [APPLICATION 1]).
    Application {
        /// The application tag number `n`.
        number: u32,
        /// The single wrapped value.
        inner: Box<Value>,
    },
}

impl Value {
    /// Build an INTEGER from a signed value, in minimal two's-complement form.
    ///
    /// Spec: X.690 8.3.2/8.3.3 (two's complement, smallest number of octets).
    #[must_use]
    pub fn integer(value: i64) -> Value {
        Value::Integer(encode_twos_complement(value))
    }

    /// Build an ENUMERATED from a signed value. Spec: X.690 8.4 (as INTEGER).
    #[must_use]
    pub fn enumerated(value: i64) -> Value {
        Value::Enumerated(encode_twos_complement(value))
    }

    /// Read an INTEGER or ENUMERATED as an `i64`.
    ///
    /// Returns [`Error::IntegerOutOfRange`] if the value does not fit, and
    /// [`Error::PrimitiveConstructedMismatch`] for any other variant.
    /// Spec: X.690 8.3.3 (two's-complement interpretation).
    pub fn as_i64(&self) -> Result<i64> {
        let bytes = match self {
            Value::Integer(b) | Value::Enumerated(b) => b.as_slice(),
            _ => return Err(Error::PrimitiveConstructedMismatch),
        };
        decode_twos_complement(bytes)
    }
}

/// Compare two complete encodings under the canonical SET OF ordering.
///
/// Spec: X.690 11.6 — the encodings are compared as octet strings, with the
/// shorter padded at its trailing end with zero octets for the comparison only.
pub(crate) fn set_of_cmp(a: &[u8], b: &[u8]) -> Ordering {
    let len = a.len().max(b.len());
    for i in 0..len {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        match x.cmp(&y) {
            Ordering::Equal => {}
            non_equal => return non_equal,
        }
    }
    Ordering::Equal
}

/// Encode a signed integer as minimal two's-complement contents octets.
///
/// Spec: X.690 8.3.2 (a leading 0x00 / 0xFF octet is dropped when the following
/// octet's top bit already supplies the sign) and 8.3.3 (two's complement).
pub(crate) fn encode_twos_complement(value: i64) -> Vec<u8> {
    let be = value.to_be_bytes();
    let mut start = 0usize;
    while start + 1 < be.len() {
        let octet = be[start];
        let next_top_set = be[start + 1] & 0x80 != 0;
        // Drop a redundant leading sign octet. Spec: X.690 8.3.2.
        if (octet == 0x00 && !next_top_set) || (octet == 0xFF && next_top_set) {
            start += 1;
        } else {
            break;
        }
    }
    be[start..].to_vec()
}

/// Interpret minimal two's-complement contents octets as an `i64`.
///
/// Spec: X.690 8.3.1 (one or more octets) and 8.3.3 (two's complement).
pub(crate) fn decode_twos_complement(bytes: &[u8]) -> Result<i64> {
    if bytes.is_empty() {
        return Err(Error::EmptyInteger);
    }
    // More than 8 octets cannot fit an i64; bail before the accumulator can
    // overflow. Spec: X.690 8.3.3 (two's complement); range is a host limit.
    if bytes.len() > 8 {
        return Err(Error::IntegerOutOfRange);
    }
    let negative = bytes[0] & 0x80 != 0;
    // Accumulate in i128 (sign-extended) then range-check to i64.
    let mut acc: i128 = if negative { -1 } else { 0 };
    for &octet in bytes {
        acc = (acc << 8) | i128::from(octet);
    }
    i64::try_from(acc).map_err(|_| Error::IntegerOutOfRange)
}
