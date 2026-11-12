//! Test vectors for the strict DER codec.
//!
//! Every vector names its source. Sources are allowed per AGENTS.md §3/§4.5:
//! examples from ITU-T X.690 (02/2021) and ITU-T X.680 (02/2021), the example
//! in RFC 4120 §5.2.3, and byte sequences hand-derived from a named clause.
//! No vector comes from any other implementation's test suite.

use parse_asn1::{decode, encode, Error, Value};

/// Assert the canonical round trips hold for `bytes` ⇄ `value`.
///
/// Spec: X.690 clause 10 (DER is a single canonical encoding), so
/// `encode(decode(bytes)) == bytes` and `decode(encode(value)) == value`.
fn assert_round_trip(bytes: &[u8], value: &Value) {
    let decoded = decode(bytes).expect("decode should accept this vector");
    assert_eq!(&decoded, value, "decoded value mismatch");
    let encoded = encode(value).expect("encode should accept this value");
    assert_eq!(encoded.as_slice(), bytes, "re-encoded bytes mismatch");
    // Full round trips in both directions.
    assert_eq!(encode(&decoded).unwrap().as_slice(), bytes);
    assert_eq!(&decode(&encoded).unwrap(), value);
}

#[test]
fn boolean_true() {
    // Source: X.690 (02/2021) 8.2 EXAMPLE — BOOLEAN TRUE is 01 01 FF (11.1).
    assert_round_trip(&[0x01, 0x01, 0xFF], &Value::Boolean(true));
}

#[test]
fn boolean_false_minimal() {
    // Source: X.690 8.2.2 (FALSE octet is zero) — hand-derived from the clause.
    assert_round_trip(&[0x01, 0x01, 0x00], &Value::Boolean(false));
}

#[test]
fn object_identifier_joint_iso_itu_t_999_3() {
    // Source: X.690 8.19 EXAMPLE — {2 999 3} encodes as 06 03 88 37 03.
    assert_round_trip(
        &[0x06, 0x03, 0x88, 0x37, 0x03],
        &Value::ObjectIdentifier(vec![2, 999, 3]),
    );
}

#[test]
fn bit_string_primitive_example() {
    // Source: X.690 8.6.4.2 EXAMPLE — '0A3B5F291CD'H as a primitive bit string:
    //   03 07 04 0A 3B 5F 29 1C D0   (initial octet 04 = four unused bits).
    assert_round_trip(
        &[0x03, 0x07, 0x04, 0x0A, 0x3B, 0x5F, 0x29, 0x1C, 0xD0],
        &Value::BitString {
            unused_bits: 4,
            bytes: vec![0x0A, 0x3B, 0x5F, 0x29, 0x1C, 0xD0],
        },
    );
}

#[test]
fn generalized_time_kerberos_example() {
    // Source: RFC 4120 5.2.3 EXAMPLE — KerberosTime "19851106210627Z"
    // (GeneralizedTime, UNIVERSAL 24, no fractional seconds, terminating Z).
    let text = b"19851106210627Z";
    let mut bytes = vec![0x18, 0x0F];
    bytes.extend_from_slice(text);
    assert_round_trip(&bytes, &Value::GeneralizedTime(text.to_vec()));
}

#[test]
fn integer_minimal_forms() {
    // Source: X.690 8.3.2/8.3.3 (two's complement, smallest number of octets) —
    // byte forms hand-derived from the clause.
    assert_round_trip(&[0x02, 0x01, 0x00], &Value::integer(0));
    assert_round_trip(&[0x02, 0x01, 0x7F], &Value::integer(127));
    // 128 needs a leading 0x00 so the value is not read as negative (8.3.2).
    assert_round_trip(&[0x02, 0x02, 0x00, 0x80], &Value::integer(128));
    assert_round_trip(&[0x02, 0x01, 0x80], &Value::integer(-128));
    assert_round_trip(&[0x02, 0x01, 0xFF], &Value::integer(-1));
    // The numeric reader agrees with the constructors.
    assert_eq!(Value::integer(128).as_i64().unwrap(), 128);
    assert_eq!(Value::integer(-128).as_i64().unwrap(), -128);
}

#[test]
fn sequence_of_integer_and_boolean() {
    // Source: X.690 8.9 (SEQUENCE is constructed; components in order), 8.3, 8.2.
    // Hand-derived: SEQUENCE { INTEGER 1, BOOLEAN TRUE }
    //   30 06 02 01 01 01 01 FF
    assert_round_trip(
        &[0x30, 0x06, 0x02, 0x01, 0x01, 0x01, 0x01, 0xFF],
        &Value::Sequence(vec![Value::integer(1), Value::Boolean(true)]),
    );
}

#[test]
fn explicit_context_tag_wraps_integer() {
    // Source: X.690 8.14.3 (explicit tag → constructed, contents = base encoding)
    // and RFC 4120 5.2.2 (PrincipalName name-type is [0] Int32). Hand-derived:
    //   [0] EXPLICIT INTEGER 1  =  A0 03 02 01 01
    assert_round_trip(
        &[0xA0, 0x03, 0x02, 0x01, 0x01],
        &Value::ContextTag {
            number: 0,
            inner: Box::new(Value::integer(1)),
        },
    );
}

#[test]
fn application_tag_wraps_sequence() {
    // Source: RFC 4120 5.3.1 (Ticket ::= [APPLICATION 1] SEQUENCE { ... }) and
    // X.690 8.14.3. Hand-derived minimal shape:
    //   [APPLICATION 1] EXPLICIT SEQUENCE { INTEGER 5 } = 61 05 30 03 02 01 05
    assert_round_trip(
        &[0x61, 0x05, 0x30, 0x03, 0x02, 0x01, 0x05],
        &Value::Application {
            number: 1,
            inner: Box::new(Value::Sequence(vec![Value::integer(5)])),
        },
    );
}

#[test]
fn set_of_is_sorted_on_encode() {
    // Source: X.690 11.6 (SET OF components appear in ascending order of their
    // encodings). Build from unsorted input; the encoder must sort.
    let value = Value::SetOf(vec![
        Value::OctetString(vec![0x02]),
        Value::OctetString(vec![0x01]),
    ]);
    let encoded = encode(&value).unwrap();
    // Canonical order: 04 01 01 before 04 01 02.
    assert_eq!(
        encoded,
        vec![0x31, 0x06, 0x04, 0x01, 0x01, 0x04, 0x01, 0x02]
    );
    // Decoding returns the components in that canonical order.
    assert_eq!(
        decode(&encoded).unwrap(),
        Value::SetOf(vec![
            Value::OctetString(vec![0x01]),
            Value::OctetString(vec![0x02]),
        ])
    );
}

// ----------------------------------------------------------------------------
// Rejection vectors (acceptance criterion docs/45 §7.2): the decoder must reject
// every non-DER / non-canonical input with a specific error.
// ----------------------------------------------------------------------------

#[test]
fn rejects_indefinite_length() {
    // X.690 8.1.3.6 / 10.1: the indefinite form is forbidden in DER.
    assert_eq!(
        decode(&[0x30, 0x80, 0x00, 0x00]),
        Err(Error::IndefiniteLength)
    );
}

#[test]
fn rejects_non_minimal_length_long_form() {
    // X.690 10.1: long form where the short form fits is non-minimal.
    assert_eq!(
        decode(&[0x01, 0x81, 0x01, 0xFF]),
        Err(Error::NonMinimalLength)
    );
}

#[test]
fn rejects_non_minimal_length_leading_zero() {
    // X.690 10.1: a leading zero length octet is non-minimal.
    assert_eq!(
        decode(&[0x04, 0x82, 0x00, 0x01, 0x41]),
        Err(Error::NonMinimalLength)
    );
}

#[test]
fn rejects_reserved_length_octet() {
    // X.690 8.1.3.5 c): 0xFF is reserved.
    assert_eq!(decode(&[0x01, 0xFF]), Err(Error::ReservedLengthOctet));
}

#[test]
fn rejects_trailing_data() {
    // Strict framing: nothing may follow a complete top-level value.
    assert_eq!(decode(&[0x01, 0x01, 0xFF, 0x00]), Err(Error::TrailingData));
}

#[test]
fn rejects_length_exceeding_input() {
    // X.690 8.1.3.3: the length counts contents octets that must be present.
    assert_eq!(
        decode(&[0x04, 0x05, 0x01, 0x02, 0x03]),
        Err(Error::LengthExceedsInput)
    );
}

#[test]
fn rejects_non_minimal_integer() {
    // X.690 8.3.2: a redundant leading 0x00 (next top bit clear) is non-minimal.
    assert_eq!(
        decode(&[0x02, 0x02, 0x00, 0x7F]),
        Err(Error::NonMinimalInteger)
    );
    // A redundant leading 0xFF (next top bit set) is non-minimal.
    assert_eq!(
        decode(&[0x02, 0x02, 0xFF, 0xFF]),
        Err(Error::NonMinimalInteger)
    );
}

#[test]
fn rejects_empty_integer() {
    // X.690 8.3.1: an INTEGER has one or more contents octets.
    assert_eq!(decode(&[0x02, 0x00]), Err(Error::EmptyInteger));
}

#[test]
fn rejects_non_canonical_boolean() {
    // X.690 11.1: in DER, TRUE is 0xFF; any other non-zero octet is invalid.
    assert_eq!(decode(&[0x01, 0x01, 0x01]), Err(Error::InvalidBoolean));
    // X.690 8.2.1: a BOOLEAN is a single octet.
    assert_eq!(
        decode(&[0x01, 0x02, 0x00, 0x00]),
        Err(Error::InvalidBoolean)
    );
}

#[test]
fn rejects_constructed_integer() {
    // X.690 8.3.1: an INTEGER encoding is primitive. 0x22 sets the constructed
    // bit on a universal INTEGER tag.
    assert_eq!(
        decode(&[0x22, 0x03, 0x02, 0x01, 0x01]),
        Err(Error::PrimitiveConstructedMismatch)
    );
}

#[test]
fn rejects_bit_string_non_zero_unused() {
    // X.690 11.2.1: unused bits in the final octet are zero.
    assert_eq!(
        decode(&[0x03, 0x02, 0x01, 0x01]),
        Err(Error::BitStringNonZeroUnused)
    );
}

#[test]
fn rejects_bit_string_too_many_unused() {
    // X.690 8.6.2.2: the unused-bit count is in the range 0..=7.
    assert_eq!(
        decode(&[0x03, 0x02, 0x08, 0x00]),
        Err(Error::BitStringUnusedBits)
    );
}

#[test]
fn rejects_non_minimal_oid_subidentifier() {
    // X.690 8.19.2: a subidentifier's leading octet is never 0x80.
    assert_eq!(
        decode(&[0x06, 0x02, 0x80, 0x01]),
        Err(Error::NonMinimalSubidentifier)
    );
}

#[test]
fn rejects_truncated_oid_subidentifier() {
    // X.690 8.19.2: the final octet of a subidentifier has bit 8 clear.
    assert_eq!(
        decode(&[0x06, 0x02, 0x81, 0x80]),
        Err(Error::OidTruncatedSubidentifier)
    );
}

#[test]
fn rejects_non_canonical_set_of() {
    // X.690 11.6: SET OF components must be in ascending order.
    assert_eq!(
        decode(&[0x31, 0x06, 0x04, 0x01, 0x02, 0x04, 0x01, 0x01]),
        Err(Error::SetOfNotCanonical)
    );
}

#[test]
fn rejects_invalid_generalized_time() {
    // X.690 11.7.1/11.7.2: must terminate with Z and carry 14 date-time digits.
    assert_eq!(
        decode(&[0x18, 0x01, 0x5A]),
        Err(Error::InvalidGeneralizedTime)
    );
    // X.690 11.7.3: fractional seconds omit trailing zeros ("...627.0Z").
    let mut with_trailing_zero = vec![0x18, 0x11];
    with_trailing_zero.extend_from_slice(b"19851106210627.0Z");
    assert_eq!(
        decode(&with_trailing_zero),
        Err(Error::InvalidGeneralizedTime)
    );
}

#[test]
fn rejects_over_depth_nesting() {
    // AGENTS.md §6 / docs/32 §8: nesting is bounded (MAX_DEPTH). Build a chain of
    // explicit context tags deeper than the limit, then decode it.
    let mut value = Value::integer(1);
    for _ in 0..(parse_asn1::MAX_DEPTH + 5) {
        value = Value::ContextTag {
            number: 0,
            inner: Box::new(value),
        };
    }
    let bytes = encode(&value).unwrap();
    assert_eq!(decode(&bytes), Err(Error::DepthExceeded));
}

#[test]
fn integer_reader_rejects_out_of_range() {
    // Host limit: an INTEGER wider than 8 octets does not fit an i64.
    // Minimal 9-octet value (first octet 0x01 is significant).
    let nine = Value::Integer(vec![0x01, 0, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(nine.as_i64(), Err(Error::IntegerOutOfRange));
}

#[test]
fn rejects_tag_number_overflow() {
    // X.690 8.1.2.4: a high-tag-number form whose value overflows the supported
    // range is rejected (not silently wrapped). 0xBF = context, constructed,
    // high-tag escape; the 0xFF continuation octets accumulate past u32.
    assert_eq!(
        decode(&[0xBF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00]),
        Err(Error::TagNumberOverflow)
    );
}

#[test]
fn rejects_oid_subidentifier_overflow() {
    // X.690 8.19.2: a subidentifier whose value overflows u64 is rejected (not
    // silently wrapped). Ten 0xFF continuation octets exceed 64 bits.
    assert_eq!(
        decode(&[0x06, 0x0A, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
        Err(Error::InvalidOid)
    );
}

#[test]
fn encoder_rejects_non_canonical_value() {
    // The encoder refuses to emit a non-canonical INTEGER (X.690 8.3.2) so its
    // output is always valid DER.
    assert_eq!(
        encode(&Value::Integer(vec![0x00, 0x7F])),
        Err(Error::NonMinimalInteger)
    );
    // And refuses a malformed OBJECT IDENTIFIER (fewer than two arcs, 8.19.4).
    assert_eq!(
        encode(&Value::ObjectIdentifier(vec![2])),
        Err(Error::InvalidOid)
    );
}
