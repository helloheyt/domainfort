//! Internal helpers that map the RFC 4120 ASN.1 constructs onto `parse-asn1`'s
//! [`Value`] model: explicit `[APPLICATION n]` / context `[n]` tags, SEQUENCE
//! components in definition order, SEQUENCE OF with element bounds, and the
//! constrained INTEGER types.
//!
//! Spec: RFC 4120 §5 ("DEFINITIONS EXPLICIT TAGS"), 5.1, 5.2.4, Appendix A;
//! X.690 (02/2021) 8.9 (sequence), 8.10 (sequence-of), 8.14.3 (explicit tag).

use crate::error::{Error, Result};
use crate::limits::MAX_MESSAGE_LEN;
use parse_asn1::Value;
use zeroize::{Zeroize, Zeroizing};

// ---------------------------------------------------------------------------
// Top-level framing
// ---------------------------------------------------------------------------

/// Decode exactly one complete DER structure, after the size bound.
///
/// Spec: RFC 4120 5.1.1 (DER only; BER is not accepted); framing, depth and
/// canonical-form rules are enforced by `parse-asn1` (X.690 clauses 8, 10, 11).
pub(crate) fn decode_top(bytes: &[u8]) -> Result<Value> {
    if bytes.len() > MAX_MESSAGE_LEN {
        return Err(Error::MessageTooLarge);
    }
    Ok(parse_asn1::decode(bytes)?)
}

/// Encode one structure as canonical DER, refusing output over the size bound
/// (so everything this crate encodes, it also decodes).
/// Spec: RFC 4120 5.1.1; X.690 clause 10.
pub(crate) fn encode_top(value: &Value) -> Result<Vec<u8>> {
    let out = parse_asn1::encode(value)?;
    if out.len() > MAX_MESSAGE_LEN {
        return Err(Error::MessageTooLarge);
    }
    Ok(out)
}

/// Decode a structure that carries key material (an EncryptionKey).
///
/// The intermediate `parse-asn1` value tree holds a copy of the key octets, so
/// it is scrubbed on every path — success or error — before returning.
/// Spec: RFC 4120 5.2.9 (EncryptionKey.keyvalue "contains the key itself");
/// docs/CLEAN-ROOM.md (secrets).
pub(crate) fn decode_secret<T>(
    bytes: &[u8],
    convert: impl FnOnce(&Value) -> Result<T>,
) -> Result<T> {
    let mut value = decode_top(bytes)?;
    let result = convert(&value);
    scrub(&mut value);
    result
}

/// Encode a structure that carries key material. The intermediate value tree is
/// scrubbed and the output is returned in a [`Zeroizing`] buffer.
/// Spec: RFC 4120 5.2.9; docs/CLEAN-ROOM.md (secrets).
pub(crate) fn encode_secret(mut value: Value) -> Result<Zeroizing<Vec<u8>>> {
    let result = parse_asn1::encode(&value).map(Zeroizing::new);
    scrub(&mut value);
    let out = result?;
    if out.len() > MAX_MESSAGE_LEN {
        // `out` is dropped here and zeroized by `Zeroizing`.
        return Err(Error::MessageTooLarge);
    }
    Ok(out)
}

/// Overwrite every buffer in a value tree with zeros (RustCrypto `zeroize`).
///
/// Iterative with an explicit work list, so the walk never recurses on an
/// input-shaped depth (docs/CLEAN-ROOM.md). Used for trees that held key material.
pub(crate) fn scrub(value: &mut Value) {
    let mut work: Vec<&mut Value> = vec![value];
    while let Some(node) = work.pop() {
        match node {
            Value::Boolean(b) => b.zeroize(),
            Value::Integer(bytes)
            | Value::Enumerated(bytes)
            | Value::OctetString(bytes)
            | Value::GeneralizedTime(bytes)
            | Value::GeneralString(bytes) => bytes.zeroize(),
            Value::BitString { bytes, .. } => bytes.zeroize(),
            Value::ObjectIdentifier(arcs) => arcs.zeroize(),
            Value::Sequence(children) | Value::SetOf(children) => work.extend(children.iter_mut()),
            Value::ContextTag { inner, .. } | Value::Application { inner, .. } => {
                work.push(inner.as_mut());
            }
        }
    }
}

/// SEQUENCE components under construction for a key-bearing type. If building
/// fails part-way (`?` returns early), the components already built — which
/// may include a copy of key octets — are scrubbed on drop.
/// Spec: RFC 4120 5.2.9; docs/CLEAN-ROOM.md (secrets).
pub(crate) struct SecretFields(Vec<Value>);

impl SecretFields {
    pub(crate) fn new() -> Self {
        SecretFields(Vec::new())
    }

    pub(crate) fn push(&mut self, value: Value) {
        self.0.push(value);
    }

    /// Hand the finished components over as a SEQUENCE value (the caller
    /// passes it on to [`encode_secret`], which scrubs it after encoding).
    pub(crate) fn into_sequence(mut self) -> Value {
        Value::Sequence(core::mem::take(&mut self.0))
    }
}

impl Drop for SecretFields {
    fn drop(&mut self) {
        for value in &mut self.0 {
            scrub(value);
        }
    }
}

// ---------------------------------------------------------------------------
// Tags
// ---------------------------------------------------------------------------

/// Unwrap an explicit `[APPLICATION number]` tag.
/// Spec: RFC 4120 5.10 (application tag numbers); 5.1.4, 5.1.5 (an
/// unrecognized tag is an error); X.690 8.14.3.
pub(crate) fn application(value: &Value, number: u32) -> Result<&Value> {
    match value {
        Value::Application { number: n, inner } if *n == number => Ok(inner),
        Value::Application { .. } => Err(Error::UnexpectedApplicationTag),
        _ => Err(Error::ExpectedApplicationTag),
    }
}

/// Build an explicit `[APPLICATION number]` tag. Spec: X.690 8.14.3.
pub(crate) fn app(number: u32, inner: Value) -> Value {
    Value::Application {
        number,
        inner: Box::new(inner),
    }
}

/// Build an explicit context tag `[number]`. Spec: X.690 8.14.3; RFC 4120 §5
/// ("DEFINITIONS EXPLICIT TAGS").
pub(crate) fn ctx(number: u32, inner: Value) -> Value {
    Value::ContextTag {
        number,
        inner: Box::new(inner),
    }
}

// ---------------------------------------------------------------------------
// SEQUENCE with explicitly tagged components
// ---------------------------------------------------------------------------

/// Reader over the components of an RFC 4120 SEQUENCE whose components are all
/// explicitly context-tagged.
///
/// [`Fields::new`] validates the whole component list up front against the
/// type's tag list (ascending, as in every RFC 4120 SEQUENCE):
/// - every component is a context tag → else [`Error::ExpectedContextTag`];
/// - every tag number is defined for the type → else [`Error::UnknownField`]
///   (RFC 4120 1.5 / 1.5.1: Kerberos is extended through typed holes, not by
///   adding fields; Appendix A has no extension marker; 5.1.4 / 5.1.5: an
///   unrecognized tag is answered with an error — fail closed);
/// - tag numbers strictly ascend → else [`Error::DuplicateField`] or
///   [`Error::FieldOutOfOrder`] (X.690 8.9.2, 8.9.3: components appear once,
///   in the order of their definition).
///
/// The `required` / `optional` calls then consume the components in order.
pub(crate) struct Fields<'a> {
    items: &'a [Value],
    pos: usize,
}

impl<'a> Fields<'a> {
    /// Validate `value` as a SEQUENCE of the given (ascending) context tags.
    pub(crate) fn new(value: &'a Value, tags: &[u32]) -> Result<Self> {
        let items = match value {
            Value::Sequence(items) => items.as_slice(),
            _ => return Err(Error::ExpectedSequence),
        };
        let mut previous: Option<u32> = None;
        for item in items {
            let number = match item {
                Value::ContextTag { number, .. } => *number,
                _ => return Err(Error::ExpectedContextTag),
            };
            if !tags.contains(&number) {
                return Err(Error::UnknownField);
            }
            if let Some(prev) = previous {
                if number == prev {
                    return Err(Error::DuplicateField);
                }
                if number < prev {
                    return Err(Error::FieldOutOfOrder);
                }
            }
            previous = Some(number);
        }
        Ok(Fields { items, pos: 0 })
    }

    /// Take the component tagged `[tag]`, which must be present.
    /// Spec: X.690 8.9.2 (a component without OPTIONAL is always encoded).
    pub(crate) fn required(&mut self, tag: u32) -> Result<&'a Value> {
        self.optional(tag).ok_or(Error::MissingField)
    }

    /// Take the component tagged `[tag]` if it is present.
    /// Spec: X.690 8.9.3 (an OPTIONAL component may be absent).
    pub(crate) fn optional(&mut self, tag: u32) -> Option<&'a Value> {
        match self.items.get(self.pos) {
            Some(Value::ContextTag { number, inner }) if *number == tag => {
                self.pos += 1;
                Some(inner)
            }
            _ => None,
        }
    }

    /// Confirm every component was consumed. Unreachable when the caller's tag
    /// list matches its reads; kept as a fail-closed guard.
    pub(crate) fn finish(self) -> Result<()> {
        if self.pos == self.items.len() {
            Ok(())
        } else {
            Err(Error::UnknownField)
        }
    }
}

// ---------------------------------------------------------------------------
// SEQUENCE OF
// ---------------------------------------------------------------------------

/// Decode a SEQUENCE OF, enforcing this crate's element bound before any
/// element is converted. Spec: X.690 8.10; resource bound per docs/CLEAN-ROOM.md
pub(crate) fn decode_sequence_of<T>(
    value: &Value,
    limit: usize,
    element: impl Fn(&Value) -> Result<T>,
) -> Result<Vec<T>> {
    let items = match value {
        Value::Sequence(items) => items,
        _ => return Err(Error::ExpectedSequence),
    };
    if items.len() > limit {
        return Err(Error::TooManyElements);
    }
    items.iter().map(element).collect()
}

/// Encode a SEQUENCE OF under the same element bound as decoding.
/// Spec: X.690 8.10.
pub(crate) fn encode_sequence_of<T>(
    items: &[T],
    limit: usize,
    element: impl Fn(&T) -> Result<Value>,
) -> Result<Value> {
    if items.len() > limit {
        return Err(Error::TooManyElements);
    }
    Ok(Value::Sequence(
        items.iter().map(element).collect::<Result<Vec<_>>>()?,
    ))
}

// ---------------------------------------------------------------------------
// INTEGER types. Spec: RFC 4120 5.2.4.
// ---------------------------------------------------------------------------

/// Read an INTEGER (never an ENUMERATED) as `i64`; an INTEGER wider than 64
/// bits is reported as `out_of_range` (it is outside every range used here).
fn integer(value: &Value, out_of_range: Error) -> Result<i64> {
    match value {
        Value::Integer(_) => value.as_i64().map_err(|_| out_of_range),
        _ => Err(Error::ExpectedInteger),
    }
}

/// `Int32 ::= INTEGER (-2147483648..2147483647)`. Spec: RFC 4120 5.2.4.
pub(crate) fn int32(value: &Value) -> Result<i32> {
    let n = integer(value, Error::Int32OutOfRange)?;
    i32::try_from(n).map_err(|_| Error::Int32OutOfRange)
}

/// `UInt32 ::= INTEGER (0..4294967295)`. Negative values are rejected (the
/// 5.5.1 seq-number leniency is not taken). Spec: RFC 4120 5.2.4, 5.5.1.
pub(crate) fn uint32(value: &Value) -> Result<u32> {
    let n = integer(value, Error::UInt32OutOfRange)?;
    u32::try_from(n).map_err(|_| Error::UInt32OutOfRange)
}

/// `Microseconds ::= INTEGER (0..999999)`. Spec: RFC 4120 5.2.4.
pub(crate) fn microseconds(value: &Value) -> Result<crate::Microseconds> {
    let n = integer(value, Error::MicrosecondsOutOfRange)?;
    let n = u32::try_from(n).map_err(|_| Error::MicrosecondsOutOfRange)?;
    crate::Microseconds::new(n)
}

/// `pvno` / `tkt-vno` / `authenticator-vno`: `INTEGER (5)`.
/// Spec: RFC 4120 5.2.4 ("always the constant integer 5"), 7.5.6.
pub(crate) fn pvno(value: &Value) -> Result<()> {
    if integer(value, Error::InvalidPvno)? == crate::constants::PVNO {
        Ok(())
    } else {
        Err(Error::InvalidPvno)
    }
}

/// `msg-type`: must be one of the values the module permits for the type
/// (`permitted`), and must equal the value implied by the application tag
/// (`expected`). Spec: RFC 4120 Appendix A; 5.4.1, 5.4.2, 5.2.4.
pub(crate) fn msg_type(value: &Value, permitted: &[i64], expected: i64) -> Result<()> {
    let n = integer(value, Error::InvalidMsgType)?;
    if !permitted.contains(&n) {
        return Err(Error::InvalidMsgType);
    }
    if n != expected {
        return Err(Error::MsgTypeMismatch);
    }
    Ok(())
}

/// Encode an INTEGER. Spec: X.690 8.3.
pub(crate) fn int(n: i64) -> Value {
    Value::integer(n)
}

// ---------------------------------------------------------------------------
// OCTET STRING. Spec: X.690 8.7.
// ---------------------------------------------------------------------------

/// Read an OCTET STRING's octets.
pub(crate) fn octet_string(value: &Value) -> Result<&[u8]> {
    match value {
        Value::OctetString(bytes) => Ok(bytes),
        _ => Err(Error::ExpectedOctetString),
    }
}

/// Encode an OCTET STRING.
pub(crate) fn octets(bytes: &[u8]) -> Value {
    Value::OctetString(bytes.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `scrub` reaches every buffer of a nested tree (docs/CLEAN-ROOM.md). The
    /// `zeroize` crate's `Vec` impl wipes the whole capacity and truncates, so
    /// every buffer is left empty.
    #[test]
    fn scrub_wipes_every_buffer() {
        let mut tree = app(
            3,
            Value::Sequence(vec![
                ctx(1, Value::Sequence(vec![ctx(1, octets(&[0x5A; 32]))])),
                ctx(2, Value::GeneralString(b"EXAMPLE.ORG".to_vec())),
                ctx(5, Value::GeneralizedTime(b"20261113090000Z".to_vec())),
                Value::SetOf(vec![Value::Integer(vec![0x12])]),
                Value::BitString {
                    unused_bits: 0,
                    bytes: vec![1, 2, 3, 4],
                },
                Value::ObjectIdentifier(vec![1, 3, 6]),
                Value::Boolean(true),
            ]),
        );
        scrub(&mut tree);
        let mut work = vec![&tree];
        while let Some(node) = work.pop() {
            match node {
                Value::Boolean(b) => assert!(!b),
                Value::Integer(v)
                | Value::Enumerated(v)
                | Value::OctetString(v)
                | Value::GeneralizedTime(v)
                | Value::GeneralString(v) => assert!(v.is_empty()),
                Value::BitString { bytes, .. } => assert!(bytes.is_empty()),
                Value::ObjectIdentifier(arcs) => assert!(arcs.is_empty()),
                Value::Sequence(children) | Value::SetOf(children) => work.extend(children),
                Value::ContextTag { inner, .. } | Value::Application { inner, .. } => {
                    work.push(inner)
                }
            }
        }
    }

    /// `into_sequence` hands the components over intact; the scrubbing `Drop`
    /// then runs on the emptied list, not on the handed-over values.
    #[test]
    fn secret_fields_hand_over_components() {
        let mut fields = SecretFields::new();
        fields.push(ctx(0, octets(&[0x5A; 4])));
        match fields.into_sequence() {
            Value::Sequence(items) => assert_eq!(items.len(), 1),
            _ => panic!("expected a SEQUENCE"),
        }
    }
}
