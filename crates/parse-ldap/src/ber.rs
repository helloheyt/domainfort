//! The LDAP-BER profile: a bounded TLV reader and a canonical TLV writer.
//!
//! LDAP is encoded with "a subset of ASN.1 Basic Encoding Rules" (RFC 4511 §4,
//! §5.1), not DER. This module enforces the identifier and length rules of that
//! subset, with the project's choices from A-45 (docs/questions/Q-160):
//!
//! * definite lengths only (RFC 4511 §5.1; X.690 8.1.3.6);
//! * a long-form length may use more octets than necessary, up to
//!   [`MAX_LENGTH_OCTETS`] (X.690 8.1.3.5 NOTE 2; A-45) — under
//!   [`Profile::Wire`]; [`Profile::Canonical`] demands the minimum (X.690 10.1);
//! * single-octet identifiers only: LDAP defines no tag >= 31 (RFC 4511 App. B;
//!   docs/49 §2.3 E6);
//! * no `[UNIVERSAL 0]` (end-of-contents) element (X.690 8.1.5).
//!
//! The writer always emits the canonical form: definite lengths in the minimum
//! number of octets (X.690 10.1), which RFC 4511 §5.1 also permits.
//!
//! Every length is checked against the octets actually present before any
//! slice is taken (AGENTS.md §6: no unbounded allocation from attacker-supplied
//! lengths), and no function indexes or panics on input.

use crate::error::{Error, Limit, Result};
use crate::limits::{MAX_LENGTH_OCTETS, MAX_TLV_DEPTH};

/// Bit 6 of an identifier octet: set for the constructed form.
/// Spec: X.690 8.1.2.5.
pub(crate) const CONSTRUCTED: u8 = 0x20;
/// Bits 8-7 of an identifier octet: the class. Spec: X.690 8.1.2.2 a), Table 1.
pub(crate) const CLASS_MASK: u8 = 0xC0;
/// Universal class. Spec: X.690 Table 1.
pub(crate) const CLASS_UNIVERSAL: u8 = 0x00;
/// Application class. Spec: X.690 Table 1.
pub(crate) const CLASS_APPLICATION: u8 = 0x40;
/// Context-specific class. Spec: X.690 Table 1.
pub(crate) const CLASS_CONTEXT: u8 = 0x80;
/// Bits 5-1 of an identifier octet: the tag number (low form); all ones is the
/// escape to the high-tag-number form. Spec: X.690 8.1.2.2 c), 8.1.2.4.1 c).
pub(crate) const NUMBER_MASK: u8 = 0x1F;

// Universal-class identifiers used by LDAP. Tag numbers: X.680 (02/2021)
// Table 1; form: X.690 8.2.1 (BOOLEAN primitive), 8.3.1 (INTEGER primitive),
// 8.4 (ENUMERATED primitive), 8.7 + RFC 4511 §5.1 (OCTET STRING primitive),
// 8.8.1 (NULL primitive), 8.9.1 / 8.10.1 (SEQUENCE, SEQUENCE OF constructed),
// 8.12.1 (SET OF constructed).
pub(crate) const BOOLEAN: u8 = 0x01;
pub(crate) const INTEGER: u8 = 0x02;
pub(crate) const OCTET_STRING: u8 = 0x04;
pub(crate) const NULL: u8 = 0x05;
pub(crate) const ENUMERATED: u8 = 0x0A;
pub(crate) const SEQUENCE: u8 = 0x30;
pub(crate) const SET: u8 = 0x31;

/// The identifier of `[APPLICATION number]` in the given form.
/// Spec: X.690 8.1.2.2; RFC 4511 App. B (IMPLICIT TAGS, so the form is that of
/// the base type — X.690 8.14.4 a)).
pub(crate) const fn application(number: u8, constructed: bool) -> u8 {
    CLASS_APPLICATION | (number & NUMBER_MASK) | if constructed { CONSTRUCTED } else { 0 }
}

/// The identifier of a context-specific tag `[number]` in the given form.
/// Spec: X.690 8.1.2.2; X.690 8.14.4 a).
pub(crate) const fn context(number: u8, constructed: bool) -> u8 {
    CLASS_CONTEXT | (number & NUMBER_MASK) | if constructed { CONSTRUCTED } else { 0 }
}

/// The identifier with the form bit cleared: class plus tag number, i.e. the
/// tag itself. Spec: X.690 8.1.2.1 (identifier octets encode class and number).
pub(crate) const fn tag_of(identifier: u8) -> u8 {
    identifier & !CONSTRUCTED
}

/// Whether the identifier announces the constructed form. Spec: X.690 8.1.2.5.
pub(crate) const fn is_constructed(identifier: u8) -> bool {
    identifier & CONSTRUCTED != 0
}

/// Which strictness the reader applies.
///
/// Spec: docs/49 §11 (R49-16) — the front decodes the wire (lenient where
/// A-45 says so) and re-encodes canonically; the engine decodes "in canonical
/// mode only".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// What a client may send: the RFC 4511 §5.1 subset with the A-45 choices —
    /// long-form lengths of up to four octets even when not minimal, and
    /// unrecognised trailing SEQUENCE components skipped (RFC 4511 §4).
    Wire,
    /// Exactly what [`crate::encode_message`] produces: minimal lengths
    /// (X.690 10.1), no unrecognised components, unrecognised CHOICE
    /// alternatives only as an empty primitive element, and a simple-bind
    /// password only as the placeholder.
    Canonical,
}

/// One element: its identifier octet and its contents octets.
/// Spec: X.690 8.1.1.1.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Tlv<'a> {
    pub(crate) identifier: u8,
    pub(crate) contents: &'a [u8],
}

/// Validate a single identifier octet.
///
/// Spec: X.690 8.1.2.4 (the high-tag-number escape — refused, E6);
/// X.690 8.1.5 and X.680 Table 1 (`[UNIVERSAL 0]` — refused, E1).
pub(crate) fn check_identifier(identifier: u8) -> Result<()> {
    if identifier & NUMBER_MASK == NUMBER_MASK {
        return Err(Error::HighTagNumber);
    }
    if tag_of(identifier) == CLASS_UNIVERSAL {
        return Err(Error::EndOfContents);
    }
    Ok(())
}

/// Outcome of parsing length octets from a possibly incomplete buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LengthOctets {
    /// The length octets are complete: the contents length, and how many
    /// length octets were consumed.
    Complete { length: usize, octets: usize },
    /// More input is needed to finish the length octets.
    Incomplete,
}

/// Parse the length octets at the start of `input`.
///
/// Spec: X.690 8.1.3.3–8.1.3.6; RFC 4511 §5.1 (definite form only);
/// A-45 (at most [`MAX_LENGTH_OCTETS`] subsequent octets; non-minimal accepted
/// by [`Profile::Wire`]); X.690 10.1 (minimal, [`Profile::Canonical`]).
pub(crate) fn parse_length(input: &[u8], profile: Profile) -> Result<LengthOctets> {
    let Some((&initial, rest)) = input.split_first() else {
        return Ok(LengthOctets::Incomplete);
    };
    // Short form: bit 8 zero, bits 7-1 the length. Spec: X.690 8.1.3.4.
    if initial & 0x80 == 0 {
        return Ok(LengthOctets::Complete {
            length: usize::from(initial),
            octets: 1,
        });
    }
    // `80` alone is the indefinite form. Spec: X.690 8.1.3.6.1; RFC 4511 §5.1.
    if initial == 0x80 {
        return Err(Error::IndefiniteLength);
    }
    // `FF` is reserved. Spec: X.690 8.1.3.5 c).
    if initial == 0xFF {
        return Err(Error::ReservedLengthOctet);
    }
    // Long form: bits 7-1 count the subsequent octets. Spec: X.690 8.1.3.5 b).
    let count = usize::from(initial & 0x7F);
    if count > MAX_LENGTH_OCTETS {
        return Err(Error::TooManyLengthOctets);
    }
    let Some(subsequent) = rest.get(..count) else {
        return Ok(LengthOctets::Incomplete);
    };
    // Unsigned big-endian integer. Spec: X.690 8.1.3.5 (the text after c)).
    // At most four octets, so the value always fits in a u64 without overflow.
    let mut value: u64 = 0;
    for &octet in subsequent {
        value = (value << 8) | u64::from(octet);
    }
    if profile == Profile::Canonical {
        // Minimum octets: no leading zero octet, and no long form where the
        // short form fits. Spec: X.690 10.1; 8.1.3.3 NOTE.
        let leading_zero = subsequent.first() == Some(&0);
        if leading_zero || value <= 0x7F {
            return Err(Error::NonMinimalLength);
        }
    }
    let length = usize::try_from(value).map_err(|_| Error::LengthExceedsInput)?;
    Ok(LengthOctets::Complete {
        length,
        octets: 1 + count,
    })
}

/// A bounded forward reader over the contents of one constructed element (or
/// the whole message).
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    profile: Profile,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8], profile: Profile) -> Self {
        Reader {
            buf,
            pos: 0,
            profile,
        }
    }

    pub(crate) fn profile(&self) -> Profile {
        self.profile
    }

    /// Whether every octet has been consumed.
    pub(crate) fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    /// The next identifier octet, without consuming it.
    pub(crate) fn peek_identifier(&self) -> Option<u8> {
        self.buf.get(self.pos).copied()
    }

    /// Take the next `n` octets, or fail with [`Error::Truncated`].
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or(Error::LengthExceedsInput)?;
        let slice = self.buf.get(self.pos..end).ok_or(Error::Truncated)?;
        self.pos = end;
        Ok(slice)
    }

    /// Read one complete element, bounding its declared length by the octets
    /// remaining in this reader.
    ///
    /// Spec: X.690 8.1.1.1, 8.1.2, 8.1.3; RFC 4511 §5.1; A-45.
    pub(crate) fn read_tlv(&mut self) -> Result<Tlv<'a>> {
        let identifier = *self.take(1)?.first().ok_or(Error::Truncated)?;
        check_identifier(identifier)?;
        let rest = self.buf.get(self.pos..).unwrap_or(&[]);
        let (length, octets) = match parse_length(rest, self.profile)? {
            LengthOctets::Complete { length, octets } => (length, octets),
            LengthOctets::Incomplete => return Err(Error::Truncated),
        };
        self.take(octets)?;
        // Bound the declared length by what is present before slicing.
        // Spec: X.690 8.1.3.3; AGENTS.md §6.
        let remaining = self.buf.len().saturating_sub(self.pos);
        if length > remaining {
            return Err(Error::LengthExceedsInput);
        }
        let contents = self.take(length)?;
        Ok(Tlv {
            identifier,
            contents,
        })
    }
}

/// Validate the structure of an element this codec does not interpret (an
/// unrecognised trailing SEQUENCE component or CHOICE alternative), before it
/// is skipped.
///
/// Every nested element must itself satisfy the profile: identifier and length
/// rules, nesting bound, and — for universal-class elements, whose type is
/// fixed by X.680 Table 1 — the form and contents rules of that type.
///
/// Spec: RFC 4511 §4 (ignore trailing components with unrecognised tags);
/// docs/49 §2.3 E12 ("skipped after full TLV validation, within the bounds");
/// X.690 8.1.2.5 (constructed contents are a series of encodings — 8.9.2,
/// 8.10.2, 8.14.3); RFC 4511 §5.1.
pub(crate) fn validate_element(tlv: &Tlv<'_>, profile: Profile, depth: usize) -> Result<()> {
    if depth > MAX_TLV_DEPTH {
        return Err(Error::LimitExceeded(Limit::TlvDepth));
    }
    let constructed = is_constructed(tlv.identifier);
    if tlv.identifier & CLASS_MASK == CLASS_UNIVERSAL {
        match tag_of(tlv.identifier) {
            BOOLEAN => {
                require_primitive(constructed)?;
                boolean_value(tlv.contents)?;
            }
            INTEGER | ENUMERATED => {
                require_primitive(constructed)?;
                integer_value(tlv.contents)?;
            }
            OCTET_STRING if constructed => return Err(Error::ConstructedOctetString),
            NULL => {
                require_primitive(constructed)?;
                if !tlv.contents.is_empty() {
                    return Err(Error::InvalidNull);
                }
            }
            t if (t == tag_of(SEQUENCE) || t == tag_of(SET)) && !constructed => {
                return Err(Error::PrimitiveConstructedMismatch)
            }
            _ => {}
        }
    }
    if constructed {
        let mut inner = Reader::new(tlv.contents, profile);
        while !inner.is_empty() {
            let child = inner.read_tlv()?;
            validate_element(&child, profile, depth + 1)?;
        }
    }
    Ok(())
}

fn require_primitive(constructed: bool) -> Result<()> {
    if constructed {
        Err(Error::PrimitiveConstructedMismatch)
    } else {
        Ok(())
    }
}

/// Decode BOOLEAN contents.
///
/// Spec: X.690 8.2.1 (one contents octet), 8.2.2 (FALSE is zero); RFC 4511
/// §5.1 (TRUE is `FF`); A-45 / Q-160 item 3 (any other octet is refused).
pub(crate) fn boolean_value(contents: &[u8]) -> Result<bool> {
    match contents {
        [0x00] => Ok(false),
        [0xFF] => Ok(true),
        _ => Err(Error::InvalidBoolean),
    }
}

/// Decode INTEGER / ENUMERATED contents into an `i64`.
///
/// Spec: X.690 8.3.1 (at least one octet), 8.3.2 (minimal: the first nine bits
/// are not all ones nor all zeros), 8.3.3 (two's complement), 8.4 (ENUMERATED
/// is encoded as its integer). Values needing more than eight octets are out of
/// range of every LDAP integer type.
pub(crate) fn integer_value(contents: &[u8]) -> Result<i64> {
    let Some((&first, rest)) = contents.split_first() else {
        return Err(Error::EmptyInteger);
    };
    if let Some(&second) = rest.first() {
        let redundant_zero = first == 0x00 && second & 0x80 == 0;
        let redundant_ones = first == 0xFF && second & 0x80 != 0;
        if redundant_zero || redundant_ones {
            return Err(Error::NonMinimalInteger);
        }
    }
    if contents.len() > 8 {
        return Err(Error::IntegerOutOfRange);
    }
    // Sign-extend into eight octets, then read big-endian.
    let fill = if first & 0x80 != 0 { 0xFF } else { 0x00 };
    let mut octets = [fill; 8];
    let start = octets.len() - contents.len();
    for (slot, &octet) in octets.iter_mut().skip(start).zip(contents) {
        *slot = octet;
    }
    Ok(i64::from_be_bytes(octets))
}

/// The minimal two's-complement contents octets of `value`.
/// Spec: X.690 8.3.2, 8.3.3.
pub(crate) fn integer_contents(value: i64) -> Vec<u8> {
    let octets = value.to_be_bytes();
    let mut start = 0;
    while start + 1 < octets.len() {
        let (Some(&first), Some(&second)) = (octets.get(start), octets.get(start + 1)) else {
            break;
        };
        let redundant_zero = first == 0x00 && second & 0x80 == 0;
        let redundant_ones = first == 0xFF && second & 0x80 != 0;
        if !(redundant_zero || redundant_ones) {
            break;
        }
        start += 1;
    }
    octets.get(start..).unwrap_or(&[0]).to_vec()
}

/// A writer that emits elements in the canonical form.
///
/// Spec: X.690 10.1 (definite length, minimum octets) — permitted by
/// RFC 4511 §5.1 and the only form [`Profile::Canonical`] accepts.
pub(crate) struct Writer {
    out: Vec<u8>,
}

impl Writer {
    pub(crate) fn new() -> Self {
        Writer { out: Vec::new() }
    }

    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.out
    }

    /// Emit identifier, minimal length octets, then the contents.
    /// Spec: X.690 8.1.1.1, 8.1.3.4, 8.1.3.5, 10.1.
    pub(crate) fn element(&mut self, identifier: u8, contents: &[u8]) -> Result<()> {
        self.out.push(identifier);
        write_length(&mut self.out, contents.len())?;
        self.out.extend_from_slice(contents);
        Ok(())
    }

    /// Emit a constructed element whose contents `fill` writes.
    pub(crate) fn constructed<F>(&mut self, identifier: u8, fill: F) -> Result<()>
    where
        F: FnOnce(&mut Writer) -> Result<()>,
    {
        let mut inner = Writer::new();
        fill(&mut inner)?;
        self.element(identifier, &inner.out)
    }

    /// Emit an INTEGER / ENUMERATED (or an implicitly tagged one).
    /// Spec: X.690 8.3, 8.4.
    pub(crate) fn integer(&mut self, identifier: u8, value: i64) -> Result<()> {
        self.element(identifier, &integer_contents(value))
    }

    /// Emit a BOOLEAN with TRUE as `FF`. Spec: X.690 8.2; RFC 4511 §5.1.
    pub(crate) fn boolean(&mut self, identifier: u8, value: bool) -> Result<()> {
        self.element(identifier, &[if value { 0xFF } else { 0x00 }])
    }
}

/// Append minimal definite length octets.
/// Spec: X.690 8.1.3.4 (short form up to 127), 8.1.3.5 (long form), 10.1.
fn write_length(out: &mut Vec<u8>, length: usize) -> Result<()> {
    if let Ok(short) = u8::try_from(length) {
        if short <= 0x7F {
            out.push(short);
            return Ok(());
        }
    }
    let value = u64::try_from(length).map_err(|_| Error::TooManyLengthOctets)?;
    let octets = value.to_be_bytes();
    let skip = octets.iter().take_while(|&&o| o == 0).count();
    let significant = octets.get(skip..).unwrap_or(&[]);
    if significant.len() > MAX_LENGTH_OCTETS {
        // Never emit what the decoder would refuse. Spec: A-45.
        return Err(Error::TooManyLengthOctets);
    }
    let count = u8::try_from(significant.len()).map_err(|_| Error::TooManyLengthOctets)?;
    out.push(0x80 | count);
    out.extend_from_slice(significant);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Source: [MS-ADTS] v20261026 6.3.3, the first six octets of the example
    /// "Network payload": `A0 84 00 00 00 A8` — length 168 in four octets.
    /// Accepted by the wire profile (A-45), refused by the canonical one.
    #[test]
    fn ms_adts_6_3_3_four_octet_length() {
        let length_octets = [0x84, 0x00, 0x00, 0x00, 0xA8];
        assert_eq!(
            parse_length(&length_octets, Profile::Wire),
            Ok(LengthOctets::Complete {
                length: 168,
                octets: 5
            })
        );
        assert_eq!(
            parse_length(&length_octets, Profile::Canonical),
            Err(Error::NonMinimalLength)
        );
    }

    /// Source: X.690 8.1.3.5 EXAMPLE — L = 201 encoded as `81 C9`.
    #[test]
    fn x690_long_form_example() {
        assert_eq!(
            parse_length(&[0x81, 0xC9], Profile::Canonical),
            Ok(LengthOctets::Complete {
                length: 201,
                octets: 2
            })
        );
        let mut out = Vec::new();
        write_length(&mut out, 201).unwrap();
        assert_eq!(out, [0x81, 0xC9]);
    }

    /// Source: X.690 8.1.3.4 EXAMPLE — L = 38 encoded as `26`.
    #[test]
    fn x690_short_form_example() {
        let mut out = Vec::new();
        write_length(&mut out, 38).unwrap();
        assert_eq!(out, [0x26]);
        assert_eq!(
            parse_length(&[0x26], Profile::Canonical),
            Ok(LengthOctets::Complete {
                length: 38,
                octets: 1
            })
        );
    }

    /// Source: A-45 — five subsequent length octets are refused even when the
    /// value is small; four are accepted (wire profile).
    #[test]
    fn length_octet_bound() {
        assert_eq!(
            parse_length(&[0x85, 0, 0, 0, 0, 1], Profile::Wire),
            Err(Error::TooManyLengthOctets)
        );
        assert_eq!(
            parse_length(&[0x84, 0, 0, 0, 1], Profile::Wire),
            Ok(LengthOctets::Complete {
                length: 1,
                octets: 5
            })
        );
        // X.690 8.1.3.5 NOTE 2: a long form for a value <= 127 is a sender's
        // option — wire accepts, canonical refuses (X.690 10.1).
        assert_eq!(
            parse_length(&[0x81, 0x05], Profile::Wire),
            Ok(LengthOctets::Complete {
                length: 5,
                octets: 2
            })
        );
        assert_eq!(
            parse_length(&[0x81, 0x05], Profile::Canonical),
            Err(Error::NonMinimalLength)
        );
    }

    /// Source: X.690 8.1.3.6.1 (indefinite `80`), 8.1.3.5 c) (`FF` reserved).
    #[test]
    fn indefinite_and_reserved() {
        assert_eq!(
            parse_length(&[0x80], Profile::Wire),
            Err(Error::IndefiniteLength)
        );
        assert_eq!(
            parse_length(&[0xFF], Profile::Wire),
            Err(Error::ReservedLengthOctet)
        );
    }

    /// Source: X.690 8.3.2 / 8.3.3, values hand-derived from the clause.
    #[test]
    fn integer_minimal_forms() {
        assert_eq!(integer_contents(0), [0x00]);
        assert_eq!(integer_contents(127), [0x7F]);
        assert_eq!(integer_contents(128), [0x00, 0x80]);
        assert_eq!(integer_contents(-1), [0xFF]);
        assert_eq!(integer_contents(-129), [0xFF, 0x7F]);
        assert_eq!(integer_contents(2_147_483_647), [0x7F, 0xFF, 0xFF, 0xFF]);
        for v in [0, 1, 127, 128, 255, 256, -1, -128, -129, i64::MAX, i64::MIN] {
            assert_eq!(integer_value(&integer_contents(v)), Ok(v));
        }
        assert_eq!(integer_value(&[0x00, 0x05]), Err(Error::NonMinimalInteger));
        assert_eq!(integer_value(&[0xFF, 0x80]), Err(Error::NonMinimalInteger));
        assert_eq!(integer_value(&[]), Err(Error::EmptyInteger));
    }

    /// Source: X.690 8.1.2.4 (high-tag-number escape `1F`), 8.1.5 (`00`).
    #[test]
    fn identifier_rules() {
        assert_eq!(check_identifier(0x1F), Err(Error::HighTagNumber));
        assert_eq!(check_identifier(0x7F), Err(Error::HighTagNumber));
        assert_eq!(check_identifier(0x00), Err(Error::EndOfContents));
        assert_eq!(check_identifier(0x20), Err(Error::EndOfContents));
        assert_eq!(check_identifier(0x30), Ok(()));
    }
}
