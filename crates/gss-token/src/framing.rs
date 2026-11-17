//! Context-establishment tokens: the RFC 2743 §3.1 framing with the RFC 4121
//! §4.1 TOK_ID.
//!
//! ```text
//! 0x60 | token length | 0x06 | OID length | OID octets | TOK_ID (2) | Kerberos message
//!      `-- element 2 counts every octet after itself ------------------------------'
//! ```
//!
//! RFC 2743 §3.1 defines the token tag "directly in terms of octets rather
//! than at the ASN.1 level", and no size specifier follows the OID: the inner
//! token runs to the end of the length counted by element 2. RFC 4121 §4.1
//! makes this framing mandatory for every context-establishment token of the
//! Kerberos V5 mechanism (the acceptor's AP-REP token too) and defines the
//! inner token as a big-endian two-octet TOK_ID followed by a Kerberos
//! message.
//!
//! Decoding is strict: tag 0x60 only; every length in the minimum number of
//! octets (2a, 2b); OID tag 0x06; the OID octets exactly those of the Kerberos
//! V5 mechanism ([MS-KILE] 1.9.1 — the truncated OID of [MS-KILE] 3.1.1.7 and
//! every other OID refused); the token length equal to the octets present (no
//! truncation, no trailing octets); the TOK_ID exactly the one the caller
//! expects; a non-empty Kerberos message. The size bound is checked before any
//! octet is read. Decoding borrows and allocates nothing; the Kerberos message
//! stays opaque (keyd decodes the AP-REQ with krb-proto — docs/60 §3.4).
//!
//! Every accepted token is canonical — minimum lengths, the one OID encoding —
//! so encoding a decoded token reproduces the input exactly.
//!
//! Spec: RFC 2743 §3.1; RFC 4121 §4.1, §4.4; [MS-KILE] 1.9.1, 3.1.1.7;
//! docs/60 §3.4 steps 2 and 6, §10.1.

use crate::error::{Error, Result};
use crate::limits::MAX_CONTEXT_TOKEN_LEN;
use crate::oid::{KERBEROS_V5_MECHANISM_OID_OCTETS, TRUNCATED_KERBEROS_OID_OCTETS};
use core::fmt;

/// Element 1: "Tag for [APPLICATION 0] SEQUENCE; indicates that constructed
/// form, definite length encoding follows." Spec: RFC 2743 §3.1 element 1.
pub const TOKEN_TAG: u8 = 0x60;

/// Element 3: "Tag for OBJECT IDENTIFIER". Spec: RFC 2743 §3.1 element 3.
pub const OID_TAG: u8 = 0x06;

/// Bit 8 of a length's first octet: set ⇒ the long form (2b).
/// Spec: RFC 2743 §3.1 elements 2a, 2b.
const LONG_FORM: u8 = 0x80;

/// The most subsequent length octets read: four octets already denote values
/// up to 2^32 − 1, far beyond [`MAX_CONTEXT_TOKEN_LEN`]; a minimum-octet
/// encoding with more octets denotes at least 2^32.
const MAX_LENGTH_OCTETS: usize = 4;

/// The TOK_ID of a context-establishment token of the Kerberos V5 mechanism —
/// only the two this profile reads or writes.
///
/// KRB_ERROR (03 00) is deliberately not a variant: no KRB_ERROR token is ever
/// produced (docs/60 R60-8, §7: not for an unknown TOK_ID, not for skew), and
/// none is accepted where an initial token is expected.
///
/// Spec: RFC 4121 §4.1; docs/60 R60-8; Q-1093 item 9.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TokId {
    /// KRB_AP_REQ, 01 00: the initiator's initial context token.
    KrbApReq,
    /// KRB_AP_REP, 02 00: the acceptor's reply token (mutual authentication).
    KrbApRep,
}

impl TokId {
    /// The two TOK_ID octets, "expressed in big-endian order".
    /// Spec: RFC 4121 §4.1.
    pub const fn octets(self) -> [u8; 2] {
        match self {
            TokId::KrbApReq => [0x01, 0x00],
            TokId::KrbApRep => [0x02, 0x00],
        }
    }

    /// The TOK_ID these octets denote, if it is one of the two above.
    fn from_octets(octets: [u8; 2]) -> Option<TokId> {
        match octets {
            [0x01, 0x00] => Some(TokId::KrbApReq),
            [0x02, 0x00] => Some(TokId::KrbApRep),
            _ => None,
        }
    }
}

/// A context-establishment token of the Kerberos V5 mechanism, borrowed from
/// its input (decoding) or from the caller's Kerberos message (encoding).
///
/// Valid by construction: [`Self::decode`] and [`Self::new`] are the only
/// ways to obtain one, both apply the size bound and require a non-empty
/// Kerberos message, so [`Self::encode`] cannot fail. `Debug` shows the TOK_ID
/// and the length of the Kerberos message, never its octets.
///
/// Spec: RFC 2743 §3.1 (InitialContextToken); RFC 4121 §4.1 (GSSAPI-Token).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ContextEstablishmentToken<'a> {
    tok_id: TokId,
    kerberos_message: &'a [u8],
    /// The octets [`Self::encode`] writes, computed (and bounded) once at
    /// construction.
    encoded_len: usize,
}

impl<'a> ContextEstablishmentToken<'a> {
    /// A token carrying `kerberos_message` (the DER of a KRB_AP_REQ or
    /// KRB_AP_REP, opaque here) under `tok_id`. Refused when the message is
    /// empty ([`Error::MissingKerberosMessage`]) or the encoded token would
    /// exceed [`MAX_CONTEXT_TOKEN_LEN`] ([`Error::ContextTokenTooLong`]).
    ///
    /// Spec: RFC 4121 §4.1; docs/60 §3.4 step 6 (the AP-REP is framed with
    /// TOK_ID 02 00), R60-11.
    pub fn new(tok_id: TokId, kerberos_message: &'a [u8]) -> Result<Self> {
        if kerberos_message.is_empty() {
            return Err(Error::MissingKerberosMessage);
        }
        let encoded_len = encoded_token_len(kerberos_message.len())?;
        Ok(ContextEstablishmentToken {
            tok_id,
            kerberos_message,
            encoded_len,
        })
    }

    /// Decode exactly one framed token whose TOK_ID must be `expected`
    /// (keyd decodes the initial context token with [`TokId::KrbApReq`]).
    ///
    /// Checks, in order: size ≤ [`MAX_CONTEXT_TOKEN_LEN`]; tag 0x60; the
    /// token length in minimum octets and equal to the octets that follow it;
    /// tag 0x06; the OID length in minimum octets and within the token; the
    /// OID exactly 1.2.840.113554.1.2.2 (the truncated OID reported as
    /// [`Error::TruncatedKerberosOid`], any other as
    /// [`Error::UnsupportedMechanism`]); a two-octet TOK_ID equal to
    /// `expected`; at least one octet of Kerberos message.
    ///
    /// Spec: RFC 2743 §3.1 elements 1–5; RFC 4121 §4.1; [MS-KILE] 1.9.1,
    /// 3.1.1.7; docs/60 §3.4 step 2; Q-1093 items 9, 11.
    pub fn decode(token: &'a [u8], expected: TokId) -> Result<Self> {
        if token.len() > MAX_CONTEXT_TOKEN_LEN {
            return Err(Error::ContextTokenTooLong);
        }
        // Element 1.
        let (&tag, rest) = token.split_first().ok_or(Error::Truncated)?;
        if tag != TOKEN_TAG {
            return Err(Error::BadTokenTag);
        }
        // Element 2: the length of everything after it.
        let (token_length, body) = read_length(rest)?;
        if token_length > body.len() {
            return Err(Error::LengthExceedsInput);
        }
        if token_length < body.len() {
            return Err(Error::TrailingOctets);
        }
        // Element 3.
        let (&oid_tag, rest) = body.split_first().ok_or(Error::Truncated)?;
        if oid_tag != OID_TAG {
            return Err(Error::BadOidTag);
        }
        // Elements 4 and 5.
        let (oid_length, rest) = read_length(rest)?;
        let (oid, inner_token) = rest
            .split_at_checked(oid_length)
            .ok_or(Error::LengthExceedsInput)?;
        if oid != KERBEROS_V5_MECHANISM_OID_OCTETS {
            return Err(if oid == TRUNCATED_KERBEROS_OID_OCTETS {
                Error::TruncatedKerberosOid
            } else {
                Error::UnsupportedMechanism
            });
        }
        // The inner token: TOK_ID, then the Kerberos message (RFC 4121 §4.1).
        let (tok_id_octets, kerberos_message) = inner_token
            .split_first_chunk::<2>()
            .ok_or(Error::Truncated)?;
        match TokId::from_octets(*tok_id_octets) {
            Some(tok_id) if tok_id == expected => {}
            _ => return Err(Error::UnexpectedTokId),
        }
        if kerberos_message.is_empty() {
            return Err(Error::MissingKerberosMessage);
        }
        // The token is canonical (minimum lengths, the one OID encoding), so
        // this equals `token.len()`; computed by the same rule as `new`.
        let encoded_len = encoded_token_len(kerberos_message.len())?;
        Ok(ContextEstablishmentToken {
            tok_id: expected,
            kerberos_message,
            encoded_len,
        })
    }

    /// The TOK_ID. Spec: RFC 4121 §4.1.
    pub fn tok_id(&self) -> TokId {
        self.tok_id
    }

    /// The Kerberos message after the TOK_ID (opaque DER here).
    /// Spec: RFC 4121 §4.1.
    pub fn kerberos_message(&self) -> &'a [u8] {
        self.kerberos_message
    }

    /// The number of octets [`Self::encode`] writes (≤
    /// [`MAX_CONTEXT_TOKEN_LEN`] by construction).
    pub fn encoded_len(&self) -> usize {
        self.encoded_len
    }

    /// Encode the framed token: 0x60, the minimum-octet token length, 0x06,
    /// the OID length, the Kerberos V5 OID octets, the TOK_ID, the Kerberos
    /// message. Allocates exactly [`Self::encoded_len`] octets.
    ///
    /// Spec: RFC 2743 §3.1 elements 1–5; RFC 4121 §4.1; [MS-KILE] 1.9.1.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());
        out.push(TOKEN_TAG);
        write_length(&mut out, inner_len(self.kerberos_message.len()));
        out.push(OID_TAG);
        write_length(&mut out, KERBEROS_V5_MECHANISM_OID_OCTETS.len());
        out.extend_from_slice(KERBEROS_V5_MECHANISM_OID_OCTETS);
        out.extend_from_slice(&self.tok_id.octets());
        out.extend_from_slice(self.kerberos_message);
        out
    }
}

impl fmt::Debug for ContextEstablishmentToken<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContextEstablishmentToken")
            .field("tok_id", &self.tok_id)
            .field("kerberos_message_len", &self.kerberos_message.len())
            .finish()
    }
}

// ===========================================================================
// Lengths — RFC 2743 §3.1 elements 2 and 4
// ===========================================================================

/// Read one length (element 2 or 4) from the front of `input`; return it and
/// the octets after the length octets.
///
/// 2a: a value below 128 is one octet with bit 8 clear. 2b: a value of 128 or
/// more is "two or more octets", the first with bit 8 set and the count of
/// subsequent octets in its other bits, the value big-endian in the minimum
/// number of octets ("no octets representing leading zeros"). So the first
/// octet 0x80 (no subsequent octet), a leading zero octet, and the long form
/// for a value below 128 are all refused.
///
/// Spec: RFC 2743 §3.1 elements 2a, 2b (element 4 "encoded per rules as
/// described in 2a. and 2b.").
fn read_length(input: &[u8]) -> Result<(usize, &[u8])> {
    let (&first, rest) = input.split_first().ok_or(Error::Truncated)?;
    if first & LONG_FORM == 0 {
        return Ok((usize::from(first), rest));
    }
    let count = usize::from(first & !LONG_FORM);
    if count == 0 {
        return Err(Error::MalformedLength);
    }
    let (octets, rest) = rest.split_at_checked(count).ok_or(Error::Truncated)?;
    let (&leading, _) = octets.split_first().ok_or(Error::Truncated)?;
    if leading == 0 {
        return Err(Error::NonMinimalLength);
    }
    if count > MAX_LENGTH_OCTETS {
        // Minimum octets and a non-zero leading octet: the value is at least
        // 2^32, more than any input this crate accepts.
        return Err(Error::LengthExceedsInput);
    }
    let mut value: u32 = 0;
    for &octet in octets {
        value = value
            .checked_mul(256)
            .and_then(|v| v.checked_add(u32::from(octet)))
            .ok_or(Error::LengthExceedsInput)?;
    }
    if value < u32::from(LONG_FORM) {
        return Err(Error::NonMinimalLength);
    }
    let value = usize::try_from(value).map_err(|_| Error::LengthExceedsInput)?;
    Ok((value, rest))
}

/// Append `value` as a length in the minimum number of octets (2a / 2b).
/// Spec: RFC 2743 §3.1 elements 2a, 2b.
fn write_length(out: &mut Vec<u8>, value: usize) {
    match u8::try_from(value) {
        Ok(short) if short < LONG_FORM => out.push(short),
        _ => {
            let octets = value.to_be_bytes();
            let skip = octets.iter().take_while(|&&o| o == 0).count();
            let (_, significant) = octets.split_at(skip);
            // At most size_of::<usize>() (8) subsequent octets: fits the
            // seven count bits.
            let count = u8::try_from(significant.len()).unwrap_or(0);
            out.push(LONG_FORM | count);
            out.extend_from_slice(significant);
        }
    }
}

/// The number of octets [`write_length`] writes for `value`.
fn length_len(value: usize) -> usize {
    if value < usize::from(LONG_FORM) {
        1
    } else {
        let octets = value.to_be_bytes();
        let skip = octets.iter().take_while(|&&o| o == 0).count();
        1 + (octets.len() - skip)
    }
}

/// The octets counted by element 2 for a Kerberos message of `message_len`
/// octets: OID tag, OID length, OID octets, TOK_ID, message.
fn inner_len(message_len: usize) -> usize {
    let oid = KERBEROS_V5_MECHANISM_OID_OCTETS.len();
    1 + length_len(oid) + oid + 2 + message_len
}

/// The whole encoded token for a message of `message_len` octets, bounded by
/// [`MAX_CONTEXT_TOKEN_LEN`]. Spec: RFC 2743 §3.1; docs/60 R60-11.
fn encoded_token_len(message_len: usize) -> Result<usize> {
    // Bound the message first so no sum below can overflow.
    if message_len > MAX_CONTEXT_TOKEN_LEN {
        return Err(Error::ContextTokenTooLong);
    }
    let inner = inner_len(message_len);
    let total = 1 + length_len(inner) + inner;
    if total > MAX_CONTEXT_TOKEN_LEN {
        return Err(Error::ContextTokenTooLong);
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2a / 2b on the boundary values, both directions. Spec: RFC 2743 §3.1
    /// elements 2a, 2b.
    #[test]
    fn lengths_round_trip_in_minimum_octets() {
        for (value, octets) in [
            (0usize, &[0x00u8][..]),
            (127, &[0x7F]),
            (128, &[0x81, 0x80]),
            (255, &[0x81, 0xFF]),
            (256, &[0x82, 0x01, 0x00]),
            (65_535, &[0x82, 0xFF, 0xFF]),
            (65_536, &[0x83, 0x01, 0x00, 0x00]),
        ] {
            let mut out = Vec::new();
            write_length(&mut out, value);
            assert_eq!(out, octets, "encode {value}");
            assert_eq!(length_len(value), octets.len());
            assert_eq!(read_length(octets), Ok((value, &[][..])), "decode {value}");
        }
    }

    /// The refusals of 2a / 2b. Spec: RFC 2743 §3.1 elements 2a, 2b.
    #[test]
    fn non_minimal_and_malformed_lengths_are_refused() {
        assert_eq!(read_length(&[]), Err(Error::Truncated));
        assert_eq!(read_length(&[0x80]), Err(Error::MalformedLength));
        assert_eq!(read_length(&[0x81]), Err(Error::Truncated));
        assert_eq!(read_length(&[0x81, 0x05]), Err(Error::NonMinimalLength));
        assert_eq!(read_length(&[0x81, 0x7F]), Err(Error::NonMinimalLength));
        assert_eq!(
            read_length(&[0x82, 0x00, 0x80]),
            Err(Error::NonMinimalLength)
        );
        assert_eq!(
            read_length(&[0x85, 0x01, 0, 0, 0, 0]),
            Err(Error::LengthExceedsInput)
        );
        assert_eq!(
            read_length(&[0x85, 0x00, 0, 0, 0, 0x80]),
            Err(Error::NonMinimalLength)
        );
    }
}
