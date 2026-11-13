//! SID — packet representation and the "S-1-..." string form.
//!
//! Spec: [MS-DTYP] 2.4.1 (SID_IDENTIFIER_AUTHORITY), 2.4.2 (SID), 2.4.2.1 (SID
//! string format syntax), 2.4.2.2 (SID packet representation), 2.4.2.4
//! (well-known SIDs); RFC 5234 §2.3 and Appendix B.1 (the ABNF conventions
//! 2.4.2.1 is written in: case-insensitive quoted strings, DIGIT, HEXDIG).
//!
//! Packet layout (2.4.2.2): Revision (1 byte, MUST be 0x01), SubAuthorityCount
//! (1 byte, at most 15), IdentifierAuthority (6 bytes), then SubAuthorityCount
//! unsigned 32-bit SubAuthority values. 2.4.2.2 leaves the byte order of the
//! multi-byte fields to "the protocol in question"; this crate handles the SID
//! as embedded in a self-relative security descriptor, which is little-endian
//! (2.4.6), as the 2.5.1.4 example shows.
//!
//! A SID is held in a fixed array of [`SID_MAX_SUB_AUTHORITIES`] entries, so
//! decoding never allocates from the attacker-supplied count (AGENTS.md §6).

use crate::error::{Error, Result};
use crate::reader::Reader;

/// The only valid SID revision. Spec: [MS-DTYP] 2.4.2.2 ("MUST be set to 0x01").
pub const SID_REVISION: u8 = 0x01;

/// Maximum number of SubAuthority elements. Spec: [MS-DTYP] 2.4.2.2 ("The
/// maximum number of elements allowed is 15").
pub const SID_MAX_SUB_AUTHORITIES: usize = 15;

/// Revision + SubAuthorityCount + IdentifierAuthority. Spec: [MS-DTYP] 2.4.2.2.
const SID_FIXED_LEN: usize = 1 + 1 + 6;

/// Size of one SubAuthority element (unsigned 32-bit). Spec: [MS-DTYP] 2.4.2.2.
const SUB_AUTHORITY_LEN: usize = 4;

// Predefined identifier authorities. Spec: [MS-DTYP] 2.4.1 table.

/// NULL_SID_AUTHORITY. Spec: [MS-DTYP] 2.4.1.
pub const NULL_SID_AUTHORITY: [u8; 6] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
/// WORLD_SID_AUTHORITY. Spec: [MS-DTYP] 2.4.1.
pub const WORLD_SID_AUTHORITY: [u8; 6] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
/// LOCAL_SID_AUTHORITY. Spec: [MS-DTYP] 2.4.1.
pub const LOCAL_SID_AUTHORITY: [u8; 6] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x02];
/// CREATOR_SID_AUTHORITY. Spec: [MS-DTYP] 2.4.1.
pub const CREATOR_SID_AUTHORITY: [u8; 6] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x03];
/// NON_UNIQUE_AUTHORITY. Spec: [MS-DTYP] 2.4.1.
pub const NON_UNIQUE_AUTHORITY: [u8; 6] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x04];
/// SECURITY_NT_AUTHORITY. Spec: [MS-DTYP] 2.4.1.
pub const SECURITY_NT_AUTHORITY: [u8; 6] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x05];
/// SECURITY_APP_PACKAGE_AUTHORITY. Spec: [MS-DTYP] 2.4.1.
pub const SECURITY_APP_PACKAGE_AUTHORITY: [u8; 6] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x0F];
/// SECURITY_MANDATORY_LABEL_AUTHORITY. Spec: [MS-DTYP] 2.4.1.
pub const SECURITY_MANDATORY_LABEL_AUTHORITY: [u8; 6] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x10];
/// SECURITY_SCOPED_POLICY_ID_AUTHORITY. Spec: [MS-DTYP] 2.4.1.
pub const SECURITY_SCOPED_POLICY_ID_AUTHORITY: [u8; 6] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x11];
/// SECURITY_AUTHENTICATION_AUTHORITY. Spec: [MS-DTYP] 2.4.1.
pub const SECURITY_AUTHENTICATION_AUTHORITY: [u8; 6] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x12];

/// A security identifier.
///
/// Field names follow [MS-DTYP] 2.4.2.2. The revision is not stored: the only
/// valid value is [`SID_REVISION`]. Entries of `sub_authority` beyond
/// `sub_authority_count` are always zero, so the derived equality and hashing
/// compare exactly the meaningful elements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Sid {
    identifier_authority: [u8; 6],
    sub_authority_count: u8,
    sub_authority: [u32; SID_MAX_SUB_AUTHORITIES],
}

impl Sid {
    /// Build a SID from its IdentifierAuthority and SubAuthority values.
    ///
    /// Returns [`Error::SidTooManySubAuthorities`] for more than 15 values.
    /// Spec: [MS-DTYP] 2.4.2.2.
    pub fn new(identifier_authority: [u8; 6], sub_authority: &[u32]) -> Result<Sid> {
        if sub_authority.len() > SID_MAX_SUB_AUTHORITIES {
            return Err(Error::SidTooManySubAuthorities);
        }
        let mut array = [0u32; SID_MAX_SUB_AUTHORITIES];
        array[..sub_authority.len()].copy_from_slice(sub_authority);
        Ok(Sid {
            identifier_authority,
            // Bounded by the check above (<= 15).
            sub_authority_count: sub_authority.len() as u8,
            sub_authority: array,
        })
    }

    /// The six-byte IdentifierAuthority. Spec: [MS-DTYP] 2.4.1, 2.4.2.2.
    #[must_use]
    pub fn identifier_authority(&self) -> [u8; 6] {
        self.identifier_authority
    }

    /// The IdentifierAuthority as a 48-bit number, `Value[0]` most significant.
    ///
    /// Spec: [MS-DTYP] 2.1 (multi-byte integers default to big-endian, "Network
    /// Byte Order"); 2.4.1 (WORLD_SID_AUTHORITY `{0,0,0,0,0,1}` is authority 1
    /// in S-1-1-0); 2.4.2.1 (the authority is compared against 2^32).
    #[must_use]
    pub fn identifier_authority_value(&self) -> u64 {
        self.identifier_authority
            .iter()
            .fold(0u64, |acc, &octet| (acc << 8) | u64::from(octet))
    }

    /// SubAuthorityCount. Spec: [MS-DTYP] 2.4.2.2.
    #[must_use]
    pub fn sub_authority_count(&self) -> u8 {
        self.sub_authority_count
    }

    /// The SubAuthority values (the last one is the RID). Spec: [MS-DTYP] 2.4.2.
    #[must_use]
    pub fn sub_authority(&self) -> &[u32] {
        &self.sub_authority[..usize::from(self.sub_authority_count)]
    }

    /// Length of the packet representation: 8 + 4 * SubAuthorityCount.
    /// Always a multiple of 4. Spec: [MS-DTYP] 2.4.2.2; 2.4.4.2 ("The length of
    /// the SID MUST be a multiple of 4").
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        SID_FIXED_LEN + SUB_AUTHORITY_LEN * usize::from(self.sub_authority_count)
    }

    /// Decode a SID packet that must occupy all of `input`.
    ///
    /// Spec: [MS-DTYP] 2.4.2.2; strict framing ([`Error::TrailingData`]).
    pub fn decode(input: &[u8]) -> Result<Sid> {
        let (sid, used) = Sid::decode_prefix(input)?;
        if used != input.len() {
            return Err(Error::TrailingData);
        }
        Ok(sid)
    }

    /// Decode a SID packet at the start of `input`; return it and its length.
    ///
    /// Spec: [MS-DTYP] 2.4.2.2.
    pub(crate) fn decode_prefix(input: &[u8]) -> Result<(Sid, usize)> {
        let mut r = Reader::new(input);
        // Revision MUST be 0x01. Spec: [MS-DTYP] 2.4.2.2.
        if r.u8(Error::SidTruncated)? != SID_REVISION {
            return Err(Error::SidRevision);
        }
        // SubAuthorityCount, at most 15 — checked before anything is read
        // from it. Spec: [MS-DTYP] 2.4.2.2.
        let count = r.u8(Error::SidTruncated)?;
        if usize::from(count) > SID_MAX_SUB_AUTHORITIES {
            return Err(Error::SidTooManySubAuthorities);
        }
        // IdentifierAuthority, six bytes in array order. Spec: [MS-DTYP] 2.4.1.
        let identifier_authority = r.array::<6>(Error::SidTruncated)?;
        // SubAuthority[count], unsigned 32-bit, little-endian (2.4.6).
        let mut sub_authority = [0u32; SID_MAX_SUB_AUTHORITIES];
        for slot in sub_authority.iter_mut().take(usize::from(count)) {
            *slot = r.u32_le(Error::SidTruncated)?;
        }
        let sid = Sid {
            identifier_authority,
            sub_authority_count: count,
            sub_authority,
        };
        Ok((sid, r.position()))
    }

    /// Append the packet representation to `out`. Spec: [MS-DTYP] 2.4.2.2.
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        out.push(SID_REVISION);
        out.push(self.sub_authority_count);
        out.extend_from_slice(&self.identifier_authority);
        for value in self.sub_authority() {
            out.extend_from_slice(&value.to_le_bytes());
        }
    }

    /// The packet representation. Spec: [MS-DTYP] 2.4.2.2.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());
        self.encode_into(&mut out);
        out
    }

    /// Parse the string form `S-1-IdentifierAuthority[-SubAuthority...]`.
    ///
    /// Grammar: [MS-DTYP] 2.4.2.1, read with RFC 5234 (which 2.4.2.1 cites):
    /// - the quoted literals `"S-1-"` and `"0x"` match case-insensitively
    ///   (RFC 5234 §2.3: "ABNF strings are case insensitive");
    /// - `DIGIT` is `%x30-39` and `HEXDIG` is `DIGIT / "A" / ... / "F"`, so a-f
    ///   are accepted too (RFC 5234 Appendix B.1, §2.3);
    /// - the IdentifierAuthority must use the canonical form for its value:
    ///   decimal (1 to 10 digits, no leading "0") iff it is below 2^32,
    ///   `"0x" 12HEXDIG` iff it is 2^32 or more (2.4.2.1 comments);
    /// - 0 to 15 SubAuthority values, each decimal with no leading "0" and
    ///   fitting 32 bits. Zero is accepted although the ABNF says
    ///   `1*SubAuthority`: see the note in the body (Q-020, resolved).
    pub fn parse_sid_string(text: &str) -> Result<Sid> {
        // SID= "S-1-" IdentifierAuthority 1*SubAuthority. Spec: [MS-DTYP]
        // 2.4.2.1; literal matched case-insensitively per RFC 5234 §2.3.
        let rest = strip_literal(text.as_bytes(), b"S-1-").ok_or(Error::SidStringSyntax)?;
        let (authority, mut rest) = match strip_literal(rest, b"0x") {
            // IdentifierAuthorityHex = "0x" 12HEXDIG, used iff the authority
            // is >= 2^32. Spec: [MS-DTYP] 2.4.2.1; RFC 5234 Appendix B.1.
            Some(hex) => {
                let (value, after) = parse_hex12(hex)?;
                if value < (1u64 << 32) {
                    return Err(Error::SidStringNonCanonicalAuthority);
                }
                (value, after)
            }
            // IdentifierAuthorityDec, used iff the authority is < 2^32.
            // Spec: [MS-DTYP] 2.4.2.1.
            None => {
                let (value, after) = parse_decimal(rest)?;
                if value >= (1u64 << 32) {
                    return Err(Error::SidStringNonCanonicalAuthority);
                }
                (value, after)
            }
        };
        let mut sub_authority = [0u32; SID_MAX_SUB_AUTHORITIES];
        let mut count = 0usize;
        while !rest.is_empty() {
            // SubAuthority= "-" 1*10DIGIT. Spec: [MS-DTYP] 2.4.2.1.
            rest = rest.strip_prefix(b"-").ok_or(Error::SidStringSyntax)?;
            let (value, after) = parse_decimal(rest)?;
            // At most 15 elements. Spec: [MS-DTYP] 2.4.2.2.
            if count == SID_MAX_SUB_AUTHORITIES {
                return Err(Error::SidTooManySubAuthorities);
            }
            // SubAuthority is an unsigned 32-bit integer. Spec: 2.4.2.2.
            sub_authority[count] =
                u32::try_from(value).map_err(|_| Error::SidStringValueOutOfRange)?;
            count += 1;
            rest = after;
        }
        // Spec conflict (Q-020, resolved): the 2.4.2.1 ABNF requires
        // `1*SubAuthority`, but 2.4.2.2 sets only a maximum for
        // SubAuthorityCount and the 2.4.2.4 table lists SIDs with none —
        // NT_AUTHORITY "S-1-5" ("A SID containing only the
        // SECURITY_NT_AUTHORITY identifier authority") and CREATOR_AUTHORITY
        // "S-1-3". Every valid packet must have a string form, so zero
        // SubAuthority values are accepted here and emitted by
        // `to_sid_string`.
        //
        // The authority is < 2^48 (at most 12 hex digits or < 2^32 decimal);
        // its six bytes are the low six big-endian bytes of the value (see
        // `identifier_authority_value`).
        let mut identifier_authority = [0u8; 6];
        identifier_authority.copy_from_slice(&authority.to_be_bytes()[2..8]);
        Sid::new(identifier_authority, &sub_authority[..count])
    }

    /// Format the canonical string form `S-1-IdentifierAuthority[-SubAuthority...]`.
    ///
    /// Spec: [MS-DTYP] 2.4.2.1 — the IdentifierAuthority in decimal when it is
    /// below 2^32, otherwise `0x` followed by all 12 hexadecimal digits; every
    /// SubAuthority in decimal; no leading zeros in decimal numbers. Literals
    /// are written as spelled in the grammar (`S-1-`, `0x`) and hex letters as
    /// spelled in the RFC 5234 Appendix B.1 HEXDIG rule (`A`-`F`). A SID with
    /// no SubAuthority is written `S-1-<authority>` (2.4.2.4, Q-020).
    #[must_use]
    pub fn to_sid_string(&self) -> String {
        let authority = self.identifier_authority_value();
        let mut text = String::from("S-1-");
        if authority < (1u64 << 32) {
            text.push_str(&authority.to_string());
        } else {
            // authority < 2^48, so exactly 12 hex digits after zero padding.
            text.push_str(&format!("0x{authority:012X}"));
        }
        for value in self.sub_authority() {
            text.push('-');
            text.push_str(&value.to_string());
        }
        text
    }
}

/// Match an ABNF quoted literal at the start of `input`, ignoring the case of
/// US-ASCII letters; return the rest.
///
/// Spec: RFC 5234 §2.3 ("ABNF strings are case insensitive and the character
/// set for these strings is US-ASCII"), as used by [MS-DTYP] 2.4.2.1.
fn strip_literal<'a>(input: &'a [u8], literal: &[u8]) -> Option<&'a [u8]> {
    if input.len() >= literal.len() && input[..literal.len()].eq_ignore_ascii_case(literal) {
        Some(&input[literal.len()..])
    } else {
        None
    }
}

/// Parse exactly 12 HEXDIG; return the value and the rest.
///
/// Spec: [MS-DTYP] 2.4.2.1 (`"0x" 12HEXDIG`); RFC 5234 Appendix B.1 (`HEXDIG =
/// DIGIT / "A" / "B" / "C" / "D" / "E" / "F"`, `DIGIT = %x30-39`) and §2.3
/// (the quoted letters are case-insensitive, so a-f match as well).
fn parse_hex12(input: &[u8]) -> Result<(u64, &[u8])> {
    if input.len() < 12 {
        return Err(Error::SidStringSyntax);
    }
    let mut value = 0u64;
    for &c in &input[..12] {
        let digit = match c {
            b'0'..=b'9' => c - b'0',
            b'A'..=b'F' => c - b'A' + 10,
            b'a'..=b'f' => c - b'a' + 10,
            _ => return Err(Error::SidStringSyntax),
        };
        // 12 digits of 4 bits: at most 2^48 - 1, no overflow.
        value = (value << 4) | u64::from(digit);
    }
    Ok((value, &input[12..]))
}

/// Parse one decimal number of the SID string form; return it and the rest.
///
/// Spec: [MS-DTYP] 2.4.2.1 — `1*10DIGIT`, and "No leading "0" characters are
/// allowed" for decimal numbers (a lone "0" is the value zero, as in S-1-0-0).
fn parse_decimal(input: &[u8]) -> Result<(u64, &[u8])> {
    let digits = input.iter().take_while(|c| c.is_ascii_digit()).count();
    if digits == 0 || digits > 10 {
        return Err(Error::SidStringSyntax);
    }
    if digits > 1 && input[0] == b'0' {
        return Err(Error::SidStringLeadingZero);
    }
    // At most 10 decimal digits, so the value is below 10^10 and fits u64.
    let value = input[..digits]
        .iter()
        .fold(0u64, |acc, &c| acc * 10 + u64::from(c - b'0'));
    Ok((value, &input[digits..]))
}
