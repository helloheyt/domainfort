//! Comparison keys: the RDN key of an object and the key of a `unique`
//! attribute value — computed in this one place (D64: canonical identity in
//! one place).
//!
//! String(Unicode) equality in AD is defined through [MS-UCODEREF] sort keys
//! ([MS-ADTS] 3.1.1.2.2.4.13, 6.5.1), and [MS-UCODEREF] is not an allowed
//! source yet (Q-080, PENDING-OWNER P-9). Until it is, phase 1 uses the
//! interim rule Q-080 proposes and A-29 / P-9 adopted:
//!
//! - a name value must be **printable ASCII**, bytes `0x20..=0x7E`; anything
//!   else is refused (fail closed — never a guess at a Unicode rule);
//! - the key is the value with `A`–`Z` folded to `a`–`z` (the "C" locale case
//!   rule that [MS-ADTS] 3.1.1.2.2.4.12 NoCaseString cites, as quoted in
//!   Q-080). On ASCII input this can only merge *more* names than a
//!   case-insensitive Unicode rule, never fewer (Q-080 item 2).
//!
//! For a value of any other syntax the comparison key is its bytes.
//!
//! Spec: Q-080 (interim, P-9); docs/46 §1 (String(Unicode) note), §8.3 item
//! 3, §8.5; [MS-ADTS] 3.1.1.1.4 / 3.1.1.3.1.2.1 (RDN value parts unique among
//! siblings), 3.1.1.5.1.2 (naming constraints).

use crate::error::Violation;
use crate::schema::ValueSyntax;
use crate::types::AttrId;
use crate::{MAX_RDN_KEY_LEN, RDN_SIZE_LIMIT};

/// `true` for a printable ASCII byte, `0x20..=0x7E`. Spec: Q-080 item 1.
fn printable_ascii(b: u8) -> bool {
    (0x20..=0x7E).contains(&b)
}

/// Fold `A`–`Z` to `a`–`z`; every other byte is kept (input is printable
/// ASCII). Spec: Q-080 item 2.
fn fold(value: &[u8]) -> Vec<u8> {
    value.iter().map(u8::to_ascii_lowercase).collect()
}

/// Check the RDN characters: no 0x00 / 0x0A ([MS-ADTS] 3.1.1.5.1.2), then
/// printable ASCII only (Q-080 interim).
fn check_rdn_characters(value: &[u8]) -> Result<(), Violation> {
    // Spec: [MS-ADTS] 3.1.1.5.1.2 — "The RDN MUST not contain a character
    // with value 0xA" / "… with value 0x0".
    if value.iter().any(|b| *b == 0x00 || *b == 0x0A) {
        return Err(Violation::RdnForbiddenCharacter);
    }
    // Spec: Q-080 item 1 (ASCII only in every RDN value, P-9).
    if !value.iter().copied().all(printable_ascii) {
        return Err(Violation::RdnNotAscii);
    }
    Ok(())
}

/// The RDN key of an object whose RDN attribute has the RDN label length
/// `att_len` and the single value `value`.
///
/// Refuses an empty value, a 0x00 / 0x0A character, a value that is not
/// printable ASCII, and an RDN whose `att=val` form is not under
/// [`RDN_SIZE_LIMIT`] characters (strict reading, docs/46 §8.3; Q-090). The
/// value is ASCII once accepted, so its length in characters — UTF-16 code
/// units, Q-080 item 4 — equals its length in bytes.
///
/// Spec: docs/46 §8.3 item 3; [MS-ADTS] 3.1.1.1.4 (RDN = "att=val"),
/// 3.1.1.5.1.2 ("The RDN size MUST be less than 255 characters"); Q-080.
pub(crate) fn rdn_key(value: &[u8], att_len: usize) -> Result<Vec<u8>, Violation> {
    if value.is_empty() {
        return Err(Violation::RdnKeyEmpty);
    }
    check_rdn_characters(value)?;
    // att + "=" + val, all ASCII: characters = bytes. Spec: 3.1.1.5.1.2.
    if att_len.saturating_add(1).saturating_add(value.len()) >= RDN_SIZE_LIMIT {
        return Err(Violation::RdnTooLong);
    }
    Ok(fold(value))
}

/// The RDN key to look a child up by, from an RDN value given by a reader.
/// The same characters rule as [`rdn_key`]; the size rule needs the RDN
/// attribute's label, which a lookup does not know, so only the codec bound
/// [`MAX_RDN_KEY_LEN`] applies (a longer name can never have been stored).
/// Spec: docs/46 §8.3 item 3; docs/32 §2, §8; Q-080.
pub(crate) fn lookup_rdn_key(value: &[u8]) -> Result<Vec<u8>, Violation> {
    if value.is_empty() {
        return Err(Violation::RdnKeyEmpty);
    }
    // Bound the work before scanning the input. Spec: docs/32 §8.
    if value.len() > MAX_RDN_KEY_LEN {
        return Err(Violation::RdnKeyTooLong);
    }
    check_rdn_characters(value)?;
    Ok(fold(value))
}

/// The comparison key of a value of a `unique` attribute: printable ASCII
/// with A–Z folded for Utf8String (Q-080 interim; any other byte →
/// [`Violation::ComparisonKeyNotAscii`]), the raw bytes for every other
/// syntax. Spec: docs/46 §8.5; Q-080.
pub(crate) fn unique_key(
    id: AttrId,
    syntax: ValueSyntax,
    value: &[u8],
) -> Result<Vec<u8>, Violation> {
    match syntax {
        ValueSyntax::Utf8String => {
            if value.iter().copied().all(printable_ascii) {
                Ok(fold(value))
            } else {
                Err(Violation::ComparisonKeyNotAscii(id))
            }
        }
        _ => Ok(value.to_vec()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Source: Q-080 items 1-2 (printable ASCII, A–Z fold) and [MS-ADTS]
    // 3.1.1.5.1.2 (0x00 / 0x0A; RDN under 255 characters, strict reading of
    // docs/46 §8.3 — `att=val` counted whole). "Peter Houston" is the RDN
    // value of the [MS-ADTS] 3.1.1.1.4 example ("cn=Peter Houston").
    #[test]
    fn rdn_key_rules() {
        assert_eq!(rdn_key(b"Peter Houston", 2).unwrap(), b"peter houston");
        assert_eq!(rdn_key(b"A-Z[]_`az~", 2).unwrap(), b"a-z[]_`az~");
        assert_eq!(rdn_key(b"", 2), Err(Violation::RdnKeyEmpty));
        assert_eq!(rdn_key(b"a\nb", 2), Err(Violation::RdnForbiddenCharacter));
        assert_eq!(rdn_key(b"a\0b", 2), Err(Violation::RdnForbiddenCharacter));
        assert_eq!(rdn_key(b"a\tb", 2), Err(Violation::RdnNotAscii));
        assert_eq!(rdn_key(b"a\x7Fb", 2), Err(Violation::RdnNotAscii));
        assert_eq!(rdn_key("é".as_bytes(), 2), Err(Violation::RdnNotAscii));
        // att_len 2: "xx=" + 251 = 254 < 255 accepted; 252 refused.
        assert!(rdn_key(&[b'v'; 251], 2).is_ok());
        assert_eq!(rdn_key(&[b'v'; 252], 2), Err(Violation::RdnTooLong));
    }

    // Source: docs/46 §8.5 (raw bytes for non-string syntaxes; Q-080 key for
    // Utf8String).
    #[test]
    fn unique_key_rules() {
        let id = AttrId(0);
        assert_eq!(
            unique_key(id, ValueSyntax::Utf8String, b"Alice@X").unwrap(),
            b"alice@x"
        );
        assert_eq!(
            unique_key(id, ValueSyntax::Utf8String, "Ä".as_bytes()),
            Err(Violation::ComparisonKeyNotAscii(id))
        );
        assert_eq!(
            unique_key(id, ValueSyntax::OctetString, b"AbC").unwrap(),
            b"AbC"
        );
    }

    #[test]
    fn lookup_key_bounds() {
        assert_eq!(lookup_rdn_key(b""), Err(Violation::RdnKeyEmpty));
        assert_eq!(
            lookup_rdn_key(&vec![b'a'; MAX_RDN_KEY_LEN + 1]),
            Err(Violation::RdnKeyTooLong)
        );
        assert_eq!(lookup_rdn_key(b"ABC").unwrap(), b"abc");
    }
}
