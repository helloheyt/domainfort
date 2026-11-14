//! admind's own password rules — the cleartext password policy of
//! [MS-SAMR] 3.1.1.7.2 as phase 1 can apply it (docs/51 §11, the password
//! row; R51-5; decision A-79), checked before the password goes anywhere.
//!
//! [MS-SAMR] 3.1.1.7.2 (v20260427, pinned; opened in this session):
//!
//! * item 1 — "The value MUST be interpreted as a UTF-16 encoded string";
//!   its odd-octet rule cannot arise here: the password arrives as UTF-8
//!   text (keyd takes passwords as text, docs/50 §3.4) and every Unicode
//!   string has a whole UTF-16 encoding;
//! * item 2 — "The value MUST be less than or equal to 256 characters (…
//!   the maximum password length constraint)": counted in **UTF-16 code
//!   units** — item 1's own interpretation, and never more permissive than
//!   counting code points ([`MAX_PASSWORD_UTF16_UNITS`]); the 1024-octet
//!   bound of the wire field (`ipc_keyd::MAX_SECRET`) applies as well (the
//!   codec);
//! * item 3.2.1 — "The number of characters in the value MUST not be
//!   smaller than the value of the Effective-MinimumPasswordLength
//!   attribute": counted in **Unicode code points**, never more permissive
//!   than counting UTF-16 units; the minimum is admind's
//!   `min_password_length` (≥ 12, A-79 / P-24), since the phase-1 schema has
//!   no minPwdLength;
//! * item 3.2.2 — "The value MUST NOT contain the sAMAccountName attribute
//!   value as a case-insensitive substring if that value contains more than
//!   two characters" — [`contains_account_name`];
//! * item 3's conditions (UF_NORMAL_ACCOUNT, not RID 502, no
//!   UF_PASSWD_NOTREQD) — admind cannot see an account's
//!   userAccountControl; it applies 3.2.1 and 3.2.2 to **every** account it
//!   sets a password for (a computer's included — stricter, never weaker);
//!   dird refuses krbtgt's password set (docs/51 §5.2 row 5; directory-admin)
//!   and no account has UF_PASSWD_NOTREQD (R46-6);
//! * items 3.2.3 (displayName) and 3.2.4 (complexity) — not applied: the
//!   phase-1 schema has neither displayName nor
//!   Effective-PasswordComplexityEnabled (docs/51 §11, §14).
//!
//! Which rule a password broke is never reported — not to the client, not
//! in the audit event, not in the log (docs/37 §2; docs/questions/Q-340
//! item 7): the callers see one class, [`PasswordRefused`].
//!
//! Spec: [MS-SAMR] 3.1.1.7.2 items 1, 2, 3; docs/51 §5.2 row 5, §7.6, §11;
//! R51-5; A-79; P-24; docs/questions/Q-401.

/// The most UTF-16 code units a password may have.
/// Spec: [MS-SAMR] 3.1.1.7.2 items 1, 2 ("less than or equal to 256
/// characters").
pub const MAX_PASSWORD_UTF16_UNITS: usize = 256;

/// A sAMAccountName longer than this many characters must not be a
/// case-insensitive substring of the password.
/// Spec: [MS-SAMR] 3.1.1.7.2 item 3.2.2 ("if that value contains more than
/// two characters").
pub const ACCOUNT_NAME_CHARS_CHECKED_ABOVE: usize = 2;

/// The password broke one of admind's rules. Deliberately no detail.
/// Spec: docs/37 §2; docs/questions/Q-340 item 7.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasswordRefused;

/// The rules that need nothing but the password: the maximum
/// ([`MAX_PASSWORD_UTF16_UNITS`] UTF-16 code units) and the minimum
/// (`min_chars` code points). Checked before dird is asked anything.
///
/// # Errors
/// [`PasswordRefused`].
///
/// Spec: [MS-SAMR] 3.1.1.7.2 items 1, 2, 3.2.1; A-79.
pub fn check_length(password: &str, min_chars: u32) -> Result<(), PasswordRefused> {
    let units = password.encode_utf16().count();
    let chars = password.chars().count();
    let min = usize::try_from(min_chars).unwrap_or(usize::MAX);
    if units > MAX_PASSWORD_UTF16_UNITS || chars < min {
        return Err(PasswordRefused);
    }
    Ok(())
}

/// The account-name rule, once dird has named the account
/// (`BeginPasswordSet`'s NT-PRINCIPAL binding).
///
/// # Errors
/// [`PasswordRefused`].
///
/// Spec: [MS-SAMR] 3.1.1.7.2 item 3.2.2.
pub fn check_account_name(password: &str, sam_account_name: &str) -> Result<(), PasswordRefused> {
    if contains_account_name(password, sam_account_name) {
        Err(PasswordRefused)
    } else {
        Ok(())
    }
}

/// Whether `password` contains `sam_account_name` as a case-insensitive
/// substring, when the name has more than two characters.
///
/// "Case-insensitive" is not defined further by the section; the strict
/// reading is taken (docs/questions/Q-401): two characters are equal when
/// they are the same character, or when each has a single-character lower
/// case mapping and those are the same, or a single-character upper case
/// mapping and those are the same (Rust's `char::to_lowercase` /
/// `to_uppercase`, the Unicode case mappings). So a name in ASCII is also
/// found when the password spells a letter with a character whose case
/// mapping is that letter (for example U+212A KELVIN SIGN for `k`).
/// Substrings are taken over characters (code points).
///
/// Spec: [MS-SAMR] 3.1.1.7.2 item 3.2.2.
#[must_use]
pub fn contains_account_name(password: &str, sam_account_name: &str) -> bool {
    let name: Vec<char> = sam_account_name.chars().collect();
    if name.len() <= ACCOUNT_NAME_CHARS_CHECKED_ABOVE {
        return false;
    }
    let text: Vec<char> = password.chars().collect();
    if text.len() < name.len() {
        return false;
    }
    text.windows(name.len()).any(|window| {
        window
            .iter()
            .zip(name.iter())
            .all(|(a, b)| same_ignoring_case(*a, *b))
    })
}

/// The single character a case mapping yields, or `None` when it yields
/// several.
fn single(mut mapped: impl Iterator<Item = char>) -> Option<char> {
    let first = mapped.next()?;
    mapped.next().is_none().then_some(first)
}

/// Equality ignoring case ([`contains_account_name`]).
fn same_ignoring_case(a: char, b: char) -> bool {
    if a == b {
        return true;
    }
    let lower = single(a.to_lowercase()).is_some_and(|x| Some(x) == single(b.to_lowercase()));
    let upper = single(a.to_uppercase()).is_some_and(|x| Some(x) == single(b.to_uppercase()));
    lower || upper
}

#[cfg(test)]
mod tests {
    use super::*;

    /// [MS-SAMR] 3.1.1.7.2 item 2: 256 UTF-16 units pass, 257 do not; a
    /// supplementary character counts two units (item 1: UTF-16).
    #[test]
    fn the_maximum_in_utf16_units() {
        assert_eq!(check_length(&"a".repeat(256), 12), Ok(()));
        assert_eq!(check_length(&"a".repeat(257), 12), Err(PasswordRefused));
        let clef = '\u{1D11E}'; // two UTF-16 units, one code point
        let at = format!("{}{}", "a".repeat(254), clef);
        assert_eq!(at.encode_utf16().count(), 256);
        assert_eq!(check_length(&at, 12), Ok(()));
        let over = format!("{}{}", "a".repeat(255), clef);
        assert_eq!(check_length(&over, 12), Err(PasswordRefused));
    }

    /// [MS-SAMR] 3.1.1.7.2 item 3.2.1 with A-79's minimum: counted in code
    /// points — twelve supplementary characters reach 12, eleven do not
    /// (although they are 22 UTF-16 units).
    #[test]
    fn the_minimum_in_code_points() {
        assert_eq!(check_length(&"a".repeat(12), 12), Ok(()));
        assert_eq!(check_length(&"a".repeat(11), 12), Err(PasswordRefused));
        assert_eq!(check_length("", 12), Err(PasswordRefused));
        let clef = '\u{1D11E}';
        assert_eq!(
            check_length(&clef.to_string().repeat(11), 12),
            Err(PasswordRefused)
        );
        assert_eq!(check_length(&clef.to_string().repeat(12), 12), Ok(()));
        assert_eq!(check_length(&"é".repeat(15), 16), Err(PasswordRefused));
        assert_eq!(check_length(&"é".repeat(16), 16), Ok(()));
    }

    /// [MS-SAMR] 3.1.1.7.2 item 3.2.2: the name anywhere, in any case.
    #[test]
    fn the_account_name_in_any_case() {
        for password in [
            "carol-is-great-123",
            "xxCAROLxx-padding",
            "My-CaRoL-password",
            "padding-padding-carol",
        ] {
            assert!(contains_account_name(password, "carol"), "{password}");
            assert_eq!(check_account_name(password, "carol"), Err(PasswordRefused));
        }
        assert!(!contains_account_name("caro-l-separated-1", "carol"));
        assert_eq!(check_account_name("a-long-passphrase", "carol"), Ok(()));
        // A computer's name with its "$".
        assert!(contains_account_name("prefix-WS9$-suffix", "ws9$"));
        assert!(!contains_account_name("prefix-WS9-suffix", "ws9$"));
    }

    /// [MS-SAMR] 3.1.1.7.2 item 3.2.2: "if that value contains more than
    /// two characters" — a name of one or two characters is not checked.
    #[test]
    fn short_names_are_not_checked() {
        assert!(!contains_account_name("jo-jo-jo-jo-jo-jo", "jo"));
        assert!(!contains_account_name("xxxxxxxxxxxx", "x"));
        assert!(!contains_account_name("anything", ""));
        assert!(contains_account_name("xx-joe-xxxxxx", "joe"));
    }

    /// The strict reading of "case-insensitive" (docs/questions/Q-401): a
    /// character whose case mapping is the name's letter counts as that
    /// letter (U+212A KELVIN SIGN lower-cases to `k`; U+017F LATIN SMALL
    /// LETTER LONG S upper-cases to `S`).
    #[test]
    fn unicode_case_mappings_count() {
        assert!(contains_account_name("xx-\u{212A}ate-xxxxxx", "kate"));
        assert!(contains_account_name("xx-\u{17F}am-xxxxxx", "sam"));
        assert!(!contains_account_name("xx-ḱate-xxxxxx", "kate"));
    }
}
