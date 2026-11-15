#![forbid(unsafe_code)]
// No heap outside the tests: the library cannot allocate, so it cannot leave
// a copy of a password in memory that is never wiped (module documentation,
// "No copy of the password").
#![cfg_attr(not(test), no_std)]
//! `admin-password-policy`: the password policy — the owner's rules (docs/56
//! §7, P-24) on top of the cleartext password policy of [MS-SAMR] 3.1.1.7.2
//! as phase 1 can apply it (docs/51 §11, the password row; R51-5; decision
//! A-79) — in **one** place.
//!
//! # One rule set, one enforcement point
//!
//! [`check_password`] is the whole rule set. It is applied by:
//!
//! * **keyd's one password-install path** (crate keyd, `directory.rs`
//!   `password_policy`, run by `Keyd::install_password` for `set_secret` and
//!   `complete_change_password`, and by kpasswd's `open` on the same value) —
//!   the **authoritative** enforcement point: every password, on every
//!   path, is cleartext there and nowhere else (docs/questions/Q-605 item 1,
//!   A-117; Q-664, A-126);
//! * `provision first-admin-secret` (crate provision, `first_admin::line`) —
//!   a pre-check with **the same function**, so a password keyd would refuse
//!   is refused before keyd is contacted (Q-605 item 3);
//! * admind's `SetPassword` (crate admin-daemon, `worker.rs`) — a
//!   non-authoritative pre-check with **the same function**, once dird has
//!   named the account; before dird is asked anything it runs
//!   [`check_password_text`], the part of the same rule set that needs only
//!   the password, so that a password refused on its text alone never makes
//!   dird act (docs/questions/Q-910 item 13).
//!
//! These two functions are the crate's only checks: no rule can be applied
//! alone from outside (class C14, docs/52 — "a partial rule set at a
//! caller" is not representable).
//!
//! The crate is a leaf: no dependency, no I/O, no state.
//!
//! # No copy of the password
//!
//! keyd holds a password only in zeroizing buffers that are wiped when the
//! operation returns (docs/10 §12 I7). A rule that collected the password's
//! characters into a heap buffer would leave a copy that is never wiped
//! (class: "a secret copied into memory nobody wipes"). The library is
//! `no_std` without `alloc` (outside its tests), so it **cannot** allocate:
//! every rule walks the password's `&str` in place, with at most a window of
//! [`RUN_LENGTH_REFUSED`] characters on the stack. The class is impossible
//! here by construction; what remains is the stack and registers any
//! computation on the password uses (docs/questions/Q-910 item 9).
//!
//! # The rules
//!
//! Each rule below names its source. "Character" means a Unicode code point
//! unless the rule says otherwise.
//!
//! 1. **Maximum** — at most [`MAX_PASSWORD_UTF16_UNITS`] UTF-16 code units
//!    ([MS-SAMR] 3.1.1.7.2 items 1, 2; Q-401 item 2).
//! 2. **Minimum** — at least `min_chars` code points, and never fewer than
//!    the owner's floor [`MIN_PASSWORD_CHARS_FLOOR`] = 8, whatever a caller
//!    passes (docs/56 §7 P-24 "8+ characters"; [MS-SAMR] 3.1.1.7.2 item
//!    3.2.1; Q-401 item 3).
//! 3. **Character classes** — at least one ASCII upper-case letter (0x41 to
//!    0x5A), one ASCII lower-case letter (0x61 to 0x7A), one ASCII digit
//!    (0x30 to 0x39) and one special character of [`SPECIAL_CHARACTERS`]
//!    (docs/56 §7 P-24 "upper/lower/digit/special"; the ranges and the
//!    special-character table are [MS-SAMR] 3.1.1.7.2 item 3.2.4's classes
//!    1, 2, 3 and 5). Any other character (a non-ASCII character, the space,
//!    a control character) counts for the length and satisfies no class —
//!    there is no Unicode source in SOURCES yet (owner item P-76), so it
//!    fails closed (docs/questions/Q-910 item 3).
//! 4. **No sequences** — no [`RUN_LENGTH_REFUSED`] consecutive characters
//!    that ascend or descend by one through the ASCII letters (case
//!    ignored) or through the ASCII digits: `abc`, `Abc`, `cba`, `123`,
//!    `321` (docs/56 §7 P-24; PENDING-OWNER P-24 "ascending/descending, 3 or
//!    more"; Q-910 item 4).
//! 5. **No repeats** — no character [`RUN_LENGTH_REFUSED`] times in a row,
//!    case ignored as in rule 6: `111`, `aaa`, `aAa`, `!!!` (docs/56 §7
//!    P-24; Q-910 item 5).
//! 6. **Not the account name** — none of the account name's fragments
//!    ([`contains_account_name`]) as a case-insensitive substring: the whole
//!    sAMAccountName ([MS-SAMR] 3.1.1.7.2 item 3.2.2, "more than two
//!    characters"), the name without a computer's trailing `$` (docs/47
//!    §9.1), and each portion delimited by [`NAME_PORTION_DELIMITERS`] that
//!    is longer than two characters (the method of [MS-SAMR] 3.1.1.7.2 item
//!    3.2.3, applied to the account name — docs/56 §7 P-24 "not even as a
//!    part"; Q-910 item 6).
//! 7. **Not the organisation name** — the same fragments of the
//!    organisation name: the realm (the domain's DNS name) **without its
//!    final, top-level label** ([`organisation_labels`]) — so each remaining
//!    label longer than two characters (docs/56 §7 P-24; main-session
//!    decision recorded in Q-910 item 6: a top-level label such as `COM` or
//!    `ORG` is a public suffix, not the organisation's name).
//! 8. **No weak words** — none of [`WEAK_WORDS`] as a case-insensitive
//!    substring (docs/56 §7 P-24 "no weak words such as admin"; the list is
//!    a product decision for owner review, docs/questions/Q-911).
//!
//! Which rule a password broke is never reported — not to the client, not
//! in the audit event, not in the log (docs/37 §2; docs/questions/Q-340
//! item 7; RFC 3244 has no result string here, A-121): the callers see one
//! class, [`PasswordRefused`]. The password itself never appears in an
//! error, a `Debug` output or a log: no function here formats it.
//!
//! Spec: [MS-SAMR] v20260427 3.1.1.7.2 items 1, 2, 3.2.1, 3.2.2, 3.2.3,
//! 3.2.4; docs/56 §7 (P-24); PENDING-OWNER P-24, A-79, A-94, A-117, A-126;
//! docs/51 §5.2 row 5, §7.6, §11; R51-5; docs/questions/Q-401, Q-605, Q-664,
//! Q-910, Q-911.

/// The most UTF-16 code units a password may have.
/// Spec: [MS-SAMR] 3.1.1.7.2 items 1, 2 ("less than or equal to 256
/// characters").
pub const MAX_PASSWORD_UTF16_UNITS: usize = 256;

/// The owner's minimum password length, in code points: no password is
/// ever accepted with fewer, whatever minimum a caller passes. keyd's
/// `MIN_PASSWORD_CHARS_FLOOR` and the config crate's `MIN_PASSWORD_LENGTH`
/// floor are pinned to this value (keyd `directory.rs`, provision
/// `configs.rs`). An administrator may only raise the minimum.
/// Spec: docs/56 §7 P-24 ("8+ characters"); PENDING-OWNER P-24 ("an
/// administrator may tighten (a higher length)"); [MS-SAMR] 3.1.1.7.2 item
/// 3.2.1.
pub const MIN_PASSWORD_CHARS_FLOOR: u32 = 8;

/// A sAMAccountName longer than this many characters must not be a
/// case-insensitive substring of the password.
/// Spec: [MS-SAMR] 3.1.1.7.2 item 3.2.2 ("if that value contains more than
/// two characters").
pub const ACCOUNT_NAME_CHARS_CHECKED_ABOVE: usize = 2;

/// A delimited portion of a name longer than this many characters must not
/// be a case-insensitive substring of the password.
/// Spec: [MS-SAMR] 3.1.1.7.2 item 3.2.3 ("any case-insensitive portion …
/// that is greater than two characters").
pub const NAME_PORTION_CHARS_CHECKED_ABOVE: usize = 2;

/// The characters that delimit the portions of a name: SP, comma, full
/// stop, HT, hyphen-minus, underscore, number sign — in the table's order.
/// Spec: [MS-SAMR] 3.1.1.7.2 item 3.2.3 (0x0020, 0x002C, 0x002E, 0x0009,
/// 0x002D, 0x005F, 0x0023).
pub const NAME_PORTION_DELIMITERS: [char; 7] = [
    '\u{20}', '\u{2C}', '\u{2E}', '\u{09}', '\u{2D}', '\u{5F}', '\u{23}',
];

/// The special characters: the 32 characters of [MS-SAMR] 3.1.1.7.2 item
/// 3.2.4's fifth class, in the table's order. (The space is not among
/// them.)
/// Spec: [MS-SAMR] 3.1.1.7.2 item 3.2.4 class 5; docs/56 §7 P-24
/// ("special character"); docs/questions/Q-910 item 3.
pub const SPECIAL_CHARACTERS: [char; 32] = [
    '\u{28}', '\u{60}', '\u{7E}', '\u{21}', '\u{40}', '\u{23}', '\u{24}', '\u{25}', '\u{5E}',
    '\u{26}', '\u{2A}', '\u{5F}', '\u{2D}', '\u{2B}', '\u{3D}', '\u{7C}', '\u{5C}', '\u{7B}',
    '\u{7D}', '\u{5B}', '\u{5D}', '\u{3A}', '\u{3B}', '\u{22}', '\u{27}', '\u{3C}', '\u{3E}',
    '\u{2C}', '\u{2E}', '\u{3F}', '\u{29}', '\u{2F}',
];

/// The shortest refused sequence and the shortest refused repeat.
/// Spec: docs/56 §7 P-24 ("sequences (≥3)", "repeats (≥3)"); PENDING-OWNER
/// P-24 (the examples `Abc`, `123`, `111` are already refused).
pub const RUN_LENGTH_REFUSED: usize = 3;

/// The weak words: none may appear in a password, in any case.
///
/// Product decision P-24; list for owner review (docs/questions/Q-911).
/// Derived only from the owner's directive ("no weak words such as admin")
/// and from account-role names this project itself names in its own
/// documents — not from any existing password list, product or data set:
/// * `admin` — the owner's own example (docs/56 §7 P-24); it also covers
///   "administrator", the role of the first administrators (docs/51 §4.4)
///   and keyd's `Admin` role (docs/10 §2);
/// * `root` — the host's superuser account, which runs provisioning
///   (docs/51 §4.3, R50-3);
/// * `krbtgt` — the KDC's account (docs/47 §1.4; [MS-SAMR] 3.1.1.7.2 item
///   3.1.2 names it by its RID).
///
/// Spec: docs/56 §7 P-24; docs/questions/Q-911.
pub const WEAK_WORDS: [&str; 3] = ["admin", "root", "krbtgt"];

/// The password broke one of the rules. Deliberately no detail.
/// Spec: docs/37 §2; docs/questions/Q-340 item 7; A-121.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasswordRefused;

/// What the rules need besides the password, all of it known at the
/// enforcement point — never a new data source (docs/questions/Q-910 item
/// 6): the minimum, the account's name and the organisation's name.
/// Spec: [MS-SAMR] 3.1.1.7.2 items 3.2.1, 3.2.2; docs/56 §7 P-24.
#[derive(Debug, Clone, Copy)]
pub struct PolicyInputs<'a> {
    /// The configured minimum length in code points (keyd's
    /// `min_password_chars`; admind's `min_password_length` for admind's
    /// and provision's pre-checks). Never below [`MIN_PASSWORD_CHARS_FLOOR`]
    /// in effect.
    pub min_chars: u32,
    /// The account's name: the components of its binding's principal name
    /// — for an account, one component, its sAMAccountName (`NAME$` for a
    /// computer, docs/47 §9.1).
    pub account_name: &'a [&'a str],
    /// The realm (the domain's DNS name in upper case, docs/47 §3.3); the
    /// organisation's name is taken from it by [`organisation_labels`].
    pub organisation_name: &'a str,
}

/// The whole rule set (module documentation, rules 1-8): the rules on the
/// password's text alone ([`check_password_text`]: rules 1-5 and 8), then
/// the name rules (6, 7). The maximum is checked first, so every later rule
/// sees at most [`MAX_PASSWORD_UTF16_UNITS`] characters. Nothing is
/// allocated (module documentation, "No copy of the password").
///
/// # Errors
/// [`PasswordRefused`] — whichever rule refused.
///
/// Spec: [MS-SAMR] 3.1.1.7.2 items 1, 2, 3.2.1-3.2.4; docs/56 §7 P-24;
/// docs/questions/Q-605 item 1, Q-910.
pub fn check_password(password: &str, inputs: &PolicyInputs<'_>) -> Result<(), PasswordRefused> {
    check_password_text(password, inputs.min_chars)?;
    if inputs
        .account_name
        .iter()
        .any(|name| contains_account_name(password, name))
        || contains_account_name(password, organisation_labels(inputs.organisation_name))
    {
        return Err(PasswordRefused);
    }
    Ok(())
}

/// The part of the rule set that needs only the password's text (module
/// documentation, rules 1-5 and 8): the maximum, the minimum (`min_chars`,
/// never fewer than [`MIN_PASSWORD_CHARS_FLOOR`]), the character classes,
/// no sequence, no repeat, no weak word. For a caller that must refuse
/// before it can know the names (admind, before dird names the account) —
/// which then runs [`check_password`] once it knows them. Never a
/// substitute for [`check_password`].
///
/// # Errors
/// [`PasswordRefused`] — whichever rule refused.
///
/// Spec: [MS-SAMR] 3.1.1.7.2 items 1, 2, 3.2.1, 3.2.4; docs/56 §7 P-24;
/// docs/questions/Q-910 item 13.
pub fn check_password_text(password: &str, min_chars: u32) -> Result<(), PasswordRefused> {
    check_length(password, min_chars)?;
    if !has_every_character_class(password)
        || has_sequence(password)
        || has_repeat(password)
        || WEAK_WORDS
            .iter()
            .any(|word| contains_ignoring_case(password, word))
    {
        return Err(PasswordRefused);
    }
    Ok(())
}

/// The organisation's name within a realm: every label but the final
/// (top-level) one — `CORP.EXAMPLE.COM` ⇒ `CORP.EXAMPLE`, `EXAMPLE.COM` ⇒
/// `EXAMPLE`. A realm of a single label has no top-level label to drop and
/// is kept whole (fail closed: otherwise nothing would be checked).
/// Spec: docs/56 §7 P-24; main-session decision in docs/questions/Q-910
/// item 6 (a top-level label is a public suffix, not the organisation's
/// name).
fn organisation_labels(realm: &str) -> &str {
    match realm.rsplit_once('.') {
        Some((labels, _top_level)) => labels,
        None => realm,
    }
}

/// Rules 1 and 2, on the password's length: the maximum
/// ([`MAX_PASSWORD_UTF16_UNITS`] UTF-16 code units) and the minimum
/// (`min_chars` code points, never fewer than [`MIN_PASSWORD_CHARS_FLOOR`]).
/// Spec: [MS-SAMR] 3.1.1.7.2 items 1, 2, 3.2.1; docs/56 §7 P-24; A-79.
fn check_length(password: &str, min_chars: u32) -> Result<(), PasswordRefused> {
    let units = password.encode_utf16().count();
    let chars = password.chars().count();
    let min = usize::try_from(min_chars.max(MIN_PASSWORD_CHARS_FLOOR)).unwrap_or(usize::MAX);
    if units > MAX_PASSWORD_UTF16_UNITS || chars < min {
        return Err(PasswordRefused);
    }
    Ok(())
}

/// Rules 6 and 7: whether `password` contains a fragment of `sam_account_name` as a
/// case-insensitive substring. The fragments:
/// * the whole name, when it has more than
///   [`ACCOUNT_NAME_CHARS_CHECKED_ABOVE`] characters ([MS-SAMR] 3.1.1.7.2
///   item 3.2.2);
/// * the name without one trailing `$` (a computer's sAMAccountName is
///   `NAME$`, docs/47 §9.1), when it has more than two characters;
/// * each portion of that name delimited by [`NAME_PORTION_DELIMITERS`]
///   that has more than [`NAME_PORTION_CHARS_CHECKED_ABOVE`] characters
///   (item 3.2.3's method; docs/56 §7 P-24 "not even as a part").
///
/// Every fragment is part of the name, so this never refuses less than item
/// 3.2.2 alone. The organisation's name ([`organisation_labels`]: the realm
/// without its top-level label) is taken apart the same way
/// ([`check_password`]): its labels are its full-stop-delimited portions.
///
/// "Case-insensitive" is not defined further by the section; the strict
/// reading is taken (docs/questions/Q-401 item 4, A-94): two characters are
/// equal when they are the same character, or when each has a
/// single-character lower case mapping and those are the same, or a
/// single-character upper case mapping and those are the same (Rust's
/// `char::to_lowercase` / `to_uppercase`, the Unicode case mappings). So a
/// name in ASCII is also found when the password spells a letter with a
/// character whose case mapping is that letter (for example U+212A KELVIN
/// SIGN for `k`). Substrings are taken over characters (code points).
///
/// Spec: [MS-SAMR] 3.1.1.7.2 items 3.2.2, 3.2.3; docs/56 §7 P-24;
/// docs/questions/Q-401 item 4, Q-910 item 6.
fn contains_account_name(password: &str, sam_account_name: &str) -> bool {
    let whole = sam_account_name;
    if whole.chars().count() > ACCOUNT_NAME_CHARS_CHECKED_ABOVE
        && contains_ignoring_case(password, whole)
    {
        return true;
    }
    let base = whole.strip_suffix('$').unwrap_or(whole);
    if base.chars().count() > ACCOUNT_NAME_CHARS_CHECKED_ABOVE
        && contains_ignoring_case(password, base)
    {
        return true;
    }
    base.split(|c| NAME_PORTION_DELIMITERS.contains(&c))
        .filter(|portion| portion.chars().count() > NAME_PORTION_CHARS_CHECKED_ABOVE)
        .any(|portion| contains_ignoring_case(password, portion))
}

/// Whether `text` contains `needle` as a case-insensitive substring
/// ([`contains_account_name`]'s reading of "case-insensitive"), over
/// characters, in place. An empty needle is never found.
fn contains_ignoring_case(text: &str, needle: &str) -> bool {
    let needle_chars = needle.chars().count();
    if needle_chars == 0 {
        return false;
    }
    text.char_indices().any(|(start, _)| {
        let mut matched = 0usize;
        for (a, b) in text[start..].chars().zip(needle.chars()) {
            if !same_ignoring_case(a, b) {
                return false;
            }
            matched += 1;
        }
        matched == needle_chars
    })
}

/// Every run of [`RUN_LENGTH_REFUSED`] consecutive characters of `text`, as
/// a stack array (no allocation).
fn windows(text: &str) -> impl Iterator<Item = [char; RUN_LENGTH_REFUSED]> + '_ {
    text.char_indices().filter_map(move |(start, _)| {
        let mut window = ['\0'; RUN_LENGTH_REFUSED];
        let mut chars = text[start..].chars();
        for slot in &mut window {
            *slot = chars.next()?;
        }
        Some(window)
    })
}

/// Rule 3: an ASCII upper-case letter, an ASCII lower-case letter, an ASCII
/// digit and a special character, each at least once.
/// Spec: [MS-SAMR] 3.1.1.7.2 item 3.2.4 classes 1 ("characters 0x41 to
/// 0x5A, inclusive"), 2 ("0x61 to 0x7a"), 3 ("0x30 to 0x39"), 5 (the
/// table, [`SPECIAL_CHARACTERS`]); docs/56 §7 P-24; Q-910 item 3.
fn has_every_character_class(text: &str) -> bool {
    let mut upper = false;
    let mut lower = false;
    let mut digit = false;
    let mut special = false;
    for c in text.chars() {
        match c {
            '\u{41}'..='\u{5A}' => upper = true,
            '\u{61}'..='\u{7A}' => lower = true,
            '\u{30}'..='\u{39}' => digit = true,
            c if SPECIAL_CHARACTERS.contains(&c) => special = true,
            // Any other character counts for the length only (fail closed,
            // P-76).
            _ => {}
        }
    }
    upper && lower && digit && special
}

/// Which ordered run a character belongs to, for the sequence rule.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Run {
    /// The ASCII letters, case ignored (0x41 to 0x5A and 0x61 to 0x7A).
    Letter,
    /// The ASCII digits (0x30 to 0x39).
    Digit,
}

/// A character's run and its position in it (a = A = 0 … z = Z = 25;
/// 0 = 0 … 9 = 9), or `None` for a character in neither run.
/// Spec: [MS-SAMR] 3.1.1.7.2 item 3.2.4 classes 1-3 (the ranges); Q-910
/// item 4.
fn position(c: char) -> Option<(Run, i16)> {
    let (run, first) = match c {
        '\u{41}'..='\u{5A}' => (Run::Letter, 0x41),
        '\u{61}'..='\u{7A}' => (Run::Letter, 0x61),
        '\u{30}'..='\u{39}' => (Run::Digit, 0x30),
        _ => return None,
    };
    let code = u8::try_from(c).ok()?;
    Some((run, i16::from(code) - first))
}

/// Whether `window` ascends (`step` = 1) or descends (`step` = -1) by one
/// position at every character, within one run.
fn runs_by(window: &[char; RUN_LENGTH_REFUSED], step: i16) -> bool {
    window
        .windows(2)
        .all(|pair| match (position(pair[0]), position(pair[1])) {
            (Some((run, at)), Some((next_run, next))) => run == next_run && next - at == step,
            _ => false,
        })
}

/// Rule 4: [`RUN_LENGTH_REFUSED`] consecutive characters of one run, each
/// one position above (or each one below) the one before it. No
/// wrap-around (`yza`, `890` are not sequences).
/// Spec: docs/56 §7 P-24; PENDING-OWNER P-24 (`abc`, `123`, `cba`); Q-910
/// item 4.
fn has_sequence(text: &str) -> bool {
    windows(text).any(|window| runs_by(&window, 1) || runs_by(&window, -1))
}

/// Rule 5: one character [`RUN_LENGTH_REFUSED`] times in a row, compared as
/// the name rules compare ([`same_ignoring_case`]).
/// Spec: docs/56 §7 P-24 (`111`); Q-910 item 5.
fn has_repeat(text: &str) -> bool {
    windows(text).any(|window| window.iter().all(|c| same_ignoring_case(*c, window[0])))
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

    /// The inputs of the tests: an account `carol` in realm `EXAMPLE.ORG`
    /// (made-up names), minimum `min`.
    fn inputs(min: u32) -> PolicyInputs<'static> {
        PolicyInputs {
            min_chars: min,
            account_name: &["carol"],
            organisation_name: "EXAMPLE.ORG",
        }
    }

    fn ok(password: &str) -> bool {
        check_password(password, &inputs(MIN_PASSWORD_CHARS_FLOOR)).is_ok()
    }

    /// A made-up password that passes every rule: classes Upper, lower,
    /// digit, special; no run of three; no name or weak word.
    const GOOD: &str = "Tq7#Lm2!";

    #[test]
    fn a_good_password_passes() {
        assert!(ok(GOOD));
        assert!(ok("Juniper-Kettle-71"));
    }

    // ---- rule 1: the maximum ([MS-SAMR] 3.1.1.7.2 items 1, 2) ----------

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
        // Through the whole rule set: a valid password padded past 256.
        let padded = format!("{GOOD}{}", "x-".repeat(124));
        assert_eq!(padded.encode_utf16().count(), 256);
        assert!(ok(&padded));
        assert!(!ok(&format!("{padded}y")));
    }

    // ---- rule 2: the minimum (docs/56 §7 P-24; [MS-SAMR] 3.1.1.7.2 item 3.2.1)

    /// docs/56 §7 P-24 ("8+ characters"): exactly 8 passes, 7 does not.
    #[test]
    fn the_boundary_at_exactly_eight() {
        assert_eq!(GOOD.chars().count(), 8);
        assert!(ok(GOOD));
        assert!(!ok("Tq7#Lm2"));
        assert_eq!(check_length("abcdefgh", 8), Ok(()));
        assert_eq!(check_length("abcdefg", 8), Err(PasswordRefused));
    }

    /// docs/56 §7 P-24 / PENDING-OWNER P-24 ("an administrator may only
    /// raise it"): a caller's minimum below 8 is lifted to 8; a higher one
    /// applies as given.
    #[test]
    fn the_floor_cannot_be_lowered_and_can_be_raised() {
        for min in [0, 1, 7] {
            assert_eq!(check_length("abcdefg", min), Err(PasswordRefused), "{min}");
            assert_eq!(check_length("abcdefgh", min), Ok(()), "{min}");
        }
        assert!(check_password(GOOD, &inputs(0)).is_ok());
        assert!(check_password("Tq7#Lm2", &inputs(0)).is_err());
        assert!(check_password(GOOD, &inputs(9)).is_err());
        assert!(check_password("Tq7#Lm2!x", &inputs(9)).is_ok());
    }

    /// [MS-SAMR] 3.1.1.7.2 item 3.2.1 with a configured minimum: counted in
    /// code points — twelve supplementary characters reach 12, eleven do
    /// not (although they are 22 UTF-16 units).
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

    // ---- rule 3: character classes (docs/56 §7 P-24; [MS-SAMR] 3.1.1.7.2 item 3.2.4)

    /// docs/56 §7 P-24: each of the four classes is required — removing any
    /// one refuses the password.
    #[test]
    fn every_character_class_is_required() {
        assert!(ok("Tq7#Lm2!"));
        assert!(!ok("tq7#lm2!"), "no upper-case letter");
        assert!(!ok("TQ7#LM2!"), "no lower-case letter");
        assert!(!ok("Tqx#Lmw!"), "no digit");
        assert!(!ok("Tq7xLm2w"), "no special character");
    }

    /// [MS-SAMR] 3.1.1.7.2 item 3.2.4 class 5: every character of the table
    /// is a special character; the table has 32 distinct printable ASCII
    /// characters, none a letter, digit or space.
    #[test]
    fn every_special_character_of_the_table_counts() {
        for special in SPECIAL_CHARACTERS {
            let password = format!("Tq7{special}Lm2w");
            assert!(ok(&password), "{special:?}");
        }
        for (i, c) in SPECIAL_CHARACTERS.iter().enumerate() {
            assert!(c.is_ascii_graphic() && !c.is_ascii_alphanumeric(), "{c:?}");
            assert!(!SPECIAL_CHARACTERS[..i].contains(c), "{c:?} twice");
        }
    }

    /// Q-910 item 3 (no Unicode source, P-76 — fail closed): a non-ASCII
    /// letter, digit or symbol, the space and a control character count for
    /// the length but satisfy no class.
    #[test]
    fn other_characters_satisfy_no_class() {
        // Upper-case: É (U+00C9) and Ω (U+03A9) are not ASCII.
        assert!(!ok("\u{C9}q7#lm2!"));
        assert!(!ok("\u{3A9}q7#lm2!"));
        // Lower-case: é.
        assert!(!ok("T\u{E9}7#LM2!"));
        // Digit: ٣ (U+0663 ARABIC-INDIC DIGIT THREE).
        assert!(!ok("Tq\u{663}#Lmw!"));
        // Special: the space, € (U+20AC), a Hebrew letter, TAB.
        assert!(!ok("Tq7 Lm2w"));
        assert!(!ok("Tq7\u{20AC}Lm2w"));
        assert!(!ok("Tq7\u{5D0}Lm2w"));
        assert!(!ok("Tq7\tLm2w"));
        // They do count for the length: seven ASCII characters of all four
        // classes plus one Hebrew letter reach 8.
        assert!(ok("Tq7#Lm2\u{5D0}"));
    }

    // ---- rule 4: sequences (docs/56 §7 P-24) ---------------------------

    /// docs/56 §7 P-24, the owner's examples: `Abc` and `123` are refused.
    #[test]
    fn the_owners_sequence_examples() {
        assert!(!ok("Abc#Tq7!"));
        assert!(!ok("Tq#123!x"));
    }

    /// PENDING-OWNER P-24 (ascending and descending, 3 or more; `abc`,
    /// `123`, `cba`), Q-910 item 4: letters case-insensitively, digits,
    /// both directions, anywhere in the password.
    #[test]
    fn ascending_and_descending_runs_are_refused() {
        for run in [
            "abc", "ABC", "aBc", "xyz", "cba", "CbA", "zyx", "012", "789", "987", "210", "mnop",
        ] {
            assert!(has_sequence(run), "{run}");
            let password = format!("Q7#{run}W!m");
            assert!(!ok(&password), "{run}");
        }
    }

    /// Q-910 item 4: two in a row are allowed; no wrap-around; a letter and
    /// a digit never form a run; a direction change is not a run.
    #[test]
    fn what_is_not_a_sequence() {
        for password in [
            "Ab#Tq7!x", // two letters in a row
            "Tq#12!xP", // two digits in a row
            "Yza#7!Tq", // y z a — no wrap-around
            "Tq#890!x", // 8 9 0 — no wrap-around
            "Tq#9a8!X", // digits around a letter
            "Tq#aba7!", // up then down
            "Tq#121!x", // up then down
            "Ace#7!Tq", // steps of two
        ] {
            assert!(!has_sequence(password), "{password}");
            assert!(ok(password), "{password}");
        }
    }

    // ---- rule 5: repeats (docs/56 §7 P-24) ------------------------------

    /// docs/56 §7 P-24, the owner's example: `111` is refused; so is any
    /// character three times in a row, letters case-insensitively.
    #[test]
    fn repeats_of_three_are_refused() {
        assert!(!ok("Tq#111!x"));
        for run in [
            "aaa",
            "AAA",
            "aAa",
            "!!!",
            "###",
            "\u{E9}\u{E9}\u{E9}",
            "\u{E9}\u{C9}\u{E9}",
        ] {
            assert!(has_repeat(run), "{run}");
            let password = format!("Q7#{run}W!m");
            assert!(!ok(&password), "{run}");
        }
    }

    /// Q-910 item 5: two in a row are allowed, and a repeat interrupted by
    /// another character is not a run.
    #[test]
    fn what_is_not_a_repeat() {
        for password in ["Tq#11!xP", "Tqq#7!Wm", "Tq#1x1!W"] {
            assert!(!has_repeat(password), "{password}");
            assert!(ok(password), "{password}");
        }
    }

    // ---- rule 6: the account name ([MS-SAMR] 3.1.1.7.2 items 3.2.2, 3.2.3)

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
        }
        assert!(!contains_account_name("caro-l-separated-1", "carol"));
        assert!(!contains_account_name("a-long-passphrase", "carol"));
        // Through the whole rule set (both cases).
        assert!(!ok("Tq7#carol!"));
        assert!(!ok("Tq7#CAROL!"));
        assert!(ok("Tq7#car!ol"));
    }

    /// [MS-SAMR] 3.1.1.7.2 item 3.2.2 ("more than two characters") and
    /// item 3.2.3 ("greater than two characters"): a name or portion of one
    /// or two characters is not checked.
    #[test]
    fn short_names_are_not_checked() {
        assert!(!contains_account_name("jo-jo-jo-jo-jo-jo", "jo"));
        assert!(!contains_account_name("xxxxxxxxxxxx", "x"));
        assert!(!contains_account_name("anything", ""));
        assert!(contains_account_name("xx-joe-xxxxxx", "joe"));
        // "jo.li": the whole name (5 characters) is checked, its two
        // portions are not.
        assert!(contains_account_name("xx-JO.LI-xx", "jo.li"));
        assert!(!contains_account_name("xx-jo-xx-li-xx", "jo.li"));
    }

    /// docs/56 §7 P-24 ("not even as a part"), with [MS-SAMR] 3.1.1.7.2
    /// item 3.2.3's delimiters and bound applied to the account name: a
    /// portion of more than two characters is refused on its own.
    #[test]
    fn a_portion_of_the_account_name() {
        for name in [
            "anna.berg",
            "anna-berg",
            "anna_berg",
            "anna berg",
            "anna,berg",
            "anna#berg",
            "anna\tberg",
        ] {
            assert!(contains_account_name("xx-BERG-xx", name), "{name:?}");
            assert!(contains_account_name("xx-Anna-xx", name), "{name:?}");
        }
        // "$" is not a delimiter of item 3.2.3.
        assert!(!contains_account_name("xx-anna-xx", "anna$berg"));
    }

    /// docs/47 §9.1 (a computer's sAMAccountName is `NAME$`): the name is
    /// found with or without its trailing `$` — never less than item
    /// 3.2.2's whole name.
    #[test]
    fn a_computers_name_with_and_without_its_dollar() {
        assert!(contains_account_name("prefix-WS9$-suffix", "ws9$"));
        assert!(contains_account_name("prefix-WS9-suffix", "ws9$"));
        // "ab$" (three characters) is checked whole; "ab" alone is not.
        assert!(contains_account_name("xx-AB$-xx", "ab$"));
        assert!(!contains_account_name("xx-ab-xx", "ab$"));
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

    /// keyd passes every component of the binding's name (Q-664 item 1):
    /// each one is checked.
    #[test]
    fn every_component_of_the_account_name() {
        let two = PolicyInputs {
            min_chars: 8,
            account_name: &["maple", "carol"],
            organisation_name: "EXAMPLE.ORG",
        };
        assert!(check_password("Tq7#Carol!", &two).is_err());
        assert!(check_password("Tq7#Maple!", &two).is_err());
        assert!(check_password(GOOD, &two).is_ok());
    }

    // ---- rule 7: the organisation name (docs/56 §7 P-24) ---------------

    /// docs/56 §7 P-24 (not the organisation's name, not even as a part):
    /// each label of the realm but the top-level one, of more than two
    /// characters, in any case (Q-910 item 6).
    #[test]
    fn the_organisation_name_in_any_case() {
        assert!(!ok("Tq7#Example!"));
        assert!(!ok("Tq7#EXAMPLE!"));
        assert!(!ok("Tq7#example.org!"));
        let corp = PolicyInputs {
            min_chars: 8,
            account_name: &["carol"],
            organisation_name: "CORP.EXAMPLE.CO.UK",
        };
        assert!(check_password("Tq7#Corp!w", &corp).is_err());
        assert!(check_password("Tq7#Example!", &corp).is_err());
        // "CO" has two characters: not checked (item 3.2.3's bound); "UK" is
        // the top-level label.
        assert!(check_password("Tq7#co!UKw", &corp).is_ok());
    }

    /// Main-session decision (Q-910 item 6): the top-level label is a public
    /// suffix, not the organisation's name — realm EXAMPLE.COM refuses
    /// "example" but accepts a password containing "com"; EXAMPLE.ORG
    /// likewise accepts "org".
    #[test]
    fn the_top_level_label_is_not_the_organisation_name() {
        let com = PolicyInputs {
            min_chars: 8,
            account_name: &["carol"],
            organisation_name: "EXAMPLE.COM",
        };
        assert!(check_password("Tq7#Example!", &com).is_err());
        assert!(check_password("Tq7#Comet!w", &com).is_ok());
        assert!(check_password("Tq7#xCOM!w", &com).is_ok());
        assert!(ok("Tq7#xORG!w"));
        assert!(ok("Tq7#Gorge!w"));
    }

    /// Q-910 item 6: which labels are the organisation's name — all but the
    /// last; a single-label realm is kept whole (fail closed).
    #[test]
    fn the_organisation_labels() {
        assert_eq!(organisation_labels("EXAMPLE.COM"), "EXAMPLE");
        assert_eq!(organisation_labels("CORP.EXAMPLE.ORG"), "CORP.EXAMPLE");
        assert_eq!(organisation_labels("CORPNET"), "CORPNET");
        let single = PolicyInputs {
            min_chars: 8,
            account_name: &["carol"],
            organisation_name: "CORPNET",
        };
        assert!(check_password("Tq7#Corpnet!", &single).is_err());
    }

    // ---- rule 8: weak words (docs/56 §7 P-24; Q-911) -------------------

    /// docs/56 §7 P-24, the owner's example: `admin` is refused, in any
    /// case and anywhere; so is every word of the list.
    #[test]
    fn the_weak_words_are_refused() {
        assert!(!ok("Tq7#admin!"));
        assert!(!ok("Tq7#ADMIN!"));
        assert!(!ok("Tq7#Administrator!"));
        for word in WEAK_WORDS {
            assert!(!ok(&format!("Tq7#{word}!")), "{word}");
            assert!(
                !ok(&format!("Tq7#{}!", word.to_ascii_uppercase())),
                "{word}"
            );
        }
        assert!(ok("Tq7#adm!in"));
    }

    /// The weak words are lower-case ASCII, so "in any case" means exactly
    /// the case mappings above; none is shorter than three characters.
    #[test]
    fn the_weak_word_list_shape() {
        for word in WEAK_WORDS {
            assert!(word.len() >= RUN_LENGTH_REFUSED, "{word}");
            assert!(word.bytes().all(|b| b.is_ascii_lowercase()), "{word}");
        }
    }

    // ---- the text-only part (Q-910 item 13) ------------------------------

    /// `check_password_text` is rules 1-5 and 8 of the same set: it refuses
    /// what those rules refuse, and passes what only a name rule refuses —
    /// which `check_password` then refuses.
    #[test]
    fn the_text_only_part_is_the_same_rules_without_the_names() {
        for refused in [
            "Tq7#Lm2",
            "tq7#lm2!x",
            "Tq7#Abc!w",
            "Tq7#111!w",
            "Tq7#Admin!",
        ] {
            assert_eq!(check_password_text(refused, 8), Err(PasswordRefused));
            assert!(!ok(refused), "{refused}");
        }
        for name_only in ["Tq7#Carol!", "Tq7#Example!"] {
            assert_eq!(check_password_text(name_only, 8), Ok(()));
            assert!(!ok(name_only), "{name_only}");
        }
        assert_eq!(check_password_text(GOOD, 8), Ok(()));
        assert_eq!(check_password_text(GOOD, 9), Err(PasswordRefused));
        assert_eq!(check_password_text("Tq7#Lm2", 0), Err(PasswordRefused));
    }

    // ---- the refusal ----------------------------------------------------

    /// docs/37 §2, A-121: one refusal, no detail — its `Debug` shows no
    /// part of the password.
    #[test]
    fn the_refusal_carries_nothing() {
        let refused = check_password("Tq7#admin!", &inputs(8)).unwrap_err();
        let shown = format!("{refused:?}");
        assert_eq!(shown, "PasswordRefused");
        assert!(!shown.contains("admin"));
    }
}
