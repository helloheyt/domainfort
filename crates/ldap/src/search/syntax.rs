//! LDAP value representations and comparison rules of the phase-1 syntaxes.
//!
//! # Representations ([MS-ADTS] 3.1.1.2.2.2)
//!
//! [MS-ADTS] 3.1.1.2.2.2 adopts the representation of most syntaxes from
//! [RFC2252]; RFC 2252 is not an allowed source, and RFC 4517 — which
//! "Obsoletes: 2252" (its header) — is, so each RFC 2252 section is read
//! through its RFC 4517 successor (docs/questions/Q-200 item 2):
//!
//! | AD syntax | dirstore form (docs/46 §1) | LDAP value | Spec |
//! |---|---|---|---|
//! | Integer | Integer32: 4 octets, big-endian | signed decimal, e.g. `-2147483646` | [MS-ADTS] 3.1.1.2.2.2 (INTEGER, note \*); RFC 4517 §3.3.16; [MS-DRSR] 5.16.3.2 ("a string expressed in base-10 notation") |
//! | LargeInteger | Integer: 8 octets, big-endian | signed decimal | 3.1.1.2.2.2 note \*; RFC 4517 §3.3.16; [MS-DRSR] 5.16.3.3 |
//! | String(Generalized-Time) | DsTime: seconds since 1601 | `YYYYMMDDHHMMSS.0Z` (UTC, 1-second granularity) | 3.1.1.2.2.2 (Generalized Time, note †††††); RFC 4517 §3.3.13; [MS-DRSR] 5.16.3.9 (example `20060609211106.0Z`) |
//! | Boolean | 1 octet, 0 / 1 | `TRUE` / `FALSE` | 3.1.1.2.2.2 (Boolean); RFC 4517 §3.3.3; [MS-DRSR] 5.16.3.1 |
//! | String(Unicode) | UTF-8 | the UTF-8 octets as stored | 3.1.1.2.2.2 (Directory String); RFC 4517 §3.3.6; [MS-DRSR] 5.16.3.7 |
//! | String(Octet) | octets | the octets | 3.1.1.2.2.2 (Binary); RFC 4517 §3.3.25; [MS-DRSR] 5.16.3.5 |
//! | String(Sid) | SID packet | the binary SID, little-endian fields | [MS-ADTS] 3.1.1.2.2.2.7 |
//! | Object(DS-DN) | the target's GUID | the target's DN, RFC 4514 string | 3.1.1.2.2.2 (DN, note \*\*); RFC 4517 §3.3.9; RFC 4514 §2 |
//! | String(Object-Identifier) | (objectClass, derived) | the class's lDAPDisplayName | 3.1.1.2.2.2 note ††† rule 3 ("identifies an attribute or class … Descr format") |
//! | String(NT-Sec-Desc) | descriptor | never returned | R49-9 |
//!
//! # Comparison rules ([MS-ADTS] 3.1.1.2.2.4)
//!
//! Each syntax maps to a rule, and the rule says which filter choices it
//! supports (the three-part table of 3.1.1.2.2.4); a choice the rule does
//! not support is Undefined (RFC 4511 §4.5.1.7: "The attribute type does not
//! define the appropriate matching rule"). Integer: "A signed comparison"
//! (.2); Bool: "TRUE is considered to be greater than FALSE" (.1); Octet:
//! length and contents, ordered octet by octet, shorter first on a common
//! prefix, substrings over octets (.7); Sid: the binary SID by the Octet
//! rule (.11); DN: "equal when they name the same object" (.5); OID: "equal
//! when they are the same OID" (.10); Time: "T1 is greater than time T2 if
//! T1 denotes a time subsequent to T2" (.14). UnicodeString (.13) is defined
//! through [MS-UCODEREF], not an allowed source (P-9): the interim rule of
//! Q-080 / Q-168 item 7 applies — both values printable ASCII and compared
//! with A–Z folded, ordered and matched octet by octet as the NoCaseString
//! rule (.12, .8) describes; a value or assertion that is not printable
//! ASCII makes that comparison Undefined (never a guess at a Unicode rule).
//!
//! Spec: [MS-ADTS] v20261026 3.1.1.2.2.2, 3.1.1.2.2.2.7, 3.1.1.2.2.4,
//! 3.1.1.2.2.4.1, .2, .5, .7, .8, .10-.14; [MS-DRSR] v20260309 5.16.3.1-
//! 5.16.3.9, 5.51; RFC 4517 §3.3.3, §3.3.6, §3.3.9, §3.3.13, §3.3.16,
//! §3.3.25, §4.2.2, §4.2.6, §4.2.16, §4.2.17, §4.2.19, §4.2.20, §4.2.27,
//! §4.2.28; RFC 4512 §1.4; RFC 4511 §4.5.1.7; Q-080; Q-168 item 7.

use core::cmp::Ordering;

use krb_proto::KerberosTime;

/// The three values of a filter (RFC 4511 §4.5.1.7: "a filter is evaluated
/// to "TRUE", "FALSE", or "Undefined"").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Tri {
    True,
    False,
    Undefined,
}

impl Tri {
    /// A comparison that is known.
    pub(crate) fn of(b: bool) -> Tri {
        if b {
            Tri::True
        } else {
            Tri::False
        }
    }

    /// "A filter of the 'not' choice is TRUE if the filter being negated is
    /// FALSE, FALSE if it is TRUE, and Undefined if it is Undefined."
    /// Spec: RFC 4511 §4.5.1.7.
    pub(crate) fn not(self) -> Tri {
        match self {
            Tri::True => Tri::False,
            Tri::False => Tri::True,
            Tri::Undefined => Tri::Undefined,
        }
    }
}

/// The value of a filter item over an attribute's values: TRUE if some
/// value matches, FALSE if every value (possibly none) is known not to
/// match, Undefined otherwise — "when the server would not be able to
/// determine whether the assertion value matches" (RFC 4511 §4.5.1.7).
pub(crate) fn any<I: IntoIterator<Item = Tri>>(results: I) -> Tri {
    let mut undefined = false;
    for r in results {
        match r {
            Tri::True => return Tri::True,
            Tri::Undefined => undefined = true,
            Tri::False => {}
        }
    }
    if undefined {
        Tri::Undefined
    } else {
        Tri::False
    }
}

// ---- strings: the Q-080 interim rule -----------------------------------------

/// `true` for printable ASCII, `0x20..=0x7E`. Spec: Q-080 item 1.
fn printable(b: u8) -> bool {
    (0x20..=0x7E).contains(&b)
}

/// The comparison form of a String(Unicode) value or assertion under the
/// interim rule: printable ASCII with A–Z folded; `None` otherwise.
/// Spec: Q-080 items 1-2; Q-168 item 7; [MS-ADTS] 3.1.1.2.2.4.12 ("The "C"
/// locale ... is used for determining whether two characters differ by
/// case").
pub(crate) fn folded(value: &[u8]) -> Option<Vec<u8>> {
    value
        .iter()
        .all(|b| printable(*b))
        .then(|| value.iter().map(u8::to_ascii_lowercase).collect())
}

/// The substring rule: the `any` pieces match disjoint portions of `value`
/// in order, `initial` matches its beginning and `final` its end. The
/// earliest match of each piece leaves the most room for the rest, so a
/// left-to-right scan decides it.
/// Spec: RFC 4511 §4.5.1.7.2; RFC 4517 §4.2.6 ("the prepared substrings of
/// the assertion value match disjoint portions of the prepared attribute
/// value character string in the order of the substrings ... an <initial>
/// substring, if present, matches the beginning ... a <final> substring, if
/// present, matches the end"); [MS-ADTS] 3.1.1.2.2.4.7, .8.
pub(crate) fn substrings_match(
    value: &[u8],
    initial: Option<&[u8]>,
    anys: &[&[u8]],
    last: Option<&[u8]>,
) -> bool {
    let mut at = 0usize;
    if let Some(prefix) = initial {
        if !value.starts_with(prefix) {
            return false;
        }
        at = prefix.len();
    }
    for piece in anys {
        let Some(rest) = value.get(at..) else {
            return false;
        };
        match find(rest, piece) {
            Some(offset) => at = at.saturating_add(offset).saturating_add(piece.len()),
            None => return false,
        }
    }
    if let Some(suffix) = last {
        // Disjoint from what matched before: the suffix starts at or after
        // `at`.
        let Some(rest) = value.get(at..) else {
            return false;
        };
        if !rest.ends_with(suffix) {
            return false;
        }
    }
    true
}

/// The first offset of `needle` in `haystack` (an empty needle at 0).
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

// ---- Integer -----------------------------------------------------------------

/// Most digits of an Integer assertion value: 38 (every such number fits
/// an i128). A longer one is treated as invalid for this server (Undefined,
/// RFC 4511 §4.5.1.7) — project bound, docs/questions/Q-200 item 3.
const MAX_INTEGER_DIGITS: usize = 38;

/// `Integer = ( HYPHEN LDIGIT *DIGIT ) / number`, `number = DIGIT / ( LDIGIT
/// 1*DIGIT )` — no "+", no leading zero, no "-0". `None` if `value` is not
/// one (Undefined).
/// Spec: RFC 4517 §3.3.16; RFC 4512 §1.4.
pub(crate) fn parse_integer(value: &[u8]) -> Option<i128> {
    let (negative, digits) = match value {
        [b'-', rest @ ..] => (true, rest),
        _ => (false, value),
    };
    match digits {
        [] => return None,
        [b'0'] if !negative => return Some(0),
        [first, ..] if !(b'1'..=b'9').contains(first) => return None,
        _ => {}
    }
    if digits.len() > MAX_INTEGER_DIGITS || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let mut n: i128 = 0;
    for d in digits {
        n = n.checked_mul(10)?.checked_add(i128::from(d - b'0'))?;
    }
    Some(if negative { -n } else { n })
}

/// An Integer value as its decimal string. Spec: RFC 4517 §3.3.16 ("the
/// optionally signed decimal digit character string representation");
/// [MS-DRSR] 5.16.3.2, 5.16.3.3.
pub(crate) fn render_integer(n: i64) -> Vec<u8> {
    n.to_string().into_bytes()
}

// ---- Boolean -----------------------------------------------------------------

/// `Boolean = "TRUE" / "FALSE"`, exactly as written (no case folding —
/// stricter reading, docs/questions/Q-200 item 4). Spec: RFC 4517 §3.3.3.
pub(crate) fn parse_boolean(value: &[u8]) -> Option<bool> {
    match value {
        b"TRUE" => Some(true),
        b"FALSE" => Some(false),
        _ => None,
    }
}

/// A Boolean value. Spec: RFC 4517 §3.3.3; [MS-DRSR] 5.16.3.1.
pub(crate) fn render_boolean(b: bool) -> Vec<u8> {
    if b {
        b"TRUE".to_vec()
    } else {
        b"FALSE".to_vec()
    }
}

// ---- Generalized Time -------------------------------------------------------

/// A Generalized Time assertion as DSTIME: the whole seconds since
/// 1601-01-01T00:00:00Z at or before it, and whether it falls exactly on
/// that second (no fractional remainder). Stored values have 1-second
/// granularity ([MS-ADTS] 3.1.1.2.2.2 note †††††), so this is all a
/// comparison needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AssertedTime {
    pub(crate) seconds: i64,
    pub(crate) exact: bool,
}

/// Most fraction digits accepted: 18 (exact in u128 arithmetic). A longer
/// fraction is treated as invalid (Undefined) — project bound,
/// docs/questions/Q-200 item 3.
const MAX_FRACTION_DIGITS: usize = 18;

/// Two decimal digits at `at`, if both are digits.
fn two_digits(s: &[u8], at: usize) -> Option<u8> {
    let hi = *s.get(at)?;
    let lo = *s.get(at + 1)?;
    (hi.is_ascii_digit() && lo.is_ascii_digit()).then(|| (hi - b'0') * 10 + (lo - b'0'))
}

/// Parse a Generalized Time:
///
/// ```text
/// GeneralizedTime = century year month day hour
///                      [ minute [ second / leap-second ] ]
///                      [ fraction ]
///                      g-time-zone
/// ```
///
/// with "Z" for UTC or a differential subtracted from the local time; a
/// fraction is "a fraction of an hour" without minute, "of a minute" without
/// second, "of a second" otherwise. Dates that do not exist are invalid
/// ("SHOULD be considered invalid"; checked by `KerberosTime::new`, the
/// project's calendar). A leap second ("60") has no DSTIME (whole seconds
/// with no leap second, [MS-DRSR] 5.51) and is treated as invalid —
/// docs/questions/Q-200 item 3. `None` = invalid (Undefined).
/// Spec: RFC 4517 §3.3.13; RFC 4512 §1.4 (DOT, COMMA, PLUS); [MS-DRSR] 5.51.
pub(crate) fn parse_generalized_time(s: &[u8]) -> Option<AssertedTime> {
    let century = two_digits(s, 0)?;
    let year = u16::from(century) * 100 + u16::from(two_digits(s, 2)?);
    let month = two_digits(s, 4)?;
    let day = two_digits(s, 6)?;
    let hour = two_digits(s, 8)?;
    let mut at = 10;
    let minute = two_digits(s, at);
    if minute.is_some() {
        at += 2;
    }
    let second = if minute.is_some() {
        let second = two_digits(s, at);
        if second.is_some() {
            at += 2;
        }
        second
    } else {
        None
    };
    // The unit a fraction is a fraction of. Spec: RFC 4517 §3.3.13.
    let unit: u128 = match (minute, second) {
        (None, _) => 3_600,
        (Some(_), None) => 60,
        (Some(_), Some(_)) => 1,
    };
    let mut fraction: (u128, usize) = (0, 0);
    if matches!(s.get(at), Some(b'.') | Some(b',')) {
        at += 1;
        let start = at;
        while s.get(at).is_some_and(u8::is_ascii_digit) {
            at += 1;
        }
        let digits = s.get(start..at)?;
        if digits.is_empty() || digits.len() > MAX_FRACTION_DIGITS {
            return None;
        }
        let mut value: u128 = 0;
        for d in digits {
            value = value * 10 + u128::from(d - b'0');
        }
        fraction = (value, digits.len());
    }
    // g-time-zone = "Z" / ( MINUS / PLUS ) hour [ minute ].
    let differential: i64 = match s.get(at) {
        Some(b'Z') => {
            at += 1;
            0
        }
        Some(sign @ (b'+' | b'-')) => {
            let sign: i64 = if *sign == b'-' { -1 } else { 1 };
            let dh = two_digits(s, at + 1)?;
            at += 3;
            let dm = match two_digits(s, at) {
                Some(dm) => {
                    at += 2;
                    dm
                }
                None => 0,
            };
            if dh > 23 || dm > 59 {
                return None;
            }
            sign * (i64::from(dh) * 3_600 + i64::from(dm) * 60)
        }
        _ => return None,
    };
    if at != s.len() {
        return None;
    }
    let local = KerberosTime::new(
        year,
        month,
        day,
        hour,
        minute.unwrap_or(0),
        second.unwrap_or(0),
    )
    .ok()?;
    let whole = directory_pip::dstime_of(&local)?;
    // fraction × unit, split into whole seconds and a remainder.
    let (value, digits) = fraction;
    let scale = 10u128.checked_pow(u32::try_from(digits).ok()?)?;
    let scaled = value.checked_mul(unit)?;
    let extra = i64::try_from(scaled / scale).ok()?;
    let exact = scaled % scale == 0;
    // "coordinated universal time can be calculated by subtracting the
    // differential from the local time". Spec: RFC 4517 §3.3.13.
    let seconds = whole.checked_add(extra)?.checked_sub(differential)?;
    Some(AssertedTime { seconds, exact })
}

/// Compare a stored DSTIME (whole seconds) with an asserted time.
/// Spec: [MS-ADTS] 3.1.1.2.2.4.14; RFC 4517 §4.2.16, §4.2.17.
pub(crate) fn compare_time(stored: i64, asserted: AssertedTime) -> Ordering {
    match stored.cmp(&asserted.seconds) {
        Ordering::Equal if !asserted.exact => Ordering::Less,
        other => other,
    }
}

/// A DSTIME value as Generalized Time, `YYYYMMDDHHMMSS.0Z` — the form of
/// the [MS-DRSR] 5.16.3.9 example (`20060609211106.0Z`). `None` if it has no
/// four-digit year (after 9999) or is negative: such a value is not
/// returned.
/// Spec: RFC 4517 §3.3.13; [MS-DRSR] 5.16.3.9, 5.51; [MS-ADTS] 3.1.1.2.2.2
/// note ††††† (granularity of 1 second).
pub(crate) fn render_dstime(seconds: i64) -> Option<Vec<u8>> {
    let t = directory_pip::time_of_dstime(seconds)?;
    Some(
        format!(
            "{:04}{:02}{:02}{:02}{:02}{:02}.0Z",
            t.year(),
            t.month(),
            t.day(),
            t.hour(),
            t.minute(),
            t.second()
        )
        .into_bytes(),
    )
}

// ---- OID ---------------------------------------------------------------------

/// Whether `s` is an `oid`: a `descr` (`keystring = leadkeychar *keychar`)
/// or a `numericoid` (`number 1*( DOT number )`).
/// Spec: RFC 4512 §1.4 (`descr`, `keystring`, `numericoid`, `number`).
pub(crate) fn is_oid(s: &str) -> bool {
    let bytes = s.as_bytes();
    match bytes.first() {
        Some(b) if b.is_ascii_alphabetic() => bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-'),
        Some(b) if b.is_ascii_digit() => {
            let mut arcs = 0usize;
            for arc in s.split('.') {
                let ok = match arc.as_bytes() {
                    [] => false,
                    [d] => d.is_ascii_digit(),
                    [lead, rest @ ..] => {
                        (b'1'..=b'9').contains(lead) && rest.iter().all(u8::is_ascii_digit)
                    }
                };
                if !ok {
                    return false;
                }
                arcs += 1;
            }
            arcs >= 2
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4517 §3.3.16 / RFC 4512 §1.4: `number = DIGIT / ( LDIGIT 1*DIGIT )`.
    #[test]
    fn integers() {
        assert_eq!(parse_integer(b"0"), Some(0));
        assert_eq!(parse_integer(b"1321"), Some(1321));
        assert_eq!(parse_integer(b"-2147483646"), Some(-2_147_483_646));
        for bad in [
            &b""[..],
            b"-",
            b"-0",
            b"00",
            b"01",
            b"+5",
            b"1 ",
            b"1a",
            b"--1",
        ] {
            assert_eq!(parse_integer(bad), None, "{bad:?}");
        }
        assert_eq!(render_integer(-2_147_483_646), b"-2147483646");
        assert_eq!(render_integer(12605), b"12605");
    }

    /// RFC 4517 §3.3.13 examples: "199412161032Z" and "199412160532-0500"
    /// "represent the same coordinated universal time: 10:32 AM, December
    /// 16, 1994".
    #[test]
    fn generalized_time_examples_of_rfc_4517() {
        let a = parse_generalized_time(b"199412161032Z").unwrap();
        let b = parse_generalized_time(b"199412160532-0500").unwrap();
        assert_eq!(a, b);
        assert!(a.exact);
    }

    /// [MS-DRSR] 5.16.3.9: "LDAP value: 20060609211106.0Z ... corresponds
    /// to DSTIME value: 0x2fa9a74ea".
    #[test]
    fn generalized_time_example_of_ms_drsr() {
        let t = parse_generalized_time(b"20060609211106.0Z").unwrap();
        assert_eq!(t.seconds, 0x2_fa9a_74ea);
        assert!(t.exact);
        assert_eq!(
            render_dstime(0x2_fa9a_74ea).unwrap(),
            b"20060609211106.0Z".to_vec()
        );
    }

    /// RFC 4517 §3.3.13: a fraction of an hour / minute / second; invalid
    /// dates and forms are refused.
    #[test]
    fn generalized_time_fractions_and_refusals() {
        let base = parse_generalized_time(b"2006060921Z").unwrap();
        let half_hour = parse_generalized_time(b"2006060921.5Z").unwrap();
        assert_eq!(half_hour.seconds, base.seconds + 1_800);
        assert!(half_hour.exact);
        let third = parse_generalized_time(b"200606092111,1Z").unwrap();
        assert_eq!(third.seconds, base.seconds + 11 * 60 + 6);
        assert!(third.exact);
        let sub = parse_generalized_time(b"20060609211106.25Z").unwrap();
        assert_eq!(sub.seconds, base.seconds + 11 * 60 + 6);
        assert!(!sub.exact);
        for bad in [
            &b"20060609211106"[..],
            b"20060231000000Z",
            b"20061301000000Z",
            b"20060609241106Z",
            b"20060609211160Z",
            b"20060609211106.Z",
            b"20060609211106Z0",
            b"2006060921110Z",
            b"20060609211106+2400",
            b"20060609211106+0060",
        ] {
            assert_eq!(parse_generalized_time(bad), None, "{bad:?}");
        }
    }

    /// RFC 4517 §4.2.17 / [MS-ADTS] 3.1.1.2.2.4.14: a stored whole second is
    /// before an assertion a fraction of a second later.
    #[test]
    fn time_ordering() {
        let t = AssertedTime {
            seconds: 100,
            exact: false,
        };
        assert_eq!(compare_time(100, t), Ordering::Less);
        assert_eq!(compare_time(101, t), Ordering::Greater);
        let e = AssertedTime {
            seconds: 100,
            exact: true,
        };
        assert_eq!(compare_time(100, e), Ordering::Equal);
    }

    /// RFC 4517 §4.2.6: disjoint, ordered, anchored pieces.
    #[test]
    fn substrings() {
        let v = b"abcabc";
        assert!(substrings_match(v, Some(b"ab"), &[b"ca"], Some(b"bc")));
        assert!(!substrings_match(v, Some(b"abc"), &[b"abc"], Some(b"c")));
        assert!(substrings_match(v, None, &[b"b", b"b"], None));
        assert!(!substrings_match(v, None, &[b"b", b"b", b"b"], None));
        assert!(!substrings_match(b"ab", Some(b"ab"), &[], Some(b"b")));
        assert!(substrings_match(b"ab", Some(b"a"), &[], Some(b"b")));
    }

    /// RFC 4512 §1.4: descr / numericoid.
    #[test]
    fn oids() {
        for ok in ["user", "organizationalUnit", "a-1", "2.5.6.5", "0.9"] {
            assert!(is_oid(ok), "{ok}");
        }
        for bad in ["", "1", "1.", "01.2", "-a", "a b", "a_b", "1.2.03"] {
            assert!(!is_oid(bad), "{bad}");
        }
    }
}
