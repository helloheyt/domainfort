//! `Time` (RFC 5280 §4.1.2.5): UTCTime or GeneralizedTime, in the exact
//! profile forms, converted to seconds since 1970-01-01T00:00:00Z.
//!
//! # Forms accepted (and nothing else)
//!
//! | type | form | source |
//! |---|---|---|
//! | UTCTime (UNIVERSAL 23) | `YYMMDDHHMMSSZ`, 13 octets; YY ≥ 50 ⇒ 19YY, YY < 50 ⇒ 20YY | RFC 5280 4.1.2.5.1 ("MUST be expressed in Greenwich Mean Time (Zulu) and MUST include seconds"); X.690 11.8.1, 11.8.2 |
//! | GeneralizedTime (UNIVERSAL 24) | `YYYYMMDDHHMMSSZ`, 15 octets, no fraction, year ≥ 2050 | RFC 5280 4.1.2.5.2 ("MUST NOT include fractional seconds"), 4.1.2.5 ("dates through the year 2049 as UTCTime; … 2050 or later MUST be encoded as GeneralizedTime"); X.690 11.7 |
//!
//! Fields: month 01-12, day 01 to the month's last day, hour 00-23, minute
//! and second 00-59 (X.680 47.3 for UTCTime's ranges; X.690 11.7.5 / 11.8.3:
//! midnight is `000000` of the following day, so hour 24 never appears; no
//! leap second). The calendar is the Gregorian one (X.680 46.3 refers to
//! ISO 8601's calendar date; the leap-year rule is the one this project
//! already uses in crates/keyd-types `time.rs`: divisible by 4, except
//! century years not divisible by 400).
//!
//! The pre-2050 GeneralizedTime refusal is a strict reading of a rule
//! RFC 5280 states for CAs ("MUST always encode"): a certificate that breaks
//! it is not one a conforming CA produced (docs/questions/Q-320).
//!
//! Spec: RFC 5280 4.1.2.5, 4.1.2.5.1, 4.1.2.5.2; X.690 11.7, 11.8;
//! X.680 46, 47.

/// Seconds in a day (no leap seconds: the fields above admit second 59 at
/// most). Spec: X.680 47.3 ("ss is seconds (00 to 59)").
const SECONDS_PER_DAY: i64 = 86_400;

/// The first year RFC 5280 requires GeneralizedTime for.
/// Spec: RFC 5280 4.1.2.5.
const FIRST_GENERALIZED_TIME_YEAR: i64 = 2050;

/// The epoch year of [`Time::unix_seconds`]: 1970-01-01T00:00:00Z.
const EPOCH_YEAR: i64 = 1970;

/// A validity instant, in seconds since 1970-01-01T00:00:00Z (negative
/// before it; UTCTime reaches back to 1950).
/// Spec: RFC 5280 4.1.2.5.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Time {
    seconds: i64,
}

impl Time {
    /// Seconds since 1970-01-01T00:00:00Z.
    #[must_use]
    pub fn unix_seconds(&self) -> i64 {
        self.seconds
    }

    /// A UTCTime's contents octets in the RFC 5280 form `YYMMDDHHMMSSZ`.
    /// `None` for any other form or a non-existent calendar instant.
    /// Spec: RFC 5280 4.1.2.5.1; X.690 11.8.1, 11.8.2; X.680 47.3.
    #[must_use]
    pub fn from_utc_time(contents: &[u8]) -> Option<Time> {
        // 12 digits then "Z". Spec: RFC 5280 4.1.2.5.1 ("YYMMDDHHMMSSZ").
        let (digits, zulu) = contents.split_at_checked(12)?;
        if zulu != b"Z" {
            return None;
        }
        let yy = i64::from(two_digits(digits, 0)?);
        // Spec: RFC 5280 4.1.2.5.1 ("Where YY is greater than or equal to
        // 50, the year SHALL be interpreted as 19YY; … less than 50 … 20YY").
        let year = if yy >= 50 { 1900 + yy } else { 2000 + yy };
        Time::from_fields(year, &digits[2..])
    }

    /// A GeneralizedTime's contents octets in the RFC 5280 form
    /// `YYYYMMDDHHMMSSZ`, for a year from 2050 on. `None` for any other form
    /// or a non-existent calendar instant.
    /// Spec: RFC 5280 4.1.2.5, 4.1.2.5.2; X.690 11.7.
    #[must_use]
    pub fn from_generalized_time(contents: &[u8]) -> Option<Time> {
        // 14 digits then "Z", no fraction. Spec: RFC 5280 4.1.2.5.2.
        let (digits, zulu) = contents.split_at_checked(14)?;
        if zulu != b"Z" {
            return None;
        }
        let year = i64::from(two_digits(digits, 0)?) * 100 + i64::from(two_digits(digits, 2)?);
        if year < FIRST_GENERALIZED_TIME_YEAR {
            return None;
        }
        Time::from_fields(year, &digits[4..])
    }

    /// `MMDDHHMMSS` (exactly 10 digits) of `year`, range-checked, as seconds
    /// since the epoch. Spec: X.680 47.3; X.690 11.7.5, 11.8.3.
    fn from_fields(year: i64, rest: &[u8]) -> Option<Time> {
        if rest.len() != 10 {
            return None;
        }
        let month = two_digits(rest, 0)?;
        let day = two_digits(rest, 2)?;
        let hour = two_digits(rest, 4)?;
        let minute = two_digits(rest, 6)?;
        let second = two_digits(rest, 8)?;
        if !(1..=12).contains(&month)
            || day < 1
            || day > days_in_month(year, month)
            || hour > 23
            || minute > 59
            || second > 59
        {
            return None;
        }
        let days = days_before_year(year)? + days_before_month(year, month) + i64::from(day - 1);
        let seconds = days * SECONDS_PER_DAY
            + i64::from(hour) * 3_600
            + i64::from(minute) * 60
            + i64::from(second);
        Some(Time { seconds })
    }
}

/// Two ASCII digits at `at` as a number; `None` for anything else.
fn two_digits(text: &[u8], at: usize) -> Option<u32> {
    let pair = text.get(at..at.checked_add(2)?)?;
    let mut value = 0u32;
    for &octet in pair {
        if !octet.is_ascii_digit() {
            return None;
        }
        value = value * 10 + u32::from(octet - b'0');
    }
    Some(value)
}

/// The Gregorian leap-year rule (module documentation).
fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

/// Days in `month` (1-12) of `year`; 0 outside 1-12.
fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

/// Days from 1970-01-01 to 1 January of `year` (negative before 1970).
/// Counted year by year: the year range here is 1950-9999, so the loop is
/// bounded by 8 030 steps. `None` outside that range (unreachable for the
/// forms above, kept as a guard).
fn days_before_year(year: i64) -> Option<i64> {
    if !(1950..=9999).contains(&year) {
        return None;
    }
    let year_length = |y: i64| if is_leap_year(y) { 366 } else { 365 };
    let days = if year >= EPOCH_YEAR {
        (EPOCH_YEAR..year).map(year_length).sum()
    } else {
        -(year..EPOCH_YEAR).map(year_length).sum::<i64>()
    };
    Some(days)
}

/// Days from 1 January to the first day of `month` in `year`.
fn days_before_month(year: i64, month: u32) -> i64 {
    (1..month).map(|m| i64::from(days_in_month(year, m))).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utc(text: &str) -> Option<i64> {
        Time::from_utc_time(text.as_bytes()).map(|t| t.unix_seconds())
    }

    fn generalized(text: &str) -> Option<i64> {
        Time::from_generalized_time(text.as_bytes()).map(|t| t.unix_seconds())
    }

    /// Hand-derived values (each derivation in the comment).
    #[test]
    fn instants_follow_the_calendar() {
        // The epoch itself.
        assert_eq!(utc("700101000000Z"), Some(0));
        // 1970-01-02T00:00:01Z: one day and one second.
        assert_eq!(utc("700102000001Z"), Some(86_401));
        // 1969-12-31T23:59:59Z: one second before the epoch.
        assert_eq!(utc("691231235959Z"), Some(-1));
        // 2000-01-01: 30 years × 365 = 10 950 days plus the leap days of
        // 1972, 76, 80, 84, 88, 92, 96 = 7 → 10 957 days × 86 400.
        assert_eq!(utc("000101000000Z"), Some(946_684_800));
        // 2025-01-01: 55 × 365 = 20 075 days plus 14 leap days (1972 …
        // 2024, every fourth year; 2000 is a leap year) → 20 089 days.
        assert_eq!(utc("250101000000Z"), Some(1_735_689_600));
        // 2024-02-29 exists (2024 divisible by 4): 2024-01-01 is 19 723
        // days (54 × 365 = 19 710 plus 13 leap days 1972 … 2020), plus 31
        // (January) plus 28 → day 19 782.
        assert_eq!(utc("240229000000Z"), Some(19_782 * 86_400));
        // 2050-01-01 as GeneralizedTime: 80 × 365 = 29 200 days plus the
        // 20 leap days 1972 … 2048 → 29 220 days.
        assert_eq!(generalized("20500101000000Z"), Some(29_220 * 86_400));
        // The RFC 5280 4.1.2.5 "no well-defined expiration date" value is
        // representable (and is the largest instant).
        assert!(generalized("99991231235959Z").is_some());
        // YY 49 is 2049, YY 50 is 1950 (RFC 5280 4.1.2.5.1).
        assert!(utc("491231235959Z").unwrap() > utc("500101000000Z").unwrap());
    }

    /// RFC 5280 4.1.2.5.1 / 4.1.2.5.2; X.690 11.7, 11.8; X.680 47.3: every
    /// other form is refused.
    #[test]
    fn other_forms_are_refused() {
        // Seconds missing (X.690 11.8.5 invalid example "9207221321Z").
        assert_eq!(utc("9207221321Z"), None);
        // Midnight as 24 (X.690 11.8.5 invalid example "920520240000Z").
        assert_eq!(utc("920520240000Z"), None);
        // A time differential instead of Z.
        assert_eq!(utc("920520120000+0100"), None);
        // No Z, extra octet, non-digits.
        assert_eq!(utc("920520120000"), None);
        assert_eq!(utc("920520120000ZZ"), None);
        assert_eq!(utc("92O520120000Z"), None);
        // Month 13, day 32, 29 February of a non-leap year (2023), minute
        // and second 60, day 00.
        assert_eq!(utc("251301000000Z"), None);
        assert_eq!(utc("250132000000Z"), None);
        assert_eq!(utc("230229000000Z"), None);
        assert_eq!(utc("250101006000Z"), None);
        assert_eq!(utc("250101000060Z"), None);
        assert_eq!(utc("250100000000Z"), None);
        // GeneralizedTime: a fraction (RFC 5280 4.1.2.5.2), a year before
        // 2050 (4.1.2.5), seconds missing, a differential.
        assert_eq!(generalized("20500101000000.5Z"), None);
        assert_eq!(generalized("20491231235959Z"), None);
        assert_eq!(generalized("205001010000Z"), None);
        assert_eq!(generalized("20500101000000+0000"), None);
        // 2100 is not a leap year (century not divisible by 400); 2400 is.
        assert_eq!(generalized("21000229000000Z"), None);
        assert!(generalized("24000229000000Z").is_some());
    }
}
