//! Time arithmetic on caller-supplied KerberosTime values.
//!
//! keyd never reads a clock: every operation takes `now` from the caller, so
//! behaviour is deterministic and testable. Residual: keyd therefore trusts
//! the caller's clock; the integrity of the system time source is the
//! platform's (RFC 4120 §1.6 / §10: clock synchronization "MUST itself be
//! secured").
//!
//! Comparisons (clock skew, lifetimes, token expiry) need differences in
//! seconds, so a KerberosTime is mapped to a count of seconds since
//! 0000-01-01T00:00:00Z on the proleptic Gregorian calendar — the same
//! calendar `krb_proto::KerberosTime::new` validates against. Only
//! differences of these counts are meaningful.
//!
//! Spec: RFC 4120 5.2.3 (KerberosTime is UTC, whole seconds), §1.6, §10.

use krb_proto::KerberosTime;

/// Seconds in a day (UTC, no leap seconds — RFC 4120 5.2.3 KerberosTime has
/// none; krb-proto rejects second 60, docs/questions/Q-030).
const SECONDS_PER_DAY: i64 = 86_400;

/// Gregorian leap-year rule: divisible by 4, except century years not
/// divisible by 400.
fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

/// Days in `month` (1-12) of `year`; 0 outside 1-12 (unreachable for a
/// validated KerberosTime).
fn days_in_month(year: i64, month: u8) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

/// Seconds since 0000-01-01T00:00:00Z (proleptic Gregorian) of a validated
/// KerberosTime. Total for every value krb-proto accepts (years 0000-9999),
/// with no overflow: the result is below 2^39.
///
/// Days before year `y` = 365·y plus the leap years in [0, y): multiples of 4
/// ((y+3)/4) minus multiples of 100 ((y+99)/100) plus multiples of 400
/// ((y+399)/400) — year 0 itself is a leap year under the rule above.
///
/// Spec: RFC 4120 5.2.3.
pub fn kerberos_time_seconds(t: &KerberosTime) -> i64 {
    let y = i64::from(t.year());
    let leap_years_before = (y + 3) / 4 - (y + 99) / 100 + (y + 399) / 400;
    let mut days = 365 * y + leap_years_before;
    let mut month = 1u8;
    while month < t.month() {
        days += days_in_month(y, month);
        month += 1;
    }
    days += i64::from(t.day()) - 1;
    days * SECONDS_PER_DAY
        + i64::from(t.hour()) * 3_600
        + i64::from(t.minute()) * 60
        + i64::from(t.second())
}

/// `true` if `a` and `b` differ by at most `skew_secs` seconds.
/// Spec: RFC 4120 3.2.3 ("differ by more than the allowable clock skew").
pub(crate) fn within_skew(a: i64, b: i64, skew_secs: u32) -> bool {
    (a - b).abs() <= i64::from(skew_secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(y: u16, mo: u8, d: u8, h: u8, mi: u8, s: u8) -> i64 {
        kerberos_time_seconds(&KerberosTime::new(y, mo, d, h, mi, s).unwrap())
    }

    /// Differences follow the Gregorian calendar (RFC 4120 5.2.3: UTC).
    /// Expected values are derived by hand in the comments.
    #[test]
    fn differences_follow_the_calendar() {
        // One day.
        assert_eq!(t(1970, 1, 2, 0, 0, 0) - t(1970, 1, 1, 0, 0, 0), 86_400);
        // 2024 is a leap year: Feb 28 -> Mar 1 is two days.
        assert_eq!(t(2024, 3, 1, 0, 0, 0) - t(2024, 2, 28, 0, 0, 0), 2 * 86_400);
        // 2023 is not: one day.
        assert_eq!(t(2023, 3, 1, 0, 0, 0) - t(2023, 2, 28, 0, 0, 0), 86_400);
        // 1900 is not a leap year (century not divisible by 400).
        assert_eq!(t(1900, 3, 1, 0, 0, 0) - t(1900, 2, 28, 0, 0, 0), 86_400);
        // 2000 is (divisible by 400).
        assert_eq!(t(2000, 3, 1, 0, 0, 0) - t(2000, 2, 28, 0, 0, 0), 2 * 86_400);
        // 1970-01-01 -> 2000-01-01: 30 years x 365 = 10950 days, plus the
        // leap days of 1972, 76, 80, 84, 88, 92, 96 = 7 -> 10957 days.
        assert_eq!(
            t(2000, 1, 1, 0, 0, 0) - t(1970, 1, 1, 0, 0, 0),
            10_957 * 86_400
        );
        // Year boundary and time-of-day fields.
        assert_eq!(t(2027, 1, 1, 0, 0, 0) - t(2026, 12, 31, 23, 59, 59), 1);
        assert_eq!(t(2026, 11, 13, 10, 5, 7) - t(2026, 11, 13, 9, 4, 6), 3_661);
    }

    /// Extremes of the KerberosTime range do not overflow.
    #[test]
    fn range_extremes() {
        assert_eq!(t(0, 1, 1, 0, 0, 0), 0);
        // Year 0 is a leap year: 366 days.
        assert_eq!(t(1, 1, 1, 0, 0, 0), 366 * 86_400);
        assert!(t(9999, 12, 31, 23, 59, 59) > 0);
    }

    #[test]
    fn skew_window_is_inclusive() {
        assert!(within_skew(100, 400, 300));
        assert!(within_skew(400, 100, 300));
        assert!(!within_skew(100, 401, 300));
    }
}
