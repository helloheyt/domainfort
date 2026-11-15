//! The project's one KerberosTime ↔ seconds pair (crate `time` module):
//! [`kerberos_time_seconds`] — the scale — and [`kerberos_time_from_unix`] —
//! a Unix clock reading as a KerberosTime. Behaviour tests of the single
//! definitions, moved with them (docs/questions/Q-955 item 5, A-158; Q-987)
//! from crates/keyd-types `time.rs` (the scale's calendar differences and
//! range) and crates/kpasswd-front (`clock.rs` fixed points; the former
//! front-to-keyd pin is now the check that the two directions agree).
//!
//! Source: RFC 4120 5.2.3 ("UTC time", whole seconds, "shall specify the UTC
//! time zone (Z)"; the example `19851106210627Z`); the proleptic Gregorian
//! leap-year rule `KerberosTime::new` validates against. Every expected value
//! is derived by hand in its comment. No vector comes from any other
//! implementation.

use krb_proto::{kerberos_time_from_unix, kerberos_time_seconds, KerberosTime};

fn kt(y: u16, mo: u8, d: u8, h: u8, mi: u8, s: u8) -> KerberosTime {
    KerberosTime::new(y, mo, d, h, mi, s).unwrap()
}

fn secs(y: u16, mo: u8, d: u8, h: u8, mi: u8, s: u8) -> i64 {
    kerberos_time_seconds(&kt(y, mo, d, h, mi, s))
}

/// RFC 4120 5.2.3 (UTC calendar time): differences on the scale follow the
/// Gregorian calendar.
#[test]
fn differences_follow_the_calendar() {
    // One day.
    assert_eq!(
        secs(1970, 1, 2, 0, 0, 0) - secs(1970, 1, 1, 0, 0, 0),
        86_400
    );
    // 2024 is a leap year: Feb 28 -> Mar 1 is two days.
    assert_eq!(
        secs(2024, 3, 1, 0, 0, 0) - secs(2024, 2, 28, 0, 0, 0),
        2 * 86_400
    );
    // 2023 is not: one day.
    assert_eq!(
        secs(2023, 3, 1, 0, 0, 0) - secs(2023, 2, 28, 0, 0, 0),
        86_400
    );
    // 1900 is not a leap year (century not divisible by 400).
    assert_eq!(
        secs(1900, 3, 1, 0, 0, 0) - secs(1900, 2, 28, 0, 0, 0),
        86_400
    );
    // 2000 is (divisible by 400).
    assert_eq!(
        secs(2000, 3, 1, 0, 0, 0) - secs(2000, 2, 28, 0, 0, 0),
        2 * 86_400
    );
    // 1970-01-01 -> 2000-01-01: 30 years x 365 = 10950 days, plus the leap
    // days of 1972, 76, 80, 84, 88, 92, 96 = 7 -> 10957 days.
    assert_eq!(
        secs(2000, 1, 1, 0, 0, 0) - secs(1970, 1, 1, 0, 0, 0),
        10_957 * 86_400
    );
    // Year boundary and time-of-day fields.
    assert_eq!(
        secs(2027, 1, 1, 0, 0, 0) - secs(2026, 12, 31, 23, 59, 59),
        1
    );
    assert_eq!(
        secs(2026, 11, 13, 10, 5, 7) - secs(2026, 11, 13, 9, 4, 6),
        3_661
    );
}

/// RFC 4120 5.2.3 (four-digit years): the extremes of the KerberosTime range
/// do not overflow the scale.
#[test]
fn the_scale_covers_the_whole_range() {
    assert_eq!(secs(0, 1, 1, 0, 0, 0), 0);
    // Year 0 is a leap year (divisible by 400): 366 days.
    assert_eq!(secs(1, 1, 1, 0, 0, 0), 366 * 86_400);
    assert!(secs(9999, 12, 31, 23, 59, 59) > 0);
}

/// RFC 4120 5.2.3: hand-derived fixed points of the Unix conversion — the
/// epoch; 1970-01-01 -> 2000-01-01 is 10,957 days (above); 2000 is a leap
/// year, so 2000-02-29 exists and is day 59 of that year (31 + 28 days
/// before it); RFC 4120's own example instant 19851106210627Z (1985-11-06:
/// 15 years after 1970 with the leap days of 1972, 76, 80, 84 = 5,479 days,
/// plus 304 days of 1985 before November and 5 of November = 5,788 days;
/// 21:06:27 = 75,987 s); the last instant a KerberosTime carries, and
/// nothing after it.
#[test]
fn unix_fixed_points_and_the_range() {
    assert_eq!(kerberos_time_from_unix(0), Some(kt(1970, 1, 1, 0, 0, 0)));
    assert_eq!(
        kerberos_time_from_unix(10_957 * 86_400 + 3_661),
        Some(kt(2000, 1, 1, 1, 1, 1))
    );
    assert_eq!(
        kerberos_time_from_unix((10_957 + 59) * 86_400),
        Some(kt(2000, 2, 29, 0, 0, 0))
    );
    assert_eq!(
        kerberos_time_from_unix((10_957 + 60) * 86_400 - 1),
        Some(kt(2000, 2, 29, 23, 59, 59))
    );
    let example = 5_788 * 86_400 + 75_987;
    assert_eq!(
        kerberos_time_from_unix(example),
        Some(kt(1985, 11, 6, 21, 6, 27))
    );
    let last = u64::try_from(secs(9999, 12, 31, 23, 59, 59) - secs(1970, 1, 1, 0, 0, 0)).unwrap();
    assert_eq!(
        kerberos_time_from_unix(last),
        Some(kt(9999, 12, 31, 23, 59, 59))
    );
    assert_eq!(kerberos_time_from_unix(last + 1), None);
    assert_eq!(kerberos_time_from_unix(u64::MAX), None);
}

/// The two directions of the one pair agree: for instants across a day's
/// edges, leap days, century years (2100 is not a leap year: 2100-03-01
/// follows 2100-02-28) and the range's end, the Unix seconds converted to a
/// KerberosTime lie exactly that many seconds after 1970-01-01T00:00:00Z on
/// the scale (RFC 4120 5.2.3: whole UTC seconds, no leap second).
#[test]
fn the_two_directions_agree() {
    let epoch = secs(1970, 1, 1, 0, 0, 0);
    let last = u64::try_from(secs(9999, 12, 31, 23, 59, 59) - epoch).unwrap();
    for unix in [
        0u64,
        59,
        86_399,
        86_400,
        951_782_400,   // 2000-02-29T00:00:00Z: (10,957 + 59) days
        951_868_799,   // 2000-02-29T23:59:59Z
        4_107_456_000, // 2100-02-28T00:00:00Z: 47,540 days
        4_107_542_400, // 2100-03-01T00:00:00Z: one day later
        1_794_744_000,
        last,
    ] {
        let time = kerberos_time_from_unix(unix).unwrap();
        assert_eq!(
            kerberos_time_seconds(&time) - epoch,
            i64::try_from(unix).unwrap(),
            "{unix}"
        );
    }
    assert_eq!(
        kerberos_time_from_unix(4_107_456_000),
        Some(kt(2100, 2, 28, 0, 0, 0))
    );
    assert_eq!(
        kerberos_time_from_unix(4_107_542_400),
        Some(kt(2100, 3, 1, 0, 0, 0))
    );
}
