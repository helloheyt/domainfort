//! The project's one KerberosTime ↔ seconds pair (crate `time` module):
//! [`kerberos_time_seconds`] — the scale — with its inverse
//! [`kerberos_time_from_seconds`], and [`kerberos_time_from_unix`] — a Unix
//! clock reading as a KerberosTime — with its inverse
//! [`kerberos_time_to_unix`]. Behaviour tests of the single definitions,
//! moved with them (docs/questions/Q-955 item 5, A-158; Q-987) from
//! crates/keyd-types `time.rs` (the scale's calendar differences and range)
//! and crates/kpasswd-front (`clock.rs` fixed points; the former
//! front-to-keyd pin is now the check that the two directions agree); the
//! Unix reading's fixed points come with the kdc's copy it replaced
//! (crates/kdc `time.rs` `unix_instant`, Q-995); the scale's inverse comes
//! with the kdc's and directory-pip's copies it replaced (`from_seconds`,
//! Q-1005) — their round trips, the kdc's "now + a lifetime" arithmetic and
//! the range's ends, widened here to every month of the whole range.
//!
//! Source: RFC 4120 5.2.3 ("UTC time", whole seconds, "shall specify the UTC
//! time zone (Z)"; the example `19851106210627Z`); the proleptic Gregorian
//! leap-year rule `KerberosTime::new` validates against. Every expected value
//! is derived by hand in its comment. No vector comes from any other
//! implementation.

use krb_proto::{
    kerberos_time_from_seconds, kerberos_time_from_unix, kerberos_time_seconds,
    kerberos_time_to_unix, KerberosTime,
};

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

/// RFC 4120 5.2.3; docs/11 §1, §10 P9 (the PDP's `Instant`, seconds since
/// 1970-01-01T00:00:00Z — crate pdp): the inverse's hand-derived fixed points — the epoch is 0, one day later 86,400; RFC
/// 4120's example instant 19851106210627Z is 5,788 days + 75,987 s (above);
/// 2026-11-13T10:00:00Z is 20,770 days + 36,000 s (56 years 1970 to 2025
/// with the 14 leap days of 1972 to 2024 = 20,454 days, plus the 304 days of
/// 2026 before November and 12 of November — the fixed point of
/// directory-daemon's former copy, Q-995); a KerberosTime before the epoch
/// has no Unix reading (`None`, the caller fails closed) — and it inverts
/// [`kerberos_time_from_unix`] on the whole range, the last second included.
#[test]
fn the_unix_reading_of_a_kerberos_time() {
    assert_eq!(kerberos_time_to_unix(&kt(1970, 1, 1, 0, 0, 0)), Some(0));
    assert_eq!(
        kerberos_time_to_unix(&kt(1970, 1, 2, 0, 0, 0)),
        Some(86_400)
    );
    assert_eq!(
        kerberos_time_to_unix(&kt(1985, 11, 6, 21, 6, 27)),
        Some(5_788 * 86_400 + 75_987)
    );
    assert_eq!(
        kerberos_time_to_unix(&kt(2026, 11, 13, 10, 0, 0)),
        Some(20_770 * 86_400 + 36_000)
    );
    assert_eq!(kerberos_time_to_unix(&kt(1969, 12, 31, 23, 59, 59)), None);
    assert_eq!(kerberos_time_to_unix(&kt(0, 1, 1, 0, 0, 0)), None);
    for time in [
        kt(1970, 1, 1, 0, 0, 0),
        kt(2000, 2, 29, 12, 34, 56),
        kt(2024, 12, 31, 23, 59, 59),
        kt(2100, 3, 1, 0, 0, 1),
        kt(9999, 12, 31, 23, 59, 59),
    ] {
        let unix = kerberos_time_to_unix(&time).unwrap();
        assert_eq!(kerberos_time_from_unix(unix), Some(time), "{time:?}");
    }
}

/// Seconds in a day (UTC, no leap second — RFC 4120 5.2.3; Q-030).
const DAY: i64 = 86_400;

/// 1970-01-01T00:00:00Z on the scale, by hand: 1970 × 365 = 719,050 days
/// plus the leap years in [0, 1970) — 493 multiples of 4 (0, 4, …, 1968)
/// minus 20 multiples of 100 (0, 100, …, 1900) plus 5 multiples of 400 (0,
/// 400, 800, 1200, 1600) = 478 — = 719,528 days.
const UNIX_EPOCH_ON_THE_SCALE: i64 = 719_528 * DAY;

/// 9999-12-31T23:59:59Z, the last instant a KerberosTime carries (four-digit
/// years, RFC 4120 5.2.3), on the scale, by hand: the 10,000 years 0 to 9999
/// are 3,650,000 days plus 2,500 − 100 + 25 = 2,425 leap days = 3,652,425
/// days; the last second is the one before their end.
const LAST_ON_THE_SCALE: i64 = 3_652_425 * DAY - 1;

/// The Gregorian rule as the calendar states it (and the comments of
/// `differences_follow_the_calendar` apply it): a leap year is divisible by
/// 4 and not by 100, or divisible by 400 — this test's own oracle for a
/// month's length, independent of the crate's.
fn days_in(year: u16, month: u8) -> u8 {
    let leap = (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400);
    match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// RFC 4120 5.2.3: hand-derived fixed points of the scale's inverse
/// [`kerberos_time_from_seconds`] — absolute counts, not only differences.
/// The origin 0 is 0000-01-01T00:00:00Z; year 0 is a leap year (divisible
/// by 400), so 366 days later is 0001-01-01 and the second before it
/// 0000-12-31T23:59:59Z; the Unix epoch and the last instant (the constants
/// above, which the scale agrees with); RFC 4120's own example instant
/// 19851106210627Z, 5,788 days + 75,987 s after the epoch (derived at
/// `unix_fixed_points_and_the_range`). And "now + a lifetime" (the kdc's
/// former `arithmetic` test, Q-1005): a day after 2026-12-31T12:00:00Z is in
/// 2027; an hour after 2028-02-28T23:00:00Z is the leap day 2028-02-29
/// (2028 is divisible by 4, not by 100).
#[test]
fn the_scales_inverse_fixed_points() {
    assert_eq!(kerberos_time_from_seconds(0), Some(kt(0, 1, 1, 0, 0, 0)));
    assert_eq!(
        kerberos_time_from_seconds(366 * DAY),
        Some(kt(1, 1, 1, 0, 0, 0))
    );
    assert_eq!(
        kerberos_time_from_seconds(366 * DAY - 1),
        Some(kt(0, 12, 31, 23, 59, 59))
    );
    assert_eq!(
        kerberos_time_from_seconds(UNIX_EPOCH_ON_THE_SCALE),
        Some(kt(1970, 1, 1, 0, 0, 0))
    );
    assert_eq!(
        kerberos_time_from_seconds(UNIX_EPOCH_ON_THE_SCALE + 5_788 * DAY + 75_987),
        Some(kt(1985, 11, 6, 21, 6, 27))
    );
    assert_eq!(
        kerberos_time_from_seconds(LAST_ON_THE_SCALE),
        Some(kt(9999, 12, 31, 23, 59, 59))
    );
    assert_eq!(secs(1970, 1, 1, 0, 0, 0), UNIX_EPOCH_ON_THE_SCALE);
    assert_eq!(secs(9999, 12, 31, 23, 59, 59), LAST_ON_THE_SCALE);
    assert_eq!(
        kerberos_time_from_seconds(secs(2026, 12, 31, 12, 0, 0) + DAY),
        Some(kt(2027, 1, 1, 12, 0, 0))
    );
    assert_eq!(
        kerberos_time_from_seconds(secs(2028, 2, 28, 23, 0, 0) + 3_600),
        Some(kt(2028, 2, 29, 0, 0, 0))
    );
}

/// RFC 4120 5.2.3 (every UTC calendar second of the years 0000-9999): the
/// inverse is exact on the whole range, both ways. For every month of every
/// year — its first second and the second before it, its last second (whose
/// day is the month's length by the Gregorian rule, this test's oracle) and
/// the second after it, and a second inside it — `seconds(from(s)) == s`
/// and `from(seconds(t)) == t`, and the month spans its length in days.
/// Then a stride of 7,919,993 s (about 91 days 15 h; coprime to 86,400 =
/// 2^7·3^3·5^2, so the sampled times of day vary) over the whole range; and
/// every day, at six times of day, of the leap years 0, 2000, 2024, 9996 and
/// the common years 1900, 2100 (centuries not divisible by 400) and 9999.
#[test]
fn the_scales_inverse_is_exact_over_the_whole_range() {
    let round_trip = |t: KerberosTime| {
        assert_eq!(
            kerberos_time_from_seconds(kerberos_time_seconds(&t)),
            Some(t),
            "{t:?}"
        );
    };
    let exact = |s: i64| -> KerberosTime {
        let t = kerberos_time_from_seconds(s).unwrap_or_else(|| panic!("{s}"));
        assert_eq!(kerberos_time_seconds(&t), s, "{t:?}");
        t
    };
    for year in 0..=9999u16 {
        for month in 1..=12u8 {
            let length = days_in(year, month);
            let first = kt(year, month, 1, 0, 0, 0);
            let last = kt(year, month, length, 23, 59, 59);
            round_trip(kt(year, month, length / 2, 12, 34, 56));
            let start = kerberos_time_seconds(&first);
            let end = kerberos_time_seconds(&last);
            assert_eq!(end - start, i64::from(length) * DAY - 1, "{first:?}");
            assert_eq!(exact(start), first);
            assert_eq!(exact(end), last);
            if start > 0 {
                let before = exact(start - 1);
                assert_eq!(
                    (before.hour(), before.minute(), before.second()),
                    (23, 59, 59),
                    "{before:?}"
                );
            }
            if end < LAST_ON_THE_SCALE {
                let after = exact(end + 1);
                assert_eq!(
                    (after.day(), after.hour(), after.minute(), after.second()),
                    (1, 0, 0, 0),
                    "{after:?}"
                );
            }
        }
    }
    let mut s = 0i64;
    while s <= LAST_ON_THE_SCALE {
        exact(s);
        s += 7_919_993;
    }
    let times_of_day = [
        (0, 0, 0),
        (0, 0, 1),
        (1, 1, 1),
        (12, 0, 0),
        (23, 59, 0),
        (23, 59, 59),
    ];
    for year in [0u16, 2000, 2024, 9996, 1900, 2100, 9999] {
        for month in 1..=12u8 {
            for day in 1..=days_in(year, month) {
                for (hour, minute, second) in times_of_day {
                    round_trip(kt(year, month, day, hour, minute, second));
                }
            }
        }
    }
}

/// RFC 4120 5.2.3: outside KerberosTime's range — before
/// 0000-01-01T00:00:00Z (a negative count) or after 9999-12-31T23:59:59Z —
/// there is no KerberosTime: `None`, never a panic, for any `i64`, the
/// extremes included; and across a window at each end exactly the counts
/// inside the range have a value.
#[test]
fn the_scales_inverse_refuses_outside_the_range() {
    for s in [
        -1,
        -DAY,
        i64::MIN,
        i64::MIN + 1,
        LAST_ON_THE_SCALE + 1,
        LAST_ON_THE_SCALE + DAY,
        LAST_ON_THE_SCALE + 366 * DAY,
        i64::MAX - 1,
        i64::MAX,
    ] {
        assert_eq!(kerberos_time_from_seconds(s), None, "{s}");
    }
    for offset in -2_000..=2_000i64 {
        assert_eq!(
            kerberos_time_from_seconds(offset).is_some(),
            offset >= 0,
            "{offset}"
        );
        let s = LAST_ON_THE_SCALE + offset;
        assert_eq!(
            kerberos_time_from_seconds(s).is_some(),
            s <= LAST_ON_THE_SCALE,
            "{s}"
        );
    }
}

/// The Unix conversion is the scale's inverse at the epoch's count plus the
/// reading (Q-1005: the calendar walked once, not twice) — the same value
/// for readings across a day's end, a leap day, 2100 and the range's end
/// (instants of `the_two_directions_agree`) — and `None` for a reading past
/// the range or beyond the scale's signed count.
#[test]
fn the_unix_conversion_is_the_scales_inverse_from_the_epoch() {
    let last = u64::try_from(LAST_ON_THE_SCALE - UNIX_EPOCH_ON_THE_SCALE).unwrap();
    for unix in [0u64, 86_399, 951_782_400, 4_107_542_400, last] {
        let on_the_scale = UNIX_EPOCH_ON_THE_SCALE + i64::try_from(unix).unwrap();
        let time = kerberos_time_from_unix(unix);
        assert!(time.is_some(), "{unix}");
        assert_eq!(time, kerberos_time_from_seconds(on_the_scale), "{unix}");
    }
    let beyond_the_scale = u64::try_from(i64::MAX).unwrap();
    assert_eq!(kerberos_time_from_unix(last + 1), None);
    assert_eq!(kerberos_time_from_unix(beyond_the_scale), None);
    assert_eq!(kerberos_time_from_unix(beyond_the_scale + 1), None);
}
