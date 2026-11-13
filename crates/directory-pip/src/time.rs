//! Directory time values as KerberosTime.
//!
//! - FILETIME (accountExpires, pwdLastSet): "the number of 100-nanosecond
//!   intervals that have elapsed since January 1, 1601, Coordinated
//!   Universal Time (UTC)" ([MS-DTYP] 2.3.3).
//! - DSTIME (whenCreated): "the number of seconds since January 1, 1601,
//!   12:00:00 A.M." ([MS-DRSR] 5.51); dirstore holds it as a non-negative
//!   8-byte value (docs/46 §8.1).
//! - KerberosTime: UTC, whole seconds (RFC 4120 5.2.3).
//!
//! The 1601 epoch is not a copied constant: it is the KerberosTime
//! 1601-01-01T00:00:00Z mapped through keyd's public seconds scale
//! ([`keyd::kerberos_time_seconds`], seconds since 0000-01-01T00:00:00Z on
//! the proleptic Gregorian calendar — the calendar krb-proto validates
//! against), as docs/47 §4.2 asks ("derive the offset from the calendar").
//! The inverse mapping is a search over that same forward mapping, so the
//! two can never disagree; an instant outside the KerberosTime range (after
//! 9999-12-31T23:59:59Z) has no KerberosTime and yields `None` — callers
//! fail closed.
//!
//! Spec: [MS-DTYP] 2.3.3; [MS-DRSR] 5.51; RFC 4120 5.2.3; docs/47 §4.2, §4.5.

use keyd::kerberos_time_seconds;
use krb_proto::KerberosTime;

const SECONDS_PER_DAY: i64 = 86_400;
const SECONDS_PER_HOUR: i64 = 3_600;
const SECONDS_PER_MINUTE: i64 = 60;

/// Nanoseconds in one second.
const NANOSECONDS_PER_SECOND: i64 = 1_000_000_000;

/// Nanoseconds in one FILETIME interval ("100-nanosecond intervals").
/// Spec: [MS-DTYP] 2.3.3.
const NANOSECONDS_PER_FILETIME_TICK: i64 = 100;

/// FILETIME intervals in one second. Spec: [MS-DTYP] 2.3.3.
pub(crate) const FILETIME_TICKS_PER_SECOND: i64 =
    NANOSECONDS_PER_SECOND / NANOSECONDS_PER_FILETIME_TICK;

/// Largest year a KerberosTime carries (four digits). Spec: RFC 4120 5.2.3.
const MAX_YEAR: u16 = 9999;

/// The FILETIME / DSTIME epoch, 1601-01-01T00:00:00Z, on keyd's seconds
/// scale. Spec: [MS-DTYP] 2.3.3 ("since January 1, 1601"); [MS-DRSR] 5.51.
fn epoch_1601() -> Option<i64> {
    KerberosTime::new(1601, 1, 1, 0, 0, 0)
        .ok()
        .map(|t| kerberos_time_seconds(&t))
}

/// `YYYY-MM-01T00:00:00Z` on keyd's scale.
fn start_of(year: u16, month: u8) -> Option<i64> {
    KerberosTime::new(year, month, 1, 0, 0, 0)
        .ok()
        .map(|t| kerberos_time_seconds(&t))
}

/// The KerberosTime at `total` seconds on keyd's scale, or `None` if it is
/// before 0000-01-01 or after 9999-12-31T23:59:59Z. Inverse of
/// [`keyd::kerberos_time_seconds`]: the year is the last one whose 1 January
/// is not after `total` (binary search), the month the last whose first day
/// is not after it, and the rest whole days, hours, minutes and seconds.
/// Spec: RFC 4120 5.2.3.
pub(crate) fn from_seconds(total: i64) -> Option<KerberosTime> {
    if total < start_of(0, 1)? {
        return None;
    }
    let (mut low, mut high) = (0u16, MAX_YEAR);
    while low < high {
        let mid = low + (high - low).div_ceil(2);
        if start_of(mid, 1)? <= total {
            low = mid;
        } else {
            high = mid - 1;
        }
    }
    let year = low;
    let mut month = 1u8;
    while month < 12 && start_of(year, month + 1)? <= total {
        month += 1;
    }
    let within = total.checked_sub(start_of(year, month)?)?;
    let day = within / SECONDS_PER_DAY + 1;
    let rest = within % SECONDS_PER_DAY;
    KerberosTime::new(
        year,
        month,
        u8::try_from(day).ok()?,
        u8::try_from(rest / SECONDS_PER_HOUR).ok()?,
        u8::try_from(rest % SECONDS_PER_HOUR / SECONDS_PER_MINUTE).ok()?,
        u8::try_from(rest % SECONDS_PER_MINUTE).ok()?,
    )
    .ok()
}

/// The KerberosTime `seconds` after 1601-01-01T00:00:00Z, or `None` if
/// negative or not representable. Spec: [MS-DRSR] 5.51; RFC 4120 5.2.3.
pub(crate) fn since_1601(seconds: i64) -> Option<KerberosTime> {
    if seconds < 0 {
        return None;
    }
    from_seconds(epoch_1601()?.checked_add(seconds)?)
}

/// A FILETIME rounded DOWN to the whole second (an expiry: earlier is the
/// stricter side). `None` if negative or not representable.
/// Spec: [MS-DTYP] 2.3.3; docs/47 §4.2.
pub(crate) fn filetime_floor(ticks: i64) -> Option<KerberosTime> {
    if ticks < 0 {
        return None;
    }
    since_1601(ticks / FILETIME_TICKS_PER_SECOND)
}

/// A FILETIME rounded UP to the whole second (a revocation cut-off: later
/// is the stricter side, docs/47 §4.5 "ceil_s(pwdLastSet)"). `None` if
/// negative or not representable. Spec: [MS-DTYP] 2.3.3; docs/47 §4.5.
pub(crate) fn filetime_ceil(ticks: i64) -> Option<KerberosTime> {
    if ticks < 0 {
        return None;
    }
    let whole = ticks / FILETIME_TICKS_PER_SECOND;
    let seconds = if ticks % FILETIME_TICKS_PER_SECOND == 0 {
        whole
    } else {
        whole.checked_add(1)?
    };
    since_1601(seconds)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(y: u16, mo: u8, d: u8, h: u8, mi: u8, s: u8) -> KerberosTime {
        KerberosTime::new(y, mo, d, h, mi, s).unwrap()
    }

    /// Hand-derived offsets on the Gregorian calendar (RFC 4120 5.2.3; the
    /// [MS-DTYP] 2.3.3 / [MS-DRSR] 5.51 epoch 1601-01-01):
    /// - 1601-01-01 → 1970-01-01: 369 years, leap years 1604..1968 = 92
    ///   multiples of 4 minus 1700, 1800, 1900 (not multiples of 400) = 89;
    ///   369 × 365 + 89 = 134 774 days = 11 644 473 600 s.
    /// - 1970-01-01 → 2027-01-01: 57 years, leap years 1972..2024 = 14;
    ///   57 × 365 + 14 = 20 819 days = 1 798 761 600 s.
    #[test]
    fn epoch_offsets_follow_the_calendar() {
        assert_eq!(since_1601(0), Some(t(1601, 1, 1, 0, 0, 0)));
        assert_eq!(since_1601(11_644_473_600), Some(t(1970, 1, 1, 0, 0, 0)));
        assert_eq!(
            since_1601(11_644_473_600 + 1_798_761_600),
            Some(t(2027, 1, 1, 0, 0, 0))
        );
        // FILETIME: × 10^7 intervals per second ([MS-DTYP] 2.3.3).
        assert_eq!(FILETIME_TICKS_PER_SECOND, 10_000_000);
        assert_eq!(
            filetime_floor(116_444_736_000_000_000),
            Some(t(1970, 1, 1, 0, 0, 0))
        );
    }

    /// Floor for expiry, ceiling for revocation (docs/47 §4.2, §4.5).
    #[test]
    fn rounding() {
        let base = 116_444_736_000_000_000i64; // 1970-01-01T00:00:00Z
        assert_eq!(filetime_floor(base + 1), Some(t(1970, 1, 1, 0, 0, 0)));
        assert_eq!(filetime_ceil(base + 1), Some(t(1970, 1, 1, 0, 0, 1)));
        assert_eq!(filetime_ceil(base), Some(t(1970, 1, 1, 0, 0, 0)));
        assert_eq!(
            filetime_ceil(base + 9_999_999),
            Some(t(1970, 1, 1, 0, 0, 1))
        );
    }

    /// Outside the KerberosTime range, or negative: no value (fail closed).
    #[test]
    fn out_of_range() {
        assert_eq!(filetime_floor(-1), None);
        assert_eq!(filetime_ceil(-1), None);
        assert_eq!(since_1601(-1), None);
        // i64::MAX intervals is about year 30828 — beyond 9999.
        assert_eq!(filetime_floor(i64::MAX), None);
        assert_eq!(filetime_ceil(i64::MAX), None);
        let last = kerberos_time_seconds(&t(9999, 12, 31, 23, 59, 59));
        assert_eq!(from_seconds(last), Some(t(9999, 12, 31, 23, 59, 59)));
        assert_eq!(from_seconds(last + 1), None);
    }

    /// The inverse reproduces every field, leap days included.
    #[test]
    fn round_trip() {
        for kt in [
            t(0, 1, 1, 0, 0, 0),
            t(1601, 1, 1, 0, 0, 0),
            t(2000, 2, 29, 12, 34, 56),
            t(2026, 11, 13, 10, 0, 0),
            t(2026, 12, 31, 23, 59, 59),
        ] {
            assert_eq!(from_seconds(kerberos_time_seconds(&kt)), Some(kt));
        }
    }
}
