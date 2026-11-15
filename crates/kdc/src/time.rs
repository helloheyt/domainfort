//! Time arithmetic on caller-supplied KerberosTime values.
//!
//! The KDC reads no clock: `now` always comes from the caller (main-session
//! decision 1). Ticket planning needs "now + a lifetime", so a count of
//! seconds must be turned back into a KerberosTime. The forward direction is
//! keyd's [`keyd_types::kerberos_time_seconds`] (seconds since 0000-01-01T00:00:00Z
//! on the proleptic Gregorian calendar, the calendar krb-proto validates
//! against); the inverse here is derived from it directly: the year is the
//! last one whose 1 January is not after the instant (binary search over the
//! KerberosTime year range), the month the last whose first day is not after
//! it, and the rest is whole days, hours, minutes and seconds. Every
//! candidate is built with `KerberosTime::new`, so an instant outside the
//! representable range (after 9999-12-31T23:59:59Z) yields `None` — callers
//! fail closed.
//!
//! Spec: RFC 4120 5.2.3 (KerberosTime is UTC, whole seconds); 5.4.1 (`till`
//! "19700101000000Z" = maximum endtime permitted by policy).

use krb_proto::KerberosTime;

const SECONDS_PER_DAY: i64 = 86_400;
const SECONDS_PER_HOUR: i64 = 3_600;
const SECONDS_PER_MINUTE: i64 = 60;

/// Largest year a KerberosTime can carry (four-digit year, RFC 4120 5.2.3).
const MAX_YEAR: u16 = 9999;

/// Seconds of `t` on keyd's scale. Spec: RFC 4120 5.2.3.
pub(crate) fn seconds(t: &KerberosTime) -> i64 {
    keyd_types::kerberos_time_seconds(t)
}

/// The KerberosTime `YYYY-MM-01T00:00:00Z`, on keyd's scale.
fn start_of(year: u16, month: u8) -> Option<i64> {
    KerberosTime::new(year, month, 1, 0, 0, 0)
        .ok()
        .map(|t| seconds(&t))
}

/// The KerberosTime at `total` seconds on keyd's scale, or `None` if it is
/// negative or after the representable range. Spec: RFC 4120 5.2.3.
pub(crate) fn from_seconds(total: i64) -> Option<KerberosTime> {
    if total < start_of(0, 1)? {
        return None;
    }
    // The last year whose 1 January 00:00:00 is not after `total`.
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
    // The last month of that year whose first day is not after `total`.
    let mut month = 1u8;
    while month < 12 && start_of(year, month + 1)? <= total {
        month += 1;
    }
    let within = total - start_of(year, month)?;
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

/// The `till` value meaning "the maximum endtime permitted according to KDC
/// policy": 19700101000000Z. Spec: RFC 4120 5.4.1 (till).
pub(crate) fn till_maximum() -> Option<KerberosTime> {
    KerberosTime::new(1970, 1, 1, 0, 0, 0).ok()
}

// The PDP's explicit `Instant` (seconds since 1970-01-01T00:00:00Z, docs/11
// §1, P9) is krb-proto's one `kerberos_time_to_unix` (crate::gate); this
// module held a copy until docs/questions/Q-987 item 5 / A-165 folded it
// (Q-995). `till_maximum` above is RFC 4120 5.4.1's `till` value, which only
// happens to be the same instant.

#[cfg(test)]
mod tests {
    use super::*;

    fn t(y: u16, mo: u8, d: u8, h: u8, mi: u8, s: u8) -> KerberosTime {
        KerberosTime::new(y, mo, d, h, mi, s).unwrap()
    }

    /// The inverse reproduces every field (round trip through keyd's
    /// forward mapping), including leap days and year boundaries
    /// (RFC 4120 5.2.3: UTC calendar times).
    #[test]
    fn round_trip() {
        for kt in [
            t(0, 1, 1, 0, 0, 0),
            t(1970, 1, 1, 0, 0, 0),
            t(2000, 2, 29, 12, 34, 56),
            t(2024, 2, 29, 23, 59, 59),
            t(2026, 11, 13, 10, 0, 0),
            t(2026, 12, 31, 23, 59, 59),
            t(2027, 1, 1, 0, 0, 0),
            t(2100, 3, 1, 0, 0, 1),
            t(9999, 12, 31, 23, 59, 59),
        ] {
            assert_eq!(from_seconds(seconds(&kt)), Some(kt), "{kt:?}");
        }
    }

    /// Adding a day crosses month and year boundaries correctly.
    #[test]
    fn arithmetic() {
        let base = seconds(&t(2026, 12, 31, 12, 0, 0));
        assert_eq!(
            from_seconds(base + SECONDS_PER_DAY),
            Some(t(2027, 1, 1, 12, 0, 0))
        );
        let leap = seconds(&t(2028, 2, 28, 23, 0, 0));
        assert_eq!(
            from_seconds(leap + SECONDS_PER_HOUR),
            Some(t(2028, 2, 29, 0, 0, 0))
        );
    }

    /// Out of range: negative and after year 9999 (fail closed).
    #[test]
    fn out_of_range() {
        assert_eq!(from_seconds(-1), None);
        let last = seconds(&t(9999, 12, 31, 23, 59, 59));
        assert_eq!(from_seconds(last + 1), None);
        assert_eq!(from_seconds(i64::MAX), None);
    }
}
