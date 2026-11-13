//! keyd's own clock.
//!
//! The keyd library reads no clock: every operation takes `now` from its
//! caller, and the constructor takes the start time of the hold-down. In the
//! daemon both come from **this process's** clock and never from the peer —
//! otherwise a compromised kdc could "turn the time back" to use an expired
//! TGT, or end the hold-down early (docs/50 R50-5, §3.5; decision A-56,
//! docs/questions/Q-222). The channel has no field for either.
//!
//! [`SystemClock`] reads the operating-system clock (`std::time::SystemTime`)
//! and converts whole seconds since 1970-01-01T00:00:00Z into a
//! `KerberosTime`. The conversion is the inverse of the project's one
//! KerberosTime-to-seconds scale ([`keyd::kerberos_time_seconds`]): the year
//! is the last one whose 1 January is not after the instant, the month the
//! last whose first day is not after it, and the rest is whole days, hours,
//! minutes and seconds; every candidate is built with `KerberosTime::new`, so
//! an instant outside the representable range yields `None` (the same method
//! crates/kdc time.rs uses for its own inverse).
//!
//! A clock that cannot be read or represented makes the daemon refuse the
//! request (`Unavailable`) — fail closed. The integrity of the host clock is
//! the platform's (RFC 4120 §1.6: clock synchronization "MUST itself be
//! secured"; docs/questions/Q-222 item 2 — a deployment requirement until the
//! time service exists).
//!
//! Spec: docs/50 R50-5, R50-6, §3.5; RFC 4120 5.2.3 (KerberosTime: UTC,
//! whole seconds), §1.6; docs/questions/Q-222 (A-56), Q-240 item 7 (A-62).

use keyd::kerberos_time_seconds;
use krb_proto::KerberosTime;
use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds in a day (KerberosTime has no leap seconds, RFC 4120 5.2.3).
const SECONDS_PER_DAY: i64 = 86_400;
/// Seconds in an hour.
const SECONDS_PER_HOUR: i64 = 3_600;
/// Seconds in a minute.
const SECONDS_PER_MINUTE: i64 = 60;
/// The first year an instant read from `SystemTime` after the epoch can
/// fall in.
const EPOCH_YEAR: u16 = 1970;
/// The last year a KerberosTime can carry (four-digit year, RFC 4120 5.2.3).
const MAX_YEAR: u16 = 9999;

/// Where the engine reads `now` (and, once, the start time of the
/// hold-down) from.
///
/// The daemon uses [`SystemClock`]. Tests inject their own clock to show the
/// hold-down boundary without waiting for it (docs/50 §9 tier 2: "the
/// startup hold-down with an injected clock"); either way the value comes
/// from inside the keyd process, never from the request.
///
/// Spec: docs/50 R50-5, §3.5, §9.
pub trait Clock: Send + 'static {
    /// The current time, or `None` if it cannot be read or represented
    /// (the request is then refused, fail closed).
    fn now(&self) -> Option<KerberosTime>;
}

/// The operating system's clock.
///
/// Spec: docs/50 R50-5 ("keyd-daemon fills `now` of every operation from its
/// own system clock").
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    /// Whole seconds of `SystemTime::now()` since the epoch; an instant
    /// before the epoch or after 9999-12-31T23:59:59Z is `None`.
    /// Spec: docs/50 R50-5; RFC 4120 5.2.3.
    fn now(&self) -> Option<KerberosTime> {
        let since = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
        kerberos_time_from_unix(since.as_secs())
    }
}

/// `YYYY-MM-01T00:00:00Z` on the project's seconds scale.
fn start_of(year: u16, month: u8) -> Option<i64> {
    KerberosTime::new(year, month, 1, 0, 0, 0)
        .ok()
        .map(|t| kerberos_time_seconds(&t))
}

/// The KerberosTime `secs` whole seconds after 1970-01-01T00:00:00Z, or
/// `None` after the representable range.
///
/// Spec: RFC 4120 5.2.3; crates/keyd-types time.rs (the forward scale).
pub fn kerberos_time_from_unix(secs: u64) -> Option<KerberosTime> {
    let epoch = start_of(EPOCH_YEAR, 1)?;
    let total = epoch.checked_add(i64::try_from(secs).ok()?)?;
    // The last year (≥ 1970) whose 1 January 00:00:00 is not after `total`.
    let (mut low, mut high) = (EPOCH_YEAR, MAX_YEAR);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn t(y: u16, mo: u8, d: u8, h: u8, mi: u8, s: u8) -> KerberosTime {
        KerberosTime::new(y, mo, d, h, mi, s).unwrap()
    }

    fn unix_of(kt: &KerberosTime) -> u64 {
        let epoch = kerberos_time_seconds(&t(1970, 1, 1, 0, 0, 0));
        u64::try_from(kerberos_time_seconds(kt) - epoch).unwrap()
    }

    /// The conversion is the inverse of the project's scale (RFC 4120 5.2.3:
    /// UTC calendar times): every field round-trips, including leap days,
    /// month and year boundaries and the last representable second.
    #[test]
    fn round_trips_through_the_project_scale() {
        for kt in [
            t(1970, 1, 1, 0, 0, 0),
            t(1970, 1, 1, 0, 0, 1),
            t(1999, 12, 31, 23, 59, 59),
            t(2000, 2, 29, 12, 34, 56),
            t(2024, 2, 29, 23, 59, 59),
            t(2026, 11, 13, 10, 0, 0),
            t(2100, 3, 1, 0, 0, 1),
            t(9999, 12, 31, 23, 59, 59),
        ] {
            assert_eq!(kerberos_time_from_unix(unix_of(&kt)), Some(kt));
        }
    }

    /// Fixed points derived by hand: the epoch is 0; 1970-01-01 → 2000-01-01
    /// is 30 × 365 days plus the 7 leap days of 1972 … 1996 = 10957 days
    /// (the derivation in crates/keyd-types time.rs).
    #[test]
    fn fixed_points() {
        assert_eq!(kerberos_time_from_unix(0), Some(t(1970, 1, 1, 0, 0, 0)));
        assert_eq!(
            kerberos_time_from_unix(10_957 * 86_400),
            Some(t(2000, 1, 1, 0, 0, 0))
        );
        assert_eq!(
            kerberos_time_from_unix(10_957 * 86_400 + 3_661),
            Some(t(2000, 1, 1, 1, 1, 1))
        );
    }

    /// After 9999-12-31T23:59:59Z there is no KerberosTime: `None` (the
    /// request is refused, fail closed).
    #[test]
    fn beyond_the_range_is_none() {
        let last = unix_of(&t(9999, 12, 31, 23, 59, 59));
        assert_eq!(kerberos_time_from_unix(last + 1), None);
        assert_eq!(kerberos_time_from_unix(u64::MAX), None);
    }

    /// The system clock gives a time (the host clock is after 1970).
    #[test]
    fn system_clock_reads() {
        assert!(SystemClock.now().is_some());
    }
}
