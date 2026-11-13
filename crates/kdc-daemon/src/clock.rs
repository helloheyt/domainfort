//! The kdc's own clock.
//!
//! The kdc library reads no clock: `Kdc::handle` takes `now` from its caller
//! ("`now` is trusted", crates/kdc lib.rs). In the daemon it comes from
//! **this process's** clock, per request (docs/50 §4.1: "`now` — the system
//! clock per request (`Kdc` reads no clock)"). keyd reads its own clock for
//! its own checks (R50-5, A-56): the same host and the same clock, a gap
//! well within the clock skew.
//!
//! [`SystemClock`] reads the operating-system clock (`std::time::SystemTime`)
//! and converts whole seconds since 1970-01-01T00:00:00Z into a
//! `KerberosTime` with the project's one method (the inverse of
//! `keyd_types::kerberos_time_seconds`, as crates/kdc time.rs and
//! crates/keyd-daemon clock.rs derive it): the year is the last one whose
//! 1 January is not after the instant, the month the last whose first day
//! is not after it, the rest whole days, hours, minutes and seconds; every
//! candidate is built with `KerberosTime::new`, so an instant outside the
//! representable range yields `None` and the request is not served (fail
//! closed). The integrity of the host clock is the platform's (RFC 4120
//! §1.6; docs/questions/Q-222 item 2).
//!
//! Spec: docs/50 §4.1, R50-5; RFC 4120 5.2.3, §1.6; docs/questions/Q-222
//! (A-56).

use keyd_types::kerberos_time_seconds;
use krb_proto::KerberosTime;
use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds in a day (KerberosTime has no leap seconds, RFC 4120 5.2.3).
const SECONDS_PER_DAY: i64 = 86_400;
const SECONDS_PER_HOUR: i64 = 3_600;
const SECONDS_PER_MINUTE: i64 = 60;
/// The first year an instant after the epoch can fall in.
const EPOCH_YEAR: u16 = 1970;
/// The last year a KerberosTime can carry (RFC 4120 5.2.3).
const MAX_YEAR: u16 = 9999;

/// Where the engine reads `now`. The daemon uses [`SystemClock`]; tests
/// inject a fixed clock so that replies can be compared octet for octet with
/// the in-process path (docs/50 §9 tier 1).
///
/// Spec: docs/50 §4.1, §9.
pub trait Clock: Send + 'static {
    /// The current time, or `None` if it cannot be read or represented.
    fn now(&self) -> Option<KerberosTime>;
}

/// The operating system's clock. Spec: docs/50 §4.1.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    /// Whole seconds of `SystemTime::now()` since the epoch.
    /// Spec: docs/50 §4.1; RFC 4120 5.2.3.
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
/// Spec: RFC 4120 5.2.3; crates/keyd-types time.rs (the forward scale).
#[must_use]
pub fn kerberos_time_from_unix(secs: u64) -> Option<KerberosTime> {
    let epoch = start_of(EPOCH_YEAR, 1)?;
    let total = epoch.checked_add(i64::try_from(secs).ok()?)?;
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

    /// RFC 4120 5.2.3 (UTC calendar times, whole seconds): the conversion is
    /// the inverse of the project's scale — leap days, month and year
    /// boundaries, the last representable second.
    #[test]
    fn round_trips_through_the_project_scale() {
        for kt in [
            t(1970, 1, 1, 0, 0, 0),
            t(1999, 12, 31, 23, 59, 59),
            t(2000, 2, 29, 12, 34, 56),
            t(2026, 11, 13, 10, 0, 0),
            t(2100, 3, 1, 0, 0, 1),
            t(9999, 12, 31, 23, 59, 59),
        ] {
            assert_eq!(kerberos_time_from_unix(unix_of(&kt)), Some(kt));
        }
    }

    /// Hand-derived fixed points: the epoch is 0; 1970-01-01 → 2000-01-01 is
    /// 30 × 365 days + 7 leap days (1972 … 1996) = 10957 days.
    #[test]
    fn fixed_points_and_the_range() {
        assert_eq!(kerberos_time_from_unix(0), Some(t(1970, 1, 1, 0, 0, 0)));
        assert_eq!(
            kerberos_time_from_unix(10_957 * 86_400 + 3_661),
            Some(t(2000, 1, 1, 1, 1, 1))
        );
        let last = unix_of(&t(9999, 12, 31, 23, 59, 59));
        assert_eq!(kerberos_time_from_unix(last + 1), None);
        assert_eq!(kerberos_time_from_unix(u64::MAX), None);
        assert!(SystemClock.now().is_some());
    }
}
