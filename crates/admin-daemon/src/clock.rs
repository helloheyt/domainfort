//! admind's clock, for the time of its audit events only (admind decides
//! nothing by time: ticket ages are dird's, key times keyd's).
//!
//! The operating-system clock (`std::time::SystemTime`), whole seconds since
//! 1970-01-01T00:00:00Z, converted to a calendar time with the inverse of the
//! project's one KerberosTime-to-seconds scale
//! (`keyd_types::kerberos_time_seconds`): the year is the last one whose
//! 1 January is not after the instant, the month the last whose first day is
//! not after it, the rest whole days, hours, minutes and seconds; every
//! candidate is built with `KerberosTime::new` — the method of crates/
//! keyd-daemon clock.rs, this project's code. A clock that cannot be read or
//! represented gives the event the calendar epoch (`CalendarTime::EPOCH`):
//! the event is still recorded (auditd stamps its own time on every record,
//! crate audit-log `Record::time`).
//!
//! Spec: RFC 4120 5.2.3 (KerberosTime: UTC, whole seconds); crate ipc-audit
//! `CalendarTime`; docs/50 §8.1.

use ipc_audit::CalendarTime;
use keyd_types::kerberos_time_seconds;
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

/// The audit form of a KerberosTime (validated calendar fields, so the
/// fallback is unreachable).
/// Spec: crate ipc-audit `CalendarTime`.
#[must_use]
pub fn calendar(time: &KerberosTime) -> CalendarTime {
    CalendarTime::new(
        time.year(),
        time.month(),
        time.day(),
        time.hour(),
        time.minute(),
        time.second(),
    )
    .unwrap_or(CalendarTime::EPOCH)
}

/// Now, for an audit event (module documentation).
/// Spec: docs/50 §8.1.
#[must_use]
pub fn event_time() -> CalendarTime {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|since| kerberos_time_from_unix(since.as_secs()))
        .map_or(CalendarTime::EPOCH, |time| calendar(&time))
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

    /// RFC 4120 5.2.3: the conversion is the inverse of the project's
    /// scale — leap days, month and year boundaries, the last second.
    #[test]
    fn round_trips_through_the_project_scale() {
        for kt in [
            t(1970, 1, 1, 0, 0, 0),
            t(2000, 2, 29, 12, 34, 56),
            t(2024, 12, 31, 23, 59, 59),
            t(2026, 11, 14, 8, 0, 0),
            t(9999, 12, 31, 23, 59, 59),
        ] {
            assert_eq!(kerberos_time_from_unix(unix_of(&kt)), Some(kt));
        }
        assert_eq!(
            kerberos_time_from_unix(unix_of(&t(9999, 12, 31, 23, 59, 59)) + 1),
            None
        );
    }

    /// Hand-derived fixed point: 1970-01-01 → 2000-01-01 is 30 × 365 days
    /// plus the 7 leap days of 1972 … 1996 = 10957 days.
    #[test]
    fn fixed_point() {
        assert_eq!(
            kerberos_time_from_unix(10_957 * 86_400 + 61),
            Some(t(2000, 1, 1, 0, 1, 1))
        );
        let c = calendar(&t(2000, 1, 1, 0, 1, 1));
        assert_eq!((c.year(), c.month(), c.day()), (2000, 1, 1));
    }

    /// The host clock reads (it is after 1970).
    #[test]
    fn reads() {
        assert_ne!(event_time(), CalendarTime::EPOCH);
    }
}
