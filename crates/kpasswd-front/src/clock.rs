//! The front's clock, for the `stime` / `susec` of its KRB-ERRORs.
//!
//! docs/53 §5.7: "`stime`/`susec` = the front's clock". RFC 4120 §5.9.1:
//! "stime — This field contains the current time on the server. It is of
//! type KerberosTime"; "susec — … the microsecond part of the server's
//! timestamp. Its value ranges from 0 to 999999". The front reads the
//! operating-system clock (`std::time::SystemTime`) and turns the whole
//! seconds since 1970-01-01T00:00:00Z into a KerberosTime — UTC, whole
//! seconds, no leap second (RFC 4120 §5.2.3; crates/krb-proto refuses second
//! 60, docs/questions/Q-030) — on the proleptic Gregorian calendar
//! krb-proto's `KerberosTime::new` validates against (X.680 46.2–46.3): a
//! year has 366 days when divisible by 4, except century years not divisible
//! by 400 (the rule as crates/keyd-types `time.rs` writes it). Every
//! candidate is built with `KerberosTime::new`, so an instant outside the
//! representable range yields `None`, and the front then closes without a
//! reply (fail closed).
//!
//! **One rule, a further copy (C14 residual).** The kdc, keyd and the kdc
//! daemon each convert between KerberosTime and seconds; the front links no
//! keyd crate (tests/holds_no_key.rs), so it cannot call keyd-types'. The
//! tests pin this conversion against keyd-types' `kerberos_time_seconds` (a
//! dev-dependency only). Root option (one conversion in krb-proto) recorded
//! in docs/questions/Q-955 item 5. A KRB-ERROR is not integrity protected
//! and its time is informational only (RFC 4120 §5.9).
//!
//! Spec: docs/53 §5.7; RFC 4120 §5.2.3, §5.9, §5.9.1; X.680 (02/2021)
//! 46.2, 46.3.

use krb_proto::{KerberosTime, Microseconds};
use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds in a day (KerberosTime has no leap seconds, RFC 4120 5.2.3).
const SECONDS_PER_DAY: u64 = 86_400;
/// Seconds in an hour.
const SECONDS_PER_HOUR: u64 = 3_600;
/// Seconds in a minute.
const SECONDS_PER_MINUTE: u64 = 60;
/// The year of 1970-01-01T00:00:00Z, where the count starts.
const EPOCH_YEAR: u16 = 1970;
/// The last year a KerberosTime can carry (four digits, RFC 4120 5.2.3).
const MAX_YEAR: u16 = 9999;

/// The server time of a KRB-ERROR: `stime` and `susec`.
/// Spec: RFC 4120 §5.9.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerTime {
    /// `stime`.
    pub stime: KerberosTime,
    /// `susec`.
    pub susec: Microseconds,
}

/// Gregorian leap-year rule (module documentation).
fn is_leap_year(year: u16) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

/// Days in `month` (1-12) of `year`.
fn days_in_month(year: u16, month: u8) -> u64 {
    match month {
        2 if is_leap_year(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// The KerberosTime `secs` whole seconds after 1970-01-01T00:00:00Z, or
/// `None` after 9999-12-31T23:59:59Z.
/// Spec: RFC 4120 5.2.3; X.680 46.2, 46.3.
#[must_use]
pub fn kerberos_time_from_unix(secs: u64) -> Option<KerberosTime> {
    let mut days = secs / SECONDS_PER_DAY;
    let within_day = secs % SECONDS_PER_DAY;
    let mut year = EPOCH_YEAR;
    loop {
        let length = if is_leap_year(year) { 366 } else { 365 };
        if days < length {
            break;
        }
        days -= length;
        if year >= MAX_YEAR {
            return None;
        }
        year += 1;
    }
    let mut month = 1u8;
    while days >= days_in_month(year, month) {
        days -= days_in_month(year, month);
        month += 1;
    }
    KerberosTime::new(
        year,
        month,
        u8::try_from(days + 1).ok()?,
        u8::try_from(within_day / SECONDS_PER_HOUR).ok()?,
        u8::try_from(within_day % SECONDS_PER_HOUR / SECONDS_PER_MINUTE).ok()?,
        u8::try_from(within_day % SECONDS_PER_MINUTE).ok()?,
    )
    .ok()
}

/// The operating system's clock now, as a KRB-ERROR's server time; `None`
/// if it reads before 1970 or after the representable range (fail closed).
/// Spec: RFC 4120 §5.9.1; docs/53 §5.7.
#[must_use]
pub fn server_time_now() -> Option<ServerTime> {
    let since = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
    Some(ServerTime {
        stime: kerberos_time_from_unix(since.as_secs())?,
        susec: Microseconds::new(since.subsec_micros()).ok()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(y: u16, mo: u8, d: u8, h: u8, mi: u8, s: u8) -> KerberosTime {
        KerberosTime::new(y, mo, d, h, mi, s).unwrap()
    }

    /// Hand-derived fixed points (RFC 4120 5.2.3: UTC calendar times): the
    /// epoch; 1970-01-01 → 2000-01-01 is 30 × 365 days + 7 leap days (1972 …
    /// 1996) = 10,957 days; 2000 is a leap year (divisible by 400), so
    /// 2000-02-29 exists and is day 59 of that year; the last second of
    /// 9999 and the one after it.
    #[test]
    fn fixed_points_and_the_range() {
        assert_eq!(kerberos_time_from_unix(0), Some(t(1970, 1, 1, 0, 0, 0)));
        assert_eq!(
            kerberos_time_from_unix(10_957 * 86_400 + 3_661),
            Some(t(2000, 1, 1, 1, 1, 1))
        );
        assert_eq!(
            kerberos_time_from_unix((10_957 + 59) * 86_400),
            Some(t(2000, 2, 29, 0, 0, 0))
        );
        assert_eq!(
            kerberos_time_from_unix((10_957 + 60) * 86_400 - 1),
            Some(t(2000, 2, 29, 23, 59, 59))
        );
        assert_eq!(kerberos_time_from_unix(u64::MAX), None);
        assert!(server_time_now().is_some());
    }
}
