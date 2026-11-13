//! dird's clock for the LDAP engine.
//!
//! The engine reads no clock (docs/49 §11): each request brings `now`, and a
//! directory search reads the caller's `SearchClock` between candidates for
//! timeLimit and the query-duration bound (crates/ldap inputs.rs). In dird
//! both come from **this process's** clock (the same rule as the kdc daemon,
//! docs/50 §4.1: "`now` — the system clock per request").
//!
//! [`SystemClock`] reads the operating-system clock (`std::time::SystemTime`)
//! and converts whole seconds since 1970-01-01T00:00:00Z to a `KerberosTime`
//! through directory-pip's DSTIME scale (seconds since 1601-01-01T00:00:00Z,
//! [MS-DRSR] 5.51): the DSTIME of the Unix epoch is computed with
//! `dstime_of`, the seconds are added, and `time_of_dstime` builds the
//! calendar time — so no epoch constant is written here, and an instant
//! outside the representable range yields `None` (the request is not served,
//! fail closed). The integrity of the host clock is the platform's (RFC 4120
//! §1.6; docs/questions/Q-222 item 2).
//!
//! Tests inject their own [`Clock`] (a fixed time, so replies can be
//! compared octet for octet; or one that holds, to fill the engine queue —
//! docs/50 §9).
//!
//! Spec: docs/49 §11; docs/50 §4.1, §9; RFC 4120 5.2.3; [MS-DRSR] 5.51;
//! docs/questions/Q-222 (A-56).

use core::fmt;
use directory_pip::{dstime_of, time_of_dstime};
use krb_proto::KerberosTime;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Where the LDAP engine thread reads `now`.
/// Spec: docs/49 §11; docs/50 §4.1, §9.
pub trait Clock: Send + Sync + 'static {
    /// The current time, or `None` if it cannot be read or represented.
    fn now(&self) -> Option<KerberosTime>;
}

/// The operating system's clock. Spec: docs/50 §4.1.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    /// Whole seconds of `SystemTime::now()` since the epoch.
    /// Spec: docs/50 §4.1; RFC 4120 5.2.3; [MS-DRSR] 5.51.
    fn now(&self) -> Option<KerberosTime> {
        let since = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
        kerberos_time_from_unix(since.as_secs())
    }
}

/// The KerberosTime `secs` whole seconds after 1970-01-01T00:00:00Z, or
/// `None` outside the representable range.
/// Spec: RFC 4120 5.2.3; [MS-DRSR] 5.51 (DSTIME); crates/directory-pip
/// time.rs.
#[must_use]
pub fn kerberos_time_from_unix(secs: u64) -> Option<KerberosTime> {
    let epoch = dstime_of(&KerberosTime::new(1970, 1, 1, 0, 0, 0).ok()?)?;
    time_of_dstime(epoch.checked_add(i64::try_from(secs).ok()?)?)
}

/// A clock shared by the daemon's parameters and the LDAP engine thread.
/// Spec: docs/50 §4.1, §9.
#[derive(Clone)]
pub struct SharedClock(Arc<dyn Clock>);

impl SharedClock {
    /// The operating system's clock.
    #[must_use]
    pub fn system() -> SharedClock {
        SharedClock(Arc::new(SystemClock))
    }

    /// Any clock (tests).
    #[must_use]
    pub fn new(clock: impl Clock) -> SharedClock {
        SharedClock(Arc::new(clock))
    }

    /// The current time. Spec: [`Clock::now`].
    #[must_use]
    pub fn now(&self) -> Option<KerberosTime> {
        self.0.now()
    }
}

impl Default for SharedClock {
    fn default() -> Self {
        SharedClock::system()
    }
}

impl fmt::Debug for SharedClock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SharedClock")
    }
}

/// A search's clock: the shared clock, falling back to the request's `now`
/// when it cannot be read (the engine counts a clock that went backwards as
/// zero elapsed time — crates/ldap search; Q-200 item 12).
/// Spec: docs/49 §6.1 item 7, §11; RFC 4511 §4.5.1.5.
pub(crate) struct SearchTime<'a> {
    pub(crate) clock: &'a SharedClock,
    pub(crate) start: KerberosTime,
}

impl ldap::SearchClock for SearchTime<'_> {
    fn now(&self) -> KerberosTime {
        self.clock.now().unwrap_or(self.start)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(y: u16, mo: u8, d: u8, h: u8, mi: u8, s: u8) -> KerberosTime {
        KerberosTime::new(y, mo, d, h, mi, s).unwrap()
    }

    /// Hand-derived fixed points: the epoch is 0; 1970-01-01 → 2000-01-01
    /// is 30 × 365 days + 7 leap days (1972 … 1996) = 10957 days; 2026-11-13
    /// is 20,770 days after the epoch (56 years: 14 leap days 1972 … 2024,
    /// so 56 × 365 + 14 = 20,454 days to 2026-01-01; then 316 days of 2026
    /// to 13 November).
    #[test]
    fn fixed_points() {
        assert_eq!(kerberos_time_from_unix(0), Some(t(1970, 1, 1, 0, 0, 0)));
        assert_eq!(
            kerberos_time_from_unix(10_957 * 86_400 + 3_661),
            Some(t(2000, 1, 1, 1, 1, 1))
        );
        assert_eq!(
            kerberos_time_from_unix(20_770 * 86_400 + 36_000),
            Some(t(2026, 11, 13, 10, 0, 0))
        );
        assert!(SystemClock.now().is_some());
    }
}
