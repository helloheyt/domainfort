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
//! with the project's one conversion, `krb_proto::kerberos_time_from_unix`
//! (this module composed its own through directory-pip's DSTIME scale until
//! docs/questions/Q-987 item 5 / A-165 folded it — Q-995); an instant
//! outside the representable range yields `None` (the request is not served,
//! fail closed). The integrity of the host clock is the platform's (RFC 4120
//! §1.6; docs/questions/Q-222 item 2).
//!
//! Tests inject their own [`Clock`] (a fixed time, so replies can be
//! compared octet for octet; or one that holds, to fill the engine queue —
//! docs/50 §9).
//!
//! Spec: docs/49 §11; docs/50 §4.1, §9; RFC 4120 5.2.3; docs/questions/Q-222
//! (A-56), Q-987 item 5 (A-165), Q-995.

use core::fmt;
use krb_proto::{kerberos_time_from_unix, KerberosTime};
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
    /// Spec: docs/50 §4.1; RFC 4120 5.2.3.
    fn now(&self) -> Option<KerberosTime> {
        let since = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
        kerberos_time_from_unix(since.as_secs())
    }
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

    /// docs/50 §4.1 ("the system clock per request"): the host clock reads
    /// and is represented (it is after 1970). The conversion's own tests are
    /// krb-proto's (`tests/time_scale.rs`).
    #[test]
    fn the_system_clock_reads() {
        assert!(SystemClock.now().is_some());
        assert!(SharedClock::system().now().is_some());
    }
}
