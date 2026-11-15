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
//! `KerberosTime` with the project's one conversion,
//! `krb_proto::kerberos_time_from_unix` (this module held a copy of it until
//! docs/questions/Q-987 item 5 / A-165 folded it — Q-995); an instant outside
//! the representable range yields `None` and the request is not served (fail
//! closed). The integrity of the host clock is the platform's (RFC 4120
//! §1.6; docs/questions/Q-222 item 2).
//!
//! Spec: docs/50 §4.1, R50-5; RFC 4120 5.2.3, §1.6; docs/questions/Q-222
//! (A-56), Q-987 item 5 (A-165), Q-995.

use krb_proto::{kerberos_time_from_unix, KerberosTime};
use std::time::{SystemTime, UNIX_EPOCH};

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

#[cfg(test)]
mod tests {
    use super::*;

    /// docs/50 §4.1 ("the system clock per request"): the host clock reads
    /// and is represented (it is after 1970). The conversion's own tests are
    /// krb-proto's (`tests/time_scale.rs`).
    #[test]
    fn the_system_clock_reads() {
        assert!(SystemClock.now().is_some());
    }
}
