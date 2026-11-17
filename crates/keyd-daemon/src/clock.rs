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
//! `KerberosTime` with the project's one conversion,
//! `krb_proto::kerberos_time_from_unix` — the inverse of the one
//! KerberosTime-to-seconds scale (`krb_proto::kerberos_time_seconds`, which
//! keyd re-exports). This module held a copy of it until docs/questions/Q-987
//! item 5 / A-165 folded it (Q-995); an instant outside the representable
//! range yields `None`.
//!
//! A clock that cannot be read or represented makes the daemon refuse the
//! request (`Unavailable`) — fail closed. The integrity of the host clock is
//! the platform's (RFC 4120 §1.6: clock synchronization "MUST itself be
//! secured"; docs/questions/Q-222 item 2 — a deployment requirement until the
//! time service exists).
//!
//! Spec: docs/50 R50-5, R50-6, §3.5; RFC 4120 5.2.3 (KerberosTime: UTC,
//! whole seconds), §1.6; docs/questions/Q-222 (A-56), Q-240 item 7 (A-62),
//! Q-987 item 5 (A-165), Q-995.

use krb_proto::{kerberos_time_from_unix, KerberosTime};
use std::time::{SystemTime, UNIX_EPOCH};

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

#[cfg(test)]
mod tests {
    use super::*;

    /// docs/50 R50-5 ("keyd-daemon fills `now` of every operation from its
    /// own system clock"): the host clock reads and is represented (it is
    /// after 1970). The conversion's own tests are krb-proto's
    /// (`tests/time_scale.rs`).
    #[test]
    fn system_clock_reads() {
        assert!(SystemClock.now().is_some());
    }
}
