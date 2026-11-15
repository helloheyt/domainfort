//! Rate limits of the daemon: the per-source and global UDP limits in front
//! of the engine (docs/50 R50-9, §4.1; Q-223 → A-57 option (a)), and the
//! PDP's `RateLimit` obligation (docs/11 §8; docs/50 §4.1 "obligations — the
//! daemon's `RateLimiter` implements the PDP's `RlKey`").
//!
//! The UDP admission check itself — [`SourceLimiter`] and its
//! [`SourceLimits`] — lives in the shared crate rate-limit since task DN3,
//! moved there unchanged so that dnsd uses the same mechanism instead of a
//! second copy (docs/54 §6.7, §10; the C14 pattern, docs/52 §3.14). It is
//! re-exported here; this module keeps the daemon's own numbers
//! ([`UDP_LIMITS`]) and the obligation limiter.
//!
//! docs/50 names these limits without a number, so they are constants in
//! the daemon (Q-230 item 4 → A-60), listed in docs/questions/Q-275 item 5.
//! Both use fixed windows: a counter per key that starts again at every new
//! window — a simple, bounded scheme (no clock-dependent decay to get
//! wrong).
//!
//! Spec: docs/50 R50-9, §4.1; docs/02 §2 (CLDAP: "rate limiting per source,
//! listening on internal interfaces only"); docs/07 §1; docs/11 §2, §8;
//! docs/questions/Q-223 (A-57), Q-230 item 4 (A-60); docs/54 §6.7 (DN3).

use core::time::Duration;
use kdc::RateLimiter;
use krb_proto::KerberosTime;
use pdp::RlKey;
use std::collections::HashMap;

/// The UDP admission check and its limits (crate rate-limit, task DN3).
/// Spec: docs/50 §4.1; docs/questions/Q-223 (A-57); docs/54 §6.7.
pub use rate_limit::{SourceLimiter, SourceLimits};

/// UDP datagrams admitted per source address per second. Project choice
/// (docs/50 §4.1 names "a rate limiter per source" with no number): a
/// native client sends a handful of requests per logon.
pub const UDP_PER_SOURCE_PER_SECOND: u32 = 32;

/// UDP datagrams admitted per second from all sources together — the
/// global reply budget of Q-223 (A-57) option (a): every reply answers one
/// admitted datagram, so it bounds the replies too. Project choice.
pub const UDP_GLOBAL_PER_SECOND: u32 = 2048;

/// The UDP window. Project choice.
pub const UDP_WINDOW: Duration = Duration::from_secs(1);

/// The daemon's UDP limits — the production value of the UDP limits
/// (`ServeParams::udp`), shared by every UDP socket of the daemon through
/// one [`SourceLimiter`]. (Before task DN3: `UdpLimits::DEFAULT`, the same
/// three constants.)
/// Spec: docs/50 §4.1; docs/questions/Q-223 (A-57), Q-275 item 5 (A-60).
pub const UDP_LIMITS: SourceLimits = SourceLimits {
    per_source: UDP_PER_SOURCE_PER_SECOND,
    global: UDP_GLOBAL_PER_SECOND,
    window: UDP_WINDOW,
};

/// Requests one `RlKey` may make per window. Project choice (docs/11 §8
/// gives the obligation, not its numbers).
pub const OBLIGATION_LIMIT: u32 = 60;

/// The obligation window, in seconds of the request's `now`. Project choice.
pub const OBLIGATION_WINDOW_SECS: i64 = 60;

/// Most keys tracked at once. Project bound (AGENTS.md §6).
pub const OBLIGATION_KEYS: usize = 4096;

/// The PDP's `RateLimit` obligation (docs/11 §8): per `RlKey`, at most
/// [`OBLIGATION_LIMIT`] admissions per window of
/// [`OBLIGATION_WINDOW_SECS`] on the request's `now` (the caller's time,
/// crates/kdc gate.rs). The table is bounded: when it is full, keys of past
/// windows are dropped; if it is still full, a new key is refused (fail
/// closed — a refusal is a deny, crates/kdc gate.rs).
///
/// Spec: docs/11 §2 ("the PEP must honour obligations"), §8; docs/50 §4.1.
#[derive(Debug, Default)]
pub struct ObligationLimiter {
    windows: HashMap<RlKey, (i64, u32)>,
}

impl ObligationLimiter {
    /// An empty limiter.
    #[must_use]
    pub fn new() -> ObligationLimiter {
        ObligationLimiter::default()
    }
}

impl RateLimiter for ObligationLimiter {
    /// Spec: docs/11 §8; crates/kdc gate.rs (`admit`: "`false` refuses").
    fn admit(&mut self, key: &RlKey, now: &KerberosTime) -> bool {
        let window = keyd_types::kerberos_time_seconds(now).div_euclid(OBLIGATION_WINDOW_SECS);
        if !self.windows.contains_key(key) && self.windows.len() >= OBLIGATION_KEYS {
            self.windows.retain(|_, (start, _)| *start == window);
            if self.windows.len() >= OBLIGATION_KEYS {
                return false;
            }
        }
        let entry = self.windows.entry(key.clone()).or_insert((window, 0));
        if entry.0 != window {
            *entry = (window, 0);
        }
        if entry.1 >= OBLIGATION_LIMIT {
            return false;
        }
        entry.1 = entry.1.saturating_add(1);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// S-1-5-21-7-8-9-`rid` ([MS-DTYP] 2.4.2.4 layout; hand-made).
    fn sid(rid: u32) -> pdp::PrincipalId {
        dtyp::Sid::new(dtyp::SECURITY_NT_AUTHORITY, &[21, 7, 8, 9, rid]).unwrap()
    }

    // The limiter's own test (`udp_per_source_and_global_limits`) moved with
    // it to crates/rate-limit (task DN3).

    /// docs/questions/Q-275 item 5 (A-60): the daemon's UDP limits are 32
    /// datagrams per source and 2048 in all per one-second window — the same
    /// numbers before and after the limiter moved to crate rate-limit (DN3:
    /// "no behaviour change in kdc").
    #[test]
    fn the_udp_limits_are_the_daemons_constants() {
        assert_eq!(
            UDP_LIMITS,
            SourceLimits {
                per_source: 32,
                global: 2048,
                window: Duration::from_secs(1),
            }
        );
    }

    /// docs/11 §8: each key gets its share per window; another key is
    /// unaffected; a new window starts again.
    #[test]
    fn obligation_limit_per_key() {
        let mut limiter = ObligationLimiter::new();
        let key = RlKey {
            principal: sid(1101),
            class: pdp::ActionClass::Kerberos,
        };
        let other = RlKey {
            principal: sid(1102),
            class: pdp::ActionClass::Kerberos,
        };
        let now = KerberosTime::new(2026, 11, 13, 10, 0, 0).unwrap();
        for _ in 0..OBLIGATION_LIMIT {
            assert!(limiter.admit(&key, &now));
        }
        assert!(!limiter.admit(&key, &now));
        assert!(limiter.admit(&other, &now));
        let next = KerberosTime::new(2026, 11, 13, 10, 1, 0).unwrap();
        assert!(limiter.admit(&key, &next));
    }
}
