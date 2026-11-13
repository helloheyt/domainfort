//! Rate limits of the daemon: the per-source and global UDP limits in front
//! of the engine (docs/50 R50-9, §4.1; Q-223 → A-57 option (a)), and the
//! PDP's `RateLimit` obligation (docs/11 §8; docs/50 §4.1 "obligations — the
//! daemon's `RateLimiter` implements the PDP's `RlKey`").
//!
//! docs/50 names these limits without a number, so they are constants in
//! the daemon (Q-230 item 4 → A-60), listed in docs/questions/Q-275 item 5.
//! Both use fixed windows: a counter per key that starts again at every new
//! window — a simple, bounded scheme (no clock-dependent decay to get
//! wrong).
//!
//! Spec: docs/50 R50-9, §4.1; docs/02 §2 (CLDAP: "rate limiting per source,
//! listening on internal interfaces only"); docs/07 §1; docs/11 §2, §8;
//! docs/questions/Q-223 (A-57), Q-230 item 4 (A-60).

use core::net::IpAddr;
use core::time::Duration;
use kdc::RateLimiter;
use krb_proto::KerberosTime;
use pdp::RlKey;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

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

/// The UDP limits.
/// Spec: docs/50 §4.1; docs/questions/Q-223 (A-57).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpLimits {
    /// Datagrams per source address per window.
    pub per_source: u32,
    /// Datagrams from all sources per window.
    pub global: u32,
    /// The window.
    pub window: Duration,
}

impl UdpLimits {
    /// The daemon's constants.
    pub const DEFAULT: UdpLimits = UdpLimits {
        per_source: UDP_PER_SOURCE_PER_SECOND,
        global: UDP_GLOBAL_PER_SECOND,
        window: UDP_WINDOW,
    };
}

#[derive(Debug)]
struct SourceWindow {
    started: Instant,
    total: u32,
    per_source: HashMap<IpAddr, u32>,
}

/// The UDP admission check, shared by every UDP socket of the daemon.
///
/// A datagram is admitted when its source has had fewer than `per_source`
/// datagrams admitted in the current window and all sources fewer than
/// `global`. Only admitted datagrams create entries, so the table never
/// holds more than `global` sources (bounded, AGENTS.md §6). The source
/// address of a UDP datagram can be forged (tokio `UdpSocket::recv_from`:
/// "should not be trusted"), so the per-source limit is a weak defence
/// alone (docs/50 §4.1); the global budget and the internal-only binding
/// carry the rest (Q-223 option (a)).
///
/// Spec: docs/50 §4.1; docs/questions/Q-223 (A-57).
#[derive(Debug)]
pub struct SourceLimiter {
    limits: UdpLimits,
    state: Mutex<SourceWindow>,
}

impl SourceLimiter {
    /// A limiter with `limits`, its first window starting `now`.
    #[must_use]
    pub fn new(limits: UdpLimits, now: Instant) -> SourceLimiter {
        SourceLimiter {
            limits,
            state: Mutex::new(SourceWindow {
                started: now,
                total: 0,
                per_source: HashMap::new(),
            }),
        }
    }

    /// Admit one datagram from `source` at `now`, or refuse it (drop).
    /// Spec: docs/50 §4.1; docs/questions/Q-223 (A-57).
    pub fn admit(&self, source: IpAddr, now: Instant) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        if now.saturating_duration_since(state.started) >= self.limits.window {
            state.started = now;
            state.total = 0;
            state.per_source.clear();
        }
        if state.total >= self.limits.global {
            return false;
        }
        let count = state.per_source.entry(source).or_insert(0);
        if *count >= self.limits.per_source {
            return false;
        }
        *count = count.saturating_add(1);
        state.total = state.total.saturating_add(1);
        true
    }
}

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
    use core::net::Ipv4Addr;

    /// S-1-5-21-7-8-9-`rid` ([MS-DTYP] 2.4.2.4 layout; hand-made).
    fn sid(rid: u32) -> pdp::PrincipalId {
        dtyp::Sid::new(dtyp::SECURITY_NT_AUTHORITY, &[21, 7, 8, 9, rid]).unwrap()
    }

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
    }

    /// docs/50 §4.1 (a limiter per source + a global reply budget; Q-223
    /// option (a)): a source past its share is dropped while others go on;
    /// all sources together stop at the global budget; a new window starts
    /// again.
    #[test]
    fn udp_per_source_and_global_limits() {
        let start = Instant::now();
        let limits = UdpLimits {
            per_source: 3,
            global: 5,
            window: Duration::from_secs(1),
        };
        let limiter = SourceLimiter::new(limits, start);
        for _ in 0..3 {
            assert!(limiter.admit(ip(1), start));
        }
        assert!(!limiter.admit(ip(1), start), "per-source share used");
        assert!(limiter.admit(ip(2), start));
        assert!(limiter.admit(ip(3), start));
        assert!(!limiter.admit(ip(4), start), "global budget used");
        let later = start + Duration::from_secs(1);
        assert!(limiter.admit(ip(1), later), "a new window");
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
