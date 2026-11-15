#![forbid(unsafe_code)]
//! `rate-limit`: the per-source and global admission limiter of the network
//! fronts (build task DN3).
//!
//! [`SourceLimiter`] admits a datagram when its source has had fewer than
//! [`SourceLimits::per_source`] datagrams admitted in the current window and
//! all sources together fewer than [`SourceLimits::global`] — docs/50 §4.1's
//! "a rate limiter per source + a global reply budget" (Q-223 → A-57 option
//! (a)). It uses fixed windows: a counter per source that starts again at
//! every new window — a simple, bounded scheme (no clock-dependent decay to
//! get wrong).
//!
//! # Why a crate of its own
//!
//! It was kdc-daemon's UDP admission check (`kdc_daemon::rate`). dnsd (task
//! DN11) needs the same mechanism in front of its UDP socket, and docs/54
//! §6.7 asks for **one** mechanism — "move kdc-daemon's `SourceLimiter` to a
//! shared crate instead of a second copy" — because two implementations of
//! one limiter diverge (the C14 pattern, docs/52 §3.14). The type and its
//! test moved here **unchanged**; kdc-daemon re-exports them, so its
//! behaviour is the same (DN3: "no behaviour change in kdc").
//!
//! # What it does not hold
//!
//! * **No numbers.** [`SourceLimits`] has no default: every daemon states its
//!   own limits — the KDC's are its constants (docs/50 §4.1 names the limits
//!   without a number; Q-230 item 4 → A-60; Q-275 item 5), dnsd's will be its
//!   own (docs/54 §6.7 ⚠). A default here would give one daemon the other's
//!   numbers.
//! * **No key policy.** The key is the address the caller passes. The KDC
//!   passes the datagram's source address; docs/54 §6.7 counts IPv6 per /64
//!   prefix, which dnsd does by passing the prefix (docs/questions/Q-930).
//! * **No dependency.** std only — no network, crypto or store crate — so
//!   dnsd, which links no dirstore, krb-crypto or keyd (docs/54 §4.7), can
//!   link it (tests/leaf.rs).
//!
//! # Security
//!
//! Bounded: only admitted datagrams create entries, so the table never holds
//! more than `global` sources (docs/CLEAN-ROOM.md). Fail closed: a poisoned lock
//! refuses. The source address of a UDP datagram can be forged (tokio
//! `UdpSocket::recv_from`: "should not be trusted"), so the per-source limit
//! is a weak defence alone (docs/50 §4.1); the global budget and the
//! internal-only binding carry the rest (Q-223 option (a)).
//!
//! # Provenance
//!
//! Moved from this project's crates/kdc-daemon `src/rate.rs` (written from
//! docs/50 §4.1 and Q-223); placed per docs/54 §6.7 and §10 (DN3). No other
//! implementation consulted or recalled (docs/CLEAN-ROOM.md).
//!
//! Spec: docs/50 R50-9, §4.1; docs/02 §2 (CLDAP: "rate limiting per source,
//! listening on internal interfaces only"); docs/54 §6.7, §10 (DN3);
//! docs/questions/Q-223 (A-57), Q-230 item 4 (A-60).

use core::net::IpAddr;
use core::time::Duration;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

/// The limits of a [`SourceLimiter`]. No default: each daemon states its
/// own (crate documentation).
/// Spec: docs/50 §4.1; docs/questions/Q-223 (A-57).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceLimits {
    /// Datagrams per source address per window.
    pub per_source: u32,
    /// Datagrams from all sources per window.
    pub global: u32,
    /// The window.
    pub window: Duration,
}

#[derive(Debug)]
struct SourceWindow {
    started: Instant,
    total: u32,
    per_source: HashMap<IpAddr, u32>,
}

/// The admission check, shared by every socket of a daemon that holds it.
///
/// A datagram is admitted when its source has had fewer than `per_source`
/// datagrams admitted in the current window and all sources fewer than
/// `global`. Only admitted datagrams create entries, so the table never
/// holds more than `global` sources (bounded, docs/CLEAN-ROOM.md). The source
/// address of a UDP datagram can be forged (tokio `UdpSocket::recv_from`:
/// "should not be trusted"), so the per-source limit is a weak defence
/// alone (docs/50 §4.1); the global budget and the internal-only binding
/// carry the rest (Q-223 option (a)).
///
/// Spec: docs/50 §4.1; docs/questions/Q-223 (A-57); docs/54 §6.7.
#[derive(Debug)]
pub struct SourceLimiter {
    limits: SourceLimits,
    state: Mutex<SourceWindow>,
}

impl SourceLimiter {
    /// A limiter with `limits`, its first window starting `now`.
    #[must_use]
    pub fn new(limits: SourceLimits, now: Instant) -> SourceLimiter {
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

#[cfg(test)]
mod tests {
    use super::*;
    use core::net::Ipv4Addr;

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
    }

    /// docs/50 §4.1 (a limiter per source + a global reply budget; Q-223
    /// option (a)): a source past its share is dropped while others go on;
    /// all sources together stop at the global budget; a new window starts
    /// again. (Moved unchanged from crates/kdc-daemon src/rate.rs — task
    /// DN3.)
    #[test]
    fn udp_per_source_and_global_limits() {
        let start = Instant::now();
        let limits = SourceLimits {
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
}
