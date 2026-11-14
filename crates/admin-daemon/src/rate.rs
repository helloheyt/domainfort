//! The per-peer-uid limits of `admin.sock`: a connection quota and a request
//! rate (decision A-85 on docs/questions/Q-340 item 8: "a per-uid rate limit
//! in A9"; docs/50 §3.6: "a connection quota per uid … a rate limiter";
//! docs/21 D98: the management API has a rate limit).
//!
//! The peer uid comes from the kernel's peer credentials and is used **only**
//! here and as the `peer_uid` of admind's audit events — never as a subject:
//! who asks is decided by dird from the Kerberos tickets (docs/51 §5.1,
//! §5.3).
//!
//! # The numbers (project choices — docs/questions/Q-405)
//!
//! * [`MAX_CONNECTIONS_PER_UID`] = 4, [`MAX_CONNECTIONS`] = 16: an
//!   administrator's tool holds one connection (one request in flight per
//!   connection, R50-7); four leave room for a second tool and a monitor;
//!   the global bound keeps the admin group's members from holding more
//!   than a few frame buffers (288 KiB each) between them.
//! * [`REQUESTS_PER_WINDOW`] = 60 per [`RATE_WINDOW`] = 60 s per uid: every
//!   operation carries its own fresh AP-REQ (R51-10), so the legitimate rate
//!   is a person's or a script's, one per second at most; a peer above it
//!   gets the shared `Busy` (the connection is kept). This bounds what one
//!   local account can make dird and admind audit — each decoded request is
//!   gating there (Q-340 item 8) — at one event per second, far below what
//!   auditd acknowledges, so no local account can keep either window full.
//!   The same numbers and the same fixed-window scheme as dird's and the
//!   kdc's `RateLimit` obligation limiter (Q-275 item 5, Q-388 item 2).
//! * [`MAX_TRACKED_UIDS`] = 256: a bounded table (AGENTS.md §6); when it is
//!   full of uids active in the current window, a new uid is refused `Busy`
//!   (fail closed). Every request frame counts, `Ping` included.
//!
//! Spec: docs/50 §3.6; docs/51 §5.1, §7.5; docs/21 D98; A-85.

use core::time::Duration;
use std::collections::HashMap;
use std::time::Instant;

/// Connections one peer uid may hold at once. Project choice (Q-405).
pub const MAX_CONNECTIONS_PER_UID: usize = 4;

/// Connections all peers may hold at once. Project choice (Q-405).
pub const MAX_CONNECTIONS: usize = 16;

/// Requests one peer uid may send per [`RATE_WINDOW`]. Project choice
/// (Q-405).
pub const REQUESTS_PER_WINDOW: u32 = 60;

/// The rate window. Project choice (Q-405).
pub const RATE_WINDOW: Duration = Duration::from_secs(60);

/// Most peer uids the rate table tracks at once. Project bound (AGENTS.md
/// §6; Q-405).
pub const MAX_TRACKED_UIDS: usize = 256;

/// The limits of one admind (the daemon uses the constants above; tests
/// tighten them).
/// Spec: module documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// [`MAX_CONNECTIONS`].
    pub max_connections: usize,
    /// [`MAX_CONNECTIONS_PER_UID`].
    pub max_connections_per_uid: usize,
    /// [`REQUESTS_PER_WINDOW`].
    pub requests_per_window: u32,
    /// [`RATE_WINDOW`].
    pub rate_window: Duration,
    /// [`MAX_TRACKED_UIDS`].
    pub max_tracked_uids: usize,
}

impl Limits {
    /// The daemon's limits.
    pub const DEFAULT: Limits = Limits {
        max_connections: MAX_CONNECTIONS,
        max_connections_per_uid: MAX_CONNECTIONS_PER_UID,
        requests_per_window: REQUESTS_PER_WINDOW,
        rate_window: RATE_WINDOW,
        max_tracked_uids: MAX_TRACKED_UIDS,
    };
}

/// The per-uid request rate: a count per uid that starts again at every new
/// window (windows counted from the limiter's start, on the monotonic
/// clock), in a bounded table.
/// Spec: module documentation.
#[derive(Debug)]
pub struct RateLimiter {
    limit: u32,
    window: Duration,
    max_uids: usize,
    started: Instant,
    table: HashMap<u32, (u64, u32)>,
}

impl RateLimiter {
    /// A limiter of `limit` requests per `window` per uid, tracking at most
    /// `max_uids` uids.
    #[must_use]
    pub fn new(limit: u32, window: Duration, max_uids: usize) -> RateLimiter {
        RateLimiter {
            limit,
            window,
            max_uids,
            started: Instant::now(),
            table: HashMap::new(),
        }
    }

    /// The window `now` falls in.
    fn window_of(&self, now: Instant) -> u64 {
        let elapsed = now.saturating_duration_since(self.started).as_nanos();
        let window = self.window.as_nanos().max(1);
        u64::try_from(elapsed / window).unwrap_or(u64::MAX)
    }

    /// Count one request of `uid` at `now`: `false` refuses it (`Busy`).
    /// Spec: module documentation.
    pub fn admit(&mut self, uid: u32, now: Instant) -> bool {
        let window = self.window_of(now);
        if !self.table.contains_key(&uid) && self.table.len() >= self.max_uids {
            self.table.retain(|_, (start, _)| *start == window);
            if self.table.len() >= self.max_uids {
                return false;
            }
        }
        let entry = self.table.entry(uid).or_insert((window, 0));
        if entry.0 != window {
            *entry = (window, 0);
        }
        if entry.1 >= self.limit {
            return false;
        }
        entry.1 = entry.1.saturating_add(1);
        true
    }
}

/// The connection quota: connections held per uid and in all.
/// Spec: docs/50 §3.6 ("a connection quota per uid").
#[derive(Debug, Default)]
pub struct ConnectionQuota {
    per_uid: HashMap<u32, usize>,
    total: usize,
}

impl ConnectionQuota {
    /// Take a connection slot for `uid`, or `false` at either bound.
    pub fn acquire(&mut self, uid: u32, limits: &Limits) -> bool {
        let held = self.per_uid.get(&uid).copied().unwrap_or(0);
        if self.total >= limits.max_connections || held >= limits.max_connections_per_uid {
            return false;
        }
        self.per_uid.insert(uid, held.saturating_add(1));
        self.total = self.total.saturating_add(1);
        true
    }

    /// Give back a slot `uid` held.
    pub fn release(&mut self, uid: u32) {
        if let Some(held) = self.per_uid.get_mut(&uid) {
            *held = held.saturating_sub(1);
            if *held == 0 {
                self.per_uid.remove(&uid);
            }
            self.total = self.total.saturating_sub(1);
        }
    }

    /// Connections held in all.
    #[must_use]
    pub fn total(&self) -> usize {
        self.total
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// docs/50 §3.6; A-85 (Q-340 item 8): a uid past its window's limit is
    /// refused while another uid goes on; the next window starts again.
    #[test]
    fn per_uid_fixed_windows() {
        let mut limiter = RateLimiter::new(3, Duration::from_secs(60), 8);
        let t0 = Instant::now();
        for _ in 0..3 {
            assert!(limiter.admit(1000, t0));
        }
        assert!(!limiter.admit(1000, t0));
        assert!(limiter.admit(1001, t0));
        assert!(limiter.admit(1000, t0 + Duration::from_secs(61)));
    }

    /// AGENTS.md §6 (bounded table): a full table of active uids refuses a
    /// new uid; expired entries are dropped to make room.
    #[test]
    fn the_table_is_bounded() {
        let mut limiter = RateLimiter::new(5, Duration::from_secs(60), 2);
        let t0 = Instant::now();
        assert!(limiter.admit(1, t0));
        assert!(limiter.admit(2, t0));
        assert!(!limiter.admit(3, t0));
        assert!(limiter.admit(3, t0 + Duration::from_secs(61)));
    }

    /// docs/50 §3.6: the per-uid and the global connection bounds.
    #[test]
    fn connection_quota() {
        let limits = Limits {
            max_connections: 3,
            max_connections_per_uid: 2,
            ..Limits::DEFAULT
        };
        let mut quota = ConnectionQuota::default();
        assert!(quota.acquire(7, &limits));
        assert!(quota.acquire(7, &limits));
        assert!(!quota.acquire(7, &limits));
        assert!(quota.acquire(8, &limits));
        assert!(!quota.acquire(9, &limits), "global bound");
        quota.release(7);
        assert!(quota.acquire(9, &limits));
        assert_eq!(quota.total(), 3);
    }
}
