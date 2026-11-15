//! The PDP's `RateLimit` obligation for LDAP operations (docs/11 §8; docs/49
//! §10.2: "`Obligation::RateLimit(RlKey{principal, Directory})` — the
//! engine, through a trait the daemon supplies").
//!
//! docs/11 §8 gives the obligation, not its numbers, so they are constants
//! in the daemon (Q-230 item 4 → A-60) — the same values and the same
//! fixed-window scheme as the kdc daemon's obligation limiter (docs/questions
//! Q-275 item 5, A-69): a counter per key that starts again at every new
//! window of the request's `now`, a bounded table, and a refused new key
//! when the table stays full (fail closed — a refusal is `busy`, crates/ldap
//! engine.rs; Q-190 item 4).
//!
//! Spec: docs/11 §2 ("the PEP must honour obligations"), §8; docs/49 §10.2;
//! docs/questions Q-230 item 4 (A-60), Q-275 item 5 (A-69).

use krb_proto::KerberosTime;
use ldap::RateLimiter;
use pdp::RlKey;
use std::collections::HashMap;

/// Requests one `RlKey` may make per window. Project choice (the kdc
/// daemon's value, Q-275 item 5).
pub const OBLIGATION_LIMIT: u32 = 60;

/// The obligation window, in seconds of the request's `now`. Project choice.
pub const OBLIGATION_WINDOW_SECS: i64 = 60;

/// Most keys tracked at once. Project bound (docs/CLEAN-ROOM.md).
pub const OBLIGATION_KEYS: usize = 4096;

/// The `RateLimit` obligation's state, owned by the LDAP engine thread.
/// Spec: module documentation.
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
    /// Spec: docs/11 §8; crates/ldap inputs.rs (`admit`: "`false` refuses
    /// it").
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
    use pdp::ActionClass;

    fn key(rid: u32) -> RlKey {
        RlKey {
            principal: dtyp::Sid::new(dtyp::SECURITY_NT_AUTHORITY, &[21, 7, 8, 9, rid]).unwrap(),
            class: ActionClass::Directory,
        }
    }

    /// docs/11 §8 (the obligation is honoured): a key past its window's
    /// limit is refused while another key goes on; a new window starts
    /// again.
    #[test]
    fn per_key_fixed_windows() {
        let mut limiter = ObligationLimiter::new();
        let t0 = KerberosTime::new(2026, 11, 13, 10, 0, 0).unwrap();
        let t1 = KerberosTime::new(2026, 11, 13, 10, 1, 0).unwrap();
        for _ in 0..OBLIGATION_LIMIT {
            assert!(limiter.admit(&key(1), &t0));
        }
        assert!(!limiter.admit(&key(1), &t0));
        assert!(limiter.admit(&key(2), &t0));
        assert!(limiter.admit(&key(1), &t1));
    }
}
