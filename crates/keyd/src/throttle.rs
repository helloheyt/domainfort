//! The throttling hook of `verify_secret`.
//!
//! keyd consults the hook BEFORE any secret work (so a throttled attempt
//! costs no key derivation and reveals nothing secret) and reports every
//! outcome afterwards. The default [`FailureWindowThrottle`] refuses a
//! principal after `max_failures` failures within `window_secs`; its table
//! is bounded and, when full of live windows, it refuses principals it
//! cannot track (fail closed — an attacker must not escape throttling by
//! flooding the table). That fail-closed choice is a denial-of-service
//! trade-off for `verify_secret` callers, documented here.
//!
//! Spec: docs/10 §6 (`verify_secret` "constant-time, throttled"); docs/07 D19
//! (online guessing); AGENTS.md §6 (bounded, fail closed).

use crate::config::ThrottlePolicy;
use crate::model::PrincipalId;
use std::collections::HashMap;

/// Throttling hook for secret verification. `now` is seconds on keyd's time
/// scale ([`crate::kerberos_time_seconds`]).
///
/// Spec: docs/10 §6.
pub trait SecretThrottle {
    /// `false` refuses the attempt (keyd returns `Error::RateLimited`).
    fn admit(&mut self, principal: &PrincipalId, now: i64) -> bool;
    /// Report the outcome of an admitted attempt.
    fn record(&mut self, principal: &PrincipalId, success: bool, now: i64);
}

/// Failure-count-per-window throttle, bounded.
#[derive(Debug)]
pub struct FailureWindowThrottle {
    policy: ThrottlePolicy,
    /// principal -> (failures in window, window start)
    windows: HashMap<PrincipalId, (u32, i64)>,
}

impl FailureWindowThrottle {
    /// Spec: docs/10 §6.
    pub fn new(policy: ThrottlePolicy) -> Self {
        FailureWindowThrottle {
            policy,
            windows: HashMap::new(),
        }
    }

    fn window_live(&self, start: i64, now: i64) -> bool {
        now - start < i64::from(self.policy.window_secs)
    }

    fn sweep(&mut self, now: i64) {
        let window = i64::from(self.policy.window_secs);
        self.windows.retain(|_, (_, start)| now - *start < window);
    }
}

impl SecretThrottle for FailureWindowThrottle {
    fn admit(&mut self, principal: &PrincipalId, now: i64) -> bool {
        match self.windows.get(principal) {
            Some(&(failures, start)) if self.window_live(start, now) => {
                failures < self.policy.max_failures
            }
            Some(_) => {
                self.windows.remove(principal);
                true
            }
            None => {
                if self.windows.len() >= self.policy.capacity {
                    self.sweep(now);
                }
                // Untrackable principal while the table is full of live
                // windows: refuse (fail closed).
                self.windows.len() < self.policy.capacity
            }
        }
    }

    fn record(&mut self, principal: &PrincipalId, success: bool, now: i64) {
        if success {
            self.windows.remove(principal);
            return;
        }
        let live = match self.windows.get(principal) {
            Some(&(_, start)) => self.window_live(start, now),
            None => false,
        };
        if live {
            if let Some(entry) = self.windows.get_mut(principal) {
                entry.0 = entry.0.saturating_add(1);
            }
            return;
        }
        if self.windows.len() >= self.policy.capacity {
            self.sweep(now);
        }
        if self.windows.len() < self.policy.capacity || self.windows.contains_key(principal) {
            self.windows.insert(*principal, (1, now));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> ThrottlePolicy {
        ThrottlePolicy {
            max_failures: 2,
            window_secs: 60,
            capacity: 2,
        }
    }

    const P: PrincipalId = PrincipalId::from_bytes([1; 16]);
    const Q: PrincipalId = PrincipalId::from_bytes([2; 16]);
    const R: PrincipalId = PrincipalId::from_bytes([3; 16]);

    #[test]
    fn refuses_after_max_failures_in_window() {
        let mut t = FailureWindowThrottle::new(policy());
        assert!(t.admit(&P, 0));
        t.record(&P, false, 0);
        assert!(t.admit(&P, 1));
        t.record(&P, false, 1);
        assert!(!t.admit(&P, 2));
        // The window ends 60 s after it started.
        assert!(t.admit(&P, 60));
    }

    #[test]
    fn success_clears_failures() {
        let mut t = FailureWindowThrottle::new(policy());
        t.record(&P, false, 0);
        t.record(&P, true, 1);
        t.record(&P, false, 2);
        assert!(t.admit(&P, 3));
    }

    /// Bounded and fail closed when full of live windows.
    #[test]
    fn full_table_refuses_untracked_principals() {
        let mut t = FailureWindowThrottle::new(policy());
        t.record(&P, false, 0);
        t.record(&Q, false, 0);
        assert!(!t.admit(&R, 1));
        // Windows expire -> room again.
        assert!(t.admit(&R, 61));
    }
}
