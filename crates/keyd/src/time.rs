//! Time arithmetic on caller-supplied KerberosTime values.
//!
//! keyd never reads a clock: every operation takes `now` from the caller, so
//! behaviour is deterministic and testable. Residual: keyd therefore trusts
//! the caller's clock; the integrity of the system time source is the
//! platform's (RFC 4120 §1.6 / §10: clock synchronization "MUST itself be
//! secured").
//!
//! Comparisons (clock skew, lifetimes, token expiry) need differences in
//! seconds on one scale: [`kerberos_time_seconds`], seconds since
//! 0000-01-01T00:00:00Z on the proleptic Gregorian calendar. It lives in the
//! crypto-free `keyd-types` crate, which the KDC, the LDAP engine and the
//! directory PIP share (D182; decision A-63), and is re-exported here; the
//! skew comparison keyd uses internally stays here.
//!
//! Spec: RFC 4120 5.2.3 (KerberosTime is UTC, whole seconds), §1.6, §10.

pub use keyd_types::kerberos_time_seconds;

/// `true` if `a` and `b` differ by at most `skew_secs` seconds.
/// Spec: RFC 4120 3.2.3 ("differ by more than the allowable clock skew").
pub(crate) fn within_skew(a: i64, b: i64, skew_secs: u32) -> bool {
    (a - b).abs() <= i64::from(skew_secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skew_window_is_inclusive() {
        assert!(within_skew(100, 400, 300));
        assert!(within_skew(400, 100, 300));
        assert!(!within_skew(100, 401, 300));
    }
}
