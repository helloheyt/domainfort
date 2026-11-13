//! The TGS authenticator replay cache.
//!
//! RFC 4120 3.2.3: the server "MUST utilize a replay cache to remember any
//! authenticator presented within the allowable clock skew", storing "at
//! least the server name, along with the client name, time, and microsecond
//! fields", and a match is KRB_AP_ERR_REPEAT. The rejection is restricted to
//! the same client principal to the same server.
//!
//! Time window: an authenticator with client time `ctime` can only pass the
//! skew check while `now <= ctime + skew`, so an entry is kept exactly until
//! then and evicted afterwards (entries older than the skew window).
//!
//! Bounded, and FAIL CLOSED when full: if the cache is full of unexpired
//! entries, a new authenticator is REJECTED rather than evicting a live
//! entry. Evicting a live entry would let that authenticator be replayed;
//! RFC 4120 3.2.3 says a server that "loses track of authenticators presented
//! within the allowable clock skew ... MUST reject all requests until the
//! clock skew interval has passed". The trade-off is a denial-of-service
//! window: a flood of distinct valid authenticators (which requires valid
//! TGTs) can fill the cache and make keyd refuse TGS requests until entries
//! age out (at most one skew window). Capacity is configurable (D33, load ⚠
//! to be measured in the lab).
//!
//! Spec: RFC 4120 3.2.3, §10; docs/10 D33; docs/30 §7, D128.

use krb_proto::{PrincipalName, Realm};
use std::collections::HashMap;

/// The replay-cache key: server name, client name, time and microseconds.
/// Spec: RFC 4120 3.2.3.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ReplayKey {
    pub(crate) server_realm: Realm,
    pub(crate) server: PrincipalName,
    pub(crate) client_realm: Realm,
    pub(crate) client: PrincipalName,
    pub(crate) ctime: i64,
    pub(crate) cusec: u32,
}

/// Why an authenticator was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReplayRefusal {
    /// Already seen. Spec: RFC 4120 3.2.3 (KRB_AP_ERR_REPEAT).
    Replay,
    /// Full of unexpired entries — fail closed.
    Full,
}

/// Bounded, time-windowed replay cache. Values are the last second at which
/// the entry can still matter (`ctime + skew`).
pub(crate) struct ReplayCache {
    entries: HashMap<ReplayKey, i64>,
    capacity: usize,
}

impl ReplayCache {
    pub(crate) fn new(capacity: usize) -> Self {
        ReplayCache {
            entries: HashMap::new(),
            capacity,
        }
    }

    /// Check `key` and record it. Call only after every other check passed,
    /// so only authenticated authenticators occupy the cache.
    /// Spec: RFC 4120 3.2.3; docs/10 D33.
    pub(crate) fn check_and_insert(
        &mut self,
        key: ReplayKey,
        skew_secs: u32,
        now: i64,
    ) -> Result<(), ReplayRefusal> {
        if self.entries.contains_key(&key) {
            return Err(ReplayRefusal::Replay);
        }
        if self.entries.len() >= self.capacity {
            // Evict only entries older than the skew window.
            self.entries.retain(|_, keep_until| now <= *keep_until);
        }
        if self.entries.len() >= self.capacity {
            return Err(ReplayRefusal::Full);
        }
        let keep_until = key.ctime + i64::from(skew_secs);
        self.entries.insert(key, keep_until);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(client: &str, ctime: i64, cusec: u32) -> ReplayKey {
        let realm = Realm::new("EXAMPLE.ORG").unwrap();
        ReplayKey {
            server_realm: realm.clone(),
            server: PrincipalName {
                name_type: 2,
                name_string: vec![
                    krb_proto::KerberosString::new("krbtgt").unwrap(),
                    realm.clone(),
                ],
            },
            client_realm: realm,
            client: PrincipalName {
                name_type: 1,
                name_string: vec![krb_proto::KerberosString::new(client).unwrap()],
            },
            ctime,
            cusec,
        }
    }

    /// RFC 4120 3.2.3: a matching tuple is a replay; other clients with the
    /// same time are not affected.
    #[test]
    fn replay_detected_per_client() {
        let mut c = ReplayCache::new(8);
        assert_eq!(c.check_and_insert(key("alice", 1000, 5), 300, 1000), Ok(()));
        assert_eq!(
            c.check_and_insert(key("alice", 1000, 5), 300, 1001),
            Err(ReplayRefusal::Replay)
        );
        assert_eq!(c.check_and_insert(key("bob", 1000, 5), 300, 1001), Ok(()));
        assert_eq!(c.check_and_insert(key("alice", 1000, 6), 300, 1001), Ok(()));
    }

    /// Full of live entries -> refuse (fail closed); once entries are older
    /// than the skew window they are evicted to make room.
    #[test]
    fn full_cache_fails_closed_then_ages_out() {
        let mut c = ReplayCache::new(2);
        assert_eq!(c.check_and_insert(key("a", 1000, 0), 300, 1000), Ok(()));
        assert_eq!(c.check_and_insert(key("b", 1000, 0), 300, 1000), Ok(()));
        assert_eq!(
            c.check_and_insert(key("c", 1100, 0), 300, 1100),
            Err(ReplayRefusal::Full)
        );
        // At 1300 the entries (kept until 1300) are still live.
        assert_eq!(
            c.check_and_insert(key("c", 1300, 0), 300, 1300),
            Err(ReplayRefusal::Full)
        );
        // At 1301 they are outside the window and are evicted.
        assert_eq!(c.check_and_insert(key("c", 1301, 0), 300, 1301), Ok(()));
    }
}
