//! The retransmit cache: replies to recently processed, successful requests,
//! resent when the identical request arrives again.
//!
//! RFC 4120 3.1.2: "the KDC MUST be prepared to retransmit responses in case
//! they are lost. If a KDC receives a request identical to one it has
//! recently processed successfully, the KDC MUST respond with a KRB_AS_REP
//! message rather than a replay error. In order to reduce ciphertext given to
//! a potential attacker, KDCs MAY send the same response generated when the
//! request was first handled. KDCs MUST obey this replay behavior even if the
//! actual transport in use is reliable." 3.3.2 applies the same to the TGS.
//!
//! Without this cache an identical TGS-REQ would be refused: keyd's replay
//! cache remembers its authenticator (D33). That matters most after
//! KRB_ERR_RESPONSE_TOO_BIG, when the client resends the same request over
//! TCP (RFC 4120 7.2.1).
//!
//! The key is the exact request octets; only a byte-identical request gets
//! the stored reply, which carries no new ticket and no new session key. An
//! entry lives for keyd's clock skew — the window in which keyd's replay
//! cache would refuse the same authenticator. The cache is bounded in entries
//! and in octets; when it is full of live entries a new reply is simply not
//! stored (a later identical request is then processed again and, for a TGS,
//! refused by keyd's replay cache — fail closed, documented residual).
//!
//! Spec: RFC 4120 3.1.2, 3.3.2, 7.2.1; docs/10 D33; AGENTS.md §6 (bounded).

use crate::accounts::NamedPrincipal;
use crate::audit::Exchange;
use crate::krb_error::ErrorContext;
use std::collections::HashMap;

/// What the KDC kept about a successful reply.
#[derive(Debug, Clone)]
pub(crate) struct StoredReply {
    /// The encoded AS-REP / TGS-REP.
    pub(crate) reply: Vec<u8>,
    /// The error context, should the reply be too big for UDP again.
    pub(crate) error: ErrorContext,
    /// Audit names of the original request.
    pub(crate) exchange: Exchange,
    pub(crate) client: Option<NamedPrincipal>,
    pub(crate) service: Option<NamedPrincipal>,
}

struct Entry {
    stored: StoredReply,
    expires_at: i64,
    octets: usize,
}

/// A bounded map from request octets to the reply sent.
/// Spec: RFC 4120 3.1.2.
pub(crate) struct RetransmitCache {
    entries: HashMap<Vec<u8>, Entry>,
    capacity: usize,
    max_octets: usize,
    octets: usize,
}

impl RetransmitCache {
    pub(crate) fn new(capacity: usize, max_octets: usize) -> Self {
        RetransmitCache {
            entries: HashMap::new(),
            capacity,
            max_octets,
            octets: 0,
        }
    }

    /// The stored reply for exactly `request`, if it has not expired at `now`
    /// (seconds on keyd's scale). Spec: RFC 4120 3.1.2.
    pub(crate) fn lookup(&self, request: &[u8], now: i64) -> Option<&StoredReply> {
        self.entries
            .get(request)
            .filter(|entry| now < entry.expires_at)
            .map(|entry| &entry.stored)
    }

    /// Store `stored` as the reply to `request` until `expires_at`. Expired
    /// entries are evicted first; if the bounds still do not allow it, the
    /// reply is not stored. Spec: RFC 4120 3.1.2; AGENTS.md §6.
    pub(crate) fn insert(
        &mut self,
        request: &[u8],
        stored: StoredReply,
        now: i64,
        expires_at: i64,
    ) {
        let octets = request.len().saturating_add(stored.reply.len());
        if octets > self.max_octets {
            return;
        }
        if let Some(old) = self.entries.remove(request) {
            self.octets = self.octets.saturating_sub(old.octets);
        }
        if self.entries.len() >= self.capacity
            || self.octets.saturating_add(octets) > self.max_octets
        {
            self.evict_expired(now);
        }
        if self.entries.len() >= self.capacity
            || self.octets.saturating_add(octets) > self.max_octets
        {
            return;
        }
        self.octets = self.octets.saturating_add(octets);
        self.entries.insert(
            request.to_vec(),
            Entry {
                stored,
                expires_at,
                octets,
            },
        );
    }

    fn evict_expired(&mut self, now: i64) {
        let mut freed = 0usize;
        self.entries.retain(|_, entry| {
            let live = now < entry.expires_at;
            if !live {
                freed = freed.saturating_add(entry.octets);
            }
            live
        });
        self.octets = self.octets.saturating_sub(freed);
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use krb_proto::Realm;

    fn stored(reply: &[u8]) -> StoredReply {
        StoredReply {
            reply: reply.to_vec(),
            error: ErrorContext::local(&Realm::new("EXAMPLE.ORG").unwrap()).unwrap(),
            exchange: Exchange::As,
            client: None,
            service: None,
        }
    }

    /// RFC 4120 3.1.2: an identical request gets the same reply while the
    /// entry is live; a different request does not.
    #[test]
    fn identical_request_only_while_live() {
        let mut cache = RetransmitCache::new(4, 1024);
        cache.insert(b"req", stored(b"rep"), 0, 10);
        assert_eq!(
            cache.lookup(b"req", 9).map(|s| s.reply.clone()),
            Some(b"rep".to_vec())
        );
        assert!(cache.lookup(b"req", 10).is_none());
        assert!(cache.lookup(b"req2", 0).is_none());
    }

    /// Bounded in entries and octets; expired entries make room
    /// (AGENTS.md §6).
    #[test]
    fn bounds() {
        let mut cache = RetransmitCache::new(2, 1024);
        cache.insert(b"a", stored(b"1"), 0, 10);
        cache.insert(b"b", stored(b"2"), 0, 20);
        cache.insert(b"c", stored(b"3"), 0, 30);
        assert_eq!(cache.len(), 2);
        assert!(cache.lookup(b"c", 0).is_none());
        // At t=10 the first entry has expired and is evicted for the new one.
        cache.insert(b"c", stored(b"3"), 10, 30);
        assert!(cache.lookup(b"c", 10).is_some());
        assert!(cache.lookup(b"a", 0).is_none());
        // Octet budget.
        let mut small = RetransmitCache::new(8, 8);
        small.insert(b"abcd", stored(b"efgh"), 0, 10);
        assert!(small.lookup(b"abcd", 0).is_some());
        small.insert(b"x", stored(b"y"), 0, 10);
        assert!(small.lookup(b"x", 0).is_none());
        small.insert(b"too", stored(b"large!"), 0, 10);
        assert!(small.lookup(b"too", 0).is_none());
    }
}
