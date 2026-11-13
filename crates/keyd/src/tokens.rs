//! One-time tokens that bind issuance to a completed authentication: the
//! AuthnProof exchange id (AS), the TGS context id, the FAST armor id of
//! an opened AS armor (docs/48 §2.3), and the service-context id of a
//! verified service ticket (docs/49 §3.3, A-46).
//!
//! Each token is 128 random bits from the entropy source, bound to the
//! calling process and to the principal, short-lived, and consumed on first
//! presentation. Expired and consumed entries are removed, and any session
//! key an entry held is zeroized (krb-crypto `ProtocolKey` wipes on drop).
//! Tables are BOUNDED: when full of live entries, a new token is refused
//! (fail closed) rather than evicting a live one.
//!
//! Lookup uses an ordinary hash map. A timing difference there could reveal
//! information about a token only to an authenticated caller, and a token is
//! useless to any caller other than the one it is bound to; tokens are
//! random, short-lived and single-use (documented residual).
//!
//! Spec: docs/10 §8 (state machines; tokens short-lived, single-use,
//! caller-bound), D36; docs/25 §2 principle 3 (per-session access); docs/48
//! §2.3 (armor id), §9.1 I4; docs/49 §3.3 (service ctx id).

use crate::authz::CallerId;
use core::fmt;
use std::collections::HashMap;

/// Length of a token id in octets (128 bits).
pub const TOKEN_ID_LENGTH: usize = 16;

/// The AS exchange token returned by `verify_preauth` inside an
/// [`crate::AuthnProof`]. Not secret by itself: it is useless to any caller
/// other than the one it was issued to. Spec: docs/10 §4 (`exchange_id`).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExchangeId([u8; TOKEN_ID_LENGTH]);

/// The TGS context token returned by `open_and_verify_tgt`.
/// Spec: docs/10 §5 (`ctx_id`).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CtxId([u8; TOKEN_ID_LENGTH]);

/// The FAST armor token returned by `open_fast_armor`: it names the armor
/// key and the inner-request facts keyd holds for one armored AS
/// conversation. Not secret by itself (useless to any other caller); the
/// armor key it names never leaves keyd.
/// Spec: docs/48 §2.3 (`armor_id: ArmorId`), §9.1 I4.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ArmorId([u8; TOKEN_ID_LENGTH]);

/// The service-context token returned by `open_and_verify_service_ticket`:
/// it names the session key (and authenticator subkey) of one verified
/// AP-REQ, which keyd holds for the later GSS steps (task L6b: `seal_ap_rep`;
/// phase 2: wrap / unwrap). Not secret by itself (useless to any other
/// caller); the keys it names never leave keyd.
/// Spec: docs/49 §3.3 (`ServiceContext { ctx_id, … }`); docs/questions/Q-165
/// item 2 (decided A-46).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ServiceCtxId([u8; TOKEN_ID_LENGTH]);

macro_rules! token_id {
    ($ty:ident) => {
        impl $ty {
            /// Rebuild a token id received back from the caller (e.g. by the
            /// IPC layer). Spec: docs/10 §8.
            pub const fn from_bytes(bytes: [u8; TOKEN_ID_LENGTH]) -> Self {
                $ty(bytes)
            }

            /// The token octets.
            pub const fn as_bytes(&self) -> &[u8; TOKEN_ID_LENGTH] {
                &self.0
            }
        }

        impl fmt::Debug for $ty {
            /// Only a short prefix, enough to correlate in tests.
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(
                    f,
                    concat!(stringify!($ty), "({:02x}{:02x}..)"),
                    self.0[0], self.0[1]
                )
            }
        }
    };
}

token_id!(ExchangeId);
token_id!(CtxId);
token_id!(ArmorId);
token_id!(ServiceCtxId);

/// Why a token could not be redeemed (audit detail only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TokenRefusal {
    Unknown,
    Expired,
    CallerMismatch,
}

/// A bounded table of one-time tokens with values of type `V`.
pub(crate) struct TokenTable<V> {
    entries: HashMap<[u8; TOKEN_ID_LENGTH], Entry<V>>,
    capacity: usize,
}

struct Entry<V> {
    caller: CallerId,
    expires_at: i64,
    value: V,
}

impl<V> TokenTable<V> {
    pub(crate) fn new(capacity: usize) -> Self {
        TokenTable {
            entries: HashMap::new(),
            capacity,
        }
    }

    /// Remove every expired entry (dropping its value zeroizes held keys).
    /// Spec: docs/10 D36.
    pub(crate) fn sweep(&mut self, now: i64) {
        self.entries.retain(|_, e| now <= e.expires_at);
    }

    /// Insert a fresh token. Refuses (returns `false`) when the table is full
    /// of live entries or the id collides — never evicts a live entry.
    /// Spec: docs/10 D36; AGENTS.md §6 (bounded, fail closed).
    pub(crate) fn insert(
        &mut self,
        id: [u8; TOKEN_ID_LENGTH],
        caller: CallerId,
        expires_at: i64,
        value: V,
        now: i64,
    ) -> bool {
        self.sweep(now);
        if self.entries.len() >= self.capacity || self.entries.contains_key(&id) {
            return false;
        }
        self.entries.insert(
            id,
            Entry {
                caller,
                expires_at,
                value,
            },
        );
        true
    }

    /// Consume a token. The entry is removed on ANY presentation — a token
    /// presented by the wrong caller is treated as leaked and destroyed
    /// (fail closed). Returns the value only if the token is live and bound
    /// to `caller`. Spec: docs/10 §8 ("one-time, caller-bound"), D36.
    pub(crate) fn take(
        &mut self,
        id: &[u8; TOKEN_ID_LENGTH],
        caller: &CallerId,
        now: i64,
    ) -> Result<V, TokenRefusal> {
        let entry = self.entries.remove(id);
        self.sweep(now);
        let entry = entry.ok_or(TokenRefusal::Unknown)?;
        if now > entry.expires_at {
            return Err(TokenRefusal::Expired);
        }
        if entry.caller != *caller {
            return Err(TokenRefusal::CallerMismatch);
        }
        Ok(entry.value)
    }

    /// Look at a live token without consuming it — for a conversation token
    /// that more than one step uses before it is consumed (the FAST armor id:
    /// `verify_preauth` uses it, `issue_as_rep` or `seal_fast_error` consumes
    /// it; docs/48 §2.3). The same refusals as [`Self::take`], and the same
    /// fail-closed rule: an expired token, or one presented by the wrong
    /// caller (treated as leaked), is removed. Expired entries are swept.
    /// Spec: docs/10 §8 ("one-time, caller-bound"), D36; docs/48 §2.3, §9.1
    /// I4.
    pub(crate) fn peek_mut(
        &mut self,
        id: &[u8; TOKEN_ID_LENGTH],
        caller: &CallerId,
        now: i64,
    ) -> Result<&mut V, TokenRefusal> {
        let refusal = match self.entries.get(id) {
            None => Some(TokenRefusal::Unknown),
            Some(entry) if now > entry.expires_at => Some(TokenRefusal::Expired),
            Some(entry) if entry.caller != *caller => Some(TokenRefusal::CallerMismatch),
            Some(_) => None,
        };
        if let Some(refusal) = refusal {
            self.entries.remove(id);
            self.sweep(now);
            return Err(refusal);
        }
        // The entry is live at `now`, so the sweep keeps it.
        self.sweep(now);
        self.entries
            .get_mut(id)
            .map(|entry| &mut entry.value)
            .ok_or(TokenRefusal::Unknown)
    }

    /// Remove every entry (live or not) whose value satisfies `stale`;
    /// dropping a value zeroizes any key it holds. Used when the key set a
    /// token was issued for is destroyed: such a token is no longer valid.
    /// Spec: docs/10 §8, §12 I4; docs/questions/Q-115 (A-35).
    pub(crate) fn discard_where(&mut self, mut stale: impl FnMut(&V) -> bool) {
        self.entries.retain(|_, e| !stale(&e.value));
    }

    /// Number of live-or-unswept entries.
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authz::Role;

    const A: CallerId = CallerId {
        uid: 1,
        role: Role::Kdc,
    };
    const B: CallerId = CallerId {
        uid: 2,
        role: Role::Kdc,
    };

    /// docs/10 D36: single use.
    #[test]
    fn token_is_single_use() {
        let mut t = TokenTable::new(4);
        assert!(t.insert([1; 16], A, 100, "v", 0));
        assert_eq!(t.take(&[1; 16], &A, 50), Ok("v"));
        assert_eq!(t.take(&[1; 16], &A, 50), Err(TokenRefusal::Unknown));
    }

    /// docs/10 D36: short-lived; expired entries are removed.
    #[test]
    fn expired_token_is_refused_and_removed() {
        let mut t = TokenTable::new(4);
        assert!(t.insert([1; 16], A, 100, (), 0));
        assert!(t.insert([2; 16], A, 100, (), 0));
        assert_eq!(t.take(&[1; 16], &A, 101), Err(TokenRefusal::Expired));
        // The sweep removed the other expired entry too.
        assert_eq!(t.len(), 0);
        assert_eq!(t.take(&[1; 16], &A, 101), Err(TokenRefusal::Unknown));
    }

    /// docs/10 §8: caller-bound; a wrong-caller presentation destroys it.
    #[test]
    fn token_bound_to_caller() {
        let mut t = TokenTable::new(4);
        assert!(t.insert([1; 16], A, 100, (), 0));
        assert_eq!(t.take(&[1; 16], &B, 1), Err(TokenRefusal::CallerMismatch));
        assert_eq!(t.take(&[1; 16], &A, 1), Err(TokenRefusal::Unknown));
    }

    /// A-35 (Q-115): tokens of a destroyed key set are discarded, others
    /// stay redeemable.
    #[test]
    fn discard_where_removes_only_matching_entries() {
        let mut t = TokenTable::new(4);
        assert!(t.insert([1; 16], A, 100, 7u8, 0));
        assert!(t.insert([2; 16], A, 100, 8u8, 0));
        t.discard_where(|v| *v == 7);
        assert_eq!(t.len(), 1);
        assert_eq!(t.take(&[1; 16], &A, 1), Err(TokenRefusal::Unknown));
        assert_eq!(t.take(&[2; 16], &A, 1), Ok(8));
    }

    /// docs/48 §2.3: a peek leaves a live, caller-bound token in place; an
    /// expired one or a wrong-caller presentation removes it, as `take` does.
    #[test]
    fn peek_keeps_a_live_token_and_removes_a_refused_one() {
        let mut t = TokenTable::new(4);
        assert!(t.insert([1; 16], A, 100, 5u8, 0));
        *t.peek_mut(&[1; 16], &A, 1).unwrap() += 1;
        assert_eq!(t.peek_mut(&[1; 16], &A, 2).copied(), Ok(6));
        assert_eq!(t.take(&[1; 16], &A, 3), Ok(6));

        assert!(t.insert([2; 16], A, 100, 0u8, 0));
        assert_eq!(
            t.peek_mut(&[2; 16], &B, 1).copied(),
            Err(TokenRefusal::CallerMismatch)
        );
        assert_eq!(t.take(&[2; 16], &A, 1), Err(TokenRefusal::Unknown));

        assert!(t.insert([3; 16], A, 100, 0u8, 0));
        assert_eq!(
            t.peek_mut(&[3; 16], &A, 101).copied(),
            Err(TokenRefusal::Expired)
        );
        assert_eq!(t.len(), 0);
        assert_eq!(
            t.peek_mut(&[3; 16], &A, 1).copied(),
            Err(TokenRefusal::Unknown)
        );
    }

    /// Bounded: full of live entries -> refuse; expired entries make room.
    #[test]
    fn table_is_bounded() {
        let mut t = TokenTable::new(2);
        assert!(t.insert([1; 16], A, 10, (), 0));
        assert!(t.insert([2; 16], A, 20, (), 0));
        assert!(!t.insert([3; 16], A, 30, (), 5));
        // Collision with a live id is refused.
        assert!(!t.insert([2; 16], A, 30, (), 5));
        // After the first expires there is room again.
        assert!(t.insert([3; 16], A, 30, (), 11));
        assert_eq!(t.len(), 2);
    }
}
