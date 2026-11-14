//! keyd configuration, validated once at construction (fail closed before any
//! key is touched).
//!
//! Defaults: the RFC 4120 §8.2 recommended KDC values where RFC 4120 gives
//! one (clock skew, minimum / maximum / renewable lifetime); otherwise this
//! project's documented choices (token lifetime, table capacities,
//! throttling), which operators tune.
//!
//! Spec: RFC 4120 §8.2; docs/10 §1 (EncType list, no weak variant), §8 / D36
//! (short-lived tokens), D33 (bounded replay cache); docs/25 §5 (minimalism);
//! docs/30 §2.6 (dangerous ticket options reduced by default); docs/48 §10.1
//! (armor table); decision A-34 (preauth throttle); docs/49 §3.3, A-46
//! (service-context table).
//!
//! Moved unchanged in meaning from keyd (D182; decision A-63). Encryption
//! types are carried as crypto-free identifiers ([`EncTypeId`]); keyd
//! converts them to its crypto profile's type internally.

use crate::enctype::{s2k_iteration_count, EncTypeId};
use crate::error::ConfigError;
use krb_proto::{Realm, TicketFlags};

/// Upper bound for every table capacity (memory bound, AGENTS.md §6).
pub const MAX_TABLE_CAPACITY: usize = 1 << 20;

/// Upper bound for the clock-skew window, in seconds.
pub const MAX_CLOCK_SKEW_SECS: u32 = 3_600;

/// Upper bound for the one-time token lifetime, in seconds (docs/10 D36:
/// "short (seconds)").
pub const MAX_TOKEN_LIFETIME_SECS: u32 = 300;

/// Ticket flags an operator MAY place in the allowed mask.
///
/// Everything else has no code path in phase 1, so config validation refuses
/// it: FORWARDED and PROXY (issuing forwarded / proxy tickets is delegation —
/// unconstrained delegation does not exist, docs/02 §3, docs/30 §4.3),
/// OK-AS-DELEGATE (tells clients to delegate), MAY-POSTDATE / POSTDATED /
/// INVALID (no postdating or VALIDATE path, RFC 4120 2.2, 2.4), and the
/// reserved bits 0 and 14-31 (RFC 4120 5.3).
///
/// Spec: RFC 4120 5.3 (TicketFlags), 2.1-2.8; docs/30 §2.6, §4.3.
pub const CONFIGURABLE_TICKET_FLAGS: TicketFlags = TicketFlags::FORWARDABLE
    .union(TicketFlags::PROXIABLE)
    .union(TicketFlags::RENEWABLE)
    .union(TicketFlags::INITIAL)
    .union(TicketFlags::PRE_AUTHENT)
    .union(TicketFlags::HW_AUTHENT)
    .union(TicketFlags::TRANSITED_POLICY_CHECKED);

/// The default allowed mask: renewable, initial, pre-authent,
/// transited-policy-checked. Denied by default: forwardable, forwarded,
/// proxiable, proxy, may-postdate, postdated, invalid, ok-as-delegate — and
/// hw-authent, which keyd has no evidence for (PA-ENC-TIMESTAMP is not a
/// hardware method, RFC 4120 2.1).
///
/// Spec: RFC 4120 5.3, 2.1; docs/30 §2.6.
pub const DEFAULT_ALLOWED_TICKET_FLAGS: TicketFlags = TicketFlags::RENEWABLE
    .union(TicketFlags::INITIAL)
    .union(TicketFlags::PRE_AUTHENT)
    .union(TicketFlags::TRANSITED_POLICY_CHECKED);

/// Ticket issuance policy that keyd enforces on every template.
///
/// Spec: RFC 4120 3.1.3, 3.3.3, §8.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TicketPolicy {
    /// Template flags must be a subset of this mask.
    pub allowed_flags: TicketFlags,
    /// Minimum ticket lifetime (endtime - starttime). RFC 4120 §8.2: 5
    /// minutes; RFC 4120 3.1.3 KDC_ERR_NEVER_VALID below it.
    pub min_lifetime_secs: u32,
    /// Maximum ticket lifetime. RFC 4120 §8.2: 1 day.
    pub max_lifetime_secs: u32,
    /// Maximum renewable lifetime (renew-till - starttime). RFC 4120 §8.2:
    /// 1 week.
    pub max_renewable_lifetime_secs: u32,
}

impl Default for TicketPolicy {
    /// Spec: RFC 4120 §8.2 (recommended KDC values); docs/30 §2.6.
    fn default() -> Self {
        TicketPolicy {
            allowed_flags: DEFAULT_ALLOWED_TICKET_FLAGS,
            min_lifetime_secs: 5 * 60,
            max_lifetime_secs: 24 * 60 * 60,
            max_renewable_lifetime_secs: 7 * 24 * 60 * 60,
        }
    }
}

/// Policy of the default `verify_secret` throttle (failures per principal in
/// a window). Spec: docs/10 §6 ("throttled").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThrottlePolicy {
    /// Failures allowed in one window before further attempts are refused.
    pub max_failures: u32,
    /// Window length in seconds.
    pub window_secs: u32,
    /// Principals tracked at once (bounded; when full of live windows,
    /// untracked principals are refused — fail closed).
    pub capacity: usize,
}

impl Default for ThrottlePolicy {
    /// This project's default choice (tunable): 5 failures per 5 minutes.
    fn default() -> Self {
        ThrottlePolicy {
            max_failures: 5,
            window_secs: 300,
            capacity: 4_096,
        }
    }
}

/// keyd configuration.
///
/// Spec: docs/10 §1, §8, D33, D36; RFC 4120 §8.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeydConfig {
    /// The realm this keyd serves. Phase 1 is single-realm: tickets are
    /// issued only for this realm (no cross-realm, docs/39).
    pub realm: Realm,
    /// Encryption types for long-term keys and session keys, in preference
    /// order. The first is used to seal tickets (RFC 4120 3.1.3: the ticket
    /// uses "the encryption type associated with the server principal's
    /// key"). Only the AES types exist (I5): an [`EncTypeId`] names no other
    /// (D182; A-63).
    pub enctypes: Vec<EncTypeId>,
    /// Acceptable clock skew in seconds. RFC 4120 §8.2: 5 minutes.
    pub clock_skew_secs: u32,
    /// Lifetime of AuthnProof / ctx tokens in seconds (docs/10 D36).
    pub token_lifetime_secs: u32,
    /// Bound of the AuthnProof table (docs/10 D36).
    pub max_authn_proofs: usize,
    /// Bound of the TGS context table (docs/10 D36).
    pub max_tgt_contexts: usize,
    /// Bound of the FAST armor table (`open_fast_armor`; docs/48 §9.1 I4,
    /// §10.1).
    pub max_armor_contexts: usize,
    /// Bound of the service-context table (`open_and_verify_service_ticket`:
    /// the session keys of unbound verified service tickets, held for the
    /// later GSS steps; docs/49 §3.3, A-46). An operation-bound verification
    /// (`verify_operation_ticket`) takes no entry (Q-523).
    pub max_service_contexts: usize,
    /// Bound of the replay cache (docs/10 D33).
    pub replay_cache_capacity: usize,
    /// Ticket template policy.
    pub ticket_policy: TicketPolicy,
    /// string-to-key parameters used by `set_secret` (four octets, RFC 3962
    /// §4 / RFC 8009 §4); `None` = the enctype default. Choosing a site
    /// iteration count is an operator decision (RFC 3962 §4 notes the
    /// default is not a recommendation for database keys).
    pub s2k_params: Option<[u8; 4]>,
    /// Cap on string-to-key iterations, enforced through krb-crypto's
    /// `max_iterations` inside keyd, and on `s2k_params` by
    /// [`KeydConfig::validate`] (RFC 3962 §4: such a limit "SHOULD be no less
    /// than 50,000").
    pub max_s2k_iterations: u32,
    /// Policy of the default `verify_secret` throttle.
    pub throttle: ThrottlePolicy,
    /// Policy of the per-principal failure throttle of `verify_preauth`
    /// (online password guessing through the AS exchange; decision A-34). A
    /// separate table from `throttle`, so the two callers' windows are
    /// configured independently.
    pub preauth_throttle: ThrottlePolicy,
}

impl KeydConfig {
    /// A configuration for `realm` with the defaults described on each field:
    /// enctypes aes256-cts-hmac-sha1-96 then aes128-cts-hmac-sha1-96
    /// (docs/02 §3; AES-SHA2 is opt-in pending client support, D8), RFC 4120
    /// §8.2 skew and lifetimes, 30-second tokens, bounded tables.
    ///
    /// Spec: RFC 4120 §8.2; docs/02 §3; docs/10 D33, D36.
    pub fn new(realm: Realm) -> Self {
        KeydConfig {
            realm,
            enctypes: vec![
                EncTypeId::Aes256CtsHmacSha196,
                EncTypeId::Aes128CtsHmacSha196,
            ],
            clock_skew_secs: 5 * 60,
            token_lifetime_secs: 30,
            max_authn_proofs: 1_024,
            max_tgt_contexts: 1_024,
            max_armor_contexts: 1_024,
            max_service_contexts: 1_024,
            replay_cache_capacity: 65_536,
            ticket_policy: TicketPolicy::default(),
            s2k_params: None,
            max_s2k_iterations: 50_000,
            throttle: ThrottlePolicy::default(),
            preauth_throttle: ThrottlePolicy::default(),
        }
    }

    /// Check every field; any inconsistency is refused (fail closed).
    ///
    /// Spec: docs/10 §1 (only the listed enctypes), D33, D36; RFC 4120 §8.2,
    /// 5.3; RFC 3962 §4.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.enctypes.is_empty() {
            return Err(ConfigError::EncTypes);
        }
        for (i, a) in self.enctypes.iter().enumerate() {
            if self.enctypes[i + 1..].contains(a) {
                return Err(ConfigError::EncTypes);
            }
        }
        if self.clock_skew_secs == 0 || self.clock_skew_secs > MAX_CLOCK_SKEW_SECS {
            return Err(ConfigError::ClockSkew);
        }
        if self.token_lifetime_secs == 0 || self.token_lifetime_secs > MAX_TOKEN_LIFETIME_SECS {
            return Err(ConfigError::TokenLifetime);
        }
        for capacity in [
            self.max_authn_proofs,
            self.max_tgt_contexts,
            self.max_armor_contexts,
            self.max_service_contexts,
            self.replay_cache_capacity,
            self.throttle.capacity,
            self.preauth_throttle.capacity,
        ] {
            if capacity == 0 || capacity > MAX_TABLE_CAPACITY {
                return Err(ConfigError::Capacity);
            }
        }
        let p = &self.ticket_policy;
        if p.min_lifetime_secs == 0
            || p.min_lifetime_secs > p.max_lifetime_secs
            || p.max_lifetime_secs > p.max_renewable_lifetime_secs
        {
            return Err(ConfigError::TicketLifetimes);
        }
        if !CONFIGURABLE_TICKET_FLAGS.contains(p.allowed_flags) {
            return Err(ConfigError::TicketFlags);
        }
        // The iteration count of RFC 3962 §4 / RFC 8009 §4 (the parameter
        // block is always four octets here, so only the cap can refuse it);
        // pinned to krb-crypto's count by keyd's tests (A-63).
        for enctype in &self.enctypes {
            let count = s2k_iteration_count(*enctype, self.s2k_params);
            if count > u64::from(self.max_s2k_iterations) {
                return Err(ConfigError::S2kParams);
            }
        }
        for throttle in [&self.throttle, &self.preauth_throttle] {
            if throttle.max_failures == 0 || throttle.window_secs == 0 {
                return Err(ConfigError::Throttle);
            }
        }
        Ok(())
    }

    /// The non-secret part of this configuration that other processes need
    /// — what `describe_config` returns.
    /// Spec: docs/50 §3.4 (`DescribeConfig`), §7.5 step 4.
    pub fn description(&self) -> ConfigDescription {
        ConfigDescription {
            realm: self.realm.clone(),
            enctypes: self.enctypes.clone(),
            clock_skew_secs: self.clock_skew_secs,
            token_lifetime_secs: self.token_lifetime_secs,
            ticket_policy: self.ticket_policy,
            s2k_params: self.s2k_params,
        }
    }
}

/// The non-secret part of keyd's configuration: what the kdc needs at start
/// (`KdcConfig::validate`: realm; planning tickets keyd will accept:
/// enctypes, clock skew, ticket policy) and what the directory process needs
/// to describe keyd's keys (realm, enctypes, string-to-key parameters —
/// docs/47 §7.3, R47-10). The result of `describe_config`.
///
/// Nothing here is secret: the realm and the policy are public, and the
/// enctypes and s2kparams are what the KDC itself sends to clients in
/// PA-ETYPE-INFO2 (RFC 4120 5.2.7.5). The table capacities and the throttle
/// policies are not described (minimalism, docs/25 §5).
///
/// Spec: docs/50 §3.4 (`DescribeConfig`: "realm, enctypes, clock_skew_secs,
/// token_lifetime_secs, ticket_policy"), §7.5 step 4; docs/47 §7.3 (R47-10);
/// RFC 4120 5.2.7.5; docs/questions/Q-240 item 2 (`s2k_params` added).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigDescription {
    /// The realm keyd serves ([`KeydConfig::realm`]).
    pub realm: Realm,
    /// The encryption types, in keyd's preference order
    /// ([`KeydConfig::enctypes`]).
    pub enctypes: Vec<EncTypeId>,
    /// The acceptable clock skew in seconds ([`KeydConfig::clock_skew_secs`]).
    pub clock_skew_secs: u32,
    /// The one-time token lifetime in seconds
    /// ([`KeydConfig::token_lifetime_secs`]).
    pub token_lifetime_secs: u32,
    /// The ticket policy keyd enforces on every template
    /// ([`KeydConfig::ticket_policy`]).
    pub ticket_policy: TicketPolicy,
    /// The string-to-key parameters `set_secret` uses
    /// ([`KeydConfig::s2k_params`]).
    pub s2k_params: Option<[u8; 4]>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> KeydConfig {
        KeydConfig::new(Realm::new("EXAMPLE.ORG").unwrap())
    }

    #[test]
    fn default_config_is_valid() {
        assert_eq!(base().validate(), Ok(()));
    }

    /// The default mask denies the docs/30 §2.6 options (RFC 4120 5.3 bits).
    #[test]
    fn default_mask_denies_dangerous_flags() {
        let mask = DEFAULT_ALLOWED_TICKET_FLAGS;
        for flag in [
            TicketFlags::FORWARDABLE,
            TicketFlags::FORWARDED,
            TicketFlags::PROXIABLE,
            TicketFlags::PROXY,
            TicketFlags::MAY_POSTDATE,
            TicketFlags::POSTDATED,
            TicketFlags::INVALID,
            TicketFlags::OK_AS_DELEGATE,
        ] {
            assert!(!mask.contains(flag), "{flag:?}");
        }
    }

    /// Flags with no phase-1 code path cannot be enabled (docs/02 §3).
    #[test]
    fn unsupported_flags_cannot_be_configured() {
        for flag in [
            TicketFlags::FORWARDED,
            TicketFlags::PROXY,
            TicketFlags::MAY_POSTDATE,
            TicketFlags::POSTDATED,
            TicketFlags::INVALID,
            TicketFlags::OK_AS_DELEGATE,
        ] {
            let mut c = base();
            c.ticket_policy.allowed_flags.insert(flag);
            assert_eq!(c.validate(), Err(ConfigError::TicketFlags), "{flag:?}");
        }
        // Reserved bit 0 (RFC 4120 5.3).
        let mut c = base();
        c.ticket_policy.allowed_flags =
            TicketFlags(krb_proto::KerberosFlags::from_bits(0x8000_0000));
        assert_eq!(c.validate(), Err(ConfigError::TicketFlags));
    }

    #[test]
    fn inconsistent_values_are_refused() {
        let mut c = base();
        c.enctypes.clear();
        assert_eq!(c.validate(), Err(ConfigError::EncTypes));
        let mut c = base();
        c.enctypes.push(EncTypeId::Aes256CtsHmacSha196);
        assert_eq!(c.validate(), Err(ConfigError::EncTypes));
        let mut c = base();
        c.clock_skew_secs = 0;
        assert_eq!(c.validate(), Err(ConfigError::ClockSkew));
        let mut c = base();
        c.token_lifetime_secs = MAX_TOKEN_LIFETIME_SECS + 1;
        assert_eq!(c.validate(), Err(ConfigError::TokenLifetime));
        let mut c = base();
        c.replay_cache_capacity = 0;
        assert_eq!(c.validate(), Err(ConfigError::Capacity));
        let mut c = base();
        c.ticket_policy.min_lifetime_secs = c.ticket_policy.max_lifetime_secs + 1;
        assert_eq!(c.validate(), Err(ConfigError::TicketLifetimes));
        // 00 00 00 00 means 2^32 iterations (RFC 3962 §4): above any cap.
        let mut c = base();
        c.s2k_params = Some([0, 0, 0, 0]);
        assert_eq!(c.validate(), Err(ConfigError::S2kParams));
        let mut c = base();
        c.throttle.max_failures = 0;
        assert_eq!(c.validate(), Err(ConfigError::Throttle));
    }

    /// The armor table and the preauth throttle are bounded and validated
    /// like the other tables (docs/48 §9.1 I4; A-34; AGENTS.md §6).
    #[test]
    fn armor_table_and_preauth_throttle_are_validated() {
        let mut c = base();
        c.max_armor_contexts = 0;
        assert_eq!(c.validate(), Err(ConfigError::Capacity));
        let mut c = base();
        c.max_armor_contexts = MAX_TABLE_CAPACITY + 1;
        assert_eq!(c.validate(), Err(ConfigError::Capacity));
        let mut c = base();
        c.preauth_throttle.capacity = 0;
        assert_eq!(c.validate(), Err(ConfigError::Capacity));
        let mut c = base();
        c.preauth_throttle.window_secs = 0;
        assert_eq!(c.validate(), Err(ConfigError::Throttle));
        let mut c = base();
        c.preauth_throttle.max_failures = 0;
        assert_eq!(c.validate(), Err(ConfigError::Throttle));
    }

    /// The service-context table is bounded and validated like the other
    /// token tables (docs/49 §3.3, A-46; AGENTS.md §6).
    #[test]
    fn service_context_table_is_validated() {
        let mut c = base();
        c.max_service_contexts = 0;
        assert_eq!(c.validate(), Err(ConfigError::Capacity));
        let mut c = base();
        c.max_service_contexts = MAX_TABLE_CAPACITY + 1;
        assert_eq!(c.validate(), Err(ConfigError::Capacity));
    }
}
