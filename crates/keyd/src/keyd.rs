//! The [`Keyd`] engine: configuration, key store, entropy, audit, one-time
//! token tables and the replay cache, plus the helpers every operation uses
//! (authorization, audit emission, sealing).
//!
//! Every public operation follows the same shape:
//! 1. admit — role in the capability table (I2), handle purposes (I3), then
//!    the startup hold-down (RFC 4120 3.2.3; [`Keyd::admit`]);
//! 2. do the work on an internal result carrying the audit-only reason;
//! 3. emit exactly one audit record (I8);
//! 4. map to the public error (docs/10 §9): uniform, except the non-secret
//!    classes an authentication step reports after its cryptographic chain
//!    completed (A-26), and `Unavailable` for the hold-down (A-56).
//!
//! Spec: docs/10 §2, §3 ("every call is recorded"), §9, §10, §12; A-26;
//! RFC 4120 3.2.3; docs/50 R50-5, R50-6, §3.5; A-56.

use crate::as_exchange::ProofEntry;
use crate::audit::{AuditKeyRef, AuditOutcome, AuditReason, AuditRecord, AuditSink};
use crate::authz::{
    provisioning_only, purpose_permitted, role_permits, startup_hold_down_applies, CallerId,
    HandleSlot, Operation,
};
use crate::change_password::ChangePasswordEntry;
use crate::config::KeydConfig;
use crate::decision::DecisionTable;
use crate::enctype::to_crypto;
use crate::entropy::{EntropySource, OsEntropy};
use crate::error::{ConfigError, Deny, Internal};
use crate::fast_armor::ArmorEntry;
use crate::model::{KeyHandle, KeyPurpose, Kvno, PrincipalId};
use crate::replay::ReplayCache;
use crate::service_ticket::ServiceContextEntry;
use crate::store::{KeyStore, StoreError};
use crate::tgs_exchange::ContextEntry;
use crate::throttle::{FailureWindowThrottle, SecretThrottle};
use crate::time::kerberos_time_seconds;
use crate::tokens::TokenTable;
use core::fmt;
use keyd_types::{CeremonyState, DecisionId};
use krb_crypto::{EncType, KeyUsage, ProtocolKey, CONFOUNDER_LENGTH};
use krb_proto::KerberosTime;
use zeroize::Zeroizing;

/// The secret-custody engine.
///
/// Generic over the key store `S`, the audit sink `A`, and the entropy
/// source `E` (always [`OsEntropy`] outside tests). Operations take
/// `&mut self`; the daemon crate (D34) serializes access.
///
/// Spec: docs/09 א (keyd), docs/10.
pub struct Keyd<S: KeyStore, A: AuditSink, E: EntropySource = OsEntropy> {
    pub(crate) config: KeydConfig,
    /// `config.enctypes` as the crypto profile's own type, in the same
    /// (preference) order, converted once at construction: the configuration
    /// carries crypto-free identifiers (D182; decision A-63) and keyd's
    /// configuration does not change after construction.
    pub(crate) enctypes: Vec<EncType>,
    pub(crate) store: S,
    pub(crate) audit: A,
    pub(crate) entropy: E,
    pub(crate) throttle: Box<dyn SecretThrottle + Send>,
    /// The per-principal failure throttle of `verify_preauth` (A-34).
    pub(crate) preauth_throttle: FailureWindowThrottle,
    pub(crate) proofs: TokenTable<ProofEntry>,
    pub(crate) contexts: TokenTable<ContextEntry>,
    /// Opened FAST armors (docs/48 §2.3, §9.1 I4).
    pub(crate) armors: TokenTable<ArmorEntry>,
    /// Verified service tickets: their session keys and subkeys, held for
    /// the later GSS steps (docs/49 §3.3, A-46).
    pub(crate) service_contexts: TokenTable<ServiceContextEntry>,
    /// Opened change-password requests: the session key, the subkey and —
    /// when acceptable — the new password, until the completion or the error
    /// seal consumes the context (task K3; docs/53 §5.5).
    pub(crate) change_password_contexts: TokenTable<ChangePasswordEntry>,
    /// The one replay cache of every AP-REQ keyd verifies (RFC 4120 3.2.3).
    pub(crate) replay: ReplayCache,
    /// The decision table (A-102, docs/52 R1 — generalizing A-100's grant
    /// table): every Directory / Admin state change runs only on an entry
    /// dird registered (crate decision.rs). In memory, bounded, lost at
    /// every start.
    pub(crate) decisions: DecisionTable,
    /// The ceremony state (A-102, docs/52 R3): `Provisioning` only when the
    /// store was empty at construction, until `seal_ceremony`.
    pub(crate) ceremony: CeremonyState,
    /// The last second (on the [`kerberos_time_seconds`] scale) of the
    /// startup hold-down: the start time given at construction plus
    /// [`STARTUP_HOLD_DOWN_SKEW_INTERVALS`] × `clock_skew_secs`
    /// ([`startup_hold_down_until`]). Operations that
    /// [`startup_hold_down_applies`] to are refused while the caller's `now`
    /// is not later than this.
    /// Spec: RFC 4120 3.2.3; docs/50 R50-6, §3.5; A-56, A-62.
    pub(crate) startup_hold_down_until: i64,
}

/// How many clock-skew intervals the startup hold-down lasts: two.
///
/// RFC 4120 3.2.3 requires rejecting requests "until the clock skew interval
/// has passed, providing assurance that any lost or replayed authenticators
/// will fall outside the allowable clock skew". That assurance needs two
/// intervals here: an authenticator keyd accepted just before it
/// (re)started, at server time ≈ S, may carry a client time `ctime` up to
/// S + skew (a client clock ahead by the skew is still accepted); it stays
/// acceptable while `now ≤ ctime + skew` — until S + 2·skew — and the
/// replay cache that would have caught it was lost in the restart. One
/// interval would leave a replay window of up to one more interval; two
/// close it (fail closed).
///
/// Spec: RFC 4120 3.2.3 (replay cache; skew check "differ by more than the
/// allowable clock skew"); docs/questions/Q-240 item 3 (decided A-62).
pub(crate) const STARTUP_HOLD_DOWN_SKEW_INTERVALS: i64 = 2;

/// The last held second: `started_at + 2 × clock_skew_secs`, in overflow-safe
/// arithmetic — a product or sum that does not fit holds for good
/// (`i64::MAX`, fail closed). Unreachable with validated inputs (seconds are
/// below 2^39, time.rs; the skew is at most `MAX_CLOCK_SKEW_SECS`).
/// Spec: RFC 4120 3.2.3; A-62; AGENTS.md §6 (fail closed).
pub(crate) fn startup_hold_down_until(started_at: i64, clock_skew_secs: u32) -> i64 {
    i64::from(clock_skew_secs)
        .checked_mul(STARTUP_HOLD_DOWN_SKEW_INTERVALS)
        .and_then(|window| started_at.checked_add(window))
        .unwrap_or(i64::MAX)
}

impl<S: KeyStore, A: AuditSink> Keyd<S, A, OsEntropy> {
    /// Build keyd with the operating-system entropy source (the only source
    /// permitted outside tests). The configuration is validated first.
    ///
    /// `started_at` is the time this keyd starts, read by the daemon from
    /// its OWN clock — the same clock it reads `now` from for every
    /// operation (docs/50 R50-5). keyd's replay cache and token tables start
    /// empty, so every operation that depends on them is refused (as
    /// `Unavailable`) until `now` is later than `started_at + 2 ×
    /// clock_skew_secs` (RFC 4120 3.2.3, A-62: an authenticator accepted just
    /// before the start may carry a client time up to one skew ahead and
    /// stays acceptable one skew after that; docs/10 §11;
    /// [`crate::authz::startup_hold_down_applies`]).
    /// The library reads no clock. **An IPC layer must never take the start
    /// time or any operation's `now` from the peer**: a compromised caller
    /// could otherwise end the hold-down early, or replay an expired ticket
    /// or an out-of-window authenticator (docs/50 §3.5, R50-5; A-56).
    ///
    /// Spec: docs/10 §11; AGENTS.md §6; RFC 4120 3.2.3; docs/50 R50-5,
    /// R50-6, §3.5; docs/questions/Q-222 (A-56), Q-240 item 3 (A-62).
    pub fn new(
        config: KeydConfig,
        store: S,
        audit: A,
        started_at: &KerberosTime,
    ) -> Result<Self, ConfigError> {
        Self::with_entropy(config, store, audit, OsEntropy::new(), started_at)
    }
}

impl<S: KeyStore, A: AuditSink, E: EntropySource> Keyd<S, A, E> {
    /// Build keyd with an injected entropy source; `started_at` as for
    /// [`Keyd::new`].
    ///
    /// **TESTS ONLY.** Production code must use [`Keyd::new`], which uses
    /// the kernel CSPRNG ([`OsEntropy`]). A deterministic source makes every
    /// session key and long-term key predictable.
    ///
    /// Spec: AGENTS.md §6 (never implement an RNG; approved sources only);
    /// RFC 4120 3.2.3; docs/50 R50-6.
    pub fn with_entropy(
        config: KeydConfig,
        store: S,
        audit: A,
        entropy: E,
        started_at: &KerberosTime,
    ) -> Result<Self, ConfigError> {
        config.validate()?;
        let enctypes = config.enctypes.iter().copied().map(to_crypto).collect();
        let throttle = Box::new(FailureWindowThrottle::new(config.throttle));
        let startup_hold_down_until =
            startup_hold_down_until(kerberos_time_seconds(started_at), config.clock_skew_secs);
        // R3 (docs/52 §4.4): the ceremony exists only for an empty store; a
        // store that holds keys at start is operational (P-17: a persistent
        // store; the development store is empty at every start).
        let ceremony = if store.is_empty() {
            CeremonyState::Provisioning
        } else {
            CeremonyState::Operational
        };
        Ok(Keyd {
            startup_hold_down_until,
            ceremony,
            proofs: TokenTable::new(config.max_authn_proofs),
            contexts: TokenTable::new(config.max_tgt_contexts),
            armors: TokenTable::new(config.max_armor_contexts),
            service_contexts: TokenTable::new(config.max_service_contexts),
            change_password_contexts: TokenTable::new(config.max_change_password_contexts),
            replay: ReplayCache::new(config.replay_cache_capacity),
            decisions: DecisionTable::new(),
            preauth_throttle: FailureWindowThrottle::new(config.preauth_throttle),
            throttle,
            enctypes,
            config,
            store,
            audit,
            entropy,
        })
    }

    /// Replace the `verify_secret` throttling hook. Spec: docs/10 §6.
    pub fn set_throttle(&mut self, throttle: Box<dyn SecretThrottle + Send>) {
        self.throttle = throttle;
    }

    /// The configuration in force.
    pub fn config(&self) -> &KeydConfig {
        &self.config
    }

    /// The audit sink (records are non-secret by construction, I8).
    pub fn audit_sink(&self) -> &A {
        &self.audit
    }

    /// Mutable access to the audit sink (e.g. to drain it).
    pub fn audit_sink_mut(&mut self) -> &mut A {
        &mut self.audit
    }

    /// The first step of every operation: the role and purpose checks
    /// ([`authorize`], I2, I3), then the startup hold-down.
    ///
    /// The hold-down is decided from `now`, the start time and the operation
    /// alone — before any key set, token, throttle window or replay-cache
    /// entry is read or written, and never from the request's content — so
    /// a held request leaves no state behind and its refusal reveals nothing
    /// about any secret (no oracle, A-56). It ends once `now` is LATER than
    /// `started_at + 2 × clock_skew_secs` (A-62; why two intervals:
    /// [`STARTUP_HOLD_DOWN_SKEW_INTERVALS`]; arithmetic that overflows holds,
    /// [`startup_hold_down_until`]). The boundary second itself is still
    /// held: the skew check is inclusive
    /// ([`crate::time`] `within_skew`, `|now − ctime| ≤ skew`). A `now`
    /// before the start (a clock stepped back) is held too: the elapsed time
    /// cannot be established (fail closed).
    ///
    /// Then the **ceremony state** (A-102, docs/52 R3): a
    /// `provisioning_only` operation (`create_key`, Admin's grant) after the
    /// seal is the uniform `Denied`, reason `CeremonySealed`.
    ///
    /// Then the **decision** (A-102, docs/52 R1; task A15a for
    /// `set_secret`): for `set_secret`, a live set-secret entry must name the
    /// handle in the `Primary` slot — a decision dird (Role::Ldap) registered
    /// after its PDP allowed the password set, or the ceremony's grant
    /// (Role::Admin) for a first administrator. None ⇒ the uniform `Denied`,
    /// reason `NoGrant`: decided from the table alone, before any key set is
    /// read, so it is an authorization refusal like the role check — one
    /// record, no intent (A-88), nothing changed. The entry is consumed by
    /// the operation right after this step (crate decision.rs). The same for
    /// `complete_change_password` (task K3): a live entry of a
    /// `ChangePassword` decision for the target handle — each entry is
    /// visible to its own executor only (Q-662). The four
    /// Admin operations that run a decision by id (`rotate_key`,
    /// `rotate_krbtgt`, `retire_kvno`, `destroy_key_set`) are never admitted
    /// here (`NoDecision`): their authorization step is
    /// `Keyd::admit_decision`, which finds the decision.
    ///
    /// Spec: docs/10 §2, §11, §12 I2, I3; RFC 4120 3.2.3 ("MUST reject all
    /// requests until the clock skew interval has passed, providing assurance
    /// that any lost or replayed authenticators will fall outside the
    /// allowable clock skew"); docs/50 R50-6, §3.5; docs/questions/Q-222
    /// (A-56), Q-240 items 1, 3 (A-62); AGENTS.md §6 (fail closed); docs/51
    /// §5.8; docs/questions/Q-291 (A-74), Q-450 items 1, 7.
    pub(crate) fn admit(
        &self,
        caller: &CallerId,
        op: Operation,
        handles: &[(HandleSlot, &KeyHandle)],
        now: &KerberosTime,
    ) -> Internal<()> {
        self.admit_base(caller, op, handles, now)?;
        match op {
            Operation::SetSecret | Operation::CompleteChangePassword => {
                let now_s = kerberos_time_seconds(now);
                let granted = handles
                    .iter()
                    .find(|(slot, _)| *slot == HandleSlot::Primary)
                    .is_some_and(|(_, handle)| self.decisions.is_live_secret(handle, op, now_s));
                if granted {
                    Ok(())
                } else {
                    Err(Deny::denied(AuditReason::NoGrant))
                }
            }
            // Only by decision id (`Keyd::admit_decision`), never here.
            Operation::RotateKey
            | Operation::RotateKrbtgt
            | Operation::RetireKvno
            | Operation::DestroyKeySet => Err(Deny::denied(AuditReason::NoDecision)),
            _ => Ok(()),
        }
    }

    /// The role and purpose checks ([`authorize`]), the startup hold-down
    /// and the ceremony state — the part of [`Keyd::admit`] every
    /// operation shares, decision or not.
    /// Spec: docs/10 §2, §11, §12 I2, I3; docs/52 §4.4 (A-102).
    pub(crate) fn admit_base(
        &self,
        caller: &CallerId,
        op: Operation,
        handles: &[(HandleSlot, &KeyHandle)],
        now: &KerberosTime,
    ) -> Internal<()> {
        authorize(caller, op, handles)?;
        let now_s = kerberos_time_seconds(now);
        if startup_hold_down_applies(op) && now_s <= self.startup_hold_down_until {
            return Err(Deny::startup_hold_down());
        }
        if provisioning_only(op) && self.ceremony == CeremonyState::Operational {
            return Err(Deny::denied(AuditReason::CeremonySealed));
        }
        Ok(())
    }

    /// Emit the one audit record of an operation. Spec: docs/10 §10, I8.
    pub(crate) fn emit<T>(
        &mut self,
        caller: &CallerId,
        op: Operation,
        now: &KerberosTime,
        fields: &AuditFields,
        result: &Internal<T>,
    ) {
        let (outcome, reason) = match result {
            // A success may name what it established (task K3: the verdict
            // of an opened change-password request, the result code of a
            // sealed error reply) — never which rule failed, never a secret.
            Ok(_) => (
                AuditOutcome::Success,
                fields.success_reason.unwrap_or(AuditReason::None),
            ),
            Err(deny) => (deny.outcome, deny.reason),
        };
        self.audit.record(&AuditRecord {
            ts: *now,
            caller_role: caller.role,
            caller_uid: caller.uid,
            op,
            principal: fields.principal,
            purpose: fields.purpose,
            kvno: fields.kvno,
            secondary: fields.secondary,
            approvers: fields.approvers,
            decision: fields.decision,
            result: outcome,
            reason,
        });
    }
}

impl<S: KeyStore, A: AuditSink, E: EntropySource> fmt::Debug for Keyd<S, A, E> {
    /// Non-secret state only (AGENTS.md §6).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Keyd")
            .field("realm", &self.config.realm)
            .field("enctypes", &self.config.enctypes)
            .field("live_authn_proofs", &self.proofs.len())
            .field("live_tgt_contexts", &self.contexts.len())
            .field("live_armor_contexts", &self.armors.len())
            .field("live_service_contexts", &self.service_contexts.len())
            .field(
                "live_change_password_contexts",
                &self.change_password_contexts.len(),
            )
            .field("decisions", &self.decisions.len())
            .field("ceremony", &self.ceremony)
            .finish()
    }
}

/// The audit fields an operation fills in as it resolves handles and kvnos.
/// Spec: docs/10 §10.
#[derive(Debug, Default)]
pub(crate) struct AuditFields {
    pub(crate) principal: Option<PrincipalId>,
    pub(crate) purpose: Option<KeyPurpose>,
    pub(crate) kvno: Option<Kvno>,
    pub(crate) secondary: Option<AuditKeyRef>,
    pub(crate) approvers: Option<[PrincipalId; 2]>,
    pub(crate) decision: Option<DecisionId>,
    /// The reason a **successful** operation records (task K3): the verdict
    /// of `open_change_password_request` or the result code
    /// `seal_change_password_error` sealed; `None` ⇒ `AuditReason::None`.
    /// Spec: docs/53 §9 ("one record with the code"); docs/10 §10.
    pub(crate) success_reason: Option<AuditReason>,
}

impl AuditFields {
    pub(crate) fn for_handle(handle: &KeyHandle) -> Self {
        AuditFields {
            principal: Some(handle.principal),
            purpose: Some(handle.purpose),
            ..AuditFields::default()
        }
    }
}

/// The two checks that precede every operation: (a) the caller's role
/// permits the operation, (b) each handle's purpose matches its slot.
/// Mismatch is `Denied` (and audited by the caller of this helper). Called
/// only through [`Keyd::admit`], which adds the startup hold-down.
///
/// Spec: docs/10 §2, §12 I2, I3.
fn authorize(
    caller: &CallerId,
    op: Operation,
    handles: &[(HandleSlot, &KeyHandle)],
) -> Internal<()> {
    if !role_permits(caller.role, op) {
        return Err(Deny::denied(AuditReason::RoleNotPermitted));
    }
    for (slot, handle) in handles {
        if !purpose_permitted(op, *slot, handle.purpose) {
            return Err(Deny::denied(AuditReason::PurposeMismatch));
        }
    }
    Ok(())
}

/// Fill `out` from the entropy source; failure is `Unavailable` (fail
/// closed, no fallback). Spec: AGENTS.md §6; RFC 4120 3.1.3.
pub(crate) fn draw<E: EntropySource>(entropy: &mut E, out: &mut [u8]) -> Internal<()> {
    entropy
        .fill(out)
        .map_err(|_| Deny::unavailable(AuditReason::EntropyFailure))
}

/// A fresh random protocol key: random-to-key over K octets of fresh
/// entropy, the buffer zeroized afterwards.
/// Spec: RFC 3961 §3 (random-to-key); RFC 3962 §4 (identity on 128/256
/// random bits); RFC 4120 3.1.3 (random session key).
pub(crate) fn new_random_key<E: EntropySource>(
    entropy: &mut E,
    enctype: EncType,
) -> Internal<ProtocolKey> {
    let mut buffer = Zeroizing::new([0u8; 32]);
    let random = buffer
        .get_mut(..enctype.key_length())
        .ok_or(Deny::unavailable(AuditReason::InternalFailure))?;
    draw(entropy, random)?;
    krb_crypto::random_to_key(enctype, random)
        .map_err(|_| Deny::unavailable(AuditReason::InternalFailure))
}

/// One fresh random key per configured enctype, in preference order. The
/// vector is allocated with its final capacity so no reallocation leaves a
/// stale copy of a key behind.
/// Spec: docs/10 §7 (create_key "draws a key"); RFC 3961 §3.
pub(crate) fn new_random_keys<E: EntropySource>(
    entropy: &mut E,
    enctypes: &[EncType],
) -> Internal<Vec<ProtocolKey>> {
    let mut keys = Vec::with_capacity(enctypes.len());
    for enctype in enctypes {
        keys.push(new_random_key(entropy, *enctype)?);
    }
    Ok(keys)
}

/// A key usage number (all of keyd's usages are non-zero constants).
/// Spec: RFC 3961 §2; RFC 4120 7.5.1.
pub(crate) fn key_usage(usage: u32) -> Internal<KeyUsage> {
    KeyUsage::new(usage).map_err(|_| Deny::unavailable(AuditReason::InternalFailure))
}

/// Encrypt `plaintext` under `key` with `usage` and a fresh confounder.
/// Spec: RFC 3961 §3 (encrypt; "a confounder should be included"); RFC 4120
/// §4 (no cipher-state chaining).
pub(crate) fn seal<E: EntropySource>(
    entropy: &mut E,
    key: &ProtocolKey,
    usage: u32,
    plaintext: &[u8],
) -> Internal<Vec<u8>> {
    let mut confounder = Zeroizing::new([0u8; CONFOUNDER_LENGTH]);
    draw(entropy, &mut confounder[..])?;
    krb_crypto::encrypt(key, key_usage(usage)?, &confounder, plaintext)
        .map_err(|_| Deny::unavailable(AuditReason::InternalFailure))
}

/// Decrypt and integrity-check `ciphertext`; any failure is `Denied`.
/// Spec: RFC 3961 §3 (decrypt: "an error indication must be returned, and
/// the data discarded"); RFC 4120 3.2.3 (KRB_AP_ERR_BAD_INTEGRITY).
pub(crate) fn open(
    key: &ProtocolKey,
    usage: u32,
    ciphertext: &[u8],
) -> Internal<Zeroizing<Vec<u8>>> {
    krb_crypto::decrypt(key, key_usage(usage)?, ciphertext)
        .map_err(|_| Deny::denied(AuditReason::IntegrityFailure))
}

/// Map a key-store refusal. Spec: docs/33 §6.1 (D178); docs/10 §9 (an
/// unknown handle is the uniform `Denied`); docs/questions/Q-115 (A-35).
pub(crate) fn store_deny(error: StoreError) -> Deny {
    match error {
        StoreError::Refused => Deny::denied(AuditReason::StoreRefusedCritical),
        StoreError::Exists => Deny::denied(AuditReason::KeyExists),
        StoreError::Full => Deny::unavailable(AuditReason::StoreFull),
        StoreError::NotFound => Deny::denied(AuditReason::KeyNotFound),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A-62: the hold-down ends two skew intervals after the start; a sum
    /// that cannot be represented holds for good (fail closed, AGENTS.md §6).
    #[test]
    fn hold_down_is_two_skew_intervals_and_overflow_holds() {
        assert_eq!(startup_hold_down_until(1_000, 300), 1_600);
        assert_eq!(startup_hold_down_until(0, 1), 2);
        assert_eq!(startup_hold_down_until(i64::MAX - 599, 300), i64::MAX);
        assert_eq!(startup_hold_down_until(i64::MAX - 600, 300), i64::MAX);
        assert_eq!(startup_hold_down_until(i64::MAX - 601, 300), i64::MAX - 1);
        assert_eq!(startup_hold_down_until(i64::MAX, u32::MAX), i64::MAX);
    }
}
