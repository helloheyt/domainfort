//! The [`Keyd`] engine: configuration, key store, entropy, audit, one-time
//! token tables and the replay cache, plus the helpers every operation uses
//! (authorization, audit emission, sealing).
//!
//! Every public operation follows the same shape:
//! 1. authorize — role in the capability table (I2), handle purposes (I3);
//! 2. do the work on an internal result carrying the audit-only reason;
//! 3. emit exactly one audit record (I8);
//! 4. map to the public error (docs/10 §9): uniform, except the non-secret
//!    classes an authentication step reports after its cryptographic chain
//!    completed (A-26).
//!
//! Spec: docs/10 §2, §3 ("every call is recorded"), §9, §10, §12; A-26.

use crate::as_exchange::ProofEntry;
use crate::audit::{AuditKeyRef, AuditOutcome, AuditReason, AuditRecord, AuditSink};
use crate::authz::{purpose_permitted, role_permits, CallerId, HandleSlot, Operation};
use crate::config::KeydConfig;
use crate::entropy::{EntropySource, OsEntropy};
use crate::error::{ConfigError, Deny, Internal};
use crate::fast_armor::ArmorEntry;
use crate::model::{KeyHandle, KeyPurpose, Kvno, PrincipalId};
use crate::replay::ReplayCache;
use crate::store::{KeyStore, StoreError};
use crate::tgs_exchange::ContextEntry;
use crate::throttle::{FailureWindowThrottle, SecretThrottle};
use crate::tokens::TokenTable;
use core::fmt;
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
    pub(crate) replay: ReplayCache,
}

impl<S: KeyStore, A: AuditSink> Keyd<S, A, OsEntropy> {
    /// Build keyd with the operating-system entropy source (the only source
    /// permitted outside tests). The configuration is validated first.
    ///
    /// Spec: docs/10 §11; AGENTS.md §6.
    pub fn new(config: KeydConfig, store: S, audit: A) -> Result<Self, ConfigError> {
        Self::with_entropy(config, store, audit, OsEntropy::new())
    }
}

impl<S: KeyStore, A: AuditSink, E: EntropySource> Keyd<S, A, E> {
    /// Build keyd with an injected entropy source.
    ///
    /// **TESTS ONLY.** Production code must use [`Keyd::new`], which uses
    /// the kernel CSPRNG ([`OsEntropy`]). A deterministic source makes every
    /// session key and long-term key predictable.
    ///
    /// Spec: AGENTS.md §6 (never implement an RNG; approved sources only).
    pub fn with_entropy(
        config: KeydConfig,
        store: S,
        audit: A,
        entropy: E,
    ) -> Result<Self, ConfigError> {
        config.validate()?;
        let throttle = Box::new(FailureWindowThrottle::new(config.throttle));
        Ok(Keyd {
            proofs: TokenTable::new(config.max_authn_proofs),
            contexts: TokenTable::new(config.max_tgt_contexts),
            armors: TokenTable::new(config.max_armor_contexts),
            replay: ReplayCache::new(config.replay_cache_capacity),
            preauth_throttle: FailureWindowThrottle::new(config.preauth_throttle),
            throttle,
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
            Ok(_) => (AuditOutcome::Success, AuditReason::None),
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
/// Mismatch is `Denied` (and audited by the caller of this helper).
///
/// Spec: docs/10 §2, §12 I2, I3.
pub(crate) fn authorize(
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
