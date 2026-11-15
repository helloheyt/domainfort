//! Directory operations: set a principal's secret from a password, and
//! verify a candidate password. `set_secret`: Role `Directory`, on a
//! decision dird registered (A-102). `verify_secret`: **no role** holds it
//! (A-102, docs/52 R4 / N3 — no process calls it, and Directory holding it
//! was a second, FAST-bypassing guess oracle); the operation stays for a
//! future declared consumer (kpasswd / P-14) and is refused at the
//! capability table until then.
//!
//! - The plaintext arrives in a RustCrypto `Zeroizing<String>` taken BY
//!   VALUE: keyd owns it and it is wiped when the operation returns (I7).
//! - Keys are derived inside keyd with string-to-key for every configured
//!   enctype; the iteration count is capped through krb-crypto's
//!   `max_iterations` (RFC 3962 §4).
//! - `verify_secret` compares the derived candidate key with the stored key
//!   through krb-crypto `get_mic` / `verify_mic` — whose comparison is the
//!   RustCrypto `hmac` constant-time verification — never a hand-rolled byte
//!   compare (I6). An unknown principal or a non-password key runs the same
//!   derivation and comparison on dummy material before refusing, so the
//!   refusal path costs about the same (equal up to differing stored
//!   iteration counts; not secret-dependent).
//!
//! - `set_secret` chooses the kvno itself and returns it (A-35): no
//!   component outside keyd knows the current kvno (there is no read
//!   operation, docs/10 §7).
//!
//! # One install path, one password policy (task K3; docs/53 §4.4, §6)
//!
//! Every password keyd installs — admind's `set_secret`, the ceremony's
//! first administrators (`set_secret` on a grant), and kpasswd's
//! `complete_change_password` — goes through **one** function,
//! [`Keyd::install_password`]: the password policy, the store's acceptance,
//! the existence rule, the name binding (A-19), keyd's choice of kvno
//! (A-35), string-to-key and the install through `BoundKeys` /
//! `NewBinding`. The policy ([`password_policy`]) is the one rule set of
//! crate admin-password-policy, `check_password` — the owner's rules
//! (docs/56 §7, P-24) on top of [MS-SAMR] 3.1.1.7.2 items 2, 3.2.1, 3.2.2 —
//! with keyd's own `min_password_chars` (≥ 8, P-24), the account's name and
//! the realm as the organisation's name. keyd's install path is the one
//! place every password is cleartext, so a password that skipped the
//! policy is impossible by construction — on every path, also against a
//! compromised admind holding a live decision (class: "a rule enforced by
//! the callers of a chokepoint instead of by the chokepoint", docs/52 C14;
//! docs/questions/Q-605 item 1). admind's and provision's own checks stay as
//! non-authoritative early checks until task K11 (docs/questions/Q-664).
//!
//! Spec: docs/10 §6 (`set_secret`, `verify_secret`), §12 I6, I7; RFC 3961
//! §3 (string-to-key on UTF-8 strings); RFC 3962 §4; RFC 4120 §4 (default
//! salt = realm + name components; the directory supplies the salt);
//! docs/questions/Q-115 (A-35).

use crate::audit::{AuditReason, AuditSink};
use crate::authz::{CallerId, HandleSlot, Operation};
use crate::config::{KeydConfig, MAX_MIN_PASSWORD_CHARS, MIN_PASSWORD_CHARS_FLOOR};
use crate::enctype::to_crypto;
use crate::entropy::EntropySource;
use crate::error::{Deny, Error, Internal};
use crate::keyd::{draw, key_usage, new_random_key, store_deny, AuditFields, Keyd};
use crate::model::{KeyHandle, Kvno, PrincipalBinding};
use crate::store::{KeyStore, KvnoKeys, StoredKeySet, UnboundUse};
use crate::template::check_new_binding;
use crate::time::kerberos_time_seconds;
use crate::usage::KEYD_INTERNAL_SECRET_COMPARE;
use krb_crypto::{EncType, ProtocolKey};
use krb_proto::{KerberosTime, PrincipalName};
use zeroize::Zeroizing;

/// Length of the random challenge the constant-time comparison MACs.
const COMPARE_CHALLENGE_LENGTH: usize = 32;

// keyd's bound on `min_password_chars` is the policy crate's maximum
// password length ([MS-SAMR] 3.1.1.7.2 item 2): one value, pinned.
const _: () =
    assert!(MAX_MIN_PASSWORD_CHARS as usize == admin_password_policy::MAX_PASSWORD_UTF16_UNITS);
// Its floor is the policy crate's floor, the owner's minimum (docs/56 §7
// P-24: 8 characters): one value, pinned.
const _: () = assert!(MIN_PASSWORD_CHARS_FLOOR == admin_password_policy::MIN_PASSWORD_CHARS_FLOOR);

/// Whether the key set an install targets must exist, must not exist, or
/// either.
/// Spec: docs/questions/Q-451 item 2 (an initial secret: the key set must
/// not exist); docs/53 §5.5 (a password **change**: the client's key set
/// exists — the AS issued its ticket from it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Existence {
    /// Create the key set or add a version to it (`set_secret` on a dird
    /// decision).
    Any,
    /// The key set must not exist yet (`set_secret` on the ceremony's
    /// initial-secret grant) — else `GrantMismatch`.
    MustNotExist,
    /// The key set must exist (`complete_change_password`) — else
    /// `KeyNotFound`.
    MustExist,
}

/// The password policy — the one rule set, applied by the one install path
/// ([`Keyd::install_password`]) and, for kpasswd, also when the request is
/// opened (before dird writes anything — the same function on the same
/// value, docs/53 §6.2): crate admin-password-policy's `check_password`
/// with
/// - `min_password_chars` as the minimum (never below the owner's 8: the
///   crate lifts a lower value, and keyd's configuration refuses one);
/// - `account_name`'s components as the account's name (the account's
///   binding is its sAMAccountName, one component — `NAME$` for a computer,
///   docs/47 §9.1; for kpasswd, the ticket's cname);
/// - keyd's realm, from which the crate takes the organisation's name —
///   every label but the top-level one (docs/56 §7 P-24; Q-910 item 6; the
///   realm is the domain's DNS name in upper case, docs/47 §3.3).
///
/// Both names are already known here — no new data source
/// (docs/questions/Q-910 item 6). The rules (the crate's documentation): at
/// most 256 UTF-16 units; at least the minimum in code points; an ASCII
/// upper-case letter, lower-case letter, digit and special character; no
/// ascending or descending run of three; no character three times in a
/// row; neither name, nor a delimited portion of either of more than two
/// characters (the realm's top-level label excepted); no weak word. Which rule failed is not reported: one reason,
/// `PasswordPolicyRefused` (docs/37 §2; Q-340 item 7); kpasswd's client
/// sees one SOFTERROR with no result string (A-121).
///
/// Spec: [MS-SAMR] 3.1.1.7.2 items 1, 2, 3.2.1-3.2.4; RFC 3244 §2 ("the
/// server will apply any local policy checks including password policy
/// checks"); docs/53 §6; docs/56 §7 (P-24); docs/questions/Q-605 items 1,
/// 2 (A-117), Q-664 (A-126), Q-910.
pub(crate) fn password_policy(
    config: &KeydConfig,
    password: &str,
    account_name: &PrincipalName,
) -> Internal<()> {
    let components: Vec<&str> = account_name
        .name_string
        .iter()
        .map(|component| component.as_str())
        .collect();
    let inputs = admin_password_policy::PolicyInputs {
        min_chars: config.min_password_chars,
        account_name: &components,
        organisation_name: config.realm.as_str(),
    };
    admin_password_policy::check_password(password, &inputs)
        .map_err(|_| Deny::denied(AuditReason::PasswordPolicyRefused))
}

impl<S: KeyStore, A: AuditSink, E: EntropySource> Keyd<S, A, E> {
    /// `set_secret`: derive the principal's keys from `password` and `salt`
    /// (string-to-key, every configured enctype) and install them under a
    /// kvno that keyd chooses, which it returns (a kvno is not secret):
    /// - the call creates the key set → [`Kvno::INITIAL`];
    /// - the key set exists → its current kvno + 1, the old current version
    ///   becoming previous; at the top of the UInt32 range the call is
    ///   refused (fail closed — a kvno never wraps back to an old value).
    ///
    /// No key material is returned; the plaintext is zeroized when this
    /// call returns.
    ///
    /// Purposes: PrincipalLongterm or Service (krbtgt is never
    /// password-derived).
    ///
    /// `binding` is the principal name of the key set. When this call
    /// creates the key set, the binding is fixed here for good (same rules
    /// as `create_key`); when the set already exists, `binding` must
    /// identify its existing binding (RFC 4120 6.2 equivalence) or the call
    /// is refused — a password change can never rename a principal.
    ///
    /// **The decision** (task A15a; docs/51 §5.8 option (b); A-102): a live
    /// set-secret entry for the handle — a `SetSecret` decision dird
    /// registered after its PDP (`register_decision`), or keyadm's ceremony
    /// grant for a first administrator (`grant_set_secret`) — is required at
    /// the authorization step (none ⇒ the uniform `Denied`, reason
    /// `NoGrant`) and consumed right after it, whatever the rest decides.
    /// Its binding must be `binding` exactly and its salt `salt` exactly
    /// (N4; else `GrantMismatch`); an initial-secret grant also requires
    /// that the key set does not exist yet (else `GrantMismatch`). The
    /// record names the decision's id.
    ///
    /// Spec: docs/10 §6 (`set_secret(principal, purpose, material, salt) ->
    /// Kvno`, "derives keys inside, zeroizes plaintext"), §12 I1, I7;
    /// docs/questions/Q-115 (A-35: "keyd chooses the next kvno and returns
    /// it"); RFC 4120 5.2.9 (kvno, UInt32); RFC 3961 §3; RFC 3962 §4;
    /// RFC 4120 6.2; docs/questions/Q-040 (A-19); docs/51 §5.8;
    /// docs/questions/Q-291 (A-74), Q-450 items 1, 7, Q-451 item 2; docs/52
    /// §4.2 (A-102, N4).
    pub fn set_secret(
        &mut self,
        caller: &CallerId,
        handle: &KeyHandle,
        binding: &PrincipalBinding,
        password: Zeroizing<String>,
        salt: &str,
        now: &KerberosTime,
    ) -> Result<Kvno, Error> {
        let mut fields = AuditFields::for_handle(handle);
        fields.decision = self
            .decisions
            .secret_decision_for(handle, Operation::SetSecret);
        let result = self
            .admit(
                caller,
                Operation::SetSecret,
                &[(HandleSlot::Primary, handle)],
                now,
            )
            .and_then(|()| {
                self.set_secret_inner(handle, binding, &password, salt, now, &mut fields)
            });
        drop(password);
        self.emit(caller, Operation::SetSecret, now, &fields, &result);
        result.map_err(Error::from)
    }

    /// `set_secret` after [`Keyd::admit`] passed (which found a live
    /// set-secret entry).
    fn set_secret_inner(
        &mut self,
        handle: &KeyHandle,
        binding: &PrincipalBinding,
        password: &str,
        salt: &str,
        now: &KerberosTime,
        fields: &mut AuditFields,
    ) -> Internal<Kvno> {
        // The entry is consumed by this presentation, before anything else
        // is decided (one attempt per decision; crate decision.rs).
        let redeemed =
            self.decisions
                .redeem_secret(handle, binding, salt, kerberos_time_seconds(now))?;
        fields.decision = redeemed.decision;
        let existence = if redeemed.initial_only {
            Existence::MustNotExist
        } else {
            Existence::Any
        };
        self.install_password(
            handle,
            binding,
            password,
            salt,
            existence,
            &redeemed.account_name,
            fields,
        )
    }

    /// The one install path of a password (module documentation, "One
    /// install path, one password policy"), after the caller redeemed its
    /// decision: `set_secret` (the caller's binding and salt, equal to the
    /// decision's) and `complete_change_password` (the decision's binding
    /// and salt). In order — every refusal before the install changes
    /// nothing:
    /// 1. the store accepts the purpose; the existence rule ([`Existence`]);
    /// 2. A-19: an existing key set is bound to `binding`; a new one passes
    ///    the creation rule;
    /// 3. keyd chooses the kvno (A-35);
    /// 4. the password policy ([`password_policy`], against `account_name`
    ///    — the decision's account) — `PasswordPolicyRefused` — before any
    ///    derivation (docs/questions/Q-605 item 1);
    /// 5. string-to-key for every configured enctype with `salt`;
    /// 6. the install through the binding proof (`BoundKeys`
    ///    `install_password_version`) or the creation proof
    ///    (`StoredKeySet::create`).
    ///
    /// Spec: docs/10 §6, I7; docs/53 R53-5, R53-10, §4.4, §6; RFC 3961 §3;
    /// RFC 3962 §4; RFC 4120 5.2.9, 6.2; docs/questions/Q-115 (A-35), Q-040
    /// (A-19), Q-451 item 2, Q-605 (A-117).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn install_password(
        &mut self,
        handle: &KeyHandle,
        binding: &PrincipalBinding,
        password: &str,
        salt: &str,
        existence: Existence,
        account_name: &PrincipalName,
        fields: &mut AuditFields,
    ) -> Internal<Kvno> {
        if !self.store.accepts(handle.purpose) {
            return Err(Deny::denied(AuditReason::StoreRefusedCritical));
        }
        let existing = self.store.get(handle);
        match (existence, existing.is_some()) {
            // An initial-secret grant (Role::Admin) never replaces a
            // password (docs/questions/Q-451 item 2).
            (Existence::MustNotExist, true) => {
                return Err(Deny::denied(AuditReason::GrantMismatch))
            }
            // A password change never creates a key set.
            (Existence::MustExist, false) => return Err(Deny::denied(AuditReason::KeyNotFound)),
            _ => {}
        }
        // A-19, before any derivation work: an existing set must be bound to
        // `binding` (its proof — the installer below checks it again, so the
        // version cannot land under another name); a new set's binding must
        // pass the creation rule, whose proof is the only way to create it
        // (crate::store, R7).
        let creation = match existing {
            Some(set) => {
                set.bound_to(&binding.realm, &binding.name)?;
                None
            }
            None => Some(check_new_binding(&self.config.realm, handle, binding)?),
        };
        // keyd chooses the kvno (A-35), before any derivation work.
        let new_kvno = match existing.map(StoredKeySet::current_kvno) {
            None => Kvno::INITIAL,
            Some(current) => current
                .next()
                .ok_or(Deny::denied(AuditReason::KvnoExhausted))?,
        };
        fields.kvno = Some(new_kvno);
        // The password policy, before any derivation: the one enforcement
        // point of every password on every path (docs/53 §6.1).
        password_policy(&self.config, password, account_name)?;
        let mut keys = Vec::with_capacity(self.enctypes.len());
        for enctype in &self.enctypes {
            keys.push(derive_password_key(
                &self.config,
                *enctype,
                password,
                salt,
                self.config.s2k_params,
            )?);
        }
        let version =
            KvnoKeys::password_derived(new_kvno, keys, salt.to_owned(), self.config.s2k_params);
        match (creation, self.store.get_mut(handle)) {
            (None, Some(set)) => set.install_password_version(binding, version)?,
            (Some(creation), None) => {
                let (handle, set) = StoredKeySet::create(creation, version);
                self.store.insert(handle, set).map_err(store_deny)?;
            }
            // The store changed between the check and the install: keyd is
            // single-threaded (`&mut self`), so this cannot happen — refuse
            // (fail closed).
            _ => return Err(Deny::unavailable(AuditReason::InternalFailure)),
        }
        Ok(new_kvno)
    }

    /// `verify_secret`: does `candidate` match the principal's current
    /// password-derived key? Constant-time comparison (krb-crypto
    /// `verify_mic`), throttled, plaintext zeroized on return.
    ///
    /// **No role may call it** (A-102, docs/52 R4): every call is refused at
    /// the capability table (`RoleNotPermitted`), one record. It returns
    /// with a declared consumer (docs/questions/Q-465).
    ///
    /// Returns `Ok(())` on a match; `Error::Denied` for a wrong password, an
    /// unknown principal, a non-password key or a wrong role — the caller
    /// cannot tell these apart; `Error::RateLimited` when the throttling
    /// hook refuses the attempt (decided before any secret work, from the
    /// public failure history only). docs/10 §6 types this result as
    /// `AuthnError`; `Error` is used so the throttle outcome of docs/10 §9
    /// is expressible, while `Denied` stays uniform.
    ///
    /// Spec: docs/10 §6 ("constant-time, throttled"), §9, §12 I6, I7;
    /// docs/52 §3.4 (N3), §7 R4; docs/questions/Q-465 (A-102).
    pub fn verify_secret(
        &mut self,
        caller: &CallerId,
        handle: &KeyHandle,
        candidate: Zeroizing<String>,
        now: &KerberosTime,
    ) -> Result<(), Error> {
        let mut fields = AuditFields::for_handle(handle);
        let result = self.verify_secret_inner(caller, handle, &candidate, now, &mut fields);
        drop(candidate);
        self.emit(caller, Operation::VerifySecret, now, &fields, &result);
        result.map_err(Error::from)
    }

    fn verify_secret_inner(
        &mut self,
        caller: &CallerId,
        handle: &KeyHandle,
        candidate: &str,
        now: &KerberosTime,
        fields: &mut AuditFields,
    ) -> Internal<()> {
        self.admit(
            caller,
            Operation::VerifySecret,
            &[(HandleSlot::Primary, handle)],
            now,
        )?;
        let now_s = kerberos_time_seconds(now);
        if !self.throttle.admit(&handle.principal, now_s) {
            return Err(Deny::rate_limited(AuditReason::Throttled));
        }
        let outcome = compare_secret(
            &self.store,
            &mut self.entropy,
            &self.config,
            handle,
            candidate,
            fields,
        );
        match &outcome {
            Ok(()) => self.throttle.record(&handle.principal, true, now_s),
            Err(deny) if deny.outcome == crate::audit::AuditOutcome::Denied => {
                self.throttle.record(&handle.principal, false, now_s)
            }
            Err(_) => {}
        }
        outcome
    }
}

/// string-to-key with the configured iteration cap.
/// Spec: RFC 3961 §3; RFC 3962 §4 (iteration limit); RFC 8009 §4.
fn derive_password_key(
    config: &KeydConfig,
    enctype: EncType,
    password: &str,
    salt: &str,
    s2k_params: Option<[u8; 4]>,
) -> Internal<ProtocolKey> {
    krb_crypto::string_to_key(
        enctype,
        password,
        salt,
        s2k_params.as_ref().map(|p| &p[..]),
        config.max_s2k_iterations,
    )
    .map_err(|_| Deny::denied(AuditReason::S2kRefused))
}

/// Compare `candidate` with `stored` in constant time: MAC a fresh random
/// challenge under the stored key (get_mic) and verify that MAC under the
/// candidate key (verify_mic, whose comparison is the RustCrypto `hmac`
/// constant-time check). Equal keys ⇔ the MAC verifies (up to HMAC
/// collisions). Returns whether they match.
///
/// Spec: RFC 3961 §4 (get_mic / verify_mic); RFC 4120 §4 / 7.5.1 (usage
/// 512, implementation-internal range); docs/10 §12 I6.
fn keys_match<E: EntropySource>(
    entropy: &mut E,
    stored: &ProtocolKey,
    candidate: &ProtocolKey,
) -> Internal<bool> {
    let mut challenge = [0u8; COMPARE_CHALLENGE_LENGTH];
    draw(entropy, &mut challenge)?;
    let cksumtype = stored.enc_type().checksum_type();
    let usage = key_usage(KEYD_INTERNAL_SECRET_COMPARE)?;
    let mic = Zeroizing::new(
        krb_crypto::get_mic(stored, cksumtype, usage, &challenge)
            .map_err(|_| Deny::unavailable(AuditReason::InternalFailure))?,
    );
    Ok(krb_crypto::verify_mic(candidate, cksumtype, usage, &challenge, &mic).is_ok())
}

/// The body of `verify_secret` after authorization and throttling.
/// Spec: docs/10 §6, §12 I6.
fn compare_secret<S: KeyStore, E: EntropySource>(
    store: &S,
    entropy: &mut E,
    config: &KeydConfig,
    handle: &KeyHandle,
    candidate: &str,
    fields: &mut AuditFields,
) -> Internal<()> {
    // A declared unbound use (crate::store `UnboundUse`, R7): nothing is
    // issued under any name here.
    let stored = store
        .get(handle)
        .map(|set| set.unbound_current(UnboundUse::SecretComparison));
    let real = stored.and_then(|version| {
        fields.kvno = Some(version.kvno());
        match (version.salt(), version.preferred()) {
            (Some(salt), Some(key)) => Some((salt, key, version.s2k_params())),
            _ => None,
        }
    });
    match real {
        Some((salt, stored_key, s2k_params)) => {
            let derived =
                derive_password_key(config, stored_key.enc_type(), candidate, salt, s2k_params)?;
            if keys_match(entropy, stored_key, &derived)? {
                Ok(())
            } else {
                Err(Deny::denied(AuditReason::SecretMismatch))
            }
        }
        None => {
            // Same work on dummy material, then refuse (uniform cost).
            dummy_compare(entropy, config, candidate);
            let reason = if stored.is_some() {
                AuditReason::NoPasswordKey
            } else {
                AuditReason::KeyNotFound
            };
            Err(Deny::denied(reason))
        }
    }
}

/// Derive and compare against a throwaway random key; the result is
/// ignored. Spec: docs/10 §9 ("no time difference between secret-dependent
/// branches").
fn dummy_compare<E: EntropySource>(entropy: &mut E, config: &KeydConfig, candidate: &str) {
    let Some(enctype) = config.enctypes.first().copied().map(to_crypto) else {
        return;
    };
    let derived = derive_password_key(
        config,
        enctype,
        candidate,
        config.realm.as_str(),
        config.s2k_params,
    );
    let throwaway = new_random_key(entropy, enctype);
    if let (Ok(derived), Ok(throwaway)) = (derived, throwaway) {
        let _ = keys_match(entropy, &throwaway, &derived);
    }
}

#[cfg(test)]
mod tests {
    //! The kvno ceiling of `set_secret` (A-35). A key set at the top of the
    //! UInt32 range is unreachable through the public API (2^32 changes),
    //! so the store is seeded here directly. All values are made up for
    //! these tests.

    use super::*;
    use crate::audit::{AuditRecord, AuditSink};
    use crate::authz::Role;
    use crate::model::{KeyPurpose, PrincipalId};
    use crate::store::InMemoryKeyStore;
    use keyd_types::{AccountKind, DecidedOperation, DecisionId, EncTypeId, SetSecretTarget};
    use krb_proto::{KerberosString, PrincipalName, Realm};

    #[derive(Default)]
    struct Records(Vec<AuditRecord>);

    impl AuditSink for Records {
        fn record(&mut self, record: &AuditRecord) {
            self.0.push(record.clone());
        }
    }

    const DIRECTORY: CallerId = CallerId {
        uid: 200,
        role: Role::Directory,
    };
    const LDAP: CallerId = CallerId {
        uid: 400,
        role: Role::Ldap,
    };
    const SALT: &str = "EXAMPLE.ORGcarol";

    fn binding() -> PrincipalBinding {
        PrincipalBinding::new(
            Realm::new("EXAMPLE.ORG").unwrap(),
            PrincipalName {
                name_type: 1,
                name_string: vec![KerberosString::new("carol").unwrap()],
            },
        )
    }

    /// The key set of `handle` at `kvno`, created through its creation proof
    /// (R7: the only way to a key set).
    fn seeded(handle: &KeyHandle, kvno: u32) -> (KeyHandle, StoredKeySet) {
        let key = krb_crypto::random_to_key(EncType::Aes256CtsHmacSha196, &[0x4C; 32]).unwrap();
        let creation =
            check_new_binding(&Realm::new("EXAMPLE.ORG").unwrap(), handle, &binding()).unwrap();
        StoredKeySet::create(
            creation,
            KvnoKeys::password_derived(Kvno::new(kvno), vec![key], SALT.to_owned(), None),
        )
    }

    /// A-35 (Q-115): keyd chooses current + 1; at the top of the UInt32
    /// range (RFC 4120 5.2.9) `set_secret` is refused — fail closed, the
    /// kvno never wraps — and the stored set is left untouched. One below
    /// the top, the top itself is still assigned.
    #[test]
    fn set_secret_refuses_kvno_overflow() {
        let at_max = KeyHandle::new(
            PrincipalId::from_bytes([0x4C; 16]),
            KeyPurpose::PrincipalLongterm,
        );
        let below_max = KeyHandle::new(PrincipalId::from_bytes([0x4D; 16]), KeyPurpose::Service);
        let mut store = InMemoryKeyStore::new(4);
        for (handle, kvno) in [(at_max, u32::MAX), (below_max, u32::MAX - 1)] {
            let (handle, set) = seeded(&handle, kvno);
            store.insert(handle, set).unwrap();
        }
        let mut config = KeydConfig::new(Realm::new("EXAMPLE.ORG").unwrap());
        config.enctypes = vec![EncTypeId::Aes256CtsHmacSha196];
        let now = KerberosTime::new(2026, 11, 13, 10, 0, 0).unwrap();
        // Started a day earlier: the startup hold-down (Directory is not
        // held anyway) is long over.
        let started = KerberosTime::new(2026, 11, 12, 10, 0, 0).unwrap();
        let mut keyd = Keyd::new(config, store, Records::default(), &started).unwrap();
        // The decisions dird would register (task A15a, A-102): one for each
        // handle.
        let target = |handle: KeyHandle| SetSecretTarget {
            handle,
            binding: binding(),
            salt: SALT.to_owned(),
        };
        let below_max_account = KeyHandle::new(below_max.principal, KeyPurpose::PrincipalLongterm);
        assert_eq!(
            keyd.register_decision(
                &LDAP,
                DecisionId::new(1),
                &DecidedOperation::SetSecret {
                    kind: AccountKind::User,
                    targets: vec![target(at_max)],
                },
                &[],
                30,
                &now
            ),
            Ok(())
        );
        assert_eq!(
            keyd.register_decision(
                &LDAP,
                DecisionId::new(2),
                &DecidedOperation::SetSecret {
                    kind: AccountKind::Computer,
                    targets: vec![target(below_max_account), target(below_max)],
                },
                &[],
                30,
                &now
            ),
            Ok(())
        );

        let refused = keyd.set_secret(
            &DIRECTORY,
            &at_max,
            &binding(),
            Zeroizing::new("Hazel-Tundra-82-Lynx".to_owned()),
            SALT,
            &now,
        );
        assert_eq!(refused, Err(Error::Denied));
        let last = keyd.audit_sink().0.last().unwrap();
        assert_eq!(last.reason, AuditReason::KvnoExhausted);
        assert_eq!(last.op, Operation::SetSecret);
        let set = keyd.store.get(&at_max).unwrap();
        assert_eq!(set.current_kvno(), Kvno::new(u32::MAX));
        assert_eq!(set.previous_kvno(), None);

        assert_eq!(
            keyd.set_secret(
                &DIRECTORY,
                &below_max,
                &binding(),
                Zeroizing::new("Hazel-Tundra-82-Lynx".to_owned()),
                SALT,
                &now,
            ),
            Ok(Kvno::new(u32::MAX))
        );
        let set = keyd.store.get(&below_max).unwrap();
        assert_eq!(set.current_kvno(), Kvno::new(u32::MAX));
        assert_eq!(set.previous_kvno(), Some(Kvno::new(u32::MAX - 1)));
        assert_eq!(
            keyd.audit_sink().0.last().unwrap().kvno,
            Some(Kvno::new(u32::MAX))
        );
    }
}
