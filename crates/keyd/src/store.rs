//! Key storage: stored key sets (current + previous kvno), the [`KeyStore`]
//! trait, and the in-memory store.
//!
//! # Compute, don't give (I1)
//!
//! A [`StoredKeySet`] is opaque outside this crate: it has no public
//! constructor and no public accessor for key material — only the non-secret
//! kvnos. Key octets live in krb-crypto `ProtocolKey` values (fixed buffers,
//! zeroized on drop, redacted `Debug`). Nothing in this crate's public API
//! returns long-term key bytes.
//!
//! # Keys only through a proof of the name binding (A-19; docs/52 §3.5, R7)
//!
//! **The class (C5):** a binding invariant checked at each call site rather
//! than through a type that cannot be had without it. Every key set is bound,
//! at creation and for good, to one principal name (A-19), and keyd may use a
//! key only for the name it is bound to. Until R7 that rule was a call to
//! `template::check_binding` written by hand next to each key use (seven
//! sites), while the set handed its keys to anyone holding it — an operation
//! that forgot the call (S4U, Netlogon, docs/10 §6) would have bypassed A-19
//! silently.
//!
//! **The root-level change:** inside this crate, too, the key material of a
//! stored set is reachable only through a proof type built here, after the
//! check:
//!
//! * `StoredKeySet::bound_to` checks that the set is bound to (realm, name)
//!   and only then returns a `BoundKeys` — whose `KeyVersion`s are the
//!   only way to a key (`KeyVersion::key_for`, `KeyVersion::preferred`);
//! * an operation in which the principal's name is **not** an input gets the
//!   current version through `StoredKeySet::unbound_current`, which names a
//!   closed `UnboundUse` — each variant states where A-19 is enforced
//!   instead, so every such access is declared here and greppable;
//! * a password-derived version — a key someone outside keyd knows — is
//!   installed on an existing set only by
//!   `StoredKeySet::install_password_version`, which checks the binding
//!   itself (a password change can never rename a principal); a version keyd
//!   drew itself is installed by `StoredKeySet::rotate_random` (known to no
//!   one, the binding unchanged);
//! * a set is created only from a `NewBinding` — built only by
//!   `template::check_new_binding`, the creation rule of A-19 — so a key set
//!   bound to a name the rule refuses is unrepresentable.
//!
//! The raw accessors (the current and previous versions, the binding, and the
//! key lookups of a version) are private to this module. A new operation that
//! tries to use a stored key without the check does not compile.
//!
//! # Critical keys need a real HSM (D178)
//!
//! [`InMemoryKeyStore::new`] REFUSES to hold krbtgt keys. Only the explicitly
//! named [`InMemoryKeyStore::new_insecure_development_allowing_krbtgt`] holds
//! them, for development and tests. Production requires an HSM-backed store
//! (docs/10 D35, docs/33 §6.1 D178).
//!
//! Residuals: key octets are in process memory (no HSM yet, D30); moving a
//! `ProtocolKey` by value (Rust move = copy) may leave stale stack copies;
//! `mlock` / no-core-dump / guard pages (docs/10 §11) belong to the daemon.
//!
//! # Destruction (A-35)
//!
//! [`KeyStore::destroy`] removes a whole key set and zeroizes it inside the
//! store; no store destroys a krbtgt key set (it is only ever rotated).
//!
//! Spec: docs/10 §1 (StoredKeySet; current + previous kvno), §7, §11, §12 I1;
//! docs/09 A.7 (D32 rotation); docs/33 §6.1 (D178); docs/questions/Q-115
//! (A-35); docs/questions/Q-040 (A-19); RFC 4120 6.2 (name equivalence);
//! docs/52 §3.5, §7 R7.

use crate::audit::AuditReason;
use crate::error::{Deny, Internal};
use crate::model::{KeyHandle, KeyPurpose, Kvno, PrincipalBinding};
use crate::template::NewBinding;
use core::fmt;
use krb_crypto::{EncType, ProtocolKey};
use krb_proto::{PrincipalName, Realm};
use std::collections::HashMap;

/// The keys of one key version: one protocol key per configured enctype, in
/// configuration preference order, plus the string-to-key salt and
/// parameters when the keys were derived from a password.
///
/// It has no key accessor: a stored version's keys are read only through a
/// [`KeyVersion`] (module documentation).
///
/// Spec: docs/10 §1 (`StoredKeySet { kvno, keys, salt, purpose }`).
pub(crate) struct KvnoKeys {
    kvno: Kvno,
    keys: Vec<ProtocolKey>,
    salt: Option<String>,
    s2k_params: Option<[u8; 4]>,
}

impl KvnoKeys {
    /// A version of keys keyd drew itself (`create_key`): no string-to-key
    /// salt. `keys` must be non-empty (callers build it from the validated,
    /// non-empty enctype list).
    /// Spec: docs/10 §1, §7; RFC 3961 §3 (random-to-key).
    pub(crate) fn random(kvno: Kvno, keys: Vec<ProtocolKey>) -> Self {
        KvnoKeys {
            kvno,
            keys,
            salt: None,
            s2k_params: None,
        }
    }

    /// A version derived from a password with `salt` and `s2k_params`
    /// (`set_secret`). `keys` must be non-empty.
    /// Spec: docs/10 §6 (`set_secret`); RFC 3961 §3 (string-to-key).
    pub(crate) fn password_derived(
        kvno: Kvno,
        keys: Vec<ProtocolKey>,
        salt: String,
        s2k_params: Option<[u8; 4]>,
    ) -> Self {
        KvnoKeys {
            kvno,
            keys,
            salt: Some(salt),
            s2k_params,
        }
    }

    fn enctypes(&self) -> Vec<EncType> {
        self.keys.iter().map(ProtocolKey::enc_type).collect()
    }
}

impl fmt::Debug for KvnoKeys {
    /// Non-secret facts only (kvno, enctypes, whether salted).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KvnoKeys")
            .field("kvno", &self.kvno)
            .field("enctypes", &self.enctypes())
            .field("password_derived", &self.salt.is_some())
            .finish()
    }
}

/// One stored key version, reached through a [`BoundKeys`] proof or a
/// declared [`UnboundUse`] — the only way to a stored key (module
/// documentation). A borrow of the stored set: it cannot outlive it, and it
/// has no constructor outside this module.
///
/// Spec: docs/10 §1; docs/52 §3.5 (R7); docs/questions/Q-040 (A-19).
#[derive(Clone, Copy)]
pub(crate) struct KeyVersion<'a> {
    keys: &'a KvnoKeys,
}

impl<'a> KeyVersion<'a> {
    /// The key version number (not secret).
    pub(crate) fn kvno(&self) -> Kvno {
        self.keys.kvno
    }

    /// The preferred key (first configured enctype), used to seal tickets.
    /// Spec: RFC 4120 3.1.3 (ticket encrypted with the server key's type).
    pub(crate) fn preferred(&self) -> Option<&'a ProtocolKey> {
        self.keys.keys.first()
    }

    /// The key of `enctype`, if this version has one.
    pub(crate) fn key_for(&self, enctype: EncType) -> Option<&'a ProtocolKey> {
        self.keys.keys.iter().find(|k| k.enc_type() == enctype)
    }

    /// The string-to-key salt (only for password-derived keys). Not secret.
    pub(crate) fn salt(&self) -> Option<&'a str> {
        self.keys.salt.as_deref()
    }

    /// Whether the keys were derived from a password (`set_secret`) — keys
    /// that may be known outside keyd — rather than drawn by keyd.
    /// Spec: docs/questions/Q-165 item 4 (A-46).
    pub(crate) fn is_password_derived(&self) -> bool {
        self.keys.salt.is_some()
    }

    /// The string-to-key parameters used (password-derived keys).
    pub(crate) fn s2k_params(&self) -> Option<[u8; 4]> {
        self.keys.s2k_params
    }
}

impl fmt::Debug for KeyVersion<'_> {
    /// Non-secret facts only, as [`KvnoKeys`].
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.keys.fmt(f)
    }
}

/// Proof that a stored key set is bound to the (realm, name) an operation
/// uses it for (A-19): built only by [`StoredKeySet::bound_to`], after the
/// check. The key versions of the set are reached through it.
///
/// Spec: docs/questions/Q-040 (A-19); RFC 4120 6.2; docs/52 §3.5 (R7).
#[derive(Clone, Copy)]
pub(crate) struct BoundKeys<'a> {
    set: &'a StoredKeySet,
}

impl<'a> BoundKeys<'a> {
    /// The current key version — the one every ticket is sealed under.
    /// Spec: docs/10 §1 ("signing/sealing always with the current kvno").
    pub(crate) fn current(&self) -> KeyVersion<'a> {
        KeyVersion {
            keys: &self.set.current,
        }
    }

    /// The versions a ticket may be decrypted under: current, then the
    /// retained previous one (until `retire_kvno`).
    /// Spec: docs/10 §1 ("decrypt may try a set of kvnos"); [MS-KILE] 3.4.5.
    pub(crate) fn versions(&self) -> [Option<KeyVersion<'a>>; 2] {
        [
            Some(self.current()),
            self.set.previous.as_ref().map(|keys| KeyVersion { keys }),
        ]
    }
}

impl fmt::Debug for BoundKeys<'_> {
    /// The binding and the current kvno only.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoundKeys")
            .field("binding", &self.set.binding)
            .field("current_kvno", &self.set.current.kvno)
            .finish()
    }
}

/// The declared uses of a stored key set's keys in which the principal's
/// name is not an input — each states where A-19 is enforced instead
/// (module documentation). Closed: a new unbound use is a new variant here,
/// with its reason.
///
/// Spec: docs/52 §3.5 ("operations in which the name is not an input …
/// receive a separate, declared accessor, so that every access is marked");
/// docs/questions/Q-040 (A-19).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnboundUse {
    /// `verify_preauth`: it issues nothing — its `AuthnProof` is bound to the
    /// key handle, and `issue_as_rep`, its only redeemer, binds the ticket's
    /// crealm / cname to that same key set ([`StoredKeySet::bound_to`])
    /// before anything is sealed. Spec: docs/10 §4, §8; A-19.
    Preauthentication,
    /// `verify_secret`: it compares a candidate password with the current
    /// password-derived key and issues nothing under any name; no role holds
    /// it (A-102, docs/52 R4). Spec: docs/10 §6.
    SecretComparison,
}

/// The stored key set of one (principal, purpose): the CURRENT key version
/// and, after a rotation, the PREVIOUS one. Sealing always uses current;
/// decrypting a ticket may try both (until `retire_kvno`).
///
/// The set is bound, at creation, to one principal name
/// ([`PrincipalBinding`]); the binding has no setter and survives every
/// rotation (no rename in phase 1). Its keys are reachable only through
/// `StoredKeySet::bound_to` or a declared `UnboundUse` (module
/// documentation).
///
/// Opaque: no public constructor, no public key accessor (I1).
///
/// Spec: docs/10 §1 ("keyd holds current + previous"; "decrypt may try a set
/// of kvnos; signing/sealing always with the current kvno"); docs/09 D32;
/// docs/questions/Q-040 (A-19, name binding); docs/52 §3.5 (R7).
pub struct StoredKeySet {
    binding: PrincipalBinding,
    current: KvnoKeys,
    previous: Option<KvnoKeys>,
}

impl StoredKeySet {
    /// A new key set from its creation proof — the binding passed the
    /// creation rule (`template::check_new_binding`) for one handle — and its
    /// first version. Returns that handle, under which the caller stores the
    /// set.
    /// Spec: docs/questions/Q-040 (A-19); docs/10 §6, §7.
    pub(crate) fn create(binding: NewBinding, current: KvnoKeys) -> (KeyHandle, StoredKeySet) {
        let (handle, binding) = binding.into_parts();
        let set = StoredKeySet {
            binding,
            current,
            previous: None,
        };
        (handle, set)
    }

    /// The current key version number (not secret).
    pub fn current_kvno(&self) -> Kvno {
        self.current.kvno
    }

    /// The retained previous key version number, if any (not secret).
    pub fn previous_kvno(&self) -> Option<Kvno> {
        self.previous.as_ref().map(|p| p.kvno)
    }

    /// The proof that this set is bound to (`realm`, `name`), through which
    /// its keys are used; otherwise `Denied` (reason `NameBindingMismatch`).
    /// The realm and every name component are compared exactly; the
    /// name-type is not significant ([`PrincipalBinding::matches`]).
    /// Spec: RFC 4120 6.2 ("Principal names that differ only in the
    /// name-type identify the same principal"); docs/questions/Q-040 (A-19);
    /// docs/52 §3.5 (R7).
    pub(crate) fn bound_to(&self, realm: &Realm, name: &PrincipalName) -> Internal<BoundKeys<'_>> {
        if self.binding.matches(realm, name) {
            Ok(BoundKeys { set: self })
        } else {
            Err(Deny::denied(AuditReason::NameBindingMismatch))
        }
    }

    /// The current version, for a declared use in which the principal's
    /// name is not an input ([`UnboundUse`] says where A-19 is enforced
    /// instead).
    /// Spec: docs/52 §3.5 (R7); docs/questions/Q-040 (A-19).
    pub(crate) fn unbound_current(&self, unbound_use: UnboundUse) -> KeyVersion<'_> {
        // The variant is the declaration; each reads the current version
        // alone (a superseded password never authenticates).
        match unbound_use {
            UnboundUse::Preauthentication | UnboundUse::SecretComparison => KeyVersion {
                keys: &self.current,
            },
        }
    }

    /// Install a version keyd drew itself (`rotate_key`, `rotate_krbtgt`)
    /// under `kvno` as current; the old current becomes previous and the old
    /// previous is dropped (its keys are zeroized by krb-crypto). The binding
    /// is unchanged and the new keys are known to no one, so no name is
    /// involved.
    /// Spec: docs/10 §7 (rotate: "the current goes down to previous").
    pub(crate) fn rotate_random(&mut self, kvno: Kvno, keys: Vec<ProtocolKey>) {
        self.rotate(KvnoKeys::random(kvno, keys));
    }

    /// Install a password-derived version on this existing set (`set_secret`
    /// on a set that exists) — only when the set is bound to `binding`;
    /// otherwise `Denied` (`NameBindingMismatch`) and nothing changes: a
    /// password change never renames a principal.
    /// Spec: docs/10 §6; docs/questions/Q-040 (A-19, question 2); RFC 4120
    /// 6.2.
    pub(crate) fn install_password_version(
        &mut self,
        binding: &PrincipalBinding,
        next: KvnoKeys,
    ) -> Internal<()> {
        if !self.binding.matches(&binding.realm, &binding.name) {
            return Err(Deny::denied(AuditReason::NameBindingMismatch));
        }
        self.rotate(next);
        Ok(())
    }

    /// The rotation itself — private: every caller goes through one of the
    /// two installers above.
    /// Spec: docs/10 §7.
    fn rotate(&mut self, next: KvnoKeys) {
        let old = core::mem::replace(&mut self.current, next);
        self.previous = Some(old);
    }

    /// Drop the previous version if it is `kvno`. Returns whether it did.
    /// Spec: docs/10 §7 (retire_kvno removes an old kvno from the decrypt
    /// set).
    pub(crate) fn retire_previous(&mut self, kvno: Kvno) -> bool {
        match &self.previous {
            Some(p) if p.kvno == kvno => {
                self.previous = None;
                true
            }
            _ => false,
        }
    }
}

impl fmt::Debug for StoredKeySet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredKeySet")
            .field("binding", &self.binding)
            .field("current", &self.current)
            .field("previous", &self.previous)
            .finish()
    }
}

/// Why a key store refused to hold or destroy a key set. Carries no data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreError {
    /// The store does not hold keys of this purpose (D178: krbtgt needs an
    /// HSM-backed or explicitly-development store), or refuses to destroy a
    /// key set of this purpose (A-35: never krbtgt).
    Refused,
    /// A key set already exists for the handle (no silent overwrite).
    Exists,
    /// The store is at capacity.
    Full,
    /// No key set is stored for the handle (destroy).
    NotFound,
}

/// A container of opaque [`StoredKeySet`]s, keyed by [`KeyHandle`].
///
/// keyd performs every cryptographic operation itself; a store only holds
/// the sets keyd built. A store decides which purposes it accepts — the
/// D178 rule is enforced by the store that holds the material.
///
/// Spec: docs/10 §1, §11; docs/33 §6.1 (D178).
pub trait KeyStore {
    /// `true` if this store may hold keys of `purpose`. Spec: D178.
    fn accepts(&self, purpose: KeyPurpose) -> bool;

    /// Whether the store holds no key set at all — keyd then starts in its
    /// provisioning ceremony (A-102, docs/52 §4.4: "keyd comes up in
    /// `Provisioning` only when the store is empty").
    fn is_empty(&self) -> bool;

    /// The key set of `handle`, if stored.
    fn get(&self, handle: &KeyHandle) -> Option<&StoredKeySet>;
    /// Mutable access for rotation / retirement of an existing set.
    fn get_mut(&mut self, handle: &KeyHandle) -> Option<&mut StoredKeySet>;
    /// Store a new set. Must refuse purposes it does not accept
    /// ([`StoreError::Refused`]) and existing handles
    /// ([`StoreError::Exists`]).
    fn insert(&mut self, handle: KeyHandle, set: StoredKeySet) -> Result<(), StoreError>;
    /// Remove the whole key set of `handle` — current and previous versions
    /// — and destroy it inside the store: its key octets are zeroized (a
    /// software store drops the krb-crypto `ProtocolKey`s, which wipe on
    /// drop), and nothing of it is handed back. Must refuse a Krbtgt handle
    /// ([`StoreError::Refused`]: krbtgt is never destroyed, only rotated)
    /// and report an unknown handle ([`StoreError::NotFound`]).
    ///
    /// Spec: docs/questions/Q-115 (A-35: `destroy_key_set`, zeroize; never
    /// krbtgt); docs/10 §7, §11 (zeroize).
    fn destroy(&mut self, handle: &KeyHandle) -> Result<(), StoreError>;
}

/// In-memory key store (keys in process RAM, zeroized on drop), bounded.
///
/// Spec: docs/10 §11 (software fallback only for development, D35); D178.
pub struct InMemoryKeyStore {
    sets: HashMap<KeyHandle, StoredKeySet>,
    capacity: usize,
    allow_krbtgt: bool,
}

impl InMemoryKeyStore {
    /// An in-memory store for principal and service keys. It REFUSES krbtgt
    /// keys: critical signing keys require a real HSM (docs/33 §6.1, D178).
    ///
    /// `capacity` bounds the number of key sets.
    pub fn new(capacity: usize) -> Self {
        InMemoryKeyStore {
            sets: HashMap::new(),
            capacity,
            allow_krbtgt: false,
        }
    }

    /// **INSECURE — DEVELOPMENT AND TESTS ONLY.**
    ///
    /// An in-memory store that ALSO holds krbtgt keys in process memory. A
    /// compromise of this process (memory read, core dump, swap) exposes the
    /// krbtgt key and with it every ticket of the realm (golden tickets).
    ///
    /// **Production requires an HSM-backed store for krbtgt** (docs/10 D35;
    /// docs/33 §6.1 D178: critical signing — krbtgt, CA root, DNSSEC KSK,
    /// PAC — is refused on a weak backend). Never use this constructor in a
    /// deployment.
    pub fn new_insecure_development_allowing_krbtgt(capacity: usize) -> Self {
        InMemoryKeyStore {
            sets: HashMap::new(),
            capacity,
            allow_krbtgt: true,
        }
    }

    /// Number of stored key sets.
    pub fn len(&self) -> usize {
        self.sets.len()
    }

    /// `true` if no key set is stored.
    pub fn is_empty(&self) -> bool {
        self.sets.is_empty()
    }
}

impl KeyStore for InMemoryKeyStore {
    /// Spec: docs/33 §6.1 (D178).
    fn accepts(&self, purpose: KeyPurpose) -> bool {
        match purpose {
            KeyPurpose::Krbtgt => self.allow_krbtgt,
            KeyPurpose::PrincipalLongterm
            | KeyPurpose::Service
            | KeyPurpose::AdminService
            | KeyPurpose::ChangePasswordService => true,
        }
    }

    /// Spec: docs/52 §4.4 (A-102).
    fn is_empty(&self) -> bool {
        self.sets.is_empty()
    }

    fn get(&self, handle: &KeyHandle) -> Option<&StoredKeySet> {
        self.sets.get(handle)
    }

    fn get_mut(&mut self, handle: &KeyHandle) -> Option<&mut StoredKeySet> {
        self.sets.get_mut(handle)
    }

    /// Spec: docs/33 §6.1 (D178); bounded per docs/CLEAN-ROOM.md
    fn insert(&mut self, handle: KeyHandle, set: StoredKeySet) -> Result<(), StoreError> {
        if !self.accepts(handle.purpose) {
            return Err(StoreError::Refused);
        }
        if self.sets.contains_key(&handle) {
            return Err(StoreError::Exists);
        }
        if self.sets.len() >= self.capacity {
            return Err(StoreError::Full);
        }
        self.sets.insert(handle, set);
        Ok(())
    }

    /// The key octets live in the `ProtocolKey`s of the version's heap
    /// buffer, not in the map slot; dropping the removed set drops each
    /// `ProtocolKey` in place, which zeroizes it (krb-crypto ZeroizeOnDrop).
    /// Krbtgt is refused in both modes, the development one included.
    ///
    /// Spec: docs/questions/Q-115 (A-35); docs/10 §11 (zeroize); docs/33
    /// §6.1 (D178, unchanged: `insert` still refuses krbtgt here).
    fn destroy(&mut self, handle: &KeyHandle) -> Result<(), StoreError> {
        if handle.purpose == KeyPurpose::Krbtgt {
            return Err(StoreError::Refused);
        }
        let set = self.sets.remove(handle).ok_or(StoreError::NotFound)?;
        drop(set);
        Ok(())
    }
}

impl fmt::Debug for InMemoryKeyStore {
    /// Counts and mode only — never keys (docs/CLEAN-ROOM.md).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InMemoryKeyStore")
            .field("key_sets", &self.sets.len())
            .field("capacity", &self.capacity)
            .field("insecure_development_krbtgt", &self.allow_krbtgt)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::PrincipalId;
    use krb_proto::{KerberosString, PrincipalName, Realm};

    fn realm() -> Realm {
        Realm::new("EXAMPLE.ORG").unwrap()
    }

    fn name(component: &str, name_type: i32) -> PrincipalName {
        PrincipalName {
            name_type,
            name_string: vec![KerberosString::new(component).unwrap()],
        }
    }

    fn binding() -> PrincipalBinding {
        PrincipalBinding::new(realm(), name("svc", 1))
    }

    fn key(byte: u8) -> ProtocolKey {
        krb_crypto::random_to_key(EncType::Aes128CtsHmacSha196, &[byte; 16]).unwrap()
    }

    /// A set built directly (this module's own tests; the creation proof is
    /// `template::check_new_binding`'s, tested there and through keyd).
    fn set(kvno: u32) -> StoredKeySet {
        StoredKeySet {
            binding: binding(),
            current: KvnoKeys::random(Kvno::new(kvno), vec![key(0x11)]),
            previous: None,
        }
    }

    /// D178: the default in-memory store refuses krbtgt; the explicitly
    /// insecure development store accepts it (docs/33 §6.1).
    #[test]
    fn krbtgt_refused_unless_development_store() {
        let h = KeyHandle::new(PrincipalId::from_bytes([1; 16]), KeyPurpose::Krbtgt);
        let mut store = InMemoryKeyStore::new(8);
        assert!(!store.accepts(KeyPurpose::Krbtgt));
        assert_eq!(store.insert(h, set(1)), Err(StoreError::Refused));
        assert!(store.get(&h).is_none());
        let mut dev = InMemoryKeyStore::new_insecure_development_allowing_krbtgt(8);
        assert_eq!(dev.insert(h, set(1)), Ok(()));
        assert_eq!(
            dev.get(&h).map(StoredKeySet::current_kvno),
            Some(Kvno::new(1))
        );
    }

    #[test]
    fn insert_is_bounded_and_never_overwrites() {
        let a = KeyHandle::new(PrincipalId::from_bytes([1; 16]), KeyPurpose::Service);
        let b = KeyHandle::new(PrincipalId::from_bytes([2; 16]), KeyPurpose::Service);
        let mut store = InMemoryKeyStore::new(1);
        assert_eq!(store.insert(a, set(1)), Ok(()));
        assert_eq!(store.insert(a, set(2)), Err(StoreError::Exists));
        assert_eq!(store.insert(b, set(1)), Err(StoreError::Full));
        assert_eq!(store.len(), 1);
    }

    /// A-35 (Q-115): destroy removes the whole set and frees its slot; an
    /// unknown handle is NotFound; krbtgt is refused by both stores (the
    /// default one never holds it — D178 — and the development one never
    /// destroys it).
    #[test]
    fn destroy_removes_set_and_refuses_krbtgt() {
        let a = KeyHandle::new(PrincipalId::from_bytes([1; 16]), KeyPurpose::Service);
        let k = KeyHandle::new(PrincipalId::from_bytes([2; 16]), KeyPurpose::Krbtgt);
        let mut store = InMemoryKeyStore::new(1);
        assert_eq!(store.insert(a, set(1)), Ok(()));
        let mut rotated = set(1);
        rotated.rotate_random(Kvno::new(2), vec![key(0x33)]);
        assert_eq!(store.destroy(&a), Ok(()));
        assert!(store.get(&a).is_none());
        assert!(store.is_empty());
        assert_eq!(store.destroy(&a), Err(StoreError::NotFound));
        // A set with a previous version goes as a whole; the slot is free.
        assert_eq!(store.insert(a, rotated), Ok(()));
        assert_eq!(store.destroy(&a), Ok(()));
        assert_eq!(store.destroy(&k), Err(StoreError::Refused));
        let mut dev = InMemoryKeyStore::new_insecure_development_allowing_krbtgt(4);
        assert_eq!(dev.insert(k, set(1)), Ok(()));
        assert_eq!(dev.destroy(&k), Err(StoreError::Refused));
        assert!(dev.get(&k).is_some());
    }

    /// Rotation keeps exactly current + previous (docs/10 §1, §7).
    #[test]
    fn rotate_and_retire() {
        let mut s = set(1);
        s.rotate_random(Kvno::new(2), vec![key(0x22)]);
        assert_eq!(s.current_kvno(), Kvno::new(2));
        assert_eq!(s.previous_kvno(), Some(Kvno::new(1)));
        assert!(!s.retire_previous(Kvno::new(2)));
        assert!(s.retire_previous(Kvno::new(1)));
        assert_eq!(s.previous_kvno(), None);
        // The binding survives rotation unchanged (Q-040, A-19).
        assert_eq!(s.binding, binding());
    }

    /// R7 (docs/52 §3.5; A-19): the keys of a set are reached only through
    /// the proof of its binding. The bound (realm, name) yields the proof —
    /// whatever the name-type (RFC 4120 6.2: "It is not significant when
    /// checking for equivalence") — and through it the current version (the
    /// sealing one) and, after a rotation, the previous one (decryption);
    /// another name, another realm or another number of components is
    /// `NameBindingMismatch`, and no key.
    #[test]
    fn keys_only_through_the_binding_proof() {
        let mut s = set(1);
        s.rotate_random(Kvno::new(2), vec![key(0x22)]);
        let bound = s.bound_to(&realm(), &name("svc", 1)).unwrap();
        assert_eq!(bound.current().kvno(), Kvno::new(2));
        let [current, previous] = bound.versions();
        assert_eq!(current.map(|v| v.kvno()), Some(Kvno::new(2)));
        assert_eq!(previous.map(|v| v.kvno()), Some(Kvno::new(1)));
        assert!(bound
            .current()
            .key_for(EncType::Aes128CtsHmacSha196)
            .is_some());
        assert!(bound
            .current()
            .key_for(EncType::Aes256CtsHmacSha196)
            .is_none());
        // The name-type is a hint only (RFC 4120 6.2).
        assert!(s.bound_to(&realm(), &name("svc", 2)).is_ok());
        let two_parts = PrincipalName {
            name_type: 1,
            name_string: vec![
                KerberosString::new("svc").unwrap(),
                KerberosString::new("host").unwrap(),
            ],
        };
        for (realm, name) in [
            (realm(), name("other", 1)),
            (realm(), name("SVC", 1)),
            (Realm::new("EXAMPLE.NET").unwrap(), name("svc", 1)),
            (realm(), two_parts),
        ] {
            assert_eq!(
                s.bound_to(&realm, &name).map(|_| ()).map_err(|d| d.reason),
                Err(AuditReason::NameBindingMismatch)
            );
        }
    }

    /// R7: a declared unbound use reads the current version only (a
    /// superseded password never authenticates — docs/10 §4).
    #[test]
    fn an_unbound_use_reads_the_current_version_only() {
        let mut s = set(1);
        s.rotate_random(Kvno::new(2), vec![key(0x22)]);
        for unbound_use in [UnboundUse::Preauthentication, UnboundUse::SecretComparison] {
            assert_eq!(s.unbound_current(unbound_use).kvno(), Kvno::new(2));
        }
    }

    /// R7, the write side (A-19, Q-040 question 2): a password-derived
    /// version is installed only on a set bound to the binding named; a
    /// mismatch is `NameBindingMismatch` and leaves the set unchanged.
    #[test]
    fn a_password_version_is_installed_only_under_its_binding() {
        let mut s = set(1);
        let other = PrincipalBinding::new(realm(), name("other", 1));
        let version = |kvno| {
            KvnoKeys::password_derived(
                Kvno::new(kvno),
                vec![key(0x44)],
                String::from("EXAMPLE.ORGsvc"),
                None,
            )
        };
        assert_eq!(
            s.install_password_version(&other, version(2))
                .map_err(|d| d.reason),
            Err(AuditReason::NameBindingMismatch)
        );
        assert_eq!(s.current_kvno(), Kvno::new(1));
        assert_eq!(s.previous_kvno(), None);
        assert_eq!(s.install_password_version(&binding(), version(2)), Ok(()));
        assert_eq!(s.current_kvno(), Kvno::new(2));
        let bound = s.bound_to(&realm(), &name("svc", 1)).unwrap();
        assert!(bound.current().is_password_derived());
        assert_eq!(bound.current().salt(), Some("EXAMPLE.ORGsvc"));
        assert_eq!(
            bound.versions()[1].map(|v| v.is_password_derived()),
            Some(false)
        );
    }

    /// Debug output carries no key octets (docs/CLEAN-ROOM.md).
    #[test]
    fn debug_has_no_key_material() {
        let s = StoredKeySet {
            binding: binding(),
            current: KvnoKeys::random(Kvno::new(3), vec![key(0x5A)]),
            previous: None,
        };
        let text = format!("{s:?}");
        assert!(text.contains("kvno"));
        assert!(!text.contains("90") && !text.contains("5a") && !text.contains("5A"));
        let bound = format!("{:?}", s.bound_to(&realm(), &name("svc", 1)).unwrap());
        assert!(!bound.contains("5a") && !bound.contains("5A"));
    }
}
