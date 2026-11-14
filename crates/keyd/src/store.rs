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
//! docs/09 א.7 (D32 rotation); docs/33 §6.1 (D178); docs/questions/Q-115
//! (A-35).

use crate::model::{KeyHandle, KeyPurpose, Kvno, PrincipalBinding};
use core::fmt;
use krb_crypto::{EncType, ProtocolKey};
use std::collections::HashMap;

/// The keys of one key version: one protocol key per configured enctype, in
/// configuration preference order, plus the string-to-key salt and
/// parameters when the keys were derived from a password.
///
/// Spec: docs/10 §1 (`StoredKeySet { kvno, keys, salt, purpose }`).
pub(crate) struct KvnoKeys {
    kvno: Kvno,
    keys: Vec<ProtocolKey>,
    salt: Option<String>,
    s2k_params: Option<[u8; 4]>,
}

impl KvnoKeys {
    /// Spec: docs/10 §1. `keys` must be non-empty (callers build it from the
    /// validated, non-empty enctype list).
    pub(crate) fn new(
        kvno: Kvno,
        keys: Vec<ProtocolKey>,
        salt: Option<String>,
        s2k_params: Option<[u8; 4]>,
    ) -> Self {
        KvnoKeys {
            kvno,
            keys,
            salt,
            s2k_params,
        }
    }

    pub(crate) fn kvno(&self) -> Kvno {
        self.kvno
    }

    /// The preferred key (first configured enctype), used to seal tickets.
    /// Spec: RFC 4120 3.1.3 (ticket encrypted with the server key's type).
    pub(crate) fn preferred(&self) -> Option<&ProtocolKey> {
        self.keys.first()
    }

    /// The key of `enctype`, if this version has one.
    pub(crate) fn key_for(&self, enctype: EncType) -> Option<&ProtocolKey> {
        self.keys.iter().find(|k| k.enc_type() == enctype)
    }

    /// The string-to-key salt (only for password-derived keys). Not secret.
    pub(crate) fn salt(&self) -> Option<&str> {
        self.salt.as_deref()
    }

    /// The string-to-key parameters used (password-derived keys).
    pub(crate) fn s2k_params(&self) -> Option<[u8; 4]> {
        self.s2k_params
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

/// The stored key set of one (principal, purpose): the CURRENT key version
/// and, after a rotation, the PREVIOUS one. Sealing always uses current;
/// decrypting a ticket may try both (until `retire_kvno`).
///
/// The set is bound, at creation, to one principal name
/// ([`PrincipalBinding`]); the binding has no setter and survives every
/// rotation (no rename in phase 1).
///
/// Opaque: no public constructor, no public key accessor (I1).
///
/// Spec: docs/10 §1 ("keyd holds current + previous"; "decrypt may try a set
/// of kvnos; signing/sealing always with the current kvno"); docs/09 D32;
/// docs/questions/Q-040 (A-19, name binding).
pub struct StoredKeySet {
    binding: PrincipalBinding,
    current: KvnoKeys,
    previous: Option<KvnoKeys>,
}

impl StoredKeySet {
    pub(crate) fn new(binding: PrincipalBinding, current: KvnoKeys) -> Self {
        StoredKeySet {
            binding,
            current,
            previous: None,
        }
    }

    /// The immutable principal-name binding. Spec: Q-040 (A-19).
    pub(crate) fn binding(&self) -> &PrincipalBinding {
        &self.binding
    }

    /// The current key version number (not secret).
    pub fn current_kvno(&self) -> Kvno {
        self.current.kvno
    }

    /// The retained previous key version number, if any (not secret).
    pub fn previous_kvno(&self) -> Option<Kvno> {
        self.previous.as_ref().map(|p| p.kvno)
    }

    pub(crate) fn current(&self) -> &KvnoKeys {
        &self.current
    }

    pub(crate) fn previous(&self) -> Option<&KvnoKeys> {
        self.previous.as_ref()
    }

    /// Install `next` as current; the old current becomes previous and the
    /// old previous is dropped (its keys are zeroized by krb-crypto).
    /// Spec: docs/10 §7 (rotate: "the current goes down to previous").
    pub(crate) fn rotate(&mut self, next: KvnoKeys) {
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
            KeyPurpose::PrincipalLongterm | KeyPurpose::Service => true,
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

    /// Spec: docs/33 §6.1 (D178); bounded per AGENTS.md §6.
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
    /// Counts and mode only — never keys (AGENTS.md §6).
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

    fn binding() -> PrincipalBinding {
        PrincipalBinding::new(
            Realm::new("EXAMPLE.ORG").unwrap(),
            PrincipalName {
                name_type: 1,
                name_string: vec![KerberosString::new("svc").unwrap()],
            },
        )
    }

    fn set(kvno: u32) -> StoredKeySet {
        let key = krb_crypto::random_to_key(EncType::Aes128CtsHmacSha196, &[0x11; 16]).unwrap();
        StoredKeySet::new(
            binding(),
            KvnoKeys::new(Kvno::new(kvno), vec![key], None, None),
        )
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
        let key = krb_crypto::random_to_key(EncType::Aes128CtsHmacSha196, &[0x33; 16]).unwrap();
        rotated.rotate(KvnoKeys::new(Kvno::new(2), vec![key], None, None));
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
        let key = krb_crypto::random_to_key(EncType::Aes128CtsHmacSha196, &[0x22; 16]).unwrap();
        s.rotate(KvnoKeys::new(Kvno::new(2), vec![key], None, None));
        assert_eq!(s.current_kvno(), Kvno::new(2));
        assert_eq!(s.previous_kvno(), Some(Kvno::new(1)));
        assert!(!s.retire_previous(Kvno::new(2)));
        assert!(s.retire_previous(Kvno::new(1)));
        assert_eq!(s.previous_kvno(), None);
        // The binding survives rotation unchanged (Q-040, A-19).
        assert_eq!(s.binding(), &binding());
    }

    /// Debug output carries no key octets (AGENTS.md §6).
    #[test]
    fn debug_has_no_key_material() {
        let key = krb_crypto::random_to_key(EncType::Aes128CtsHmacSha196, &[0x5A; 16]).unwrap();
        let s = StoredKeySet::new(
            binding(),
            KvnoKeys::new(Kvno::new(3), vec![key], None, None),
        );
        let text = format!("{s:?}");
        assert!(text.contains("kvno"));
        assert!(!text.contains("90") && !text.contains("5a") && !text.contains("5A"));
    }
}
