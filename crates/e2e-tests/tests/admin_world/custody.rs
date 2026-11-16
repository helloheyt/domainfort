//! **TEST-ONLY** key custody across keyd lifetimes (task A13; the
//! single-uid role problem — docs/questions/Q-430).
//!
//! keyd maps one uid to one Role (docs/50 R50-3), and the test process has
//! one uid. The admin-plane flow needs that uid as Admin (`keyadm
//! ceremony`), Directory (`provision first-admin-secret`, admind's
//! `set_secret`), Kdc (the kdc) and Ldap (dird's admin service) — and the
//! key sets one role creates must be the ones the next role uses. keyd's
//! development store is in memory and lost when keyd stops (P-17), so the
//! harness's "restart keyd with another uid map" pattern alone would lose
//! the ceremony's keys.
//!
//! [`CustodyStore`] is a `keyd::KeyStore` written here, in the test crate,
//! from that trait's documented contract (crates/keyd store.rs: `accepts`,
//! `get`, `get_mut`, `insert` — refuses an existing handle and a full store,
//! `destroy` — refuses krbtgt, reports an unknown handle) and the
//! development store's rules (krbtgt accepted — development only, D178;
//! bounded). It holds the key sets by value (`StoredKeySet` is opaque: no
//! key octet is reachable from here) and, **when keyd drops it** (the engine
//! thread ending at the daemon's stop), it hands its sets back to its
//! [`Custody`]. The next keyd lifetime — the real `keyd_daemon::serve`, with
//! the test uid mapped to the next role — is built on them. Nothing in keyd
//! or keyd-daemon is changed or bypassed: every call still goes through the
//! daemon's socket, its uid map and keyd's own role / purpose / binding
//! checks; only the store survives the restart, as a persistent store would
//! (the P-17 direction). The keys stay in this process's memory and are
//! never written to disk.
//!
//! During an admin phase two keyd lifetimes run at once (dird's under Ldap,
//! admind's under Directory); admind's starts from an empty custody, and
//! [`Custody::merge_from`] folds the key sets it created (new accounts'
//! passwords) back into the main custody when both have stopped. A handle
//! present on both sides is refused (the tests never set the password of an
//! account whose key set already exists during an admin phase).
//!
//! **The attestation key travels with the key sets** (task PN11, A-190):
//! since A-190 it is part of keyd's `KeyStore` (`attestation_key`,
//! `install_attestation_key` — once, `Exists` when held), so the custody
//! holds it by value beside the sets and hands it home with them: the keyd
//! of a later phase — operational, with no ceremony — still verifies dird's
//! name resolutions, as a keyd over KL3's sealed store will. Only the
//! ceremony's keyd installs it (Role::Admin, keyd's own rule); admind's
//! custody never holds one, and [`Custody::merge_from`] refuses a key held
//! on both sides.
//!
//! Spec: docs/50 R50-3, R50-18, §9 (tier 2: "the uid map is injected with
//! the test's own uid for the role under test"); docs/10 §1, §11; crates/keyd
//! `KeyStore` (its documentation); P-17; A-82; docs/59 §7.4; docs/questions/
//! Q-1063 item 3 (A-190).

use keyd::{AttestationKey, KeyHandle, KeyPurpose, KeyStore, StoreError, StoredKeySet};
use keyd_types::Kvno;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// The bound of a custody (key sets), as keyd-daemon's development store
/// (`keyd_daemon::startup::KEY_STORE_CAPACITY`). Test data.
pub const CAPACITY: usize = 4096;

type Sets = HashMap<KeyHandle, StoredKeySet>;

/// What a custody holds between keyd lifetimes: the key sets and the
/// attestation key (A-190), by value.
#[derive(Default)]
struct Held {
    sets: Sets,
    attestation_key: Option<AttestationKey>,
}

/// Where the key sets and the attestation key rest between keyd lifetimes.
/// `None` while lent to a running keyd.
#[derive(Clone, Default)]
pub struct Custody(Arc<Mutex<Option<Held>>>);

impl Custody {
    /// An empty custody.
    pub fn new() -> Custody {
        Custody(Arc::new(Mutex::new(Some(Held::default()))))
    }

    /// Lend the key sets and the attestation key to the next keyd: the
    /// store keyd is built on. Panics if they are still lent (a keyd of
    /// this custody runs).
    pub fn lend(&self) -> CustodyStore {
        let held = self
            .0
            .lock()
            .unwrap()
            .take()
            .expect("the key sets are back from the previous keyd");
        CustodyStore {
            held,
            home: self.clone(),
        }
    }

    /// `true` once the last keyd built on this custody dropped its store.
    pub fn is_home(&self) -> bool {
        self.0.lock().unwrap().is_some()
    }

    /// Move every key set of `other` (whose keyd has stopped) into this
    /// custody, and its attestation key if it holds one. A handle on both
    /// sides, or an attestation key on both sides, is a test error (admind's
    /// custody never holds a key: only the ceremony's keyd installs one).
    pub fn merge_from(&self, other: &Custody) {
        let moved = other
            .0
            .lock()
            .unwrap()
            .replace(Held::default())
            .expect("the other keyd has stopped");
        let mut held = self.0.lock().unwrap();
        let held = held.as_mut().expect("this custody's keyd has stopped");
        for (handle, set) in moved.sets {
            assert!(
                held.sets.insert(handle, set).is_none(),
                "a key set was created on both sides: {handle:?}"
            );
        }
        if let Some(key) = moved.attestation_key {
            assert!(
                held.attestation_key.is_none(),
                "an attestation key is held on both sides"
            );
            held.attestation_key = Some(key);
        }
    }

    /// The current kvno of `handle`'s key set, if held (not secret: docs/37
    /// §2 metadata). Panics while lent.
    pub fn kvno(&self, handle: &KeyHandle) -> Option<Kvno> {
        let held = self.0.lock().unwrap();
        held.as_ref()
            .expect("the key sets are home")
            .sets
            .get(handle)
            .map(StoredKeySet::current_kvno)
    }

    /// How many key sets are held. Panics while lent.
    pub fn len(&self) -> usize {
        self.0.lock().unwrap().as_ref().expect("home").sets.len()
    }
}

/// The key store of one keyd lifetime (module documentation).
pub struct CustodyStore {
    held: Held,
    home: Custody,
}

impl KeyStore for CustodyStore {
    /// Development only: krbtgt accepted, as keyd-daemon's development store
    /// (`InMemoryKeyStore::new_insecure_development_allowing_krbtgt`; D178:
    /// production needs an HSM-backed store for krbtgt). TESTS ONLY.
    fn accepts(&self, purpose: KeyPurpose) -> bool {
        match purpose {
            KeyPurpose::Krbtgt
            | KeyPurpose::PrincipalLongterm
            | KeyPurpose::Service
            | KeyPurpose::AdminService
            | KeyPurpose::ChangePasswordService => true,
        }
    }

    /// docs/52 §4.4 (A-102): a keyd whose store is empty at start is in its
    /// provisioning ceremony; the later phases' keyds start with the
    /// carried key sets (and the attestation key — A-190) and so are
    /// operational. Empty = no key set and no attestation key (the trait's
    /// contract).
    fn is_empty(&self) -> bool {
        self.held.sets.is_empty() && self.held.attestation_key.is_none()
    }

    /// The trait's contract (A-190): the key the ceremony installed, carried
    /// from lifetime to lifetime.
    fn attestation_key(&self) -> Option<&AttestationKey> {
        self.held.attestation_key.as_ref()
    }

    /// The trait's contract (A-190): once — `Exists` when one is held (the
    /// refused key wipes on drop).
    fn install_attestation_key(&mut self, key: AttestationKey) -> Result<(), StoreError> {
        if self.held.attestation_key.is_some() {
            return Err(StoreError::Exists);
        }
        self.held.attestation_key = Some(key);
        Ok(())
    }

    fn get(&self, handle: &KeyHandle) -> Option<&StoredKeySet> {
        self.held.sets.get(handle)
    }

    fn get_mut(&mut self, handle: &KeyHandle) -> Option<&mut StoredKeySet> {
        self.held.sets.get_mut(handle)
    }

    /// The trait's contract: an existing handle ⇒ `Exists`, a full store ⇒
    /// `Full` (bounded, AGENTS.md §6).
    fn insert(&mut self, handle: KeyHandle, set: StoredKeySet) -> Result<(), StoreError> {
        if !self.accepts(handle.purpose) {
            return Err(StoreError::Refused);
        }
        if self.held.sets.contains_key(&handle) {
            return Err(StoreError::Exists);
        }
        if self.held.sets.len() >= CAPACITY {
            return Err(StoreError::Full);
        }
        self.held.sets.insert(handle, set);
        Ok(())
    }

    /// The trait's contract: never krbtgt (A-35), an unknown handle ⇒
    /// `NotFound`; the removed set is dropped here (its keys wipe on drop,
    /// docs/10 §11).
    fn destroy(&mut self, handle: &KeyHandle) -> Result<(), StoreError> {
        if handle.purpose == KeyPurpose::Krbtgt {
            return Err(StoreError::Refused);
        }
        let set = self.held.sets.remove(handle).ok_or(StoreError::NotFound)?;
        drop(set);
        Ok(())
    }
}

impl Drop for CustodyStore {
    /// Hand the key sets and the attestation key back (module
    /// documentation).
    fn drop(&mut self) {
        let held = std::mem::take(&mut self.held);
        if let Ok(mut home) = self.home.0.lock() {
            *home = Some(held);
        }
    }
}
