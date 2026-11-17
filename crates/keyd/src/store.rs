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
//! * a `BoundKeys` — whose `KeyVersion`s are the only way to a key
//!   (`KeyVersion::key_for`, `KeyVersion::preferred`) — is returned only by
//!   one of four doors, each after its check (task PN11 — see "The doors"
//!   below);
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
//!   bound to a name the rule refuses is unrepresentable;
//!
//! # The doors (task PN11; docs/59 §7.2, §7.3)
//!
//! | door | for | check |
//! |---|---|---|
//! | `bound_by` | AS / TGS issuance under a client or service key set (the AS client, the change-password service, every TGS service) | the set is the one stored under the handle a `VerifiedNameResolution` names — dird's statement whose tag, realm and freshness keyd checked (crate name_resolution); the door looks it up itself, so no other set can be handed to it (task PN11b) — it is no krbtgt, the resolution's canonical name is its bound name in the namespace's equivalence (`principal-names`), and the name the ticket will carry is one of the resolution's two names |
//! | `StoredKeySet::ticket_granting` | the krbtgt: sealing a TGT, opening a TGT or a FAST armor ticket | the set is a Krbtgt key set bound to this realm's TGS name — the canonical `krbtgt/<REALM>` the KDC always writes, exactly, no resolution ([MS-KILE] 3.3.5.1.2; RFC 4120 §7.3; docs/59 §7.2) |
//! | `StoredKeySet::accepting` | the acceptor (a service AP-REQ, a change-password request) | the ticket's (srealm, sname) and the set's binding are the same principal in the namespace's one equivalence (`principal-names` — Q-1011 item 6, A-173) |
//! | `StoredKeySet::bound_to` | `set_secret` on an existing set (dird's own install path) | the set is bound to the (realm, name) of the request's binding — never an issuance (docs/59 §3 M4: `directory.rs` stays) |
//!
//! So the KDC cannot choose which key set a name maps to (class C3, closed
//! for names), no issuance reaches a client or service key on the KDC's word
//! alone (C5 kept closed: every door is a proof type built after its check),
//! no issuance request names a resolved key set twice — the resolution is
//! the only name keyd looks it up by (task PN11b; "one request states one
//! fact twice", docs/questions/Q-1067),
//! and no door compares names by a second equivalence (C49: the two
//! namespace compares go through `principal-names`; the two exact ones
//! compare against one fixed name — the canonical TGS name — or the
//! request's own binding). `tests/key_access_inventory.rs` pins which file
//! uses which door.
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
//! # The attestation key lives in the store (A-190)
//!
//! **The class:** a key keyd needs in order to operate was held outside its
//! key store (a field of `Keyd`), so a store that outlives a keyd lifetime —
//! KL3's sealed store, or a test custody that emulates one — did not carry
//! it, and a keyd restarted over that store was operational yet could verify
//! no name resolution: it issued nothing. **The root-level change:** the
//! attestation key is part of the store — [`KeyStore::attestation_key`]
//! (read) and [`KeyStore::install_attestation_key`] (once; `Exists` when one
//! is held — never replaced) — and `Keyd` holds no copy: it reads the key
//! only from its store. A store that carries its key sets carries the key
//! with them; [`KeyStore::is_empty`] means no key set **and** no attestation
//! key. keyd's PEP rules are unchanged: only `Keyd::install_attestation_key`
//! (Role::Admin, the ceremony only, an acknowledged intent) installs it,
//! and `seal_ceremony` refuses without it (Q-1056).
//!
//! The read accessor hands a reference only to the store's owner; inside
//! keyd the owner is `Keyd`, which exposes no reference to its store, and
//! the one use is `name_attestation::verify` (pinned by
//! tests/attestation_key_custody.rs). `AttestationKey` has no accessor,
//! `Debug` or `Clone`, and wipes itself on drop (crate name-attestation:
//! a `Zeroizing` buffer).
//!
//! The development store ([`InMemoryKeyStore`]) holds the key in RAM, like
//! its key sets. KL3's sealed store must persist it with them; the sealed
//! format (KL1, crates/keyd-types `sealed_store`) has no record for it yet —
//! docs/questions/Q-1064.
//!
//! Spec: docs/10 §1 (StoredKeySet; current + previous kvno), §7, §11, §12 I1;
//! docs/09 א.7 (D32 rotation); docs/33 §6.1 (D178); docs/questions/Q-115
//! (A-35); docs/questions/Q-040 (A-19); RFC 4120 6.2 (name equivalence);
//! docs/52 §3.5, §4.4, §7 R7; docs/59 §7.4; docs/questions/Q-1033 item 5,
//! Q-1063 item 3 (A-190).

use crate::audit::AuditReason;
use crate::error::{Deny, Internal};
use crate::model::{KeyHandle, KeyPurpose, Kvno, PrincipalBinding};
use crate::name_resolution::{same_principal, VerifiedNameResolution};
use crate::template::{tgs_name, NewBinding};
use core::fmt;
use krb_crypto::{EncType, ProtocolKey};
use krb_proto::{PrincipalName, Realm};
use name_attestation::AttestationKey;
use principal_names::NameContext;
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

/// Proof that a stored key set may be used for the name an operation uses
/// it for (A-19): built only by one of the four doors — `bound_by`, and
/// [`StoredKeySet`]'s `ticket_granting`, `accepting`, `bound_to` (module
/// documentation, "The doors") — after its check. The key versions of the
/// set are reached through it.
///
/// Spec: docs/questions/Q-040 (A-19); RFC 4120 6.2; docs/52 §3.5 (R7);
/// docs/59 §7.2.
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
    /// key handle, and `issue_as_rep`, its only redeemer, requires that key
    /// set to be the one dird's verified client resolution names and binds
    /// the ticket's crealm / cname to it through that resolution
    /// (`bound_by`, tasks PN11, PN11b) before anything is sealed.
    /// Spec: docs/10 §4, §8; A-19; docs/59 §7.2; docs/questions/Q-1080.
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
/// one of its four doors or a declared `UnboundUse` (module documentation).
///
/// Opaque: no public constructor, no public key accessor (I1).
///
/// The set also keeps the handle its creation rule was checked for (task
/// PN8) — the purpose its doors judge (a krbtgt set opens only through
/// `ticket_granting`). The issuance door `bound_by` looks a set up by the
/// handle a verified name resolution names, so no handle passed alongside
/// the resolution exists to compare (task PN11b).
///
/// Spec: docs/10 §1 ("keyd holds current + previous"; "decrypt may try a set
/// of kvnos; signing/sealing always with the current kvno"); docs/09 D32;
/// docs/questions/Q-040 (A-19, name binding); docs/52 §3.5 (R7); docs/59
/// §7.2 step 4.
pub struct StoredKeySet {
    handle: KeyHandle,
    binding: PrincipalBinding,
    current: KvnoKeys,
    previous: Option<KvnoKeys>,
}

impl StoredKeySet {
    /// A new key set from its creation proof — the binding passed the
    /// creation rule (`template::check_new_binding`) for one handle — and its
    /// first version. Returns that handle, under which the caller stores the
    /// set; the set keeps it too (the purpose its doors judge).
    /// Spec: docs/questions/Q-040 (A-19); docs/10 §6, §7; docs/59 §7.2.
    pub(crate) fn create(binding: NewBinding, current: KvnoKeys) -> (KeyHandle, StoredKeySet) {
        let (handle, binding) = binding.into_parts();
        let set = StoredKeySet {
            handle,
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
    ///
    /// Since task PN11 the door of one path only: `set_secret` on an
    /// existing set, where the name compared is the request's own binding
    /// (dird's install path — docs/59 §3 M4) — never an issuance, which
    /// reaches a key only through `bound_by` or, for the krbtgt,
    /// [`StoredKeySet::ticket_granting`] (pinned by
    /// tests/key_access_inventory.rs).
    ///
    /// Spec: RFC 4120 6.2 ("Principal names that differ only in the
    /// name-type identify the same principal"); docs/questions/Q-040 (A-19);
    /// docs/52 §3.5 (R7); docs/59 §7.2, §7.3.
    pub(crate) fn bound_to(&self, realm: &Realm, name: &PrincipalName) -> Internal<BoundKeys<'_>> {
        if self.binding.matches(realm, name) {
            Ok(BoundKeys { set: self })
        } else {
            Err(Deny::denied(AuditReason::NameBindingMismatch))
        }
    }

    /// The proof that this is a krbtgt key set bound to the TGS name of
    /// `realm` — `krbtgt/<realm>`, the realm and both components exactly,
    /// the name-type not significant — through which its keys are used;
    /// otherwise `Denied` (`NameBindingMismatch`). No name resolution: the
    /// TGS name never reaches the namespace (it is reserved — RFC 4120 §6.2,
    /// §7.3), and the KDC always writes the canonical `krbtgt/<REALM>` for
    /// a TGT ([MS-KILE] 3.3.5.1.2), so its one stored binding is the check
    /// (docs/59 §7.2: "the krbtgt check stays against the stored binding,
    /// exact"). The door of sealing a TGT (`issue_as_rep`) and of opening a
    /// TGT or an armor ticket (`open_local_tgt`).
    /// Spec: RFC 4120 §6.2, §7.3; [MS-KILE] v20261110 3.3.5.1.2; docs/59
    /// §7.2; docs/questions/Q-040 (A-19), Q-1034 item 5 (i).
    pub(crate) fn ticket_granting(&self, realm: &Realm) -> Internal<BoundKeys<'_>> {
        if self.handle.purpose == KeyPurpose::Krbtgt
            && self.binding.matches(realm, &tgs_name(realm))
        {
            Ok(BoundKeys { set: self })
        } else {
            Err(Deny::denied(AuditReason::NameBindingMismatch))
        }
    }

    /// The proof that a ticket presented for (`srealm`, `sname`) may be
    /// opened under this (non-krbtgt) key set: the two names are the same
    /// principal in the namespace's one equivalence — the same
    /// `principal-names` key, the name-type ignored and the case folded —
    /// otherwise `Denied` (`NameBindingMismatch`). The acceptor's door
    /// (`verify_service_ap_req`: the LDAP front, dird's admin channel, the
    /// change-password request). The sname is outside the ticket's enc-part
    /// (RFC 4120 §5.3), so this is a consistency check, not the protection —
    /// the key the ticket decrypts under is (docs/59 §9 S6, C21); it is kept
    /// rather than dropped, and never an octet compare (Q-1011 item 6).
    /// Spec: docs/59 §7.2 (acceptor), §4.2; docs/questions/Q-1011 item 6
    /// (A-173: "the acceptor-side sname compare goes through principal-names
    /// (folded key equality)"); RFC 4120 §5.3, §6.2.
    pub(crate) fn accepting(
        &self,
        srealm: &Realm,
        sname: &PrincipalName,
        context: &NameContext,
    ) -> Internal<BoundKeys<'_>> {
        if self.handle.purpose != KeyPurpose::Krbtgt
            && same_principal(
                srealm,
                sname,
                &self.binding.realm,
                &self.binding.name,
                context,
            )
        {
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
            .field("handle", &self.handle)
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

    /// Whether the store holds nothing — no key set **and** no attestation
    /// key — keyd then starts in its provisioning ceremony (A-102, docs/52
    /// §4.4: "keyd comes up in `Provisioning` only when the store is
    /// empty"; A-190: the attestation key is part of the store).
    fn is_empty(&self) -> bool;

    /// The attestation key dird's name resolutions are verified with, once
    /// the ceremony installed it (module documentation); `None` before.
    /// Only its owner reads it — inside keyd, `Keyd`, for
    /// `name_attestation::verify` alone.
    /// Spec: docs/59 §7.2 step 1, §7.4; docs/questions/Q-1011 item 2
    /// (A-173), Q-1063 item 3 (A-190).
    fn attestation_key(&self) -> Option<&AttestationKey>;

    /// Keep `key` as the store's attestation key. Must refuse when one is
    /// already held ([`StoreError::Exists`]: never replaced — the refused
    /// key is dropped, and wipes itself). Called only by
    /// `Keyd::install_attestation_key`, after its own checks (Role::Admin,
    /// the ceremony only, an acknowledged intent).
    /// Spec: docs/59 §7.4; docs/questions/Q-1011 item 2 (A-173), Q-1033
    /// (A-177), Q-1063 item 3 (A-190).
    fn install_attestation_key(&mut self, key: AttestationKey) -> Result<(), StoreError>;

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

/// The door of AS / TGS issuance to a client or service key set (task
/// PN11): the proof that the key set a **verified** name resolution names
/// may be used for a ticket that will carry (`ticket_realm`,
/// `ticket_name`) — dird's statement, checked by keyd
/// (`name_attestation::verify` ⇒ realm ⇒ freshness,
/// `Keyd::verify_name_resolution`). Otherwise `Denied`: `KeyNotFound` when
/// no set is stored for the resolution's key set, `NameResolutionMismatch`
/// for every other refusal.
///
/// **The set comes from the resolution** (task PN11b; docs/questions/
/// Q-1067): the door looks it up in `store` under the resolution's own
/// `(principal, key_purpose)` (docs/59 §7.1, §7.2 step 4) — it takes no set
/// and no handle from its caller, so no request can name the key set beside
/// the resolution, and no keyd code can open one set with another set's
/// resolution. Step 4's compare (`principal == handle.principal`,
/// `key_purpose == handle.purpose`) is the lookup itself: nothing is left to
/// compare.
///
/// Then all of:
/// 1. the set is not a krbtgt key set — the krbtgt is reached only by its
///    exact stored binding ([`StoredKeySet::ticket_granting`]), never by a
///    resolution (docs/59 §7.2: "the KDC always writes the canonical
///    `krbtgt/<REALM>`"; RFC 4120 §7.3);
/// 2. the resolution's canonical name is the set's bound name in the
///    namespace's one equivalence — the same `principal-names` key, the
///    name-type ignored (RFC 4120 §6.2) and the case folded — never an
///    octet comparison: keyd holds no second definition of "the same name"
///    (class C49, docs/59 §3 M3; Q-1011 item 6);
/// 3. the ticket's (realm, name) is one of the resolution's two pairs — as
///    the request sent it, or canonical — exactly: keyd does not fold here,
///    dird already chose (docs/59 §7.2 step 5). Checked in the door, so no
///    issuance can take the keys and write another name.
///
/// The type does the rest: a `VerifiedNameResolution` exists only after the
/// tag, realm and freshness checks (crate name_resolution), so an unchecked
/// or stale resolution cannot reach this function.
///
/// Spec: docs/59 §7.1, §7.2 steps 1–5, §3 (M4 = C3, keeping C5 closed —
/// R7); docs/questions/Q-1011 items 4–6 (A-173), Q-1034 (A-177: the binding
/// compare is kept through PN11), Q-1067 (task PN11b); RFC 4120 §6.2, §7.3;
/// AGENTS.md §6.1 (a proof type built only after the check, one chokepoint;
/// the restatement unrepresentable).
pub(crate) fn bound_by<'s, S: KeyStore + ?Sized>(
    store: &'s S,
    verified: &VerifiedNameResolution,
    ticket_realm: &Realm,
    ticket_name: &PrincipalName,
) -> Internal<BoundKeys<'s>> {
    let set = store
        .get(&verified.handle())
        .ok_or(Deny::denied(AuditReason::KeyNotFound))?;
    let mismatch = Err(Deny::denied(AuditReason::NameResolutionMismatch));
    if set.handle.purpose == KeyPurpose::Krbtgt {
        return mismatch;
    }
    if !verified.names_binding(&set.binding) {
        return mismatch;
    }
    if !verified.names_ticket(ticket_realm, ticket_name) {
        return mismatch;
    }
    Ok(BoundKeys { set })
}

/// In-memory key store (keys in process RAM, zeroized on drop), bounded.
/// It holds the attestation key too (A-190), in RAM, wiped on drop
/// (`AttestationKey`'s `Zeroizing` buffer).
///
/// Spec: docs/10 §11 (software fallback only for development, D35); D178;
/// docs/59 §7.4.
pub struct InMemoryKeyStore {
    sets: HashMap<KeyHandle, StoredKeySet>,
    capacity: usize,
    allow_krbtgt: bool,
    attestation_key: Option<AttestationKey>,
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
            attestation_key: None,
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
            attestation_key: None,
        }
    }

    /// Number of stored key sets.
    pub fn len(&self) -> usize {
        self.sets.len()
    }

    /// `true` if nothing is stored: no key set and no attestation key
    /// ([`KeyStore::is_empty`]).
    pub fn is_empty(&self) -> bool {
        self.sets.is_empty() && self.attestation_key.is_none()
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

    /// Spec: docs/52 §4.4 (A-102); A-190.
    fn is_empty(&self) -> bool {
        InMemoryKeyStore::is_empty(self)
    }

    /// Spec: docs/59 §7.4; A-190.
    fn attestation_key(&self) -> Option<&AttestationKey> {
        self.attestation_key.as_ref()
    }

    /// Once; `Exists` when one is held (the refused key wipes on drop).
    /// Spec: docs/59 §7.4; docs/questions/Q-1011 item 2; A-190.
    fn install_attestation_key(&mut self, key: AttestationKey) -> Result<(), StoreError> {
        if self.attestation_key.is_some() {
            return Err(StoreError::Exists);
        }
        self.attestation_key = Some(key);
        Ok(())
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
    /// Counts and mode only — never keys (AGENTS.md §6); whether the
    /// attestation key is held, never anything of it.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InMemoryKeyStore")
            .field("key_sets", &self.sets.len())
            .field("capacity", &self.capacity)
            .field("insecure_development_krbtgt", &self.allow_krbtgt)
            .field("attestation_key_held", &self.attestation_key.is_some())
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
            handle: KeyHandle::new(PrincipalId::from_bytes([1; 16]), KeyPurpose::Service),
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

    /// A-190 (docs/59 §7.4; Q-1011 item 2): the store holds the attestation
    /// key once — a second install is `Exists` and leaves the first — and a
    /// store holding only the key is not empty (a keyd started over it is
    /// operational, docs/52 §4.4); its `Debug` says only whether the key is
    /// held.
    #[test]
    fn the_store_holds_the_attestation_key_once() {
        let key = |byte| AttestationKey::from_bytes(&[byte; 32]).unwrap();
        let mut store = InMemoryKeyStore::new(4);
        assert!(store.is_empty());
        assert!(store.attestation_key().is_none());
        assert!(format!("{store:?}").contains("attestation_key_held: false"));
        assert_eq!(store.install_attestation_key(key(0x5A)), Ok(()));
        assert!(store.attestation_key().is_some());
        assert!(!store.is_empty());
        assert!(!KeyStore::is_empty(&store));
        assert_eq!(
            store.install_attestation_key(key(0x6B)),
            Err(StoreError::Exists)
        );
        let text = format!("{store:?}");
        assert!(text.contains("attestation_key_held: true"), "{text}");
        assert!(!text.contains("5a") && !text.contains("5A") && !text.contains("90,"));
    }

    /// Debug output carries no key octets (AGENTS.md §6).
    #[test]
    fn debug_has_no_key_material() {
        let s = StoredKeySet {
            handle: KeyHandle::new(PrincipalId::from_bytes([1; 16]), KeyPurpose::Service),
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
