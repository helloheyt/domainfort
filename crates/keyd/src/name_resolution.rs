//! keyd's side of dird's name-resolution attestation (task PN8; docs/59 §7;
//! decision A-173 — docs/questions/Q-1011): the verified resolution, the
//! one function that makes it, and the attestation key's slot it reads.
//!
//! # What it does
//!
//! dird resolves the name a request carries and states the result as a
//! `NameResolution` (crate keyd-types), tagged with the attestation key
//! (`AttestedNameResolution`, crate name-attestation); the KDC only forwards
//! it. keyd checks it in the order of docs/59 §7.2 —
//!
//! 1. the tag, under the attestation key installed in this start's ceremony,
//!    compared in constant time **before** any field is used
//!    (`name_attestation::verify` ⇒ `AuthenticatedNameResolution`);
//! 2. the canonical realm is keyd's own realm;
//! 3. freshness on keyd's own clock: `|now − issued_at| ≤ 30 s`
//!    (`NameResolution::is_fresh_at`; `now` never from the wire — R50-5);
//!
//! — and only then is there a [`VerifiedNameResolution`]. Step 4 (the
//! resolution names the key set: principal, purpose, bound name) is
//! `StoredKeySet::bound_by` (crate store), the only way from a verified
//! resolution to a key.
//!
//! # Additive (task PN8)
//!
//! Nothing outside tests calls [`Keyd::verify_name_resolution`] or
//! `StoredKeySet::bound_by` yet: AS / TGS issuance still binds by
//! `StoredKeySet::bound_to` and moves to the resolution in task PN11; the
//! wire of the install operation is task PN9 (docs/59 §10).
//!
//! # Classes closed by construction (AGENTS.md §6.1)
//!
//! * **Use of an unverified resolution** (docs/59 §7.2 step 1; class C3 —
//!   the KDC asserting which key set a name maps to). [`VerifiedNameResolution`]
//!   has private fields and one constructor, which takes the proof type
//!   `AuthenticatedNameResolution` **by value** (only
//!   `name_attestation::verify` builds one, after the tag compared equal) and
//!   itself runs steps 2 and 3. So a resolution whose tag, realm or
//!   freshness was not checked cannot be represented as verified, and the
//!   only door to a key (`bound_by`) takes nothing else.
//! * **Key export / MAC oracle** (D28 / D29; A-145 RC-6, C42). The key enters
//!   once, by `Keyd::install_attestation_key` (crate admin), and is held in a
//!   private slot of [`Keyd`]; `AttestationKey` has no accessor, `Debug` or
//!   `Clone`, so no keyd code can hand out its octets, and no keyd function
//!   returns the key or tags with it — keyd only verifies (pinned lexically
//!   by tests/attestation_key_custody.rs: the product source never names
//!   `name_attestation::tag` or `AttestationKey::from_bytes`, and no
//!   signature returns an `AttestationKey`).
//! * **A second name equivalence** (C49). Whether the resolution's canonical
//!   name is the key set's bound name is decided by `principal-names` (the
//!   namespace key of both names), never by an octet comparison written here.
//!
//! # Residuals (documented, not hidden)
//!
//! * A compromised KDC can replay a true, fresh resolution within the 30 s
//!   window (docs/59 §7.5, S4) — it cannot invent a mapping.
//! * A compromised dird can sign a false resolution (S5; dird owns the fact —
//!   C16): `check_new_binding` at creation and the binding compare of
//!   `bound_by` narrow what it can map a name to.
//! * The key lives in process memory, installed again at every start (the
//!   development custody until KL3 — P-71); a keyd that starts operational
//!   (a non-empty store) has no ceremony and so no key: every resolution is
//!   refused (fail closed) until the sealed store keeps the key (KL3).
//! * The install is the operation `InstallAttestationKey` since task PN9
//!   (capability-table row, one audit record, its intent acknowledged by
//!   auditd first, the wire of ipc-keyd and the codes of ipc-audit —
//!   docs/questions/Q-1033, Q-1038).
//!
//! # Provenance
//!
//! Written only from docs/59 (§3 M4, §7.1–§7.5, §10 the PN8 row),
//! docs/questions/Q-1011 (A-173), Q-1018, Q-1023 (A-175), Q-792, PENDING-OWNER
//! A-19, A-63, A-65, A-102, A-145, A-150, A-173, A-175, RFC 4120 §6.2 and
//! §7.3 (pinned copy, SHA-256 re-checked against tools/spec-pin/manifest.json
//! in this session), and the public APIs of this project's crates keyd-types,
//! name-attestation and principal-names. No other implementation was
//! consulted or recalled (AGENTS.md §1-3).
//!
//! Spec: docs/59 §7.2, §7.4; docs/questions/Q-1011 items 2–4, 6 (A-173);
//! A-145 RC-6; AGENTS.md §6.1.

use crate::audit::{AuditReason, AuditSink};
use crate::entropy::EntropySource;
use crate::error::{Deny, Internal};
use crate::keyd::Keyd;
use crate::model::{KeyHandle, PrincipalBinding};
use crate::store::KeyStore;
use keyd_types::{AttestedNameResolution, NameResolution};
use krb_proto::{KerberosTime, Realm};
use name_attestation::AuthenticatedNameResolution;
use principal_names::{key_of_request, NameContext, RequestKey};

/// A name resolution keyd verified: dird's tag checked under the installed
/// attestation key, the canonical realm keyd's own, issued within the
/// freshness window of keyd's clock (docs/59 §7.2 steps 1–3). Built only
/// from the proof `AuthenticatedNameResolution`, by
/// [`Keyd::verify_name_resolution`]; its fields are private. Consumed by
/// `StoredKeySet::bound_by` (step 4). Not secret.
///
/// Spec: docs/59 §7.2; docs/questions/Q-1011 item 4 (A-173: "`BoundKeys`
/// only from `VerifiedNameResolution`"); AGENTS.md §6.1.
#[derive(Debug)]
#[cfg_attr(not(test), allow(dead_code))] // issuance adopts it in PN11
pub(crate) struct VerifiedNameResolution {
    resolution: NameResolution,
    /// The namespace of keyd's realm (its one alias — principal-names), in
    /// which `bound_by` compares names.
    context: NameContext,
}

#[cfg_attr(not(test), allow(dead_code))] // issuance adopts it in PN11
impl VerifiedNameResolution {
    /// Steps 2 and 3 of docs/59 §7.2 on a resolution whose tag
    /// `name_attestation::verify` accepted (step 1 — the proof, taken by
    /// value): the canonical realm is `realm` (keyd's), octet for octet —
    /// both sides hold the configured realm (the DNS name in upper case,
    /// docs/59 §4.5, R47-4), so a variant is a misconfiguration and fails closed
    /// (`WrongRealm`); and the realm forms a namespace (`NameContext`) — or
    /// `WrongRealm`; then freshness on keyd's `now` (`NameResolutionStale`).
    /// Spec: docs/59 §7.2 steps 2–3; docs/questions/Q-1011 items 3, 4;
    /// docs/59 §7.2 step 3 (R50-5); AGENTS.md §6 (fail closed).
    fn from_authenticated(
        authenticated: AuthenticatedNameResolution,
        realm: &Realm,
        now: &KerberosTime,
    ) -> Internal<VerifiedNameResolution> {
        let resolution = authenticated.into_resolution();
        if resolution.canonical_realm().as_bytes() != realm.as_bytes() {
            return Err(Deny::denied(AuditReason::WrongRealm));
        }
        let context =
            NameContext::new(realm.as_str()).map_err(|_| Deny::denied(AuditReason::WrongRealm))?;
        if !resolution.is_fresh_at(now) {
            return Err(Deny::denied(AuditReason::NameResolutionStale));
        }
        Ok(VerifiedNameResolution {
            resolution,
            context,
        })
    }

    /// The verified resolution (its names, for the ticket-template check of
    /// task PN11: the names in a ticket are one of its two name pairs —
    /// docs/59 §7.2 step 5). Spec: docs/59 §7.1.
    pub(crate) fn resolution(&self) -> &NameResolution {
        &self.resolution
    }

    /// The key set the resolution names: `(principal, key_purpose)`.
    /// Spec: docs/59 §7.2 step 4; docs/10 §1.
    pub(crate) fn handle(&self) -> KeyHandle {
        KeyHandle::new(self.resolution.principal(), self.resolution.key_purpose())
    }

    /// `true` if the resolution's canonical (realm, name) and `binding` are
    /// the same principal in the namespace's one equivalence: both give the
    /// same namespace key (`principal_names::key_of_request` — the name-type
    /// ignored, RFC 4120 §6.2; the case folded; the realm one of keyd's
    /// realm's aliases). A name that gives no key (a TGS name, a realm alias,
    /// a foreign realm, a malformed name) is the same as nothing. Never an
    /// octet comparison (class C49).
    /// Spec: docs/59 §4.2, §7.2 step 4; docs/questions/Q-1011 item 6
    /// (A-173: "folded key equality"); RFC 4120 §6.2.
    pub(crate) fn names_binding(&self, binding: &PrincipalBinding) -> bool {
        let canonical = key_of_request(
            self.resolution.canonical_name(),
            self.resolution.canonical_realm(),
            &self.context,
        );
        let bound = key_of_request(&binding.name, &binding.realm, &self.context);
        matches!((canonical, bound), (RequestKey::Key(a), RequestKey::Key(b)) if a == b)
    }
}

impl<S: KeyStore, A: AuditSink, E: EntropySource> Keyd<S, A, E> {
    /// Verify dird's attested name resolution — docs/59 §7.2 steps 1–3 — on
    /// keyd's own clock `now` (never a value from the request, R50-5):
    ///
    /// 1. keyd holds an attestation key (else `AttestationKeyMissing`: none
    ///    was installed in this start's ceremony — fail closed);
    /// 2. its tag verifies under that key, in constant time, before any
    ///    field is read (`name_attestation::verify`; else
    ///    `NameResolutionInvalid`);
    /// 3. the canonical realm is keyd's realm (else `WrongRealm`);
    /// 4. `|now − issued_at| ≤ 30 s` (else `NameResolutionStale`).
    ///
    /// Every refusal is the uniform `Denied` (A-26: decided before any
    /// ticket work). The step of the operation that uses it (AS / TGS
    /// issuance, task PN11) carries the reason in its one audit record; this
    /// function emits none. Reads only.
    ///
    /// Spec: docs/59 §7.2 steps 1–3; docs/questions/Q-1011 items 2–4
    /// (A-173); A-26 (uniform before the cryptographic chain).
    #[cfg_attr(not(test), allow(dead_code))] // issuance adopts it in PN11
    pub(crate) fn verify_name_resolution(
        &self,
        attested: &AttestedNameResolution,
        now: &KerberosTime,
    ) -> Internal<VerifiedNameResolution> {
        let key = self
            .attestation_key
            .as_ref()
            .ok_or(Deny::denied(AuditReason::AttestationKeyMissing))?;
        let authenticated = name_attestation::verify(key, attested)
            .map_err(|_| Deny::denied(AuditReason::NameResolutionInvalid))?;
        VerifiedNameResolution::from_authenticated(authenticated, &self.config.realm, now)
    }
}

#[cfg(test)]
mod tests {
    //! Sources: docs/59 §7.2 (the checks and their order), §10.1 (the
    //! attacks: a wrong tag, a stale resolution, another principal, another
    //! purpose, a tag of another key), docs/questions/Q-1011 items 2–4, 6
    //! (A-173: ceremony-only install, W = 30 s, folded key equality) and
    //! RFC 4120 §6.2 (the name-type is not significant), §7.3 (the TGS
    //! name). The test signer is `name_attestation::tag` under a key made up
    //! here — test code only (the product never tags: tests/
    //! attestation_key_custody.rs). Every value is constructed by hand; no
    //! vector comes from any other implementation.

    use super::*;
    use crate::audit::AuditRecord;
    use crate::authz::{CallerId, Role};
    use crate::config::KeydConfig;
    use crate::model::{KeyPurpose, PrincipalId};
    use crate::store::InMemoryKeyStore;
    use crate::EncTypeId;
    use keyd_types::{CeremonyState, NameResolutionFields};
    use krb_proto::{KerberosString, PrincipalName};
    use name_attestation::{AttestationKey, ATTESTATION_KEY_LEN};

    /// The attestation key of these tests (dird's and keyd's copy).
    const TEST_KEY: [u8; ATTESTATION_KEY_LEN] = [0x5C; ATTESTATION_KEY_LEN];
    /// Another key (a forger's, or a stale deployment's).
    const OTHER_KEY: [u8; ATTESTATION_KEY_LEN] = [0x3A; ATTESTATION_KEY_LEN];

    const ADMIN: CallerId = CallerId {
        uid: 300,
        role: Role::Admin,
    };
    const KDC: CallerId = CallerId {
        uid: 100,
        role: Role::Kdc,
    };
    const DIRECTORY: CallerId = CallerId {
        uid: 200,
        role: Role::Directory,
    };
    const LDAP: CallerId = CallerId {
        uid: 400,
        role: Role::Ldap,
    };

    const REALM: &str = "EXAMPLE.ORG";
    const SERVICE_ID: PrincipalId = PrincipalId::from_bytes([0x5E; 16]);
    const ALICE_ID: PrincipalId = PrincipalId::from_bytes([0xA1; 16]);
    const KRBTGT_ID: PrincipalId = PrincipalId::from_bytes([0x7B; 16]);
    const SERVICE: KeyHandle = KeyHandle::new(SERVICE_ID, KeyPurpose::Service);
    const ALICE: KeyHandle = KeyHandle::new(ALICE_ID, KeyPurpose::PrincipalLongterm);
    const KRBTGT: KeyHandle = KeyHandle::new(KRBTGT_ID, KeyPurpose::Krbtgt);

    #[derive(Default)]
    struct Records(Vec<AuditRecord>);

    impl AuditSink for Records {
        fn record(&mut self, record: &AuditRecord) {
            self.0.push(record.clone());
        }
    }

    type TestKeyd = Keyd<InMemoryKeyStore, Records>;

    fn key(bytes: &[u8; ATTESTATION_KEY_LEN]) -> AttestationKey {
        AttestationKey::from_bytes(bytes).unwrap()
    }

    fn s(text: &str) -> KerberosString {
        KerberosString::new(text).unwrap()
    }

    fn name(name_type: i32, parts: &[&str]) -> PrincipalName {
        PrincipalName {
            name_type,
            name_string: parts.iter().map(|p| s(p)).collect(),
        }
    }

    fn realm() -> Realm {
        s(REALM)
    }

    /// keyd's clock in these tests, and a second offset from it.
    fn at(second: u8) -> KerberosTime {
        KerberosTime::new(2026, 11, 15, 10, 20, second).unwrap()
    }

    fn now() -> KerberosTime {
        at(30)
    }

    fn service_name() -> PrincipalName {
        name(3, &["host", "files.example.org"])
    }

    /// A keyd in its ceremony with a krbtgt, a service and a user key set
    /// (keyd-drawn keys; the kernel CSPRNG — `Keyd::new`).
    fn keyd() -> TestKeyd {
        let mut config = KeydConfig::new(realm());
        config.enctypes = vec![EncTypeId::Aes256CtsHmacSha196];
        let store = InMemoryKeyStore::new_insecure_development_allowing_krbtgt(8);
        let started = KerberosTime::new(2026, 11, 14, 10, 0, 0).unwrap();
        let mut keyd = Keyd::new(config, store, Records::default(), &started).unwrap();
        for (handle, binding) in [
            (KRBTGT, name(2, &["krbtgt", REALM])),
            (SERVICE, service_name()),
            (ALICE, name(1, &["alice"])),
        ] {
            keyd.create_key(
                &ADMIN,
                &handle,
                &PrincipalBinding::new(realm(), binding),
                &now(),
            )
            .unwrap();
        }
        keyd
    }

    fn keyd_with_key() -> TestKeyd {
        let mut keyd = keyd();
        keyd.install_attestation_key(&ADMIN, key(&TEST_KEY), &now())
            .unwrap();
        keyd
    }

    /// dird's resolution of the service's SPN, issued at keyd's `now`.
    fn fields() -> NameResolutionFields {
        NameResolutionFields {
            realm_as_sent: realm(),
            name_as_sent: service_name(),
            canonical_realm: realm(),
            canonical_name: service_name(),
            principal: SERVICE_ID,
            key_purpose: KeyPurpose::Service,
            snapshot: 7,
            issued_at: now(),
        }
    }

    /// The test signer: dird's `tag` under `signing_key`.
    fn signed(
        fields: NameResolutionFields,
        signing_key: &[u8; ATTESTATION_KEY_LEN],
    ) -> AttestedNameResolution {
        let resolution = NameResolution::new(fields).unwrap();
        name_attestation::tag(&key(signing_key), &resolution).unwrap()
    }

    fn reason<T>(result: Internal<T>) -> Result<(), AuditReason> {
        result.map(|_| ()).map_err(|deny| deny.reason)
    }

    /// docs/59 §7.2 steps 1–3: a resolution dird tagged with the installed
    /// key, of keyd's realm, issued now, verifies — and names the key set
    /// `(principal, key_purpose)` it states.
    #[test]
    fn a_tagged_fresh_resolution_of_this_realm_verifies() {
        let keyd = keyd_with_key();
        let verified = keyd
            .verify_name_resolution(&signed(fields(), &TEST_KEY), &now())
            .unwrap();
        assert_eq!(verified.handle(), SERVICE);
        assert_eq!(verified.resolution().canonical_name(), &service_name());
        assert_eq!(verified.resolution().snapshot(), 7);
    }

    /// Q-1011 item 2: the key comes only from this start's ceremony; without
    /// it no resolution — not even a correctly tagged one — is believed
    /// (fail closed).
    #[test]
    fn without_an_installed_key_every_resolution_is_refused() {
        let keyd = keyd();
        assert!(!keyd.has_attestation_key());
        assert_eq!(
            reason(keyd.verify_name_resolution(&signed(fields(), &TEST_KEY), &now())),
            Err(AuditReason::AttestationKeyMissing)
        );
    }

    /// docs/59 §7.2 step 1, §10.1: a tag under another key, a changed tag
    /// bit, or a field changed after tagging is not dird's statement.
    #[test]
    fn a_wrong_tag_is_refused() {
        let keyd = keyd_with_key();
        assert_eq!(
            reason(keyd.verify_name_resolution(&signed(fields(), &OTHER_KEY), &now())),
            Err(AuditReason::NameResolutionInvalid)
        );
        let good = signed(fields(), &TEST_KEY);
        for bit in [0usize, 7, 128, 255] {
            let mut tag = *good.tag();
            tag[bit / 8] ^= 1 << (bit % 8);
            let flipped = AttestedNameResolution::new(good.resolution().clone(), tag);
            assert_eq!(
                reason(keyd.verify_name_resolution(&flipped, &now())),
                Err(AuditReason::NameResolutionInvalid),
                "bit {bit}"
            );
        }
        // The service's tag on a resolution naming alice's key set instead.
        let mut other = fields();
        other.principal = ALICE_ID;
        other.key_purpose = KeyPurpose::PrincipalLongterm;
        let swapped = AttestedNameResolution::new(NameResolution::new(other).unwrap(), *good.tag());
        assert_eq!(
            reason(keyd.verify_name_resolution(&swapped, &now())),
            Err(AuditReason::NameResolutionInvalid)
        );
    }

    /// docs/59 §7.2 step 2: the canonical realm is keyd's, octet for octet
    /// (a case variant is another configuration — fail closed).
    #[test]
    fn another_canonical_realm_is_refused() {
        let keyd = keyd_with_key();
        for other in ["example.org", "EXAMPLE.NET"] {
            let mut f = fields();
            f.canonical_realm = s(other);
            assert_eq!(
                reason(keyd.verify_name_resolution(&signed(f, &TEST_KEY), &now())),
                Err(AuditReason::WrongRealm),
                "{other}"
            );
        }
    }

    /// Q-1011 item 3 (A-173): W = 30 s either side of keyd's own clock,
    /// inclusive; and the order of docs/59 §7.2 — the tag before the realm,
    /// the realm before freshness.
    #[test]
    fn freshness_is_thirty_seconds_on_keyds_clock() {
        let keyd = keyd_with_key();
        let issued = signed(fields(), &TEST_KEY);
        for second in [0, 30, 59] {
            assert_eq!(
                reason(keyd.verify_name_resolution(&issued, &at(second))),
                Ok(()),
                "{second}"
            );
        }
        let late = KerberosTime::new(2026, 11, 15, 10, 21, 1).unwrap();
        let early = KerberosTime::new(2026, 11, 15, 10, 19, 59).unwrap();
        for when in [late, early] {
            assert_eq!(
                reason(keyd.verify_name_resolution(&issued, &when)),
                Err(AuditReason::NameResolutionStale)
            );
        }
        let stale_forged = signed(fields(), &OTHER_KEY);
        assert_eq!(
            reason(keyd.verify_name_resolution(&stale_forged, &late)),
            Err(AuditReason::NameResolutionInvalid)
        );
        let mut f = fields();
        f.canonical_realm = s("EXAMPLE.NET");
        assert_eq!(
            reason(keyd.verify_name_resolution(&signed(f, &TEST_KEY), &late)),
            Err(AuditReason::WrongRealm)
        );
    }

    /// The verified resolution of `f` (tagged with the installed key).
    fn verified(keyd: &TestKeyd, f: NameResolutionFields) -> VerifiedNameResolution {
        keyd.verify_name_resolution(&signed(f, &TEST_KEY), &now())
            .unwrap()
    }

    fn bound_by(
        keyd: &TestKeyd,
        handle: &KeyHandle,
        f: NameResolutionFields,
    ) -> Result<(), AuditReason> {
        let resolution = verified(keyd, f);
        let set = keyd.store.get(handle).unwrap();
        reason(set.bound_by(&resolution))
    }

    /// docs/59 §7.2 step 4: the resolution of the service's own handle and
    /// bound name yields the set's keys (its current version).
    #[test]
    fn bound_by_its_own_resolution_gives_the_keys() {
        let keyd = keyd_with_key();
        let resolution = verified(&keyd, fields());
        let set = keyd.store.get(&SERVICE).unwrap();
        let bound = set.bound_by(&resolution).unwrap();
        assert_eq!(bound.current().kvno(), crate::Kvno::INITIAL);
        // The user's key set by its own resolution, too.
        let mut f = fields();
        f.name_as_sent = name(1, &["alice"]);
        f.canonical_name = name(1, &["alice"]);
        f.principal = ALICE_ID;
        f.key_purpose = KeyPurpose::PrincipalLongterm;
        assert_eq!(bound_by(&keyd, &ALICE, f), Ok(()));
    }

    /// docs/59 §7.2 step 4, §10.1: a verified resolution of another
    /// principal or another purpose never opens this set — the comparison
    /// is with the set's own handle.
    #[test]
    fn bound_by_refuses_another_principal_or_purpose() {
        let keyd = keyd_with_key();
        let mut other_principal = fields();
        other_principal.principal = ALICE_ID;
        assert_eq!(
            bound_by(&keyd, &SERVICE, other_principal),
            Err(AuditReason::NameResolutionMismatch)
        );
        for purpose in [
            KeyPurpose::PrincipalLongterm,
            KeyPurpose::AdminService,
            KeyPurpose::ChangePasswordService,
            KeyPurpose::Krbtgt,
        ] {
            let mut f = fields();
            f.key_purpose = purpose;
            assert_eq!(
                bound_by(&keyd, &SERVICE, f),
                Err(AuditReason::NameResolutionMismatch),
                "{purpose:?}"
            );
        }
        // Alice's resolution presented to the service's set.
        let mut alice = fields();
        alice.canonical_name = name(1, &["alice"]);
        alice.principal = ALICE_ID;
        alice.key_purpose = KeyPurpose::PrincipalLongterm;
        assert_eq!(
            bound_by(&keyd, &SERVICE, alice),
            Err(AuditReason::NameResolutionMismatch)
        );
    }

    /// Q-1011 item 6 (A-173: folded key equality, through principal-names);
    /// RFC 4120 §6.2: the canonical name matches the bound name in the
    /// namespace's equivalence — whatever the name-type or the case — and
    /// not otherwise: another name, a "/" inside one component (no key —
    /// injectivity, docs/59 §4.2), an extra component.
    #[test]
    fn bound_by_compares_names_by_the_namespace_key() {
        let keyd = keyd_with_key();
        for (canonical, expected) in [
            (name(3, &["host", "files.example.org"]), Ok(())),
            (name(1, &["host", "files.example.org"]), Ok(())),
            (name(0, &["HOST", "Files.Example.ORG"]), Ok(())),
            (
                name(3, &["host", "other.example.org"]),
                Err(AuditReason::NameResolutionMismatch),
            ),
            (
                name(1, &["host/files.example.org"]),
                Err(AuditReason::NameResolutionMismatch),
            ),
            (
                name(3, &["host", "files.example.org", "x"]),
                Err(AuditReason::NameResolutionMismatch),
            ),
            (name(1, &["host"]), Err(AuditReason::NameResolutionMismatch)),
        ] {
            let mut f = fields();
            f.canonical_name = canonical.clone();
            assert_eq!(bound_by(&keyd, &SERVICE, f), expected, "{canonical:?}");
        }
    }

    /// docs/59 §7.2 ("the krbtgt check stays against the stored binding,
    /// exact — without resolution"); RFC 4120 §7.3: no resolution opens a
    /// krbtgt key set, not even one naming its handle and its TGS name.
    #[test]
    fn no_resolution_opens_a_krbtgt_key_set() {
        let keyd = keyd_with_key();
        let mut f = fields();
        f.name_as_sent = name(2, &["krbtgt", REALM]);
        f.canonical_name = name(2, &["krbtgt", REALM]);
        f.principal = KRBTGT_ID;
        f.key_purpose = KeyPurpose::Krbtgt;
        assert_eq!(
            bound_by(&keyd, &KRBTGT, f),
            Err(AuditReason::NameResolutionMismatch)
        );
    }

    /// Q-1011 item 2 (A-173): the key is installed by Role::Admin only, in
    /// the ceremony only, once only; a refused install changes nothing (the
    /// first key stays the one verifying).
    #[test]
    fn the_key_is_installed_once_by_admin_in_the_ceremony() {
        let mut keyd = keyd();
        for caller in [KDC, DIRECTORY, LDAP] {
            assert_eq!(
                reason(keyd.install_attestation_key_inner(&caller, key(&TEST_KEY), &now())),
                Err(AuditReason::RoleNotPermitted),
                "{caller:?}"
            );
            assert!(!keyd.has_attestation_key());
        }
        assert_eq!(
            reason(keyd.install_attestation_key_inner(&ADMIN, key(&TEST_KEY), &now())),
            Ok(())
        );
        assert!(keyd.has_attestation_key());
        assert_eq!(
            reason(keyd.install_attestation_key_inner(&ADMIN, key(&OTHER_KEY), &now())),
            Err(AuditReason::AttestationKeyInstalled)
        );
        assert!(keyd
            .verify_name_resolution(&signed(fields(), &TEST_KEY), &now())
            .is_ok());
        assert!(keyd
            .verify_name_resolution(&signed(fields(), &OTHER_KEY), &now())
            .is_err());
        // After the seal, no install — on a keyd that has none, either.
        let mut sealed = TestKeyd::new(
            {
                let mut c = KeydConfig::new(realm());
                c.enctypes = vec![EncTypeId::Aes256CtsHmacSha196];
                c
            },
            InMemoryKeyStore::new(4),
            Records::default(),
            &KerberosTime::new(2026, 11, 14, 10, 0, 0).unwrap(),
        )
        .unwrap();
        sealed.seal_ceremony(&ADMIN, &now()).unwrap();
        assert_eq!(sealed.ceremony_state(), CeremonyState::Operational);
        assert_eq!(
            reason(sealed.install_attestation_key_inner(&ADMIN, key(&TEST_KEY), &now())),
            Err(AuditReason::CeremonySealed)
        );
        assert!(!sealed.has_attestation_key());
        // A keyd whose store holds keys at start is operational from the
        // start (docs/52 §4.4): it never had a ceremony to install in.
        let mut store = InMemoryKeyStore::new(4);
        let creation = crate::template::check_new_binding(
            &realm(),
            &SERVICE,
            &PrincipalBinding::new(realm(), service_name()),
        )
        .unwrap();
        let random =
            krb_crypto::random_to_key(krb_crypto::EncType::Aes256CtsHmacSha196, &[0x42; 32])
                .unwrap();
        let (handle, set) = crate::store::StoredKeySet::create(
            creation,
            crate::store::KvnoKeys::random(crate::Kvno::INITIAL, vec![random]),
        );
        store.insert(handle, set).unwrap();
        let mut config = KeydConfig::new(realm());
        config.enctypes = vec![EncTypeId::Aes256CtsHmacSha196];
        let mut operational = TestKeyd::new(
            config,
            store,
            Records::default(),
            &KerberosTime::new(2026, 11, 14, 10, 0, 0).unwrap(),
        )
        .unwrap();
        assert_eq!(operational.ceremony_state(), CeremonyState::Operational);
        assert_eq!(
            reason(operational.install_attestation_key_inner(&ADMIN, key(&TEST_KEY), &now())),
            Err(AuditReason::CeremonySealed)
        );
        assert!(!operational.has_attestation_key());
    }

    /// AGENTS.md §6 (secrets never in Debug): keyd's Debug says whether a
    /// key is installed, never anything of it.
    #[test]
    fn debug_shows_only_whether_a_key_is_installed() {
        let mut keyd = keyd();
        assert!(format!("{keyd:?}").contains("attestation_key_installed: false"));
        keyd.install_attestation_key(&ADMIN, key(&TEST_KEY), &now())
            .unwrap();
        let text = format!("{keyd:?}");
        assert!(text.contains("attestation_key_installed: true"));
        assert!(!text.contains("5c") && !text.contains("5C"));
    }
}
