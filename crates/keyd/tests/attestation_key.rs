//! The attestation key slot through keyd's public API (task PN8; docs/59
//! §7.4): `install_attestation_key` succeeds once, for Role::Admin, in the
//! provisioning ceremony only; every other attempt is the uniform `Denied`
//! and changes nothing; keyd's `Debug` says only whether a key is
//! installed.
//!
//! Source: docs/59 §7.4, §10 (the PN8 row); docs/questions/Q-1011 item 2
//! (A-173: "delivered to keyd in ceremony mode only, never exported");
//! docs/52 §4.4, §7 R3 (A-102: the ceremony exists only for an empty store,
//! until `seal_ceremony`). The verification itself (tag, realm, freshness,
//! `bound_by`) is crate-internal until issuance adopts it (task PN11) and is
//! tested in crates/keyd/src/name_resolution.rs. Every value is made up
//! here; no vector comes from any other implementation.

mod common;

use common::*;
use keyd::{AttestationKey, CeremonyState, Error, InMemoryKeyStore, Keyd, ATTESTATION_KEY_LEN};

/// The key the ceremony hands keyd in these tests (made up).
const KEY: [u8; ATTESTATION_KEY_LEN] = [0x6E; ATTESTATION_KEY_LEN];

fn key() -> AttestationKey {
    AttestationKey::from_bytes(&KEY).unwrap()
}

/// A keyd in its provisioning ceremony (an empty store at start).
fn ceremony_keyd() -> TestKeyd {
    Keyd::with_entropy(
        config(),
        InMemoryKeyStore::new_insecure_development_allowing_krbtgt(8),
        CollectingAudit::default(),
        TestEntropy::default(),
        &keyd_started(),
    )
    .unwrap()
}

/// Q-1011 item 2: Role::Admin installs the key in the ceremony; a second
/// install — even of the same key — is refused, and the slot stays filled.
#[test]
fn admin_installs_the_key_once_in_the_ceremony() {
    let mut keyd = ceremony_keyd();
    assert_eq!(keyd.ceremony_state(), CeremonyState::Provisioning);
    assert!(!keyd.has_attestation_key());
    assert_eq!(keyd.install_attestation_key(&ADMIN, key()), Ok(()));
    assert!(keyd.has_attestation_key());
    assert_eq!(
        keyd.install_attestation_key(&ADMIN, key()),
        Err(Error::Denied)
    );
    assert!(keyd.has_attestation_key());
    // Sealing keeps the installed key (the ceremony's result).
    assert_eq!(keyd.seal_ceremony(&ADMIN, &now()), Ok(()));
    assert!(keyd.has_attestation_key());
}

/// Q-1011 item 8 (one Role::Admin operation): no other role installs it.
#[test]
fn no_other_role_installs_the_key() {
    let mut keyd = ceremony_keyd();
    for caller in [KDC, DIRECTORY, LDAP] {
        assert_eq!(
            keyd.install_attestation_key(&caller, key()),
            Err(Error::Denied),
            "{caller:?}"
        );
        assert!(!keyd.has_attestation_key());
    }
}

/// docs/52 R3 (A-102); Q-1011 item 2: after the seal no key is installed —
/// neither on an empty keyd nor on one whose ceremony created key sets. (A
/// keyd that starts operational has no ceremony at all — crate tests of
/// `install_attestation_key_inner`.)
#[test]
fn no_key_is_installed_outside_the_ceremony() {
    let mut sealed = ceremony_keyd();
    assert_eq!(sealed.seal_ceremony(&ADMIN, &now()), Ok(()));
    assert_eq!(
        sealed.install_attestation_key(&ADMIN, key()),
        Err(Error::Denied)
    );
    assert!(!sealed.has_attestation_key());

    // A ceremony that already created keys, then sealed.
    let mut f = Fixture::new();
    assert_eq!(f.keyd.seal_ceremony(&ADMIN, &now()), Ok(()));
    assert_eq!(
        f.keyd.install_attestation_key(&ADMIN, key()),
        Err(Error::Denied)
    );
    assert!(!f.keyd.has_attestation_key());
}

/// AGENTS.md §6 (secrets never in Debug); D28 / D29: keyd's `Debug` shows
/// whether the slot is filled and nothing of the key.
#[test]
fn debug_shows_only_whether_the_key_is_installed() {
    let mut keyd = ceremony_keyd();
    assert!(format!("{keyd:?}").contains("attestation_key_installed: false"));
    assert_eq!(keyd.install_attestation_key(&ADMIN, key()), Ok(()));
    let text = format!("{keyd:?}");
    assert!(text.contains("attestation_key_installed: true"), "{text}");
    assert!(!text.contains("6e") && !text.contains("6E"));
}
