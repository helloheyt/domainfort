//! The attestation key slot through keyd's public API (task PN8; docs/59
//! §7.4): `install_attestation_key` succeeds once, for Role::Admin, in the
//! provisioning ceremony only; every other attempt is the uniform `Denied`
//! and changes nothing; keyd's `Debug` says only whether a key is
//! installed. Since task PN9 it is the operation `InstallAttestationKey`:
//! every call — success or refusal — emits exactly one audit record (I8),
//! naming the operation, the caller and the reason, and nothing of the key.
//!
//! Source: docs/59 §7.4, §7.5, §10 (the PN8 and PN9 rows);
//! docs/questions/Q-1011 items 2, 8 (A-173: "delivered to keyd in ceremony
//! mode only, never exported"), Q-1033 (A-177: the `Operation`, the
//! capability-table row, the audit record); docs/52 §4.4, §7 R3 (A-102: the
//! ceremony exists only for an empty store, until `seal_ceremony`); docs/10
//! §10, §12 I8; docs/questions/Q-1056 item 4 (A-188: no seal without the
//! key — task PN11). The verification itself is tested through issuance in
//! tests/issuance_by_resolution.rs and inside the crate in
//! crates/keyd/src/name_resolution.rs. Every value is made up here; no
//! vector comes from any other implementation.

mod common;

use common::*;
use keyd::{
    AttestationKey, AuditOutcome, AuditReason, CeremonyState, Error, InMemoryKeyStore, Keyd,
    Operation, ATTESTATION_KEY_LEN,
};

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

/// The last audit record's operation, outcome and reason.
fn last(keyd: &TestKeyd) -> (Operation, AuditOutcome, AuditReason) {
    let record = keyd.audit_sink().records.last().unwrap();
    (record.op, record.result, record.reason)
}

/// Q-1011 item 2: Role::Admin installs the key in the ceremony; a second
/// install — even of the same key — is refused, and the slot stays filled.
/// Q-1033 (PN9): one record each — `Success`, then `Denied` /
/// `AttestationKeyInstalled`.
#[test]
fn admin_installs_the_key_once_in_the_ceremony() {
    let mut keyd = ceremony_keyd();
    assert_eq!(keyd.ceremony_state(), CeremonyState::Provisioning);
    assert!(!keyd.has_attestation_key());
    assert_eq!(keyd.install_attestation_key(&ADMIN, key(), &now()), Ok(()));
    assert!(keyd.has_attestation_key());
    assert_eq!(
        last(&keyd),
        (
            Operation::InstallAttestationKey,
            AuditOutcome::Success,
            AuditReason::None
        )
    );
    assert_eq!(
        keyd.install_attestation_key(&ADMIN, key(), &now()),
        Err(Error::Denied)
    );
    assert!(keyd.has_attestation_key());
    assert_eq!(
        last(&keyd),
        (
            Operation::InstallAttestationKey,
            AuditOutcome::Denied,
            AuditReason::AttestationKeyInstalled
        )
    );
    assert_eq!(keyd.audit_sink().records.len(), 2, "one record per call");
    // Sealing keeps the installed key (the ceremony's result).
    assert_eq!(keyd.seal_ceremony(&ADMIN, &now()), Ok(()));
    assert!(keyd.has_attestation_key());
}

/// Q-1011 item 8 (one Role::Admin operation; the capability table's Admin
/// row): no other role installs it — one record each, `RoleNotPermitted`.
#[test]
fn no_other_role_installs_the_key() {
    let mut keyd = ceremony_keyd();
    for caller in [KDC, DIRECTORY, LDAP] {
        assert_eq!(
            keyd.install_attestation_key(&caller, key(), &now()),
            Err(Error::Denied),
            "{caller:?}"
        );
        assert!(!keyd.has_attestation_key());
        let record = keyd.audit_sink().records.last().unwrap();
        assert_eq!(record.op, Operation::InstallAttestationKey);
        assert_eq!(record.caller_role, caller.role);
        assert_eq!(record.caller_uid, caller.uid);
        assert_eq!(record.reason, AuditReason::RoleNotPermitted);
    }
    assert_eq!(keyd.audit_sink().records.len(), 3);
}

/// Q-1056 item 4 (A-188; task PN11): keyd refuses to seal its ceremony
/// while it holds no attestation key — `Denied` / `AttestationKeyNotInstalled`,
/// one record, the ceremony still open — for every client (the PEP, not a
/// tool, holds the rule); once the key is installed the seal succeeds. A
/// sealed keyd that could verify no name resolution is unrepresentable.
#[test]
fn no_seal_without_the_attestation_key() {
    let mut keyd = ceremony_keyd();
    assert_eq!(keyd.seal_ceremony(&ADMIN, &now()), Err(Error::Denied));
    assert_eq!(keyd.ceremony_state(), CeremonyState::Provisioning);
    assert_eq!(
        last(&keyd),
        (
            Operation::SealCeremony,
            AuditOutcome::Denied,
            AuditReason::AttestationKeyNotInstalled
        )
    );
    // The authorization step still comes first (another role: its reason).
    assert_eq!(keyd.seal_ceremony(&KDC, &now()), Err(Error::Denied));
    assert_eq!(last(&keyd).2, AuditReason::RoleNotPermitted);
    // With the key the ceremony seals — and a re-run of the seal is
    // harmless, as before.
    assert_eq!(keyd.install_attestation_key(&ADMIN, key(), &now()), Ok(()));
    assert_eq!(keyd.seal_ceremony(&ADMIN, &now()), Ok(()));
    assert_eq!(keyd.ceremony_state(), CeremonyState::Operational);
    assert_eq!(keyd.seal_ceremony(&ADMIN, &now()), Ok(()));
    assert_eq!(keyd.audit_sink().records.len(), 5, "one record per call");
}

/// docs/52 R3 (A-102); Q-1011 item 2: after the seal no key is installed —
/// neither a replacement on an empty keyd nor on one whose ceremony created
/// key sets; the refusal is `CeremonySealed` (the authorization step's, as
/// for `create_key`), and the key the ceremony installed stays. (A keyd
/// that starts operational has no ceremony at all — crate tests of
/// `install_attestation_key_inner`.)
#[test]
fn no_key_is_installed_outside_the_ceremony() {
    let mut sealed = ceremony_keyd();
    assert_eq!(
        sealed.install_attestation_key(&ADMIN, key(), &now()),
        Ok(())
    );
    assert_eq!(sealed.seal_ceremony(&ADMIN, &now()), Ok(()));
    assert_eq!(
        sealed.install_attestation_key(&ADMIN, key(), &now()),
        Err(Error::Denied)
    );
    assert!(sealed.has_attestation_key());
    assert_eq!(
        last(&sealed),
        (
            Operation::InstallAttestationKey,
            AuditOutcome::Denied,
            AuditReason::CeremonySealed
        )
    );

    // A ceremony that already created keys (and installed the fixtures'
    // key), then sealed.
    let mut f = Fixture::new();
    assert_eq!(f.keyd.seal_ceremony(&ADMIN, &now()), Ok(()));
    assert_eq!(
        f.keyd.install_attestation_key(&ADMIN, key(), &now()),
        Err(Error::Denied)
    );
    assert!(f.keyd.has_attestation_key());
    assert_eq!(
        f.records().last().map(|r| r.reason),
        Some(AuditReason::CeremonySealed)
    );
}

/// docs/10 §10, §12 I8 (a record holds no secret); AGENTS.md §6: the
/// install's record carries no principal, purpose, kvno or decision — no
/// field could hold a key octet — and its rendering shows nothing of the key.
#[test]
fn the_install_record_names_no_key() {
    let mut keyd = ceremony_keyd();
    keyd.install_attestation_key(&ADMIN, key(), &now()).unwrap();
    let record = keyd.audit_sink().records.last().unwrap();
    assert_eq!(record.principal, None);
    assert_eq!(record.purpose, None);
    assert_eq!(record.kvno, None);
    assert_eq!(record.secondary, None);
    assert_eq!(record.approvers, None);
    assert_eq!(record.decision, None);
    let text = format!("{record:?}");
    assert!(!text.contains("110, 110") && !text.contains("6e6e") && !text.contains("6E6E"));
}

/// AGENTS.md §6 (secrets never in Debug); D28 / D29: keyd's `Debug` shows
/// whether the slot is filled and nothing of the key.
#[test]
fn debug_shows_only_whether_the_key_is_installed() {
    let mut keyd = ceremony_keyd();
    assert!(format!("{keyd:?}").contains("attestation_key_installed: false"));
    assert_eq!(keyd.install_attestation_key(&ADMIN, key(), &now()), Ok(()));
    let text = format!("{keyd:?}");
    assert!(text.contains("attestation_key_installed: true"), "{text}");
    assert!(!text.contains("6e") && !text.contains("6E"));
}
