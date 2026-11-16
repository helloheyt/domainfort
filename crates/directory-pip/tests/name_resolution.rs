//! dird's side of the attested name resolution (task PN10; docs/59 §7):
//! `ResolvedPrincipal::name_resolution`, the signer a context carries, the
//! resolution every account record carries, and the `principal-namespace`
//! marker dird checks before it opens a store — over a real dirstore with
//! the phase-1 schema.
//!
//! Sources, named on each test: docs/59 §4.7 (`snapshot`), §5.5 (stores
//! without the marker), §7.1 (the fields), §7.2 (what keyd checks: the tag,
//! the canonical realm, `|now − issued_at| ≤ 30 s`), §7.4 (the key), §7.5
//! (the records carry it); docs/questions/Q-1008 item 5, Q-1011 items 1-3
//! (A-173), Q-1027 items 4, 6 (A-178), Q-1043 item 1 (A-185); docs/29 §2
//! (change-seq); RFC 4120 §5.2.3, §6.2. The directory is the shared fixture
//! of tests/common; the test key is made up there (tests/common/signer.rs).
//! No vector or fixture comes from any other implementation.

mod common;

use common::signer::{test_signer, test_signer_at, TEST_ATTESTATION_KEY};
use common::*;
use directory_pip::{
    principal_namespace_marked, DirectoryContext, LookupCtx, NameResolutionSigner,
    ResolvedPrincipal, SignerRefused, PRINCIPAL_NAMESPACE_COUNTER,
    PRINCIPAL_NAMESPACE_END_EXCLUSIVE, PRINCIPAL_NAMESPACE_FIRST,
};
use dirstore::{IntegrityKey, Store};
use kdc::{AccountSource, AccountSourceError};
use keyd::{KeyPurpose, PrincipalId};
use keyd_types::AttestedNameResolution;
use krb_proto::constants::{KRB_NT_ENTERPRISE, KRB_NT_PRINCIPAL, KRB_NT_SRV_HST};
use krb_proto::KerberosTime;
use name_attestation::{verify, AttestationKey};
use std::sync::Arc;

fn test_key() -> AttestationKey {
    AttestationKey::from_bytes(&TEST_ATTESTATION_KEY).unwrap()
}

/// The fixed issue time of `test_signer` (tests/common/signer.rs).
fn signer_time() -> KerberosTime {
    KerberosTime::new(2026, 11, 16, 12, 0, 0).unwrap()
}

/// The `origin_seq` of the stamp on `object`'s `PRINCIPAL_NAME_KEY` value
/// `key` — docs/29 §2's change-seq of the write that stored it.
fn key_seq(d: &Dir, id: u32, key: &[u8]) -> u64 {
    let view = d.view();
    let object = view
        .authority_snapshot()
        .get_object(guid(id))
        .unwrap()
        .unwrap();
    object
        .attribute(ad_schema::PRINCIPAL_NAME_KEY)
        .unwrap()
        .values
        .iter()
        .find(|v| v.value == key)
        .unwrap()
        .stamp
        .origin_seq
}

/// docs/59 §4.7, §7.1; Q-1011 item 1; Q-1027 item 4: the conversion takes
/// every field from the lookup — the realm and name as sent (name-type
/// included), the canonical realm (the configured realm) and name, the
/// principal (objectGUID) and key purpose, and the snapshot: the change-seq
/// of the write that bound the probed key to the object (docs/29 §2) — and
/// only the issue time from the caller.
#[test]
fn the_resolution_is_the_lookups_own() {
    let d = Dir::standard("resolution-fields");
    let view = d.view();
    let sent = name(KRB_NT_ENTERPRISE, &["alice"]);
    let resolved = view
        .canonical_principal(&realm(), &sent, LookupCtx::AsClient)
        .unwrap()
        .unwrap();
    let at = KerberosTime::new(2026, 11, 16, 9, 0, 1).unwrap();
    let r = resolved.name_resolution(at).unwrap();
    assert_eq!(r.realm_as_sent(), &realm());
    assert_eq!(r.name_as_sent(), &sent);
    assert_eq!(r.canonical_realm(), d.ctx.realm());
    assert_eq!(r.canonical_name(), resolved.canonical_name());
    assert_eq!(
        r.principal(),
        PrincipalId::from_bytes(guid(ALICE).to_packet())
    );
    assert_eq!(r.key_purpose(), KeyPurpose::PrincipalLongterm);
    assert_eq!(r.issued_at(), at);
    assert_eq!(r.snapshot(), resolved.snapshot());
    assert_eq!(resolved.snapshot(), key_seq(&d, ALICE, b"alice"));
    assert!(resolved.snapshot() > 0);

    let host = name(KRB_NT_SRV_HST, &["host", "ws01.example.test"]);
    let service = view
        .canonical_principal(&realm(), &host, LookupCtx::TgsServer)
        .unwrap()
        .unwrap();
    let r = service.name_resolution(at).unwrap();
    assert_eq!(r.canonical_name(), &host);
    assert_eq!(r.key_purpose(), KeyPurpose::Service);
    assert_eq!(
        service.snapshot(),
        key_seq(&d, WS01, b"host/ws01.example.test")
    );
}

/// docs/59 §7.1, §7.5 (the records carry dird's attested resolution);
/// §7.2 (keyd's checks): the record a view answers carries the resolution of
/// that very lookup, tagged under the context's key — the tag verifies with
/// that key (crate name-attestation `verify`, keyd's), the canonical realm
/// is the configured realm, and it is fresh at its issue time and 30 s on,
/// stale at 31 s (keyd-types `is_fresh_at`; Q-1011 item 3).
#[test]
fn every_record_carries_the_attested_resolution_of_its_lookup() {
    let d = Dir::standard("resolution-records");
    let view = d.view();
    let alice = view
        .client(&realm(), &name(KRB_NT_PRINCIPAL, &["alice"]))
        .unwrap()
        .unwrap();
    let checked = verify(&test_key(), &alice.resolution).unwrap();
    let r = checked.resolution();
    assert_eq!(r.principal(), alice.key.principal);
    assert_eq!(r.key_purpose(), alice.key.purpose);
    assert_eq!(r.canonical_realm(), d.ctx.realm());
    assert_eq!(r.name_as_sent(), &name(KRB_NT_PRINCIPAL, &["alice"]));
    assert!(r.is_fresh_at(&signer_time()));
    assert!(r.is_fresh_at(&KerberosTime::new(2026, 11, 16, 12, 0, 30).unwrap()));
    assert!(!r.is_fresh_at(&KerberosTime::new(2026, 11, 16, 12, 0, 31).unwrap()));

    let ws01 = view
        .service(
            &realm(),
            &name(KRB_NT_SRV_HST, &["host", "ws01.example.test"]),
        )
        .unwrap()
        .unwrap();
    let checked = verify(&test_key(), &ws01.resolution).unwrap();
    assert_eq!(checked.resolution().principal(), ws01.key.principal);
    assert_eq!(checked.resolution().key_purpose(), KeyPurpose::Service);
    // Another key does not verify it (only dird's key attests).
    let other = AttestationKey::from_bytes(&[0x3A; 32]).unwrap();
    assert!(verify(&other, &ws01.resolution).is_err());
}

/// A signer that refuses every resolution.
struct Refusing;

impl NameResolutionSigner for Refusing {
    fn attest(&self, _: &ResolvedPrincipal) -> Result<AttestedNameResolution, SignerRefused> {
        Err(SignerRefused)
    }
}

/// docs/59 §7.5; AGENTS.md §6 (fail closed): a context with no signer, or
/// one whose signer refuses, answers no account record — `Failed`, the
/// "cannot tell" the KDC answers with KRB_ERR_GENERIC, never "no such
/// principal" — while the one lookup path itself, and every other question
/// of the view, is unaffected.
#[test]
fn without_an_attestation_no_record_is_answered() {
    let d = Dir::standard("resolution-unsigned");
    let unsigned = DirectoryContext::new(d.p1.clone(), &keyd_config(), naming_context()).unwrap();
    let refusing = DirectoryContext::new(d.p1.clone(), &keyd_config(), naming_context())
        .unwrap()
        .with_name_resolution_signer(Arc::new(Refusing));
    for ctx in [&unsigned, &refusing] {
        let view = ctx.view(&d.store, &d.empty_tiers).unwrap();
        assert_eq!(
            found(&view.client(&realm(), &name(KRB_NT_PRINCIPAL, &["alice"]))),
            Err(AccountSourceError::Failed)
        );
        assert_eq!(
            found(&view.service(
                &realm(),
                &name(KRB_NT_SRV_HST, &["host", "ws01.example.test"])
            )),
            Err(AccountSourceError::Failed)
        );
        // No such principal stays "no such principal": nothing is attested.
        assert_eq!(
            found(&view.client(&realm(), &name(KRB_NT_PRINCIPAL, &["nobody"]))),
            Ok(false)
        );
        assert!(view
            .canonical_principal(
                &realm(),
                &name(KRB_NT_PRINCIPAL, &["alice"]),
                LookupCtx::AsClient
            )
            .unwrap()
            .is_some());
    }
}

/// docs/59 §7.1 (`issued_at` is the attesting process's clock): the signer
/// stamps its own time, whatever the lookup.
#[test]
fn the_issue_time_is_the_signers() {
    let d = Dir::standard("resolution-time");
    let at = KerberosTime::new(2027, 1, 2, 3, 4, 5).unwrap();
    let ctx = DirectoryContext::new(d.p1.clone(), &keyd_config(), naming_context())
        .unwrap()
        .with_name_resolution_signer(test_signer_at(at));
    let view = ctx.view(&d.store, &d.empty_tiers).unwrap();
    let alice = view
        .client(&realm(), &name(KRB_NT_PRINCIPAL, &["alice"]))
        .unwrap()
        .unwrap();
    assert_eq!(alice.resolution.resolution().issued_at(), at);
    // The fixture's default signer issues at its own fixed time.
    let fixture = d
        .view()
        .client(&realm(), &name(KRB_NT_PRINCIPAL, &["alice"]))
        .unwrap()
        .unwrap();
    assert_eq!(fixture.resolution.resolution().issued_at(), signer_time());
    let _ = test_signer();
}

/// docs/59 §5.2 (c), §5.5; Q-1008 item 5; Q-1043 item 1 (A-185): the marker
/// is the counter `principal-namespace` with the one-value range [1, 2),
/// never taken — defined once, in this crate; a store carries it exactly as
/// provisioning creates it, or dird must not open it: absent, another
/// range, or a value taken ⇒ not marked.
#[test]
fn the_principal_namespace_marker_is_checked() {
    assert_eq!(PRINCIPAL_NAMESPACE_COUNTER, "principal-namespace");
    assert_eq!(
        (PRINCIPAL_NAMESPACE_FIRST, PRINCIPAL_NAMESPACE_END_EXCLUSIVE),
        (1, 2)
    );
    // The fixture's store carries it (tests/common/namespace.rs).
    let d = Dir::standard("marker-present");
    assert_eq!(principal_namespace_marked(&d.store), Ok(true));

    let dir = TempDir::new("marker-shapes");
    let p1 = ad_schema::phase1().unwrap();
    let open = |file: &str| {
        let path = dir.path().join(file);
        Store::open(
            path,
            IntegrityKey::from_bytes(&[0x47; 32]),
            p1.schema().clone(),
        )
        .unwrap()
    };
    // Absent.
    let bare = open("bare.redb");
    assert_eq!(principal_namespace_marked(&bare), Ok(false));
    // Another range.
    let other = open("other.redb");
    let mut txn = other.begin_write().unwrap();
    txn.create_counter(PRINCIPAL_NAMESPACE_COUNTER, 1, 3)
        .unwrap();
    txn.commit().unwrap();
    assert_eq!(principal_namespace_marked(&other), Ok(false));
    // Its value taken.
    let taken = open("taken.redb");
    let mut txn = taken.begin_write().unwrap();
    txn.create_counter(
        PRINCIPAL_NAMESPACE_COUNTER,
        PRINCIPAL_NAMESPACE_FIRST,
        PRINCIPAL_NAMESPACE_END_EXCLUSIVE,
    )
    .unwrap();
    txn.take_counter_value(PRINCIPAL_NAMESPACE_COUNTER).unwrap();
    txn.commit().unwrap();
    assert_eq!(principal_namespace_marked(&taken), Ok(false));
}
