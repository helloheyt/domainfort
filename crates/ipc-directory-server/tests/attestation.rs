//! Tier 1 (docs/50 §9: in-process): dird's signer of name resolutions (task
//! PN10; docs/59 §7.1, §7.4, §7.5) — `ResolutionSigner` over the
//! directory-pip fixtures (crates/directory-pip/tests/common, reused through
//! `#[path]`): what it signs is exactly what keyd verifies (docs/59 §7.2,
//! crates/keyd `name_resolution.rs`): the tag under the attestation key
//! (crate name-attestation `verify`), the canonical realm (the configured
//! realm), freshness within 30 s of the issue time on the verifier's clock;
//! the issue time is dird's clock; a clock that cannot be read refuses the
//! record; and the resolution crosses the dird-kdc channel unchanged — the
//! record the kdc decodes verifies as dird signed it.
//!
//! Sources: docs/59 §7.1, §7.2, §7.4, §7.5; docs/questions/Q-1011 items 1-3
//! (A-173); docs/50 §3.4; RFC 4120 §5.2.3; AGENTS.md §6 (no secret in
//! output). The keys are made up here; every other value is the fixtures'
//! own data. No vector comes from any other implementation.

#[path = "../../directory-pip/tests/common/mod.rs"]
mod common;

use common::*;
use directory_pip::DirectoryContext;
use ipc::{decode_reply, encode_frame, Direction, Reply};
use ipc_directory::typed::Query;
use ipc_directory::wire::DirectoryReply;
use ipc_directory::DIRECTORY_CHANNEL;
use ipc_directory_server::{answer, ResolutionSigner, SharedAttestationKey};
use kdc::{AccountSource, AccountSourceError};
use keyd_types::{KeyHandle, KeyPurpose, PrincipalId, NAME_RESOLUTION_WINDOW_SECS};
use krb_proto::constants::{KRB_NT_PRINCIPAL, KRB_NT_SRV_HST};
use krb_proto::KerberosTime;
use name_attestation::{verify, AttestationKey};
use std::sync::Arc;

/// dird's attestation key in these tests (made up here).
const KEY: [u8; 32] = [0x6D; 32];

/// The instant dird's clock reads in these tests.
fn dird_now() -> KerberosTime {
    KerberosTime::new(2026, 11, 16, 15, 30, 0).unwrap()
}

/// A context over `d`'s store signed by dird's `ResolutionSigner` with
/// [`KEY`] and a clock that reads `clock()`.
fn signed(
    d: &Dir,
    clock: impl Fn() -> Option<KerberosTime> + Send + Sync + 'static,
) -> DirectoryContext {
    let signer = ResolutionSigner::new(
        SharedAttestationKey::from_bytes(&KEY).unwrap(),
        Arc::new(clock),
    );
    DirectoryContext::new(d.p1.clone(), &keyd_config(), naming_context())
        .unwrap()
        .with_name_resolution_signer(Arc::new(signer))
}

/// docs/59 §7.1, §7.2 steps 1-3 (keyd's checks, in its order), §7.4: a
/// record's resolution verifies under the attestation key — and under no
/// other — names the record's key set, has the configured realm as its
/// canonical realm, was issued at dird's clock, and is fresh for
/// `NAME_RESOLUTION_WINDOW_SECS` (30 s) either side of it on the verifier's
/// clock, stale beyond.
#[test]
fn the_signer_signs_what_keyd_verifies() {
    let d = Dir::standard("signer-verifies");
    let ctx = signed(&d, || Some(dird_now()));
    let view = ctx.view(&d.store, &d.empty_tiers).unwrap();
    let alice = view
        .client(&realm(), &name(KRB_NT_PRINCIPAL, &["alice"]))
        .unwrap()
        .unwrap();
    let ws01 = view
        .service(
            &realm(),
            &name(KRB_NT_SRV_HST, &["host", "ws01.example.test"]),
        )
        .unwrap()
        .unwrap();
    let key = AttestationKey::from_bytes(&KEY).unwrap();
    // The key sets the lookups resolve to, known independently of the
    // records (objectGUID + purpose, docs/47 §2.3): a record states its key
    // set only through its resolution (task PN10c).
    let handle_of =
        |id, purpose| KeyHandle::new(PrincipalId::from_bytes(guid(id).to_packet()), purpose);
    for (attested, handle) in [
        (
            &alice.resolution,
            handle_of(ALICE, KeyPurpose::PrincipalLongterm),
        ),
        (&ws01.resolution, handle_of(WS01, KeyPurpose::Service)),
    ] {
        let checked = verify(&key, attested).unwrap();
        let r = checked.resolution();
        assert_eq!(r.canonical_realm().as_bytes(), ctx.realm().as_bytes());
        assert_eq!(
            (r.principal(), r.key_purpose()),
            (handle.principal, handle.purpose)
        );
        assert_eq!(r.issued_at(), dird_now());
        let at =
            |second: u8, minute: u8| KerberosTime::new(2026, 11, 16, 15, minute, second).unwrap();
        assert!(r.is_fresh_at(&at(30, 30)));
        assert!(r.is_fresh_at(&at(30, 29)));
        assert!(!r.is_fresh_at(&at(31, 30)));
        assert!(!r.is_fresh_at(&at(29, 29)));
        let other = AttestationKey::from_bytes(&[0x6E; 32]).unwrap();
        assert!(verify(&other, attested).is_err());
    }
    assert_eq!(NAME_RESOLUTION_WINDOW_SECS, 30);
}

/// docs/59 §7.1 (`issued_at` — dird's clock), AGENTS.md §6 (fail closed): a
/// clock that cannot be read attests nothing, so the record is not answered
/// (`Failed`); "no such principal" stays itself.
#[test]
fn an_unreadable_clock_answers_no_record() {
    let d = Dir::standard("signer-no-clock");
    let ctx = signed(&d, || None);
    let view = ctx.view(&d.store, &d.empty_tiers).unwrap();
    assert_eq!(
        found(&view.client(&realm(), &name(KRB_NT_PRINCIPAL, &["alice"]))),
        Err(AccountSourceError::Failed)
    );
    assert_eq!(
        found(&view.client(&realm(), &name(KRB_NT_PRINCIPAL, &["nobody"]))),
        Ok(false)
    );
}

/// docs/59 §7.5 (the dird-kdc channel carries the resolution); docs/50
/// §3.4: the reply dird's dispatcher gives a `Client` query, encoded and
/// decoded as the kdc decodes it, carries a resolution that verifies under
/// dird's key exactly as signed.
#[test]
fn the_resolution_crosses_the_channel_as_signed() {
    let d = Dir::standard("signer-channel");
    let ctx = signed(&d, || Some(dird_now()));
    let view = ctx.view(&d.store, &d.empty_tiers).unwrap();
    let reply = answer(
        &view,
        &Query::Client {
            realm: realm(),
            name: name(KRB_NT_PRINCIPAL, &["alice"]),
        },
    );
    let frame = encode_frame(DIRECTORY_CHANNEL, Direction::Reply, &reply).unwrap();
    let Reply::Message(decoded) =
        decode_reply::<DirectoryReply>(DIRECTORY_CHANNEL, frame.body()).unwrap()
    else {
        panic!("a message")
    };
    let record = decoded.into_client().unwrap().unwrap().unwrap();
    let key = AttestationKey::from_bytes(&KEY).unwrap();
    let checked = verify(&key, &record.resolution).unwrap();
    assert_eq!(
        checked.resolution().principal(),
        PrincipalId::from_bytes(guid(ALICE).to_packet())
    );
    assert_eq!(
        checked.resolution().name_as_sent(),
        &name(KRB_NT_PRINCIPAL, &["alice"])
    );
}

/// AGENTS.md §6 (secrets never in output); docs/59 §7.4 (no `Debug` that
/// shows the key): neither the key's shared handle nor the signer prints
/// an octet.
#[test]
fn the_key_and_the_signer_print_nothing() {
    let key = SharedAttestationKey::from_bytes(&KEY).unwrap();
    assert_eq!(format!("{key:?}"), "SharedAttestationKey(..)");
    let signer = ResolutionSigner::new(key, Arc::new(|| Some(dird_now())));
    assert_eq!(format!("{signer:?}"), "ResolutionSigner");
    // The all-zero key is refused (a buffer never filled).
    assert!(SharedAttestationKey::from_bytes(&[0; 32]).is_err());
}
