//! The one lookup path by name (task PN4; docs/59 §6, wave 2):
//! `DirectoryView::canonical_principal`, `LookupCtx`, `ResolvedPrincipal`,
//! over a real dirstore with the phase-1 schema.
//!
//! Sources, named on each test: docs/59 §4.4, §4.7, §5.1 (N7), §6.1-§6.3,
//! §10.1; docs/47 §1.3 (R47-1), §1.4 (R47-2), §2.3 (R47-3), R47-13;
//! docs/questions/Q-1007 items 2-4, 7, 10, Q-1009 items 1-3, 7, Q-1018
//! items 5-6, Q-1019 (a), Q-1026; A-27; A-73; [MS-KILE] v20261110 3.1.5.7,
//! 3.3.5.1.1, 3.3.5.6.1; [MS-ADTS] v20261026 2.2.21; RFC 4120 §6.2, §7.3;
//! RFC 3244 §2. The directory is the shared fixture of tests/common (this
//! project's own test data); no vector or fixture comes from any other
//! implementation.

mod common;

use common::*;
use directory_pip::{
    DirectoryContext, DirectoryView, LookupCtx, NamingContext, ResolvedPrincipal, ViewError,
};
use dtyp::Guid;
use kdc::{AccountSource, AccountSourceError};
use keyd::{KeyHandle, KeyPurpose, PrincipalId};
use krb_proto::constants::{KRB_NT_ENTERPRISE, KRB_NT_PRINCIPAL, KRB_NT_SRV_HST, KRB_NT_SRV_INST};
use krb_proto::Realm;
use principal_names::{key_of_request, KindSet, NameKind, PrincipalClass, RequestKey};
use std::collections::BTreeSet;

use LookupCtx::*;

const CONTEXTS: [LookupCtx; 4] = [AsClient, TicketClient, TgsServer, ServiceObject];

fn resolve(
    view: &DirectoryView<'_>,
    ctx: LookupCtx,
    name_type: i32,
    parts: &[&str],
) -> Result<Option<ResolvedPrincipal>, AccountSourceError> {
    view.canonical_principal(&realm(), &name(name_type, parts), ctx)
}

/// What a resolution says, comparable: the object, the class, the matched
/// kinds, the canonical name's components and the key purpose.
type Said = Option<(Guid, PrincipalClass, Vec<NameKind>, Vec<String>, KeyPurpose)>;

fn said(result: Result<Option<ResolvedPrincipal>, AccountSourceError>) -> Result<Said, ()> {
    result
        .map(|found| {
            found.map(|r| {
                (
                    r.guid(),
                    r.class(),
                    r.matched().iter().collect(),
                    r.canonical_name()
                        .name_string
                        .iter()
                        .map(|c| c.as_str().to_owned())
                        .collect(),
                    r.key_purpose(),
                )
            })
        })
        .map_err(|_| ())
}

fn kinds(list: &[NameKind]) -> KindSet {
    list.iter()
        .fold(KindSet::EMPTY, |set, kind| set.with(*kind))
}

fn principal(id: u32) -> PrincipalId {
    PrincipalId::from_bytes(guid(id).to_packet())
}

/// Write the principals' namespace keys as the one checker stores them
/// from task PN5 on (docs/59 §5.1, N7) — tests/common
/// `Dir::write_principal_keys`.
fn write_keys(d: &Dir, ids: &[u32], services: &BTreeSet<Guid>) {
    d.write_principal_keys(ids, services);
}

/// The standard directory's security principals.
const PRINCIPALS: [u32; 11] = [
    ALICE, BOB, ROOTADMIN, WS01, DC01, STAFF, ALLSTAFF, MAIL, HIDDEN, TIER0, KRBTGT,
];

/// docs/59 §4.7 (`ResolvedPrincipal`), §6.1, §6.2; docs/47 §1.3 (R47-1),
/// §2.3 (R47-3: KeyHandle = (objectGUID, purpose)); Q-1007 item 4 (alice's
/// sAMAccountName and UPN local part are one key with two kinds); RFC 4120
/// §6.2 (the name-type is kept as sent, not significant for the match).
#[test]
fn every_context_over_the_standard_directory() {
    let d = Dir::standard("resolve-standard");
    let view = d.view();
    for ctx in [AsClient, TicketClient] {
        let alice = resolve(&view, ctx, KRB_NT_ENTERPRISE, &["alice"])
            .unwrap()
            .expect("alice");
        assert_eq!(alice.guid(), guid(ALICE));
        assert_eq!(alice.principal(), principal(ALICE));
        assert_eq!(alice.sid(), &sid_of(ALICE));
        assert_eq!(alice.account_kind(), directory_pip::AccountKind::User);
        assert_eq!(alice.class(), PrincipalClass::User);
        assert_eq!(
            alice.matched(),
            kinds(&[NameKind::SamAccountName, NameKind::UpnLocal])
        );
        assert_eq!(alice.lookup(), ctx);
        assert_eq!(alice.realm_as_sent(), &realm());
        assert_eq!(alice.canonical_realm(), &realm());
        assert_eq!(alice.name_as_sent(), &name(KRB_NT_ENTERPRISE, &["alice"]));
        assert_eq!(alice.canonical_name(), &name(KRB_NT_ENTERPRISE, &["alice"]));
        assert_eq!(alice.key_purpose(), KeyPurpose::PrincipalLongterm);
        assert_eq!(
            alice.key_handle(),
            KeyHandle::new(principal(ALICE), KeyPurpose::PrincipalLongterm)
        );

        let ws01 = resolve(&view, ctx, KRB_NT_PRINCIPAL, &["ws01$"])
            .unwrap()
            .expect("ws01$");
        assert_eq!(ws01.class(), PrincipalClass::Computer);
        assert_eq!(ws01.account_kind(), directory_pip::AccountKind::Computer);
        assert_eq!(ws01.matched(), kinds(&[NameKind::SamAccountName]));
        let dc01 = resolve(&view, ctx, KRB_NT_PRINCIPAL, &["dc01$"])
            .unwrap()
            .expect("dc01$");
        assert_eq!(dc01.class(), PrincipalClass::DomainController);
    }
    for ctx in [TgsServer, ServiceObject] {
        let host = resolve(&view, ctx, KRB_NT_SRV_HST, &["host", "ws01.example.test"])
            .unwrap()
            .expect("host/ws01");
        assert_eq!(host.guid(), guid(WS01));
        assert_eq!(host.class(), PrincipalClass::Computer);
        assert_eq!(host.matched(), kinds(&[NameKind::ServicePrincipalName]));
        assert_eq!(
            host.canonical_name(),
            &name(KRB_NT_SRV_HST, &["host", "ws01.example.test"])
        );
        assert_eq!(host.key_purpose(), KeyPurpose::Service);
        assert_eq!(
            host.key_handle(),
            KeyHandle::new(principal(WS01), KeyPurpose::Service)
        );
        let ldap = resolve(&view, ctx, KRB_NT_SRV_HST, &["ldap", "dc01.example.test"])
            .unwrap()
            .expect("ldap/dc01");
        assert_eq!(ldap.class(), PrincipalClass::DomainController);
    }
    // The account source is a thin wrapper of the same path (R59-5).
    let client = view
        .client(&realm(), &name(KRB_NT_PRINCIPAL, &["alice"]))
        .unwrap()
        .expect("alice");
    assert_eq!(
        client.key,
        KeyHandle::new(principal(ALICE), KeyPurpose::PrincipalLongterm)
    );
}

/// docs/59 §6.3 (wave 2 keeps the acceptance of R47-1: octet for octet to
/// the stored value, AS = sAMAccountName, TGS = SPN), docs/47 §1.3 ("What
/// is refused in phase 1"), A-27, Q-1007 item 10: each request below
/// probes a key the object holds in the one namespace — the case variant,
/// the computer's base name ([MS-KILE] 3.3.5.6.1 step 2), the UPN local part
/// (step 3, NT-ENTERPRISE steps 4-5), the host name, the one-component sname
/// (3.3.5.1.1 step 2.2) — and is still "no such principal" in every
/// context, as before PN4.
#[test]
fn the_phase_one_acceptance_is_kept() {
    let d = Dir::standard("resolve-acceptance");
    let view = d.view();
    let name_ctx = d.ctx.name_context();
    for (id, name_type, parts) in [
        (ALICE, KRB_NT_PRINCIPAL, &["ALICE"][..]),
        (ALICE, KRB_NT_PRINCIPAL, &["alice@example.test"][..]),
        (ALICE, KRB_NT_ENTERPRISE, &["alice@EXAMPLE.TEST"][..]),
        (WS01, KRB_NT_PRINCIPAL, &["ws01"][..]),
        (WS01, KRB_NT_PRINCIPAL, &["WS01$"][..]),
        (WS01, KRB_NT_ENTERPRISE, &["ws01@example.test"][..]),
        (WS01, KRB_NT_PRINCIPAL, &["ws01.example.test"][..]),
        (WS01, KRB_NT_SRV_HST, &["HOST", "ws01.example.test"][..]),
        (WS01, KRB_NT_SRV_HST, &["host", "WS01.example.test"][..]),
        (DC01, KRB_NT_SRV_HST, &["LDAP", "dc01.example.test"][..]),
    ] {
        let keys = view
            .principal_keys(
                &view
                    .authority_snapshot()
                    .get_object(guid(id))
                    .unwrap()
                    .unwrap(),
                &BTreeSet::new(),
            )
            .unwrap()
            .unwrap();
        match key_of_request(&name(name_type, parts), &realm(), name_ctx) {
            RequestKey::Key(key) => assert!(keys.contains(&key), "{parts:?}"),
            other => panic!("{parts:?}: {other:?}"),
        }
        for ctx in CONTEXTS {
            assert_eq!(
                said(resolve(&view, ctx, name_type, parts)),
                Ok(None),
                "{ctx:?} {parts:?}"
            );
        }
    }
    // A client name is one component, a service name two or more; the
    // realm is the configured one octet for octet (docs/47 §1.3).
    for ctx in [AsClient, TicketClient] {
        assert_eq!(
            said(resolve(
                &view,
                ctx,
                KRB_NT_SRV_HST,
                &["host", "ws01.example.test"]
            )),
            Ok(None)
        );
    }
    for ctx in [TgsServer, ServiceObject] {
        for parts in [&["ws01$"][..], &["host/ws01.example.test"][..]] {
            assert_eq!(
                said(resolve(&view, ctx, KRB_NT_PRINCIPAL, parts)),
                Ok(None),
                "{ctx:?} {parts:?}"
            );
        }
    }
    for other in ["example.test", "OTHER.TEST"] {
        let r = Realm::new(other).unwrap();
        for ctx in [AsClient, TicketClient] {
            let found = view.canonical_principal(&r, &name(KRB_NT_PRINCIPAL, &["alice"]), ctx);
            assert_eq!(said(found), Ok(None), "{other}");
        }
        for ctx in [TgsServer, ServiceObject] {
            let found = view.canonical_principal(
                &r,
                &name(KRB_NT_SRV_HST, &["host", "ws01.example.test"]),
                ctx,
            );
            assert_eq!(said(found), Ok(None), "{other}");
        }
    }
}

/// docs/47 §1.4 (R47-2: the krbtgt account is never a client or a service),
/// docs/59 §4.2 (`krbtgt/X` never reaches the index; Q-1018 item 5), RFC
/// 4120 §6.2 ("reserved"), §7.3; Q-1007 items 7 and 9 (groups and the realm
/// alias are in the namespace but accepted by no context).
#[test]
fn the_krbtgt_account_groups_and_the_realm_alias_resolve_in_no_context() {
    let d = Dir::standard("resolve-reserved");
    let view = d.view();
    for (name_type, parts) in [
        (KRB_NT_PRINCIPAL, &["krbtgt"][..]),
        (KRB_NT_PRINCIPAL, &["KRBTGT"][..]),
        (KRB_NT_ENTERPRISE, &["krbtgt@example.test"][..]),
        (KRB_NT_SRV_INST, &["krbtgt", REALM][..]),
        (KRB_NT_SRV_INST, &["krbtgt", "example.test"][..]),
        (KRB_NT_SRV_INST, &["KRBTGT", REALM][..]),
        (KRB_NT_PRINCIPAL, &["example.test"][..]),
        (KRB_NT_PRINCIPAL, &["staff"][..]),
        (KRB_NT_PRINCIPAL, &["mail"][..]),
        (KRB_NT_PRINCIPAL, &["tier0"][..]),
    ] {
        for ctx in CONTEXTS {
            assert_eq!(
                said(resolve(&view, ctx, name_type, parts)),
                Ok(None),
                "{ctx:?} {parts:?}"
            );
        }
    }
}

/// docs/59 §6.3 (wave 2: external behaviour unchanged), §5.1 (N7: the one
/// checker stores exactly `keys_of_names` — task PN5), docs/questions/
/// Q-1026: the same requests give the same answers on a store without
/// namespace keys (today's) and on one whose principals carry them; and on
/// the keyed store, every resolution is the object a probe of the union
/// index (`PRINCIPAL_NAME_KEY`) returns for the request's key — the
/// equivalence that lets the probe move to that index unchanged.
#[test]
fn wave_two_answers_are_the_same_with_and_without_namespace_keys() {
    let plain = Dir::standard("resolve-plain");
    let keyed = Dir::standard("resolve-keyed");
    write_keys(&keyed, &PRINCIPALS, &BTreeSet::new());
    let requests: Vec<(i32, Vec<&str>)> = vec![
        (KRB_NT_PRINCIPAL, vec!["alice"]),
        (KRB_NT_PRINCIPAL, vec!["ALICE"]),
        (KRB_NT_ENTERPRISE, vec!["alice@example.test"]),
        (KRB_NT_PRINCIPAL, vec!["bob"]),
        (KRB_NT_PRINCIPAL, vec!["rootadmin"]),
        (KRB_NT_PRINCIPAL, vec!["ws01$"]),
        (KRB_NT_PRINCIPAL, vec!["ws01"]),
        (KRB_NT_PRINCIPAL, vec!["dc01$"]),
        (KRB_NT_PRINCIPAL, vec!["ws01.example.test"]),
        (KRB_NT_PRINCIPAL, vec!["staff"]),
        (KRB_NT_PRINCIPAL, vec!["krbtgt"]),
        (KRB_NT_PRINCIPAL, vec!["example.test"]),
        (KRB_NT_PRINCIPAL, vec!["nobody"]),
        (KRB_NT_SRV_HST, vec!["host", "ws01.example.test"]),
        (KRB_NT_SRV_HST, vec!["HOST", "ws01.example.test"]),
        (KRB_NT_SRV_HST, vec!["ldap", "dc01.example.test"]),
        (
            KRB_NT_SRV_HST,
            vec!["ldap", "dc01.example.test", "example.test"],
        ),
        (KRB_NT_SRV_HST, vec!["cifs", "ws01.example.test"]),
        (KRB_NT_SRV_INST, vec!["krbtgt", REALM]),
    ];
    let (plain_view, keyed_view) = (plain.view(), keyed.view());
    let mut resolved = 0;
    for (name_type, parts) in &requests {
        for ctx in CONTEXTS {
            let before = said(resolve(&plain_view, ctx, *name_type, parts));
            let after = said(resolve(&keyed_view, ctx, *name_type, parts));
            assert_eq!(before, after, "{ctx:?} {parts:?}");
            if let Ok(Some((found, ..))) = after {
                resolved += 1;
                let RequestKey::Key(key) =
                    key_of_request(&name(*name_type, parts), &realm(), keyed.ctx.name_context())
                else {
                    panic!("{parts:?} resolved without a key");
                };
                let probed = keyed_view
                    .authority_snapshot()
                    .lookup_unique(ad_schema::PRINCIPAL_NAME_KEY, key.as_bytes())
                    .unwrap();
                assert_eq!(probed, Some(found), "{ctx:?} {parts:?}");
            }
        }
    }
    // alice, bob, rootadmin, ws01$, dc01$ in two client contexts; two SPNs in
    // two service contexts.
    assert_eq!(resolved, 5 * 2 + 2 * 2);
}

/// docs/59 §6.1 step 6 and §3 M3 (class C49); docs/questions/Q-1009 items
/// 2-3 (the purpose from the resolved object's stored name; a reserved name
/// judged on the folded form), item 7 (only `kadmin/changepw` is reserved);
/// A-73 (`admind/<host>`); RFC 3244 §2 (`kadmin/changepw`): the purpose is
/// the one derivation over the stored canonical name, and a stored case
/// variant of a reserved name — writable through the admin plane until task
/// PN5 — is refused when found (fail closed). (`KADMIN/changepw` needs a
/// store of its own: the servicePrincipalName index already folds case.)
#[test]
fn the_purpose_comes_from_the_stored_name() {
    let wt = || vec![bits(uac::ADS_UF_WORKSTATION_TRUST_ACCOUNT)];
    let store = |test: &str, spns: &[(u32, &str, &str)]| {
        let d = Dir::new(test);
        let mut objects = d.standard_objects();
        for (id, sam, spn) in spns {
            objects.push(d.computer(
                *id,
                STAFF_OU,
                sam,
                &[
                    ("userAccountControl", wt()),
                    ("servicePrincipalName", vec![spn.as_bytes().to_vec()]),
                ],
            ));
        }
        d.create_all(objects);
        d
    };
    let exact = store(
        "resolve-purpose",
        &[
            (70, "admind-svc$", "admind/dc01.example.test"),
            (71, "changepw-svc$", "kadmin/changepw"),
            (72, "ws08$", "ADMIND/ws08.example.test"),
            (74, "ws06$", "kadmin/ws06.example.test"),
        ],
    );
    let variant = store(
        "resolve-purpose-variant",
        &[(73, "ws07$", "KADMIN/changepw")],
    );
    for ctx in [TgsServer, ServiceObject] {
        let purpose = |d: &Dir, parts: &[&str]| {
            resolve(&d.view(), ctx, KRB_NT_SRV_INST, parts).map(|r| r.map(|r| r.key_purpose()))
        };
        assert_eq!(
            purpose(&exact, &["admind", "dc01.example.test"]),
            Ok(Some(KeyPurpose::AdminService))
        );
        assert_eq!(
            purpose(&exact, &["kadmin", "changepw"]),
            Ok(Some(KeyPurpose::ChangePasswordService))
        );
        assert_eq!(
            purpose(&exact, &["kadmin", "ws06.example.test"]),
            Ok(Some(KeyPurpose::Service))
        );
        assert_eq!(
            purpose(&exact, &["ADMIND", "ws08.example.test"]),
            Err(AccountSourceError::Failed)
        );
        assert_eq!(
            purpose(&variant, &["KADMIN", "changepw"]),
            Err(AccountSourceError::Failed)
        );
        // Spelled differently from what is stored: no such principal.
        assert_eq!(purpose(&exact, &["ADMIND", "dc01.example.test"]), Ok(None));
        assert_eq!(purpose(&exact, &["admind", "ws08.example.test"]), Ok(None));
        assert_eq!(purpose(&variant, &["kadmin", "changepw"]), Ok(None));
    }
}

/// docs/59 §4.4 (N2-N5: refusal, not correction) and §6.1 step 3 (the
/// lookup re-derives the keys and fails closed); docs/questions/Q-1026:
/// objects whose stored names the namespace refuses — writable through the
/// admin plane until task PN5 — are no longer handed out: a foreign UPN
/// suffix (N3; Q-1007 item 3) and `KRBTGT/<host>` (N4; RFC 4120 §6.2) are
/// faults when found; a sAMAccountName with "@" (N2) or equal to the realm
/// alias (N5) is a name no request can probe.
#[test]
fn stored_names_the_namespace_refuses_fail_closed() {
    let d = Dir::new("resolve-refused");
    let normal = || vec![bits(uac::ADS_UF_NORMAL_ACCOUNT)];
    let mut objects = d.standard_objects();
    objects.push(d.user(
        60,
        STAFF_OU,
        "carol",
        &[
            ("userAccountControl", normal()),
            ("userPrincipalName", vec![b"carol@foreign.test".to_vec()]),
        ],
    ));
    objects.push(d.user(61, STAFF_OU, "a@b", &[("userAccountControl", normal())]));
    objects.push(d.computer(
        62,
        STAFF_OU,
        "ws09$",
        &[
            (
                "userAccountControl",
                vec![bits(uac::ADS_UF_WORKSTATION_TRUST_ACCOUNT)],
            ),
            (
                "servicePrincipalName",
                vec![b"KRBTGT/ws09.example.test".to_vec()],
            ),
        ],
    ));
    objects.push(d.user(
        63,
        STAFF_OU,
        "Example.Test",
        &[("userAccountControl", normal())],
    ));
    d.create_all(objects);
    let view = d.view();
    for ctx in [AsClient, TicketClient] {
        assert!(resolve(&view, ctx, KRB_NT_PRINCIPAL, &["carol"]).is_err());
        assert!(resolve(&view, ctx, KRB_NT_PRINCIPAL, &["ws09$"]).is_err());
        assert_eq!(
            said(resolve(&view, ctx, KRB_NT_PRINCIPAL, &["a@b"])),
            Ok(None)
        );
        assert_eq!(
            said(resolve(&view, ctx, KRB_NT_PRINCIPAL, &["Example.Test"])),
            Ok(None)
        );
    }
    for ctx in [TgsServer, ServiceObject] {
        assert_eq!(
            said(resolve(
                &view,
                ctx,
                KRB_NT_SRV_HST,
                &["KRBTGT", "ws09.example.test"]
            )),
            Ok(None)
        );
    }
    // The rest of the directory is unaffected.
    assert!(resolve(&view, AsClient, KRB_NT_PRINCIPAL, &["alice"])
        .unwrap()
        .is_some());
}

/// docs/questions/Q-1019 option (a) (A-175): the provisioned service
/// objects are held by the `DirectoryContext` and the lookup re-derives
/// their keys with them (docs/59 §4.3: "as computer **without** HostName";
/// Q-1010 item 3) — so on a store whose service objects carry the keys the
/// checker wrote (N7), the resolution is the same and the class is
/// `ProvisionedService`; unlisted (the empty default) the class is
/// `Computer` and the answer otherwise the same (no context accepts the
/// host name); an object listed that is not a workstation computer is
/// refused when resolved (fail closed).
#[test]
fn the_service_object_set_is_held_by_the_context() {
    let d = Dir::new("resolve-services");
    let wt = || vec![bits(uac::ADS_UF_WORKSTATION_TRUST_ACCOUNT)];
    let host = || vec![b"dc1.example.test".to_vec()];
    let mut objects = d.standard_objects();
    objects.push(d.computer(
        50,
        STAFF_OU,
        "dc1$",
        &[
            (
                "userAccountControl",
                vec![bits(uac::ADS_UF_SERVER_TRUST_ACCOUNT)],
            ),
            ("dNSHostName", host()),
        ],
    ));
    for (id, sam, spn) in [
        (51, "ldap-svc$", "ldap/dc1.example.test"),
        (52, "admind-svc$", "admind/dc1.example.test"),
        (53, "changepw-svc$", "kadmin/changepw"),
    ] {
        objects.push(d.computer(
            id,
            STAFF_OU,
            sam,
            &[
                ("userAccountControl", wt()),
                ("dNSHostName", host()),
                ("servicePrincipalName", vec![spn.as_bytes().to_vec()]),
            ],
        ));
    }
    d.create_all(objects);
    let services: BTreeSet<Guid> = [51, 52, 53].into_iter().map(guid).collect();
    write_keys(&d, &[50, 51, 52, 53], &services);

    let configured = DirectoryContext::new(d.p1.clone(), &keyd_config(), naming_context())
        .unwrap()
        .with_service_objects(services.clone());
    assert_eq!(configured.service_objects(), &services);
    assert!(d.ctx.service_objects().is_empty());
    let listed = configured.view(&d.store, &d.empty_tiers).unwrap();
    let unlisted = d.view();
    for ctx in [TgsServer, ServiceObject] {
        for (id, parts, purpose) in [
            (51, ["ldap", "dc1.example.test"], KeyPurpose::Service),
            (52, ["admind", "dc1.example.test"], KeyPurpose::AdminService),
            (
                53,
                ["kadmin", "changepw"],
                KeyPurpose::ChangePasswordService,
            ),
        ] {
            let with = resolve(&listed, ctx, KRB_NT_SRV_INST, &parts)
                .unwrap()
                .expect("listed");
            assert_eq!(with.guid(), guid(id));
            assert_eq!(with.class(), PrincipalClass::ProvisionedService);
            assert_eq!(with.key_purpose(), purpose);
            let without = resolve(&unlisted, ctx, KRB_NT_SRV_INST, &parts)
                .unwrap()
                .expect("unlisted");
            assert_eq!(without.class(), PrincipalClass::Computer);
            assert_eq!(
                (without.guid(), without.matched(), without.key_purpose()),
                (with.guid(), with.matched(), with.key_purpose())
            );
        }
    }

    let alice_listed = DirectoryContext::new(d.p1.clone(), &keyd_config(), naming_context())
        .unwrap()
        .with_service_objects(BTreeSet::from([guid(ALICE)]));
    let view = alice_listed.view(&d.store, &d.empty_tiers).unwrap();
    assert_eq!(
        said(resolve(&view, AsClient, KRB_NT_PRINCIPAL, &["alice"])),
        Err(())
    );
    assert_eq!(
        view.client(&realm(), &name(KRB_NT_PRINCIPAL, &["alice"])),
        Err(AccountSourceError::Failed)
    );
}

/// docs/59 §4.2 (`NameContext` from `NamingContext`); RFC 4120 §6.1
/// (domain-style realms contain neither ":" nor "/"), §6.2 ("krbtgt"
/// reserved); A-53: a naming context whose DNS name cannot be the
/// namespace's realm alias gives no context at all (fail closed at setup).
#[test]
fn the_context_needs_a_realm_alias_the_namespace_can_hold() {
    let p1 = ad_schema::phase1().unwrap();
    for (labels, realm) in [
        (&["krbtgt"][..], "KRBTGT"),
        (&["ex:ample", "test"][..], "EX:AMPLE.TEST"),
    ] {
        let keyd = keyd::KeydConfig::new(Realm::new(realm).unwrap());
        let nc = NamingContext::new(labels).unwrap();
        assert!(
            matches!(
                DirectoryContext::new(p1.clone(), &keyd, nc),
                Err(ViewError::NamingContext)
            ),
            "{labels:?}"
        );
    }
    let d = Dir::new("resolve-context");
    assert!(d.ctx.name_context().is_realm_alias("EXAMPLE.TEST"));
}
