//! An object's principal names and keys in the one namespace (task PN1;
//! docs/59 §4.2, §4.3, §8): `DirectoryView::principal_names_of`,
//! `DirectoryView::principal_keys`, `name_context_of`, over a real dirstore
//! with the phase-1 schema.
//!
//! Sources, named on each test: docs/59 §4.1-§4.4, §6.1 step 3, §10.1;
//! docs/questions/Q-1007 items 2, 4, 9, Q-1008 item 4, Q-1010 item 3,
//! Q-1012 (P-84), Q-1019; A-53; [MS-SAMR] v20260427 2.2.1.14, 3.1.1.6
//! item 14; [MS-ADTS] v20261026 2.2.16, 3.1.1.1.5; [MS-KILE] v20261110
//! 3.1.5.7, 3.3.5.6.1; RFC 4120 §6.2, §7.3; Q-080. The directory is the
//! shared fixture of tests/common (this project's own test data); no vector
//! or fixture comes from any other implementation.

mod common;

use common::*;
use directory_pip::{name_context_of, NamingContext, PrincipalNamesError};
use dirstore::Object;
use dtyp::Guid;
use krb_proto::constants::{KRB_NT_ENTERPRISE, KRB_NT_PRINCIPAL, KRB_NT_SRV_HST};
use principal_names::{
    fold, key_of_request, KeySet, NameKind, NameRefused, PrincipalClass, RequestKey,
};
use std::collections::{BTreeMap, BTreeSet};

use NameKind::*;

fn object(d: &Dir, id: u32) -> Object {
    d.view()
        .authority_snapshot()
        .get_object(guid(id))
        .expect("store")
        .expect("object")
}

fn keys_of(d: &Dir, id: u32, services: &BTreeSet<Guid>) -> Option<KeySet> {
    d.view()
        .principal_keys(&object(d, id), services)
        .expect("principal keys")
}

fn listed(keys: &KeySet) -> Vec<(String, Vec<NameKind>)> {
    keys.iter()
        .map(|(key, kinds)| (key.as_str().to_owned(), kinds.iter().collect()))
        .collect()
}

fn entry(key: &str, kinds: &[NameKind]) -> (String, Vec<NameKind>) {
    (key.to_owned(), kinds.to_vec())
}

fn none() -> BTreeSet<Guid> {
    BTreeSet::new()
}

/// docs/59 §4.3 (the derivation per class) over the standard directory;
/// the class from authoritative data only — RID 502 ([MS-SAMR] 2.2.1.14,
/// 3.1.1.6 item 14) and ST ([MS-ADTS] 2.2.16); Q-1007 item 4 (alice's
/// sAMAccountName and UPN local part are one key); Q-1007 item 9 (the realm
/// alias is a key of the krbtgt account); objects that are not security
/// principals have no names.
#[test]
fn the_standard_principals_and_their_keys() {
    let d = Dir::standard("principal-standard");
    let view = d.view();
    let class = |id| {
        view.principal_names_of(&object(&d, id), &none())
            .unwrap()
            .map(|n| n.class)
    };
    assert_eq!(class(ALICE), Some(PrincipalClass::User));
    assert_eq!(class(WS01), Some(PrincipalClass::Computer));
    assert_eq!(class(DC01), Some(PrincipalClass::DomainController));
    assert_eq!(class(KRBTGT), Some(PrincipalClass::TicketGrantingService));
    assert_eq!(class(STAFF), Some(PrincipalClass::Group));
    for id in [ROOT, STAFF_OU, ADMINS_OU, USERS_CN] {
        assert_eq!(class(id), None, "{id}");
        assert_eq!(keys_of(&d, id, &none()), None, "{id}");
    }

    let keys = |id| listed(&keys_of(&d, id, &none()).expect("a principal"));
    assert_eq!(keys(ALICE), [entry("alice", &[SamAccountName, UpnLocal])]);
    assert_eq!(keys(BOB), [entry("bob", &[SamAccountName])]);
    assert_eq!(
        keys(WS01),
        [
            entry("host/ws01.example.test", &[ServicePrincipalName]),
            entry("ws01", &[ComputerBase]),
            entry("ws01$", &[SamAccountName]),
            entry("ws01.example.test", &[HostName]),
        ]
    );
    assert_eq!(
        keys(DC01),
        [
            entry("dc01", &[ComputerBase]),
            entry("dc01$", &[SamAccountName]),
            entry("ldap/dc01.example.test", &[ServicePrincipalName]),
        ]
    );
    assert_eq!(
        keys(KRBTGT),
        [
            entry("example.test", &[RealmAlias]),
            entry("krbtgt", &[SamAccountName])
        ]
    );
    assert_eq!(keys(STAFF), [entry("staff", &[SamAccountName])]);
}

/// docs/59 §6.1 step 3 and §10.1 (writer and reader agree — class C49):
/// each standard principal's names, sent as a client spells them, probe a
/// key the object holds, of the right kind — [MS-KILE] 3.3.5.6.1
/// (NT-PRINCIPAL cname / cname without "$" / `cname@realm`; NT-ENTERPRISE),
/// 3.1.5.7 (case), RFC 4120 §6.2 (name-type a hint); the krbtgt account is
/// reached only as `krbtgt/<realm>` (RFC 4120 §7.3).
#[test]
fn request_keys_reach_the_keys_the_object_holds() {
    let d = Dir::standard("principal-requests");
    let ctx = name_context_of(&naming_context()).expect("name context");
    let realm = realm();
    for (id, name_type, parts, kind) in [
        (ALICE, KRB_NT_PRINCIPAL, &["alice"][..], SamAccountName),
        (
            ALICE,
            KRB_NT_ENTERPRISE,
            &["alice@example.test"][..],
            UpnLocal,
        ),
        (ALICE, KRB_NT_PRINCIPAL, &["ALICE"][..], SamAccountName),
        (
            BOB,
            KRB_NT_ENTERPRISE,
            &["bob@EXAMPLE.TEST"][..],
            SamAccountName,
        ),
        (WS01, KRB_NT_PRINCIPAL, &["ws01$"][..], SamAccountName),
        (WS01, KRB_NT_PRINCIPAL, &["WS01"][..], ComputerBase),
        (
            WS01,
            KRB_NT_ENTERPRISE,
            &["ws01@example.test"][..],
            ComputerBase,
        ),
        (
            WS01,
            KRB_NT_SRV_HST,
            &["HOST", "ws01.example.test"][..],
            ServicePrincipalName,
        ),
        (
            DC01,
            KRB_NT_SRV_HST,
            &["ldap", "dc01.example.test"][..],
            ServicePrincipalName,
        ),
        (STAFF, KRB_NT_PRINCIPAL, &["staff"][..], SamAccountName),
    ] {
        let keys = keys_of(&d, id, &none()).expect("a principal");
        match key_of_request(&name(name_type, parts), &realm, &ctx) {
            RequestKey::Key(key) => assert!(
                keys.kinds_of(&key).contains(kind),
                "{parts:?} probes {key:?}; {keys:?}"
            ),
            other => panic!("{parts:?}: {other:?}"),
        }
    }
    let krbtgt = keys_of(&d, KRBTGT, &none()).expect("the krbtgt account");
    for parts in [&["krbtgt"][..], &["example.test"][..]] {
        assert_eq!(
            key_of_request(&name(KRB_NT_PRINCIPAL, parts), &realm, &ctx),
            RequestKey::NoSuchPrincipal,
            "{parts:?}"
        );
    }
    assert_eq!(
        key_of_request(&name(2, &["krbtgt", REALM]), &realm, &ctx),
        RequestKey::LocalTgs
    );
    assert_eq!(krbtgt.len(), 2);
}

/// docs/59 §4.3 and Q-1010 item 3 (decided A-173): the provisioned service
/// objects carry the DC's dNSHostName without its key — told apart only by
/// the configured set (Q-1019). Unlisted, the same objects would each claim
/// the DC's host name, which the store's unique index would refuse for all
/// but one (docs/59 §4.6).
#[test]
fn provisioned_service_objects_claim_no_host_name() {
    let d = Dir::new("principal-services");
    let wt = || vec![bits(uac::ADS_UF_WORKSTATION_TRUST_ACCOUNT)];
    let host = || vec![b"dc1.example.test".to_vec()];
    let mut objects = d.standard_objects()[..2].to_vec();
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
    let services: BTreeSet<Guid> = [51, 52, 53].into_iter().map(guid).collect();
    d.create_all_with_service_objects(objects, &services);

    let dc = keys_of(&d, 50, &services).unwrap();
    assert!(dc
        .iter()
        .any(|(key, kinds)| key.as_str() == "dc1.example.test" && kinds.contains(HostName)));
    for id in [51, 52, 53] {
        let service = object(&d, id);
        let names = d
            .view()
            .principal_names_of(&service, &services)
            .unwrap()
            .unwrap();
        assert_eq!(names.class, PrincipalClass::ProvisionedService, "{id}");
        let keys = keys_of(&d, id, &services).unwrap();
        assert_eq!(keys.len(), 3, "{id}");
        assert!(
            !keys.iter().any(|(_, kinds)| kinds.contains(HostName)),
            "{id}"
        );
        assert!(!keys.keys().any(|key| dc.contains(key)), "{id}");

        let unlisted = keys_of(&d, id, &none()).unwrap();
        assert!(unlisted
            .keys()
            .any(|key| key.as_str() == "dc1.example.test" && dc.contains(key)));
    }
}

/// Q-1019 / module `principal` (fail closed): an object listed as a
/// provisioned service object that is not a WT computer — a user, the
/// krbtgt account, a group, the DC's account, an OU — is an inconsistency.
#[test]
fn only_a_wt_computer_can_be_a_provisioned_service_object() {
    let d = Dir::standard("principal-listed");
    for id in [ALICE, KRBTGT, STAFF, DC01, STAFF_OU] {
        let listed: BTreeSet<Guid> = BTreeSet::from([guid(id)]);
        assert_eq!(
            d.view().principal_names_of(&object(&d, id), &listed),
            Err(PrincipalNamesError::Inconsistent),
            "{id}"
        );
        assert_eq!(
            d.view().principal_keys(&object(&d, id), &listed),
            Err(PrincipalNamesError::Inconsistent),
            "{id}"
        );
    }
    let ws01: BTreeSet<Guid> = BTreeSet::from([guid(WS01)]);
    assert_eq!(
        d.view()
            .principal_names_of(&object(&d, WS01), &ws01)
            .unwrap()
            .map(|n| n.class),
        Some(PrincipalClass::ProvisionedService)
    );
}

/// docs/59 §4.4 (refusal, not correction) and §6.1 step 3 (the lookup's
/// re-derivation fails closed): names the store accepts (printable ASCII)
/// but the namespace refuses — a foreign UPN suffix (N3; Q-1007 item 3), an
/// "@" in a sAMAccountName (N2), `KRBTGT/<host>` on a computer (N4; RFC 4120
/// §6.2), a user named like the realm (N5).
#[test]
fn stored_names_the_namespace_refuses() {
    let d = Dir::new("principal-refused");
    let normal = || vec![bits(uac::ADS_UF_NORMAL_ACCOUNT)];
    let mut objects = d.standard_objects()[..2].to_vec();
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
    // Objects the one checker would refuse: written beneath it, keyless.
    d.create_all_beneath_checker(objects);
    for (id, refusal) in [
        (60, NameRefused::UpnSuffix),
        (61, NameRefused::Separator),
        (62, NameRefused::Reserved),
        (63, NameRefused::Reserved),
    ] {
        assert_eq!(
            d.view().principal_keys(&object(&d, id), &none()),
            Err(PrincipalNamesError::Refused(refusal)),
            "{id}"
        );
    }
}

/// docs/59 §4.2 (`NameContext` from `NamingContext`): the one alias is the
/// NC's DNS name ([MS-ADTS] 3.1.1.1.5; A-53), compared folded ([MS-KILE]
/// 3.1.5.7); no flat-name alias (P-84, Q-1012). A naming context whose DNS
/// name is not a domain-style realm name (RFC 4120 §6.1: no ":" or "/";
/// docs/59 §4.2: no "@") has no namespace context.
#[test]
fn the_name_context_of_the_naming_context() {
    let ctx = name_context_of(&naming_context()).unwrap();
    assert!(ctx.is_realm_alias(REALM));
    assert!(ctx.is_realm_alias("example.test"));
    assert!(!ctx.is_realm_alias("EXAMPLE"));
    assert_eq!(
        ctx.realm_aliases()
            .map(|alias| alias.as_str())
            .collect::<Vec<_>>(),
        ["example.test"]
    );
    for labels in [
        &["a/b", "test"][..],
        &["a:b", "test"][..],
        &["a@b", "test"][..],
    ] {
        let nc = NamingContext::new(labels).expect("a naming context");
        assert_eq!(
            name_context_of(&nc),
            Err(NameRefused::RealmName),
            "{labels:?}"
        );
    }
}

/// Q-1008 item 4 (decided A-173; docs/59 §4.2, §9 S1): the namespace's fold
/// (crate principal-names) and dirstore's comparison key of a unique
/// Utf8String attribute are two definitions of Q-080's rule — pinned equal
/// on all 95 printable octets. One group per fold class `k<x>` is stored;
/// then for every printable octet `b` the store's unique index must find,
/// for `k<b>`, exactly the group of the class `fold(k<b>)` (a split, a merge
/// or a remapping by either side fails here); for every other octet the
/// namespace has no key and the store finds nothing.
#[test]
fn the_fold_is_pinned_to_dirstore_on_every_printable_octet() {
    let d = Dir::new("principal-fold-pin");
    let mut classes: BTreeMap<String, u32> = BTreeMap::new();
    for octet in 0x20u8..=0x7E {
        let folded = fold(&format!("k{}", char::from(octet))).expect("printable");
        let next = 100 + u32::try_from(classes.len()).unwrap();
        classes.entry(folded).or_insert(next);
    }
    assert_eq!(classes.len(), 95 - 26);
    let mut objects = d.standard_objects()[..2].to_vec();
    for (sam, id) in &classes {
        objects.push(d.group(*id, STAFF_OU, sam, GLOBAL_SECURITY, &[]));
    }
    // Some of these names the namespace refuses ("k/", "k@", "k$"): this
    // test pins dirstore's per-attribute fold, so the groups are written
    // beneath the checker, keyless.
    d.create_all_beneath_checker(objects);

    let sam = d.attr("sAMAccountName");
    let view = d.view();
    let snapshot = view.authority_snapshot();
    for octet in 0x20u8..=0x7E {
        let name = format!("k{}", char::from(octet));
        let id = classes[&fold(&name).unwrap()];
        assert_eq!(
            snapshot
                .lookup_unique(sam, name.as_bytes())
                .expect("lookup"),
            Some(guid(id)),
            "{octet:#04x}"
        );
    }
    for octet in (0u8..0x20).chain(0x7F..=0xFF) {
        assert_eq!(
            fold(&format!("k{}", char::from(octet))),
            None,
            "{octet:#04x}"
        );
        assert!(
            !matches!(snapshot.lookup_unique(sam, &[b'k', octet]), Ok(Some(_))),
            "{octet:#04x}"
        );
    }
}
