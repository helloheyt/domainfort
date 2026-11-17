//! The write side: `keys_of_names` per class (docs/59 §4.3) and the
//! namespace's refusals (docs/59 §4.4), including the attacks of docs/59
//! §10.1 that are decided at the key level (the store's unique index then
//! refuses the second holder of a key — tasks PN2 / PN5).
//!
//! Sources, named on each test: docs/59 §4.1, §4.3, §4.4, §10.1;
//! docs/questions/Q-1007 items 2-4, 7-9, Q-1009 items 1-2, Q-1010 item 3;
//! [MS-SAMR] v20260427 3.1.1.6 items 10, 11, 14, 3.1.1.8.4 item 2; [MS-ADTS]
//! v20261026 2.2.21 (the example "ldap/dc-01.fabrikam.com/fabrikam.com"),
//! 3.1.1.5.3.1.1.4; RFC 4120 §6.2, §7.3. The realm "example.test" and the
//! account names are this project's own test data; no vector or fixture
//! comes from any other implementation.

use principal_names::{
    keys_of_names, KeySet, KindSet, NameContext, NameKind, NameRefused, PrincipalClass,
    PrincipalNames,
};

fn ctx() -> NameContext {
    NameContext::new("example.test").expect("realm DNS name")
}

fn names(class: PrincipalClass, sam: &str) -> PrincipalNames<'_> {
    PrincipalNames {
        class,
        sam_account_name: sam,
        user_principal_name: None,
        service_principal_names: Vec::new(),
        dns_host_name: None,
    }
}

/// The keys as `(text, kinds)` for comparison.
fn listed(keys: &KeySet) -> Vec<(String, Vec<NameKind>)> {
    keys.iter()
        .map(|(key, kinds)| (key.as_str().to_owned(), kinds.iter().collect()))
        .collect()
}

fn entry(key: &str, kinds: &[NameKind]) -> (String, Vec<NameKind>) {
    (key.to_owned(), kinds.to_vec())
}

fn intersect(a: &KeySet, b: &KeySet) -> bool {
    a.keys().any(|key| b.contains(key))
}

use NameKind::*;

/// docs/59 §4.3 (user; group); §4.1 and Q-1007 item 4 (the same key with
/// two kinds: user `bob` with UPN `bob@<realm>` stores one value).
#[test]
fn a_user_and_a_group() {
    let ctx = ctx();
    let alice = keys_of_names(&names(PrincipalClass::User, "Alice"), &ctx).unwrap();
    assert_eq!(listed(&alice), [entry("alice", &[SamAccountName])]);

    let mut bob = names(PrincipalClass::User, "bob");
    bob.user_principal_name = Some("bob@EXAMPLE.TEST");
    let bob = keys_of_names(&bob, &ctx).unwrap();
    assert_eq!(listed(&bob), [entry("bob", &[SamAccountName, UpnLocal])]);

    let mut carol = names(PrincipalClass::User, "carol");
    carol.user_principal_name = Some("Carol.Jones@example.test");
    let carol = keys_of_names(&carol, &ctx).unwrap();
    assert_eq!(
        listed(&carol),
        [
            entry("carol", &[SamAccountName]),
            entry("carol.jones", &[UpnLocal])
        ]
    );

    let staff = keys_of_names(&names(PrincipalClass::Group, "Staff"), &ctx).unwrap();
    assert_eq!(listed(&staff), [entry("staff", &[SamAccountName])]);
}

/// docs/59 §4.3 (computer: `x$`, `x`, SPN, host); [MS-SAMR] 3.1.1.6 item 11;
/// RFC 4120 §6.2.1 (the host component lower case — the key is folded in
/// any case).
#[test]
fn a_computer() {
    let mut ws01 = names(PrincipalClass::Computer, "WS01$");
    ws01.service_principal_names = vec!["host/ws01.example.test"];
    ws01.dns_host_name = Some("ws01.example.test");
    ws01.user_principal_name = Some("ws01@example.test");
    let keys = keys_of_names(&ws01, &ctx()).unwrap();
    assert_eq!(
        listed(&keys),
        [
            entry("host/ws01.example.test", &[ServicePrincipalName]),
            entry("ws01", &[ComputerBase, UpnLocal]),
            entry("ws01$", &[SamAccountName]),
            entry("ws01.example.test", &[HostName]),
        ]
    );
    assert!(keys.len() <= principal_names::MAX_KEYS_PER_OBJECT);
}

/// docs/59 §4.3 (the `DcAccount` claim as a computer; the service claims
/// without `HostName` — Q-1010 item 3, decided A-173; the `Krbtgt` claim:
/// `krbtgt` and every realm alias — Q-1007 item 9).
#[test]
fn the_provisioned_objects() {
    let ctx = ctx();
    let mut dc = names(PrincipalClass::DomainController, "dc01$");
    dc.dns_host_name = Some("dc01.example.test");
    assert_eq!(
        listed(&keys_of_names(&dc, &ctx).unwrap()),
        [
            entry("dc01", &[ComputerBase]),
            entry("dc01$", &[SamAccountName]),
            entry("dc01.example.test", &[HostName]),
        ]
    );

    for (sam, spn) in [
        ("ldap-svc$", "ldap/dc01.example.test"),
        ("admind-svc$", "admind/dc01.example.test"),
        ("changepw-svc$", "kadmin/changepw"),
    ] {
        let mut service = names(PrincipalClass::ProvisionedService, sam);
        service.dns_host_name = Some("dc01.example.test");
        service.service_principal_names = vec![spn];
        let keys = keys_of_names(&service, &ctx).unwrap();
        assert_eq!(keys.len(), 3, "{sam}");
        assert!(
            !keys.iter().any(|(_, kinds)| kinds.contains(HostName)),
            "{sam}"
        );
        assert!(keys
            .iter()
            .any(|(key, kinds)| key.as_str() == spn && kinds.contains(ServicePrincipalName)));
    }

    let krbtgt = keys_of_names(
        &names(PrincipalClass::TicketGrantingService, "krbtgt"),
        &ctx,
    );
    assert_eq!(
        listed(&krbtgt.unwrap()),
        [
            entry("example.test", &[RealmAlias]),
            entry("krbtgt", &[SamAccountName])
        ]
    );
}

/// [MS-SAMR] 3.1.1.6 item 14 ("sAMAccountName MUST be the value "krbtgt" …
/// if the RID of the objectSid attribute is DOMAIN_USER_RID_KRBTGT"); RFC
/// 4120 §6.2 ("Names of any type with an initial component of 'krbtgt' are
/// reserved"); docs/59 §4.3 (the krbtgt account carries no other kind).
#[test]
fn the_tgs_name_belongs_to_the_krbtgt_account_only() {
    let ctx = ctx();
    for sam in ["KRBTGT", "krbtgt2", "krbtgt$"] {
        assert_eq!(
            keys_of_names(&names(PrincipalClass::TicketGrantingService, sam), &ctx),
            Err(NameRefused::Reserved),
            "{sam}"
        );
    }
    for (class, sam) in [
        (PrincipalClass::User, "krbtgt"),
        (PrincipalClass::User, "KrbTgt"),
        (PrincipalClass::Group, "KRBTGT"),
        (PrincipalClass::Computer, "krbtgt$"),
    ] {
        assert_eq!(
            keys_of_names(&names(class, sam), &ctx),
            Err(NameRefused::Reserved),
            "{class:?} {sam}"
        );
    }
    let mut upn = names(PrincipalClass::User, "alice");
    upn.user_principal_name = Some("KRBTGT@example.test");
    assert_eq!(keys_of_names(&upn, &ctx), Err(NameRefused::Reserved));
    let mut host = names(PrincipalClass::Computer, "ws01$");
    host.dns_host_name = Some("krbtgt");
    assert_eq!(keys_of_names(&host, &ctx), Err(NameRefused::Reserved));
    let mut tgs_upn = names(PrincipalClass::TicketGrantingService, "krbtgt");
    tgs_upn.user_principal_name = Some("krbtgt@example.test");
    assert_eq!(keys_of_names(&tgs_upn, &ctx), Err(NameRefused::NotForClass));
}

/// docs/59 §4.4 N4 and Q-1009 item 1: `KRBTGT/<host>` is refused in any
/// case (the octet compare of crates/directory-admin `spn_ok` let a case
/// variant through); N5 / Q-1007 item 9: no object but the krbtgt account
/// holds a key equal to a realm alias.
#[test]
fn reserved_spns_and_realm_aliases_are_refused() {
    let ctx = ctx();
    for spn in [
        "krbtgt/ws01.example.test",
        "KRBTGT/ws01.example.test",
        "KrbTgt/x",
    ] {
        let mut ws01 = names(PrincipalClass::Computer, "ws01$");
        ws01.service_principal_names = vec![spn];
        assert_eq!(
            keys_of_names(&ws01, &ctx),
            Err(NameRefused::Reserved),
            "{spn}"
        );
    }
    let alias_user = names(PrincipalClass::User, "Example.Test");
    assert_eq!(keys_of_names(&alias_user, &ctx), Err(NameRefused::Reserved));
    let mut alias_host = names(PrincipalClass::Computer, "ws01$");
    alias_host.dns_host_name = Some("example.test");
    assert_eq!(keys_of_names(&alias_host, &ctx), Err(NameRefused::Reserved));
}

/// docs/59 §4.4 N2 ([MS-SAMR] 3.1.1.6 item 10: no "/"; the project rule: no
/// "@"; item 11: a computer's name ends with a single "$", Q-355 item 2: no
/// other ends with "$").
#[test]
fn sam_account_name_rules_of_the_namespace() {
    let ctx = ctx();
    for (class, sam, refusal) in [
        (PrincipalClass::User, "a/b", NameRefused::Separator),
        (PrincipalClass::User, "a@b", NameRefused::Separator),
        (PrincipalClass::User, "alice$", NameRefused::ComputerSuffix),
        (PrincipalClass::Group, "staff$", NameRefused::ComputerSuffix),
        (
            PrincipalClass::Computer,
            "ws01",
            NameRefused::ComputerSuffix,
        ),
        (
            PrincipalClass::Computer,
            "ws01$$",
            NameRefused::ComputerSuffix,
        ),
        (PrincipalClass::Computer, "$", NameRefused::Empty),
        (
            PrincipalClass::DomainController,
            "dc01",
            NameRefused::ComputerSuffix,
        ),
        (PrincipalClass::User, "", NameRefused::Empty),
        (PrincipalClass::User, "caf\u{e9}", NameRefused::NotPrintable),
        (PrincipalClass::User, "a\tb", NameRefused::NotPrintable),
    ] {
        assert_eq!(
            keys_of_names(&names(class, sam), &ctx),
            Err(refusal),
            "{sam:?}"
        );
    }
    let long = "a".repeat(principal_names::MAX_KEY_OCTETS + 1);
    assert_eq!(
        keys_of_names(&names(PrincipalClass::Group, &long), &ctx),
        Err(NameRefused::TooLong)
    );
}

/// docs/59 §4.4 N3 (exactly one "@"; local non-empty, no "/", no final
/// "$"; suffix a realm alias); Q-1007 item 3 (a foreign suffix is refused);
/// Q-1012 (P-84: no other suffix); docs/59 §4.1 (UPN on user / computer).
#[test]
fn user_principal_name_rules() {
    let ctx = ctx();
    for (upn, refusal) in [
        ("alice", NameRefused::UpnForm),
        ("a@b@example.test", NameRefused::UpnForm),
        ("ws01$@example.test", NameRefused::UpnForm),
        ("@example.test", NameRefused::Empty),
        ("a/b@example.test", NameRefused::Separator),
        ("alice@foreign.example", NameRefused::UpnSuffix),
        ("alice@EXAMPLE", NameRefused::UpnSuffix),
        ("alice@", NameRefused::UpnSuffix),
    ] {
        let mut alice = names(PrincipalClass::User, "alice");
        alice.user_principal_name = Some(upn);
        assert_eq!(keys_of_names(&alice, &ctx), Err(refusal), "{upn:?}");
    }
    let mut group = names(PrincipalClass::Group, "staff");
    group.user_principal_name = Some("staff@example.test");
    assert_eq!(keys_of_names(&group, &ctx), Err(NameRefused::NotForClass));
}

/// docs/59 §4.4 N4: two parts in phase 1 ([MS-ADTS] 3.1.1.5.3.1.1.4: a
/// three-part SPN only on a DC's object — task PN16; the [MS-ADTS] 2.2.21
/// example "ldap/dc-01.fabrikam.com/fabrikam.com" is therefore refused as a
/// stored value); no empty part, no "@"; no ":instancename", a numeric
/// ":port" accepted ([MS-ADTS] 2.2.21); SPNs only on computers (A-37 / A-38);
/// one in phase 1 (R47-13).
#[test]
fn service_principal_name_rules() {
    let ctx = ctx();
    let with_spns = |spns: Vec<&'static str>| {
        let mut ws01 = names(PrincipalClass::Computer, "ws01$");
        ws01.service_principal_names = spns;
        keys_of_names(&ws01, &ctx)
    };
    for (spn, refusal) in [
        ("ldap/dc-01.fabrikam.com/fabrikam.com", NameRefused::SpnForm),
        ("host", NameRefused::SpnForm),
        ("host/", NameRefused::Empty),
        ("/ws01.example.test", NameRefused::Empty),
        ("host/ws01.example.test:instance", NameRefused::SpnForm),
        ("host/ws01@example.test", NameRefused::Separator),
        ("host@x/ws01.example.test", NameRefused::Separator),
    ] {
        assert_eq!(with_spns(vec![spn]), Err(refusal), "{spn:?}");
    }
    let port = with_spns(vec!["http/ws01.example.test:8080"]).unwrap();
    assert!(port
        .keys()
        .any(|key| key.as_str() == "http/ws01.example.test:8080"));
    assert_eq!(
        with_spns(vec!["host/a.example.test", "http/a.example.test"]),
        Err(NameRefused::TooManyServicePrincipalNames)
    );
    let mut user = names(PrincipalClass::User, "alice");
    user.service_principal_names = vec!["http/alice.example.test"];
    assert_eq!(keys_of_names(&user, &ctx), Err(NameRefused::NotForClass));
    let mut user_host = names(PrincipalClass::User, "alice");
    user_host.dns_host_name = Some("alice.example.test");
    assert_eq!(
        keys_of_names(&user_host, &ctx),
        Err(NameRefused::NotForClass)
    );
    let mut bad_host = names(PrincipalClass::Computer, "ws01$");
    bad_host.dns_host_name = Some("ws01/example.test");
    assert_eq!(keys_of_names(&bad_host, &ctx), Err(NameRefused::Separator));
}

/// docs/59 §10.1 "attacks" at the key level; [MS-SAMR] 3.1.1.8.4 item 2
/// (sAMAccountName unique "with respect to the union"), RFC 4120 §6.2 ("no
/// two names can be the same"): every pair below shares a key, so the
/// store's unique index refuses the second object (task PN2) — noPac (a
/// computer `dc$` beside a user `dc`, and the reverse), a UPN beside another
/// object's sAMAccountName, one SPN in two spellings on two computers, a
/// group beside a computer's base name (Q-1007 item 7), a host name beside
/// a user's name (Q-1007 item 8).
#[test]
fn colliding_names_share_a_key() {
    let ctx = ctx();
    let keys = |n: &PrincipalNames<'_>| keys_of_names(n, &ctx).unwrap();

    let user_dc = keys(&names(PrincipalClass::User, "dc"));
    let computer_dc = keys(&names(PrincipalClass::Computer, "DC$"));
    assert!(intersect(&user_dc, &computer_dc));

    let bob = keys(&names(PrincipalClass::User, "bob"));
    let mut other = names(PrincipalClass::User, "robert");
    other.user_principal_name = Some("Bob@example.test");
    assert!(intersect(&bob, &keys(&other)));

    let mut a = names(PrincipalClass::Computer, "a$");
    a.service_principal_names = vec!["cifs/files.example.test"];
    let mut b = names(PrincipalClass::Computer, "b$");
    b.service_principal_names = vec!["CIFS/FILES.example.test"];
    assert!(intersect(&keys(&a), &keys(&b)));

    let group = keys(&names(PrincipalClass::Group, "ws01"));
    let ws01 = keys(&names(PrincipalClass::Computer, "ws01$"));
    assert!(intersect(&group, &ws01));

    let user_fqdn = keys(&names(PrincipalClass::User, "WS02.example"));
    let mut ws02 = names(PrincipalClass::Computer, "ws02$");
    ws02.dns_host_name = Some("ws02.example");
    assert!(intersect(&user_fqdn, &keys(&ws02)));

    // And names that differ only after the fold do not collide.
    let ws03 = keys(&names(PrincipalClass::Computer, "ws03$"));
    assert!(!intersect(&ws01, &ws03));
}

/// docs/59 §4.1: `KindSet` answers "which kinds does this key carry" for
/// the lookup's filter (§6.2); a key the object does not hold carries none.
#[test]
fn kinds_of_a_key() {
    let mut bob = names(PrincipalClass::User, "bob");
    bob.user_principal_name = Some("bob@example.test");
    let keys = keys_of_names(&bob, &ctx()).unwrap();
    let key = keys.keys().next().unwrap().clone();
    let kinds = keys.kinds_of(&key);
    assert_eq!(kinds, KindSet::EMPTY.with(SamAccountName).with(UpnLocal));
    let ws01 = keys_of_names(&names(PrincipalClass::Computer, "ws01$"), &ctx()).unwrap();
    let other = ws01.keys().next().unwrap();
    assert!(keys.kinds_of(other).is_empty());
}

/// Task PN10c (docs/questions/Q-1066; the A-190 residual of Q-1060):
/// `key_of_stored_name` reads one stored name in principal-name form — the
/// form of a key set's binding — with the write side's rules, never as a
/// request: a sAMAccountName (one component; a computer's when it ends with
/// a single "$" — [MS-SAMR] 3.1.1.6 item 11) and a phase-1
/// servicePrincipalName (two components, a numeric ":port" allowed —
/// [MS-ADTS] 2.2.21) have the key `keys_of_names` stores for them; a
/// request-only spelling has none: a one-part `local@<realm alias>` (a
/// userPrincipalName — `key_of_request` maps it to `local`; docs/59 §4.4
/// N2), "x$$", three parts in phase 1 and an ":instancename" ([MS-ADTS]
/// 3.1.1.5.3.1.1.4), an empty or "/"-holding part, no component; nor does a
/// name reserved for the krbtgt account (RFC 4120 §6.2, §7.3; N5) — the
/// TGS's own name included, a protocol name no object stores. The
/// name-type is not significant (RFC 4120 §6.2).
#[test]
fn one_stored_name_is_read_by_the_writers_rules() {
    use krb_proto::constants::{KRB_NT_ENTERPRISE, KRB_NT_PRINCIPAL, KRB_NT_SRV_HST};
    use krb_proto::{KerberosString, PrincipalName};
    use principal_names::key_of_stored_name;
    let ctx = ctx();
    let name = |name_type: i32, parts: &[&str]| PrincipalName {
        name_type,
        name_string: parts
            .iter()
            .map(|p| KerberosString::new(p).unwrap())
            .collect(),
    };
    let stored = |n: &PrincipalName| key_of_stored_name(n, &ctx);

    // The writer's keys, through the stored-name reading.
    let alice = keys_of_names(&names(PrincipalClass::User, "Alice"), &ctx).unwrap();
    let key = stored(&name(KRB_NT_PRINCIPAL, &["Alice"])).unwrap();
    assert!(alice.kinds_of(&key).contains(SamAccountName));
    let mut ws01 = names(PrincipalClass::Computer, "WS01$");
    ws01.service_principal_names = vec!["HTTP/ws01.example.test:8080"];
    let ws01 = keys_of_names(&ws01, &ctx).unwrap();
    let key = stored(&name(KRB_NT_PRINCIPAL, &["ws01$"])).unwrap();
    assert!(ws01.kinds_of(&key).contains(SamAccountName));
    let key = stored(&name(KRB_NT_SRV_HST, &["http", "WS01.example.test:8080"])).unwrap();
    assert!(ws01.kinds_of(&key).contains(ServicePrincipalName));
    // The name-type is not significant.
    assert_eq!(
        stored(&name(KRB_NT_ENTERPRISE, &["alice"])),
        stored(&name(KRB_NT_PRINCIPAL, &["alice"]))
    );

    // Request-only spellings and non-stored forms have no key.
    for (parts, refused) in [
        (&["alice@example.test"][..], NameRefused::Separator),
        (&["alice@EXAMPLE.TEST"][..], NameRefused::Separator),
        (&["x$$"][..], NameRefused::ComputerSuffix),
        (&["$"][..], NameRefused::Empty),
        (
            &["ldap", "dc01.example.test", "example.test"][..],
            NameRefused::SpnForm,
        ),
        (
            &["host", "ws01.example.test:inst"][..],
            NameRefused::SpnForm,
        ),
        (&["host", ""][..], NameRefused::Empty),
        (&["host", "a/b"][..], NameRefused::Separator),
        (&[][..], NameRefused::Empty),
    ] {
        assert_eq!(
            stored(&name(KRB_NT_PRINCIPAL, parts)),
            Err(refused),
            "{parts:?}"
        );
    }
    // Reserved for the krbtgt account: any "krbtgt" first component, the
    // realm alias — and so the TGS's name itself.
    for parts in [
        &["krbtgt"][..],
        &["KRBTGT", "EXAMPLE.TEST"][..],
        &["krbtgt", "ws01.example.test"][..],
        &["example.test"][..],
    ] {
        assert_eq!(
            stored(&name(KRB_NT_PRINCIPAL, parts)),
            Err(NameRefused::Reserved),
            "{parts:?}"
        );
    }
}
