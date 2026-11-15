//! The lookup side: `key_of_request` (docs/59 §4.2, the request table).
//!
//! Sources, named on each test: docs/59 §4.2, §10.1; docs/questions/Q-1007
//! items 2, 3, 5, 9; RFC 4120 §6.2, §7.3 (the TGS name examples
//! "ATHENA.MIT.EDU" and ("krbtgt", "MIT.EDU")); [MS-KILE] v20261110
//! 3.1.5.7, 3.3.5.1.1, 3.3.5.6.1; [MS-ADTS] v20261026 2.2.21 (the example
//! "ldap/dc-01.fabrikam.com/fabrikam.com"); [MS-DRSR] v20260309 4.1.4.2.22
//! (the example "username@example.fabrikam.com"). Realm "example.test" and
//! the account names are this project's own test data; no vector or fixture
//! comes from any other implementation.

use krb_proto::constants::{KRB_NT_ENTERPRISE, KRB_NT_PRINCIPAL, KRB_NT_SRV_HST, KRB_NT_SRV_INST};
use krb_proto::{KerberosString, PrincipalName, Realm};
use principal_names::{key_of_request, NameContext, RequestKey};

fn ctx() -> NameContext {
    NameContext::new("example.test").expect("realm DNS name")
}

fn name(name_type: i32, parts: &[&str]) -> PrincipalName {
    PrincipalName {
        name_type,
        name_string: parts
            .iter()
            .map(|p| KerberosString::new(p).expect("KerberosString"))
            .collect(),
    }
}

fn realm(r: &str) -> Realm {
    Realm::new(r).expect("realm")
}

/// The key text a request probes, or the other outcome.
fn probe(ctx: &NameContext, realm_name: &str, parts: &[&str]) -> Result<String, RequestKey> {
    match key_of_request(&name(KRB_NT_PRINCIPAL, parts), &realm(realm_name), ctx) {
        RequestKey::Key(key) => Ok(key.as_str().to_owned()),
        other => Err(other),
    }
}

/// RFC 4120 §6.2 ("The name-type SHOULD be treated only as a hint … It is
/// not significant when checking for equivalence"): the same components
/// give the same key under every name-type, and [MS-KILE] 3.1.5.7 ("MUST
/// NOT be case sensitive"): under every spelling — of the name and of the
/// realm.
#[test]
fn name_type_and_case_are_not_significant() {
    let ctx = ctx();
    for parts in [
        &["alice"][..],
        &["host", "ws01.example.test"][..],
        &["alice@example.test"][..],
    ] {
        let expected = key_of_request(&name(KRB_NT_PRINCIPAL, parts), &realm("EXAMPLE.TEST"), &ctx);
        assert!(matches!(expected, RequestKey::Key(_)), "{parts:?}");
        for name_type in [
            0,
            KRB_NT_SRV_INST,
            KRB_NT_SRV_HST,
            KRB_NT_ENTERPRISE,
            7,
            -128,
            999,
        ] {
            let got = key_of_request(&name(name_type, parts), &realm("EXAMPLE.TEST"), &ctx);
            assert_eq!(got, expected, "{parts:?} {name_type}");
        }
        let upper: Vec<String> = parts.iter().map(|p| p.to_ascii_uppercase()).collect();
        let upper: Vec<&str> = upper.iter().map(String::as_str).collect();
        for realm_name in ["example.test", "Example.Test"] {
            assert_eq!(
                key_of_request(&name(KRB_NT_PRINCIPAL, &upper), &realm(realm_name), &ctx),
                expected,
                "{upper:?} @ {realm_name}"
            );
        }
    }
}

/// RFC 4120 §7.3: "a TGT issued by the ATHENA.MIT.EDU realm to be used to
/// get tickets from the ATHENA.MIT.EDU KDC has a principal identifier of
/// "ATHENA.MIT.EDU" (realm), ("krbtgt", "ATHENA.MIT.EDU") (name)" — the
/// local TGS; ("krbtgt", "MIT.EDU") is another realm's TGS — foreign. And a
/// realm that is not ours is foreign for every name ([MS-KILE] 3.3.5.6.1:
/// "If the realm field is not present in the request or is the DC's domain
/// name").
#[test]
fn the_tgs_name_and_foreign_realms() {
    let athena = NameContext::new("athena.mit.edu").unwrap();
    assert_eq!(
        probe(&athena, "ATHENA.MIT.EDU", &["krbtgt", "ATHENA.MIT.EDU"]),
        Err(RequestKey::LocalTgs)
    );
    assert_eq!(
        probe(&athena, "ATHENA.MIT.EDU", &["KRBTGT", "athena.mit.edu"]),
        Err(RequestKey::LocalTgs)
    );
    assert_eq!(
        probe(&athena, "ATHENA.MIT.EDU", &["krbtgt", "MIT.EDU"]),
        Err(RequestKey::Foreign)
    );
    assert_eq!(
        probe(&athena, "MIT.EDU", &["alice"]),
        Err(RequestKey::Foreign)
    );
    assert_eq!(
        probe(&athena, "MIT.EDU", &["krbtgt", "ATHENA.MIT.EDU"]),
        Err(RequestKey::Foreign)
    );
}

/// docs/59 §4.2 ("`krbtgt/X` never reaches the index"; "`fold(c0) ==
/// krbtgt` in any other form ⇒ not found"); RFC 4120 §6.2 ("Names of any
/// type with an initial component of 'krbtgt' are reserved"); Q-1007 item 9
/// (a realm alias is a key of the krbtgt account only): no `Key` ever leads
/// to the krbtgt account.
#[test]
fn the_krbtgt_account_is_reached_only_as_the_tgs() {
    let ctx = ctx();
    for parts in [
        &["krbtgt"][..],
        &["KRBTGT"][..],
        &["krbtgt@example.test"][..],
        &["KrbTgt@EXAMPLE.TEST"][..],
        &["krbtgt", "a", "b"][..],
        &["example.test"][..],
        &["EXAMPLE.TEST"][..],
    ] {
        assert_eq!(
            probe(&ctx, "EXAMPLE.TEST", parts),
            Err(RequestKey::NoSuchPrincipal),
            "{parts:?}"
        );
    }
    assert_eq!(
        probe(&ctx, "EXAMPLE.TEST", &["krbtgt$"]).as_deref(),
        Ok("krbtgt$")
    );
}

/// [MS-KILE] 3.3.5.6.1 NT-PRINCIPAL steps 1-3 (cname; cname + "$";
/// `cname@realm`) and NT-ENTERPRISE steps 1-5 (UPNClientName before the
/// "@", then UPNClientName + "$"): each form is ONE key, and the keys a
/// computer `ws01$` stores are `ws01$` and `ws01` (docs/59 §4.3), so every
/// step of the chain is one probe (Q-1007 item 2).
#[test]
fn the_client_lookup_chain_is_one_probe() {
    let ctx = ctx();
    assert_eq!(
        probe(&ctx, "EXAMPLE.TEST", &["alice"]).as_deref(),
        Ok("alice")
    );
    assert_eq!(
        probe(&ctx, "EXAMPLE.TEST", &["WS01"]).as_deref(),
        Ok("ws01")
    );
    assert_eq!(
        probe(&ctx, "EXAMPLE.TEST", &["ws01$"]).as_deref(),
        Ok("ws01$")
    );
    assert_eq!(
        probe(&ctx, "EXAMPLE.TEST", &["alice@example.test"]).as_deref(),
        Ok("alice")
    );
    assert_eq!(
        probe(&ctx, "EXAMPLE.TEST", &["ws01@EXAMPLE.TEST"]).as_deref(),
        Ok("ws01")
    );
    assert_eq!(
        probe(&ctx, "EXAMPLE.TEST", &["ws01$@example.test"]).as_deref(),
        Ok("ws01$")
    );
}

/// [MS-DRSR] 4.1.4.2.22: "The user name is the component before the '@'.
/// For example, when the input is "username@example.fabrikam.com", then
/// "username" is returned" — whatever the domain. Here the suffix must be a
/// realm alias: with the realm example.fabrikam.com the example probes
/// `username`; with another realm it is no such principal (the stricter
/// deviation of Q-1007 item 3, decided A-173). Two "@", an empty local
/// part or an empty suffix are no name.
#[test]
fn a_foreign_upn_suffix_is_no_such_principal() {
    let fabrikam = NameContext::new("example.fabrikam.com").unwrap();
    assert_eq!(
        probe(
            &fabrikam,
            "EXAMPLE.FABRIKAM.COM",
            &["username@example.fabrikam.com"]
        )
        .as_deref(),
        Ok("username")
    );
    let ctx = ctx();
    for parts in [
        &["username@example.fabrikam.com"][..],
        &["alice@foreign.example"][..],
        &["alice@example.test@example.test"][..],
        &["@example.test"][..],
        &["alice@"][..],
    ] {
        assert_eq!(
            probe(&ctx, "EXAMPLE.TEST", parts),
            Err(RequestKey::NoSuchPrincipal),
            "{parts:?}"
        );
    }
}

/// [MS-ADTS] 2.2.21: an SPN "consists of either two parts or three parts";
/// its example "ldap/dc-01.fabrikam.com/fabrikam.com" is one key; [MS-KILE]
/// 3.3.5.1.1 (KerberosString[0] + "/" + the remaining elements in order).
#[test]
fn service_names_of_two_and_three_parts() {
    let ctx = ctx();
    assert_eq!(
        probe(&ctx, "EXAMPLE.TEST", &["HOST", "WS01.example.test"]).as_deref(),
        Ok("host/ws01.example.test")
    );
    assert_eq!(
        probe(
            &ctx,
            "EXAMPLE.TEST",
            &["ldap", "dc-01.fabrikam.com", "fabrikam.com"]
        )
        .as_deref(),
        Ok("ldap/dc-01.fabrikam.com/fabrikam.com")
    );
    assert_eq!(
        probe(&ctx, "EXAMPLE.TEST", &["kadmin", "changepw"]).as_deref(),
        Ok("kadmin/changepw")
    );
    assert_eq!(
        probe(&ctx, "EXAMPLE.TEST", &["a", "b", "c", "d"]),
        Err(RequestKey::NoSuchPrincipal)
    );
}

/// docs/59 §4.2 ("injectivity": "/" is refused inside a component and "@"
/// in every multi-component name, so joining never gives one key for two
/// component lists); Q-1007 item 5; an empty name, an empty component,
/// a name longer than any key.
#[test]
fn shapes_that_name_nothing() {
    let ctx = ctx();
    for parts in [
        &[][..],
        &[""][..],
        &["host/ws01.example.test"][..],
        &["host", "a/b"][..],
        &["host", ""][..],
        &["", "ws01.example.test"][..],
        &["host", "ws01@example.test"][..],
        &["alice@example.test", "x"][..],
    ] {
        assert_eq!(
            probe(&ctx, "EXAMPLE.TEST", parts),
            Err(RequestKey::NoSuchPrincipal),
            "{parts:?}"
        );
    }
    let long = "a".repeat(principal_names::MAX_KEY_OCTETS);
    assert!(probe(&ctx, "EXAMPLE.TEST", &[&long]).is_ok());
    let too_long = "a".repeat(principal_names::MAX_KEY_OCTETS + 1);
    assert_eq!(
        probe(&ctx, "EXAMPLE.TEST", &[&too_long]),
        Err(RequestKey::NoSuchPrincipal)
    );
    let half = "a".repeat(principal_names::MAX_KEY_OCTETS / 2);
    assert_eq!(
        probe(&ctx, "EXAMPLE.TEST", &[&half, &half]),
        Err(RequestKey::NoSuchPrincipal)
    );
}
