//! One equivalence for the writer and the reader (class C49, docs/59 §3
//! M3): the properties of `tests/support/properties.rs` — the same ones
//! the fuzz target `principal_key_of_request` checks — run deterministically
//! over every request built from a small alphabet of components and realms,
//! and over every object built from a small alphabet of stored names.
//!
//! The alphabets are this project's own test data, chosen to reach every
//! row of the docs/59 §4.2 table and every rule of §4.4: plain names, case
//! variants, "$", "@" with an alias / a foreign / an empty suffix, "/",
//! "krbtgt", the realm alias itself, ":port" and ":instancename", empty
//! strings. Source: docs/59 §4.2, §4.3, §4.4, §10.1; RFC 4120 §6.2;
//! [MS-KILE] 3.1.5.7, 3.3.5.1.1, 3.3.5.6.1; [MS-ADTS] 2.2.21. No vector or
//! fixture comes from any other implementation.

#[path = "support/properties.rs"]
mod properties;

use krb_proto::{KerberosString, PrincipalName, Realm};
use principal_names::{NameContext, PrincipalClass, PrincipalNames, RequestKey};
use std::collections::BTreeMap;

const COMPONENTS: [&str; 14] = [
    "",
    "alice",
    "ALICE",
    "ws01$",
    "host",
    "ws01.example.test",
    "alice@example.test",
    "alice@EXAMPLE.TEST",
    "alice@foreign.test",
    "@example.test",
    "a/b",
    "krbtgt",
    "KrbTgt",
    "example.test",
];

const REALMS: [&str; 4] = ["EXAMPLE.TEST", "example.test", "FOREIGN.TEST", "EXAMPLE"];

fn ctx() -> NameContext {
    NameContext::new("example.test").expect("realm DNS name")
}

fn kstr(s: &str) -> KerberosString {
    KerberosString::new(s).expect("KerberosString")
}

/// docs/59 §4.2 (the request table) with properties 1-4: every request of
/// zero to four components over the alphabet, in every realm. Also checks
/// injectivity across requests directly: requests that probe one key are
/// the same name after the fold.
#[test]
fn every_request_over_the_alphabet() {
    let ctx = ctx();
    let mut seen: BTreeMap<String, String> = BTreeMap::new();
    let mut counts: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut lists: Vec<Vec<&str>> = vec![Vec::new()];
    let mut frontier: Vec<Vec<&str>> = vec![Vec::new()];
    for _ in 0..4 {
        frontier = frontier
            .iter()
            .flat_map(|list| {
                COMPONENTS.iter().map(move |c| {
                    let mut next = list.clone();
                    next.push(*c);
                    next
                })
            })
            .collect();
        lists.extend(frontier.iter().cloned());
    }
    for parts in &lists {
        let name = PrincipalName {
            name_type: 1,
            name_string: parts.iter().map(|p| kstr(p)).collect(),
        };
        for realm in REALMS {
            let realm = Realm::new(realm).expect("realm");
            let outcome = properties::check_request(&name, &realm, &ctx);
            let label = match &outcome {
                RequestKey::Foreign => "foreign",
                RequestKey::LocalTgs => "tgs",
                RequestKey::NoSuchPrincipal => "none",
                RequestKey::Key(key) => {
                    let normal = parts.join("\u{1}").to_ascii_lowercase();
                    let normal = match normal.split_once('@') {
                        Some((local, _)) if parts.len() == 1 => local.to_owned(),
                        _ => normal,
                    };
                    let previous = seen
                        .entry(key.as_str().to_owned())
                        .or_insert(normal.clone());
                    assert_eq!(*previous, normal, "two names probe {key:?}");
                    "key"
                }
            };
            *counts.entry(label).or_default() += 1;
        }
    }
    // Every outcome is reached (the alphabet is not vacuous).
    for label in ["foreign", "tgs", "none", "key"] {
        assert!(
            counts.get(label).copied().unwrap_or(0) > 0,
            "{label}: {counts:?}"
        );
    }
    assert!(lists.len() > 40_000, "{}", lists.len());
}

const SAMS: [&str; 9] = [
    "alice",
    "Bob",
    "ws01$",
    "WS02$",
    "krbtgt",
    "a@b",
    "a/b",
    "x$$",
    "example.test",
];
const UPNS: [Option<&str>; 6] = [
    None,
    Some("alice@example.test"),
    Some("Bob@EXAMPLE.TEST"),
    Some("carol@foreign.test"),
    Some("ws01$@example.test"),
    Some("a@b@example.test"),
];
const SPNS: [&[&str]; 6] = [
    &[],
    &["host/ws01.example.test"],
    &["HTTP/ws01.example.test:8080"],
    &["ldap/dc01.example.test/example.test"],
    &["KRBTGT/ws01.example.test"],
    &["host/ws01.example.test:inst"],
];
const HOSTS: [Option<&str>; 4] = [
    None,
    Some("ws01.example.test"),
    Some("WS02.Example.Test"),
    Some("a/b"),
];
const CLASSES: [PrincipalClass; 6] = [
    PrincipalClass::User,
    PrincipalClass::Computer,
    PrincipalClass::DomainController,
    PrincipalClass::ProvisionedService,
    PrincipalClass::TicketGrantingService,
    PrincipalClass::Group,
];

/// docs/59 §4.3, §4.4 with properties 3 and 5 (writer and reader agree):
/// every object over the alphabet that `keys_of_names` accepts stores keys
/// of a key's form, and each of its names, sent as a request, probes the
/// key it stores for that name.
#[test]
fn every_object_over_the_alphabet() {
    let ctx = ctx();
    let realm = Realm::new("EXAMPLE.TEST").expect("realm");
    let mut accepted = 0usize;
    let mut refused = 0usize;
    for class in CLASSES {
        for sam in SAMS {
            for upn in UPNS {
                for spns in SPNS {
                    for host in HOSTS {
                        let names = PrincipalNames {
                            class,
                            sam_account_name: sam,
                            user_principal_name: upn,
                            service_principal_names: spns.to_vec(),
                            dns_host_name: host,
                        };
                        match properties::check_stored(&names, &realm, &ctx) {
                            Some(_) => accepted += 1,
                            None => refused += 1,
                        }
                    }
                }
            }
        }
    }
    assert!(accepted > 50, "{accepted}");
    assert!(refused > 1000, "{refused}");
}
