//! The command line (crates/provision cli.rs): the documented shapes, and
//! every malformed one refused before anything else happens.
//!
//! Sources: docs/51 §4.3 (the input: no secret), §5.10 (`provision
//! policy`); docs/50 §7.1 (numeric ids, printable ASCII); D95 as cited in
//! docs/51 §3 (no secret in argv). Values are obviously fake test data.

use std::ffi::OsString;

use pdp::Tier;
use provision::cli::{parse, CliError, Command};
use provision::policy::TierChange;

/// A full `domain` command line (test data).
fn domain_args() -> Vec<String> {
    let mut a: Vec<&str> = vec![
        "domain",
        "--realm",
        "EXAMPLE.TEST",
        "--naming-context",
        "dc=example,dc=test",
        "--dc-fqdn",
        "dc1.example.test",
        "--dc-name",
        "DC1",
        "--ldap-service-name",
        "ldapsvc",
        "--admin-service-name",
        "adminsvc",
        "--tier0-ou",
        "Tier0",
        "--workstations-ou",
        "Workstations",
        "--tier0-group",
        "tier0-admins",
        "--bootstrap-group",
        "machine-bootstrap",
        "--first-admin",
        "alice",
        "--first-admin",
        "bob",
        "--keyd-account",
        "61001:61001",
        "--dird-account",
        "61002:61002",
        "--kdc-account",
        "61003:61003",
        "--ldap-front-account",
        "61004:61004",
        "--auditd-account",
        "61005:61005",
        "--admind-account",
        "61006:61006",
        "--keyadm-uid",
        "61007",
        "--admin-socket-group",
        "61010",
        "--kdc-listen",
        "127.0.0.1:88",
        "--ldaps-listen",
        "127.0.0.1:636",
        "--internal-network",
        "10.0.0.0/8",
        "--internal-network",
        "127.0.0.0/8",
    ];
    let paths = [
        ("--staging-dir", "/srv/p/etc/staging"),
        ("--database-path", "/srv/p/var/directory.redb"),
        ("--integrity-key-path", "/srv/p/etc/integrity.key"),
        ("--policy-path", "/srv/p/etc/policy.store"),
        ("--manifest-path", "/srv/p/etc/provision.manifest"),
        ("--audit-log-path", "/srv/p/var/audit.log"),
        ("--keyd-config", "/srv/p/etc/keyd.conf"),
        ("--dird-config", "/srv/p/etc/dird.conf"),
        ("--kdc-config", "/srv/p/etc/kdc.conf"),
        ("--ldap-front-config", "/srv/p/etc/ldap-front.conf"),
        ("--auditd-config", "/srv/p/etc/auditd.conf"),
        ("--admind-config", "/srv/p/etc/admind.conf"),
        ("--keyadm-config", "/srv/p/etc/keyadm.conf"),
        ("--keyd-socket", "/srv/p/run/keyd/keyd.sock"),
        ("--dird-kdc-socket", "/srv/p/run/dk/dird-kdc.sock"),
        ("--dird-ldap-socket", "/srv/p/run/dl/dird-ldap.sock"),
        ("--dird-admin-socket", "/srv/p/run/da/dird-admin.sock"),
        ("--audit-socket", "/srv/p/run/au/audit.sock"),
        ("--admin-socket", "/srv/p/run/ad/admin.sock"),
        ("--tls-certificate-path", "/srv/p/etc/dc-cert.der"),
        ("--tls-private-key-path", "/srv/p/etc/dc-key.der"),
        ("--policy-next-path", "/srv/p/var/dird-policy/policy.next"),
    ];
    for (flag, value) in paths {
        a.push(flag);
        a.push(value);
    }
    a.into_iter().map(str::to_owned).collect()
}

fn os(args: &[String]) -> Vec<OsString> {
    args.iter().map(OsString::from).collect()
}

fn usage(args: &[String]) -> bool {
    matches!(parse(os(args)), Err(CliError::Usage(_)))
}

/// docs/51 §4.3: every input value from the command line, none defaulted.
#[test]
fn a_full_domain_command_parses() {
    let Command::Domain(input) = parse(os(&domain_args())).unwrap() else {
        panic!("not domain");
    };
    assert_eq!(input.realm, "EXAMPLE.TEST");
    assert_eq!(input.naming_context, ["example", "test"]);
    assert_eq!(input.names.first_admins, ["alice", "bob"]);
    assert_eq!(input.accounts.dird.uid, 61002);
    assert_eq!(input.accounts.keyadm_uid, 61007);
    assert_eq!(input.paths.database.as_str(), "/srv/p/var/directory.redb");
    assert_eq!(input.network.kdc_listen, ["127.0.0.1:88"]);
    assert!(input.network.ldap_listen.is_empty());
}

/// Unknown, repeated or value-less flags; a missing required flag; a value
/// that is a flag; non-printable or non-UTF-8 arguments; no command.
#[test]
fn malformed_domain_commands_are_usage_errors() {
    let base = domain_args();
    let mut unknown = base.clone();
    unknown.extend(["--force".to_owned(), "yes".to_owned()]);
    assert!(usage(&unknown));
    let mut twice = base.clone();
    twice.extend(["--realm".to_owned(), "EXAMPLE.TEST".to_owned()]);
    assert!(usage(&twice));
    let mut missing_value = base.clone();
    missing_value.push("--first-admin".to_owned());
    assert!(usage(&missing_value));
    let without_realm: Vec<String> = {
        let i = base.iter().position(|a| a == "--realm").unwrap();
        let mut v = base.clone();
        v.drain(i..i + 2);
        v
    };
    assert!(usage(&without_realm));
    let mut flag_as_value = base.clone();
    let i = flag_as_value
        .iter()
        .position(|a| a == "--tier0-ou")
        .unwrap();
    flag_as_value[i + 1] = "--bootstrap-group".to_owned();
    assert!(usage(&flag_as_value));
    let mut tab = base.clone();
    tab[2] = "EXAMPLE\t.TEST".to_owned();
    assert!(usage(&tab));
    assert!(matches!(
        parse(Vec::<OsString>::new()),
        Err(CliError::Usage(_))
    ));
    assert!(matches!(
        parse(vec![OsString::from("password")]),
        Err(CliError::Usage(_))
    ));
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        let mut args = os(&base);
        args[2] = OsString::from_vec(vec![0x45, 0xff]);
        assert!(matches!(parse(args), Err(CliError::Usage(_))));
    }
    let many: Vec<String> = std::iter::repeat_n("x".to_owned(), 600).collect();
    assert!(usage(&many));
}

/// Values that break their type: a relative path, a non-canonical id, a
/// naming context without `dc=`.
#[test]
fn values_of_the_wrong_type_are_input_errors() {
    let base = domain_args();
    let set = |flag: &str, value: &str| {
        let mut v = base.clone();
        let i = v.iter().position(|a| a == flag).unwrap();
        v[i + 1] = value.to_owned();
        v
    };
    for (flag, value) in [
        ("--database-path", "var/directory.redb"),
        ("--database-path", "/srv/p/../directory.redb"),
        ("--database-path", "/srv/p/var/"),
        ("--keyd-account", "61001"),
        ("--keyd-account", "061001:61001"),
        ("--keyd-account", "-1:61001"),
        ("--keyadm-uid", "+61007"),
        ("--naming-context", "DC=example,dc=test"),
    ] {
        assert!(
            matches!(parse(os(&set(flag, value))), Err(CliError::Input(_))),
            "{flag} {value}"
        );
    }
}

/// docs/51 §5.10: the documented change forms; DN components one argument
/// each, leaf first.
#[test]
fn policy_commands_parse() {
    let args: Vec<String> = [
        "policy",
        "--policy-path",
        "/srv/p/etc/policy.store",
        "--add-principal",
        "S-1-5-21-1-2-3-1200",
        "Tier1",
        "--add-subtree",
        "Tier1",
        "ou=Help, desk",
        "dc=example",
        "dc=test",
        "--remove-principal",
        "S-1-5-21-1-2-3-1300",
        "--remove-subtree",
        "ou=Old",
        "dc=example",
        "dc=test",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect();
    let Command::Policy { path, changes } = parse(os(&args)).unwrap() else {
        panic!("not policy");
    };
    assert_eq!(path.as_str(), "/srv/p/etc/policy.store");
    assert_eq!(changes.len(), 4);
    match &changes[1] {
        TierChange::AddSubtree(dn, Tier::Tier1) => {
            assert_eq!(dn.rdns(), ["ou=Help, desk", "dc=example", "dc=test"]);
        }
        other => panic!("{other:?}"),
    }
}

/// `policy` without a path, without a change, with a bad tier, SID or
/// empty subtree, or with an unknown flag.
#[test]
fn malformed_policy_commands_are_refused() {
    let p = |rest: &[&str]| {
        let mut v = vec!["policy".to_owned()];
        v.extend(rest.iter().map(|s| (*s).to_owned()));
        v
    };
    assert!(usage(&p(&["--add-subtree", "Tier1", "ou=A", "dc=x"])));
    assert!(usage(&p(&["--policy-path", "/srv/p/policy.store"])));
    assert!(usage(&p(&[
        "--policy-path",
        "/srv/p/policy.store",
        "--add-principal",
        "S-1-5-21-1-2-3-4",
        "Untiered"
    ])));
    assert!(usage(&p(&[
        "--policy-path",
        "/srv/p/policy.store",
        "--add-principal",
        "not-a-sid",
        "Tier1"
    ])));
    assert!(usage(&p(&[
        "--policy-path",
        "/srv/p/policy.store",
        "--add-subtree",
        "Tier1"
    ])));
    assert!(usage(&p(&[
        "--policy-path",
        "/srv/p/policy.store",
        "--set-version",
        "9"
    ])));
}
