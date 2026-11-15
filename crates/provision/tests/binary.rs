//! The `provision` binary as an operator runs it — here as the (non-root)
//! test user: the production ownership refuses to exist without root, so
//! the binary refuses before anything is written; a malformed command line
//! is refused first.
//!
//! Sources: docs/51 §4.3 ("root; no daemon runs"), §4.4; the task rule
//! "the production implementation requires root and refuses otherwise";
//! crates/provision main.rs (exit status 1: refused, nothing written).
//! The tool is never run as root here.

mod common;

use common::*;

use std::process::Command;

use provision::RootOwnership;

const BIN: &str = env!("CARGO_BIN_EXE_provision");

/// The domain command line of `input` (test data).
fn args(input: &provision::DomainInput) -> Vec<String> {
    let p = &input.paths;
    let a = &input.accounts;
    let mut v: Vec<String> = vec!["domain".into()];
    let mut push = |flag: &str, value: String| {
        v.push(flag.into());
        v.push(value);
    };
    push("--realm", input.realm.clone());
    push("--naming-context", "dc=example,dc=test".into());
    push("--dc-fqdn", input.dc_fqdn.clone());
    push("--dc-name", input.names.dc_name.clone());
    push("--ldap-service-name", input.names.ldap_service_name.clone());
    push(
        "--admin-service-name",
        input.names.admin_service_name.clone(),
    );
    push(
        "--change-password-service-name",
        input.names.change_password_service_name.clone(),
    );
    push("--tier0-ou", input.names.tier0_ou.clone());
    push("--tier0-group", input.names.tier0_group.clone());
    push("--bootstrap-group", input.names.bootstrap_group.clone());
    for admin in &input.names.first_admins {
        push("--first-admin", admin.clone());
    }
    let account = |x: provision::Account| format!("{}:{}", x.uid, x.gid);
    push("--keyd-account", account(a.keyd));
    push("--dird-account", account(a.dird));
    push("--kdc-account", account(a.kdc));
    push("--ldap-front-account", account(a.ldap_front));
    push("--auditd-account", account(a.auditd));
    push("--admind-account", account(a.admind));
    push("--kpasswd-front-account", account(a.kpasswd_front));
    push("--dnsd-account", account(a.dnsd));
    push("--keyadm-uid", a.keyadm_uid.to_string());
    push("--admin-socket-group", a.admin_socket_group.to_string());
    for (flag, path) in [
        ("--staging-dir", &p.staging),
        ("--database-path", &p.database),
        ("--integrity-key-path", &p.integrity_key),
        ("--policy-path", &p.policy),
        ("--manifest-path", &p.manifest),
        ("--audit-log-path", &p.audit_log),
        ("--keyd-config", &p.keyd_config),
        ("--dird-config", &p.dird_config),
        ("--kdc-config", &p.kdc_config),
        ("--ldap-front-config", &p.ldap_front_config),
        ("--auditd-config", &p.auditd_config),
        ("--admind-config", &p.admind_config),
        ("--keyadm-config", &p.keyadm_config),
        ("--kpasswd-front-config", &p.kpasswd_front_config),
        ("--dnsd-config", &p.dnsd_config),
        ("--keyd-socket", &p.keyd_socket),
        ("--dird-kdc-socket", &p.dird_kdc_socket),
        ("--dird-ldap-socket", &p.dird_ldap_socket),
        ("--dird-admin-socket", &p.dird_admin_socket),
        ("--dird-kpasswd-socket", &p.dird_kpasswd_socket),
        ("--dird-dns-socket", &p.dird_dns_socket),
        ("--audit-socket", &p.audit_socket),
        ("--admin-socket", &p.admin_socket),
        ("--tls-certificate-path", &p.tls_certificate),
        ("--tls-private-key-path", &p.tls_private_key),
        ("--policy-next-path", &p.policy_next),
    ] {
        push(flag, path.as_str().to_owned());
    }
    push("--kdc-listen", input.network.kdc_listen[0].clone());
    push("--ldap-listen", input.network.ldap_listen[0].clone());
    push("--ldaps-listen", input.network.ldaps_listen[0].clone());
    push("--kpasswd-listen", input.network.kpasswd_listen[0].clone());
    push("--dnsd-listen", input.network.dnsd_listen[0].clone());
    for network in &input.network.internal_networks {
        push("--internal-network", network.clone());
    }
    for address in &input.network.dc_addresses {
        push("--dc-address", address.clone());
    }
    v
}

/// Without root the binary refuses (`RootOwnership::new` is `NotRoot`),
/// exit status 1, nothing written, nothing secret printed.
#[test]
fn the_binary_refuses_without_root_and_writes_nothing() {
    let dir = TempDir::new();
    let uid = my_uid(&dir);
    if skip_as_root(uid) {
        return;
    }
    assert!(RootOwnership::new().is_err());
    let mut input = input(&dir, 61002, 61007);
    input.names.workstations_ou = None;
    let out = Command::new(BIN).args(args(&input)).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("must run as root"), "{stderr}");
    assert!(out.stdout.is_empty());
    assert!(nothing_written(&input));
    // `provision policy` refuses the same way.
    let out = Command::new(BIN)
        .args([
            "policy",
            "--policy-path",
            input.paths.policy.as_str(),
            "--remove-principal",
            "S-1-5-21-1-2-3-4",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
}

/// A malformed command line: exit status 1, a usage message.
#[test]
fn a_malformed_command_line_is_refused() {
    for args in [
        vec![],
        vec!["domain", "--force"],
        vec!["first-admin-secret"],
    ] {
        let out = Command::new(BIN).args(&args).output().unwrap();
        assert_eq!(out.status.code(), Some(1), "{args:?}");
        assert!(String::from_utf8(out.stderr).unwrap().contains("usage"));
    }
}
