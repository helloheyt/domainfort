//! Guard of docs/49 R49-16 ("ldap-front — TLS + parse-ldap, no dirstore,
//! no keyd"), docs/50 §2.4 (ldap-front holds "rustls state, framing
//! buffers, the TLS private key" and talks to "dird only … auditd") and
//! docs/25 §3.3 ("a compromise of ldap-front gives no direct access to
//! dirstore or keyd"): the front must not link the LDAP engine (`ldap`),
//! the store (`dirstore`), the KV engine (`redb`), the directory PIP
//! (`directory-pip`), the schema (`ad-schema`), the account model (`kdc`),
//! dird's dispatcher (`ipc-ldap-server`), dird itself (`directory-daemon`),
//! keyd and its channel (`keyd`, `ipc-keyd`), any Kerberos crypto
//! (`krb-crypto`; D182), or the FIPS crypto module whose license is outside
//! the allowlist (`aws-lc-fips-sys`; Q-210, P-15).
//!
//! The test asks cargo for this crate's NORMAL dependency graph (`cargo tree
//! --edges normal`: no dev- or build-dependencies) and fails if any of them
//! appears. A positive control checks that the same query finds rustls and
//! the non-FIPS aws-lc-sys (so the guard cannot pass vacuously). Offline,
//! host target (as crates/ipc-ldap's guard; its residual applies). A failing
//! `cargo tree` fails the test (fail closed).
//!
//! Source: docs/49 R49-16, §11; docs/50 §2.4, §5.2, §10 (the `ldap-front`
//! row: "tokio, rustls, parse-ldap, ipc-ldap, config, daemon-sandbox");
//! docs/25 §3.3; docs/questions Q-210 (P-15), Q-255 item 8 (the guard
//! pattern, A-65). Test-only.

use std::process::Command;

/// What the front must never link.
const FORBIDDEN: [&str; 12] = [
    "ldap",
    "dirstore",
    "redb",
    "directory-pip",
    "ad-schema",
    "kdc",
    "ipc-ldap-server",
    "directory-daemon",
    "keyd",
    "ipc-keyd",
    "krb-crypto",
    "aws-lc-fips-sys",
];

/// The package names in `package`'s normal dependency graph.
fn normal_dependency_graph(package: &str) -> Vec<String> {
    let manifest = concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.toml");
    let output = Command::new(env!("CARGO"))
        .args([
            "tree",
            "--manifest-path",
            manifest,
            "--package",
            package,
            "--edges",
            "normal",
            "--prefix",
            "none",
            "--format",
            "{p}",
            "--offline",
        ])
        .output()
        .expect("cargo tree runs");
    assert!(
        output.status.success(),
        "cargo tree failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .map(str::to_owned)
        .collect()
}

/// docs/49 R49-16; docs/25 §3.3; Q-210: none of the forbidden packages is
/// in the front's normal graph; rustls and the non-FIPS aws-lc-sys are.
#[test]
fn the_front_links_no_engine_store_keyd_or_fips_module() {
    let graph = normal_dependency_graph("ldap-front");
    for forbidden in FORBIDDEN {
        assert!(
            !graph.iter().any(|name| name == forbidden),
            "ldap-front links {forbidden}"
        );
    }
    for expected in [
        "rustls",
        "aws-lc-rs",
        "aws-lc-sys",
        "parse-ldap",
        "ipc-ldap",
    ] {
        assert!(
            graph.iter().any(|name| name == expected),
            "the guard sees {expected}"
        );
    }
}
