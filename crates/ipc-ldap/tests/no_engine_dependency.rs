//! Guard of docs/49 R49-16 ("ldap-front — TLS + parse-ldap, no dirstore /
//! keyd") and docs/25 §3.3 ("a compromise of ldap-front gives no direct
//! access to dirstore or keyd"): the LDAP engine (the PEP) runs in dird,
//! which owns the directory. So the front's side of the channel — this crate
//! — must not link the engine (`ldap`), the store (`dirstore`, which holds
//! the integrity-key code), the KV engine (`redb`), the directory PIP
//! (`directory-pip`), the schema (`ad-schema`), the account model (`kdc`),
//! the server side (`ipc-ldap-server`), or any crypto profile (`keyd`,
//! `krb-crypto`; D182).
//!
//! The test asks cargo for this crate's NORMAL dependency graph (`cargo tree
//! --edges normal`: no dev- or build-dependencies) and fails if any of them
//! appears. A positive control checks that the same query finds the engine,
//! the store and the directory PIP under `ipc-ldap-server`, so the guard
//! cannot pass vacuously. Offline, host target (as crates/ipc-directory's
//! no_store_dependency.rs; its residual applies). A failing `cargo tree`
//! fails the test (fail closed).
//!
//! Source: docs/49 R49-16, §11; docs/50 §2.1, §10 (the `ipc-ldap` row: "ipc,
//! parse-ldap"); docs/25 §3.3; docs/questions Q-255 item 8 (the guard
//! pattern, A-65). Test-only; no vector from any other implementation.

use std::process::Command;

/// What the front's side must never link.
const FORBIDDEN: [&str; 9] = [
    "ldap",
    "dirstore",
    "redb",
    "directory-pip",
    "ad-schema",
    "kdc",
    "ipc-ldap-server",
    "keyd",
    "krb-crypto",
];

/// The package names in `package`'s normal dependency graph (the package
/// itself included), as `cargo tree` lists them.
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
        "cargo tree --package {package} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("cargo tree prints UTF-8")
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .map(str::to_owned)
        .collect()
}

/// docs/49 R49-16; docs/25 §3.3; D182: the front's side links no engine, no
/// store, no redb, no directory PIP, no server side and no crypto profile.
#[test]
fn the_front_side_links_no_engine_and_no_store() {
    let graph = normal_dependency_graph("ipc-ldap");
    assert!(
        graph.iter().any(|name| name == "ipc-ldap"),
        "cargo tree did not list ipc-ldap itself: {graph:?}"
    );
    assert!(
        graph.iter().any(|name| name == "parse-ldap"),
        "the front's side links the codec: {graph:?}"
    );
    for forbidden in FORBIDDEN {
        assert!(
            !graph.iter().any(|name| name == forbidden),
            "ipc-ldap depends on {forbidden} (R49-16: the front has no engine / store): {graph:?}"
        );
    }
}

/// Positive control: the same query finds the engine and the store under
/// the server side.
#[test]
fn the_query_finds_the_engine_under_the_server_side() {
    let graph = normal_dependency_graph("ipc-ldap-server");
    for expected in ["ldap", "dirstore", "redb", "directory-pip"] {
        assert!(
            graph.iter().any(|name| name == expected),
            "ipc-ldap-server should link {expected}: {graph:?}"
        );
    }
}
