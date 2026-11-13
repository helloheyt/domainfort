//! Guard of docs/50 R50-2 (decision A-58) and Q-213 → A-57: dird is the
//! only process that opens the redb file and holds the dirstore
//! IntegrityKey; the kdc asks it over the directory-view channel. So the
//! kdc's side of the channel — this crate — must not link the store
//! (`dirstore`, which holds the integrity-key code), the KV engine (`redb`),
//! the directory PIP over the store (`directory-pip`), or the server side
//! (`ipc-directory-server`); nor the crypto profile (D182).
//!
//! The test asks cargo for this crate's NORMAL dependency graph (`cargo tree
//! --edges normal`: no dev- or build-dependencies) and fails if any of them
//! appears. A positive control checks that the same query finds `dirstore`
//! and `redb` under `ipc-directory-server`, so the guard cannot pass
//! vacuously. Offline, host target (as crates/keyd-types'
//! no_crypto_dependency.rs; its residual applies). A failing `cargo tree`
//! fails the test (fail closed).
//!
//! Source: docs/50 R50-2, §2.2 (option A: "the kdc does not touch the
//! file"), §10 (the `ipc-directory` row); docs/questions/Q-213 (A-57),
//! Q-255 item 8 (the guard pattern, A-65). Test-only; no vector from any
//! other implementation.

use std::process::Command;

/// What the kdc's side must never link.
const FORBIDDEN: [&str; 6] = [
    "dirstore",
    "redb",
    "directory-pip",
    "ipc-directory-server",
    "krb-crypto",
    "keyd",
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

/// docs/50 R50-2; A-57; D182: the kdc's side links no store, no redb, no
/// directory PIP, no server side and no crypto profile.
#[test]
fn the_kdc_side_links_no_store() {
    let graph = normal_dependency_graph("ipc-directory");
    assert!(
        graph.iter().any(|name| name == "ipc-directory"),
        "cargo tree did not list ipc-directory itself: {graph:?}"
    );
    for forbidden in FORBIDDEN {
        assert!(
            !graph.iter().any(|name| name == forbidden),
            "ipc-directory depends on {forbidden} (R50-2: only dird opens the store): {graph:?}"
        );
    }
}

/// Positive control: the same query finds the store under the server side.
#[test]
fn the_query_finds_the_store_under_the_server_side() {
    let graph = normal_dependency_graph("ipc-directory-server");
    for expected in ["dirstore", "redb", "directory-pip"] {
        assert!(
            graph.iter().any(|name| name == expected),
            "ipc-directory-server should link {expected}: {graph:?}"
        );
    }
}
