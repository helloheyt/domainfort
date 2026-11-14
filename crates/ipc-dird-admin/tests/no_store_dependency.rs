//! Guard: admind links this crate as its client of dird, and admind never
//! opens the directory (docs/50 R50-2: dird is the only owner of the redb
//! file; docs/51 §5.1: "admind is stateless and has no database") and holds
//! no Kerberos crypto (D182, A-73: D182 binds the DC's processes, admind
//! among them). So this crate's NORMAL dependency graph (`cargo tree --edges
//! normal`) must contain none of the store, the KV engine, the directory
//! PIP, the write PEP, keyd or the crypto profile. A positive control finds
//! dirstore under directory-admin, so the guard cannot pass vacuously.
//! Offline, host target; a failing `cargo tree` fails the test.
//!
//! Source: docs/50 R50-2; docs/51 §5.1, §7; D182; A-63; A-73; the guard
//! pattern of crates/ipc-directory tests/no_store_dependency.rs (A-68).

use std::process::Command;

/// What the admin channel's client side must never link.
const FORBIDDEN: [&str; 7] = [
    "dirstore",
    "redb",
    "directory-pip",
    "directory-admin",
    "keyd",
    "krb-crypto",
    "ipc-keyd-server",
];

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

/// docs/50 R50-2; D182: none of [`FORBIDDEN`] is linked.
#[test]
fn the_admin_channel_links_no_store_pep_or_crypto() {
    let graph = normal_dependency_graph("ipc-dird-admin");
    assert!(graph.iter().any(|n| n == "ipc-dird-admin"), "{graph:?}");
    for forbidden in FORBIDDEN {
        assert!(
            !graph.iter().any(|n| n == forbidden),
            "ipc-dird-admin depends on {forbidden}: {graph:?}"
        );
    }
}

/// Positive control: the same query finds dirstore under directory-admin.
#[test]
fn the_query_finds_the_store_under_the_pep() {
    let graph = normal_dependency_graph("directory-admin");
    assert!(graph.iter().any(|n| n == "dirstore"), "{graph:?}");
}
