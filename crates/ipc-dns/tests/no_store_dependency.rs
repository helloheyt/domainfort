//! Guard: dnsd links this crate as its client of dird, and dnsd holds no key,
//! no store and is not mapped in keyd (docs/54 §4.3: "no key, no token, no
//! GSS context"; R54-4: "no key, no dirstore, and no access to keyd at
//! all"; §4.7: "a test that dns-daemon does not link `dirstore`,
//! `krb-crypto`, `keyd`, `ipc-keyd`"). So this crate's NORMAL dependency
//! graph (`cargo tree --edges normal`) must contain none of the store, the
//! KV engine, the directory PIP, the write PEP, keyd or its types and
//! channel, the Kerberos crypto profile or DER codec, or dird's side of this
//! channel. A positive control finds dirstore under directory-admin and
//! ipc-dns under ipc-dns-server, so the guard cannot pass vacuously.
//! Offline, host target; a failing `cargo tree` fails the test.
//!
//! Source: docs/54 R54-4, §4.3, §4.7; docs/50 R50-2; D182; the guard
//! pattern of crates/ipc-dird-admin and crates/ipc-ldap (A-65, A-68).

use std::process::Command;

/// What dnsd's side of the channel must never link.
const FORBIDDEN: [&str; 10] = [
    "dirstore",
    "redb",
    "directory-pip",
    "directory-admin",
    "keyd",
    "keyd-types",
    "ipc-keyd",
    "krb-crypto",
    "krb-proto",
    "ipc-dns-server",
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

/// docs/54 R54-4, §4.7: none of [`FORBIDDEN`] is linked.
#[test]
fn the_dnsd_side_links_no_store_keyd_or_crypto() {
    let graph = normal_dependency_graph("ipc-dns");
    assert!(graph.iter().any(|n| n == "ipc-dns"), "{graph:?}");
    for forbidden in FORBIDDEN {
        assert!(
            !graph.iter().any(|n| n == forbidden),
            "ipc-dns depends on {forbidden}: {graph:?}"
        );
    }
}

/// Positive controls: the same query finds dirstore under directory-admin,
/// and this crate under dird's side of the channel.
#[test]
fn the_query_finds_what_it_looks_for() {
    let graph = normal_dependency_graph("directory-admin");
    assert!(graph.iter().any(|n| n == "dirstore"), "{graph:?}");
    let graph = normal_dependency_graph("ipc-dns-server");
    assert!(graph.iter().any(|n| n == "ipc-dns"), "{graph:?}");
}
