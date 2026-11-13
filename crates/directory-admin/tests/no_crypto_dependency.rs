//! Guard of D182 / decision A-63 for this crate: dird links it, and only
//! keyd links the Kerberos crypto profile (`krb-crypto`). The PEP names key
//! sets by handle only (the `BeginPasswordSet` reply) and never holds a key,
//! so its NORMAL dependency graph (`cargo tree --edges normal`) must contain
//! neither `krb-crypto` nor `keyd`. A positive control checks that the same
//! query finds `krb-crypto` under keyd, so the guard cannot pass vacuously.
//! The query runs offline; a failing `cargo tree` fails the test.
//!
//! Source: docs/45 §10 (D182) and A-63, as applied by the same guard in
//! crate keyd-types (tests/no_crypto_dependency.rs); A-73 (D182 applies to
//! the DC processes — dird among them). Test-only.

use std::process::Command;

/// The package names in `package`'s normal dependency graph, as
/// `cargo tree` lists them.
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

/// D182 / A-63: neither krb-crypto nor keyd is among this crate's normal
/// dependencies, directly or transitively.
#[test]
fn directory_admin_does_not_link_the_crypto_profile() {
    let graph = normal_dependency_graph("directory-admin");
    assert!(
        graph.iter().any(|name| name == "directory-admin"),
        "{graph:?}"
    );
    for forbidden in ["krb-crypto", "keyd", "ipc-keyd-server"] {
        assert!(
            !graph.iter().any(|name| name == forbidden),
            "directory-admin depends on {forbidden}: {graph:?}"
        );
    }
}

/// Positive control: the same query finds krb-crypto under keyd.
#[test]
fn the_query_finds_the_crypto_profile_under_keyd() {
    let graph = normal_dependency_graph("keyd");
    assert!(graph.iter().any(|name| name == "krb-crypto"), "{graph:?}");
}
