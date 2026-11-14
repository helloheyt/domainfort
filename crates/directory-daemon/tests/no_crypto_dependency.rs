//! Guard of D182 / decision A-63 for dird: only keyd links the Kerberos
//! crypto profile (`krb-crypto`), and D182 binds the DC's processes, dird
//! among them (A-73). dird now links a keyd **client** (ipc-keyd, Role::Ldap)
//! and the write PEP (directory-admin) for its admin service (task A8) —
//! neither may bring keyd or krb-crypto into dird's NORMAL dependency graph
//! (`cargo tree --edges normal`; its tests may still run a real keyd). A
//! positive control finds krb-crypto under keyd, so the guard cannot pass
//! vacuously. Offline, host target; a failing `cargo tree` fails the test.
//!
//! Source: docs/45 §10 (D182); A-63; A-73 (D182 applies to the DC
//! processes); docs/51 §7; the guard pattern of crates/directory-admin
//! tests/no_crypto_dependency.rs.

use std::process::Command;

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

/// D182 / A-63 / A-73: neither krb-crypto nor keyd (nor keyd's server side)
/// is among dird's normal dependencies, directly or transitively.
#[test]
fn dird_does_not_link_the_crypto_profile() {
    let graph = normal_dependency_graph("directory-daemon");
    assert!(graph.iter().any(|n| n == "directory-daemon"), "{graph:?}");
    assert!(
        graph.iter().any(|n| n == "ipc-keyd"),
        "the keyd client is linked"
    );
    for forbidden in ["krb-crypto", "keyd", "ipc-keyd-server"] {
        assert!(
            !graph.iter().any(|n| n == forbidden),
            "directory-daemon depends on {forbidden}: {graph:?}"
        );
    }
}

/// Positive control: the same query finds krb-crypto under keyd.
#[test]
fn the_query_finds_the_crypto_profile_under_keyd() {
    let graph = normal_dependency_graph("keyd");
    assert!(graph.iter().any(|n| n == "krb-crypto"), "{graph:?}");
}
