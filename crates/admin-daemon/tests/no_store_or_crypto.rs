//! Guard (D182, A-73; docs/51 §5.1): admind is one of the DC's processes —
//! D182 binds it — so it links no Kerberos crypto (`krb-crypto`), no keyd
//! (nor keyd's server side), and, stateless with no store, never the
//! directory: not dirstore, not its KV engine redb, not the directory PIP or
//! the write PEP. Its NORMAL dependency graph (`cargo tree --edges normal`)
//! must contain none of them — for admin-daemon and for its channel crate
//! ipc-admin (adminctl, task A11, links ipc-admin too). Its tests may still
//! run a real keyd and dird (dev-dependencies). A positive control finds
//! krb-crypto under keyd and dirstore under directory-admin, so the guard
//! cannot pass vacuously. Offline, host target; a failing `cargo tree`
//! fails the test.
//!
//! Source: docs/45 §10 (D182); A-63; A-73 ("the guard test enumerates the
//! daemons explicitly and every new daemon is added to it"); docs/51 §5.1;
//! docs/50 R50-2; the guard pattern of crates/kdc-daemon
//! tests/no_store_or_crypto.rs and crates/ipc-dird-admin
//! tests/no_store_dependency.rs.

use std::process::Command;

/// What admind must never link.
const FORBIDDEN: [&str; 7] = [
    "krb-crypto",
    "keyd",
    "ipc-keyd-server",
    "dirstore",
    "redb",
    "directory-pip",
    "directory-admin",
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

/// D182; A-73; docs/51 §5.1: none of [`FORBIDDEN`] is linked by admind or
/// by its channel crate; admind does link its clients of dird and keyd.
#[test]
fn admind_links_no_store_pep_keyd_or_crypto() {
    let graph = normal_dependency_graph("admin-daemon");
    assert!(graph.iter().any(|n| n == "admin-daemon"), "{graph:?}");
    for client in ["ipc-admin", "ipc-dird-admin", "ipc-keyd", "ipc-audit"] {
        assert!(graph.iter().any(|n| n == client), "{client} is linked");
    }
    for package in ["admin-daemon", "ipc-admin"] {
        let graph = normal_dependency_graph(package);
        for forbidden in FORBIDDEN {
            assert!(
                !graph.iter().any(|n| n == forbidden),
                "{package} depends on {forbidden}: {graph:?}"
            );
        }
    }
}

/// Positive controls: the same query finds krb-crypto under keyd and
/// dirstore (and redb) under directory-admin.
#[test]
fn the_query_finds_what_it_looks_for() {
    let keyd = normal_dependency_graph("keyd");
    assert!(keyd.iter().any(|n| n == "krb-crypto"), "{keyd:?}");
    let pep = normal_dependency_graph("directory-admin");
    assert!(pep.iter().any(|n| n == "dirstore"), "{pep:?}");
    assert!(pep.iter().any(|n| n == "redb"), "{pep:?}");
}
