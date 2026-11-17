//! Guard of docs/50 R50-2 (only dird opens the store), docs/30 §1 (the KDC
//! holds no key), D182 (only keyd links the crypto profile) and A-68 (the
//! shared policy-store crate keeps the kdc free of directory code): the kdc
//! daemon's NORMAL dependency graph (`cargo tree --edges normal`: no dev- or
//! build-dependencies) must not contain the store, the KV engine, the
//! directory PIP, either IPC server side, keyd or the crypto profile. A
//! positive control finds the store under dird, so the guard cannot pass
//! vacuously. Offline, host target (the residual of crates/keyd-types'
//! no_crypto_dependency.rs applies). A failing `cargo tree` fails the test.
//!
//! Source: docs/50 R50-2, §2.2, §10 (the `kdc-daemon` row: tokio, kdc,
//! ipc-keyd, ipc-directory, ipc-audit, config, daemon-sandbox); D182;
//! docs/questions/Q-255 item 8 (the guard pattern, A-65), Q-270 (A-68).

use std::process::Command;

/// What the kdc daemon must never link.
/// `name-attestation`, `hmac` and `sha2` (A-173, A-175; docs/59 §7): the KDC
/// forwards a dird-attested name resolution to keyd but never holds the
/// attestation key nor links MAC code (C3 — a compromised KDC cannot forge
/// a resolution).
const FORBIDDEN: [&str; 11] = [
    "dirstore",
    "redb",
    "directory-pip",
    "ipc-directory-server",
    "ipc-keyd-server",
    "keyd",
    "krb-crypto",
    "directory-daemon",
    "name-attestation",
    "hmac",
    "sha2",
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

/// docs/50 R50-2; docs/30 §1; D182; A-68.
#[test]
fn the_kdc_daemon_links_no_store_no_keyd_and_no_crypto() {
    let graph = normal_dependency_graph("kdc-daemon");
    assert!(
        graph.iter().any(|name| name == "kdc-daemon"),
        "cargo tree did not list kdc-daemon itself: {graph:?}"
    );
    for forbidden in FORBIDDEN {
        assert!(
            !graph.iter().any(|name| name == forbidden),
            "kdc-daemon depends on {forbidden}: {graph:?}"
        );
    }
    // The shared policy file is linked (A-68).
    assert!(graph.iter().any(|name| name == "policy-store"));
}

/// Positive control: the same query finds the store under dird, and the
/// policy-store crate alone links no directory code.
#[test]
fn the_query_finds_the_store_under_dird_and_none_under_policy_store() {
    let dird = normal_dependency_graph("directory-daemon");
    for expected in ["dirstore", "redb", "directory-pip", "policy-store"] {
        assert!(
            dird.iter().any(|name| name == expected),
            "directory-daemon should link {expected}: {dird:?}"
        );
    }
    let store = normal_dependency_graph("policy-store");
    for forbidden in ["dirstore", "redb", "directory-pip", "keyd", "krb-crypto"] {
        assert!(
            !store.iter().any(|name| name == forbidden),
            "policy-store depends on {forbidden}: {store:?}"
        );
    }
}
