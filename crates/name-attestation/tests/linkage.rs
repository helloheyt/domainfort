//! Guard of D182 / A-63 / A-65 for this crate: dird (the signer) and keyd
//! (the verifier) link `name-attestation`, so it must bring them nothing
//! but the MAC it needs — HMAC-SHA-256 and the crypto-free keyd-types — and
//! never the Kerberos crypto profile (krb-crypto, which only keyd links),
//! keyd itself, another primitive crate, a TLS or general-purpose crypto
//! library, or the store. The query is the crate's NORMAL dependency graph
//! (`cargo tree --edges normal`: no dev- or build-dependencies). A positive
//! control finds what it must (hmac, sha2, zeroize, keyd-types), so the
//! guard cannot pass vacuously. Offline, host target (the residual of
//! crates/keyd-types tests/no_crypto_dependency.rs applies); a failing
//! `cargo tree` fails the test.
//!
//! Source: docs/45 §10 (D182); PENDING-OWNER A-63, A-65, A-144 (r4-b
//! §4.1's capability classes, as crates/e2e-tests
//! tests/weak_primitive_confinement.rs uses them: M = keyed MAC, D =
//! unkeyed hash); docs/59 §7.4 (a small crate `name-attestation` that dird
//! and keyd link, keyd-types staying free of crypto); the guard pattern of
//! crates/keyd-types tests/no_crypto_dependency.rs (this project's own
//! code). Test-only.

use std::process::Command;

/// What this crate must never bring into dird's or keyd's graph.
const FORBIDDEN: [&str; 13] = [
    "krb-crypto",
    "keyd",
    "ipc-keyd-server",
    "aes",
    "sha1",
    "pbkdf2",
    "aws-lc-rs",
    "aws-lc-sys",
    "ring",
    "rustls",
    "dirstore",
    "redb",
    "directory-pip",
];

/// What it must link (positive control).
const EXPECTED: [&str; 5] = ["name-attestation", "hmac", "sha2", "zeroize", "keyd-types"];

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

/// D182 / A-65: only the MAC and the crypto-free types, nothing else.
#[test]
fn name_attestation_links_only_the_mac_and_the_types() {
    let graph = normal_dependency_graph("name-attestation");
    for expected in EXPECTED {
        assert!(
            graph.iter().any(|name| name == expected),
            "{expected} missing: {graph:?}"
        );
    }
    for forbidden in FORBIDDEN {
        assert!(
            !graph.iter().any(|name| name == forbidden),
            "name-attestation links {forbidden}: {graph:?}"
        );
    }
}

/// Positive control: the same query finds krb-crypto under keyd.
#[test]
fn the_query_finds_the_crypto_profile_under_keyd() {
    let graph = normal_dependency_graph("keyd");
    assert!(graph.iter().any(|name| name == "krb-crypto"), "{graph:?}");
}
