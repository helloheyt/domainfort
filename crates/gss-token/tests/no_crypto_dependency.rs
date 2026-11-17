//! Guard of docs/60 §10 task LG1 ("a leaf crate `gss-token` without
//! cryptography") and of D182 (only keyd links the Kerberos crypto profile
//! `krb-crypto`): this crate's normal dependency graph is this crate alone —
//! no krb-crypto, no RustCrypto crate, nothing else.
//!
//! The query is the one of keyd-types' `tests/no_crypto_dependency.rs`
//! (`cargo tree --edges normal`, offline, host target). A positive control
//! checks that the same query does find krb-crypto under keyd, so the guard
//! cannot pass vacuously. A failing `cargo tree` fails the test (fail closed).
//!
//! Source: docs/60 R60-3, §3.3, §10 LG1, §10 "special gates" (the keyd-types
//! no-crypto guard); docs/45 §10 (D182); docs/CLEAN-ROOM.md (no crypto primitive
//! outside approved dependencies — and none here at all). Test-only.

use std::process::Command;

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

/// docs/60 §10 LG1: gss-token links nothing — in particular not krb-crypto,
/// keyd, or any crypto crate.
#[test]
fn gss_token_has_no_dependency_at_all() {
    let graph = normal_dependency_graph("gss-token");
    assert!(
        graph.iter().all(|name| name == "gss-token") && !graph.is_empty(),
        "gss-token must have no normal dependency (no crypto — docs/60 §10 LG1): {graph:?}"
    );
    for forbidden in [
        "krb-crypto",
        "keyd",
        "name-attestation",
        "aes",
        "sha1",
        "sha2",
        "hmac",
    ] {
        assert!(
            !graph.iter().any(|name| name == forbidden),
            "gss-token depends on {forbidden}: {graph:?}"
        );
    }
}

/// Positive control: the same query finds krb-crypto under keyd.
#[test]
fn the_query_finds_the_crypto_profile_under_keyd() {
    let graph = normal_dependency_graph("keyd");
    assert!(
        graph.iter().any(|name| name == "krb-crypto"),
        "keyd should link krb-crypto: {graph:?}"
    );
}
