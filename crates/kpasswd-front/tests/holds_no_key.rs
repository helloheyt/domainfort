//! Guard of docs/53 R53-4 and §4.2 option D ("the front: framing, bounds,
//! KRB-ERROR — **without keyd, without a store, without a secret**"): the
//! front's NORMAL dependency graph (`cargo tree --edges normal`: no dev- or
//! build-dependencies) contains no Kerberos crypto (krb-crypto and the
//! primitive crates under it — so it cannot decrypt the KRB-PRIV that holds
//! the new password, or seal a reply), no keyd crate (no keyd channel, no
//! keyd vocabulary), no store, no KV engine, no directory crate and no
//! server side of any channel. A positive control finds those crates under
//! keyd and dird and the front's own channel and framing under the front,
//! so the guard cannot pass vacuously. Offline, host target; a failing
//! `cargo tree` fails the test.
//!
//! Source: docs/53 R53-4, §4.1 (only keyd decrypts), §4.2 option D, §8
//! ("front compromised": does not see the password; cannot forge a success
//! — that needs the subkey); D182 (only keyd links the crypto profile);
//! docs/research/r4-b §4.2 (`kpasswd-front` | N — no crypto class); the
//! guard pattern of crates/kdc-daemon tests/no_store_or_crypto.rs (A-65).

use std::process::Command;

/// What the front must never link.
const FORBIDDEN: [&str; 19] = [
    "krb-crypto",
    "aes",
    "sha1",
    "sha2",
    "hmac",
    "pbkdf2",
    "rustls",
    "aws-lc-rs",
    "keyd",
    "keyd-types",
    "keyd-daemon",
    "ipc-keyd",
    "ipc-keyd-server",
    "dirstore",
    "redb",
    "directory-pip",
    "directory-admin",
    "directory-daemon",
    "ipc-directory-server",
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

/// docs/53 R53-4, §4.2 option D; D182: none of [`FORBIDDEN`] is linked.
#[test]
fn the_front_holds_no_key_no_store_and_no_keyd_channel() {
    let graph = normal_dependency_graph("kpasswd-front");
    assert!(graph.iter().any(|n| n == "kpasswd-front"), "{graph:?}");
    for forbidden in FORBIDDEN {
        assert!(
            !graph.iter().any(|n| n == forbidden),
            "kpasswd-front depends on {forbidden}: {graph:?}"
        );
    }
}

/// Positive controls: the same query finds the front's own channel and
/// framing under the front, the crypto and keyd's types under keyd, and the
/// store under dird.
#[test]
fn the_query_finds_what_it_looks_for() {
    let front = normal_dependency_graph("kpasswd-front");
    for expected in [
        "ipc-kpasswd",
        "parse-kpasswd",
        "krb-proto",
        "daemon-sandbox",
    ] {
        assert!(front.iter().any(|n| n == expected), "{expected}: {front:?}");
    }
    let keyd = normal_dependency_graph("keyd");
    for expected in ["krb-crypto", "keyd-types", "sha2"] {
        assert!(keyd.iter().any(|n| n == expected), "{expected}: {keyd:?}");
    }
    let dird = normal_dependency_graph("directory-daemon");
    for expected in ["dirstore", "redb", "directory-pip"] {
        assert!(dird.iter().any(|n| n == expected), "{expected}: {dird:?}");
    }
}
