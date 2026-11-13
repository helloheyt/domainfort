//! Guard of D182 / decision A-63: only keyd links the Kerberos crypto
//! profile (`krb-crypto`).
//!
//! The KDC, the LDAP engine, the directory PIP and the ipc-keyd client
//! (the kdc's side of the keyd channel) depend on keyd's crypto-free types
//! (this crate), never on keyd: their processes hold no key (docs/50 §1) and
//! now carry no crypto code either. This test asks cargo for each crate's
//! NORMAL dependency graph (`cargo tree --edges normal`: no dev- or
//! build-dependencies — the tests of these crates may still use a real keyd)
//! and fails if `krb-crypto` or `keyd` appears in it. A positive control
//! checks that the same query does find `krb-crypto` under keyd, so the
//! guard cannot pass vacuously.
//!
//! The query runs offline and for the host target: krb-crypto is reachable
//! only through path dependencies inside this workspace, none of which is
//! target-specific; the CI host is Linux, the product target. A failing
//! `cargo tree` fails the test (fail closed).
//!
//! Source: docs/45 §10 (D182: "krb-crypto, which only keyd links");
//! docs/questions/Q-245 item 3 and PENDING-OWNER A-63 (the keyd-types split);
//! docs/50 §1, §10. Test-only; no vector from any other implementation.

use std::process::Command;

/// The crypto profile that only keyd may link (D182).
const CRYPTO_PROFILE: &str = "krb-crypto";

/// The crates that must not link it (A-63): this crate, and the dependents
/// moved onto it. `ipc-keyd` is the client side of the keyd channel; its
/// server side is the separate crate `ipc-keyd-server`.
const CRYPTO_FREE: [&str; 5] = ["keyd-types", "kdc", "ldap", "directory-pip", "ipc-keyd"];

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

/// D182 / A-63: no crate of [`CRYPTO_FREE`] has krb-crypto — or keyd, which
/// links it — among its normal dependencies, directly or transitively.
#[test]
fn crypto_free_crates_do_not_link_the_crypto_profile() {
    for package in CRYPTO_FREE {
        let graph = normal_dependency_graph(package);
        assert!(
            graph.iter().any(|name| name == package),
            "cargo tree did not list {package} itself: {graph:?}"
        );
        for forbidden in [CRYPTO_PROFILE, "keyd", "ipc-keyd-server"] {
            assert!(
                !graph.iter().any(|name| name == forbidden),
                "{package} depends on {forbidden} (D182: only keyd links krb-crypto): {graph:?}"
            );
        }
    }
}

/// Positive control: the same query finds krb-crypto under keyd (and under
/// ipc-keyd-server, the keyd-daemon's side of the channel).
#[test]
fn the_query_finds_the_crypto_profile_under_keyd() {
    for package in ["keyd", "ipc-keyd-server"] {
        let graph = normal_dependency_graph(package);
        assert!(
            graph.iter().any(|name| name == CRYPTO_PROFILE),
            "{package} should link {CRYPTO_PROFILE}: {graph:?}"
        );
    }
}
