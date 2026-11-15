//! Guard of docs/54 §4.3 / R54-4 (dnsd holds "no key, no dirstore, and no
//! access to keyd at all"; it is not mapped in keyd) and §4.7 ("a test that
//! dns-daemon does not link `dirstore`, `krb-crypto`, `keyd`, `ipc-keyd`"):
//! the dns-daemon's NORMAL dependency graph (`cargo tree --edges normal`: no
//! dev- or build-dependencies) must contain none of the store, the KV
//! engine, keyd, keyd's types or channel (either side), the Kerberos crypto
//! profile or DER codec, dird's side of the DNS channel, or **any**
//! `directory-*` crate (the PIP, the write PEP, the dird daemon). A positive
//! control finds the store, keyd and the crypto profile under dird, and the
//! DNS channel under dird's side of it, so the guard cannot pass vacuously.
//! Offline, host target; a failing `cargo tree` fails the test.
//!
//! Source: docs/54 R54-4, §4.3, §4.7, §10 (DN11: "guard (no dirstore /
//! krb-crypto / keyd)"); docs/50 R50-2; D182; the guard pattern of
//! crates/kdc-daemon tests/no_store_or_crypto.rs and crates/ipc-dns
//! tests/no_store_dependency.rs (A-65, A-152).

use std::process::Command;

/// What dnsd must never link, by exact package name.
const FORBIDDEN: [&str; 11] = [
    "dirstore",
    "redb",
    "keyd",
    "keyd-types",
    "keyd-daemon",
    "ipc-keyd",
    "ipc-keyd-server",
    "krb-crypto",
    "krb-proto",
    "ipc-dns-server",
    "ipc-directory-server",
];

/// Every package whose name starts with this is dird's or the directory's.
const FORBIDDEN_PREFIX: &str = "directory-";

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

/// docs/54 R54-4, §4.3, §4.7: none of [`FORBIDDEN`] and no `directory-*`
/// crate is linked; the channel's client side, dns-zone and the shared
/// limiter are.
#[test]
fn dnsd_links_no_store_no_keyd_and_no_crypto() {
    let graph = normal_dependency_graph("dns-daemon");
    assert!(
        graph.iter().any(|name| name == "dns-daemon"),
        "cargo tree did not list dns-daemon itself: {graph:?}"
    );
    for forbidden in FORBIDDEN {
        assert!(
            !graph.iter().any(|name| name == forbidden),
            "dns-daemon depends on {forbidden}: {graph:?}"
        );
    }
    assert!(
        !graph.iter().any(|name| name.starts_with(FORBIDDEN_PREFIX)),
        "dns-daemon depends on a {FORBIDDEN_PREFIX}* crate: {graph:?}"
    );
    for expected in ["ipc-dns", "dns-zone", "rate-limit", "ipc-audit-client"] {
        assert!(
            graph.iter().any(|name| name == expected),
            "dns-daemon should link {expected}: {graph:?}"
        );
    }
}

/// Positive controls: the same query finds the store, keyd's types and
/// channel and `directory-*` crates under dird; keyd and the crypto profile
/// under keyd's daemon (since A-149 the only one that links krb-crypto);
/// and the DNS channel's client side under dird's side of it.
#[test]
fn the_query_finds_what_it_looks_for() {
    let dird = normal_dependency_graph("directory-daemon");
    for expected in ["dirstore", "redb", "keyd-types", "ipc-keyd", "krb-proto"] {
        assert!(
            dird.iter().any(|name| name == expected),
            "directory-daemon should link {expected}: {dird:?}"
        );
    }
    assert!(dird.iter().any(|name| name.starts_with(FORBIDDEN_PREFIX)));
    let keyd = normal_dependency_graph("keyd-daemon");
    for expected in ["keyd", "krb-crypto", "ipc-keyd-server"] {
        assert!(
            keyd.iter().any(|name| name == expected),
            "keyd-daemon should link {expected}: {keyd:?}"
        );
    }
    let server = normal_dependency_graph("ipc-dns-server");
    assert!(server.iter().any(|name| name == "ipc-dns"), "{server:?}");
}
