//! Guard: the new password never crosses `dird-kpasswd.sock` in clear —
//! the type-level property of docs/53 R53-4 ("only keyd decrypts the new
//! password"; the front forwards the AP-REQ + KRB-PRIV octets), checked two
//! ways, each with a positive control so neither can pass vacuously.
//!
//! 1. **No type and no capability for it.** This crate's NORMAL dependency
//!    graph (`cargo tree --edges normal`) contains no Kerberos codec
//!    (`krb-proto` — whose `UserData` / `EncKrbPrivPart` /
//!    `ChangePasswdData` / `NewPasswd` are the types that hold a decrypted
//!    KRB-PRIV payload), no Kerberos crypto (`krb-crypto`, nor the
//!    primitive crates under it), no keyd crate, no store and no directory
//!    crate. Positive control: the same query finds `krb-crypto` and
//!    `krb-proto` under keyd, and this crate under kpasswd-front.
//! 2. **No field for it.** No code line of `src/` names a secret-holding
//!    type or codec path (`NewPasswd`, `ChangePasswdData`, `UserData`,
//!    `EncKrbPrivPart`, ipc's `Secret`, `read_secret`, `write_secret`).
//!    Comment lines are skipped (the documentation names them to say they
//!    are absent). Positive control: the same scan finds `read_secret` in
//!    crates/ipc-keyd, whose `SetSecret` carries a password.
//!
//! Offline, host target; a failing `cargo tree` fails the test.
//!
//! Source: docs/53 R53-4, §4.1, §4.3, §8 ("front compromised": "does not
//! see the password"); RFC 3244 §2 (the user-data is encrypted under the
//! subkey); D182 (only keyd links the crypto profile); the guard pattern of
//! crates/ipc-dns tests/no_store_dependency.rs (A-65, A-68).

use std::path::Path;
use std::process::Command;

/// What this crate must never link.
const FORBIDDEN: [&str; 17] = [
    "krb-proto",
    "krb-crypto",
    "parse-asn1",
    "aes",
    "sha1",
    "sha2",
    "hmac",
    "pbkdf2",
    "keyd",
    "keyd-types",
    "ipc-keyd",
    "ipc-keyd-server",
    "dirstore",
    "redb",
    "directory-pip",
    "directory-admin",
    "parse-kpasswd",
];

/// The identifiers no code line of this crate may contain.
const SECRET_NAMES: [&str; 7] = [
    "NewPasswd",
    "ChangePasswdData",
    "UserData",
    "EncKrbPrivPart",
    "Secret",
    "read_secret",
    "write_secret",
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

/// The code lines (not comment lines) of every `.rs` file under `dir` that
/// contain one of `names`, as `file: line`.
fn code_lines_naming(dir: &Path, names: &[&str]) -> Vec<String> {
    let mut found = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(next) = pending.pop() {
        for entry in std::fs::read_dir(&next).expect("readable source directory") {
            let path = entry.expect("directory entry").path();
            if path.is_dir() {
                pending.push(path);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("UTF-8 source");
            for line in text.lines() {
                let code = line.trim_start();
                if code.starts_with("//") {
                    continue;
                }
                let code = code.split("//").next().unwrap_or_default();
                let names_one = code
                    .split(|c: char| !c.is_alphanumeric() && c != '_')
                    .any(|word| names.contains(&word));
                if names_one {
                    found.push(format!("{}: {line}", path.display()));
                }
            }
        }
    }
    found
}

/// docs/53 R53-4; D182: none of [`FORBIDDEN`] is linked.
#[test]
fn the_channel_links_no_kerberos_codec_crypto_keyd_or_store() {
    let graph = normal_dependency_graph("ipc-kpasswd");
    assert!(graph.iter().any(|n| n == "ipc-kpasswd"), "{graph:?}");
    for forbidden in FORBIDDEN {
        assert!(
            !graph.iter().any(|n| n == forbidden),
            "ipc-kpasswd depends on {forbidden}: {graph:?}"
        );
    }
}

/// docs/53 R53-4: no code line names a secret-holding type or codec path.
#[test]
fn no_code_line_names_a_password_type() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let found = code_lines_naming(&src, &SECRET_NAMES);
    assert!(found.is_empty(), "{found:#?}");
}

/// Positive controls: the same query finds the crypto and the codec under
/// keyd, and this crate under kpasswd-front; the same scan finds the secret
/// codec path in ipc-keyd.
#[test]
fn the_guards_find_what_they_look_for() {
    let keyd = normal_dependency_graph("keyd");
    for expected in ["krb-crypto", "krb-proto"] {
        assert!(keyd.iter().any(|n| n == expected), "{keyd:?}");
    }
    let front = normal_dependency_graph("kpasswd-front");
    assert!(front.iter().any(|n| n == "ipc-kpasswd"), "{front:?}");
    let ipc_keyd = Path::new(env!("CARGO_MANIFEST_DIR")).join("../ipc-keyd/src");
    assert!(!code_lines_naming(&ipc_keyd, &["read_secret"]).is_empty());
}
