#![forbid(unsafe_code)]
//! Guard of decision A-145 (task CI3; docs/questions/Q-844, Q-998; r4-a §6,
//! §13 CI3): the one weak primitive the project cannot avoid (SHA-1) is
//! confined to the crate that needs it, and the weak primitives it never
//! needs (MD4, MD5, RC4, DES / 3DES, CRC-32) have no crate at all; the
//! legacy API of the one general-purpose crypto library the workspace links
//! (aws-lc-rs) is never named and never switched on.
//!
//! What this test pins, against `Cargo.lock`, the workspace's manifests, its
//! non-test sources (`crates/*/src`) and cargo's resolved features:
//!
//! 1. **SHA-1 only in krb-crypto** (RFC 3962 §4, §6: H = SHA-1 and PBKDF2's
//!    SHA-1 HMAC, for etypes 17 / 18 — §7; RFC 6113 App. A: the AES PRF over
//!    SHA-1; later the PAC signatures — A-145). (a) Every lock package whose
//!    name carries the SHA-1 mark has no dependent but krb-crypto. (b) No
//!    non-test source outside `crates/krb-crypto/src` names the `sha1` crate
//!    in code; inside krb-crypto only `mac.rs` and `simplified.rs` do, and
//!    never in a `pub` item (no re-export). aws-lc-rs's own SHA-1 items are
//!    rule 5's.
//! 2. **No MD4 crate** (A-145: MD4 only in one keyd function at install
//!    time, and only if owner item P-45 decides so — today: no holder). No
//!    lock package carries the MD4 mark.
//! 3. **No MD5 / RC4 / DES / 3DES / CRC-32 crate** (A-145; docs/02;
//!    docs/CLEAN-ROOM.md). No lock package carries one of their marks.
//! 4. **The lock is a closed world** (the root option of class C41, "only
//!    what is explicitly forbidden is blocked" — docs/52; r4-b §3.5 G6): the
//!    lock's third-party packages are exactly [`REVIEWED_THIRD_PARTY`], each
//!    reviewed for this guard and classed with r4-b §4.1's capability
//!    classes. A package that enters the lock under **any** name fails here
//!    until a reviewer classes it — so rules 2 and 3 do not rest on knowing
//!    a weak crate's name. (IB3's lock classification, A-144, supersedes this
//!    table when it lands — Q-998.)
//! 5. **aws-lc-rs's legacy API is never used** (Q-844 item 4; r4-a §3.3 item
//!    4; docs.rs aws-lc-rs 1.19.0, all items and feature flags): (a) no
//!    non-test source names an item whose name ends in
//!    `_FOR_LEGACY_USE_ONLY`, nor one of the DES / SHA-1 items without that
//!    suffix ([`LEGACY_ITEMS`]), nor the raw bindings `aws_lc_sys`; (b) no
//!    manifest of the workspace names a legacy feature
//!    ([`LEGACY_FEATURES`]); (c) in the worst-case build — the whole
//!    workspace, every feature, every target, normal + build + dev edges —
//!    aws-lc-rs has none of them enabled (by us or by any third-party crate);
//!    (d) the general-purpose libraries (class C) are reached by the
//!    workspace's crates only through aws-lc-rs, and their raw FFI would need
//!    `unsafe`, which the workspace forbids (`unsafe_code = "forbid"`,
//!    inherited by every crate).
//!
//! Why `Cargo.lock` for rules 1–4: it is the union graph — every package any
//! build of the workspace can use, for every target, every dependency kind
//! and every feature combination (it even holds packages no build activates:
//! r4-b §3.4, `ring`). A package absent from it is absent from every build;
//! the dependents it lists are a superset of every build's. Every
//! dependency the lock names is itself a lock entry (checked), so "no weak
//! crate in the lock" is also "no dependency on one".
//!
//! The marks are algorithm names from the specs, not package names: no
//! existing crate is named here but the ones `Cargo.lock` itself lists.
//! Comments are not code (`//` in sources, `#` in manifests). Files under a
//! `tests/` directory and files named `tests.rs` / `*_tests.rs` are test code
//! and not scanned (as crates/e2e-tests tests/no_test_seams_in_product.rs).
//! Positive controls: each scan must find what it must (krb-crypto's SHA-1
//! use, ldap-front's aws-lc-rs provider, aws-lc-rs's `non-fips` feature, the
//! workspace's 52 crates) and each detector flags planted violations.
//!
//! Lexical, not a type: a reviewer decides any new hit. Home: e2e-tests, the
//! crate of the workspace-wide guards (r4-a §13 CI3), not krb-crypto, whose
//! tests test krb-crypto (Q-998 item 1).
//!
//! Source: PENDING-OWNER A-144, A-145; docs/questions/Q-844, Q-852; r4-a
//! §0.2, §3.1, §3.3, §6, §13; r4-b §3.1, §3.4, §3.5, §4.1; docs/52 C15, C41;
//! RFC 3961 §6.1–§6.3, §8; RFC 3962 §4, §6, §7; RFC 6113 App. A (pinned,
//! SHA-256 re-checked against tools/spec-pin/manifest.json); docs.rs
//! aws-lc-rs 1.19.0 (API pages only); docs/CLEAN-ROOM.md. Test-only.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The SHA-1 mark in a package name ("SHA-1": RFC 3962 §6; "sha1": RFC 3961
/// §8), matched with separators removed.
const SHA1_MARK: &str = "sha1";

/// The one crate that may depend on a SHA-1 crate (A-145; D182).
const SHA1_HOLDER: &str = "krb-crypto";

/// The SHA-1 crate of the lock (r4-a §3.1), as a package and as a library.
const SHA1_PACKAGE: &str = "sha1";
const SHA1_LIB: &str = "sha1";

/// The files of krb-crypto that name the `sha1` crate, relative to
/// `crates/`: the HMAC (RFC 3962 §6) and the simplified profile — PBKDF2
/// (RFC 3962 §4) and the PRF (RFC 3961 §5.3; RFC 6113 App. A).
const SHA1_FILES: [&str; 2] = ["krb-crypto/src/mac.rs", "krb-crypto/src/simplified.rs"];

/// The MD4 mark ("rsa-md4": RFC 3961 §6.1.2; "des-cbc-md4": §8), matched
/// with separators removed.
const MD4_MARK: &str = "md4";

/// Marks of the absent primitives matched with separators removed: "rsa-md5"
/// (RFC 3961 §6.1.1), "rc4-hmac" (RFC 3961 §8; "RC4": RFC 6113 App. A),
/// "CRC-32" / "crc32" (RFC 3961 §6.1.3, §8) — "crc" alone, so a crate of
/// generic CRCs is caught too.
const ABSENT_JOINED_MARKS: [&str; 3] = ["md5", "rc4", "crc"];

/// Marks of the absent primitives that must be a whole word of the name
/// (split at every non-alphanumeric character), because "des" occurs inside
/// ordinary words: "des" (RFC 3961 §6.2, §8 "des-cbc-crc", "des-ede3-cbc"),
/// "des3" (§6.3 "des3-cbc-hmac-sha1-kd"), "tripledes" (§6.3 "Triple DES"),
/// "3des" (docs/CLEAN-ROOM.md "DES/3DES"), "tdes" (aws-lc-rs
/// `cmac::TDES_FOR_LEGACY_USE_ONLY`; Q-844 item 4).
const ABSENT_WORD_MARKS: [&str; 5] = ["des", "des3", "tripledes", "3des", "tdes"];

/// A capability class of r4-b §4.1 (accepted as design under A-144).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    /// N — no primitive: runtime, OS bindings, storage, build tools, and the
    /// crypto support crates (traits, arrays, CPU detection, constant-time
    /// helpers, zeroization).
    N,
    /// D — unkeyed hash: SHA-2.
    D,
    /// M — keyed MAC: HMAC.
    M,
    /// K — the Kerberos profile's primitives: AES, SHA-1, PBKDF2.
    K,
    /// T — the TLS stack.
    T,
    /// C — native code; here the general-purpose crypto libraries, which
    /// carry many algorithms, legacy ones among them (r4-a §3.3 item 4).
    C,
}

/// Every third-party package of `Cargo.lock` (rule 4), sorted, with its
/// r4-b §4.1 class. Reviewed for CI3 (Q-998 item 4) against its
/// `cargo metadata` description and r4-a §3.1 / r4-b §3.1, §4.1: none is an
/// implementation of MD4, MD5, RC4, DES / 3DES or CRC-32; the class-C
/// libraries carry such code inside and are confined by rule 5 (aws-lc-rs,
/// aws-lc-sys) or are lock-only and never built (ring — r4-b §3.4, Q-852).
/// A new package fails [`every_third_party_package_is_reviewed`] until a
/// reviewer adds it here with its class.
const REVIEWED_THIRD_PARTY: [(&str, Class); 60] = [
    ("aes", Class::K),
    ("aws-lc-rs", Class::C),
    ("aws-lc-sys", Class::C),
    ("bitflags", Class::N),
    ("block-buffer", Class::D),
    ("bytes", Class::N),
    ("cc", Class::N),
    ("cfg-if", Class::N),
    ("cipher", Class::N),
    ("cmake", Class::N),
    ("cmov", Class::N),
    ("cpubits", Class::N),
    ("cpufeatures", Class::N),
    ("crypto-common", Class::N),
    ("ctutils", Class::N),
    ("digest", Class::N),
    ("dunce", Class::N),
    ("errno", Class::N),
    ("find-msvc-tools", Class::N),
    ("fs_extra", Class::N),
    ("getrandom", Class::N),
    ("hmac", Class::M),
    ("hybrid-array", Class::N),
    ("inout", Class::N),
    ("jobserver", Class::N),
    ("libc", Class::N),
    ("linux-raw-sys", Class::N),
    ("mio", Class::N),
    ("once_cell", Class::N),
    ("pbkdf2", Class::K),
    ("pin-project-lite", Class::N),
    ("pkg-config", Class::N),
    ("r-efi", Class::N),
    ("redb", Class::N),
    ("ring", Class::C),
    ("rustix", Class::N),
    ("rustls", Class::T),
    ("rustls-pki-types", Class::T),
    ("rustls-webpki", Class::T),
    ("sha1", Class::K),
    ("sha2", Class::D),
    ("shlex", Class::N),
    ("socket2", Class::N),
    ("subtle", Class::T),
    ("tokio", Class::N),
    ("typenum", Class::N),
    ("untrusted", Class::T),
    ("wasi", Class::N),
    ("windows-link", Class::N),
    ("windows-sys", Class::N),
    ("windows-targets", Class::N),
    ("windows_aarch64_gnullvm", Class::N),
    ("windows_aarch64_msvc", Class::N),
    ("windows_i686_gnu", Class::N),
    ("windows_i686_gnullvm", Class::N),
    ("windows_i686_msvc", Class::N),
    ("windows_x86_64_gnu", Class::N),
    ("windows_x86_64_gnullvm", Class::N),
    ("windows_x86_64_msvc", Class::N),
    ("zeroize", Class::N),
];

/// The one class-C library the workspace's crates may depend on directly:
/// the TLS provider (OD-9, P-21; L-1), whose legacy API rule 5 closes.
const AWS_LC_RS: &str = "aws-lc-rs";

/// aws-lc-rs's raw bindings: a package, and a library name in code.
const AWS_LC_SYS: &str = "aws-lc-sys";
const AWS_LC_SYS_LIB: &str = "aws_lc_sys";

/// The suffix of aws-lc-rs's legacy items (Q-844 item 4; docs.rs aws-lc-rs
/// 1.19.0: `cipher::DES_FOR_LEGACY_USE_ONLY`, `cipher::DES_EDE_…`,
/// `cipher::DES_EDE3_…`, `cmac::DES_EDE3_…`, `cmac::TDES_…`,
/// `digest::SHA1_…`, `hkdf::HKDF_SHA1_…`, `hmac::HMAC_SHA1_…`,
/// `signature::RSA_PKCS1_1024_8192_SHA1_…` / `…SHA256_…` / `…SHA512_…`,
/// `signature::RSA_PKCS1_2048_8192_SHA1_…`).
const LEGACY_SUFFIX: &str = "_FOR_LEGACY_USE_ONLY";

/// aws-lc-rs 1.19.0 items of the legacy algorithms whose names lack the
/// suffix (docs.rs, all items): the DES key and IV lengths (`cipher`), the
/// SHA-1 output length (`digest`), PBKDF2 over HMAC-SHA1 (`pbkdf2`), OAEP
/// over SHA-1 (`rsa`) and ECDSA over SHA-1 (`signature`).
const LEGACY_ITEMS: [&str; 10] = [
    "DES_KEY_LEN",
    "DES_EDE_KEY_LEN",
    "DES_EDE3_KEY_LEN",
    "DES_CBC_IV_LEN",
    "SHA1_OUTPUT_LEN",
    "PBKDF2_HMAC_SHA1",
    "OAEP_SHA1_MGF1SHA1",
    "ECDSA_P256_SHA1_ASN1",
    "ECDSA_P521_SHA1_ASN1",
    "ECDSA_P521_SHA1_FIXED",
];

/// aws-lc-rs 1.19.0 features never enabled (docs.rs feature flags):
/// `legacy-des` (Q-844 item 4; it enables aws-lc-sys `all-bindings`) and
/// `dev-tests-only` (by its name, for the library's own tests — a product
/// build would carry a test seam, class C18; Q-998 item 6).
const LEGACY_FEATURES: [&str; 2] = ["legacy-des", "dev-tests-only"];

/// A feature aws-lc-rs does have in every build of ldap-front (its manifest:
/// `features = ["non-fips"]`) — the positive control of rule 5 (c).
const PRESENT_FEATURE: &str = "non-fips";

/// The product crate that uses the TLS provider in code (ldap-front
/// `src/tls.rs`: `rustls::crypto::aws_lc_rs`) — rule 5 (a)'s positive
/// control.
const PROVIDER_USER: &str = "ldap-front/src/tls.rs";
const PROVIDER_PATH: &str = "aws_lc_rs";

// ---------------------------------------------------------------- names

/// The name lower-cased with every non-alphanumeric character removed.
fn joined(name: &str) -> String {
    name.chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// The name's words, lower-cased, split at every non-alphanumeric character.
fn words(name: &str) -> Vec<String> {
    name.split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

/// Whether a package name carries the SHA-1 mark.
fn carries_sha1_mark(name: &str) -> bool {
    joined(name).contains(SHA1_MARK)
}

/// Whether a package name carries the MD4 mark.
fn carries_md4_mark(name: &str) -> bool {
    joined(name).contains(MD4_MARK)
}

/// The mark of an absent primitive a package name carries, if any.
fn absent_mark(name: &str) -> Option<&'static str> {
    let joined = joined(name);
    if let Some(mark) = ABSENT_JOINED_MARKS
        .into_iter()
        .find(|m| joined.contains(*m))
    {
        return Some(mark);
    }
    let words = words(name);
    ABSENT_WORD_MARKS
        .into_iter()
        .find(|m| words.iter().any(|w| w == m))
}

// ----------------------------------------------------------------- lock

/// One `[[package]]` entry of `Cargo.lock`: the dependencies by name only.
#[derive(Debug, Default, Clone)]
struct LockPackage {
    name: String,
    source: Option<String>,
    dependencies: Vec<String>,
}

/// The value of `key = "value"`, if the line is that.
fn string_value(line: &str, key: &str) -> Option<String> {
    let rest = line
        .strip_prefix(key)?
        .trim_start()
        .strip_prefix('=')?
        .trim();
    Some(rest.strip_prefix('"')?.strip_suffix('"')?.to_owned())
}

/// The package name of a dependency entry: `"name"`, `"name version"` or
/// `"name version (source)"`, with or without its trailing comma.
fn dependency_name(entry: &str) -> Option<String> {
    let entry = entry.trim().trim_end_matches(',').trim();
    let inner = entry.strip_prefix('"')?.strip_suffix('"')?;
    inner.split_whitespace().next().map(str::to_owned)
}

/// Every `[[package]]` of a `Cargo.lock` text, in order. One pass, no
/// recursion; any other table ends the current package.
fn parse_lock(text: &str) -> Vec<LockPackage> {
    let mut packages = Vec::new();
    let mut current: Option<LockPackage> = None;
    let mut in_dependencies = false;
    for line in text.lines() {
        let line = line.trim();
        if in_dependencies {
            if line == "]" {
                in_dependencies = false;
            } else if let Some(package) = current.as_mut() {
                package.dependencies.extend(dependency_name(line));
            }
            continue;
        }
        if line.starts_with('[') {
            if let Some(package) = current.take() {
                packages.push(package);
            }
            if line == "[[package]]" {
                current = Some(LockPackage::default());
            }
            continue;
        }
        let Some(package) = current.as_mut() else {
            continue;
        };
        if let Some(name) = string_value(line, "name") {
            package.name = name;
        } else if let Some(source) = string_value(line, "source") {
            package.source = Some(source);
        } else if let Some(rest) = line.strip_prefix("dependencies = [") {
            match rest.trim_end().strip_suffix(']') {
                Some(inline) => package
                    .dependencies
                    .extend(inline.split(',').filter_map(dependency_name)),
                None => {
                    in_dependencies = true;
                    package.dependencies.extend(dependency_name(rest));
                }
            }
        }
    }
    if let Some(package) = current {
        packages.push(package);
    }
    packages
}

/// The workspace's `Cargo.lock`, parsed and checked: every entry named,
/// more than a hundred entries, and every dependency a lock entry itself
/// (so a package absent from the lock is no package's dependency).
fn lock() -> Vec<LockPackage> {
    let path = crates_dir()
        .parent()
        .expect("workspace root")
        .join("Cargo.lock");
    let text = std::fs::read_to_string(path).expect("Cargo.lock");
    let packages = parse_lock(&text);
    assert!(packages.len() > 100, "{} lock entries", packages.len());
    assert!(packages.iter().all(|p| !p.name.is_empty()), "unnamed entry");
    let names: BTreeSet<&str> = packages.iter().map(|p| p.name.as_str()).collect();
    for package in &packages {
        for dependency in &package.dependencies {
            assert!(
                names.contains(dependency.as_str()),
                "{} depends on {dependency}, which is not a lock entry",
                package.name
            );
        }
    }
    packages
}

/// The packages that depend on `name`, by any kind of dependency.
fn dependents<'a>(lock: &'a [LockPackage], name: &str) -> BTreeSet<&'a str> {
    lock.iter()
        .filter(|p| p.dependencies.iter().any(|d| d == name))
        .map(|p| p.name.as_str())
        .collect()
}

/// The lock's third-party packages (those with a `source`), by name.
fn third_party(lock: &[LockPackage]) -> BTreeSet<&str> {
    lock.iter()
        .filter(|p| p.source.is_some())
        .map(|p| p.name.as_str())
        .collect()
}

// --------------------------------------------------- workspace and files

/// The workspace's `crates/` directory.
fn crates_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/ directory")
        .to_path_buf()
}

/// Every crate directory with a manifest, sorted.
fn crate_dirs() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(crates_dir())
        .expect("readable crates/")
        .map(|e| e.expect("entry").path())
        .filter(|p| p.join("Cargo.toml").is_file())
        .collect();
    dirs.sort();
    dirs
}

/// Every `.rs` file below `dir`, recursively, without test code
/// (directories named `tests`, files named `tests.rs` or `*_tests.rs`).
fn product_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(read) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<PathBuf> = read.map(|e| e.expect("entry").path()).collect();
    entries.sort();
    for path in entries {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if path.is_dir() {
            if name != "tests" {
                product_sources(&path, out);
            }
        } else if name.ends_with(".rs") && name != "tests.rs" && !name.ends_with("_tests.rs") {
            out.push(path);
        }
    }
}

/// Every product source of the workspace: `(path relative to crates/, text)`.
fn workspace_product_sources() -> Vec<(PathBuf, String)> {
    let crates = crates_dir();
    let mut out = Vec::new();
    for dir in crate_dirs() {
        let mut files = Vec::new();
        product_sources(&dir.join("src"), &mut files);
        for file in files {
            let rel = file.strip_prefix(&crates).unwrap_or(&file).to_path_buf();
            let text = std::fs::read_to_string(&file).expect("UTF-8 source");
            out.push((rel, text));
        }
    }
    out
}

/// The code of each line of `text`, `//` comments removed:
/// `(line number, code)`.
fn code_lines(text: &str) -> impl Iterator<Item = (usize, &str)> {
    text.lines()
        .enumerate()
        .map(|(n, line)| (n + 1, line.split("//").next().unwrap_or("")))
}

/// A manifest's lines without `#` comments, each with the table it is in.
fn manifest_lines(text: &str) -> Vec<(String, String)> {
    let mut table = String::new();
    let mut out = Vec::new();
    for line in text.lines() {
        let code = line.split('#').next().unwrap_or("").trim().to_owned();
        if code.starts_with('[') && code.ends_with(']') {
            table = code.trim_matches(|c| c == '[' || c == ']').to_owned();
            continue;
        }
        if !code.is_empty() {
            out.push((table.clone(), code));
        }
    }
    out
}

// -------------------------------------------------------- source scans

/// `true` for a character of a Rust identifier.
fn ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// Whether one line of code (comments removed) names the crate whose
/// library is `lib`: a path `lib::…` (also `::lib::…`, `<lib::T>`,
/// `lib :: T`), `use lib…` or `extern crate lib`. `lib` inside a longer
/// identifier or inside words like `hmac-sha1-96` is not a naming.
fn names_crate(code: &str, lib: &str) -> bool {
    let mut from = 0;
    while let Some(at) = code[from..].find(lib) {
        let start = from + at;
        let end = start + lib.len();
        from = end;
        let before = code[..start].chars().next_back();
        let after = code[end..].chars().next();
        if before.is_some_and(ident_char) || after.is_some_and(ident_char) {
            continue;
        }
        if code[end..].trim_start().starts_with("::") {
            return true;
        }
        let preceding = code[..start].trim_end();
        let word_start = preceding
            .char_indices()
            .rev()
            .find(|(_, c)| !ident_char(*c))
            .map_or(0, |(i, c)| i + c.len_utf8());
        if matches!(&preceding[word_start..], "use" | "crate") {
            return true;
        }
    }
    false
}

/// The lines of `text` that name the crate `lib` in code:
/// `(line number, code)`.
fn crate_namings(text: &str, lib: &str) -> Vec<(usize, String)> {
    code_lines(text)
        .filter(|(_, code)| names_crate(code, lib))
        .map(|(n, code)| (n, code.trim().to_owned()))
        .collect()
}

/// Whether a line of code is a public item (`pub …`); `pub(crate)`,
/// `pub(super)` and `pub(in …)` are not.
fn is_public_item(code: &str) -> bool {
    code.trim_start().starts_with("pub ")
}

/// The identifiers of one line of code.
fn identifiers(code: &str) -> impl Iterator<Item = &str> {
    code.split(|c: char| !ident_char(c))
        .filter(|w| !w.is_empty())
}

/// Why an identifier is a forbidden aws-lc name (rule 5 (a)), if it is one.
fn legacy_name(ident: &str) -> Option<&'static str> {
    if ident.ends_with(LEGACY_SUFFIX) {
        Some("a `_FOR_LEGACY_USE_ONLY` item")
    } else if LEGACY_ITEMS.contains(&ident) {
        Some("a legacy-algorithm item")
    } else if ident == AWS_LC_SYS_LIB {
        Some("the raw bindings")
    } else {
        None
    }
}

/// The forbidden aws-lc names in `text`'s code: `(line, identifier, why)`.
fn legacy_namings(text: &str) -> Vec<(usize, String, &'static str)> {
    let mut found = Vec::new();
    for (n, code) in code_lines(text) {
        for ident in identifiers(code) {
            if let Some(why) = legacy_name(ident) {
                found.push((n, ident.to_owned(), why));
            }
        }
    }
    found
}

/// The manifest lines (outside comments) that name a legacy feature:
/// `[table] code`.
fn legacy_feature_lines(text: &str) -> Vec<String> {
    manifest_lines(text)
        .into_iter()
        .filter(|(_, code)| {
            LEGACY_FEATURES
                .iter()
                .any(|f| code.contains(&format!("\"{f}\"")))
        })
        .map(|(table, code)| format!("[{table}] {code}"))
        .collect()
}

// ------------------------------------------------------------ cargo tree

/// aws-lc-rs's enabled features in the worst-case build — the whole
/// workspace, every feature of every member, every target, normal + build +
/// dev edges (r4-b §3.4: the graph from `cargo tree`, not the metadata
/// resolve) — with the number of lines printed and of aws-lc-rs nodes.
fn worst_case_features(package: &str) -> (BTreeSet<String>, usize, usize) {
    let manifest = concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.toml");
    let output = Command::new(env!("CARGO"))
        .args([
            "tree",
            "--manifest-path",
            manifest,
            "--workspace",
            "--all-features",
            "--target",
            "all",
            "--edges",
            "normal,build,dev",
            "--prefix",
            "none",
            "--format",
            "{p}|{f}",
            "--offline",
            "--locked",
        ])
        .output()
        .expect("cargo tree runs");
    assert!(
        output.status.success(),
        "cargo tree failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).expect("cargo tree prints UTF-8");
    let mut features = BTreeSet::new();
    let mut lines = 0usize;
    let mut nodes = 0usize;
    for line in text.lines() {
        let Some((node, list)) = line.rsplit_once('|') else {
            continue;
        };
        lines += 1;
        if node.split_whitespace().next() != Some(package) {
            continue;
        }
        nodes += 1;
        let list = list.trim().trim_end_matches("(*)").trim();
        features.extend(
            list.split(',')
                .map(str::trim)
                .filter(|f| !f.is_empty())
                .map(str::to_owned),
        );
    }
    (features, lines, nodes)
}

// ----------------------------------------------------------------- rules

/// Rule 1 (a): every SHA-1 crate of the lock has no dependent but
/// krb-crypto — no other crate of ours, and no third-party crate, by any
/// kind of dependency, for any target.
#[test]
fn sha1_crates_have_no_dependent_but_krb_crypto() {
    let lock = lock();
    let sha1_crates: Vec<&str> = lock
        .iter()
        .map(|p| p.name.as_str())
        .filter(|n| carries_sha1_mark(n))
        .collect();
    let mut violations = Vec::new();
    for name in &sha1_crates {
        for dependent in dependents(&lock, name) {
            if dependent != SHA1_HOLDER {
                violations.push(format!("{dependent} depends on {name}"));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "a SHA-1 crate is a dependency of a crate other than {SHA1_HOLDER} (A-145): \
         {violations:#?}"
    );
    // Positive control: the lock's SHA-1 crate is seen, and krb-crypto
    // depends on it.
    assert!(sha1_crates.contains(&SHA1_PACKAGE), "{sha1_crates:?}");
    assert_eq!(
        dependents(&lock, SHA1_PACKAGE)
            .into_iter()
            .collect::<Vec<_>>(),
        vec![SHA1_HOLDER]
    );
}

/// Rule 1 (b): no product source outside krb-crypto names the `sha1` crate;
/// inside krb-crypto only `mac.rs` and `simplified.rs` do, never in a `pub`
/// item.
#[test]
fn only_krb_crypto_sources_name_the_sha1_crate() {
    let mut violations = Vec::new();
    let mut holder_files = Vec::new();
    let mut scanned = 0usize;
    let holder_src = Path::new(SHA1_HOLDER).join("src");
    for (rel, text) in workspace_product_sources() {
        scanned += 1;
        let namings = crate_namings(&text, SHA1_LIB);
        if namings.is_empty() {
            continue;
        }
        if !rel.starts_with(&holder_src) {
            for (line, code) in namings {
                violations.push(format!("{}:{line}: {code}", rel.display()));
            }
            continue;
        }
        for (line, code) in &namings {
            if is_public_item(code) {
                violations.push(format!("{}:{line}: re-export: {code}", rel.display()));
            }
        }
        holder_files.push(rel);
    }
    assert!(
        violations.is_empty(),
        "the `{SHA1_LIB}` crate named outside {SHA1_HOLDER}, or re-exported by it (A-145): \
         {violations:#?}"
    );
    // Positive control (and pin): krb-crypto names it exactly in its HMAC
    // and simplified-profile files; the scan covered the workspace.
    let expected: Vec<PathBuf> = SHA1_FILES.into_iter().map(PathBuf::from).collect();
    assert_eq!(
        holder_files, expected,
        "the files of {SHA1_HOLDER} that use SHA-1"
    );
    assert!(scanned > 100, "{scanned}");
}

/// Rule 2: no MD4 crate in the lock (A-145: no holder until P-45 decides).
/// Every dependency is a lock entry (`lock()`), so no package depends on
/// one either.
#[test]
fn the_lock_holds_no_md4_crate() {
    let lock = lock();
    let found: Vec<&str> = lock
        .iter()
        .map(|p| p.name.as_str())
        .filter(|n| carries_md4_mark(n))
        .collect();
    assert!(
        found.is_empty(),
        "an MD4 crate is in Cargo.lock (A-145: MD4 only if P-45 decides so, in one keyd \
         function — then this guard is changed by that decision): {found:?}"
    );
}

/// Rule 3: no MD5, RC4, DES / 3DES or CRC-32 crate in the lock, so no
/// dependency on one.
#[test]
fn the_lock_holds_no_md5_rc4_des_or_crc32_crate() {
    let lock = lock();
    let found: Vec<(&str, &str)> = lock
        .iter()
        .filter_map(|p| absent_mark(&p.name).map(|m| (p.name.as_str(), m)))
        .collect();
    assert!(
        found.is_empty(),
        "a crate of a primitive with no code path is in Cargo.lock (A-145; docs/02): \
         {found:?}"
    );
}

/// Rule 4: the lock's third-party packages are exactly the reviewed table;
/// the table itself carries no weak mark but the confined SHA-1 crate, and
/// the source-less lock entries are exactly the workspace's crates.
#[test]
fn every_third_party_package_is_reviewed() {
    let lock = lock();
    let reviewed: Vec<&str> = REVIEWED_THIRD_PARTY.iter().map(|(n, _)| *n).collect();
    assert!(
        reviewed.windows(2).all(|w| w[0] < w[1]),
        "keep REVIEWED_THIRD_PARTY sorted and without duplicates"
    );
    let reviewed: BTreeSet<&str> = reviewed.into_iter().collect();
    let locked = third_party(&lock);
    let unreviewed: Vec<&&str> = locked.difference(&reviewed).collect();
    let stale: Vec<&&str> = reviewed.difference(&locked).collect();
    assert!(
        unreviewed.is_empty(),
        "third-party packages not reviewed for weak primitives (rule 4; Q-998): {unreviewed:?} \
         — check that none implements MD4, MD5, RC4, DES / 3DES or CRC-32 (or SHA-1 outside \
         krb-crypto) and add each to REVIEWED_THIRD_PARTY with its r4-b §4.1 class"
    );
    assert!(
        stale.is_empty(),
        "REVIEWED_THIRD_PARTY lists packages no longer in Cargo.lock: {stale:?}"
    );
    for (name, class) in REVIEWED_THIRD_PARTY {
        assert!(!carries_md4_mark(name), "{name}");
        assert_eq!(absent_mark(name), None, "{name}");
        assert!(
            !carries_sha1_mark(name) || (name == SHA1_PACKAGE && class == Class::K),
            "{name}"
        );
    }
    // Positive control: the lock's other entries are exactly the
    // workspace's crates (one per crates/* manifest), so the split between
    // ours and third-party is the right one.
    let ours: BTreeSet<&str> = lock
        .iter()
        .filter(|p| p.source.is_none())
        .map(|p| p.name.as_str())
        .collect();
    let mut members = BTreeSet::new();
    for dir in crate_dirs() {
        let text = std::fs::read_to_string(dir.join("Cargo.toml")).expect("manifest");
        let name = manifest_lines(&text)
            .into_iter()
            .filter(|(t, _)| t == "package")
            .find_map(|(_, code)| string_value(&code, "name"))
            .unwrap_or_else(|| panic!("{}: no package name", dir.display()));
        members.insert(name);
    }
    let members: BTreeSet<&str> = members.iter().map(String::as_str).collect();
    assert_eq!(ours, members);
    assert!(members.len() >= 50, "{}", members.len());
}

/// Rule 5 (d): the class-C libraries are reached by the workspace's crates
/// only through aws-lc-rs; aws-lc-sys has no dependent but aws-lc-rs; and
/// the raw FFI they expose needs `unsafe`, which every crate forbids.
#[test]
fn general_crypto_libraries_are_reached_only_through_aws_lc_rs() {
    let lock = lock();
    let class_c: BTreeSet<&str> = REVIEWED_THIRD_PARTY
        .iter()
        .filter(|(_, c)| *c == Class::C)
        .map(|(n, _)| *n)
        .collect();
    let mut violations = Vec::new();
    let mut provider_users = BTreeSet::new();
    for package in lock.iter().filter(|p| p.source.is_none()) {
        for dependency in &package.dependencies {
            if !class_c.contains(dependency.as_str()) {
                continue;
            }
            if dependency == AWS_LC_RS {
                provider_users.insert(package.name.as_str());
            } else {
                violations.push(format!("{} depends on {dependency}", package.name));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "a workspace crate depends on a general-purpose crypto library other than \
         {AWS_LC_RS} (rule 5): {violations:#?}"
    );
    assert_eq!(
        dependents(&lock, AWS_LC_SYS)
            .into_iter()
            .collect::<Vec<_>>(),
        vec![AWS_LC_RS]
    );
    // Positive control: ldap-front (the TLS front) does depend on aws-lc-rs.
    assert!(provider_users.contains("ldap-front"), "{provider_users:?}");

    // `unsafe_code = "forbid"` for the workspace, inherited by every crate.
    let root = crates_dir().parent().expect("workspace root").to_path_buf();
    let workspace = std::fs::read_to_string(root.join("Cargo.toml")).expect("workspace manifest");
    assert!(
        manifest_lines(&workspace)
            .iter()
            .any(|(t, c)| t == "workspace.lints.rust"
                && c.replace(' ', "") == "unsafe_code=\"forbid\""),
        "the workspace must forbid unsafe code"
    );
    for dir in crate_dirs() {
        let text = std::fs::read_to_string(dir.join("Cargo.toml")).expect("manifest");
        assert!(
            manifest_lines(&text)
                .iter()
                .any(|(t, c)| t == "lints" && c.replace(' ', "") == "workspace=true"),
            "{}: does not inherit the workspace lints",
            dir.display()
        );
    }
}

/// Rule 5 (a): no product source names a legacy aws-lc item or the raw
/// bindings.
#[test]
fn no_product_source_names_an_aws_lc_legacy_item() {
    let mut violations = Vec::new();
    let mut provider_seen = false;
    let mut scanned = 0usize;
    for (rel, text) in workspace_product_sources() {
        scanned += 1;
        for (line, ident, why) in legacy_namings(&text) {
            violations.push(format!("{}:{line}: {ident} ({why})", rel.display()));
        }
        if rel == Path::new(PROVIDER_USER) {
            provider_seen = code_lines(&text).any(|(_, c)| names_crate(c, PROVIDER_PATH));
        }
    }
    assert!(
        violations.is_empty(),
        "a product source names aws-lc's legacy API (A-145; Q-844 item 4): {violations:#?}"
    );
    // Positive control: the scan reached the product file that does use the
    // provider, and saw that use.
    assert!(
        provider_seen,
        "{PROVIDER_USER} not scanned or its provider use not seen"
    );
    assert!(scanned > 100, "{scanned}");
}

/// Rule 5 (b): no manifest of the workspace names a legacy feature.
#[test]
fn no_manifest_enables_an_aws_lc_legacy_feature() {
    let root = crates_dir().parent().expect("workspace root").to_path_buf();
    let mut manifests = vec![root.join("Cargo.toml")];
    manifests.extend(crate_dirs().into_iter().map(|d| d.join("Cargo.toml")));
    let mut violations = Vec::new();
    let mut provider_lines = 0usize;
    for manifest in &manifests {
        let text = std::fs::read_to_string(manifest).expect("manifest");
        for line in legacy_feature_lines(&text) {
            violations.push(format!("{}: {line}", manifest.display()));
        }
        provider_lines += manifest_lines(&text)
            .iter()
            .filter(|(t, c)| {
                t.ends_with("dependencies")
                    && c.starts_with(AWS_LC_RS)
                    && c.contains(&format!("\"{PRESENT_FEATURE}\""))
            })
            .count();
    }
    assert!(
        violations.is_empty(),
        "a manifest names an aws-lc-rs legacy feature (Q-844 item 4): {violations:#?}"
    );
    // Positive control: the manifests' aws-lc-rs lines are read (ldap-front
    // and e2e-tests ask for `non-fips`).
    assert!(provider_lines >= 1, "{provider_lines}");
}

/// Rule 5 (c): in the worst-case build aws-lc-rs has no legacy feature —
/// neither from the workspace nor from a third-party crate (e.g. rustls).
#[test]
fn the_worst_case_build_enables_no_aws_lc_legacy_feature() {
    let (features, lines, nodes) = worst_case_features(AWS_LC_RS);
    let enabled: Vec<&&str> = LEGACY_FEATURES
        .iter()
        .filter(|f| features.contains(**f))
        .collect();
    assert!(
        enabled.is_empty(),
        "aws-lc-rs is built with a legacy feature (Q-844 item 4): {enabled:?} of {features:?}"
    );
    // Positive control: aws-lc-rs is in the graph with the feature
    // ldap-front asks for, so the features are read.
    assert!(nodes >= 1 && lines > 100, "{nodes} / {lines}");
    assert!(features.contains(PRESENT_FEATURE), "{features:?}");
}

// ----------------------------------------------------- positive controls

/// The marks flag planted names (synthetic, built from the marks — no real
/// package is named), in every spelling: bare, prefixed, suffixed, upper
/// case, split by a separator; words that merely contain the letters are
/// not flagged.
#[test]
fn the_name_marks_see_planted_packages() {
    for mark in ABSENT_JOINED_MARKS {
        let (head, tail) = mark.split_at(mark.len() - 1);
        for name in [
            mark.to_owned(),
            format!("x-{mark}"),
            format!("{mark}_y"),
            mark.to_ascii_uppercase(),
            format!("{head}-{tail}"),
        ] {
            assert_eq!(absent_mark(&name), Some(mark), "{name}");
        }
    }
    for mark in ABSENT_WORD_MARKS {
        for name in [
            mark.to_owned(),
            format!("x-{mark}"),
            format!("{mark}_y-z"),
            mark.to_ascii_uppercase(),
        ] {
            assert_eq!(absent_mark(&name), Some(mark), "{name}");
        }
    }
    for name in ["md4", "x-md4", "md-4", "MD4_y"] {
        assert!(carries_md4_mark(name), "{name}");
        assert_eq!(absent_mark(name), None, "{name}");
    }
    for name in ["sha1", "sha-1", "x_sha1", "SHA1-y"] {
        assert!(carries_sha1_mark(name), "{name}");
    }
    for name in [
        "designer",
        "x-describe",
        "list-destroy-decisions",
        "codes",
        "sha2",
        "sha256-x",
        "md-tools",
    ] {
        assert_eq!(absent_mark(name), None, "{name}");
        assert!(!carries_md4_mark(name), "{name}");
        assert!(!carries_sha1_mark(name), "{name}");
    }
}

/// The lock parser reads planted entries: names, sources, multi-line and
/// inline dependency lists in all three entry forms, and other tables.
#[test]
fn the_lock_parser_reads_planted_entries() {
    let text = "# comment\nversion = 4\n\n\
                [[package]]\nname = \"alpha\"\nversion = \"1.0.0\"\n\
                source = \"registry+https://example.invalid/index\"\nchecksum = \"00\"\n\
                dependencies = [\n \"beta\",\n \"gamma 0.2.0\",\n \
                \"delta 1.0.0 (registry+https://example.invalid/index)\",\n]\n\n\
                [[package]]\nname = \"beta\"\nversion = \"0.1.0\"\ndependencies = [\"gamma\", \"delta\"]\n\n\
                [[package]]\nname = \"gamma\"\nversion = \"0.2.0\"\n\n\
                [metadata]\nname = \"not-a-package\"\n";
    let packages = parse_lock(text);
    let names: Vec<&str> = packages.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, ["alpha", "beta", "gamma"]);
    assert_eq!(packages[0].dependencies, ["beta", "gamma", "delta"]);
    assert!(packages[0].source.is_some());
    assert_eq!(packages[1].dependencies, ["gamma", "delta"]);
    assert!(packages[1].source.is_none());
    assert!(packages[2].dependencies.is_empty());
    assert_eq!(
        dependents(&packages, "gamma")
            .into_iter()
            .collect::<Vec<_>>(),
        ["alpha", "beta"]
    );
    assert_eq!(
        third_party(&packages).into_iter().collect::<Vec<_>>(),
        ["alpha"]
    );
}

/// The source scanners see planted uses — every form of naming the `sha1`
/// crate, a re-export, aws-lc's legacy items and raw bindings — and not
/// comments, spec names that merely contain the letters, or other items.
#[test]
fn the_source_scanners_see_planted_uses() {
    for code in [
        "use sha1::Sha1;",
        "    pbkdf2::pbkdf2_hmac::<sha1::Sha1>(p, s, i, &mut k);",
        "use sha1;",
        "extern crate sha1;",
        "pub use sha1 as h;",
        "let d = ::sha1::Sha1::digest(m);",
        "use {sha1 :: Sha1};",
    ] {
        assert!(names_crate(code, SHA1_LIB), "{code}");
    }
    for code in [
        "let name = \"aes256-cts-hmac-sha1-96\";",
        "EncType::Aes256CtsHmacSha196 => 18,",
        "let sha1x = 1;",
        "my_sha1::f();",
        "HashAlg::Sha1 => keyed::<Hmac<Sha1>>(key, parts)?",
    ] {
        assert!(!names_crate(code, SHA1_LIB), "{code}");
    }
    let text = "// use sha1::Sha1;\n/// See `sha1::Sha1`.\nuse sha1::Sha1; // HMAC\n";
    assert_eq!(
        crate_namings(text, SHA1_LIB)
            .into_iter()
            .map(|(n, _)| n)
            .collect::<Vec<_>>(),
        [3]
    );
    assert!(is_public_item("pub use sha1::Sha1;"));
    assert!(is_public_item("    pub type H = sha1::Sha1;"));
    assert!(!is_public_item("pub(crate) use sha1::Sha1;"));
    assert!(!is_public_item("use sha1::Sha1;"));

    let text = "use aws_lc_rs::cmac::TDES_FOR_LEGACY_USE_ONLY;\n\
                let a = &digest::SHA1_FOR_LEGACY_USE_ONLY;\n\
                let b = &signature::ECDSA_P256_SHA1_ASN1;\n\
                let c = pbkdf2::PBKDF2_HMAC_SHA1;\n\
                let d = aws_lc_sys::foo();\n\
                // cipher::DES_FOR_LEGACY_USE_ONLY in a comment\n\
                let e = ADS_UF_USE_DES_KEY_ONLY | 1;\n\
                let f = &signature::ECDSA_P256_SHA256_ASN1;\n\
                let g = aws_lc_rs::default_provider();\n";
    let found: Vec<(usize, String)> = legacy_namings(text)
        .into_iter()
        .map(|(n, i, _)| (n, i))
        .collect();
    assert_eq!(
        found,
        [
            (1, "TDES_FOR_LEGACY_USE_ONLY".to_owned()),
            (2, "SHA1_FOR_LEGACY_USE_ONLY".to_owned()),
            (3, "ECDSA_P256_SHA1_ASN1".to_owned()),
            (4, "PBKDF2_HMAC_SHA1".to_owned()),
            (5, "aws_lc_sys".to_owned()),
        ]
    );
}

/// The manifest scanner sees a planted legacy feature in an inline table,
/// a dotted dependency table and a target table, and not in a comment or
/// another feature.
#[test]
fn the_manifest_scanner_sees_planted_features() {
    let manifest = "[dependencies]\n\
                    aws-lc-rs = { version = \"1.19.0\", features = [\"non-fips\", \"legacy-des\"] }\n\
                    # aws-lc-rs = { features = [\"legacy-des\"] }\n\
                    [dependencies.aws-lc-rs]\nfeatures = [\"dev-tests-only\"]\n\
                    [target.'cfg(unix)'.dev-dependencies]\n\
                    aws-lc-rs = { version = \"1\", features = [\"legacy-des\"] }\n\
                    [dev-dependencies]\naws-lc-rs = { version = \"1\", features = [\"non-fips\"] }\n";
    let found = legacy_feature_lines(manifest);
    assert_eq!(found.len(), 3, "{found:#?}");
    assert!(found[0].starts_with("[dependencies] aws-lc-rs"));
    assert!(found[1].starts_with("[dependencies.aws-lc-rs] features"));
    assert!(found[2].starts_with("[target.'cfg(unix)'.dev-dependencies]"));
}
