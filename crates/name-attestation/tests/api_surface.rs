//! Guard of A-145 RC-6 (class C42, "a general MAC or signature oracle over a
//! long-term key") and of D28 / D29 (no operation returns key material) for
//! this crate: its public surface is exactly the reviewed one — the key's
//! constructor, `tag` and `verify` on a name resolution, the proof type and
//! the two errors — and no public function but the key's constructor names
//! octets in its signature.
//!
//! What this test pins, in the crate's non-test source (`src/`):
//!
//! 1. The `pub` items — functions, methods, types, constants, fields,
//!    re-exports — are exactly [`REVIEWED`]. A new public item (a
//!    `pub fn mac(key, data: &[u8])`, a `pub` field holding the key, a
//!    re-export of the private HMAC helper) fails here until a reviewer
//!    decides it.
//! 2. No `pub fn` signature mentions `u8` — so none takes caller-chosen
//!    octets to tag and none returns octets — except
//!    `AttestationKey::from_bytes`, which takes the key and returns none.
//!
//! Lexical, not a type: it catches the shape of the regression, and a
//! reviewer decides any new hit. Line comments are dropped and the
//! `#[cfg(test)] mod … {` block is not scanned. Positive controls: the scan
//! of `src/` finds every reviewed item (exact equality), and the scanner
//! flags planted violations and not comments or test code.
//!
//! Source: PENDING-OWNER A-145 (RC-6, C42); docs/59 §7.4; docs/questions/
//! Q-1011 item 2 (A-173: the key is never exported); D28 / D29; AGENTS.md
//! §6.1. Test-only; modelled on this project's own source-scan guards
//! (crates/keyd-types tests/one_service_purpose_derivation.rs).

use std::collections::BTreeSet;
use std::path::Path;

/// The reviewed public surface: (kind, name).
const REVIEWED: [(&str, &str); 10] = [
    ("const", "ATTESTATION_KEY_LEN"),
    ("struct", "AttestationKey"),
    ("fn", "from_bytes"),
    ("struct", "KeyRefused"),
    ("struct", "AttestationError"),
    ("struct", "AuthenticatedNameResolution"),
    ("fn", "resolution"),
    ("fn", "into_resolution"),
    ("fn", "tag"),
    ("fn", "verify"),
];

/// The one public function that may name octets: it takes the key.
const TAKES_THE_KEY: &str = "from_bytes";

/// Item keywords after `pub`; any other word is a field.
const KEYWORDS: [&str; 9] = [
    "fn", "struct", "enum", "const", "static", "type", "trait", "mod", "use",
];

/// The non-test code of a file: line comments removed, everything from a
/// `#[cfg(test)]` line followed by an inline `mod … {` to the end dropped.
fn code_of(text: &str) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        if line.trim() == "#[cfg(test)]" {
            let next = lines.get(i + 1).map(|l| l.trim()).unwrap_or("");
            if next.starts_with("mod ") && next.ends_with('{') {
                break;
            }
        }
        out.push_str(line.split("//").next().unwrap_or(""));
        out.push('\n');
        i += 1;
    }
    out
}

/// A public item found by the scan.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Item {
    kind: String,
    name: String,
    /// For a function: its signature up to the body's `{`.
    signature: String,
}

/// Every `pub` item of `code` (`pub(crate)` and narrower are not public).
fn public_items(code: &str) -> Vec<Item> {
    let mut items = Vec::new();
    let mut rest = code;
    while let Some(at) = rest.find("pub ") {
        let before = &rest[..at];
        let boundary = before
            .chars()
            .last()
            .is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '_'));
        let after = &rest[at + 4..];
        rest = after;
        if !boundary {
            continue;
        }
        let words: Vec<&str> = after
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .filter(|w| !w.is_empty())
            .take(3)
            .collect();
        let word = |i: usize| words.get(i).copied().unwrap_or("");
        let (kind, name) = if ["const", "async", "unsafe"].contains(&word(0)) && word(1) == "fn" {
            ("fn", word(2))
        } else if KEYWORDS.contains(&word(0)) {
            (word(0), word(1))
        } else {
            ("field", word(0))
        };
        // A function's signature runs to its body's `{` (a `;` may stand
        // inside an array type, `[u8; N]`); other items need none.
        let end = after.find('{').unwrap_or(after.len());
        items.push(Item {
            kind: kind.to_owned(),
            name: name.to_owned(),
            signature: after[..end]
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" "),
        });
    }
    items
}

/// The violations of rules 1 and 2 in `code`.
fn violations(code: &str) -> Vec<String> {
    let reviewed: BTreeSet<(&str, &str)> = REVIEWED.iter().copied().collect();
    let mut out = Vec::new();
    for item in public_items(code) {
        if !reviewed.contains(&(item.kind.as_str(), item.name.as_str())) {
            out.push(format!("unreviewed public {} {}", item.kind, item.name));
        }
        if item.kind == "fn" {
            let names_octets = item.signature.contains("u8");
            let returns_octets = item
                .signature
                .split("->")
                .nth(1)
                .is_some_and(|ret| ret.contains("u8"));
            if (names_octets && item.name != TAKES_THE_KEY) || returns_octets {
                out.push(format!(
                    "octets in pub fn {}: {}",
                    item.name, item.signature
                ));
            }
        }
    }
    out
}

fn crate_source() -> String {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut text = String::new();
    let mut entries: Vec<_> = std::fs::read_dir(&src)
        .expect("readable src/")
        .map(|e| e.expect("entry").path())
        .collect();
    entries.sort();
    for path in entries {
        assert!(
            path.extension().is_some_and(|e| e == "rs"),
            "only .rs files expected in src/: {}",
            path.display()
        );
        text.push_str(&code_of(
            &std::fs::read_to_string(&path).expect("readable source"),
        ));
    }
    text
}

/// Rules 1 and 2 on the crate, with the positive control that every
/// reviewed item is found (the surface is exactly the reviewed one).
#[test]
fn the_public_surface_is_exactly_the_reviewed_one() {
    let code = crate_source();
    assert_eq!(violations(&code), Vec::<String>::new());
    let found: BTreeSet<(String, String)> = public_items(&code)
        .into_iter()
        .map(|i| (i.kind, i.name))
        .collect();
    let expected: BTreeSet<(String, String)> = REVIEWED
        .iter()
        .map(|(k, n)| ((*k).to_owned(), (*n).to_owned()))
        .collect();
    assert_eq!(found, expected);
}

/// The scanner flags planted violations — a MAC over caller-chosen octets,
/// `tag` reshaped to take octets, a key accessor, a public key field, a
/// re-export — and not comments, `pub(crate)` items or test code.
#[test]
fn the_scanner_flags_planted_violations() {
    let planted = [
        "pub fn mac(key: &AttestationKey, data: &[u8]) -> Result<[u8; 32], AttestationError> {",
        "pub fn tag(key: &AttestationKey, message: &[u8]) -> Result<AttestedNameResolution, AttestationError> {",
        "pub fn as_bytes(&self) -> &[u8; ATTESTATION_KEY_LEN] {",
        "pub fn from_bytes(bytes: &[u8; ATTESTATION_KEY_LEN]) -> [u8; 32] {",
        "pub struct AttestationKey {\n    pub key: Zeroizing<[u8; ATTESTATION_KEY_LEN]>,\n}",
        "pub use self::hmac_sha256 as mac;",
        "pub const fn key_octets(&self) -> &[u8] {",
    ];
    for code in planted {
        assert!(!violations(code).is_empty(), "not flagged: {code}");
    }
    let clean = [
        "// pub fn mac(key: &AttestationKey, data: &[u8]) -> [u8; 32] {",
        "pub(crate) fn helper(data: &[u8]) {",
        "fn hmac_sha256(key: &AttestationKey, message: &[u8]) -> Result<[u8; 32], E> {",
        "pub fn tag(\n    key: &AttestationKey,\n    resolution: &NameResolution,\n) -> Result<AttestedNameResolution, AttestationError> {",
        "pub fn from_bytes(bytes: &[u8; ATTESTATION_KEY_LEN]) -> Result<AttestationKey, KeyRefused> {",
        "#[cfg(test)]\nmod tests {\n    pub fn mac(data: &[u8]) -> [u8; 32] {\n",
    ];
    for code in clean {
        assert_eq!(violations(&code_of(code)), Vec::<String>::new(), "{code}");
    }
}
