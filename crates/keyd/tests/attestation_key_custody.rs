//! Guard of the attestation key's custody in keyd (task PN8; docs/59 §7.4;
//! decision A-173 — docs/questions/Q-1011 item 2: "never exported"; A-145
//! RC-6, class C42: no general MAC oracle over a long-term key).
//!
//! keyd links crate name-attestation, which holds both the verifier
//! (`verify`) and dird's signer (`tag`). keyd must only verify: if it tagged
//! a caller's resolution, or handed out the key (even by reference, to a
//! caller who then tags), any component reaching keyd could have false name
//! resolutions believed — exactly the oracle Q-1011 item 2 refused. The
//! types already make the key's octets unreachable (`AttestationKey` has no
//! accessor, `Debug` or `Clone`); this lexical scan pins the rest, in the
//! non-test source of crates/keyd/src:
//!
//! 1. every naming of the crate `name_attestation` is a path to one of
//!    [`ALLOWED_ITEMS`] — never `tag`, a glob, a group or an alias;
//! 2. keyd never makes an attestation key (`AttestationKey::from_bytes`):
//!    the only key it holds came through `install_attestation_key`;
//! 3. `name_attestation::verify(` appears only in [`VERIFIER_FILE`], with
//!    the installed key;
//! 4. no line returns an `AttestationKey` (`->` … `AttestationKey`, by
//!    value or by reference).
//!
//! A lexical scan, not a type: a reviewer decides any new hit. Test code is
//! not scanned (a file's `#[cfg(test)] mod … {` block to its end) and
//! comments are dropped. Positive controls: the scanner flags planted
//! violations, and the workspace scan sees the real uses (so it cannot pass
//! vacuously).
//!
//! Source: docs/59 §7.4; docs/questions/Q-1011 item 2 (A-173); A-145 RC-6
//! (C42); D28 / D29; AGENTS.md §6.1. The scanner pattern follows this
//! project's own guards (crates/keyd-types tests/
//! one_service_purpose_derivation.rs). Test-only.

use std::path::{Path, PathBuf};

/// The crate's name in Rust paths.
const CRATE: &str = "name_attestation";

/// The items of name-attestation keyd's product source may name.
const ALLOWED_ITEMS: [&str; 4] = [
    "verify(",
    "AttestationKey",
    "ATTESTATION_KEY_LEN",
    "AuthenticatedNameResolution",
];

/// The one file that verifies.
const VERIFIER_FILE: &str = "name_resolution.rs";

fn src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .expect("src directory")
        .map(|e| e.expect("entry").path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n != "tests") {
                rust_files(&path, out);
            }
        } else if path.extension().is_some_and(|e| e == "rs")
            && !path
                .file_name()
                .is_some_and(|n| n.to_string_lossy().ends_with("tests.rs"))
        {
            out.push(path);
        }
    }
}

/// The product lines of `text`: up to the first `#[cfg(test)]` that opens a
/// module, with `//` comments removed.
fn product_lines(text: &str) -> Vec<String> {
    let lines: Vec<&str> = text.lines().collect();
    let mut out = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let opens_test_module = line.trim() == "#[cfg(test)]"
            && lines
                .get(i + 1)
                .is_some_and(|next| next.trim_start().starts_with("mod "));
        if opens_test_module {
            break;
        }
        let code = line.split("//").next().unwrap_or("");
        out.push(code.to_owned());
    }
    out
}

/// The violations of rules 1, 2 and 4 on one product line.
fn line_violations(code: &str) -> Vec<&'static str> {
    let mut found = Vec::new();
    let mut rest = code;
    while let Some(at) = rest.find(CRATE) {
        let before_ok = rest[..at]
            .chars()
            .last()
            .is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '_'));
        let after = &rest[at + CRATE.len()..];
        if before_ok {
            let item = after.strip_prefix("::");
            let allowed = item.is_some_and(|item| {
                ALLOWED_ITEMS.iter().any(|allowed| {
                    item.strip_prefix(allowed).is_some_and(|tail| {
                        // A call ends at its "("; a type or constant must
                        // end there (no longer identifier, no alias).
                        allowed.ends_with('(')
                            || (!tail.trim_start().starts_with("as ")
                                && !tail
                                    .starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_'))
                    })
                })
            });
            if !allowed {
                found.push("rule 1: names name_attestation other than by an allowed item");
            }
        }
        rest = after;
    }
    if code.contains("AttestationKey::from_bytes") {
        found.push("rule 2: makes an attestation key");
    }
    if code
        .split_once("->")
        .is_some_and(|(_, ret)| ret.contains("AttestationKey"))
    {
        found.push("rule 4: returns an attestation key");
    }
    found
}

/// Every violation in keyd's product source, and the files that call
/// `name_attestation::verify(`.
fn scan() -> (Vec<String>, Vec<String>, usize) {
    let mut files = Vec::new();
    rust_files(&src_dir(), &mut files);
    let mut violations = Vec::new();
    let mut verifiers = Vec::new();
    let mut key_mentions = 0;
    for path in files {
        let text = std::fs::read_to_string(&path).expect("source file");
        let name = path
            .file_name()
            .expect("file name")
            .to_string_lossy()
            .into_owned();
        for (n, code) in product_lines(&text).iter().enumerate() {
            for rule in line_violations(code) {
                violations.push(format!("{name}:{}: {rule}: {}", n + 1, code.trim()));
            }
            if code.contains("name_attestation::verify(") {
                verifiers.push(name.clone());
            }
            if code.contains("AttestationKey") {
                key_mentions += 1;
            }
        }
    }
    (violations, verifiers, key_mentions)
}

/// Rules 1–4 over keyd's product source; positive control: the scan sees
/// the verifier and the key's slot.
#[test]
fn keyd_only_verifies_and_never_hands_out_the_attestation_key() {
    let (violations, verifiers, key_mentions) = scan();
    assert!(violations.is_empty(), "{violations:#?}");
    assert!(!verifiers.is_empty(), "the scan did not see the verifier");
    assert!(
        verifiers.iter().all(|file| file == VERIFIER_FILE),
        "rule 3: name_attestation::verify outside {VERIFIER_FILE}: {verifiers:?}"
    );
    assert!(key_mentions >= 3, "the scan did not see the key's slot");
}

/// Positive controls: planted violations are flagged; allowed namings,
/// comments and test modules are not.
#[test]
fn the_scanner_flags_planted_violations() {
    for planted in [
        "let attested = name_attestation::tag(&self.key, &resolution)?;",
        "use name_attestation::{tag, verify};",
        "use name_attestation::*;",
        "use name_attestation as na;",
        "use name_attestation::AttestationKey as Key;",
        "use name_attestation::tagger;",
        "let k = AttestationKey::from_bytes(&bytes)?;",
        "pub fn attestation_key(&self) -> Option<&AttestationKey> {",
        "fn take(&mut self) -> AttestationKey {",
    ] {
        assert!(
            !line_violations(planted).is_empty(),
            "not flagged: {planted}"
        );
    }
    for allowed in [
        "use name_attestation::AttestationKey;",
        "pub use name_attestation::ATTESTATION_KEY_LEN;",
        "use name_attestation::AuthenticatedNameResolution;",
        "let a = name_attestation::verify(key, attested)",
        "pub(crate) attestation_key: Option<AttestationKey>,",
        "key: AttestationKey,",
        "fn f(my_name_attestation_x: u8) -> u8 {",
    ] {
        assert!(line_violations(allowed).is_empty(), "flagged: {allowed}");
    }
    let text = "use name_attestation::AttestationKey; // not name_attestation::tag\n\
                fn a() {}\n\
                #[cfg(test)]\n\
                mod tests {\n\
                    use name_attestation::tag;\n\
                }\n";
    let lines = product_lines(text);
    assert_eq!(lines.len(), 2);
    assert!(lines.iter().all(|l| line_violations(l).is_empty()));
}
