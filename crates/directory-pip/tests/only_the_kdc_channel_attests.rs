//! Guard of task PN10b (decision A-187 on docs/questions/Q-1047; docs/59
//! §6.2, §6.4, §7.5; class "a component obtains a capability it does not
//! need"): dird's attested name resolutions reach only the KDC channel.
//!
//! The mechanism is types and module privacy: the subject checks read
//! `directory_pip::TicketSubjects` (no resolution in its record); a PEP's
//! `PepView` hands out that and no account source; crate ldap's inputs
//! carry no account source; crate directory-admin does not link crate kdc;
//! the signer is a private field of `DirectoryContext`, read only by a
//! private function of module `view`. What Rust cannot express — that a
//! module does not call a public trait impl of its own crate, that a crate
//! keeps not linking another, that a daemon builds one context with the
//! signer — is pinned here, over the workspace's non-test source:
//!
//! 1. In crate directory-pip, `src/subject.rs` names none of the KDC's
//!    account-source items or the attestation (`AccountSource`,
//!    `ClientAccount`, `ServiceAccount`, `NameResolution`,
//!    `AttestedNameResolution`, `name_resolution(`, `attested(`, `.attest(`,
//!    `signer`, `.client(`, `.service(`), and `src/pep.rs` names no
//!    `AccountSource`; the signer (`signer`, `.attest(`) is named only in
//!    `src/view.rs`, `src/resolve.rs` (the trait) and `src/lib.rs` (the
//!    export).
//! 2. Crates directory-admin and ldap name none of `AccountSource`,
//!    `ClientAccount`, `ServiceAccount`, `AttestedNameResolution` or
//!    `.accounts()`; crate directory-admin names no `kdc::` path, and its
//!    manifest declares no `kdc` dependency (the compile-time barrier).
//! 3. Crate directory-daemon installs a signer exactly once
//!    (`with_name_resolution_signer(`) and builds one exactly once
//!    (`ResolutionSigner::new(`), both inside `fn kdc_channel_context`,
//!    which is called exactly once.
//!
//! Test code is not scanned (directories named `tests`, files whose name
//! ends in `tests.rs`, and a file's `#[cfg(test)] mod … {` block to its
//! end); line comments are dropped. Positive controls: the scan sees the
//! signer in `src/view.rs`, the `TicketClient` lookup in `src/subject.rs`,
//! the subject lookup in both consumer crates and the one KDC-channel
//! constructor, so it cannot pass vacuously; and the scanner flags planted
//! violations but not comments or longer identifiers.
//!
//! Source: docs/questions/Q-1047 (A-187), Q-1046 item 5; docs/59 §6.2,
//! §6.4, §7.5; AGENTS.md §6.1 ("removing the capability from the component
//! that should not have it"). Test-only; modelled on
//! tests/pep_receives_only_the_gate.rs and tests/one_lookup_path.rs.

use std::path::{Path, PathBuf};

/// The workspace's `crates/` directory.
fn crates_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/ directory")
        .to_path_buf()
}

/// Every non-test `.rs` file below `dir`, recursively.
fn sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .expect("readable source directory")
        .map(|e| e.expect("directory entry").path())
        .collect();
    entries.sort();
    for path in entries {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if path.is_dir() {
            if name != "tests" {
                sources(&path, out);
            }
        } else if name.ends_with(".rs") && !name.ends_with("tests.rs") {
            out.push(path);
        }
    }
}

/// The non-test code of a file: line comments removed, and everything from
/// a `#[cfg(test)]` line followed by an inline `mod … {` to the end of the
/// file dropped.
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
            i += 1;
            continue;
        }
        out.push_str(line.split("//").next().unwrap_or(""));
        out.push('\n');
        i += 1;
    }
    out
}

/// `true` for a character of a Rust identifier.
fn ident(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// The lines (1-based) on which `token` occurs in `code` as a whole token.
fn lines_with(code: &str, token: &str) -> Vec<usize> {
    let starts_ident = token.chars().next().is_some_and(ident);
    let ends_ident = token.chars().next_back().is_some_and(ident);
    let mut found = Vec::new();
    let mut from = 0;
    while let Some(at) = code[from..].find(token) {
        let start = from + at;
        let end = start + token.len();
        from = end;
        if starts_ident && code[..start].chars().next_back().is_some_and(ident) {
            continue;
        }
        if ends_ident && code[end..].chars().next().is_some_and(ident) {
            continue;
        }
        found.push(code[..start].matches('\n').count() + 1);
    }
    found
}

/// Every non-test source file of crate `name`: `(file below src/, code)`.
fn crate_code(name: &str) -> Vec<(String, String)> {
    let src = crates_dir().join(name).join("src");
    let mut files = Vec::new();
    sources(&src, &mut files);
    assert!(!files.is_empty(), "{name}: no source files");
    files
        .into_iter()
        .map(|f| {
            let text = std::fs::read_to_string(&f).expect("UTF-8 source");
            let rel = f.strip_prefix(&src).unwrap_or(&f).display().to_string();
            (rel, code_of(&text))
        })
        .collect()
}

/// The code of `file` in `files`.
fn file<'f>(files: &'f [(String, String)], name: &str) -> &'f str {
    files
        .iter()
        .find(|(f, _)| f == name)
        .map(|(_, code)| code.as_str())
        .unwrap_or_else(|| panic!("{name} not scanned"))
}

/// The tokens `src/subject.rs` of crate directory-pip may not name (rule 1).
const SUBJECT_FORBIDDEN: [&str; 11] = [
    "AccountSource",
    "ClientAccount",
    "ServiceAccount",
    "NameResolution",
    "AttestedNameResolution",
    "name_resolution(",
    "attested(",
    ".attest(",
    "signer",
    ".client(",
    ".service(",
];

/// The signer tokens only `src/view.rs`, `src/resolve.rs` and `src/lib.rs`
/// of crate directory-pip may name (rule 1).
const SIGNER_TOKENS: [&str; 2] = ["signer", ".attest("];

/// The tokens crates directory-admin and ldap may not name (rule 2).
const CONSUMER_FORBIDDEN: [&str; 5] = [
    "AccountSource",
    "ClientAccount",
    "ServiceAccount",
    "AttestedNameResolution",
    ".accounts()",
];

/// The violations of rule 1 in crate directory-pip's `files`.
fn pip_violations(files: &[(String, String)]) -> Vec<String> {
    let mut violations = Vec::new();
    for (name, code) in files {
        if name == "subject.rs" {
            for token in SUBJECT_FORBIDDEN {
                for line in lines_with(code, token) {
                    violations.push(format!("{name}:{line}: {token}"));
                }
            }
        }
        if name == "pep.rs" {
            for line in lines_with(code, "AccountSource") {
                violations.push(format!("{name}:{line}: AccountSource"));
            }
        }
        if !matches!(
            name.as_str(),
            "view.rs" | "resolve.rs" | "lib.rs" | "subject.rs"
        ) {
            for token in SIGNER_TOKENS {
                for line in lines_with(code, token) {
                    violations.push(format!("{name}:{line}: {token}"));
                }
            }
        }
    }
    violations
}

/// The violations of rule 2 in a consumer crate's `files`; `no_kdc` also
/// forbids any `kdc::` path.
fn consumer_violations(krate: &str, files: &[(String, String)], no_kdc: bool) -> Vec<String> {
    let mut violations = Vec::new();
    for (name, code) in files {
        for token in CONSUMER_FORBIDDEN {
            for line in lines_with(code, token) {
                violations.push(format!("{krate}/{name}:{line}: {token}"));
            }
        }
        if no_kdc {
            for line in lines_with(code, "kdc::") {
                violations.push(format!("{krate}/{name}:{line}: kdc::"));
            }
        }
    }
    violations
}

/// `true` if the manifest text declares a dependency named `kdc` (a line
/// `kdc = …` or `kdc.workspace = …`, comments dropped).
fn declares_kdc(manifest: &str) -> bool {
    manifest.lines().any(|line| {
        let line = line.split('#').next().unwrap_or("").trim_start();
        line.strip_prefix("kdc")
            .is_some_and(|rest| rest.trim_start().starts_with('=') || rest.starts_with('.'))
    })
}

/// The text of the top-level `fn <name>(` in `code`: from its signature to
/// its closing brace at the start of a line, or to the next top-level
/// `fn ` if that comes first (a one-line function).
fn fn_body<'c>(code: &'c str, name: &str) -> &'c str {
    let signature = format!("fn {name}(");
    let start = code
        .find(&signature)
        .unwrap_or_else(|| panic!("{signature} not found"));
    let rest = &code[start + signature.len()..];
    let close = rest.find("\n}\n").unwrap_or(rest.len());
    let next = rest.find("\nfn ").unwrap_or(rest.len());
    &code[start..start + signature.len() + close.min(next)]
}

/// docs/questions/Q-1047; docs/59 §6.2: rule 1 over crate directory-pip,
/// with positive controls.
#[test]
fn the_subject_lookup_cannot_reach_the_signer() {
    let files = crate_code("directory-pip");
    let violations = pip_violations(&files);
    assert!(
        violations.is_empty(),
        "the attestation named outside its owners: {violations:#?}"
    );
    // Positive controls: the signer lives in view.rs; the subject lookup is
    // the one lookup path in the TicketClient context.
    assert!(!lines_with(file(&files, "view.rs"), "signer").is_empty());
    assert_eq!(lines_with(file(&files, "view.rs"), ".attest(").len(), 1);
    let subject = file(&files, "subject.rs");
    assert_eq!(lines_with(subject, "resolve_principal(").len(), 1);
    assert_eq!(lines_with(subject, "LookupCtx::TicketClient").len(), 1);
    assert!(!lines_with(file(&files, "pep.rs"), "TicketSubjects").is_empty());
}

/// docs/questions/Q-1047 items 1-2 (A-187): rule 2 over crates
/// directory-admin and ldap, with positive controls.
#[test]
fn the_subject_checks_name_no_account_source() {
    let admin = crate_code("directory-admin");
    let ldap = crate_code("ldap");
    let mut violations = consumer_violations("directory-admin", &admin, true);
    violations.extend(consumer_violations("ldap", &ldap, false));
    assert!(
        violations.is_empty(),
        "a subject check reaches the KDC's account source: {violations:#?}"
    );
    let manifest = std::fs::read_to_string(crates_dir().join("directory-admin/Cargo.toml"))
        .expect("directory-admin manifest");
    assert!(
        !declares_kdc(&manifest),
        "crate directory-admin links crate kdc again"
    );
    // Positive controls: both consumers read the ticket-subject lookup.
    let names = |files: &[(String, String)], token: &str| {
        files
            .iter()
            .map(|(_, code)| lines_with(code, token).len())
            .sum::<usize>()
    };
    assert!(names(&admin, "ticket_subject(") >= 2, "subject + guard");
    assert!(names(&admin, ".subjects()") >= 1);
    assert!(names(&ldap, "TicketSubjects") >= 2, "inputs + re-check");
    assert!(names(&ldap, "ticket_subject(") >= 1);
}

/// docs/questions/Q-1047 (only the KDC channel's context carries the
/// signer); docs/59 §7.4, §7.5: rule 3 over crate directory-daemon.
#[test]
fn dird_installs_the_signer_on_the_kdc_channel_only() {
    let files = crate_code("directory-daemon");
    let count = |token: &str| {
        files
            .iter()
            .flat_map(|(name, code)| lines_with(code, token).into_iter().map(move |_| name))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        count("with_name_resolution_signer("),
        vec!["daemon.rs"],
        "one signing context"
    );
    assert_eq!(
        count("ResolutionSigner::new("),
        vec!["daemon.rs"],
        "one signer"
    );
    let daemon = file(&files, "daemon.rs");
    let body = fn_body(daemon, "kdc_channel_context");
    assert_eq!(lines_with(body, "with_name_resolution_signer(").len(), 1);
    assert_eq!(lines_with(body, "ResolutionSigner::new(").len(), 1);
    // Its definition and one call.
    assert_eq!(lines_with(daemon, "kdc_channel_context(").len(), 2);
}

/// Positive control of the scanners: planted violations are flagged, while
/// comments and longer identifiers are not.
#[test]
fn the_scanners_flag_planted_violations() {
    let planted = "\
use kdc::AccountSource;
let r = self.attested(&resolved)?;
let a = self.ctx.signer.as_ref();
let c = view.client(realm, name);
let s = signer.attest(resolved);
let ok = NameResolutionSigner::attest;
// let x = view.client(realm, name); AccountSource
let p = pep.accounts();
";
    let in_subject = vec![("subject.rs".to_owned(), code_of(planted))];
    assert_eq!(
        pip_violations(&in_subject),
        vec![
            "subject.rs:1: AccountSource",
            "subject.rs:2: attested(",
            "subject.rs:5: .attest(",
            "subject.rs:3: signer",
            "subject.rs:5: signer",
            "subject.rs:4: .client(",
        ]
    );
    let elsewhere = vec![("zone.rs".to_owned(), code_of(planted))];
    assert_eq!(
        pip_violations(&elsewhere),
        vec![
            "zone.rs:3: signer",
            "zone.rs:5: signer",
            "zone.rs:5: .attest("
        ]
    );
    let consumer = vec![("checks.rs".to_owned(), code_of(planted))];
    assert_eq!(
        consumer_violations("directory-admin", &consumer, true),
        vec![
            "directory-admin/checks.rs:1: AccountSource",
            "directory-admin/checks.rs:8: .accounts()",
            "directory-admin/checks.rs:1: kdc::",
        ]
    );
    assert!(declares_kdc("kdc = { path = \"../kdc\" }\n"));
    assert!(declares_kdc("  kdc.workspace = true\n"));
    assert!(!declares_kdc(
        "# kdc = { path = \"../kdc\" }\nkdc-daemon = 1\n"
    ));
    let daemon = "fn a() {}\nfn kdc_channel_context(x) {\n  y.with_name_resolution_signer(s)\n}\nfn b() {}\n";
    assert_eq!(
        lines_with(
            fn_body(daemon, "kdc_channel_context"),
            "with_name_resolution_signer("
        )
        .len(),
        1
    );
    assert!(lines_with(fn_body(daemon, "a"), "with_name_resolution_signer(").is_empty());
}
