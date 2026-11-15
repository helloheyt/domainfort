//! Guard of docs/52 R2b (class: one fact derived in two places — a
//! divergence that fails open or closed by luck; AGENTS.md §6.1): the
//! purpose of a service object's key set is derived from the service's name
//! in exactly one place, `KeyPurpose::of_service_name` (crate keyd-types
//! `model.rs`), which `ServiceKeyHandle::of_service` — the only constructor
//! of that type — calls. Before R2b the admin plane's key operations named
//! `Service` by a literal for every service object while the KDC derived
//! `AdminService` for the admin service, so the admin service key could not
//! be rotated (docs/questions/Q-493 item 1).
//!
//! What this test pins, in the workspace's non-test source (`crates/*/src`):
//!
//! 1. Outside keyd's own crates and the channel codecs (listed in
//!    [`CUSTODY_AND_CODECS`], each with its reason), `KeyPurpose::Service`,
//!    `KeyPurpose::AdminService` and `KeyPurpose::ChangePasswordService`
//!    (docs/53 §5.2: `kadmin/changepw`, derived by the same one function —
//!    task K3) appear only where a purpose is
//!    **matched or compared** — a match arm's pattern (`… =>`, `… |`), a
//!    comparison (`==`, `!=`) — never where one is **chosen** (a handle's
//!    argument, a field value, an arm's result, …). A component that needs a
//!    service object's key set gets it from `ServiceKeyHandle::of_service`
//!    (or `KeyPurpose::of_service_name`), so it cannot contradict the name.
//! 2. `ADMIN_SERVICE_CLASS` — the name class the derivation keys on — is
//!    defined once (keyd-types `model.rs`); other crates re-export it.
//!
//! A lexical scan, not a type: it catches the shape of the regression (a
//! literal purpose for a service object), and a reviewer decides any new
//! hit. Test code is not scanned (directories named `tests`, files whose
//! name ends in `tests.rs`, and a file's `#[cfg(test)] mod … {` block to its
//! end). Positive controls: the scanner flags planted choices — among them
//! the exact line R2b removed — and does not flag matches, comparisons or
//! comments; and the workspace scan finds the matches it must see, so it
//! cannot pass vacuously.
//!
//! Source: docs/52 §3.2, §5 item 3, R2b; docs/questions/Q-491 item 1, Q-493
//! item 1; AGENTS.md §6.1 ("a single chokepoint", "a type that can only be
//! built after the check"). Test-only; modelled on crates/directory-admin
//! tests/single_write_path.rs.

use std::path::{Path, PathBuf};

/// The purpose literals this guard follows: every service object's purpose
/// `KeyPurpose::of_service_name` can derive — `Service`, `AdminService`
/// (R2) and `ChangePasswordService` (docs/53 §5.2, task K3; A-117).
const PURPOSES: [&str; 3] = [
    "KeyPurpose::Service",
    "KeyPurpose::AdminService",
    "KeyPurpose::ChangePasswordService",
];

/// Crates not scanned for rule 1, with the reason: keyd's custody crates
/// define the derivation and enforce the pairing of a purpose with its bound
/// name at key-set creation (keyd `template.rs` `check_new_binding`), keep
/// the per-purpose permissions (keyd-types `authz.rs`), the binding ⇒
/// purpose pairing of a service ticket (`service_ticket.rs`) and destroy a
/// deleted account's key sets by purpose (a tombstone has no name; a destroy
/// never names `AdminService`); the codecs decode a purpose code the sender
/// chose, and the receiver checks it (keyd at creation; the KDC at TGS step
/// 8 against `of_service_name`).
const CUSTODY_AND_CODECS: [&str; 8] = [
    "keyd-types",
    "keyd",
    "keyd-daemon",
    "ipc-keyd",
    "ipc-keyd-server",
    "ipc-directory",
    "ipc-dird-admin",
    "ipc-audit",
];

/// The workspace's `crates/` directory.
fn crates_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/ directory")
        .to_path_buf()
}

/// Every crate directory with a `src/`, sorted.
fn crate_dirs() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(crates_dir())
        .expect("readable crates/")
        .map(|e| e.expect("entry").path())
        .filter(|p| p.join("src").is_dir())
        .collect();
    dirs.sort();
    dirs
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
/// file dropped (a `#[cfg(test)] mod x;` declaration is only skipped).
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

/// Where a purpose literal stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Use {
    /// A pattern or a comparison: the purpose is matched, not chosen.
    Matched,
    /// Anything else: the purpose is chosen.
    Chosen,
}

/// Every purpose literal in `code`: `(line, literal, use)`.
fn uses(code: &str) -> Vec<(usize, &'static str, Use)> {
    let mut found = Vec::new();
    for literal in PURPOSES {
        let mut from = 0;
        while let Some(at) = code[from..].find(literal) {
            let start = from + at;
            let end = start + literal.len();
            from = end;
            // A whole path segment: not `KeyPurpose::ServiceX`.
            if code[end..].chars().next().is_some_and(ident) {
                continue;
            }
            // Part of a longer identifier (`MyKeyPurpose::…`): not ours.
            let previous = code[..start].chars().next_back();
            if previous.is_some_and(ident) {
                continue;
            }
            // Walk back over a path prefix (`keyd_types::`).
            let before_path = if previous == Some(':') {
                code[..start].trim_end_matches(|c: char| ident(c) || c == ':')
            } else {
                &code[..start]
            };
            let before = before_path.trim_end();
            let after = code[end..].trim_start();
            let matched = after.starts_with("=>")
                || after.starts_with('|')
                || after.starts_with("if ")
                || before.ends_with('|')
                || before.ends_with("==")
                || before.ends_with("!=");
            let line = code[..start].matches('\n').count() + 1;
            found.push((
                line,
                literal,
                if matched { Use::Matched } else { Use::Chosen },
            ));
        }
    }
    found.sort();
    found
}

/// docs/52 R2b, rule 1: outside keyd's crates and the codecs, no non-test
/// source chooses a service purpose by a literal.
#[test]
fn no_component_chooses_a_service_purpose_by_a_literal() {
    let crates = crates_dir();
    let dirs = crate_dirs();
    assert!(dirs.len() > 10, "{dirs:?}");
    let mut violations = Vec::new();
    let mut matched = Vec::new();
    for dir in dirs {
        let name = dir.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if CUSTODY_AND_CODECS.contains(&name) {
            continue;
        }
        let mut files = Vec::new();
        sources(&dir.join("src"), &mut files);
        for file in files {
            let text = std::fs::read_to_string(&file).expect("UTF-8 source");
            let rel = file.strip_prefix(&crates).unwrap_or(&file).to_path_buf();
            for (line, literal, used) in uses(&code_of(&text)) {
                let at = format!("{}:{line}: {literal}", rel.display());
                match used {
                    Use::Chosen => violations.push(at),
                    Use::Matched => matched.push(at),
                }
            }
        }
    }
    assert!(
        violations.is_empty(),
        "a service object's key-set purpose chosen by a literal instead of \
         `ServiceKeyHandle::of_service` / `KeyPurpose::of_service_name` \
         (docs/52 R2b): {violations:#?}"
    );
    // Positive control: the scan sees the matches it must see — each of the
    // three service purposes is matched (not chosen) somewhere in the scanned
    // sources. The control is not pinned to one file: the admin plane's
    // key-operation digest codes that it used to name
    // (directory-admin/src/key_requests.rs) were folded into the one
    // operation digest by A-159 (Q-935), and admind's request classification
    // now holds the three matches.
    for literal in PURPOSES {
        assert!(
            matched.iter().any(|m| m.ends_with(literal)),
            "{literal} not seen as a match anywhere: {matched:#?}"
        );
    }
}

/// docs/52 R2b, rule 2: the admin service's name class is one constant.
#[test]
fn the_admin_service_class_is_defined_once() {
    let crates = crates_dir();
    let mut definitions = Vec::new();
    for dir in crate_dirs() {
        let mut files = Vec::new();
        sources(&dir.join("src"), &mut files);
        for file in files {
            let text = std::fs::read_to_string(&file).expect("UTF-8 source");
            if code_of(&text).contains("const ADMIN_SERVICE_CLASS") {
                definitions.push(
                    file.strip_prefix(&crates)
                        .unwrap_or(&file)
                        .display()
                        .to_string(),
                );
            }
        }
    }
    assert_eq!(definitions, vec!["keyd-types/src/model.rs".to_owned()]);
}

/// Positive control of the scanner: planted choices are flagged — among
/// them the line R2b removed from directory-admin (`} => KeyPurpose::Service,`)
/// and the provisioning manifest's former argument form — while matches,
/// comparisons, a longer identifier and comments are not.
#[test]
fn the_scanner_tells_a_choice_from_a_match() {
    let text = "\
let a = KeyHandle::new(p, KeyPurpose::Service);
            } => KeyPurpose::Service,
    purpose: KeyPurpose::AdminService,
    Self::object(&doc, keys::LDAP, &mut seen, KeyPurpose::Service, b)?;
    KeyPurpose::Service => 2,
    keyd_types::KeyPurpose::Krbtgt | keyd_types::KeyPurpose::AdminService => Err(e),
    .is_some_and(|key| key.handle.purpose == KeyPurpose::Service),
    if p != KeyPurpose::AdminService { x }
// KeyHandle::new(p, KeyPurpose::Service)
let b = KeyPurpose::ServiceLike;
let d = KeyHandle::new(p, KeyPurpose::ChangePasswordService);
    KeyPurpose::ChangePasswordService => 4,
#[cfg(test)]
mod tests {
    let c = KeyHandle::new(p, KeyPurpose::AdminService);
}
";
    let code = code_of(text);
    assert_eq!(
        uses(&code),
        vec![
            (1, "KeyPurpose::Service", Use::Chosen),
            (2, "KeyPurpose::Service", Use::Chosen),
            (3, "KeyPurpose::AdminService", Use::Chosen),
            (4, "KeyPurpose::Service", Use::Chosen),
            (5, "KeyPurpose::Service", Use::Matched),
            (6, "KeyPurpose::AdminService", Use::Matched),
            (7, "KeyPurpose::Service", Use::Matched),
            (8, "KeyPurpose::AdminService", Use::Matched),
            (11, "KeyPurpose::ChangePasswordService", Use::Chosen),
            (12, "KeyPurpose::ChangePasswordService", Use::Matched),
        ]
    );
}
