//! Guard of docs/52 R-a (decision A-103 on docs/questions/Q-486: "PEPs
//! will receive only a gate, and `snapshot()` will not be public"; class C6
//! through a new PEP — a raw object read and put on the wire without the
//! visibility gate).
//!
//! The mechanism is a type: a PEP is handed a `directory_pip::PepView`,
//! which has no way back to the `DirectoryView` or its snapshot, and
//! `DirectoryView::snapshot` is no longer public. What Rust cannot express —
//! that a public item is callable only from named crates — is pinned here,
//! over the workspace's non-test source (`crates/*/src`):
//!
//! 1. `DirectoryView::authority_snapshot` is called only by the authority's
//!    own reads that docs/questions/Q-486 puts outside the gate: crate
//!    directory-pip itself, crate directory-admin's `checks` module (the
//!    write invariants and internal checks — the raw view is a private
//!    field of `checks::Cx` there), and crate provision's `store` module
//!    (the ceremony verifying its own store).
//! 2. Crate ldap — a PEP and nothing else — names none of
//!    `DirectoryView`, `Snapshot`, `.snapshot(`, `authority_snapshot`,
//!    `get_object(` or `.view(` (taking a view from a context): it can reach
//!    the directory only through the `PepView` its inputs carry.
//! 3. (Task DN6; docs/54 §4.4) the zone image dird serves to dnsd is built
//!    only by directory-pip's zone projection — the authority's own read of
//!    its snapshot, listed here with that reason: no other code on the
//!    directory's side builds a `dns_zone::ZoneImage`.
//!
//! Test code is not scanned (directories named `tests`, files whose name
//! ends in `tests.rs`, and a file's `#[cfg(test)] mod … {` block to its
//! end). Positive controls: the scan finds the authority calls it allows
//! and the `PepView` crate ldap uses, so it cannot pass vacuously, and the
//! scanner flags each forbidden token in planted text but not in comments
//! or inside a longer identifier.
//!
//! Source: docs/52 §3.6 (C6), R-a; docs/questions/Q-486 (R-a, A-103);
//! docs/CLEAN-ROOM.md ("removing the capability from the component that should
//! not have it"). Test-only; modelled on crates/directory-admin
//! tests/single_write_path.rs.

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

/// The lines of `code` holding `token` as a whole token: no identifier
/// character just before it (when it starts with one) or just after it
/// (when it ends with one).
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

/// The tokens crate ldap must not name (module documentation, rule 2).
const LDAP_FORBIDDEN: [&str; 6] = [
    "DirectoryView",
    "Snapshot",
    ".snapshot(",
    "authority_snapshot",
    "get_object(",
    ".view(",
];

/// Every non-test source file of crate `name`, with its code.
fn crate_code(name: &str) -> Vec<(PathBuf, String)> {
    let mut files = Vec::new();
    sources(&crates_dir().join(name).join("src"), &mut files);
    files
        .into_iter()
        .map(|f| {
            let text = std::fs::read_to_string(&f).expect("UTF-8 source");
            (f, code_of(&text))
        })
        .collect()
}

/// The files allowed to call `authority_snapshot` (rule 1).
fn authority(rel: &Path) -> bool {
    rel.starts_with("directory-pip/src")
        || rel == Path::new("directory-admin/src/checks.rs")
        || rel == Path::new("provision/src/store.rs")
}

/// docs/52 R-a, rule 1: the raw snapshot is read only by the authority.
#[test]
fn only_the_authority_reads_the_raw_snapshot() {
    let crates = crates_dir();
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(&crates)
        .expect("readable crates/")
        .map(|e| e.expect("entry").path())
        .filter(|p| p.join("src").is_dir())
        .collect();
    dirs.sort();
    assert!(dirs.len() > 10, "{dirs:?}");
    let mut violations = Vec::new();
    let mut allowed = Vec::new();
    for dir in dirs {
        let mut files = Vec::new();
        sources(&dir.join("src"), &mut files);
        for file in files {
            let text = std::fs::read_to_string(&file).expect("UTF-8 source");
            let rel = file.strip_prefix(&crates).unwrap_or(&file).to_path_buf();
            for line in lines_with(&code_of(&text), ".authority_snapshot(") {
                let at = format!("{}:{line}", rel.display());
                if authority(&rel) {
                    allowed.push(at);
                } else {
                    violations.push(at);
                }
            }
        }
    }
    assert!(
        violations.is_empty(),
        "the raw snapshot read outside the authority's own reads \
         (docs/52 R-a; docs/questions/Q-486): {violations:#?}"
    );
    // Positive control: the admin plane's internal reads and provision's
    // check of its own store are seen.
    for file in ["directory-admin/src/checks.rs", "provision/src/store.rs"] {
        assert!(
            allowed.iter().any(|a| a.starts_with(file)),
            "{file} not seen: {allowed:#?}"
        );
    }
}

/// docs/52 R-a, rule 2: crate ldap reaches the directory only through the
/// `PepView` it is handed.
#[test]
fn the_ldap_pep_names_no_raw_directory_access() {
    let crates = crates_dir();
    let mut violations = Vec::new();
    let mut uses_pep_view = false;
    for (file, code) in crate_code("ldap") {
        let rel = file.strip_prefix(&crates).unwrap_or(&file).to_path_buf();
        for token in LDAP_FORBIDDEN {
            for line in lines_with(&code, token) {
                violations.push(format!("{}:{line}: {token}", rel.display()));
            }
        }
        uses_pep_view |= !lines_with(&code, "PepView").is_empty();
    }
    assert!(
        violations.is_empty(),
        "crate ldap names raw directory access (docs/52 R-a): {violations:#?}"
    );
    // Positive control: the scan read the engine's sources.
    assert!(uses_pep_view, "crate ldap's PepView not seen");
}

/// The crates on the directory's side of the DNS channel: the authority
/// (directory-pip), its write PEP (directory-admin) and dird
/// (directory-daemon) — every crate that holds a `DirectoryView`. dnsd's
/// side (dns-daemon, ipc-dns) rebuilds images from the channel's octets and
/// is not scanned here.
const DIRECTORY_SIDE: [&str; 3] = ["directory-pip", "directory-admin", "directory-daemon"];

/// docs/54 §4.4 (task DN6; the A-111 scan list, decision A-119): the zone
/// image dird serves is built by ONE function over the authority's
/// snapshot — directory-pip's zone projection — so the image carries only
/// what that function puts in it (host label, addresses, TTL; SOA / NS /
/// SRV synthesized) and no second projection over a raw read can put more
/// of an object on the wire (class C6). In the directory-side crates'
/// non-test source, `ZoneImage::new(` and `ZoneImageParts {` appear only
/// in `directory-pip/src/zone.rs`. Positive control: the projection's own
/// call is seen.
#[test]
fn the_zone_image_is_built_only_by_the_projection() {
    let crates = crates_dir();
    let mut violations = Vec::new();
    let mut seen = false;
    for name in DIRECTORY_SIDE {
        for (file, code) in crate_code(name) {
            let rel = file.strip_prefix(&crates).unwrap_or(&file).to_path_buf();
            for token in ["ZoneImage::new(", "ZoneImageParts {"] {
                for line in lines_with(&code, token) {
                    if rel == Path::new("directory-pip/src/zone.rs") {
                        seen = true;
                    } else {
                        violations.push(format!("{}:{line}: {token}", rel.display()));
                    }
                }
            }
        }
    }
    assert!(
        violations.is_empty(),
        "a zone image built outside the one projection (docs/54 §4.4): {violations:#?}"
    );
    assert!(seen, "the projection's ZoneImage::new not seen");
}

/// Positive control of the scanner: each forbidden token is seen in
/// planted text; a comment, a longer identifier (`PolicySnapshot`,
/// `my_get_object(`) and a field access (`.view.`) are not.
#[test]
fn the_scanner_sees_planted_raw_access() {
    let text = "\
let v: &DirectoryView<'_> = x;
let s: &Snapshot<'_> = v.snapshot();
let o = v.authority_snapshot().get_object(g);
let w = ctx.view(&store, &tiers);
let p: &PolicySnapshot = q;
let z = my_get_object(g);
let y = self.view.children(c);
// let o = v.snapshot().get_object(g);
";
    let code = code_of(text);
    let hits: Vec<(&str, Vec<usize>)> = LDAP_FORBIDDEN
        .iter()
        .map(|t| (*t, lines_with(&code, t)))
        .collect();
    assert_eq!(
        hits,
        vec![
            ("DirectoryView", vec![1]),
            ("Snapshot", vec![2]),
            (".snapshot(", vec![2]),
            ("authority_snapshot", vec![3]),
            ("get_object(", vec![3]),
            (".view(", vec![4]),
        ]
    );
    assert_eq!(lines_with(&code, ".authority_snapshot("), vec![3]);
}
