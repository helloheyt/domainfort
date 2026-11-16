//! Guard of docs/59 §5.3 and §6.1 (tasks PN4, PN4b; decisions A-173,
//! A-178; classes C31 and C49): in crate directory-pip, a name reaches an
//! object only through the one lookup path — the one probe of the
//! namespace's union index in `src/resolve.rs`.
//!
//! The mechanism is a single chokepoint: the KDC's client and service
//! lookups are thin wrappers of `canonical_principal`, the DNS record owner
//! asks `host_name_holder` (the holder of a `HostName` key — docs/questions/
//! Q-1036 item 6), both go through the private `probe`, and
//! `ResolvedPrincipal` can be built only there. What Rust cannot express —
//! that no other function of this crate probes a name index, derives a
//! purpose from a name or compares host names by a fold of its own — is
//! pinned here, over the crate's non-test source
//! (`crates/directory-pip/src`):
//!
//! 1. `lookup_unique(` is asked of a name only by `src/resolve.rs`, and
//!    only of `PRINCIPAL_NAME_KEY` — exactly one call, the one probe
//!    (Q-1026; task PN4b): no per-attribute name index (sAMAccountName,
//!    userPrincipalName, servicePrincipalName, dNSHostName) is asked
//!    anywhere, `src/host.rs` included. Everywhere else it is asked only of
//!    objectSid (a SID is not a name — docs/59 §5.3 item 2), plus
//!    `PepView`'s generic pass-through in `src/pep.rs` (the LDAP
//!    attribute-equality fast path — docs/59 §5.3 item 1, §6.4).
//! 2. The request's key (`key_of_request(`), the reserved-name predicate
//!    (`reserved_name_of(`), the purpose derivation from a name
//!    (`KeyPurpose::of_service_name(`), the namespace attribute
//!    (`PRINCIPAL_NAME_KEY`) and the probe itself (`probe(`) appear only in
//!    `src/resolve.rs`: the purpose and the reservation are judged on the
//!    resolved object's stored name there, never on a request's spelling
//!    elsewhere (Q-1009 item 3; class C49).
//! 3. The per-role search keys of R47-1 (`client_search_key`,
//!    `service_search_key`) exist nowhere (docs/59 §6.3 wave 2, item (c)).
//! 4. `src/host.rs` compares names only through the namespace's one fold
//!    (`principal_names::fold`): no `eq_ignore_ascii_case(`,
//!    `to_ascii_lowercase(` or `to_lowercase(` there (Q-1036 item 6; class
//!    C49 — the DNS owner rule and rule N6 cannot hold a second
//!    equivalence).
//!
//! Test code is not scanned (directories named `tests`, files whose name
//! ends in `tests.rs`, and a file's `#[cfg(test)] mod … {` block to its
//! end). Positive controls: the scan sees the one probe and its two callers,
//! the host-record lookup's one call into the path, the objectSid lookups,
//! the pass-through and both account-source wrappers, so it cannot pass
//! vacuously; and the scanner flags planted violations but not comments.
//!
//! Source: docs/59 §5.3, §6.1, §6.3, §10 (the PN4 row); docs/52 C31, C49;
//! docs/questions/Q-1009 items 1-3, Q-1026, Q-1036 item 6, Q-1042; AGENTS.md
//! §6.1 ("a single chokepoint through which the action must pass").
//! Test-only; modelled on tests/pep_receives_only_the_gate.rs and
//! crates/directory-admin tests/single_write_path.rs.

use std::path::{Path, PathBuf};

/// This crate's `src/` directory.
fn src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
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

/// Every occurrence of `token` in `code` as a whole token: `(line, the
/// text after it)`.
fn occurrences<'c>(code: &'c str, token: &str) -> Vec<(usize, &'c str)> {
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
        found.push((code[..start].matches('\n').count() + 1, &code[end..]));
    }
    found
}

/// The first argument of a call whose text starts right after its `(`.
fn first_argument(after: &str) -> &str {
    let end = after.find([',', ')']).unwrap_or(after.len());
    after[..end].trim()
}

/// How one `lookup_unique(` is allowed (rule 1), or `None`.
fn allowed_probe(file: &str, argument: &str) -> Option<&'static str> {
    if argument.contains("object_sid") {
        return Some("objectSid");
    }
    match (file, argument) {
        ("resolve.rs", "PRINCIPAL_NAME_KEY") => Some("the one probe"),
        ("pep.rs", "&self" | "attr") => Some("the LDAP pass-through"),
        _ => None,
    }
}

/// The tokens only `src/resolve.rs` may name (rule 2).
const RESOLVE_ONLY: [&str; 5] = [
    "key_of_request(",
    "reserved_name_of(",
    "KeyPurpose::of_service_name(",
    "PRINCIPAL_NAME_KEY",
    "probe(",
];

/// The tokens no file may name (rule 3).
const GONE: [&str; 2] = ["client_search_key", "service_search_key"];

/// The comparisons `src/host.rs` may not make (rule 4).
const HOST_NO_SECOND_FOLD: [&str; 3] = [
    "eq_ignore_ascii_case(",
    "to_ascii_lowercase(",
    "to_lowercase(",
];

/// Every non-test source file of this crate: `(file name, code)`.
fn crate_code() -> Vec<(String, String)> {
    let mut files = Vec::new();
    sources(&src_dir(), &mut files);
    assert!(files.len() > 10, "{files:?}");
    files
        .into_iter()
        .map(|f| {
            let text = std::fs::read_to_string(&f).expect("UTF-8 source");
            let name = f
                .strip_prefix(src_dir())
                .unwrap_or(&f)
                .display()
                .to_string();
            (name, code_of(&text))
        })
        .collect()
}

/// The violations of rules 1-4 in `files`, and the allowed probes seen.
fn scan(files: &[(String, String)]) -> (Vec<String>, Vec<String>) {
    let mut violations = Vec::new();
    let mut seen = Vec::new();
    for (file, code) in files {
        for (line, after) in occurrences(code, "lookup_unique(") {
            let argument = first_argument(after);
            match allowed_probe(file, argument) {
                Some(why) => seen.push(format!("{file}: {why}")),
                None => violations.push(format!("{file}:{line}: lookup_unique({argument}, …)")),
            }
        }
        for token in RESOLVE_ONLY {
            if file != "resolve.rs" {
                for (line, _) in occurrences(code, token) {
                    violations.push(format!("{file}:{line}: {token}"));
                }
            }
        }
        for token in GONE {
            for (line, _) in occurrences(code, token) {
                violations.push(format!("{file}:{line}: {token}"));
            }
        }
        if file == "host.rs" {
            for token in HOST_NO_SECOND_FOLD {
                for (line, _) in occurrences(code, token) {
                    violations.push(format!("{file}:{line}: {token}"));
                }
            }
        }
    }
    (violations, seen)
}

/// docs/59 §5.3, §6.1; docs/questions/Q-1026, Q-1036 item 6: rules 1-4
/// over this crate's source, with the positive controls of the module
/// documentation.
#[test]
fn a_name_reaches_an_object_only_through_the_one_lookup_path() {
    let files = crate_code();
    let (violations, seen) = scan(&files);
    assert!(
        violations.is_empty(),
        "a lookup by name outside the one path (docs/59 §5.3): {violations:#?}"
    );
    let count = |entry: &str| seen.iter().filter(|s| s.as_str() == entry).count();
    assert_eq!(count("resolve.rs: the one probe"), 1, "{seen:#?}");
    assert_eq!(count("pep.rs: the LDAP pass-through"), 2, "{seen:#?}");
    assert!(count("view.rs: objectSid") >= 2, "{seen:#?}");
    assert!(!seen.iter().any(|s| s.starts_with("host.rs")), "{seen:#?}");
    // The account source's two lookups are wrappers of the one path, the
    // DNS record owner asks it once, and the one path derives the request's
    // key (for a principal and for a host name) and the purpose, and probes
    // the union index from both entries.
    let code_of_file = |name: &str| {
        files
            .iter()
            .find(|(file, _)| file == name)
            .map(|(_, code)| code.as_str())
            .unwrap_or_else(|| panic!("{name} not scanned"))
    };
    assert_eq!(
        occurrences(code_of_file("view.rs"), "resolve_principal(").len(),
        2
    );
    assert_eq!(
        occurrences(code_of_file("host.rs"), "host_name_holder(").len(),
        1
    );
    for (token, expected) in [
        ("key_of_request(", 2),
        ("KeyPurpose::of_service_name(", 1),
        ("self.probe(", 2),
    ] {
        assert_eq!(
            occurrences(code_of_file("resolve.rs"), token).len(),
            expected,
            "{token}"
        );
    }
    // host.rs compares through the namespace fold.
    assert!(!occurrences(code_of_file("host.rs"), "fold(").is_empty());
}

/// Positive control of the scanner: planted violations are flagged — a
/// second probe of sAMAccountName, a probe of servicePrincipalName (both
/// now outside the one path wherever they stand), a purpose derived from a
/// request's name, the namespace attribute named, the probe called, a
/// resurrected search key, a second fold of host names — while comments,
/// the objectSid lookup and the allowed files are not.
#[test]
fn the_scanner_flags_planted_lookups_by_name() {
    let planted = "\
let g = self.snapshot.lookup_unique(ids.sam_account_name, key.as_bytes())?;
let s = snapshot
    .lookup_unique(self.ctx.ids.service_principal_name, spn.as_bytes())?;
let p = KeyPurpose::of_service_name(name);
let a = ad_schema::PRINCIPAL_NAME_KEY;
let k = client_search_key(name);
let o = self.snapshot.lookup_unique(ids.object_sid, &sid.encode())?;
let h = self.probe(&key)?;
let n = first.eq_ignore_ascii_case(label);
let u = self.snapshot.lookup_unique(PRINCIPAL_NAME_KEY, key.as_bytes())?;
// let x = self.snapshot.lookup_unique(ids.sam_account_name, b\"x\");
";
    let files = vec![("view.rs".to_owned(), code_of(planted))];
    let (violations, seen) = scan(&files);
    assert_eq!(
        violations,
        vec![
            "view.rs:1: lookup_unique(ids.sam_account_name, …)",
            "view.rs:3: lookup_unique(self.ctx.ids.service_principal_name, …)",
            "view.rs:10: lookup_unique(PRINCIPAL_NAME_KEY, …)",
            "view.rs:4: KeyPurpose::of_service_name(",
            "view.rs:5: PRINCIPAL_NAME_KEY",
            "view.rs:10: PRINCIPAL_NAME_KEY",
            "view.rs:8: probe(",
            "view.rs:6: client_search_key",
        ]
    );
    assert_eq!(seen, vec!["view.rs: objectSid"]);
    // In the one path only the union probe is allowed: a per-attribute
    // name index is not, and neither is the search key.
    let in_resolve = vec![("resolve.rs".to_owned(), code_of(planted))];
    let (violations, seen) = scan(&in_resolve);
    assert_eq!(
        violations,
        vec![
            "resolve.rs:1: lookup_unique(ids.sam_account_name, …)",
            "resolve.rs:3: lookup_unique(self.ctx.ids.service_principal_name, …)",
            "resolve.rs:6: client_search_key",
        ]
    );
    assert_eq!(
        seen,
        vec!["resolve.rs: objectSid", "resolve.rs: the one probe"]
    );
    // In host.rs a second fold is flagged too.
    let in_host = vec![("host.rs".to_owned(), code_of(planted))];
    let (violations, _) = scan(&in_host);
    assert!(violations.contains(&"host.rs:9: eq_ignore_ascii_case(".to_owned()));
    assert!(violations.contains(&"host.rs:1: lookup_unique(ids.sam_account_name, …)".to_owned()));
}
