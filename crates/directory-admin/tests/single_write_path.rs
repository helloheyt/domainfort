//! Guard of docs/52 R13 (class C14, decision A-102): every directory write
//! goes through the one write-invariant checker. In this workspace's
//! non-test source (`crates/*/src`), dirstore's mutating calls —
//! `create_object`, `modify_object`, `delete_object`, `create_counter`,
//! `take_counter_value`, `purge_tombstones` — appear only in
//! directory-admin's `src/invariants/` (the checker and its provisioning
//! session) and in dirstore itself (where they are defined). A new write
//! path that calls dirstore directly fails this test; it must go through
//! `CheckedWrite` / `Provisioning` instead.
//!
//! Test code may still write beneath the checker (fixtures, forced states):
//! files under a `tests/` directory and files named `tests.rs` are not
//! scanned. A positive control checks that the scan finds the checker's own
//! calls, so it cannot pass vacuously, and that it would see a planted
//! call.
//!
//! Source: docs/52 §3.14, §7 (R13); docs/CLEAN-ROOM.md ("a single chokepoint
//! through which the action must pass"); crate::invariants (directory-admin
//! `src/invariants/mod.rs`). Test-only.

use std::path::{Path, PathBuf};

/// The dirstore methods that change the store.
const MUTATORS: [&str; 6] = [
    "create_object",
    "modify_object",
    "delete_object",
    "create_counter",
    "take_counter_value",
    "purge_tombstones",
];

/// The workspace's `crates/` directory.
fn crates_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/ directory")
        .to_path_buf()
}

/// Every `.rs` file below `dir`, recursively (directories named `tests`
/// and files named `tests.rs` are test code and skipped).
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
        } else if name.ends_with(".rs") && name != "tests.rs" {
            out.push(path);
        }
    }
}

/// The mutator calls in `text` (outside line comments): `(line, method)`
/// for each `.method(` or `::method(`.
fn calls(text: &str) -> Vec<(usize, &'static str)> {
    let mut found = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let code = line.split("//").next().unwrap_or("");
        for method in MUTATORS {
            for prefix in [".", "::"] {
                if code.contains(&format!("{prefix}{method}(")) {
                    found.push((n + 1, method));
                }
            }
        }
    }
    found
}

/// The files allowed to call the mutators: the checker and dirstore.
fn allowed(path: &Path, crates: &Path) -> bool {
    let rel = path.strip_prefix(crates).unwrap_or(path);
    rel.starts_with("dirstore/src") || rel.starts_with("directory-admin/src/invariants")
}

/// docs/52 R13: no non-test source outside the checker calls dirstore's
/// mutating API.
#[test]
fn only_the_write_invariants_call_dirstores_mutating_api() {
    let crates = crates_dir();
    let mut crate_dirs: Vec<PathBuf> = std::fs::read_dir(&crates)
        .expect("readable crates/")
        .map(|e| e.expect("entry").path())
        .filter(|p| p.join("src").is_dir())
        .collect();
    crate_dirs.sort();
    assert!(crate_dirs.len() > 10, "{crate_dirs:?}");
    let mut violations = Vec::new();
    let mut in_checker = Vec::new();
    for dir in crate_dirs {
        let mut files = Vec::new();
        sources(&dir.join("src"), &mut files);
        for file in files {
            let text = std::fs::read_to_string(&file).expect("UTF-8 source");
            for (line, method) in calls(&text) {
                let rel = file.strip_prefix(&crates).unwrap_or(&file).to_path_buf();
                if allowed(&file, &crates) {
                    in_checker.push(method);
                } else {
                    violations.push(format!("{}:{line}: {method}", rel.display()));
                }
            }
        }
    }
    assert!(
        violations.is_empty(),
        "dirstore written outside crate directory-admin's invariants module \
         (docs/52 R13): {violations:#?}"
    );
    // Positive control: the checker's own calls are found (every mutator
    // but purge, which no path calls yet).
    for method in &MUTATORS[..5] {
        assert!(in_checker.contains(method), "{method} not found");
    }
}

/// Positive control of the scanner: a planted call is seen in both call
/// forms, a commented one is not.
#[test]
fn the_scanner_sees_a_planted_call() {
    let text = "let x = 1;\n    txn.create_object(new, &o)?;\n// txn.modify_object(a)\n\
                WriteTxn::delete_object(&mut txn, g, &o)\n";
    assert_eq!(
        calls(text),
        vec![(2, "create_object"), (4, "delete_object")]
    );
}
