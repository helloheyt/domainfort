//! Guard of docs/52 R11 (class C13, decisions A-102, A-104): every open of
//! a file by path in this workspace's non-test source (`crates/*/src`) goes
//! through this crate's walk. The calls that reach a file by a plain path —
//! `File::open(`, `File::create(`, `OpenOptions`, `fs::read(`,
//! `fs::read_to_string(`, `fs::write(`, `read_dir(`, `openat(`, redb's
//! `Database::create(` / `Database::open(` and dirstore's path-taking
//! `Store::open(` — appear only in `crates/protected-file/src` (the walk
//! itself) and in the files listed in [`ALLOWED`], each with its reason
//! (docs/questions/Q-530, Q-532). A new raw open in daemon, tool or library
//! source fails this test; it must use `protected_file::open`,
//! `open_append`, `open_read_write`, `create_new_append` or
//! `for_each_entry_beside` instead.
//!
//! Test code may still open files directly (fixtures): files under a
//! `tests/` directory, files named `tests.rs`, and everything from a line
//! `#[cfg(test)]` to the end of a file (this workspace keeps its unit-test
//! module last) are not scanned. Positive controls check that the scan
//! finds this crate's own opens, so it cannot pass vacuously, and that it
//! would see a planted call.
//!
//! Source: docs/52 §3.13, §7 (R11); docs/questions/Q-468 option 3, Q-481,
//! Q-530; docs/CLEAN-ROOM.md ("a single chokepoint through which the action
//! must pass"); crates/directory-admin/tests/single_write_path.rs (the same
//! guard for R13, this project's own). Test-only.

use std::path::{Path, PathBuf};

/// The calls that reach a file by its path.
const RAW_OPENS: [&str; 12] = [
    "File::open(",
    "File::create(",
    "OpenOptions",
    "fs::read(",
    "fs::read_to_string(",
    "fs::write(",
    "read_dir(",
    "openat(",
    "Database::create(",
    "Database::open(",
    "Builder::new().create(",
    "Store::open(",
];

/// The source files outside this crate allowed to reach a file by path,
/// relative to `crates/`, with the reason (docs/questions/Q-532; task R11c
/// removed provision's installer from this list — it goes through this
/// crate's walk now, Q-550 item 3).
const ALLOWED: [(&str, &str); 3] = [
    (
        "dirstore/src/store.rs",
        "Store::open(path): the library's path form, for tests only — it \
         opens the file and builds the store through Store::open_file, the \
         one construction path (Q-531 item 7); dird and provision use \
         Store::open_file on a descriptor this crate checked (Q-550)",
    ),
    (
        "keyd/src/entropy.rs",
        "/dev/urandom, a device, not a protected file (Q-481 item d)",
    ),
    (
        "directory-admin/src/random.rs",
        "/dev/urandom, a device, not a protected file (Q-481 item d)",
    ),
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

/// The raw opens in `text` (outside line comments, before the first
/// `#[cfg(test)]` line): `(line, call)`.
fn raw_opens(text: &str) -> Vec<(usize, &'static str)> {
    let mut found = Vec::new();
    for (n, line) in text.lines().enumerate() {
        if line.trim_start().starts_with("#[cfg(test)]") {
            break;
        }
        let code = line.split("//").next().unwrap_or("");
        for call in RAW_OPENS {
            if code.contains(call) {
                found.push((n + 1, call));
            }
        }
    }
    found
}

/// docs/52 R11: no non-test source outside this crate and [`ALLOWED`]
/// reaches a file by its path.
#[test]
fn every_open_by_path_goes_through_the_walk() {
    let crates = crates_dir();
    let mut crate_dirs: Vec<PathBuf> = std::fs::read_dir(&crates)
        .expect("readable crates/")
        .map(|e| e.expect("entry").path())
        .filter(|p| p.join("src").is_dir())
        .collect();
    crate_dirs.sort();
    assert!(crate_dirs.len() > 10, "{crate_dirs:?}");
    let mut violations = Vec::new();
    let mut in_walk = Vec::new();
    let mut allowed_seen = Vec::new();
    for dir in crate_dirs {
        let mut files = Vec::new();
        sources(&dir.join("src"), &mut files);
        for file in files {
            let text = std::fs::read_to_string(&file).expect("UTF-8 source");
            let rel = file.strip_prefix(&crates).unwrap_or(&file).to_path_buf();
            for (line, call) in raw_opens(&text) {
                if rel.starts_with("protected-file/src") {
                    in_walk.push(call);
                } else if let Some((path, _)) = ALLOWED.iter().find(|(p, _)| rel == Path::new(p)) {
                    allowed_seen.push(*path);
                } else {
                    violations.push(format!("{}:{line}: {call}", rel.display()));
                }
            }
        }
    }
    assert!(
        violations.is_empty(),
        "a file reached by its path outside crate protected-file \
         (docs/52 R11, Q-530): {violations:#?}"
    );
    // Positive control: the walk's own opens are found.
    assert!(in_walk.contains(&"openat("), "{in_walk:?}");
    // Every allowance is still used (a stale one would hide nothing, but
    // the list must stay the true list of exceptions).
    for (path, reason) in ALLOWED {
        assert!(
            allowed_seen.contains(&path),
            "{path} no longer opens by path ({reason}): remove it from ALLOWED"
        );
    }
}

/// Positive control of the scanner: planted calls are seen, a commented
/// one and one after `#[cfg(test)]` are not.
#[test]
fn the_scanner_sees_a_planted_open() {
    let text = "let x = 1;\n    let f = std::fs::File::open(path)?;\n\
                // std::fs::read(path)\n    let db = Database::create(p)?;\n\
                #[cfg(test)]\nmod tests { fn t() { std::fs::read_dir(d); } }\n";
    assert_eq!(
        raw_opens(text),
        vec![(2, "File::open("), (4, "Database::create(")]
    );
}
