//! Guard of task R11c (docs/52 R11, class C13; docs/questions Q-532,
//! decision A-109): every privileged path operation that is not an open —
//! changing an entry's owner or mode, creating, renaming or removing an
//! entry, inspecting an entry by path before acting on it — goes through
//! this crate, which walks the path from `/` and acts relative to the walked
//! directory's descriptor. In this workspace's non-test source
//! (`crates/*/src`) the calls that do such a thing **by path** —
//! `chown(`, `lchown(`, `set_permissions(`, `create_dir(`,
//! `create_dir_all(`, `DirBuilder::new(`, `remove_file(`, `remove_dir(`,
//! `remove_dir_all(`, `rename(`, `hard_link(`, `symlink(`,
//! `symlink_metadata(`, the `*at` calls a caller could aim at a directory
//! of its own choosing (`mkdirat(`, `unlinkat(`, `renameat(`,
//! `renameat_with(`, `chmodat(`, `chownat(`, `linkat(`, `symlinkat(`) and
//! the socket bind by path (`UnixListener::bind(`) — appear only in
//! `crates/protected-file/src` and in the files listed in [`ALLOWED`], each
//! with its reason. A new one in daemon, tool or library source fails this
//! test; it must use `protected_file::prepare_socket_directory` (or
//! `prepare_daemon_directory`, task A16) or the
//! installer's operations (`entry_facts`, `create_new_directory`,
//! `create_new_file`, `create_new_read_write`, `rename_no_replace`,
//! `rename_replace`, `remove_empty_directory`, `remove_entry` (task A16),
//! `sync_directory`) instead.
//!
//! A call matches only as a whole name: the character before it is not part
//! of an identifier, so `fchown(` (on a descriptor) is not `chown(`, and
//! `unlinkat(` is not `linkat(`. Test code is skipped as in the open scan
//! (`tests/` directories, files named `tests.rs`, everything from a line
//! `#[cfg(test)]` on). Positive controls check that the scan finds this
//! crate's own `*at` calls and would see a planted call.
//!
//! Source: docs/52 §3.13, §7 (R11); docs/questions Q-532 items 1, 2, 5
//! (A-109), Q-550; docs/CLEAN-ROOM.md ("a single chokepoint through which the
//! action must pass"); tests/single_open_path.rs (the same guard for
//! opens, this project's own). Test-only.

use std::path::{Path, PathBuf};

/// The calls that create, change, remove or inspect an entry by its path.
const PATH_OPERATIONS: [&str; 22] = [
    "chown(",
    "lchown(",
    "set_permissions(",
    "create_dir(",
    "create_dir_all(",
    "DirBuilder::new(",
    "remove_file(",
    "remove_dir(",
    "remove_dir_all(",
    "rename(",
    "hard_link(",
    "symlink(",
    "symlink_metadata(",
    "mkdirat(",
    "unlinkat(",
    "renameat(",
    "renameat_with(",
    "chmodat(",
    "chownat(",
    "linkat(",
    "symlinkat(",
    "UnixListener::bind(",
];

/// The reason shared by the four socket-serving daemons' post-drop socket
/// code (docs/questions Q-550 item 2).
const SOCKET_AFTER_THE_DROP: &str = "after the privilege drop, as the daemon's own account: the \
     socket bound (UnixListener::bind — no descriptor-relative bind exists; nothing is removed \
     before it: the stale-socket removal is protected_file::prepare_socket_directory's alone, \
     task R15b / Q-631) and its mode set (set_permissions — chmodat cannot refuse a link on \
     Linux), the socket this run bound removed at stop or on a failed start (remove_file) — all \
     inside the socket directory protected_file::prepare_socket_directory walked and checked at \
     this start, so only root or the daemon's own account can change any component of the path \
     (Q-550 item 2)";

/// The source files outside this crate allowed a path operation, relative
/// to `crates/`, with the reason.
const ALLOWED: [(&str, &str); 5] = [
    ("keyd-daemon/src/daemon.rs", SOCKET_AFTER_THE_DROP),
    ("directory-daemon/src/daemon.rs", SOCKET_AFTER_THE_DROP),
    ("admin-daemon/src/daemon.rs", SOCKET_AFTER_THE_DROP),
    ("audit-daemon/src/listener.rs", SOCKET_AFTER_THE_DROP),
    (
        "test-scratch/src/lib.rs",
        "a dev-only helper (used only from [dev-dependencies], never linked \
         by a product): creates and removes the tests' scratch directories \
         (Q-480)",
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

/// Whether `call` occurs in `code` as a whole name (the character before
/// it, if any, is not part of an identifier).
fn contains_call(code: &str, call: &str) -> bool {
    code.match_indices(call).any(|(at, _)| {
        code[..at]
            .chars()
            .next_back()
            .is_none_or(|before| !(before.is_ascii_alphanumeric() || before == '_'))
    })
}

/// The path operations in `text` (outside line comments, before the first
/// `#[cfg(test)]` line): `(line, call)`.
fn path_operations(text: &str) -> Vec<(usize, &'static str)> {
    let mut found = Vec::new();
    for (n, line) in text.lines().enumerate() {
        if line.trim_start().starts_with("#[cfg(test)]") {
            break;
        }
        let code = line.split("//").next().unwrap_or("");
        for call in PATH_OPERATIONS {
            if contains_call(code, call) {
                found.push((n + 1, call));
            }
        }
    }
    found
}

/// Task R11c: no non-test source outside this crate and [`ALLOWED`] creates,
/// changes, removes or inspects an entry by its path.
#[test]
fn every_path_operation_goes_through_the_walk() {
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
            for (line, call) in path_operations(&text) {
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
        "an entry created, changed, removed or inspected by its path outside \
         crate protected-file (docs/52 R11, Q-550): {violations:#?}"
    );
    // Positive control: the walk's own descriptor-relative calls are found.
    for own in ["mkdirat(", "unlinkat(", "renameat_with(", "renameat("] {
        assert!(in_walk.contains(&own), "{own}: {in_walk:?}");
    }
    // Every allowance is still used.
    for (path, reason) in ALLOWED {
        assert!(
            allowed_seen.contains(&path),
            "{path} no longer operates on a path ({reason}): remove it from ALLOWED"
        );
    }
}

/// Positive control of the scanner: planted path operations are seen; a
/// descriptor operation with a longer name (`fchown(`, `unlinkat(` for
/// `linkat(`), an import, a commented call and one after `#[cfg(test)]` are
/// not.
#[test]
fn the_scanner_sees_a_planted_path_operation() {
    let text = "use std::os::unix::fs::DirBuilderExt;\n\
                std::os::unix::fs::chown(dir, Some(uid), Some(gid))?;\n\
                rustix::fs::fchown(&fd, None, None)?;\n\
                std::fs::set_permissions(dir, mode)?;\n\
                // std::fs::remove_file(path)\n\
                rustix::fs::unlinkat(CWD, path, AtFlags::empty())?;\n\
                std::fs::rename(a, b)?;\n\
                std::fs::DirBuilder::new().mode(0o750).create(dir)?;\n\
                #[cfg(test)]\nmod tests { fn t() { std::fs::remove_dir_all(d); } }\n";
    assert_eq!(
        path_operations(text),
        vec![
            (2, "chown("),
            (4, "set_permissions("),
            (6, "unlinkat("),
            (7, "rename("),
            (8, "DirBuilder::new("),
        ]
    );
}
