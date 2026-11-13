//! Truncation and mutation sweep: no input derived from a valid file makes
//! any parser panic, every cut line is refused, every error names only a key
//! of the daemon's own table, and every accepted keyd / auditd map still holds
//! its invariants.
//!
//! The inputs are the `common` samples, cut at every octet, with every octet
//! replaced by each of a fixed set of octets, with every octet deleted, and
//! with every line deleted, doubled or moved, or borrowed from another
//! daemon's file. (Arbitrary inputs are the fuzz target's job — docs/50 §9,
//! `config_file`.)
//!
//! Spec: AGENTS.md §6 (strict, bounded parsers; no panic on input); docs/50
//! R50-3, R50-15, §7.1, §9.

mod common;

use common::{parse_all, Daemon, ALL};
use config::{AuditdSettings, Error, KeydSettings};

/// Octets substituted at every position: structure (LF, space, `#`, `=`,
/// `,`, `:`, `/`, `.`), digits and letters, a `$`, and octets the format
/// refuses (NUL, TAB, CR, DEL, high octets).
const SUBSTITUTES: &[u8] = &[
    0x00, b'\t', b'\n', b'\r', b' ', b'#', b'=', b',', b':', b'/', b'.', b'0', b'1', b'9', b'a',
    b'Z', b'$', b's', b'-', 0x7F, 0x80, 0xFF,
];

/// Checks one parse result of `daemon`: an error's key, if any, comes from
/// the daemon's own table (so it is never input text).
fn check_result(daemon: Daemon, result: &Result<(), Error>) {
    if let Err(err) = result {
        if let Some(key) = err.key() {
            assert!(
                daemon.keys().contains(&key),
                "{daemon:?}: foreign key {key}"
            );
        }
        if let Some(line) = err.line() {
            assert!(line >= 1, "line numbers are 1-based");
        }
    }
}

/// Parses `input` as `daemon` and, for keyd and auditd, checks the map
/// invariants of any accepted file (R50-3: uid 0 never mapped; one entry per
/// uid).
fn check(daemon: Daemon, input: &[u8]) {
    check_result(daemon, &daemon.parse(input));
    match daemon {
        Daemon::Keyd => {
            if let Ok(settings) = KeydSettings::parse(input) {
                let map = settings.uid_roles();
                assert!(!map.is_empty());
                assert_eq!(map.role_of(0), None);
                let uids: Vec<u32> = map.iter().map(|(uid, _)| uid).collect();
                for (i, uid) in uids.iter().enumerate() {
                    assert_ne!(*uid, 0);
                    assert!(!uids.get(..i).unwrap_or_default().contains(uid));
                    assert_ne!(*uid, settings.run_as().uid());
                }
            }
        }
        Daemon::Auditd => {
            if let Ok(settings) = AuditdSettings::parse(input) {
                let map = settings.uid_sources();
                assert!(!map.is_empty());
                assert_eq!(map.source_of(0), None);
                assert!(map.iter().all(|(uid, _)| uid != settings.run_as().uid()));
            }
        }
        _ => {}
    }
}

/// Every prefix of every sample: no parser panics, and a prefix that cuts a
/// line (does not end with LF) is refused by all six.
/// Spec: docs/50 §7.1 (fail closed); Q-230 item 2 (final LF).
#[test]
fn truncation_sweep() {
    for &(daemon, full, minimal) in ALL {
        for sample in [full, minimal] {
            let bytes = sample.as_bytes();
            for end in 0..bytes.len() {
                let prefix = bytes.get(..end).unwrap_or_default();
                let results = parse_all(prefix);
                for (&(each, ..), result) in ALL.iter().zip(&results) {
                    check_result(each, result);
                }
                if prefix.last().is_some_and(|&b| b != b'\n') {
                    assert!(
                        results.iter().all(Result::is_err),
                        "{daemon:?}: a cut line at {end} was accepted"
                    );
                }
            }
        }
    }
}

/// Every octet of every full sample replaced by each substitute, and every
/// octet deleted: no panic; errors are well-formed; accepted maps hold their
/// invariants. Spec: AGENTS.md §6; docs/50 R50-3, R50-15.
#[test]
fn octet_mutation_sweep() {
    for &(daemon, full, _) in ALL {
        let bytes = full.as_bytes();
        for index in 0..bytes.len() {
            for &octet in SUBSTITUTES {
                let mut mutated = bytes.to_vec();
                if let Some(slot) = mutated.get_mut(index) {
                    *slot = octet;
                }
                check(daemon, &mutated);
            }
            let mut deleted = bytes.to_vec();
            deleted.remove(index);
            check(daemon, &deleted);
        }
    }
}

/// Every line deleted, doubled, or moved to the end; and every line of every
/// other daemon's file appended. A doubled `key = value` line is always a
/// duplicate key. Spec: docs/50 R50-15, §7.1.
#[test]
fn line_mutation_sweep() {
    for &(daemon, full, _) in ALL {
        let lines: Vec<&str> = full.lines().collect();
        let join = |chosen: &[&str]| {
            let mut text = String::new();
            for line in chosen {
                text.push_str(line);
                text.push('\n');
            }
            text
        };
        for index in 0..lines.len() {
            let mut deleted = lines.clone();
            let line = deleted.remove(index);
            check(daemon, join(&deleted).as_bytes());

            let mut moved = deleted.clone();
            moved.push(line);
            check(daemon, join(&moved).as_bytes());

            let mut doubled = lines.clone();
            doubled.insert(index, line);
            let text = join(&doubled);
            check(daemon, text.as_bytes());
            if line.contains(" = ") {
                let err = daemon.parse(text.as_bytes()).expect_err("doubled entry");
                assert_eq!(err.kind(), config::ErrorKind::DuplicateKey, "{line}");
            }
        }
        for &(_, other, _) in ALL {
            for borrowed in other.lines() {
                let text = format!("{full}{borrowed}\n");
                check(daemon, text.as_bytes());
            }
        }
    }
}
