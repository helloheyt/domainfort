#![no_main]
//! Fuzz target for `config::line_format`, the one docs/50 §7.1 line parser
//! (shared by every daemon schema and by crates/provision-manifest since
//! task F7, the A-86 follow-up).
//!
//! docs/CLEAN-ROOM.md / docs/32 §8 (every parser gets a fuzz target before it
//! merges to main). On any octets, against a fixed closed table,
//! `Entries::parse` must return without panicking, and:
//!
//! * input over the file bound, or not ending in LF, is refused (docs/50
//!   §7.1);
//! * an error names, at most, a key of the table — never input text — and a
//!   key only together with a line (docs/CLEAN-ROOM.md; A-60);
//! * accepted input is printable ASCII and LF only; every entry's key is in
//!   the table and appears once; every value is non-empty, printable, without
//!   a leading or trailing space and within the value bound; the entries'
//!   lines strictly increase and none is beyond the line bound;
//! * the entries are exactly the `key = value` lines of the input
//!   (re-joining them gives back each such line);
//! * each daemon schema and the line layer agree on the line rules: if the
//!   line layer refuses with a line rule against a schema's table, that
//!   schema refuses with the same line and rule.
//!
//! Spec: docs/50 R50-15, §7.1, §9; PENDING-OWNER A-86.

use config::limits::{MAX_FILE_OCTETS, MAX_LINES, MAX_VALUE_OCTETS, SEPARATOR};
use config::line_format::{is_printable, Entries, LineErrorKind};
use config::{KeyadmSettings, KeydSettings};
use libfuzzer_sys::fuzz_target;

/// A small closed table (keyadm's), so that accepted inputs are reachable.
const KEYS: &[&str] = KeyadmSettings::KEYS;

fuzz_target!(|data: &[u8]| {
    let result = Entries::parse(data, KEYS);
    let cut = !data.is_empty() && data.last() != Some(&b'\n');
    if data.len() > MAX_FILE_OCTETS || cut {
        assert!(result.is_err(), "bound and final LF enforced");
    }
    match result {
        Err(err) => {
            if let Some(key) = err.key() {
                assert!(KEYS.contains(&key), "error key comes from the table");
                assert!(err.line().is_some(), "a key only with its line");
            }
            // The schema over the same table reports the same line and key
            // (its line layer is this one, its errors mapped rule for rule).
            match KeyadmSettings::parse(data) {
                Err(schema) => {
                    assert_eq!(schema.line(), err.line());
                    assert_eq!(schema.key(), err.key());
                }
                Ok(_) => panic!("the schema accepted what its line layer refused"),
            }
        }
        Ok(entries) => {
            assert!(data.iter().all(|&b| b == b'\n' || is_printable(b)));
            let mut last_line = 0u32;
            let mut seen: Vec<&str> = Vec::new();
            for entry in entries.iter() {
                assert!(KEYS.contains(&entry.key()));
                assert!(!seen.contains(&entry.key()), "each key once");
                seen.push(entry.key());
                let value = entry.value();
                assert!(!value.is_empty() && value.len() <= MAX_VALUE_OCTETS);
                assert!(!value.starts_with(' ') && !value.ends_with(' '));
                assert!(value.bytes().all(is_printable));
                assert!(entry.line() > last_line, "lines increase");
                last_line = entry.line();
                assert!(usize::try_from(entry.line()).is_ok_and(|n| n <= MAX_LINES));
                let line = format!("{}{SEPARATOR}{value}", entry.key());
                let text = core::str::from_utf8(data).expect("printable ASCII");
                assert!(text.lines().any(|l| l == line), "an entry is a line");
            }
            assert_eq!(entries.len(), seen.len());
            // keyd's table is another closed table: a key of keyadm's that
            // keyd does not know is refused there as unknown, never kept.
            if let Err(err) = Entries::parse(data, KeydSettings::KEYS) {
                assert!(matches!(
                    err.kind(),
                    LineErrorKind::UnknownKey | LineErrorKind::DuplicateKey
                ));
            }
        }
    }
});
