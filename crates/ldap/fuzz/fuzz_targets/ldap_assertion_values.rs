#![no_main]
//! Fuzz target for the LDAP engine's filter assertion-value parsers
//! (crates/ldap/src/search/syntax.rs, through `ldap::fuzz_hooks`).
//!
//! docs/CLEAN-ROOM.md / docs/32 §8 (every parser of network input gets a fuzz
//! target before it merges to main). On any input nothing panics, and:
//!
//! * Integer (RFC 4517 §3.3.16): the grammar admits one spelling per number,
//!   so an accepted value prints back to exactly its input;
//! * Generalized Time (RFC 4517 §3.3.13): the engine's rendering of a parsed
//!   time (`YYYYMMDDHHMMSS.0Z`, [MS-DRSR] 5.16.3.9) parses back to the same
//!   whole second, exactly; any DSTIME the renderer accepts round-trips too;
//! * Boolean (RFC 4517 §3.3.3): only `TRUE` and `FALSE`;
//! * the Q-080 fold: defined exactly on printable ASCII, keeps the length,
//!   leaves no A–Z, and is idempotent;
//! * the OID check (RFC 4512 §1.4): an accepted OID holds only letters,
//!   digits, "-" and ".";
//! * the substring rule (RFC 4517 §4.2.6): pieces cut from a value in order
//!   and disjoint always match it; arbitrary pieces never panic.
//!
//! Spec: RFC 4517 §3.3.3, §3.3.13, §3.3.16, §4.2.6; RFC 4512 §1.4;
//! [MS-DRSR] 5.16.3.9; Q-080.

use ldap::fuzz_hooks::{
    folded, is_oid, parse_boolean, parse_generalized_time, parse_integer, render_dstime,
    render_integer, substrings_match,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Integer.
    if let Some(n) = parse_integer(data) {
        assert_eq!(n.to_string().as_bytes(), data, "one spelling per number");
        if let Ok(small) = i64::try_from(n) {
            assert_eq!(render_integer(small), data);
        }
    }

    // Generalized Time, and the renderer on a DSTIME taken from the input.
    if let Some((seconds, _exact)) = parse_generalized_time(data) {
        if let Some(rendered) = render_dstime(seconds) {
            assert_eq!(rendered.len(), 17, "YYYYMMDDHHMMSS.0Z");
            assert_eq!(parse_generalized_time(&rendered), Some((seconds, true)));
        }
    }
    if let Some(first) = data.get(..8) {
        let mut octets = [0u8; 8];
        octets.copy_from_slice(first);
        let seconds = i64::from_be_bytes(octets);
        if let Some(rendered) = render_dstime(seconds) {
            assert_eq!(parse_generalized_time(&rendered), Some((seconds, true)));
        }
    }

    // Boolean.
    assert_eq!(
        parse_boolean(data).is_some(),
        data == b"TRUE" || data == b"FALSE"
    );

    // The Q-080 fold.
    let printable = data.iter().all(|b| (0x20..=0x7E).contains(b));
    match folded(data) {
        Some(f) => {
            assert!(printable);
            assert_eq!(f.len(), data.len());
            assert!(!f.iter().any(u8::is_ascii_uppercase));
            assert_eq!(folded(&f).as_deref(), Some(f.as_slice()));
        }
        None => assert!(!printable),
    }

    // The OID check.
    if let Ok(text) = core::str::from_utf8(data) {
        if is_oid(text) {
            assert!(!text.is_empty());
            assert!(text
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.'));
        }
    }

    // The substring rule: three cut points from the first octets, ordered
    // and disjoint pieces of the rest must match it.
    if let (Some(cuts), Some(value)) = (data.get(..3), data.get(3..)) {
        let span = value.len() + 1;
        let mut points = [
            usize::from(cuts[0]) % span,
            usize::from(cuts[1]) % span,
            usize::from(cuts[2]) % span,
        ];
        points.sort_unstable();
        let [a, b, c] = points;
        if let (Some(initial), Some(middle), Some(last)) =
            (value.get(..a), value.get(a..b), value.get(c..))
        {
            assert!(substrings_match(
                value,
                Some(initial),
                &[middle],
                Some(last)
            ));
            assert!(substrings_match(value, None, &[middle], None));
        }
        // Arbitrary pieces (split at NUL): any answer, never a panic.
        let pieces: Vec<&[u8]> = value.split(|b| *b == 0).collect();
        let (first, rest) = pieces
            .split_first()
            .map_or((None, &[][..]), |(f, r)| (Some(*f), r));
        let _ = substrings_match(value, first, rest, pieces.last().copied());
        let _ = substrings_match(data, None, &pieces, None);
    }
});
