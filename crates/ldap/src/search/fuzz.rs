//! Hooks for the detached fuzz workspace `crates/ldap/fuzz` (docs/CLEAN-ROOM.md:
//! every parser of network input gets a fuzz target before it merges to
//! main). Compiled only with the `fuzz-hooks` feature, which no product
//! build enables; not part of the engine's API.
//!
//! What is exposed is the engine's own code, unchanged:
//!
//! - the assertion-value parsers and renderers of crate::search::syntax
//!   (RFC 4517 Integer, Generalized Time, Boolean; the Q-080 string fold;
//!   the RFC 4512 OID check; the substring rule);
//! - filter evaluation (crate::search::filter: the three-valued tree, the
//!   steps of an item, assertion parsing and comparison) over a FIXED
//!   in-memory entry, which stands in for the directory-backed candidate
//!   through the same [`EntryView`] seam. The directory-only parts — the
//!   description lookup in the schema, the PDP's read decision, DN / OID
//!   assertions resolved in the directory — are not reached here: DN
//!   assertions go through parse-ldap's DN parser, which has its own fuzz
//!   target (`crates/parse-ldap/fuzz`, `parse_ldap_dn`).
//!
//! The fixed entry (hand-made test data):
//!
//! | description | rule | readable | values |
//! |---|---|---|---|
//! | `cn` | Text | yes | `alice`, `Al\u{e9}` (UTF-8, not ASCII) |
//! | `description` | Text | no | `secret` |
//! | `count` | Integer | yes | -5, 512 |
//! | `when` | Time | yes | 13 437 964 800 (2026-11-01T00:00:00Z as DSTIME) |
//! | `flag` | Bool | yes | TRUE |
//! | `blob` | Octet | yes | `00 FF 41` |
//! | `empty` | Octet | yes | (none) |
//! | `secret` | Never | — | — |
//! | `memberof` | Constructed | — | — |
//!
//! Descriptions are matched ASCII case-insensitively (RFC 4512 §2.5).
//!
//! Spec: docs/CLEAN-ROOM.md; docs/49 §2.5; RFC 4511 §4.5.1.7; RFC 4517 §3.3.3,
//! §3.3.13, §3.3.16; RFC 4512 §1.4, §2.5; Q-080.

use parse_ldap::Filter;

use super::filter::{evaluate, Assertion, EntryView, Rule, Values};
use super::syntax::{self, Tri};
use super::Stop;

/// RFC 4517 §3.3.16 Integer (crate::search::syntax).
#[must_use]
pub fn parse_integer(value: &[u8]) -> Option<i128> {
    syntax::parse_integer(value)
}

/// An Integer value as its decimal string (crate::search::syntax).
#[must_use]
pub fn render_integer(n: i64) -> Vec<u8> {
    syntax::render_integer(n)
}

/// RFC 4517 §3.3.13 Generalized Time: `(DSTIME seconds, exact)`
/// (crate::search::syntax).
#[must_use]
pub fn parse_generalized_time(value: &[u8]) -> Option<(i64, bool)> {
    syntax::parse_generalized_time(value).map(|t| (t.seconds, t.exact))
}

/// A DSTIME value as Generalized Time (crate::search::syntax).
#[must_use]
pub fn render_dstime(seconds: i64) -> Option<Vec<u8>> {
    syntax::render_dstime(seconds)
}

/// RFC 4517 §3.3.3 Boolean (crate::search::syntax).
#[must_use]
pub fn parse_boolean(value: &[u8]) -> Option<bool> {
    syntax::parse_boolean(value)
}

/// The Q-080 interim comparison form of a string (crate::search::syntax).
#[must_use]
pub fn folded(value: &[u8]) -> Option<Vec<u8>> {
    syntax::folded(value)
}

/// RFC 4512 §1.4 `descr` / `numericoid` (crate::search::syntax).
#[must_use]
pub fn is_oid(text: &str) -> bool {
    syntax::is_oid(text)
}

/// The substring rule (crate::search::syntax).
#[must_use]
pub fn substrings_match(
    value: &[u8],
    initial: Option<&[u8]>,
    anys: &[&[u8]],
    last: Option<&[u8]>,
) -> bool {
    syntax::substrings_match(value, initial, anys, last)
}

/// One attribute of the fixed entry.
struct FixedAttr {
    description: &'static str,
    rule: Rule,
    readable: bool,
}

/// The attributes of the fixed entry (module documentation).
const FIXED: [FixedAttr; 9] = [
    FixedAttr {
        description: "cn",
        rule: Rule::Text,
        readable: true,
    },
    FixedAttr {
        description: "description",
        rule: Rule::Text,
        readable: false,
    },
    FixedAttr {
        description: "count",
        rule: Rule::Integer,
        readable: true,
    },
    FixedAttr {
        description: "when",
        rule: Rule::Time,
        readable: true,
    },
    FixedAttr {
        description: "flag",
        rule: Rule::Bool,
        readable: true,
    },
    FixedAttr {
        description: "blob",
        rule: Rule::Octet,
        readable: true,
    },
    FixedAttr {
        description: "empty",
        rule: Rule::Octet,
        readable: true,
    },
    FixedAttr {
        description: "secret",
        rule: Rule::Never,
        readable: false,
    },
    FixedAttr {
        description: "memberof",
        rule: Rule::Constructed,
        readable: false,
    },
];

/// The fixed in-memory entry (module documentation).
struct FixedEntry;

impl EntryView for FixedEntry {
    type Attr = usize;

    fn describe(&self, description: &str) -> Option<(usize, Rule)> {
        FIXED
            .iter()
            .position(|a| a.description.eq_ignore_ascii_case(description))
            .and_then(|i| FIXED.get(i).map(|a| (i, a.rule)))
    }

    /// No directory behind the fixed entry, and none of its attributes has a
    /// directory-resolved rule.
    fn directory_assertion(
        &mut self,
        _rule: Rule,
        _value: &[u8],
    ) -> Result<Option<Assertion<'static>>, Stop> {
        Ok(None)
    }

    fn readable(&mut self, attr: &usize) -> bool {
        FIXED.get(*attr).is_some_and(|a| a.readable)
    }

    fn values(&mut self, attr: &usize) -> Result<Values, Stop> {
        let description = FIXED.get(*attr).map_or("", |a| a.description);
        Ok(match description {
            "cn" => Values::Bytes(vec![b"alice".to_vec(), "Al\u{e9}".as_bytes().to_vec()]),
            "description" => Values::Bytes(vec![b"secret".to_vec()]),
            "count" => Values::Integers(vec![-5, 512]),
            "when" => Values::Times(vec![13_437_964_800]),
            "flag" => Values::Bools(vec![true]),
            "blob" => Values::Bytes(vec![vec![0x00, 0xFF, 0x41]]),
            _ => Values::Bytes(Vec::new()),
        })
    }
}

/// Evaluate `filter` over the fixed entry with the engine's filter code:
/// `Some(true)` = TRUE, `Some(false)` = FALSE, `None` = Undefined.
/// Spec: RFC 4511 §4.5.1.7; crate::search::filter.
#[must_use]
pub fn evaluate_on_fixed_entry(filter: &Filter) -> Option<bool> {
    match evaluate(&mut FixedEntry, filter) {
        Ok(Tri::True) => Some(true),
        Ok(Tri::False) => Some(false),
        Ok(Tri::Undefined) | Err(_) => None,
    }
}
