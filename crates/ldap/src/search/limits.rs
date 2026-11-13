//! The bounds of one directory search, each a named constant with its
//! justification.
//!
//! docs/32 §8 and AGENTS.md §6 require bounds and fix no numbers; docs/49
//! §6.1 (R49-3, R49-9) chose the visit budget, the page bound and the
//! response bound, anchored to the LDAP policies of [MS-ADTS] 3.1.1.3.4.6 and
//! never above their defaults. The engine reads no clock (docs/49 §11): the
//! time limits are measured on the caller's [`crate::SearchClock`].
//!
//! Spec: docs/49 §6.1 items 3, 7, §6.5, §10.2 (R49-3, R49-9); [MS-ADTS]
//! v20261026 3.1.1.3.4.6 (MaxTempTableSize 10,000; MaxPageSize 1,000;
//! MaxQueryDuration 120 s; MaxValRange 1,500); RFC 4511 §4.5.1.4,
//! §4.5.1.5.

/// Most candidate objects one search reads and evaluates: 10,000.
///
/// Spec: docs/49 §6.1 item 3 (`MAX_CANDIDATES_VISITED` = 10,000 — anchor
/// MaxTempTableSize, "the maximum number of rows that a DC will create in a
/// temporary database table to hold intermediate results during query
/// processing", default 10,000, [MS-ADTS] 3.1.1.3.4.6). Deterministic: the
/// same snapshot and request always stop at the same candidate. Exceeded →
/// adminLimitExceeded (Q-168 item 5).
pub const MAX_CANDIDATES_VISITED: u32 = 10_000;

/// Most entries one search returns: 1,000.
///
/// Spec: docs/49 §6.1 item 7 (`MaxPageSize = 1000`); [MS-ADTS] 3.1.1.3.4.6
/// MaxPageSize ("The maximum number of objects that are returned in a
/// single search result", default 1,000). A lower `Constrain(MaxPageSize)`
/// obligation of the PDP applies on top (docs/11 §8). Exceeded →
/// adminLimitExceeded (Q-168 item 5); the client's sizeLimit →
/// sizeLimitExceeded (RFC 4511 §4.5.1.4).
pub const MAX_PAGE_SIZE: u32 = 1_000;

/// Longest a search may run, by the caller's clock: 60 seconds.
///
/// Project choice, stricter than MaxQueryDuration ("The maximum time, in
/// seconds, that a DC will spend on a single search", default 120 s,
/// [MS-ADTS] 3.1.1.3.4.6 — "When this limit is reached, the DC returns a
/// timeLimitExceeded"). The visit budget bounds the work deterministically;
/// this bounds the wall time it may take. Exceeded → timeLimitExceeded
/// (docs/49 §9).
pub const MAX_QUERY_SECONDS: u64 = 60;

/// Most octets of SearchResultEntry messages one search sends: 8 MiB.
///
/// Spec: docs/49 §6.1 item 7 (`MAX_RESPONSE_OCTETS` = 8 MiB). Exceeded →
/// adminLimitExceeded; the entries already sent stand (RFC 4511 §4.5.2).
pub const MAX_RESPONSE_OCTETS: usize = 8 * 1024 * 1024;

/// Most DN-valued values (member, memberOf targets, and DN assertions of the
/// filter) one search resolves: 65,536.
///
/// Project choice: docs/49 §6.5 makes every DN value cost one visibility
/// decision, "bounded by 4096" per attribute (`dirstore::MAX_VALUES_PER_
/// ATTRIBUTE`); with up to [`MAX_PAGE_SIZE`] entries that is not a bound on
/// the search, so the search has its own: sixteen full groups' worth.
/// Exceeded → adminLimitExceeded.
pub const MAX_DN_VALUES_RESOLVED: usize = 16 * dirstore::MAX_VALUES_PER_ATTRIBUTE;

/// Most values one returned attribute carries: 4,096.
///
/// Spec: docs/49 §6.3 (range retrieval is avoided by construction: the
/// project's value bound is `dirstore::MAX_VALUES_PER_ATTRIBUTE`, so no
/// stored attribute "has too many values to be returned at one time" —
/// [MS-ADTS] 3.1.1.3.1.3.3); parse-ldap `MAX_ATTRIBUTE_VALUES`. Only a
/// constructed back link (memberOf) can exceed it; that stops the search
/// with adminLimitExceeded rather than return a silently truncated set.
pub const MAX_VALUES_PER_RETURNED_ATTRIBUTE: usize = parse_ldap::MAX_ATTRIBUTE_VALUES;

/// Children read per page of a one-level or subtree enumeration: 64.
///
/// Project choice, within `dirstore::MAX_CHILDREN_PER_PAGE` (1,000): a
/// subtree walk holds one page per level of depth, so the page size bounds
/// its memory (64 levels × 64 GUIDs). Spec: docs/49 §6.1 item 3
/// (`Snapshot::children` with paging); A-49.
pub const CHILD_PAGE_SIZE: usize = 64;

/// The bounds of one search. [`SearchLimits::PHASE1`] is the only value the
/// engine uses; the crate's own tests use smaller budgets to reach each
/// bound with a small directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SearchLimits {
    /// [`MAX_CANDIDATES_VISITED`].
    pub(crate) visit_budget: u32,
    /// [`MAX_PAGE_SIZE`].
    pub(crate) max_page_size: u32,
    /// [`MAX_QUERY_SECONDS`].
    pub(crate) max_query_seconds: u64,
    /// [`MAX_RESPONSE_OCTETS`].
    pub(crate) max_response_octets: usize,
    /// [`MAX_DN_VALUES_RESOLVED`].
    pub(crate) max_dn_values: usize,
    /// [`CHILD_PAGE_SIZE`].
    pub(crate) child_page: usize,
    /// Whether an equality on a unique attribute is answered through the
    /// unique index (docs/49 §6.1 item 3, the fast path). Always `true` in
    /// the engine; the crate's tests turn it off to show both paths return
    /// the same entries.
    pub(crate) unique_index: bool,
}

impl SearchLimits {
    /// The phase-1 bounds (module documentation).
    pub(crate) const PHASE1: SearchLimits = SearchLimits {
        visit_budget: MAX_CANDIDATES_VISITED,
        max_page_size: MAX_PAGE_SIZE,
        max_query_seconds: MAX_QUERY_SECONDS,
        max_response_octets: MAX_RESPONSE_OCTETS,
        max_dn_values: MAX_DN_VALUES_RESOLVED,
        child_page: CHILD_PAGE_SIZE,
        unique_index: true,
    };
}
