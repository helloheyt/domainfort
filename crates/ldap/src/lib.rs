#![forbid(unsafe_code)]
//! `ldap`: the LDAP engine — the Policy Enforcement Point behind
//! `ldap-front` (docs/49 R49-16, §11) — build tasks L4 (the skeleton) and
//! L8 (Search over the directory) of docs/49 §12.
//!
//! # What it is
//!
//! A library, like `kdc`: no sockets, no TLS, no clock, no threads, no
//! secret. The front (task L11) owns TCP, rustls and the framer; for each
//! LDAPMessage it re-encodes the client's message in parse-ldap's canonical
//! form and calls [`Engine::handle`] with the connection's [`Session`] and
//! the [`RequestInputs`] of that request: one policy snapshot and its PIP,
//! the account source of the same directory view, the caller's rate
//! limiter, `now`, the [`TransportReport`] (source zone, whether TLS is
//! up, whether more octets are already buffered), and — for a search of the
//! directory — the [`DirectoryInputs`] (the request's directory view and the
//! caller's [`SearchClock`]). The engine decodes the
//! message with the **canonical profile only** (R49-16: a compromised front
//! reaches the engine only with canonical, bounded input) and returns an
//! [`Outcome`]: zero or more canonical response encodings, a
//! [`ConnectionAction`] (Continue / StartTls / Close) and exactly one
//! [`AuditEvent`].
//!
//! # Scope (docs/49 §12)
//!
//! - L4: the session state machine — cleartext / TLS (LDAPS or StartTLS), a
//!   pending StartTLS, anonymous / bound identity, closed (the session
//!   module's documentation; R49-15); dispatch, the error table (R49-13),
//!   audit (R49-14), the size bound per authentication state, the rootDSE
//!   (R49-10), Unbind, Abandon, StartTLS with the injection protection, and
//!   every refusal path of docs/49 §3.1, §5.1, §5.3.
//! - L8: Search over the directory (R49-9, crate::search): base resolution
//!   through the naming context (A-53) and `<GUID=hex>`, the three scopes
//!   with paging and pruning, visibility before the filter, the
//!   three-valued filter over readable attributes, the unique-index fast
//!   path, the bounds (visit budget, page, octets, sizeLimit, timeLimit on
//!   the caller's clock), attribute selection, derived attributes, the LDAP
//!   representations of the phase-1 syntaxes, DN values filtered by
//!   visibility; Secret attributes and nTSecurityDescriptor never returned.
//! - Not here: the GSSAPI bind (task L7, blocked on owner item P-13 — every
//!   SASL mechanism is authMethodNotSupported, with a single seam in the
//!   bind module; until then only the crate's tests build a bound session),
//!   writes (none in phase 1, A-48 / Q-167), controls (none, R49-8).
//!
//! # Refusals and their result codes (docs/49 §3.1, §5, §9)
//!
//! | Situation | Response |
//! |---|---|
//! | larger than the session's bound | close, no response ([MS-ADTS] 3.1.1.3.4.6) |
//! | not canonical / undecodable / not a request | Notice of Disconnection (protocolError 2) + close (RFC 4511 §4.1.1; R49-16, A-52) |
//! | request while StartTLS pending, or TLS state mismatch | close (RFC 4511 §4.14.1; docs/49 §4.4) |
//! | bound identity expired / revoked / unverifiable | Notice of Disconnection (strongerAuthRequired 8) + close ([MS-ADTS] 5.1.1.6; R49-15; Q-169) |
//! | any critical control | the operation's response, unavailableCriticalExtension (12) (RFC 4511 §4.1.11; R49-8) |
//! | Bind version ≠ 3 | protocolError (2) |
//! | simple bind with a password | authMethodNotSupported (7), before any lookup, never keyd (P-14) |
//! | unauthenticated simple bind | unwillingToPerform (53) (RFC 4513 §5.1.2) |
//! | SASL GSSAPI without TLS | confidentialityRequired (13) |
//! | any SASL mechanism (L4) / other AuthenticationChoice | authMethodNotSupported (7) |
//! | StartTLS on TLS | operationsError (1) |
//! | StartTLS with octets already pending | operationsError (1) + close |
//! | StartTLS with a requestValue | protocolError (2) |
//! | other extended operation | protocolError (2), no responseName (RFC 4511 §4.12) |
//! | search, unrecognised scope | protocolError (2) (docs/49 E14) |
//! | the empty base not at baseObject; a directory search with no directory view | unwillingToPerform (53) |
//! | directory search: base not an LDAPDN | invalidDNSyntax (34) (Q-195 item 4) |
//! | directory search: base absent, outside the NC, or not visible | noSuchObject (32), identical octets (R49-13, A-48) |
//! | directory search, anonymous / weak transport | operationsError (1) / confidentialityRequired (13) / strongerAuthRequired (8), before the base is looked at (Q-169 item 3) |
//! | directory search: sizeLimit / server page, visit, octet, value or depth bound / timeLimit or query duration | sizeLimitExceeded (4) / adminLimitExceeded (11) / timeLimitExceeded (3), after the entries already sent (RFC 4511 §4.5.2) |
//! | directory failure (integrity, consistency, storage), PIP failure, naming-context mismatch | other (80) |
//! | rootDSE denied by the PDP | operationsError / confidentialityRequired / strongerAuthRequired / insufficientAccessRights / other (crate::subject) |
//! | rootDSE rate-limited / page size 0 | busy (51) / adminLimitExceeded (11) |
//! | Modify / Add / Delete / ModifyDN / Compare | unwillingToPerform (53), matching response tag (A-48) |
//!
//! matchedDN and diagnosticMessage are always empty (R49-13).
//!
//! # Fuzzing
//!
//! The engine's message input goes through `parse_ldap::decode_message` and
//! its DNs (search base, DN assertions) through
//! `parse_ldap::dn::parse_ldap_dn`, whose fuzz targets live in
//! `crates/parse-ldap/fuzz` (docs/49 §2.5). The engine's own parsers of
//! filter assertion values (RFC 4517 Integer, Generalized Time, Boolean; the
//! Q-080 fold; the OID check; the substring rule — crate::search::syntax)
//! and filter evaluation over a fixed in-memory entry (crate::search::filter,
//! through the same `EntryView` seam a candidate uses) have fuzz targets in
//! the detached workspace `crates/ldap/fuzz` (`ldap_assertion_values`,
//! `ldap_filter_fixed_entry`), reached through the `fuzz-hooks` feature,
//! which no product build enables (docs/CLEAN-ROOM.md; built only after owner item
//! P-1).
//!
//! # Residuals (documented, not hidden)
//!
//! - The rootDSE follows [MS-ADTS] 3.1.1.3.2's "Operational?" column, not
//!   RFC 4512 §5.1 (Q-190 item 5); the filter of a rootDSE search is ignored
//!   ([MS-ADTS] 3.1.1.3.1.3.6).
//! - The rootDSE is readable anonymously from an internal network before
//!   TLS (docs/49 §4.3, §5.2); an attacker on the path can strip
//!   supportedExtension (RFC 4513 §6.2) — the native client requires TLS by
//!   configuration (docs/49 §5.2).
//! - Search: the response time of a wholeSubtree search depends on the size
//!   of the visible subtree (docs/49 §6.6); the budget and pruning bound it,
//!   they do not hide it. objectCategory is evaluated in filters but not
//!   returned (no schema NC, Q-168 item 3). String(Unicode) comparison is
//!   the ASCII interim rule (Q-080, P-9). The interpretations of this build
//!   are docs/questions/Q-200.
//!
//! # Provenance
//!
//! Written only from the allowed sources, opened in this session from the
//! pinned cache `tools/spec-pin/cache/` (SHA-256 verified against
//! `tools/spec-pin/manifest.json`): RFC 4511 (49c6aab6…06fd) §3.1, §4,
//! §4.1.1, §4.1.1.1, §4.1.9, §4.1.11, §4.2, §4.2.1, §4.2.2, §4.3, §4.4,
//! §4.4.1, §4.5.1-§4.5.1.6, §4.5.1.7.5-§4.5.1.8, §4.5.2, §4.11-§4.14.3, §5,
//! §5.1-§5.3, §6, App. A, App. B (head) and the response definitions of
//! §4.6-§4.10; RFC 4512 (c3380501…d5bf) §2.5, §5.1-§5.1.7; RFC 4513
//! (2215320f…2f6a) §2, §3, §3.1, §3.1.1, §3.1.5, §3.2, §3.3, §4, §5,
//! §5.1-§5.1.3, §5.2.1.5, §6.1-§6.4; RFC 4517 (326d546c…d327) §3.3.16; RFC
//! 4422 (69fbd4a5…8c42) §3.1; RFC 4752 (3a53db51…d48d) §3; [MS-ADTS]
//! v20261026 (55b59eb1…b2b1) 3.1.1.2.2.2 (table and notes), 3.1.1.3.1.3.6,
//! 3.1.1.3.1.12, 3.1.1.3.2 (introduction, the operational/syntax table,
//! .1-.26, .33), 3.1.1.3.4 (introduction), 3.1.1.3.4.1 (introduction and OID
//! table), 3.1.1.3.4.2 (introduction and table), 3.1.1.3.4.2.1, 5.1.1.6,
//! 5.1.2.1, 5.1.2.2, 5.1.3, 5.1.3.1; [MS-DTYP] v20241119 (0f4a3744…83b3)
//! 2.4.2.4; ITU-T X.690 (02/2021) (6ac799a2…bd6c) 8.1.2.2-8.1.2.5,
//! 8.1.3.3-8.1.3.5, 8.3.1, 8.9.1, 8.14.3, 8.14.4; ITU-T X.680 (02/2021)
//! (b69dc475…ee14) Table 1. Task L8 added: RFC 4511 §4.5 (all of
//! §4.5.1-§4.5.3), App. A (result codes); RFC 4512 §1.4, §2.5; RFC 4517
//! §3.3.3, §3.3.6, §3.3.9, §3.3.13, §3.3.16, §3.3.25, §3.3.26, §3.3.30,
//! §4.2.2, §4.2.6, §4.2.16, §4.2.17, §4.2.19, §4.2.20, §4.2.27, §4.2.28 and
//! its header ("Obsoletes: 2252"); [MS-ADTS] 3.1.1.1.4, 3.1.1.1.5,
//! 3.1.1.2.2.2 (with .1-.8), 3.1.1.2.2.3, 3.1.1.2.2.4 (with .1-.14),
//! 3.1.1.3.1.1.3 (introduction), 3.1.1.3.1.2.1-3.1.1.3.1.2.5,
//! 3.1.1.3.1.3.1-3.1.1.3.1.3.6, 3.1.1.3.4.6, 3.1.1.4.1-3.1.1.4.5
//! (introduction), 5.1.3.3.6; [MS-DRSR] v20260309 (e8ce0c8c…b62c)
//! 5.16.3.1-5.16.3.10, 5.51. This project's documents: docs/CLEAN-ROOM.md,
//! docs/CLEAN-ROOM.md, docs/46 §1, §2.3, §5, §6, §7, docs/47 §8.2, docs/49 (decided,
//! A-45..A-48), docs/11 §2, docs/questions Q-163, Q-166, Q-167, Q-168,
//! Q-169, Q-170 (A-51), Q-175 (A-49), Q-185 (A-52), Q-190 (A-54), Q-195
//! (A-53), PENDING-OWNER (A-28..A-54, P-7, P-9, P-12, P-13, P-14). The
//! source and documentation of this project's own crates parse-ldap, pdp,
//! kdc, directory-pip, dirstore, ad-schema, keyd, krb-proto and dtyp were
//! read for their APIs. No other implementation was consulted or recalled
//! (docs/CLEAN-ROOM.md).
//!
//! Spec: docs/49 §3-§12; RFC 4511; RFC 4513.

mod audit;
mod bind;
mod config;
mod engine;
mod inputs;
mod respond;
mod root_dse;
mod search;
mod session;
mod subject;
mod time;

#[cfg(test)]
mod tests;

pub use audit::{
    AuditEvent, AuditOperation, AuditReason, AuditScope, AuditTarget, AuditText, AuditTransport,
    BindAudit, BindMechanism, SearchAudit, MAX_AUDIT_TEXT_OCTETS,
};
pub use config::{ConfigError, EngineConfig, RootDseConfig};
pub use engine::{ConnectionAction, Engine, Outcome};
pub use inputs::{DirectoryInputs, RateLimiter, RequestInputs, SearchClock, TransportReport};
pub use search::limits::{
    CHILD_PAGE_SIZE, MAX_CANDIDATES_VISITED, MAX_DN_VALUES_RESOLVED, MAX_PAGE_SIZE,
    MAX_QUERY_SECONDS, MAX_RESPONSE_OCTETS, MAX_VALUES_PER_RETURNED_ATTRIBUTE,
};
pub use session::{Listener, Session};

/// Hooks for the detached fuzz workspace `crates/ldap/fuzz` only (docs/CLEAN-ROOM.md
/// §6); compiled with the `fuzz-hooks` feature, which no product build
/// enables. Not part of the engine's API.
#[cfg(feature = "fuzz-hooks")]
#[doc(hidden)]
pub use search::fuzz as fuzz_hooks;
