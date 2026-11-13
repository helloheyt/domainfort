#![forbid(unsafe_code)]
//! `ldap`: the LDAP engine — the Policy Enforcement Point behind
//! `ldap-front` (docs/49 R49-16, §11) — build task L4, the skeleton
//! (docs/49 §12).
//!
//! # What it is
//!
//! A library, like `kdc`: no sockets, no TLS, no clock, no threads, no
//! secret. The front (task L11) owns TCP, rustls and the framer; for each
//! LDAPMessage it re-encodes the client's message in parse-ldap's canonical
//! form and calls [`Engine::handle`] with the connection's [`Session`] and
//! the [`RequestInputs`] of that request: one policy snapshot and its PIP,
//! the account source of the same directory view, the caller's rate
//! limiter, `now`, and the [`TransportReport`] (source zone, whether TLS is
//! up, whether more octets are already buffered). The engine decodes the
//! message with the **canonical profile only** (R49-16: a compromised front
//! reaches the engine only with canonical, bounded input) and returns an
//! [`Outcome`]: zero or more canonical response encodings, a
//! [`ConnectionAction`] (Continue / StartTls / Close) and exactly one
//! [`AuditEvent`].
//!
//! # Scope of L4 (docs/49 §12)
//!
//! - The session state machine — cleartext / TLS (LDAPS or StartTLS), a
//!   pending StartTLS, anonymous / bound identity, closed (the session
//!   module's documentation; R49-15).
//! - Dispatch, the error table (R49-13), audit (R49-14), the size bound
//!   per authentication state, the rootDSE (R49-10), Unbind, Abandon,
//!   StartTLS with the injection protection, and every refusal path of
//!   docs/49 §3.1, §5.1, §5.3.
//! - Not here: search of the directory (task L8 — every search other than
//!   the rootDSE is unwillingToPerform), the GSSAPI bind (task L7, blocked on
//!   owner item P-13 — every SASL mechanism is authMethodNotSupported, with
//!   a single seam in the bind module), DN handling (task L5), writes (none in
//!   phase 1, A-48 / Q-167).
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
//! | search of anything but the rootDSE, or the empty base not at baseObject | unwillingToPerform (53) |
//! | rootDSE denied by the PDP | operationsError / confidentialityRequired / strongerAuthRequired / insufficientAccessRights / other (crate::subject) |
//! | rootDSE rate-limited / page size 0 | busy (51) / adminLimitExceeded (11) |
//! | Modify / Add / Delete / ModifyDN / Compare | unwillingToPerform (53), matching response tag (A-48) |
//!
//! matchedDN and diagnosticMessage are always empty (R49-13).
//!
//! # Fuzzing
//!
//! No fuzz target here: the engine parses nothing itself — every octet it
//! reads goes through `parse_ldap::decode_message`, whose fuzz targets live
//! in `crates/parse-ldap/fuzz` (docs/49 §2.5). The engine's own octet step
//! (the response tag of crate::respond) runs only on its own encoder output.
//!
//! # Residuals (documented, not hidden)
//!
//! - `pdp::Transport` has no cleartext-LDAP variant; the engine reports
//!   `Ldaps` with the truthful `transport_sec` (Q-190 item 2).
//! - The rootDSE follows [MS-ADTS] 3.1.1.3.2's "Operational?" column, not
//!   RFC 4512 §5.1 (Q-190 item 5); the filter of a rootDSE search is ignored
//!   ([MS-ADTS] 3.1.1.3.1.3.6).
//! - The rootDSE is readable anonymously from an internal network before
//!   TLS (docs/49 §4.3, §5.2); an attacker on the path can strip
//!   supportedExtension (RFC 4513 §6.2) — the native client requires TLS by
//!   configuration (docs/49 §5.2).
//! - The responses of the five unsupported operations are produced by
//!   rewriting one identifier octet of a canonical SearchResultDone
//!   (crate::respond; Q-190 item 1).
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
//! (b69dc475…ee14) Table 1. This project's documents: AGENT-ONBOARDING,
//! AGENTS, docs/49 (decided, A-45..A-48), docs/11 §2, docs/questions Q-163,
//! Q-166, Q-167, Q-169, Q-170 (A-51), Q-185 (A-52), PENDING-OWNER (A-45..A-52,
//! P-12, P-13, P-14). The source and documentation of this project's own
//! crates parse-ldap, pdp, kdc, directory-pip, keyd, krb-proto and dtyp were
//! read for their APIs. No other implementation was consulted or recalled
//! (AGENTS.md §1-3).
//!
//! Spec: docs/49 §3-§5, §9-§12; RFC 4511; RFC 4513.

mod audit;
mod bind;
mod config;
mod engine;
mod inputs;
mod respond;
mod root_dse;
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
pub use inputs::{RateLimiter, RequestInputs, TransportReport};
pub use session::{Listener, Session};
