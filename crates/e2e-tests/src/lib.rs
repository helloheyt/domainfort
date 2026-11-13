#![forbid(unsafe_code)]
//! `e2e-tests`: runtime task P12 (docs/50 §10) — end-to-end tests over real
//! sockets, docs/50 §9 tier 2 across **all** daemons together.
//!
//! This library is intentionally empty: the crate holds no production code.
//! Everything lives under `tests/`:
//!
//! | file | what |
//! |---|---|
//! | `tests/support/` | the harness: the five real daemons in the docs/50 §7.5 order, the fixtures, the RFC clients |
//! | `tests/login_and_audit.rs` | scenario 1 (full login over UDP and TCP), scenario 2 (audit end to end) |
//! | `tests/ldap_chain.rs` | scenario 3 (ldap-front → dird → auditd: LDAPS, StartTLS, injection, password bind) |
//! | `tests/fail_closed.rs` | scenario 4 (keyd, dird, auditd stopped and restarted) |
//! | `tests/policy_and_identity.rs` | scenario 5 (policy versions) and 6 (cross-wired channels) |
//! | `tests/tier3_distinct_uids.rs` | tier 3: distinct uids per daemon (root on Linux, ignored by default) |
//!
//! Spec: docs/50 §9 (tier 2), §10 (P12).
