#![forbid(unsafe_code)]
//! `keyd-types`: the crypto-free vocabulary of keyd's interface.
//!
//! Everything a caller of keyd names — and nothing that computes with a
//! key:
//!
//! | what | items |
//! |---|---|
//! | ids and handles | [`PrincipalId`], [`Kvno`], [`KeyPurpose`], [`KeyHandle`], [`PrincipalBinding`] |
//! | caller model | [`CallerId`], [`Role`], [`Operation`], [`authz::CAPABILITY_TABLE`], [`authz::role_permits`], [`authz::purpose_permitted`] (with the compile-time pins) |
//! | errors | [`AuthnError`], [`IssueError`], [`Error`], [`ConfigError`] |
//! | operation arguments and results | [`AuthnProof`], [`AsTicketTemplate`], [`AsRepParts`], [`TgsFastRequest`], [`TgtContext`], [`TgsTicketTemplate`], [`TgsRepParts`], [`FastArmor`], [`FastConversation`], [`ServiceContext`], [`AccountKind`], [`SetSecretTarget`] |
//! | the set_secret grant (task A15a) | [`grant`]: [`MAX_GRANT_TARGETS`], [`MAX_SET_SECRET_GRANT_SECS`], [`MAX_INITIAL_SECRET_GRANT_SECS`], [`MAX_SET_SECRET_GRANTS`], [`grant::max_grant_lifetime_secs`] |
//! | the decision table and the ceremony (A-102, docs/52 R1, R3) | [`decision`]: [`DecisionId`], [`DecidedOperation`], [`DecisionIntent`], [`PendingDestruction`], [`DestructionPage`], [`CeremonyState`], the bounds |
//! | one-time token ids | [`ExchangeId`], [`CtxId`], [`ArmorId`], [`ServiceCtxId`] |
//! | configuration | [`KeydConfig`], [`TicketPolicy`], [`ThrottlePolicy`], [`ConfigDescription`], [`EncTypeId`] |
//! | audit | [`AuditRecord`], [`AuditOutcome`], [`AuditReason`], [`AuditKeyRef`], [`AuditSink`] |
//! | time scale | [`kerberos_time_seconds`] |
//! | the KDC's custody seam | [`KeyCustody`] |
//!
//! # Why a separate crate (D182; decision A-63)
//!
//! Only keyd links the Kerberos crypto profile (`krb-crypto`, D182). The
//! KDC, the LDAP engine, the directory PIP and the ipc-keyd client need
//! keyd's types but perform no key operation; they depend on this crate
//! instead of keyd, so `krb-crypto` is not in their dependency graph and its
//! code is not in their processes (docs/50 §1: keys stay in the keyd
//! process; now the crypto code does too). `tests/no_crypto_dependency.rs`
//! checks it with `cargo tree`.
//!
//! keyd re-exports every item, so `keyd::KeyHandle` and
//! `keyd_types::KeyHandle` are the same type. keyd keeps the operations, the
//! key store, the entropy source, the throttles, the token tables, the
//! internal refusal-to-error mapping and the in-process custody
//! (`LocalKeyd`); ipc-keyd keeps the wire codec and the IPC custody.
//!
//! Encryption types appear here only as identifiers ([`EncTypeId`]: the
//! numbers of RFC 3961 §8, RFC 3962 §7 and RFC 8009 §7); keyd converts them
//! to its profile's type. [`KeydConfig::validate`] applies the string-to-key
//! iteration count of RFC 3962 §4 / RFC 8009 §4 itself, pinned to the
//! profile's by keyd's tests.
//!
//! # Provenance
//!
//! Moved unchanged in meaning from this project's crates keyd and kdc
//! (`KeyCustody`), whose items keep their `Spec:` references (docs/10,
//! docs/48, docs/49 §3.3, docs/50, RFC 4120, RFC 6113 and the decisions
//! cited on each item). New in this crate: [`EncTypeId`] and the iteration
//! count rule, written from RFC 3961 §8, RFC 3962 §4, §7 and RFC 8009 §4, §7
//! (pinned copies in tools/spec-pin/cache, SHA-256 verified against the
//! manifest), opened in-session. No other implementation was consulted or
//! recalled (AGENTS.md §1-3).
//!
//! The decision table's vocabulary ([`decision`], A-102) is written from
//! this project's docs/52 §3.1, §3.4, §4 and docs/questions/Q-460..Q-462,
//! Q-465, opened in-session; no other implementation was consulted or
//! recalled.
//!
//! Spec: docs/10; docs/45 §10 (D182); docs/questions/Q-245 item 3 (A-63);
//! docs/50 §1, §10; docs/52 §4 (A-102).

mod as_exchange;
pub mod audit;
pub mod authz;
pub mod config;
mod custody;
pub mod decision;
mod enctype;
mod error;
mod fast_armor;
pub mod grant;
pub mod model;
mod service_ticket;
mod tgs_exchange;
mod time;
mod tokens;

pub use as_exchange::{AsRepParts, AsTicketTemplate, AuthnProof};
pub use audit::{AuditKeyRef, AuditOutcome, AuditReason, AuditRecord, AuditSink};
pub use authz::{CallerId, Operation, Role};
pub use config::{ConfigDescription, KeydConfig, ThrottlePolicy, TicketPolicy};
pub use custody::KeyCustody;
pub use decision::{
    CeremonyState, DecidedOperation, DecisionId, DecisionIntent, DestructionPage,
    PendingDestruction, MAX_DECISION_APPROVERS, MAX_DESTROY_DECISIONS, MAX_DESTROY_DECISION_PAGE,
    MAX_DESTROY_DECISION_SECS, MAX_KEY_DECISIONS, MAX_KEY_DECISION_SECS,
    MIN_KEY_DECISION_APPROVERS,
};
pub use enctype::EncTypeId;
pub use error::{AuthnError, ConfigError, Error, IssueError};
pub use fast_armor::{FastArmor, FastConversation, MAX_FX_COOKIE_LENGTH};
pub use grant::{
    AccountKind, SetSecretTarget, MAX_GRANT_TARGETS, MAX_INITIAL_SECRET_GRANT_SECS,
    MAX_SET_SECRET_GRANTS, MAX_SET_SECRET_GRANT_SECS,
};
pub use model::{KeyHandle, KeyPurpose, Kvno, PrincipalBinding, PrincipalId};
pub use service_ticket::ServiceContext;
pub use tgs_exchange::{TgsFastRequest, TgsRepParts, TgsTicketTemplate, TgtContext};
pub use time::kerberos_time_seconds;
pub use tokens::{ArmorId, CtxId, ExchangeId, ServiceCtxId, TOKEN_ID_LENGTH};
