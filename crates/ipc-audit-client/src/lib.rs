#![forbid(unsafe_code)]
//! `ipc-audit-client`: a sender's side of the audit channel — the one audit
//! client and the audit gate it drives (docs/50 R50-17, §8.1; docs/52
//! §3.11, §3.12). The channel's wire shapes, the event codec and the
//! sender window are crate `ipc_audit`'s.
//!
//! # Why a crate of its own (task IB1)
//!
//! Before task IB1 both lived in crate `ipc_audit`, the client behind the
//! feature `client` (an optional tokio). Class C40 — "what an artifact links
//! depends on what is built with it" (docs/questions/Q-851, decision A-144):
//! in a shared build cargo unifies features, so one daemon's feature reached
//! every daemon. Here tokio is not optional; no manifest of the workspace
//! declares an `optional` dependency, so no feature of ours changes a graph
//! (docs/research/r4-b §5.6).
//!
//! # The audit client
//!
//! [`AuditLink`]: the one implementation of a sender's link to auditd (task
//! R9b) — built only with an [`ExpectedAuditd`] (auditd's uid and the source
//! it must record this process under), it verifies both on every new
//! connection before any batch, and delivers a daemon's [`AuditGate`]
//! window. Used by keyd-daemon, kdc-daemon, directory-daemon, admin-daemon
//! and ldap-front's start-up check. auditd does not link this crate.
//!
//! # The gate and the proof of an acknowledged intent (docs/52 R6, A-102)
//!
//! [`AuditGate`]: the window and the audit client's view of auditd behind
//! one lock — the one gate every sending daemon (keyd, the kdc, dird,
//! admind) builds its own wrapper on. [`AckedIntent<T>`] is obtainable only
//! from [`AuditGate::wait_acknowledged`], after auditd acknowledged the
//! intent record ([`IntentRecord`]) of that very value: a mutation entry
//! point that takes it by value cannot run before the acknowledgement
//! (dird's `apply`, keyd's key-state changes, dird's decision
//! registrations). [`AuditGate::close`] is the one bounded flush at stop
//! ([`AUDIT_FLUSH_GRACE`], [`FlushWait`], [`Unflushed`]). The gate's link
//! side — auditd reachable, the batch to send, auditd's `Ack`, a lost batch
//! — is crate-private: only the one audit client (which verified the
//! connection) drives it, so no code outside this crate can open a gate or
//! acknowledge, i.e. mint a proof (task R15b, docs/questions/Q-630). That
//! is why the gate is in the client's crate (docs/questions/Q-900).
//!
//! # Security
//!
//! No `unsafe`; no panic or `unwrap` on a network path; the reply's length
//! is checked against the channel's reply bound before any body octet is
//! read; no error or `Debug` output carries frame or event octets (docs/50
//! §8.2). A poisoned gate lock is "audit not available" (fail closed).
//!
//! # Provenance
//!
//! Moved unchanged from crate `ipc_audit` (this project's own code: its
//! modules `client`, `gate`, `test_seams`) by task IB1, written there only
//! from this project's decided design (docs/50, docs/52 §3.11, §3.12,
//! PENDING-OWNER A-57, A-67, A-85, A-87, A-88, A-101, A-102, A-105, A-107,
//! A-112, docs/questions Q-218, Q-252, Q-260, Q-313, Q-350, Q-365, Q-395,
//! Q-500, Q-502, Q-510, Q-512, Q-560, Q-570, Q-630) and the docs.rs API
//! pages of tokio 1.54.1. The split itself: docs/questions/Q-851, A-144,
//! docs/research/r4-b §5.6. No other implementation, serializer, RPC
//! framework or audit format was consulted or recalled (docs/CLEAN-ROOM.md).
//!
//! Spec: docs/50 R50-17, §3.6, §3.7, §8.1; docs/52 §3.11 R6 (A-102), §3.12
//! (task R9b, A-112; Q-512, Q-560); docs/questions/Q-630; Decision: A-144;
//! Q-851.

mod client;
mod gate;
#[cfg(feature = "test-seams")]
#[doc(hidden)]
pub mod test_seams;

pub use client::{
    AttachedLink, AuditConnection, AuditEndpoint, AuditLink, AuditLinkError, ExpectedAuditd,
    LinkedGate, AUDIT_DEADLINE, HEARTBEAT,
};
pub use gate::{
    AckedIntent, AuditGate, FlushWait, IntentRecord, PendingIntent, Unflushed, WindowSteps,
    AUDIT_FLUSH_GRACE, FLUSH_POLL,
};
