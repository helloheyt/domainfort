//! **Test seams of the audit gate's link side — tests only** (task R15b,
//! docs/questions/Q-630; the docs/52 R15 rules, docs/questions/Q-570 item
//! 2, A-118).
//!
//! In a product build this module does not exist: it is declared behind the
//! feature `test-seams`, which only `[dev-dependencies]` enable (cargo's
//! resolver 2 activates a dev-dependency's features only in builds of test
//! targets), and no product source names it (crates/e2e-tests
//! `tests/no_test_seams_in_product.rs`, which also pins *which* tests may).
//!
//! The link side of [`AuditGate`] — auditd reachable, the batch to send,
//! auditd's `Ack`, a lost batch — is crate-private: in a product only the one
//! audit client (`crate::client`, after verifying auditd's uid and reported
//! source) drives it, so no code can mint an [`crate::AckedIntent`] without
//! auditd. Tests that need an acknowledged intent play auditd through a fake
//! auditd and the **real** client (crates/ipc-audit `tests/linked`). Only the
//! in-process tier-1 tests of a daemon's own gate (docs/50 §9: "in-process …
//! without sockets") play the *client* itself at the window level — a batch
//! taken and inspected without being delivered, a connection lost, an
//! acknowledgement at a chosen moment — which a socket and the asynchronous
//! client cannot express without races; they use these four functions.
//!
//! Spec: docs/52 §3.11 R6 (a), §3.18 (C18), §7 R15; docs/50 §8.1, §9;
//! docs/questions/Q-560 (A-115), Q-570 §5 item a (A-118), Q-630.

use crate::channel::{Ack, Append};
use crate::gate::AuditGate;
use crate::window::WindowError;

/// The audit client's view of auditd (`AuditGate::set_reachable`). Tests
/// only.
pub fn set_reachable(gate: &AuditGate, reachable: bool) {
    gate.set_reachable(reachable);
}

/// The next batch the client would send (`AuditGate::next_batch`). Tests
/// only.
#[must_use]
pub fn next_batch(gate: &AuditGate) -> Option<Append> {
    gate.next_batch()
}

/// auditd's acknowledgement as the client would feed it
/// (`AuditGate::acknowledge`). Tests only.
///
/// # Errors
/// The window's [`WindowError`].
pub fn acknowledge(gate: &AuditGate, ack: &Ack) -> Result<usize, WindowError> {
    gate.acknowledge(ack)
}

/// The connection the client held was lost (`AuditGate::connection_lost`).
/// Tests only.
pub fn connection_lost(gate: &AuditGate) {
    gate.connection_lost();
}
