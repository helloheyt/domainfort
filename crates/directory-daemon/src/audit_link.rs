//! dird's link to auditd: the one audit client of crate ipc-audit
//! (`ipc_audit::client`, task R9b) with dird's expectation — auditd's uid
//! and the source auditd must record dird's events under, [`AUDIT_SOURCE`].
//! Verified first, before dird opens the directory or listens (docs/50
//! R50-16: "auditd → keyd → dird → …; a daemon binds nothing until its
//! dependencies were verified"), then kept open to deliver the LDAP
//! engine's and the admin plane's events.
//!
//! On every new connection, before any batch, the shared client checks the
//! peer uid and that auditd's `Pong` names [`AUDIT_SOURCE`]; an auditd whose
//! map gives dird's uid another source receives no event, and dird's gate
//! counts auditd as unreachable — LDAP operations and admin writes are
//! refused until a connection verified both ways is back (A-57, A-85;
//! docs/questions/Q-512, Q-560). The directory-view channel issues nothing
//! (the kdc audits every request itself); the refused peers of dird's
//! channels are counted on stderr, as keyd does (docs/questions/Q-260
//! item 5; Q-270 item 6). What stays dird's own: its gate wrapper
//! (crate::ldap_audit, which implements `ipc_audit::client::LinkedGate`),
//! its notes and this expectation.
//!
//! Spec: docs/50 R50-3, R50-16, R50-17, §3.2, §8.1; docs/51 §5.7; docs/52
//! §3.12; docs/questions/Q-512 (A-112), Q-560.

pub use ipc_audit::client::{AuditEndpoint, AuditLinkError, AUDIT_DEADLINE, HEARTBEAT};
use ipc_audit::client::{AuditLink, ExpectedAuditd};
use ipc_audit::EventSource;

/// The source auditd must record dird's events under: dird sends the
/// `Ldap` and `DirAdmin` shapes, which auditd accepts only from `Dird`
/// (A-85; crates/audit-daemon `binding`).
/// Spec: docs/50 §3.2, §4.2, §8.1; docs/51 §5.7 item 1; docs/questions/
/// Q-341 (A-85), Q-512.
pub const AUDIT_SOURCE: EventSource = EventSource::Dird;

/// dird's link to the auditd of `endpoint`, expecting [`AUDIT_SOURCE`].
///
/// # Errors
/// [`AuditLinkError::RootServerUid`] (auditd's uid is 0).
///
/// Spec: docs/50 R50-3; docs/questions/Q-512, Q-560.
pub fn link(endpoint: &AuditEndpoint) -> Result<AuditLink, AuditLinkError> {
    let expected = ExpectedAuditd::new(endpoint.uid, AUDIT_SOURCE)?;
    Ok(AuditLink::new(endpoint.socket.clone(), expected))
}
