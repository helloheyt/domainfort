//! The kdc's audit client: the one audit client of crate ipc-audit
//! (`ipc_audit::client`, task R9b) with the kdc's expectation — auditd's
//! uid and the source auditd must record the kdc's events under,
//! [`AUDIT_SOURCE`].
//!
//! On every new connection, before any batch, the shared client checks the
//! peer uid and that auditd's `Pong` names [`AUDIT_SOURCE`]; an auditd whose
//! map gives the kdc's uid another source receives no event, and the kdc's
//! gate counts auditd as unreachable — requests are not served until a
//! connection verified both ways is back (A-57, A-67 item 2; docs/questions/
//! Q-512, Q-560). What stays the kdc's own: its gate wrapper (crate::audit,
//! which implements `ipc_audit::client::LinkedGate`), its notes and this
//! expectation.
//!
//! Spec: docs/50 R50-3, R50-16, R50-17, §3.2, §8.1; docs/52 §3.12;
//! docs/questions/Q-512 (A-112), Q-560.

pub use ipc_audit::client::{AuditEndpoint, AuditLinkError, AUDIT_DEADLINE, HEARTBEAT};
use ipc_audit::client::{AuditLink, ExpectedAuditd};
use ipc_audit::EventSource;

/// The source auditd must record the kdc's events under: the kdc sends the
/// `Kdc` shape, which auditd accepts only from `Kdc` (A-85; crates/
/// audit-daemon `binding`).
/// Spec: docs/50 §3.2, §8.1; docs/questions/Q-341 (A-85), Q-512.
pub const AUDIT_SOURCE: EventSource = EventSource::Kdc;

/// The kdc's link to the auditd of `endpoint`, expecting [`AUDIT_SOURCE`].
///
/// # Errors
/// [`AuditLinkError::RootServerUid`] (auditd's uid is 0).
///
/// Spec: docs/50 R50-3; docs/questions/Q-512, Q-560.
pub fn link(endpoint: &AuditEndpoint) -> Result<AuditLink, AuditLinkError> {
    let expected = ExpectedAuditd::new(endpoint.uid, AUDIT_SOURCE)?;
    Ok(AuditLink::new(endpoint.socket.clone(), expected))
}
