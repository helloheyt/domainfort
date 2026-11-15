//! admind's link to auditd: the one audit client of crate ipc-audit
//! (`ipc_audit_client`, task R9b) with admind's expectation — auditd's uid
//! and the source auditd must record admind's events under,
//! [`AUDIT_SOURCE`]. Verified first, before admind listens (docs/50 R50-16:
//! "auditd → keyd → dird → … → admind; a daemon binds nothing until its
//! dependencies were verified" — admind refuses to start without auditd),
//! then kept open to deliver admind's events.
//!
//! On every new connection, before any batch, the shared client checks the
//! peer uid and that auditd's `Pong` names [`AUDIT_SOURCE`]; an auditd whose
//! map gives admind's uid another source receives no event, and admind's
//! gate counts auditd as unreachable — `SetPassword` is refused `Busy` until
//! a connection verified both ways is back (A-57; docs/questions/Q-512,
//! Q-560). What stays admind's own: its gate wrapper (crate::audit, which
//! implements `ipc_audit_client::LinkedGate`), its notes and this
//! expectation.
//!
//! Spec: docs/50 R50-3, R50-16, R50-17, §3.2, §8.1; docs/51 §5.7 item 3;
//! docs/52 §3.12; docs/questions/Q-512 (A-112), Q-560.

use ipc_audit::EventSource;
pub use ipc_audit_client::{AuditEndpoint, AuditLinkError, AUDIT_DEADLINE, HEARTBEAT};
use ipc_audit_client::{AuditLink, ExpectedAuditd};

/// The source auditd must record admind's events under: admind sends the
/// `Admind` shape, which auditd accepts only from `Admind` (A-85;
/// crates/audit-daemon `binding`).
/// Spec: docs/50 §3.2, §8.1; docs/51 §5.7 item 3; docs/questions/Q-341
/// (A-85), Q-512.
pub const AUDIT_SOURCE: EventSource = EventSource::Admind;

/// admind's link to the auditd of `endpoint`, expecting [`AUDIT_SOURCE`].
///
/// # Errors
/// [`AuditLinkError::RootServerUid`] (auditd's uid is 0).
///
/// Spec: docs/50 R50-3; docs/questions/Q-512, Q-560.
pub fn link(endpoint: &AuditEndpoint) -> Result<AuditLink, AuditLinkError> {
    let expected = ExpectedAuditd::new(endpoint.uid, AUDIT_SOURCE)?;
    Ok(AuditLink::new(endpoint.socket.clone(), expected))
}
