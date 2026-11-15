//! The start-up check of auditd (docs/50 R50-16: "a daemon does not bind a
//! network port until its dependencies are verified (configuration, keyd,
//! dird, audit)"; §7.5).
//!
//! The front sends **no events**: docs/50 §4.2 assigns the LDAP events to
//! dird ("the LDAP event (`Outcome.audit`) is written by dird (the PEP), not
//! by the front (R49-14)"), §8.1 names the sources (kdc, keyd, the LDAP
//! engine's `Outcome.audit`) and ipc-audit has no front event shape. So the
//! front verifies that auditd is there and answering — through the one audit
//! client of crate ipc-audit (`ipc_audit_client::AuditLink::verify`, task
//! R9b): the peer uid is the configured `auditd_uid` and auditd's `Pong`
//! names the source auditd records the front under, which must be
//! [`AUDIT_SOURCE`] — and then closes the connection; its own layer is only
//! counted (crate::log). docs/questions/Q-285 item 9, Q-512, Q-560 item 5.
//!
//! Spec: docs/50 R50-3, R50-16, R50-17, §3.2, §3.3, §4.2, §7.5, §8.1;
//! docs/52 §3.12; docs/questions/Q-512 (A-112), Q-560.

use crate::dird::Endpoint;
use ipc_audit::EventSource;
use ipc_audit_client::{AuditLink, ExpectedAuditd};

/// Why the check failed: the one audit client's error (carries no octet of
/// any frame). Spec: docs/50 §7.5, §8.2.
pub use ipc_audit_client::AuditLinkError as AuditCheckError;

/// How long one step of the check may take: the one audit client's
/// deadline. Project choice (as the other daemons' audit deadline; docs/50
/// gives none — Q-260 item 4).
pub use ipc_audit_client::AUDIT_DEADLINE as AUDIT_CHECK_DEADLINE;

/// The source auditd must record the front under (docs/50 §2.4, §3.2: the
/// front's uid is mapped to `ldap-front`, crates/config `AuditSource`).
/// Spec: docs/50 §3.2; docs/questions/Q-560 item 5.
pub const AUDIT_SOURCE: EventSource = EventSource::LdapFront;

/// Connect to auditd, check its uid, `Ping` → a `Pong` naming
/// [`AUDIT_SOURCE`], close.
///
/// # Errors
/// [`AuditCheckError`] — among them `RootServerUid` for a configured uid 0
/// and `SourceMismatch` for an auditd that records the front under another
/// source.
///
/// Spec: docs/50 R50-3, R50-16, §3.2, §7.5; docs/questions/Q-560 item 5.
pub async fn verify_auditd(endpoint: &Endpoint) -> Result<(), AuditCheckError> {
    let expected = ExpectedAuditd::new(endpoint.uid, AUDIT_SOURCE)?;
    AuditLink::new(endpoint.socket.clone(), expected)
        .verify()
        .await
}
