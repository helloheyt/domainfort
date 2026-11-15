//! The front's audit: the start-up check of auditd through the one audit
//! client, and the counted events (crate::log).
//!
//! # What the front audits (docs/53 §9)
//!
//! The change itself is audited by dird (the `ChangePassword` decision and
//! outcome events, acknowledged before the commit) and keyd (one record per
//! operation, intent and outcome for the completion) — docs/53 §9. The front
//! sends **no events**: its layer — connections closed for their source or
//! a limit, framing failures, other versions — is noise, which A-57 counts
//! instead of recording one event per occurrence ("a count, not a record per
//! datagram"); the counts are crate::log's [`crate::log::Counts`]. ipc-audit
//! has no front event shape, as for ldap-front (docs/questions/Q-285 item 9;
//! Q-955 item 1, accepted with A-158; the reading is restated in
//! docs/questions/Q-961).
//!
//! # The start-up check (docs/50 R50-16, §7.5)
//!
//! "A daemon does not bind a network port until its dependencies are
//! verified (configuration, keyd, dird, audit)." The front verifies auditd
//! through crate ipc-audit-client — `AuditLink::verify`: the peer uid is the
//! configured `auditd_uid` and auditd's `Pong` names the source auditd
//! records this process under, which must be [`FRONT_AUDIT_SOURCE`] — before
//! it serves. The source is that constant, never a parameter (task DN12,
//! docs/questions/Q-955 item 1, Q-960): it is auditd that assigns it, from
//! the front's peer uid and its own `uid_sources` map (docs/50 §3.2) — an
//! auditd that does not map the front's uid to `kpasswd-front` closes the
//! connection or names another source, and the front does not serve (fail
//! closed).
//!
//! Spec: docs/53 §9; docs/50 R50-3, R50-16, R50-17, §3.2, §7.5, §8.1; A-57;
//! docs/52 §3.12; docs/questions/Q-512, Q-560, Q-955 item 1 (A-158), Q-960.

use crate::daemon::Endpoint;
use ipc_audit::EventSource;
use ipc_audit_client::{AuditLink, AuditLinkError, ExpectedAuditd};

/// The source auditd must record the front under — `kpasswd-front`, code 8.
/// Spec: docs/50 §3.2 ("the source is set from the uid"); docs/53 §9;
/// docs/questions/Q-955 item 1 (A-158), Q-960.
pub const FRONT_AUDIT_SOURCE: EventSource = EventSource::KpasswdFront;

/// Connect to auditd, check its uid, `Ping` → a `Pong` naming
/// [`FRONT_AUDIT_SOURCE`], close.
///
/// # Errors
/// [`AuditLinkError`] (uid 0 configured, connect, peer uid, another source,
/// deadline, I/O, protocol, refusal).
///
/// Spec: docs/50 R50-3, R50-16, §3.2, §7.5; docs/questions/Q-560 item 5.
pub async fn verify_auditd(endpoint: &Endpoint) -> Result<(), AuditLinkError> {
    let expected = ExpectedAuditd::new(endpoint.uid, FRONT_AUDIT_SOURCE)?;
    AuditLink::new(endpoint.socket.clone(), expected)
        .verify()
        .await
}
