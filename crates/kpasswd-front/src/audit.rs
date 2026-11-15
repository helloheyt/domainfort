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
//! has no front event shape, as for ldap-front (docs/questions/Q-285 item 9).
//!
//! # The start-up check (docs/50 R50-16, §7.5)
//!
//! "A daemon does not bind a network port until its dependencies are
//! verified (configuration, keyd, dird, audit)." The front verifies auditd
//! through crate ipc-audit-client — `AuditLink::verify`: the peer uid is the
//! configured `auditd_uid` and auditd's `Pong` names the source auditd
//! records this process under — before it serves.
//!
//! **The source does not exist yet.** ipc-audit's `EventSource` and
//! config's `AuditSource` are closed tables without a kpasswd-front value
//! (crates outside task K8), so auditd cannot even map the front's uid, and
//! the front cannot name what to expect. [`FRONT_AUDIT_SOURCE`] is therefore
//! `None`, and the check **fails closed**
//! ([`AuditCheckError::SourceUndefined`]): a product front does not serve
//! until the source is appended — one value in each table, then this
//! constant (docs/questions/Q-955 item 1). The crate's own `#[cfg(test)]`
//! modules run the same check against a test auditd with a stand-in source
//! (crate-internal — no other crate can supply one, docs/52 C18).
//!
//! Spec: docs/53 §9; docs/50 R50-3, R50-16, R50-17, §3.2, §7.5, §8.1; A-57;
//! docs/52 §3.12; docs/questions/Q-512, Q-560, Q-955.

use crate::daemon::Endpoint;
use core::fmt;
use ipc_audit::EventSource;
use ipc_audit_client::{AuditLink, AuditLinkError, ExpectedAuditd};

/// The source auditd must record the front under — none yet (module
/// documentation; docs/questions/Q-955 item 1).
/// Spec: docs/50 §3.2 ("the source is set from the uid"); docs/53 §9.
pub const FRONT_AUDIT_SOURCE: Option<EventSource> = None;

/// Why the start-up check of auditd failed. Carries no octet of any frame.
/// Spec: docs/50 §7.5, §8.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditCheckError {
    /// No audit source exists for the front (module documentation): the
    /// check cannot be made, so the front does not serve.
    SourceUndefined,
    /// The one audit client's error (uid 0, connect, peer uid, source,
    /// deadline, I/O, protocol, refusal).
    Link(AuditLinkError),
}

impl fmt::Display for AuditCheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuditCheckError::SourceUndefined => {
                f.write_str("no audit source is defined for kpasswd-front (docs/questions/Q-955)")
            }
            AuditCheckError::Link(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for AuditCheckError {}

/// Connect to auditd, check its uid, `Ping` → a `Pong` naming `source`,
/// close. No source ⇒ [`AuditCheckError::SourceUndefined`] without
/// connecting.
///
/// # Errors
/// [`AuditCheckError`].
///
/// Spec: docs/50 R50-3, R50-16, §3.2, §7.5; docs/questions/Q-560 item 5.
pub async fn verify_auditd(
    endpoint: &Endpoint,
    source: Option<EventSource>,
) -> Result<(), AuditCheckError> {
    let source = source.ok_or(AuditCheckError::SourceUndefined)?;
    let expected = ExpectedAuditd::new(endpoint.uid, source).map_err(AuditCheckError::Link)?;
    AuditLink::new(endpoint.socket.clone(), expected)
        .verify()
        .await
        .map_err(AuditCheckError::Link)
}
