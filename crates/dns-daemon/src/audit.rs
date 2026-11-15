//! dnsd's audit check: auditd verified first (docs/50 R50-16; docs/54 §4.8:
//! "configuration ⇒ bind ⇒ hardening ⇒ auditd verified (the one audit
//! client, source `dnsd` — R9b) ⇒ dird verified ⇒ …").
//!
//! The check is the one audit client's (crates/ipc-audit-client
//! `AuditLink::verify`, task R9b): connect, check auditd's uid, `Ping` → a
//! `Pong` naming the source auditd records **this** process under — another
//! source ⇒ nothing sent, no start (docs/52 §3.12 C12; docs/questions/
//! Q-560). There is no way to skip it.
//!
//! # The source `dnsd` does not exist yet (docs/questions/Q-950)
//!
//! docs/54 §9 and docs/questions/Q-619 item 2 give dnsd its own audit source
//! (`dnsd`, code 7 ⚠), added to ipc-audit's closed `EventSource` table, the
//! audit log's source codes, auditd's `uid_sources` and its shape ↔ source
//! binding — task DN12, not built. dnsd must not borrow another process's
//! source: auditd would record dnsd's connection as that process (the C12
//! class R9b closed). So the source dnsd expects is [`AUDIT_SOURCE`] =
//! `None` until DN12, and with `None` the check refuses
//! ([`AuditCheckError::SourceNotRegistered`]) — **the product daemon does
//! not start** (fail closed, docs/50 §7.5). When DN12 adds the variant, this
//! constant becomes `Some(EventSource::Dnsd)` and nothing else changes.
//!
//! Nor does dnsd send events yet: docs/54 §9 gives it noise counters only
//! (`WindowSummary`), and no event shape of its own exists (DN12). Like
//! ldap-front (which "sends no events; verifies auditd at start"), dnsd
//! verifies auditd at start and reports its counters on its operational log
//! (crate::log) meanwhile. Queries are not gated on auditd (docs/54 §9: "no
//! record per query"); the UPDATE decisions are audited — gating — by dird,
//! their PEP (docs/54 §4.5 step 7, §9).
//!
//! Spec: docs/50 R50-3, R50-16, §3.2, §7.5; docs/54 §4.8, §9; docs/52 §3.12;
//! docs/questions/Q-560 item 5, Q-619 items 2, 3, Q-950.

use ipc_audit::EventSource;
use ipc_audit_client::{AuditEndpoint, AuditLink, AuditLinkError, ExpectedAuditd};

/// The source auditd must record dnsd under — `dnsd` (docs/54 §9; Q-619
/// item 2), not yet in ipc-audit's closed table (task DN12): `None` until
/// then, so the start-up check refuses (module documentation; Q-950).
pub const AUDIT_SOURCE: Option<EventSource> = None;

/// Why the audit check failed. Carries no octet of any frame.
/// Spec: docs/50 §7.5, §8.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditCheckError {
    /// dnsd has no audit source of its own yet (task DN12, docs/questions/
    /// Q-950): nothing was connected.
    SourceNotRegistered,
    /// The one audit client's check failed (uid 0 configured, connect, peer
    /// uid, the source auditd named, a deadline, …).
    Link(AuditLinkError),
}

impl core::fmt::Display for AuditCheckError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AuditCheckError::SourceNotRegistered => f.write_str(
                "dnsd has no audit source of its own yet (task DN12); auditd not contacted",
            ),
            AuditCheckError::Link(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for AuditCheckError {}

/// Verify the auditd of `endpoint`, expecting it to record this process
/// under `source` (module documentation).
///
/// # Errors
/// [`AuditCheckError`].
///
/// Spec: docs/50 R50-3, R50-16, §3.2, §7.5; docs/questions/Q-560 item 5,
/// Q-950.
pub async fn verify_auditd(
    endpoint: &AuditEndpoint,
    source: Option<EventSource>,
) -> Result<(), AuditCheckError> {
    let source = source.ok_or(AuditCheckError::SourceNotRegistered)?;
    let expected = ExpectedAuditd::new(endpoint.uid, source).map_err(AuditCheckError::Link)?;
    AuditLink::new(endpoint.socket.clone(), expected)
        .verify()
        .await
        .map_err(AuditCheckError::Link)
}
