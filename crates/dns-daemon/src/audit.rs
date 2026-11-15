//! dnsd's audit: auditd verified first, then dnsd's noise counters
//! delivered as `WindowSummary` events (docs/54 §9).
//!
//! # The start-up check (docs/50 R50-16; docs/54 §4.8)
//!
//! "configuration ⇒ bind ⇒ hardening ⇒ auditd verified (the one audit
//! client, source `dnsd` — R9b) ⇒ dird verified ⇒ …". The check is the one
//! audit client's (crates/ipc-audit-client `AuditLink::connect`, task R9b):
//! connect, check auditd's uid, `Ping` → a `Pong` naming the source auditd
//! records **this** process under, which must be [`AUDIT_SOURCE`] — another
//! source ⇒ nothing sent, no start (docs/52 §3.12 C12; docs/questions/
//! Q-560). There is no way to skip it, and no other source to expect: the
//! source is this constant, not a parameter (task DN12, docs/questions/
//! Q-950, Q-960). It is auditd that decides the source, from dnsd's peer uid
//! and its own `uid_sources` map (docs/50 §3.2) — an auditd that does not
//! map dnsd's uid to `dnsd` closes the connection or names another source,
//! and dnsd does not start (fail closed, docs/50 §7.5).
//!
//! # What dnsd records (docs/54 §9, R54-11)
//!
//! "dnsd — a new source (`dnsd`, source code 7): only counters
//! (`WindowSummary` — noise: dropped / limited / malformed / refused) … no
//! record per query." dnsd has no event shape of its own: every peer-driven
//! noise occurrence (crate::daemon `Shared::noise` — the one place it is
//! counted) is counted into the shared gate's window
//! ([`AuditGate::count_noise`]), which takes no slot; the audit link sends
//! the count as the next `WindowSummary` (`suppressed_noise`) on the shared
//! gate's summary pace: a window that holds only counters leaves at most
//! once per ipc-audit-client `HEARTBEAT`, however fast auditd acknowledges
//! (docs/questions/Q-989, A-165 — the bound every counters-only sender gets
//! from ipc-audit-client) — so a flood yields at most one summary per
//! heartbeat, never one record per datagram. dnsd reserves no slot:
//! queries are not gated on auditd (docs/54 §9); the UPDATE decisions are
//! audited — gating — by dird, their PEP (docs/54 §4.5 step 7, §9). Which
//! counters are noise is crate::daemon's reading of docs/54 §9
//! (docs/questions/Q-961).
//!
//! Spec: docs/50 R50-3, R50-16, R50-17, §3.2, §7.5, §8.1; docs/54 §4.8, §9,
//! R54-11; docs/52 §3.12; A-57; docs/questions/Q-560 item 5, Q-619 items 2,
//! 3, Q-950 (A-157), Q-960, Q-961, Q-989 (A-165).

use crate::log::{note, Note};
use core::future::Future;
use core::time::Duration;
use ipc_audit::{EventSource, WindowConfig};
use ipc_audit_client::{
    AuditEndpoint, AuditLink, AuditLinkError, ExpectedAuditd, FlushWait, Unflushed,
};

/// The source auditd must record dnsd under — `dnsd`, code 7.
/// Spec: docs/54 §9; docs/questions/Q-619 item 2, Q-950 (A-157), Q-960.
pub const AUDIT_SOURCE: EventSource = EventSource::Dnsd;

/// dnsd's audit window: ipc-audit's default. dnsd commits no event of its
/// own and reserves no slot, so the window only ever holds its summaries.
/// Project choice (the shared default, ipc-audit `WindowConfig::DEFAULT`).
pub const AUDIT_WINDOW: WindowConfig = WindowConfig::DEFAULT;

/// dnsd's link to the auditd of `endpoint`, expecting [`AUDIT_SOURCE`].
///
/// # Errors
/// [`AuditLinkError::RootServerUid`] for a configured auditd uid of 0.
///
/// Spec: docs/50 R50-3, R50-16, §3.2; docs/questions/Q-560 item 5.
pub fn link(endpoint: &AuditEndpoint) -> Result<AuditLink, AuditLinkError> {
    let expected = ExpectedAuditd::new(endpoint.uid, AUDIT_SOURCE)?;
    Ok(AuditLink::new(endpoint.socket.clone(), expected))
}

/// dnsd's gate: the shared `ipc_audit_client::AuditGate` (its window, the
/// reachability the audit link alone sets, the stop's flush) with dnsd's
/// one way to record — a counted noise occurrence.
/// Spec: docs/54 §9; docs/52 §3.11 R6; A-57.
#[derive(Debug)]
pub struct AuditGate {
    core: ipc_audit_client::AuditGate,
}

impl AuditGate {
    /// A gate over an empty window; auditd counts as unreachable until the
    /// audit link says otherwise.
    #[must_use]
    pub fn new(window: WindowConfig) -> AuditGate {
        AuditGate {
            core: ipc_audit_client::AuditGate::new(window),
        }
    }

    /// Count one peer-driven noise occurrence into the next
    /// `WindowSummary` — kept while auditd is unreachable, never a slot.
    /// Spec: docs/54 §9; A-57; docs/questions/Q-961.
    pub fn count_noise(&self) {
        self.core.count_noise();
    }

    /// Noise counted and not yet queued as a summary (for tests and the
    /// daemon's own reports); `None` if the gate's lock is poisoned.
    #[must_use]
    pub fn counted_noise(&self) -> Option<u64> {
        self.core.inspect(ipc_audit::SendWindow::suppressed_noise)
    }

    /// The stop's flush (`ipc_audit_client::AuditGate::close`): wait at most
    /// `grace` for the summaries already queued and — while auditd is
    /// reachable — for the counts the summary pace still holds, stopping
    /// early once the link counts auditd as unreachable (nothing dnsd sends
    /// gates an operation — the kdc's and keyd's rule, A-87); then end the
    /// link.
    /// Spec: docs/questions/Q-313 (A-82), Q-350 item 11 (A-87), Q-961 item
    /// 6, Q-989; docs/52 §3.11 R6 (b).
    pub(crate) async fn close<E: Future<Output = ()>>(
        &self,
        grace: Duration,
        end_link: E,
    ) -> Unflushed {
        self.core
            .close(
                grace,
                FlushWait::UntilAcknowledgedOrUnreachable,
                tokio::time::sleep,
                end_link,
            )
            .await
    }
}

/// What dnsd's gate gives the one audit client (task R9b): the shared gate,
/// no wake-up (dnsd records no event; its counts leave on the gate's
/// summary pace — module documentation), and dnsd's notes when the link is
/// restored or lost.
/// Spec: docs/52 §3.11 R6, §3.12; docs/questions/Q-512, Q-560 item 4,
/// Q-989.
impl ipc_audit_client::LinkedGate for AuditGate {
    fn audit_gate(&self) -> &ipc_audit_client::AuditGate {
        &self.core
    }

    fn recorded(&self) -> impl Future<Output = ()> + Send + '_ {
        core::future::pending()
    }

    fn link_restored(&self) {
        note(Note::AuditRestored, None);
    }

    fn link_lost(&self) {
        note(Note::AuditLost, None);
    }
}
