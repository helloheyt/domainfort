//! The front's audit: auditd verified first, then the front's noise
//! delivered as `WindowSummary` counts over the one audit client.
//!
//! # What the front audits (docs/53 §9)
//!
//! The change itself is audited by dird (the `ChangePassword` decision and
//! outcome events, acknowledged before the commit) and keyd (one record per
//! operation, intent and outcome for the completion) — docs/53 §9. The
//! front's own layer — "connection closed (source outside
//! `internal_networks`, malformed framing, version) — with the A-57 noise
//! rule (a count, not a record per datagram)" — is **noise**: the front has
//! no event shape of its own (auditd accepts only `WindowSummary` from the
//! source `kpasswd-front`, docs/50 §8.1, A-160), and every noise occurrence
//! is counted into the next `WindowSummary`'s `suppressed_noise` — never one
//! record per connection (docs/questions/Q-961 item 7, accepted under A-160;
//! Q-988). Which counted cases are noise, and the one place they are counted
//! (`Counters::noise`, which needs this module's [`AuditGate`]), is
//! crate::log's.
//!
//! # The start-up check (docs/50 R50-16, §7.5)
//!
//! "A daemon does not bind a network port until its dependencies are
//! verified (configuration, keyd, dird, audit)." The front verifies auditd
//! through crate ipc-audit-client — [`link`] then `AuditLink::connect`: the
//! peer uid is the configured `auditd_uid` and auditd's `Pong` names the
//! source auditd records this process under, which must be
//! [`FRONT_AUDIT_SOURCE`] — before it asks dird or serves. The source is
//! that constant, never a parameter (task DN12, docs/questions/Q-955 item 1,
//! Q-960): it is auditd that assigns it, from the front's peer uid and its
//! own `uid_sources` map (docs/50 §3.2) — an auditd that does not map the
//! front's uid to `kpasswd-front` closes the connection or names another
//! source, and the front does not serve (fail closed). The verified
//! connection is **kept**: once the listeners serve, the audit link is
//! attached to it (the gate opens on that connection only — task R15b,
//! docs/questions/Q-630) and runs for the life of the front, reconnecting —
//! and verifying again — after a loss.
//!
//! # At most one summary per heartbeat (A-57: "rate-limited")
//!
//! Each noise occurrence is counted straight into the shared gate's window
//! ([`AuditGate::count_noise`] → ipc-audit-client `AuditGate::count_noise`),
//! and the one audit client sends the counts as a `WindowSummary` on the
//! gate's own pace: a window that holds only counters leaves at most once
//! per `HEARTBEAT`, whatever the flood and however fast auditd acknowledges
//! — the root fix of docs/questions/Q-989 (A-165) in ipc-audit-client, the
//! bound every counters-only sender (dnsd too) gets by construction. The
//! front keeps no pace, counter or hand-over of its own (Q-988 item 4's
//! local form is gone).
//!
//! # Not gating (docs/53 §9)
//!
//! The front reserves no slot and sends no gating event: auditd lost while
//! serving ⇒ requests are unaffected, the counts are kept (saturating) and
//! sent once the link is verified again. At stop the one flush of every
//! daemon (`AuditGate::close`; `AUDIT_FLUSH_GRACE`, stopping early once
//! auditd counts as unreachable — the kdc's and keyd's rule, A-87) waits,
//! bounded and while auditd is reachable, for the counts still held to leave
//! as a summary and be acknowledged (ipc-audit-client, Q-989).
//!
//! Spec: docs/53 §9; docs/50 R50-3, R50-16, R50-17, §3.2, §7.5, §8.1; A-57;
//! A-87; A-160; A-165; docs/52 §3.11 R6, §3.12; docs/questions/Q-512, Q-560
//! items 4, 5, Q-630, Q-955 item 1 (A-158), Q-960, Q-961 items 1-7 (A-160),
//! Q-988, Q-989; tokio 1.54.1 docs.rs: `time::sleep`.

use crate::daemon::Endpoint;
use crate::log::{note, Note};
use core::future::Future;
use core::time::Duration;
use ipc_audit::{EventSource, WindowConfig};
use ipc_audit_client::{AuditLink, AuditLinkError, ExpectedAuditd, FlushWait, Unflushed};

/// The source auditd must record the front under — `kpasswd-front`, code 8.
/// Spec: docs/50 §3.2 ("the source is set from the uid"); docs/53 §9;
/// docs/questions/Q-955 item 1 (A-158), Q-960.
pub const FRONT_AUDIT_SOURCE: EventSource = EventSource::KpasswdFront;

/// The front's audit window: ipc-audit's default. The front commits no
/// event and reserves no slot, so the window only ever holds its summaries.
/// Project choice (the shared default, as dnsd's — ipc-audit
/// `WindowConfig::DEFAULT`).
pub const AUDIT_WINDOW: WindowConfig = WindowConfig::DEFAULT;

/// The front's link to the auditd of `endpoint`, expecting
/// [`FRONT_AUDIT_SOURCE`].
///
/// # Errors
/// [`AuditLinkError::RootServerUid`] for a configured auditd uid of 0.
///
/// Spec: docs/50 R50-3, R50-16, §3.2; docs/questions/Q-560 item 5.
pub fn link(endpoint: &Endpoint) -> Result<AuditLink, AuditLinkError> {
    let expected = ExpectedAuditd::new(endpoint.uid, FRONT_AUDIT_SOURCE)?;
    Ok(AuditLink::new(endpoint.socket.clone(), expected))
}

/// The front's gate: the shared `ipc_audit_client::AuditGate` (its window,
/// the reachability only the audit link sets, the summary pace, the stop's
/// flush) with the front's one way to record — a counted noise occurrence.
/// Spec: docs/53 §9; docs/52 §3.11 R6; A-57; docs/questions/Q-988, Q-989.
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

    /// Count one noise occurrence into the next `WindowSummary`
    /// (`suppressed_noise`) — kept while auditd is unreachable, never a
    /// slot, saturating; sent on the gate's pace (module documentation).
    /// Reached only through crate::log's `Counters::noise` (the one place
    /// noise is counted).
    /// Spec: docs/53 §9; A-57; docs/questions/Q-961 item 7, Q-988, Q-989;
    /// ipc-audit-client `AuditGate::count_noise`.
    pub(crate) fn count_noise(&self) {
        self.core.count_noise();
    }

    /// The stop's flush (`ipc_audit_client::AuditGate::close`): wait at most
    /// `grace` — while auditd is reachable — for the counts still held to
    /// leave as a summary and for every queued summary to be acknowledged,
    /// stopping early once the link counts auditd as unreachable (nothing
    /// the front sends gates an operation — the kdc's and keyd's rule,
    /// A-87); then end the link.
    /// Spec: docs/questions/Q-313 (A-82), Q-350 item 11 (A-87), Q-961 item
    /// 6, Q-988 item 1, Q-989; docs/52 §3.11 R6 (b).
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

/// What the front's gate gives the one audit client (task R9b): the shared
/// gate, no wake-up (the front records no event; its counts leave on the
/// gate's pace — module documentation), and the front's notes when the link
/// is restored or lost.
/// Spec: docs/52 §3.11 R6, §3.12; docs/questions/Q-500 item 1, Q-512, Q-560
/// item 4, Q-989.
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

#[cfg(test)]
mod tests {
    //! Sources: docs/53 §9 (the front's counted cases); A-57 (noise counted,
    //! not recorded per occurrence); docs/questions/Q-961 items 1, 3, 7
    //! (A-160), Q-988 (the reading: which counted cases are noise), Q-989
    //! (A-165: the counts go straight to the shared window). Values are
    //! constructed for these tests.
    use super::*;
    use crate::log::{Counters, Failure, Noise};
    use ipc_audit::SendWindow;

    fn window_counts(gate: &AuditGate) -> u64 {
        gate.core.inspect(SendWindow::suppressed_noise).unwrap()
    }

    /// Every noise case counts once on the operational log and once in the
    /// audit window — through the one chokepoint, at once (no local
    /// counter, no hand-over); the operational failures (dird not serving,
    /// a failed accept) reach neither.
    #[test]
    fn noise_reaches_the_window_at_once_and_failures_never() {
        let counters = Counters::default();
        let gate = AuditGate::new(AUDIT_WINDOW);
        for noise in Noise::ALL {
            counters.noise(noise, &gate);
        }
        counters.failure(Failure::DirdNotServing);
        counters.failure(Failure::AcceptFailed);
        let counts = counters.snapshot();
        for noise in Noise::ALL {
            assert_eq!(counts.of(noise), 1, "{noise:?}");
        }
        assert_eq!(counts.noise(), 6);
        assert_eq!((counts.dird_not_serving, counts.accept_failed), (1, 1));
        assert_eq!(
            window_counts(&gate),
            6,
            "the six noise cases, not the two failures"
        );
    }

    /// The counts are kept while auditd is unreachable (a new gate counts
    /// auditd as unreachable until the audit link says otherwise) — noise is
    /// never refused or dropped for it — and take no slot.
    #[test]
    fn counts_are_kept_while_auditd_is_unreachable() {
        let gate = AuditGate::new(AUDIT_WINDOW);
        assert!(!gate.core.is_reachable());
        gate.count_noise();
        gate.count_noise();
        assert_eq!(window_counts(&gate), 2);
        assert_eq!(gate.core.outstanding(), 0, "no slot taken");
    }
}
