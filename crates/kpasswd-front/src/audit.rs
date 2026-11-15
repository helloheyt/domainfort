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
//! The link sends the window's summary whenever it looks at the window and
//! something was counted — after each acknowledged batch, too — so counts
//! that reached the window at every occurrence would leave as fast as auditd
//! acknowledges, under a sustained flood. The front therefore keeps the
//! occurrences in its own counter (`AuditGate::count_noise`, one atomic
//! add, no lock) and hands them to the window once per [`SUMMARY_PERIOD`] —
//! the audit link's own `HEARTBEAT`, one value — in `pace_summaries`; the
//! hand-over wakes the link, which sends them as one `WindowSummary`. A
//! summary is queued only when the window holds counts, and counts reach the
//! window only at a hand-over: **at most one summary per period**, whatever
//! the flood (docs/questions/Q-988 item 4; Q-989 records the class and the
//! root option in ipc-audit-client, which would bound every counters-only
//! sender).
//!
//! # Not gating (docs/53 §9)
//!
//! The front reserves no slot and sends no gating event: auditd lost while
//! serving ⇒ requests are unaffected, the counts are kept (saturating) and
//! sent once the link is verified again. At stop the last counts are handed
//! over and the one flush of every daemon waits, bounded, for them
//! (`AuditGate::close`; `AUDIT_FLUSH_GRACE`, stopping early once auditd
//! counts as unreachable — the kdc's and keyd's rule, A-87).
//!
//! Spec: docs/53 §9; docs/50 R50-3, R50-16, R50-17, §3.2, §7.5, §8.1; A-57;
//! A-87; A-160; docs/52 §3.11 R6, §3.12; docs/questions/Q-512, Q-560 items
//! 4, 5, Q-630, Q-955 item 1 (A-158), Q-960, Q-961 items 1-7 (A-160), Q-988,
//! Q-989;
//! tokio 1.54.1 docs.rs: `sync::Notify::{notify_one, notified}`,
//! `time::sleep`.

use crate::daemon::Endpoint;
use crate::log::{note, Note};
use core::future::Future;
use core::time::Duration;
use ipc_audit::{EventSource, SendWindow, WindowConfig};
use ipc_audit_client::{AuditLink, AuditLinkError, ExpectedAuditd, FlushWait, Unflushed};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::Notify;
use tokio::time::Instant;

/// The source auditd must record the front under — `kpasswd-front`, code 8.
/// Spec: docs/50 §3.2 ("the source is set from the uid"); docs/53 §9;
/// docs/questions/Q-955 item 1 (A-158), Q-960.
pub const FRONT_AUDIT_SOURCE: EventSource = EventSource::KpasswdFront;

/// The front's audit window: ipc-audit's default. The front commits no
/// event and reserves no slot, so the window only ever holds its summaries.
/// Project choice (the shared default, as dnsd's — ipc-audit
/// `WindowConfig::DEFAULT`).
pub const AUDIT_WINDOW: WindowConfig = WindowConfig::DEFAULT;

/// How often the noise counted at the front's layer is handed to the audit
/// window, i.e. the shortest interval between two of the front's
/// `WindowSummary` events: the audit link's heartbeat (one value).
/// Spec: A-57 ("rate-limited"); docs/questions/Q-961 item 5, Q-988;
/// ipc-audit-client `HEARTBEAT`.
pub const SUMMARY_PERIOD: Duration = ipc_audit_client::HEARTBEAT;

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
/// the reachability only the audit link sets, the stop's flush) with the
/// front's one way to record — a counted noise occurrence, handed to the
/// window once per [`SUMMARY_PERIOD`] (module documentation).
/// Spec: docs/53 §9; docs/52 §3.11 R6; A-57; docs/questions/Q-988.
#[derive(Debug)]
pub struct AuditGate {
    core: ipc_audit_client::AuditGate,
    /// Noise counted since the last hand-over to the window.
    counted: AtomicU64,
    /// Signalled by a hand-over that moved counts: wakes the audit link.
    handed: Notify,
}

impl AuditGate {
    /// A gate over an empty window; auditd counts as unreachable until the
    /// audit link says otherwise.
    #[must_use]
    pub fn new(window: WindowConfig) -> AuditGate {
        AuditGate {
            core: ipc_audit_client::AuditGate::new(window),
            counted: AtomicU64::new(0),
            handed: Notify::new(),
        }
    }

    /// Count one noise occurrence for the next hand-over — kept while
    /// auditd is unreachable, never a slot, saturating. Reached only through
    /// crate::log's `Counters::noise` (the one place noise is counted).
    /// Spec: docs/53 §9; A-57; docs/questions/Q-961 item 7, Q-988.
    pub(crate) fn count_noise(&self) {
        // The closure never returns `None`, so the update cannot fail.
        let _ = self
            .counted
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_add(1))
            });
    }

    /// Hand the noise counted since the last hand-over to the window — its
    /// next `WindowSummary` (`suppressed_noise`) — and wake the audit link
    /// if anything moved; the number handed over. The work is one window
    /// step per occurrence already counted (bounded by what the period's
    /// connections produced).
    /// Spec: docs/questions/Q-961 items 1, 5, Q-988; ipc-audit-client
    /// `AuditGate::count_noise`.
    pub(crate) fn hand_over(&self) -> u64 {
        let counted = self.counted.swap(0, Ordering::Relaxed);
        for _ in 0..counted {
            self.core.count_noise();
        }
        if counted > 0 {
            self.handed.notify_one();
        }
        counted
    }

    /// Whether the window holds counts the audit link has not yet queued as
    /// a summary (a poisoned lock holds nothing that can be delivered).
    fn window_holds_counts(&self) -> bool {
        self.core
            .inspect(SendWindow::suppressed_noise)
            .is_some_and(|counted| counted > 0)
    }

    /// The stop's flush: hand the last counts over and wait, at most
    /// `grace` in all and only while auditd is reachable, for the audit link
    /// to queue them; then the one flush of every daemon
    /// (`ipc_audit_client::AuditGate::close`) with what is left of `grace`
    /// — until the queued summaries are acknowledged or auditd counts as
    /// unreachable (nothing the front sends gates an operation: A-87) —
    /// and `end_link`.
    /// Spec: docs/questions/Q-313 (A-82), Q-350 item 11 (A-87), Q-961 item
    /// 6, Q-988; docs/52 §3.11 R6 (b).
    pub(crate) async fn close<E: Future<Output = ()>>(
        &self,
        grace: Duration,
        end_link: E,
    ) -> Unflushed {
        let start = Instant::now();
        self.hand_over();
        while self.window_holds_counts() && self.core.is_reachable() && start.elapsed() < grace {
            tokio::time::sleep(ipc_audit_client::FLUSH_POLL).await;
        }
        let left = grace.saturating_sub(start.elapsed());
        self.core
            .close(
                left,
                FlushWait::UntilAcknowledgedOrUnreachable,
                tokio::time::sleep,
                end_link,
            )
            .await
    }
}

/// What the front's gate gives the one audit client (task R9b): the shared
/// gate, the wake-up of a hand-over (module documentation), and the front's
/// notes when the link is restored or lost.
/// Spec: docs/52 §3.11 R6, §3.12; docs/questions/Q-500 item 1, Q-512, Q-560
/// item 4.
impl ipc_audit_client::LinkedGate for AuditGate {
    fn audit_gate(&self) -> &ipc_audit_client::AuditGate {
        &self.core
    }

    fn recorded(&self) -> impl Future<Output = ()> + Send + '_ {
        self.handed.notified()
    }

    fn link_restored(&self) {
        note(Note::AuditRestored, None);
    }

    fn link_lost(&self) {
        note(Note::AuditLost, None);
    }
}

/// The summary pace: every [`SUMMARY_PERIOD`], hand the noise counted since
/// to the window (module documentation). Runs until the front aborts it at
/// stop.
/// Spec: A-57; docs/questions/Q-961 item 5, Q-988.
pub(crate) async fn pace_summaries(gate: Arc<AuditGate>) {
    loop {
        tokio::time::sleep(SUMMARY_PERIOD).await;
        gate.hand_over();
    }
}

#[cfg(test)]
mod tests {
    //! Sources: docs/53 §9 (the front's counted cases); A-57 (noise counted,
    //! not recorded per occurrence); docs/questions/Q-961 items 1, 3, 7
    //! (A-160), Q-988 (the reading: which counted cases are noise; the
    //! hand-over). Values are constructed for these tests.
    use super::*;
    use crate::log::{Counters, Failure, Noise};

    fn window_counts(gate: &AuditGate) -> u64 {
        gate.core.inspect(SendWindow::suppressed_noise).unwrap()
    }

    /// Every noise case counts once on the operational log and once for the
    /// window — through the one chokepoint — and reaches the window only at
    /// a hand-over; the operational failures (dird not serving, a failed
    /// accept) reach neither.
    #[test]
    fn noise_reaches_the_window_at_a_hand_over_and_failures_never() {
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
        assert_eq!(gate.counted.load(Ordering::Relaxed), 6);
        assert_eq!(window_counts(&gate), 0, "nothing before the hand-over");
        assert_eq!(gate.hand_over(), 6);
        assert_eq!(
            window_counts(&gate),
            6,
            "the six noise cases, not the two failures"
        );
        assert_eq!(gate.hand_over(), 0, "a hand-over moves each count once");
        assert_eq!(window_counts(&gate), 6);
    }

    /// The counts are kept while auditd is unreachable (a new gate counts
    /// auditd as unreachable until the audit link says otherwise) — noise is
    /// never refused or dropped for it — and the count saturates.
    #[test]
    fn counts_are_kept_unreachable_and_saturate() {
        let gate = AuditGate::new(AUDIT_WINDOW);
        assert!(!gate.core.is_reachable());
        gate.count_noise();
        gate.count_noise();
        assert_eq!(gate.hand_over(), 2);
        assert_eq!(window_counts(&gate), 2);
        gate.counted.store(u64::MAX, Ordering::Relaxed);
        gate.count_noise();
        assert_eq!(gate.counted.load(Ordering::Relaxed), u64::MAX);
    }

    /// A hand-over that moved counts wakes the audit link (a stored wake-up,
    /// so a link busy at that moment still sees it); one that moved nothing
    /// does not.
    #[test]
    fn a_hand_over_with_counts_wakes_the_link() {
        use ipc_audit_client::LinkedGate;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let gate = AuditGate::new(AUDIT_WINDOW);
        gate.hand_over();
        let quiet = runtime.block_on(async {
            tokio::time::timeout(Duration::from_millis(50), gate.recorded()).await
        });
        assert!(quiet.is_err(), "nothing handed over, no wake-up");
        gate.count_noise();
        gate.hand_over();
        let woken = runtime.block_on(async {
            tokio::time::timeout(Duration::from_millis(50), gate.recorded()).await
        });
        assert!(woken.is_ok());
    }
}
