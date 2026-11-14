//! `keyadm destroy-sweep`: run the destroy decisions dird registered (docs/51
//! §6, §9; A-102, docs/52 §4.3).
//!
//! A `Delete` of a user or computer in dird leaves a tombstone (GUID +
//! classes, A-18) and the account's key sets in keyd — unreachable by the
//! KDC (no object ⇒ no handle), but not yet zeroized (docs/51 §9, the
//! "delete" row). Since A-102 dird, after it committed the `Delete`,
//! registers in keyd a **destroy decision** for that GUID (Role::Ldap,
//! `register_decision`, `DestroyKeySet { principal }`). The sweep:
//!
//! 1. **Contact** keyd (`ping`; the client checks keyd's uid before
//!    anything is sent, R50-3).
//! 2. **List** — keyd's `list_destroy_decisions {after}`, page by page: the
//!    pending destroy decisions (id and principal), ascending by id.
//! 3. **Destroy** — for each, `destroy_key_set(decision id)`: keyd destroys
//!    the decided principal's `PrincipalLongterm` and `Service` key sets,
//!    whichever exist (docs/10 §7; A-35). keyd's `Ok` ⇒ **destroyed**;
//!    its uniform `Denied` ⇒ **skipped** (e.g. the decision expired between
//!    the listing and the call — keyd's audit names the reason), and the
//!    sweep goes on; anything else — keyd's `Unavailable` / `RateLimited`,
//!    not sent, not performed, outcome unknown — stops the sweep: **retry
//!    later**. Every step is idempotent: a rerun lists only decisions not yet
//!    executed, and a decision presented again returns its recorded result
//!    (docs/52 §3.10).
//!
//! **keyadm destroys only what dird decided** (docs/52 §3.1, N1/N2): the
//! only key sets it can name are those of decisions keyd holds — no GUID
//! comes from keyadm, admind or any listing outside keyd (the
//! `ListPendingDestruction` forward of task A10 is retired).
//!
//! The listing is bounded: each page's cursor must move strictly forward,
//! and at most [`MAX_PAGES`] pages are read — a peer that loops is refused
//! (fail closed, AGENTS.md §6).
//!
//! Spec: docs/51 §6, §9; docs/52 §3.1, §4.2, §4.3, §4.6; docs/10 §7, §9;
//! A-18; A-35; A-88; A-90; A-102.

use crate::ceremony::{classify, Outcome};
use crate::ports::KeydPort;
use ipc_keyd::{Answer, Call};
use keyd_types::{
    DecisionId, DestructionPage, Error as KeydError, PendingDestruction, MAX_DESTROY_DECISIONS,
    MAX_DESTROY_DECISION_PAGE,
};

/// Most pages one sweep reads: enough for every destroy decision keyd can
/// hold ([`MAX_DESTROY_DECISIONS`] in pages of [`MAX_DESTROY_DECISION_PAGE`])
/// plus one. Project bound (AGENTS.md §6).
pub const MAX_PAGES: usize = MAX_DESTROY_DECISIONS.div_ceil(MAX_DESTROY_DECISION_PAGE) + 1;

/// Why the sweep stopped before the end.
/// Spec: module documentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stopped {
    /// keyd did not answer a listing with a page (its refusal, or the
    /// request's fate).
    Listing(Outcome<()>),
    /// The listing did not move forward, or exceeded [`MAX_PAGES`].
    ListingLooped,
    /// A `destroy_key_set` was not done: retry later.
    RetryLater {
        /// The decision.
        entry: PendingDestruction,
        /// How the call ended.
        outcome: Outcome<()>,
    },
}

/// What one sweep did.
/// Spec: module documentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SweepReport {
    /// The `ping` that opened (and verified) keyd's connection.
    pub contact: Outcome<()>,
    /// Pending destroy decisions listed.
    pub listed: usize,
    /// Decisions keyd ran now (keyd answered `Ok`: no key set of the
    /// principal is left).
    pub destroyed: Vec<PendingDestruction>,
    /// Decisions keyd refused (its uniform `Denied`), skipped.
    pub skipped: Vec<PendingDestruction>,
    /// Why the sweep stopped, if it did not finish.
    pub stopped: Option<Stopped>,
}

impl SweepReport {
    /// The sweep went through the whole listing.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.contact.succeeded() && self.stopped.is_none()
    }

    /// A `destroy_key_set` was sent (whatever came of it).
    #[must_use]
    pub fn keyd_attempted(&self) -> bool {
        !self.destroyed.is_empty()
            || !self.skipped.is_empty()
            || matches!(
                self.stopped,
                Some(Stopped::RetryLater {
                    outcome: Outcome::Answered(_) | Outcome::NotPerformed(_) | Outcome::Unknown(_),
                    ..
                })
            )
    }
}

/// The same outcome without its success value (a listing that failed has
/// none to keep).
fn without_value<T>(outcome: Outcome<T>) -> Outcome<()> {
    match outcome {
        Outcome::Answered(result) => Outcome::Answered(result.map(|_| ())),
        Outcome::NotSent(reason) => Outcome::NotSent(reason),
        Outcome::NotPerformed(refused) => Outcome::NotPerformed(refused),
        Outcome::Unknown(reason) => Outcome::Unknown(reason),
    }
}

/// One page of the listing, or why there is none.
/// Spec: docs/52 §4.6.
fn list(keyd: &mut dyn KeydPort, after: Option<DecisionId>) -> Result<DestructionPage, Stopped> {
    let outcome = classify(
        keyd.call_with_fate(&Call::ListDestroyDecisions { after }),
        |answer| match answer {
            Answer::ListDestroyDecisions(result) => Some(result),
            _ => None,
        },
    );
    match outcome {
        Outcome::Answered(Ok(page)) => Ok(page),
        other => Err(Stopped::Listing(without_value(other))),
    }
}

/// Run the sweep (module documentation). Never retries a call.
///
/// Spec: docs/51 §6, §9; docs/52 §4.2, §4.3; docs/10 §7; A-35; A-88; A-90.
pub fn run(keyd: &mut dyn KeydPort) -> SweepReport {
    let contact = classify(keyd.call_with_fate(&Call::Ping), |answer| match answer {
        Answer::Ping(result) => Some(result),
        _ => None,
    });
    let mut report = SweepReport {
        contact,
        listed: 0,
        destroyed: Vec::new(),
        skipped: Vec::new(),
        stopped: None,
    };
    if !report.contact.succeeded() {
        return report;
    }
    let mut after: Option<DecisionId> = None;
    for _ in 0..MAX_PAGES {
        let page = match list(keyd, after) {
            Ok(page) => page,
            Err(stopped) => {
                report.stopped = Some(stopped);
                return report;
            }
        };
        for entry in &page.entries {
            report.listed += 1;
            let outcome = classify(
                keyd.call_with_fate(&Call::DestroyKeySet {
                    decision: entry.decision,
                }),
                |answer| match answer {
                    Answer::DestroyKeySet(result) => Some(result),
                    _ => None,
                },
            );
            match outcome {
                Outcome::Answered(Ok(())) => report.destroyed.push(*entry),
                Outcome::Answered(Err(KeydError::Denied)) => report.skipped.push(*entry),
                other => {
                    report.stopped = Some(Stopped::RetryLater {
                        entry: *entry,
                        outcome: other,
                    });
                    return report;
                }
            }
        }
        match page.next {
            None => return report,
            Some(next) => {
                // The cursor moves strictly forward (decision ids ascend).
                if after.is_some_and(|after| next <= after) {
                    report.stopped = Some(Stopped::ListingLooped);
                    return report;
                }
                after = Some(next);
            }
        }
    }
    report.stopped = Some(Stopped::ListingLooped);
    report
}
