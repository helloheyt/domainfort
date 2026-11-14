//! The re-registration of destroy decisions keyd lost (decision A-105,
//! docs/questions/Q-470 item 4).
//!
//! # The problem
//!
//! dird registers a `DestroyKeySet` decision in keyd after each committed
//! `Delete` of a user or computer (docs/52 §4.3, crate::admin_engine step
//! 8b); keyadm's `destroy-sweep` runs it. A registration that failed (keyd
//! down at the `Delete`) or a decision keyd lost (keyd's table is memory
//! only — every keyd start loses it) would leave the account's key sets
//! orphaned: unreachable (no object ⇒ no handle, docs/51 §9), but never
//! zeroized — forever, once keyd's key store persists (P-17).
//!
//! # One run (bounded)
//!
//! At the admin service's start and every
//! `AdminParams::destroy_reconcile_interval`, between jobs on the admin
//! thread (the admin service's one keyd client):
//!
//! 1. **The candidates** — dird's tombstones of the `user` class (users and
//!    computers, `DirectoryAdmin::destruction_targets`), from where the last
//!    run stopped, at most [`MAX_PAGES_PER_RUN`] pages of
//!    [`TOMBSTONE_PAGE`], at most [`MAX_REGISTRATIONS_PER_RUN`] of them, and
//!    none already **settled** (below). No candidate ⇒ nothing is asked of
//!    keyd.
//! 2. **keyd's pending destroy decisions** — `list_destroy_decisions`
//!    (Role::Ldap since task R6), every page (bounded as keyadm's sweep
//!    bounds it): a candidate whose principal has a pending decision is left
//!    alone (keyadm will run it) — no duplicate.
//! 3. **Register** each other candidate's decision
//!    (`DecisionRegistration::of_tombstone`) under its **stable id**
//!    (crate::registration `destroy_decision_id`). keyd answers from its
//!    **key store** (R6b): while the principal still has a key set the
//!    registration is accepted — a pending decision, new or the identical
//!    one (A-105) — and the candidate was **re-registered**; when it has
//!    none, keyd refuses (its uniform `Denied`, `KeyNotFound` in its own
//!    record): the destruction is **complete** — the candidate is
//!    **settled**, and nothing is scheduled.
//!
//! keyd unreachable, a listing that fails, a registration not performed or
//! with an unknown outcome, or keyd's table full ⇒ the run stops where it
//! is (a log note); the next run starts from the same place. keyd's
//! `Denied` settles the candidate whatever its reason — no key set left (the
//! normal end), or another decision holding the id (a GUID-halves collision,
//! docs/questions/Q-501 item 3): nothing dird can register would change it;
//! keyd's record names which.
//!
//! **How dird learns "complete"** (docs/questions/Q-501 decision, R6b;
//! Q-520): from keyd's key store, through the refusal — not from dird's
//! memory, and not from the executed decision keyd keeps for a replay (a
//! table entry, memory only, gone after 7 days or a keyd start). The
//! **settled** set below is a bounded cache that spares keyd a registration
//! per run; it is not the source of truth: after a dird restart (cache
//! empty) each tombstone keyd already destroyed is registered once, refused,
//! and settled again — no destroy decision is scheduled, nothing is left
//! for keyadm's `destroy-sweep`.
//!
//! keyd records every registration and listing (intent and outcome for a
//! registration, A-88); dird logs how many decisions a run re-registered.
//!
//! Spec: docs/52 §3.10 (a), §4.2, §4.3 ("`RegisterPendingDestructions` —
//! dird registers for every tombstone of a user/computer, page by page …
//! harmless by construction"), §4.6, §4.7; docs/51 §6, §9; A-18; A-102;
//! A-105; A-107; docs/questions/Q-470, Q-471 items 3, 5, Q-501 (items 4–5
//! and the decision: R6b), Q-503, Q-520.

use crate::admin_engine::AdminWorker;
use crate::admin_service::RegistrationFailure;
use crate::log::{note, Note};
use crate::registration::DecisionRegistration;
use directory_admin::TombstonedPrincipal;
use dtyp::Guid;
use keyd_types::{
    DecisionId, Error as KeydError, PrincipalId, MAX_DESTROY_DECISIONS, MAX_DESTROY_DECISION_PAGE,
};
use std::collections::BTreeSet;
use std::sync::Arc;

/// Tombstones of any class one page of the candidate listing may hold
/// (dirstore caps a page and the records one call examines itself).
/// Project choice (docs/questions/Q-501).
pub const TOMBSTONE_PAGE: usize = 256;

/// Pages of the candidate listing one run reads. Project choice
/// (docs/questions/Q-501).
pub const MAX_PAGES_PER_RUN: usize = 4;

/// Registrations one run sends at most (each is a keyd round trip with an
/// acknowledged intent, A-88, on the admin thread). Project choice
/// (docs/questions/Q-501).
pub const MAX_REGISTRATIONS_PER_RUN: usize = 32;

/// Settled tombstones remembered at most; past it the memory starts again
/// empty (the cost: one more registration each, which keyd refuses — R6b).
/// Project bound (AGENTS.md §6).
pub const MAX_SETTLED: usize = 4096;

/// Pages of keyd's pending destroy decisions one listing reads at most:
/// every decision keyd can hold, plus one (the bound keyadm's sweep uses).
/// Spec: keyd-types `MAX_DESTROY_DECISIONS`, `MAX_DESTROY_DECISION_PAGE`.
const MAX_LISTING_PAGES: usize = MAX_DESTROY_DECISIONS.div_ceil(MAX_DESTROY_DECISION_PAGE) + 1;

/// Why a run stopped early: the class of its log note.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stop {
    /// keyd's listing failed.
    Listing = 1,
    /// A registration was not performed, or its outcome is unknown.
    NotRegistered = 2,
    /// keyd refused one as unavailable (its destroy family full) or
    /// throttled.
    KeydUnavailable = 3,
    /// The tombstones could not be read.
    Tombstones = 4,
}

/// The re-registration state of the admin thread (module documentation).
/// Spec: A-105; docs/questions/Q-470 item 4, Q-501.
#[derive(Debug, Default)]
pub(crate) struct Reconciler {
    /// Where the candidate listing resumes; `None`: from the first
    /// tombstone.
    cursor: Option<Guid>,
    /// Tombstones keyd refused a destroy decision for — no key set left
    /// (R6b), or the id held by another decision: not registered again by
    /// this run of dird. A bounded cache, not the source of truth (module
    /// documentation).
    settled: BTreeSet<Guid>,
}

impl Reconciler {
    /// Nothing settled yet; the first run starts at the first tombstone.
    pub(crate) fn new() -> Reconciler {
        Reconciler::default()
    }

    /// One run (module documentation). Never fails: a stop is noted and the
    /// next run resumes from the same place.
    /// Spec: A-105; docs/52 §4.3; docs/questions/Q-501 (R6b).
    pub(crate) fn run(&mut self, worker: &mut AdminWorker) {
        let mut reregistered: usize = 0;
        let (candidates, resume) = match self.candidates(worker) {
            Ok(found) => found,
            Err(stop) => {
                note(Note::AdminDestroyReconcileStopped, Some(stop as u64));
                return;
            }
        };
        if candidates.is_empty() {
            self.cursor = resume;
            return;
        }
        let Some(pending) = pending_principals(worker) else {
            note(
                Note::AdminDestroyReconcileStopped,
                Some(Stop::Listing as u64),
            );
            return;
        };
        let mut stopped = None;
        for target in candidates {
            if pending.contains(&target.principal()) {
                continue;
            }
            match worker
                .verifier
                .register_decision(DecisionRegistration::of_tombstone(&target))
            {
                // keyd accepted: the principal still has a key set, so the
                // decision is pending (an executed one leaves no key set,
                // and nothing recreates a tombstone's) — re-registered.
                Ok(()) => reregistered += 1,
                // keyd refused from its key store: no key set left — the
                // destruction is complete (R6b), and stays so: every
                // registration (the `Delete`'s first) also discarded any live
                // set-secret decision for the principal, so none can be
                // created later — or the id is another decision's; either way
                // there is nothing to register.
                Err(RegistrationFailure::Refused(KeydError::Denied)) => {
                    self.settle(target.guid());
                }
                Err(RegistrationFailure::Refused(_)) => {
                    stopped = Some(Stop::KeydUnavailable);
                    break;
                }
                Err(RegistrationFailure::NotPerformed | RegistrationFailure::OutcomeUnknown) => {
                    stopped = Some(Stop::NotRegistered);
                    break;
                }
            }
        }
        if reregistered > 0 {
            note(
                Note::AdminDestroyReregistered,
                u64::try_from(reregistered).ok(),
            );
        }
        match stopped {
            // Resume where this run started: the candidates not reached are
            // examined again (the ones done are pending or settled now).
            Some(stop) => note(Note::AdminDestroyReconcileStopped, Some(stop as u64)),
            None => self.cursor = resume,
        }
    }

    /// Step 1: the tombstoned users and computers not settled, from the
    /// cursor, bounded; and where the next run resumes.
    /// Spec: docs/52 §4.3; directory-admin `destruction_targets`.
    fn candidates(
        &self,
        worker: &AdminWorker,
    ) -> Result<(Vec<TombstonedPrincipal>, Option<Guid>), Stop> {
        let store = Arc::clone(&worker.store);
        let view = worker
            .ctx
            .view(&store, &worker.tiers)
            .map_err(|_| Stop::Tombstones)?;
        let mut candidates = Vec::new();
        let mut after = self.cursor;
        for _ in 0..MAX_PAGES_PER_RUN {
            let page = worker
                .admin
                .destruction_targets(&view, after, TOMBSTONE_PAGE)
                .map_err(|_| Stop::Tombstones)?;
            for target in page.targets {
                if self.settled.contains(&target.guid()) {
                    continue;
                }
                if candidates.len() == MAX_REGISTRATIONS_PER_RUN {
                    // Resume strictly after the last candidate taken.
                    let resume = candidates.last().map(TombstonedPrincipal::guid);
                    return Ok((candidates, resume));
                }
                candidates.push(target);
            }
            match page.next {
                // The listing is complete: the next run starts over.
                None => return Ok((candidates, None)),
                Some(next) => {
                    // The listing moves strictly forward (GUID order).
                    if after.is_some_and(|after| next.to_packet() <= after.to_packet()) {
                        return Err(Stop::Tombstones);
                    }
                    after = Some(next);
                }
            }
        }
        Ok((candidates, after))
    }

    /// Remember a settled tombstone (bounded: past [`MAX_SETTLED`] the
    /// memory starts again).
    fn settle(&mut self, guid: Guid) {
        if self.settled.len() >= MAX_SETTLED {
            self.settled.clear();
        }
        self.settled.insert(guid);
    }
}

/// Step 2: the principals of keyd's pending destroy decisions, every page;
/// `None` when a page did not come or the listing did not move forward.
/// Spec: docs/52 §4.6; keyd `list_destroy_decisions` (ascending ids).
fn pending_principals(worker: &mut AdminWorker) -> Option<BTreeSet<PrincipalId>> {
    let mut principals = BTreeSet::new();
    let mut after: Option<DecisionId> = None;
    for _ in 0..MAX_LISTING_PAGES {
        let page = worker.verifier.list_destroy_decisions(after)?;
        principals.extend(page.entries.iter().map(|entry| entry.principal));
        match page.next {
            None => return Some(principals),
            Some(next) => {
                if after.is_some_and(|after| next <= after) {
                    return None;
                }
                after = Some(next);
            }
        }
    }
    None
}
