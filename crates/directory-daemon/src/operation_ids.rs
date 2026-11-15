//! dird's operation numbers: one counter for every thread that decides an
//! audited operation — the admin thread and the kpasswd thread (task K7).
//!
//! # The class (AGENTS.md §6.1)
//!
//! An operation number is the `operation_id` of the operation's `DirAdmin`
//! events (Q-340 item 1: a decision and its outcome carry the same number)
//! **and** the id of the decision dird registers in keyd after a committed
//! password write (`DecisionId::new(operation_id)` — a `BeginPasswordSet`'s
//! `SetSecret`, a `ChangePassword`'s `ChangePassword`; both of keyd's
//! set-secret family, one id space — keyd-types `decision.rs`). Two threads
//! numbering on their own would give two decisions one id: keyd would
//! refuse the second (`DecisionConflict`) and two events would share a
//! number. **Root option taken:** one counter, shared — two numbers are
//! never equal, whichever thread draws them.
//!
//! # The first number
//!
//! The start's DSTIME seconds × 2^20 + 1 (as the admin thread numbered
//! before task K7), so the numbers of two runs do not overlap unless one run
//! performs a million operations per second it lasted. Project choice
//! (docs/questions/Q-388 item 4).
//!
//! Spec: docs/52 §4.2 (`DecisionId(u64)`, dird's to assign); docs/questions
//! Q-340 item 1, Q-388 item 4; docs/53 §5.6 step 5.

use crate::clock::SharedClock;
use std::sync::atomic::{AtomicU64, Ordering};

/// Operation numbers per second of the start time (2^20). Project choice
/// (docs/questions/Q-388 item 4).
const OPERATION_ID_SHIFT: u32 = 20;

/// The shared counter (module documentation).
#[derive(Debug)]
pub(crate) struct OperationIds(AtomicU64);

impl OperationIds {
    /// Numbers following `clock`'s start (module documentation); 0 if the
    /// clock cannot say (the first number is then 1).
    /// Spec: docs/questions/Q-388 item 4.
    pub(crate) fn starting_at(clock: &SharedClock) -> OperationIds {
        let first = clock
            .now()
            .and_then(|now| directory_admin::wall_clock(&now))
            .map_or(0, |seconds| seconds.0.wrapping_shl(OPERATION_ID_SHIFT));
        OperationIds(AtomicU64::new(first))
    }

    /// The next number — never one any thread drew before.
    /// Spec: module documentation.
    pub(crate) fn next(&self) -> u64 {
        self.0.fetch_add(1, Ordering::SeqCst).wrapping_add(1)
    }
}
