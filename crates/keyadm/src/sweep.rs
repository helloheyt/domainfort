//! `keyadm destroy-sweep`: destroy the key sets of deleted accounts (docs/51
//! §6, §9; task A10).
//!
//! A `Delete` in dird leaves a tombstone (GUID + classes, A-18) and the
//! account's key sets in keyd — unreachable by the KDC (no object ⇒ no
//! handle), but not yet zeroized (docs/51 §9, the "delete" row). The sweep:
//!
//! 1. **Contact** keyd (`ping`; the client checks keyd's uid before
//!    anything is sent, R50-3).
//! 2. **List** — `ListPendingDestruction {cursor}` to `admin.sock` (admind
//!    forwards it only from `keyadm_uid`), page by page: the tombstones of
//!    users and computers. Phase 1 never purges a tombstone, so every sweep
//!    sees every deleted account (docs/51 §9).
//! 3. **Destroy** — for each, `destroy_key_set` on `(GUID,
//!    PrincipalLongterm)` and `(GUID, Service)` (docs/10 §7; A-35). keyd's
//!    `Ok` or its uniform `Denied` (an unknown handle — already destroyed,
//!    or never created, e.g. a user's `Service` — docs/10 §7) counts as
//!    **done**; anything else — keyd's `Unavailable` / `RateLimited`, not
//!    sent, not performed, outcome unknown — stops the sweep: **retry
//!    later**. Every step is idempotent, so a rerun picks up where this one
//!    stopped (and a sweep after a complete one destroys nothing: every
//!    call is `Denied`).
//!
//! No approval is needed: the sweep only clears key sets of objects already
//! deleted under a PDP decision in dird (docs/51 §6).
//!
//! The listing is bounded: each page's cursor must move strictly forward
//! (GUID packets ascend), and at most [`MAX_PAGES`] pages are read — a
//! peer that loops is refused (fail closed, AGENTS.md §6).
//!
//! Spec: docs/51 §6, §9; docs/10 §7, §9; A-18; A-35; A-88; A-90.

use crate::ceremony::{classify, Outcome};
use crate::ports::{AdmindPort, KeydPort};
use dtyp::Guid;
use ipc_admin::{AdmindFailure, RefusalStatus, Reply, Request};
use ipc_dird_admin::{DestructionEntry, KeyadmRequest};
use ipc_keyd::{Answer, Call};
use keyd_types::{Error as KeydError, KeyHandle, KeyPurpose, PrincipalId};

/// Most pages one sweep reads (each ≤ 256 entries: up to 2^24 accounts).
/// Project bound (AGENTS.md §6).
pub const MAX_PAGES: usize = 65_536;

/// The two purposes of an account's key sets, in the order destroyed.
/// Spec: docs/51 §6 ("`(GUID, PrincipalLongterm)` and `(GUID, Service)`");
/// docs/47 §9.1.
pub const PURPOSES: [KeyPurpose; 2] = [KeyPurpose::PrincipalLongterm, KeyPurpose::Service];

/// Why the sweep stopped before the end.
/// Spec: module documentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stopped {
    /// The listing was refused (status) — e.g. this account is not
    /// `keyadm_uid` (`Denied`).
    ListingRefused(RefusalStatus),
    /// admind did not answer a listing usably.
    ListingFailed(AdmindFailure),
    /// The listing did not move forward, or exceeded [`MAX_PAGES`].
    ListingLooped,
    /// A `destroy_key_set` was not done: retry later.
    RetryLater {
        /// The account.
        guid: Guid,
        /// The key set's purpose.
        purpose: KeyPurpose,
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
    /// Tombstones of users / computers listed.
    pub accounts: usize,
    /// Key sets destroyed now (keyd answered `Ok`).
    pub destroyed: Vec<(Guid, KeyPurpose)>,
    /// Key sets keyd did not know (its uniform `Denied`: destroyed earlier
    /// or never created) — done.
    pub absent: usize,
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
            || self.absent > 0
            || matches!(
                self.stopped,
                Some(Stopped::RetryLater {
                    outcome: Outcome::Answered(_) | Outcome::NotPerformed(_) | Outcome::Unknown(_),
                    ..
                })
            )
    }
}

/// One page of the listing, or why there is none.
fn list(
    admind: &mut dyn AdmindPort,
    cursor: Option<Guid>,
) -> Result<(Vec<DestructionEntry>, Option<Guid>), Stopped> {
    match admind.call(&Request::Keyadm(KeyadmRequest::ListPendingDestruction {
        cursor,
    })) {
        Ok(Reply::PendingDestruction(page)) => Ok((page.entries, page.next)),
        Ok(Reply::Refused(status)) => Err(Stopped::ListingRefused(status)),
        // The client checks the reply answers the request: unreachable.
        Ok(_) => Err(Stopped::ListingRefused(RefusalStatus::OutcomeUnknown)),
        Err(failure) => Err(Stopped::ListingFailed(failure)),
    }
}

/// Run the sweep (module documentation). Never retries a call.
///
/// Spec: docs/51 §6, §9; docs/10 §7; A-35; A-88; A-90.
pub fn run(admind: &mut dyn AdmindPort, keyd: &mut dyn KeydPort) -> SweepReport {
    let contact = classify(keyd.call_with_fate(&Call::Ping), |answer| match answer {
        Answer::Ping(result) => Some(result),
        _ => None,
    });
    let mut report = SweepReport {
        contact,
        accounts: 0,
        destroyed: Vec::new(),
        absent: 0,
        stopped: None,
    };
    if !report.contact.succeeded() {
        return report;
    }
    let mut cursor: Option<Guid> = None;
    for _ in 0..MAX_PAGES {
        let (entries, next) = match list(admind, cursor) {
            Ok(page) => page,
            Err(stopped) => {
                report.stopped = Some(stopped);
                return report;
            }
        };
        for entry in &entries {
            report.accounts += 1;
            // A user has no `Service` key set; asking is harmless (keyd's
            // uniform `Denied` counts as done) and keeps one rule for both
            // kinds (the entry's kind is reported, not relied on).
            for purpose in PURPOSES {
                let handle =
                    KeyHandle::new(PrincipalId::from_bytes(entry.guid.to_packet()), purpose);
                let outcome = classify(
                    keyd.call_with_fate(&Call::DestroyKeySet { handle }),
                    |answer| match answer {
                        Answer::DestroyKeySet(result) => Some(result),
                        _ => None,
                    },
                );
                match outcome {
                    Outcome::Answered(Ok(())) => report.destroyed.push((entry.guid, purpose)),
                    Outcome::Answered(Err(KeydError::Denied)) => report.absent += 1,
                    other => {
                        report.stopped = Some(Stopped::RetryLater {
                            guid: entry.guid,
                            purpose,
                            outcome: other,
                        });
                        return report;
                    }
                }
            }
        }
        match next {
            None => return report,
            Some(next) => {
                // The cursor moves strictly forward (GUID packets ascend).
                if cursor.is_some_and(|c| next.to_packet() <= c.to_packet()) {
                    report.stopped = Some(Stopped::ListingLooped);
                    return report;
                }
                cursor = Some(next);
            }
        }
    }
    report.stopped = Some(Stopped::ListingLooped);
    report
}
