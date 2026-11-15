//! The serial-only zone write (task DN10b; docs/questions/Q-1002, decision
//! A-172): dird advances the zone's SOA SERIAL without a content write —
//! through the **one** commit, with its own audit decision — for the two
//! changes of the zone's content that no commit can see.
//!
//! # The class and the root-level change (AGENTS.md §6.1)
//!
//! **Class — "the zone's content changes while its SERIAL does not"**
//! (docs/questions/Q-993; RFC 2136 §3.6: "If the zone appears to change, the
//! SOA must appear to change as well"). DN6 closed it for every *write*: the
//! one commit takes the `dns-zone-serial` counter for every write that
//! changes the zone. Two instances remained, with no write to hang the take
//! on (Q-1002 item 1): (a) **the clock** — an address reaching
//! `dns_record_max_age`, an account its accountExpires; (b) **a dird
//! restart with other zone values** (RNAME, SOA times, TTLs, registrable
//! networks, the `_kpasswd` switch) — the new process projects other
//! content under the same SERIAL.
//!
//! **The change.** A write whose whole content is the SERIAL: crate
//! `invariants`' `Op::ZoneSerial`, checked by `Invariants::check_zone_serial`
//! and committed by the one `CheckedWrite::commit`, which takes the counter
//! exactly as for a content write (`take_zone_serial`: one take, one more if
//! SERIAL would be 0 — RFC 2136 §7.11). There is still exactly **one**
//! writer of the counter and **one** door to it; dirstore's
//! `take_counter_value` stays reachable only from `invariants` (pinned by
//! `tests/single_write_path.rs`). This module is the public entry dird's DNS
//! service calls ([`ZoneSerialWriter`]), in three steps like every dird state
//! change:
//!
//! 1. [`ZoneSerialWriter::prepare`] — in the caller's `WriteTxn` (begun
//!    first, as for every write — A-89): the zone's current SERIAL (the one
//!    the advance goes past), the counter present and not exhausted; the
//!    `ZoneSerial` decision event (crate ipc-audit — its own shape: the
//!    write has no requester, no object and no PDP decision, and its whole
//!    content is a SERIAL `DirAdmin` has no field for; docs/questions/Q-1013
//!    item 3).
//! 2. The caller has auditd acknowledge the decision
//!    (`ipc_audit_client::AuditGate`): only that proof (`AckedIntent`,
//!    docs/52 R6) opens step 3.
//! 3. [`ZoneSerialWriter::apply`] — the counter is re-verified (moved since
//!    the decision ⇒ the advance is **not needed**: another write already
//!    advanced it — nothing is written, RFC 2136 §7.10: serial numbers are
//!    conserved), then the checked write and the one commit; the new SERIAL
//!    and the outcome event come back. The caller commits its transaction
//!    and sends the outcome.
//!
//! When dird calls it (crates/directory-daemon `dns_service`): once at every
//! DNS service start (instance (b): every image of a new process has a
//! SERIAL after every SERIAL an earlier one served — nothing to remember,
//! nothing to compare), and when the projection's content under the current
//! SERIAL changed with the clock (instance (a)), at most once per bounded
//! interval.
//!
//! # What the write does not do
//!
//! It writes no object, so it takes no change-seq (the change-seq is the
//! `Origin` of an originating object write — docs/29 §2 as cited in docs/51
//! §8.3) and needs no node-id; its commit is still refused if the
//! change-seq moved between its check and its commit (the one commit's
//! basis rule). It decides nothing about any principal: no Subject, no PDP,
//! no plan (A-167 binds the admin plane's operations) — it is dird's own
//! state change, recorded under dird's own source (A-85).
//!
//! Spec: RFC 2136 §3.6, §7.10, §7.11; docs/54 §4.4, §5.4; docs/51 §5.7 item
//! 2; docs/52 §3.11 R6, R13; A-83; A-85; A-170; docs/questions/Q-993 item 3,
//! Q-1002 (A-172), Q-1013.
//!
//! Written only from, opened in this session: AGENT-ONBOARDING, AGENTS,
//! docs/54 (§3.1, §4.4–§4.8, §5, §9, §10), docs/50 §8, docs/questions Q-962,
//! Q-991..Q-994, Q-1000..Q-1004, PENDING-OWNER (A-85, A-119, A-160, A-163,
//! A-167, A-170, A-172), the pinned RFC 2136 §3.6, §7.10, §7.11 (SHA-256
//! verified against tools/spec-pin/manifest.json) and this repository's own
//! code. No other implementation was consulted or recalled (AGENTS.md §1-3).

use core::num::NonZeroU32;
use std::collections::BTreeSet;

use ad_schema::Phase1Schema;
use dirstore::{CounterState, WriteTxn};
use ipc_audit::{
    EventBody, ZoneSerialCause, ZoneSerialEvent, ZoneSerialFailure, ZoneSerialOutcome,
    ZoneSerialStage,
};
use ipc_audit_client::{AckedIntent, IntentRecord};
use krb_proto::KerberosTime;

use crate::config::{ConfigError, DNS_ZONE_SERIAL_COUNTER};
use crate::invariants::{CommitError, Fault, Invariants, Refused};
use crate::time;

/// The door of the serial-only write (module documentation): the one
/// checker, for the phase-1 schema. Holds no zone and no node-id — the
/// write needs neither.
/// Spec: module documentation; docs/questions/Q-1002 item 2 (A-172).
#[derive(Debug, Clone)]
pub struct ZoneSerialWriter {
    invariants: Invariants,
}

/// A serial advance decided (step 1), waiting for auditd's acknowledgement
/// of its decision event. Not `Clone`: one decision, one write.
/// Spec: module documentation; docs/52 §3.11 R6 (a).
#[derive(Debug, PartialEq, Eq)]
pub struct PreparedSerialAdvance {
    /// The counter's state the decision was made on.
    seen: CounterState,
    decision: ZoneSerialEvent,
}

/// What [`ZoneSerialWriter::apply`] did inside the caller's transaction
/// (not yet committed): advanced the serial — the new SERIAL — or found it
/// already advanced (nothing written). Commit the transaction, then send
/// [`AppliedSerialAdvance::outcome_event`] — or, if the commit fails,
/// [`AppliedSerialAdvance::commit_failure_event`].
/// Spec: module documentation; docs/51 §5.7 item 2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedSerialAdvance {
    serial: Option<NonZeroU32>,
    outcome: ZoneSerialEvent,
    commit_failure: ZoneSerialEvent,
}

/// A decided serial advance that was not written: the outcome event to
/// send; the caller aborts its transaction.
/// Spec: docs/51 §5.7 item 2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SerialAdvanceFailed {
    event: ZoneSerialEvent,
}

impl SerialAdvanceFailed {
    /// The `Outcome` event (`Failed`).
    #[must_use]
    pub fn event(&self) -> &ZoneSerialEvent {
        &self.event
    }

    /// Why it failed.
    #[must_use]
    pub fn failure(&self) -> ZoneSerialFailure {
        match self.event.stage {
            ZoneSerialStage::Outcome(ZoneSerialOutcome::Failed(failure)) => failure,
            // Built only with a `Failed` outcome (below).
            ZoneSerialStage::Outcome(_) | ZoneSerialStage::Decision => {
                ZoneSerialFailure::InternalFailure
            }
        }
    }
}

impl PreparedSerialAdvance {
    /// The `Decision` event: what auditd must acknowledge before
    /// [`ZoneSerialWriter::apply`].
    #[must_use]
    pub fn decision_event(&self) -> &ZoneSerialEvent {
        &self.decision
    }

    /// The SERIAL the advance goes past.
    #[must_use]
    pub fn from(&self) -> NonZeroU32 {
        self.decision.from
    }

    /// The `Outcome` event of this decision when it is not written for
    /// `failure` (at `now`) — e.g. auditd did not acknowledge the decision in
    /// time (`AuditUnacknowledged`: docs/51 §5.7 item 2, A-85).
    #[must_use]
    pub fn failure_event(&self, failure: ZoneSerialFailure, now: &KerberosTime) -> ZoneSerialEvent {
        outcome_of(&self.decision, ZoneSerialOutcome::Failed(failure), now)
    }
}

impl IntentRecord for PreparedSerialAdvance {
    /// The `Decision` event (A-85: acknowledged before the write).
    /// Spec: docs/51 §5.7 item 2; docs/52 §3.11 R6 (a).
    fn intent_event(&self) -> EventBody {
        EventBody::ZoneSerial(Box::new(self.decision.clone()))
    }
}

impl AppliedSerialAdvance {
    /// The zone's new SOA SERIAL, or `None` when the advance was not needed
    /// (the counter had moved since the decision; nothing written).
    #[must_use]
    pub fn serial(&self) -> Option<NonZeroU32> {
        self.serial
    }

    /// The `Outcome` event to send once the transaction committed.
    #[must_use]
    pub fn outcome_event(&self) -> &ZoneSerialEvent {
        &self.outcome
    }

    /// The `Outcome` event to send when the transaction's commit failed.
    #[must_use]
    pub fn commit_failure_event(&self) -> &ZoneSerialEvent {
        &self.commit_failure
    }
}

/// The `Outcome` event of `decision`: same number, cause and SERIAL, at
/// `now`.
/// Spec: docs/questions/Q-1013 (one number for a decision and its outcome).
fn outcome_of(
    decision: &ZoneSerialEvent,
    outcome: ZoneSerialOutcome,
    now: &KerberosTime,
) -> ZoneSerialEvent {
    ZoneSerialEvent {
        time: time::calendar(now),
        stage: ZoneSerialStage::Outcome(outcome),
        ..decision.clone()
    }
}

/// The zone's SERIAL of a counter state, if the counter can still be taken:
/// present, not exhausted, and showing a SERIAL (never 0 — crate
/// directory-pip `zone_serial`).
/// Spec: docs/54 §5.4; RFC 2136 §7.11; A-83.
fn current_serial(
    state: Option<CounterState>,
) -> Result<(CounterState, NonZeroU32), ZoneSerialFailure> {
    let state = state.ok_or(ZoneSerialFailure::CounterUnavailable)?;
    if state.is_exhausted() {
        return Err(ZoneSerialFailure::CounterUnavailable);
    }
    let serial = directory_pip::zone_serial(&state)
        .and_then(NonZeroU32::new)
        .ok_or(ZoneSerialFailure::CounterUnavailable)?;
    Ok((state, serial))
}

/// A refusal of the check, as a failure of the write.
fn check_failure(refused: &Refused) -> ZoneSerialFailure {
    match refused {
        Refused::Fault(Fault::Store(_) | Fault::Integrity | Fault::Missing) => {
            ZoneSerialFailure::StoreFailure
        }
        // The serial-only write creates no principal (task PN5): unreachable.
        Refused::Fault(Fault::Namespace) | Refused::Rule(_) => ZoneSerialFailure::InternalFailure,
    }
}

/// A commit failure, as a failure of the write.
fn commit_failure(error: &CommitError) -> ZoneSerialFailure {
    match error {
        CommitError::ZoneSerial(_) => ZoneSerialFailure::CounterUnavailable,
        CommitError::Counter(_) | CommitError::Read(_) | CommitError::Write(_) => {
            ZoneSerialFailure::StoreFailure
        }
        CommitError::Stale
        | CommitError::Rid(_)
        | CommitError::RidRange
        | CommitError::Sid
        | CommitError::ChangeSeq(_)
        | CommitError::Unstamped => ZoneSerialFailure::InternalFailure,
    }
}

impl ZoneSerialWriter {
    /// The door for the phase-1 schema. Fails closed if the schema lacks a
    /// name the checker needs.
    ///
    /// # Errors
    /// [`ConfigError::Schema`].
    ///
    /// Spec: module documentation.
    pub fn new(schema: &Phase1Schema) -> Result<ZoneSerialWriter, ConfigError> {
        Ok(ZoneSerialWriter {
            // No host zone and no principal namespace: the serial-only
            // write writes no object (task PN5: no principal, so no keys).
            invariants: Invariants::new(schema, BTreeSet::new(), None, None)?,
        })
    }

    /// Step 1 (module documentation): decide, in `txn` — begun by the caller
    /// before anything is read, as for every write — to advance the zone's
    /// SERIAL past the current one, for `cause`, as dird's operation
    /// `operation_id`, at `now`. The decision event is the returned value's
    /// intent record.
    ///
    /// # Errors
    /// `CounterUnavailable` (the counter missing or exhausted — A-83: never
    /// created here), `StoreFailure`. Nothing was decided: no event.
    ///
    /// Spec: module documentation; docs/54 §5.4; RFC 2136 §3.6; A-83.
    pub fn prepare(
        &self,
        txn: &WriteTxn<'_>,
        operation_id: u64,
        cause: ZoneSerialCause,
        now: &KerberosTime,
    ) -> Result<PreparedSerialAdvance, ZoneSerialFailure> {
        let state = txn
            .counter(DNS_ZONE_SERIAL_COUNTER)
            .map_err(|_| ZoneSerialFailure::StoreFailure)?;
        let (seen, from) = current_serial(state)?;
        Ok(PreparedSerialAdvance {
            seen,
            decision: ZoneSerialEvent {
                time: time::calendar(now),
                operation_id,
                cause,
                from,
                stage: ZoneSerialStage::Decision,
            },
        })
    }

    /// Step 3 (module documentation): with auditd's acknowledgement of the
    /// decision, write it in `txn`: the counter re-verified — moved since the
    /// decision ⇒ not needed, nothing written —, then the one checker and
    /// the one commit, which takes the zone serial. Commit `txn` on `Ok`; on
    /// `Err` abort it and send the failure's event.
    ///
    /// # Errors
    /// [`SerialAdvanceFailed`] (`StoreFailure`, `CounterUnavailable`,
    /// `InternalFailure`).
    ///
    /// Spec: module documentation; docs/52 §3.11 R6 (a), R13; RFC 2136 §3.6,
    /// §7.10, §7.11; docs/questions/Q-1002 item 2 (A-172).
    pub fn apply(
        &self,
        acked: AckedIntent<PreparedSerialAdvance>,
        txn: &mut WriteTxn<'_>,
        now: &KerberosTime,
    ) -> Result<AppliedSerialAdvance, SerialAdvanceFailed> {
        let PreparedSerialAdvance { seen, decision } = acked.into_inner();
        let failed = |failure| SerialAdvanceFailed {
            event: outcome_of(&decision, ZoneSerialOutcome::Failed(failure), now),
        };
        let commit_failure_event = outcome_of(
            &decision,
            ZoneSerialOutcome::Failed(ZoneSerialFailure::StoreFailure),
            now,
        );
        let current = txn
            .counter(DNS_ZONE_SERIAL_COUNTER)
            .map_err(|_| failed(ZoneSerialFailure::StoreFailure))?;
        if current != Some(seen) {
            // Another write took the counter after the decision: the zone's
            // SERIAL is already past `from` (RFC 2136 §7.10).
            return Ok(AppliedSerialAdvance {
                serial: None,
                outcome: outcome_of(&decision, ZoneSerialOutcome::NotNeeded, now),
                commit_failure: commit_failure_event,
            });
        }
        let checked = self
            .invariants
            .check_zone_serial(txn)
            .map_err(|refused| failed(check_failure(&refused)))?;
        let committed = checked
            .commit(txn, None)
            .map_err(|error| failed(commit_failure(&error)))?;
        let serial = committed
            .zone_serial
            .and_then(NonZeroU32::new)
            .ok_or_else(|| failed(ZoneSerialFailure::InternalFailure))?;
        Ok(AppliedSerialAdvance {
            serial: Some(serial),
            outcome: outcome_of(&decision, ZoneSerialOutcome::Advanced { serial }, now),
            commit_failure: commit_failure_event,
        })
    }
}
