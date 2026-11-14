//! The admin thread: one dedicated OS thread runs the write PEP
//! (crate directory-admin) over dird's store, fed through its own bounded
//! queue (docs/51 §7.5: "an admin thread in dird with a bounded queue (full
//! ⇒ `Busy`); writes serialized (dirstore's single writer)").
//!
//! # One request (docs/51 §7.4, as A-89 fixed the order)
//!
//! 0. `now` from dird's clock; the audit slots — two for a write (decision
//!    and outcome), one for an operation that commits nothing — reserved
//!    with auditd reachable, all or none; otherwise the operation is
//!    answered `Unavailable` and nothing is done (no keyd call, no write):
//!    "auditd unavailable ⇒ the operation is refused before any commit"
//!    (A-85). Every `DirAdmin` event is gating (Q-340 item 8).
//! 1. **Verify the AP-REQs through keyd** (Role::Ldap,
//!    `open_and_verify_service_ticket` on the admin service's key set) —
//!    the requester's, then each approval's. keyd unreachable ⇒
//!    `Unavailable` (A-56); any other failure ⇒ the uniform `Denied`
//!    (A-26) — `DirectoryAdmin::refuse_unverified` plans the refusal event.
//! 2. **Begin the `WriteTxn`** (for a write) — dird's admin thread is the
//!    only runtime writer, and beginning first makes the view the
//!    transaction's starting state (Q-358 item 1).
//! 3. **Take the view** (one snapshot + the tier map of the loaded policy).
//! 4. **`prepare`** — every check of the PEP; a refusal carries its
//!    `Decision` event. The `RateLimit` / `Constrain` obligations of the
//!    requester's Allow are honoured here (docs/11 §2; Q-358 item 7).
//! 5. **The decision event, acknowledged**: committed into its slot, and
//!    the thread waits (bounded) until auditd acknowledged it — persisted it.
//!    No acknowledgement in time ⇒ the transaction is aborted, the outcome
//!    slot records the operation as not performed, and the answer is
//!    `Unavailable`.
//! 6. **`apply`** inside the transaction (it re-verifies what could have
//!    changed); a refusal ⇒ abort, its `Outcome` event.
//! 7. **Commit.**
//! 8. **The outcome event** (`Committed`), or `commit_failure_event` when
//!    the commit failed — into the slot reserved in step 0, so it is never
//!    refused for want of room.
//! 9. **Reply.**
//!
//! An operation that commits nothing (`Lookup`, `CompletePasswordSet`) has
//! its decision event only, committed into the window before the reply
//! (the LDAP rule, A-64/A-70: "commit, then reply").
//!
//! Every refusal sends its event (into the reserved slot) before the reply.
//! AP-REQ octets are never logged; the thread logs fixed notes only.
//!
//! Spec: docs/51 §5.7 (R51-12), §7.4, §7.5; A-26; A-56; A-73; A-85; A-89
//! (docs/questions/Q-358 items 1, 7); docs/50 R50-7, §3.6; docs/questions/
//! Q-388.

use crate::admin_service::{pep_operation, wire_reply, wire_status, TicketVerifier};
use crate::clock::SharedClock;
use crate::engine::{EngineError, EngineThread, OnExit, SubmitError};
use crate::ldap_audit::AuditGate;
use crate::log::{Note, Thinned};
use crate::rate::ObligationLimiter;
use core::time::Duration;
use directory_admin::{
    DirectoryAdmin, Operation as PepOperation, OsRandom, Prepared, Request as PepRequest,
    VerificationFailure, VerifiedTicket,
};
use directory_pip::{DirectoryContext, TierMap};
use dirstore::{Store, WriteTxn};
use ipc_audit::{
    AdminFailure, AdminRefusal, DecisionResult, DirAdminEvent, DirAdminStage, OutcomeResult,
    Reservation,
};
use ipc_dird_admin::{Auth, Operation, RefusalStatus, Reply};
use keyd_types::{AuthnError, KeyHandle};
use krb_proto::KerberosTime;
use ldap::RateLimiter;
use pdp::{Constraint, Obligation, PolicySnapshot};
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::oneshot;

/// Operations answered `Unavailable` because auditd could not take their
/// events (thinned log).
static AUDIT_UNAVAILABLE: Thinned = Thinned::new(Note::AdminAuditUnavailable);
/// Outcome events that could not be committed after a commit (thinned log;
/// cannot happen for events built from ipc-audit's types).
static OUTCOME_UNRECORDED: Thinned = Thinned::new(Note::AdminOutcomeUnrecorded);

/// Operation numbers per second of the start time (2^20): the first number
/// of a run is the start's DSTIME seconds × 2^20 + 1, so the numbers of two
/// runs do not overlap unless one run performs a million operations per
/// second it lasted. Project choice (docs/questions/Q-388 item 4).
const OPERATION_ID_SHIFT: u32 = 20;

/// One job for the admin thread.
/// Spec: docs/51 §7.5; docs/50 R50-7.
pub(crate) struct AdminJob {
    auth: Auth,
    operation: Operation,
    reply: oneshot::Sender<Reply>,
}

/// The sending side of the admin queue; one clone per connection task.
#[derive(Debug, Clone)]
pub(crate) struct AdminEngineHandle {
    queue: SyncSender<AdminJob>,
}

impl AdminEngineHandle {
    /// Queue one request without waiting: a full queue is
    /// [`SubmitError::Busy`].
    /// Spec: docs/51 §7.5 ("full ⇒ `Busy`"); docs/50 R50-7.
    pub(crate) fn submit(
        &self,
        auth: Auth,
        operation: Operation,
    ) -> Result<oneshot::Receiver<Reply>, SubmitError> {
        let (reply, answer) = oneshot::channel();
        match self.queue.try_send(AdminJob {
            auth,
            operation,
            reply,
        }) {
            Ok(()) => Ok(answer),
            Err(TrySendError::Full(_)) => Err(SubmitError::Busy),
            Err(TrySendError::Disconnected(_)) => Err(SubmitError::Stopped),
        }
    }
}

/// What the admin thread owns.
/// Spec: docs/51 §7.4, §7.5; A-73.
pub(crate) struct AdminWorker {
    /// The store (shared; this thread is its only writer at run time).
    pub(crate) store: Arc<Store>,
    /// The directory context (A-53).
    pub(crate) ctx: DirectoryContext,
    /// The tier map of the loaded policy.
    pub(crate) tiers: TierMap,
    /// The PDP snapshot of the same policy (docs/47 §8.1).
    pub(crate) policy: PolicySnapshot,
    /// The write PEP.
    pub(crate) admin: DirectoryAdmin<OsRandom>,
    /// keyd, Role::Ldap.
    pub(crate) verifier: Box<dyn TicketVerifier>,
    /// The admin service's key set.
    pub(crate) service: KeyHandle,
    /// The shared audit gate.
    pub(crate) gate: Arc<AuditGate>,
    /// dird's clock.
    pub(crate) clock: SharedClock,
    /// How long a decision event may wait for its acknowledgement.
    pub(crate) ack_deadline: Duration,
}

/// The running state of the admin thread.
struct Running {
    worker: AdminWorker,
    next_operation: u64,
    rate: ObligationLimiter,
}

/// An event with another stage (the request-derived fields kept): used for
/// the three cases the PEP has no planner for — a store failure before
/// `prepare`, an obligation that refuses, a decision auditd did not
/// acknowledge (docs/questions/Q-388 items 1-2).
fn restage(event: &DirAdminEvent, stage: DirAdminStage) -> DirAdminEvent {
    let mut event = event.clone();
    event.stage = stage;
    event
}

impl Running {
    /// The next operation number (Q-340 item 1).
    fn next_id(&mut self) -> u64 {
        self.next_operation = self.next_operation.wrapping_add(1);
        self.next_operation
    }

    /// Commit `event` into `slot`; the sequence number, or `None`.
    fn commit(&self, slot: Option<Reservation>, event: &DirAdminEvent) -> Option<u64> {
        slot.and_then(|slot| self.worker.gate.commit_admin(slot, event).ok())
    }

    /// Give a slot back.
    fn release(&self, slot: Option<Reservation>) {
        if let Some(slot) = slot {
            self.worker.gate.release(slot);
        }
    }

    /// A refusal before any write: its event into the first slot, the
    /// second given back, the status answered (or `Unavailable` if the
    /// event could not be committed — no answer leaves unaudited).
    /// Spec: docs/51 §7.4; A-85.
    fn refuse(
        &self,
        first: Option<Reservation>,
        second: Option<Reservation>,
        event: &DirAdminEvent,
        status: RefusalStatus,
    ) -> Reply {
        self.release(second);
        match self.commit(first, event) {
            Some(_) => Reply::Refused(status),
            None => Reply::Refused(RefusalStatus::Unavailable),
        }
    }

    /// Step 1: the requester's AP-REQ, then each approval's, through keyd.
    /// Spec: docs/51 §7.4 step 1; A-26; A-56; A-73.
    fn verify(
        &mut self,
        auth: &Auth,
    ) -> Result<(VerifiedTicket, Vec<VerifiedTicket>), VerificationFailure> {
        let service = self.worker.service;
        let requester = self
            .worker
            .verifier
            .verify(&service, &auth.requester)
            .map_err(|e| match e {
                AuthnError::Unavailable => VerificationFailure::KeydUnavailable,
                _ => VerificationFailure::Requester,
            })?;
        let mut approvals = Vec::with_capacity(auth.approvals.len());
        for approval in &auth.approvals {
            let context = self
                .worker
                .verifier
                .verify(&service, approval)
                .map_err(|e| match e {
                    AuthnError::Unavailable => VerificationFailure::KeydUnavailable,
                    _ => VerificationFailure::Approver,
                })?;
            approvals.push(VerifiedTicket::from_service_context(&context));
        }
        Ok((VerifiedTicket::from_service_context(&requester), approvals))
    }

    /// The obligations of the requester's Allow: `RateLimit` through the
    /// same fixed-window limiter (and constants) as the LDAP engine's;
    /// `Constrain(MaxPageSize)` is met by every admin answer (at most one
    /// entry) unless it is 0 for a `Lookup`. `false` ⇒ refused.
    /// Spec: docs/11 §2 ("the PEP must honour obligations"), §8;
    /// docs/questions/Q-358 item 7, Q-388 item 2.
    fn honour(
        &mut self,
        prepared: &Prepared,
        operation: &PepOperation,
        now: &KerberosTime,
    ) -> bool {
        for obligation in prepared.obligations() {
            match obligation {
                Obligation::RateLimit(key) => {
                    if !self.rate.admit(key, now) {
                        return false;
                    }
                }
                Obligation::Constrain(Constraint::MaxPageSize(size)) => {
                    if *size == 0 && matches!(operation, PepOperation::Lookup(_)) {
                        return false;
                    }
                }
                Obligation::Audit => {}
            }
        }
        true
    }

    /// The decision event of a failure before `prepare` (no planner in the
    /// PEP for it): the request's fields, stage `Decision(Failed(failure))`.
    fn failed_decision(
        &self,
        operation_id: u64,
        operation: &PepOperation,
        failure: AdminFailure,
        now: &KerberosTime,
    ) -> DirAdminEvent {
        let base = self.worker.admin.refuse_unverified(
            operation_id,
            operation,
            VerificationFailure::KeydUnavailable,
            now,
        );
        restage(
            base.event(),
            DirAdminStage::Decision(DecisionResult::Failed(failure)),
        )
    }

    /// One request (module documentation).
    /// Spec: docs/51 §7.4; A-85; A-89.
    fn handle(&mut self, auth: &Auth, operation: &Operation) -> Reply {
        let operation = pep_operation(operation);
        let Some(now) = self.worker.clock.now() else {
            return Reply::Refused(RefusalStatus::Unavailable);
        };
        let writes = operation.writes();
        // Step 0: the audit slots, before anything is done.
        let Some(slots) = self.worker.gate.admit_slots(if writes { 2 } else { 1 }) else {
            AUDIT_UNAVAILABLE.hit(None);
            return Reply::Refused(RefusalStatus::Unavailable);
        };
        let mut slots = slots.into_iter();
        let first = slots.next();
        let second = slots.next();
        let operation_id = self.next_id();

        // Step 1: the tickets.
        let (requester, approvals) = match self.verify(auth) {
            Ok(verified) => verified,
            Err(failure) => {
                let refusal =
                    self.worker
                        .admin
                        .refuse_unverified(operation_id, &operation, failure, &now);
                return self.refuse(
                    first,
                    second,
                    refusal.event(),
                    wire_status(refusal.status()),
                );
            }
        };
        let request = PepRequest {
            operation_id,
            operation,
            requester,
            approvals,
        };

        // Steps 2-3: the transaction first, then the view.
        let store = Arc::clone(&self.worker.store);
        let mut txn: Option<WriteTxn<'_>> = None;
        if writes {
            match store.begin_write() {
                Ok(begun) => txn = Some(begun),
                Err(_) => {
                    let event = self.failed_decision(
                        operation_id,
                        &request.operation,
                        AdminFailure::StoreFailure,
                        &now,
                    );
                    return self.refuse(first, second, &event, RefusalStatus::Unavailable);
                }
            }
        }
        let prepared = match self.worker.ctx.view(&store, &self.worker.tiers) {
            // Step 4: every check of the PEP against this one view.
            Ok(view) => self
                .worker
                .admin
                .prepare(&request, &view, &self.worker.policy, &now),
            Err(_) => {
                abort(txn);
                let event = self.failed_decision(
                    operation_id,
                    &request.operation,
                    AdminFailure::StoreFailure,
                    &now,
                );
                return self.refuse(first, second, &event, RefusalStatus::Unavailable);
            }
        };
        let prepared = match prepared {
            Ok(prepared) => prepared,
            Err(refusal) => {
                abort(txn);
                return self.refuse(
                    first,
                    second,
                    refusal.event(),
                    wire_status(refusal.status()),
                );
            }
        };
        if !self.honour(&prepared, &request.operation, &now) {
            abort(txn);
            let event = restage(
                prepared.decision_event(),
                DirAdminStage::Decision(DecisionResult::Refused(AdminRefusal::PolicyDenied)),
            );
            return self.refuse(first, second, &event, RefusalStatus::Denied);
        }

        // An operation that commits nothing: its decision event, then the
        // reply.
        if !prepared.writes() {
            abort(txn);
            let Some(reply) = prepared.reply().map(wire_reply) else {
                self.release(first);
                self.release(second);
                return Reply::Refused(RefusalStatus::Unavailable);
            };
            self.release(second);
            return match self.commit(first, prepared.decision_event()) {
                Some(_) => reply,
                None => Reply::Refused(RefusalStatus::Unavailable),
            };
        }
        let Some(mut txn) = txn else {
            // Cannot happen: a write began its transaction above.
            self.release(first);
            self.release(second);
            return Reply::Refused(RefusalStatus::Unavailable);
        };

        // Step 5: the decision event, acknowledged before anything commits.
        let decision = prepared.decision_event().clone();
        let Some(seq) = self.commit(first, &decision) else {
            abort(Some(txn));
            self.release(second);
            return Reply::Refused(RefusalStatus::Unavailable);
        };
        let deadline = Instant::now() + self.worker.ack_deadline;
        if !self.worker.gate.wait_acknowledged(seq, deadline) {
            abort(Some(txn));
            let not_performed = restage(
                &decision,
                DirAdminStage::Outcome(OutcomeResult::Failed(AdminFailure::InternalFailure)),
            );
            if self.commit(second, &not_performed).is_none() {
                OUTCOME_UNRECORDED.hit(None);
            }
            return Reply::Refused(RefusalStatus::Unavailable);
        }

        // Step 6: apply in the transaction.
        match self.worker.admin.apply(prepared, &mut txn, &now) {
            Err(refusal) => {
                abort(Some(txn));
                if self.commit(second, refusal.event()).is_none() {
                    OUTCOME_UNRECORDED.hit(None);
                }
                Reply::Refused(wire_status(refusal.status()))
            }
            // Steps 7-9: commit, the outcome event, the reply.
            Ok(applied) => match txn.commit() {
                Ok(()) => {
                    if self.commit(second, applied.outcome_event()).is_none() {
                        OUTCOME_UNRECORDED.hit(None);
                    }
                    wire_reply(applied.reply())
                }
                Err(_) => {
                    if self
                        .commit(second, applied.commit_failure_event())
                        .is_none()
                    {
                        OUTCOME_UNRECORDED.hit(None);
                    }
                    Reply::Refused(RefusalStatus::Unavailable)
                }
            },
        }
    }
}

/// Abort a transaction (nothing of it is committed; a failure to abort
/// leaves nothing committed either — the transaction is dropped).
/// Spec: dirstore `WriteTxn::abort`; A-83 ("abort the transaction when the
/// object create is refused").
fn abort(txn: Option<WriteTxn<'_>>) {
    if let Some(txn) = txn {
        let _ = txn.abort();
    }
}

impl AdminWorker {
    /// Move the worker onto its own OS thread behind a queue of `capacity`
    /// jobs (0 < capacity ≤ [`crate::admin_service::MAX_ADMIN_QUEUE_CAPACITY`]).
    /// `on_exit` runs when the thread ends, so the daemon stops instead of
    /// serving without it.
    ///
    /// # Errors
    /// [`EngineError::QueueCapacity`], [`EngineError::Spawn`].
    ///
    /// Spec: docs/51 §7.5; docs/50 R50-7, R50-14.
    pub(crate) fn spawn<X>(
        self,
        capacity: usize,
        on_exit: X,
    ) -> Result<(AdminEngineHandle, EngineThread), EngineError>
    where
        X: FnOnce() + Send + 'static,
    {
        if capacity == 0 || capacity > crate::admin_service::MAX_ADMIN_QUEUE_CAPACITY {
            return Err(EngineError::QueueCapacity);
        }
        let (queue, jobs) = sync_channel::<AdminJob>(capacity);
        let first_id = self
            .clock
            .now()
            .and_then(|now| directory_admin::wall_clock(&now))
            .map_or(0, |seconds| seconds.0.wrapping_shl(OPERATION_ID_SHIFT));
        let mut running = Running {
            worker: self,
            next_operation: first_id,
            rate: ObligationLimiter::new(),
        };
        let thread = std::thread::Builder::new()
            .name(String::from("dird-admin"))
            .spawn(move || {
                let _exit = OnExit(Some(on_exit));
                while let Ok(job) = jobs.recv() {
                    let AdminJob {
                        auth,
                        operation,
                        reply,
                    } = job;
                    let answer = running.handle(&auth, &operation);
                    drop(auth);
                    // The connection may be gone; its answer is dropped.
                    let _ = reply.send(answer);
                }
            })
            .map_err(|_| EngineError::Spawn)?;
        Ok((AdminEngineHandle { queue }, EngineThread { thread }))
    }
}
