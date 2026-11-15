//! The kpasswd thread (task K7, dird side): one dedicated OS thread runs
//! ipc-kpasswd's dispatcher and docs/53 §5.6 over dird's store, fed through
//! its own bounded queue — so a flood on TCP 464 starves neither the LDAP
//! engine nor the admin thread (docs/53 §5.6 step 1; docs/07 §1, "a
//! separate pool").
//!
//! # Design (the LDAP engine's, docs/50 R50-7)
//!
//! * Each channel connection's state — its `KpasswdConnection`, whose zone
//!   the listener fixed from the front's peer uid — **travels with the
//!   request** into the job; this thread runs the dispatcher over it
//!   (`KpasswdConnection::handle`, the one place a request is decoded and
//!   answered) and hands it back with the dispatch.
//! * Queue full ⇒ `Refused::Busy` at once (`try_send`); the front answers
//!   HARDERROR (docs/53 §5.6 step 1, §5.7).
//! * dird's only other runtime writer is the admin thread; both begin their
//!   `WriteTxn` before taking their view (dirstore waits while another write
//!   transaction is open), so each `prepare` reads the state its write
//!   starts from, and `apply` re-verifies it (crate directory-admin).
//!
//! # One change request (docs/53 §5.6, in its order)
//!
//! 0. `now` from dird's clock; the two audit slots — the decision and the
//!    outcome event — reserved with auditd reachable, all or none; otherwise
//!    `Unavailable` (the front answers HARDERROR) and **nothing else is
//!    done**: keyd is not asked (A-85: "auditd unavailable ⇒ refused before
//!    any commit"; every `DirAdmin` event is gating, Q-340 item 8).
//! 1. **keyd `open_change_password_request`** (Role::Ldap) with the request's
//!    two messages and the addresses the front's kernel reported. keyd not
//!    available ⇒ `Unsealed(HARDERROR)`; any refusal ⇒ `Unsealed(AUTHERROR)`
//!    — uniform (A-26; A-126 on docs/questions/Q-660 item 3). There is no
//!    context to seal in.
//! 2. **keyd's verdict** not `Acceptable` ⇒ keyd seals **its verdict's**
//!    code (MALFORMED 1, SOFTERROR 4, ACCESSDENIED 5 for a set request,
//!    INITIAL_FLAG_NEEDED 7 — docs/questions/Q-663 item 2) — before any
//!    directory work, so a refused password never moves `pwdLastSet`
//!    (docs/53 §6.2).
//! 3. **The `WriteTxn`, then the view, then directory-admin's
//!    `prepare_change_password`** — the Subject from keyd's facts,
//!    `ticket_age`, users only, `DirControlRight(User-Change-Password)` on
//!    the account itself, Tier0 refused (crate directory-admin). A refusal:
//!    its `Decision` event into the first slot, then keyd seals the code of
//!    docs/53 §5.7 (`change_password_result`: AUTHERROR 3 or ACCESSDENIED
//!    5). The obligations of the Allow are honoured (docs/11 §2) — the
//!    admin thread's own limiter rule.
//! 4. **The decision event, acknowledged** (`AckedIntent<Prepared>`, docs/52
//!    R6) — none in time ⇒ the transaction aborted, the outcome
//!    `AuditUnacknowledged`, HARDERROR sealed.
//! 5. **`apply`** (`pwdLastSet = now`, the one write path), **commit**, the
//!    **outcome event**, then **`register_decision(ChangePassword { the
//!    user's key set })`** — the order of A-100 (docs/53 §5.6 step 5). Any
//!    failure ⇒ HARDERROR sealed: the account is in the safe state of
//!    docs/47 §9.2 (old password valid, old tickets revoked).
//! 6. **keyd `complete_change_password`** — keyd installs the password
//!    through `set_secret`'s one install path and only then releases its
//!    sealed success reply (docs/questions/Q-663 item 1). Refused or not
//!    performed ⇒ nothing installed, HARDERROR sealed; outcome unknown ⇒
//!    `Unsealed(HARDERROR)` (keyd's audit records tell what happened —
//!    docs/53 §5.6 step 6).
//!
//! Every reply after step 1 is a reply keyd sealed under the client's subkey
//! (docs/53 §5.5: "exactly one reply per context"), or — only when keyd
//! could not seal — the front's unauthenticated KRB-ERROR with HARDERROR.
//! No message octets, no password and no key ever reach a log or an event
//! (docs/53 §9).
//!
//! Spec: docs/53 §5.4–§5.7, §6.2, §9; docs/50 R50-7, R50-14; docs/51 §5.7
//! item 2; docs/52 §3.11 R6, §4.2; A-26; A-85; A-100; A-126.

use crate::admin_engine::{abort, honour_obligations, restage, NOT_PERFORMED, OBLIGATION_REFUSED};
use crate::clock::SharedClock;
use crate::engine::{EngineError, EngineThread, OnExit, SubmitError};
use crate::kpasswd_service::{
    sealed_for_front, CompletionOutcome, KpasswdKeyd, OpenArguments, MAX_KPASSWD_QUEUE_CAPACITY,
};
use crate::ldap_audit::AuditGate;
use crate::log::{note, Note, Thinned};
use crate::operation_ids::OperationIds;
use crate::rate::ObligationLimiter;
use crate::registration::DecisionRegistration;
use core::time::Duration;
use directory_admin::{
    change_password_result, ChangePasswordRequest as PepChange, ChangePasswordTicket,
    DirectoryAdmin, OsRandom, Reply as PepReply,
};
use directory_pip::{DirectoryContext, TierMap};
use dirstore::Store;
use ipc_audit::{AdminFailure, DirAdminEvent, Reservation};
use ipc_kpasswd::{
    ChangePasswordRequest, Dispatch, FrontZone, HostUnserved, KpasswdAnswer, KpasswdConnection,
    KpasswdHost, UnsealedCode,
};
use keyd_types::{AuthnError, ChangePasswordCtxId, DecisionId, KeyHandle};
use krb_proto::{KerberosTime, NonZeroResultCode};
use pdp::PolicySnapshot;
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::oneshot;
use zeroize::Zeroizing;

/// Change requests answered before keyd was asked because auditd could not
/// take their events (thinned log).
static AUDIT_UNAVAILABLE: Thinned = Thinned::new(Note::KpasswdAuditUnavailable);
/// Outcome events that could not be committed after a commit (thinned log;
/// cannot happen for events built from ipc-audit's types).
static OUTCOME_UNRECORDED: Thinned = Thinned::new(Note::KpasswdOutcomeUnrecorded);

/// What a connection gets back from the kpasswd thread: its connection state
/// and the dispatch.
pub(crate) type Answered = (KpasswdConnection, Dispatch);

/// One job for the kpasswd thread: a request body, the connection's state,
/// and where the answer goes.
/// Spec: docs/50 R50-7; docs/53 §5.6 step 1.
pub(crate) struct KpasswdJob {
    connection: KpasswdConnection,
    body: Zeroizing<Vec<u8>>,
    reply: oneshot::Sender<Answered>,
}

/// The sending side of the kpasswd queue; one clone per connection task.
/// Spec: docs/50 R50-7; docs/53 §5.6 step 1.
#[derive(Debug, Clone)]
pub(crate) struct KpasswdEngineHandle {
    queue: SyncSender<KpasswdJob>,
}

impl KpasswdEngineHandle {
    /// Queue one request without waiting: a full queue is
    /// [`SubmitError::Busy`]. The connection state comes back with the
    /// answer.
    /// Spec: docs/53 §5.6 step 1 ("full ⇒ `Busy`"); docs/50 R50-7.
    pub(crate) fn submit(
        &self,
        connection: KpasswdConnection,
        body: Zeroizing<Vec<u8>>,
    ) -> Result<oneshot::Receiver<Answered>, SubmitError> {
        let (reply, answer) = oneshot::channel();
        match self.queue.try_send(KpasswdJob {
            connection,
            body,
            reply,
        }) {
            Ok(()) => Ok(answer),
            Err(TrySendError::Full(_)) => Err(SubmitError::Busy),
            Err(TrySendError::Disconnected(_)) => Err(SubmitError::Stopped),
        }
    }
}

/// What the kpasswd thread owns.
/// Spec: docs/53 §5.6; docs/47 §8.1 (the view and the policy of one
/// version).
pub(crate) struct KpasswdWorker {
    /// The store (shared; written here and by the admin thread).
    pub(crate) store: Arc<Store>,
    /// The directory context (A-53).
    pub(crate) ctx: DirectoryContext,
    /// The tier map of the loaded policy.
    pub(crate) tiers: TierMap,
    /// The PDP snapshot of the same policy.
    pub(crate) policy: PolicySnapshot,
    /// The write PEP (its own instance: the configuration of the admin
    /// service's).
    pub(crate) admin: DirectoryAdmin<OsRandom>,
    /// keyd, Role::Ldap.
    pub(crate) keyd: Box<dyn KpasswdKeyd>,
    /// The change-password service's key set (`kadmin/changepw`).
    pub(crate) service: KeyHandle,
    /// The shared audit gate.
    pub(crate) gate: Arc<AuditGate>,
    /// dird's clock.
    pub(crate) clock: SharedClock,
    /// How long a decision event may wait for its acknowledgement (the admin
    /// service's).
    pub(crate) ack_deadline: Duration,
    /// dird's operation numbers, shared with the admin thread
    /// (crate::operation_ids).
    pub(crate) ids: Arc<OperationIds>,
}

/// The running state of the kpasswd thread: the dispatcher's host.
struct Running {
    worker: KpasswdWorker,
    rate: ObligationLimiter,
}

impl Running {
    /// Give a slot back.
    fn release(&self, slot: Option<Reservation>) {
        if let Some(slot) = slot {
            self.worker.gate.release(slot);
        }
    }

    /// Commit `event` into `slot`; whether it was committed.
    fn commit(&self, slot: Option<Reservation>, event: &DirAdminEvent) -> bool {
        slot.is_some_and(|slot| self.worker.gate.commit_admin(slot, event).is_ok())
    }

    /// Commit the outcome event of a write whose decision event is already
    /// in the window; a gap (cannot happen) is counted into the next
    /// `WindowSummary` and noted.
    /// Spec: docs/51 §5.7 item 2; A-88 (Q-366 option (a)).
    fn commit_outcome(&self, slot: Option<Reservation>, event: &DirAdminEvent) {
        if !self.commit(slot, event) {
            self.worker.gate.count_unrecorded_outcome();
            OUTCOME_UNRECORDED.hit(None);
        }
    }

    /// keyd's error reply for `ctx` with `code`, for the front; HARDERROR in
    /// the front's KRB-ERROR when keyd did not seal it.
    /// Spec: docs/53 §5.5 (`seal_change_password_error`), §5.7.
    fn seal(&mut self, ctx: &ChangePasswordCtxId, code: NonZeroResultCode) -> KpasswdAnswer {
        self.worker
            .keyd
            .seal_error(ctx, code)
            .and_then(|sealed| sealed_for_front(&sealed))
            .map_or(KpasswdAnswer::Unsealed(UnsealedCode::HardError), |sealed| {
                KpasswdAnswer::Sealed(sealed)
            })
    }

    /// A refusal before any write: its event into the first slot, the second
    /// given back, then keyd seals `code` — HARDERROR if the event could not
    /// be committed (no answer leaves unaudited; cannot happen).
    /// Spec: docs/53 §5.6 step 4, §5.7; A-85.
    fn refuse(
        &mut self,
        first: Option<Reservation>,
        second: Option<Reservation>,
        event: &DirAdminEvent,
        code: NonZeroResultCode,
        ctx: &ChangePasswordCtxId,
    ) -> KpasswdAnswer {
        self.release(second);
        let code = if self.commit(first, event) {
            code
        } else {
            NonZeroResultCode::HardError
        };
        self.seal(ctx, code)
    }

    /// The change after keyd opened it acceptably (module documentation,
    /// steps 3-6).
    /// Spec: docs/53 §5.6 steps 4-6.
    fn decide_and_complete(
        &mut self,
        ticket: ChangePasswordTicket,
        ctx: &ChangePasswordCtxId,
        first: Option<Reservation>,
        second: Option<Reservation>,
        now: &KerberosTime,
    ) -> KpasswdAnswer {
        let hard = NonZeroResultCode::HardError;
        let operation_id = self.worker.ids.next();
        let request = PepChange {
            operation_id,
            ticket,
        };
        // Step 3: the transaction first, then the view, then the PEP.
        let store = Arc::clone(&self.worker.store);
        let Ok(mut txn) = store.begin_write() else {
            let refusal = self.worker.admin.refuse_failed_change_password(
                operation_id,
                AdminFailure::ViewUnavailable,
                now,
            );
            return self.refuse(first, second, refusal.event(), hard, ctx);
        };
        let prepared = match self.worker.ctx.view(&store, &self.worker.tiers) {
            Ok(view) => {
                self.worker
                    .admin
                    .prepare_change_password(&request, &view, &self.worker.policy, now)
            }
            Err(_) => {
                abort(Some(txn));
                let refusal = self.worker.admin.refuse_failed_change_password(
                    operation_id,
                    AdminFailure::ViewUnavailable,
                    now,
                );
                return self.refuse(first, second, refusal.event(), hard, ctx);
            }
        };
        let prepared = match prepared {
            Ok(prepared) => prepared,
            Err(refusal) => {
                abort(Some(txn));
                let code = change_password_result(&refusal);
                return self.refuse(first, second, refusal.event(), code, ctx);
            }
        };
        if !honour_obligations(&mut self.rate, prepared.obligations(), false, now) {
            abort(Some(txn));
            let event = restage(prepared.decision_event(), OBLIGATION_REFUSED);
            return self.refuse(first, second, &event, NonZeroResultCode::AccessDenied, ctx);
        }

        // Step 4: the decision event, acknowledged before anything commits
        // (docs/52 R6: `apply` takes the write only as `AckedIntent`).
        let Some(slot) = first else {
            // Cannot happen: two slots were reserved.
            abort(Some(txn));
            self.release(second);
            return self.seal(ctx, hard);
        };
        let pending = match self.worker.gate.begin_intent(slot, prepared) {
            Ok(pending) => pending,
            Err(_) => {
                // Cannot happen (the slot was reserved): nothing committed.
                abort(Some(txn));
                self.release(second);
                return self.seal(ctx, hard);
            }
        };
        let deadline = Instant::now() + self.worker.ack_deadline;
        let acked = match self.worker.gate.wait_acknowledged(pending, deadline) {
            Ok(acked) => acked,
            Err(prepared) => {
                abort(Some(txn));
                self.commit_outcome(second, &restage(prepared.decision_event(), NOT_PERFORMED));
                return self.seal(ctx, hard);
            }
        };

        // Step 5: apply, commit, the outcome event, the decision.
        let applied = match self.worker.admin.apply(acked, &mut txn, now) {
            Ok(applied) => applied,
            Err(refusal) => {
                abort(Some(txn));
                self.commit_outcome(second, refusal.event());
                let code = change_password_result(&refusal);
                return self.seal(ctx, code);
            }
        };
        if txn.commit().is_err() {
            self.commit_outcome(second, applied.commit_failure_event());
            return self.seal(ctx, hard);
        }
        self.commit_outcome(second, applied.outcome_event());
        let PepReply::PasswordChange(change) = applied.reply() else {
            // Cannot happen: a `ChangePassword` applies to this reply.
            return self.seal(ctx, hard);
        };
        let target = change.key.handle;
        let Some(registration) =
            DecisionRegistration::of_password_change(DecisionId::new(operation_id), &applied)
        else {
            return self.seal(ctx, hard);
        };
        if let Err(failure) = self.worker.keyd.register_decision(registration) {
            // Fail closed: no password is installed; the account is in the
            // safe state of docs/47 §9.2.
            note(Note::KpasswdDecisionNotRegistered, Some(failure.code()));
            return self.seal(ctx, hard);
        }

        // Step 6: keyd installs, then releases its sealed success reply.
        match self.worker.keyd.complete(ctx, &target) {
            CompletionOutcome::Completed(sealed) => sealed_for_front(&sealed).map_or(
                // keyd installed the password but its reply does not fit the
                // channel (cannot happen: keyd seals a two-octet result):
                // the client hears HARDERROR, keyd's records say the truth.
                KpasswdAnswer::Unsealed(UnsealedCode::HardError),
                KpasswdAnswer::Sealed,
            ),
            CompletionOutcome::NotInstalled => self.seal(ctx, hard),
            CompletionOutcome::OutcomeUnknown => {
                note(Note::KpasswdCompletionUnknown, None);
                KpasswdAnswer::Unsealed(UnsealedCode::HardError)
            }
        }
    }
}

impl KpasswdHost for Running {
    /// docs/53 §5.6 over one request (module documentation).
    /// Spec: docs/53 §5.5–§5.7; A-85; A-126.
    fn change_password(
        &mut self,
        zone: FrontZone,
        request: &ChangePasswordRequest,
    ) -> Result<KpasswdAnswer, HostUnserved> {
        // The zone was fixed by the listener from the front's peer uid;
        // phase 1 has one — the internal zone every PDP context of this
        // request names (docs/53 §3.3; docs/52 R14).
        match zone {
            FrontZone::Internal => {}
        }
        let Some(now) = self.worker.clock.now() else {
            return Err(HostUnserved::Unavailable);
        };
        // Step 0: the decision and the outcome slots, before anything.
        let Some(slots) = self.worker.gate.admit_slots(2) else {
            AUDIT_UNAVAILABLE.hit(None);
            return Err(HostUnserved::Unavailable);
        };
        let mut slots = slots.into_iter();
        let first = slots.next();
        let second = slots.next();

        // Step 1: keyd opens the request — keyd alone decrypts it.
        let open = OpenArguments::of(request);
        let service = self.worker.service.principal;
        let context = match self.worker.keyd.open(
            &service,
            open.ap_req,
            open.krb_priv,
            &open.peer,
            &open.local,
        ) {
            Ok(context) => context,
            Err(error) => {
                self.release(first);
                self.release(second);
                return Ok(KpasswdAnswer::Unsealed(match error {
                    AuthnError::Unavailable => UnsealedCode::HardError,
                    _ => UnsealedCode::AuthError,
                }));
            }
        };
        // Step 2: keyd's verdict.
        let Some(ticket) = ChangePasswordTicket::from_context(&context) else {
            self.release(first);
            self.release(second);
            let code = context
                .verdict
                .result_code()
                .unwrap_or(NonZeroResultCode::HardError);
            return Ok(self.seal(&context.ctx_id, code));
        };
        // Steps 3-6.
        Ok(self.decide_and_complete(ticket, &context.ctx_id, first, second, &now))
    }
}

impl KpasswdWorker {
    /// Move the worker onto its own OS thread behind a queue of `capacity`
    /// jobs (0 < capacity ≤ [`MAX_KPASSWD_QUEUE_CAPACITY`]). `on_exit` runs
    /// when the thread ends, so the daemon stops instead of serving without
    /// it.
    ///
    /// # Errors
    /// [`EngineError::QueueCapacity`], [`EngineError::Spawn`].
    ///
    /// Spec: docs/53 §5.6 step 1; docs/50 R50-7, R50-14.
    pub(crate) fn spawn<X>(
        self,
        capacity: usize,
        on_exit: X,
    ) -> Result<(KpasswdEngineHandle, EngineThread), EngineError>
    where
        X: FnOnce() + Send + 'static,
    {
        if capacity == 0 || capacity > MAX_KPASSWD_QUEUE_CAPACITY {
            return Err(EngineError::QueueCapacity);
        }
        let (queue, jobs) = sync_channel::<KpasswdJob>(capacity);
        let mut running = Running {
            worker: self,
            rate: ObligationLimiter::new(),
        };
        let thread = std::thread::Builder::new()
            .name(String::from("dird-kpasswd"))
            .spawn(move || {
                let _exit = OnExit(Some(on_exit));
                while let Ok(job) = jobs.recv() {
                    let KpasswdJob {
                        mut connection,
                        body,
                        reply,
                    } = job;
                    let dispatch = connection.handle(&body, &mut running);
                    drop(body);
                    // The connection may be gone; its answer is dropped.
                    let _ = reply.send((connection, dispatch));
                }
            })
            .map_err(|_| EngineError::Spawn)?;
        Ok((KpasswdEngineHandle { queue }, EngineThread { thread }))
    }
}
