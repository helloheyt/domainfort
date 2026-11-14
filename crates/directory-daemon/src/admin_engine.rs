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
//!    `open_and_verify_service_ticket` on the admin service's key set,
//!    bound to the request's operation digest — R2, docs/52 §5: computed
//!    here from the decoded operation, `ipc_dird_admin::operation_digest`)
//!    — the requester's, then each approval's. keyd unreachable ⇒
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
//!    slot records the operation as not performed
//!    (`Outcome(Failed(AuditUnacknowledged))`), and the answer is
//!    `Unavailable`. The prepared write goes into the gate with its
//!    decision event and comes back as an `ipc_audit::AckedIntent<Prepared>`
//!    only after the acknowledgement (docs/52 R6) — the only form `apply`
//!    takes.
//! 6. **`apply`** inside the transaction (it re-verifies what could have
//!    changed); a refusal ⇒ abort, its `Outcome` event.
//! 7. **Commit.**
//! 8. **The outcome event** (`Committed`), or `commit_failure_event` when
//!    the commit failed — into the slot reserved in step 0, so it is never
//!    refused for want of room. An outcome event that still cannot be
//!    committed is counted into the window's next `WindowSummary`
//!    (`unrecorded_outcomes`, A-88) and noted on stderr.
//!
//!    8a. **The `SetSecret` decision** (task A15a; docs/51 §5.8 option
//!    (b); A-102) — only for a committed `BeginPasswordSet`: keyd
//!    (Role::Ldap) `register_decision` of exactly the key targets and salt
//!    of the reply, live for [`SET_SECRET_GRANT_LIFETIME_SECS`]. Its place
//!    is the last before the reply, so that a grant exists only once the
//!    PDP's decision is
//!    acknowledged by auditd (step 5), `pwdLastSet` is committed (step 7 —
//!    docs/47 §9.2: before any `set_secret`, so a password can never be set
//!    with the old tickets still valid, even by a compromised admind racing
//!    the reply) and dird's own trail of the write is complete (step 8).
//!    Any failure — keyd refusing, keyd down, not performed, outcome unknown
//!    — answers `Unavailable`: admind sets no password (a failed
//!    `BeginPasswordSet` is followed by no `set_secret` and no completion),
//!    and the account is in the begun-but-not-set state docs/51 §9 already
//!    names as safe (old password valid, old tickets revoked). The outcome
//!    event stays `Committed` — the write did commit; keyd's own records of
//!    the grant (intent and outcome, A-88) and admind's event say the rest
//!    (docs/questions/Q-453 item 1).
//!
//!    8b. **The `DestroyKeySet` decision** (A-102, docs/52 §4.3 row
//!    `destroy_key_set` option (a)) — only for a committed `Delete` whose
//!    tombstone is of the `user` class (users and computers): keyd
//!    `register_decision(the tombstone's stable id, DestroyKeySet { the
//!    tombstone's GUID }, no approvers, keyd_types::MAX_DESTROY_DECISION_SECS)`
//!    (crate::registration), after the outcome event, so a destroy decision
//!    exists only for an account whose deletion is durably recorded and
//!    committed. keyadm's `destroy-sweep` executes it in keyd. keyd's
//!    refusal (`Denied`) means the account has no key set to destroy (R6b)
//!    and is no failure; any other failure is
//!    noted (`AdminDestroyNotRegistered`) and the reply stays the `Delete`'s
//!    success: the account is deleted, and its key sets are unreachable (no
//!    object ⇒ no handle — docs/51 §9, fail closed); the re-registration
//!    (below) registers it later.
//! 9. **Reply.**
//!
//! Every registration in keyd is a `crate::DecisionRegistration`, built only
//! from its evidence — the `AckedIntent<QuorumStep>` of an `Approve`, the
//! `Applied` of a `BeginPasswordSet`, a `TombstonedPrincipal` (docs/52 R6;
//! crate::registration).
//!
//! # Re-registering lost destroy decisions (A-105)
//!
//! Between jobs — at the thread's start and every
//! `destroy_reconcile_interval` (`DESTROY_RECONCILE_INTERVAL` in production) — the thread registers again
//! the destroy decision of every tombstoned user or computer that keyd does
//! not hold as pending; keyd refuses it once the account has no key set
//! left, which settles it (crate::reconcile; docs/questions/Q-470 item 4,
//! Q-501, R6b).
//!
//! An operation that commits nothing (`Lookup`, `CompletePasswordSet`) has
//! its decision event only, committed into the window before the reply
//! (the LDAP rule, A-64/A-70: "commit, then reply").
//!
//! Every refusal sends its event (into the reserved slot) before the reply.
//! AP-REQ octets are never logged; the thread logs fixed notes only.
//!
//! # The key-plane steps (task A10; docs/51 §5.6, §6)
//!
//! `RequestKeyOperation` and `Approve` (each with exactly one AP-REQ — the
//! requester's, the approver's) act on the pending requests this thread
//! holds **in memory** (`directory_admin::KeyRequests`; a dird restart
//! drops them). keyadm's former `FetchApproved`, `Complete`,
//! `ListPendingDestruction` are retired (A-102, docs/52 §4.6, §4.8):
//! 0. `now`; the audit slots — two for `Approve` (its decision and the
//!    outcome of its decision's registration), one for
//!    `RequestKeyOperation` — all or none, auditd reachable;
//! 1. the AP-REQ through keyd;
//! 2. one view (no `WriteTxn`: nothing of the directory is written);
//! 3. `DirectoryAdmin::key_step` — the Subject, `PolicyAdmin` on the `keys`
//!    scope, the obligations honoured before the table changes, the step;
//! 4. its decision event committed into the first slot before the reply
//!    (it commits nothing to the directory: no acknowledgement wait —
//!    Q-340 item 1, the LDAP rule) — **except** for the `Approve` that
//!    completed the quorum (A-102, docs/52 §4.3): its decision event is
//!    **acknowledged** by auditd first (no loosening of keyd without the
//!    decision durably recorded — A-85, Q-453 item 1), then the decision is
//!    registered in keyd (`register_decision`, Role::Ldap,
//!    `call_with_fate`), then the registration's `Outcome` event goes into
//!    the second slot. No acknowledgement in time, or any registration
//!    failure ⇒ the approval is **withdrawn** (`KeyRequests::withdraw`: the
//!    approver may approve again; keyd accepts an identical decision again
//!    unchanged) and the answer is `Unavailable`. An `Approve` that does not
//!    complete the quorum releases the second slot.
//!
//! # The policy change (task A16; docs/51 §5.10, R51-21; A-80)
//!
//! `ChangePolicy` — a tier-map edit carrying the requester's AP-REQ and the
//! approvers' in its `auth`, every one bound to the request's digest:
//! 0. `now`; two audit slots (decision and outcome), all or none, auditd
//!    reachable; `policy_next_path` not configured ⇒ its `Decision(Failed)`
//!    and `Unavailable`;
//! 1. the AP-REQs through keyd (requester, then each approval);
//! 2. whether `policy.next` is pending (dird's own file, through
//!    crates/protected-file) — unreadable ⇒ `Unavailable`;
//! 3. one view (no `WriteTxn`: the directory is not written), then
//!    `DirectoryAdmin::prepare_policy_change` — `PolicyAdmin` on the
//!    `tier-map` scope, mandatory dual control with the PEP's one approval
//!    rule, one pending change at a time, the candidate built by crate
//!    policy-store's one tier-map edit (version + 1) and re-read by the
//!    format's own decoder; the requester's obligations honoured;
//! 4. the decision event committed and **acknowledged** — no
//!    acknowledgement in time ⇒ the outcome `AuditUnacknowledged`, nothing
//!    written, `Unavailable`; the candidate exists only as the
//!    `PolicyCandidate` of the proof (docs/52 R6);
//! 5. `policy.next` written (crate::policy_next: exclusive partial file,
//!    `fsync`, no-replace rename, directory `fsync`); its `Outcome` event —
//!    `Committed`, `Refused(PendingLimit)` when one appeared meanwhile, or
//!    `Failed(StoreFailure)`; the reply `PolicyNext {version}` or
//!    `Unavailable`. Activation is root's (`provision policy
//!    --activate-next`), followed by a restart of dird and the kdc (A-69).
//!
//! # The three events the PEP does not plan
//!
//! Each has its own code, appended to ipc-audit's closed tables by task F4
//! (A-91; docs/questions/Q-388 item 1, Q-397); the event is one the PEP
//! planned for the same request with only its stage replaced (the
//! request-derived fields stay):
//!
//! | case | stage |
//! |---|---|
//! | the `WriteTxn` cannot begin, or the view cannot be taken, before `prepare` | `Decision(Failed(ViewUnavailable))` |
//! | an obligation of the requester's Allow cannot be honoured | `Decision(Refused(ObligationRefused))` — the PDP reason stays `Allowed` |
//! | auditd did not acknowledge the decision in time (not performed) | `Outcome(Failed(AuditUnacknowledged))`, the decision's number |
//!
//! Spec: docs/51 §5.7 (R51-12), §7.4, §7.5; A-26; A-56; A-73; A-85; A-89
//! (docs/questions/Q-358 items 1, 7); docs/50 R50-7, §3.6; docs/questions/
//! Q-388; A-88 (Q-366, Q-395); A-91 (Q-397); docs/11 §2, §8.

use crate::admin_service::{
    key_request_of, pep_operation, policy_change_of, wire_key_reply, wire_reply, wire_status,
    RegistrationFailure, TicketVerifier, MAX_DESTROY_RECONCILE_INTERVAL,
    MIN_DESTROY_RECONCILE_INTERVAL,
};
use crate::clock::SharedClock;
use crate::engine::{EngineError, EngineThread, OnExit, SubmitError};
use crate::ldap_audit::AuditGate;
use crate::log::{note, Note, Thinned};
use crate::policy::DevelopmentPolicy;
use crate::policy_next::{PolicyNextError, PolicyNextFile};
use crate::rate::ObligationLimiter;
use crate::reconcile::Reconciler;
use crate::registration::DecisionRegistration;
use core::time::Duration;
use directory_admin::{
    DirectoryAdmin, KeyAdminOperation, KeyDecision, KeyRequests, KeyStep,
    Operation as PepOperation, OsRandom, Prepared, RegistrationOutcome, Request as PepRequest,
    VerificationFailure, VerifiedTicket,
};
use directory_admin::{PolicyCandidate, PolicyChangeRequest};
use directory_pip::{DirectoryContext, TierMap};
use dirstore::{Store, WriteTxn};
use ipc_audit::{
    AdminFailure, AdminRefusal, DecisionResult, DirAdminEvent, DirAdminStage, OutcomeResult,
    Reservation,
};
use ipc_dird_admin::{operation_digest, Auth, Operation, RefusalStatus, Reply};
use keyd_types::{AuthnError, DecisionId, KeyHandle, OperationDigest};
use krb_proto::KerberosTime;
use ldap::RateLimiter;
use pdp::{Constraint, Obligation, PolicySnapshot};
use policy_store::TierChange;
use std::sync::mpsc::{sync_channel, RecvTimeoutError, SyncSender, TrySendError};
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

/// What a job asks of the admin thread.
/// Spec: docs/51 §6, §7.3.
pub(crate) enum AdminWork {
    /// An operation with its tickets (`auth`).
    Operation {
        /// The raw AP-REQs.
        auth: Auth,
        /// The operation.
        operation: Operation,
    },
}

/// One job for the admin thread.
/// Spec: docs/51 §7.5; docs/50 R50-7.
pub(crate) struct AdminJob {
    work: AdminWork,
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
    pub(crate) fn submit(&self, work: AdminWork) -> Result<oneshot::Receiver<Reply>, SubmitError> {
        let (reply, answer) = oneshot::channel();
        match self.queue.try_send(AdminJob { work, reply }) {
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
    /// The pending key-operation requests (memory only; docs/51 §5.6).
    pub(crate) key_requests: KeyRequests,
    /// How often lost destroy decisions are re-registered (A-105;
    /// crate::reconcile), kept within [`MIN_DESTROY_RECONCILE_INTERVAL`] ..=
    /// [`MAX_DESTROY_RECONCILE_INTERVAL`].
    pub(crate) reconcile_interval: Duration,
    /// The loaded policy (of the version `policy` is a snapshot of): the base
    /// of a tier-map change (task A16).
    pub(crate) installed: DevelopmentPolicy,
    /// Where an approved tier-map change is written (task A16); `None` ⇒
    /// `ChangePolicy` is answered `Unavailable`.
    pub(crate) policy_next: Option<PolicyNextFile>,
}

/// The running state of the admin thread.
struct Running {
    worker: AdminWorker,
    next_operation: u64,
    rate: ObligationLimiter,
    /// The re-registration of lost destroy decisions (A-105).
    reconciler: Reconciler,
}

/// The stage of a request whose `WriteTxn` could not begin, or whose view
/// could not be taken, before `prepare`: no check ran, nothing was decided.
/// Spec: docs/51 §7.4 steps 2-3; docs/questions/Q-358 item 1 (A-89),
/// Q-388 item 1, Q-397 (A-91: its own code).
const VIEW_UNAVAILABLE: DirAdminStage =
    DirAdminStage::Decision(DecisionResult::Failed(AdminFailure::ViewUnavailable));

/// The stage of a request the PDP allowed whose obligations dird cannot
/// honour (the PDP reason stays `Allowed`).
/// Spec: docs/11 §2 ("the PEP must honour obligations"), §8;
/// docs/questions/Q-358 item 7, Q-388 item 2, Q-397 (A-91: its own code).
const OBLIGATION_REFUSED: DirAdminStage =
    DirAdminStage::Decision(DecisionResult::Refused(AdminRefusal::ObligationRefused));

/// The outcome stage of a write whose decision event auditd did not
/// acknowledge in time: not performed (the transaction was aborted).
/// Spec: docs/51 §5.7 item 2 ("decision acknowledged ⇒ commit"); A-85;
/// docs/questions/Q-388 items 1, 3, Q-397 (A-91: its own code).
const NOT_PERFORMED: DirAdminStage =
    DirAdminStage::Outcome(OutcomeResult::Failed(AdminFailure::AuditUnacknowledged));

/// An event with another stage (the request-derived fields kept): used for
/// the three cases the PEP has no planner for — [`VIEW_UNAVAILABLE`],
/// [`OBLIGATION_REFUSED`], [`NOT_PERFORMED`] (module documentation;
/// docs/questions/Q-388 items 1-2, Q-397).
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

    /// Commit the outcome event of a write whose decision event is already
    /// in the window; if it cannot be committed (cannot happen for an event
    /// built from ipc-audit's types into its reserved slot), the gap is
    /// counted into the next `WindowSummary` and noted on stderr.
    /// Spec: docs/51 §5.7 item 2; docs/questions/Q-388 item 6; A-88
    /// (Q-366 option (a), Q-395).
    fn commit_outcome(&self, slot: Option<Reservation>, event: &DirAdminEvent) {
        if self.commit(slot, event).is_none() {
            self.worker.gate.count_unrecorded_outcome();
            OUTCOME_UNRECORDED.hit(None);
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

    /// The one AP-REQ of a key-plane step (the requester's or the
    /// approver's), through keyd, bound to `digest` (R2).
    /// Spec: docs/51 §7.4 step 1; docs/52 §5 item 4; A-26; A-56; A-73.
    fn verify_one(
        &mut self,
        ap_req: &[u8],
        digest: &OperationDigest,
    ) -> Result<VerifiedTicket, VerificationFailure> {
        let service = self.worker.service.principal;
        self.worker
            .verifier
            .verify(&service, digest, ap_req)
            .map(|ticket| VerifiedTicket::from_operation_ticket(&ticket))
            .map_err(|e| match e {
                AuthnError::Unavailable => VerificationFailure::KeydUnavailable,
                _ => VerificationFailure::Requester,
            })
    }

    /// Step 1: the requester's AP-REQ, then each approval's, through keyd —
    /// every one bound to `digest`, the request's own (R2: an approval
    /// authorizes exactly this request).
    /// Spec: docs/51 §7.4 step 1; docs/52 §5 item 4; A-26; A-56; A-73.
    fn verify(
        &mut self,
        auth: &Auth,
        digest: &OperationDigest,
    ) -> Result<(VerifiedTicket, Vec<VerifiedTicket>), VerificationFailure> {
        let service = self.worker.service.principal;
        let requester = self
            .worker
            .verifier
            .verify(&service, digest, &auth.requester)
            .map_err(|e| match e {
                AuthnError::Unavailable => VerificationFailure::KeydUnavailable,
                _ => VerificationFailure::Requester,
            })?;
        let mut approvals = Vec::with_capacity(auth.approvals.len());
        for approval in &auth.approvals {
            let ticket = self
                .worker
                .verifier
                .verify(&service, digest, approval)
                .map_err(|e| match e {
                    AuthnError::Unavailable => VerificationFailure::KeydUnavailable,
                    _ => VerificationFailure::Approver,
                })?;
            approvals.push(VerifiedTicket::from_operation_ticket(&ticket));
        }
        Ok((VerifiedTicket::from_operation_ticket(&requester), approvals))
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
        honour_obligations(
            &mut self.rate,
            prepared.obligations(),
            matches!(operation, PepOperation::Lookup(_)),
            now,
        )
    }

    /// The decision event of a request whose `WriteTxn` could not begin or
    /// whose view could not be taken (no planner in the PEP for it): the
    /// request's fields, stage [`VIEW_UNAVAILABLE`].
    /// Spec: docs/51 §7.4 steps 2-3; docs/questions/Q-388 item 1, Q-397.
    fn view_unavailable_decision(
        &self,
        operation_id: u64,
        operation: &PepOperation,
        now: &KerberosTime,
    ) -> DirAdminEvent {
        let base = self.worker.admin.refuse_unverified(
            operation_id,
            operation,
            VerificationFailure::KeydUnavailable,
            now,
        );
        restage(base.event(), VIEW_UNAVAILABLE)
    }

    /// One job: a key-plane step, or an operation on the directory.
    /// Spec: docs/51 §5.6, §6, §7.3, §7.4.
    fn handle(&mut self, work: &AdminWork) -> Reply {
        match work {
            AdminWork::Operation { auth, operation } => {
                // R2 (docs/52 §5 item 4): the digest of the operation dird
                // decoded — what every AP-REQ must be bound to. A decoded
                // operation always has one; fail closed if not.
                let Ok(digest) = operation_digest(operation) else {
                    return Reply::Refused(RefusalStatus::Unavailable);
                };
                if let Some(changes) = policy_change_of(operation) {
                    return self.handle_policy(auth, &changes, &digest);
                }
                match key_request_of(operation) {
                    Some(request) => self.handle_key(auth, request, &digest),
                    None => match pep_operation(operation) {
                        Some(operation) => self.handle_directory(auth, operation, &digest),
                        // Cannot happen: every other operation maps.
                        None => Reply::Refused(RefusalStatus::Unavailable),
                    },
                }
            }
        }
    }

    /// One key-plane step (module documentation, "The key-plane steps").
    /// Spec: docs/51 §5.6, §6, §7.4; A-85; A-89; docs/11 §2.
    fn handle_key(
        &mut self,
        auth: &Auth,
        request: KeyAdminOperation,
        digest: &OperationDigest,
    ) -> Reply {
        let Some(now) = self.worker.clock.now() else {
            return Reply::Refused(RefusalStatus::Unavailable);
        };
        // Step 0: the audit slots, before anything is done.
        let Some(slots) = self.worker.gate.admit_slots(request.audit_events()) else {
            AUDIT_UNAVAILABLE.hit(None);
            return Reply::Refused(RefusalStatus::Unavailable);
        };
        let mut slots = slots.into_iter();
        let first = slots.next();
        let second = slots.next();
        let operation_id = self.next_id();

        // Step 1: the step's one AP-REQ, bound to this step (R2).
        let ticket = match self.verify_one(&auth.requester, digest) {
            Ok(ticket) => ticket,
            Err(failure) => {
                let refusal =
                    self.worker
                        .admin
                        .refuse_unverified_key(operation_id, &request, failure, &now);
                return self.refuse(
                    first,
                    second,
                    refusal.event(),
                    wire_status(refusal.status()),
                );
            }
        };
        let approvals_supplied = auth.approvals.len();

        // Steps 2-3: one view (nothing is written), then the step.
        let store = Arc::clone(&self.worker.store);
        let step = {
            let Running { worker, rate, .. } = self;
            match worker.ctx.view(&store, &worker.tiers) {
                Ok(view) => {
                    let mut honour = |obligations: &[Obligation]| {
                        honour_obligations(rate, obligations, false, &now)
                    };
                    Some(worker.admin.key_step(
                        &mut worker.key_requests,
                        operation_id,
                        &request,
                        digest,
                        Some(&ticket),
                        approvals_supplied,
                        &view,
                        &worker.policy,
                        &now,
                        &mut honour,
                    ))
                }
                Err(_) => None,
            }
        };
        match step {
            None => {
                let refusal = self.worker.admin.refuse_failed_key(
                    operation_id,
                    &request,
                    AdminFailure::ViewUnavailable,
                    &now,
                );
                self.refuse(first, second, refusal.event(), RefusalStatus::Unavailable)
            }
            Some(Err(refusal)) => self.refuse(
                first,
                second,
                refusal.event(),
                wire_status(refusal.status()),
            ),
            // Step 4 (A-102): the Approve that completed the quorum.
            Some(Ok(step)) if step.decision().is_some() => {
                self.register_key_decision(step, first, second)
            }
            // Step 4: the events into their slots, then the reply.
            Some(Ok(step)) => {
                let mut slots = [first, second].into_iter();
                let mut recorded = true;
                for event in step.events() {
                    if self.commit(slots.next().flatten(), event).is_none() {
                        recorded = false;
                    }
                }
                for unused in slots {
                    self.release(unused);
                }
                if recorded {
                    wire_key_reply(step.reply())
                } else {
                    // Cannot happen (the slots were reserved); no answer
                    // leaves unaudited.
                    OUTCOME_UNRECORDED.hit(None);
                    Reply::Refused(RefusalStatus::Unavailable)
                }
            }
        }
    }

    /// Step 4 of an `Approve` that completed its request's quorum (module
    /// documentation, "The key-plane steps"): its decision event committed
    /// and acknowledged ⇒ the decision registered in keyd ⇒ the
    /// registration's `Outcome` event ⇒ the reply. Any failure withdraws the
    /// approval and answers `Unavailable`.
    /// Spec: docs/52 §4.2, §4.3, §4.5 (A-102); docs/51 §5.6, §5.7 item 2;
    /// A-85; docs/questions/Q-453 item 1, Q-460.
    fn register_key_decision(
        &mut self,
        step: KeyStep,
        first: Option<Reservation>,
        second: Option<Reservation>,
    ) -> Reply {
        let quorum = match step.into_quorum() {
            Ok(quorum) => quorum,
            Err(step) => {
                // Cannot happen (the caller checked): nothing to register.
                self.release(first);
                self.release(second);
                if let Some(decision) = step.decision() {
                    return self.withdraw(decision);
                }
                return Reply::Refused(RefusalStatus::Unavailable);
            }
        };
        // docs/52 R6: the step's decision event into the first slot; the
        // registration needs its acknowledgement as a value
        // (`AckedIntent<QuorumStep>` ⇒ `DecisionRegistration::of_quorum`).
        let Some(slot) = first else {
            // Cannot happen (two slots were reserved).
            self.release(second);
            return self.withdraw(quorum.decision());
        };
        let pending = match self.worker.gate.begin_intent(slot, quorum) {
            Ok(pending) => pending,
            Err(quorum) => {
                // Cannot happen (the slot was reserved); no answer leaves
                // unaudited, and keyd was not asked.
                OUTCOME_UNRECORDED.hit(None);
                self.release(second);
                return self.withdraw(quorum.decision());
            }
        };
        let deadline = Instant::now() + self.worker.ack_deadline;
        let acked = match self.worker.gate.wait_acknowledged(pending, deadline) {
            Ok(acked) => acked,
            Err(quorum) => {
                self.commit_outcome(
                    second,
                    &quorum.registration_event(RegistrationOutcome::NotPerformed),
                );
                note(
                    Note::AdminDecisionNotRegistered,
                    Some(RegistrationFailure::NotPerformed.code()),
                );
                return self.withdraw(quorum.decision());
            }
        };
        let (registration, quorum) = DecisionRegistration::of_quorum(acked);
        let registered = self.worker.verifier.register_decision(registration);
        let outcome = match registered {
            Ok(()) => RegistrationOutcome::Registered,
            Err(RegistrationFailure::Refused(_)) => RegistrationOutcome::Refused,
            Err(RegistrationFailure::NotPerformed) => RegistrationOutcome::NotPerformed,
            Err(RegistrationFailure::OutcomeUnknown) => RegistrationOutcome::OutcomeUnknown,
        };
        self.commit_outcome(second, &quorum.registration_event(outcome));
        match registered {
            Ok(()) => wire_key_reply(quorum.reply()),
            Err(failure) => {
                note(Note::AdminDecisionNotRegistered, Some(failure.code()));
                self.withdraw(quorum.decision())
            }
        }
    }

    /// Withdraw the approval that completed `decision`'s quorum and answer
    /// `Unavailable` (module documentation, "The key-plane steps", step 4).
    /// Spec: docs/52 §4.3; docs/questions/Q-453 item 1 (fail closed).
    fn withdraw(&mut self, decision: &KeyDecision) -> Reply {
        let _ = self.worker.key_requests.withdraw(decision);
        Reply::Refused(RefusalStatus::Unavailable)
    }

    /// Step 8b (module documentation): after a committed `Delete`, the
    /// `DestroyKeySet` decision of its tombstone when it is a user or a
    /// computer — from the tombstone itself (`TombstonedPrincipal`, under
    /// its stable id, crate::registration). Never changes the reply: a
    /// failure is noted only, and the re-registration (crate::reconcile)
    /// registers it later.
    /// Spec: docs/52 §4.3 (A-102), §3.11 R6; docs/51 §6, §9;
    /// docs/questions/Q-470 (A-105).
    fn register_destruction(&mut self, target: dtyp::Guid) {
        let store = Arc::clone(&self.worker.store);
        let tombstoned = match self.worker.ctx.view(&store, &self.worker.tiers) {
            Ok(view) => self.worker.admin.destruction_target(&view, target),
            Err(_) => Err(AdminFailure::ViewUnavailable),
        };
        let tombstoned = match tombstoned {
            Ok(Some(tombstoned)) => tombstoned,
            Ok(None) => return,
            Err(_) => {
                note(Note::AdminDestroyNotRegistered, Some(4));
                return;
            }
        };
        match self
            .worker
            .verifier
            .register_decision(DecisionRegistration::of_tombstone(&tombstoned))
        {
            // keyd refuses a destroy decision for an account with no key set
            // (R6b, docs/questions/Q-501): nothing to destroy — not a failure.
            Ok(()) | Err(RegistrationFailure::Refused(keyd_types::Error::Denied)) => {}
            Err(failure) => note(Note::AdminDestroyNotRegistered, Some(failure.code())),
        }
    }

    /// One `ChangePolicy` (module documentation, "The policy change"; task
    /// A16): the audit slots, the tickets through keyd, one view, whether a
    /// `policy.next` is pending, the PEP's decision, the obligations, the
    /// decision event **acknowledged**, then `policy.next` written from the
    /// acknowledged candidate, its `Outcome` event, the reply.
    /// Spec: docs/51 §5.6, §5.7 item 2, §5.10, §7.4; A-85; docs/52 §3.11 R6;
    /// docs/questions/Q-591.
    fn handle_policy(
        &mut self,
        auth: &Auth,
        changes: &[TierChange],
        digest: &OperationDigest,
    ) -> Reply {
        let Some(now) = self.worker.clock.now() else {
            return Reply::Refused(RefusalStatus::Unavailable);
        };
        // Step 0: the decision and the outcome slots, before anything.
        let Some(slots) = self.worker.gate.admit_slots(2) else {
            AUDIT_UNAVAILABLE.hit(None);
            return Reply::Refused(RefusalStatus::Unavailable);
        };
        let mut slots = slots.into_iter();
        let first = slots.next();
        let second = slots.next();
        let operation_id = self.next_id();

        // Not configured: the online path does not exist here (fail closed,
        // and recorded).
        let Some(policy_next) = self.worker.policy_next.clone() else {
            let refusal = self.worker.admin.refuse_failed_policy_change(
                operation_id,
                changes,
                AdminFailure::InternalFailure,
                &now,
            );
            return self.refuse(first, second, refusal.event(), RefusalStatus::Unavailable);
        };

        // Step 1: the requester's and every approval's AP-REQ, each bound to
        // this request (R2).
        let (requester, approvals) = match self.verify(auth, digest) {
            Ok(verified) => verified,
            Err(failure) => {
                let refusal = self.worker.admin.refuse_unverified_policy_change(
                    operation_id,
                    changes,
                    failure,
                    &now,
                );
                return self.refuse(
                    first,
                    second,
                    refusal.event(),
                    wire_status(refusal.status()),
                );
            }
        };
        let request = PolicyChangeRequest {
            operation_id,
            changes: changes.to_vec(),
            operation_digest: *digest,
            requester,
            approvals,
        };

        // Steps 2-3: whether a change is pending, one view, the decision.
        let pending = match policy_next.pending() {
            Ok(pending) => pending,
            Err(error) => {
                note(Note::AdminPolicyNextNotWritten, Some(error.code()));
                let refusal = self.worker.admin.refuse_failed_policy_change(
                    operation_id,
                    changes,
                    AdminFailure::StoreFailure,
                    &now,
                );
                return self.refuse(first, second, refusal.event(), RefusalStatus::Unavailable);
            }
        };
        let store = Arc::clone(&self.worker.store);
        let prepared = match self.worker.ctx.view(&store, &self.worker.tiers) {
            Ok(view) => self.worker.admin.prepare_policy_change(
                &request,
                &view,
                &self.worker.policy,
                &self.worker.installed,
                pending,
                &now,
            ),
            Err(_) => {
                let refusal = self.worker.admin.refuse_failed_policy_change(
                    operation_id,
                    changes,
                    AdminFailure::ViewUnavailable,
                    &now,
                );
                return self.refuse(first, second, refusal.event(), RefusalStatus::Unavailable);
            }
        };
        let prepared = match prepared {
            Ok(prepared) => prepared,
            Err(refusal) => {
                return self.refuse(
                    first,
                    second,
                    refusal.event(),
                    wire_status(refusal.status()),
                )
            }
        };
        if !honour_obligations(&mut self.rate, prepared.obligations(), false, &now) {
            let event = restage(prepared.decision_event(), OBLIGATION_REFUSED);
            return self.refuse(first, second, &event, RefusalStatus::Denied);
        }

        // Step 4: the decision event, acknowledged before anything is
        // written — the candidate leaves the prepared value only with the
        // proof (docs/52 R6: `AckedIntent<PreparedPolicyChange>`).
        let Some(slot) = first else {
            // Cannot happen: two slots were reserved.
            self.release(second);
            return Reply::Refused(RefusalStatus::Unavailable);
        };
        let pending = match self.worker.gate.begin_intent(slot, prepared) {
            Ok(pending) => pending,
            Err(_) => {
                self.release(second);
                return Reply::Refused(RefusalStatus::Unavailable);
            }
        };
        let deadline = Instant::now() + self.worker.ack_deadline;
        let candidate = match self.worker.gate.wait_acknowledged(pending, deadline) {
            Ok(acked) => PolicyCandidate::from_acknowledged(acked),
            Err(prepared) => {
                self.commit_outcome(second, &restage(prepared.decision_event(), NOT_PERFORMED));
                return Reply::Refused(RefusalStatus::Unavailable);
            }
        };

        // Step 5: `policy.next`, then its outcome event, then the reply.
        match policy_next.write(&candidate) {
            Ok(()) => {
                self.commit_outcome(second, &candidate.written_event(&now));
                note(Note::AdminPolicyNextWritten, Some(candidate.version().0));
                Reply::PolicyNext {
                    version: candidate.version().0,
                }
            }
            Err(PolicyNextError::Pending) => {
                self.commit_outcome(second, &candidate.pending_event(&now));
                Reply::Refused(RefusalStatus::Unavailable)
            }
            Err(error) => {
                self.commit_outcome(second, &candidate.failed_event(&now));
                note(Note::AdminPolicyNextNotWritten, Some(error.code()));
                Reply::Refused(RefusalStatus::Unavailable)
            }
        }
    }

    /// One operation on the directory (module documentation).
    /// Spec: docs/51 §7.4; A-85; A-89.
    fn handle_directory(
        &mut self,
        auth: &Auth,
        operation: PepOperation,
        digest: &OperationDigest,
    ) -> Reply {
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

        // Step 1: the tickets, each bound to this request (R2).
        let (requester, approvals) = match self.verify(auth, digest) {
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
            operation_digest: *digest,
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
                    let event =
                        self.view_unavailable_decision(operation_id, &request.operation, &now);
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
                let event = self.view_unavailable_decision(operation_id, &request.operation, &now);
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
            let event = restage(prepared.decision_event(), OBLIGATION_REFUSED);
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

        // Step 5: the decision event, acknowledged before anything commits —
        // `apply` takes the prepared write only with that proof (docs/52
        // R6: `AckedIntent<Prepared>`, made only by the gate).
        let Some(slot) = first else {
            // Cannot happen: a write reserved two slots.
            abort(Some(txn));
            self.release(second);
            return Reply::Refused(RefusalStatus::Unavailable);
        };
        let pending = match self.worker.gate.begin_intent(slot, prepared) {
            Ok(pending) => pending,
            Err(_) => {
                abort(Some(txn));
                self.release(second);
                return Reply::Refused(RefusalStatus::Unavailable);
            }
        };
        let deadline = Instant::now() + self.worker.ack_deadline;
        let acked = match self.worker.gate.wait_acknowledged(pending, deadline) {
            Ok(acked) => acked,
            Err(prepared) => {
                abort(Some(txn));
                self.commit_outcome(second, &restage(prepared.decision_event(), NOT_PERFORMED));
                return Reply::Refused(RefusalStatus::Unavailable);
            }
        };

        // Step 6: apply in the transaction.
        match self.worker.admin.apply(acked, &mut txn, &now) {
            Err(refusal) => {
                abort(Some(txn));
                self.commit_outcome(second, refusal.event());
                Reply::Refused(wire_status(refusal.status()))
            }
            // Steps 7-9: commit, the outcome event, (8a) the SetSecret
            // decision of a BeginPasswordSet, (8b) the DestroyKeySet
            // decision of a Delete, the reply.
            Ok(applied) => match txn.commit() {
                Ok(()) => {
                    self.commit_outcome(second, applied.outcome_event());
                    if let Some(registration) = DecisionRegistration::of_password_set(
                        DecisionId::new(operation_id),
                        &applied,
                    ) {
                        if let Err(failure) = self.worker.verifier.register_decision(registration) {
                            // Fail closed: admind is told Unavailable and
                            // sets no password; the begun password set is
                            // the documented safe state (docs/51 §9).
                            note(Note::AdminGrantNotRegistered, Some(failure.code()));
                            return Reply::Refused(RefusalStatus::Unavailable);
                        }
                    }
                    if let PepOperation::Delete { target } = request.operation {
                        self.register_destruction(target);
                    }
                    wire_reply(applied.reply())
                }
                Err(_) => {
                    self.commit_outcome(second, applied.commit_failure_event());
                    Reply::Refused(RefusalStatus::Unavailable)
                }
            },
        }
    }
}

/// The obligations of an Allow: `RateLimit` through the same fixed-window
/// limiter (and constants) as the LDAP engine's; `Constrain(MaxPageSize)` is
/// met by every admin answer (at most one entry) unless it is 0 for a
/// `Lookup`. `false` ⇒ refused.
/// Spec: docs/11 §2 ("the PEP must honour obligations"), §8;
/// docs/questions/Q-358 item 7, Q-388 item 2.
fn honour_obligations(
    rate: &mut ObligationLimiter,
    obligations: &[Obligation],
    lookup: bool,
    now: &KerberosTime,
) -> bool {
    for obligation in obligations {
        match obligation {
            Obligation::RateLimit(key) => {
                if !rate.admit(key, now) {
                    return false;
                }
            }
            Obligation::Constrain(Constraint::MaxPageSize(size)) => {
                if *size == 0 && lookup {
                    return false;
                }
            }
            Obligation::Audit => {}
        }
    }
    true
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
        let interval = self.reconcile_interval.clamp(
            MIN_DESTROY_RECONCILE_INTERVAL,
            MAX_DESTROY_RECONCILE_INTERVAL,
        );
        let mut running = Running {
            worker: self,
            next_operation: first_id,
            rate: ObligationLimiter::new(),
            reconciler: Reconciler::new(),
        };
        let thread = std::thread::Builder::new()
            .name(String::from("dird-admin"))
            .spawn(move || {
                let _exit = OnExit(Some(on_exit));
                // A-105: the lost destroy decisions are registered again at
                // start and every `interval`, between jobs (this thread is
                // the one keyd client of the admin service).
                let mut due = Instant::now();
                loop {
                    let now = Instant::now();
                    if now >= due {
                        running.reconciler.run(&mut running.worker);
                        due = Instant::now().checked_add(interval).unwrap_or(now);
                        continue;
                    }
                    let job = match jobs.recv_timeout(due.saturating_duration_since(now)) {
                        Ok(job) => job,
                        Err(RecvTimeoutError::Timeout) => continue,
                        Err(RecvTimeoutError::Disconnected) => break,
                    };
                    let AdminJob { work, reply } = job;
                    let answer = running.handle(&work);
                    drop(work);
                    // The connection may be gone; its answer is dropped.
                    let _ = reply.send(answer);
                }
            })
            .map_err(|_| EngineError::Spawn)?;
        Ok((AdminEngineHandle { queue }, EngineThread { thread }))
    }
}
