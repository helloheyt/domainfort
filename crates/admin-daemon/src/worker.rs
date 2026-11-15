//! The worker: one OS thread owns admind's clients of dird and keyd (both
//! synchronous, blocking sockets with deadlines) and serves the operations
//! the listener hands it through a bounded queue (full ⇒ `Busy`, docs/50
//! R50-7). One operation at a time: dird serializes admin writes anyway
//! (one admin thread, docs/51 §7.5), and keyd one engine.
//!
//! # A forwarded operation (docs/51 §5.1, §7.6)
//!
//! The request goes to dird as it came — `auth` (the raw AP-REQs) is passed
//! on untouched, admind interprets, logs and alters none of it (A-70, A-73);
//! dird verifies, decides and audits. dird's reply goes back unchanged, a
//! refusal with dird's status by name. When dird gives no usable answer:
//!
//! | what the dird client reports | the administrator gets |
//! |---|---|
//! | not sent: connect, peer credentials, peer uid, unencodable | `Unavailable` |
//! | dird's shared refusal: `Busy` | the shared `Busy` |
//! | dird's shared refusal: `Unavailable`, `Malformed`, `VersionMismatch` | `Unavailable` (dird refused before acting) |
//! | after sending: deadline, close, I/O, framing, a reply that does not decode or answer | a write: `OutcomeUnknown` (dird may have committed — its audit trail says; never a resend, A-87); `Lookup`: `Unavailable` |
//!
//! # `SetPassword` (docs/51 §5.2 row 5, §7.6, §9; docs/47 §9.2)
//!
//! 0. **The audit slot** of its `Admind` event, reserved first; auditd
//!    unreachable or the window full ⇒ the shared `Busy`, nothing done
//!    (docs/51 §5.7; A-64).
//! 1. **The password rules that need only the password** — crate
//!    admin-password-policy's `check_password_text`, the text-only part of
//!    keyd's one rule set: at most 256 UTF-16 units, at least
//!    `min_password_length` characters, the character classes, no sequence,
//!    no repeat, no weak word ([MS-SAMR] 3.1.1.7.2 items 2, 3.2.1; docs/56 §7
//!    P-24) — before dird is asked, so such a password never makes dird act:
//!    a refusal is `Invalid`, event `Failed{Validation, PasswordPolicy}`.
//! 2. **dird `BeginPasswordSet`** with the request's `auth` — dird decides
//!    (`DirControlRight(User-Force-Change-Password)`, dual control), writes
//!    `pwdLastSet` first (R47-7) and answers the account kind, the key
//!    targets (handle + binding, 1 or 2) and the salt. Its reply must name
//!    the requested account's key sets, `PrincipalLongterm` first with an
//!    NT-PRINCIPAL binding of one component (docs/47 §9.1), else nothing is
//!    set (fail closed).
//! 3. **The whole rule set** — `check_password`, the very function keyd's
//!    install path runs, with keyd's inputs: the sAMAccountName of that
//!    NT-PRINCIPAL binding and the binding's realm (keyd binds every key set
//!    to its own realm, so for any install keyd could accept it is keyd's
//!    realm); only the minimum is admind's own `min_password_length` (keyd's
//!    is not visible to admind — task K9/K11). Non-authoritative: keyd checks
//!    again. Necessarily after step 2 for the name rules, which already moved
//!    `pwdLastSet` (that only revokes the account's tickets, which the
//!    requester was authorized to do; docs/47 §9.2 step 3 "a safe state") —
//!    docs/questions/Q-402, Q-910 item 13.
//! 4. **keyd `set_secret`** through `call_with_fate` (A-90), once per key
//!    target in dird's order (a computer: `PrincipalLongterm` then `Service`,
//!    the same password and salt — docs/47 §9.1); the first failure stops.
//! 5. **dird `CompletePasswordSet {outcome, kvnos}`** — whenever step 2
//!    succeeded — with the request's `completion` AP-REQ (keyd's replay cache
//!    makes the `BeginPasswordSet` one single-use; docs/questions/Q-400).
//! 6. **The `Admind` event** committed into its slot (`Completed`, or the
//!    first failing step with its class; the kvnos keyd chose), then the
//!    reply.
//!
//! | how it ended | the administrator gets |
//! |---|---|
//! | every `set_secret` succeeded | `PasswordChanged {kvnos, completion_recorded}` |
//! | a rule broken (step 1 or 3) | `Invalid` |
//! | dird refused / failed `BeginPasswordSet` | dird's status / `Unavailable` (no key changed) |
//! | keyd refused (`Denied`, `RateLimited`, `Unavailable`), or did not perform it (not sent, shared refusal) | `Denied` / `Unavailable` — or `Incomplete` if an earlier key set of the computer was already set |
//! | a `set_secret` reached keyd and no usable answer came back | `OutcomeUnknown` — check keyd's audit (intent + outcome) before retrying (A-88, A-90) |
//!
//! The password lives only in zeroizing buffers ([`ipc_admin::Password`],
//! one zeroizing copy per keyd call), never reaches dird, a log line, an
//! error or an event (docs/51 §7.6; docs/50 §3.3, §8.2).
//!
//! Spec: docs/51 §5.1, §5.2 row 5, §5.7, §7.6, §9; docs/47 §9.1, §9.2;
//! docs/10 §6; docs/50 R50-7, §3.6, §3.7; [MS-SAMR] 3.1.1.7.2; A-26; A-56;
//! A-64; A-70; A-73; A-79; A-85; A-87; A-88; A-90.

use crate::audit::AuditGate;
use crate::clock;
use crate::links::{DirdLink, KeydLink};
use crate::log::{Note, Thinned};
use crate::password;
use dtyp::Guid;
use ipc::Refused;
use ipc_admin::{Password, PasswordChanged, RefusalStatus, Reply, SetPassword};
use ipc_audit::{
    AdmindActivity, AdmindEvent, BoundedSeq, KeyPurposeCode, PasswordFailure, PasswordResult,
    PasswordStep,
};
use ipc_dird_admin::{
    AccountKind, Auth, Operation, PasswordSet, PasswordSetOutcome, Request as DirdRequest,
    TransportError as DirdTransport, Unserved as DirdUnserved,
};
use ipc_keyd::{Answer as KeydAnswer, Call, CallFailure, RequestFate, Unserved as KeydUnserved};
use keyd_types::KeyPurpose;
use krb_proto::constants::KRB_NT_PRINCIPAL;
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread::JoinHandle;
use tokio::sync::oneshot;

/// `SetPassword`s answered `Busy` for want of an audit slot (thinned log).
static AUDIT_UNAVAILABLE: Thinned = Thinned::new(Note::AuditUnavailable);
/// Events that could not be committed after their operation.
static EVENT_UNRECORDED: Thinned = Thinned::new(Note::EventUnrecorded);

/// What the worker answers.
/// Spec: docs/51 §7.6; docs/50 §3.3 (the shared `Refused`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Answer {
    /// One of the channel's replies.
    Reply(Reply),
    /// The shared transport refusal (the connection is kept).
    Refused(Refused),
}

/// What the worker serves.
#[derive(Debug)]
pub(crate) enum Work {
    /// An operation forwarded to dird unchanged.
    Forward {
        /// The raw AP-REQs, untouched.
        auth: Auth,
        /// The operation.
        operation: Operation,
    },
    /// `SetPassword`.
    SetPassword(SetPassword),
}

impl Work {
    /// The answer an administrator gets when the worker took the request
    /// and gave no answer (it ended — cannot happen without a panic, and no
    /// panic is allowed on this path): never "not done" for an operation
    /// that may have changed something (A-88, A-90).
    /// Spec: docs/questions/Q-370 item 9 (the same case in keyd-daemon).
    pub(crate) fn lost_answer(&self) -> Reply {
        match self {
            Work::Forward {
                operation: Operation::Lookup(_),
                ..
            } => Reply::Refused(RefusalStatus::Unavailable),
            _ => Reply::Refused(RefusalStatus::OutcomeUnknown),
        }
    }
}

/// One job for the worker.
struct Job {
    peer_uid: u32,
    work: Work,
    reply: oneshot::Sender<Answer>,
}

/// Why a job was not queued.
/// Spec: docs/50 R50-7.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SubmitError {
    /// The queue is full (`Busy`).
    Busy,
    /// The worker has ended.
    Stopped,
}

/// The sending side of the worker's queue (one per connection task).
#[derive(Debug, Clone)]
pub(crate) struct WorkerHandle {
    queue: SyncSender<Job>,
}

impl WorkerHandle {
    /// Queue one request without waiting. On `Err` the refused job — and
    /// with it any password — is dropped (zeroized) here at once.
    /// Spec: docs/50 R50-7 ("a bounded queue; full ⇒ `Busy`").
    pub(crate) fn submit(
        &self,
        peer_uid: u32,
        work: Work,
    ) -> Result<oneshot::Receiver<Answer>, SubmitError> {
        let (reply, answer) = oneshot::channel();
        match self.queue.try_send(Job {
            peer_uid,
            work,
            reply,
        }) {
            Ok(()) => Ok(answer),
            Err(TrySendError::Full(_)) => Err(SubmitError::Busy),
            Err(TrySendError::Disconnected(_)) => Err(SubmitError::Stopped),
        }
    }
}

/// What the worker owns.
/// Spec: docs/51 §5.1 ("admind is stateless and has no store").
pub(crate) struct Worker {
    /// dird's admin channel.
    pub(crate) dird: Box<dyn DirdLink>,
    /// keyd's channel (Role::Directory).
    pub(crate) keyd: Box<dyn KeydLink>,
    /// The audit window.
    pub(crate) gate: Arc<AuditGate>,
    /// `min_password_length` (A-79).
    pub(crate) min_password_length: u32,
}

impl Worker {
    /// Start the worker thread with a queue of `capacity` jobs; `on_exit`
    /// runs when the thread ends (the daemon notes an early end).
    ///
    /// # Errors
    /// The thread could not be spawned.
    pub(crate) fn spawn(
        self,
        capacity: usize,
        on_exit: impl FnOnce() + Send + 'static,
    ) -> std::io::Result<(WorkerHandle, JoinHandle<()>)> {
        let (queue, jobs) = sync_channel(capacity);
        let thread = std::thread::Builder::new()
            .name(String::from("admind-worker"))
            .spawn(move || {
                self.run(&jobs);
                on_exit();
            })?;
        Ok((WorkerHandle { queue }, thread))
    }

    /// Serve jobs until every sender is gone.
    fn run(mut self, jobs: &Receiver<Job>) {
        while let Ok(job) = jobs.recv() {
            let answer = match job.work {
                Work::Forward { auth, operation } => self.forward(auth, operation),
                Work::SetPassword(request) => self.set_password(job.peer_uid, request),
            };
            let _ = job.reply.send(answer);
        }
    }

    /// A forwarded operation (module documentation).
    /// Spec: docs/51 §5.1, §7.6; A-70; A-87.
    fn forward(&mut self, auth: Auth, operation: Operation) -> Answer {
        let lookup = matches!(operation, Operation::Lookup(_));
        let unknown = if lookup {
            RefusalStatus::Unavailable
        } else {
            RefusalStatus::OutcomeUnknown
        };
        let request = DirdRequest::Operation { auth, operation };
        match self.dird.call(&request) {
            Ok(reply) => Answer::Reply(Reply::from_dird(reply).unwrap_or(Reply::Refused(unknown))),
            Err(unserved) => match dird_fate(unserved) {
                DirdFate::Busy => Answer::Refused(Refused::Busy),
                DirdFate::NotDone => Answer::Reply(Reply::Refused(RefusalStatus::Unavailable)),
                DirdFate::Unknown => Answer::Reply(Reply::Refused(unknown)),
            },
        }
    }

    /// `SetPassword` (module documentation).
    /// Spec: docs/51 §5.2 row 5, §5.7, §7.6, §9.
    fn set_password(&mut self, peer_uid: u32, request: SetPassword) -> Answer {
        let Some(slot) = self.gate.reserve() else {
            AUDIT_UNAVAILABLE.hit(Some(peer_uid));
            return Answer::Refused(Refused::Busy);
        };
        let SetPassword {
            auth,
            completion,
            target,
            password,
        } = request;
        let ended = self.password_steps(auth, completion, target, &password);
        // The password's buffer is wiped here, before anything else happens.
        drop(password);
        let event = AdmindEvent {
            time: clock::event_time(),
            peer_uid: Some(peer_uid),
            activity: AdmindActivity::SetPassword {
                target: target.to_packet(),
                kvnos: BoundedSeq::new(ended.kvnos).unwrap_or_default(),
                result: ended.result,
            },
        };
        if self.gate.commit(slot, &event).is_err() {
            // The answer stays the true one; the gap is visible in the log.
            EVENT_UNRECORDED.hit(Some(peer_uid));
        }
        Answer::Reply(ended.reply)
    }

    /// Steps 1-5 of `SetPassword`.
    /// Spec: docs/51 §7.6; docs/47 §9.2.
    fn password_steps(
        &mut self,
        auth: Auth,
        completion: Vec<u8>,
        target: Guid,
        password: &Password,
    ) -> Ended {
        // 1. The rules that need only the password: the text-only part of
        //    keyd's rule set ([MS-SAMR] 3.1.1.7.2 items 2, 3.2.1, 3.2.4;
        //    docs/56 §7 P-24; Q-910 item 13).
        if password::check_password_text(password.expose(), self.min_password_length).is_err() {
            return Ended::refused(
                PasswordStep::Validation,
                PasswordFailure::PasswordPolicy,
                RefusalStatus::Invalid,
            );
        }
        // 2. dird's BeginPasswordSet (auth forwarded untouched).
        let begin = DirdRequest::Operation {
            auth,
            operation: Operation::BeginPasswordSet { target },
        };
        let set = match self.dird.call(&begin) {
            Ok(ipc_dird_admin::Reply::PasswordSet(set)) => set,
            Ok(ipc_dird_admin::Reply::Refused(status)) => {
                return Ended::refused(
                    PasswordStep::BeginPasswordSet,
                    dird_status_cause(status),
                    RefusalStatus::from_dird(status),
                )
            }
            // The client checks a reply answers its request: unreachable.
            Ok(_) => {
                return Ended::refused(
                    PasswordStep::BeginPasswordSet,
                    PasswordFailure::Malformed,
                    RefusalStatus::Unavailable,
                )
            }
            // No key was touched, whatever dird did: `Unavailable` is true
            // of the password.
            Err(unserved) => {
                return Ended::refused(
                    PasswordStep::BeginPasswordSet,
                    dird_unserved_cause(unserved),
                    RefusalStatus::Unavailable,
                )
            }
        };
        // dird's reply must describe the requested account (fail closed).
        let (Some(sam), Some(first)) = (account_name(&set, &target), set.keys.first()) else {
            // Reported whatever its own fate: nothing was set either way.
            let _reported =
                self.complete(completion, target, PasswordSetOutcome::Failed, Vec::new());
            return Ended::refused(
                PasswordStep::BeginPasswordSet,
                PasswordFailure::Malformed,
                RefusalStatus::Unavailable,
            );
        };
        // 3. The whole rule set, with keyd's inputs: the sAMAccountName and
        //    the realm of the account's binding (keyd binds every key set to
        //    its own realm); the minimum is admind's (Q-910 item 13).
        //    Non-authoritative — keyd's install path checks again.
        let inputs = password::PolicyInputs {
            min_chars: self.min_password_length,
            account_name: &[sam.as_str()],
            organisation_name: first.binding.realm.as_str(),
        };
        if password::check_password(password.expose(), &inputs).is_err() {
            // Reported whatever its own fate: nothing was set either way.
            let _reported =
                self.complete(completion, target, PasswordSetOutcome::Failed, Vec::new());
            return Ended::refused(
                PasswordStep::Validation,
                PasswordFailure::PasswordPolicy,
                RefusalStatus::Invalid,
            );
        }
        // 4. keyd set_secret, once per key target, through call_with_fate.
        let mut kvnos = Vec::with_capacity(set.keys.len());
        let mut failure: Option<(PasswordStep, PasswordFailure, RefusalStatus)> = None;
        for key in &set.keys {
            let step = PasswordStep::SetSecret(purpose_code(key.handle.purpose));
            let call = Call::SetSecret {
                handle: key.handle,
                binding: key.binding.clone(),
                password: ipc_keyd::Password::new(password.zeroizing_copy()),
                salt: set.salt.as_str().to_owned(),
            };
            let result = self.keyd.call_with_fate(&call);
            drop(call);
            match result {
                Ok(KeydAnswer::SetSecret(Ok(kvno))) => kvnos.push(kvno.get()),
                Ok(KeydAnswer::SetSecret(Err(error))) => {
                    failure = Some((step, keyd_error_cause(error), keyd_error_status(error)));
                    break;
                }
                // The client checks the answer belongs to the call:
                // unreachable — and keyd may have run it.
                Ok(_) => {
                    failure = Some((
                        step,
                        PasswordFailure::Malformed,
                        RefusalStatus::OutcomeUnknown,
                    ));
                    break;
                }
                Err(call_failure) => {
                    let (cause, status) = keyd_failure(call_failure);
                    failure = Some((step, cause, status));
                    break;
                }
            }
        }
        // 5. dird's CompletePasswordSet (the completion AP-REQ, untouched).
        let outcome = if failure.is_none() {
            PasswordSetOutcome::Completed
        } else {
            PasswordSetOutcome::Failed
        };
        let recorded = self.complete(completion, target, outcome, kvnos.clone());
        match failure {
            None => match recorded {
                Ok(()) => Ended {
                    reply: Reply::PasswordChanged(PasswordChanged {
                        kvnos: kvnos.clone(),
                        completion_recorded: true,
                    }),
                    kvnos,
                    result: PasswordResult::Completed,
                },
                Err(cause) => Ended {
                    reply: Reply::PasswordChanged(PasswordChanged {
                        kvnos: kvnos.clone(),
                        completion_recorded: false,
                    }),
                    kvnos,
                    result: PasswordResult::Failed {
                        step: PasswordStep::CompletePasswordSet,
                        cause,
                    },
                },
            },
            Some((step, cause, status)) => {
                // A computer whose first key set already holds the new
                // password: carried out in part (docs/51 §9) — unless the
                // failing call's own outcome is unknown.
                let status = if !kvnos.is_empty() && status != RefusalStatus::OutcomeUnknown {
                    RefusalStatus::Incomplete
                } else {
                    status
                };
                Ended {
                    reply: Reply::Refused(status),
                    kvnos,
                    result: PasswordResult::Failed { step, cause },
                }
            }
        }
    }

    /// dird's `CompletePasswordSet` with the `completion` AP-REQ (no
    /// approvals: it never needs dual control, directory-admin). `Ok` when
    /// dird answered `Done`; otherwise the failure's class.
    /// Spec: docs/51 §7.3 (`CompletePasswordSet {target, outcome, kvnos}`:
    /// "audit only, no state"), §9.
    fn complete(
        &mut self,
        completion: Vec<u8>,
        target: Guid,
        outcome: PasswordSetOutcome,
        kvnos: Vec<u32>,
    ) -> Result<(), PasswordFailure> {
        let request = DirdRequest::Operation {
            auth: Auth {
                requester: completion,
                approvals: Vec::new(),
            },
            operation: Operation::CompletePasswordSet {
                target,
                outcome,
                kvnos,
            },
        };
        match self.dird.call(&request) {
            Ok(ipc_dird_admin::Reply::Done) => Ok(()),
            Ok(ipc_dird_admin::Reply::Refused(status)) => Err(dird_status_cause(status)),
            Ok(_) => Err(PasswordFailure::Malformed),
            Err(unserved) => Err(dird_unserved_cause(unserved)),
        }
    }
}

/// How a `SetPassword` ended: the reply, the key versions keyd chose, the
/// event's result.
struct Ended {
    reply: Reply,
    kvnos: Vec<u32>,
    result: PasswordResult,
}

impl Ended {
    /// Refused or failed before any key was set.
    fn refused(step: PasswordStep, cause: PasswordFailure, status: RefusalStatus) -> Ended {
        Ended {
            reply: Reply::Refused(status),
            kvnos: Vec::new(),
            result: PasswordResult::Failed { step, cause },
        }
    }
}

/// The sAMAccountName of dird's `BeginPasswordSet` reply, if the reply
/// describes the requested account: every key target is `target`'s; the
/// first is `PrincipalLongterm` with an NT-PRINCIPAL binding of exactly one
/// component (the sAMAccountName); a user has one key target, a computer
/// one, or two with `Service` second.
/// Spec: docs/47 §9.1 (the bindings: "`(REALM, NT-PRINCIPAL
/// [sAMAccountName])`"); docs/51 §7.3 ("handles (1 or 2), bindings").
fn account_name(set: &PasswordSet, target: &Guid) -> Option<String> {
    let packet = target.to_packet();
    if set
        .keys
        .iter()
        .any(|key| key.handle.principal.as_bytes() != &packet)
    {
        return None;
    }
    let first = set.keys.first()?;
    if first.handle.purpose != KeyPurpose::PrincipalLongterm {
        return None;
    }
    let shape_ok = match (set.kind, set.keys.len()) {
        (AccountKind::User, 1) | (AccountKind::Computer, 1) => true,
        (AccountKind::Computer, 2) => set
            .keys
            .get(1)
            .is_some_and(|key| key.handle.purpose == KeyPurpose::Service),
        _ => false,
    };
    if !shape_ok {
        return None;
    }
    let name = &first.binding.name;
    if name.name_type != KRB_NT_PRINCIPAL || name.name_string.len() != 1 {
        return None;
    }
    name.name_string
        .first()
        .map(|component| component.as_str().to_owned())
}

/// The audit code of a key purpose. Spec: crate ipc-audit `KeyPurposeCode`.
fn purpose_code(purpose: KeyPurpose) -> KeyPurposeCode {
    match purpose {
        KeyPurpose::PrincipalLongterm => KeyPurposeCode::PrincipalLongterm,
        KeyPurpose::Krbtgt => KeyPurposeCode::Krbtgt,
        KeyPurpose::Service => KeyPurposeCode::Service,
        // Never a `set_secret` target (R2; task K3) — named for completeness.
        KeyPurpose::AdminService => KeyPurposeCode::AdminService,
        KeyPurpose::ChangePasswordService => KeyPurposeCode::ChangePasswordService,
    }
}

/// What the dird client's failure says about the request (module
/// documentation, the forwarded-operation table).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirdFate {
    /// dird answered the shared `Busy`.
    Busy,
    /// The request never reached dird, or dird refused it before acting.
    NotDone,
    /// The request may have reached dird; no usable answer came back.
    Unknown,
}

/// Spec: crate ipc-dird-admin client documentation ("What the caller
/// sees"); docs/50 §3.7; A-87; docs/questions/Q-404.
fn dird_fate(unserved: DirdUnserved) -> DirdFate {
    match unserved {
        DirdUnserved::Transport(DirdTransport::Connect | DirdTransport::PeerCredentials)
        | DirdUnserved::PeerMismatch
        | DirdUnserved::Unencodable => DirdFate::NotDone,
        DirdUnserved::Refused(Refused::Busy) => DirdFate::Busy,
        DirdUnserved::Refused(
            Refused::Unavailable | Refused::Malformed | Refused::VersionMismatch,
        ) => DirdFate::NotDone,
        DirdUnserved::Transport(
            DirdTransport::DeadlineExceeded
            | DirdTransport::Closed
            | DirdTransport::Io
            | DirdTransport::Framing,
        )
        | DirdUnserved::MalformedReply(_)
        | DirdUnserved::UnexpectedReply(_) => DirdFate::Unknown,
    }
}

/// The event class of dird's own refusal: dird's uniform refusal is
/// `Denied`; `Unavailable` is dird's "could not be carried out now".
/// Spec: crate ipc-audit `PasswordFailure` ("`Denied` … dird's uniform
/// refusal"); A-26.
fn dird_status_cause(status: ipc_dird_admin::RefusalStatus) -> PasswordFailure {
    match status {
        ipc_dird_admin::RefusalStatus::Unavailable => PasswordFailure::Unavailable,
        ipc_dird_admin::RefusalStatus::Denied
        | ipc_dird_admin::RefusalStatus::ApprovalRequired
        | ipc_dird_admin::RefusalStatus::NotFound
        | ipc_dird_admin::RefusalStatus::Invalid
        | ipc_dird_admin::RefusalStatus::Conflict => PasswordFailure::Denied,
    }
}

/// The event class of a dird client failure: the shared refusal by name; a
/// reply that did not decode is `Malformed`; a transport failure **after**
/// the request was handed to dird (deadline, close, I/O, framing) is
/// `OutcomeUnknown` (task F6 — dird may have acted on it, A-88 / A-90);
/// one before sending (connect, peer credentials, peer uid, unencodable) is
/// `Unavailable`.
/// Spec: crate ipc-audit `PasswordFailure`; docs/questions/Q-404 item 5,
/// Q-406 item 2 (A-94).
fn dird_unserved_cause(unserved: DirdUnserved) -> PasswordFailure {
    match unserved {
        DirdUnserved::Refused(refused) => refused_cause(refused),
        DirdUnserved::MalformedReply(_) | DirdUnserved::UnexpectedReply(_) => {
            PasswordFailure::Malformed
        }
        DirdUnserved::Transport(
            DirdTransport::DeadlineExceeded
            | DirdTransport::Closed
            | DirdTransport::Io
            | DirdTransport::Framing,
        ) => PasswordFailure::OutcomeUnknown,
        DirdUnserved::Transport(DirdTransport::Connect | DirdTransport::PeerCredentials)
        | DirdUnserved::PeerMismatch
        | DirdUnserved::Unencodable => PasswordFailure::Unavailable,
    }
}

/// The shared refusal by name. Spec: crate ipc-audit `PasswordFailure`.
fn refused_cause(refused: Refused) -> PasswordFailure {
    match refused {
        Refused::Busy => PasswordFailure::Busy,
        Refused::Unavailable => PasswordFailure::Unavailable,
        Refused::Malformed => PasswordFailure::Malformed,
        Refused::VersionMismatch => PasswordFailure::VersionMismatch,
    }
}

/// keyd's own refusal of `set_secret`: the event class.
/// Spec: crates/keyd-types error.rs (`Error`); crate ipc-audit
/// `PasswordFailure`.
fn keyd_error_cause(error: keyd_types::Error) -> PasswordFailure {
    match error {
        keyd_types::Error::Denied => PasswordFailure::Denied,
        keyd_types::Error::RateLimited => PasswordFailure::RateLimited,
        keyd_types::Error::Unavailable => PasswordFailure::Unavailable,
    }
}

/// keyd's own refusal of `set_secret`: what the administrator is told. keyd
/// did not set the key in any of these cases (docs/10 §9, §10).
/// Spec: docs/10 §9; A-26; A-56.
fn keyd_error_status(error: keyd_types::Error) -> RefusalStatus {
    match error {
        keyd_types::Error::Denied => RefusalStatus::Denied,
        keyd_types::Error::RateLimited | keyd_types::Error::Unavailable => {
            RefusalStatus::Unavailable
        }
    }
}

/// A `set_secret` keyd did not answer with a result: the event class and
/// what the administrator is told — "outcome unknown" whenever the request
/// may have reached keyd, never "not done" (A-88, A-90). The event records
/// a transport failure of a request whose fate is unknown as
/// `OutcomeUnknown` (task F6; before it, `Unavailable` — Q-406 item 2).
/// Spec: docs/50 §3.7; docs/questions/Q-367, Q-370 (`RequestFate`), Q-406.
fn keyd_failure(failure: CallFailure) -> (PasswordFailure, RefusalStatus) {
    let cause = match failure.unserved {
        KeydUnserved::Refused(refused) => refused_cause(refused),
        KeydUnserved::MalformedReply(_) | KeydUnserved::UnexpectedReply(_) => {
            PasswordFailure::Malformed
        }
        KeydUnserved::Transport(_) if failure.fate == RequestFate::OutcomeUnknown => {
            PasswordFailure::OutcomeUnknown
        }
        KeydUnserved::Transport(_) | KeydUnserved::PeerMismatch | KeydUnserved::Unencodable => {
            PasswordFailure::Unavailable
        }
    };
    let status = match failure.fate {
        RequestFate::NotSent | RequestFate::NotPerformed => RefusalStatus::Unavailable,
        RequestFate::OutcomeUnknown => RefusalStatus::OutcomeUnknown,
    };
    (cause, status)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipc_dird_admin::KeyTarget;
    use keyd_types::{KeyHandle, PrincipalBinding, PrincipalId};
    use krb_proto::constants::KRB_NT_SRV_HST;
    use krb_proto::{KerberosString, PrincipalName};

    fn guid(n: u32) -> Guid {
        Guid {
            data1: n,
            data2: 0xA9,
            data3: 0x0001,
            data4: [9; 8],
        }
    }

    fn target(g: Guid, purpose: KeyPurpose, name_type: i32, names: &[&str]) -> KeyTarget {
        KeyTarget {
            handle: KeyHandle::new(PrincipalId::from_bytes(g.to_packet()), purpose),
            binding: PrincipalBinding::new(
                KerberosString::new("EXAMPLE.ORG").unwrap(),
                PrincipalName {
                    name_type,
                    name_string: names
                        .iter()
                        .map(|n| KerberosString::new(n).unwrap())
                        .collect(),
                },
            ),
        }
    }

    fn set(kind: AccountKind, keys: Vec<KeyTarget>) -> PasswordSet {
        PasswordSet {
            kind,
            keys,
            salt: KerberosString::new("EXAMPLE.ORGcarol").unwrap(),
        }
    }

    /// docs/47 §9.1: the sAMAccountName is the one component of the
    /// NT-PRINCIPAL binding of the `PrincipalLongterm` key set; anything
    /// else in dird's reply is refused (fail closed).
    #[test]
    fn the_account_name_comes_from_the_nt_principal_binding() {
        let g = guid(1);
        let user = set(
            AccountKind::User,
            vec![target(
                g,
                KeyPurpose::PrincipalLongterm,
                KRB_NT_PRINCIPAL,
                &["carol"],
            )],
        );
        assert_eq!(account_name(&user, &g).as_deref(), Some("carol"));
        let computer = set(
            AccountKind::Computer,
            vec![
                target(
                    g,
                    KeyPurpose::PrincipalLongterm,
                    KRB_NT_PRINCIPAL,
                    &["ws9$"],
                ),
                target(
                    g,
                    KeyPurpose::Service,
                    KRB_NT_SRV_HST,
                    &["host", "ws9.example.org"],
                ),
            ],
        );
        assert_eq!(account_name(&computer, &g).as_deref(), Some("ws9$"));
        // Another account's key set, a Service first, two user key sets, a
        // name of two components, another name type, no key: refused.
        assert_eq!(account_name(&user, &guid(2)), None);
        let refused = [
            set(
                AccountKind::Computer,
                vec![target(
                    g,
                    KeyPurpose::Service,
                    KRB_NT_SRV_HST,
                    &["host", "x"],
                )],
            ),
            set(
                AccountKind::User,
                vec![
                    target(g, KeyPurpose::PrincipalLongterm, KRB_NT_PRINCIPAL, &["a"]),
                    target(g, KeyPurpose::Service, KRB_NT_SRV_HST, &["host", "x"]),
                ],
            ),
            set(
                AccountKind::User,
                vec![target(
                    g,
                    KeyPurpose::PrincipalLongterm,
                    KRB_NT_PRINCIPAL,
                    &["a", "b"],
                )],
            ),
            set(
                AccountKind::User,
                vec![target(
                    g,
                    KeyPurpose::PrincipalLongterm,
                    KRB_NT_SRV_HST,
                    &["carol"],
                )],
            ),
            set(AccountKind::User, vec![]),
            set(
                AccountKind::Computer,
                vec![
                    target(g, KeyPurpose::PrincipalLongterm, KRB_NT_PRINCIPAL, &["w$"]),
                    target(g, KeyPurpose::PrincipalLongterm, KRB_NT_PRINCIPAL, &["w$"]),
                ],
            ),
        ];
        for candidate in refused {
            assert_eq!(account_name(&candidate, &g), None, "{candidate:?}");
        }
    }

    /// docs/50 §3.7; A-87; docs/questions/Q-404: only a request that never
    /// reached dird, or that dird refused, is "not done".
    #[test]
    fn dird_fates() {
        use ipc_dird_admin::ConversionError;
        for (unserved, fate) in [
            (
                DirdUnserved::Transport(DirdTransport::Connect),
                DirdFate::NotDone,
            ),
            (
                DirdUnserved::Transport(DirdTransport::PeerCredentials),
                DirdFate::NotDone,
            ),
            (DirdUnserved::PeerMismatch, DirdFate::NotDone),
            (DirdUnserved::Unencodable, DirdFate::NotDone),
            (DirdUnserved::Refused(Refused::Busy), DirdFate::Busy),
            (
                DirdUnserved::Refused(Refused::Unavailable),
                DirdFate::NotDone,
            ),
            (
                DirdUnserved::Transport(DirdTransport::DeadlineExceeded),
                DirdFate::Unknown,
            ),
            (
                DirdUnserved::Transport(DirdTransport::Closed),
                DirdFate::Unknown,
            ),
            (
                DirdUnserved::MalformedReply(ipc::Error::Truncated),
                DirdFate::Unknown,
            ),
            (
                DirdUnserved::UnexpectedReply(ConversionError::UnexpectedReply),
                DirdFate::Unknown,
            ),
        ] {
            assert_eq!(dird_fate(unserved), fate, "{unserved:?}");
        }
    }

    /// docs/50 §3.7; A-88, A-90: keyd's fates — "outcome unknown" is never
    /// reported as "not done".
    #[test]
    fn keyd_fates() {
        let failure = |unserved, fate| CallFailure { unserved, fate };
        assert_eq!(
            keyd_failure(failure(
                KeydUnserved::Transport(ipc_keyd::TransportError::Connect),
                RequestFate::NotSent
            )),
            (PasswordFailure::Unavailable, RefusalStatus::Unavailable)
        );
        assert_eq!(
            keyd_failure(failure(
                KeydUnserved::Refused(Refused::Busy),
                RequestFate::NotPerformed
            )),
            (PasswordFailure::Busy, RefusalStatus::Unavailable)
        );
        // Task F6 (Q-406 item 2): the event says "outcome unknown" too.
        assert_eq!(
            keyd_failure(failure(
                KeydUnserved::Transport(ipc_keyd::TransportError::DeadlineExceeded),
                RequestFate::OutcomeUnknown
            )),
            (
                PasswordFailure::OutcomeUnknown,
                RefusalStatus::OutcomeUnknown
            )
        );
        // Not sent: the event says "unavailable".
        assert_eq!(
            keyd_failure(failure(
                KeydUnserved::Transport(ipc_keyd::TransportError::DeadlineExceeded),
                RequestFate::NotSent
            )),
            (PasswordFailure::Unavailable, RefusalStatus::Unavailable)
        );
        // dird: after sending ⇒ OutcomeUnknown, before ⇒ Unavailable.
        assert_eq!(
            dird_unserved_cause(DirdUnserved::Transport(DirdTransport::Closed)),
            PasswordFailure::OutcomeUnknown
        );
        assert_eq!(
            dird_unserved_cause(DirdUnserved::Transport(DirdTransport::Connect)),
            PasswordFailure::Unavailable
        );
        assert_eq!(
            keyd_failure(failure(
                KeydUnserved::MalformedReply(ipc::Error::Truncated),
                RequestFate::OutcomeUnknown
            )),
            (PasswordFailure::Malformed, RefusalStatus::OutcomeUnknown)
        );
        assert_eq!(
            keyd_error_status(keyd_types::Error::Denied),
            RefusalStatus::Denied
        );
        assert_eq!(
            keyd_error_cause(keyd_types::Error::RateLimited),
            PasswordFailure::RateLimited
        );
    }
}
