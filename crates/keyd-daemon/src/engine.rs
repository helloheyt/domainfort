//! The engine: one dedicated OS thread owns `Keyd`, fed through a bounded
//! queue.
//!
//! # Design (docs/50 R50-7, §3.6)
//!
//! * keyd's operations take `&mut self`; one thread holds the [`keyd::Keyd`]
//!   and serves requests one at a time. The connection tasks (tokio) read a
//!   whole request frame, then hand its body with the connection's
//!   [`CallerId`] and a reply `oneshot` to the engine through a **bounded**
//!   `tokio::sync::mpsc` channel ("capacity … the maximum number of values
//!   that can be stored").
//! * Queue full → the connection answers `Refused::Busy` at once
//!   ([`EngineHandle::submit`] uses `try_send`); never an unbounded queue and
//!   never `spawn_blocking` (whose queue has no back-pressure, per the tokio
//!   `runtime::Builder` page).
//! * Per request the engine reads **its own clock** (R50-5), decodes the
//!   body ([`ipc_keyd::decode_request`]), classifies it
//!   ([`ipc_keyd_server::classify`]: does keyd's authorization step admit a
//!   change that needs an acknowledged intent?), passes the A-57 audit gate
//!   (`crate::audit`), runs the call on keyd ([`ipc_keyd_server::execute`],
//!   or [`ipc_keyd_server::execute_acknowledged`] with the proof) with the
//!   transport's caller and that `now`, commits keyd's record, and encodes
//!   the answer ([`ipc_keyd::encode_answer`]). This is the sequence of
//!   ipc-keyd-server's loopback `dispatch` with the gate inserted between
//!   decoding and running — `dispatch` has no point at which a slot could be
//!   reserved after the operation is known and before keyd runs it, and
//!   decoding the body twice would double the strict DER work on the one
//!   engine thread (docs/questions/Q-260 item 3). The refusal rules are
//!   `dispatch`'s.
//! * The hold-down start (`started_at`) is read from the same clock when the
//!   engine is constructed ([`Engine::start`], A-62: `Keyd::new(…,
//!   started_at)`).
//!
//! # Key-state changes: intent acknowledged, then the change (decision A-86)
//!
//! A call that changes keyd's key state (`keyd::changes_key_state`) — or
//! loosens keyd's authorization (`grant_set_secret`, task A15a;
//! `register_decision`, A-102; both: `keyd::requires_acknowledged_intent`,
//! docs/questions/Q-452) — and that keyd's own authorization step admits
//! (`keyd::Keyd::admits`: role, purpose, the ceremony state, and for
//! `set_secret` a live decision; for an execution by decision id,
//! `keyd::Keyd::decided_intent`: a pending decision of its kind, whose
//! registered parameters fill the intent — A-102) takes another path
//! (crate::audit, steps 1-3): the intent record
//! is committed and **acknowledged by auditd before keyd runs the call**; no
//! acknowledgement in time ⇒ `Refused::Unavailable` and keyd does not run
//! it; after the change keyd's own record (the true result) is committed and
//! the true result is the reply, even if that record could not be committed
//! (the gap is counted). An authorization refusal takes the ordinary path:
//! one record, no intent, no wait.
//!
//! **By construction (docs/52 §3.11 R6):** the classification is
//! [`ipc_keyd_server::classify`]'s; an admitted change is a
//! `ipc_keyd_server::KeyStateCall` that only
//! [`ipc_keyd_server::execute_acknowledged`] runs, and only with the
//! `ipc_audit_client::AckedIntent` the shared gate gives after auditd's
//! acknowledgement; [`ipc_keyd_server::execute`] refuses (`NotRun`) to run
//! a plain call that keyd would now admit as such a change.
//!
//! **The wait and issuance.** The wait blocks this thread — the one that
//! serves every keyd call, the Kerberos exchanges included — so it is
//! bounded by the daemon's [`IntentAckBudget`] ([`INTENT_ACK_BUDGET`] in
//! production, never above [`MAX_INTENT_ACK_BUDGET`]), counted from the
//! moment the request was **queued** ([`EngineHandle::submit`]), not from
//! the moment the engine took it:
//!
//! * the production budget is half the keyd client's 2 s deadline (docs/50
//!   §3.6), so a change that is performed has the other half to run and to
//!   reach a caller that keeps that deadline — a reply arriving after the
//!   caller gave up would read as "unavailable" for a change that was done,
//!   the very ambiguity A-86 removes (what is left of it:
//!   docs/questions/Q-365);
//! * counted from queueing, a burst of changes holds the engine at most until
//!   the last one's budget ends, so a kdc request queued behind them is served
//!   within the budget plus the queue's own work — inside its own 2 s
//!   deadline.
//!
//! The budget is a daemon parameter (`test_seams::DaemonParams::intent_ack_budget`,
//! decision A-93's follow-up F5; a test seam only since docs/52 R15 — the
//! product parameters have no field for it) only so that tests on a loaded machine can
//! give a slow auditd more time, together with a client that waits
//! correspondingly longer. Production takes [`INTENT_ACK_BUDGET`] — there is
//! no configuration key — and no budget above [`MAX_INTENT_ACK_BUDGET`] can
//! be built (docs/questions/Q-415).
//!
//! The single-threaded engine and the bounded queue are unchanged. While
//! auditd is known to be away, changes are refused `Busy` at once, with no
//! wait (the gate's reachability, A-67 item 2); only a reachable but slow
//! auditd makes the engine wait, at most the budget per change.
//!
//! # Threads and hardening
//!
//! The engine thread is spawned by [`Engine::spawn`], which the daemon calls
//! only inside its tokio runtime — that is, after `main` applied the
//! process-wide hardening (identity drop, no_new_privs, capabilities, rlimits,
//! not-dumpable, mlockall) on the then only thread (R50-14; rustix's identity
//! calls act on the calling thread, so the drop must precede every thread).
//! The thread therefore inherits the hardened identity; it does nothing to
//! change it.
//!
//! Spec: docs/50 R50-5, R50-6, R50-7, R50-14, §3.5, §3.6; docs/10 §2, §11;
//! docs/questions/Q-218 (A-57), Q-222 (A-56), Q-240 item 7 (A-62), Q-245
//! item 12 (A-63), Q-346 (A-86), Q-365, Q-415.

use crate::audit::{AuditGate, IntentRefused, RecordBuffer, Waited};
use crate::clock::Clock;
use crate::log::{Note, Thinned};
use core::fmt;
use core::time::Duration;
use ipc::{encode_refused, Refused};
use ipc_keyd::{decode_request, encode_answer, KEYD_CHANNEL};
use ipc_keyd_server::{
    classify, execute, execute_acknowledged, Classified, Dispatch, KeyStateCall,
};
use keyd::{CallerId, ConfigError, EntropySource, KeyStore, Keyd};
use krb_proto::KerberosTime;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{mpsc, oneshot};
use zeroize::Zeroizing;

/// Largest engine queue accepted by [`Engine::spawn`]. Project bound
/// (tokio's `mpsc::channel` panics on 0 or "too large"; docs/CLEAN-ROOM.md).
pub const MAX_QUEUE_CAPACITY: usize = 1024;

/// The production intent-acknowledgement budget: how long after a key-state
/// change was queued its intent record may take to be acknowledged by
/// auditd; past it the change is answered `Refused::Unavailable` and not run
/// (module documentation). Half the keyd client's deadline (docs/50 §3.6:
/// 2 s), so a performed change has the other half to reach its caller.
/// Project choice (docs/50 gives no audit deadline; docs/questions/Q-365,
/// decided A-88). Every production daemon uses it
/// ([`IntentAckBudget::PRODUCTION`]; `DaemonParams::from_settings`).
pub const INTENT_ACK_BUDGET: Duration = Duration::from_secs(1);

/// The ceiling of any daemon's intent-acknowledgement budget: the longest
/// deadline a production keyd client waits for its reply — ipc-keyd's
/// `DEFAULT_DEADLINE`, which the kdc and dird use, and the most crates/config
/// accepts for any `keyd_deadline` key (`KEYD_DEADLINE_SECS`), both docs/50
/// §3.6's 2 s. A longer wait could only perform changes after every
/// production caller has given up — each would then read a performed change
/// as "unavailable", the ambiguity A-86 removes — and would hold every
/// Kerberos request queued behind it past its own deadline. Production stays
/// at half of it ([`INTENT_ACK_BUDGET`], the A-88 rule); a budget between the
/// two exists only for tests whose own client waits at least twice as long.
/// Project choice (docs/questions/Q-415).
pub const MAX_INTENT_ACK_BUDGET: Duration = ipc_keyd::DEFAULT_DEADLINE;

// The production budget leaves at least half the client's deadline for the
// change and the reply (docs/questions/Q-365, A-88).
const _: () = assert!(INTENT_ACK_BUDGET.as_nanos() * 2 <= ipc_keyd::DEFAULT_DEADLINE.as_nanos());
// The production budget is within the ceiling, and the ceiling is no longer
// than any deadline a production keyd client may be configured with
// (docs/questions/Q-415).
const _: () = assert!(INTENT_ACK_BUDGET.as_nanos() <= MAX_INTENT_ACK_BUDGET.as_nanos());
const _: () = assert!(
    MAX_INTENT_ACK_BUDGET.as_nanos() <= ipc_keyd::DEFAULT_DEADLINE.as_nanos()
        && MAX_INTENT_ACK_BUDGET.as_secs() <= config::limits::KEYD_DEADLINE_SECS.max as u64
);

/// The intent-acknowledgement budget of one daemon: more than zero and at
/// most [`MAX_INTENT_ACK_BUDGET`]. The range is checked when the value is
/// built ([`IntentAckBudget::new`]), so a `DaemonParams` can only carry a
/// budget within the ceiling. There is no configuration key for it: the
/// daemon's parameters from its file always hold
/// [`IntentAckBudget::PRODUCTION`].
/// Spec: docs/questions/Q-365 (A-88), Q-415; A-93 (follow-up F5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntentAckBudget(Duration);

/// A budget of zero or above [`MAX_INTENT_ACK_BUDGET`] was refused.
/// Spec: docs/questions/Q-415.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntentAckBudgetOutOfRange;

impl fmt::Display for IntentAckBudgetOutOfRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("intent acknowledgement budget out of range")
    }
}

impl std::error::Error for IntentAckBudgetOutOfRange {}

impl IntentAckBudget {
    /// [`INTENT_ACK_BUDGET`], the budget of every production daemon.
    pub const PRODUCTION: IntentAckBudget = IntentAckBudget(INTENT_ACK_BUDGET);

    /// `budget`, if it is more than zero and at most
    /// [`MAX_INTENT_ACK_BUDGET`].
    ///
    /// # Errors
    /// [`IntentAckBudgetOutOfRange`]: zero (every key-state change would be
    /// refused — a fault, not a setting) or above the ceiling.
    ///
    /// Spec: docs/questions/Q-415.
    pub const fn new(budget: Duration) -> Result<IntentAckBudget, IntentAckBudgetOutOfRange> {
        if budget.is_zero() || budget.as_nanos() > MAX_INTENT_ACK_BUDGET.as_nanos() {
            Err(IntentAckBudgetOutOfRange)
        } else {
            Ok(IntentAckBudget(budget))
        }
    }

    /// The budget.
    #[must_use]
    pub const fn get(self) -> Duration {
        self.0
    }
}

/// Outcome records of key-state changes that could not be committed: noted
/// on stderr (thinned), counted by the gate (A-86: "the gap is surfaced").
static OUTCOME_UNRECORDED: Thinned = Thinned::new(Note::OutcomeUnrecorded);

/// Why the engine could not start.
/// Spec: docs/50 §7.5 ("every daemon exits with an error code on any start-up
/// failure").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineError {
    /// The clock could not be read for the hold-down start (R50-5).
    Clock,
    /// keyd refused its configuration.
    Config(ConfigError),
    /// The queue capacity is 0 or above [`MAX_QUEUE_CAPACITY`].
    QueueCapacity,
    /// The operating system refused the engine thread.
    Spawn,
}

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EngineError::Clock => f.write_str("engine: clock unreadable"),
            EngineError::Config(_) => f.write_str("engine: keyd configuration refused"),
            EngineError::QueueCapacity => f.write_str("engine: queue capacity out of range"),
            EngineError::Spawn => f.write_str("engine: thread could not be started"),
        }
    }
}

impl std::error::Error for EngineError {}

/// One request for the engine: the connection's caller identity (from its
/// peer credentials), the request body (zeroized on drop: it may carry a
/// password), when it was queued (the start of a key-state change's
/// [`IntentAckBudget`]), and where to send the outcome.
/// Spec: docs/50 R50-7, §3.2, §3.3 (secret-bearing buffers wiped);
/// docs/questions/Q-346 (A-86).
pub(crate) struct Job {
    caller: CallerId,
    body: Zeroizing<Vec<u8>>,
    queued: Instant,
    reply: oneshot::Sender<Dispatch>,
}

/// Why a request was not queued.
/// Spec: docs/50 §3.6, §3.7.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SubmitError {
    /// The queue is full: answer `Refused::Busy` at once (R50-7).
    Busy,
    /// The engine has stopped: answer `Refused::Unavailable`.
    Stopped,
}

/// The sending side of the engine queue; one clone per connection task.
/// Spec: docs/50 R50-7.
#[derive(Debug, Clone)]
pub struct EngineHandle {
    queue: mpsc::Sender<Job>,
}

impl EngineHandle {
    /// Queue one request without waiting: a full queue is
    /// [`SubmitError::Busy`]. The receiver yields the engine's outcome; if
    /// the engine drops the job unanswered the receiver fails.
    /// Spec: docs/50 R50-7 ("queue full ⇒ immediate `Busy`").
    pub(crate) fn submit(
        &self,
        caller: CallerId,
        body: Zeroizing<Vec<u8>>,
    ) -> Result<oneshot::Receiver<Dispatch>, SubmitError> {
        let (reply, outcome) = oneshot::channel();
        match self.queue.try_send(Job {
            caller,
            body,
            queued: Instant::now(),
            reply,
        }) {
            Ok(()) => Ok(outcome),
            // The rejected job (and its body) is dropped and wiped here.
            Err(mpsc::error::TrySendError::Full(_)) => Err(SubmitError::Busy),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(SubmitError::Stopped),
        }
    }
}

/// The engine thread, to be joined after the daemon stopped.
#[derive(Debug)]
pub struct EngineThread {
    thread: std::thread::JoinHandle<()>,
}

/// The engine thread ended by unwinding (a defect): nothing was lost that
/// keyd held durably — the development store holds nothing durably.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnginePanicked;

impl EngineThread {
    /// Wait for the engine thread. It ends when every [`EngineHandle`] is
    /// dropped and the queue is drained.
    ///
    /// # Errors
    /// [`EnginePanicked`] if the thread unwound.
    pub fn join(self) -> Result<(), EnginePanicked> {
        self.thread.join().map_err(|_| EnginePanicked)
    }
}

/// A refusal frame, then close (the refusal rule of
/// `ipc_keyd_server::dispatch`). A refusal that cannot be encoded (never,
/// given ipc's minimum body bound) closes without a reply.
/// Spec: docs/50 §3.3; A-59.
pub(crate) fn refuse(refused: Refused) -> Dispatch {
    match encode_refused(KEYD_CHANNEL, refused) {
        Ok(frame) => Dispatch::ReplyAndClose(frame),
        Err(_) => Dispatch::Close,
    }
}

/// A refusal frame; the connection stays open (`Busy`: try again later).
/// Spec: docs/50 §3.6.
pub(crate) fn refuse_and_stay(refused: Refused) -> Dispatch {
    match encode_refused(KEYD_CHANNEL, refused) {
        Ok(frame) => Dispatch::Reply(frame),
        Err(_) => Dispatch::Close,
    }
}

/// Runs a closure when dropped — on normal return and on unwinding.
struct OnExit<F: FnOnce()>(Option<F>);

impl<F: FnOnce()> Drop for OnExit<F> {
    fn drop(&mut self) {
        if let Some(f) = self.0.take() {
            f();
        }
    }
}

/// The engine: keyd, the clock it reads `now` from, the audit gate, and the
/// daemon's intent-acknowledgement budget.
/// Spec: docs/50 R50-5, R50-7; docs/questions/Q-365, Q-415.
pub(crate) struct Engine<S: KeyStore, E: EntropySource, C: Clock> {
    keyd: Keyd<S, RecordBuffer, E>,
    clock: C,
    gate: Arc<AuditGate>,
    budget: IntentAckBudget,
}

impl<S, E, C> Engine<S, E, C>
where
    S: KeyStore + Send + 'static,
    E: EntropySource + Send + 'static,
    C: Clock,
{
    /// Construct the engine: read the clock once for the hold-down start and
    /// build keyd with it (`build` is `Keyd::new` with the development store
    /// in the daemon, a deterministic test keyd in tests). `budget` bounds
    /// every key-state change's wait for its intent's acknowledgement.
    ///
    /// # Errors
    /// [`EngineError::Clock`], [`EngineError::Config`].
    ///
    /// Spec: docs/50 R50-5, R50-6, §3.5; docs/10 §11 (`Keyd::new(…,
    /// started_at)`); A-62; docs/questions/Q-365, Q-415.
    pub(crate) fn start<F>(
        clock: C,
        gate: Arc<AuditGate>,
        budget: IntentAckBudget,
        build: F,
    ) -> Result<Self, EngineError>
    where
        F: FnOnce(&KerberosTime) -> Result<Keyd<S, RecordBuffer, E>, ConfigError>,
    {
        let started_at = clock.now().ok_or(EngineError::Clock)?;
        let keyd = build(&started_at).map_err(EngineError::Config)?;
        Ok(Engine {
            keyd,
            clock,
            gate,
            budget,
        })
    }

    /// The engine's keyd, for tier-1 tests that set up state (a set_secret
    /// grant) straight in it. Tests only.
    #[cfg(test)]
    pub(crate) fn keyd_mut(&mut self) -> &mut Keyd<S, RecordBuffer, E> {
        &mut self.keyd
    }

    /// Serve one request body as `caller`, queued at `queued` (module
    /// documentation).
    ///
    /// Spec: docs/50 R50-5, §3.3, §3.7; docs/questions/Q-218 (A-57), Q-346
    /// (A-86); crates/ipc-keyd-server `dispatch` (the refusal rules).
    pub(crate) fn handle(&mut self, caller: CallerId, body: &[u8], queued: Instant) -> Dispatch {
        // R50-5: keyd's own clock, per request; unreadable ⇒ not served.
        let Some(now) = self.clock.now() else {
            return refuse(Refused::Unavailable);
        };
        let call = match decode_request(body) {
            Ok(call) => call,
            Err(rejection) => {
                return match rejection.refusal() {
                    Some(refused) => refuse(refused),
                    None => Dispatch::Close,
                }
            }
        };
        // A-86 / docs/52 R6: a key-state change keyd's authorization step
        // admits has its intent acknowledged before keyd runs it — and can
        // only be run with that proof. An authorization refusal changes
        // nothing and takes the ordinary path below (one record, as before).
        let plain = match classify(&self.keyd, caller, now, call) {
            Classified::Plain(plain) => plain,
            Classified::KeyStateChange(change) => return self.change_key_state(change, queued),
            // keyd and the classification disagree on what needs an intent:
            // not served (fail closed; docs/CLEAN-ROOM.md).
            Classified::Inconsistent => return refuse(Refused::Unavailable),
        };
        // A-57: a gating operation reserves its record's slot before keyd
        // runs it; auditd unreachable or the window full ⇒ Busy, keyd not
        // called. The connection stays open (Busy is not a protocol error).
        let admission = match self.gate.admit(plain.operation()) {
            Ok(admission) => admission,
            Err(_) => return refuse_and_stay(Refused::Busy),
        };
        let answer = match execute(&mut self.keyd, plain) {
            Ok(answer) => answer,
            Err(_) => {
                // Cannot happen (classified just above, on this thread):
                // keyd would admit it as a change needing its proof — not
                // run, "not done".
                self.gate.release(admission);
                return refuse(Refused::Unavailable);
            }
        };
        let (records, overflowed) = self.keyd.audit_sink_mut().take();
        if self.gate.record(admission, &records, overflowed).is_err() {
            // Never a gating result without its record in the window.
            return refuse(Refused::Unavailable);
        }
        match encode_answer(&answer) {
            Ok(frame) => Dispatch::Reply(frame),
            Err(_) => refuse(Refused::Unavailable),
        }
    }

    /// Serve a key-state change keyd's authorization step admitted:
    /// intent committed and acknowledged ⇒ keyd runs the call ⇒ its record
    /// committed ⇒ the true result (crate::audit, steps 1-3).
    ///
    /// * auditd unreachable / no two free slots ⇒ `Refused::Busy` (the
    ///   connection stays open), nothing recorded, keyd not called;
    /// * the intent not acknowledged within the engine's budget of
    ///   `queued` ⇒ a `NotPerformed` outcome, `Refused::Unavailable`, keyd
    ///   not called;
    /// * otherwise the reply is keyd's answer, whether or not its record
    ///   could be committed (a gap is counted and noted, never turned into
    ///   `Unavailable`: the change happened). An answer that cannot be
    ///   encoded (cannot happen for these replies — a kvno or a unit) closes
    ///   the connection without a reply rather than claim `Unavailable`.
    ///
    /// Spec: docs/questions/Q-346 (A-86), Q-365; docs/51 §5.7 item 2 (A-85);
    /// docs/50 §3.6 (bounded waits), §3.7.
    fn change_key_state(&mut self, change: KeyStateCall, queued: Instant) -> Dispatch {
        let caller = change.caller();
        let pending = match self.gate.begin_key_state_change(change) {
            Ok(pending) => pending,
            Err(IntentRefused::GateClosed) => return refuse_and_stay(Refused::Busy),
            Err(IntentRefused::NotRecorded) => return refuse(Refused::Unavailable),
        };
        // The proof, within the engine's budget of `queued`; a deadline that
        // cannot be represented is "not acknowledged" (fail closed).
        let waited = match queued.checked_add(self.budget.get()) {
            Some(deadline) => self.gate.wait_acknowledged(pending, deadline),
            None => {
                let (change, slot) = self.gate.give_up(pending);
                Waited::NotAcknowledged(change, slot)
            }
        };
        let (acked, slot) = match waited {
            Waited::Acknowledged(acked, slot) => (acked, slot),
            Waited::NotAcknowledged(change, slot) => {
                // "Unavailable" means "not done": keyd is not called. The
                // outcome record says so; if even it cannot be committed,
                // the gate counts it.
                if self
                    .gate
                    .abandon_key_state_change(slot, &change.not_performed_event())
                    .is_err()
                {
                    OUTCOME_UNRECORDED.hit(Some(caller.uid));
                }
                return refuse(Refused::Unavailable);
            }
        };
        let answer = execute_acknowledged(&mut self.keyd, acked);
        let (records, overflowed) = self.keyd.audit_sink_mut().take();
        if self
            .gate
            .finish_key_state_change(slot, &records, overflowed)
            .is_err()
        {
            OUTCOME_UNRECORDED.hit(Some(caller.uid));
        }
        match encode_answer(&answer) {
            Ok(frame) => Dispatch::Reply(frame),
            Err(_) => Dispatch::Close,
        }
    }

    /// Move the engine onto its own OS thread behind a queue of `capacity`
    /// requests. `on_exit` runs when the thread ends — normally (every
    /// handle dropped and the queue drained) or by unwinding — so that the
    /// daemon stops instead of serving without an engine.
    ///
    /// Called only after the process-wide hardening (module documentation).
    ///
    /// # Errors
    /// [`EngineError::QueueCapacity`], [`EngineError::Spawn`].
    ///
    /// Spec: docs/50 R50-7, R50-14, §3.6.
    pub(crate) fn spawn<X>(
        self,
        capacity: usize,
        on_exit: X,
    ) -> Result<(EngineHandle, EngineThread), EngineError>
    where
        X: FnOnce() + Send + 'static,
    {
        if capacity == 0 || capacity > MAX_QUEUE_CAPACITY {
            return Err(EngineError::QueueCapacity);
        }
        let (queue, mut jobs) = mpsc::channel::<Job>(capacity);
        let mut engine = self;
        let thread = std::thread::Builder::new()
            .name(String::from("keyd-engine"))
            .spawn(move || {
                let _exit = OnExit(Some(on_exit));
                // A plain OS thread, never inside a runtime: `blocking_recv`
                // is the documented receive "outside of asynchronous
                // contexts". `None` once every sender is gone and the
                // buffer is empty — queued requests are served first.
                while let Some(job) = jobs.blocking_recv() {
                    let Job {
                        caller,
                        body,
                        queued,
                        reply,
                    } = job;
                    let outcome = engine.handle(caller, &body, queued);
                    drop(body);
                    // The connection may be gone; its outcome is dropped.
                    let _ = reply.send(outcome);
                }
            })
            .map_err(|_| EngineError::Spawn)?;
        Ok((EngineHandle { queue }, EngineThread { thread }))
    }
}
