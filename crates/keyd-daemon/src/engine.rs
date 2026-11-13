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
//!   body ([`ipc_keyd::decode_request`]), passes the A-57 audit gate
//!   (`crate::audit`), runs the call on keyd ([`ipc_keyd_server::execute`])
//!   with the transport's caller and that `now`, commits keyd's record, and
//!   encodes the answer ([`ipc_keyd::encode_answer`]). This is the sequence of
//!   [`ipc_keyd_server::dispatch`] with the gate inserted between decoding and
//!   running — `dispatch` has no point at which a slot could be reserved
//!   after the operation is known and before keyd runs it, and decoding the
//!   body twice would double the strict DER work on the one engine thread
//!   (docs/questions/Q-260 item 3). The refusal rules are `dispatch`'s.
//! * The hold-down start (`started_at`) is read from the same clock when the
//!   engine is constructed ([`Engine::start`], A-62: `Keyd::new(…,
//!   started_at)`).
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
//! item 12 (A-63).

use crate::audit::{AuditGate, RecordBuffer};
use crate::clock::Clock;
use core::fmt;
use ipc::{encode_refused, Refused};
use ipc_keyd::{decode_request, encode_answer, KEYD_CHANNEL};
use ipc_keyd_server::{execute, Dispatch};
use keyd::{CallerId, ConfigError, EntropySource, KeyStore, Keyd};
use krb_proto::KerberosTime;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};
use zeroize::Zeroizing;

/// Largest engine queue accepted by [`Engine::spawn`]. Project bound
/// (tokio's `mpsc::channel` panics on 0 or "too large"; AGENTS.md §6).
pub const MAX_QUEUE_CAPACITY: usize = 1024;

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
/// password), and where to send the outcome.
/// Spec: docs/50 R50-7, §3.2, §3.3 (secret-bearing buffers wiped).
pub(crate) struct Job {
    caller: CallerId,
    body: Zeroizing<Vec<u8>>,
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

/// The engine: keyd, the clock it reads `now` from, and the audit gate.
/// Spec: docs/50 R50-5, R50-7.
pub(crate) struct Engine<S: KeyStore, E: EntropySource, C: Clock> {
    keyd: Keyd<S, RecordBuffer, E>,
    clock: C,
    gate: Arc<AuditGate>,
}

impl<S, E, C> Engine<S, E, C>
where
    S: KeyStore + Send + 'static,
    E: EntropySource + Send + 'static,
    C: Clock,
{
    /// Construct the engine: read the clock once for the hold-down start and
    /// build keyd with it (`build` is `Keyd::new` with the development store
    /// in the daemon, a deterministic test keyd in tests).
    ///
    /// # Errors
    /// [`EngineError::Clock`], [`EngineError::Config`].
    ///
    /// Spec: docs/50 R50-5, R50-6, §3.5; docs/10 §11 (`Keyd::new(…,
    /// started_at)`); A-62.
    pub(crate) fn start<F>(clock: C, gate: Arc<AuditGate>, build: F) -> Result<Self, EngineError>
    where
        F: FnOnce(&KerberosTime) -> Result<Keyd<S, RecordBuffer, E>, ConfigError>,
    {
        let started_at = clock.now().ok_or(EngineError::Clock)?;
        let keyd = build(&started_at).map_err(EngineError::Config)?;
        Ok(Engine { keyd, clock, gate })
    }

    /// Serve one request body as `caller` (module documentation).
    ///
    /// Spec: docs/50 R50-5, §3.3, §3.7; docs/questions/Q-218 (A-57);
    /// crates/ipc-keyd-server `dispatch` (the refusal rules).
    pub(crate) fn handle(&mut self, caller: CallerId, body: &[u8]) -> Dispatch {
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
        // A-57: a gating operation reserves its record's slot before keyd
        // runs it; auditd unreachable or the window full ⇒ Busy, keyd not
        // called. The connection stays open (Busy is not a protocol error).
        let admission = match self.gate.admit(call.operation()) {
            Ok(admission) => admission,
            Err(_) => return refuse_and_stay(Refused::Busy),
        };
        let answer = execute(&mut self.keyd, caller, now, call);
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
                        reply,
                    } = job;
                    let outcome = engine.handle(caller, &body);
                    drop(body);
                    // The connection may be gone; its outcome is dropped.
                    let _ = reply.send(outcome);
                }
            })
            .map_err(|_| EngineError::Spawn)?;
        Ok((EngineHandle { queue }, EngineThread { thread }))
    }
}
