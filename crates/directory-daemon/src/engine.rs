//! The engine: one dedicated OS thread owns the directory — the store, the
//! directory context, the tier map — and the view table
//! ([`ipc_directory_server::DirectoryServer`]), fed through a bounded queue.
//!
//! # Design (docs/50 R50-2, R50-7, §3.4, §3.6)
//!
//! * A `directory_pip::DirectoryView` borrows the store, the context and the
//!   tier map, and a view stays pinned across requests of one connection; so
//!   one thread holds them all and serves requests one at a time. The
//!   connection tasks (tokio) read a whole request frame and hand its body,
//!   with the connection id the listener assigned, and a reply `oneshot` to
//!   the engine through a **bounded** `std::sync::mpsc::sync_channel`.
//! * Queue full → the connection answers `Refused::Busy` at once
//!   ([`EngineHandle::submit`] uses `try_send`); never an unbounded queue.
//! * The engine reads its own **monotonic** clock (`std::time::Instant`)
//!   per request for the view lifetime, and sweeps expired views when the
//!   queue is idle ([`SWEEP_INTERVAL`]), so an abandoned view is released
//!   within its lifetime plus one sweep.
//! * A connection that ends sends a release job; if the queue is full at
//!   that moment the release is dropped and the view is freed by the
//!   lifetime sweep instead (bounded: ≤ the view lifetime).
//!
//! # Threads and hardening
//!
//! The engine thread is spawned by [`DirectoryEngine::spawn`], which the
//! daemon calls only inside its tokio runtime — after `main` applied the
//! process-wide hardening on the then only thread (R50-14). The thread
//! inherits the hardened identity.
//!
//! Spec: docs/50 R50-2, R50-7, R50-14, §3.4, §3.6; docs/47 §8.1; docs/11 §6.

use core::fmt;
use core::time::Duration;
use directory_pip::{DirectoryContext, TierMap};
use dirstore::Store;
use ipc::Refused;
use ipc_directory::DomainDescription;
use ipc_directory_server::{
    refuse, ConnectionId, DirectoryServer, Dispatch, StartError, ViewLimits,
};
use pdp::PolicyVersion;
use std::sync::mpsc::{sync_channel, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::oneshot;
use zeroize::Zeroizing;

/// Largest engine queue accepted by [`DirectoryEngine::spawn`]. Project
/// bound (AGENTS.md §6).
pub const MAX_QUEUE_CAPACITY: usize = 1024;

/// How often an idle engine sweeps expired views. Project choice.
/// Spec: docs/50 §3.4 (view lifetime).
pub const SWEEP_INTERVAL: Duration = Duration::from_millis(250);

/// Why the engine could not start.
/// Spec: docs/50 §7.5 ("every daemon exits with an error code on any start-up
/// failure").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineError {
    /// The directory is not usable (no domain root, no krbtgt account, the
    /// limits out of range, no snapshot).
    Directory(StartError),
    /// The queue capacity is 0 or above [`MAX_QUEUE_CAPACITY`].
    QueueCapacity,
    /// The operating system refused the engine thread.
    Spawn,
}

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EngineError::Directory(error) => write!(f, "engine: {error}"),
            EngineError::QueueCapacity => f.write_str("engine: queue capacity out of range"),
            EngineError::Spawn => f.write_str("engine: thread could not be started"),
        }
    }
}

impl std::error::Error for EngineError {}

/// One job for the engine.
/// Spec: docs/50 R50-7, §3.4.
pub(crate) enum Job {
    /// A request body from `connection`, and where its outcome goes.
    Request {
        connection: ConnectionId,
        body: Zeroizing<Vec<u8>>,
        reply: oneshot::Sender<Dispatch>,
    },
    /// `connection` ended: release its view.
    Release { connection: ConnectionId },
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
    queue: SyncSender<Job>,
}

impl EngineHandle {
    /// Queue one request without waiting: a full queue is
    /// [`SubmitError::Busy`].
    /// Spec: docs/50 R50-7 ("queue full ⇒ immediate `Busy`").
    pub(crate) fn submit(
        &self,
        connection: ConnectionId,
        body: Zeroizing<Vec<u8>>,
    ) -> Result<oneshot::Receiver<Dispatch>, SubmitError> {
        let (reply, outcome) = oneshot::channel();
        match self.queue.try_send(Job::Request {
            connection,
            body,
            reply,
        }) {
            Ok(()) => Ok(outcome),
            Err(TrySendError::Full(_)) => Err(SubmitError::Busy),
            Err(TrySendError::Disconnected(_)) => Err(SubmitError::Stopped),
        }
    }

    /// Ask the engine to release `connection`'s view (best effort: a full
    /// queue leaves it to the lifetime sweep).
    /// Spec: docs/50 §3.4 ("released on EndView or disconnect").
    pub(crate) fn release(&self, connection: ConnectionId) {
        let _ = self.queue.try_send(Job::Release { connection });
    }
}

/// The engine thread, to be joined after the daemon stopped.
#[derive(Debug)]
pub struct EngineThread {
    thread: std::thread::JoinHandle<()>,
}

/// The engine thread ended by unwinding (a defect).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnginePanicked;

impl EngineThread {
    /// Wait for the engine thread; it ends when every [`EngineHandle`] is
    /// dropped.
    ///
    /// # Errors
    /// [`EnginePanicked`] if the thread unwound.
    pub fn join(self) -> Result<(), EnginePanicked> {
        self.thread.join().map_err(|_| EnginePanicked)
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

/// The directory the engine serves: the opened store, the context, the tier
/// map and policy version of the loaded policy, and the view limits.
/// Spec: docs/50 R50-2, §3.4, §7.2.
pub struct DirectoryEngine {
    store: Arc<Store>,
    ctx: DirectoryContext,
    tiers: TierMap,
    policy_version: PolicyVersion,
    limits: ViewLimits,
    domain: DomainDescription,
}

impl fmt::Debug for DirectoryEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DirectoryEngine")
            .field("policy_version", &self.policy_version)
            .field("limits", &self.limits)
            .finish()
    }
}

impl DirectoryEngine {
    /// Check the directory and build the engine: the server must be
    /// buildable (the domain root, the domain SID and the krbtgt account
    /// resolve; the limits are in range).
    ///
    /// # Errors
    /// [`EngineError::Directory`].
    ///
    /// Spec: docs/50 §7.5 step 3; docs/47 §1.4 (R47-2).
    pub fn new(
        store: Arc<Store>,
        ctx: DirectoryContext,
        tiers: TierMap,
        policy_version: PolicyVersion,
        limits: ViewLimits,
    ) -> Result<DirectoryEngine, EngineError> {
        let domain = DirectoryServer::new(&ctx, &store, &tiers, policy_version, limits)
            .map_err(EngineError::Directory)?
            .domain()
            .clone();
        Ok(DirectoryEngine {
            store,
            ctx,
            tiers,
            policy_version,
            limits,
            domain,
        })
    }

    /// The domain description `DescribeDomain` answers.
    #[must_use]
    pub fn domain(&self) -> &DomainDescription {
        &self.domain
    }

    /// Move the engine onto its own OS thread behind a queue of `capacity`
    /// jobs. `on_exit` runs when the thread ends — normally (every handle
    /// dropped) or by unwinding — so the daemon stops instead of serving
    /// without an engine.
    ///
    /// # Errors
    /// [`EngineError::QueueCapacity`], [`EngineError::Spawn`].
    ///
    /// Spec: docs/50 R50-7, R50-14, §3.4, §3.6.
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
        let (queue, jobs) = sync_channel::<Job>(capacity);
        let engine = self;
        let thread = std::thread::Builder::new()
            .name(String::from("dird-engine"))
            .spawn(move || {
                let _exit = OnExit(Some(on_exit));
                let DirectoryEngine {
                    store,
                    ctx,
                    tiers,
                    policy_version,
                    limits,
                    domain: _,
                } = engine;
                let Ok(mut server) =
                    DirectoryServer::new(&ctx, &store, &tiers, policy_version, limits)
                else {
                    return;
                };
                loop {
                    match jobs.recv_timeout(SWEEP_INTERVAL) {
                        Ok(Job::Request {
                            connection,
                            body,
                            reply,
                        }) => {
                            let outcome = server.handle(connection, &body, Instant::now());
                            drop(body);
                            // The connection may be gone; its outcome is
                            // dropped.
                            let _ = reply.send(outcome);
                        }
                        Ok(Job::Release { connection }) => {
                            server.release(connection);
                        }
                        Err(RecvTimeoutError::Timeout) => {
                            server.expire(Instant::now());
                        }
                        Err(RecvTimeoutError::Disconnected) => break,
                    }
                }
            })
            .map_err(|_| EngineError::Spawn)?;
        Ok((EngineHandle { queue }, EngineThread { thread }))
    }
}

/// The outcome for a request the engine could not take (stopped).
/// Spec: docs/50 §3.7.
pub(crate) fn unavailable() -> Dispatch {
    refuse(Refused::Unavailable)
}
