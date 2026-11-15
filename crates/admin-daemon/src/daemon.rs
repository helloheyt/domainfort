//! The serving part of the daemon, run inside the tokio runtime that `main`
//! builds after hardening.
//!
//! [`serve`], in order (docs/50 R50-16, §7.5: a daemon exposes nothing until
//! its dependencies are verified, and exits on any start-up failure):
//!
//! 1. **auditd first** — connect to `audit_socket`, check the peer uid is
//!    `auditd_uid` and that auditd answers `Ping` (R50-3, R50-16). No auditd
//!    ⇒ admind does not start: every `SetPassword` is gating on it (docs/51
//!    §5.7). The verified connection then delivers admind's events
//!    (crate::audit_link).
//! 2. **the worker** — its thread owns the dird and keyd clients
//!    (crate::worker). dird and keyd are not asked at start: each request's
//!    new connection checks the server's uid before anything is sent
//!    (A-63), and a dependency that is down answers that request
//!    `Unavailable` (docs/50 §3.7) — docs/questions/Q-407.
//! 3. **the listener** — `admin_socket`: bind, set the socket file's mode
//!    ([`SOCKET_FILE_MODE`]), accept (crate::listener); the one stale-socket
//!    removal is the root-side preparation's, before the drop — an occupied
//!    path fails the bind (task R15b).
//! 4. **until stopped** — [`DaemonControl::stop`]: stop accepting, answer
//!    new requests `Unavailable`, wait (bounded by [`DRAIN_GRACE`]) for the
//!    requests in flight, then (bounded by [`AUDIT_FLUSH_GRACE`]) until
//!    auditd acknowledged every event in admind's window — the audit task
//!    keeps running meanwhile — and only then end the audit task; the
//!    events still unacknowledged and the counts never sent as a summary
//!    are reported (one note per kind; [`Stopped::unflushed_audit`] —
//!    docs/questions/Q-995); remove the socket file and
//!    return. The caller drops the runtime, after which the worker thread
//!    ends and is joined ([`Stopped::join`]).
//!
//! SIGTERM is not wired to the stop (the keyd-daemon residual,
//! docs/questions/Q-260 item 9): the default action ends the process.
//! admind holds nothing that is not elsewhere (it has no store, docs/51
//! §5.1) except the events of its audit window not yet acknowledged — at
//! most the window's capacity (Q-252 item 9) — and a `SetPassword` in
//! progress, whose dird and keyd steps are recorded by dird and keyd.
//!
//! Spec: docs/51 §5.1, §5.7, §7.6; docs/50 R50-3, R50-7, R50-14, R50-16,
//! R50-17, §3.1, §3.6, §3.7, §7.5, §8.1; docs/questions/Q-252 item 9
//! (A-64), Q-313 (A-82).

use crate::audit::AuditGate;
use crate::audit_link::{self, AuditEndpoint, AuditLinkError};
use crate::links::{DirdLink, KeydLink, UnixDird, UnixKeyd};
use crate::listener::{accept_loop, ServeContext};
use crate::log::{audit_undelivered, note, Note};
use crate::rate::Limits;
use crate::worker::Worker;
use core::fmt;
use core::time::Duration;
use ipc_audit::WindowConfig;
use ipc_audit_client::Unflushed;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Instant;
use tokio::net::UnixListener;
use tokio::sync::Notify;
use tokio::time::sleep;

/// Jobs the worker's queue holds before a request is answered `Busy`.
/// Project choice: one per connection the busiest single uid may hold
/// (crate::rate `MAX_CONNECTIONS_PER_UID`), so one administrator's tools
/// never meet `Busy` from the queue alone (docs/50 R50-7: a bounded queue).
pub const WORKER_QUEUE_CAPACITY: usize = 4;

/// Mode of `admin.sock` after bind: every account that can reach it may
/// connect. The fence is the socket's directory — mode 0750, group
/// `admin_socket_group` (docs/50 §3.1; docs/51 §5.1: defence in depth only;
/// the authorization is Kerberos, decided by dird). The socket file itself
/// cannot carry the admin group: it is created by admind's account after
/// the privilege drop, which leaves no supplementary group to give it
/// (docs/50 §6.1). Project choice — docs/questions/Q-405 item 5.
pub const SOCKET_FILE_MODE: u32 = 0o666;

/// How long a stop waits for requests in flight. Project choice (dird's
/// value).
pub const DRAIN_GRACE: Duration = Duration::from_secs(5);

/// How long a stop waits for auditd to acknowledge admind's window: the one
/// bound of every daemon, `ipc_audit_client::AUDIT_FLUSH_GRACE` (5 s;
/// docs/questions/Q-313, A-82; docs/52 §3.11 R6 (b)).
pub const AUDIT_FLUSH_GRACE: Duration = ipc_audit_client::AUDIT_FLUSH_GRACE;

/// Poll interval while draining. Project choice.
const DRAIN_POLL: Duration = Duration::from_millis(10);

/// What admind's configuration file sets for the daemon — **and nothing
/// else** (docs/52 C18, task R15): the product parameters. Its clients of
/// dird and keyd are the production ones — concrete types over their Unix
/// sockets ([`UnixDird`], [`UnixKeyd`]), not any [`DirdLink`] / [`KeydLink`];
/// its per-uid limits, worker queue and audit window are the daemon's
/// production constants, supplied by [`serve`].
/// Spec: docs/50 §2.4, §3.1, §3.2, §3.6, §7.1; docs/51 §5.1, §7.6; A-79;
/// docs/52 §3.18.
pub struct DaemonParams {
    /// `admin_socket`.
    pub admin_socket: PathBuf,
    /// auditd's socket and uid.
    pub audit: AuditEndpoint,
    /// How long a started frame may take (docs/50 §3.6).
    pub frame_timeout: Duration,
    /// `min_password_length` (A-79, P-24).
    pub min_password_length: u32,
    /// admind's client of dird over `dird_socket` (dird's uid checked on
    /// every connection).
    pub dird: UnixDird,
    /// admind's client of keyd over `keyd_socket`, Role::Directory (keyd's
    /// uid and role checked on every connection — task R9).
    pub keyd: UnixKeyd,
}

impl fmt::Debug for DaemonParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DaemonParams")
            .field("admin_socket", &self.admin_socket)
            .field("audit", &self.audit)
            .field("frame_timeout", &self.frame_timeout)
            .field("min_password_length", &self.min_password_length)
            .finish_non_exhaustive()
    }
}

impl From<DaemonParams> for ServeParams {
    /// The product parameters with the daemon's production values: the
    /// production clients as the worker's links, `Limits::DEFAULT`,
    /// [`WORKER_QUEUE_CAPACITY`] and `WindowConfig::DEFAULT` — the only
    /// values a product admind runs with (docs/52 C18, task R15).
    /// Spec: docs/50 §3.6, §8.1; docs/51 §5.1, §7.6.
    fn from(params: DaemonParams) -> ServeParams {
        ServeParams {
            admin_socket: params.admin_socket,
            audit: params.audit,
            frame_timeout: params.frame_timeout,
            min_password_length: params.min_password_length,
            dird: Box::new(params.dird),
            keyd: Box::new(params.keyd),
            limits: Limits::DEFAULT,
            queue_capacity: WORKER_QUEUE_CAPACITY,
            audit_window: WindowConfig::DEFAULT,
        }
    }
}

/// Everything [`serve_with`] needs: the product [`DaemonParams`] plus the
/// test seams (any dird / keyd link, the limits, the queue, the window).
/// Built for a product admind only by `From<DaemonParams>`; reachable
/// outside this crate only as `test_seams::DaemonParams` (docs/52 C18, task
/// R15).
/// Spec: docs/50 §2.4, §3.1, §3.2, §3.6, §7.1; docs/51 §5.1, §7.6; A-79.
pub struct ServeParams {
    /// `admin_socket`.
    pub admin_socket: PathBuf,
    /// auditd's socket and uid.
    pub audit: AuditEndpoint,
    /// How long a started frame may take (docs/50 §3.6).
    pub frame_timeout: Duration,
    /// `min_password_length` (A-79, P-24).
    pub min_password_length: u32,
    /// admind's client of dird (dird's uid checked on every connection).
    pub dird: Box<dyn DirdLink>,
    /// admind's client of keyd, Role::Directory (keyd's uid checked on every
    /// connection).
    pub keyd: Box<dyn KeydLink>,
    /// The per-uid limits of `admin.sock` (crate::rate).
    pub limits: Limits,
    /// The worker's queue ([`WORKER_QUEUE_CAPACITY`]).
    pub queue_capacity: usize,
    /// admind's audit window (`WindowConfig::DEFAULT`).
    pub audit_window: WindowConfig,
}

impl fmt::Debug for ServeParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServeParams")
            .field("admin_socket", &self.admin_socket)
            .field("audit", &self.audit)
            .field("frame_timeout", &self.frame_timeout)
            .field("min_password_length", &self.min_password_length)
            .field("limits", &self.limits)
            .field("queue_capacity", &self.queue_capacity)
            .finish_non_exhaustive()
    }
}

/// Why [`serve`] could not start.
/// Spec: docs/50 §7.5 ("every daemon exits with an error code on any start-up
/// failure").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaemonError {
    /// auditd could not be verified (R50-16).
    Audit(AuditLinkError),
    /// The worker thread could not be started.
    Worker,
    /// The socket could not be bound or its mode set — among others, its
    /// path is occupied: the stale socket of an earlier run is removed by
    /// the root-side preparation alone (`startup::prepare_socket_directory`,
    /// task R15b), never here.
    Bind,
}

impl fmt::Display for DaemonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DaemonError::Audit(error) => write!(f, "auditd not verified: {error}"),
            DaemonError::Worker => f.write_str("worker thread could not be started"),
            DaemonError::Bind => f.write_str("admin socket could not be bound"),
        }
    }
}

impl std::error::Error for DaemonError {}

/// Shared between the daemon and whoever may stop it.
#[derive(Debug, Default)]
struct ControlState {
    stop: Notify,
    stopping: AtomicBool,
    serving: AtomicBool,
    worker_ended: AtomicBool,
}

/// Starts and observes the stop of a running [`serve`].
#[derive(Debug, Clone, Default)]
pub struct DaemonControl {
    state: Arc<ControlState>,
}

impl DaemonControl {
    /// A control for one daemon.
    #[must_use]
    pub fn new() -> DaemonControl {
        DaemonControl::default()
    }

    /// Ask the daemon to stop (callable from any thread).
    pub fn stop(&self) {
        self.state.stopping.store(true, Ordering::SeqCst);
        self.state.stop.notify_one();
    }

    /// Whether a stop was asked for.
    #[must_use]
    pub fn is_stopping(&self) -> bool {
        self.state.stopping.load(Ordering::SeqCst)
    }

    /// Whether the daemon is accepting connections.
    #[must_use]
    pub fn is_serving(&self) -> bool {
        self.state.serving.load(Ordering::SeqCst)
    }
}

/// The daemon stopped; join the worker after dropping the runtime.
#[derive(Debug)]
pub struct Stopped {
    worker: JoinHandle<()>,
    worker_failed: bool,
    unflushed: Unflushed,
}

/// The worker thread unwound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkerPanicked;

impl Stopped {
    /// Whether the worker thread ended before the stop was asked for.
    #[must_use]
    pub fn worker_failed(&self) -> bool {
        self.worker_failed
    }

    /// admind's audit events auditd had not acknowledged when the stop
    /// ended the audit task (after waiting up to [`AUDIT_FLUSH_GRACE`]):
    /// lost with the process (Q-252 item 9). 0 after a clean stop. Only the
    /// events part: the whole report is [`Stopped::unflushed_audit`].
    #[must_use]
    pub fn unacknowledged_audit_events(&self) -> usize {
        self.unflushed.events()
    }

    /// Everything the stop could not deliver to auditd — the events above
    /// and the counts never sent as a summary (`suppressed_noise`,
    /// `refused_gating`, `unrecorded_outcomes`): the shared flush's whole
    /// report (`ipc_audit_client::AuditGate::close`), read with
    /// `Unflushed::undelivered` (docs/questions/Q-990 item 4, A-166; Q-995).
    /// Spec: docs/questions/Q-313 (A-82), Q-995.
    pub fn unflushed_audit(&self) -> Unflushed {
        self.unflushed
    }

    /// Wait for the worker thread; call after the runtime was dropped.
    ///
    /// # Errors
    /// [`WorkerPanicked`].
    pub fn join(self) -> Result<(), WorkerPanicked> {
        self.worker.join().map_err(|_| WorkerPanicked)
    }
}

/// Bind `admin_socket` and set its mode. Nothing is removed first: the one
/// stale-socket removal is the root-side preparation's
/// (`protected_file::prepare_socket_directory`, relative to the walked and
/// checked directory, before the drop — task R11c); a path occupied after it
/// (only root or admind's account could have done that) fails the bind
/// (task R15b, docs/questions/Q-631).
/// Spec: docs/50 §3.1 ("the daemon manages this explicitly"); tokio
/// `net::UnixListener::bind`.
fn bind(path: &Path) -> Result<UnixListener, DaemonError> {
    let listener = UnixListener::bind(path).map_err(|_| DaemonError::Bind)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(SOCKET_FILE_MODE))
        .map_err(|_| DaemonError::Bind)?;
    Ok(listener)
}

/// Wait until `done()` or `grace` passed.
async fn wait_until(grace: Duration, done: impl Fn() -> bool) {
    let start = Instant::now();
    while !done() && start.elapsed() < grace {
        sleep(DRAIN_POLL).await;
    }
}

/// Run the product admind until [`DaemonControl::stop`] (module
/// documentation): the product parameters with the daemon's production
/// values (docs/52 C18, task R15).
///
/// Must run inside a tokio runtime with I/O and time enabled, built after
/// the process hardening.
///
/// # Errors
/// [`DaemonError`] for a start-up failure (nothing is listening then).
///
/// Spec: docs/51 §5.1, §5.7, §7.6; docs/50 R50-7, R50-14, R50-16, R50-17,
/// §3.1, §3.6, §7.5, §8.1; docs/52 §3.18.
pub async fn serve(params: DaemonParams, control: DaemonControl) -> Result<Stopped, DaemonError> {
    serve_with(ServeParams::from(params), control).await
}

/// [`serve`] with every value given: the parameters with their seams.
/// Reachable outside this crate only as `test_seams::serve` (docs/52 C18,
/// task R15).
///
/// # Errors
/// [`DaemonError`] for a start-up failure (nothing is listening then).
///
/// Spec: docs/51 §5.1, §5.7, §7.6; docs/50 R50-7, R50-14, R50-16, R50-17,
/// §3.1, §3.6, §7.5, §8.1.
pub async fn serve_with(
    params: ServeParams,
    control: DaemonControl,
) -> Result<Stopped, DaemonError> {
    // 1. auditd first (R50-16): its uid and the source it records admind
    //    under (task R9b); the verified connection is kept for admind's
    //    events.
    let link = audit_link::link(&params.audit).map_err(DaemonError::Audit)?;
    let audit = link.connect().await.map_err(DaemonError::Audit)?;
    note(Note::AuditVerified, None);
    let gate = Arc::new(AuditGate::new(params.audit_window));
    // The gate opens on the verified connection — by the audit client, the
    // one owner of "auditd is reachable" (task R15b, docs/questions/Q-630).
    let attached = link.attach(Arc::clone(&gate), audit);

    // 2. The worker.
    let worker = Worker {
        dird: params.dird,
        keyd: params.keyd,
        gate: Arc::clone(&gate),
        min_password_length: params.min_password_length,
    };
    let ended = Arc::clone(&control.state);
    let (handle, worker_thread) = worker
        .spawn(params.queue_capacity, move || {
            ended.worker_ended.store(true, Ordering::SeqCst);
            ended.stopping.store(true, Ordering::SeqCst);
            ended.stop.notify_one();
        })
        .map_err(|_| DaemonError::Worker)?;
    let audit_task = tokio::spawn(attached.run());

    // 3. The listener.
    let listener = match bind(&params.admin_socket) {
        Ok(listener) => listener,
        Err(error) => {
            audit_task.abort();
            let _ = audit_task.await;
            drop(handle);
            let _ = worker_thread.join();
            return Err(error);
        }
    };
    let context = Arc::new(ServeContext::new(
        params.frame_timeout,
        params.limits,
        Arc::clone(&gate),
        handle,
    ));
    let accept_task = tokio::spawn(accept_loop(listener, Arc::clone(&context)));
    control.state.serving.store(true, Ordering::SeqCst);
    note(Note::Listening, None);

    // 4. Until stopped.
    control.state.stop.notified().await;
    note(Note::Draining, None);
    accept_task.abort();
    let _ = accept_task.await;
    control.state.serving.store(false, Ordering::SeqCst);
    context.start_draining();
    wait_until(DRAIN_GRACE, || context.in_flight() == 0).await;
    // The one flush of every daemon (`ipc_audit_client::AuditGate::close`, docs/52
    // R6): admind's full wait, as built (A-87's rule for dird).
    // The report names every event auditd did not acknowledge and every
    // count never sent as a summary (docs/questions/Q-990 item 4, A-166;
    // Q-995).
    let unflushed = gate
        .close(AUDIT_FLUSH_GRACE, async {
            audit_task.abort();
            let _ = audit_task.await;
        })
        .await;
    audit_undelivered(unflushed);
    let _ = std::fs::remove_file(&params.admin_socket);
    drop(context);
    let worker_failed = control.state.worker_ended.load(Ordering::SeqCst);
    if worker_failed {
        note(Note::WorkerStopped, None);
    }
    note(Note::Stopped, None);
    Ok(Stopped {
        worker: worker_thread,
        worker_failed,
        unflushed,
    })
}
