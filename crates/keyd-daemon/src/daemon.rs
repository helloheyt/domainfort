//! The serving part of the daemon, run inside the tokio runtime that `main`
//! builds after hardening.
//!
//! [`serve`], in order (docs/50 R50-16, §7.5: a daemon exposes nothing until
//! its dependencies are verified, and exits on any start-up failure):
//!
//! 1. **auditd first** — connect to `audit_socket`, check the peer uid is
//!    `auditd_uid` and that auditd answers `Ping` (R50-3, R50-16). Failure ⇒
//!    error, the daemon exits (the service manager restarts it, §7.5).
//! 2. **engine** — read keyd's clock for the hold-down start and build keyd
//!    (the in-memory development store, R50-18); log the development-store
//!    warning (D178 / P-17) and the hold-down; spawn the engine thread
//!    (R50-7) — after hardening, since `serve` runs in the runtime `main`
//!    builds only after `daemon_sandbox::apply` (R50-14).
//! 3. **audit client** task, on the verified connection (R50-17).
//! 4. **listener** — remove a stale socket file at `keyd_socket` (only if it
//!    is a socket; anything else ⇒ error), bind, set the socket file's mode,
//!    accept (docs/50 §3.1: "removing an old socket file before bind … the
//!    daemon manages this explicitly").
//! 5. **until stopped** — [`DaemonControl::stop`]: stop accepting, answer new
//!    requests `Unavailable`, wait (bounded) for queued requests to be
//!    answered, remove the socket file, wait (bounded) for auditd to
//!    acknowledge what is in the window, then return. The caller drops the
//!    runtime (ending the idle connection tasks and with them the last queue
//!    senders), after which the engine thread ends and is joined
//!    ([`Stopped::join`]).
//!
//! **SIGTERM.** tokio's signal handling needs its `signal` feature, which
//! docs/50 §10 does not list, and installing a handler through rustix or std
//! is not possible without `unsafe` code. So nothing in the daemon calls
//! [`DaemonControl::stop`] on a signal yet: SIGTERM keeps its default action
//! (the process ends at once; the development store holds nothing durable,
//! and the window's unacknowledged events — at most its capacity — are lost:
//! the bounded loss of docs/questions/Q-252 item 9). The stop path exists and
//! is exercised by the tests; wiring a signal to it is docs/questions/Q-260
//! item 9.
//!
//! Spec: docs/50 R50-3, R50-7, R50-14, R50-16, R50-17, R50-18, §3.1, §3.6,
//! §7.5, §8.1; docs/questions/Q-218 (A-57), Q-252 item 9.

use crate::audit::{AuditGate, RecordBuffer};
use crate::audit_client::{self, AuditEndpoint, AuditLinkError};
use crate::callers::{CallerMap, CallerMapError};
use crate::clock::Clock;
use crate::engine::{Engine, EngineError, EnginePanicked, EngineThread};
use crate::listener::{accept_loop, ServeContext};
use crate::log::{note, Note};
use config::KeydSettings;
use core::fmt;
use core::time::Duration;
use ipc_audit::WindowConfig;
use keyd::{ConfigError, EntropySource, KeyStore, Keyd};
use krb_proto::KerberosTime;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::net::UnixListener;
use tokio::sync::Notify;
use tokio::time::sleep;

/// Requests the engine queue holds before new ones are answered `Busy`.
/// Project choice — docs/50 §3.6 gives no number (docs/questions/Q-230 item
/// 4: "constants in the daemon code"); below the 32 connections four mapped
/// uids may hold at the per-uid ceiling of 8, so a burst from every caller
/// meets `Busy` rather than an unbounded wait.
pub const ENGINE_QUEUE_CAPACITY: usize = 16;

/// Mode of the socket file after bind: owner and group may connect. The
/// directory (0750, docs/50 §3.1) is the outer fence; the authorization is
/// the uid map (R50-3). Project choice (docs/questions/Q-260 item 6).
pub const SOCKET_FILE_MODE: u32 = 0o660;

/// How long a stop waits for queued requests to be answered. Project choice.
pub const DRAIN_GRACE: Duration = Duration::from_secs(5);

/// How long a stop waits for auditd to acknowledge the window. Project
/// choice.
pub const AUDIT_FLUSH_GRACE: Duration = Duration::from_secs(5);

/// Poll interval while draining. Project choice.
const DRAIN_POLL: Duration = Duration::from_millis(10);

/// What [`serve`] needs besides the clock and keyd.
///
/// Spec: docs/50 §2.4, §3.1, §3.2, §3.6, §7.1, §8.1.
#[derive(Debug, Clone)]
pub struct DaemonParams {
    /// `keyd_socket`.
    pub keyd_socket: PathBuf,
    /// The `uid → Role` map (R50-3).
    pub callers: CallerMap,
    /// auditd's socket and uid.
    pub audit: AuditEndpoint,
    /// How long a started frame may take (docs/50 §3.6).
    pub frame_timeout: Duration,
    /// Open connections per mapped uid (docs/50 §3.6).
    pub max_connections_per_uid: u32,
    /// Requests the engine queue holds (R50-7).
    pub queue_capacity: usize,
    /// The audit window (A-57).
    pub window: WindowConfig,
}

impl DaemonParams {
    /// The parameters of keyd's configuration file, with the daemon's
    /// constants for what the file does not set (Q-230 item 4).
    ///
    /// # Errors
    /// [`CallerMapError`] (not reachable for a parsed file).
    ///
    /// Spec: docs/50 §7.1; docs/questions/Q-230 items 4, 5.
    pub fn from_settings(settings: &KeydSettings) -> Result<DaemonParams, CallerMapError> {
        Ok(DaemonParams {
            keyd_socket: settings.keyd_socket().as_path().to_path_buf(),
            callers: CallerMap::from_role_map(settings.uid_roles())?,
            audit: AuditEndpoint {
                socket: settings.audit().socket().as_path().to_path_buf(),
                uid: settings.audit().uid(),
            },
            frame_timeout: settings.frame_timeout(),
            max_connections_per_uid: settings.max_connections_per_uid(),
            queue_capacity: ENGINE_QUEUE_CAPACITY,
            window: WindowConfig::DEFAULT,
        })
    }
}

/// Why [`serve`] could not start.
/// Spec: docs/50 §7.5 ("every daemon exits with an error code on any start-up
/// failure").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaemonError {
    /// auditd could not be verified (R50-16).
    Audit(AuditLinkError),
    /// The engine could not start.
    Engine(EngineError),
    /// A non-socket file is in the way of `keyd_socket`.
    SocketPathOccupied,
    /// The socket could not be bound or its mode set.
    Bind,
}

impl fmt::Display for DaemonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DaemonError::Audit(error) => write!(f, "auditd not verified: {error}"),
            DaemonError::Engine(error) => write!(f, "{error}"),
            DaemonError::SocketPathOccupied => {
                f.write_str("keyd socket path is occupied by a file that is not a socket")
            }
            DaemonError::Bind => f.write_str("keyd socket could not be bound"),
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
    engine_ended: AtomicBool,
}

/// Starts and observes the stop of a running [`serve`].
/// Spec: task P7 ("drain the queue and close").
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
        // A stored permit if `serve` is not waiting yet.
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

/// The daemon stopped; join the engine after dropping the runtime.
#[derive(Debug)]
pub struct Stopped {
    engine: EngineThread,
    engine_failed: bool,
}

impl Stopped {
    /// Whether the engine thread ended before the stop was asked for (the
    /// daemon then stopped itself — exit with failure).
    #[must_use]
    pub fn engine_failed(&self) -> bool {
        self.engine_failed
    }

    /// Wait for the engine thread; call after the runtime was dropped.
    ///
    /// # Errors
    /// [`EnginePanicked`].
    pub fn join(self) -> Result<(), EnginePanicked> {
        self.engine.join()
    }
}

/// Remove a stale socket file at `path`, if any; refuse to remove anything
/// that is not a socket.
/// Spec: docs/50 §3.1 ("the daemon manages this explicitly").
fn remove_stale_socket(path: &Path) -> Result<(), DaemonError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            std::fs::remove_file(path).map_err(|_| DaemonError::Bind)
        }
        Ok(_) => Err(DaemonError::SocketPathOccupied),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(DaemonError::Bind),
    }
}

/// Bind `keyd_socket` and set its mode.
/// Spec: docs/50 §3.1; tokio `net::UnixListener::bind`.
fn bind(path: &Path) -> Result<UnixListener, DaemonError> {
    remove_stale_socket(path)?;
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

/// Run the keyd daemon until [`DaemonControl::stop`] (module
/// documentation). `build_keyd` receives the hold-down start read from
/// `clock` and returns keyd (the development store in the daemon).
///
/// Must run inside a tokio runtime with I/O and time enabled, built after
/// the process hardening.
///
/// # Errors
/// [`DaemonError`] for a start-up failure (nothing is listening then).
///
/// Spec: docs/50 R50-3, R50-5, R50-6, R50-7, R50-14, R50-16, R50-17, R50-18,
/// §3.1, §7.5.
pub async fn serve<S, E, C, F>(
    params: DaemonParams,
    clock: C,
    build_keyd: F,
    control: DaemonControl,
) -> Result<Stopped, DaemonError>
where
    S: KeyStore + Send + 'static,
    E: EntropySource + Send + 'static,
    C: Clock,
    F: FnOnce(&KerberosTime) -> Result<Keyd<S, RecordBuffer, E>, ConfigError>,
{
    // 1. auditd first (R50-16).
    let first = audit_client::connect_verified(&params.audit)
        .await
        .map_err(DaemonError::Audit)?;
    note(Note::AuditVerified, None);
    let gate = Arc::new(AuditGate::new(params.window));
    gate.set_reachable(true);

    // 2. The engine: hold-down start from keyd's clock, then its thread.
    let engine =
        Engine::start(clock, Arc::clone(&gate), build_keyd).map_err(DaemonError::Engine)?;
    note(Note::DevelopmentKeyStore, None);
    note(Note::StartupHoldDown, None);
    let ended = Arc::clone(&control.state);
    let (handle, engine_thread) = engine
        .spawn(params.queue_capacity, move || {
            ended.engine_ended.store(true, Ordering::SeqCst);
            ended.stopping.store(true, Ordering::SeqCst);
            ended.stop.notify_one();
        })
        .map_err(DaemonError::Engine)?;

    // 3. The audit client.
    let audit_task = tokio::spawn(audit_client::run(
        Arc::clone(&gate),
        params.audit.clone(),
        first,
    ));

    // 4. The listener.
    let listener = match bind(&params.keyd_socket) {
        Ok(listener) => listener,
        Err(error) => {
            audit_task.abort();
            drop(handle);
            // The only sender is gone: the engine thread ends at once.
            let _ = engine_thread.join();
            return Err(error);
        }
    };
    let context = Arc::new(ServeContext::new(
        params.callers,
        params.frame_timeout,
        params.max_connections_per_uid,
        handle,
    ));
    let accept_task = tokio::spawn(accept_loop(listener, Arc::clone(&context)));
    control.state.serving.store(true, Ordering::SeqCst);
    note(Note::Listening, None);

    // 5. Until stopped.
    control.state.stop.notified().await;
    note(Note::Draining, None);
    accept_task.abort();
    let _ = accept_task.await;
    control.state.serving.store(false, Ordering::SeqCst);
    context.start_draining();
    wait_until(DRAIN_GRACE, || context.in_flight() == 0).await;
    let _ = std::fs::remove_file(&params.keyd_socket);
    wait_until(AUDIT_FLUSH_GRACE, || {
        gate.outstanding() == 0 || !gate.is_reachable()
    })
    .await;
    audit_task.abort();
    let _ = audit_task.await;
    let engine_failed = control.state.engine_ended.load(Ordering::SeqCst);
    if engine_failed {
        note(Note::EngineStopped, None);
    }
    note(Note::Stopped, None);
    Ok(Stopped {
        engine: engine_thread,
        engine_failed,
    })
}
