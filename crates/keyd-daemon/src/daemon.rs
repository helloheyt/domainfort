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
//! 4. **listener** — bind `keyd_socket`, set the socket file's mode, accept
//!    (docs/50 §3.1: "removing an old socket file before bind … the daemon
//!    manages this explicitly" — the root-side preparation did, before the
//!    drop, the one stale-socket removal; an occupied path fails the bind —
//!    task R15b).
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
use crate::clock::{Clock, SystemClock};
use crate::engine::{Engine, EngineError, EnginePanicked, EngineThread, IntentAckBudget};
use crate::listener::{accept_loop, ServeContext};
use crate::log::{note, Note};
use crate::startup::development_keyd;
use config::KeydSettings;
use core::fmt;
use core::time::Duration;
use ipc_audit::WindowConfig;
use keyd::{ConfigError, EntropySource, KeyStore, Keyd};
use krb_proto::{KerberosTime, Realm};
use std::os::unix::fs::PermissionsExt;
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

/// How long a stop waits for auditd to acknowledge the window: the one
/// bound of every daemon, `ipc_audit::AUDIT_FLUSH_GRACE` (5 s; a project
/// choice). Spec: docs/52 §3.11 R6 (b); docs/questions/Q-313 (A-82).
pub const AUDIT_FLUSH_GRACE: Duration = ipc_audit::AUDIT_FLUSH_GRACE;

/// Poll interval while draining. Project choice.
const DRAIN_POLL: Duration = Duration::from_millis(10);

/// One more socket served by the **same** engine — the same keyd, key store
/// and grant table — with its own `uid → Role` map (and its own connection
/// quota).
///
/// **A test seam (docs/52 C18, task R15): not part of the product API.** The
/// product [`DaemonParams`] has no field for it and the product [`serve`]
/// serves `keyd_socket` alone (docs/50 §3.1, R50-3: one role per uid); only
/// [`ServeParams::extra_listeners`] carries it, and that type is reachable
/// outside this crate only as `test_seams::DaemonParams` (feature
/// `test-seams`, which only dev-dependencies enable). It exists for the single-uid tier-2 harnesses (A-82),
/// which since task A15a need one keyd to serve the one test uid in two
/// roles at once — dird's grant (Role::Ldap) must be in the grant table that
/// admind's `set_secret` (Role::Directory) is checked against
/// (docs/questions/Q-430 "follow-up", Q-453). Each listener still maps the
/// peer's uid from the kernel's peer credentials to its role; nothing is
/// taken from the peer.
///
/// Spec: docs/50 §3.1, §3.2, §3.6, R50-3; docs/questions/Q-430, Q-453.
#[derive(Debug, Clone)]
pub struct ExtraListener {
    /// The socket path (bound, moded and removed as `keyd_socket` is).
    pub socket: PathBuf,
    /// Its `uid → Role` map.
    pub callers: CallerMap,
}

/// What keyd's configuration file sets for the daemon — **and nothing
/// else** (docs/52 C18, task R15): the product parameters. Every value no
/// configuration key sets (the engine queue, the audit window, the
/// intent-acknowledgement budget, extra listeners) is the daemon's own
/// production constant, supplied by [`serve`]; it is not a field here, so no
/// code that builds the product parameters can change it.
///
/// Spec: docs/50 §2.4, §3.1, §3.2, §3.6, §7.1, §8.1; docs/52 §3.18.
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
}

/// Everything [`serve_with`] needs besides the clock and keyd: the product
/// [`DaemonParams`] plus the test seams. Built for a product daemon only by
/// `From<DaemonParams>` (the production constants); reachable outside this
/// crate only as `test_seams::DaemonParams` (docs/52 C18, task R15).
///
/// Spec: docs/50 §2.4, §3.1, §3.2, §3.6, §7.1, §8.1; docs/52 §3.18.
#[derive(Debug, Clone)]
pub struct ServeParams {
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
    /// How long a key-state change may wait for auditd to acknowledge its
    /// intent, from queueing (A-86). Production: always
    /// [`IntentAckBudget::PRODUCTION`] — no configuration key exists, so an
    /// operator cannot widen it; the type refuses anything above
    /// `MAX_INTENT_ACK_BUDGET` when it is built (docs/questions/Q-415).
    pub intent_ack_budget: IntentAckBudget,
    /// More sockets on the same engine ([`ExtraListener`]): always empty in
    /// production (no configuration key; docs/questions/Q-453).
    pub extra_listeners: Vec<ExtraListener>,
}

impl DaemonParams {
    /// The parameters of keyd's configuration file — the one product
    /// constructor (docs/52 C18, task R15). The daemon's constants for what
    /// the file does not set (Q-230 item 4) — among them the production
    /// intent-acknowledgement budget, which no key of the file sets
    /// (docs/questions/Q-415) — are added by [`serve`].
    ///
    /// # Errors
    /// [`CallerMapError`] (not reachable for a parsed file).
    ///
    /// Spec: docs/50 §7.1; docs/questions/Q-230 items 4, 5; Q-365 (A-88),
    /// Q-415.
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
        })
    }
}

impl From<DaemonParams> for ServeParams {
    /// The product parameters with the daemon's production constants: the
    /// engine queue ([`ENGINE_QUEUE_CAPACITY`]), the audit window
    /// (`WindowConfig::DEFAULT`), the intent budget
    /// ([`IntentAckBudget::PRODUCTION`]) and no extra listener — the only
    /// values a product daemon runs with (docs/52 C18, task R15).
    /// Spec: docs/50 §3.6, §8.1; docs/questions/Q-230 item 4, Q-415, Q-453.
    fn from(params: DaemonParams) -> ServeParams {
        ServeParams {
            keyd_socket: params.keyd_socket,
            callers: params.callers,
            audit: params.audit,
            frame_timeout: params.frame_timeout,
            max_connections_per_uid: params.max_connections_per_uid,
            queue_capacity: ENGINE_QUEUE_CAPACITY,
            window: WindowConfig::DEFAULT,
            intent_ack_budget: IntentAckBudget::PRODUCTION,
            extra_listeners: Vec::new(),
        }
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
            DaemonError::Engine(error) => write!(f, "{error}"),
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

/// Bind `keyd_socket` and set its mode. Nothing is removed first: the one
/// stale-socket removal is the root-side preparation's
/// (`protected_file::prepare_socket_directory`, relative to the walked and
/// checked directory, before the drop — task R11c); a path occupied after it
/// (only root or keyd's account could have done that) fails the bind (task
/// R15b, docs/questions/Q-631).
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

/// Run the product keyd daemon until [`DaemonControl::stop`] (module
/// documentation): the product parameters with the daemon's production
/// constants, keyd's own system clock (R50-5), and keyd built on the
/// development store for `realm` (R50-18; P-17) at the hold-down start read
/// from that clock. Nothing else can be supplied: the alternatives exist only
/// in `test_seams` (docs/52 C18, task R15).
///
/// Must run inside a tokio runtime with I/O and time enabled, built after
/// the process hardening.
///
/// # Errors
/// [`DaemonError`] for a start-up failure (nothing is listening then).
///
/// Spec: docs/50 R50-3, R50-5, R50-6, R50-7, R50-14, R50-16, R50-17, R50-18,
/// §3.1, §7.5; docs/52 §3.18.
pub async fn serve(
    params: DaemonParams,
    realm: Realm,
    control: DaemonControl,
) -> Result<Stopped, DaemonError> {
    serve_with(
        ServeParams::from(params),
        SystemClock,
        development_keyd(realm),
        control,
    )
    .await
}

/// [`serve`] with every value given: the parameters with their seams, the
/// clock, and the keyd builder (which receives the hold-down start read from
/// `clock`). Reachable outside this crate only as `test_seams::serve`
/// (docs/52 C18, task R15).
///
/// # Errors
/// [`DaemonError`] for a start-up failure (nothing is listening then).
///
/// Spec: docs/50 R50-3, R50-5, R50-6, R50-7, R50-14, R50-16, R50-17, R50-18,
/// §3.1, §7.5.
pub async fn serve_with<S, E, C, F>(
    params: ServeParams,
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
    // 1. auditd first (R50-16): its uid and the source it records keyd
    //    under (task R9b), both verified before anything else is sent.
    let link = audit_client::link(&params.audit).map_err(DaemonError::Audit)?;
    let first = link.connect().await.map_err(DaemonError::Audit)?;
    note(Note::AuditVerified, None);
    let gate = Arc::new(AuditGate::new(params.window));
    // The gate opens on the verified connection — by the audit client, the
    // one owner of "auditd is reachable" (task R15b, docs/questions/Q-630).
    let attached = link.attach(Arc::clone(&gate), first);

    // 2. The engine: hold-down start from keyd's clock, then its thread.
    let engine = Engine::start(
        clock,
        Arc::clone(&gate),
        params.intent_ack_budget,
        build_keyd,
    )
    .map_err(DaemonError::Engine)?;
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

    // 3. The audit client (the one of ipc-audit, task R9b).
    let audit_task = tokio::spawn(attached.run());

    // 4. The listener — `keyd_socket`, then any extra listener on the same
    // engine (tests only, docs/questions/Q-453). All are bound before any
    // accepts; a failure removes what was bound and stops.
    let sockets: Vec<(PathBuf, CallerMap)> =
        core::iter::once((params.keyd_socket.clone(), params.callers.clone()))
            .chain(
                params
                    .extra_listeners
                    .iter()
                    .map(|extra| (extra.socket.clone(), extra.callers.clone())),
            )
            .collect();
    let mut bound = Vec::with_capacity(sockets.len());
    for (path, callers) in sockets {
        match bind(&path) {
            Ok(listener) => bound.push((path, callers, listener)),
            Err(error) => {
                for (done, _, _) in &bound {
                    let _ = std::fs::remove_file(done);
                }
                drop(bound);
                audit_task.abort();
                drop(handle);
                // The only sender is gone: the engine thread ends at once.
                let _ = engine_thread.join();
                return Err(error);
            }
        }
    }
    let mut served = Vec::with_capacity(bound.len());
    for (path, callers, listener) in bound {
        let context = Arc::new(ServeContext::new(
            callers,
            params.frame_timeout,
            params.max_connections_per_uid,
            handle.clone(),
        ));
        let accept_task = tokio::spawn(accept_loop(listener, Arc::clone(&context)));
        served.push((path, context, accept_task));
    }
    // Only the connection contexts hold queue senders from here on.
    drop(handle);
    control.state.serving.store(true, Ordering::SeqCst);
    note(Note::Listening, None);

    // 5. Until stopped.
    control.state.stop.notified().await;
    note(Note::Draining, None);
    for (_, _, accept_task) in &served {
        accept_task.abort();
    }
    let mut contexts = Vec::with_capacity(served.len());
    for (path, context, accept_task) in served {
        let _ = accept_task.await;
        contexts.push((path, context));
    }
    control.state.serving.store(false, Ordering::SeqCst);
    for (_, context) in &contexts {
        context.start_draining();
    }
    wait_until(DRAIN_GRACE, || {
        contexts.iter().all(|(_, context)| context.in_flight() == 0)
    })
    .await;
    for (path, _) in &contexts {
        let _ = std::fs::remove_file(path);
    }
    // The one flush of every daemon (`ipc_audit::AuditGate::close`, docs/52
    // R6): keyd's rule ends the wait early when auditd counts as unreachable
    // (A-87 kept it). What auditd did not acknowledge is lost with this
    // process (Q-252 item 9) — among it, perhaps, the outcome of a key-state
    // change whose intent is in the log (A-86): say so, with the count.
    let unflushed = gate
        .close(AUDIT_FLUSH_GRACE, async {
            audit_task.abort();
            let _ = audit_task.await;
        })
        .await
        .events();
    if unflushed > 0 {
        note(
            Note::AuditUnflushed,
            Some(u64::try_from(unflushed).unwrap_or(u64::MAX)),
        );
    }
    // And the total of outcomes that never reached the window (A-86).
    let unrecorded = gate.unrecorded_outcomes();
    if unrecorded > 0 {
        note(Note::OutcomeUnrecorded, Some(unrecorded));
    }
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
