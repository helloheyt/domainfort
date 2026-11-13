//! The serving part of the daemon, run inside the tokio runtime that `main`
//! builds after hardening.
//!
//! [`serve`], in order (docs/50 R50-16, §7.5: a daemon exposes nothing until
//! its dependencies are verified, and exits on any start-up failure):
//!
//! 1. **auditd first** — connect to `audit_socket`, check the peer uid is
//!    `auditd_uid` and that auditd answers `Ping` (R50-3, R50-16).
//! 2. **the directory** — open the redb file (dird is its only owner, R50-2)
//!    with the integrity key (a wrong key ⇒ `Error::Tamper`, docs/50 §7.5),
//!    build the directory context, take the tier map of the loaded policy,
//!    and check the domain (naming-context root, domain SID, krbtgt account)
//!    — then spawn the engine thread (R50-7).
//! 3. **the listener** — remove a stale socket file at `dird_kdc_socket`
//!    (only if it is a socket; anything else ⇒ error), bind, set the socket
//!    file's mode, accept (docs/50 §3.1). The LDAP and admin sockets are not
//!    bound: their services are tasks P10 and P13.
//! 4. **until stopped** — [`DaemonControl::stop`]: stop accepting, answer
//!    new requests `Unavailable`, wait (bounded) for queued requests, remove
//!    the socket file, return; the caller drops the runtime, after which the
//!    engine thread ends and is joined ([`Stopped::join`]).
//!
//! SIGTERM is not wired to the stop (tokio `signal` is not in docs/50 §10's
//! feature list — the keyd-daemon residual, docs/questions/Q-260 item 9):
//! the default action ends the process; dird holds nothing that is not on
//! disk (every write is a committed redb transaction, D136).
//!
//! Spec: docs/50 R50-2, R50-3, R50-7, R50-14, R50-16, §3.1, §3.4, §3.6,
//! §6.4, §7.4, §7.5; docs/questions/Q-213 (A-57), Q-270.

use crate::audit_link::{self, AuditEndpoint, AuditLinkError};
use crate::engine::{DirectoryEngine, EngineError, EnginePanicked, EngineThread};
use crate::listener::{accept_loop, ServeContext};
use crate::log::{note, Note};
use crate::policy::{tier_map, DevelopmentPolicy};
use core::fmt;
use core::time::Duration;
use directory_pip::{DirectoryContext, NamingContext};
use dirstore::{IntegrityKey, Store};
use ipc_directory_server::ViewLimits;
use keyd_types::KeydConfig;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::net::UnixListener;
use tokio::sync::Notify;
use tokio::time::sleep;

/// Jobs the engine queue holds before new requests are answered `Busy`.
/// Project choice — docs/50 §3.6 gives no number for dird (Q-230 item 4:
/// constants in the daemon); above the kdc's connection quota, so the kdc's
/// own connections never meet `Busy` from one request each.
pub const ENGINE_QUEUE_CAPACITY: usize = 16;

/// Connections the kdc may hold open at once. Project choice (docs/50 §3.6
/// gives "kdc ≤ 8" for keyd; the same value here; Q-270 item 5).
pub const MAX_KDC_CONNECTIONS: usize = 8;

/// Views open at once. Project choice: the kdc's engine is one thread
/// (R50-9), so it holds one view at a time; the headroom covers a view whose
/// release is still on its way (Q-270 item 5).
pub const MAX_OPEN_VIEWS: usize = 4;

/// Mode of the socket file after bind: owner and group may connect. The
/// directory (0750, docs/50 §3.1) is the outer fence; the authorization is
/// the peer-uid check (R50-3). Project choice (as keyd-daemon, Q-260 item 6).
pub const SOCKET_FILE_MODE: u32 = 0o660;

/// How long a stop waits for queued requests to be answered. Project choice.
pub const DRAIN_GRACE: Duration = Duration::from_secs(5);

/// Poll interval while draining. Project choice.
const DRAIN_POLL: Duration = Duration::from_millis(10);

/// What [`serve`] needs besides the store and the policy.
/// Spec: docs/50 §2.4, §3.1, §3.2, §3.4, §3.6, §7.1.
#[derive(Debug, Clone)]
pub struct DaemonParams {
    /// `dird_kdc_socket`.
    pub kdc_socket: PathBuf,
    /// `kdc_uid`: the only peer admitted on it (docs/50 §3.2).
    pub kdc_uid: u32,
    /// auditd's socket and uid.
    pub audit: AuditEndpoint,
    /// How long a started frame may take (docs/50 §3.6).
    pub frame_timeout: Duration,
    /// How long a pinned view lives (docs/50 §3.4).
    pub view_lifetime: Duration,
    /// Views open at once.
    pub max_views: usize,
    /// Connections the kdc may hold open.
    pub max_connections: usize,
    /// Jobs the engine queue holds (R50-7).
    pub queue_capacity: usize,
    /// The naming context (A-53).
    pub naming_context: NamingContext,
    /// keyd's (non-secret) configuration: the realm, the enctypes and the
    /// s2kparams the account records advertise (docs/47 R47-10: one
    /// configuration shared with keyd).
    pub keyd: KeydConfig,
}

/// Where the directory comes from.
/// Spec: docs/50 R50-2 (dird the only owner of the redb file), §6.4 (the
/// file owned by dird, 0600), §7.4 (the integrity key held by dird, A-57).
pub enum StoreSource {
    /// Open the redb file at `path` with `key`. The file must exist (dird
    /// never creates an empty directory in place of a missing one — a
    /// provisioning step creates it), be a regular file owned by
    /// `owner_uid` (dird's account), and give no access to group or others.
    File {
        /// `database_path`.
        path: PathBuf,
        /// The integrity key (from the development key file — Q-213 interim).
        key: IntegrityKey,
        /// dird's uid.
        owner_uid: u32,
    },
    /// A store already opened in this process (a provisioning step that
    /// runs before serving; the tests).
    Opened(Arc<Store>),
}

impl fmt::Debug for StoreSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreSource::File {
                path, owner_uid, ..
            } => f
                .debug_struct("File")
                .field("path", path)
                .field("owner_uid", owner_uid)
                .finish_non_exhaustive(),
            StoreSource::Opened(_) => f.write_str("Opened"),
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
    /// The redb file is missing, not a regular file, not owned by dird's
    /// account, or open to group / others.
    StoreFile,
    /// The store refused to open (a wrong integrity key is `Tamper`).
    Store,
    /// The schema could not be built.
    Schema,
    /// The directory context refused the configuration (realm vs naming
    /// context, keyd's configuration).
    Context,
    /// The policy's tier map was refused.
    Policy,
    /// The engine could not start (the directory has no usable domain root
    /// or krbtgt account, or a limit is out of range).
    Engine(EngineError),
    /// A non-socket file is in the way of `dird_kdc_socket`.
    SocketPathOccupied,
    /// The socket could not be bound or its mode set.
    Bind,
}

impl fmt::Display for DaemonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DaemonError::Audit(error) => write!(f, "auditd not verified: {error}"),
            DaemonError::StoreFile => f.write_str(
                "directory file must exist, be a regular file owned by dird's account, with no group or other access",
            ),
            DaemonError::Store => f.write_str("directory store could not be opened"),
            DaemonError::Schema => f.write_str("phase-1 schema could not be built"),
            DaemonError::Context => f.write_str("directory context refused the configuration"),
            DaemonError::Policy => f.write_str("policy tier map refused"),
            DaemonError::Engine(error) => write!(f, "{error}"),
            DaemonError::SocketPathOccupied => {
                f.write_str("dird-kdc socket path is occupied by a file that is not a socket")
            }
            DaemonError::Bind => f.write_str("dird-kdc socket could not be bound"),
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

/// The daemon stopped; join the engine after dropping the runtime.
#[derive(Debug)]
pub struct Stopped {
    engine: EngineThread,
    engine_failed: bool,
}

impl Stopped {
    /// Whether the engine thread ended before the stop was asked for.
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

/// Open the redb file (dird's own, never created here).
/// Spec: docs/50 R50-2, §6.4 ("access to the redb file only (owned by dird,
/// 0600)"), §7.5 step 3 (`Store::open` with the IntegrityKey — wrong key ⇒
/// `Error::Tamper`); Q-270 item 3.
fn open_store(path: &Path, key: IntegrityKey, owner_uid: u32) -> Result<Store, DaemonError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| DaemonError::StoreFile)?;
    if !metadata.is_file() || metadata.uid() != owner_uid || metadata.mode() & 0o077 != 0 {
        return Err(DaemonError::StoreFile);
    }
    let schema = ad_schema::phase1().map_err(|_| DaemonError::Schema)?;
    Store::open(path, key, schema.schema().clone()).map_err(|_| DaemonError::Store)
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

/// Bind `dird_kdc_socket` and set its mode.
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

/// Run dird's directory-view service until [`DaemonControl::stop`] (module
/// documentation).
///
/// Must run inside a tokio runtime with I/O and time enabled, built after
/// the process hardening.
///
/// # Errors
/// [`DaemonError`] for a start-up failure (nothing is listening then).
///
/// Spec: docs/50 R50-2, R50-7, R50-14, R50-16, §3.1, §3.4, §7.5.
pub async fn serve(
    params: DaemonParams,
    source: StoreSource,
    policy: DevelopmentPolicy,
    control: DaemonControl,
) -> Result<Stopped, DaemonError> {
    // 1. auditd first (R50-16).
    audit_link::verify(&params.audit)
        .await
        .map_err(DaemonError::Audit)?;
    note(Note::AuditVerified, None);

    // 2. The directory, the policy's tier map, the domain check, the engine.
    let store = match source {
        StoreSource::File {
            path,
            key,
            owner_uid,
        } => Arc::new(open_store(&path, key, owner_uid)?),
        StoreSource::Opened(store) => store,
    };
    let schema = ad_schema::phase1().map_err(|_| DaemonError::Schema)?;
    let ctx = DirectoryContext::new(schema, &params.keyd, params.naming_context.clone())
        .map_err(|_| DaemonError::Context)?;
    let tiers = tier_map(&policy).map_err(|_| DaemonError::Policy)?;
    let limits = ViewLimits {
        max_views: params.max_views,
        lifetime: params.view_lifetime,
    };
    let engine = DirectoryEngine::new(store, ctx, tiers, policy.version, limits)
        .map_err(DaemonError::Engine)?;
    note(Note::DirectoryOpen, Some(policy.version.0));
    let ended = Arc::clone(&control.state);
    let (handle, engine_thread) = engine
        .spawn(params.queue_capacity, move || {
            ended.engine_ended.store(true, Ordering::SeqCst);
            ended.stopping.store(true, Ordering::SeqCst);
            ended.stop.notify_one();
        })
        .map_err(DaemonError::Engine)?;

    // 3. The listener.
    let listener = match bind(&params.kdc_socket) {
        Ok(listener) => listener,
        Err(error) => {
            drop(handle);
            let _ = engine_thread.join();
            return Err(error);
        }
    };
    let context = Arc::new(ServeContext::new(
        params.kdc_uid,
        params.frame_timeout,
        params.max_connections,
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
    let _ = std::fs::remove_file(&params.kdc_socket);
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
