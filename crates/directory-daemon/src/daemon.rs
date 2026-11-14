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
//! 3. **the LDAP service** (task P10) — the engine (`ldap::Engine` with the
//!    naming context and `dns_host_name`), the PDP snapshot of the same
//!    policy file, its own directory context and tier map, the audit gate
//!    (the connection verified in step 1 now delivers
//!    the LDAP events, crate::audit_link) — then the LDAP engine thread and
//!    its own bounded queue (crate::ldap_engine).
//! 4. **the listeners** — for `dird_kdc_socket` and `dird_ldap_socket`:
//!    remove a stale socket file (only if it is a socket; anything else ⇒
//!    error), bind, set the socket file's mode, accept (docs/50 §3.1). The
//!    admin socket is not bound (task P13).
//! 5. **until stopped** — [`DaemonControl::stop`]: stop accepting, answer
//!    new requests `Unavailable`, wait (bounded) for queued requests, then
//!    wait (bounded by [`AUDIT_FLUSH_GRACE`], the bound keyd and the kdc
//!    use) until auditd acknowledged every event in the LDAP audit window —
//!    the audit task keeps running meanwhile, reconnecting if the link
//!    dropped — and only then end the audit task; the events still
//!    unacknowledged are reported (the log note
//!    `AuditUnacknowledged` with their count, and
//!    [`Stopped::unacknowledged_audit_events`]); remove the socket files,
//!    return; the caller drops the runtime, after which the engine threads
//!    end and are joined ([`Stopped::join`]).
//!
//! SIGTERM is not wired to the stop (tokio `signal` is not in docs/50 §10's
//! feature list — the keyd-daemon residual, docs/questions/Q-260 item 9):
//! the default action ends the process; dird holds nothing that is not on
//! disk (every write is a committed redb transaction, D136) except the LDAP
//! events of its audit window not yet acknowledged — at most the window's
//! capacity (Q-252 item 9).
//!
//! Spec: docs/50 R50-2, R50-3, R50-7, R50-14, R50-16, R50-17, §3.1, §3.4,
//! §3.6, §6.4, §7.4, §7.5, §8.1; docs/questions/Q-213 (A-57), Q-252 item 9
//! (A-64), Q-270, Q-313 (A-82).

use crate::admin_engine::AdminWorker;
use crate::admin_listener::{self, AdminServeContext};
use crate::admin_service::{
    admin_service_handle, check_manifest, key_targets, protected_objects, AdminParams, NotStarted,
};
use crate::audit_link::{self, AuditEndpoint, AuditLinkError};
use crate::clock::SharedClock;
use crate::engine::{DirectoryEngine, EngineError, EnginePanicked, EngineThread};
use crate::ldap_audit::AuditGate;
use crate::ldap_engine::LdapService;
use crate::ldap_listener::{self, LdapServeContext};
use crate::listener::{accept_loop, ServeContext};
use crate::log::{note, Note};
use crate::policy::{tier_map, DevelopmentPolicy};
use core::fmt;
use core::time::Duration;
use directory_pip::{DirectoryContext, NamingContext};
use dirstore::{IntegrityKey, Store};
use ipc_audit::WindowConfig;
use ipc_directory_server::ViewLimits;
use ipc_ldap_server::Fronts;
use keyd_types::KeydConfig;
use ldap::{Engine, EngineConfig, RootDseConfig};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::net::UnixListener;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
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

/// LDAP sessions (channel connections) open at once. Project choice: docs/50
/// §4.1 gives "e.g. 1024 connections" as the kdc's global TCP bound; the
/// same number here, so a full front fits (docs/questions/Q-280 item 4).
/// Spec: docs/50 §3.6, §4.2.
pub const MAX_LDAP_SESSIONS: usize = 1024;

/// Jobs the LDAP engine queue holds before a request is answered `Busy`.
/// Project choice (docs/50 R50-7: a bounded queue; no number is given for
/// dird — Q-230 item 4, Q-280 item 4).
pub const LDAP_QUEUE_CAPACITY: usize = 64;

/// Mode of the socket file after bind: owner and group may connect. The
/// directory (0750, docs/50 §3.1) is the outer fence; the authorization is
/// the peer-uid check (R50-3). Project choice (as keyd-daemon, Q-260 item 6).
pub const SOCKET_FILE_MODE: u32 = 0o660;

/// How long a stop waits for queued requests to be answered. Project choice.
pub const DRAIN_GRACE: Duration = Duration::from_secs(5);

/// How long a stop waits for auditd to acknowledge the LDAP audit window:
/// the one bound of every daemon, `ipc_audit::AUDIT_FLUSH_GRACE` (5 s).
/// docs/questions/Q-313 (A-82: "the same bound keyd and the kdc use");
/// docs/52 §3.11 R6 (b).
pub const AUDIT_FLUSH_GRACE: Duration = ipc_audit::AUDIT_FLUSH_GRACE;

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
    /// `dird_ldap_socket` (docs/50 §3.1, §4.2).
    pub ldap_socket: PathBuf,
    /// `ldap_front_uid`: the only peer admitted on it (docs/50 §3.2) — the
    /// internal front; its connections' requests are decided under the
    /// internal zone (docs/52 R14; ipc-ldap-server `Fronts`).
    pub ldap_front_uid: u32,
    /// LDAP sessions open at once ([`MAX_LDAP_SESSIONS`]).
    pub max_ldap_sessions: usize,
    /// Jobs the LDAP engine queue holds ([`LDAP_QUEUE_CAPACITY`]).
    pub ldap_queue_capacity: usize,
    /// The DC's DNS host name, reported by the rootDSE ([MS-ADTS]
    /// 3.1.1.3.2.4).
    pub dns_host_name: String,
    /// The LDAP events' sender window (A-57; `WindowConfig::DEFAULT`).
    pub audit_window: WindowConfig,
    /// The LDAP engine's clock (the system clock; tests inject one).
    pub clock: SharedClock,
}

/// Where the directory comes from.
/// Spec: docs/50 R50-2 (dird the only owner of the redb file), §6.4 (the
/// file owned by dird, 0600), §7.4 (the integrity key held by dird, A-57).
pub enum StoreSource {
    /// Open the redb file at `path` with `key`. The file must exist (dird
    /// never creates an empty directory in place of a missing one — a
    /// provisioning step creates it), be a regular file owned by
    /// `owner_uid` (dird's account), and give no access to group or others;
    /// every directory on its path must be root's or dird's and not
    /// writable by group or others (crates/protected-file walk, task
    /// R11b).
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
    /// A directory on the redb file's path is a symbolic link or not a
    /// directory, is owned by neither root nor dird's account, or is
    /// writable by group or others (crates/protected-file walk; task R11b).
    StorePath,
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
    /// The policy's PDP snapshot was refused (a rule-set error).
    PolicySnapshot,
    /// The LDAP engine refused its configuration (naming context, DNS host
    /// name).
    LdapEngine,
    /// A non-socket file is in the way of `dird_ldap_socket`.
    LdapSocketPathOccupied,
    /// The LDAP socket could not be bound or its mode set.
    LdapBind,
}

impl fmt::Display for DaemonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DaemonError::Audit(error) => write!(f, "auditd not verified: {error}"),
            DaemonError::StoreFile => f.write_str(
                "directory file must exist, be a regular file owned by dird's account, with no group or other access",
            ),
            DaemonError::StorePath => f.write_str(
                "directory file's path must pass only through directories owned by root or dird's account, not writable by group or others, and no symbolic link",
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
            DaemonError::PolicySnapshot => f.write_str("policy rule set refused"),
            DaemonError::LdapEngine => {
                f.write_str("LDAP engine refused the naming context or the DNS host name")
            }
            DaemonError::LdapSocketPathOccupied => {
                f.write_str("dird-ldap socket path is occupied by a file that is not a socket")
            }
            DaemonError::LdapBind => f.write_str("dird-ldap socket could not be bound"),
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

/// The daemon stopped; join the engines after dropping the runtime.
#[derive(Debug)]
pub struct Stopped {
    engine: EngineThread,
    ldap_engine: EngineThread,
    admin_engine: Option<EngineThread>,
    engine_failed: bool,
    unacknowledged: usize,
}

impl Stopped {
    /// Whether an engine thread ended before the stop was asked for.
    #[must_use]
    pub fn engine_failed(&self) -> bool {
        self.engine_failed
    }

    /// The LDAP audit events auditd had not acknowledged when the stop
    /// ended the audit task (after waiting up to [`AUDIT_FLUSH_GRACE`]):
    /// lost with the process (Q-252 item 9). 0 after a clean stop.
    /// Spec: docs/50 R50-17, §8.1; docs/questions/Q-313 (A-82).
    #[must_use]
    pub fn unacknowledged_audit_events(&self) -> usize {
        self.unacknowledged
    }

    /// Wait for the engine threads (the admin thread too, if the admin
    /// service ran); call after the runtime was dropped.
    ///
    /// # Errors
    /// [`EnginePanicked`] if any unwound.
    pub fn join(self) -> Result<(), EnginePanicked> {
        let directory = self.engine.join();
        let ldap = self.ldap_engine.join();
        let admin = self.admin_engine.map_or(Ok(()), EngineThread::join);
        directory.and(ldap).and(admin)
    }
}

/// The rule on the redb file's facts: a regular file (a link's facts never
/// are), owned by dird's account, no permission for group or others — the
/// one data-file rule (crates/protected-file `data_file_rule`, shared with
/// auditd's segments; task R11c).
/// Spec: docs/50 §6.4 ("access to the redb file only (owned by dird,
/// 0600)"); Q-270 item 3; docs/questions Q-531 item 4 (A-109).
fn store_file_rule(facts: &protected_file::FileFacts, owner_uid: u32) -> Result<(), DaemonError> {
    protected_file::data_file_rule(facts, owner_uid).map_err(|_| DaemonError::StoreFile)
}

/// Open the redb file (dird's own, never created here): walk its path from
/// `/` with dird's account as the owner, inspect and open the file for
/// reading and writing without following a link, apply
/// [`store_file_rule`] before and after the open (crates/protected-file
/// `open_read_write`), and hand redb **that descriptor** — no second lookup
/// of the path (dirstore `Store::open_file`; docs/52 R11; docs/questions
/// Q-481 item c, Q-530). Runs after the privilege drop, as dird.
/// Spec: docs/50 R50-2, §6.4 ("access to the redb file only (owned by dird,
/// 0600)"), §7.5 step 3 (`Store::open` with the IntegrityKey — wrong key ⇒
/// `Error::Tamper`); Q-270 item 3; Q-468 (A-102); Q-481 (A-104).
fn open_store(path: &Path, key: IntegrityKey, owner_uid: u32) -> Result<Store, DaemonError> {
    let file =
        protected_file::open_read_write(path, owner_uid, |facts| store_file_rule(facts, owner_uid))
            .map_err(|error| match error {
                protected_file::OpenError::Path(_) => DaemonError::StorePath,
                protected_file::OpenError::Io(_) => DaemonError::StoreFile,
                protected_file::OpenError::Refused(refusal) => refusal,
            })?;
    let schema = ad_schema::phase1().map_err(|_| DaemonError::Schema)?;
    Store::open_file(file, key, schema.schema().clone()).map_err(|_| DaemonError::Store)
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

/// Bind a socket path and set its mode.
/// Spec: docs/50 §3.1; tokio `net::UnixListener::bind`.
fn bind(path: &Path) -> Result<UnixListener, DaemonError> {
    remove_stale_socket(path)?;
    let listener = UnixListener::bind(path).map_err(|_| DaemonError::Bind)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(SOCKET_FILE_MODE))
        .map_err(|_| DaemonError::Bind)?;
    Ok(listener)
}

/// Bind `dird_ldap_socket` (the LDAP variants of [`bind`]'s errors).
/// Spec: docs/50 §3.1, §4.2.
fn bind_ldap(path: &Path) -> Result<UnixListener, DaemonError> {
    bind(path).map_err(|error| match error {
        DaemonError::SocketPathOccupied => DaemonError::LdapSocketPathOccupied,
        _ => DaemonError::LdapBind,
    })
}

/// Wait until `done()` or `grace` passed.
async fn wait_until(grace: Duration, done: impl Fn() -> bool) {
    let start = Instant::now();
    while !done() && start.elapsed() < grace {
        sleep(DRAIN_POLL).await;
    }
}

/// A running admin service.
struct AdminRunning {
    context: Arc<AdminServeContext>,
    accept: JoinHandle<()>,
    thread: EngineThread,
    socket: PathBuf,
}

/// Start the admin service (docs/51 §7, task A8): check the manifest
/// against dird's domain, build the PEP's view of the loaded policy, find
/// the admin service's key set in the directory (A-73), build the write PEP
/// with the protected objects, start the admin thread, bind
/// `dird-admin.sock`, accept. Any failure ⇒ [`NotStarted`]: dird's other
/// services run regardless (docs/51 §4.6).
/// Spec: docs/51 §4.6, §5.3, §7.1, §7.5; A-73; docs/questions/Q-386.
fn start_admin(
    admin: AdminParams,
    params: &DaemonParams,
    store: &Arc<Store>,
    policy: &DevelopmentPolicy,
    gate: &Arc<AuditGate>,
    state: &Arc<ControlState>,
) -> Result<AdminRunning, NotStarted> {
    let factory = admin.keyd.clone().ok_or(NotStarted::NoKeyd)?;
    check_manifest(
        &admin.manifest,
        &params.keyd.realm,
        &params.naming_context,
        &params.dns_host_name,
    )?;
    let schema = ad_schema::phase1().map_err(|_| NotStarted::Configuration)?;
    let ctx = DirectoryContext::new(schema.clone(), &params.keyd, params.naming_context.clone())
        .map_err(|_| NotStarted::Configuration)?;
    let tiers = tier_map(policy).map_err(|_| NotStarted::Configuration)?;
    let snapshot = policy.snapshot().map_err(|_| NotStarted::Configuration)?;
    let service = {
        let view = ctx
            .view(store, &tiers)
            .map_err(|_| NotStarted::DirectoryUnreadable)?;
        admin_service_handle(&view, &admin.manifest)?
    };
    let config = directory_admin::AdminConfig::new(
        admin.ticket_age_max,
        admin.quorum,
        params.keyd.realm.clone(),
        params.naming_context.clone(),
        admin.node_id,
        protected_objects(&admin.manifest, policy),
    )
    .map_err(|_| NotStarted::Configuration)?;
    let pep =
        directory_admin::DirectoryAdmin::new(config, &schema, directory_admin::OsRandom::new())
            .map_err(|_| NotStarted::Configuration)?;
    let verifier = factory().ok_or(NotStarted::NoKeyd)?;
    // The pending key-operation requests (task A10): their ids start after
    // the start's DSTIME seconds × 2^20, as the operation numbers do
    // (docs/questions/Q-388 item 4).
    let first_key_id = params
        .clock
        .now()
        .and_then(|now| directory_admin::wall_clock(&now))
        .map_or(0, |seconds| seconds.0.wrapping_shl(20));
    let key_requests = directory_admin::KeyRequests::new(
        key_targets(&admin.manifest),
        admin.key_request_lifetime,
        first_key_id,
    )
    .map_err(|_| NotStarted::Configuration)?;
    let worker = AdminWorker {
        store: Arc::clone(store),
        ctx,
        tiers,
        policy: snapshot,
        admin: pep,
        verifier,
        service,
        gate: Arc::clone(gate),
        clock: params.clock.clone(),
        ack_deadline: admin.ack_deadline.get(),
        key_requests,
        reconcile_interval: admin.destroy_reconcile_interval,
    };
    let ended = Arc::clone(state);
    let (handle, thread) = worker
        .spawn(admin.queue_capacity, move || {
            ended.engine_ended.store(true, Ordering::SeqCst);
            ended.stopping.store(true, Ordering::SeqCst);
            ended.stop.notify_one();
        })
        .map_err(|_| NotStarted::Spawn)?;
    let listener = match bind(&admin.socket) {
        Ok(listener) => listener,
        Err(_) => {
            drop(handle);
            let _ = thread.join();
            return Err(NotStarted::Bind);
        }
    };
    let context = Arc::new(AdminServeContext::new(
        admin.admind_uid,
        params.frame_timeout,
        admin.max_connections,
        handle,
    ));
    let accept = tokio::spawn(admin_listener::accept_loop(listener, Arc::clone(&context)));
    Ok(AdminRunning {
        context,
        accept,
        thread,
        socket: admin.socket,
    })
}

/// Run dird's directory-view service and its LDAP service until
/// [`DaemonControl::stop`] (module documentation); no admin service.
///
/// # Errors
/// [`DaemonError`] for a start-up failure (nothing is listening then).
///
/// Spec: docs/50 R50-2, R50-7, R50-10, R50-14, R50-16, R50-17, §3.1, §3.4,
/// §4.2, §7.5, §8.1.
pub async fn serve(
    params: DaemonParams,
    source: StoreSource,
    policy: DevelopmentPolicy,
    control: DaemonControl,
) -> Result<Stopped, DaemonError> {
    serve_with_admin(params, None, source, policy, control).await
}

/// [`serve`], plus — when `admin` is given — the admin service on
/// `dird-admin.sock` (docs/51 §7, task A8). The admin service is optional:
/// when it cannot start (no keyd endpoint, the admin service object absent,
/// a manifest of another domain, the socket path occupied, …) dird logs why
/// and runs its other services (docs/51 §4.6).
///
/// Must run inside a tokio runtime with I/O and time enabled, built after
/// the process hardening.
///
/// # Errors
/// [`DaemonError`] for a start-up failure of the directory-view or LDAP
/// service (nothing is listening then).
///
/// Spec: docs/50 R50-2, R50-7, R50-10, R50-14, R50-16, R50-17, §3.1, §3.4,
/// §4.2, §7.5, §8.1; docs/51 §4.6, §7.
pub async fn serve_with_admin(
    params: DaemonParams,
    admin: Option<AdminParams>,
    source: StoreSource,
    policy: DevelopmentPolicy,
    control: DaemonControl,
) -> Result<Stopped, DaemonError> {
    // 1. auditd first (R50-16); the verified connection is kept for the
    //    LDAP events (crate::audit_link).
    let audit = audit_link::connect_verified(&params.audit)
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
    let engine = DirectoryEngine::new(Arc::clone(&store), ctx, tiers, policy.version, limits)
        .map_err(DaemonError::Engine)?;
    note(Note::DirectoryOpen, Some(policy.version.0));

    // 3. The LDAP service (task P10): its own directory context and tier
    //    map of the same policy, the PDP snapshot of the same file (A-68),
    //    the engine, the audit gate. No zone table: the zone is the
    //    front's, from its peer uid (docs/52 R14).
    let ldap_schema = ad_schema::phase1().map_err(|_| DaemonError::Schema)?;
    let ldap_ctx = DirectoryContext::new(ldap_schema, &params.keyd, params.naming_context.clone())
        .map_err(|_| DaemonError::Context)?;
    let ldap_tiers = tier_map(&policy).map_err(|_| DaemonError::Policy)?;
    let snapshot = policy.snapshot().map_err(|_| DaemonError::PolicySnapshot)?;
    let ldap_engine = Engine::new(EngineConfig {
        root_dse: RootDseConfig {
            naming_context: params.naming_context.clone(),
            dns_host_name: params.dns_host_name.clone(),
        },
    })
    .map_err(|_| DaemonError::LdapEngine)?;
    // auditd was verified a moment ago (step 1); the audit task takes over
    // the reachability from here.
    let gate = Arc::new(AuditGate::new(params.audit_window));
    gate.set_reachable(true);
    let service = LdapService {
        store: Arc::clone(&store),
        ctx: ldap_ctx,
        tiers: ldap_tiers,
        policy: snapshot,
        engine: ldap_engine,
        gate: Arc::clone(&gate),
        clock: params.clock.clone(),
    };

    let ended = Arc::clone(&control.state);
    let (handle, engine_thread) = engine
        .spawn(params.queue_capacity, move || {
            ended.engine_ended.store(true, Ordering::SeqCst);
            ended.stopping.store(true, Ordering::SeqCst);
            ended.stop.notify_one();
        })
        .map_err(DaemonError::Engine)?;
    let ended = Arc::clone(&control.state);
    let spawned = service.spawn(params.ldap_queue_capacity, move || {
        ended.engine_ended.store(true, Ordering::SeqCst);
        ended.stopping.store(true, Ordering::SeqCst);
        ended.stop.notify_one();
    });
    let (ldap_handle, ldap_thread) = match spawned {
        Ok(spawned) => spawned,
        Err(error) => {
            drop(handle);
            let _ = engine_thread.join();
            return Err(DaemonError::Engine(error));
        }
    };
    let audit_task = tokio::spawn(audit_link::run(
        Arc::clone(&gate),
        params.audit.clone(),
        audit,
    ));

    // 4. The listeners.
    let listeners = match bind(&params.kdc_socket) {
        Ok(kdc) => match bind_ldap(&params.ldap_socket) {
            Ok(ldap) => Ok((kdc, ldap)),
            Err(error) => {
                let _ = std::fs::remove_file(&params.kdc_socket);
                Err(error)
            }
        },
        Err(error) => Err(error),
    };
    let (listener, ldap_listener) = match listeners {
        Ok(listeners) => listeners,
        Err(error) => {
            audit_task.abort();
            let _ = audit_task.await;
            drop(handle);
            drop(ldap_handle);
            let _ = engine_thread.join();
            let _ = ldap_thread.join();
            return Err(error);
        }
    };
    let context = Arc::new(ServeContext::new(
        params.kdc_uid,
        params.frame_timeout,
        params.max_connections,
        handle,
    ));
    let ldap_context = Arc::new(LdapServeContext::new(
        Fronts::new(params.ldap_front_uid),
        params.frame_timeout,
        params.max_ldap_sessions,
        ldap_handle,
    ));
    let accept_task = tokio::spawn(accept_loop(listener, Arc::clone(&context)));
    let ldap_accept_task = tokio::spawn(ldap_listener::accept_loop(
        ldap_listener,
        Arc::clone(&ldap_context),
    ));
    // The admin service (task A8), optional: a failure is logged and dird
    // serves on without it (docs/51 §4.6).
    let admin_running = match admin {
        None => None,
        Some(admin) => match start_admin(admin, &params, &store, &policy, &gate, &control.state) {
            Ok(running) => {
                note(Note::AdminListening, None);
                Some(running)
            }
            Err(reason) => {
                note(Note::AdminNotStarted, Some(reason.code()));
                None
            }
        },
    };
    drop(store);
    control.state.serving.store(true, Ordering::SeqCst);
    note(Note::Listening, None);
    note(Note::LdapListening, None);

    // 5. Until stopped.
    control.state.stop.notified().await;
    note(Note::Draining, None);
    accept_task.abort();
    ldap_accept_task.abort();
    let _ = accept_task.await;
    let _ = ldap_accept_task.await;
    let admin_parts = match admin_running {
        Some(running) => {
            running.accept.abort();
            let _ = running.accept.await;
            Some((running.context, running.thread, running.socket))
        }
        None => None,
    };
    control.state.serving.store(false, Ordering::SeqCst);
    context.start_draining();
    ldap_context.start_draining();
    if let Some((admin_context, _, _)) = admin_parts.as_ref() {
        admin_context.start_draining();
    }
    wait_until(DRAIN_GRACE, || {
        context.in_flight() == 0
            && ldap_context.in_flight() == 0
            && admin_parts
                .as_ref()
                .is_none_or(|(admin_context, _, _)| admin_context.in_flight() == 0)
    })
    .await;
    // Q-313 (A-82: "waits, bounded, for auditd's acknowledgement of every
    // queued audit event"): the events already committed to the window
    // (their operations answered) reach auditd before the audit task ends.
    // The wait does not end early when the link counts as unreachable — the
    // audit task keeps reconnecting (crate::audit_link) and a link that
    // dropped just before the stop can still deliver within the bound
    // (docs/questions/Q-350 item 11). The one flush of every daemon
    // (`ipc_audit::AuditGate::close`, docs/52 R6).
    let unacknowledged = gate
        .close(AUDIT_FLUSH_GRACE, async {
            audit_task.abort();
            let _ = audit_task.await;
        })
        .await
        .events();
    if unacknowledged > 0 {
        note(
            Note::AuditUnacknowledged,
            Some(u64::try_from(unacknowledged).unwrap_or(u64::MAX)),
        );
    }
    let _ = std::fs::remove_file(&params.kdc_socket);
    let _ = std::fs::remove_file(&params.ldap_socket);
    let admin_engine = admin_parts.map(|(_, thread, socket)| {
        let _ = std::fs::remove_file(&socket);
        thread
    });
    let engine_failed = control.state.engine_ended.load(Ordering::SeqCst);
    if engine_failed {
        note(Note::EngineStopped, None);
    }
    note(Note::Stopped, None);
    Ok(Stopped {
        engine: engine_thread,
        ldap_engine: ldap_thread,
        admin_engine,
        engine_failed,
        unacknowledged,
    })
}
