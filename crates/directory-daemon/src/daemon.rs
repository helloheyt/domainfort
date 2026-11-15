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
//!    bind, set the socket file's mode, accept (docs/50 §3.1; the one
//!    stale-socket removal is the root-side preparation's, before the drop —
//!    an occupied path fails the bind, task R15b). The admin socket is not
//!    bound (task P13). The optional services follow — the admin and
//!    kpasswd services (tasks A8, K7) and, independent of them, the DNS
//!    service on `dird-dns.sock` (task DN10a, crate::dns_service): each
//!    that cannot start is logged and the others run.
//! 5. **until stopped** — [`DaemonControl::stop`]: stop accepting, answer
//!    new requests `Unavailable`, wait (bounded) for queued requests, then
//!    wait (bounded by [`AUDIT_FLUSH_GRACE`], the bound keyd and the kdc
//!    use) until auditd acknowledged every event in the LDAP audit window —
//!    the audit task keeps running meanwhile, reconnecting if the link
//!    dropped — and only then end the audit task; the events still
//!    unacknowledged are reported (the log note
//!    `AuditUnacknowledged` with their count, and
//!    [`Stopped::unacknowledged_audit_events`]), and so are the counts never
//!    sent as a summary (one note per kind; [`Stopped::unflushed_audit`] —
//!    docs/questions/Q-995); remove the socket files,
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
    admin_service_handle, check_manifest, key_targets, protected_objects, AdminParams,
    AdminServeParams, NotStarted,
};
use crate::audit_link::{self, AuditEndpoint, AuditLinkError};
use crate::clock::SharedClock;
use crate::dns_listener::{self, DnsServeContext};
use crate::dns_service::{DnsNotStarted, DnsParams, DnsServeParams, DnsWorker, SerialAdvance};
use crate::engine::{DirectoryEngine, EngineError, EnginePanicked, EngineThread};
use crate::kpasswd_engine::KpasswdWorker;
use crate::kpasswd_listener::{self, KpasswdServeContext};
use crate::kpasswd_service::{
    change_password_service_handle, KpasswdNotStarted, KpasswdParams, KpasswdServeParams,
};
use crate::ldap_audit::AuditGate;
use crate::ldap_engine::LdapService;
use crate::ldap_listener::{self, LdapServeContext};
use crate::listener::{accept_loop, ServeContext};
use crate::log::{audit_undelivered, note, Note};
use crate::operation_ids::OperationIds;
use crate::policy::{tier_map, DevelopmentPolicy};
use core::fmt;
use core::time::Duration;
use directory_pip::{DirectoryContext, NamingContext};
use dirstore::{IntegrityKey, Store};
use ipc_audit::WindowConfig;
use ipc_audit_client::Unflushed;
use ipc_directory_server::ViewLimits;
use ipc_dns_server::DnsFronts;
use ipc_kpasswd::KpasswdFronts;
use ipc_ldap_server::Fronts;
use keyd_types::KeydConfig;
use ldap::{Engine, EngineConfig, RootDseConfig};
use std::os::unix::fs::PermissionsExt;
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
/// the one bound of every daemon, `ipc_audit_client::AUDIT_FLUSH_GRACE` (5 s).
/// docs/questions/Q-313 (A-82: "the same bound keyd and the kdc use");
/// docs/52 §3.11 R6 (b).
pub const AUDIT_FLUSH_GRACE: Duration = ipc_audit_client::AUDIT_FLUSH_GRACE;

/// Poll interval while draining. Project choice.
const DRAIN_POLL: Duration = Duration::from_millis(10);

/// What dird's configuration file sets for the daemon — **and nothing
/// else** (docs/52 C18, task R15): the product parameters. The values no
/// configuration key sets (the view, connection and session bounds, the
/// queues, the audit window, the LDAP engine's clock) are the daemon's
/// production constants, supplied by [`serve`] / [`serve_with_admin`]; they
/// are not fields here.
/// Spec: docs/50 §2.4, §3.1, §3.2, §3.4, §3.6, §7.1; docs/52 §3.18.
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
    /// The DC's DNS host name, reported by the rootDSE ([MS-ADTS]
    /// 3.1.1.3.2.4).
    pub dns_host_name: String,
}

impl From<DaemonParams> for ServeParams {
    /// The product parameters with the daemon's production constants:
    /// [`MAX_OPEN_VIEWS`], [`MAX_KDC_CONNECTIONS`], [`ENGINE_QUEUE_CAPACITY`],
    /// [`MAX_LDAP_SESSIONS`], [`LDAP_QUEUE_CAPACITY`], `WindowConfig::DEFAULT`
    /// and the system clock — the only values a product daemon runs with
    /// (docs/52 C18, task R15).
    /// Spec: docs/50 §3.4, §3.6, §8.1; docs/questions/Q-230 item 4, Q-280
    /// item 4.
    fn from(params: DaemonParams) -> ServeParams {
        ServeParams {
            kdc_socket: params.kdc_socket,
            kdc_uid: params.kdc_uid,
            audit: params.audit,
            frame_timeout: params.frame_timeout,
            view_lifetime: params.view_lifetime,
            max_views: MAX_OPEN_VIEWS,
            max_connections: MAX_KDC_CONNECTIONS,
            queue_capacity: ENGINE_QUEUE_CAPACITY,
            naming_context: params.naming_context,
            keyd: params.keyd,
            ldap_socket: params.ldap_socket,
            ldap_front_uid: params.ldap_front_uid,
            max_ldap_sessions: MAX_LDAP_SESSIONS,
            ldap_queue_capacity: LDAP_QUEUE_CAPACITY,
            dns_host_name: params.dns_host_name,
            audit_window: WindowConfig::DEFAULT,
            clock: SharedClock::system(),
        }
    }
}

/// Everything [`serve_with`] needs besides the store and the policy: the
/// product [`DaemonParams`] plus the test seams. Built for a product daemon
/// only by `From<DaemonParams>` (the production constants); reachable
/// outside this crate only as `test_seams::DaemonParams` (docs/52 C18, task
/// R15).
/// Spec: docs/50 §2.4, §3.1, §3.2, §3.4, §3.6, §7.1; docs/52 §3.18.
#[derive(Debug, Clone)]
pub struct ServeParams {
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
    /// A store already opened in this process — **a test seam** (docs/52
    /// C18, task R15): it skips the file's owner, mode and path checks and
    /// the integrity key of the configuration. [`OpenedStore`] is built only
    /// by `test_seams::opened` (feature `test-seams`), so no product code can
    /// pass one.
    Opened(OpenedStore),
}

/// The payload of [`StoreSource::Opened`]: a store opened in this process.
/// Its field is private to this crate — the one constructor is
/// `test_seams::opened` (docs/52 C18, task R15).
pub struct OpenedStore(pub(crate) Arc<Store>);

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
    /// The socket could not be bound or its mode set — among others, its
    /// path is occupied: the stale socket of an earlier run is removed by
    /// the root-side preparation alone (`startup::prepare_socket_directory`,
    /// task R15b), never here.
    Bind,
    /// The policy's PDP snapshot was refused (a rule-set error).
    PolicySnapshot,
    /// The LDAP engine refused its configuration (naming context, DNS host
    /// name).
    LdapEngine,
    /// The LDAP socket could not be bound or its mode set (an occupied path
    /// included, as for [`DaemonError::Bind`]).
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
            DaemonError::Bind => f.write_str("dird-kdc socket could not be bound"),
            DaemonError::PolicySnapshot => f.write_str("policy rule set refused"),
            DaemonError::LdapEngine => {
                f.write_str("LDAP engine refused the naming context or the DNS host name")
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
    /// The kpasswd thread, if the kpasswd service ran (task K7).
    kpasswd_engine: Option<EngineThread>,
    /// The DNS thread, if the DNS service ran (task DN10a).
    dns_engine: Option<EngineThread>,
    engine_failed: bool,
    unflushed: Unflushed,
}

impl Stopped {
    /// Whether an engine thread ended before the stop was asked for.
    #[must_use]
    pub fn engine_failed(&self) -> bool {
        self.engine_failed
    }

    /// The LDAP audit events auditd had not acknowledged when the stop
    /// ended the audit task (after waiting up to [`AUDIT_FLUSH_GRACE`]):
    /// lost with the process (Q-252 item 9). 0 after a clean stop. Only the
    /// events part: the whole report is [`Stopped::unflushed_audit`].
    /// Spec: docs/50 R50-17, §8.1; docs/questions/Q-313 (A-82).
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

    /// Wait for the engine threads (the admin, kpasswd and DNS threads
    /// too, if their services ran); call after the runtime was dropped.
    ///
    /// # Errors
    /// [`EnginePanicked`] if any unwound.
    pub fn join(self) -> Result<(), EnginePanicked> {
        let directory = self.engine.join();
        let ldap = self.ldap_engine.join();
        let admin = self.admin_engine.map_or(Ok(()), EngineThread::join);
        let kpasswd = self.kpasswd_engine.map_or(Ok(()), EngineThread::join);
        let dns = self.dns_engine.map_or(Ok(()), EngineThread::join);
        directory.and(ldap).and(admin).and(kpasswd).and(dns)
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

/// Bind a socket path and set its mode. Nothing is removed first: the one
/// stale-socket removal is the root-side preparation's
/// (`protected_file::prepare_socket_directory`, relative to the walked and
/// checked directory, before the drop — task R11c); a path occupied after it
/// (only root or dird's account could have done that) fails the bind (task
/// R15b, docs/questions/Q-631).
/// Spec: docs/50 §3.1 ("the daemon manages this explicitly"); tokio
/// `net::UnixListener::bind`.
fn bind(path: &Path) -> Result<UnixListener, DaemonError> {
    let listener = UnixListener::bind(path).map_err(|_| DaemonError::Bind)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(SOCKET_FILE_MODE))
        .map_err(|_| DaemonError::Bind)?;
    Ok(listener)
}

/// Bind `dird_ldap_socket` (the LDAP variant of [`bind`]'s error).
/// Spec: docs/50 §3.1, §4.2.
fn bind_ldap(path: &Path) -> Result<UnixListener, DaemonError> {
    bind(path).map_err(|_| DaemonError::LdapBind)
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
    admin: AdminServeParams,
    params: &ServeParams,
    store: &Arc<Store>,
    policy: &DevelopmentPolicy,
    gate: &Arc<AuditGate>,
    state: &Arc<ControlState>,
    ids: &Arc<OperationIds>,
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
    // The key sets a key operation may name: all from the manifest (krbtgt
    // and every service object — the change-password service's included, so
    // that its rotation goes through the same dual-controlled decision as the
    // other service keys: A-126, task F3, A-163; docs/questions/Q-978).
    let targets = key_targets(&admin.manifest);
    // The pending requests of every dual-controlled operation (task D2-c;
    // docs/questions/Q-882): their ids are drawn from the CSPRNG by the PEP
    // (no counter a restart could reset — Q-882 item 3).
    let requests = directory_admin::PendingRequests::new(
        targets,
        admin.request_lifetime,
        admin.requests_per_requester,
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
        requests,
        reconcile_interval: admin.destroy_reconcile_interval,
        // Task A16: the base of a tier-map change, and where it is written.
        installed: policy.clone(),
        policy_next: admin.policy_next.clone(),
        // Task K7: dird's one counter of operation numbers.
        ids: Arc::clone(ids),
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

/// A running kpasswd service (task K7).
struct KpasswdRunning {
    context: Arc<KpasswdServeContext>,
    accept: JoinHandle<()>,
    thread: EngineThread,
    socket: PathBuf,
}

/// Start the kpasswd service (task K7, dird side; docs/53 §5.6): with the
/// admin service's settings (`admin` — the ticket-age threshold, the
/// protected objects of the manifest, the node-id, the
/// decision-acknowledgement wait), build its own write PEP over the loaded
/// policy, find the change-password service's key set (`kadmin/changepw`,
/// as the KDC resolves it — crate::kpasswd_service), build its keyd client,
/// start the kpasswd thread, bind `dird-kpasswd.sock`, accept. Any failure
/// ⇒ [`KpasswdNotStarted`]: dird's other services run.
/// Spec: docs/53 §5.6 steps 1, 4; docs/51 §4.6 (the admin service's
/// precedent); docs/50 R50-3, R50-7.
#[allow(clippy::too_many_arguments)]
fn start_kpasswd(
    kpasswd: KpasswdServeParams,
    admin: &AdminServeParams,
    params: &ServeParams,
    store: &Arc<Store>,
    policy: &DevelopmentPolicy,
    gate: &Arc<AuditGate>,
    state: &Arc<ControlState>,
    ids: &Arc<OperationIds>,
) -> Result<KpasswdRunning, KpasswdNotStarted> {
    let factory = kpasswd.keyd.clone().ok_or(KpasswdNotStarted::NoKeyd)?;
    let schema = ad_schema::phase1().map_err(|_| KpasswdNotStarted::Configuration)?;
    let ctx = DirectoryContext::new(schema.clone(), &params.keyd, params.naming_context.clone())
        .map_err(|_| KpasswdNotStarted::Configuration)?;
    let tiers = tier_map(policy).map_err(|_| KpasswdNotStarted::Configuration)?;
    let snapshot = policy
        .snapshot()
        .map_err(|_| KpasswdNotStarted::Configuration)?;
    let service = {
        let view = ctx
            .view(store, &tiers)
            .map_err(|_| KpasswdNotStarted::DirectoryUnreadable)?;
        change_password_service_handle(&view, &params.keyd.realm, &admin.manifest)?
    };
    // The admin service's configuration: one ticket-age threshold (R51-10,
    // docs/53 §5.6 step 4), the same protected objects and node-id.
    let config = directory_admin::AdminConfig::new(
        admin.ticket_age_max,
        admin.quorum,
        params.keyd.realm.clone(),
        params.naming_context.clone(),
        admin.node_id,
        protected_objects(&admin.manifest, policy),
    )
    .map_err(|_| KpasswdNotStarted::Configuration)?;
    let pep =
        directory_admin::DirectoryAdmin::new(config, &schema, directory_admin::OsRandom::new())
            .map_err(|_| KpasswdNotStarted::Configuration)?;
    let keyd = factory().ok_or(KpasswdNotStarted::NoKeyd)?;
    let worker = KpasswdWorker {
        store: Arc::clone(store),
        ctx,
        tiers,
        policy: snapshot,
        admin: pep,
        keyd,
        service,
        gate: Arc::clone(gate),
        clock: params.clock.clone(),
        ack_deadline: admin.ack_deadline.get(),
        ids: Arc::clone(ids),
    };
    let ended = Arc::clone(state);
    let (handle, thread) = worker
        .spawn(kpasswd.queue_capacity, move || {
            ended.engine_ended.store(true, Ordering::SeqCst);
            ended.stopping.store(true, Ordering::SeqCst);
            ended.stop.notify_one();
        })
        .map_err(|_| KpasswdNotStarted::Spawn)?;
    let listener = match bind(&kpasswd.socket) {
        Ok(listener) => listener,
        Err(_) => {
            drop(handle);
            let _ = thread.join();
            return Err(KpasswdNotStarted::Bind);
        }
    };
    let context = Arc::new(KpasswdServeContext::new(
        KpasswdFronts::new(kpasswd.front_uid),
        params.frame_timeout,
        kpasswd.max_connections,
        handle,
    ));
    let accept = tokio::spawn(kpasswd_listener::accept_loop(
        listener,
        Arc::clone(&context),
    ));
    Ok(KpasswdRunning {
        context,
        accept,
        thread,
        socket: kpasswd.socket,
    })
}

/// A running DNS service (task DN10a).
struct DnsRunning {
    context: Arc<DnsServeContext>,
    accept: JoinHandle<()>,
    thread: EngineThread,
    socket: PathBuf,
}

/// Start the DNS service (task DN10a; docs/54 §4.6): its own directory
/// context and tier map of the loaded policy, the serial-only write's door
/// (task DN10b), then the DNS thread, whose first step is the start
/// ([`DnsWorker::start`]): the zone must project — a directory whose zone
/// cannot be projected (no DC host address, no zone serial counter, …)
/// would serve nothing, so the service does not start and says why — then
/// the start's serial advance through the one checker, its decision
/// acknowledged by auditd (docs/questions/Q-1002 item 4 (b): zone values
/// changed in dird's file are never served under an earlier SERIAL), then
/// the first projection. Only then `dird-dns.sock` is bound and accepted
/// on. Independent of the admin and kpasswd services: the zone image and
/// the serial advance need neither keyd nor the write PEP
/// (docs/questions/Q-1000 item 1). Any failure ⇒ [`DnsNotStarted`]: dird's
/// other services run (the admin service's precedent, docs/51 §4.6); a
/// provisioned dnsd then stops at its dird check (docs/54 §4.8 — fail
/// closed).
/// Spec: docs/54 §4.3, §4.4, §4.6, §4.8, §5.4; docs/50 R50-3, R50-7;
/// docs/questions/Q-1002 (A-172).
async fn start_dns(
    dns: DnsServeParams,
    params: &ServeParams,
    store: &Arc<Store>,
    policy: &DevelopmentPolicy,
    gate: &Arc<AuditGate>,
    state: &Arc<ControlState>,
    ids: &Arc<OperationIds>,
) -> Result<(DnsRunning, u32), DnsNotStarted> {
    let schema = ad_schema::phase1().map_err(|_| DnsNotStarted::Configuration)?;
    let writer = directory_admin::ZoneSerialWriter::new(&schema)
        .map_err(|_| DnsNotStarted::Configuration)?;
    let ctx = DirectoryContext::new(schema, &params.keyd, params.naming_context.clone())
        .map_err(|_| DnsNotStarted::Configuration)?;
    let tiers = tier_map(policy).map_err(|_| DnsNotStarted::Configuration)?;
    let advance = SerialAdvance::new(
        writer,
        Arc::clone(gate),
        Arc::clone(ids),
        dns.min_serial_advance_interval,
    );
    let worker = DnsWorker::new(
        Arc::clone(store),
        ctx,
        tiers,
        dns.zone.clone(),
        params.clock.clone(),
        advance,
    );
    let ended = Arc::clone(state);
    let (started, start) = tokio::sync::oneshot::channel();
    let (handle, thread) = worker
        .spawn(dns.queue_capacity, started, move || {
            ended.engine_ended.store(true, Ordering::SeqCst);
            ended.stopping.store(true, Ordering::SeqCst);
            ended.stop.notify_one();
        })
        .map_err(|_| DnsNotStarted::Spawn)?;
    // The start runs on the DNS thread (its acknowledgement wait must not
    // block this runtime, which runs the audit client); the thread ends at
    // once when it fails.
    let serial = match start.await {
        Ok(Ok(serial)) => serial,
        Ok(Err(reason)) => {
            drop(handle);
            let _ = thread.join();
            return Err(reason);
        }
        Err(_) => {
            drop(handle);
            let _ = thread.join();
            return Err(DnsNotStarted::Spawn);
        }
    };
    let listener = match bind(&dns.socket) {
        Ok(listener) => listener,
        Err(_) => {
            drop(handle);
            let _ = thread.join();
            return Err(DnsNotStarted::Bind);
        }
    };
    let context = Arc::new(DnsServeContext::new(
        DnsFronts::new(dns.dnsd_uid),
        params.frame_timeout,
        dns.max_connections,
        handle,
    ));
    let accept = tokio::spawn(dns_listener::accept_loop(listener, Arc::clone(&context)));
    Ok((
        DnsRunning {
            context,
            accept,
            thread,
            socket: dns.socket,
        },
        serial,
    ))
}

/// Run dird's directory-view service and its LDAP service until
/// [`DaemonControl::stop`] (module documentation); no admin service. The
/// product parameters run with the daemon's production constants (docs/52
/// C18, task R15).
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
    serve_with(
        ServeParams::from(params),
        None,
        None,
        None,
        source,
        policy,
        control,
    )
    .await
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
/// The product parameters run with the daemon's production constants, and
/// the admin service with its production keyd client
/// (`KeydTicketVerifier` over `ipc_keyd::UnixConnector`, Role::Ldap, keyd's
/// uid and dird's realm — task R9) and its production bounds (docs/52 C18,
/// task R15).
///
/// Spec: docs/50 R50-2, R50-7, R50-10, R50-14, R50-16, R50-17, §3.1, §3.4,
/// §4.2, §7.5, §8.1; docs/51 §4.6, §7; docs/52 §3.18.
pub async fn serve_with_admin(
    params: DaemonParams,
    admin: Option<AdminParams>,
    source: StoreSource,
    policy: DevelopmentPolicy,
    control: DaemonControl,
) -> Result<Stopped, DaemonError> {
    serve_with_services(params, admin, None, None, source, policy, control).await
}

/// [`serve_with_admin`], plus — when `kpasswd` is given — the kpasswd
/// service on `dird-kpasswd.sock` (task K7; docs/53 §5.6), and — when `dns`
/// is given — the DNS service on `dird-dns.sock` (task DN10a; docs/54
/// §4.6). The kpasswd service runs only with the admin service, whose
/// settings it shares (the ticket-age threshold, the manifest, the node-id,
/// keyd); the DNS service needs neither. When either cannot start, dird
/// logs why and runs its other services.
///
/// # Errors
/// [`DaemonError`] for a start-up failure of the directory-view or LDAP
/// service (nothing is listening then).
///
/// The kpasswd service runs with its production keyd client
/// (`KeydKpasswdClient` over `ipc_keyd::UnixConnector`, Role::Ldap, the
/// admin service's keyd and dird's realm) and its production bounds
/// (docs/52 C18).
///
/// Spec: docs/53 §5.6; docs/54 §4.6; docs/51 §4.6, §7; docs/50 R50-3,
/// R50-7; docs/52 §3.18.
pub async fn serve_with_services(
    params: DaemonParams,
    admin: Option<AdminParams>,
    kpasswd: Option<KpasswdParams>,
    dns: Option<DnsParams>,
    source: StoreSource,
    policy: DevelopmentPolicy,
    control: DaemonControl,
) -> Result<Stopped, DaemonError> {
    let realm = params.keyd.realm.clone();
    let keyd = admin.as_ref().and_then(|admin| admin.keyd.clone());
    let kpasswd =
        kpasswd.map(|kpasswd| KpasswdServeParams::production(kpasswd, keyd.as_ref(), &realm));
    let admin = admin.map(|admin| AdminServeParams::production(admin, &realm));
    let dns = dns.map(DnsServeParams::production);
    serve_with(
        ServeParams::from(params),
        admin,
        kpasswd,
        dns,
        source,
        policy,
        control,
    )
    .await
}

/// [`serve_with_admin`] with every value given: the parameters with their
/// seams and the admin service's parameters with theirs. Reachable outside
/// this crate only as `test_seams::serve_with_admin` (docs/52 C18, task
/// R15).
///
/// # Errors
/// [`DaemonError`] for a start-up failure of the directory-view or LDAP
/// service (nothing is listening then).
///
/// Spec: docs/50 R50-2, R50-7, R50-10, R50-14, R50-16, R50-17, §3.1, §3.4,
/// §4.2, §7.5, §8.1; docs/51 §4.6, §7.
pub async fn serve_with(
    params: ServeParams,
    admin: Option<AdminServeParams>,
    kpasswd: Option<KpasswdServeParams>,
    dns: Option<DnsServeParams>,
    source: StoreSource,
    policy: DevelopmentPolicy,
    control: DaemonControl,
) -> Result<Stopped, DaemonError> {
    // 1. auditd first (R50-16): its uid and the source it records dird
    //    under (task R9b); the verified connection is kept for the LDAP
    //    events (crate::audit_link).
    let link = audit_link::link(&params.audit).map_err(DaemonError::Audit)?;
    let audit = link.connect().await.map_err(DaemonError::Audit)?;
    note(Note::AuditVerified, None);

    // 2. The directory, the policy's tier map, the domain check, the engine.
    let store = match source {
        StoreSource::File {
            path,
            key,
            owner_uid,
        } => Arc::new(open_store(&path, key, owner_uid)?),
        StoreSource::Opened(OpenedStore(store)) => store,
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
    // auditd was verified a moment ago (step 1): the gate opens on that
    // connection — by the audit client, the one owner of "auditd is
    // reachable" (task R15b, docs/questions/Q-630) — and the audit task
    // keeps the reachability from here.
    let gate = Arc::new(AuditGate::new(params.audit_window));
    let attached = link.attach(Arc::clone(&gate), audit);
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
    let audit_task = tokio::spawn(attached.run());

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
    // dird's one counter of operation numbers (task K7,
    // crate::operation_ids): the admin thread and the kpasswd thread draw
    // from it, so their events and keyd decisions never share a number.
    let ids = Arc::new(OperationIds::starting_at(&params.clock));
    // The admin service (task A8), optional: a failure is logged and dird
    // serves on without it (docs/51 §4.6).
    let admin_settings = admin.clone();
    let admin_running = match admin {
        None => None,
        Some(admin) => {
            match start_admin(admin, &params, &store, &policy, &gate, &control.state, &ids) {
                Ok(running) => {
                    note(Note::AdminListening, None);
                    Some(running)
                }
                Err(reason) => {
                    note(Note::AdminNotStarted, Some(reason.code()));
                    None
                }
            }
        }
    };
    // The kpasswd service (task K7), optional, and only beside a running
    // admin service (crate::kpasswd_service): a failure is logged and dird
    // serves on without it.
    let kpasswd_running = match (kpasswd, admin_settings.as_ref(), admin_running.is_some()) {
        (None, _, _) => None,
        (Some(kpasswd), Some(admin), true) => match start_kpasswd(
            kpasswd,
            admin,
            &params,
            &store,
            &policy,
            &gate,
            &control.state,
            &ids,
        ) {
            Ok(running) => {
                note(Note::KpasswdListening, None);
                Some(running)
            }
            Err(reason) => {
                note(Note::KpasswdNotStarted, Some(reason.code()));
                None
            }
        },
        (Some(_), _, _) => {
            note(
                Note::KpasswdNotStarted,
                Some(KpasswdNotStarted::NoAdminService.code()),
            );
            None
        }
    };
    // The DNS service (task DN10a), optional and independent of the admin
    // service: a failure is logged and dird serves on without it.
    let dns_running = match dns {
        None => None,
        Some(dns) => {
            match start_dns(dns, &params, &store, &policy, &gate, &control.state, &ids).await {
                Ok((running, serial)) => {
                    note(Note::DnsListening, Some(u64::from(serial)));
                    Some(running)
                }
                Err(reason) => {
                    note(Note::DnsNotStarted, Some(reason.code()));
                    None
                }
            }
        }
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
    let kpasswd_parts = match kpasswd_running {
        Some(running) => {
            running.accept.abort();
            let _ = running.accept.await;
            Some((running.context, running.thread, running.socket))
        }
        None => None,
    };
    let dns_parts = match dns_running {
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
    if let Some((kpasswd_context, _, _)) = kpasswd_parts.as_ref() {
        kpasswd_context.start_draining();
    }
    if let Some((dns_context, _, _)) = dns_parts.as_ref() {
        dns_context.start_draining();
    }
    wait_until(DRAIN_GRACE, || {
        context.in_flight() == 0
            && ldap_context.in_flight() == 0
            && admin_parts
                .as_ref()
                .is_none_or(|(admin_context, _, _)| admin_context.in_flight() == 0)
            && kpasswd_parts
                .as_ref()
                .is_none_or(|(kpasswd_context, _, _)| kpasswd_context.in_flight() == 0)
            && dns_parts
                .as_ref()
                .is_none_or(|(dns_context, _, _)| dns_context.in_flight() == 0)
    })
    .await;
    // Q-313 (A-82: "waits, bounded, for auditd's acknowledgement of every
    // queued audit event"): the events already committed to the window
    // (their operations answered) reach auditd before the audit task ends.
    // The wait does not end early when the link counts as unreachable — the
    // audit task keeps reconnecting (crate::audit_link) and a link that
    // dropped just before the stop can still deliver within the bound
    // (docs/questions/Q-350 item 11). The one flush of every daemon
    // (`ipc_audit_client::AuditGate::close`, docs/52 R6). The report names
    // every event auditd did not acknowledge and every count never sent as
    // a summary (docs/questions/Q-990 item 4, A-166; Q-995).
    let unflushed = gate
        .close(AUDIT_FLUSH_GRACE, async {
            audit_task.abort();
            let _ = audit_task.await;
        })
        .await;
    audit_undelivered(unflushed);
    // Whether an engine ended before the stop asked for it — read before
    // the admin, kpasswd and DNS contexts are dropped below: dropping a context
    // drops its thread's queue, which ends that thread (its `on_exit` then
    // marks it ended), and a thread ended by the stop is no failure.
    let engine_failed = control.state.engine_ended.load(Ordering::SeqCst);
    let _ = std::fs::remove_file(&params.kdc_socket);
    let _ = std::fs::remove_file(&params.ldap_socket);
    let admin_engine = admin_parts.map(|(_, thread, socket)| {
        let _ = std::fs::remove_file(&socket);
        thread
    });
    let kpasswd_engine = kpasswd_parts.map(|(_, thread, socket)| {
        let _ = std::fs::remove_file(&socket);
        thread
    });
    let dns_engine = dns_parts.map(|(_, thread, socket)| {
        let _ = std::fs::remove_file(&socket);
        thread
    });
    if engine_failed {
        note(Note::EngineStopped, None);
    }
    note(Note::Stopped, None);
    Ok(Stopped {
        engine: engine_thread,
        ldap_engine: ldap_thread,
        admin_engine,
        kpasswd_engine,
        dns_engine,
        engine_failed,
        unflushed,
    })
}
