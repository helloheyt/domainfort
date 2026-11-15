//! The serving part of the daemon, run inside the tokio runtime that `main`
//! builds after hardening.
//!
//! [`serve`], in order (docs/50 R50-16, §7.5: "auditd → keyd → dird → kdc";
//! "a daemon does not bind a network port until its dependencies were
//! verified"; every start-up failure exits):
//!
//! 1. **the engine thread** is spawned holding the keyd and dird
//!    connectors; it waits for the go-ahead (crate::engine);
//! 2. **auditd first** — connect to `audit_socket`, check the peer uid is
//!    `auditd_uid`, `Ping` → `Pong` (R50-3, R50-16); failure ⇒ error, the
//!    engine is cancelled;
//! 3. **keyd, dird, the policy version, the KDC** — the go-ahead; the engine
//!    verifies keyd (`DescribeConfig`) and dird (`DescribeDomain`), checks
//!    that dird's policy version equals the kdc's file (R50-2) and builds
//!    the `Kdc` (§7.5 step 4); any failure ⇒ error;
//! 4. **the audit client** task on the verified connection (R50-17);
//! 5. **the listeners** — the UDP sockets and TCP listeners `main` bound as
//!    root before the drop (docs/50 §6.2) are handed to tokio (`from_std`,
//!    non-blocking) and served only now; until this step nothing was read
//!    from them or answered (Q-275 item 3);
//! 6. **until stopped** — [`DaemonControl::stop`]: stop receiving and
//!    accepting, wait (bounded) for the requests in flight, close the
//!    queues, wait (bounded) for auditd to acknowledge the window, return.
//!    The caller drops the runtime and joins the engine ([`Stopped::join`]).
//!
//! **SIGTERM** is not handled, as in the other daemons (tokio `signal` is
//! not in docs/50 §10's feature list; Q-260 item 9 → A-67, waiting on
//! P-16): the default action ends the process; the window's unacknowledged
//! events — at most its capacity — are lost (Q-252 item 9).
//!
//! Spec: docs/50 R50-2, R50-3, R50-7, R50-9, R50-14, R50-16, R50-17, §4.1,
//! §6.2, §7.5, §8.1; docs/questions/Q-218 (A-57), Q-252 item 9.

use crate::audit::AuditGate;
use crate::audit_client::{self, AuditEndpoint, AuditLinkError};
use crate::clock::{Clock, SystemClock};
use crate::engine::{self, EngineSetup, EngineThread, StartError};
use crate::log::{note, Note};
use crate::queues::RequestQueues;
use crate::rate::{SourceLimiter, UdpLimits};
use crate::tcp::{accept_tcp, TcpContext, TcpLimits};
use crate::udp::serve_udp;
use crate::zones::ZoneTable;
use config::KdcSettings;
use core::fmt;
use core::time::Duration;
use ipc_audit::WindowConfig;
use pdp::PolicyVersion;
use policy_store::DevelopmentPolicy;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::time::Instant;
use tokio::sync::{oneshot, Notify};
use tokio::time::sleep;

/// Requests the AS queue holds before new ones are dropped (UDP) or their
/// connection closed (TCP). Project choice — docs/50 §4.1 gives no number
/// (Q-230 item 4 → A-60: constants in the daemon).
pub const AS_QUEUE_CAPACITY: usize = 64;

/// Requests the TGS queue holds. Project choice (as [`AS_QUEUE_CAPACITY`]).
pub const TGS_QUEUE_CAPACITY: usize = 64;

/// How long a stop waits for the requests in flight. Project choice.
pub const DRAIN_GRACE: Duration = Duration::from_secs(5);

/// How long a stop waits for auditd to acknowledge the window: the one
/// bound of every daemon, `ipc_audit_client::AUDIT_FLUSH_GRACE` (5 s; a project
/// choice). Spec: docs/52 §3.11 R6 (b); docs/questions/Q-313 (A-82).
pub const AUDIT_FLUSH_GRACE: Duration = ipc_audit_client::AUDIT_FLUSH_GRACE;

/// Poll interval while draining. Project choice.
const DRAIN_POLL: Duration = Duration::from_millis(10);

/// What the kdc's configuration file sets for the daemon — **and nothing
/// else** (docs/52 C18, task R15): the product parameters. The values no
/// configuration key sets (the UDP limits, the queue capacities, the audit
/// window, the UDP reply bound) are the daemon's production constants,
/// supplied by [`serve`]; they are not fields here.
/// Spec: docs/50 §2.4, §3.2, §3.6, §4.1, §7.1, §8.1; docs/52 §3.18.
#[derive(Debug, Clone)]
pub struct DaemonParams {
    /// keyd's uid (the keyd client checks it before sending, R50-3).
    pub keyd_uid: u32,
    /// The keyd client's deadline (docs/50 §3.6).
    pub keyd_deadline: Duration,
    /// dird's uid (R50-3).
    pub dird_uid: u32,
    /// The directory client's deadline (docs/50 §3.6).
    pub dird_deadline: Duration,
    /// auditd's socket and uid.
    pub audit: AuditEndpoint,
    /// The zone table for `Peer.src_net` (docs/50 §4.1).
    pub zones: ZoneTable,
    /// The TCP limits (docs/50 §4.1).
    pub tcp: TcpLimits,
}

/// Everything [`serve_with`] needs besides the policy, the listeners, the
/// connectors and the clock: the product [`DaemonParams`] plus the test
/// seams. Built for a product daemon only by `From<DaemonParams>` (the
/// production constants); reachable outside this crate only as
/// `test_seams::DaemonParams` (docs/52 C18, task R15).
/// Spec: docs/50 §2.4, §3.2, §3.6, §4.1, §7.1, §8.1; docs/52 §3.18.
#[derive(Debug, Clone)]
pub struct ServeParams {
    /// keyd's uid (the keyd client checks it before sending, R50-3).
    pub keyd_uid: u32,
    /// The keyd client's deadline (docs/50 §3.6).
    pub keyd_deadline: Duration,
    /// dird's uid (R50-3).
    pub dird_uid: u32,
    /// The directory client's deadline (docs/50 §3.6).
    pub dird_deadline: Duration,
    /// auditd's socket and uid.
    pub audit: AuditEndpoint,
    /// The zone table for `Peer.src_net` (docs/50 §4.1).
    pub zones: ZoneTable,
    /// The TCP limits (docs/50 §4.1).
    pub tcp: TcpLimits,
    /// The UDP limits (docs/50 §4.1; Q-223).
    pub udp: UdpLimits,
    /// Capacity of the AS queue (R50-9).
    pub as_queue_capacity: usize,
    /// Capacity of the TGS queue (R50-9).
    pub tgs_queue_capacity: usize,
    /// The audit window (A-57).
    pub window: WindowConfig,
    /// The largest reply sent over UDP before KRB_ERR_RESPONSE_TOO_BIG
    /// (RFC 4120 §7.2.1; `kdc::DEFAULT_UDP_MAX_REPLY_LEN` unless set).
    pub udp_max_reply_len: usize,
}

impl DaemonParams {
    /// The parameters of the kdc's configuration file — the one product
    /// constructor (docs/52 C18, task R15); the daemon's constants for what
    /// the file does not set (Q-230 item 4 → A-60) are added by [`serve`].
    /// Spec: docs/50 §3.6, §4.1, §7.1.
    #[must_use]
    pub fn from_settings(settings: &KdcSettings) -> DaemonParams {
        let limits = settings.limits();
        DaemonParams {
            keyd_uid: settings.keyd().uid(),
            keyd_deadline: limits.keyd_deadline(),
            dird_uid: settings.dird().uid(),
            dird_deadline: limits.dird_deadline(),
            audit: AuditEndpoint {
                socket: settings.audit().socket().as_path().to_path_buf(),
                uid: settings.audit().uid(),
            },
            zones: ZoneTable::from_settings(settings.internal_networks()),
            tcp: TcpLimits {
                max_connections: limits.max_tcp_connections(),
                max_per_source: limits.max_tcp_connections_per_source(),
                first_frame_timeout: limits.tcp_first_frame_timeout(),
                frame_timeout: limits.tcp_frame_timeout(),
                idle_timeout: limits.tcp_idle_timeout(),
                max_requests: limits.max_requests_per_tcp_connection(),
            },
        }
    }
}

impl From<DaemonParams> for ServeParams {
    /// The product parameters with the daemon's production constants:
    /// `UdpLimits::DEFAULT`, [`AS_QUEUE_CAPACITY`], [`TGS_QUEUE_CAPACITY`],
    /// `WindowConfig::DEFAULT` and `kdc::DEFAULT_UDP_MAX_REPLY_LEN` — the
    /// only values a product daemon runs with (docs/52 C18, task R15).
    /// Spec: docs/50 §3.6, §4.1, §8.1; docs/questions/Q-223, Q-230 item 4.
    fn from(params: DaemonParams) -> ServeParams {
        ServeParams {
            keyd_uid: params.keyd_uid,
            keyd_deadline: params.keyd_deadline,
            dird_uid: params.dird_uid,
            dird_deadline: params.dird_deadline,
            audit: params.audit,
            zones: params.zones,
            tcp: params.tcp,
            udp: UdpLimits::DEFAULT,
            as_queue_capacity: AS_QUEUE_CAPACITY,
            tgs_queue_capacity: TGS_QUEUE_CAPACITY,
            window: WindowConfig::DEFAULT,
            udp_max_reply_len: kdc::DEFAULT_UDP_MAX_REPLY_LEN,
        }
    }
}

/// The sockets `main` bound (as root, before the drop): one UDP socket and
/// one TCP listener per configured address (docs/50 §4.1: "each address
/// served on UDP and TCP"). Bound, not yet served.
/// Spec: docs/50 §6.2; RFC 4120 §7.2.1, §7.2.2.
#[derive(Debug, Default)]
pub struct Listeners {
    /// The UDP sockets.
    pub udp: Vec<std::net::UdpSocket>,
    /// The TCP listeners.
    pub tcp: Vec<std::net::TcpListener>,
}

/// Why [`serve`] could not start.
/// Spec: docs/50 §7.5.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaemonError {
    /// auditd could not be verified (R50-16).
    Audit(AuditLinkError),
    /// The engine did not start (keyd, dird, the policy version, the KDC).
    Start(StartError),
    /// The engine thread could not be spawned, or ended before reporting.
    Engine,
    /// A listener could not be handed to the runtime.
    Listener,
    /// A listener's local address lies outside every internal network
    /// (docs/50 R50-9: "binding to internal interfaces only"; task R15b):
    /// nothing was served; auditd, keyd and dird were not contacted.
    ListenerNotInternal,
}

impl fmt::Display for DaemonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DaemonError::Audit(error) => write!(f, "auditd not verified: {error}"),
            DaemonError::Start(error) => write!(f, "{error}"),
            DaemonError::Engine => f.write_str("engine thread could not be started"),
            DaemonError::Listener => f.write_str("listener could not be served"),
            DaemonError::ListenerNotInternal => {
                f.write_str("a listener is outside every configured internal network")
            }
        }
    }
}

impl std::error::Error for DaemonError {}

/// What the network tasks share.
#[derive(Debug)]
pub(crate) struct Shared {
    pub(crate) queues: Arc<RequestQueues>,
    pub(crate) zones: ZoneTable,
    /// Set at shutdown: nothing new is queued.
    pub(crate) draining: AtomicBool,
    /// Requests queued or being answered.
    in_flight: AtomicUsize,
}

/// One request counted as in flight until dropped.
pub(crate) struct InFlight(Arc<Shared>);

impl InFlight {
    pub(crate) fn new(shared: &Arc<Shared>) -> InFlight {
        shared.in_flight.fetch_add(1, Ordering::SeqCst);
        InFlight(Arc::clone(shared))
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.in_flight.fetch_sub(1, Ordering::SeqCst);
    }
}

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

    /// Whether the listeners serve.
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
    policy_version: PolicyVersion,
    unacknowledged: usize,
}

impl Stopped {
    /// Whether the engine thread ended before the stop was asked for.
    #[must_use]
    pub fn engine_failed(&self) -> bool {
        self.engine_failed
    }

    /// The policy version the daemon served with.
    #[must_use]
    pub fn policy_version(&self) -> PolicyVersion {
        self.policy_version
    }

    /// The audit events auditd had not acknowledged when the stop ended the
    /// audit task (after waiting up to [`AUDIT_FLUSH_GRACE`], or less once
    /// auditd counted as unreachable): lost with the process (Q-252 item 9).
    /// The shared flush's report (`ipc_audit_client::AuditGate::close`, docs/52
    /// R6), as dird and admind expose it; the kdc writes no log note for it,
    /// as before.
    /// Spec: docs/50 R50-17, §8.1; docs/questions/Q-313 (A-82).
    #[must_use]
    pub fn unacknowledged_audit_events(&self) -> usize {
        self.unacknowledged
    }

    /// Wait for the engine thread; call after the runtime was dropped.
    ///
    /// # Errors
    /// [`crate::EnginePanicked`].
    pub fn join(self) -> Result<(), crate::EnginePanicked> {
        self.engine.join()
    }
}

/// Every UDP socket's and TCP listener's local address lies in an internal
/// network of the zone table (an unreadable address counts as outside) —
/// the configuration's rule (crates/config: every `listen` address inside
/// `internal_networks`) checked again at the one place every listener
/// passes, also one `main` did not bind from the file (tests bind their
/// own), as ldap-front's `serve` does (docs/52 R14).
///
/// # Errors
/// [`DaemonError::ListenerNotInternal`]: nothing is served; auditd, keyd and
/// dird are not contacted.
///
/// Spec: docs/50 R50-9 ("binding to internal interfaces only"), §4.1;
/// docs/questions/Q-223 (A-57 (a)), Q-580 (A-114), Q-632.
fn check_listeners(listeners: &Listeners, zones: &ZoneTable) -> Result<(), DaemonError> {
    let udp = listeners.udp.iter().map(std::net::UdpSocket::local_addr);
    let tcp = listeners.tcp.iter().map(std::net::TcpListener::local_addr);
    for local in udp.chain(tcp) {
        match local {
            Ok(address) if zones.is_internal(address.ip()) => {}
            _ => return Err(DaemonError::ListenerNotInternal),
        }
    }
    Ok(())
}

/// Wait until `done()` or `grace` passed.
async fn wait_until(grace: Duration, done: impl Fn() -> bool) {
    let start = Instant::now();
    while !done() && start.elapsed() < grace {
        sleep(DRAIN_POLL).await;
    }
}

/// Run the product kdc daemon until [`DaemonControl::stop`] (module
/// documentation): the product parameters with the daemon's production
/// constants, the kdc's system clock, and the production connectors to
/// keyd's and dird's sockets (`ipc_keyd::UnixConnector` /
/// `ipc_directory::UnixConnector`: rustix peer credentials, R50-3) — the
/// connector types are fixed here, so no other transport can be supplied;
/// the alternatives exist only in `test_seams` (docs/52 C18, task R15). Must
/// run inside a tokio runtime with I/O and time enabled, built after the
/// process hardening.
///
/// # Errors
/// [`DaemonError`] for a start-up failure (nothing is served then).
///
/// Spec: docs/50 R50-2, R50-3, R50-9, R50-14, R50-16, R50-17, §4.1, §7.5;
/// docs/52 §3.18.
pub async fn serve(
    params: DaemonParams,
    policy: DevelopmentPolicy,
    listeners: Listeners,
    keyd: ipc_keyd::UnixConnector,
    dird: ipc_directory::UnixConnector,
    control: DaemonControl,
) -> Result<Stopped, DaemonError> {
    serve_with(
        ServeParams::from(params),
        policy,
        listeners,
        keyd,
        dird,
        SystemClock,
        control,
    )
    .await
}

/// [`serve`] with every value given: the parameters with their seams, any
/// connectors and any clock. Reachable outside this crate only as
/// `test_seams::serve` (docs/52 C18, task R15).
///
/// # Errors
/// [`DaemonError`] for a start-up failure (nothing is served then).
///
/// Spec: docs/50 R50-2, R50-3, R50-9, R50-14, R50-16, R50-17, §4.1, §7.5.
pub async fn serve_with<KC, DC, C>(
    params: ServeParams,
    policy: DevelopmentPolicy,
    listeners: Listeners,
    keyd: KC,
    dird: DC,
    clock: C,
    control: DaemonControl,
) -> Result<Stopped, DaemonError>
where
    KC: ipc_keyd::Connector + Send + 'static,
    DC: ipc_directory::Connector + Send + 'static,
    C: Clock,
{
    // 1. The engine thread, waiting for the go-ahead.
    let gate = Arc::new(AuditGate::new(params.window));
    let queues = Arc::new(RequestQueues::new(
        params.as_queue_capacity,
        params.tgs_queue_capacity,
    ));
    let (go, wait_for_go) = mpsc::channel();
    let (report, started) = oneshot::channel();
    let ended = Arc::clone(&control.state);
    let engine_thread = engine::spawn(
        EngineSetup {
            keyd,
            keyd_uid: params.keyd_uid,
            keyd_deadline: params.keyd_deadline,
            dird,
            dird_uid: params.dird_uid,
            dird_deadline: params.dird_deadline,
            policy,
            udp_max_reply_len: params.udp_max_reply_len,
            clock,
            gate: Arc::clone(&gate),
        },
        Arc::clone(&queues),
        wait_for_go,
        report,
        move || {
            ended.engine_ended.store(true, Ordering::SeqCst);
            ended.stopping.store(true, Ordering::SeqCst);
            ended.stop.notify_one();
        },
    )
    .map_err(|_| DaemonError::Engine)?;

    // 1b. Every listener on an internal interface (R50-9; task R15b) — the
    //     chokepoint for any listener, however bound — before auditd, keyd
    //     or dird is contacted. On failure `go` is dropped: the engine
    //     thread ends without contacting keyd or dird (and the connectors
    //     it owns are dropped there, not in this task).
    if let Err(error) = check_listeners(&listeners, &params.zones) {
        drop(go);
        let _ = started.await;
        let _ = engine_thread.join();
        return Err(error);
    }

    // 2. auditd first (R50-16): its uid and the source it records the kdc
    //    under (task R9b). On failure `go` is dropped: the engine thread
    //    ends without contacting keyd or dird.
    let verified = match audit_client::link(&params.audit) {
        Ok(link) => link.connect().await.map(|first| (link, first)),
        Err(error) => Err(error),
    };
    let (link, first) = match verified {
        Ok(verified) => verified,
        Err(error) => {
            drop(go);
            let _ = started.await;
            let _ = engine_thread.join();
            return Err(DaemonError::Audit(error));
        }
    };
    note(Note::AuditVerified, None);
    // The gate opens on the verified connection — by the audit client, the
    // one owner of "auditd is reachable" (task R15b, docs/questions/Q-630).
    let attached = link.attach(Arc::clone(&gate), first);

    // 3. keyd, dird, the policy version, the KDC — on the engine thread.
    let _ = go.send(());
    let policy_version = match started.await {
        Ok(Ok(version)) => version,
        Ok(Err(error)) => {
            let _ = engine_thread.join();
            return Err(DaemonError::Start(error));
        }
        Err(_) => {
            let _ = engine_thread.join();
            return Err(DaemonError::Engine);
        }
    };
    note(Note::DependenciesVerified, Some(policy_version.0));

    // 4. The audit client (the one of ipc-audit, task R9b).
    let audit_task = tokio::spawn(attached.run());

    // 5. The listeners, served only now.
    let shared = Arc::new(Shared {
        queues: Arc::clone(&queues),
        zones: params.zones.clone(),
        draining: AtomicBool::new(false),
        in_flight: AtomicUsize::new(0),
    });
    let limiter = Arc::new(SourceLimiter::new(params.udp, Instant::now()));
    let tcp_context = Arc::new(TcpContext::new(params.tcp));
    let mut tasks = Vec::new();
    let mut failed = false;
    for socket in listeners.udp {
        match socket
            .set_nonblocking(true)
            .and_then(|()| tokio::net::UdpSocket::from_std(socket))
        {
            Ok(socket) => tasks.push(tokio::spawn(serve_udp(
                Arc::new(socket),
                Arc::clone(&shared),
                Arc::clone(&limiter),
            ))),
            Err(_) => failed = true,
        }
    }
    for listener in listeners.tcp {
        match listener
            .set_nonblocking(true)
            .and_then(|()| tokio::net::TcpListener::from_std(listener))
        {
            Ok(listener) => tasks.push(tokio::spawn(accept_tcp(
                listener,
                Arc::clone(&shared),
                Arc::clone(&tcp_context),
            ))),
            Err(_) => failed = true,
        }
    }
    if failed {
        for task in &tasks {
            task.abort();
        }
        audit_task.abort();
        queues.close();
        drop(tasks);
        let _ = engine_thread.join();
        return Err(DaemonError::Listener);
    }
    control.state.serving.store(true, Ordering::SeqCst);
    note(Note::Listening, None);

    // 6. Until stopped.
    control.state.stop.notified().await;
    // Whether the engine ended on its own before the stop (its exit asks
    // for the stop): read before the queues are closed below.
    let engine_failed = control.state.engine_ended.load(Ordering::SeqCst);
    note(Note::Draining, None);
    shared.draining.store(true, Ordering::SeqCst);
    for task in &tasks {
        task.abort();
    }
    for task in tasks {
        let _ = task.await;
    }
    control.state.serving.store(false, Ordering::SeqCst);
    wait_until(DRAIN_GRACE, || shared.in_flight.load(Ordering::SeqCst) == 0).await;
    queues.close();
    // The one flush of every daemon (`ipc_audit_client::AuditGate::close`, docs/52
    // R6): the kdc's rule ends the wait early when auditd counts as
    // unreachable (A-87 kept it).
    let unacknowledged = gate
        .close(AUDIT_FLUSH_GRACE, async {
            audit_task.abort();
            let _ = audit_task.await;
        })
        .await
        .events();
    if engine_failed {
        note(Note::EngineStopped, None);
    }
    note(Note::Stopped, None);
    Ok(Stopped {
        engine: engine_thread,
        engine_failed,
        policy_version,
        unacknowledged,
    })
}
