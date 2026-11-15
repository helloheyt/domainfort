//! [`serve`]: the start-up checks, then the TCP listeners with their
//! connection limits.
//!
//! # Order (docs/50 R50-16, §7.5)
//!
//! The listeners are bound as root by `main` before the drop
//! (crate::startup); here, after the drop and with the runtime up:
//!
//! 1. at least one listener, and every listener's local address lies in an
//!    internal network ([`FrontParams::internal_networks`]) — else no start
//!    ([`DaemonError::ListenerNotInternal`]): this front is the internal
//!    zone's (docs/53 §3.3; docs/52 R14), whatever bound the listeners;
//! 2. the realm is a valid Kerberos realm (the KRB-ERROR encoder,
//!    crate::reply);
//! 3. auditd is verified (crate::audit) — R50-16; today this fails closed,
//!    no audit source existing for the front (docs/questions/Q-955 item 1);
//! 4. dird is verified on the kpasswd channel (peer uid, `Ping` → `Pong`
//!    naming the internal zone) — §7.5;
//! 5. only now are the listeners served. Until then nothing is read from
//!    them (a TCP handshake can complete into the kernel's backlog; a failed
//!    start closes it) — the kdc's and ldap-front's arrangement (Q-275
//!    item 3).
//!
//! # One front, the internal zone (docs/53 §3.3; docs/52 §7 R14)
//!
//! dird decides every request of this front under the internal zone, which
//! it derives from this process's uid. So the front makes "internal" true
//! where it owns the facts — its sockets: it listens only on internal
//! addresses (step 1; crates/config refuses any other listener) and closes,
//! **without a byte**, every accepted connection whose source address — the
//! kernel's, from `accept` — is outside the internal networks (counted).
//!
//! # Connection limits (docs/53 §5.1; docs/50 §4.1)
//!
//! Each accepted connection from an internal source must take, at once, a
//! slot of the global bound and a slot of its source address' bound (the
//! configured `max_tcp_connections`, `max_tcp_connections_per_source`) — or
//! it is closed without a byte and counted. A connection holds its slots
//! until it ends: one request, one reply, close (crate::connection).
//!
//! # Stopping
//!
//! [`DaemonControl::stop`] ends every accept loop; each loop owns its
//! connections' tasks (a tokio `JoinSet`, whose drop aborts them). SIGTERM
//! is not handled (as the other daemons, Q-260 item 9).
//!
//! Spec: docs/53 R53-3, §3.3, §5.1, §5.6; docs/50 R50-16, §4.1, §6.2, §7.5;
//! docs/52 §7 R14; tokio 1.54.1 docs.rs: `net::TcpListener::{from_std,
//! accept}`, `net::TcpStream::local_addr`, `sync::{Semaphore, Notify}`,
//! `task::JoinSet`, `spawn`; std `net::TcpListener::local_addr`.

use crate::audit::{verify_auditd, AuditCheckError, FRONT_AUDIT_SOURCE};
use crate::connection;
use crate::log::{note, Counters, Counts, Note};
use crate::reply::{InvalidRealm, ReplyEncoder};
use config::{is_internal, KpasswdFrontSettings, Network};
use core::fmt;
use core::net::IpAddr;
use core::time::Duration;
use ipc_audit::EventSource;
use ipc_kpasswd::{
    ClientConfigError, ExpectedDird, FrontZone, KpasswdClient, Unserved, MAX_FRONT_CONNECTIONS,
};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use tokio::sync::{Notify, Semaphore};
use tokio::task::JoinSet;
use tokio::time::{sleep, Instant};

// The configuration's default (and ceiling) dird deadline is the channel's
// default deadline — one value (crates/config cannot link ipc-kpasswd; this
// crate links both). Spec: docs/53 §5.6; docs/50 §3.6.
const _: () = assert!(
    config::DIRD_KPASSWD_DEADLINE_SECS.default as u64 == ipc_kpasswd::DEFAULT_DEADLINE.as_secs()
        && config::DIRD_KPASSWD_DEADLINE_SECS.max as u64 == ipc_kpasswd::DEFAULT_DEADLINE.as_secs()
);

/// Pause after a failed `accept` (for example, the open-files limit) so the
/// loop does not spin. Project choice.
const ACCEPT_RETRY: Duration = Duration::from_millis(50);

/// Where a local server listens and which uid it must run as.
/// Spec: docs/50 R50-3, §3.1, §3.2 (crates/config `Endpoint`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    /// The socket path.
    pub socket: PathBuf,
    /// The server's uid.
    pub uid: u32,
}

/// The connection bounds (crates/config `KpasswdFrontLimits`).
/// Spec: docs/53 §5.1; docs/50 §4.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionLimits {
    /// Open client connections, all sources.
    pub max_connections: u32,
    /// Open client connections per source address.
    pub max_per_source: u32,
}

/// The timeouts and the dird deadline (crates/config `KpasswdFrontLimits`).
/// Spec: docs/53 §5.1, §5.6; docs/50 §3.6, §4.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timeouts {
    /// The request frame, from the accept.
    pub first_frame: Duration,
    /// The write of the reply.
    pub reply_write: Duration,
    /// dird's answer to one request.
    pub dird_deadline: Duration,
}

/// What kpasswd-front's configuration sets for the daemon — **and nothing
/// else** (docs/52 C18, task R15): the product parameters.
/// Spec: docs/53 §3.3, §5.1, §5.7; docs/50 §3.6, §4.1; docs/52 §3.18.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrontParams {
    /// dird's `dird-kpasswd.sock` and uid.
    pub dird: Endpoint,
    /// auditd's socket and uid.
    pub audit: Endpoint,
    /// The realm of the front's KRB-ERRORs.
    pub realm: String,
    /// The timeouts and the dird deadline.
    pub timeouts: Timeouts,
    /// The connection bounds.
    pub limits: ConnectionLimits,
    /// The zone table: every listener's address and every served client's
    /// source address lie in one of these networks.
    pub internal_networks: Vec<Network>,
}

impl FrontParams {
    /// The parameters of `settings` — the one product constructor (docs/52
    /// C18).
    /// Spec: docs/53 §3.3, §5.1; crates/config `KpasswdFrontSettings`.
    #[must_use]
    pub fn from_settings(settings: &KpasswdFrontSettings) -> FrontParams {
        let limits = settings.limits();
        FrontParams {
            dird: Endpoint {
                socket: settings.dird().socket().as_path().to_path_buf(),
                uid: settings.dird().uid(),
            },
            audit: Endpoint {
                socket: settings.audit().socket().as_path().to_path_buf(),
                uid: settings.audit().uid(),
            },
            realm: settings.realm().to_owned(),
            timeouts: Timeouts {
                first_frame: limits.tcp_first_frame_timeout(),
                reply_write: limits.tcp_frame_timeout(),
                dird_deadline: limits.dird_deadline(),
            },
            limits: ConnectionLimits {
                max_connections: limits.max_tcp_connections(),
                max_per_source: limits.max_tcp_connections_per_source(),
            },
            internal_networks: settings.internal_networks().to_vec(),
        }
    }
}

/// Everything [`serve_with`] needs besides the listeners: the product
/// [`FrontParams`] plus the audit source the front must be recorded under.
/// Built for a product front only by `From<FrontParams>`, with
/// [`FRONT_AUDIT_SOURCE`] (none yet — the start fails closed, crate::audit).
/// Crate-private: only this crate's `#[cfg(test)]` modules build one with a
/// stand-in source for their test auditd — no other crate, in any build,
/// can (docs/52 C18: no test seam in a product API).
/// Spec: docs/52 §3.18; docs/50 R50-16; docs/questions/Q-955 item 1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ServeParams {
    /// The product parameters.
    pub(crate) front: FrontParams,
    /// The source auditd must record the front under.
    pub(crate) audit_source: Option<EventSource>,
}

impl From<FrontParams> for ServeParams {
    /// The product parameters with the product audit source.
    /// Spec: crate::audit.
    fn from(front: FrontParams) -> ServeParams {
        ServeParams {
            front,
            audit_source: FRONT_AUDIT_SOURCE,
        }
    }
}

/// The bound TCP listeners (crate::startup binds them as root).
/// Spec: docs/53 R53-3; docs/50 §6.2.
#[derive(Debug, Default)]
pub struct Listeners {
    /// The TCP 464 listeners (no UDP — A-117).
    pub tcp: Vec<std::net::TcpListener>,
}

/// Why [`serve`] did not start. Carries no secret.
/// Spec: docs/50 §7.5 (fail closed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaemonError {
    /// No listener was given.
    NoListener,
    /// A listener's local address is outside every internal network (or
    /// cannot be read).
    /// Spec: docs/53 §3.3; docs/52 §7 R14.
    ListenerNotInternal,
    /// The realm is not a valid Kerberos realm.
    Realm(InvalidRealm),
    /// auditd was not verified.
    Audit(AuditCheckError),
    /// dird's configured uid is unusable.
    DirdConfig(ClientConfigError),
    /// dird did not answer the check.
    Dird(Unserved),
    /// A listener could not be handed to the runtime.
    Listener,
}

impl fmt::Display for DaemonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DaemonError::NoListener => f.write_str("no listener"),
            DaemonError::ListenerNotInternal => {
                f.write_str("listener address outside every internal network")
            }
            DaemonError::Realm(error) => write!(f, "{error}"),
            DaemonError::Audit(error) => write!(f, "auditd not verified: {error}"),
            DaemonError::DirdConfig(error) => write!(f, "dird endpoint refused: {error}"),
            DaemonError::Dird(error) => write!(f, "dird not verified: {error}"),
            DaemonError::Listener => f.write_str("listener could not be served"),
        }
    }
}

impl std::error::Error for DaemonError {}

/// The shared stop / serving state and the counters.
#[derive(Debug, Default)]
struct ControlState {
    stop: Notify,
    stopping: AtomicBool,
    serving: AtomicBool,
    counters: Counters,
}

/// Stops a running [`serve`], tells whether it serves, and reads its
/// counted events.
/// Spec: docs/50 §9 (tier-2 tests run the real servers in threads); docs/53
/// §9 (counts).
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

    /// Whether the listeners serve.
    #[must_use]
    pub fn is_serving(&self) -> bool {
        self.state.serving.load(Ordering::SeqCst)
    }

    /// The daemon's counted events (crate::log).
    #[must_use]
    pub fn counts(&self) -> Counts {
        self.state.counters.snapshot()
    }

    /// Wait until a stop was asked for.
    async fn stopped(&self) {
        while !self.state.stopping.load(Ordering::SeqCst) {
            self.state.stop.notified().await;
        }
    }
}

/// What every connection task needs (crate::connection).
pub(crate) struct Context {
    /// The front's client of dird (built only with the expected dird).
    pub(crate) client: KpasswdClient,
    /// The dird slots ([`MAX_FRONT_CONNECTIONS`]).
    pub(crate) dird_slots: Semaphore,
    /// The KRB-ERROR encoder.
    pub(crate) encoder: ReplyEncoder,
    /// The timeouts.
    pub(crate) timeouts: Timeouts,
    /// The control state, whose counters this front counts into.
    state: Arc<ControlState>,
}

impl Context {
    /// The counters.
    pub(crate) fn counters(&self) -> &Counters {
        &self.state.counters
    }
}

/// The open connections per source and in all; a slot is given back on
/// drop.
/// Spec: docs/50 §4.1 ("a counter per source address").
#[derive(Debug, Default)]
struct Open {
    total: u32,
    per_source: HashMap<IpAddr, u32>,
}

/// The admission state (module documentation).
struct Admission {
    limits: ConnectionLimits,
    open: Mutex<Open>,
}

impl Admission {
    /// A slot for a connection from `source`, or `None` at a bound. A
    /// poisoned counter refuses (fail closed).
    /// Spec: docs/53 §5.1; docs/50 §4.1.
    fn admit(self: &Arc<Self>, source: IpAddr) -> Option<Slot> {
        let mut open = self.open.lock().ok()?;
        if open.total >= self.limits.max_connections {
            return None;
        }
        let count = open.per_source.entry(source).or_insert(0);
        if *count >= self.limits.max_per_source {
            if *count == 0 {
                open.per_source.remove(&source);
            }
            return None;
        }
        *count = count.saturating_add(1);
        open.total = open.total.saturating_add(1);
        Some(Slot {
            admission: Arc::clone(self),
            source,
        })
    }
}

/// One held connection slot; given back when the connection ends.
struct Slot {
    admission: Arc<Admission>,
    source: IpAddr,
}

impl Drop for Slot {
    fn drop(&mut self) {
        if let Ok(mut open) = self.admission.open.lock() {
            open.total = open.total.saturating_sub(1);
            let empty = match open.per_source.get_mut(&self.source) {
                Some(count) => {
                    *count = count.saturating_sub(1);
                    *count == 0
                }
                None => false,
            };
            if empty {
                open.per_source.remove(&self.source);
            }
        }
    }
}

/// At least one listener, and every listener's local address lies in an
/// internal network (an address that cannot be read fails closed).
/// Spec: docs/53 §3.3; docs/52 §7 R14.
fn check_listeners(listeners: &Listeners, internal: &[Network]) -> Result<(), DaemonError> {
    if listeners.tcp.is_empty() {
        return Err(DaemonError::NoListener);
    }
    for listener in &listeners.tcp {
        let local = listener
            .local_addr()
            .map_err(|_| DaemonError::ListenerNotInternal)?;
        if !is_internal(internal, local.ip()) {
            return Err(DaemonError::ListenerNotInternal);
        }
    }
    Ok(())
}

/// Accept connections on one listener until aborted (module documentation).
/// Spec: docs/53 §3.3, §5.1; docs/52 R14.
async fn accept_loop(
    listener: TcpListener,
    context: Arc<Context>,
    admission: Arc<Admission>,
    internal: Arc<[Network]>,
) {
    let mut tasks = JoinSet::new();
    loop {
        while tasks.try_join_next().is_some() {}
        match listener.accept().await {
            Ok((stream, peer)) => {
                let accepted = Instant::now();
                // A source outside the internal networks has no path: closed
                // before any slot is taken or any byte is read.
                if !is_internal(&internal, peer.ip()) {
                    context.counters().source_not_internal.hit();
                    drop(stream);
                    continue;
                }
                let Some(slot) = admission.admit(peer.ip()) else {
                    context.counters().connection_limited.hit();
                    drop(stream);
                    continue;
                };
                let Ok(local) = stream.local_addr() else {
                    drop(stream);
                    continue;
                };
                let context = Arc::clone(&context);
                tasks.spawn(async move {
                    let _slot = slot;
                    connection::run(stream, peer, local, context, accepted).await;
                });
            }
            Err(_) => {
                context.counters().accept_failed.hit();
                sleep(ACCEPT_RETRY).await;
            }
        }
    }
}

/// Run the product kpasswd-front until [`DaemonControl::stop`] (module
/// documentation): the product parameters and the product audit source
/// (docs/52 C18).
///
/// # Errors
/// [`DaemonError`] — a start-up check failed; nothing was served.
///
/// Spec: docs/53 §3.3, §5.1; docs/50 R50-16, §7.5; docs/52 §3.18.
pub async fn serve(
    params: FrontParams,
    listeners: Listeners,
    control: DaemonControl,
) -> Result<(), DaemonError> {
    serve_with(ServeParams::from(params), listeners, control).await
}

/// [`serve`] with every value given. Crate-private (see [`ServeParams`]).
///
/// # Errors
/// [`DaemonError`] — a start-up check failed; nothing was served.
///
/// Spec: docs/53 §3.3, §5.1, §5.6; docs/50 R50-16, §7.5; docs/52 §7 R14.
pub(crate) async fn serve_with(
    params: ServeParams,
    listeners: Listeners,
    control: DaemonControl,
) -> Result<(), DaemonError> {
    let ServeParams {
        front,
        audit_source,
    } = params;
    check_listeners(&listeners, &front.internal_networks)?;
    let encoder = ReplyEncoder::new(&front.realm).map_err(DaemonError::Realm)?;
    verify_auditd(&front.audit, audit_source)
        .await
        .map_err(DaemonError::Audit)?;
    note(Note::AuditVerified, None);
    let expected =
        ExpectedDird::new(front.dird.uid, FrontZone::Internal).map_err(DaemonError::DirdConfig)?;
    let client = KpasswdClient::new(front.dird.socket, expected, front.timeouts.dird_deadline);
    client.ping().await.map_err(DaemonError::Dird)?;
    note(Note::DirdVerified, None);

    let admission = Arc::new(Admission {
        limits: front.limits,
        open: Mutex::new(Open::default()),
    });
    let internal: Arc<[Network]> = Arc::from(front.internal_networks);
    let context = Arc::new(Context {
        client,
        dird_slots: Semaphore::new(MAX_FRONT_CONNECTIONS),
        encoder,
        timeouts: front.timeouts,
        state: Arc::clone(&control.state),
    });
    let mut served = Vec::with_capacity(listeners.tcp.len());
    for listener in listeners.tcp {
        listener
            .set_nonblocking(true)
            .map_err(|_| DaemonError::Listener)?;
        served.push(TcpListener::from_std(listener).map_err(|_| DaemonError::Listener)?);
    }
    let loops: Vec<_> = served
        .into_iter()
        .map(|listener| {
            tokio::spawn(accept_loop(
                listener,
                Arc::clone(&context),
                Arc::clone(&admission),
                Arc::clone(&internal),
            ))
        })
        .collect();
    control.state.serving.store(true, Ordering::SeqCst);
    note(Note::Listening, None);

    control.stopped().await;
    for accept in &loops {
        accept.abort();
    }
    for accept in loops {
        let _ = accept.await;
    }
    control.state.serving.store(false, Ordering::SeqCst);
    note(Note::Stopped, None);
    Ok(())
}
