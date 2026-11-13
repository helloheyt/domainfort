//! [`serve`]: the start-up checks, then the listeners with their
//! connection limits.
//!
//! # Order (docs/50 R50-16, §7.5 step 5)
//!
//! "ldap-front — configuration, certificate + key (`with_single_cert`
//! verifies the match), a test connection to dird ⇒ binds 389/636." The
//! certificate, key and listeners are handled as root by `main` before the
//! drop (crate::startup); here, after the drop and with the runtime up:
//!
//! 1. the TLS configuration is checked against docs/50 R50-11
//!    ([`crate::tls::check_policy`]) — any difference ⇒ no start;
//! 2. auditd is verified (peer uid, `Ping` → `Pong`) — R50-16;
//! 3. dird is verified on the LDAP channel (peer uid, `Ping` → `Pong`) —
//!    §7.5 step 5;
//! 4. only now are the listeners served. Until then nothing is read from
//!    them (a TCP handshake can complete into the kernel's backlog; a failed
//!    start closes it) — the kdc daemon's arrangement (Q-275 item 3).
//!
//! # Connection limits (docs/50 §4.1, §4.2; docs/07 §1)
//!
//! Each accepted connection must take, at once (or it is closed without a
//! byte and counted):
//!
//! * a slot of the global bound ([`MAX_CONNECTIONS`]);
//! * a slot of its source address' bound ([`MAX_CONNECTIONS_PER_SOURCE`]);
//! * a slot of the unauthenticated pool ([`MAX_UNAUTHENTICATED_CONNECTIONS`]),
//!   kept while dird reports the framing state `Unauthenticated`
//!   (crate::connection) — so a flood of unauthenticated connections cannot
//!   take the slots of authenticated sessions ("a separate pool for
//!   unauthenticated connections", docs/50 §4.2; docs/07 §1).
//!
//! The numbers are constants (config has no key for them; Q-230 item 4 →
//! A-60: "constants in the daemon"); docs/questions/Q-285 item 5.
//!
//! # Stopping
//!
//! [`DaemonControl::stop`] ends every accept loop; each loop owns its
//! connections' tasks (a tokio `JoinSet`: "When the JoinSet is dropped, all
//! tasks in the JoinSet are immediately aborted"), so they end with it.
//! SIGTERM is not handled (as the other daemons, Q-260 item 9).
//!
//! Spec: docs/50 R50-10, R50-11, R50-16, §4.1, §4.2, §6.2, §7.5; docs/07 §1;
//! tokio 1.54.1 docs.rs: `net::TcpListener::{from_std, accept}`,
//! `sync::{Semaphore, Notify}`, `task::JoinSet`, `spawn`.

use crate::audit::{verify_auditd, AuditCheckError};
use crate::connection::{self, ConnectionContext, Slots, Timeouts, CLIENT_WRITE_TIMEOUT};
use crate::dird::{ping, Endpoint};
use crate::log::{note, Note, ACCEPT_FAILED, CONNECTION_LIMITED};
use crate::tls::{check_policy, PolicyField};
use config::LdapFrontSettings;
use core::fmt;
use core::net::IpAddr;
use core::time::Duration;
use ipc_ldap::{ChannelFailure, Listener};
use rustls::server::ServerConfig;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use tokio::sync::{Notify, Semaphore};
use tokio::task::JoinSet;
use tokio::time::{sleep, Instant};

/// Most client connections at once: dird's LDAP session bound (crates/
/// directory-daemon `MAX_LDAP_SESSIONS`, 1024 — "docs/50 §4.1's 'e.g. 1024
/// connections'", A-70), so dird never has to refuse a session for its own
/// bound while the front is within its own.
/// Spec: docs/50 §4.1, §4.2; docs/questions/Q-280 item 4 (A-70).
pub const MAX_CONNECTIONS: usize = 1024;

/// Most connections from one source address at once.
/// Spec: docs/50 §4.1 ("a counter per source address (e.g. 16)"), §4.2
/// ("a connection quota per source").
pub const MAX_CONNECTIONS_PER_SOURCE: usize = 16;

/// Most connections at once whose framing state is unauthenticated: three
/// quarters of [`MAX_CONNECTIONS`], leaving a quarter to authenticated
/// sessions. Project choice.
/// Spec: docs/50 §4.2 ("a separate pool for unauthenticated connections");
/// docs/07 §1.
pub const MAX_UNAUTHENTICATED_CONNECTIONS: usize = MAX_CONNECTIONS / 4 * 3;

/// Pause after a failed `accept`. Project choice.
const ACCEPT_RETRY: Duration = Duration::from_millis(50);

// The pool is inside the global bound, and the global bound is dird's.
const _: () = assert!(MAX_UNAUTHENTICATED_CONNECTIONS < MAX_CONNECTIONS);
const _: () = assert!(MAX_CONNECTIONS_PER_SOURCE <= MAX_UNAUTHENTICATED_CONNECTIONS);

/// The connection bounds.
/// Spec: module documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionLimits {
    /// The global bound.
    pub max_connections: usize,
    /// The per-source bound.
    pub max_per_source: usize,
    /// The unauthenticated pool.
    pub max_unauthenticated: usize,
}

impl ConnectionLimits {
    /// The daemon's constants.
    pub const DEFAULT: ConnectionLimits = ConnectionLimits {
        max_connections: MAX_CONNECTIONS,
        max_per_source: MAX_CONNECTIONS_PER_SOURCE,
        max_unauthenticated: MAX_UNAUTHENTICATED_CONNECTIONS,
    };
}

/// Everything [`serve`] needs besides the TLS configuration and the
/// listeners.
/// Spec: docs/50 §2.4, §3.6, §4.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrontParams {
    /// dird's `dird-ldap.sock` and uid.
    pub dird: Endpoint,
    /// auditd's socket and uid.
    pub audit: Endpoint,
    /// The timeouts.
    pub timeouts: Timeouts,
    /// The connection bounds.
    pub limits: ConnectionLimits,
}

impl FrontParams {
    /// The parameters of `settings`, with the daemon's constant bounds.
    /// Spec: docs/50 §3.6, §4.2, §7.1; crates/config `LdapFrontSettings`.
    #[must_use]
    pub fn from_settings(settings: &LdapFrontSettings) -> FrontParams {
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
            timeouts: Timeouts {
                init_recv: limits.init_recv_timeout(),
                max_idle: limits.max_conn_idle_time(),
                tls_handshake: limits.tls_handshake_timeout(),
                dird_deadline: limits.dird_deadline(),
                client_write: CLIENT_WRITE_TIMEOUT,
            },
            limits: ConnectionLimits::DEFAULT,
        }
    }
}

/// The bound listeners (crate::startup binds them as root).
/// Spec: docs/50 §4.2, §6.2.
#[derive(Debug, Default)]
pub struct Listeners {
    /// LDAP with StartTLS (389-style).
    pub ldap: Vec<std::net::TcpListener>,
    /// LDAPS (636-style).
    pub ldaps: Vec<std::net::TcpListener>,
}

/// Why [`serve`] did not start. Carries no secret.
/// Spec: docs/50 §7.5 (fail closed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaemonError {
    /// The TLS configuration is outside docs/50 R50-11.
    TlsPolicy(PolicyField),
    /// auditd did not answer the check.
    Audit(AuditCheckError),
    /// dird did not answer the check.
    Dird(ChannelFailure),
    /// A listener could not be handed to the runtime.
    Listener,
}

impl fmt::Display for DaemonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DaemonError::TlsPolicy(field) => {
                write!(f, "TLS configuration outside the profile: {field:?}")
            }
            DaemonError::Audit(error) => write!(f, "auditd not verified: {error}"),
            DaemonError::Dird(failure) => write!(f, "dird not verified: {failure}"),
            DaemonError::Listener => f.write_str("listener could not be served"),
        }
    }
}

impl std::error::Error for DaemonError {}

/// The shared stop / serving state.
#[derive(Debug, Default)]
struct ControlState {
    stop: Notify,
    stopping: AtomicBool,
    serving: AtomicBool,
}

/// Stops a running [`serve`] and tells whether it serves.
/// Spec: docs/50 §9 (tier-2 tests run the real servers in threads).
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

    /// Wait until a stop was asked for.
    async fn stopped(&self) {
        while !self.state.stopping.load(Ordering::SeqCst) {
            self.state.stop.notified().await;
        }
    }
}

/// One source address' open connections; released on drop.
/// Spec: docs/50 §4.1 ("a counter per source address").
pub(crate) struct SourceSlot {
    counts: Arc<Mutex<HashMap<IpAddr, usize>>>,
    source: IpAddr,
}

impl Drop for SourceSlot {
    fn drop(&mut self) {
        if let Ok(mut counts) = self.counts.lock() {
            let empty = match counts.get_mut(&self.source) {
                Some(count) => {
                    *count = count.saturating_sub(1);
                    *count == 0
                }
                None => false,
            };
            if empty {
                counts.remove(&self.source);
            }
        }
    }
}

/// The admission state (module documentation).
struct Admission {
    total: Arc<Semaphore>,
    unauthenticated: Arc<Semaphore>,
    per_source: Arc<Mutex<HashMap<IpAddr, usize>>>,
    max_per_source: usize,
}

impl Admission {
    fn new(limits: ConnectionLimits) -> Admission {
        Admission {
            total: Arc::new(Semaphore::new(
                limits.max_connections.min(Semaphore::MAX_PERMITS),
            )),
            unauthenticated: Arc::new(Semaphore::new(
                limits.max_unauthenticated.min(Semaphore::MAX_PERMITS),
            )),
            per_source: Arc::new(Mutex::new(HashMap::new())),
            max_per_source: limits.max_per_source,
        }
    }

    /// The three slots for a connection from `source`, or `None` (close).
    /// A poisoned counter refuses (fail closed).
    /// Spec: module documentation.
    fn admit(&self, source: IpAddr) -> Option<Slots> {
        let total = Arc::clone(&self.total).try_acquire_owned().ok()?;
        let slot = {
            let mut counts = self.per_source.lock().ok()?;
            let count = counts.entry(source).or_insert(0);
            if *count >= self.max_per_source {
                if *count == 0 {
                    counts.remove(&source);
                }
                return None;
            }
            *count += 1;
            SourceSlot {
                counts: Arc::clone(&self.per_source),
                source,
            }
        };
        let unauthenticated = Arc::clone(&self.unauthenticated).try_acquire_owned().ok()?;
        Some(Slots {
            _total: total,
            _source: slot,
            unauthenticated: Some(unauthenticated),
        })
    }
}

/// Accept connections on one listener until aborted.
/// Spec: module documentation.
async fn accept_loop(
    listener: TcpListener,
    kind: Listener,
    context: Arc<ConnectionContext>,
    admission: Arc<Admission>,
) {
    let mut tasks = JoinSet::new();
    loop {
        while tasks.try_join_next().is_some() {}
        match listener.accept().await {
            Ok((stream, peer)) => {
                let accepted = Instant::now();
                match admission.admit(peer.ip()) {
                    Some(slots) => {
                        tasks.spawn(connection::run(
                            stream,
                            peer,
                            kind,
                            Arc::clone(&context),
                            slots,
                            accepted,
                        ));
                    }
                    None => {
                        CONNECTION_LIMITED.hit();
                        drop(stream);
                    }
                }
            }
            Err(_) => {
                ACCEPT_FAILED.hit();
                sleep(ACCEPT_RETRY).await;
            }
        }
    }
}

/// Run ldap-front until [`DaemonControl::stop`] (module documentation).
///
/// # Errors
/// [`DaemonError`] — a start-up check failed; nothing was served.
///
/// Spec: docs/50 R50-10, R50-11, R50-16, §4.2, §7.5.
pub async fn serve(
    params: FrontParams,
    tls: Arc<ServerConfig>,
    listeners: Listeners,
    control: DaemonControl,
) -> Result<(), DaemonError> {
    check_policy(&tls).map_err(DaemonError::TlsPolicy)?;
    verify_auditd(&params.audit)
        .await
        .map_err(DaemonError::Audit)?;
    note(Note::AuditVerified, None);
    ping(&params.dird, params.timeouts.dird_deadline)
        .await
        .map_err(DaemonError::Dird)?;
    note(Note::DirdVerified, None);

    let admission = Arc::new(Admission::new(params.limits));
    let context = Arc::new(ConnectionContext {
        dird: params.dird,
        timeouts: params.timeouts,
        tls,
        unauthenticated: Arc::clone(&admission.unauthenticated),
    });
    let mut served = Vec::new();
    for (kind, bound) in [
        (Listener::Ldap, listeners.ldap),
        (Listener::Ldaps, listeners.ldaps),
    ] {
        for listener in bound {
            listener
                .set_nonblocking(true)
                .map_err(|_| DaemonError::Listener)?;
            served.push((
                kind,
                TcpListener::from_std(listener).map_err(|_| DaemonError::Listener)?,
            ));
        }
    }
    let loops: Vec<_> = served
        .into_iter()
        .map(|(kind, listener)| {
            tokio::spawn(accept_loop(
                listener,
                kind,
                Arc::clone(&context),
                Arc::clone(&admission),
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
