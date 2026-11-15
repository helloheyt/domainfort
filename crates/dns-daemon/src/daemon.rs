//! [`serve`]: the start-up checks, then the listeners.
//!
//! # Order (docs/54 §4.8; docs/50 R50-16, §7.5)
//!
//! "dnsd: configuration ⇒ bind ⇒ hardening ⇒ auditd verified ⇒ dird verified
//! (`Ping` ⇒ `Pong` with the zone) ⇒ `FetchZoneImage` (A-154: without
//! `DescribeZone`) ⇒ **only then** serve. dird down at start ⇒ dnsd does not
//! come up." The configuration, the binding and the hardening are `main`'s
//! (crate::startup); here, after the drop and with the runtime up:
//!
//! 1. every listener's local address lies in an internal network — else no
//!    start ([`DaemonError::ListenerNotInternal`]), nothing contacted
//!    (docs/54 §4.7: "`serve` refuses a listener whose local address lies
//!    outside it");
//! 2. auditd is verified (crate::audit: its uid, and a `Pong` naming the
//!    source `dnsd`) — else no start; the verified connection is kept for
//!    dnsd's counters;
//! 3. the zone thread verifies dird on its connection and fetches the whole
//!    image (`FetchZoneImage { have: None }`) — else no start;
//! 4. the forwarding thread verifies dird on its own connection — else no
//!    start;
//! 5. **only now** are the listeners served — and the audit link attached to
//!    the connection verified in step 2, delivering dnsd's noise counters
//!    (crate::audit; docs/54 §9). Until then nothing was read from the
//!    listeners or answered (a datagram waits in the receive buffer, a TCP
//!    handshake can complete into the backlog; a failed start closes them
//!    all — the kdc's and ldap-front's arrangement, Q-275 item 3).
//!
//! # Noise counters (docs/54 §9)
//!
//! Every peer-driven noise occurrence passes [`Shared::noise`], the one
//! place it is counted — into the operational log's thinned counter and
//! into dnsd's audit window (one `WindowSummary` per audit heartbeat at
//! most — the shared gate's summary pace, docs/questions/Q-989; no record
//! per query). The reading of docs/54 §9's "dropped /
//! limited / malformed / refused" (docs/questions/Q-961): dropped — a
//! source outside `internal_networks`; limited — the UDP, TCP-message,
//! TCP-connection and forwarding limits; malformed — a request dns-zone
//! answers with silence; refused — a signed UPDATE refused for a full
//! forwarding queue. dnsd's own operational failures (a receive or accept
//! error, a failed SERIAL check, dird not serving a forward, a stale image)
//! are not peer noise and stay on the operational log only.
//!
//! # Fail closed (docs/54 §4.4, §4.8; AGENTS.md §6)
//!
//! | condition | effect |
//! |---|---|
//! | dird never reached, or no valid image, at start | no start: nothing is ever answered |
//! | auditd not verified at start (another uid, or a source other than `dnsd` — its `uid_sources` does not map dnsd) | no start |
//! | auditd lost while serving | queries unaffected (not gated, docs/54 §9); counts kept and sent once the link is verified again |
//! | a listener outside `internal_networks` | no start |
//! | image not confirmed within `zone_image_max_age` | every query SERVFAIL (dns-zone row 12) until a SERIAL check succeeds |
//! | source outside `internal_networks` | UDP: dropped; TCP: closed before a byte is read |
//! | forwarding queue full, limit reached, dird fails | SERVFAIL (dns-zone's fallback reply) |
//! | dird answers `reply: None` | TCP: close without a reply |
//!
//! # Stopping
//!
//! [`DaemonControl::stop`] ends every listener task (each TCP accept loop
//! owns its connections in a `JoinSet`, which aborts them when dropped);
//! the forwarding queue and the zone thread's request channel then have no
//! sender left, so both threads end after their current dird call (bounded
//! by the channel deadline); the caller joins them ([`Stopped::join`]) after
//! dropping the runtime. The audit gate's one flush (`AUDIT_FLUSH_GRACE`,
//! stopping early once auditd counts as unreachable) then ends the audit
//! link; noise counted since the link's last look at the window is not
//! summarised (it stays on the operational log — docs/questions/Q-961).
//! SIGTERM is not handled, as in the other daemons (Q-260 item 9).
//!
//! Spec: docs/54 §4.4, §4.6–§4.8, §6.6, §6.7; docs/50 R50-14, R50-16, §6.2,
//! §7.5; A-114; A-152; docs/questions/Q-921 item 6; tokio 1.54.1 docs.rs:
//! `net::{UdpSocket, TcpListener}::from_std`, `task::JoinSet`, `spawn`,
//! `sync::{mpsc, oneshot, Notify}`.

use crate::audit::{self, AuditGate, AUDIT_WINDOW};
use crate::clock::{Clock, MonotonicClock};
use crate::forward::{self, ForwardJob, ForwardThread};
use crate::limits::{
    FORWARD_ANSWER_TIMEOUT, FORWARD_LIMITS, FORWARD_QUEUE_CAPACITY, REFRESH_INTERVAL, REFRESH_WAIT,
    TCP_MESSAGE_LIMITS, UDP_LIMITS,
};
use crate::log::{note, Note, Thinned, ZONE_UNAVAILABLE};
use crate::source::is_served;
use crate::tcp::{accept_tcp, TcpContext, TcpLimits};
use crate::udp::serve_udp;
use crate::zone::{self, ZoneThread, ZoneView};
use config::{DnsdSettings, Network};
use core::fmt;
use core::time::Duration;
use dns_zone::{answer, Transport, Verdict, ZoneState};
use ipc_audit_client::{AuditEndpoint, AuditLinkError, AUDIT_FLUSH_GRACE};
use ipc_dns::{
    ClientConfigError, Connector, DnsClient, ExpectedDird, FrontZone, UnixConnector, Unserved,
};
use rate_limit::{SourceLimiter, SourceLimits};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::sync_channel;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Instant;
use tokio::sync::{mpsc, oneshot, Notify};

/// dird's DNS socket and uid (dnsd's configuration).
/// Spec: docs/54 §4.6; docs/50 R50-3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirdEndpoint {
    /// `dird_dns_socket`.
    pub socket: PathBuf,
    /// `dird_uid`.
    pub uid: u32,
}

/// What dnsd's configuration file sets for the daemon — **and nothing
/// else** (docs/52 C18, task R15): the product parameters. The values no
/// configuration key sets (the rate limits, the forwarding queue, the
/// refresh interval, the dird deadline) are the daemon's constants,
/// supplied by [`serve`]; they are not fields here. The audit source is not
/// a parameter anywhere: it is `audit::AUDIT_SOURCE` (task DN12).
/// Spec: docs/54 §4.3, §4.4, §4.6, §4.7, §6.7; docs/52 §3.18.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonParams {
    /// dird's `dird-dns.sock` and uid.
    pub dird: DirdEndpoint,
    /// auditd's socket and uid.
    pub audit: AuditEndpoint,
    /// The zone table: every listener and every served source lies in one of
    /// these networks (A-114).
    pub internal_networks: Vec<Network>,
    /// The TCP connection bounds and timeouts (docs/54 §6.7).
    pub tcp: TcpLimits,
    /// The zone image's staleness bound (docs/54 §4.4).
    pub zone_image_max_age: Duration,
}

impl DaemonParams {
    /// The parameters of `settings` — the one product constructor (docs/52
    /// C18, task R15); the daemon's constants are added by [`serve`].
    /// Spec: docs/54 §4.3, §4.4, §6.7; crates/config `DnsdSettings`.
    #[must_use]
    pub fn from_settings(settings: &DnsdSettings) -> DaemonParams {
        let limits = settings.limits();
        DaemonParams {
            dird: DirdEndpoint {
                socket: settings.dird().socket().as_path().to_path_buf(),
                uid: settings.dird().uid(),
            },
            audit: AuditEndpoint {
                socket: settings.audit().socket().as_path().to_path_buf(),
                uid: settings.audit().uid(),
            },
            internal_networks: settings.internal_networks().to_vec(),
            tcp: TcpLimits {
                max_connections: limits.max_tcp_connections(),
                max_per_source: limits.max_tcp_connections_per_source(),
                first_octet_timeout: limits.tcp_first_octet_timeout(),
                frame_timeout: limits.tcp_frame_timeout(),
                idle_timeout: limits.tcp_idle_timeout(),
                max_requests: limits.max_requests_per_tcp_connection(),
            },
            zone_image_max_age: limits.zone_image_max_age(),
        }
    }
}

/// Everything [`serve_with`] needs besides the listeners, the connectors and
/// the clock: the product [`DaemonParams`] plus the test seams. Built for a
/// product daemon only by `From<DaemonParams>` (the production constants);
/// reachable outside this crate only as `test_seams::DaemonParams` (docs/52
/// C18, task R15).
/// Spec: docs/54 §4.4, §4.6, §6.7; docs/52 §3.18.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServeParams {
    /// dird's uid (the client checks it on every connection, R50-3).
    pub dird_uid: u32,
    /// The deadline of one call on the dird channel (docs/50 §3.6).
    pub dird_deadline: Duration,
    /// auditd's socket and uid (the source it must name is
    /// `audit::AUDIT_SOURCE`, never a parameter — task DN12).
    pub audit: AuditEndpoint,
    /// The zone table (A-114).
    pub internal_networks: Vec<Network>,
    /// The TCP connection bounds and timeouts.
    pub tcp: TcpLimits,
    /// The zone image's staleness bound.
    pub zone_image_max_age: Duration,
    /// The UDP limits (docs/54 §6.7).
    pub udp: SourceLimits,
    /// The TCP message limits (docs/54 §6.7, R54-10).
    pub tcp_messages: SourceLimits,
    /// The forwarding limits (docs/54 §6.7).
    pub forwards: SourceLimits,
    /// The forwarding queue (docs/54 §6.7).
    pub forward_queue_capacity: usize,
    /// How long a TCP connection waits for its forward's outcome.
    pub forward_answer_timeout: Duration,
    /// The periodic SERIAL check (docs/54 §4.4 (b)).
    pub refresh_interval: Duration,
    /// How long a forward's reply waits for the image it changed.
    pub refresh_wait: Duration,
}

impl From<DaemonParams> for ServeParams {
    /// The product parameters with the daemon's constants — the only values a
    /// product dnsd runs with (docs/52 C18, task R15).
    /// Spec: docs/54 §4.4, §4.6, §6.7; docs/questions/Q-951.
    fn from(params: DaemonParams) -> ServeParams {
        ServeParams {
            dird_uid: params.dird.uid,
            dird_deadline: crate::limits::DIRD_DEADLINE,
            audit: params.audit,
            internal_networks: params.internal_networks,
            tcp: params.tcp,
            zone_image_max_age: params.zone_image_max_age,
            udp: UDP_LIMITS,
            tcp_messages: TCP_MESSAGE_LIMITS,
            forwards: FORWARD_LIMITS,
            forward_queue_capacity: FORWARD_QUEUE_CAPACITY,
            forward_answer_timeout: FORWARD_ANSWER_TIMEOUT,
            refresh_interval: REFRESH_INTERVAL,
            refresh_wait: REFRESH_WAIT,
        }
    }
}

/// The sockets `main` bound (as root, before the drop): one UDP socket and
/// one TCP listener per configured address. Bound, not yet served.
/// Spec: RFC 1035 §4.2, §4.2.1, §4.2.2; docs/54 §4.7; docs/50 §6.2.
#[derive(Debug, Default)]
pub struct Listeners {
    /// The UDP sockets.
    pub udp: Vec<std::net::UdpSocket>,
    /// The TCP listeners.
    pub tcp: Vec<std::net::TcpListener>,
}

/// Why [`serve`] did not start. Carries no octet of any message.
/// Spec: docs/50 §7.5 (fail closed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaemonError {
    /// A listener's local address lies outside every internal network (or
    /// cannot be read): nothing was served; auditd and dird were not
    /// contacted. Spec: docs/54 §4.7; A-114.
    ListenerNotInternal,
    /// auditd was not verified (docs/50 R50-16): unreachable, another uid,
    /// or a source other than `dnsd` (its `uid_sources` does not map dnsd —
    /// task DN12); nothing was sent and dird was not contacted.
    Audit(AuditLinkError),
    /// dird's uid is configured as 0 (never a server uid, docs/50 §3.2).
    DirdConfig(ClientConfigError),
    /// dird was not verified or did not serve a valid zone image at start
    /// (docs/54 §4.8: "dird down at start ⇒ dnsd does not come up").
    Dird(Unserved),
    /// A thread could not be spawned, or ended before reporting.
    Thread,
    /// A listener could not be handed to the runtime.
    Listener,
}

impl fmt::Display for DaemonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DaemonError::ListenerNotInternal => {
                f.write_str("a listener is outside every configured internal network")
            }
            DaemonError::Audit(error) => write!(f, "auditd not verified: {error}"),
            DaemonError::DirdConfig(_) => f.write_str("dird's uid cannot be 0"),
            DaemonError::Dird(_) => f.write_str("dird not verified or no valid zone image"),
            DaemonError::Thread => f.write_str("a dird thread could not be started"),
            DaemonError::Listener => f.write_str("listener could not be served"),
        }
    }
}

impl std::error::Error for DaemonError {}

/// What the listener tasks share.
pub(crate) struct Shared {
    zone: ZoneView,
    clock: Arc<dyn Clock>,
    /// The staleness bound in whole seconds (dnsd's monotonic clock).
    max_age: u64,
    internal: Arc<[Network]>,
    pub(crate) udp_limiter: SourceLimiter,
    pub(crate) tcp_limiter: SourceLimiter,
    pub(crate) forward_limiter: SourceLimiter,
    pub(crate) forwards: mpsc::Sender<ForwardJob>,
    pub(crate) forward_answer_timeout: Duration,
    /// Set at shutdown: nothing new is answered.
    pub(crate) draining: AtomicBool,
    /// dnsd's audit gate: the noise counters' way to the audit log.
    audit: Arc<AuditGate>,
}

impl fmt::Debug for Shared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Shared")
            .field("max_age", &self.max_age)
            .finish_non_exhaustive()
    }
}

impl Shared {
    /// Whether dnsd serves `source` (A-114; crate::source).
    pub(crate) fn serves(&self, source: IpAddr) -> bool {
        is_served(&self.internal, source)
    }

    /// Count one peer-driven noise occurrence — the one place it is
    /// counted: the operational log's thinned `counter` and dnsd's audit
    /// window, sent as the next `WindowSummary` (module documentation,
    /// "Noise counters").
    /// Spec: docs/54 §9, R54-11; A-57; docs/questions/Q-961.
    pub(crate) fn noise(&self, counter: &Thinned) {
        counter.hit();
        self.audit.count_noise();
    }

    /// dns-zone's verdict on `request` received over `transport`, from the
    /// current image — or as unavailable, when no image was confirmed within
    /// the bound (docs/54 §4.4: SERVFAIL to every query).
    /// Spec: docs/54 §4.4, §6.4–§6.6; crates/dns-zone `answer`.
    pub(crate) fn verdict<'a>(&self, request: &'a [u8], transport: Transport) -> Verdict<'a> {
        let held = self.zone.current();
        let now = self.clock.now_secs();
        let state = match held.as_deref() {
            Some(held) => held.state(now, self.max_age),
            None => ZoneState::Unavailable,
        };
        let unavailable = matches!(state, ZoneState::Unavailable);
        let verdict = answer(state, request, transport);
        if unavailable && matches!(verdict, Verdict::Reply(_)) {
            ZONE_UNAVAILABLE.hit();
        }
        verdict
    }
}

#[cfg(test)]
pub(crate) mod tests {
    //! In-crate support for the listener tests: a `Shared` serving the RFC
    //! 2782 example zone to 192.0.2.0/24 and fd00:1234::/32 (hand-made).
    use super::*;
    use parse_dns::{Class, Header, Message, Opcode, Question, Rcode, RrType};

    /// A clock that stands still.
    struct Still;

    impl Clock for Still {
        fn now_secs(&self) -> u64 {
            1_000
        }
    }

    /// A `Shared` with a current image, 192.0.2.0/24 internal, `per_source`
    /// UDP and TCP messages per source per hour, and a forwarding queue
    /// nobody reads.
    pub(crate) fn shared_for_test(per_source: u32) -> Arc<Shared> {
        let now = Instant::now();
        let limits = SourceLimits {
            per_source,
            global: 1_000,
            window: Duration::from_secs(3600),
        };
        let (forwards, _jobs) = mpsc::channel(1);
        let v4 = Network::new(IpAddr::V4(core::net::Ipv4Addr::new(192, 0, 2, 0)), 24);
        let v6 = Network::new(
            IpAddr::V6(core::net::Ipv6Addr::new(0xfd00, 0x1234, 0, 0, 0, 0, 0, 0)),
            32,
        );
        Arc::new(Shared {
            zone: zone::current_for_test(zone::tests::image(7), 1_000),
            clock: Arc::new(Still),
            max_age: 60,
            internal: v4.into_iter().chain(v6).collect(),
            udp_limiter: SourceLimiter::new(limits, now),
            tcp_limiter: SourceLimiter::new(limits, now),
            forward_limiter: SourceLimiter::new(limits, now),
            forwards,
            forward_answer_timeout: Duration::from_secs(1),
            draining: AtomicBool::new(false),
            audit: Arc::new(AuditGate::new(AUDIT_WINDOW)),
        })
    }

    /// The noise `shared` counted into its audit window (not yet sent).
    pub(crate) fn counted_noise(shared: &Shared) -> u64 {
        shared.audit.counted_noise().expect("gate")
    }

    /// A QUERY for `server.example.com` A (RFC 1035 §4.1.1, §4.1.2),
    /// encoded by parse-dns.
    pub(crate) fn example_query(id: u16) -> Vec<u8> {
        parse_dns::encode(&Message {
            header: Header {
                id,
                qr: false,
                opcode: Opcode::Query,
                aa: false,
                tc: false,
                rd: false,
                ra: false,
                rcode: Rcode::NOERROR,
            },
            question: Some(Question {
                qname: ipc_dns::Name::from_dotted("server.example.com").expect("name"),
                qtype: RrType::A,
                qclass: Class::IN,
            }),
            answer: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
            tsig: None,
        })
        .expect("encode")
    }
}

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

    /// Wait until a stop was asked for.
    async fn stopped(&self) {
        while !self.state.stopping.load(Ordering::SeqCst) {
            self.state.stop.notified().await;
        }
    }
}

/// The daemon stopped; join its two dird threads after dropping the runtime.
#[derive(Debug)]
pub struct Stopped {
    zone: JoinHandle<()>,
    forward: JoinHandle<()>,
}

impl Stopped {
    /// Wait for the zone and forwarding threads (each ends after its current
    /// dird call, bounded by the channel deadline).
    ///
    /// # Errors
    /// A thread panicked.
    pub fn join(self) -> Result<(), ThreadPanicked> {
        let forward = self.forward.join();
        let zone = self.zone.join();
        match (forward, zone) {
            (Ok(()), Ok(())) => Ok(()),
            _ => Err(ThreadPanicked),
        }
    }
}

/// A dird thread panicked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThreadPanicked;

impl fmt::Display for ThreadPanicked {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a dird thread panicked")
    }
}

impl std::error::Error for ThreadPanicked {}

/// Every UDP socket's and TCP listener's local address lies in an internal
/// network (an unreadable address counts as outside) — the configuration's
/// rule checked again at the one place every listener passes, also one
/// `main` did not bind from the file (tests bind their own).
/// Spec: docs/54 §4.7 ("`serve` refuses a listener whose local address lies
/// outside it"); A-114.
fn check_listeners(listeners: &Listeners, internal: &[Network]) -> Result<(), DaemonError> {
    let udp = listeners.udp.iter().map(std::net::UdpSocket::local_addr);
    let tcp = listeners.tcp.iter().map(std::net::TcpListener::local_addr);
    for local in udp.chain(tcp) {
        match local {
            Ok(address) if is_served(internal, address.ip()) => {}
            _ => return Err(DaemonError::ListenerNotInternal),
        }
    }
    Ok(())
}

/// Run the product dnsd until [`DaemonControl::stop`] (module
/// documentation): the product parameters with the daemon's constants, the
/// monotonic clock, and the production connector to dird's socket
/// (`ipc_dns::UnixConnector`: rustix peer credentials, docs/50 R50-3) — the
/// connector type is fixed here, so no other transport can be supplied; the
/// alternatives exist only in `test_seams` (docs/52 C18, task R15). Must run
/// inside a tokio runtime with I/O and time enabled, built after the process
/// hardening.
///
/// # Errors
/// [`DaemonError`] for a start-up failure (nothing is served then).
///
/// Spec: docs/54 §4.8; docs/50 R50-14, R50-16, §7.5; docs/52 §3.18.
pub async fn serve(
    params: DaemonParams,
    listeners: Listeners,
    control: DaemonControl,
) -> Result<Stopped, DaemonError> {
    let socket = params.dird.socket.clone();
    serve_with(
        ServeParams::from(params),
        listeners,
        UnixConnector::new(socket.clone()),
        UnixConnector::new(socket),
        Arc::new(MonotonicClock::start()),
        control,
    )
    .await
}

/// [`serve`] with every value given: the parameters with their seams, the
/// two connectors (zone thread, forwarding thread) and the clock. Reachable
/// outside this crate only as `test_seams::serve` (docs/52 C18, task R15).
///
/// # Errors
/// [`DaemonError`] for a start-up failure (nothing is served then).
///
/// Spec: docs/54 §4.4, §4.6–§4.8; docs/50 R50-16, §7.5.
pub async fn serve_with<C>(
    params: ServeParams,
    listeners: Listeners,
    zone_connector: C,
    forward_connector: C,
    clock: Arc<dyn Clock>,
    control: DaemonControl,
) -> Result<Stopped, DaemonError>
where
    C: Connector + Send + 'static,
    C::Connection: Send,
{
    // 1. Every listener internal (docs/54 §4.7) — nothing contacted before.
    check_listeners(&listeners, &params.internal_networks)?;

    // 2. auditd first (docs/50 R50-16; docs/54 §4.8): its uid and the
    //    source `dnsd` (task R9b, DN12). The verified connection is kept for
    //    the audit link (step 5); dropped with `link` on a later failure.
    let link = audit::link(&params.audit).map_err(DaemonError::Audit)?;
    let first_audit = link.connect().await.map_err(DaemonError::Audit)?;
    note(Note::AuditVerified, None);

    // 3. dird and the first image, on the zone thread (docs/54 §4.8).
    let expected =
        ExpectedDird::new(params.dird_uid, FrontZone::Internal).map_err(DaemonError::DirdConfig)?;
    let (view, writer) = zone::slot();
    let (refresh, requests) = sync_channel(1);
    let (started_tx, started_rx) = oneshot::channel();
    let zone_thread = zone::spawn(ZoneThread {
        client: DnsClient::new(zone_connector, expected, params.dird_deadline),
        writer,
        clock: Arc::clone(&clock),
        interval: params.refresh_interval,
        requests,
        started: started_tx,
    })
    .map_err(|_| DaemonError::Thread)?;
    let serial = match started_rx.await {
        Ok(Ok(serial)) => serial,
        Ok(Err(unserved)) => {
            let _ = zone_thread.join();
            return Err(DaemonError::Dird(unserved));
        }
        Err(_) => {
            let _ = zone_thread.join();
            return Err(DaemonError::Thread);
        }
    };
    note(Note::ZoneImageFetched, Some(u64::from(serial)));

    // 4. The forwarding thread, verified on its own connection.
    let (forwards, jobs) = mpsc::channel(params.forward_queue_capacity.max(1));
    let (ready_tx, ready_rx) = oneshot::channel();
    let forward_thread = match forward::spawn(ForwardThread {
        client: DnsClient::new(forward_connector, expected, params.dird_deadline),
        jobs,
        zone: view.clone(),
        refresh,
        refresh_wait: params.refresh_wait,
        ready: ready_tx,
    }) {
        Ok(thread) => thread,
        Err(_) => {
            // The refresh sender went into the closure that failed to spawn
            // and is dropped with it: the zone thread ends.
            let _ = zone_thread.join();
            return Err(DaemonError::Thread);
        }
    };
    let failed = match ready_rx.await {
        Ok(Ok(())) => None,
        Ok(Err(unserved)) => Some(DaemonError::Dird(unserved)),
        Err(_) => Some(DaemonError::Thread),
    };
    if let Some(error) = failed {
        drop(forwards);
        let _ = forward_thread.join();
        let _ = zone_thread.join();
        return Err(error);
    }

    // 5. The listeners, served only now — and the audit link, attached to
    //    the connection verified in step 2 (the gate opens on it: task
    //    R15b, docs/questions/Q-630), delivering the noise counters.
    let gate = Arc::new(AuditGate::new(AUDIT_WINDOW));
    let audit_task = tokio::spawn(link.attach(Arc::clone(&gate), first_audit).run());
    let now = Instant::now();
    let shared = Arc::new(Shared {
        zone: view,
        clock,
        max_age: params.zone_image_max_age.as_secs(),
        internal: Arc::from(params.internal_networks),
        udp_limiter: SourceLimiter::new(params.udp, now),
        tcp_limiter: SourceLimiter::new(params.tcp_messages, now),
        forward_limiter: SourceLimiter::new(params.forwards, now),
        forwards,
        forward_answer_timeout: params.forward_answer_timeout,
        draining: AtomicBool::new(false),
        audit: Arc::clone(&gate),
    });
    let tcp_context = Arc::new(TcpContext::new(params.tcp));
    let mut tasks = Vec::new();
    let mut failed = false;
    for socket in listeners.udp {
        match socket
            .set_nonblocking(true)
            .and_then(|()| tokio::net::UdpSocket::from_std(socket))
        {
            Ok(socket) => tasks.push(tokio::spawn(serve_udp(socket, Arc::clone(&shared)))),
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
        for task in tasks {
            let _ = task.await;
        }
        audit_task.abort();
        let _ = audit_task.await;
        drop(shared);
        let _ = forward_thread.join();
        let _ = zone_thread.join();
        return Err(DaemonError::Listener);
    }
    control.state.serving.store(true, Ordering::SeqCst);
    note(Note::Listening, None);

    // 6. Until stopped.
    control.stopped().await;
    note(Note::Draining, None);
    shared.draining.store(true, Ordering::SeqCst);
    for task in &tasks {
        task.abort();
    }
    for task in tasks {
        let _ = task.await;
    }
    control.state.serving.store(false, Ordering::SeqCst);
    // The last holder of the forwarding queue's sender: the forwarding
    // thread ends, and with it the last sender of the zone thread's channel.
    drop(shared);
    // The one flush of every daemon (`ipc_audit_client::AuditGate::close`,
    // docs/52 R6 (b)), then the audit link ends.
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
    note(Note::Stopped, None);
    Ok(Stopped {
        zone: zone_thread,
        forward: forward_thread,
    })
}
