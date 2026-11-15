//! Tier-2 support for dnsd (docs/50 §9: "real servers run in the test's
//! threads; Unix sockets in a unique temporary directory (0700); UDP / TCP
//! on loopback at port 0 — the system picks a port read back with
//! `local_addr`; the uid map is injected with the test's own uid").
//!
//! * **dird** — the real dispatcher of dird's side of the channel
//!   (crates/ipc-dns-server `DnsConnection`, A-152) with a test `ZoneHost`,
//!   reached over an in-process loopback connection (the pattern of
//!   crates/ipc-dns-server tests/dispatch.rs): dnsd's real `DnsClient` talks
//!   the real channel codec to it, its uid check and zone check included.
//!   (ipc-dns's Unix connector reads the peer uid with rustix, Linux only;
//!   the loopback reports a fixed uid, so the tests run everywhere.)
//! * **auditd** — a minimal auditd on a Unix socket answering `Ping` with a
//!   `Pong` naming a source — dnsd's own, `dnsd` (task DN12), unless a test
//!   names another — and every `Append` with the `Ack` of its last number,
//!   keeping the decoded events (the pattern of crates/ipc-audit-client
//!   tests/linked). The real auditd's mapping of the uid to `dnsd` is
//!   tested in tests/product_audit.rs.
//! * **dnsd** — the real `dns_daemon::test_seams::serve` on its own thread
//!   with its own current-thread runtime, a UDP socket and a TCP listener
//!   bound on 127.0.0.1 at ports the system picks (never a privileged port,
//!   never port 53).
//! * **clients** — UDP (one datagram per message) and TCP (a two-octet
//!   length before each message), written from RFC 1035 §4.2.1 / §4.2.2;
//!   the requests encoded and the replies decoded by parse-dns.
//!
//! Sources of the values: the zone of RFC 2782's "Fictional example"
//! (`example.com`, SOA `server.example.com. root.example.com. ( 1995032001
//! 3600 3600 604800 86400 )`, hosts `server` 172.30.79.10, `old-slow-box`
//! 172.30.79.11, `sysadmins-box` 172.30.79.12, `new-fast-box` 172.30.79.13)
//! and the addresses of RFC 1034 §3.7.1. Uids, IDs and TTLs are hand-made.
//! No octet comes from any other implementation or capture.
#![allow(dead_code)] // each test binary uses a different subset

use config::Network;
use core::net::{IpAddr, Ipv4Addr, SocketAddr};
use core::time::Duration;
use dns_daemon::audit::AUDIT_SOURCE;
use dns_daemon::clock::Clock;
use dns_daemon::test_seams::{serve, DaemonParams};
use dns_daemon::{DaemonControl, DaemonError, Listeners, TcpLimits};
use ipc::{Direction, FrameReader, Reply};
use ipc_audit::{
    decode_event, decode_request as audit_decode_request, encode_reply as audit_encode_reply, Ack,
    AuditReply, AuditRequest, EventBody, EventSource, WindowSummary, AUDIT_CHANNEL,
};
use ipc_audit_client::AuditEndpoint;
use ipc_dns::{
    Connection, Connector, DnsMessage, ForwardRequest, Forwarded, FrontZone, HostRecordParts,
    ImageTransfer, KpasswdService, Name, Serial, SoaParameters, TransportError, ZoneImageParts,
};
use ipc_dns_server::{DnsConnection, ImageAnswer, Unserved, ZoneHost};
use parse_dns::{
    decode, Class, Header, Message, Opcode, Profile, Question, Rcode, RrType, Transport, TsigError,
    TsigMac, TsigRecord, TsigTime,
};
use rate_limit::SourceLimits;
use std::collections::VecDeque;
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Instant;
use zeroize::Zeroizing;

/// dird's uid as the loopback reports it (hand-made).
pub const DIRD_UID: u32 = 61_002;

/// RFC 2782 "Fictional example": SERIAL.
pub const SERIAL: u32 = 1_995_032_001;

/// The zone's apex. Spec: RFC 2782 "Fictional example".
pub const APEX: &str = "example.com";

// ---- scratch, uid ----------------------------------------------------------

static NEXT_DIR: AtomicUsize = AtomicUsize::new(0);

/// A unique temporary directory (0700), removed on drop (docs/50 §9).
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new() -> TempDir {
        let n = NEXT_DIR.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!("dnsd{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .expect("temp dir");
        TempDir(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The test's own uid (the owner of a directory it made).
pub fn my_uid(dir: &TempDir) -> u32 {
    std::fs::metadata(dir.path()).expect("metadata").uid()
}

/// Tier 2 needs a non-root uid: uid 0 is never a server uid (docs/50 R50-3;
/// `ExpectedAuditd` / `ExpectedDird` refuse it).
pub fn skip_as_root(uid: u32) -> bool {
    if uid == 0 {
        eprintln!("skipped: running as root (docs/50 R50-3: uid 0 is never mapped)");
        true
    } else {
        false
    }
}

/// Poll `done` until it holds or `wait` passed.
pub fn eventually(wait: Duration, done: impl Fn() -> bool) -> bool {
    let start = Instant::now();
    while start.elapsed() < wait {
        if done() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    done()
}

// ---- the zone ----------------------------------------------------------------

pub fn name(dotted: &str) -> Name {
    Name::from_dotted(dotted).expect("name")
}

pub fn host(label: &str, addresses: &[[u8; 4]]) -> HostRecordParts {
    HostRecordParts {
        label: label.as_bytes().to_vec(),
        addresses: addresses.iter().map(|a| Ipv4Addr::from(*a)).collect(),
        ttl: 3600,
    }
}

/// The RFC 2782 example zone (DC `server`) with SERIAL `serial`, plus the
/// hosts in `extra`.
pub fn parts(serial: u32, extra: &[HostRecordParts]) -> ZoneImageParts {
    let mut hosts = vec![
        host("old-slow-box", &[[172, 30, 79, 11]]),
        host("sysadmins-box", &[[172, 30, 79, 12]]),
        host("new-fast-box", &[[172, 30, 79, 13]]),
    ];
    hosts.extend_from_slice(extra);
    ZoneImageParts {
        apex: name(APEX),
        serial,
        soa: SoaParameters {
            rname: name("root.example.com"),
            refresh: 3600,
            retry: 3600,
            expire: 604_800,
            minimum: 86_400,
        },
        infrastructure_ttl: 3600,
        dc: host("server", &[[172, 30, 79, 10]]),
        hosts,
        kpasswd: KpasswdService::Absent,
    }
}

pub fn transfer(parts: &ZoneImageParts) -> ImageTransfer {
    ImageTransfer::new(parts).expect("valid image")
}

pub fn serial(value: u32) -> Serial {
    Serial::new(value).expect("non-zero")
}

// ---- the fake dird -------------------------------------------------------------

/// What the test dird answers, and what it was asked.
pub struct HostState {
    /// The image `FetchZoneImage` serves.
    pub image: ImageTransfer,
    /// `FetchZoneImage` refused (`Unavailable`) while set.
    pub refuse_images: bool,
    /// The answer to `Forward`.
    pub forward_answer: Result<Forwarded, Unserved>,
    /// Once a forward was answered, serve this image (the update committed —
    /// RFC 2136 §3.5).
    pub image_after_forward: Option<ImageTransfer>,
    /// The `have` of every `FetchZoneImage`.
    pub fetches: Vec<Option<Serial>>,
    /// Every forwarded request, with the zone of its connection.
    pub forwards: Vec<(FrontZone, ForwardRequest)>,
    /// Blocks the first `FetchZoneImage` until a value arrives.
    pub gate: Option<std::sync::mpsc::Receiver<()>>,
    /// Blocks the first `Forward` until a value arrives.
    pub forward_gate: Option<std::sync::mpsc::Receiver<()>>,
}

/// The test dird's `ZoneHost`, shared by every loopback connection.
#[derive(Clone)]
pub struct TestDird(pub Arc<Mutex<HostState>>);

impl TestDird {
    pub fn new(image: ImageTransfer) -> TestDird {
        TestDird(Arc::new(Mutex::new(HostState {
            image,
            refuse_images: false,
            forward_answer: Err(Unserved::Unavailable),
            image_after_forward: None,
            fetches: Vec::new(),
            forwards: Vec::new(),
            gate: None,
            forward_gate: None,
        })))
    }

    pub fn state(&self) -> std::sync::MutexGuard<'_, HostState> {
        self.0.lock().expect("host state")
    }
}

impl ZoneHost for TestDird {
    fn zone_image(&mut self, have: Option<Serial>) -> Result<ImageAnswer, Unserved> {
        let gate = self.state().gate.take();
        if let Some(gate) = gate {
            let _ = gate.recv();
        }
        let mut state = self.state();
        state.fetches.push(have);
        if state.refuse_images {
            return Err(Unserved::Unavailable);
        }
        if have == Some(state.image.serial()) {
            Ok(ImageAnswer::Unchanged(state.image.serial()))
        } else {
            Ok(ImageAnswer::Image(state.image.clone()))
        }
    }

    fn forward(
        &mut self,
        zone: FrontZone,
        request: &ForwardRequest,
    ) -> Result<Forwarded, Unserved> {
        let gate = self.state().forward_gate.take();
        if let Some(gate) = gate {
            let _ = gate.recv();
        }
        let mut state = self.state();
        state.forwards.push((zone, request.clone()));
        if let Some(image) = state.image_after_forward.take() {
            state.image = image;
        }
        state.forward_answer.clone()
    }
}

/// An in-process connection whose far end is dird's real dispatcher.
pub struct Loopback {
    uid: u32,
    connection: DnsConnection,
    host: TestDird,
    pending: VecDeque<Vec<u8>>,
}

impl Connection for Loopback {
    fn peer_uid(&self) -> Result<u32, TransportError> {
        Ok(self.uid)
    }

    fn send(&mut self, frame: &[u8], _deadline: Duration) -> Result<(), TransportError> {
        if self.connection.is_closed() {
            return Err(TransportError::Closed);
        }
        let body = frame.get(4..).ok_or(TransportError::Framing)?;
        let mut host = self.host.clone();
        let dispatch = self.connection.handle(body, &mut host);
        self.pending
            .extend(dispatch.frames().iter().map(|frame| frame.body().to_vec()));
        Ok(())
    }

    fn receive(
        &mut self,
        limit: ipc::FrameLimit,
        _deadline: Duration,
    ) -> Result<Zeroizing<Vec<u8>>, TransportError> {
        let body = self.pending.pop_front().ok_or(TransportError::Closed)?;
        if body.len() > limit.max_body() as usize {
            return Err(TransportError::Framing);
        }
        Ok(Zeroizing::new(body))
    }

    fn check_idle(&mut self) -> Result<(), TransportError> {
        if self.connection.is_closed() || !self.pending.is_empty() {
            Err(TransportError::Closed)
        } else {
            Ok(())
        }
    }
}

/// Opens loopback connections to the test dird: reports `uid` as the peer's,
/// and refuses to connect while `down` is set.
#[derive(Clone)]
pub struct LoopbackConnector {
    pub host: TestDird,
    pub uid: u32,
    pub down: Arc<AtomicBool>,
    next: Arc<AtomicU64>,
}

impl LoopbackConnector {
    pub fn new(host: &TestDird) -> LoopbackConnector {
        LoopbackConnector {
            host: host.clone(),
            uid: DIRD_UID,
            down: Arc::new(AtomicBool::new(false)),
            next: Arc::new(AtomicU64::new(0)),
        }
    }
}

impl Connector for LoopbackConnector {
    type Connection = Loopback;

    fn connect(&mut self) -> Result<Loopback, TransportError> {
        if self.down.load(Ordering::SeqCst) {
            return Err(TransportError::Connect);
        }
        let id = self.next.fetch_add(1, Ordering::SeqCst);
        Ok(Loopback {
            uid: self.uid,
            connection: DnsConnection::new(id, FrontZone::Internal),
            host: self.host.clone(),
            pending: VecDeque::new(),
        })
    }
}

// ---- the fake auditd ------------------------------------------------------------

/// What the fake auditd saw: the `Ping`s answered and the events appended.
#[derive(Default)]
struct AuditSeen {
    pings: AtomicUsize,
    events: Mutex<Vec<EventBody>>,
}

/// A minimal auditd whose `Pong` names `source` and which acknowledges
/// every `Append` (the pattern of crates/ipc-audit-client tests/linked).
pub struct FakeAuditd {
    path: PathBuf,
    stop: Arc<AtomicBool>,
    seen: Arc<AuditSeen>,
    thread: Option<JoinHandle<()>>,
}

impl FakeAuditd {
    pub fn start(path: &Path, source: EventSource) -> FakeAuditd {
        let _ = std::fs::remove_file(path);
        let listener = UnixListener::bind(path).expect("audit socket");
        listener.set_nonblocking(true).expect("nonblocking");
        let stop = Arc::new(AtomicBool::new(false));
        let seen = Arc::new(AuditSeen::default());
        let thread = {
            let (stop, seen) = (Arc::clone(&stop), Arc::clone(&seen));
            std::thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            stream.set_nonblocking(false).expect("blocking");
                            let seen = Arc::clone(&seen);
                            std::thread::spawn(move || audit_serve(stream, source, &seen));
                        }
                        Err(e) if e.kind() == ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(2));
                        }
                        Err(_) => return,
                    }
                }
            })
        };
        FakeAuditd {
            path: path.to_path_buf(),
            stop,
            seen,
            thread: Some(thread),
        }
    }

    pub fn pings(&self) -> usize {
        self.seen.pings.load(Ordering::SeqCst)
    }

    /// Every event appended so far, in order.
    pub fn events(&self) -> Vec<EventBody> {
        self.seen.events.lock().expect("events").clone()
    }

    /// The `WindowSummary` events appended so far.
    pub fn summaries(&self) -> Vec<WindowSummary> {
        self.events()
            .into_iter()
            .filter_map(|event| match event {
                EventBody::WindowSummary(summary) => Some(summary),
                _ => None,
            })
            .collect()
    }

    /// The noise counted in every summary so far.
    pub fn counted_noise(&self) -> u64 {
        self.summaries().iter().map(|s| s.suppressed_noise).sum()
    }
}

impl Drop for FakeAuditd {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

/// `Ping` → `Pong(source)`; `Append` → its events kept, `Ack` of its last
/// number; anything else closes. Spec: docs/50 §7.5, §8.1.
fn audit_serve(mut stream: UnixStream, source: EventSource, seen: &AuditSeen) {
    loop {
        let mut reader = FrameReader::new(AUDIT_CHANNEL.limit(Direction::Request));
        let mut chunk = [0u8; 1024];
        let body = loop {
            if let Some(body) = reader.body() {
                break body.to_vec();
            }
            let wanted = reader.wanted().min(chunk.len());
            match stream.read(&mut chunk[..wanted]) {
                Ok(0) | Err(_) => return,
                Ok(read) => {
                    if reader.push(&chunk[..read]).is_err() {
                        return;
                    }
                }
            }
        };
        let reply = match audit_decode_request(&body) {
            Ok(AuditRequest::Ping) => {
                seen.pings.fetch_add(1, Ordering::SeqCst);
                AuditReply::Pong(source)
            }
            Ok(AuditRequest::Append(append)) => {
                let mut events = seen.events.lock().expect("events");
                for event in append.events() {
                    events.push(decode_event(event.as_bytes()).expect("a valid event"));
                }
                AuditReply::Ack(Ack {
                    through_seq: append.last_seq(),
                    head_hash: [0; 32],
                })
            }
            Err(_) => return,
        };
        let frame = audit_encode_reply(&Reply::Message(reply)).expect("reply");
        if stream.write_all(frame.as_bytes()).is_err() {
            return;
        }
    }
}

// ---- the clock --------------------------------------------------------------------

/// dnsd's staleness clock, set by the test.
#[derive(Debug, Default)]
pub struct TestClock(AtomicU64);

impl TestClock {
    pub fn at(secs: u64) -> Arc<TestClock> {
        Arc::new(TestClock(AtomicU64::new(secs)))
    }

    pub fn advance(&self, secs: u64) {
        self.0.fetch_add(secs, Ordering::SeqCst);
    }
}

impl Clock for TestClock {
    fn now_secs(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

// ---- dnsd ---------------------------------------------------------------------------

/// Limits wide enough never to bite unless a test narrows them.
pub const WIDE: SourceLimits = SourceLimits {
    per_source: 10_000,
    global: 100_000,
    window: Duration::from_secs(1),
};

/// dnsd's parameters for a test: the fake auditd at `audit`, loopback as the
/// internal network, short timings, wide limits. (The audit source is not a
/// parameter: dnsd always expects `dnsd` — task DN12.)
pub fn params(audit: &Path, auditd_uid: u32) -> DaemonParams {
    DaemonParams {
        dird_uid: DIRD_UID,
        dird_deadline: Duration::from_secs(2),
        audit: AuditEndpoint {
            socket: audit.to_path_buf(),
            uid: auditd_uid,
        },
        internal_networks: vec![loopback_network()],
        tcp: TcpLimits {
            max_connections: 32,
            max_per_source: 8,
            first_octet_timeout: Duration::from_secs(2),
            frame_timeout: Duration::from_secs(2),
            idle_timeout: Duration::from_secs(5),
            max_requests: 64,
        },
        zone_image_max_age: Duration::from_secs(60),
        udp: WIDE,
        tcp_messages: WIDE,
        forwards: WIDE,
        forward_queue_capacity: 4,
        forward_answer_timeout: Duration::from_secs(5),
        refresh_interval: Duration::from_millis(50),
        refresh_wait: Duration::from_secs(2),
    }
}

/// 127.0.0.0/8 — the tests' listeners and clients are on loopback (docs/50
/// §9), so it is their internal network (A-114: a network of the zone
/// table).
pub fn loopback_network() -> Network {
    Network::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)), 8).expect("network")
}

/// A running dnsd (module documentation).
pub struct Dnsd {
    pub udp: SocketAddr,
    pub tcp: SocketAddr,
    pub control: DaemonControl,
    thread: Option<JoinHandle<Result<(), DaemonError>>>,
}

impl Dnsd {
    /// Bind 127.0.0.1:0 for UDP and TCP and run dnsd on its own thread.
    pub fn start(
        params: DaemonParams,
        connector: &LoopbackConnector,
        clock: Arc<dyn Clock>,
    ) -> Dnsd {
        let udp = UdpSocket::bind("127.0.0.1:0").expect("udp");
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").expect("tcp");
        let addresses = (
            udp.local_addr().expect("udp"),
            tcp.local_addr().expect("tcp"),
        );
        Dnsd::start_with(
            params,
            Listeners {
                udp: vec![udp],
                tcp: vec![tcp],
            },
            addresses,
            connector,
            clock,
        )
    }

    /// Run dnsd over the given listeners.
    pub fn start_with(
        params: DaemonParams,
        listeners: Listeners,
        (udp, tcp): (SocketAddr, SocketAddr),
        connector: &LoopbackConnector,
        clock: Arc<dyn Clock>,
    ) -> Dnsd {
        let control = DaemonControl::new();
        let thread = {
            let control = control.clone();
            let connector = connector.clone();
            std::thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("runtime");
                let result = runtime.block_on(serve(
                    params,
                    listeners,
                    connector.clone(),
                    connector,
                    clock,
                    control,
                ));
                drop(runtime);
                match result {
                    Ok(stopped) => {
                        stopped.join().expect("threads joined");
                        Ok(())
                    }
                    Err(error) => Err(error),
                }
            })
        };
        Dnsd {
            udp,
            tcp,
            control,
            thread: Some(thread),
        }
    }

    /// Wait until dnsd serves.
    pub fn serving(&self) -> bool {
        eventually(Duration::from_secs(10), || self.control.is_serving())
    }

    /// Stop, and return how `serve` ended.
    pub fn stop(mut self) -> Result<(), DaemonError> {
        self.control.stop();
        self.join()
    }

    /// Wait for `serve` to end (a failed start ends on its own).
    pub fn join(&mut self) -> Result<(), DaemonError> {
        self.thread
            .take()
            .expect("running")
            .join()
            .expect("dnsd thread")
    }
}

impl Drop for Dnsd {
    fn drop(&mut self) {
        if let Some(thread) = self.thread.take() {
            self.control.stop();
            let _ = thread.join();
        }
    }
}

/// Everything a test needs: a temp dir, auditd, the test dird, a clock, and
/// a dnsd started with `adjust`ed parameters. `None` when running as root.
pub struct World {
    pub dir: TempDir,
    pub auditd: FakeAuditd,
    pub dird: TestDird,
    pub connector: LoopbackConnector,
    pub clock: Arc<TestClock>,
    pub uid: u32,
}

impl World {
    pub fn new(image: ImageTransfer) -> Option<World> {
        let dir = TempDir::new();
        let uid = my_uid(&dir);
        if skip_as_root(uid) {
            return None;
        }
        let auditd = FakeAuditd::start(&dir.path().join("audit.sock"), AUDIT_SOURCE);
        let dird = TestDird::new(image);
        let connector = LoopbackConnector::new(&dird);
        Some(World {
            dir,
            auditd,
            dird,
            connector,
            clock: TestClock::at(1_000),
            uid,
        })
    }

    pub fn params(&self) -> DaemonParams {
        params(&self.dir.path().join("audit.sock"), self.uid)
    }

    pub fn start(&self, params: DaemonParams) -> Dnsd {
        let clock: Arc<dyn Clock> = self.clock.clone();
        Dnsd::start(params, &self.connector, clock)
    }
}

// ---- requests and replies ------------------------------------------------------------

/// A QUERY request header. Spec: RFC 1035 §4.1.1.
pub fn query_header(id: u16) -> Header {
    Header {
        id,
        qr: false,
        opcode: Opcode::Query,
        aa: false,
        tc: false,
        rd: true,
        ra: false,
        rcode: Rcode::NOERROR,
    }
}

/// A one-question QUERY of class IN, encoded by parse-dns.
/// Spec: RFC 1035 §4.1.1, §4.1.2.
pub fn query(id: u16, qname: &str, qtype: RrType) -> Vec<u8> {
    parse_dns::encode(&Message {
        header: query_header(id),
        question: Some(Question {
            qname: name(qname),
            qtype,
            qclass: Class::IN,
        }),
        answer: Vec::new(),
        authority: Vec::new(),
        additional: Vec::new(),
        tsig: None,
    })
    .expect("encode")
}

/// A request TSIG RR. Spec: RFC 8945 §4.2 (Error zero in requests; Original
/// ID equal to the message ID).
pub fn request_tsig(key: &str, algorithm: &str, id: u16) -> TsigRecord {
    TsigRecord {
        key_name: name(key),
        algorithm_name: name(algorithm),
        time_signed: TsigTime::new(1_700_000_000).expect("48-bit"),
        fudge: 300,
        mac: TsigMac::new(vec![0x5A; 28]).expect("mac"),
        original_id: id,
        error: TsigError::NOERROR,
        other_data: Vec::new(),
    }
}

/// An UPDATE request (zone section only), optionally signed.
/// Spec: RFC 2136 §2.2, §2.3 (ZTYPE SOA, ZCLASS IN).
pub fn update(id: u16, tsig: Option<TsigRecord>) -> Vec<u8> {
    parse_dns::encode(&Message {
        header: Header {
            id,
            qr: false,
            opcode: Opcode::Update,
            aa: false,
            tc: false,
            rd: false,
            ra: false,
            rcode: Rcode::NOERROR,
        },
        question: Some(Question {
            qname: name(APEX),
            qtype: RrType::SOA,
            qclass: Class::IN,
        }),
        answer: Vec::new(),
        authority: Vec::new(),
        additional: Vec::new(),
        tsig,
    })
    .expect("encode")
}

/// A signed UPDATE: a `gss-tsig` TSIG (RFC 3645 §5.1 via parse-dns's
/// `GSS_TSIG_ALGORITHM`), which dns-zone forwards (docs/54 §4.5 step 1).
pub fn signed_update(id: u16) -> Vec<u8> {
    update(
        id,
        Some(request_tsig(
            "key.example.com",
            parse_dns::GSS_TSIG_ALGORITHM,
            id,
        )),
    )
}

/// A hand-made UPDATE reply as dird would build it: ID and opcode copied,
/// QR = 1, zero counts (RFC 2136 §3.8).
pub fn update_reply(id: u16, rcode: u8) -> DnsMessage {
    let flags: u16 = 0x8000 | (5 << 11) | u16::from(rcode);
    let mut octets = Vec::new();
    for word in [id, flags, 0, 0, 0, 0] {
        octets.extend_from_slice(&word.to_be_bytes());
    }
    DnsMessage::new(&octets).expect("message")
}

/// Decode a reply. Spec: RFC 1035 §4.1 (parse-dns `Response` profile).
pub fn reply(octets: &[u8], transport: Transport) -> Message {
    decode(octets, Profile::Response(transport))
        .expect("reply decodes")
        .into_message()
}

// ---- clients -------------------------------------------------------------------------

/// A UDP client socket on 127.0.0.1.
pub fn udp_client() -> UdpSocket {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("udp client");
    socket
        .set_read_timeout(Some(Duration::from_millis(400)))
        .expect("timeout");
    socket
}

/// Send one datagram and wait for one reply (RFC 1035 §4.2.1).
pub fn udp_exchange(client: &UdpSocket, server: SocketAddr, request: &[u8]) -> Option<Vec<u8>> {
    client.send_to(request, server).expect("send");
    let mut buffer = [0u8; 2048];
    match client.recv_from(&mut buffer) {
        Ok((length, from)) if from == server => Some(buffer[..length].to_vec()),
        _ => None,
    }
}

/// Connect to dnsd's TCP listener.
pub fn tcp_connect(server: SocketAddr) -> TcpStream {
    let stream = TcpStream::connect(server).expect("tcp connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    stream
}

/// Write one message with its two-octet length (RFC 1035 §4.2.2).
pub fn tcp_write(stream: &mut TcpStream, message: &[u8]) {
    let length = u16::try_from(message.len()).expect("fits");
    let mut framed = length.to_be_bytes().to_vec();
    framed.extend_from_slice(message);
    stream.write_all(&framed).expect("write");
}

/// Read one length-prefixed message; `None` if the connection closed or
/// nothing came in time.
pub fn tcp_read(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut length = [0u8; 2];
    stream.read_exact(&mut length).ok()?;
    let mut message = vec![0u8; usize::from(u16::from_be_bytes(length))];
    stream.read_exact(&mut message).ok()?;
    Some(message)
}

/// One request, one reply, on a fresh connection.
pub fn tcp_exchange(server: SocketAddr, request: &[u8]) -> Option<Vec<u8>> {
    let mut stream = tcp_connect(server);
    tcp_write(&mut stream, request);
    tcp_read(&mut stream)
}

/// Whether the server closed `stream` (end of stream or reset) within
/// `wait`, without sending anything first.
pub fn closed_without_reply(stream: &mut TcpStream, wait: Duration) -> bool {
    stream.set_read_timeout(Some(wait)).expect("timeout");
    let mut octet = [0u8; 1];
    match stream.read(&mut octet) {
        Ok(0) => true,
        Ok(_) => false,
        Err(e) => matches!(
            e.kind(),
            ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted | ErrorKind::BrokenPipe
        ),
    }
}
