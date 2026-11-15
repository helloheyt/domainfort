//! The front's test world: a test dird (this repository's dispatcher,
//! crates/ipc-kpasswd `KpasswdConnection`, over a host that records every
//! request and answers as the test scripts), a test auditd (the real audit
//! channel's `Ping` → `Pong`, naming the front's own source `kpasswd-front`
//! unless a test names another, and `Append` → the `Ack` of its last number,
//! its events kept with their arrival time — docs/50 §7.5, §8.1; the pattern
//! of crates/ipc-audit-client tests/linked and crates/dns-daemon
//! tests/common), and the front itself — the product entry,
//! `serve` (task DN12: the audit source is a constant, so the tests need no
//! other entry — docs/52 C18) — on a loopback listener of a port the system
//! picks (never port 464).
//!
//! The test dird and auditd run in this process, so their uid is the test's
//! own; as root the tests skip (uid 0 is never mapped — docs/50 R50-3).
//! Socket paths are in the system's temporary directory (the socket-path
//! length limit, crates/test-scratch). Requests are built by hand from RFC
//! 3244 §2's layout (parse-kpasswd's `RequestMessage::new` or raw octets);
//! the Kerberos messages are opaque octets with the identifier octet of
//! their `[APPLICATION n]` tag (RFC 4120 §5.10; X.690 8.1.2.2) — RFC 3244
//! and RFC 4120 have no examples, and no vector comes from another
//! implementation.

#![allow(dead_code)]
#![cfg(unix)]

use crate::audit::FRONT_AUDIT_SOURCE;
use crate::{
    serve, ConnectionLimits, DaemonControl, DaemonError, Endpoint, FrontParams, Listeners, Timeouts,
};
use config::Network;
use core::net::{IpAddr, Ipv4Addr, SocketAddr};
use core::time::Duration;
use ipc::{FrameReader, Reply};
use ipc_audit::{
    Ack, AuditReply, AuditRequest, EventBody, EventSource, WindowSummary, AUDIT_CHANNEL,
};
use ipc_kpasswd::{
    ApRepOctets, ChangePasswordRequest, FrontZone, HostUnserved, KpasswdAnswer, KpasswdConnection,
    KpasswdHost, KrbPrivOctets, SealedReply, REQUEST_LIMIT,
};
use krb_proto::KrbError;
use parse_kpasswd::{ReplyBody, ReplyMessage, RequestMessage};
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Instant;

/// The realm of the tests (obviously fake test data).
pub const REALM: &str = "EXAMPLE.TEST";
/// How long a test waits for anything.
pub const LONG: Duration = Duration::from_secs(10);
/// The front's first-frame timeout in the tests (the configuration admits
/// 1 s ..= 10 s).
pub const FIRST_FRAME: Duration = Duration::from_secs(1);

/// `[APPLICATION 14]` (AP-REQ). Source: RFC 4120 §5.10; X.690 8.1.2.2.
pub const AP_REQ: u8 = 0x6E;
/// `[APPLICATION 15]` (AP-REP). Source: RFC 4120 §5.10; X.690 8.1.2.2.
pub const AP_REP: u8 = 0x6F;
/// `[APPLICATION 21]` (KRB-PRIV). Source: RFC 4120 §5.10; X.690 8.1.2.2.
pub const KRB_PRIV: u8 = 0x75;
/// `[APPLICATION 28]` (EncKrbPrivPart). Source: RFC 4120 §5.10.
pub const ENC_KRB_PRIV_PART: u8 = 0x7C;

/// `len` octets starting with `identifier`, then `fill`.
pub fn octets(identifier: u8, len: usize, fill: u8) -> Vec<u8> {
    let mut out = vec![fill; len];
    out[0] = identifier;
    out
}

/// A well-formed RFC 3244 request (version 0xff80), TCP-framed.
/// Source: RFC 3244 §2 (request message, TCP header).
pub fn request_frame(ap_req: &[u8], krb_priv: &[u8]) -> Vec<u8> {
    RequestMessage::new(ap_req, krb_priv)
        .expect("a valid request")
        .encode_tcp()
}

/// An RFC 3244-shaped request with any `version`, TCP-framed, built octet
/// by octet. Source: RFC 3244 §2 ("All 16 bit fields are in big-endian
/// order"; message length includes itself).
pub fn request_with_version(version: u16, ap_req: &[u8], krb_priv: &[u8]) -> Vec<u8> {
    let total = 6 + ap_req.len() + krb_priv.len();
    let mut out = (total as u32).to_be_bytes().to_vec();
    out.extend_from_slice(&(total as u16).to_be_bytes());
    out.extend_from_slice(&version.to_be_bytes());
    out.extend_from_slice(&(ap_req.len() as u16).to_be_bytes());
    out.extend_from_slice(ap_req);
    out.extend_from_slice(krb_priv);
    out
}

/// keyd's sealed reply as the test dird returns it.
pub fn sealed() -> SealedReply {
    SealedReply::new(
        ApRepOctets::new(&octets(AP_REP, 33, 0x5A)).unwrap(),
        KrbPrivOctets::new(&octets(KRB_PRIV, 21, 0x6B)).unwrap(),
    )
    .unwrap()
}

/// A unique socket path in the temporary directory.
pub(crate) fn socket_path(tag: &str) -> PathBuf {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("kpf-{tag}-{}-{n}.sock", std::process::id()))
}

/// The test's own uid, or `None` as root (docs/50 R50-3).
pub fn own_uid() -> Option<u32> {
    let path = socket_path("uid").with_extension("probe");
    std::fs::write(&path, b"").ok()?;
    let uid = std::fs::metadata(&path).ok()?.uid();
    let _ = std::fs::remove_file(&path);
    if uid == 0 {
        eprintln!("skipped: running as root (docs/50 R50-3: uid 0 is never mapped)");
        None
    } else {
        Some(uid)
    }
}

/// Read one frame body from a blocking Unix stream, or `None` at the end.
fn read_frame(stream: &mut UnixStream, limit: ipc::FrameLimit) -> Option<Vec<u8>> {
    let mut reader = FrameReader::new(limit);
    let mut chunk = vec![0u8; 4096];
    loop {
        if let Some(body) = reader.body() {
            return Some(body.to_vec());
        }
        let wanted = reader.wanted().min(chunk.len());
        let read = stream.read(&mut chunk[..wanted]).ok()?;
        if read == 0 {
            return None;
        }
        reader.push(&chunk[..read]).ok()?;
    }
}

/// What the test dird answers and what it was asked.
#[derive(Clone)]
pub struct Dird {
    pub answer: Arc<Mutex<Result<KpasswdAnswer, HostUnserved>>>,
    pub requests: Arc<Mutex<Vec<ChangePasswordRequest>>>,
    pub connections: Arc<AtomicU32>,
}

struct Host(Dird);

impl KpasswdHost for Host {
    fn change_password(
        &mut self,
        zone: FrontZone,
        request: &ChangePasswordRequest,
    ) -> Result<KpasswdAnswer, HostUnserved> {
        assert_eq!(zone, FrontZone::Internal);
        self.0.requests.lock().unwrap().push(request.clone());
        self.0.answer.lock().unwrap().clone()
    }
}

/// Start the test dird on `path` (crates/ipc-kpasswd's dispatcher).
fn start_dird(path: &PathBuf) -> Dird {
    let dird = Dird {
        answer: Arc::new(Mutex::new(Ok(KpasswdAnswer::Sealed(sealed())))),
        requests: Arc::new(Mutex::new(Vec::new())),
        connections: Arc::new(AtomicU32::new(0)),
    };
    let listener = UnixListener::bind(path).unwrap();
    let shared = dird.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            shared.connections.fetch_add(1, Ordering::SeqCst);
            let host_dird = shared.clone();
            std::thread::spawn(move || {
                let mut connection = KpasswdConnection::new(1, FrontZone::Internal);
                let mut host = Host(host_dird);
                while let Some(body) = read_frame(&mut stream, REQUEST_LIMIT) {
                    let dispatch = connection.handle(&body, &mut host);
                    if let Some(frame) = dispatch.frame() {
                        let _ = stream.write_all(frame.as_bytes());
                    }
                    if dispatch.closes() {
                        return;
                    }
                }
            });
        }
    });
    dird
}

/// What the test auditd was sent: every appended event, with the instant
/// its batch arrived.
#[derive(Clone, Default)]
pub struct AuditSeen {
    events: Arc<Mutex<Vec<(Instant, EventBody)>>>,
}

impl AuditSeen {
    /// Every event appended so far, in order.
    pub fn events(&self) -> Vec<EventBody> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .map(|(_, event)| event.clone())
            .collect()
    }

    /// The `WindowSummary` events appended so far, with their arrival.
    pub fn summaries(&self) -> Vec<(Instant, WindowSummary)> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter_map(|(at, event)| match event {
                EventBody::WindowSummary(summary) => Some((*at, *summary)),
                _ => None,
            })
            .collect()
    }

    /// The noise counted in every summary so far.
    pub fn counted_noise(&self) -> u64 {
        self.summaries()
            .iter()
            .map(|(_, summary)| summary.suppressed_noise)
            .sum()
    }
}

/// How a test auditd behaves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuditdBehaviour {
    /// Answer every `Ping`; acknowledge every `Append` after this delay (an
    /// auditd's persistence before its `Ack`, docs/50 §8.1).
    Acknowledge(Duration),
    /// Answer the first connection's first `Ping` (the start-up check), then
    /// close it, and close every later connection at once: auditd lost
    /// while the front serves.
    LostAfterStart,
}

/// Start a test auditd on `path` that names `source` in its `Pong` and
/// acknowledges every `Append` at once (its events kept); anything else
/// closes.
/// Spec: docs/50 §7.5, §8.1.
pub(crate) fn start_auditd(path: &PathBuf, source: EventSource) -> AuditSeen {
    start_auditd_with(path, source, AuditdBehaviour::Acknowledge(Duration::ZERO))
}

/// [`start_auditd`] with a chosen [`AuditdBehaviour`].
/// Spec: docs/50 §7.5, §8.1.
pub(crate) fn start_auditd_with(
    path: &PathBuf,
    source: EventSource,
    behaviour: AuditdBehaviour,
) -> AuditSeen {
    let listener = UnixListener::bind(path).unwrap();
    let seen = AuditSeen::default();
    let shared = seen.clone();
    std::thread::spawn(move || {
        let mut first = true;
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let ack_delay = match behaviour {
                AuditdBehaviour::Acknowledge(delay) => delay,
                AuditdBehaviour::LostAfterStart if first => Duration::ZERO,
                AuditdBehaviour::LostAfterStart => continue,
            };
            let only_one_ping = behaviour == AuditdBehaviour::LostAfterStart;
            first = false;
            let seen = shared.clone();
            std::thread::spawn(move || {
                let limit = AUDIT_CHANNEL.limit(ipc::Direction::Request);
                while let Some(body) = read_frame(&mut stream, limit) {
                    let reply = match ipc_audit::decode_request(&body) {
                        Ok(AuditRequest::Ping) => AuditReply::Pong(source),
                        Ok(AuditRequest::Append(append)) => {
                            std::thread::sleep(ack_delay);
                            let at = Instant::now();
                            let mut events = seen.events.lock().unwrap();
                            for event in append.events() {
                                let event = ipc_audit::decode_event(event.as_bytes())
                                    .expect("a valid event");
                                events.push((at, event));
                            }
                            AuditReply::Ack(Ack {
                                through_seq: append.last_seq(),
                                head_hash: [0; 32],
                            })
                        }
                        Err(_) => return,
                    };
                    let frame = ipc_audit::encode_reply(&Reply::Message(reply)).unwrap();
                    if stream.write_all(frame.as_bytes()).is_err() || only_one_ping {
                        return;
                    }
                }
            });
        }
    });
    seen
}

/// The internal network of the tests: 127.0.0.1/32.
pub fn loopback_only() -> Vec<Network> {
    vec![Network::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 32).unwrap()]
}

/// One running front, its test dird and its test auditd.
pub struct World {
    pub front: SocketAddr,
    pub control: DaemonControl,
    pub dird: Dird,
    pub dird_socket: PathBuf,
    pub auditd: AuditSeen,
    pub uid: u32,
    thread: Option<JoinHandle<Result<(), DaemonError>>>,
    paths: Vec<PathBuf>,
}

impl Drop for World {
    fn drop(&mut self) {
        self.control.stop();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        for path in &self.paths {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// The parameters of a world (before `adjust`): the test dird and auditd,
/// the realm, a 1 s first frame, 16 connections, 8 per source, the loopback
/// network only.
pub(crate) fn params(dird: PathBuf, audit: PathBuf, uid: u32) -> FrontParams {
    FrontParams {
        dird: Endpoint { socket: dird, uid },
        audit: Endpoint { socket: audit, uid },
        realm: REALM.to_owned(),
        timeouts: Timeouts {
            first_frame: FIRST_FRAME,
            reply_write: Duration::from_secs(2),
            dird_deadline: Duration::from_secs(5),
        },
        limits: ConnectionLimits {
            max_connections: 16,
            max_per_source: 8,
        },
        internal_networks: loopback_only(),
    }
}

/// Start a world, or `None` as root. `adjust` changes the parameters before
/// the front starts.
pub(crate) fn world(adjust: impl FnOnce(&mut FrontParams)) -> Option<World> {
    let uid = own_uid()?;
    let dird_path = socket_path("dird");
    let audit_path = socket_path("audit");
    let dird = start_dird(&dird_path);
    let auditd = start_auditd(&audit_path, FRONT_AUDIT_SOURCE);
    let mut params = params(dird_path.clone(), audit_path.clone(), uid);
    adjust(&mut params);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let front = listener.local_addr().unwrap();
    let control = DaemonControl::new();
    let thread_control = control.clone();
    let thread = std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(serve(
                params,
                Listeners {
                    tcp: vec![listener],
                },
                thread_control,
            ))
    });
    let start = Instant::now();
    while !control.is_serving() {
        assert!(!thread.is_finished(), "the front did not start");
        assert!(start.elapsed() < LONG, "the front did not start in time");
        std::thread::sleep(Duration::from_millis(10));
    }
    Some(World {
        front,
        control,
        dird,
        dird_socket: dird_path.clone(),
        auditd,
        uid,
        thread: Some(thread),
        paths: vec![dird_path, audit_path],
    })
}

/// Run `serve` once with `params` and `listeners` and return its start-up
/// error (the test dird and auditd are started on the parameters' paths).
pub(crate) fn start_error(
    params: FrontParams,
    listeners: Listeners,
    dird: bool,
    auditd: Option<EventSource>,
) -> Option<DaemonError> {
    if dird {
        start_dird(&params.dird.socket);
    }
    if let Some(source) = auditd {
        start_auditd(&params.audit.socket, source);
    }
    let control = DaemonControl::new();
    let result = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(serve(params, listeners, control));
    result.err()
}

/// Fresh socket paths for a start-up test, and the uid (or `None` as
/// root).
pub fn start_paths() -> Option<(PathBuf, PathBuf, u32)> {
    let uid = own_uid()?;
    Some((socket_path("dird"), socket_path("audit"), uid))
}

/// Send `request` on a fresh connection and read until the front closes.
pub fn exchange(front: SocketAddr, request: &[u8]) -> Vec<u8> {
    let mut stream = std::net::TcpStream::connect(front).unwrap();
    stream.set_read_timeout(Some(LONG)).unwrap();
    stream.write_all(request).unwrap();
    let mut reply = Vec::new();
    let _ = stream.read_to_end(&mut reply);
    reply
}

/// The KRB-ERROR of a framed reply (panics if the reply is not one).
pub fn krb_error_of(reply: &[u8]) -> KrbError {
    match ReplyMessage::parse_tcp(reply)
        .expect("an RFC 3244 reply")
        .body()
    {
        ReplyBody::KrbError { krb_error } => KrbError::decode(krb_error).expect("a KRB-ERROR"),
        ReplyBody::ApRep { .. } => panic!("an AP-REP reply, not a KRB-ERROR"),
    }
}

/// The result code a KRB-ERROR reply carries in its e-data.
pub fn result_code_of(reply: &[u8]) -> u16 {
    let error = krb_error_of(reply);
    let data = error.e_data.expect("e-data");
    assert_eq!(data.len(), 2, "no result string");
    u16::from_be_bytes([data[0], data[1]])
}

/// Whether the peer closes `stream` without sending an octet within `LONG`.
pub fn closed_without_a_byte(stream: &mut std::net::TcpStream) -> bool {
    stream.set_read_timeout(Some(LONG)).unwrap();
    let mut buffer = [0u8; 16];
    match stream.read(&mut buffer) {
        Ok(0) => true,
        Ok(_) => false,
        Err(error) => error.kind() == std::io::ErrorKind::ConnectionReset,
    }
}

/// Repeat `attempt` until it returns `true` or `limit` passes.
pub fn eventually(limit: Duration, mut attempt: impl FnMut() -> bool) -> bool {
    let start = Instant::now();
    loop {
        if attempt() {
            return true;
        }
        if start.elapsed() > limit {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}
