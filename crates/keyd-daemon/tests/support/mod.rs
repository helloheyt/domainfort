//! Tier-2 support (docs/50 §9: "real servers run in the test's threads;
//! Unix sockets in a unique temporary directory (0700); the uid map is
//! injected with the test's own uid for the role under test").
//!
//! * [`TempDir`] — a unique 0700 directory, removed on drop.
//! * [`my_uid`] — the test process's uid, read from the owner of a directory
//!   it created (std only, no `unsafe`).
//! * [`FakeAuditd`] — a minimal audit server written from the audit channel's
//!   own message set (crates/ipc-audit): `Ping` → `Pong` naming the source
//!   it records its peers under (keyd's unless told otherwise — task R9b),
//!   `Append` → `Ack` of its last number; it records the events it received
//!   and can be stopped to play "auditd unreachable".
//! * [`Daemon`] — the real `keyd_daemon::serve` on its own thread with its
//!   own current-thread runtime, stopped through `DaemonControl`.
//! * [`RawClient`] — a blocking client of the keyd channel over a real
//!   socket, built from crates/ipc-keyd's codec.
//! * [`TestClock`] — keyd's clock, set by the test (docs/50 §9: "the startup
//!   hold-down with an injected clock").
//!
//! Real peer credentials are used on both sides: the daemon reads them with
//! tokio `UnixStream::peer_cred`; the daemon checks the fake auditd's uid the
//! same way. No test-only seam is compiled into the daemon.
//!
//! Sources: docs/50 §3.1-§3.7, §8.1, §9; crates/ipc-audit and crates/ipc-keyd
//! message sets. Every value is constructed by hand for these tests; no
//! vector comes from any other implementation.
#![allow(dead_code)] // each test binary uses a different subset

use ipc::{decode_reply, encode_frame, Direction, FrameReader, Refused, Reply};
use ipc_audit::{
    decode_event, decode_request, encode_reply, Ack, AuditReply, AuditRequest, EventBody,
    EventSource, AUDIT_CHANNEL,
};
use ipc_keyd::{Answer, Call, KeydReply, KEYD_CHANNEL, REPLY_LIMIT};
use keyd::{EntropySource, KeyStore, Keyd};
// The full parameters and the generic `serve` are the daemon's test seams
// (docs/52 C18, task R15; feature `test-seams`, enabled by the
// dev-dependency).
use keyd_daemon::test_seams::{serve, DaemonParams};
use keyd_daemon::{AuditEndpoint, CallerMap, Clock, DaemonControl, IntentAckBudget, RecordBuffer};
use krb_proto::KerberosTime;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

static NEXT_DIR: AtomicU32 = AtomicU32::new(0);

/// A unique temporary directory (mode 0700), removed on drop. Short names:
/// a Unix socket path is limited in length.
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    pub fn new() -> TempDir {
        let n = NEXT_DIR.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!("kdd{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        TempDir { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn join(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// The test process's uid: the owner of a directory it just created.
pub fn my_uid(dir: &TempDir) -> u32 {
    std::fs::metadata(dir.path()).unwrap().uid()
}

/// Tier 2 needs a non-root uid: uid 0 is never mapped (R50-3) and the keyd
/// client refuses a root server uid (Q-245 item 5).
pub fn skip_as_root(uid: u32) -> bool {
    if uid == 0 {
        eprintln!("skipped: running as root (docs/50 R50-3: uid 0 is never mapped)");
        true
    } else {
        false
    }
}

/// keyd's clock, set by the test; `None` plays an unreadable clock.
#[derive(Clone)]
pub struct TestClock(Arc<Mutex<Option<KerberosTime>>>);

impl TestClock {
    pub fn at(time: KerberosTime) -> TestClock {
        TestClock(Arc::new(Mutex::new(Some(time))))
    }

    pub fn set(&self, time: KerberosTime) {
        *self.0.lock().unwrap() = Some(time);
    }
}

impl Clock for TestClock {
    fn now(&self) -> Option<KerberosTime> {
        *self.0.lock().unwrap()
    }
}

/// Read one frame from a blocking stream with `limit`; `None` if the peer
/// closed before a whole frame, or the read timed out.
fn read_frame(stream: &mut UnixStream, limit: ipc::FrameLimit) -> Option<Vec<u8>> {
    let mut reader = FrameReader::new(limit);
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(body) = reader.body() {
            return Some(body.to_vec());
        }
        let wanted = reader.wanted().min(chunk.len());
        if wanted == 0 {
            return None;
        }
        match stream.read(&mut chunk[..wanted]) {
            Ok(0) => return None,
            Ok(n) => {
                reader.push(&chunk[..n]).ok()?;
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(_) => return None,
        }
    }
}

/// A minimal auditd for the tests (module documentation). Its `Pong` names
/// the source it records its peers under (task R9b, docs/questions/Q-560):
/// keyd's ([`FakeAuditd::start`]) unless started for another sender
/// ([`FakeAuditd::start_recording_as`]) — or cross-wired by a test.
pub struct FakeAuditd {
    path: PathBuf,
    stop: Arc<AtomicBool>,
    events: Arc<Mutex<Vec<EventBody>>>,
    connections: Arc<Mutex<Vec<UnixStream>>>,
    thread: Option<JoinHandle<()>>,
}

impl FakeAuditd {
    /// An auditd that records its peers as keyd (the sender this support
    /// was written for).
    pub fn start(path: &Path) -> FakeAuditd {
        FakeAuditd::start_recording_as(path, EventSource::Keyd)
    }

    /// An auditd whose `Pong` names `source`: the source it records every
    /// peer under (docs/50 §3.2) — a sender's own source, or another one to
    /// play an auditd whose map is cross-wired (task R9b).
    pub fn start_recording_as(path: &Path, source: EventSource) -> FakeAuditd {
        let _ = std::fs::remove_file(path);
        let listener = UnixListener::bind(path).unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let events = Arc::new(Mutex::new(Vec::new()));
        let connections = Arc::new(Mutex::new(Vec::new()));
        let thread = {
            let (stop, events, connections) = (
                Arc::clone(&stop),
                Arc::clone(&events),
                Arc::clone(&connections),
            );
            std::thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            stream.set_nonblocking(false).unwrap();
                            connections
                                .lock()
                                .unwrap()
                                .push(stream.try_clone().unwrap());
                            let events = Arc::clone(&events);
                            std::thread::spawn(move || serve_audit(stream, source, &events));
                        }
                        Err(e) if e.kind() == ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => return,
                    }
                }
            })
        };
        FakeAuditd {
            path: path.to_path_buf(),
            stop,
            events,
            connections,
            thread: Some(thread),
        }
    }

    /// Stop accepting, close every connection, remove the socket file. Only
    /// the first call acts (a later instance may have bound the same path).
    pub fn stop(&mut self) {
        let Some(thread) = self.thread.take() else {
            return;
        };
        self.stop.store(true, Ordering::SeqCst);
        thread.join().unwrap();
        for stream in self.connections.lock().unwrap().drain(..) {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
        let _ = std::fs::remove_file(&self.path);
    }

    /// The events received so far.
    pub fn events(&self) -> Vec<EventBody> {
        self.events.lock().unwrap().clone()
    }
}

impl Drop for FakeAuditd {
    fn drop(&mut self) {
        self.stop();
    }
}

/// One audit connection: `Ping` → `Pong` naming `source`, `Append` → `Ack`
/// (crates/ipc-audit channel; docs/50 §8.1). Anything else closes it.
fn serve_audit(mut stream: UnixStream, source: EventSource, events: &Mutex<Vec<EventBody>>) {
    while let Some(body) = read_frame(&mut stream, AUDIT_CHANNEL.limit(Direction::Request)) {
        let reply = match decode_request(&body) {
            Ok(AuditRequest::Ping) => AuditReply::Pong(source),
            Ok(AuditRequest::Append(append)) => {
                let mut held = events.lock().unwrap();
                for event in append.events() {
                    held.push(decode_event(event.as_bytes()).unwrap());
                }
                AuditReply::Ack(Ack {
                    through_seq: append.last_seq(),
                    head_hash: [0; 32],
                })
            }
            Err(_) => return,
        };
        let frame = encode_reply(&Reply::Message(reply)).unwrap();
        if stream.write_all(frame.as_bytes()).is_err() {
            return;
        }
    }
}

/// The parameters of a test daemon in `dir`: keyd at `k.sock`, auditd at
/// `a.sock` running as `auditd_uid`, `frame_timeout` 1 s, quota 8, the
/// production intent budget (a test whose own client waits longer may raise
/// it, up to the ceiling — docs/questions/Q-415).
pub fn params(dir: &TempDir, callers: CallerMap, auditd_uid: u32) -> DaemonParams {
    DaemonParams {
        keyd_socket: dir.join("k.sock"),
        callers,
        audit: AuditEndpoint {
            socket: dir.join("a.sock"),
            uid: auditd_uid,
        },
        frame_timeout: Duration::from_secs(1),
        max_connections_per_uid: 8,
        queue_capacity: 16,
        window: ipc_audit::WindowConfig::DEFAULT,
        intent_ack_budget: IntentAckBudget::PRODUCTION,
        extra_listeners: Vec::new(),
    }
}

/// The real daemon on its own thread (module documentation).
pub struct Daemon {
    control: DaemonControl,
    thread: Option<JoinHandle<Result<(), String>>>,
    pub socket: PathBuf,
}

impl Daemon {
    /// Start `serve` and wait until it listens; a start-up failure is
    /// returned as its message.
    pub fn start<S, E, C, F>(params: DaemonParams, clock: C, build: F) -> Result<Daemon, String>
    where
        S: KeyStore + Send + 'static,
        E: EntropySource + Send + 'static,
        C: Clock,
        F: FnOnce(&KerberosTime) -> Result<Keyd<S, RecordBuffer, E>, keyd::ConfigError>
            + Send
            + 'static,
    {
        let control = DaemonControl::new();
        let socket = params.keyd_socket.clone();
        let thread = {
            let control = control.clone();
            std::thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| e.to_string())?;
                let result = runtime.block_on(serve(params, clock, build, control));
                drop(runtime);
                match result {
                    Ok(stopped) => {
                        let failed = stopped.engine_failed();
                        stopped
                            .join()
                            .map_err(|_| String::from("engine panicked"))?;
                        if failed {
                            Err(String::from("engine stopped early"))
                        } else {
                            Ok(())
                        }
                    }
                    Err(error) => Err(error.to_string()),
                }
            })
        };
        let start = Instant::now();
        while !control.is_serving() {
            if thread.is_finished() {
                return Err(thread.join().unwrap().err().unwrap_or_default());
            }
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "daemon did not start"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        Ok(Daemon {
            control,
            thread: Some(thread),
            socket,
        })
    }

    /// Stop the daemon and wait for it (engine joined).
    pub fn stop(mut self) -> Result<(), String> {
        self.control.stop();
        self.thread.take().unwrap().join().unwrap()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if let Some(thread) = self.thread.take() {
            self.control.stop();
            let _ = thread.join();
        }
    }
}

/// How one exchange on a raw connection ended.
#[derive(Debug, PartialEq, Eq)]
pub enum Received {
    /// A reply body.
    Reply(Vec<u8>),
    /// The daemon closed the connection without (further) reply.
    Closed,
}

/// A blocking client of the keyd channel over a real socket.
pub struct RawClient {
    pub stream: UnixStream,
}

impl RawClient {
    pub fn connect(path: &Path) -> RawClient {
        let stream = UnixStream::connect(path).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        RawClient { stream }
    }

    /// Send raw octets.
    pub fn send_raw(&mut self, octets: &[u8]) {
        let _ = self.stream.write_all(octets);
    }

    /// Send one call's request frame.
    pub fn send(&mut self, call: &Call) {
        let frame =
            encode_frame(KEYD_CHANNEL, Direction::Request, &call.to_wire().unwrap()).unwrap();
        self.send_raw(frame.as_bytes());
    }

    /// Read one reply frame, or see the connection closed.
    pub fn receive(&mut self) -> Received {
        match read_frame(&mut self.stream, REPLY_LIMIT) {
            Some(body) => Received::Reply(body),
            None => Received::Closed,
        }
    }

    /// One call: keyd's answer, the shared refusal, or `None` if the
    /// connection was closed without a reply.
    pub fn call(&mut self, call: &Call) -> Option<Result<Answer, Refused>> {
        self.send(call);
        match self.receive() {
            Received::Reply(body) => Some(
                match decode_reply::<KeydReply>(KEYD_CHANNEL, &body).unwrap() {
                    Reply::Message(message) => {
                        Ok(Answer::from_wire(call.operation(), message).unwrap())
                    }
                    Reply::Refused(refused) => Err(refused),
                },
            ),
            Received::Closed => None,
        }
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
