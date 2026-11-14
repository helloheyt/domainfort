//! The one audit client (`ipc_audit::client`, task R9b) over real Unix
//! sockets: the peer uid and the source auditd reports are verified on every
//! new connection before any batch, and an auditd that would record this
//! process under another source receives nothing — the gate keeps auditd
//! unreachable meanwhile, so gating operations are refused.
//!
//! The auditd here is a minimal server written from the audit channel's own
//! message set (this crate): `Ping` → `Pong` naming the source it was told
//! to report, `Append` → `Ack` of its last number; it counts what it
//! received. Real peer credentials on both sides (the test's own uid); as
//! root the tests are skipped (uid 0 is never an expected auditd uid —
//! docs/50 R50-3).
//!
//! Source: docs/50 R50-3 ("the client verifies the server's uid too"),
//! §3.2 ("the source is set from the uid"), §3.6, §3.7, §7.5, §8.1; docs/52
//! §3.12 (C12); PENDING-OWNER A-57, A-67 item 2 (auditd unreachable ⇒
//! gating refused); docs/questions/Q-512 (A-112), Q-560. Every value is made
//! up here.
#![cfg(feature = "client")]

use ipc::{Direction, FrameReader, Reply};
use ipc_audit::client::{AuditLink, AuditLinkError, ExpectedAuditd, LinkedGate};
use ipc_audit::{
    decode_request, encode_reply, Ack, AuditGate, AuditReply, AuditRequest, EventBody, EventSource,
    WindowConfig, WindowSummary, AUDIT_CHANNEL,
};
use std::future::Future;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

static NEXT_DIR: AtomicU32 = AtomicU32::new(0);

/// A unique temporary directory (mode 0700), removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> TempDir {
        let n = NEXT_DIR.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!("iac{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        TempDir(path)
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    /// The test process's uid: the owner of the directory it just created;
    /// `None` as root.
    fn uid(&self) -> Option<u32> {
        let uid = std::fs::metadata(&self.0).unwrap().uid();
        if uid == 0 {
            eprintln!("skipped: running as root (docs/50 R50-3: uid 0 is never expected)");
            None
        } else {
            Some(uid)
        }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// What the fake auditd received.
#[derive(Default)]
struct Received {
    connections: AtomicUsize,
    pings: AtomicUsize,
    appends: AtomicUsize,
}

/// A minimal auditd whose `Pong` names `source` (module documentation).
struct FakeAuditd {
    path: PathBuf,
    stop: Arc<AtomicBool>,
    received: Arc<Received>,
    streams: Arc<Mutex<Vec<UnixStream>>>,
    thread: Option<JoinHandle<()>>,
}

impl FakeAuditd {
    fn start(path: &Path, source: EventSource) -> FakeAuditd {
        let _ = std::fs::remove_file(path);
        let listener = UnixListener::bind(path).unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let received = Arc::new(Received::default());
        let streams = Arc::new(Mutex::new(Vec::new()));
        let thread = {
            let (stop, received, streams) = (
                Arc::clone(&stop),
                Arc::clone(&received),
                Arc::clone(&streams),
            );
            std::thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            stream.set_nonblocking(false).unwrap();
                            received.connections.fetch_add(1, Ordering::SeqCst);
                            streams.lock().unwrap().push(stream.try_clone().unwrap());
                            let received = Arc::clone(&received);
                            std::thread::spawn(move || serve(stream, source, &received));
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
            received,
            streams,
            thread: Some(thread),
        }
    }

    fn pings(&self) -> usize {
        self.received.pings.load(Ordering::SeqCst)
    }

    fn appends(&self) -> usize {
        self.received.appends.load(Ordering::SeqCst)
    }

    fn connections(&self) -> usize {
        self.received.connections.load(Ordering::SeqCst)
    }

    /// Stop accepting, close every connection, remove the socket file.
    fn stop(&mut self) {
        let Some(thread) = self.thread.take() else {
            return;
        };
        self.stop.store(true, Ordering::SeqCst);
        thread.join().unwrap();
        for stream in self.streams.lock().unwrap().drain(..) {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

impl Drop for FakeAuditd {
    fn drop(&mut self) {
        self.stop();
    }
}

/// One connection: `Ping` → `Pong(source)`, `Append` → `Ack` of its last
/// number (docs/50 §7.5, §8.1). Anything else closes it.
fn serve(mut stream: UnixStream, source: EventSource, received: &Received) {
    while let Some(body) = read_frame(&mut stream) {
        let reply = match decode_request(&body) {
            Ok(AuditRequest::Ping) => {
                received.pings.fetch_add(1, Ordering::SeqCst);
                AuditReply::Pong(source)
            }
            Ok(AuditRequest::Append(append)) => {
                received.appends.fetch_add(1, Ordering::SeqCst);
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

/// One request frame from a blocking stream; `None` once the peer closed.
fn read_frame(stream: &mut UnixStream) -> Option<Vec<u8>> {
    let mut reader = FrameReader::new(AUDIT_CHANNEL.limit(Direction::Request));
    let mut chunk = [0u8; 1024];
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

/// A daemon's gate as the link sees it: the shared gate and a wake-up.
struct TestGate {
    core: AuditGate,
    wake: tokio::sync::Notify,
}

impl TestGate {
    fn new() -> Arc<TestGate> {
        Arc::new(TestGate {
            core: AuditGate::new(WindowConfig::DEFAULT),
            wake: tokio::sync::Notify::new(),
        })
    }

    /// Commit one gating event without asking for reachability (a test
    /// step: what a daemon commits is refused while auditd is unreachable,
    /// and the test wants something pending to see it is not sent).
    fn commit_pending(&self) {
        let event = EventBody::WindowSummary(WindowSummary {
            suppressed_noise: 1,
            refused_gating: 2,
            unrecorded_outcomes: 3,
        });
        self.core
            .with_steps(|window| {
                let slot = window.reserve().unwrap();
                window.commit(slot, &event).unwrap();
            })
            .unwrap();
        self.wake.notify_one();
    }
}

impl LinkedGate for TestGate {
    fn audit_gate(&self) -> &AuditGate {
        &self.core
    }

    fn recorded(&self) -> impl Future<Output = ()> + Send + '_ {
        self.wake.notified()
    }

    fn link_restored(&self) {}

    fn link_lost(&self) {}
}

/// `future` on a fresh current-thread runtime.
fn block_on<F: Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(future)
}

/// The link's task on its own thread and runtime: `connect` (the start-up
/// verification), then `run` until dropped.
struct LinkRun {
    stop: Arc<tokio::sync::Notify>,
    thread: Option<JoinHandle<()>>,
}

impl LinkRun {
    fn start(link: AuditLink, gate: Arc<TestGate>) -> Result<LinkRun, AuditLinkError> {
        let (report, started) = mpsc::channel();
        let stop = Arc::new(tokio::sync::Notify::new());
        let thread = {
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                block_on(async move {
                    match link.connect().await {
                        Ok(first) => {
                            let _ = report.send(Ok(()));
                            let task = tokio::spawn(link.run(gate, first));
                            stop.notified().await;
                            task.abort();
                            let _ = task.await;
                        }
                        Err(error) => {
                            let _ = report.send(Err(error));
                        }
                    }
                });
            })
        };
        match started.recv().unwrap() {
            Ok(()) => Ok(LinkRun {
                stop,
                thread: Some(thread),
            }),
            Err(error) => {
                thread.join().unwrap();
                Err(error)
            }
        }
    }
}

impl Drop for LinkRun {
    fn drop(&mut self) {
        self.stop.notify_one();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Poll `condition` until it holds or 10 s passed.
fn eventually(mut condition: impl FnMut() -> bool) -> bool {
    let end = Instant::now() + Duration::from_secs(10);
    while Instant::now() < end {
        if condition() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    condition()
}

fn link(path: &Path, uid: u32, source: EventSource) -> AuditLink {
    AuditLink::new(
        path.to_path_buf(),
        ExpectedAuditd::new(uid, source).unwrap(),
    )
}

/// Attack (docs/questions/Q-512 item 2): an auditd whose map gives this
/// process's uid another source — for each source a sender can expect, the
/// cross-wired auditd reports some other one — is refused at the first
/// `Pong`: one `Ping` and nothing else reaches it, no batch.
#[test]
fn a_cross_wired_auditd_receives_no_batch() {
    let dir = TempDir::new();
    let Some(uid) = dir.uid() else { return };
    for expected in EventSource::ALL {
        for reported in EventSource::ALL.into_iter().filter(|s| *s != expected) {
            let path = dir.join("a.sock");
            let auditd = FakeAuditd::start(&path, reported);
            let gate = TestGate::new();
            gate.commit_pending();
            let got = LinkRun::start(link(&path, uid, expected), Arc::clone(&gate));
            assert_eq!(got.err(), Some(AuditLinkError::SourceMismatch));
            assert_eq!(auditd.pings(), 1, "{expected:?} / {reported:?}");
            assert_eq!(auditd.appends(), 0, "no batch: {expected:?} / {reported:?}");
            assert!(!gate.core.is_reachable(), "the gate never saw auditd");
            assert!(gate.core.reserve().is_none(), "gating refused");
        }
    }
}

/// Attack (docs/50 R50-3): a peer of another uid than auditd's receives no
/// request at all — not even the `Ping`.
#[test]
fn a_peer_of_another_uid_receives_nothing() {
    let dir = TempDir::new();
    let Some(uid) = dir.uid() else { return };
    let path = dir.join("a.sock");
    let auditd = FakeAuditd::start(&path, EventSource::Keyd);
    let other = uid.wrapping_add(1).max(1);
    let got = block_on(link(&path, other, EventSource::Keyd).connect());
    assert_eq!(got.err(), Some(AuditLinkError::PeerMismatch));
    assert!(eventually(|| auditd.connections() == 1));
    assert_eq!(auditd.pings(), 0);
    assert_eq!(auditd.appends(), 0);
}

/// docs/50 §3.2 ("uid 0 is never mapped"); docs/questions/Q-510 item 1 (the
/// pattern): no expectation names auditd as uid 0.
#[test]
fn auditd_as_root_is_never_expected() {
    for source in EventSource::ALL {
        assert_eq!(
            ExpectedAuditd::new(0, source),
            Err(AuditLinkError::RootServerUid)
        );
    }
    let expected = ExpectedAuditd::new(7, EventSource::Dird).unwrap();
    assert_eq!((expected.uid(), expected.source()), (7, EventSource::Dird));
}

/// Positive (docs/50 §8.1): the expected auditd is verified, then every
/// committed event is delivered and acknowledged; the one-shot `verify`
/// (ldap-front's start-up check) passes too.
#[test]
fn the_expected_auditd_is_served() {
    let dir = TempDir::new();
    let Some(uid) = dir.uid() else { return };
    let path = dir.join("a.sock");
    let auditd = FakeAuditd::start(&path, EventSource::Kdc);
    assert_eq!(
        block_on(link(&path, uid, EventSource::Kdc).verify()),
        Ok(())
    );
    let gate = TestGate::new();
    let run = LinkRun::start(link(&path, uid, EventSource::Kdc), Arc::clone(&gate)).unwrap();
    assert!(eventually(|| gate.core.is_reachable()));
    gate.commit_pending();
    gate.commit_pending();
    assert!(eventually(|| gate.core.outstanding() == 0), "acknowledged");
    assert!(auditd.appends() >= 1);
    drop(run);
}

/// Attack on the reconnection path (docs/questions/Q-512, Q-560; A-57,
/// A-67 item 2): after the verified auditd goes away, a cross-wired one at
/// the same path receives `Ping`s and never a batch; the gate counts auditd
/// as unreachable all along (gating refused) and the pending event stays in
/// the window — until an auditd that reports the right source is back, which
/// then receives it.
#[test]
fn reconnecting_to_a_cross_wired_auditd_sends_nothing() {
    let dir = TempDir::new();
    let Some(uid) = dir.uid() else { return };
    let path = dir.join("a.sock");
    let mut first = FakeAuditd::start(&path, EventSource::Admind);
    let gate = TestGate::new();
    let run = LinkRun::start(link(&path, uid, EventSource::Admind), Arc::clone(&gate)).unwrap();
    gate.commit_pending();
    assert!(eventually(|| gate.core.outstanding() == 0));
    assert!(first.appends() >= 1);

    first.stop();
    assert!(eventually(|| !gate.core.is_reachable()), "the loss is seen");
    let cross_wired = FakeAuditd::start(&path, EventSource::Dird);
    gate.commit_pending();
    assert!(
        eventually(|| cross_wired.pings() >= 2),
        "the link keeps trying, verifying each new connection"
    );
    assert_eq!(
        cross_wired.appends(),
        0,
        "no batch to the cross-wired auditd"
    );
    assert!(!gate.core.is_reachable());
    assert!(gate.core.reserve().is_none(), "gating refused meanwhile");
    assert_eq!(gate.core.outstanding(), 1, "the event waits");
    drop(cross_wired);

    let back = FakeAuditd::start(&path, EventSource::Admind);
    assert!(eventually(|| gate.core.outstanding() == 0), "delivered");
    assert!(back.appends() >= 1);
    assert!(gate.core.is_reachable());
    drop(run);
}
