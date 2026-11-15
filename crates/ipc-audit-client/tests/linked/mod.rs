//! A fake auditd and the **real** audit client (crate `ipc_audit_client`)
//! linked to a gate — the way a test obtains an acknowledged intent (task
//! R15b, docs/questions/Q-630).
//!
//! The audit gate's link side (auditd reachable, the batch to send,
//! auditd's `Ack`) is crate-private to ipc-audit-client: only the one
//! client, after verifying auditd's uid and the source auditd reports,
//! drives it. So a
//! test that needs an [`AckedIntent`] (dird's `apply`, keyd's
//! `execute_acknowledged`) plays **auditd**, never the client: a minimal
//! auditd on a Unix socket in a unique temporary directory, the real
//! `AuditLink` connected to it (uid and `Pong` source verified), attached to
//! a gate and running on its own thread and runtime.
//!
//! * [`FakeAuditd`] — `Ping` → `Pong` naming the source it was told to
//!   report; `Append` → `Ack` of its last number ([`Acks::Every`]) or no
//!   reply at all ([`Acks::Never`]: sent, never acknowledged); it counts what
//!   it received.
//! * [`TestGate`] — a daemon's gate as the client sees it: the shared
//!   `AuditGate` and a wake-up.
//! * [`LinkRun`] — `connect` (the start-up verification), `attach`, then
//!   `run` until dropped.
//! * [`Linked`], [`acknowledged`], [`not_acknowledged`] — the whole chain
//!   for one value.
//!
//! Real peer credentials on both sides (the test's own uid). uid 0 is never
//! an expected auditd uid (docs/50 R50-3), so these helpers need a non-root
//! account: [`Linked::start`] panics as root with that reason (a test that
//! needs an acknowledged intent cannot run as root; it is not skipped
//! silently).
//!
//! Shared through `#[path]` by crates/ipc-audit-client `tests/client.rs`,
//! crates/directory-admin `tests/common`, crates/provision
//! `tests/admin_plane.rs`, crates/ipc-keyd-server
//! `tests/acknowledged_intent.rs` and crates/e2e-tests `tests/admin_world`
//! (each needs `ipc`, `ipc-audit`, `ipc-audit-client`, and tokio with
//! `rt` and `sync` as dev-dependencies).
//!
//! Source: docs/50 R50-3 ("the client verifies the server's uid too"),
//! §3.2, §3.6, §3.7, §7.5, §8.1 (an `Ack` only after auditd's sync);
//! docs/52 §3.11 R6, §3.12; docs/questions/Q-512, Q-560, Q-630. Moved from
//! crates/ipc-audit `tests/client.rs` (this project's test code, task R9b),
//! with the silent mode and the chain added; moved with the client to
//! crates/ipc-audit-client by task IB1 (docs/questions/Q-851). Every value
//! is made up here.
#![allow(dead_code)] // each test binary uses a different subset

use ipc::{Direction, FrameReader, Reply};
use ipc_audit::{
    decode_request, encode_reply, Ack, AuditReply, AuditRequest, EventBody, EventSource,
    WindowConfig, WindowSummary, AUDIT_CHANNEL,
};
use ipc_audit_client::{
    AckedIntent, AuditGate, AuditLink, AuditLinkError, ExpectedAuditd, IntentRecord, LinkedGate,
    PendingIntent,
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

/// A unique temporary directory (mode 0700), removed on drop. Short names:
/// a Unix socket path is limited in length.
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new() -> TempDir {
        let n = NEXT_DIR.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!("ial{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        TempDir(path)
    }

    pub fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    /// The test process's uid: the owner of the directory it just created;
    /// `None` as root.
    pub fn uid(&self) -> Option<u32> {
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
pub struct Received {
    connections: AtomicUsize,
    pings: AtomicUsize,
    appends: AtomicUsize,
}

/// Whether the fake auditd acknowledges the batches it receives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Acks {
    /// `Append` → `Ack` of its last number (docs/50 §8.1).
    Every,
    /// `Append` is received and counted, never answered: sent, never
    /// acknowledged (the client gives the connection up at its deadline).
    Never,
}

/// A minimal auditd whose `Pong` names `source` (module documentation).
pub struct FakeAuditd {
    path: PathBuf,
    stop: Arc<AtomicBool>,
    received: Arc<Received>,
    streams: Arc<Mutex<Vec<UnixStream>>>,
    thread: Option<JoinHandle<()>>,
}

impl FakeAuditd {
    /// An auditd that acknowledges every batch.
    pub fn start(path: &Path, source: EventSource) -> FakeAuditd {
        FakeAuditd::start_with(path, source, Acks::Every)
    }

    /// An auditd that receives batches and never acknowledges them.
    pub fn start_silent(path: &Path, source: EventSource) -> FakeAuditd {
        FakeAuditd::start_with(path, source, Acks::Never)
    }

    fn start_with(path: &Path, source: EventSource, acks: Acks) -> FakeAuditd {
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
                            std::thread::spawn(move || serve(stream, source, acks, &received));
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
            received,
            streams,
            thread: Some(thread),
        }
    }

    pub fn pings(&self) -> usize {
        self.received.pings.load(Ordering::SeqCst)
    }

    pub fn appends(&self) -> usize {
        self.received.appends.load(Ordering::SeqCst)
    }

    pub fn connections(&self) -> usize {
        self.received.connections.load(Ordering::SeqCst)
    }

    /// Stop accepting, close every connection, remove the socket file.
    pub fn stop(&mut self) {
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
/// number or, under [`Acks::Never`], nothing (docs/50 §7.5, §8.1). Anything
/// else closes it.
fn serve(mut stream: UnixStream, source: EventSource, acks: Acks, received: &Received) {
    while let Some(body) = read_frame(&mut stream) {
        let reply = match decode_request(&body) {
            Ok(AuditRequest::Ping) => {
                received.pings.fetch_add(1, Ordering::SeqCst);
                AuditReply::Pong(source)
            }
            Ok(AuditRequest::Append(append)) => {
                received.appends.fetch_add(1, Ordering::SeqCst);
                if acks == Acks::Never {
                    continue;
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
pub struct TestGate {
    pub core: AuditGate,
    pub wake: tokio::sync::Notify,
}

impl TestGate {
    pub fn new() -> Arc<TestGate> {
        Arc::new(TestGate {
            core: AuditGate::new(WindowConfig::DEFAULT),
            wake: tokio::sync::Notify::new(),
        })
    }

    /// Commit one gating event without asking for reachability (a test
    /// step: what a daemon commits is refused while auditd is unreachable,
    /// and the test wants something pending to see it is not sent).
    pub fn commit_pending(&self) {
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
pub fn block_on<F: Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(future)
}

/// The link's task on its own thread and runtime: `connect` (the start-up
/// verification), `attach` (the gate counts auditd reachable from here),
/// then `run` until dropped.
pub struct LinkRun {
    stop: Arc<tokio::sync::Notify>,
    thread: Option<JoinHandle<()>>,
}

impl LinkRun {
    /// Returns once the link is attached (the gate open) — or with the
    /// start-up verification's error (the gate never opened).
    pub fn start<G: LinkedGate + 'static>(
        link: AuditLink,
        gate: Arc<G>,
    ) -> Result<LinkRun, AuditLinkError> {
        let (report, started) = mpsc::channel();
        let stop = Arc::new(tokio::sync::Notify::new());
        let thread = {
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                block_on(async move {
                    match link.connect().await {
                        Ok(first) => {
                            let attached = link.attach(gate, first);
                            let _ = report.send(Ok(()));
                            let task = tokio::spawn(attached.run());
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
pub fn eventually(mut condition: impl FnMut() -> bool) -> bool {
    let end = Instant::now() + Duration::from_secs(10);
    while Instant::now() < end {
        if condition() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    condition()
}

pub fn link(path: &Path, uid: u32, source: EventSource) -> AuditLink {
    AuditLink::new(
        path.to_path_buf(),
        ExpectedAuditd::new(uid, source).unwrap(),
    )
}

/// A gate linked through the real client to a fake auditd (module
/// documentation). Dropped in field order: the link, then auditd, then the
/// directory.
pub struct Linked {
    gate: Arc<TestGate>,
    run: LinkRun,
    auditd: FakeAuditd,
    dir: TempDir,
}

impl Linked {
    /// A fake auditd (`acks`) reporting the dird source, and the real
    /// client verified against it and attached to a fresh gate.
    ///
    /// # Panics
    /// As root (uid 0 is never an expected auditd uid — docs/50 R50-3), or
    /// if the link does not verify.
    pub fn start(acks: Acks) -> Linked {
        let dir = TempDir::new();
        let Some(uid) = dir.uid() else {
            panic!(
                "an acknowledged intent comes only through the audit client, which never \
                 accepts auditd as uid 0 (docs/50 R50-3): run this test as a non-root account"
            );
        };
        let path = dir.join("a.sock");
        let auditd = FakeAuditd::start_with(&path, EventSource::Dird, acks);
        let gate = TestGate::new();
        let run = match LinkRun::start(link(&path, uid, EventSource::Dird), Arc::clone(&gate)) {
            Ok(run) => run,
            Err(error) => panic!("the audit link did not verify: {error}"),
        };
        Linked {
            gate,
            run,
            auditd,
            dir,
        }
    }

    /// The shared gate.
    pub fn gate(&self) -> &AuditGate {
        &self.gate.core
    }

    /// The fake auditd.
    pub fn auditd(&self) -> &FakeAuditd {
        &self.auditd
    }

    /// Commit `value`'s intent record into the gate and wake the client.
    ///
    /// # Panics
    /// No slot (the gate must be open: the link is attached).
    pub fn intent<T: IntentRecord>(&self, value: T) -> PendingIntent<T> {
        let slot = match self.gate.core.reserve() {
            Some(slot) => slot,
            None => panic!("the attached link opened the gate"),
        };
        let pending = match self.gate.core.begin_intent(slot, value) {
            Ok(pending) => pending,
            Err(_) => panic!("the intent record commits"),
        };
        self.gate.wake.notify_one();
        pending
    }
}

/// `value` with the proof that auditd acknowledged its intent record: the
/// record committed into a gate, delivered by the real client to an auditd
/// that acknowledges it (docs/50 §8.1), the proof taken from the gate —
/// the only way any code outside ipc-audit-client obtains one.
///
/// # Panics
/// As [`Linked::start`]; no acknowledgement within 10 s.
pub fn acknowledged<T: IntentRecord>(value: T) -> AckedIntent<T> {
    let linked = Linked::start(Acks::Every);
    let pending = linked.intent(value);
    let deadline = Instant::now() + Duration::from_secs(10);
    match linked.gate().wait_acknowledged(pending, deadline) {
        Ok(acked) => acked,
        Err(_) => panic!("auditd acknowledged the intent within 10 s"),
    }
}

/// `value` back **without** a proof: its intent record was delivered by the
/// real client to an auditd that never acknowledges (sent, not
/// acknowledged), and the wait ended at its deadline (docs/52 §3.11 R6 (a)).
///
/// # Panics
/// As [`Linked::start`]; the batch not received within 10 s; a proof.
pub fn not_acknowledged<T: IntentRecord>(value: T) -> T {
    let linked = Linked::start(Acks::Never);
    let pending = linked.intent(value);
    assert!(
        eventually(|| linked.auditd().appends() >= 1),
        "the intent was sent to auditd"
    );
    let deadline = Instant::now() + Duration::from_millis(20);
    match linked.gate().wait_acknowledged(pending, deadline) {
        Ok(_) => panic!("an auditd that acknowledges nothing gave no proof"),
        Err(value) => value,
    }
}
