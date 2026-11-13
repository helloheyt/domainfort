//! The keyd client's connection rules decided in A-82 (docs/50 §9 tiers 1
//! and 2):
//!
//! * **Q-312** — a held connection is checked, without blocking and without
//!   sending, before it is reused: a dead one (keyd restarted while it was
//!   idle) or one with octets waiting is dropped and a fresh connection
//!   serves the call; a call that failed after it was sent is never sent
//!   again.
//! * **Q-311** — `IpcKeyd` requires every new connection to answer
//!   `DescribeConfig` with the description it started from, before anything
//!   else is sent on it: keyd's refusal (a role that may not call it) or
//!   another description is `Unavailable` (the KDC's 29), never keyd's
//!   `Denied` of the operation (24).
//!
//! Tier 1 drives the client over a scripted in-process connection; tier 2
//! over real Unix stream sockets in a private (0700) temporary directory
//! with the crate's own blocking `UnixConnection`, played against a scripted
//! keyd built from this crate's `decode_request` / `encode_answer`. The
//! socket connector here reports the server uid the test configured (on
//! every host the test process plays keyd itself); the kernel peer-credential
//! path is crates/ipc-keyd-server tests/unix_socket.rs.
//!
//! Sources: docs/50 R50-3, R50-7, R50-8, §3.3, §3.4 (`DescribeConfig` — Kdc,
//! Ldap), §3.6 (idle connections held; one deadline per call), §3.7, §7.5
//! step 4, §9; docs/10 §2; docs/questions/Q-311, Q-312 (A-82). Every value
//! is constructed by hand (tests/samples).
#![cfg(unix)]

mod samples;

use core::time::Duration;
use ipc::FrameLimit;
use ipc::FrameReader;
use ipc_keyd::{
    decode_request, encode_answer, Answer, Call, Connection, Connector, IpcKeyd, KeydClient,
    TransportError, UnixConnection, Unserved, REQUEST_LIMIT,
};
use keyd_types::{AuthnError, ConfigDescription, KeyCustody, KeyPurpose, Operation};
use krb_proto::Realm;
use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::mpsc;
use std::thread;
use std::time::Instant;
use zeroize::Zeroizing;

/// keyd's uid as the tests configure it (never 0).
const KEYD_UID: u32 = 61001;

/// The description keyd gives (tests/samples).
fn description() -> ConfigDescription {
    samples::description(true)
}

/// Another keyd's description: another realm.
fn other_description() -> ConfigDescription {
    ConfigDescription {
        realm: Realm::new("OTHER.EXAMPLE").unwrap(),
        ..description()
    }
}

// ---- tier 1: a scripted keyd ------------------------------------------------------

/// What the scripted keyd answers, and what each connection carried.
#[derive(Default)]
struct Script {
    /// The calls each connection carried, by connection index.
    carried: Vec<Vec<Operation>>,
    /// Connections whose idle check fails, with the failure.
    stale: BTreeMap<usize, TransportError>,
    /// The answers, in order (an `Err` is a transport failure after the
    /// request was written).
    answers: VecDeque<Result<Answer, TransportError>>,
}

impl Script {
    fn connects(&self) -> usize {
        self.carried.len()
    }
}

#[derive(Clone)]
struct ScriptConnector(Rc<RefCell<Script>>);

struct ScriptConnection {
    script: Rc<RefCell<Script>>,
    index: usize,
}

impl Connector for ScriptConnector {
    type Connection = ScriptConnection;
    fn connect(&mut self) -> Result<ScriptConnection, TransportError> {
        let mut script = self.0.borrow_mut();
        script.carried.push(Vec::new());
        Ok(ScriptConnection {
            script: Rc::clone(&self.0),
            index: script.carried.len() - 1,
        })
    }
}

impl Connection for ScriptConnection {
    fn peer_uid(&self) -> Result<u32, TransportError> {
        Ok(KEYD_UID)
    }

    fn exchange(
        &mut self,
        frame: &[u8],
        _reply_limit: FrameLimit,
        _deadline: Duration,
    ) -> Result<Zeroizing<Vec<u8>>, TransportError> {
        let call = decode_request(&frame[4..]).unwrap();
        let mut script = self.script.borrow_mut();
        script.carried[self.index].push(call.operation());
        let answer = script
            .answers
            .pop_front()
            .unwrap_or(Err(TransportError::Closed))?;
        Ok(Zeroizing::new(
            encode_answer(&answer).unwrap().body().to_vec(),
        ))
    }

    fn check_idle(&mut self) -> Result<(), TransportError> {
        match self.script.borrow().stale.get(&self.index) {
            Some(error) => Err(*error),
            None => Ok(()),
        }
    }
}

fn scripted() -> (Rc<RefCell<Script>>, KeydClient<ScriptConnector>) {
    let script = Rc::new(RefCell::new(Script::default()));
    let client = KeydClient::new(
        ScriptConnector(Rc::clone(&script)),
        KEYD_UID,
        Duration::from_secs(2),
    )
    .unwrap();
    (script, client)
}

fn answer(script: &Rc<RefCell<Script>>, answer: Answer) {
    script.borrow_mut().answers.push_back(Ok(answer));
}

/// docs/50 §3.6, §3.7, R50-7; Q-312 (A-82): a held connection whose idle
/// check finds the end of the stream (keyd went away) or a waiting octet (a
/// protocol error) is dropped before the call; the call goes, once, on a
/// fresh connection — nothing is sent on the old one.
#[test]
fn a_held_connection_failing_its_idle_check_is_replaced_before_the_call() {
    for failure in [TransportError::Closed, TransportError::Framing] {
        let (script, mut client) = scripted();
        answer(&script, Answer::Ping(Ok(())));
        assert_eq!(client.ping(), Ok(()));
        assert!(client.is_connected());
        script.borrow_mut().stale.insert(0, failure);
        answer(&script, Answer::Ping(Ok(())));
        assert_eq!(client.ping(), Ok(()), "{failure:?}");
        let script = script.borrow();
        assert_eq!(script.connects(), 2);
        assert_eq!(script.carried[0], [Operation::Ping], "nothing more on it");
        assert_eq!(script.carried[1], [Operation::Ping]);
    }
}

/// docs/50 §3.6: a held connection that passes its idle check is reused
/// (one connection for many calls, R50-7).
#[test]
fn a_usable_held_connection_is_reused() {
    let (script, mut client) = scripted();
    for _ in 0..3 {
        answer(&script, Answer::Ping(Ok(())));
        assert_eq!(client.ping(), Ok(()));
    }
    assert_eq!(script.borrow().connects(), 1);
    assert_eq!(script.borrow().carried[0].len(), 3);
}

/// Q-312 (A-82: "no blind resend of a request that may already have reached
/// the server"): a call whose request was written and whose reply did not
/// come — the peer closed, the deadline passed — is `Unavailable`, the
/// connection is dropped, and the request is not sent again; the next call
/// starts on a new connection.
#[test]
fn a_call_that_failed_after_it_was_sent_is_not_sent_again() {
    for failure in [TransportError::Closed, TransportError::DeadlineExceeded] {
        let (script, mut client) = scripted();
        script.borrow_mut().answers.push_back(Err(failure));
        assert_eq!(client.ping(), Err(keyd_types::Error::Unavailable));
        assert!(!client.is_connected());
        assert_eq!(script.borrow().connects(), 1, "{failure:?}");
        assert_eq!(script.borrow().carried[0], [Operation::Ping], "sent once");
        answer(&script, Answer::Ping(Ok(())));
        assert_eq!(client.ping(), Ok(()));
        assert_eq!(script.borrow().carried[1], [Operation::Ping]);
    }
}

/// docs/10 §2 (`DescribeConfig` is the Kdc's and the Ldap role's only): a
/// plain `KeydClient` (the directory's, an admin tool's) requires no
/// description, so its new connections carry only its own calls.
#[test]
fn a_plain_client_sends_no_describe_config_on_a_new_connection() {
    let (script, mut client) = scripted();
    assert!(client.required_description().is_none());
    answer(&script, Answer::Ping(Ok(())));
    assert_eq!(client.ping(), Ok(()));
    script.borrow_mut().stale.insert(0, TransportError::Closed);
    answer(&script, Answer::Ping(Ok(())));
    assert_eq!(client.ping(), Ok(()));
    assert_eq!(script.borrow().carried[1], [Operation::Ping]);
}

/// The custody of the kdc over the scripted keyd (its start-up
/// `DescribeConfig` answered with [`description`]).
fn custody() -> (Rc<RefCell<Script>>, IpcKeyd<ScriptConnector>) {
    let (script, client) = scripted();
    answer(&script, Answer::DescribeConfig(Ok(description())));
    let custody = IpcKeyd::connect(client).unwrap();
    assert_eq!(custody.config(), &description());
    assert_eq!(
        custody.client().required_description(),
        Some(&description())
    );
    (script, custody)
}

fn verify_preauth(custody: &mut IpcKeyd<ScriptConnector>) -> Result<(), AuthnError> {
    custody
        .verify_preauth(
            &samples::handle(0xA1, KeyPurpose::PrincipalLongterm),
            &samples::padata(2),
            None,
            &samples::time(0),
        )
        .map(|_| ())
}

/// docs/50 R50-8, §3.4, §7.5 step 4; docs/10 §2; Q-311 (A-82): after the
/// held connection went away, the new connection's `DescribeConfig` is
/// refused — keyd now maps this uid to a role that may not call it — so the
/// operation is `Unavailable` (29), not keyd's `Denied` (24); only
/// `DescribeConfig` was sent on it, and it was dropped. The same for
/// another description (another realm) and for keyd's shared refusal.
#[test]
fn ipc_keyd_requires_every_new_connection_to_describe_the_same_keyd() {
    let (script, mut custody) = custody();
    assert_eq!(script.borrow().carried[0], [Operation::DescribeConfig]);
    let refusals = [
        Answer::DescribeConfig(Err(keyd_types::Error::Denied)),
        Answer::DescribeConfig(Ok(other_description())),
        Answer::Ping(Ok(())),
    ];
    for (n, refusal) in refusals.into_iter().enumerate() {
        let previous = script.borrow().connects() - 1;
        script
            .borrow_mut()
            .stale
            .insert(previous, TransportError::Closed);
        answer(&script, refusal);
        assert_eq!(verify_preauth(&mut custody), Err(AuthnError::Unavailable));
        assert!(!custody.client().is_connected(), "dropped ({n})");
        let script = script.borrow();
        assert_eq!(
            script.carried.last().unwrap(),
            &[Operation::DescribeConfig],
            "nothing but DescribeConfig was sent ({n})"
        );
    }
    // The DescribeConfig exchange itself failing (keyd closed the new
    // connection — an unmapped uid): also not served.
    script
        .borrow_mut()
        .answers
        .push_back(Err(TransportError::Closed));
    assert_eq!(verify_preauth(&mut custody), Err(AuthnError::Unavailable));

    // keyd describes itself as before: the operation is sent, and keyd's own
    // answer passes through unchanged (A-26 / A-63).
    answer(&script, Answer::DescribeConfig(Ok(description())));
    answer(&script, Answer::VerifyPreauth(Err(AuthnError::Denied)));
    assert_eq!(verify_preauth(&mut custody), Err(AuthnError::Denied));
    let last = script.borrow().connects() - 1;
    assert_eq!(
        script.borrow().carried[last],
        [Operation::DescribeConfig, Operation::VerifyPreauth]
    );
    // That verified connection is reused without a second DescribeConfig.
    answer(&script, Answer::VerifyPreauth(Ok(samples::proof())));
    assert_eq!(verify_preauth(&mut custody), Ok(()));
    assert_eq!(script.borrow().connects() - 1, last);
    assert_eq!(
        script.borrow().carried[last],
        [
            Operation::DescribeConfig,
            Operation::VerifyPreauth,
            Operation::VerifyPreauth
        ]
    );
}

/// Q-311: the `DescribeConfig` failures map to `Unserved` cases that are
/// all `Unavailable` for the caller: keyd's refusal and another description
/// are `PeerMismatch`.
#[test]
fn the_describe_check_failures_are_peer_mismatch() {
    for refusal in [
        Answer::DescribeConfig(Err(keyd_types::Error::Denied)),
        Answer::DescribeConfig(Ok(other_description())),
    ] {
        let (script, mut client) = scripted();
        client.require_description(description());
        answer(&script, refusal);
        assert_eq!(client.call(&Call::Ping), Err(Unserved::PeerMismatch));
        assert!(!client.is_connected());
        assert_eq!(script.borrow().carried[0], [Operation::DescribeConfig]);
    }
}

// ---- tier 2: real sockets -----------------------------------------------------------

/// A unique, private (0700) temporary directory for one test's socket.
fn private_dir(test: &str) -> PathBuf {
    use std::os::unix::fs::DirBuilderExt;
    let dir = std::env::temp_dir().join(format!("ipckeydcr-{}-{test}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    dir
}

/// Connects to the socket at a path with the crate's blocking connection;
/// the server uid is the one the test configured (module documentation).
struct SocketConnector {
    path: PathBuf,
}

struct SocketConnection(UnixConnection);

impl SocketConnector {
    fn new(path: &Path) -> SocketConnector {
        SocketConnector {
            path: path.to_path_buf(),
        }
    }
}

impl Connector for SocketConnector {
    type Connection = SocketConnection;
    fn connect(&mut self) -> Result<SocketConnection, TransportError> {
        UnixStream::connect(&self.path)
            .map(|stream| SocketConnection(UnixConnection::from_stream(stream)))
            .map_err(|_| TransportError::Connect)
    }
}

impl Connection for SocketConnection {
    fn peer_uid(&self) -> Result<u32, TransportError> {
        Ok(KEYD_UID)
    }
    fn exchange(
        &mut self,
        frame: &[u8],
        reply_limit: FrameLimit,
        deadline: Duration,
    ) -> Result<Zeroizing<Vec<u8>>, TransportError> {
        self.0.exchange(frame, reply_limit, deadline)
    }
    fn check_idle(&mut self) -> Result<(), TransportError> {
        self.0.check_idle()
    }
}

fn socket_client(path: &Path) -> KeydClient<SocketConnector> {
    KeydClient::new(SocketConnector::new(path), KEYD_UID, Duration::from_secs(2)).unwrap()
}

/// The scripted keyd's side: one request frame, or `None` at the end of the
/// stream.
fn read_request(stream: &mut UnixStream) -> Option<Call> {
    let mut reader = FrameReader::new(REQUEST_LIMIT);
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(body) = reader.body() {
            return Some(decode_request(body).unwrap());
        }
        let wanted = reader.wanted().min(chunk.len());
        match stream.read(&mut chunk[..wanted]) {
            Ok(0) | Err(_) => return None,
            Ok(n) => {
                reader.push(&chunk[..n]).unwrap();
            }
        }
    }
}

fn write_answer(stream: &mut UnixStream, answer: &Answer) {
    stream
        .write_all(encode_answer(answer).unwrap().as_bytes())
        .unwrap();
}

/// The scripted keyd's answer: `Ping` and `DescribeConfig` only.
fn answer_to(call: &Call) -> Answer {
    match call {
        Call::Ping => Answer::Ping(Ok(())),
        Call::DescribeConfig => Answer::DescribeConfig(Ok(description())),
        other => panic!("not scripted: {:?}", other.operation()),
    }
}

/// Answer every request on `stream` until the peer closes; the operations
/// served.
fn serve(mut stream: UnixStream) -> Vec<Operation> {
    let mut served = Vec::new();
    while let Some(call) = read_request(&mut stream) {
        write_answer(&mut stream, &answer_to(&call));
        served.push(call.operation());
    }
    served
}

/// docs/50 §3.6, §3.7; Q-312 (A-82): keyd is stopped (its connection and
/// its listener go) and started again on the same path while the client
/// holds its idle connection; the client's **first** call afterwards is
/// served by the new keyd, on a fresh connection.
#[test]
fn after_a_keyd_restart_the_first_call_is_served_on_a_fresh_connection() {
    let dir = private_dir("restart");
    let path = dir.join("keyd.sock");
    let old = UnixListener::bind(&path).unwrap();
    let (stop, wait_stop) = mpsc::channel::<()>();
    let old = thread::spawn(move || {
        let (mut stream, _) = old.accept().unwrap();
        let call = read_request(&mut stream).unwrap();
        write_answer(&mut stream, &answer_to(&call));
        wait_stop.recv().unwrap();
        call.operation()
        // The old keyd stops: stream and listener dropped.
    });
    let mut client = socket_client(&path);
    assert_eq!(client.ping(), Ok(()));
    assert!(client.is_connected(), "the connection is held, idle");
    stop.send(()).unwrap();
    assert_eq!(old.join().unwrap(), Operation::Ping);
    std::fs::remove_file(&path).unwrap();
    let new = UnixListener::bind(&path).unwrap();
    let new = thread::spawn(move || serve(new.accept().unwrap().0));

    assert_eq!(client.ping(), Ok(()), "the first call after the restart");
    assert_eq!(client.describe_config(), Ok(description()));
    drop(client);
    assert_eq!(
        new.join().unwrap(),
        [Operation::Ping, Operation::DescribeConfig]
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// docs/50 R50-7 (strict request → reply); Q-312 (A-82: "octets pending on
/// an idle request/response channel ⇒ protocol error ⇒ drop"): keyd writes
/// a whole extra reply frame (another keyd's description) on the idle
/// connection; the client's next call does not read it as its reply — the
/// connection is dropped unread and the call is served on a fresh one.
#[test]
fn octets_waiting_on_an_idle_connection_are_never_read_as_a_reply() {
    let dir = private_dir("pending");
    let path = dir.join("keyd.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let (written, wait_written) = mpsc::channel();
    let server = thread::spawn(move || {
        let (mut first, _) = listener.accept().unwrap();
        let call = read_request(&mut first).unwrap();
        write_answer(&mut first, &answer_to(&call));
        write_answer(&mut first, &Answer::DescribeConfig(Ok(other_description())));
        written.send(()).unwrap();
        let on_second = serve(listener.accept().unwrap().0);
        let more_on_first = read_request(&mut first).map(|call| call.operation());
        (call.operation(), more_on_first, on_second)
    });
    let mut client = socket_client(&path);
    assert_eq!(client.describe_config(), Ok(description()));
    wait_written.recv().unwrap();
    assert_eq!(
        client.describe_config(),
        Ok(description()),
        "the waiting frame was not taken as the reply"
    );
    drop(client);
    let (first, more_on_first, on_second) = server.join().unwrap();
    assert_eq!(first, Operation::DescribeConfig);
    assert_eq!(more_on_first, None, "nothing more was sent on it");
    assert_eq!(on_second, [Operation::DescribeConfig]);
    let _ = std::fs::remove_dir_all(dir);
}

/// Q-312 (A-82: "no blind resend"): keyd receives the request and goes away
/// before answering; the call is `Unavailable`, the connection dropped, and
/// the client neither reconnects nor sends the request again.
#[test]
fn a_request_lost_after_it_was_sent_is_not_resent_over_a_socket() {
    let dir = private_dir("noresend");
    let path = dir.join("keyd.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let (gone, wait_gone) = mpsc::channel::<()>();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let call = read_request(&mut stream).unwrap();
        drop(stream);
        // Any later connection during the client's call, and for 300 ms
        // after it returned.
        listener.set_nonblocking(true).unwrap();
        let mut later = 0usize;
        let mut until = None;
        loop {
            match listener.accept() {
                Ok(_) => later += 1,
                Err(_) => thread::sleep(Duration::from_millis(5)),
            }
            if until.is_none() && wait_gone.try_recv().is_ok() {
                until = Some(Instant::now() + Duration::from_millis(300));
            }
            if until.is_some_and(|until| Instant::now() >= until) {
                break;
            }
        }
        (call.operation(), later)
    });
    let mut client = socket_client(&path);
    assert_eq!(client.ping(), Err(keyd_types::Error::Unavailable));
    assert!(!client.is_connected());
    gone.send(()).unwrap();
    let (call, later) = server.join().unwrap();
    assert_eq!(call, Operation::Ping);
    assert_eq!(later, 0, "no new connection, no second request");
    drop(client);
    let _ = std::fs::remove_dir_all(dir);
}

/// docs/50 §3.6 (idle connections held): the real blocking connection's idle
/// check — usable while nothing is waiting (and still usable for an
/// exchange afterwards), `Framing` for a waiting octet, `Closed` once the
/// peer has closed.
#[test]
fn the_blocking_connections_idle_check() {
    let (client_end, mut peer) = UnixStream::pair().unwrap();
    let mut connection = UnixConnection::from_stream(client_end);
    assert_eq!(connection.check_idle(), Ok(()));
    assert_eq!(connection.check_idle(), Ok(()), "and again");
    let server = thread::spawn(move || {
        let call = read_request(&mut peer).unwrap();
        write_answer(&mut peer, &answer_to(&call));
        peer
    });
    let frame = ipc::encode_frame(
        ipc_keyd::KEYD_CHANNEL,
        ipc::Direction::Request,
        &Call::Ping.to_wire().unwrap(),
    )
    .unwrap();
    assert!(connection
        .exchange(
            frame.as_bytes(),
            ipc_keyd::REPLY_LIMIT,
            Duration::from_secs(2)
        )
        .is_ok());
    let mut peer = server.join().unwrap();
    assert_eq!(connection.check_idle(), Ok(()));
    peer.write_all(&[0]).unwrap();
    assert_eq!(connection.check_idle(), Err(TransportError::Framing));

    let (client_end, peer) = UnixStream::pair().unwrap();
    let mut connection = UnixConnection::from_stream(client_end);
    drop(peer);
    assert_eq!(connection.check_idle(), Err(TransportError::Closed));
}
