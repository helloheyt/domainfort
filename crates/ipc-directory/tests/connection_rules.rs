//! The kdc's directory client's connection rules decided in A-82 (docs/50
//! §9 tiers 1 and 2):
//!
//! * **Q-312** — a held connection is checked, without blocking and without
//!   sending, before it is reused: outside a view a dead one (dird restarted
//!   while it was idle) or one with octets waiting is dropped and a fresh
//!   connection serves the request; inside a view (whose state lived on the
//!   dropped connection) the query fails `Unavailable` without being sent; a
//!   request that failed after it was sent is never sent again.
//! * **Q-311** (task R9: always) — the client exists only with the domain
//!   its start-time `DescribeDomain` gave (`DirectoryClient::connect`, A-69);
//!   every new connection must answer `DescribeDomain` with the same realm,
//!   naming context, krbtgt handle and policy version before anything else
//!   is sent on it.
//!
//! Tier 1 drives the client over a scripted in-process connection; tier 2
//! over real Unix stream sockets in a private (0700) temporary directory
//! with the crate's own blocking `UnixConnection`, against a scripted dird
//! built from this crate's message set. The socket connector reports the
//! server uid the test configured (the test process plays dird itself; the
//! kernel peer-credential path is crates/directory-daemon's tier-2 tests).
//!
//! Sources: docs/50 R50-2, R50-3, R50-7, R50-8, §3.3, §3.4 (views,
//! `DescribeDomain`), §3.6 (idle connections held; one deadline per call),
//! §3.7, §7.5 step 4, §9; A-69; docs/questions/Q-311, Q-312 (A-82), Q-466
//! (A-102). Every value is hand-made (tests/common).
#![cfg(unix)]

mod common;

use common::*;
use core::time::Duration;
use ipc::{encode_frame, Direction, FrameLimit, FrameReader};
use ipc_directory::typed::Request;
use ipc_directory::wire::DirectoryReply;
use ipc_directory::{
    Connection, Connector, DirectoryClient, DomainDescription, TransportError, UnixConnection,
    Unserved, DIRECTORY_CHANNEL, REQUEST_LIMIT,
};
use kdc::{AccountSource, AccountSourceError};
use krb_proto::Realm;
use pdp::PolicyVersion;
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

const DIRD_UID: u32 = 61002;
const VERSION: PolicyVersion = PolicyVersion(7);

/// The kind of a request, for the record of what a connection carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    BeginView,
    Query,
    EndView,
    DescribeDomain,
    Ping,
}

fn kind(request: &Request) -> Kind {
    match request {
        Request::BeginView => Kind::BeginView,
        Request::Query { .. } => Kind::Query,
        Request::EndView { .. } => Kind::EndView,
        Request::DescribeDomain => Kind::DescribeDomain,
        Request::Ping => Kind::Ping,
    }
}

// ---- tier 1: a scripted dird ------------------------------------------------------

#[derive(Default)]
struct Script {
    carried: Vec<Vec<Kind>>,
    stale: BTreeMap<usize, TransportError>,
    replies: VecDeque<Result<DirectoryReply, TransportError>>,
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
        Ok(DIRD_UID)
    }

    fn exchange(
        &mut self,
        frame: &[u8],
        _reply_limit: FrameLimit,
        _deadline: Duration,
    ) -> Result<Zeroizing<Vec<u8>>, TransportError> {
        let request = decode_request(&frame[4..]).unwrap();
        let mut script = self.script.borrow_mut();
        script.carried[self.index].push(kind(&request));
        let reply = script
            .replies
            .pop_front()
            .unwrap_or(Err(TransportError::Closed))?;
        Ok(Zeroizing::new(reply_body(&reply)))
    }

    fn check_idle(&mut self) -> Result<(), TransportError> {
        match self.script.borrow().stale.get(&self.index) {
            Some(error) => Err(*error),
            None => Ok(()),
        }
    }
}

/// A client connected to the scripted dird: connection 0 carried the
/// start-time `DescribeDomain`, answered with [`domain`] (task R9).
fn scripted() -> (Rc<RefCell<Script>>, DirectoryClient<ScriptConnector>) {
    let script = Rc::new(RefCell::new(Script::default()));
    reply(&script, DirectoryReply::from_domain(&domain()));
    let client = DirectoryClient::connect(
        ScriptConnector(Rc::clone(&script)),
        DIRD_UID,
        Duration::from_secs(2),
        VERSION,
    )
    .unwrap();
    assert_eq!(carried(&script, 0), [Kind::DescribeDomain]);
    (script, client)
}

fn reply(script: &Rc<RefCell<Script>>, reply: DirectoryReply) {
    script.borrow_mut().replies.push_back(Ok(reply));
}

fn begun(view: u64) -> DirectoryReply {
    DirectoryReply::ViewBegun {
        view,
        policy_version: VERSION.0,
    }
}

fn carried(script: &Rc<RefCell<Script>>, index: usize) -> Vec<Kind> {
    script.borrow().carried[index].clone()
}

fn alice() -> krb_proto::PrincipalName {
    name(1, &["alice"])
}

/// docs/50 §3.6, §3.7, R50-7; Q-312 (A-82): outside a view, a held
/// connection failing its idle check (end of stream; a waiting octet) is
/// dropped before the request, which goes once on a fresh connection.
#[test]
fn a_held_connection_failing_its_idle_check_is_replaced_before_begin_view() {
    for failure in [TransportError::Closed, TransportError::Framing] {
        let (script, mut client) = scripted();
        reply(&script, DirectoryReply::Pong);
        assert_eq!(client.ping(), Ok(()));
        script.borrow_mut().stale.insert(0, failure);
        reply(&script, DirectoryReply::from_domain(&domain()));
        reply(&script, begun(1));
        reply(&script, DirectoryReply::ViewEnded);
        let view = client.begin_view().expect("served on a fresh connection");
        drop(view);
        assert_eq!(
            carried(&script, 0),
            [Kind::DescribeDomain, Kind::Ping],
            "{failure:?}"
        );
        assert_eq!(
            carried(&script, 1),
            [Kind::DescribeDomain, Kind::BeginView, Kind::EndView]
        );
    }
}

/// docs/50 §3.4 (dird releases a connection's view when it ends); Q-312: a
/// held connection that fails its idle check in the middle of a view is not
/// replaced — the query is `Unavailable` and is not sent anywhere, and the
/// view is broken.
#[test]
fn inside_a_view_a_stale_connection_fails_the_query_without_sending_it() {
    let (script, mut client) = scripted();
    reply(&script, begun(4));
    let view = client.begin_view().unwrap();
    script.borrow_mut().stale.insert(0, TransportError::Closed);
    assert_eq!(
        view.client(&realm(), &alice()).err(),
        Some(AccountSourceError::Unavailable)
    );
    assert!(!view.is_open());
    drop(view);
    assert_eq!(script.borrow().carried.len(), 1, "no new connection");
    assert_eq!(
        carried(&script, 0),
        [Kind::DescribeDomain, Kind::BeginView],
        "nothing more sent"
    );
    assert!(!client.is_connected());
}

/// Q-312 (A-82: no blind resend): a request whose reply did not come is
/// `Unavailable` and not sent again; the next request starts on a new
/// connection.
#[test]
fn a_request_that_failed_after_it_was_sent_is_not_sent_again() {
    for failure in [TransportError::Closed, TransportError::DeadlineExceeded] {
        let (script, mut client) = scripted();
        script.borrow_mut().replies.push_back(Err(failure));
        assert_eq!(client.ping(), Err(Unserved::Transport(failure)));
        assert!(!client.is_connected());
        assert_eq!(script.borrow().carried.len(), 1);
        assert_eq!(
            carried(&script, 0),
            [Kind::DescribeDomain, Kind::Ping],
            "sent once"
        );
    }
}

/// A domain described differently: `edit` applied to [`domain`].
fn changed(edit: impl FnOnce(&mut DomainDescription)) -> DomainDescription {
    let mut domain = domain();
    edit(&mut domain);
    domain
}

/// docs/50 R50-2, §3.4, §7.5 step 4; A-69; Q-311 (A-82), Q-466 (task R9:
/// always): a new connection whose `DescribeDomain` answers another policy
/// version than the pinned domain's is `PolicyVersionMismatch`, another
/// realm / naming context / krbtgt handle `PeerMismatch` — dropped, with
/// nothing but `DescribeDomain` sent on it; the same description lets the
/// request through, and that connection is reused without asking again.
#[test]
fn every_new_connection_must_describe_the_same_domain() {
    let refusals = [
        (
            changed(|d| d.policy_version = PolicyVersion(8)),
            Unserved::PolicyVersionMismatch {
                dird: PolicyVersion(8),
            },
        ),
        (
            changed(|d| d.realm = Realm::new("OTHER.EXAMPLE").unwrap()),
            Unserved::PeerMismatch,
        ),
        (
            changed(|d| d.naming_context = vec![String::from("other")]),
            Unserved::PeerMismatch,
        ),
        (
            changed(|d| {
                d.krbtgt = keyd_types::KeyHandle::new(
                    keyd_types::PrincipalId::from_bytes([0x7C; 16]),
                    keyd_types::KeyPurpose::Krbtgt,
                )
            }),
            Unserved::PeerMismatch,
        ),
    ];
    for (n, (other, expected)) in refusals.into_iter().enumerate() {
        let (script, mut client) = scripted();
        script.borrow_mut().stale.insert(0, TransportError::Closed);
        reply(&script, DirectoryReply::from_domain(&other));
        assert_eq!(client.begin_view().err(), Some(expected), "{n}");
        assert!(!client.is_connected());
        assert_eq!(carried(&script, 1), [Kind::DescribeDomain], "{n}");
    }

    let (script, mut client) = scripted();
    assert_eq!(client.domain(), &domain());
    script.borrow_mut().stale.insert(0, TransportError::Closed);
    reply(&script, DirectoryReply::from_domain(&domain()));
    reply(&script, begun(1));
    reply(&script, DirectoryReply::ViewEnded);
    drop(client.begin_view().unwrap());
    reply(&script, begun(2));
    reply(&script, DirectoryReply::ViewEnded);
    drop(client.begin_view().unwrap());
    assert_eq!(script.borrow().carried.len(), 2);
    assert_eq!(
        carried(&script, 1),
        [
            Kind::DescribeDomain,
            Kind::BeginView,
            Kind::EndView,
            Kind::BeginView,
            Kind::EndView
        ]
    );
}

/// docs/50 §3.7 (R50-8): the `DescribeDomain` of a new connection failing
/// (a refusal, a closed connection) is not served.
#[test]
fn a_failed_describe_domain_is_not_served() {
    let (script, mut client) = scripted();
    script.borrow_mut().stale.insert(0, TransportError::Closed);
    reply(
        &script,
        DirectoryReply::ViewFailure(ipc_directory::ViewFailure::Snapshot),
    );
    assert!(client.begin_view().is_err());
    script
        .borrow_mut()
        .replies
        .push_back(Err(TransportError::Closed));
    assert_eq!(
        client.begin_view().err(),
        Some(Unserved::Transport(TransportError::Closed))
    );
    assert_eq!(carried(&script, 1), [Kind::DescribeDomain]);
    assert_eq!(carried(&script, 2), [Kind::DescribeDomain]);
}

// ---- tier 2: real sockets -----------------------------------------------------------

/// A unique, private (0700) temporary directory for one test's socket.
fn private_dir(test: &str) -> PathBuf {
    use std::os::unix::fs::DirBuilderExt;
    let dir = std::env::temp_dir().join(format!("ipcdircr-{}-{test}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    dir
}

/// Connects with the crate's blocking connection; the server uid is the one
/// the test configured (module documentation).
struct SocketConnector {
    path: PathBuf,
}

struct SocketConnection(UnixConnection);

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
        Ok(DIRD_UID)
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

/// A client connected over the socket (its start-time `DescribeDomain`
/// served by the scripted dird, task R9).
fn socket_client(path: &Path) -> DirectoryClient<SocketConnector> {
    DirectoryClient::connect(
        SocketConnector {
            path: path.to_path_buf(),
        },
        DIRD_UID,
        Duration::from_secs(2),
        VERSION,
    )
    .unwrap()
}

/// The scripted dird's side: one request, or `None` at the end of the
/// stream.
fn read_request(stream: &mut UnixStream) -> Option<Request> {
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

fn write_reply(stream: &mut UnixStream, reply: &DirectoryReply) {
    let frame = encode_frame(DIRECTORY_CHANNEL, Direction::Reply, reply).unwrap();
    stream.write_all(frame.as_bytes()).unwrap();
}

/// The scripted dird: `Ping`, `DescribeDomain`, `BeginView`, `EndView`.
fn reply_to(request: &Request) -> DirectoryReply {
    match request {
        Request::Ping => DirectoryReply::Pong,
        Request::DescribeDomain => DirectoryReply::from_domain(&domain()),
        Request::BeginView => begun(1),
        Request::EndView { .. } => DirectoryReply::ViewEnded,
        Request::Query { .. } => panic!("not scripted"),
    }
}

/// Answer every request until the peer closes; the kinds served.
fn serve(mut stream: UnixStream) -> Vec<Kind> {
    let mut served = Vec::new();
    while let Some(request) = read_request(&mut stream) {
        write_reply(&mut stream, &reply_to(&request));
        served.push(kind(&request));
    }
    served
}

/// docs/50 §3.6, §3.7; Q-311, Q-312 (A-82): dird is stopped and started
/// again on the same path while the kdc's client holds its idle connection;
/// the first request afterwards is served by the new dird on a fresh
/// connection — after the new connection's `DescribeDomain` matched.
#[test]
fn after_a_dird_restart_the_first_request_is_served_on_a_fresh_connection() {
    let dir = private_dir("restart");
    let path = dir.join("d.sock");
    let old = UnixListener::bind(&path).unwrap();
    let (stop, wait_stop) = mpsc::channel::<()>();
    let old = thread::spawn(move || {
        let (mut stream, _) = old.accept().unwrap();
        let request = read_request(&mut stream).unwrap();
        write_reply(&mut stream, &reply_to(&request));
        wait_stop.recv().unwrap();
        kind(&request)
    });
    let mut client = socket_client(&path);
    assert_eq!(client.domain(), &domain());
    stop.send(()).unwrap();
    assert_eq!(old.join().unwrap(), Kind::DescribeDomain);
    std::fs::remove_file(&path).unwrap();
    let new = UnixListener::bind(&path).unwrap();
    let new = thread::spawn(move || serve(new.accept().unwrap().0));

    let view = client
        .begin_view()
        .expect("the first request after the restart");
    drop(view);
    drop(client);
    assert_eq!(
        new.join().unwrap(),
        [Kind::DescribeDomain, Kind::BeginView, Kind::EndView]
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// docs/50 R50-7; Q-312 (A-82): a whole reply frame waiting on the idle
/// connection (another view, another policy version) is not taken as the
/// reply to the next `BeginView`: the connection is dropped unread and the
/// request is served on a fresh one.
#[test]
fn a_frame_waiting_on_an_idle_connection_is_never_read_as_a_reply() {
    let dir = private_dir("pending");
    let path = dir.join("d.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let (written, wait_written) = mpsc::channel();
    let server = thread::spawn(move || {
        let (mut first, _) = listener.accept().unwrap();
        let mut on_first = Vec::new();
        for _ in 0..2 {
            let request = read_request(&mut first).unwrap();
            write_reply(&mut first, &reply_to(&request));
            on_first.push(kind(&request));
        }
        write_reply(
            &mut first,
            &DirectoryReply::ViewBegun {
                view: 99,
                policy_version: 8,
            },
        );
        written.send(()).unwrap();
        let on_second = serve(listener.accept().unwrap().0);
        let more_on_first = read_request(&mut first).map(|request| kind(&request));
        (on_first, more_on_first, on_second)
    });
    let mut client = socket_client(&path);
    assert_eq!(client.ping(), Ok(()));
    wait_written.recv().unwrap();
    let view = client.begin_view().expect("not the waiting frame");
    assert_eq!(view.id(), 1);
    drop(view);
    drop(client);
    let (on_first, more_on_first, on_second) = server.join().unwrap();
    assert_eq!(on_first, [Kind::DescribeDomain, Kind::Ping]);
    assert_eq!(more_on_first, None, "nothing more was sent on it");
    assert_eq!(
        on_second,
        [Kind::DescribeDomain, Kind::BeginView, Kind::EndView]
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// Q-312 (A-82: no blind resend): dird receives `BeginView` and goes away
/// before answering; the request is not sent again, on any connection.
#[test]
fn a_request_lost_after_it_was_sent_is_not_resent_over_a_socket() {
    let dir = private_dir("noresend");
    let path = dir.join("d.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let (gone, wait_gone) = mpsc::channel::<()>();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        // The start-time DescribeDomain (task R9), served.
        let describe = read_request(&mut stream).unwrap();
        write_reply(&mut stream, &reply_to(&describe));
        let request = read_request(&mut stream).unwrap();
        drop(stream);
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
        (kind(&request), later)
    });
    let mut client = socket_client(&path);
    assert!(matches!(
        client.begin_view().err(),
        Some(Unserved::Transport(_))
    ));
    assert!(!client.is_connected());
    gone.send(()).unwrap();
    let (request, later) = server.join().unwrap();
    assert_eq!(request, Kind::BeginView);
    assert_eq!(later, 0, "no new connection, no second request");
    let _ = std::fs::remove_dir_all(dir);
}

/// docs/50 §3.6: the real blocking connection's idle check — usable while
/// nothing waits, `Framing` for a waiting octet, `Closed` after the peer
/// closed.
#[test]
fn the_blocking_connections_idle_check() {
    let (client_end, mut peer) = UnixStream::pair().unwrap();
    let mut connection = UnixConnection::from_stream(client_end);
    assert_eq!(connection.check_idle(), Ok(()));
    peer.write_all(&[0]).unwrap();
    assert_eq!(connection.check_idle(), Err(TransportError::Framing));
    let (client_end, peer) = UnixStream::pair().unwrap();
    let mut connection = UnixConnection::from_stream(client_end);
    drop(peer);
    assert_eq!(connection.check_idle(), Err(TransportError::Closed));
}
