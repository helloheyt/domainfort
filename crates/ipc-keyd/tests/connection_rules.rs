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
//! * **Q-351** (A-87) — that answer must also name the caller role `Kdc`,
//!   at start and on every new connection: keyd mapping the kdc's uid to
//!   Ldap (which may call `DescribeConfig` too) is `Unavailable` with only
//!   `DescribeConfig` sent.
//! * **Q-367** (A-88) — `call_with_fate` tells a request that was **not
//!   sent**, one keyd refused (**not performed**), and one written without a
//!   usable answer (**outcome unknown**).
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
//! step 4, §9; docs/10 §2, §10; docs/questions/Q-311, Q-312 (A-82), Q-351
//! (A-87), Q-365, Q-367 (A-88). Every value is constructed by hand
//! (tests/samples).
#![cfg(unix)]

mod samples;

use core::time::Duration;
use ipc::{encode_refused, FrameLimit, FrameReader, Refused, Reply};
use ipc_keyd::{
    decode_request, encode_answer, Answer, Call, CallFailure, Connection, Connector,
    DescribedConfig, IpcKeyd, KeydClient, RequestFate, TransportError, UnixConnection, Unserved,
    KEYD_CHANNEL, REQUEST_LIMIT,
};
use keyd_types::{AuthnError, ConfigDescription, KeyCustody, KeyPurpose, Kvno, Operation, Role};
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

/// keyd's `DescribeConfig` answer: `description` for a caller keyd resolved
/// to `role` (Q-351).
fn described_as(description: ConfigDescription, role: Role) -> Answer {
    Answer::DescribeConfig(Ok(DescribedConfig {
        description,
        caller_role: role,
    }))
}

/// keyd's answer to the kdc: its description, the caller role Kdc.
fn described_to_the_kdc() -> Answer {
    described_as(description(), Role::Kdc)
}

/// A key-state change (docs/10 §10): `create_key`.
fn create_key() -> Call {
    Call::CreateKey {
        handle: samples::handle(0xB2, KeyPurpose::Service),
        binding: samples::binding(),
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
    /// The replies, in order — keyd's answer or its shared refusal (an
    /// `Err` is a transport failure after the request was written).
    answers: VecDeque<Result<Reply<Answer>, TransportError>>,
    /// When set, the connector fails with it (no connection is opened).
    connect_fails: Option<TransportError>,
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
        if let Some(error) = script.connect_fails {
            return Err(error);
        }
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
        let reply = script
            .answers
            .pop_front()
            .unwrap_or(Err(TransportError::Closed))?;
        let frame = match reply {
            Reply::Message(answer) => encode_answer(&answer).unwrap(),
            Reply::Refused(refused) => encode_refused(KEYD_CHANNEL, refused).unwrap(),
        };
        Ok(Zeroizing::new(frame.body().to_vec()))
    }

    fn check_idle(&mut self) -> Result<(), TransportError> {
        match self.script.borrow().stale.get(&self.index) {
            Some(error) => Err(*error),
            None => Ok(()),
        }
    }
}

fn scripted() -> (Rc<RefCell<Script>>, KeydClient<ScriptConnector>) {
    scripted_with_deadline(Duration::from_secs(2))
}

fn scripted_with_deadline(
    deadline: Duration,
) -> (Rc<RefCell<Script>>, KeydClient<ScriptConnector>) {
    let script = Rc::new(RefCell::new(Script::default()));
    let client = KeydClient::new(ScriptConnector(Rc::clone(&script)), KEYD_UID, deadline).unwrap();
    (script, client)
}

fn answer(script: &Rc<RefCell<Script>>, answer: Answer) {
    script
        .borrow_mut()
        .answers
        .push_back(Ok(Reply::Message(answer)));
}

/// keyd's shared transport refusal as the next reply.
fn refuse(script: &Rc<RefCell<Script>>, refused: Refused) {
    script
        .borrow_mut()
        .answers
        .push_back(Ok(Reply::Refused(refused)));
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
    assert!(client.required_caller_role().is_none());
    answer(&script, Answer::Ping(Ok(())));
    assert_eq!(client.ping(), Ok(()));
    script.borrow_mut().stale.insert(0, TransportError::Closed);
    answer(&script, Answer::Ping(Ok(())));
    assert_eq!(client.ping(), Ok(()));
    assert_eq!(script.borrow().carried[1], [Operation::Ping]);
}

/// The custody of the kdc over the scripted keyd (its start-up
/// `DescribeConfig` answered with [`description`] for the Kdc caller).
fn custody() -> (Rc<RefCell<Script>>, IpcKeyd<ScriptConnector>) {
    let (script, client) = scripted();
    answer(&script, described_to_the_kdc());
    let custody = IpcKeyd::connect(client).unwrap();
    assert_eq!(custody.config(), &description());
    assert_eq!(
        custody.client().required_description(),
        Some(&description())
    );
    assert_eq!(custody.client().required_caller_role(), Some(Role::Kdc));
    (script, custody)
}

/// docs/50 §7.5 step 4, §3.7; docs/10 §2; Q-351 (A-87: "the kdc's client
/// requires Role::Kdc"): a keyd whose start-up `DescribeConfig` names
/// another caller role — this uid mapped to Ldap, which may call it; or to
/// Directory / Admin, which keyd would refuse anyway — gives no custody:
/// `IpcKeyd::connect` is `Unavailable` (the kdc does not start), and only
/// `DescribeConfig` was sent.
#[test]
fn ipc_keyd_does_not_start_on_a_keyd_that_gives_it_another_role() {
    for role in [Role::Ldap, Role::Directory, Role::Admin] {
        let (script, client) = scripted();
        answer(&script, described_as(description(), role));
        assert_eq!(
            IpcKeyd::connect(client).map(|_| ()),
            Err(keyd_types::Error::Unavailable),
            "{role:?}"
        );
        assert_eq!(script.borrow().carried, [[Operation::DescribeConfig]]);
    }
}

/// docs/50 R50-8, §3.4 (`DescribeConfig` — Kdc, Ldap), §3.7; docs/10 §2;
/// Q-351 (A-87): keyd restarted with the kdc's uid mapped to **Ldap** answers
/// the new connection's `DescribeConfig` with the right description — Ldap
/// may call it — but names the caller role Ldap: the connection is dropped
/// with only `DescribeConfig` sent, and the operation is `Unavailable` (29),
/// never keyd's `Denied` of `verify_preauth` (24); the client reports it as
/// a peer mismatch on a request that was not sent.
#[test]
fn a_new_connection_describing_the_ldap_role_is_unavailable() {
    let (script, mut custody) = custody();
    script.borrow_mut().stale.insert(0, TransportError::Closed);
    answer(&script, described_as(description(), Role::Ldap));
    assert_eq!(verify_preauth(&mut custody), Err(AuthnError::Unavailable));
    assert!(!custody.client().is_connected());
    assert_eq!(script.borrow().connects(), 2);
    assert_eq!(script.borrow().carried[1], [Operation::DescribeConfig]);

    // The same through the client's fate: not sent, a peer mismatch.
    script.borrow_mut().stale.clear();
    answer(&script, described_as(description(), Role::Ldap));
    assert_eq!(
        custody.client_mut().call_with_fate(&Call::Ping),
        Err(CallFailure {
            unserved: Unserved::PeerMismatch,
            fate: RequestFate::NotSent,
        })
    );
    assert_eq!(script.borrow().carried[2], [Operation::DescribeConfig]);

    // keyd back with the Kdc role: served on a fresh connection.
    answer(&script, described_to_the_kdc());
    answer(&script, Answer::VerifyPreauth(Ok(samples::proof())));
    assert_eq!(verify_preauth(&mut custody), Ok(()));
    assert_eq!(
        script.borrow().carried[3],
        [Operation::DescribeConfig, Operation::VerifyPreauth]
    );
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
/// another description (another realm), for the right description of
/// another caller role (Q-351, A-87), and for an answer of another
/// operation.
#[test]
fn ipc_keyd_requires_every_new_connection_to_describe_the_same_keyd() {
    let (script, mut custody) = custody();
    assert_eq!(script.borrow().carried[0], [Operation::DescribeConfig]);
    let refusals = [
        Answer::DescribeConfig(Err(keyd_types::Error::Denied)),
        described_as(other_description(), Role::Kdc),
        described_as(description(), Role::Ldap),
        described_as(description(), Role::Directory),
        described_as(description(), Role::Admin),
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
    answer(&script, described_to_the_kdc());
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
/// are `PeerMismatch`; so is another caller role (Q-351) — with the
/// description and the role required together, and with the role alone.
#[test]
fn the_describe_check_failures_are_peer_mismatch() {
    for (refusal, with_description) in [
        (Answer::DescribeConfig(Err(keyd_types::Error::Denied)), true),
        (described_as(other_description(), Role::Kdc), true),
        (described_as(description(), Role::Ldap), true),
        (
            Answer::DescribeConfig(Err(keyd_types::Error::Denied)),
            false,
        ),
        (described_as(description(), Role::Ldap), false),
    ] {
        let (script, mut client) = scripted();
        if with_description {
            client.require_description(description());
        }
        client.require_caller_role(Role::Kdc);
        answer(&script, refusal);
        assert_eq!(client.call(&Call::Ping), Err(Unserved::PeerMismatch));
        assert!(!client.is_connected());
        assert_eq!(script.borrow().carried[0], [Operation::DescribeConfig]);
    }
    // The role alone, answered for the Kdc caller (any description): served.
    let (script, mut client) = scripted();
    client.require_caller_role(Role::Kdc);
    answer(&script, described_as(other_description(), Role::Kdc));
    answer(&script, Answer::Ping(Ok(())));
    assert_eq!(client.ping(), Ok(()));
    assert_eq!(
        script.borrow().carried[0],
        [Operation::DescribeConfig, Operation::Ping]
    );
}

// ---- tier 1: the fate of a request keyd did not answer (Q-367, A-88) --------------------

/// Q-367 (A-88: "a client-side deadline or transport failure **after** the
/// request was sent is reported as 'outcome unknown — check before
/// retrying'"); docs/50 §3.6, §3.7: a key-state request (`create_key`) that
/// was written and never answered — the deadline passed, keyd closed, an
/// I/O failure, a reply that did not frame — or answered with a reply that
/// does not belong to it is **outcome unknown**. It was sent exactly once,
/// the connection is dropped, and `call` still reports the same `Unserved`
/// and the typed method `Unavailable` (both unchanged).
#[test]
fn a_key_state_request_left_unanswered_is_outcome_unknown() {
    for failure in [
        TransportError::DeadlineExceeded,
        TransportError::Closed,
        TransportError::Io,
        TransportError::Framing,
    ] {
        let (script, mut client) = scripted();
        script.borrow_mut().answers.push_back(Err(failure));
        assert_eq!(
            client.call_with_fate(&create_key()),
            Err(CallFailure {
                unserved: Unserved::Transport(failure),
                fate: RequestFate::OutcomeUnknown,
            }),
            "{failure:?}"
        );
        assert!(!client.is_connected());
        assert_eq!(
            script.borrow().carried,
            [[Operation::CreateKey]],
            "sent once"
        );
        script.borrow_mut().answers.push_back(Err(failure));
        assert_eq!(
            client.call(&create_key()),
            Err(Unserved::Transport(failure))
        );
        script.borrow_mut().answers.push_back(Err(failure));
        assert_eq!(
            client.create_key(
                &samples::handle(0xB2, KeyPurpose::Service),
                &samples::binding()
            ),
            Err(keyd_types::Error::Unavailable)
        );
    }
    let (script, mut client) = scripted();
    answer(&script, Answer::Ping(Ok(())));
    assert!(matches!(
        client.call_with_fate(&create_key()),
        Err(CallFailure {
            unserved: Unserved::UnexpectedReply(_),
            fate: RequestFate::OutcomeUnknown,
        })
    ));
}

/// docs/10 §10 and Q-365 items 7, 11 (A-88: keyd-daemon refuses a
/// key-state change — `Busy` while auditd is away, `Unavailable` when the
/// intent was not acknowledged in time — only before keyd runs it; a
/// request it cannot decode is not run): keyd's shared refusal of a
/// key-state request is **not performed**, for every `Refused` code. keyd's
/// own `Unavailable` answer is keyd's answer, not a failure.
#[test]
fn keyds_refusal_of_a_key_state_request_is_not_performed() {
    for refused in [
        Refused::Unavailable,
        Refused::Busy,
        Refused::Malformed,
        Refused::VersionMismatch,
    ] {
        let (script, mut client) = scripted();
        refuse(&script, refused);
        assert_eq!(
            client.call_with_fate(&create_key()),
            Err(CallFailure {
                unserved: Unserved::Refused(refused),
                fate: RequestFate::NotPerformed,
            }),
            "{refused:?}"
        );
        assert_eq!(script.borrow().carried, [[Operation::CreateKey]]);
        refuse(&script, refused);
        assert_eq!(client.call(&create_key()), Err(Unserved::Refused(refused)));
    }
    let (script, mut client) = scripted();
    answer(
        &script,
        Answer::CreateKey(Err(keyd_types::Error::Unavailable)),
    );
    assert_eq!(
        client.call_with_fate(&create_key()),
        Ok(Answer::CreateKey(Err(keyd_types::Error::Unavailable)))
    );
    answer(&script, Answer::CreateKey(Ok(Kvno::INITIAL)));
    assert_eq!(
        client.call_with_fate(&create_key()),
        Ok(Answer::CreateKey(Ok(Kvno::INITIAL)))
    );
}

/// docs/50 R50-3, §3.6, §3.7; Q-367 (A-88): a request that never left the
/// process is **not sent** — the connection could not be opened, the
/// deadline passed before the request was written, or the new connection's
/// `DescribeConfig` check failed (only `DescribeConfig` was sent, never the
/// request).
#[test]
fn a_failure_before_sending_is_not_sent() {
    let (script, mut client) = scripted();
    script.borrow_mut().connect_fails = Some(TransportError::Connect);
    assert_eq!(
        client.call_with_fate(&create_key()),
        Err(CallFailure {
            unserved: Unserved::Transport(TransportError::Connect),
            fate: RequestFate::NotSent,
        })
    );
    assert!(script.borrow().carried.is_empty());

    let (script, mut client) = scripted_with_deadline(Duration::ZERO);
    assert_eq!(
        client.call_with_fate(&create_key()),
        Err(CallFailure {
            unserved: Unserved::Transport(TransportError::DeadlineExceeded),
            fate: RequestFate::NotSent,
        })
    );
    assert_eq!(script.borrow().carried, [Vec::<Operation>::new()]);

    for describe in [
        Err(TransportError::Closed),
        Ok(Reply::Message(described_as(description(), Role::Ldap))),
        Ok(Reply::Refused(Refused::Busy)),
    ] {
        let (script, mut client) = scripted();
        client.require_caller_role(Role::Kdc);
        let expected = match &describe {
            Err(error) => Unserved::Transport(*error),
            Ok(Reply::Refused(refused)) => Unserved::Refused(*refused),
            Ok(Reply::Message(_)) => Unserved::PeerMismatch,
        };
        script.borrow_mut().answers.push_back(describe);
        assert_eq!(
            client.call_with_fate(&create_key()),
            Err(CallFailure {
                unserved: expected,
                fate: RequestFate::NotSent,
            })
        );
        assert_eq!(script.borrow().carried, [[Operation::DescribeConfig]]);
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
        Call::DescribeConfig => described_to_the_kdc(),
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
        write_answer(&mut first, &described_as(other_description(), Role::Kdc));
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

/// What the scripted keyd of the fate tests does with the one request it
/// reads.
#[derive(Clone, Copy)]
enum Behaviour {
    /// Never answer; keep the connection open until the client is done.
    Silent,
    /// Answer with the shared refusal; keep the connection open until the
    /// client is done.
    Refuse(Refused),
    /// Answer with the shared refusal and close at once — as keyd-daemon
    /// does after `Refused::Unavailable` (Q-350 item 14: some platforms then
    /// refuse the client's read timeout).
    RefuseAndClose(Refused),
}

/// A scripted keyd on a fresh socket that reads one request and behaves as
/// told; the client's `call_with_fate(create_key)` result (deadline
/// 300 ms), and the operation keyd received.
fn fate_over_a_socket(
    test: &str,
    behaviour: Behaviour,
) -> (Result<Answer, CallFailure>, Operation) {
    let dir = private_dir(test);
    let path = dir.join("keyd.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let (done, wait_done) = mpsc::channel::<()>();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let call = read_request(&mut stream).unwrap();
        match behaviour {
            Behaviour::Silent => {}
            Behaviour::Refuse(refused) | Behaviour::RefuseAndClose(refused) => {
                stream
                    .write_all(encode_refused(KEYD_CHANNEL, refused).unwrap().as_bytes())
                    .unwrap();
            }
        }
        if matches!(behaviour, Behaviour::RefuseAndClose(_)) {
            drop(stream);
            wait_done.recv().unwrap();
        } else {
            wait_done.recv().unwrap();
            drop(stream);
        }
        call.operation()
    });
    let mut client = KeydClient::new(
        SocketConnector::new(&path),
        KEYD_UID,
        Duration::from_millis(300),
    )
    .unwrap();
    let result = client.call_with_fate(&create_key());
    assert!(!client.is_connected());
    done.send(()).unwrap();
    let received = server.join().unwrap();
    drop(client);
    let _ = std::fs::remove_dir_all(dir);
    (result, received)
}

/// Q-367 (A-88): over a real socket, a keyd that receives a key-state
/// request (`create_key`) and never answers it leaves the client's
/// deadline to pass after the request was written — **outcome unknown**,
/// not "not performed".
#[test]
fn over_a_socket_a_key_state_request_keyd_never_answers_is_outcome_unknown() {
    let (result, received) = fate_over_a_socket("silent", Behaviour::Silent);
    assert_eq!(received, Operation::CreateKey);
    assert_eq!(
        result,
        Err(CallFailure {
            unserved: Unserved::Transport(TransportError::DeadlineExceeded),
            fate: RequestFate::OutcomeUnknown,
        })
    );
}

/// docs/10 §10 (A-88: keyd's `Unavailable` on a key-state change means "not
/// performed"); docs/50 §3.3 (a refusal, then close): over a real socket,
/// keyd's shared `Refused::Unavailable` to a `create_key` it received is
/// **not performed** — also when keyd closes right after writing it, as
/// keyd-daemon does (the refusal is still read, Q-350 item 14).
#[test]
fn over_a_socket_keyds_unavailable_refusal_is_not_performed() {
    for (test, behaviour) in [
        ("refused", Behaviour::Refuse(Refused::Unavailable)),
        ("refclose", Behaviour::RefuseAndClose(Refused::Unavailable)),
    ] {
        let (result, received) = fate_over_a_socket(test, behaviour);
        assert_eq!(received, Operation::CreateKey);
        assert_eq!(
            result,
            Err(CallFailure {
                unserved: Unserved::Refused(Refused::Unavailable),
                fate: RequestFate::NotPerformed,
            }),
            "{test}"
        );
    }
}

/// docs/50 §3.7; Q-367 (A-88): no keyd listening on the path — the request
/// is **not sent**.
#[test]
fn over_a_socket_no_keyd_listening_is_not_sent() {
    let dir = private_dir("absent");
    let mut client = KeydClient::new(
        SocketConnector::new(&dir.join("keyd.sock")),
        KEYD_UID,
        Duration::from_millis(300),
    )
    .unwrap();
    assert_eq!(
        client.call_with_fate(&create_key()),
        Err(CallFailure {
            unserved: Unserved::Transport(TransportError::Connect),
            fate: RequestFate::NotSent,
        })
    );
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
