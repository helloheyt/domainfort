//! The keyd client's connection rules (docs/50 §9 tiers 1 and 2):
//!
//! * **Q-466 (A-102, task R9)** — a client exists only with an
//!   `ExpectedPeer`: on every new connection, before anything else is sent,
//!   keyd's uid, then the caller role keyd resolves for this process — the
//!   connection's `Ping` probe (every role may ping; the reply names the
//!   role), or `DescribeConfig` when a description is expected. A keyd of
//!   another uid, another role or another realm receives **no request**:
//!   the call is `Unavailable` and **not sent**. The attack tests here wire a
//!   client of each role to such a keyd and send it state calls.
//! * **Q-312** — a held connection is checked, without blocking and without
//!   sending, before it is reused: a dead one (keyd restarted while it was
//!   idle) or one with octets waiting is dropped and a fresh, verified
//!   connection serves the call; a call that failed after it was sent is
//!   never sent again.
//! * **Q-311 / Q-351** — `IpcKeyd` expects every new connection to describe
//!   the keyd it started from, with the caller role `Kdc`: keyd's refusal
//!   (a role that may not call `DescribeConfig`), another description or
//!   another role is `Unavailable` (the KDC's 29), never keyd's `Denied` of
//!   the operation (24).
//! * **Q-367** (A-88) — `call_with_fate` (and every typed state method)
//!   tells a request that was **not sent**, one keyd refused (**not
//!   performed**), and one written without a usable answer (**outcome
//!   unknown**); a state call has no other path (`call` takes only an
//!   `IssuanceCall` — the API shape, tests/messages.rs and the compile-fail
//!   examples of `ipc_keyd::IssuanceCall`).
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
//! Ldap; `Ping` — every role), §3.6 (idle connections held; one deadline per
//! call), §3.7, §7.5 step 4, §9; docs/10 §2, §7א, §10; docs/52 §3.10,
//! §3.12, §7 R9; docs/questions/Q-311, Q-312 (A-82), Q-351 (A-87), Q-365,
//! Q-367 (A-88), Q-403 option (c), Q-466 (A-102). Every value is
//! constructed by hand (tests/samples).
#![cfg(unix)]

mod samples;

use core::time::Duration;
use ipc::{encode_refused, FrameLimit, FrameReader, Refused, Reply};
use ipc_keyd::{
    decode_request, encode_answer, Answer, Call, CallFailure, ClientConfigError, Connection,
    Connector, DescribedConfig, ExpectedDescription, ExpectedPeer, IpcKeyd, IssuanceCall,
    KeydClient, RequestFate, TransportError, UnixConnection, Unserved, KEYD_CHANNEL, REQUEST_LIMIT,
};
use keyd_types::{
    AccountKind, AuthnError, ConfigDescription, DecidedOperation, DecisionId, KeyCustody,
    KeyPurpose, Kvno, Operation, Role,
};
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

/// The four phase-1 roles (docs/10 §2).
const ROLES: [Role; 4] = [Role::Kdc, Role::Directory, Role::Admin, Role::Ldap];

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

/// keyd's `Ping` answer for a caller it resolved to `role` (Q-466 item 2).
fn pong(role: Role) -> Answer {
    Answer::Ping(Ok(role))
}

/// A key-state change (docs/10 §10): `create_key` (Role::Admin).
fn create_key() -> Call {
    Call::CreateKey {
        handle: samples::handle(0xB2, KeyPurpose::Service),
        binding: samples::binding(),
    }
}

/// A key-state change: `set_secret` (Role::Directory).
fn set_secret() -> Call {
    Call::SetSecret {
        handle: samples::handle(0xA1, KeyPurpose::PrincipalLongterm),
        binding: samples::binding(),
        password: samples::password("correct horse battery staple"),
        salt: String::from("EXAMPLE.ORGalice"),
    }
}

/// A call that loosens keyd: `register_decision` (Role::Ldap).
fn register_decision() -> Call {
    Call::RegisterDecision {
        id: DecisionId::new(7),
        operation: DecidedOperation::SetSecret {
            kind: AccountKind::User,
            targets: vec![samples::alice_target()],
        },
        approvers: Vec::new(),
        lifetime_secs: 30,
    }
}

/// The state call a client of `role` would send.
fn state_call_of(role: Role) -> Call {
    match role {
        Role::Directory => set_secret(),
        Role::Ldap => register_decision(),
        Role::Admin | Role::Kdc => create_key(),
    }
}

/// `call` as an issuance call (it is not a state call).
fn issuance(call: Call) -> IssuanceCall {
    IssuanceCall::new(call).expect("not a state call")
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
    /// The peer uid the connections report; `None` ⇒ keyd's.
    peer_uid: Option<u32>,
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
        Ok(self.script.borrow().peer_uid.unwrap_or(KEYD_UID))
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

/// A client of `role` (no description expected) over a scripted keyd.
fn scripted(role: Role) -> (Rc<RefCell<Script>>, KeydClient<ScriptConnector>) {
    scripted_with(
        ExpectedPeer::new(KEYD_UID, role).unwrap(),
        Duration::from_secs(2),
    )
}

fn scripted_with(
    peer: ExpectedPeer,
    deadline: Duration,
) -> (Rc<RefCell<Script>>, KeydClient<ScriptConnector>) {
    let script = Rc::new(RefCell::new(Script::default()));
    let client = KeydClient::new(ScriptConnector(Rc::clone(&script)), peer, deadline);
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

// ---- tier 1: the expected peer (task R9) ------------------------------------------

/// docs/50 §3.2 ("uid 0 is never mapped"); docs/10 §2 (`DescribeConfig` —
/// Kdc, Ldap only); Q-466 item 1: the expectation is checked when it is
/// made — keyd's uid 0 is refused, and so is a description expected of a
/// role that may not call `DescribeConfig` (it would refuse every
/// connection). Kdc and Ldap may expect one.
#[test]
fn an_unacceptable_expectation_is_refused_when_it_is_made() {
    for role in ROLES {
        assert_eq!(
            ExpectedPeer::new(0, role),
            Err(ClientConfigError::RootServerUid)
        );
        let peer = ExpectedPeer::new(KEYD_UID, role).unwrap();
        assert_eq!(
            (peer.uid(), peer.role(), peer.description()),
            (KEYD_UID, role, None)
        );
        let with = peer.with_description(ExpectedDescription::Realm(samples::realm()));
        match role {
            Role::Kdc | Role::Ldap => assert_eq!(
                with.unwrap().description(),
                Some(&ExpectedDescription::Realm(samples::realm()))
            ),
            Role::Directory | Role::Admin => {
                assert_eq!(with, Err(ClientConfigError::DescriptionNotCallable))
            }
        }
    }
}

/// docs/50 R50-3; Q-466 items 1-2 (A-102): a client of each role verifies
/// every new connection before its first call — with `Ping` (every role may
/// ping) when no description is expected, with `DescribeConfig` when one
/// is — and then carries its calls on that connection.
#[test]
fn every_new_connection_is_probed_before_the_first_call() {
    for role in ROLES {
        let (script, mut client) = scripted(role);
        answer(&script, pong(role));
        answer(&script, pong(role));
        assert_eq!(client.ping(), Ok(role));
        assert_eq!(
            script.borrow().carried,
            [[Operation::Ping, Operation::Ping]]
        );
    }
    for role in [Role::Kdc, Role::Ldap] {
        let peer = ExpectedPeer::new(KEYD_UID, role)
            .unwrap()
            .with_description(ExpectedDescription::Realm(samples::realm()))
            .unwrap();
        let (script, mut client) = scripted_with(peer, Duration::from_secs(2));
        answer(&script, described_as(description(), role));
        answer(&script, pong(role));
        assert_eq!(client.ping(), Ok(role));
        assert_eq!(
            script.borrow().carried,
            [[Operation::DescribeConfig, Operation::Ping]]
        );
    }
}

/// **Attack test** — docs/50 R50-3, §3.7; docs/52 §3.12 (C12); Q-466 items
/// 1-2 (A-102): a client of each role wired to a keyd that resolves its uid
/// to **another role** sends that keyd no state call. Its state call
/// (`set_secret` for Directory, `register_decision` for Ldap, `create_key`
/// for Admin and Kdc) is **not sent** (`PeerMismatch`): the new connection
/// carried only the `Ping` probe, and was dropped. The same through the
/// typed state methods.
#[test]
fn a_keyd_resolving_another_role_receives_no_state_call() {
    for role in ROLES {
        for other in ROLES.into_iter().filter(|other| *other != role) {
            let (script, mut client) = scripted(role);
            answer(&script, pong(other));
            assert_eq!(
                client.call_with_fate(&state_call_of(role)),
                Err(CallFailure {
                    unserved: Unserved::PeerMismatch,
                    fate: RequestFate::NotSent,
                }),
                "{role:?} wired to a keyd that resolves it to {other:?}"
            );
            assert!(!client.is_connected());
            assert_eq!(script.borrow().carried, [[Operation::Ping]]);
        }
    }
    // The typed state methods: the same fate, nothing but the probe sent.
    let (script, mut client) = scripted(Role::Directory);
    answer(&script, pong(Role::Admin));
    assert_eq!(
        client.set_secret(
            &samples::handle(0xA1, KeyPurpose::PrincipalLongterm),
            &samples::binding(),
            Zeroizing::new(String::from("correct horse battery staple")),
            "EXAMPLE.ORGalice",
        ),
        Err(CallFailure {
            unserved: Unserved::PeerMismatch,
            fate: RequestFate::NotSent,
        })
    );
    let (script2, mut admin) = scripted(Role::Admin);
    answer(&script2, pong(Role::Directory));
    assert_eq!(
        admin.rotate_krbtgt(DecisionId::new(9)),
        Err(CallFailure {
            unserved: Unserved::PeerMismatch,
            fate: RequestFate::NotSent,
        })
    );
    assert_eq!(script.borrow().carried, [[Operation::Ping]]);
    assert_eq!(script2.borrow().carried, [[Operation::Ping]]);
}

/// **Attack test** — docs/50 §3.4, §3.7, §7.5 step 4; Q-311, Q-466 item 1:
/// dird's client (Role::Ldap, its realm expected) wired to a keyd serving
/// **another realm** registers no decision there: `register_decision` is
/// not sent, the connection carried only `DescribeConfig`. A keyd of the
/// right realm whose other settings differ is admitted (dird expects the
/// realm, not the whole description).
#[test]
fn a_keyd_of_another_realm_receives_no_state_call() {
    let peer = ExpectedPeer::new(KEYD_UID, Role::Ldap)
        .unwrap()
        .with_description(ExpectedDescription::Realm(samples::realm()))
        .unwrap();
    let (script, mut client) = scripted_with(peer.clone(), Duration::from_secs(2));
    answer(&script, described_as(other_description(), Role::Ldap));
    assert_eq!(
        client.call_with_fate(&register_decision()),
        Err(CallFailure {
            unserved: Unserved::PeerMismatch,
            fate: RequestFate::NotSent,
        })
    );
    assert_eq!(script.borrow().carried, [[Operation::DescribeConfig]]);

    let (script, mut client) = scripted_with(peer, Duration::from_secs(2));
    let mut same_realm = description();
    same_realm.clock_skew_secs += 1;
    answer(&script, described_as(same_realm, Role::Ldap));
    answer(&script, Answer::RegisterDecision(Ok(())));
    assert_eq!(
        client.call_with_fate(&register_decision()),
        Ok(Answer::RegisterDecision(Ok(())))
    );
    assert_eq!(
        script.borrow().carried,
        [[Operation::DescribeConfig, Operation::RegisterDecision]]
    );
}

/// **Attack test** — docs/50 R50-3 ("the client also verifies the server's
/// uid"), §3.2; A-63: a process of **another uid** on keyd's socket path
/// receives nothing at all — not even the probe — whatever the client's
/// role; the state call is not sent.
#[test]
fn a_peer_of_another_uid_receives_nothing() {
    for role in ROLES {
        let (script, mut client) = scripted(role);
        script.borrow_mut().peer_uid = Some(KEYD_UID + 1);
        assert_eq!(
            client.call_with_fate(&state_call_of(role)),
            Err(CallFailure {
                unserved: Unserved::PeerMismatch,
                fate: RequestFate::NotSent,
            })
        );
        assert_eq!(script.borrow().carried, [Vec::<Operation>::new()]);
    }
}

/// docs/50 R50-3, R50-8, §3.7; Q-466 items 1-2: the probe failures map to
/// `Unserved` cases that are all `Unavailable` for the caller and **not
/// sent**: keyd's refusal of the probe and another role or description are
/// `PeerMismatch`; the shared refusal and a failed exchange are what they
/// are; an answer of another operation is `UnexpectedReply`.
#[test]
fn the_probe_failures_are_not_served() {
    let kdc_described = ExpectedPeer::new(KEYD_UID, Role::Kdc)
        .unwrap()
        .with_description(ExpectedDescription::Exact(description()))
        .unwrap();
    let cases: Vec<(
        ExpectedPeer,
        Result<Reply<Answer>, TransportError>,
        Unserved,
    )> = vec![
        (
            ExpectedPeer::new(KEYD_UID, Role::Admin).unwrap(),
            Ok(Reply::Message(Answer::Ping(Err(keyd_types::Error::Denied)))),
            Unserved::PeerMismatch,
        ),
        (
            ExpectedPeer::new(KEYD_UID, Role::Admin).unwrap(),
            Ok(Reply::Message(pong(Role::Kdc))),
            Unserved::PeerMismatch,
        ),
        (
            ExpectedPeer::new(KEYD_UID, Role::Admin).unwrap(),
            Ok(Reply::Refused(Refused::Busy)),
            Unserved::Refused(Refused::Busy),
        ),
        (
            ExpectedPeer::new(KEYD_UID, Role::Admin).unwrap(),
            Err(TransportError::Closed),
            Unserved::Transport(TransportError::Closed),
        ),
        (
            ExpectedPeer::new(KEYD_UID, Role::Admin).unwrap(),
            Ok(Reply::Message(described_as(description(), Role::Admin))),
            Unserved::UnexpectedReply(ipc_keyd::ConversionError::UnexpectedReply),
        ),
        (
            kdc_described.clone(),
            Ok(Reply::Message(Answer::DescribeConfig(Err(
                keyd_types::Error::Denied,
            )))),
            Unserved::PeerMismatch,
        ),
        (
            kdc_described.clone(),
            Ok(Reply::Message(described_as(other_description(), Role::Kdc))),
            Unserved::PeerMismatch,
        ),
        (
            kdc_described,
            Ok(Reply::Message(described_as(description(), Role::Ldap))),
            Unserved::PeerMismatch,
        ),
    ];
    for (n, (peer, probe, expected)) in cases.into_iter().enumerate() {
        let probe_operation = if peer.description().is_some() {
            Operation::DescribeConfig
        } else {
            Operation::Ping
        };
        let (script, mut client) = scripted_with(peer, Duration::from_secs(2));
        script.borrow_mut().answers.push_back(probe);
        assert_eq!(
            client.call_with_fate(&create_key()),
            Err(CallFailure {
                unserved: expected,
                fate: RequestFate::NotSent,
            }),
            "case {n}"
        );
        assert!(!client.is_connected());
        assert_eq!(script.borrow().carried, [[probe_operation]], "case {n}");
    }
}

/// docs/50 §3.6, §3.7, R50-7; Q-312 (A-82), Q-466 item 4: a held connection
/// whose idle check finds the end of the stream (keyd went away) or a
/// waiting octet (a protocol error) is dropped **before** the call; the
/// call goes, once, on a fresh connection — verified first — and nothing is
/// sent on the old one.
#[test]
fn a_held_connection_failing_its_idle_check_is_replaced_before_the_call() {
    for failure in [TransportError::Closed, TransportError::Framing] {
        let (script, mut client) = scripted(Role::Directory);
        answer(&script, pong(Role::Directory));
        answer(&script, pong(Role::Directory));
        assert_eq!(client.ping(), Ok(Role::Directory));
        assert!(client.is_connected());
        script.borrow_mut().stale.insert(0, failure);
        answer(&script, pong(Role::Directory));
        answer(&script, Answer::SetSecret(Ok(Kvno::INITIAL)));
        assert_eq!(
            client.call_with_fate(&set_secret()),
            Ok(Answer::SetSecret(Ok(Kvno::INITIAL))),
            "{failure:?}"
        );
        let script = script.borrow();
        assert_eq!(script.connects(), 2);
        assert_eq!(
            script.carried[0],
            [Operation::Ping, Operation::Ping],
            "nothing more on it"
        );
        assert_eq!(script.carried[1], [Operation::Ping, Operation::SetSecret]);
    }
}

/// docs/50 §3.6: a held connection that passes its idle check is reused
/// (one connection, one probe, many calls, R50-7).
#[test]
fn a_usable_held_connection_is_reused() {
    let (script, mut client) = scripted(Role::Admin);
    answer(&script, pong(Role::Admin));
    for _ in 0..3 {
        answer(&script, pong(Role::Admin));
        assert_eq!(client.ping(), Ok(Role::Admin));
    }
    assert_eq!(script.borrow().connects(), 1);
    assert_eq!(script.borrow().carried[0].len(), 4);
}

/// Q-312 (A-82: "no blind resend of a request that may already have reached
/// the server"): a call whose request was written and whose reply did not
/// come — the peer closed, the deadline passed — is `Unavailable`, the
/// connection is dropped, and the request is not sent again; the next call
/// starts on a new, verified connection.
#[test]
fn a_call_that_failed_after_it_was_sent_is_not_sent_again() {
    for failure in [TransportError::Closed, TransportError::DeadlineExceeded] {
        let (script, mut client) = scripted(Role::Kdc);
        answer(&script, pong(Role::Kdc));
        script.borrow_mut().answers.push_back(Err(failure));
        assert_eq!(client.ping(), Err(keyd_types::Error::Unavailable));
        assert!(!client.is_connected());
        assert_eq!(script.borrow().connects(), 1, "{failure:?}");
        assert_eq!(
            script.borrow().carried[0],
            [Operation::Ping, Operation::Ping],
            "the probe, then the call, once"
        );
        answer(&script, pong(Role::Kdc));
        answer(&script, pong(Role::Kdc));
        assert_eq!(client.ping(), Ok(Role::Kdc));
        assert_eq!(
            script.borrow().carried[1],
            [Operation::Ping, Operation::Ping]
        );
    }
}

/// The custody of the kdc over the scripted keyd: the client expects the
/// Kdc role (its first connection's `Ping` probe answered for the Kdc
/// caller), and the start-up `DescribeConfig` is answered with
/// [`description`] — then expected, exactly, of every new connection.
fn custody() -> (Rc<RefCell<Script>>, IpcKeyd<ScriptConnector>) {
    let (script, client) = scripted(Role::Kdc);
    answer(&script, pong(Role::Kdc));
    answer(&script, described_to_the_kdc());
    let custody = IpcKeyd::connect(client).unwrap();
    assert_eq!(custody.config(), &description());
    assert_eq!(
        custody.client().expected_peer().description(),
        Some(&ExpectedDescription::Exact(description()))
    );
    assert_eq!(custody.client().expected_peer().role(), Role::Kdc);
    assert_eq!(
        script.borrow().carried,
        [[Operation::Ping, Operation::DescribeConfig]]
    );
    (script, custody)
}

/// docs/50 §7.5 step 4, §3.7; docs/10 §2; Q-351 (A-87: "the kdc's client
/// requires Role::Kdc"), Q-466: a keyd that resolves the kdc's uid to
/// another role gives no custody — `IpcKeyd::connect` is `Unavailable` (the
/// kdc does not start) with only the `Ping` probe sent (not even
/// `DescribeConfig`); a keyd whose probe says Kdc but whose `DescribeConfig`
/// says otherwise is refused too; and a client that expects another role
/// cannot become the kdc's custody at all (nothing is sent).
#[test]
fn ipc_keyd_does_not_start_on_a_keyd_that_gives_it_another_role() {
    for role in [Role::Ldap, Role::Directory, Role::Admin] {
        let (script, client) = scripted(Role::Kdc);
        answer(&script, pong(role));
        assert_eq!(
            IpcKeyd::connect(client).map(|_| ()),
            Err(keyd_types::Error::Unavailable),
            "{role:?}"
        );
        assert_eq!(script.borrow().carried, [[Operation::Ping]]);
    }
    let (script, client) = scripted(Role::Kdc);
    answer(&script, pong(Role::Kdc));
    answer(&script, described_as(description(), Role::Ldap));
    assert_eq!(
        IpcKeyd::connect(client).map(|_| ()),
        Err(keyd_types::Error::Unavailable)
    );
    assert_eq!(
        script.borrow().carried,
        [[Operation::Ping, Operation::DescribeConfig]]
    );
    for role in [Role::Ldap, Role::Directory, Role::Admin] {
        let (script, client) = scripted(role);
        assert_eq!(
            IpcKeyd::connect(client).map(|_| ()),
            Err(keyd_types::Error::Unavailable)
        );
        assert!(script.borrow().carried.is_empty(), "{role:?}");
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
    let refusals = [
        Answer::DescribeConfig(Err(keyd_types::Error::Denied)),
        described_as(other_description(), Role::Kdc),
        described_as(description(), Role::Ldap),
        described_as(description(), Role::Directory),
        described_as(description(), Role::Admin),
        pong(Role::Kdc),
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
    // That verified connection is reused without a second probe.
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

// ---- tier 1: the fate of a request keyd did not answer (Q-367, A-88) --------------------

/// Q-367 (A-88: "a client-side deadline or transport failure **after** the
/// request was sent is reported as 'outcome unknown — check before
/// retrying'"); docs/50 §3.6, §3.7; Q-466 item 3: a state request
/// (`create_key`) that was written and never answered — the deadline
/// passed, keyd closed, an I/O failure, a reply that did not frame — or
/// answered with a reply that does not belong to it is **outcome unknown**,
/// through `call_with_fate` and through the typed state method alike (there
/// is no fate-dropping path for it). It was sent exactly once, after the
/// probe; the connection is dropped.
#[test]
fn a_state_request_left_unanswered_is_outcome_unknown() {
    for failure in [
        TransportError::DeadlineExceeded,
        TransportError::Closed,
        TransportError::Io,
        TransportError::Framing,
    ] {
        let (script, mut client) = scripted(Role::Admin);
        answer(&script, pong(Role::Admin));
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
            [[Operation::Ping, Operation::CreateKey]],
            "sent once"
        );
        answer(&script, pong(Role::Admin));
        script.borrow_mut().answers.push_back(Err(failure));
        assert_eq!(
            client.create_key(
                &samples::handle(0xB2, KeyPurpose::Service),
                &samples::binding()
            ),
            Err(CallFailure {
                unserved: Unserved::Transport(failure),
                fate: RequestFate::OutcomeUnknown,
            })
        );
    }
    let (script, mut client) = scripted(Role::Admin);
    answer(&script, pong(Role::Admin));
    answer(&script, pong(Role::Admin));
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
/// request it cannot decode is not run): keyd's shared refusal of a state
/// request is **not performed**, for every `Refused` code, through
/// `call_with_fate` and the typed state method alike. keyd's own
/// `Unavailable` answer is keyd's answer, not a failure.
#[test]
fn keyds_refusal_of_a_state_request_is_not_performed() {
    for refused in [
        Refused::Unavailable,
        Refused::Busy,
        Refused::Malformed,
        Refused::VersionMismatch,
    ] {
        let (script, mut client) = scripted(Role::Admin);
        answer(&script, pong(Role::Admin));
        refuse(&script, refused);
        assert_eq!(
            client.call_with_fate(&create_key()),
            Err(CallFailure {
                unserved: Unserved::Refused(refused),
                fate: RequestFate::NotPerformed,
            }),
            "{refused:?}"
        );
        assert_eq!(
            script.borrow().carried,
            [[Operation::Ping, Operation::CreateKey]]
        );
        answer(&script, pong(Role::Admin));
        refuse(&script, refused);
        assert_eq!(
            client.create_key(
                &samples::handle(0xB2, KeyPurpose::Service),
                &samples::binding()
            ),
            Err(CallFailure {
                unserved: Unserved::Refused(refused),
                fate: RequestFate::NotPerformed,
            })
        );
    }
    let (script, mut client) = scripted(Role::Admin);
    answer(&script, pong(Role::Admin));
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
        client.create_key(
            &samples::handle(0xB2, KeyPurpose::Service),
            &samples::binding()
        ),
        Ok(Ok(Kvno::INITIAL))
    );
}

/// docs/50 R50-3, §3.6, §3.7; Q-367 (A-88): a request that never left the
/// process is **not sent** — the connection could not be opened, or the
/// deadline passed before the request was written (the probe of the new
/// connection then has no time either).
#[test]
fn a_failure_before_sending_is_not_sent() {
    let (script, mut client) = scripted(Role::Admin);
    script.borrow_mut().connect_fails = Some(TransportError::Connect);
    assert_eq!(
        client.call_with_fate(&create_key()),
        Err(CallFailure {
            unserved: Unserved::Transport(TransportError::Connect),
            fate: RequestFate::NotSent,
        })
    );
    assert!(script.borrow().carried.is_empty());

    let (script, mut client) = scripted_with(
        ExpectedPeer::new(KEYD_UID, Role::Admin).unwrap(),
        Duration::ZERO,
    );
    assert_eq!(
        client.call_with_fate(&create_key()),
        Err(CallFailure {
            unserved: Unserved::Transport(TransportError::DeadlineExceeded),
            fate: RequestFate::NotSent,
        })
    );
    assert_eq!(script.borrow().carried, [Vec::<Operation>::new()]);
}

/// docs/50 §3.7 (R50-8); Q-466 item 3: `call` — which takes only an
/// `IssuanceCall` and reports `Unserved` without a fate — serves the calls
/// that are not state calls, with the same verification of the new
/// connection.
#[test]
fn the_plain_call_serves_issuance_calls() {
    let (script, mut client) = scripted(Role::Admin);
    answer(&script, pong(Role::Admin));
    answer(&script, Answer::SealCeremony(Ok(())));
    assert_eq!(
        client.call(&issuance(Call::SealCeremony)),
        Ok(Answer::SealCeremony(Ok(())))
    );
    refuse(&script, Refused::Busy);
    assert_eq!(
        client.call(&issuance(Call::Ping)),
        Err(Unserved::Refused(Refused::Busy))
    );
    assert_eq!(
        script.borrow().carried,
        [[Operation::Ping, Operation::SealCeremony, Operation::Ping]]
    );
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

/// A client of `role` over the socket at `path`, with `deadline`.
fn socket_client(path: &Path, role: Role, deadline: Duration) -> KeydClient<SocketConnector> {
    KeydClient::new(
        SocketConnector::new(path),
        ExpectedPeer::new(KEYD_UID, role).unwrap(),
        deadline,
    )
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

/// The scripted keyd's answer to a caller it resolves to Kdc: `Ping` and
/// `DescribeConfig` only.
fn answer_to(call: &Call) -> Answer {
    match call {
        Call::Ping => pong(Role::Kdc),
        Call::DescribeConfig => described_to_the_kdc(),
        other => panic!("not scripted: {:?}", other.operation()),
    }
}

/// Answer `count` requests on `stream`; their operations.
fn answer_some(stream: &mut UnixStream, count: usize) -> Vec<Operation> {
    let mut served = Vec::with_capacity(count);
    for _ in 0..count {
        let call = read_request(stream).unwrap();
        write_answer(stream, &answer_to(&call));
        served.push(call.operation());
    }
    served
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

/// docs/50 §3.6, §3.7; Q-312 (A-82), Q-466: keyd is stopped (its connection
/// and its listener go) and started again on the same path while the
/// client holds its idle connection; the client's **first** call afterwards
/// is served by the new keyd, on a fresh connection verified first.
#[test]
fn after_a_keyd_restart_the_first_call_is_served_on_a_fresh_connection() {
    let dir = private_dir("restart");
    let path = dir.join("keyd.sock");
    let old = UnixListener::bind(&path).unwrap();
    let (stop, wait_stop) = mpsc::channel::<()>();
    let old = thread::spawn(move || {
        let (mut stream, _) = old.accept().unwrap();
        let served = answer_some(&mut stream, 2);
        wait_stop.recv().unwrap();
        served
        // The old keyd stops: stream and listener dropped.
    });
    let mut client = socket_client(&path, Role::Kdc, Duration::from_secs(2));
    assert_eq!(client.ping(), Ok(Role::Kdc));
    assert!(client.is_connected(), "the connection is held, idle");
    stop.send(()).unwrap();
    assert_eq!(old.join().unwrap(), [Operation::Ping, Operation::Ping]);
    std::fs::remove_file(&path).unwrap();
    let new = UnixListener::bind(&path).unwrap();
    let new = thread::spawn(move || serve(new.accept().unwrap().0));

    assert_eq!(
        client.ping(),
        Ok(Role::Kdc),
        "the first call after the restart"
    );
    assert_eq!(client.describe_config(), Ok(description()));
    drop(client);
    assert_eq!(
        new.join().unwrap(),
        [Operation::Ping, Operation::Ping, Operation::DescribeConfig]
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
        let on_first = answer_some(&mut first, 2);
        write_answer(&mut first, &described_as(other_description(), Role::Kdc));
        written.send(()).unwrap();
        let on_second = serve(listener.accept().unwrap().0);
        let more_on_first = read_request(&mut first).map(|call| call.operation());
        (on_first, more_on_first, on_second)
    });
    let mut client = socket_client(&path, Role::Kdc, Duration::from_secs(2));
    assert_eq!(client.describe_config(), Ok(description()));
    wait_written.recv().unwrap();
    assert_eq!(
        client.describe_config(),
        Ok(description()),
        "the waiting frame was not taken as the reply"
    );
    drop(client);
    let (on_first, more_on_first, on_second) = server.join().unwrap();
    assert_eq!(on_first, [Operation::Ping, Operation::DescribeConfig]);
    assert_eq!(more_on_first, None, "nothing more was sent on it");
    assert_eq!(on_second, [Operation::Ping, Operation::DescribeConfig]);
    let _ = std::fs::remove_dir_all(dir);
}

/// Q-312 (A-82: "no blind resend"): keyd answers the probe, receives the
/// request and goes away before answering; the call is `Unavailable`, the
/// connection dropped, and the client neither reconnects nor sends the
/// request again.
#[test]
fn a_request_lost_after_it_was_sent_is_not_resent_over_a_socket() {
    let dir = private_dir("noresend");
    let path = dir.join("keyd.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let (gone, wait_gone) = mpsc::channel::<()>();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let probe = answer_some(&mut stream, 1);
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
        (probe, call.operation(), later)
    });
    let mut client = socket_client(&path, Role::Kdc, Duration::from_secs(2));
    assert_eq!(
        client.describe_config(),
        Err(keyd_types::Error::Unavailable)
    );
    assert!(!client.is_connected());
    gone.send(()).unwrap();
    let (probe, call, later) = server.join().unwrap();
    assert_eq!(probe, [Operation::Ping]);
    assert_eq!(call, Operation::DescribeConfig);
    assert_eq!(later, 0, "no new connection, no second request");
    drop(client);
    let _ = std::fs::remove_dir_all(dir);
}

/// What the scripted keyd of the fate tests does with the one request it
/// reads after the probe.
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

/// A scripted keyd on a fresh socket that answers the Admin client's probe,
/// reads one request and behaves as told; the client's
/// `call_with_fate(create_key)` result (deadline 300 ms), and the operation
/// keyd received.
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
        let probe = read_request(&mut stream).unwrap();
        assert_eq!(probe.operation(), Operation::Ping);
        write_answer(&mut stream, &pong(Role::Admin));
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
    let mut client = socket_client(&path, Role::Admin, Duration::from_millis(300));
    let result = client.call_with_fate(&create_key());
    assert!(!client.is_connected());
    done.send(()).unwrap();
    let received = server.join().unwrap();
    drop(client);
    let _ = std::fs::remove_dir_all(dir);
    (result, received)
}

/// Q-367 (A-88): over a real socket, a keyd that receives a state request
/// (`create_key`) and never answers it leaves the client's deadline to pass
/// after the request was written — **outcome unknown**, not "not
/// performed".
#[test]
fn over_a_socket_a_state_request_keyd_never_answers_is_outcome_unknown() {
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
    let mut client = socket_client(
        &dir.join("keyd.sock"),
        Role::Admin,
        Duration::from_millis(300),
    );
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
