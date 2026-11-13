//! Tier 1 (docs/50 §9): the front's side of a session without a socket —
//! [`FrontChannel`]'s order and reply bounds, and [`LdapChannelClient`] over
//! an in-process loopback connection whose "dird" is a scripted list of
//! reply frames.
//!
//! * the session's order (Open first; after `Done { StartTls }` only
//!   `TlsEstablished` or `Close`; one request at a time);
//! * reassembly of parts, and the per-reply bounds;
//! * dird's uid checked before anything is sent; a root uid refused;
//! * every failure → the client connection closes, with a Notice of
//!   Disconnection (busy for `Busy`, unavailable otherwise).
//!
//! Sources: docs/50 R50-3, R50-7, R50-10, §3.3, §3.7, §4.2, §4.3, §7.5;
//! RFC 4511 §4.4.1, App. A (pinned, opened in-session); crates/ipc-ldap
//! channel documentation. Every value is hand-made.

use core::net::{IpAddr, Ipv4Addr};
use core::time::Duration;
use ipc::{decode_body, encode_frame, encode_refused, Direction, FrameLimit, Refused};
use ipc_ldap::{
    notice_of_disconnection, ping, ChannelFailure, Connection, ConnectionAction, Connector,
    FrontChannel, LdapChannelClient, LdapReply, LdapRequest, Listener, Progress, ResponsePart,
    TransportError, TransportFacts, LDAP_CHANNEL, MAX_REPLY_OCTETS, MAX_RESPONSES,
    MAX_RESPONSE_PART,
};
use parse_ldap::{
    decode_message, AuthState, DecodeOptions, Direction as LdapDirection, Profile, ProtocolOp,
    ResultCode, MAX_AUTH_MESSAGE_OCTETS, NOTICE_OF_DISCONNECTION_OID,
};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;
use zeroize::Zeroizing;

const DIRD_UID: u32 = 61010;
const PART: usize = MAX_RESPONSE_PART as usize;

fn peer() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7))
}

fn body(reply: &LdapReply) -> Vec<u8> {
    encode_frame(LDAP_CHANNEL, Direction::Reply, reply)
        .unwrap()
        .body()
        .to_vec()
}

fn part(octets: &[u8], more: bool) -> Vec<u8> {
    body(&LdapReply::Response(
        ResponsePart::new(octets, more).unwrap(),
    ))
}

fn done(action: ConnectionAction) -> Vec<u8> {
    body(&LdapReply::Done {
        action,
        framing: AuthState::Unauthenticated,
    })
}

fn opened() -> Vec<u8> {
    body(&LdapReply::Opened {
        framing: AuthState::Unauthenticated,
    })
}

fn refused(refused: Refused) -> Vec<u8> {
    encode_refused(LDAP_CHANNEL, refused)
        .unwrap()
        .body()
        .to_vec()
}

const CLEAR: TransportFacts = TransportFacts {
    tls_established: false,
    input_pending: false,
};

/// docs/50 §4.2, §4.3: Open → Opened; Message → parts, Done{Continue}; a
/// StartTLS reply allows only TlsEstablished (or Close); TlsAccepted makes
/// the session ready again; Done{Close} ends it.
#[test]
fn the_session_order() {
    let mut front = FrontChannel::new();
    assert_eq!(front.framing(), AuthState::Unauthenticated);
    // Nothing but Open (or Ping) first.
    assert_eq!(
        FrontChannel::new()
            .encode_message(&[0x30, 0x00], CLEAR)
            .err(),
        Some(ChannelFailure::OutOfSequence)
    );
    assert_eq!(
        FrontChannel::new().encode_tls_established().err(),
        Some(ChannelFailure::OutOfSequence)
    );
    front.encode_open(Listener::Ldap, peer()).unwrap();
    // One request at a time.
    let mut busy = FrontChannel::new();
    busy.encode_open(Listener::Ldap, peer()).unwrap();
    assert_eq!(
        busy.encode_message(&[0x30, 0x00], CLEAR).err(),
        Some(ChannelFailure::OutOfSequence)
    );
    assert_eq!(
        front.accept_reply(&opened()).unwrap(),
        Progress::Opened {
            framing: AuthState::Unauthenticated
        }
    );
    assert!(front.is_ready());

    front.encode_message(&[0x30, 0x00], CLEAR).unwrap();
    assert_eq!(
        front.accept_reply(&part(&[1, 2, 3], false)).unwrap(),
        Progress::Pending
    );
    match front
        .accept_reply(&done(ConnectionAction::StartTls))
        .unwrap()
    {
        Progress::Done(exchange) => {
            assert_eq!(exchange.responses, vec![vec![1, 2, 3]]);
            assert_eq!(exchange.action, ConnectionAction::StartTls);
        }
        other => panic!("{other:?}"),
    }
    assert!(front.awaits_tls());
    // After StartTls: no Message until TLS is reported up.
    let mut strict = FrontChannel::new();
    strict.encode_open(Listener::Ldap, peer()).unwrap();
    strict.accept_reply(&opened()).unwrap();
    strict.encode_message(&[0x30, 0x00], CLEAR).unwrap();
    strict
        .accept_reply(&done(ConnectionAction::StartTls))
        .unwrap();
    assert_eq!(
        strict.encode_message(&[0x30, 0x00], CLEAR).err(),
        Some(ChannelFailure::OutOfSequence)
    );

    front.encode_tls_established().unwrap();
    assert_eq!(
        front
            .accept_reply(&body(&LdapReply::TlsAccepted {
                framing: AuthState::Unauthenticated
            }))
            .unwrap(),
        Progress::TlsAccepted {
            framing: AuthState::Unauthenticated
        }
    );
    assert!(front.is_ready());
    front
        .encode_message(
            &[0x30, 0x00],
            TransportFacts {
                tls_established: true,
                input_pending: false,
            },
        )
        .unwrap();
    match front.accept_reply(&done(ConnectionAction::Close)).unwrap() {
        Progress::Done(exchange) => assert!(exchange.responses.is_empty()),
        other => panic!("{other:?}"),
    }
    assert!(front.is_finished());
}

/// docs/50 §4.2 (the framing state of the last `Done`): the framing state
/// the front applies follows dird's report.
#[test]
fn the_framing_state_follows_dird() {
    let mut front = FrontChannel::new();
    front.encode_open(Listener::Ldaps, peer()).unwrap();
    front.accept_reply(&opened()).unwrap();
    front
        .encode_message(
            &[0x30, 0x00],
            TransportFacts {
                tls_established: true,
                input_pending: false,
            },
        )
        .unwrap();
    front
        .accept_reply(&body(&LdapReply::Done {
            action: ConnectionAction::Continue,
            framing: AuthState::Authenticated,
        }))
        .unwrap();
    assert_eq!(front.framing(), AuthState::Authenticated);
}

/// crates/ipc-ldap channel documentation: parts reassemble into one
/// response; a response whose last part never came, a reply in the wrong
/// state, and a decoding failure all fail the channel.
#[test]
fn reassembly_and_order_failures() {
    let ready = || {
        let mut front = FrontChannel::new();
        front.encode_open(Listener::Ldap, peer()).unwrap();
        front.accept_reply(&opened()).unwrap();
        front.encode_message(&[0x30, 0x00], CLEAR).unwrap();
        front
    };
    let mut front = ready();
    let first = vec![0x11; PART];
    front.accept_reply(&part(&first, true)).unwrap();
    front.accept_reply(&part(&[0x22, 0x33], false)).unwrap();
    front.accept_reply(&part(&[0x44], false)).unwrap();
    match front
        .accept_reply(&done(ConnectionAction::Continue))
        .unwrap()
    {
        Progress::Done(exchange) => {
            let mut expected = first.clone();
            expected.extend_from_slice(&[0x22, 0x33]);
            assert_eq!(exchange.responses, vec![expected, vec![0x44]]);
        }
        other => panic!("{other:?}"),
    }

    let mut cut = ready();
    cut.accept_reply(&part(&first, true)).unwrap();
    assert_eq!(
        cut.accept_reply(&done(ConnectionAction::Continue)).err(),
        Some(ChannelFailure::UnexpectedReply)
    );
    assert!(cut.is_finished());

    let mut wrong = ready();
    assert_eq!(
        wrong.accept_reply(&opened()).err(),
        Some(ChannelFailure::UnexpectedReply)
    );

    let mut garbage = ready();
    assert!(matches!(
        garbage.accept_reply(&[0x4C, 0x44, 1, 0x99]).err(),
        Some(ChannelFailure::MalformedReply(_))
    ));

    let mut refusal = ready();
    assert_eq!(
        refusal.accept_reply(&refused(Refused::Busy)).err(),
        Some(ChannelFailure::Refused(Refused::Busy))
    );
}

/// crates/ipc-ldap channel documentation (per-reply bounds): more than
/// `MAX_RESPONSES` responses, or more than `MAX_REPLY_OCTETS` octets, fail
/// the channel.
#[test]
fn the_reply_bounds() {
    let ready = || {
        let mut front = FrontChannel::new();
        front.encode_open(Listener::Ldap, peer()).unwrap();
        front.accept_reply(&opened()).unwrap();
        front.encode_message(&[0x30, 0x00], CLEAR).unwrap();
        front
    };
    let mut many = ready();
    let small = part(&[0x30, 0x00], false);
    for _ in 0..MAX_RESPONSES {
        assert_eq!(many.accept_reply(&small).unwrap(), Progress::Pending);
    }
    assert_eq!(
        many.accept_reply(&small).err(),
        Some(ChannelFailure::ReplyOverBound)
    );

    // 8 responses of 1 MiB = 8 MiB, within; one more full part is over the
    // reply's octet bound (8 MiB + 64 KiB).
    let mut big = ready();
    let full = part(&vec![0x55; PART], false);
    for _ in 0..8 {
        big.accept_reply(&full).unwrap();
    }
    const _: () = assert!(9 * PART > MAX_REPLY_OCTETS);
    assert_eq!(
        big.accept_reply(&full).err(),
        Some(ChannelFailure::ReplyOverBound)
    );

    // One response of more than 8 parts is over the response bound.
    let mut long = ready();
    let more = part(&vec![0x66; PART], true);
    for _ in 0..8 {
        long.accept_reply(&more).unwrap();
    }
    assert_eq!(
        long.accept_reply(&more).err(),
        Some(ChannelFailure::ReplyOverBound)
    );
}

// ---- the blocking client over a scripted loopback --------------------------

/// What the loopback saw and what it answers.
#[derive(Default)]
struct Script {
    replies: VecDeque<Vec<u8>>,
    sent: Vec<LdapRequest>,
    connects: u32,
}

struct Loopback {
    uid: u32,
    script: Rc<RefCell<Script>>,
    refuse_connect: bool,
}

struct LoopConnection {
    uid: u32,
    script: Rc<RefCell<Script>>,
}

impl Connector for Loopback {
    type Connection = LoopConnection;
    fn connect(&mut self) -> Result<LoopConnection, TransportError> {
        if self.refuse_connect {
            return Err(TransportError::Connect);
        }
        self.script.borrow_mut().connects += 1;
        Ok(LoopConnection {
            uid: self.uid,
            script: Rc::clone(&self.script),
        })
    }
}

impl Connection for LoopConnection {
    fn peer_uid(&self) -> Result<u32, TransportError> {
        Ok(self.uid)
    }
    fn send(&mut self, frame: &[u8], _deadline: Duration) -> Result<(), TransportError> {
        let request: LdapRequest =
            decode_body(LDAP_CHANNEL, Direction::Request, &frame[4..]).unwrap();
        self.script.borrow_mut().sent.push(request);
        Ok(())
    }
    fn receive(
        &mut self,
        _limit: FrameLimit,
        _deadline: Duration,
    ) -> Result<Zeroizing<Vec<u8>>, TransportError> {
        self.script
            .borrow_mut()
            .replies
            .pop_front()
            .map(Zeroizing::new)
            .ok_or(TransportError::Closed)
    }
}

fn loopback(uid: u32, replies: Vec<Vec<u8>>) -> (Loopback, Rc<RefCell<Script>>) {
    let script = Rc::new(RefCell::new(Script {
        replies: replies.into(),
        ..Script::default()
    }));
    (
        Loopback {
            uid,
            script: Rc::clone(&script),
            refuse_connect: false,
        },
        script,
    )
}

/// docs/50 §4.2: a session over the client — Open, a Message with a
/// two-part response, Close (no reply awaited).
#[test]
fn a_session_through_the_client() {
    let (mut connector, script) = loopback(
        DIRD_UID,
        vec![
            opened(),
            part(&vec![0x77; PART], true),
            part(&[0x78], false),
            done(ConnectionAction::Continue),
        ],
    );
    let (mut client, framing) = LdapChannelClient::open(
        &mut connector,
        DIRD_UID,
        Listener::Ldap,
        peer(),
        Duration::from_secs(5),
    )
    .unwrap();
    assert_eq!(framing, AuthState::Unauthenticated);
    let exchange = client.message(&[0x30, 0x00], CLEAR).unwrap();
    assert_eq!(exchange.responses.len(), 1);
    assert_eq!(exchange.responses[0].len(), PART + 1);
    client.close();
    let sent = &script.borrow().sent;
    assert!(matches!(
        sent[0],
        LdapRequest::Open {
            listener: Listener::Ldap,
            ..
        }
    ));
    assert!(matches!(sent[1], LdapRequest::Message(_)));
    assert_eq!(sent[2], LdapRequest::Close);
}

/// docs/50 R50-3 ("the client also verifies the server's uid … receives no
/// request"; uid 0 never accepted — Q-245 item 5): a peer of another uid
/// gets nothing; a configured root uid is refused before connecting.
#[test]
fn dirds_uid_is_checked_before_anything_is_sent() {
    let (mut connector, script) = loopback(DIRD_UID + 1, vec![opened()]);
    let result = LdapChannelClient::open(
        &mut connector,
        DIRD_UID,
        Listener::Ldap,
        peer(),
        Duration::from_secs(5),
    );
    assert_eq!(result.err(), Some(ChannelFailure::PeerMismatch));
    assert!(script.borrow().sent.is_empty());

    let (mut connector, script) = loopback(0, vec![opened()]);
    let result = LdapChannelClient::open(
        &mut connector,
        0,
        Listener::Ldap,
        peer(),
        Duration::from_secs(5),
    );
    assert_eq!(result.err(), Some(ChannelFailure::RootServerUid));
    assert_eq!(script.borrow().connects, 0);
}

/// Decode a Notice of Disconnection and return its resultCode.
/// Spec: RFC 4511 §4.4.1 (responseName 1.3.6.1.4.1.1466.20036, messageID 0).
fn notice_code(octets: &[u8]) -> ResultCode {
    let msg = decode_message(
        octets,
        &DecodeOptions {
            direction: LdapDirection::Response,
            profile: Profile::Canonical,
            max_message_octets: MAX_AUTH_MESSAGE_OCTETS,
        },
    )
    .unwrap();
    assert_eq!(msg.message_id.get(), 0);
    match msg.protocol_op {
        ProtocolOp::ExtendedResponse(response) => {
            assert_eq!(
                response.response_name.as_deref(),
                Some(NOTICE_OF_DISCONNECTION_OID)
            );
            assert!(response.response_value.is_none());
            response.result.result_code
        }
        other => panic!("{other:?}"),
    }
}

/// docs/50 §3.7 ("ldap-front without dird ⇒ the connection is closed");
/// RFC 4511 §4.4.1, App. A: dird refusing `Busy` → the front's notice says
/// busy (51); dird down, dird closing, any other refusal → unavailable (52).
#[test]
fn failures_close_with_a_notice_of_disconnection() {
    // dird answers Busy to a message.
    let (mut connector, _) = loopback(DIRD_UID, vec![opened(), refused(Refused::Busy)]);
    let (mut client, _) = LdapChannelClient::open(
        &mut connector,
        DIRD_UID,
        Listener::Ldap,
        peer(),
        Duration::from_secs(5),
    )
    .unwrap();
    let failure = client.message(&[0x30, 0x00], CLEAR).unwrap_err();
    assert_eq!(failure, ChannelFailure::Refused(Refused::Busy));
    assert_eq!(
        notice_code(&notice_of_disconnection(&failure).unwrap()),
        ResultCode::Busy
    );
    // The connection is gone: the next call fails without a reply.
    assert!(matches!(
        client.message(&[0x30, 0x00], CLEAR).err(),
        Some(ChannelFailure::OutOfSequence | ChannelFailure::Transport(TransportError::Closed))
    ));

    // dird closes the connection mid-reply.
    let (mut connector, _) = loopback(DIRD_UID, vec![opened(), part(&[1], false)]);
    let (mut client, _) = LdapChannelClient::open(
        &mut connector,
        DIRD_UID,
        Listener::Ldap,
        peer(),
        Duration::from_secs(5),
    )
    .unwrap();
    let failure = client.message(&[0x30, 0x00], CLEAR).unwrap_err();
    assert_eq!(failure, ChannelFailure::Transport(TransportError::Closed));
    assert_eq!(
        notice_code(&notice_of_disconnection(&failure).unwrap()),
        ResultCode::Unavailable
    );

    // dird down.
    let (mut connector, _) = loopback(DIRD_UID, vec![]);
    connector.refuse_connect = true;
    let failure = LdapChannelClient::open(
        &mut connector,
        DIRD_UID,
        Listener::Ldaps,
        peer(),
        Duration::from_secs(5),
    )
    .unwrap_err();
    assert_eq!(failure, ChannelFailure::Transport(TransportError::Connect));
    assert_eq!(
        notice_code(&notice_of_disconnection(&failure).unwrap()),
        ResultCode::Unavailable
    );

    for other in [
        Refused::Unavailable,
        Refused::Malformed,
        Refused::VersionMismatch,
    ] {
        assert_eq!(
            ChannelFailure::Refused(other).notice_code(),
            ResultCode::Unavailable
        );
    }
}

/// docs/50 §7.5 (`Ping` on every channel; the front's test connection):
/// Ping → Pong; anything else is a failure.
#[test]
fn the_health_check() {
    let (mut connector, script) = loopback(DIRD_UID, vec![body(&LdapReply::Pong)]);
    ping(&mut connector, DIRD_UID, Duration::from_secs(5)).unwrap();
    assert_eq!(script.borrow().sent, vec![LdapRequest::Ping]);
    let (mut connector, _) = loopback(DIRD_UID, vec![opened()]);
    assert_eq!(
        ping(&mut connector, DIRD_UID, Duration::from_secs(5)).err(),
        Some(ChannelFailure::UnexpectedReply)
    );
}
