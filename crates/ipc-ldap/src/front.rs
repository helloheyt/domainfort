//! The front's side of one session, without I/O: [`FrontChannel`] encodes the
//! front's requests and decodes dird's replies strictly, in the order the
//! channel allows, and reassembles the responses within the reply bounds.
//! The blocking client (crate::client) drives it over a socket; an
//! asynchronous front (task P11) can drive the same state machine.
//!
//! # The order of a session
//!
//! ```text
//!   new ──open──► AwaitOpened ──Opened──► Ready
//!   Ready ──message──► AwaitDone ──Response*, Done{Continue}──► Ready
//!                                └─Done{StartTls}──► AwaitTlsEstablished
//!                                └─Done{Close}──► Closed
//!   AwaitTlsEstablished ──tls_established──► AwaitTlsAccepted ──TlsAccepted──► Ready
//!   any ──close──► Closed           any failure ──► Failed
//! ```
//!
//! * One request at a time; the front sends nothing while a reply is out
//!   (docs/50 §4.3 step 1: "stops reading from the socket until the
//!   answer"; R50-7: strict request → reply).
//! * After `Done { StartTls }` the only requests allowed are
//!   `TlsEstablished` and `Close` (docs/50 §4.3 step 3: the front writes the
//!   response in cleartext, requires and **discards** an empty cleartext
//!   buffer, and from then on reads only into rustls). The front must report
//!   `TlsEstablished` only after the handshake completed with the docs/50
//!   R50-11 parameters (TLS 1.3, an AEAD suite from the list — §4.3 step 4),
//!   and from then on every message carries `tls_established = true`.
//! * The framing state ([`FrontChannel::framing`]) is the last one dird
//!   reported; the front applies its size bound to the next message
//!   (`parse_ldap::frame_length(buffer, framing)` — docs/50 §4.2).
//!
//! # When dird does not serve (docs/50 §3.7: "ldap-front without dird ⇒
//! the connection is closed (no answer without a PEP)")
//!
//! Every failure — a transport error, dird's uid not the configured one, a
//! shared `Refused` (`Busy`, `Unavailable`, `Malformed`, `VersionMismatch`),
//! a reply that does not decode, is out of order or over a bound, or a
//! request out of sequence — is a [`ChannelFailure`], the channel is failed,
//! and the front **closes the client connection**. Before closing it sends a
//! Notice of Disconnection ([`notice_of_disconnection`]): RFC 4511 §4.4.1
//! ("the server is about to terminate the LDAP session on its own
//! initiative … to assist clients in distinguishing between an exceptional
//! server condition and a transient network failure"), with resultCode
//! `busy` (51, "too busy to service the operation") for `Refused::Busy` and
//! `unavailable` (52, "a subsystem necessary to complete the operation is
//! offline") for everything else (RFC 4511 App. A). parse-ldap's canonical
//! encoder produces it; if it ever could not, the front closes without it
//! ("if the codec allows"). The notice is written on the connection's
//! current layer — never between a StartTLS response and the end of the TLS
//! handshake, where the front just closes (docs/50 §4.3: no cleartext after
//! StartTLS).
//!
//! Spec: docs/50 R50-7, R50-8, R50-10, §3.3, §3.7, §4.2, §4.3; docs/49
//! §4.4 (R49-15); RFC 4511 §4.4.1, App. A; A-59.

use crate::channel::{
    ConnectionAction, Listener, LDAP_CHANNEL, MAX_REPLY_OCTETS, MAX_RESPONSES, MAX_RESPONSE_MESSAGE,
};
use crate::wire::{LdapReply, LdapRequest, MessageRequest, ReportedPeer, TransportFacts};
use core::fmt;
use core::net::IpAddr;
use ipc::{decode_reply, encode_frame, Direction, EncodedFrame, Refused, Reply};
use parse_ldap::{encode_message, AuthState, LdapMessage, ResultCode};
use zeroize::Zeroizing;

/// A transport failure of the front's connection to dird. Carries no octet
/// of any frame.
/// Spec: docs/50 §3.6, §3.7, §8.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportError {
    /// The connection could not be opened (dird down, no socket).
    Connect,
    /// The peer's credentials could not be read (or are not available on
    /// this platform — fail closed).
    PeerCredentials,
    /// dird closed the connection.
    Closed,
    /// The deadline passed before the reply arrived.
    DeadlineExceeded,
    /// Another I/O failure.
    Io,
    /// A reply frame did not frame (bad length prefix, over the bound).
    Framing,
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            TransportError::Connect => "dird connection could not be opened",
            TransportError::PeerCredentials => "dird peer credentials unavailable",
            TransportError::Closed => "dird closed the connection",
            TransportError::DeadlineExceeded => "dird deadline exceeded",
            TransportError::Io => "dird connection I/O failure",
            TransportError::Framing => "dird reply did not frame",
        })
    }
}

impl std::error::Error for TransportError {}

/// Why dird did not serve. Every case closes the client connection (module
/// documentation); none carries frame octets.
/// Spec: docs/50 §3.7, §8.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelFailure {
    /// The transport failed.
    Transport(TransportError),
    /// The configured dird uid is 0: dird never runs as root after its
    /// hardening (docs/50 §6), and accepting uid 0 would accept any root
    /// process (as the kdc's clients, docs/questions/Q-245 item 5).
    RootServerUid,
    /// The peer is not the configured dird uid; nothing was sent.
    PeerMismatch,
    /// dird answered with the shared transport refusal.
    Refused(Refused),
    /// A reply did not decode at the ipc layer.
    MalformedReply(ipc::Error),
    /// A reply decoded but is not one the channel allows here.
    UnexpectedReply,
    /// The reply to one message exceeded [`MAX_RESPONSES`],
    /// [`MAX_RESPONSE_MESSAGE`] or [`MAX_REPLY_OCTETS`].
    ReplyOverBound,
    /// The front asked for a request the session's state does not allow
    /// (nothing was sent).
    OutOfSequence,
    /// The request could not be encoded (over its bound); nothing was sent.
    Unencodable,
}

impl fmt::Display for ChannelFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChannelFailure::Transport(error) => write!(f, "{error}"),
            ChannelFailure::RootServerUid => f.write_str("dird's uid cannot be 0"),
            ChannelFailure::PeerMismatch => f.write_str("dird peer is not the configured uid"),
            ChannelFailure::Refused(refused) => write!(f, "dird refused: {refused:?}"),
            ChannelFailure::MalformedReply(error) => write!(f, "dird reply malformed: {error}"),
            ChannelFailure::UnexpectedReply => f.write_str("dird reply out of order"),
            ChannelFailure::ReplyOverBound => f.write_str("dird reply over its bound"),
            ChannelFailure::OutOfSequence => f.write_str("request out of sequence"),
            ChannelFailure::Unencodable => f.write_str("request could not be encoded"),
        }
    }
}

impl std::error::Error for ChannelFailure {}

impl ChannelFailure {
    /// The resultCode of the Notice of Disconnection for this failure:
    /// `busy` for `Refused::Busy`, `unavailable` otherwise.
    /// Spec: RFC 4511 §4.4.1, App. A (busy 51, unavailable 52).
    #[must_use]
    pub fn notice_code(&self) -> ResultCode {
        match self {
            ChannelFailure::Refused(Refused::Busy) => ResultCode::Busy,
            _ => ResultCode::Unavailable,
        }
    }
}

/// The Notice of Disconnection the front writes before it closes the client
/// connection because of `failure` (module documentation), or `None` if the
/// codec cannot encode it (then the front closes without it).
/// Spec: RFC 4511 §4.4, §4.4.1; docs/50 §3.7.
#[must_use]
pub fn notice_of_disconnection(failure: &ChannelFailure) -> Option<Vec<u8>> {
    encode_message(&LdapMessage::notice_of_disconnection(failure.notice_code())).ok()
}

/// The front's account of the reply to one `Message`: the canonical
/// responses to write, in order, the action, and the framing state of the
/// next message.
/// Spec: docs/50 §4.2.
#[derive(Clone, PartialEq, Eq)]
pub struct Exchange {
    /// The canonical LDAPMessage encodings to write to the client, in order.
    pub responses: Vec<Vec<u8>>,
    /// What to do with the client connection afterwards.
    pub action: ConnectionAction,
    /// The framing state of the next message.
    pub framing: AuthState,
}

impl fmt::Debug for Exchange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Exchange")
            .field("responses", &self.responses.len())
            .field("action", &self.action)
            .field("framing", &self.framing)
            .finish()
    }
}

/// What one reply frame did.
/// Spec: docs/50 §4.2, §4.3, §7.5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Progress {
    /// The session exists (reply to `Open`).
    Opened {
        /// The framing state of the first message.
        framing: AuthState,
    },
    /// A response part was taken; the reply goes on.
    Pending,
    /// The reply to a `Message` is complete.
    Done(Exchange),
    /// dird took the TLS report (reply to `TlsEstablished`).
    TlsAccepted {
        /// The framing state.
        framing: AuthState,
    },
    /// The health check was answered (reply to `Ping`).
    Pong,
}

/// Where the session stands (module documentation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    New,
    AwaitOpened,
    AwaitPong,
    Ready,
    AwaitDone,
    AwaitTlsEstablished,
    AwaitTlsAccepted,
    Closed,
    Failed,
}

/// The front's side of one session (module documentation).
/// Spec: docs/50 R50-10, §4.2, §4.3.
pub struct FrontChannel {
    state: State,
    framing: AuthState,
    responses: Vec<Vec<u8>>,
    partial: Vec<u8>,
    total: usize,
}

impl fmt::Debug for FrontChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FrontChannel")
            .field("state", &self.state)
            .field("framing", &self.framing)
            .finish()
    }
}

impl Default for FrontChannel {
    fn default() -> Self {
        FrontChannel::new()
    }
}

impl FrontChannel {
    /// A channel before `Open`; the framing state starts unauthenticated
    /// (RFC 4513 §4: a new session is anonymous).
    /// Spec: docs/50 §4.2 ("start: `Unauthenticated`").
    #[must_use]
    pub fn new() -> FrontChannel {
        FrontChannel {
            state: State::New,
            framing: AuthState::Unauthenticated,
            responses: Vec::new(),
            partial: Vec::new(),
            total: 0,
        }
    }

    /// The framing state dird reported last.
    /// Spec: docs/50 §4.2.
    #[must_use]
    pub fn framing(&self) -> AuthState {
        self.framing
    }

    /// Whether the session can take a `Message` now.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.state == State::Ready
    }

    /// Whether dird asked for StartTLS and the front owes `TlsEstablished`
    /// (or `Close`).
    /// Spec: docs/50 §4.3 step 3.
    #[must_use]
    pub fn awaits_tls(&self) -> bool {
        self.state == State::AwaitTlsEstablished
    }

    /// Whether the session ended (closed or failed).
    #[must_use]
    pub fn is_finished(&self) -> bool {
        matches!(self.state, State::Closed | State::Failed)
    }

    /// Fail the channel and drop what was gathered.
    fn fail(&mut self, failure: ChannelFailure) -> ChannelFailure {
        self.state = State::Failed;
        self.responses.clear();
        self.partial = Vec::new();
        self.total = 0;
        failure
    }

    /// Encode `request` if the session is in `expected`, then move to `next`.
    fn request(
        &mut self,
        expected: State,
        next: State,
        request: &LdapRequest,
    ) -> Result<EncodedFrame, ChannelFailure> {
        if self.state != expected {
            return Err(self.fail(ChannelFailure::OutOfSequence));
        }
        match encode_frame(LDAP_CHANNEL, Direction::Request, request) {
            Ok(frame) => {
                self.state = next;
                Ok(frame)
            }
            Err(_) => Err(self.fail(ChannelFailure::Unencodable)),
        }
    }

    /// `Open { listener, reported_peer }` — the first request. `peer_addr`
    /// is the client address the front's socket gave it; dird keeps it for
    /// the audit record only (crate::wire `ReportedPeer`; docs/52 R14).
    ///
    /// # Errors
    /// [`ChannelFailure::OutOfSequence`] unless the channel is new.
    ///
    /// Spec: docs/50 §4.2; docs/52 §7 R14.
    pub fn encode_open(
        &mut self,
        listener: Listener,
        peer_addr: IpAddr,
    ) -> Result<EncodedFrame, ChannelFailure> {
        self.request(
            State::New,
            State::AwaitOpened,
            &LdapRequest::Open {
                listener,
                reported_peer: ReportedPeer::new(peer_addr),
            },
        )
    }

    /// `Ping` — a health-check connection's only request.
    ///
    /// # Errors
    /// [`ChannelFailure::OutOfSequence`] unless the channel is new.
    ///
    /// Spec: docs/50 §7.5.
    pub fn encode_ping(&mut self) -> Result<EncodedFrame, ChannelFailure> {
        self.request(State::New, State::AwaitPong, &LdapRequest::Ping)
    }

    /// `Message` — one canonical LDAPMessage with the transport facts.
    ///
    /// # Errors
    /// [`ChannelFailure::OutOfSequence`] unless the session is ready (in
    /// particular after `Done { StartTls }`, until `TlsAccepted`);
    /// [`ChannelFailure::Unencodable`] over the canonical-message bound.
    ///
    /// Spec: docs/50 §4.2, §4.3.
    pub fn encode_message(
        &mut self,
        canonical: &[u8],
        transport: TransportFacts,
    ) -> Result<EncodedFrame, ChannelFailure> {
        let mut octets = Zeroizing::new(Vec::with_capacity(canonical.len()));
        octets.extend_from_slice(canonical);
        let request = LdapRequest::Message(MessageRequest {
            canonical: octets,
            transport,
        });
        let frame = self.request(State::Ready, State::AwaitDone, &request)?;
        self.responses.clear();
        self.partial = Vec::new();
        self.total = 0;
        Ok(frame)
    }

    /// `TlsEstablished` — only right after `Done { StartTls }`.
    ///
    /// # Errors
    /// [`ChannelFailure::OutOfSequence`] otherwise.
    ///
    /// Spec: docs/50 §4.3 steps 3-4.
    pub fn encode_tls_established(&mut self) -> Result<EncodedFrame, ChannelFailure> {
        self.request(
            State::AwaitTlsEstablished,
            State::AwaitTlsAccepted,
            &LdapRequest::TlsEstablished,
        )
    }

    /// `Close` — allowed in every state but a closed one; the session is
    /// over afterwards. No reply follows.
    ///
    /// # Errors
    /// [`ChannelFailure::OutOfSequence`] on a closed channel.
    ///
    /// Spec: docs/50 §4.2.
    pub fn encode_close(&mut self) -> Result<EncodedFrame, ChannelFailure> {
        if self.state == State::Closed {
            return Err(ChannelFailure::OutOfSequence);
        }
        let frame = encode_frame(LDAP_CHANNEL, Direction::Request, &LdapRequest::Close)
            .map_err(|_| ChannelFailure::Unencodable);
        self.state = State::Closed;
        self.responses.clear();
        self.partial = Vec::new();
        frame
    }

    /// Decode one reply frame body and apply it (module documentation).
    ///
    /// # Errors
    /// [`ChannelFailure`] — the channel is failed; the front closes the
    /// client connection.
    ///
    /// Spec: docs/50 §3.3 (replies decoded with the same strictness), §4.2,
    /// §4.3; A-59.
    pub fn accept_reply(&mut self, body: &[u8]) -> Result<Progress, ChannelFailure> {
        let reply = match decode_reply::<LdapReply>(LDAP_CHANNEL, body) {
            Ok(Reply::Message(reply)) => reply,
            Ok(Reply::Refused(refused)) => return Err(self.fail(ChannelFailure::Refused(refused))),
            Err(error) => return Err(self.fail(ChannelFailure::MalformedReply(error))),
        };
        match (self.state, reply) {
            (State::AwaitOpened, LdapReply::Opened { framing }) => {
                self.framing = framing;
                self.state = State::Ready;
                Ok(Progress::Opened { framing })
            }
            (State::AwaitPong, LdapReply::Pong) => {
                self.state = State::Closed;
                Ok(Progress::Pong)
            }
            (State::AwaitDone, LdapReply::Response(part)) => {
                self.take_part(part.octets(), part.more())
            }
            (State::AwaitDone, LdapReply::Done { action, framing }) => {
                if !self.partial.is_empty() {
                    // A response whose last part never came.
                    return Err(self.fail(ChannelFailure::UnexpectedReply));
                }
                self.framing = framing;
                self.state = match action {
                    ConnectionAction::Continue => State::Ready,
                    ConnectionAction::StartTls => State::AwaitTlsEstablished,
                    ConnectionAction::Close => State::Closed,
                };
                self.total = 0;
                Ok(Progress::Done(Exchange {
                    responses: core::mem::take(&mut self.responses),
                    action,
                    framing,
                }))
            }
            (State::AwaitTlsAccepted, LdapReply::TlsAccepted { framing }) => {
                self.framing = framing;
                self.state = State::Ready;
                Ok(Progress::TlsAccepted { framing })
            }
            _ => Err(self.fail(ChannelFailure::UnexpectedReply)),
        }
    }

    /// Take one response part within the reply bounds.
    /// Spec: crate::channel module documentation (per-reply bounds).
    fn take_part(&mut self, part: &[u8], more: bool) -> Result<Progress, ChannelFailure> {
        let within_response = self
            .partial
            .len()
            .checked_add(part.len())
            .is_some_and(|len| len <= MAX_RESPONSE_MESSAGE);
        let total = self.total.checked_add(part.len());
        let within_reply = total.is_some_and(|total| total <= MAX_REPLY_OCTETS);
        let starts_response = self.partial.is_empty();
        if !within_response
            || !within_reply
            || (starts_response && self.responses.len() >= MAX_RESPONSES)
        {
            return Err(self.fail(ChannelFailure::ReplyOverBound));
        }
        self.total = total.unwrap_or(MAX_REPLY_OCTETS);
        self.partial.extend_from_slice(part);
        if !more {
            self.responses.push(core::mem::take(&mut self.partial));
        }
        Ok(Progress::Pending)
    }
}
