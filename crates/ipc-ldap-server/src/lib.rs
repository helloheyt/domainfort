#![forbid(unsafe_code)]
//! `ipc-ldap-server`: dird's side of the ldap-front ↔ dird channel (docs/50
//! R50-10, §4.2, §4.3, §10 task P10; docs/49 R49-16; decision A-58).
//!
//! [`LdapConnection`] is the state of **one** channel connection — one client
//! connection of the front, one `ldap::Session` (R50-10: 1:1, no session ids).
//! [`LdapConnection::handle`] decodes one request body, keeps the channel's
//! order, runs [`ldap::Engine::handle`] over the connection's session with
//! the per-request inputs the host supplies ([`RequestHost`]), and encodes
//! the reply. It holds no socket, no thread, no clock and no directory: dird
//! builds the inputs (its store snapshot, policy, rate limiter, clock), maps
//! the peer address to a zone, and gates and records the audit event.
//!
//! # The channel's order
//!
//! | state | request | effect |
//! |---|---|---|
//! | awaiting `Open` | `Ping` | `Pong` (a health check; the connection stays before `Open`) |
//! | awaiting `Open` | `Open { listener, peer_addr }` | `Session::new(connection id, listener)`; zone = the host's mapping of `peer_addr` (docs/50 §4.2: "the mapping belongs to the PEP"); TLS up iff LDAPS; `Opened { framing }` |
//! | open | `Message { canonical, tls_established, input_pending }` | `tls_established` must equal the channel's TLS state (LDAPS, or `TlsEstablished` accepted) — else `Refused::Malformed` + close, the engine not called; otherwise the engine runs with `TransportReport { zone, tls_established, input_pending }` and the reply is `Response` parts for every response, then `Done { action, framing }` |
//! | open, after `Done { StartTls }` | `TlsEstablished` | the TLS state becomes up; `TlsAccepted { framing }` |
//! | open, any other time | `TlsEstablished` | refused (`Refused::Malformed` + close): TLS can come up only through LDAPS or a successful StartTLS (docs/49 §4.4; crates/ldap session.rs) |
//! | any | `Close` | the session ends; no reply |
//! | any | anything else (`Open` twice, `Ping` after `Open`, `Message` before `Open`) | `Refused::Malformed` + close |
//! | closed | anything | close without a reply |
//!
//! A `Message` that arrives in cleartext after `Done { StartTls }` (the TLS
//! state still down, as the front reports it) reaches the engine, whose
//! session closes it unparsed (crates/ldap engine.rs step 1: "RequestDuringStartTls")
//! — with its audit event. A front that reports TLS the channel never
//! accepted is refused before the engine (the report cannot contradict the
//! channel's own history).
//!
//! # Host refusals
//!
//! [`RequestHost::serve`] may refuse to run the engine — dird's queue is
//! full ([`Unserved::Busy`] → `Refused::Busy`), auditd is unreachable or its
//! window is full, a snapshot or the clock failed, or the event could not be
//! committed ([`Unserved::Unavailable`] → `Refused::Unavailable`). Either
//! way the connection closes after the refusal and the front closes the
//! client connection with a Notice of Disconnection (crates/ipc-ldap front).
//!
//! # Bounds
//!
//! The channel's per-reply bounds (crates/ipc-ldap channel) are pinned here
//! to the engine's: one response ≤ `ldap::MAX_RESPONSE_OCTETS`, the count ≥
//! `ldap::MAX_PAGE_SIZE` + 2. An outcome that would break them anyway is not
//! sent (`Refused::Unavailable` + close — fail closed; it cannot happen with
//! the engine's limits).
//!
//! Spec: docs/50 R50-7, R50-10, §3.3, §4.2, §4.3, §7.5; docs/49 R49-14,
//! R49-15, R49-16, §4.4; A-47; A-59.
//!
//! # Provenance
//!
//! Written only from this project's decided design, opened in-session
//! (docs/50, docs/49, docs/questions Q-163, Q-190, Q-200, Q-225, Q-270,
//! Q-275, PENDING-OWNER) and the public API of this project's crates ipc,
//! ipc-ldap, ldap, parse-ldap and pdp (ipc-directory-server as the pattern).
//! No other implementation, LDAP server or RPC framework was consulted or
//! recalled (AGENTS.md §1-3).

use core::fmt;
use core::net::IpAddr;
use ipc::{decode_body, encode_frame, encode_refused, Direction, EncodedFrame, Refused};
use ipc_ldap::wire::{split_response, LdapReply, LdapRequest, MessageRequest};
use ipc_ldap::{LDAP_CHANNEL, MAX_REPLY_OCTETS, MAX_RESPONSES, MAX_RESPONSE_MESSAGE};
use ldap::{ConnectionAction, Engine, Listener, Outcome, RequestInputs, Session, TransportReport};
use pdp::IpScope;

// The channel's per-reply bounds are the engine's (crates/ipc-ldap links no
// engine, so they are pinned here, where both are linked). Checked at
// compile time.
// Spec: docs/49 §6.1 item 7; crates/ldap search/limits.rs.
const _: () = assert!(MAX_RESPONSE_MESSAGE == ldap::MAX_RESPONSE_OCTETS);
const _: () = assert!(MAX_RESPONSES >= ldap::MAX_PAGE_SIZE as usize + 2);
const _: () = assert!(MAX_REPLY_OCTETS >= ldap::MAX_RESPONSE_OCTETS);

/// The connection a request came on, as dird numbers them (never anything
/// the peer sent); also the `ldap::Session`'s connection id.
/// Spec: docs/50 §4.2 ("dird creates `ldap::Session::new(connection_id,
/// listener)` for every Unix connection (an id it assigns)").
pub type ConnectionId = u64;

/// What to send, and whether the connection then closes.
/// Spec: docs/50 §3.3 (bad prefix, wrong magic, unknown kind ⇒ close without
/// a reply; wrong version ⇒ `Refused{VersionMismatch}` + close; malformed ⇒
/// `Malformed` + close), §4.2.
pub enum Dispatch {
    /// Send the frames in order; the connection stays open.
    Reply(Vec<EncodedFrame>),
    /// Send the frames in order, then close the connection.
    ReplyAndClose(Vec<EncodedFrame>),
    /// Close the connection without a reply.
    Close,
}

impl fmt::Debug for Dispatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Dispatch::Reply(frames) => f.debug_tuple("Reply").field(&frames.len()).finish(),
            Dispatch::ReplyAndClose(frames) => {
                f.debug_tuple("ReplyAndClose").field(&frames.len()).finish()
            }
            Dispatch::Close => f.write_str("Close"),
        }
    }
}

impl Dispatch {
    /// The frames to send (none for [`Dispatch::Close`]).
    #[must_use]
    pub fn frames(&self) -> &[EncodedFrame] {
        match self {
            Dispatch::Reply(frames) | Dispatch::ReplyAndClose(frames) => frames,
            Dispatch::Close => &[],
        }
    }

    /// Whether the connection closes after the frames.
    #[must_use]
    pub fn closes(&self) -> bool {
        !matches!(self, Dispatch::Reply(_))
    }
}

/// The shared refusal frame, then close; a refusal that cannot be encoded
/// (never, given ipc's minimum body bound) closes without a reply.
/// Spec: docs/50 §3.3; A-59.
#[must_use]
pub fn refuse(refused: Refused) -> Dispatch {
    match encode_refused(LDAP_CHANNEL, refused) {
        Ok(frame) => Dispatch::ReplyAndClose(vec![frame]),
        Err(_) => Dispatch::Close,
    }
}

/// Why the host did not run the engine (module documentation).
/// Spec: docs/50 R50-7 ("queue full ⇒ `Busy`"), §3.7, §8.1; docs/questions
/// Q-218 (A-57).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unserved {
    /// The host's bounded queue is full.
    Busy,
    /// A dependency the request needs is not available (auditd, the store
    /// snapshot, the clock), or the event could not be recorded.
    Unavailable,
}

/// What dird supplies for one connection's requests.
/// Spec: docs/50 §4.2; docs/49 §11 ("the caller supplies `now`,
/// `source_zone`, `connection_id` and the transport state").
pub trait RequestHost {
    /// The zone of a peer address: dird's own zone table.
    /// Spec: docs/50 §4.2 ("dird maps the address to `IpScope` by **its**
    /// zone table — the mapping belongs to the PEP"), §4.1.
    fn zone(&self, peer: IpAddr) -> IpScope;

    /// Build one request's inputs — the policy snapshot, one fresh directory
    /// view as the PIP, the account source and the directory, the rate
    /// limiter, `now`, the search clock — with `transport`, and call `run`
    /// with them exactly once; return its outcome after the outcome's audit
    /// event was recorded. Refuse (without calling `run`, or withholding its
    /// outcome when the event cannot be recorded) with [`Unserved`].
    ///
    /// # Errors
    /// [`Unserved`].
    ///
    /// Spec: docs/49 §4.4 (R49-15: a fresh snapshot per operation), §10.1
    /// (R49-14: exactly one event per operation), §11; docs/50 §8.1;
    /// docs/questions Q-218 (A-57), Q-252 item 9 (A-64: commit, then reply).
    fn serve(
        &mut self,
        transport: TransportReport,
        run: &mut dyn FnMut(RequestInputs<'_>) -> Outcome,
    ) -> Result<Outcome, Unserved>;
}

/// The channel's facts of an open session.
/// Spec: docs/50 R50-10, §4.2, §4.3; docs/49 §4.4.
struct OpenSession {
    session: Session,
    src_net: IpScope,
    /// TLS protects the client connection: LDAPS, or `TlsEstablished`
    /// accepted after a StartTLS.
    tls: bool,
    /// The last outcome asked the front for StartTLS and its
    /// `TlsEstablished` has not come yet.
    tls_pending: bool,
}

/// Where the connection stands (module documentation).
/// Spec: docs/50 §4.2, §4.3.
enum Phase {
    AwaitOpen,
    Open(Box<OpenSession>),
    Closed,
}

/// One channel connection: one client connection's session (module
/// documentation).
/// Spec: docs/50 R50-10, §4.2.
pub struct LdapConnection {
    id: ConnectionId,
    phase: Phase,
}

impl fmt::Debug for LdapConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let phase = match &self.phase {
            Phase::AwaitOpen => "await-open",
            Phase::Open(_) => "open",
            Phase::Closed => "closed",
        };
        f.debug_struct("LdapConnection")
            .field("id", &self.id)
            .field("phase", &phase)
            .finish()
    }
}

/// The engine's listener for the channel's.
/// Spec: docs/50 §4.2; crates/ldap session.rs.
fn listener_of(listener: ipc_ldap::Listener) -> Listener {
    match listener {
        ipc_ldap::Listener::Ldap => Listener::Ldap,
        ipc_ldap::Listener::Ldaps => Listener::Ldaps,
    }
}

/// The channel's action for the engine's.
/// Spec: docs/50 §4.2; crates/ldap engine.rs.
fn action_of(action: ConnectionAction) -> ipc_ldap::ConnectionAction {
    match action {
        ConnectionAction::Continue => ipc_ldap::ConnectionAction::Continue,
        ConnectionAction::StartTls => ipc_ldap::ConnectionAction::StartTls,
        ConnectionAction::Close => ipc_ldap::ConnectionAction::Close,
    }
}

/// One reply frame, or `None` if it does not encode.
/// Spec: docs/50 §3.3, §4.2.
fn reply_frame(reply: &LdapReply) -> Option<EncodedFrame> {
    encode_frame(LDAP_CHANNEL, Direction::Reply, reply).ok()
}

impl LdapConnection {
    /// A new connection numbered `id` by dird, before `Open`.
    /// Spec: docs/50 §4.2.
    #[must_use]
    pub fn new(id: ConnectionId) -> LdapConnection {
        LdapConnection {
            id,
            phase: Phase::AwaitOpen,
        }
    }

    /// dird's number for this connection.
    #[must_use]
    pub fn id(&self) -> ConnectionId {
        self.id
    }

    /// Whether the connection is over (nothing more is processed).
    #[must_use]
    pub fn is_closed(&self) -> bool {
        matches!(self.phase, Phase::Closed)
    }

    /// Whether `Open` was accepted and the session is live.
    #[must_use]
    pub fn is_open(&self) -> bool {
        matches!(self.phase, Phase::Open(_))
    }

    /// Close and send `refused`.
    fn refuse(&mut self, refused: Refused) -> Dispatch {
        self.phase = Phase::Closed;
        refuse(refused)
    }

    /// One reply frame; the connection stays open. A frame that does not
    /// encode (cannot happen) fails closed.
    fn reply(&mut self, reply: &LdapReply) -> Dispatch {
        match reply_frame(reply) {
            Some(frame) => Dispatch::Reply(vec![frame]),
            None => self.refuse(Refused::Unavailable),
        }
    }

    /// Handle one request body (module documentation).
    /// Spec: docs/50 §3.3, §4.2, §4.3; A-59.
    pub fn handle(&mut self, engine: &Engine, body: &[u8], host: &mut dyn RequestHost) -> Dispatch {
        if self.is_closed() {
            return Dispatch::Close;
        }
        let request = match decode_body::<LdapRequest>(LDAP_CHANNEL, Direction::Request, body) {
            Ok(request) => request,
            Err(error) => {
                self.phase = Phase::Closed;
                return match error.refusal() {
                    Some(refused) => refuse(refused),
                    None => Dispatch::Close,
                };
            }
        };
        let phase = core::mem::replace(&mut self.phase, Phase::Closed);
        match (phase, request) {
            (_, LdapRequest::Close) => Dispatch::Close,
            (Phase::AwaitOpen, LdapRequest::Ping) => {
                self.phase = Phase::AwaitOpen;
                self.reply(&LdapReply::Pong)
            }
            (
                Phase::AwaitOpen,
                LdapRequest::Open {
                    listener,
                    peer_addr,
                },
            ) => {
                let listener = listener_of(listener);
                let session = Session::new(self.id, listener);
                let framing = session.auth_state();
                self.phase = Phase::Open(Box::new(OpenSession {
                    session,
                    src_net: host.zone(peer_addr),
                    tls: listener == Listener::Ldaps,
                    tls_pending: false,
                }));
                self.reply(&LdapReply::Opened { framing })
            }
            (Phase::Open(open), LdapRequest::Message(message)) => {
                self.message(engine, open, &message, host)
            }
            (Phase::Open(mut open), LdapRequest::TlsEstablished) => {
                if !open.tls_pending {
                    // TLS comes up only through LDAPS or a successful
                    // StartTLS. Spec: docs/49 §4.4; docs/50 §4.3.
                    return self.refuse(Refused::Malformed);
                }
                open.tls = true;
                open.tls_pending = false;
                let framing = open.session.auth_state();
                self.phase = Phase::Open(open);
                self.reply(&LdapReply::TlsAccepted { framing })
            }
            // Out of order: Message / TlsEstablished before Open, Open twice,
            // Ping after Open.
            _ => self.refuse(Refused::Malformed),
        }
    }

    /// A `Message` on an open session (module documentation).
    /// Spec: docs/50 §4.2, §4.3; docs/49 §4.4, R49-16.
    fn message(
        &mut self,
        engine: &Engine,
        mut open: Box<OpenSession>,
        message: &MessageRequest,
        host: &mut dyn RequestHost,
    ) -> Dispatch {
        // The front's report cannot contradict the channel's own history.
        // Spec: docs/49 §4.4 ("always close; no return to cleartext").
        if message.transport.tls_established != open.tls {
            return self.refuse(Refused::Malformed);
        }
        let transport = TransportReport {
            src_net: open.src_net,
            tls_established: message.transport.tls_established,
            input_pending: message.transport.input_pending,
        };
        let outcome = {
            let session = &mut open.session;
            let canonical: &[u8] = &message.canonical;
            let mut run = |inputs: RequestInputs<'_>| engine.handle(session, canonical, inputs);
            host.serve(transport, &mut run)
        };
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(Unserved::Busy) => return self.refuse(Refused::Busy),
            Err(Unserved::Unavailable) => return self.refuse(Refused::Unavailable),
        };
        let framing = open.session.auth_state();
        let Some(frames) = encode_outcome(&outcome, framing) else {
            return self.refuse(Refused::Unavailable);
        };
        match outcome.action {
            ConnectionAction::Close => Dispatch::ReplyAndClose(frames),
            ConnectionAction::StartTls => {
                open.tls_pending = true;
                self.phase = Phase::Open(open);
                Dispatch::Reply(frames)
            }
            ConnectionAction::Continue => {
                self.phase = Phase::Open(open);
                Dispatch::Reply(frames)
            }
        }
    }
}

/// The reply frames of one outcome: the parts of every response in order,
/// then `Done`. `None` if the outcome is over the channel's reply bounds or
/// a frame does not encode (fail closed).
/// Spec: docs/50 §4.2; crates/ipc-ldap channel (per-reply bounds).
fn encode_outcome(outcome: &Outcome, framing: parse_ldap::AuthState) -> Option<Vec<EncodedFrame>> {
    if outcome.responses.len() > MAX_RESPONSES {
        return None;
    }
    let total = outcome
        .responses
        .iter()
        .try_fold(0usize, |sum, response| sum.checked_add(response.len()))?;
    if total > MAX_REPLY_OCTETS {
        return None;
    }
    let mut frames = Vec::new();
    for response in &outcome.responses {
        for part in split_response(response)? {
            frames.push(reply_frame(&LdapReply::Response(part))?);
        }
    }
    frames.push(reply_frame(&LdapReply::Done {
        action: action_of(outcome.action),
        framing,
    })?);
    Some(frames)
}
