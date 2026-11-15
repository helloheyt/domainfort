//! admind's side: a synchronous client of the admin channel (crate API only
//! — admind itself is task A9).
//!
//! # Connections
//!
//! [`Connector`] opens a connection; [`Connection`] reports the peer's uid
//! (from the transport's peer credentials) and carries one request frame and
//! its one reply frame within a deadline. Tests use an in-process loopback;
//! admind a blocking Unix stream socket (`crate::unix`).
//!
//! [`AdminClient`] checks the peer uid of every new connection against
//! dird's configured uid **before** anything is sent on it (docs/51 §7.1:
//! "the client (admind) verifies before sending that the server's uid =
//! dird's uid", precedent A-63) — a process that captured the socket path
//! receives no AP-REQ — then keeps it for the following calls: one request
//! in flight, strict request → reply (docs/50 R50-7). Any failure drops the
//! connection; the next call reconnects.
//!
//! # A held connection is checked before it is reused (F1, A-87)
//!
//! Before a call reuses the connection it holds, the client asks it,
//! without blocking and without sending, whether it is still usable
//! ([`Connection::check_idle`]); a dead or misbehaving one is dropped and a
//! fresh one opened — and checked — before the request is sent. A request is
//! never sent twice: once written, any failure ends the call and the next
//! call starts over (dird may already have committed the operation; its
//! audit trail says so).
//!
//! # What the caller sees
//!
//! | what happened | result |
//! |---|---|
//! | connect, I/O, peer closed, deadline | `Err(Unserved::Transport)` |
//! | peer uid unreadable or not dird's (nothing sent) | `Err(Unserved::PeerMismatch)` / `Transport(PeerCredentials)` |
//! | the shared `Refused` (Busy, Unavailable, Malformed, VersionMismatch) | `Err(Unserved::Refused)` |
//! | a reply that does not decode or does not answer the request | `Err(Unserved::MalformedReply / UnexpectedReply)` |
//! | dird's own answer — including `Reply::Refused(status)` | `Ok(reply)` |
//!
//! Spec: docs/51 §7.1, §7.5 (one request in flight; admind's deadline
//! "above keyd's deadline (2 s) × 3"); docs/50 R50-3, R50-7, R50-8, §3.6,
//! §3.7; A-63; A-87 (docs/questions/Q-312: idle check, no resend).

use crate::channel::{ADMIN_CHANNEL, REPLY_LIMIT};
use crate::typed::{ConversionError, Operation, Reply, Request};
use crate::wire::AdminReply;
use core::fmt;
use core::time::Duration;
use ipc::{decode_reply, encode_frame, Direction, FrameLimit, Refused};
use std::time::Instant;
use zeroize::Zeroizing;

/// The default per-call deadline of the admin client: 24 s. dird's admin
/// path, worst case, makes four keyd calls — three AP-REQ verifications and
/// the set_secret grant of a `BeginPasswordSet` (task A15a) — at keyd's 2 s
/// deadline each, and waits for auditd's acknowledgement of the decision
/// event (at most dird's 4 s ceiling): 12 s; with ≤ 2 connections a request
/// may wait behind one other request in dird's queue — twice that. dird
/// const-asserts this bound. docs/51 §7.5 asks for a deadline "above keyd's
/// deadline (2 s) × 3" (⚠ a project choice; was 20 s before A15a — A-100).
/// Spec: docs/51 §7.5; docs/50 §3.6.
pub const DEFAULT_DEADLINE: Duration = Duration::from_secs(24);

/// A transport failure. Carries no octet of any frame.
/// Spec: docs/50 §3.6, §3.7, §8.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportError {
    /// The connection could not be opened.
    Connect,
    /// The peer's credentials could not be read (or are not available on
    /// this platform — fail closed).
    PeerCredentials,
    /// The peer closed the connection.
    Closed,
    /// The deadline passed before the reply arrived.
    DeadlineExceeded,
    /// Another I/O failure.
    Io,
    /// The reply did not frame (bad length prefix, over the bound, or octets
    /// beyond the one reply).
    Framing,
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            TransportError::Connect => "dird admin connection could not be opened",
            TransportError::PeerCredentials => "dird peer credentials unavailable",
            TransportError::Closed => "dird closed the connection",
            TransportError::DeadlineExceeded => "dird deadline exceeded",
            TransportError::Io => "dird connection I/O failure",
            TransportError::Framing => "dird reply did not frame",
        })
    }
}

impl std::error::Error for TransportError {}

/// One open connection to dird's admin socket.
/// Spec: docs/50 §3.1, §3.2, §3.6.
pub trait Connection {
    /// The uid of the process at the other end, from the transport's peer
    /// credentials — never from anything the peer sends.
    /// Spec: docs/50 R50-3, §3.2; docs/51 §7.1.
    fn peer_uid(&self) -> Result<u32, TransportError>;

    /// Send one whole request frame (length prefix included) and receive the
    /// one reply frame, returning its body. The reply's declared length is
    /// checked against `reply_limit` before its body is awaited; the whole
    /// exchange completes within `deadline`.
    /// Spec: docs/50 §3.3 (bound before allocation), §3.6, R50-7.
    fn exchange(
        &mut self,
        frame: &[u8],
        reply_limit: FrameLimit,
        deadline: Duration,
    ) -> Result<Zeroizing<Vec<u8>>, TransportError>;

    /// Check, before this held connection is reused, that it is still usable
    /// — without blocking and without sending anything (end of stream, a
    /// pending error or a waiting octet ⇒ `Err`). **No default** (task R9;
    /// docs/52 §2 row 19): every connection decides — a transport that
    /// truly cannot tell says so in its own implementation.
    /// Spec: docs/50 §3.6, §3.7; docs/questions/Q-312 (A-82), Q-350 item 6
    /// (A-87), Q-466 item 4 (A-102).
    fn check_idle(&mut self) -> Result<(), TransportError>;
}

/// Opens connections to dird's admin socket.
/// Spec: docs/50 §3.1, §3.7.
pub trait Connector {
    /// The connection type.
    type Connection: Connection;

    /// Open a new connection.
    fn connect(&mut self) -> Result<Self::Connection, TransportError>;
}

/// Why dird did not serve a call.
/// Spec: docs/50 §3.7 (R50-8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unserved {
    /// The transport failed.
    Transport(TransportError),
    /// The peer's uid is not dird's; nothing was sent.
    PeerMismatch,
    /// dird answered with the shared transport refusal.
    Refused(Refused),
    /// The reply did not decode at the ipc layer.
    MalformedReply(ipc::Error),
    /// The reply decoded but its content did not, or it does not answer the
    /// request.
    UnexpectedReply(ConversionError),
    /// The request could not be encoded; nothing was sent.
    Unencodable,
}

/// The client was configured with an unacceptable dird uid.
/// Spec: docs/50 §3.2 ("uid 0 is never mapped").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientConfigError {
    /// dird's uid cannot be 0: dird never runs as root after its hardening
    /// (docs/50 §6), and accepting uid 0 would accept any root process.
    RootServerUid,
}

/// The time left of a call's `deadline` that started at `start`.
/// Spec: docs/50 §3.6.
fn remaining(start: Instant, deadline: Duration) -> Result<Duration, TransportError> {
    match deadline.checked_sub(start.elapsed()) {
        Some(left) if !left.is_zero() => Ok(left),
        _ => Err(TransportError::DeadlineExceeded),
    }
}

/// Whether `reply` is an answer `request` can receive (the closed reply
/// column of docs/51 §7.3: `GUID, SID` for a create, the key targets for
/// `BeginPasswordSet`, `()` for the others (`Reject` and `Withdraw`
/// included), `Found` for `Lookup`, the pending request's state for
/// `Propose` / `Approve`, the list for `ListRequests`, the request for
/// `ShowRequest` (task D2-c, Q-882), the version written for `ChangePolicy`
/// (task A16); a refusal for any operation; `Pong` for `Ping`).
/// Spec: docs/51 §7.3; docs/50 §3.3 (replies decoded with the same
/// strictness).
#[must_use]
pub fn answers(request: &Request, reply: &Reply) -> bool {
    match request {
        Request::Ping => matches!(reply, Reply::Pong),
        Request::Operation { operation, .. } => match reply {
            Reply::Refused(_) => true,
            Reply::Pong => false,
            Reply::PolicyNext { .. } => matches!(operation, Operation::ChangePolicy { .. }),
            Reply::PendingRequest(_) => matches!(
                operation,
                Operation::Propose { .. } | Operation::Approve { .. }
            ),
            Reply::RequestList(_) => matches!(operation, Operation::ListRequests(_)),
            Reply::RequestShown(_) => matches!(operation, Operation::ShowRequest { .. }),
            Reply::Created { .. } => matches!(
                operation,
                Operation::CreateUser { .. }
                    | Operation::CreateComputer { .. }
                    | Operation::CreateGroup { .. }
                    | Operation::CreateOu { .. }
                    | Operation::CreateContainer { .. }
            ),
            Reply::PasswordSet(_) => matches!(operation, Operation::BeginPasswordSet { .. }),
            Reply::Found(_) => matches!(operation, Operation::Lookup(_)),
            Reply::Done => matches!(
                operation,
                Operation::CompletePasswordSet { .. }
                    | Operation::SetEnabled { .. }
                    | Operation::SetAccountExpires { .. }
                    | Operation::AddMember { .. }
                    | Operation::RemoveMember { .. }
                    | Operation::Delete { .. }
                    | Operation::Reject { .. }
                    | Operation::Withdraw { .. }
            ),
        },
    }
}

/// A synchronous client of dird's admin channel.
/// Spec: docs/51 §7.1, §7.5; docs/50 R50-3, R50-7, §3.6, §3.7.
pub struct AdminClient<C: Connector> {
    connector: C,
    expected_uid: u32,
    deadline: Duration,
    connection: Option<C::Connection>,
}

impl<C: Connector> fmt::Debug for AdminClient<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdminClient")
            .field("expected_uid", &self.expected_uid)
            .field("deadline", &self.deadline)
            .field("connected", &self.connection.is_some())
            .finish()
    }
}

impl<C: Connector> AdminClient<C> {
    /// A client of the dird process running as `expected_uid`, with a
    /// per-call `deadline` ([`DEFAULT_DEADLINE`] unless admind chooses
    /// another).
    ///
    /// # Errors
    /// [`ClientConfigError::RootServerUid`].
    ///
    /// Spec: docs/51 §7.1; docs/50 R50-3, §3.6.
    pub fn new(
        connector: C,
        expected_uid: u32,
        deadline: Duration,
    ) -> Result<Self, ClientConfigError> {
        if expected_uid == 0 {
            return Err(ClientConfigError::RootServerUid);
        }
        Ok(AdminClient {
            connector,
            expected_uid,
            deadline,
            connection: None,
        })
    }

    /// Whether a verified connection is held.
    #[must_use]
    pub fn is_connected(&self) -> bool {
        self.connection.is_some()
    }

    /// The connector.
    pub fn connector(&self) -> &C {
        &self.connector
    }

    /// The held connection if it is still usable, or a new one whose peer
    /// uid is dird's — before anything is sent on it.
    /// Spec: docs/51 §7.1; docs/50 R50-3; docs/questions/Q-312 (A-82).
    fn verified(&mut self) -> Result<&mut C::Connection, Unserved> {
        let stale = match self.connection.as_mut() {
            Some(held) => held.check_idle().is_err(),
            None => false,
        };
        if stale {
            self.connection = None;
        }
        if self.connection.is_none() {
            let connection = self.connector.connect().map_err(Unserved::Transport)?;
            let uid = connection.peer_uid().map_err(Unserved::Transport)?;
            if uid != self.expected_uid {
                // Dropped here: nothing was sent on it.
                return Err(Unserved::PeerMismatch);
            }
            self.connection = Some(connection);
        }
        self.connection
            .as_mut()
            .ok_or(Unserved::Transport(TransportError::Connect))
    }

    /// Perform one call: encode, send on a verified connection, receive and
    /// decode the reply strictly, check that it answers the request. Any
    /// failure drops the connection; the request is never sent twice.
    ///
    /// # Errors
    /// [`Unserved`].
    ///
    /// Spec: docs/51 §7.3; docs/50 §3.3, §3.6, §3.7, R50-7.
    pub fn call(&mut self, request: &Request) -> Result<Reply, Unserved> {
        let result = self.call_inner(request);
        if result.is_err() {
            self.connection = None;
        }
        result
    }

    fn call_inner(&mut self, request: &Request) -> Result<Reply, Unserved> {
        let start = Instant::now();
        let wire = request.to_wire().map_err(|_| Unserved::Unencodable)?;
        let frame = encode_frame(ADMIN_CHANNEL, Direction::Request, &wire)
            .map_err(|_| Unserved::Unencodable)?;
        drop(wire);
        let deadline = self.deadline;
        let connection = self.verified()?;
        let left = remaining(start, deadline).map_err(Unserved::Transport)?;
        let body = connection
            .exchange(frame.as_bytes(), REPLY_LIMIT, left)
            .map_err(Unserved::Transport)?;
        drop(frame);
        let reply = match decode_reply::<AdminReply>(ADMIN_CHANNEL, &body)
            .map_err(Unserved::MalformedReply)?
        {
            ipc::Reply::Refused(refused) => return Err(Unserved::Refused(refused)),
            ipc::Reply::Message(reply) => {
                Reply::from_wire(&reply).map_err(Unserved::UnexpectedReply)?
            }
        };
        if !answers(request, &reply) {
            return Err(Unserved::UnexpectedReply(ConversionError::UnexpectedReply));
        }
        Ok(reply)
    }

    /// The health check. Spec: docs/50 §7.5.
    ///
    /// # Errors
    /// [`Unserved`].
    pub fn ping(&mut self) -> Result<(), Unserved> {
        self.call(&Request::Ping).map(|_| ())
    }
}
