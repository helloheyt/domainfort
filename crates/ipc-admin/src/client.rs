//! A synchronous client of `admin.sock` (task A10): keyadm's — and
//! `adminctl`'s, when task A11 builds it.
//!
//! # Connections
//!
//! The transport is the one dird's admin channel already defines for a
//! blocking Unix stream with peer credentials: [`ipc_dird_admin::Connector`]
//! opens a connection, [`ipc_dird_admin::Connection`] reports the server's
//! uid (from the transport's peer credentials — never from anything the peer
//! sends) and carries one request frame and its one reply frame within a
//! deadline. Those traits are frame-agnostic; this client fills the frames
//! with this channel's codec ([`crate::encode_request`],
//! [`crate::decode_reply`]) under this channel's reply bound
//! ([`crate::REPLY_LIMIT`]).
//!
//! # Rules (as every client of this project)
//!
//! * The peer uid of every new connection is checked against admind's
//!   configured uid **before anything is sent** on it (docs/50 R50-3;
//!   precedent A-63): a process that took over the socket path receives
//!   nothing.
//! * One request in flight; strict request → reply (docs/50 R50-7).
//! * A held connection is checked before reuse, without blocking or
//!   sending; a request is **never sent twice** — after a failure the next
//!   call starts over on a new connection (A-87). Whether a failed request
//!   may have reached admind is reported ([`AdmindFailure::sent`]), so a
//!   caller never says "not done" of something that may have been done
//!   (A-88, A-90).
//! * Replies are decoded with the same strictness as requests and must
//!   answer the request ([`crate::answers`]).
//!
//! Spec: docs/51 §6 (keyadm sends `FetchApproved` / `Complete` /
//! `ListPendingDestruction` to `admin.sock`), §7.6; docs/50 R50-3, R50-7,
//! §3.3, §3.6, §3.7; A-63; A-87; A-88; A-90; docs/questions/Q-404 item 10
//! (the client deferred to its first user), Q-423.

use crate::channel::REPLY_LIMIT;
use crate::codec::{decode_reply, encode_request, ReplyError};
use crate::typed::{answers, Reply, Request};
use core::fmt;
use core::time::Duration;
use ipc::Refused;
use ipc_dird_admin::{Connection, Connector, TransportError};
use std::time::Instant;

/// The default per-call deadline: 30 s — admind's own worst case is dird's
/// client deadline (`ipc_dird_admin::DEFAULT_DEADLINE`, 20 s) behind at most
/// one queued request of keyd's 2 s deadline, plus margin. Project choice.
/// Spec: docs/51 §7.5; docs/50 §3.6; docs/questions/Q-389 item 5.
pub const DEFAULT_DEADLINE: Duration = Duration::from_secs(30);

/// Why admind did not serve a call. Carries no frame octet.
/// Spec: docs/50 §3.7 (R50-8), §8.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmindUnserved {
    /// The transport failed.
    Transport(TransportError),
    /// The peer's uid is not admind's; nothing was sent.
    PeerMismatch,
    /// admind answered with the shared transport refusal.
    Refused(Refused),
    /// The reply did not decode, or does not answer the request.
    MalformedReply,
    /// The request could not be encoded; nothing was sent.
    Unencodable,
}

/// A call admind did not serve, and whether the request may have reached
/// it.
/// Spec: docs/50 §3.7; A-88, A-90.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmindFailure {
    /// What failed.
    pub unserved: AdmindUnserved,
    /// `true` once the request was handed to the connection: from then on
    /// admind may have acted on it (unless it answered the shared refusal,
    /// which it sends only before acting).
    pub sent: bool,
}

impl fmt::Display for AdmindFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let what = match self.unserved {
            AdmindUnserved::Transport(TransportError::Connect) => {
                "admin socket could not be connected"
            }
            AdmindUnserved::Transport(TransportError::PeerCredentials) => {
                "admin socket peer credentials could not be read"
            }
            AdmindUnserved::Transport(TransportError::DeadlineExceeded) => {
                "admind did not answer in time"
            }
            AdmindUnserved::Transport(TransportError::Closed) => "admind closed the connection",
            AdmindUnserved::Transport(_) => "admin socket I/O failure",
            AdmindUnserved::PeerMismatch => "admin socket peer uid is not admind_uid",
            AdmindUnserved::Refused(Refused::Busy) => "admind is busy",
            AdmindUnserved::Refused(_) => "admind refused the request",
            AdmindUnserved::MalformedReply => "admind's reply could not be read",
            AdmindUnserved::Unencodable => "the request could not be encoded",
        };
        f.write_str(what)
    }
}

impl std::error::Error for AdmindFailure {}

/// The client was configured with an unacceptable admind uid.
/// Spec: docs/50 §3.2 ("uid 0 is never mapped").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RootServerUid;

/// The time left of a call's `deadline` that started at `start`.
/// Spec: docs/50 §3.6.
fn remaining(start: Instant, deadline: Duration) -> Result<Duration, TransportError> {
    match deadline.checked_sub(start.elapsed()) {
        Some(left) if !left.is_zero() => Ok(left),
        _ => Err(TransportError::DeadlineExceeded),
    }
}

/// A synchronous client of `admin.sock` (module documentation).
/// Spec: docs/51 §6, §7.6; docs/50 R50-3, R50-7, §3.6, §3.7.
pub struct AdmindClient<C: Connector> {
    connector: C,
    expected_uid: u32,
    deadline: Duration,
    connection: Option<C::Connection>,
}

impl<C: Connector> fmt::Debug for AdmindClient<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdmindClient")
            .field("expected_uid", &self.expected_uid)
            .field("deadline", &self.deadline)
            .field("connected", &self.connection.is_some())
            .finish()
    }
}

impl<C: Connector> AdmindClient<C> {
    /// A client of the admind process running as `expected_uid`.
    ///
    /// # Errors
    /// [`RootServerUid`] for uid 0.
    ///
    /// Spec: docs/50 R50-3, §3.2, §3.6.
    pub fn new(
        connector: C,
        expected_uid: u32,
        deadline: Duration,
    ) -> Result<AdmindClient<C>, RootServerUid> {
        if expected_uid == 0 {
            return Err(RootServerUid);
        }
        Ok(AdmindClient {
            connector,
            expected_uid,
            deadline,
            connection: None,
        })
    }

    /// The held connection if still usable, or a new one whose peer uid is
    /// admind's — before anything is sent on it.
    /// Spec: docs/50 R50-3; A-63; A-87.
    fn verified(&mut self) -> Result<&mut C::Connection, AdmindUnserved> {
        let stale = match self.connection.as_mut() {
            Some(held) => held.check_idle().is_err(),
            None => false,
        };
        if stale {
            self.connection = None;
        }
        if self.connection.is_none() {
            let connection = self
                .connector
                .connect()
                .map_err(AdmindUnserved::Transport)?;
            let uid = connection.peer_uid().map_err(AdmindUnserved::Transport)?;
            if uid != self.expected_uid {
                return Err(AdmindUnserved::PeerMismatch);
            }
            self.connection = Some(connection);
        }
        self.connection
            .as_mut()
            .ok_or(AdmindUnserved::Transport(TransportError::Connect))
    }

    /// Perform one call: encode, send on a verified connection, decode the
    /// reply strictly, check it answers the request. Any failure drops the
    /// connection; the request is never sent twice.
    ///
    /// # Errors
    /// [`AdmindFailure`].
    ///
    /// Spec: docs/51 §7.6; docs/50 §3.3, §3.6, §3.7, R50-7; A-87.
    pub fn call(&mut self, request: &Request) -> Result<Reply, AdmindFailure> {
        let result = self.call_inner(request);
        if result.is_err() {
            self.connection = None;
        }
        result
    }

    fn call_inner(&mut self, request: &Request) -> Result<Reply, AdmindFailure> {
        let unsent = |unserved| AdmindFailure {
            unserved,
            sent: false,
        };
        let start = Instant::now();
        let frame = encode_request(request).map_err(|_| unsent(AdmindUnserved::Unencodable))?;
        let deadline = self.deadline;
        let connection = self.verified().map_err(unsent)?;
        let left = remaining(start, deadline).map_err(|e| unsent(AdmindUnserved::Transport(e)))?;
        let body = connection
            .exchange(frame.as_bytes(), REPLY_LIMIT, left)
            .map_err(|e| AdmindFailure {
                unserved: AdmindUnserved::Transport(e),
                sent: true,
            })?;
        drop(frame);
        let sent = |unserved| AdmindFailure {
            unserved,
            sent: true,
        };
        let reply = match decode_reply(&body) {
            Ok(ipc::Reply::Refused(refused)) => return Err(sent(AdmindUnserved::Refused(refused))),
            Ok(ipc::Reply::Message(reply)) => reply,
            Err(ReplyError::Malformed(_) | ReplyError::Conversion(_)) => {
                return Err(sent(AdmindUnserved::MalformedReply))
            }
        };
        if !answers(request, &reply) {
            return Err(sent(AdmindUnserved::MalformedReply));
        }
        Ok(reply)
    }

    /// admind's health check. Spec: docs/50 §7.5.
    ///
    /// # Errors
    /// [`AdmindFailure`].
    pub fn ping(&mut self) -> Result<(), AdmindFailure> {
        self.call(&Request::Ping).map(|_| ())
    }
}
