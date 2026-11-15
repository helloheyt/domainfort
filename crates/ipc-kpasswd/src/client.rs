//! The front's side: an asynchronous client of `dird-kpasswd.sock` (tokio),
//! for kpasswd-front. It links no store, no keyd and no Kerberos crate
//! (tests/no_cleartext_password.rs).
//!
//! # The peer is verified on every connection, by construction (C12)
//!
//! A [`KpasswdClient`] cannot be built without an [`ExpectedDird`]: dird's
//! uid (never 0) and the [`FrontZone`] dird must have assigned **this**
//! process. Every call opens a fresh connection and, **before** anything
//! else is sent on it, checks:
//!
//! 1. the peer uid, read from the kernel's peer credentials (tokio
//!    `UnixStream::peer_cred`), is dird's — so a process that captured the
//!    socket path receives no request, not one forwarded KRB-PRIV (docs/50
//!    R50-3);
//! 2. dird answers `Ping` with a `Pong` naming the expected zone — the zone
//!    dird derived for this connection from the front's peer uid (the R14 +
//!    R9b pattern; docs/53 §3.3).
//!
//! Anything else — another uid, another zone, a refusal or failure of the
//! probe — drops the connection and the request is not sent. There is no
//! constructor without the expectation and nothing to switch it off (the
//! pattern of crates/ipc-dns `ExpectedDird` and crates/ipc-audit-client
//! `ExpectedAuditd`).
//!
//! # One request per connection; no resend
//!
//! RFC 3244 §2 has one request and one reply per client connection, and dird
//! closes a channel connection after its `ChangePassword` (crate::server),
//! so the client opens one channel connection per change: connect, verify,
//! request, one reply, close — no held connection to check, no idle state. A
//! request is never sent twice: once written, any failure ends the call as
//! [`Unserved::OutcomeUnknown`] (dird may already have committed the change;
//! its audit trail and keyd's say what happened — docs/53 §5.6 step 6, the
//! "safe state" of docs/47 §9.2), and the front answers HARDERROR.
//!
//! # Deadline
//!
//! One deadline per call covers the connect, the verification, the request
//! and the reply ([`crate::DEFAULT_DEADLINE`] unless the front's
//! configuration lowers it). Reply frames are read with ipc's
//! [`FrameReader`] under [`REPLY_LIMIT`] — the declared length is checked
//! before the body is awaited — and decoded with the same strictness as a
//! request (docs/50 §3.3).
//!
//! # What the caller sees
//!
//! | what happened | result |
//! |---|---|
//! | connect, I/O, peer closed, deadline — before the request was written | `Err(Unserved::Transport)` |
//! | the same after the request was written | `Err(Unserved::OutcomeUnknown)` |
//! | peer uid unreadable or not dird's (nothing sent) | `Err(Unserved::Transport(PeerCredentials))` / `Err(Unserved::PeerMismatch)` |
//! | the `Pong` named another zone (only the `Ping` was sent) | `Err(Unserved::ZoneMismatch)` |
//! | the shared `Refused` (Busy, Unavailable, Malformed, VersionMismatch) | `Err(Unserved::Refused)` |
//! | a reply that does not decode | `Err(Unserved::MalformedReply)` |
//! | a reply that does not answer the request | `Err(Unserved::UnexpectedReply)` |
//! | dird's answer | `Ok(…)` |
//!
//! Spec: docs/53 §4.3, §5.6, §5.7; docs/50 R50-3, R50-7, R50-8, §3.3, §3.6,
//! §3.7; docs/52 §3.12 (C12); tokio 1.54.1 docs.rs: `net::UnixStream::
//! {connect, peer_cred}`, `net::unix::UCred::uid`, `time::timeout`,
//! `io::{AsyncReadExt::read, AsyncWriteExt::write_all}`.

use crate::channel::{KPASSWD_CHANNEL, REPLY_LIMIT};
use crate::values::{ChangePasswordRequest, FrontZone, KpasswdAnswer};
use crate::wire::{KpasswdReply, KpasswdRequest};
use core::fmt;
use core::time::Duration;
use ipc::{decode_reply, encode_frame, Direction, FrameReader, Refused, Reply};
use std::path::{Path, PathBuf};
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::time::timeout;
use zeroize::Zeroizing;

/// Octets read from dird per read call at most. Project choice.
const READ_CHUNK: usize = 4096;

/// A transport failure. Carries no octet of any frame.
/// Spec: docs/50 §3.6, §3.7, §8.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportError {
    /// The connection could not be opened (dird down, no socket).
    Connect,
    /// The peer's credentials could not be read — fail closed.
    PeerCredentials,
    /// dird closed the connection.
    Closed,
    /// The deadline passed before the exchange completed.
    DeadlineExceeded,
    /// Another I/O failure.
    Io,
    /// A reply did not frame (bad length prefix, over the bound).
    Framing,
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            TransportError::Connect => "dird kpasswd connection could not be opened",
            TransportError::PeerCredentials => "dird peer credentials unavailable",
            TransportError::Closed => "dird closed the connection",
            TransportError::DeadlineExceeded => "dird deadline exceeded",
            TransportError::Io => "dird connection I/O failure",
            TransportError::Framing => "dird reply did not frame",
        })
    }
}

impl std::error::Error for TransportError {}

/// The client was configured with an unacceptable expectation.
/// Spec: docs/50 §3.2 ("uid 0 is never mapped").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientConfigError {
    /// dird's uid cannot be 0: dird never runs as root after its hardening
    /// (docs/50 §6), and accepting uid 0 would accept any root process.
    RootServerUid,
}

impl fmt::Display for ClientConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientConfigError::RootServerUid => f.write_str("dird's uid cannot be 0"),
        }
    }
}

impl std::error::Error for ClientConfigError {}

/// What the front expects of dird on every connection: its uid, and the
/// zone it must have assigned this process (module documentation).
/// Spec: docs/53 §3.3, §5.6 step 1; docs/50 R50-3; docs/52 §3.12 (C12).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpectedDird {
    uid: u32,
    zone: FrontZone,
}

impl ExpectedDird {
    /// Expect dird to run as `uid` and to name `zone` in its `Pong`.
    ///
    /// # Errors
    /// [`ClientConfigError::RootServerUid`].
    ///
    /// Spec: docs/53 §5.6; docs/50 §3.2.
    pub const fn new(uid: u32, zone: FrontZone) -> Result<ExpectedDird, ClientConfigError> {
        if uid == 0 {
            return Err(ClientConfigError::RootServerUid);
        }
        Ok(ExpectedDird { uid, zone })
    }

    /// dird's uid.
    #[must_use]
    pub const fn uid(&self) -> u32 {
        self.uid
    }

    /// The zone dird must name.
    #[must_use]
    pub const fn zone(&self) -> FrontZone {
        self.zone
    }
}

/// Why dird did not serve a call (module documentation). Every case is
/// answered HARDERROR by the front (docs/53 §5.7: "keyd / dird not
/// available, `Busy`, an unknown outcome ⇒ 2").
/// Spec: docs/50 §3.7 (R50-8); docs/53 §5.6, §5.7.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unserved {
    /// The transport failed before the request was written.
    Transport(TransportError),
    /// The transport failed after the request was written: dird may have
    /// acted on it.
    OutcomeUnknown(TransportError),
    /// The peer's uid is not dird's; nothing was sent.
    PeerMismatch,
    /// dird's `Pong` named another zone; only the `Ping` was sent.
    ZoneMismatch,
    /// dird answered with the shared transport refusal.
    Refused(Refused),
    /// A reply did not decode at the ipc layer.
    MalformedReply(ipc::Error),
    /// A reply decoded but does not answer the request.
    UnexpectedReply,
    /// The request could not be encoded; nothing was sent.
    Unencodable,
}

impl fmt::Display for Unserved {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Unserved::Transport(error) => write!(f, "{error}"),
            Unserved::OutcomeUnknown(error) => write!(f, "outcome unknown: {error}"),
            Unserved::PeerMismatch => f.write_str("dird peer is not the configured uid"),
            Unserved::ZoneMismatch => f.write_str("dird assigned another zone"),
            Unserved::Refused(refused) => write!(f, "dird refused: {refused:?}"),
            Unserved::MalformedReply(error) => write!(f, "dird reply malformed: {error}"),
            Unserved::UnexpectedReply => f.write_str("dird reply does not answer the request"),
            Unserved::Unencodable => f.write_str("request could not be encoded"),
        }
    }
}

impl std::error::Error for Unserved {}

/// The time left of a call's `deadline` that started at `start`.
/// Spec: docs/50 §3.6.
fn remaining(start: Instant, deadline: Duration) -> Result<Duration, TransportError> {
    match deadline.checked_sub(start.elapsed()) {
        Some(left) if !left.is_zero() => Ok(left),
        _ => Err(TransportError::DeadlineExceeded),
    }
}

/// A socket error as a transport error.
/// Spec: docs/50 §3.6, §3.7.
fn io_error(kind: std::io::ErrorKind) -> TransportError {
    use std::io::ErrorKind;
    match kind {
        ErrorKind::UnexpectedEof
        | ErrorKind::BrokenPipe
        | ErrorKind::ConnectionReset
        | ErrorKind::ConnectionAborted => TransportError::Closed,
        ErrorKind::TimedOut => TransportError::DeadlineExceeded,
        _ => TransportError::Io,
    }
}

/// Write one whole frame within the deadline.
/// Spec: docs/50 §3.6.
async fn send(
    stream: &mut UnixStream,
    frame: &[u8],
    start: Instant,
    deadline: Duration,
) -> Result<(), TransportError> {
    timeout(remaining(start, deadline)?, stream.write_all(frame))
        .await
        .map_err(|_| TransportError::DeadlineExceeded)?
        .map_err(|e| io_error(e.kind()))
}

/// Read exactly one reply frame and return its body: the declared length
/// checked against [`REPLY_LIMIT`] before the body is awaited; never more
/// octets than the frame still needs.
/// Spec: docs/50 §3.3 (bound before allocation), §3.6.
async fn receive(
    stream: &mut UnixStream,
    start: Instant,
    deadline: Duration,
) -> Result<Zeroizing<Vec<u8>>, TransportError> {
    let mut reader = FrameReader::new(REPLY_LIMIT);
    let mut chunk = Zeroizing::new([0u8; READ_CHUNK]);
    loop {
        if let Some(body) = reader.body() {
            let mut reply = Zeroizing::new(Vec::with_capacity(body.len()));
            reply.extend_from_slice(body);
            reader.reset();
            return Ok(reply);
        }
        let wanted = reader.wanted().min(READ_CHUNK);
        if wanted == 0 {
            return Err(TransportError::Framing);
        }
        let buffer = chunk.get_mut(..wanted).ok_or(TransportError::Framing)?;
        let read = timeout(remaining(start, deadline)?, stream.read(buffer))
            .await
            .map_err(|_| TransportError::DeadlineExceeded)?
            .map_err(|e| io_error(e.kind()))?;
        if read == 0 {
            return Err(TransportError::Closed);
        }
        let received = buffer.get(..read).ok_or(TransportError::Framing)?;
        let taken = reader.push(received).map_err(|_| TransportError::Framing)?;
        if taken != read {
            return Err(TransportError::Framing);
        }
    }
}

/// Decode one reply body strictly; the shared refusal is an error.
/// Spec: docs/50 §3.3 (replies decoded with the same strictness); A-59.
fn decode_one(body: &[u8]) -> Result<KpasswdReply, Unserved> {
    match decode_reply::<KpasswdReply>(KPASSWD_CHANNEL, body).map_err(Unserved::MalformedReply)? {
        Reply::Refused(refused) => Err(Unserved::Refused(refused)),
        Reply::Message(reply) => Ok(reply),
    }
}

/// An asynchronous client of dird's kpasswd channel (module documentation).
/// Spec: docs/53 §4.3, §5.6; docs/50 R50-3, R50-7, §3.6, §3.7.
#[derive(Debug, Clone)]
pub struct KpasswdClient {
    socket: PathBuf,
    expected: ExpectedDird,
    deadline: Duration,
}

impl KpasswdClient {
    /// A client of the dird `expected` describes, listening on `socket`,
    /// with a per-call `deadline`.
    /// Spec: docs/53 §5.6; docs/50 §3.6.
    #[must_use]
    pub fn new(socket: PathBuf, expected: ExpectedDird, deadline: Duration) -> KpasswdClient {
        KpasswdClient {
            socket,
            expected,
            deadline,
        }
    }

    /// What this client expects of dird.
    #[must_use]
    pub fn expected(&self) -> ExpectedDird {
        self.expected
    }

    /// The socket path.
    #[must_use]
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// The per-call deadline.
    #[must_use]
    pub fn deadline(&self) -> Duration {
        self.deadline
    }

    /// A new connection that passed both checks — dird's uid, then a `Pong`
    /// naming the expected zone — before anything else was sent on it.
    /// Spec: docs/53 §5.6 step 1; docs/50 R50-3; module documentation.
    async fn verified(&self, start: Instant) -> Result<UnixStream, Unserved> {
        let left = remaining(start, self.deadline).map_err(Unserved::Transport)?;
        let mut stream = timeout(left, UnixStream::connect(&self.socket))
            .await
            .map_err(|_| Unserved::Transport(TransportError::DeadlineExceeded))?
            .map_err(|_| Unserved::Transport(TransportError::Connect))?;
        let uid = stream
            .peer_cred()
            .map_err(|_| Unserved::Transport(TransportError::PeerCredentials))?
            .uid();
        if uid != self.expected.uid {
            // Dropped here: nothing was sent on it.
            return Err(Unserved::PeerMismatch);
        }
        let ping = encode_frame(KPASSWD_CHANNEL, Direction::Request, &KpasswdRequest::Ping)
            .map_err(|_| Unserved::Unencodable)?;
        send(&mut stream, ping.as_bytes(), start, self.deadline)
            .await
            .map_err(Unserved::Transport)?;
        let body = receive(&mut stream, start, self.deadline)
            .await
            .map_err(Unserved::Transport)?;
        // Dropped on any failure: only the `Ping` was sent on it.
        match decode_one(&body)? {
            KpasswdReply::Pong { zone } if zone == self.expected.zone => Ok(stream),
            KpasswdReply::Pong { .. } => Err(Unserved::ZoneMismatch),
            _ => Err(Unserved::UnexpectedReply),
        }
    }

    /// The start-up and health check: connect, dird's uid, `Ping` → a `Pong`
    /// naming the expected zone, close.
    ///
    /// # Errors
    /// [`Unserved`].
    ///
    /// Spec: docs/50 R50-16, §7.5; docs/53 §5.6 step 1.
    pub async fn ping(&self) -> Result<(), Unserved> {
        self.verified(Instant::now()).await.map(drop)
    }

    /// Hand one change request to dird and return its answer: keyd's sealed
    /// reply, or the code of the front's KRB-ERROR. The request is encoded
    /// first (nothing is sent if it cannot be), then sent once on a fresh
    /// verified connection.
    ///
    /// # Errors
    /// [`Unserved`]; the front answers HARDERROR (docs/53 §5.7).
    ///
    /// Spec: docs/53 §4.3, §5.5–§5.7; docs/50 §3.3, §3.6, §3.7, R50-7.
    pub async fn change_password(
        &self,
        request: &ChangePasswordRequest,
    ) -> Result<KpasswdAnswer, Unserved> {
        let start = Instant::now();
        let frame = encode_frame(
            KPASSWD_CHANNEL,
            Direction::Request,
            &KpasswdRequest::ChangePassword(request.clone()),
        )
        .map_err(|_| Unserved::Unencodable)?;
        let mut stream = self.verified(start).await?;
        // From the first octet written on, a failure leaves the outcome
        // unknown (module documentation).
        send(&mut stream, frame.as_bytes(), start, self.deadline)
            .await
            .map_err(Unserved::OutcomeUnknown)?;
        drop(frame);
        let body = receive(&mut stream, start, self.deadline)
            .await
            .map_err(Unserved::OutcomeUnknown)?;
        match decode_one(&body)? {
            KpasswdReply::Sealed(sealed) => Ok(KpasswdAnswer::Sealed(sealed)),
            KpasswdReply::Unsealed(code) => Ok(KpasswdAnswer::Unsealed(code)),
            KpasswdReply::Pong { .. } => Err(Unserved::UnexpectedReply),
        }
    }
}
