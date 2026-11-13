//! A blocking Unix stream socket connection to dird's `dird-ldap.sock`.
//!
//! * The peer uid comes from the kernel's peer credentials through rustix
//!   `net::sockopt::socket_peercred` ("Get credentials of Unix domain socket
//!   peer process"; Linux kernels with crate feature `net`), whose
//!   `UCred::uid` is a `fs::Uid` read with `as_raw`. On any other platform
//!   the peer cannot be verified, so [`Connection::peer_uid`] fails and the
//!   client never sends a request (fail closed).
//! * [`Connection::receive`] reads exactly one frame with
//!   [`ipc::FrameReader`] — never more octets than the current frame still
//!   needs (the next frame of the same reply stays in the socket), the
//!   declared length checked against the bound before the body is awaited —
//!   within the deadline; the socket timeouts are set to the time remaining
//!   before each step.
//!
//! Spec: docs/50 §3.1 ("Unix domain stream sockets"), §3.2 (R50-3: "rustix
//! `socket_peercred` in the synchronous client"), §3.3, §3.6; rustix 1.1.6
//! docs.rs: `net::sockopt::socket_peercred`, `net::UCred`, `fs::Uid::as_raw`,
//! `fd::AsFd`.

use crate::client::{Connection, Connector};
use crate::front::TransportError;
use core::time::Duration;
use ipc::{FrameLimit, FrameReader};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Instant;
use zeroize::Zeroizing;

/// Octets read from the socket per read call at most. Project choice.
const READ_CHUNK: usize = 64 * 1024;

/// Connects to dird's `dird-ldap.sock` at a fixed path.
/// Spec: docs/50 §3.1 (one socket per (server, channel)).
#[derive(Debug, Clone)]
pub struct UnixConnector {
    path: PathBuf,
}

impl UnixConnector {
    /// A connector for the socket at `path` (from the front's configuration,
    /// `dird_ldap_socket`, docs/50 §7.1).
    /// Spec: docs/50 §3.1, §7.1.
    #[must_use]
    pub fn new(path: PathBuf) -> UnixConnector {
        UnixConnector { path }
    }
}

impl Connector for UnixConnector {
    type Connection = UnixConnection;

    /// Spec: docs/50 §3.1.
    fn connect(&mut self) -> Result<UnixConnection, TransportError> {
        UnixStream::connect(&self.path)
            .map(|stream| UnixConnection { stream })
            .map_err(|_| TransportError::Connect)
    }
}

/// One blocking connection to dird.
/// Spec: docs/50 §3.1, §3.6.
#[derive(Debug)]
pub struct UnixConnection {
    stream: UnixStream,
}

impl UnixConnection {
    /// Wrap an already connected stream (e.g. one whose peer uid a test
    /// read another way).
    /// Spec: docs/50 §3.1.
    #[must_use]
    pub fn from_stream(stream: UnixStream) -> UnixConnection {
        UnixConnection { stream }
    }
}

/// The time left before `deadline` measured from `start`.
/// Spec: docs/50 §3.6.
fn remaining(start: Instant, deadline: Duration) -> Result<Duration, TransportError> {
    match deadline.checked_sub(start.elapsed()) {
        Some(left) if !left.is_zero() => Ok(left),
        _ => Err(TransportError::DeadlineExceeded),
    }
}

/// A socket error as a transport error: a timeout is the deadline.
/// Spec: docs/50 §3.6, §3.7.
fn io_error(kind: ErrorKind) -> TransportError {
    match kind {
        ErrorKind::WouldBlock | ErrorKind::TimedOut => TransportError::DeadlineExceeded,
        ErrorKind::UnexpectedEof
        | ErrorKind::BrokenPipe
        | ErrorKind::ConnectionReset
        | ErrorKind::ConnectionAborted => TransportError::Closed,
        _ => TransportError::Io,
    }
}

/// The peer's uid from the kernel's peer credentials.
/// Spec: docs/50 R50-3; rustix 1.1.6 `net::sockopt::socket_peercred`,
/// `net::UCred` (`uid: Uid`), `fs::Uid::as_raw`.
#[cfg(target_os = "linux")]
fn peer_uid_of(stream: &UnixStream) -> Result<u32, TransportError> {
    rustix::net::sockopt::socket_peercred(stream)
        .map(|credentials| credentials.uid.as_raw())
        .map_err(|_| TransportError::PeerCredentials)
}

/// No verified source of peer credentials on this platform: fail closed.
/// Spec: docs/50 R50-3; AGENTS.md §6 (fail closed).
#[cfg(not(target_os = "linux"))]
fn peer_uid_of(_stream: &UnixStream) -> Result<u32, TransportError> {
    Err(TransportError::PeerCredentials)
}

impl Connection for UnixConnection {
    /// Spec: docs/50 R50-3, §3.2.
    fn peer_uid(&self) -> Result<u32, TransportError> {
        peer_uid_of(&self.stream)
    }

    /// Spec: docs/50 §3.6.
    fn send(&mut self, frame: &[u8], deadline: Duration) -> Result<(), TransportError> {
        let start = Instant::now();
        self.stream
            .set_write_timeout(Some(remaining(start, deadline)?))
            .map_err(|e| io_error(e.kind()))?;
        self.stream.write_all(frame).map_err(|e| io_error(e.kind()))
    }

    /// Spec: docs/50 §3.3, §3.6.
    fn receive(
        &mut self,
        limit: FrameLimit,
        deadline: Duration,
    ) -> Result<Zeroizing<Vec<u8>>, TransportError> {
        let start = Instant::now();
        let mut reader = FrameReader::new(limit);
        let mut chunk = Zeroizing::new(vec![0u8; READ_CHUNK]);
        loop {
            if let Some(body) = reader.body() {
                let mut reply = Zeroizing::new(Vec::with_capacity(body.len()));
                reply.extend_from_slice(body);
                reader.reset();
                return Ok(reply);
            }
            // Some platforms refuse to set a socket timeout once the peer has
            // closed its end (dird refuses, then closes). The octets it wrote
            // before closing are still readable, without waiting: read them
            // without blocking; nothing there is the end of the stream.
            let timed = self
                .stream
                .set_read_timeout(Some(remaining(start, deadline)?))
                .is_ok();
            if !timed {
                self.stream
                    .set_nonblocking(true)
                    .map_err(|e| io_error(e.kind()))?;
            }
            let wanted = reader.wanted().min(READ_CHUNK);
            if wanted == 0 {
                return Err(TransportError::Framing);
            }
            let buffer = chunk.get_mut(..wanted).ok_or(TransportError::Framing)?;
            let read = match self.stream.read(buffer) {
                Ok(0) => return Err(TransportError::Closed),
                Ok(read) => read,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) if !timed && e.kind() == ErrorKind::WouldBlock => {
                    return Err(TransportError::Closed)
                }
                Err(e) => return Err(io_error(e.kind())),
            };
            let received = buffer.get(..read).ok_or(TransportError::Framing)?;
            let taken = reader.push(received).map_err(|_| TransportError::Framing)?;
            if taken != read {
                return Err(TransportError::Framing);
            }
        }
    }
}
