//! A blocking Unix stream socket connection to dird's DNS socket, for dnsd
//! (the same transport as the other channels' clients, crates/ipc-dird-admin
//! and crates/ipc-ldap).
//!
//! * The peer uid comes from the kernel's peer credentials through rustix
//!   `net::sockopt::socket_peercred` (Linux, crate feature `net`); elsewhere
//!   the peer cannot be verified, so [`Connection::peer_uid`] fails and the
//!   client never sends a request (fail closed).
//! * [`Connection::send`] writes the whole frame; [`Connection::receive`]
//!   reads exactly one frame with [`ipc::FrameReader`] — the declared length
//!   checked against the bound before the body is awaited — never reading
//!   past it; the socket timeouts are set to the time remaining.
//! * [`Connection::check_idle`]: non-blocking, one read of at most one
//!   octet — end of stream is `Closed`, an octet is `Framing`, `WouldBlock`
//!   means usable (back to blocking mode); nothing is written.
//!
//! Spec: docs/50 §3.1, §3.2 (R50-3), §3.3, §3.6, §3.7, R50-7; docs/54 §4.6;
//! docs/questions/Q-312 (A-82); rustix 1.1.6 docs.rs:
//! `net::sockopt::socket_peercred`, `net::UCred`, `fs::Uid::as_raw`; std
//! 1.95.0 API documentation (the toolchain's rust-docs pages, API only):
//! `os::unix::net::UnixStream::{connect, set_nonblocking,
//! set_read_timeout, set_write_timeout}`, `io::Read::read`,
//! `io::Write::write_all`, `io::ErrorKind`.

use crate::client::{Connection, Connector, TransportError};
use core::time::Duration;
use ipc::{FrameLimit, FrameReader};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Instant;
use zeroize::Zeroizing;

/// Octets read from the socket per read call at most. Project choice.
const READ_CHUNK: usize = 4096;

/// Connects to `dird-dns.sock` at a fixed path.
/// Spec: docs/54 §4.6; docs/50 §3.1.
#[derive(Debug, Clone)]
pub struct UnixConnector {
    path: PathBuf,
}

impl UnixConnector {
    /// A connector for the socket at `path` (dnsd's `dird_dns_socket`,
    /// docs/questions/Q-619 item 4).
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

/// One blocking connection to dird's DNS socket.
/// Spec: docs/50 §3.1, §3.6.
#[derive(Debug)]
pub struct UnixConnection {
    stream: UnixStream,
}

impl UnixConnection {
    /// Wrap an already connected stream.
    #[must_use]
    pub fn from_stream(stream: UnixStream) -> UnixConnection {
        UnixConnection { stream }
    }
}

/// The time left before `deadline` measured from `start`.
fn remaining(start: Instant, deadline: Duration) -> Result<Duration, TransportError> {
    match deadline.checked_sub(start.elapsed()) {
        Some(left) if !left.is_zero() => Ok(left),
        _ => Err(TransportError::DeadlineExceeded),
    }
}

/// A socket error as a transport error: a timeout is the deadline.
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
/// Spec: docs/50 R50-3; rustix 1.1.6 `net::sockopt::socket_peercred`.
#[cfg(target_os = "linux")]
fn peer_uid_of(stream: &UnixStream) -> Result<u32, TransportError> {
    rustix::net::sockopt::socket_peercred(stream)
        .map(|credentials| credentials.uid.as_raw())
        .map_err(|_| TransportError::PeerCredentials)
}

/// No verified source of peer credentials on this platform: fail closed.
/// Spec: docs/50 R50-3; AGENTS.md §6.
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

    /// Spec: docs/50 §3.3 (bound before allocation), §3.6, R50-7.
    fn receive(
        &mut self,
        limit: FrameLimit,
        deadline: Duration,
    ) -> Result<Zeroizing<Vec<u8>>, TransportError> {
        let start = Instant::now();
        let mut reader = FrameReader::new(limit);
        let mut chunk = Zeroizing::new([0u8; READ_CHUNK]);
        loop {
            if let Some(body) = reader.body() {
                let mut reply = Zeroizing::new(Vec::with_capacity(body.len()));
                reply.extend_from_slice(body);
                reader.reset();
                return Ok(reply);
            }
            self.stream
                .set_read_timeout(Some(remaining(start, deadline)?))
                .map_err(|e| io_error(e.kind()))?;
            // Never read past the frame: the next frame of a multi-frame
            // reply stays in the socket for the next call.
            let wanted = reader.wanted().min(READ_CHUNK);
            let buffer = chunk.get_mut(..wanted).ok_or(TransportError::Framing)?;
            let read = match self.stream.read(buffer) {
                Ok(0) => return Err(TransportError::Closed),
                Ok(read) => read,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(io_error(e.kind())),
            };
            let received = buffer.get(..read).ok_or(TransportError::Framing)?;
            let taken = reader.push(received).map_err(|_| TransportError::Framing)?;
            if taken != read {
                return Err(TransportError::Framing);
            }
        }
    }

    /// Spec: docs/50 §3.6, §3.7; docs/questions/Q-312 (A-82).
    fn check_idle(&mut self) -> Result<(), TransportError> {
        self.stream
            .set_nonblocking(true)
            .map_err(|e| io_error(e.kind()))?;
        let mut probe = Zeroizing::new([0u8; 1]);
        let state = loop {
            match self.stream.read(&mut probe[..]) {
                Ok(0) => break Err(TransportError::Closed),
                Ok(_) => break Err(TransportError::Framing),
                Err(e) if e.kind() == ErrorKind::WouldBlock => break Ok(()),
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => break Err(io_error(e.kind())),
            }
        };
        state?;
        self.stream
            .set_nonblocking(false)
            .map_err(|e| io_error(e.kind()))
    }
}
