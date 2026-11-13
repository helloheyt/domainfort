//! A blocking Unix stream socket connection to keyd, for the kdc daemon's
//! synchronous engine thread.
//!
//! * The peer uid comes from the kernel's peer credentials through rustix
//!   `net::sockopt::socket_peercred` ("Get credentials of Unix domain socket
//!   peer process"; available on Linux kernels with crate feature `net`),
//!   whose `UCred::uid` is a `fs::Uid` read with `as_raw`. On any other
//!   platform the peer cannot be verified, so [`Connection::peer_uid`]
//!   fails and the client never sends a request (fail closed).
//! * Each exchange writes the whole request frame, then reads exactly one
//!   reply frame with [`ipc::FrameReader`] — never more octets than the
//!   current frame still needs, the declared length checked against the
//!   reply bound before the body is awaited — all within the deadline; the
//!   socket read / write timeouts are set to the time remaining before each
//!   step. Where the platform refuses a read timeout because keyd already
//!   closed its end (it does after a refusal), what keyd wrote is read
//!   without blocking, and nothing left is the end of the stream — so a
//!   refusal is not lost (as crates/ipc-ldap unix.rs; docs/questions/Q-350
//!   item 14, Q-367).
//! * Before a held connection is reused, [`Connection::check_idle`] looks at
//!   it without blocking: the stream is put in non-blocking mode and one
//!   read of at most one octet is tried — end of stream (`Ok(0)`) is
//!   `Closed`, an octet is `Framing` (nothing may arrive on an idle strict
//!   request → reply connection), another error is that error, and
//!   `WouldBlock` (nothing to read) means usable: the stream goes back to
//!   blocking mode. Nothing is written.
//!
//! Spec: docs/50 §3.1 ("Unix domain stream sockets"), §3.2 (R50-3: "rustix
//! `socket_peercred` in the synchronous client … the client verifies that
//! the server's uid is the configured uid of keyd"), §3.3, §3.6 ("kdc:
//! synchronous client — std `UnixStream` + timeout"; deadline 2 s; idle
//! connections held), §3.7, R50-7; docs/questions/Q-312 (A-82); rustix 1.1.6
//! docs.rs: `net::sockopt::socket_peercred`, `net::UCred`,
//! `fs::Uid::as_raw`, `fd::AsFd`; std 1.95.0 API documentation (the
//! toolchain's rust-docs pages, API only): `os::unix::net::UnixStream::
//! set_nonblocking` ("Moves the socket into or out of nonblocking mode"),
//! `io::Read::read` (`Ok(0)`: "end of file"), `io::ErrorKind::{WouldBlock,
//! Interrupted}`.

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

/// Connects to keyd's socket at a fixed path.
/// Spec: docs/50 §3.1 (`keyd.sock`, one socket per (server, channel)).
#[derive(Debug, Clone)]
pub struct UnixConnector {
    path: PathBuf,
}

impl UnixConnector {
    /// A connector for the keyd socket at `path` (from the daemon's
    /// configuration, docs/50 §7.1).
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

/// One blocking connection to keyd.
/// Spec: docs/50 §3.1, §3.6.
#[derive(Debug)]
pub struct UnixConnection {
    stream: UnixStream,
}

impl UnixConnection {
    /// Wrap an already connected stream (e.g. one end of a socket pair).
    /// Spec: docs/50 §3.1.
    #[must_use]
    pub fn from_stream(stream: UnixStream) -> UnixConnection {
        UnixConnection { stream }
    }
}

/// The time left before `deadline` measured from `start`; none left is
/// [`TransportError::DeadlineExceeded`] (a zero timeout is not a valid
/// socket timeout).
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
/// Spec: docs/50 R50-3; rustix 1.1.6 `net::sockopt::socket_peercred`
/// (`getsockopt(fd, SOL_SOCKET, SO_PEERCRED)`), `net::UCred` (`uid: Uid`,
/// "User ID of peer"), `fs::Uid::as_raw`.
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

/// Look at an idle stream without blocking and without writing (module
/// documentation). Usable ⇒ the stream is back in blocking mode; otherwise
/// the caller drops it.
/// Spec: docs/50 §3.6, §3.7, R50-7; docs/questions/Q-312 (A-82); std
/// `UnixStream::set_nonblocking`, `io::Read::read`.
fn check_idle_stream(stream: &mut UnixStream) -> Result<(), TransportError> {
    stream
        .set_nonblocking(true)
        .map_err(|e| io_error(e.kind()))?;
    let mut probe = Zeroizing::new([0u8; 1]);
    let state = loop {
        match stream.read(&mut probe[..]) {
            Ok(0) => break Err(TransportError::Closed),
            // An octet on an idle request → reply connection (R50-7).
            Ok(_) => break Err(TransportError::Framing),
            Err(e) if e.kind() == ErrorKind::WouldBlock => break Ok(()),
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => break Err(io_error(e.kind())),
        }
    };
    state?;
    stream
        .set_nonblocking(false)
        .map_err(|e| io_error(e.kind()))
}

impl Connection for UnixConnection {
    /// Spec: docs/50 R50-3, §3.2.
    fn peer_uid(&self) -> Result<u32, TransportError> {
        peer_uid_of(&self.stream)
    }

    /// Spec: docs/50 §3.6, §3.7, R50-7; docs/questions/Q-312 (A-82).
    fn check_idle(&mut self) -> Result<(), TransportError> {
        check_idle_stream(&mut self.stream)
    }

    /// Spec: docs/50 §3.3, §3.6, R50-7.
    fn exchange(
        &mut self,
        frame: &[u8],
        reply_limit: FrameLimit,
        deadline: Duration,
    ) -> Result<Zeroizing<Vec<u8>>, TransportError> {
        let start = Instant::now();
        self.stream
            .set_write_timeout(Some(remaining(start, deadline)?))
            .map_err(|e| io_error(e.kind()))?;
        self.stream
            .write_all(frame)
            .map_err(|e| io_error(e.kind()))?;
        let mut reader = FrameReader::new(reply_limit);
        let mut chunk = Zeroizing::new([0u8; READ_CHUNK]);
        loop {
            if let Some(body) = reader.body() {
                let mut reply = Zeroizing::new(Vec::with_capacity(body.len()));
                reply.extend_from_slice(body);
                reader.reset();
                return Ok(reply);
            }
            // Some platforms refuse to set a socket timeout once the peer
            // has closed its end — keyd closes after a refusal
            // (`Refused::Unavailable`, which since A-88 means "not
            // performed" for a key-state change). The octets it wrote before
            // closing are still readable without waiting: read them without
            // blocking; nothing there is the end of the stream. (The same
            // rule as crates/ipc-ldap unix.rs; docs/questions/Q-350 item 14.)
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
                // Octets beyond the one reply: not a strict request → reply
                // peer (R50-7).
                return Err(TransportError::Framing);
            }
        }
    }
}
