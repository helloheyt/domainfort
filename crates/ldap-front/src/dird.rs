//! The front's asynchronous client of dird's `dird-ldap.sock`: one Unix
//! connection per client connection (docs/50 R50-10: "1:1, no session ids"),
//! driving ipc-ldap's sans-I/O [`FrontChannel`] (whose documentation: "an
//! asynchronous front (task P11) can drive the same state machine").
//!
//! * **Server identity first.** After `connect`, the peer uid read from the
//!   kernel (tokio `UnixStream::peer_cred`) must be dird's configured uid —
//!   and never 0 — **before** anything is sent (docs/50 R50-3: "the client
//!   also verifies the server's uid, so that a process that captured the
//!   socket path receives no request"; ipc-ldap's `RootServerUid`).
//! * **Strict request → reply.** One request at a time; the reply's frames
//!   are read with ipc's [`FrameReader`] under the reply bound — never more
//!   octets than the current frame still needs — and decoded by the state
//!   machine with the same strictness as a request (docs/50 §3.3, R50-7).
//! * **Deadline.** Each exchange (the request and every frame of its reply)
//!   within the configured `dird_deadline` (docs/50 §3.6: "dird-ldap: 65 s").
//! * **Failure.** Every failure is an ipc-ldap [`ChannelFailure`]; the
//!   connection is dropped and the front closes the client connection with
//!   the Notice of Disconnection of `ipc_ldap::notice_of_disconnection`
//!   (docs/50 §3.7: "ldap-front without dird ⇒ the connection is closed").
//!
//! Spec: docs/50 R50-3, R50-7, R50-10, §3.1-§3.3, §3.6, §3.7, §4.2, §4.3,
//! §7.5; A-70; tokio 1.54.1 docs.rs: `net::UnixStream::{connect, peer_cred}`,
//! `net::unix::UCred::uid`, `time::timeout`, `io::{AsyncReadExt::read,
//! AsyncWriteExt::write_all}`.

use core::net::IpAddr;
use core::time::Duration;
use ipc::FrameReader;
use ipc_ldap::{
    ChannelFailure, Exchange, FrontChannel, Listener, Progress, TransportError, TransportFacts,
    CLOSE_DEADLINE, REPLY_LIMIT,
};
use parse_ldap::AuthState;
use std::path::PathBuf;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::time::timeout;
use zeroize::Zeroizing;

/// Octets read from dird per read call at most. Project choice.
const READ_CHUNK: usize = 64 * 1024;

/// Where a local server listens and which uid it must run as.
/// Spec: docs/50 R50-3, §3.1, §3.2 (crates/config `Endpoint`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    /// The socket path.
    pub socket: PathBuf,
    /// The server's uid.
    pub uid: u32,
}

/// The time left before `deadline`, measured from `start`.
/// Spec: docs/50 §3.6.
fn remaining(start: Instant, deadline: Duration) -> Result<Duration, ChannelFailure> {
    match deadline.checked_sub(start.elapsed()) {
        Some(left) if !left.is_zero() => Ok(left),
        _ => Err(ChannelFailure::Transport(TransportError::DeadlineExceeded)),
    }
}

/// A socket error as a transport error.
/// Spec: docs/50 §3.6, §3.7.
fn io_failure(kind: std::io::ErrorKind) -> ChannelFailure {
    use std::io::ErrorKind;
    ChannelFailure::Transport(match kind {
        ErrorKind::UnexpectedEof
        | ErrorKind::BrokenPipe
        | ErrorKind::ConnectionReset
        | ErrorKind::ConnectionAborted => TransportError::Closed,
        _ => TransportError::Io,
    })
}

/// Connect and verify the peer uid; nothing is sent.
/// Spec: docs/50 R50-3, §3.2.
async fn connect_verified(
    endpoint: &Endpoint,
    deadline: Duration,
) -> Result<UnixStream, ChannelFailure> {
    if endpoint.uid == 0 {
        return Err(ChannelFailure::RootServerUid);
    }
    let stream = timeout(deadline, UnixStream::connect(&endpoint.socket))
        .await
        .map_err(|_| ChannelFailure::Transport(TransportError::DeadlineExceeded))?
        .map_err(|_| ChannelFailure::Transport(TransportError::Connect))?;
    let uid = stream
        .peer_cred()
        .map_err(|_| ChannelFailure::Transport(TransportError::PeerCredentials))?
        .uid();
    if uid != endpoint.uid {
        // Dropped here: nothing was sent on it.
        return Err(ChannelFailure::PeerMismatch);
    }
    Ok(stream)
}

/// Read exactly one reply frame and return its body.
/// Spec: docs/50 §3.3 (bound before allocation), §3.6.
async fn receive(
    stream: &mut UnixStream,
    start: Instant,
    deadline: Duration,
) -> Result<Zeroizing<Vec<u8>>, ChannelFailure> {
    let mut reader = FrameReader::new(REPLY_LIMIT);
    let mut chunk = Zeroizing::new(vec![0u8; READ_CHUNK]);
    loop {
        if let Some(body) = reader.body() {
            let mut reply = Zeroizing::new(Vec::with_capacity(body.len()));
            reply.extend_from_slice(body);
            reader.reset();
            return Ok(reply);
        }
        let wanted = reader.wanted().min(READ_CHUNK);
        if wanted == 0 {
            return Err(ChannelFailure::Transport(TransportError::Framing));
        }
        let buffer = chunk
            .get_mut(..wanted)
            .ok_or(ChannelFailure::Transport(TransportError::Framing))?;
        let read = timeout(remaining(start, deadline)?, stream.read(buffer))
            .await
            .map_err(|_| ChannelFailure::Transport(TransportError::DeadlineExceeded))?
            .map_err(|e| io_failure(e.kind()))?;
        if read == 0 {
            return Err(ChannelFailure::Transport(TransportError::Closed));
        }
        let received = buffer
            .get(..read)
            .ok_or(ChannelFailure::Transport(TransportError::Framing))?;
        let taken = reader
            .push(received)
            .map_err(|_| ChannelFailure::Transport(TransportError::Framing))?;
        if taken != read {
            return Err(ChannelFailure::Transport(TransportError::Framing));
        }
    }
}

/// Write one whole frame within the deadline.
/// Spec: docs/50 §3.6.
async fn send(
    stream: &mut UnixStream,
    frame: &[u8],
    start: Instant,
    deadline: Duration,
) -> Result<(), ChannelFailure> {
    timeout(remaining(start, deadline)?, stream.write_all(frame))
        .await
        .map_err(|_| ChannelFailure::Transport(TransportError::DeadlineExceeded))?
        .map_err(|e| io_failure(e.kind()))
}

/// The front's side of one session with dird (module documentation).
/// Spec: docs/50 R50-10, §4.2, §4.3.
#[derive(Debug)]
pub struct DirdSession {
    stream: UnixStream,
    channel: FrontChannel,
    deadline: Duration,
}

impl DirdSession {
    /// Open a session for a client accepted on `listener` from `peer`:
    /// connect, verify dird's uid, `Open`, `Opened`. Returns the session and
    /// the framing state of the first message.
    ///
    /// # Errors
    /// [`ChannelFailure`].
    ///
    /// Spec: docs/50 R50-3, R50-10, §4.2.
    pub async fn open(
        endpoint: &Endpoint,
        listener: Listener,
        peer: IpAddr,
        deadline: Duration,
    ) -> Result<(DirdSession, AuthState), ChannelFailure> {
        let stream = connect_verified(endpoint, deadline).await?;
        let mut session = DirdSession {
            stream,
            channel: FrontChannel::new(),
            deadline,
        };
        let frame = session.channel.encode_open(listener, peer)?;
        match session.exchange(frame.as_bytes()).await? {
            Progress::Opened { framing } => Ok((session, framing)),
            _ => Err(ChannelFailure::UnexpectedReply),
        }
    }

    /// Hand one canonical LDAPMessage to dird and gather the whole reply.
    ///
    /// # Errors
    /// [`ChannelFailure`].
    ///
    /// Spec: docs/50 §4.2, §4.3 step 1.
    pub async fn message(
        &mut self,
        canonical: &[u8],
        transport: TransportFacts,
    ) -> Result<Exchange, ChannelFailure> {
        let frame = self.channel.encode_message(canonical, transport)?;
        match self.exchange(frame.as_bytes()).await? {
            Progress::Done(exchange) => Ok(exchange),
            _ => Err(ChannelFailure::UnexpectedReply),
        }
    }

    /// Report that the TLS layer the last `StartTls` asked for is up, with
    /// the docs/50 R50-11 parameters. Returns the framing state.
    ///
    /// # Errors
    /// [`ChannelFailure`].
    ///
    /// Spec: docs/50 §4.3 step 4.
    pub async fn tls_established(&mut self) -> Result<AuthState, ChannelFailure> {
        let frame = self.channel.encode_tls_established()?;
        match self.exchange(frame.as_bytes()).await? {
            Progress::TlsAccepted { framing } => Ok(framing),
            _ => Err(ChannelFailure::UnexpectedReply),
        }
    }

    /// End the session: a best-effort `Close` (no reply), then the
    /// connection is dropped, which dird reads as the end as well.
    /// Spec: docs/50 §4.2.
    pub async fn close(mut self) {
        if let Ok(frame) = self.channel.encode_close() {
            let _ = send(
                &mut self.stream,
                frame.as_bytes(),
                Instant::now(),
                CLOSE_DEADLINE,
            )
            .await;
        }
    }

    /// Send one request frame, then read reply frames until one completes
    /// the request, all within the deadline.
    /// Spec: docs/50 §3.6, R50-7.
    async fn exchange(&mut self, frame: &[u8]) -> Result<Progress, ChannelFailure> {
        let start = Instant::now();
        send(&mut self.stream, frame, start, self.deadline).await?;
        loop {
            let body = receive(&mut self.stream, start, self.deadline).await?;
            match self.channel.accept_reply(&body)? {
                Progress::Pending => continue,
                progress => return Ok(progress),
            }
        }
    }
}

/// Health check: connect, verify dird's uid, `Ping` → `Pong` (docs/50 §7.5
/// step 5: ldap-front makes "a test connection to dird" before it serves).
///
/// # Errors
/// [`ChannelFailure`].
///
/// Spec: docs/50 R50-3, R50-16, §7.5.
pub async fn ping(endpoint: &Endpoint, deadline: Duration) -> Result<(), ChannelFailure> {
    let start = Instant::now();
    let mut stream = connect_verified(endpoint, deadline).await?;
    let mut channel = FrontChannel::new();
    let frame = channel.encode_ping()?;
    send(&mut stream, frame.as_bytes(), start, deadline).await?;
    let body = receive(&mut stream, start, deadline).await?;
    match channel.accept_reply(&body)? {
        Progress::Pong => Ok(()),
        _ => Err(ChannelFailure::UnexpectedReply),
    }
}
