//! The front's blocking client of one session: [`LdapChannelClient`] drives
//! a [`FrontChannel`] over a [`Connection`], one request at a time, each
//! reply within a deadline.
//!
//! # Connections
//!
//! [`Connector`] opens a connection; [`Connection`] reports the peer's uid
//! (from the transport's peer credentials — never from anything the peer
//! sends), sends one whole frame, and receives exactly one frame (its
//! declared length checked against the bound before the body is awaited).
//! Tests use an in-process loopback; a front a blocking Unix stream socket
//! (`crate::unix`). One client connection to the front is one connection to
//! dird (docs/50 R50-10: "one Unix connection to dird per client
//! connection, 1:1, no session ids").
//!
//! The peer uid of the new connection must be dird's configured uid
//! **before** anything is sent (docs/50 R50-3: "the client also verifies the
//! server's uid, so that a process that captured the socket path receives no
//! request"). Any failure drops the connection; the session cannot go on and
//! the front closes the client connection with the Notice of Disconnection
//! of crate::front.
//!
//! Spec: docs/50 R50-3, R50-7, R50-10, §3.1, §3.2, §3.6 (dird-ldap
//! deadline 65 s), §3.7, §4.2, §7.5.

use crate::channel::{Listener, REPLY_LIMIT};
use crate::front::{ChannelFailure, Exchange, FrontChannel, Progress, TransportError};
use crate::wire::TransportFacts;
use core::fmt;
use core::net::IpAddr;
use core::time::Duration;
use ipc::FrameLimit;
use parse_ldap::AuthState;
use std::time::Instant;
use zeroize::Zeroizing;

/// The default deadline for dird's reply to one request: 65 seconds, above
/// the engine's 60-second query bound.
/// Spec: docs/50 §3.6 ("dird-ldap: 65 s (above `MAX_QUERY_SECONDS` = 60 of
/// the engine)"); crates/config ldap_front.rs `DIRD_LDAP_DEADLINE_SECS`.
pub const DEFAULT_DEADLINE: Duration = Duration::from_secs(65);

/// How long a best-effort `Close` may take to write. Project choice.
pub const CLOSE_DEADLINE: Duration = Duration::from_secs(1);

/// One open connection to dird.
/// Spec: docs/50 §3.1 (Unix stream socket), §3.2 (peer credentials), §3.6.
pub trait Connection {
    /// The uid of the process at the other end, from the transport's peer
    /// credentials. Spec: docs/50 R50-3, §3.2.
    fn peer_uid(&self) -> Result<u32, TransportError>;

    /// Write one whole frame (length prefix included) within `deadline`.
    /// Spec: docs/50 §3.6.
    fn send(&mut self, frame: &[u8], deadline: Duration) -> Result<(), TransportError>;

    /// Read exactly one frame and return its body: never more octets than
    /// the frame needs; its declared length checked against `limit` before
    /// the body is awaited; within `deadline`.
    /// Spec: docs/50 §3.3 (bound before allocation), §3.6.
    fn receive(
        &mut self,
        limit: FrameLimit,
        deadline: Duration,
    ) -> Result<Zeroizing<Vec<u8>>, TransportError>;
}

/// Opens connections to dird.
/// Spec: docs/50 §3.1.
pub trait Connector {
    /// The connection type.
    type Connection: Connection;

    /// Open a new connection.
    fn connect(&mut self) -> Result<Self::Connection, TransportError>;
}

/// The time left before `deadline` measured from `start`.
/// Spec: docs/50 §3.6.
fn remaining(start: Instant, deadline: Duration) -> Result<Duration, ChannelFailure> {
    match deadline.checked_sub(start.elapsed()) {
        Some(left) if !left.is_zero() => Ok(left),
        _ => Err(ChannelFailure::Transport(TransportError::DeadlineExceeded)),
    }
}

/// A new connection whose peer is dird's configured uid; nothing has been
/// sent on it. Spec: docs/50 R50-3, §3.2.
fn verified<K: Connector>(
    connector: &mut K,
    expected_uid: u32,
) -> Result<K::Connection, ChannelFailure> {
    if expected_uid == 0 {
        return Err(ChannelFailure::RootServerUid);
    }
    let connection = connector.connect().map_err(ChannelFailure::Transport)?;
    let uid = connection.peer_uid().map_err(ChannelFailure::Transport)?;
    if uid != expected_uid {
        // Dropped here: nothing was sent on it.
        return Err(ChannelFailure::PeerMismatch);
    }
    Ok(connection)
}

/// The front's client of one session (module documentation).
/// Spec: docs/50 R50-10, §4.2, §4.3.
pub struct LdapChannelClient<C: Connection> {
    connection: Option<C>,
    channel: FrontChannel,
    deadline: Duration,
}

impl<C: Connection> fmt::Debug for LdapChannelClient<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LdapChannelClient")
            .field("connected", &self.connection.is_some())
            .field("channel", &self.channel)
            .field("deadline", &self.deadline)
            .finish()
    }
}

impl<C: Connection> LdapChannelClient<C> {
    /// Open a session for a client accepted on `listener` from `peer_addr`:
    /// connect, verify dird's uid, send `Open`, read `Opened`. Returns the
    /// client and the framing state of the first message.
    ///
    /// # Errors
    /// [`ChannelFailure`] — the front closes the client connection.
    ///
    /// Spec: docs/50 R50-3, R50-10, §4.2.
    pub fn open<K: Connector<Connection = C>>(
        connector: &mut K,
        expected_uid: u32,
        listener: Listener,
        peer_addr: IpAddr,
        deadline: Duration,
    ) -> Result<(LdapChannelClient<C>, AuthState), ChannelFailure> {
        let connection = verified(connector, expected_uid)?;
        let mut client = LdapChannelClient {
            connection: Some(connection),
            channel: FrontChannel::new(),
            deadline,
        };
        let frame = client.channel.encode_open(listener, peer_addr)?;
        match client.exchange(frame.as_bytes())? {
            Progress::Opened { framing } => Ok((client, framing)),
            _ => Err(client.failed(ChannelFailure::UnexpectedReply)),
        }
    }

    /// The framing state dird reported last.
    #[must_use]
    pub fn framing(&self) -> AuthState {
        self.channel.framing()
    }

    /// The session's state machine (read-only).
    #[must_use]
    pub fn channel(&self) -> &FrontChannel {
        &self.channel
    }

    /// Hand one canonical LDAPMessage to dird and gather the whole reply.
    ///
    /// # Errors
    /// [`ChannelFailure`] — the front closes the client connection.
    ///
    /// Spec: docs/50 §4.2, §4.3 step 1.
    pub fn message(
        &mut self,
        canonical: &[u8],
        transport: TransportFacts,
    ) -> Result<Exchange, ChannelFailure> {
        let frame = match self.channel.encode_message(canonical, transport) {
            Ok(frame) => frame,
            Err(failure) => return Err(self.failed(failure)),
        };
        match self.exchange(frame.as_bytes())? {
            Progress::Done(exchange) => Ok(exchange),
            _ => Err(self.failed(ChannelFailure::UnexpectedReply)),
        }
    }

    /// Report that the TLS layer is up (only after `Done { StartTls }`).
    /// Returns the framing state.
    ///
    /// # Errors
    /// [`ChannelFailure`] — the front closes the client connection.
    ///
    /// Spec: docs/50 §4.3 step 4.
    pub fn tls_established(&mut self) -> Result<AuthState, ChannelFailure> {
        let frame = match self.channel.encode_tls_established() {
            Ok(frame) => frame,
            Err(failure) => return Err(self.failed(failure)),
        };
        match self.exchange(frame.as_bytes())? {
            Progress::TlsAccepted { framing } => Ok(framing),
            _ => Err(self.failed(ChannelFailure::UnexpectedReply)),
        }
    }

    /// End the session: a best-effort `Close` (no reply), then the
    /// connection is dropped, which dird also reads as the end.
    /// Spec: docs/50 §4.2.
    pub fn close(mut self) {
        if let (Ok(frame), Some(connection)) =
            (self.channel.encode_close(), self.connection.as_mut())
        {
            let _ = connection.send(frame.as_bytes(), CLOSE_DEADLINE);
        }
        self.connection = None;
    }

    /// Drop the connection and report `failure`.
    fn failed(&mut self, failure: ChannelFailure) -> ChannelFailure {
        self.connection = None;
        failure
    }

    /// Send one request frame, then read reply frames until one completes
    /// the request, all within the deadline.
    /// Spec: docs/50 §3.6, R50-7.
    fn exchange(&mut self, frame: &[u8]) -> Result<Progress, ChannelFailure> {
        let result = self.exchange_inner(frame);
        if result.is_err() {
            self.connection = None;
        }
        result
    }

    fn exchange_inner(&mut self, frame: &[u8]) -> Result<Progress, ChannelFailure> {
        let start = Instant::now();
        let deadline = self.deadline;
        let connection = self
            .connection
            .as_mut()
            .ok_or(ChannelFailure::Transport(TransportError::Closed))?;
        connection
            .send(frame, remaining(start, deadline)?)
            .map_err(ChannelFailure::Transport)?;
        loop {
            let body = connection
                .receive(REPLY_LIMIT, remaining(start, deadline)?)
                .map_err(ChannelFailure::Transport)?;
            match self.channel.accept_reply(&body)? {
                Progress::Pending => continue,
                progress => return Ok(progress),
            }
        }
    }
}

/// Health check: open a connection, verify dird's uid, `Ping` → `Pong`
/// (docs/50 §7.5 step 5: ldap-front makes "a test connection to dird" before
/// it binds 389 / 636).
///
/// # Errors
/// [`ChannelFailure`].
///
/// Spec: docs/50 R50-3, R50-16, §7.5.
pub fn ping<K: Connector>(
    connector: &mut K,
    expected_uid: u32,
    deadline: Duration,
) -> Result<(), ChannelFailure> {
    let mut connection = verified(connector, expected_uid)?;
    let mut channel = FrontChannel::new();
    let frame = channel.encode_ping()?;
    let start = Instant::now();
    connection
        .send(frame.as_bytes(), remaining(start, deadline)?)
        .map_err(ChannelFailure::Transport)?;
    let body = connection
        .receive(REPLY_LIMIT, remaining(start, deadline)?)
        .map_err(ChannelFailure::Transport)?;
    match channel.accept_reply(&body)? {
        Progress::Pong => Ok(()),
        _ => Err(ChannelFailure::UnexpectedReply),
    }
}
