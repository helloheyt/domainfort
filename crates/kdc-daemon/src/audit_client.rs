//! The audit client: the kdc's connection to auditd (`audit.sock`) — the
//! keyd daemon's design (crates/keyd-daemon audit_client.rs, this project's
//! code) over the kdc's gate.
//!
//! * **Server identity.** After `connect`, the peer uid (tokio
//!   `UnixStream::peer_cred`) must be the configured `auditd_uid`, and auditd
//!   must answer a `Ping` with `Pong`, before the connection is used (docs/50
//!   R50-3: "the client verifies the server's uid too"; §7.5: `Ping`).
//! * **Strict request → reply.** One request in flight (docs/50 §3.6): an
//!   `Append` of the window's next batch, answered by `Ack` only after auditd
//!   synced it (§8.1); the reply is read with ipc's [`FrameReader`] under the
//!   reply bound and decoded with the same strictness as a request (§3.3).
//! * **Liveness.** When nothing is pending for [`HEARTBEAT`], a `Ping`; a
//!   connection that fails it, or any exchange, is dropped and auditd counts
//!   as unreachable — requests are not served until a verified connection
//!   is back (A-57; Q-260 item 2).
//! * **Reconnection** with a bounded, doubling backoff (docs/50 §3.7); the
//!   batch in flight is resent with the same numbers (Q-252 item 7).
//!
//! Spec: docs/50 R50-3, R50-16, R50-17, §3.3, §3.6, §3.7, §7.5, §8.1;
//! docs/questions/Q-218 (A-57), Q-252 (A-64), Q-260 (A-67); tokio 1.54.1
//! docs.rs: `net::UnixStream::{connect, peer_cred}`, `net::unix::UCred::uid`,
//! `time::{timeout, sleep}`, `io::{AsyncReadExt::read,
//! AsyncWriteExt::write_all}`.

use crate::audit::AuditGate;
use crate::log::{note, Note};
use core::time::Duration;
use ipc::{Direction, FrameReader, Reply};
use ipc_audit::{decode_reply, encode_request, AuditReply, AuditRequest, AUDIT_CHANNEL};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::time::{sleep, timeout};

/// How long one exchange with auditd may take. Project choice (as
/// keyd-daemon; docs/50 gives no audit deadline — Q-260 item 4).
pub const AUDIT_DEADLINE: Duration = Duration::from_secs(5);

/// Idle time after which the client checks auditd with a `Ping`. Project
/// choice (as keyd-daemon).
pub const HEARTBEAT: Duration = Duration::from_secs(1);

/// First and longest wait between reconnection attempts. Project choices
/// (docs/50 §3.7: "reconnection with bounded backoff").
const BACKOFF_MIN: Duration = Duration::from_millis(100);
const BACKOFF_MAX: Duration = Duration::from_secs(5);

/// Octets read per read call at most. Project choice.
const READ_CHUNK: usize = 1024;

/// Where auditd listens and which uid it must run as.
/// Spec: docs/50 R50-3, §2.4 (crates/config `Endpoint`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEndpoint {
    /// `audit_socket`.
    pub socket: PathBuf,
    /// `auditd_uid`.
    pub uid: u32,
}

/// Why the audit connection failed. Carries no octet of any frame.
/// Spec: docs/50 §3.7, §8.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditLinkError {
    /// The socket could not be connected.
    Connect,
    /// The peer credentials could not be read.
    PeerCredentials,
    /// The peer is not the configured auditd uid; nothing was sent.
    PeerMismatch,
    /// The deadline passed.
    Deadline,
    /// auditd closed the connection.
    Closed,
    /// Another I/O failure.
    Io,
    /// The reply did not frame, did not decode, or did not answer.
    Protocol,
    /// auditd answered with the shared refusal.
    Refused,
}

impl core::fmt::Display for AuditLinkError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            AuditLinkError::Connect => "audit socket could not be connected",
            AuditLinkError::PeerCredentials => "audit peer credentials unreadable",
            AuditLinkError::PeerMismatch => "audit peer is not the configured auditd uid",
            AuditLinkError::Deadline => "audit exchange deadline exceeded",
            AuditLinkError::Closed => "auditd closed the connection",
            AuditLinkError::Io => "audit connection I/O failure",
            AuditLinkError::Protocol => "audit reply refused",
            AuditLinkError::Refused => "auditd refused the request",
        })
    }
}

impl std::error::Error for AuditLinkError {}

/// A verified connection to auditd.
#[derive(Debug)]
pub(crate) struct AuditConnection {
    stream: UnixStream,
}

fn remaining(start: Instant, deadline: Duration) -> Result<Duration, AuditLinkError> {
    match deadline.checked_sub(start.elapsed()) {
        Some(left) if !left.is_zero() => Ok(left),
        _ => Err(AuditLinkError::Deadline),
    }
}

/// Connect to auditd, check its uid, and check it answers `Ping`.
///
/// # Errors
/// [`AuditLinkError`].
///
/// Spec: docs/50 R50-3, R50-16, §7.5.
pub(crate) async fn connect_verified(
    endpoint: &AuditEndpoint,
) -> Result<AuditConnection, AuditLinkError> {
    let stream = timeout(AUDIT_DEADLINE, UnixStream::connect(&endpoint.socket))
        .await
        .map_err(|_| AuditLinkError::Deadline)?
        .map_err(|_| AuditLinkError::Connect)?;
    let uid = stream
        .peer_cred()
        .map_err(|_| AuditLinkError::PeerCredentials)?
        .uid();
    if uid != endpoint.uid {
        return Err(AuditLinkError::PeerMismatch);
    }
    let mut connection = AuditConnection { stream };
    match connection.exchange(&AuditRequest::Ping).await? {
        AuditReply::Pong => Ok(connection),
        AuditReply::Ack(_) => Err(AuditLinkError::Protocol),
    }
}

impl AuditConnection {
    /// Send one request and read its one reply, within [`AUDIT_DEADLINE`].
    /// Spec: docs/50 §3.3, §3.6, §8.1.
    async fn exchange(&mut self, request: &AuditRequest) -> Result<AuditReply, AuditLinkError> {
        let frame = encode_request(request).map_err(|_| AuditLinkError::Protocol)?;
        let start = Instant::now();
        timeout(
            remaining(start, AUDIT_DEADLINE)?,
            self.stream.write_all(frame.as_bytes()),
        )
        .await
        .map_err(|_| AuditLinkError::Deadline)?
        .map_err(|_| AuditLinkError::Io)?;
        drop(frame);
        let mut reader = FrameReader::new(AUDIT_CHANNEL.limit(Direction::Reply));
        let mut chunk = [0u8; READ_CHUNK];
        loop {
            if let Some(body) = reader.body() {
                return match decode_reply(body).map_err(|_| AuditLinkError::Protocol)? {
                    Reply::Message(reply) => Ok(reply),
                    Reply::Refused(_) => Err(AuditLinkError::Refused),
                };
            }
            let wanted = reader.wanted().min(READ_CHUNK);
            if wanted == 0 {
                return Err(AuditLinkError::Protocol);
            }
            let buffer = chunk.get_mut(..wanted).ok_or(AuditLinkError::Protocol)?;
            let read = timeout(remaining(start, AUDIT_DEADLINE)?, self.stream.read(buffer))
                .await
                .map_err(|_| AuditLinkError::Deadline)?
                .map_err(|_| AuditLinkError::Io)?;
            if read == 0 {
                return Err(AuditLinkError::Closed);
            }
            let received = buffer.get(..read).ok_or(AuditLinkError::Protocol)?;
            let taken = reader
                .push(received)
                .map_err(|_| AuditLinkError::Protocol)?;
            if taken != read {
                return Err(AuditLinkError::Protocol);
            }
        }
    }

    /// Deliver the window's batches until the connection fails.
    /// Spec: docs/50 §8.1, §7.5; docs/questions/Q-218 (A-57).
    async fn pump(&mut self, gate: &AuditGate) -> AuditLinkError {
        loop {
            match gate.next_batch() {
                Some(append) => match self.exchange(&AuditRequest::Append(append)).await {
                    Ok(AuditReply::Ack(ack)) => {
                        if gate.acknowledge(&ack).is_err() {
                            return AuditLinkError::Protocol;
                        }
                    }
                    Ok(AuditReply::Pong) => return AuditLinkError::Protocol,
                    Err(error) => return error,
                },
                None => {
                    if timeout(HEARTBEAT, gate.recorded()).await.is_err() {
                        match self.exchange(&AuditRequest::Ping).await {
                            Ok(AuditReply::Pong) => {}
                            Ok(AuditReply::Ack(_)) => return AuditLinkError::Protocol,
                            Err(error) => return error,
                        }
                    }
                }
            }
        }
    }
}

/// The audit client task: deliver events over `first`, then reconnect with
/// backoff whenever it fails; runs until aborted at shutdown.
/// Spec: docs/50 R50-17, §3.7, §8.1; docs/questions/Q-218 (A-57).
pub(crate) async fn run(gate: Arc<AuditGate>, endpoint: AuditEndpoint, first: AuditConnection) {
    let mut connection = Some(first);
    let mut backoff = BACKOFF_MIN;
    loop {
        let mut current = match connection.take() {
            Some(current) => current,
            None => match connect_verified(&endpoint).await {
                Ok(current) => {
                    note(Note::AuditRestored, None);
                    backoff = BACKOFF_MIN;
                    current
                }
                Err(_) => {
                    sleep(backoff).await;
                    backoff = backoff.saturating_mul(2).min(BACKOFF_MAX);
                    continue;
                }
            },
        };
        gate.set_reachable(true);
        let _failure = current.pump(&gate).await;
        gate.set_reachable(false);
        gate.connection_lost();
        drop(current);
        note(Note::AuditLost, None);
        sleep(backoff).await;
    }
}
