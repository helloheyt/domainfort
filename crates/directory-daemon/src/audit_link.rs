//! dird's link to auditd (`audit.sock`): verified first, before dird opens
//! the directory or listens (docs/50 R50-16: "auditd → keyd → dird → …; a
//! daemon binds nothing until its dependencies were verified").
//!
//! * **Server identity.** After `connect`, the peer uid (tokio
//!   `UnixStream::peer_cred`) must be the configured `auditd_uid`, and auditd
//!   must answer a `Ping` with `Pong`, before anything else — a process that
//!   captured the socket path receives nothing (R50-3: "the client also
//!   verifies the server's uid"; §7.5: `Ping` on every channel).
//! * **No events yet.** The directory-view channel issues nothing (the kdc
//!   audits every request itself, crates/kdc audit.rs), and ipc-audit has no
//!   event shape for what dird could record here (a refused peer, a view
//!   limit reached, the policy version loaded) — so in this task dird sends
//!   no event, and needs none of ipc-audit's conversion features (A-66).
//!   Refused peers are counted on stderr, as keyd does (docs/questions/Q-260
//!   item 5; Q-270 item 6).
//!
//! Spec: docs/50 R50-3, R50-16, R50-17, §3.3, §3.6, §7.5, §8.1;
//! docs/questions/Q-218 (A-57), Q-260 item 5, Q-270 item 6; tokio 1.54.1
//! docs.rs: `net::UnixStream::{connect, peer_cred}`, `net::unix::UCred::uid`,
//! `time::timeout`, `io::{AsyncReadExt::read, AsyncWriteExt::write_all}`.

use core::time::Duration;
use ipc::{Direction, FrameReader, Reply};
use ipc_audit::{decode_reply, encode_request, AuditReply, AuditRequest, AUDIT_CHANNEL};
use std::path::PathBuf;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::time::timeout;

/// How long the verification exchange with auditd may take. Project choice
/// (the same value as keyd-daemon's audit deadline; docs/50 gives none).
pub const AUDIT_DEADLINE: Duration = Duration::from_secs(5);

/// Octets read from the socket per read call at most. Project choice.
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

/// Why auditd could not be verified. Carries no octet of any frame.
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
    /// The reply did not frame, did not decode, or did not answer `Ping`.
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

/// The time left before `deadline` from `start`.
fn remaining(start: Instant, deadline: Duration) -> Result<Duration, AuditLinkError> {
    match deadline.checked_sub(start.elapsed()) {
        Some(left) if !left.is_zero() => Ok(left),
        _ => Err(AuditLinkError::Deadline),
    }
}

/// Connect to auditd, check its uid, and check it answers `Ping` with
/// `Pong`, within [`AUDIT_DEADLINE`].
///
/// # Errors
/// [`AuditLinkError`].
///
/// Spec: docs/50 R50-3 (server uid), R50-16 (auditd first), §3.3 (bound
/// before allocation; replies decoded strictly), §3.6, §7.5 (`Ping`).
pub async fn verify(endpoint: &AuditEndpoint) -> Result<(), AuditLinkError> {
    let start = Instant::now();
    let mut stream = timeout(AUDIT_DEADLINE, UnixStream::connect(&endpoint.socket))
        .await
        .map_err(|_| AuditLinkError::Deadline)?
        .map_err(|_| AuditLinkError::Connect)?;
    let uid = stream
        .peer_cred()
        .map_err(|_| AuditLinkError::PeerCredentials)?
        .uid();
    if uid != endpoint.uid {
        // Dropped here: nothing was sent on it.
        return Err(AuditLinkError::PeerMismatch);
    }
    let frame = encode_request(&AuditRequest::Ping).map_err(|_| AuditLinkError::Protocol)?;
    timeout(
        remaining(start, AUDIT_DEADLINE)?,
        stream.write_all(frame.as_bytes()),
    )
    .await
    .map_err(|_| AuditLinkError::Deadline)?
    .map_err(|_| AuditLinkError::Io)?;
    let mut reader = FrameReader::new(AUDIT_CHANNEL.limit(Direction::Reply));
    let mut chunk = [0u8; READ_CHUNK];
    loop {
        if let Some(body) = reader.body() {
            return match decode_reply(body).map_err(|_| AuditLinkError::Protocol)? {
                Reply::Message(AuditReply::Pong) => Ok(()),
                Reply::Message(AuditReply::Ack(_)) => Err(AuditLinkError::Protocol),
                Reply::Refused(_) => Err(AuditLinkError::Refused),
            };
        }
        let wanted = reader.wanted().min(READ_CHUNK);
        if wanted == 0 {
            return Err(AuditLinkError::Protocol);
        }
        let buffer = chunk.get_mut(..wanted).ok_or(AuditLinkError::Protocol)?;
        let read = timeout(remaining(start, AUDIT_DEADLINE)?, stream.read(buffer))
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
