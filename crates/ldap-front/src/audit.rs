//! The start-up check of auditd (docs/50 R50-16: "a daemon does not bind a
//! network port until its dependencies are verified (configuration, keyd,
//! dird, audit)"; §7.5).
//!
//! The front sends **no events**: docs/50 §4.2 assigns the LDAP events to
//! dird ("the LDAP event (`Outcome.audit`) is written by dird (the PEP), not
//! by the front (R49-14)"), §8.1 names the sources (kdc, keyd, the LDAP
//! engine's `Outcome.audit`) and ipc-audit has no front event shape. So the
//! front verifies that auditd is there and answering — the peer uid is the
//! configured `auditd_uid` and a `Ping` gets a `Pong` — and then closes the
//! connection; its own layer is only counted (crate::log). docs/questions/
//! Q-285 item 9.
//!
//! Spec: docs/50 R50-3, R50-16, R50-17, §3.3, §4.2, §7.5, §8.1; tokio
//! 1.54.1 docs.rs: `net::UnixStream::{connect, peer_cred}`, `time::timeout`.

use crate::dird::Endpoint;
use core::fmt;
use core::time::Duration;
use ipc::{Direction, FrameReader, Reply};
use ipc_audit::{decode_reply, encode_request, AuditReply, AuditRequest, AUDIT_CHANNEL};
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::time::timeout;

/// How long the check may take. Project choice (as the other daemons'
/// audit deadline; docs/50 gives none — Q-260 item 4).
pub const AUDIT_CHECK_DEADLINE: Duration = Duration::from_secs(5);

/// Octets read per read call at most. Project choice.
const READ_CHUNK: usize = 1024;

/// Why the check failed. Carries no octet of any frame.
/// Spec: docs/50 §7.5, §8.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditCheckError {
    /// The configured auditd uid is 0.
    RootServerUid,
    /// The socket could not be connected.
    Connect,
    /// The peer credentials could not be read.
    PeerCredentials,
    /// The peer is not the configured auditd uid; nothing was sent.
    PeerMismatch,
    /// The deadline passed.
    Deadline,
    /// auditd closed the connection, or another I/O failure.
    Io,
    /// The reply did not frame, did not decode, or was not `Pong`.
    Protocol,
}

impl fmt::Display for AuditCheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            AuditCheckError::RootServerUid => "auditd's uid cannot be 0",
            AuditCheckError::Connect => "audit socket could not be connected",
            AuditCheckError::PeerCredentials => "audit peer credentials unreadable",
            AuditCheckError::PeerMismatch => "audit peer is not the configured auditd uid",
            AuditCheckError::Deadline => "audit check deadline exceeded",
            AuditCheckError::Io => "audit connection failed",
            AuditCheckError::Protocol => "audit reply refused",
        })
    }
}

impl std::error::Error for AuditCheckError {}

/// The time left before the deadline.
fn remaining(start: Instant) -> Result<Duration, AuditCheckError> {
    match AUDIT_CHECK_DEADLINE.checked_sub(start.elapsed()) {
        Some(left) if !left.is_zero() => Ok(left),
        _ => Err(AuditCheckError::Deadline),
    }
}

/// Connect to auditd, check its uid, `Ping` → `Pong`, close.
///
/// # Errors
/// [`AuditCheckError`].
///
/// Spec: docs/50 R50-3, R50-16, §3.3, §7.5.
pub async fn verify_auditd(endpoint: &Endpoint) -> Result<(), AuditCheckError> {
    if endpoint.uid == 0 {
        return Err(AuditCheckError::RootServerUid);
    }
    let start = Instant::now();
    let mut stream = timeout(remaining(start)?, UnixStream::connect(&endpoint.socket))
        .await
        .map_err(|_| AuditCheckError::Deadline)?
        .map_err(|_| AuditCheckError::Connect)?;
    let uid = stream
        .peer_cred()
        .map_err(|_| AuditCheckError::PeerCredentials)?
        .uid();
    if uid != endpoint.uid {
        return Err(AuditCheckError::PeerMismatch);
    }
    let frame = encode_request(&AuditRequest::Ping).map_err(|_| AuditCheckError::Protocol)?;
    timeout(remaining(start)?, stream.write_all(frame.as_bytes()))
        .await
        .map_err(|_| AuditCheckError::Deadline)?
        .map_err(|_| AuditCheckError::Io)?;
    let mut reader = FrameReader::new(AUDIT_CHANNEL.limit(Direction::Reply));
    let mut chunk = [0u8; READ_CHUNK];
    loop {
        if let Some(body) = reader.body() {
            return match decode_reply(body).map_err(|_| AuditCheckError::Protocol)? {
                Reply::Message(AuditReply::Pong) => Ok(()),
                _ => Err(AuditCheckError::Protocol),
            };
        }
        let wanted = reader.wanted().min(READ_CHUNK);
        if wanted == 0 {
            return Err(AuditCheckError::Protocol);
        }
        let buffer = chunk.get_mut(..wanted).ok_or(AuditCheckError::Protocol)?;
        let read = timeout(remaining(start)?, stream.read(buffer))
            .await
            .map_err(|_| AuditCheckError::Deadline)?
            .map_err(|_| AuditCheckError::Io)?;
        if read == 0 {
            return Err(AuditCheckError::Io);
        }
        let received = buffer.get(..read).ok_or(AuditCheckError::Protocol)?;
        let taken = reader
            .push(received)
            .map_err(|_| AuditCheckError::Protocol)?;
        if taken != read {
            return Err(AuditCheckError::Protocol);
        }
    }
}
