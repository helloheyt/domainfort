//! The `audit.sock` listener: peer identity from the transport, one request
//! in flight per connection, bounded frames and deadlines, and every
//! `Append` handed to the single writer.
//!
//! Per connection:
//!
//! 1. **Identity.** tokio `UnixStream::peer_cred` ("Returns effective
//!    credentials of the process which called `connect`") gives the uid; the
//!    configured `uid → source` map gives the [`Source`]. An unmapped uid is
//!    closed **with no reply** and counted for the `Auditd` summary record;
//!    uid 0 and auditd's own uid are never in the map (crates/config
//!    `SourceMap`). The source is never read from a message (docs/50 §3.2,
//!    R50-3).
//! 2. **Quota.** At most [`MAX_CONNECTIONS_PER_SOURCE`] connections per
//!    mapped source, so no sender can make auditd hold unbounded frame
//!    buffers (AGENTS.md §6). Over the quota: closed, no reply, counted.
//! 3. **Frames.** `ipc::FrameReader` with the channel's request bound: the
//!    declared length is checked before any body octet is allocated or
//!    awaited, and no more octets are read than the current frame needs, so
//!    a pipelined second request waits until the first is answered (docs/50
//!    §3.3, §3.6, R50-7). An idle connection may stay open; a frame that has
//!    started must be complete within `frame_timeout` (docs/50 §3.6: "a
//!    frame that has started must finish within 5 s … otherwise close; an
//!    idle connection is allowed"). Writing a reply has the same deadline.
//! 4. **Requests.** `Ping` → `Pong` while the writer is available, otherwise
//!    `Refused::Unavailable` (docs/50 §7.5). The `Pong` names the source
//!    this connection's events are recorded under — the very [`Source`] of
//!    step 1, so what auditd reports is what it records ([`reported_source`];
//!    task R9b: every sender requires its own source before its first
//!    batch, docs/questions/Q-512, Q-560). `Append` → the connection's
//!    `AppendCursor` must accept its numbering (else `Refused::Malformed` +
//!    close, docs/questions/Q-265 item 3); every event's shape must be one
//!    its source may send — `Kdc` only from kdc, `Keyd` only from keyd,
//!    `Ldap` and `DirAdmin` only from dird, `Admind` only from admind,
//!    `WindowSummary` from any (crate::binding; else nothing of the batch is
//!    persisted, `Refused::Malformed` + close, counted for an
//!    `EventsMisbound` record — docs/51 §5.7, Q-341); then the job goes to
//!    the writer's queue: full → `Refused::Busy` (connection stays open —
//!    A-57); writer
//!    failed → `Refused::Unavailable`; persisted → `Ack { through_seq,
//!    head_hash }` and only then the cursor advances (docs/50 §8.1;
//!    docs/questions/Q-252 item 7). The writer's resend check
//!    (crate::resend) appends only the events not yet persisted: a batch
//!    resent after a lost acknowledgement — on the sender's next connection
//!    — is acknowledged the same way, with nothing appended twice; a batch
//!    that reuses persisted numbers without being their byte-identical
//!    resend → `Refused::Malformed` + close, counted for a `ResendsRefused`
//!    record (decision A-98, follow-up F8; docs/questions/Q-445). Each job
//!    carries the source's numbering ([`binding::numbering`] of the
//!    production table) and whether it is the connection's first `Append`.
//! 5. **Errors** follow `ipc::Error::refusal` (A-59): a wrong version →
//!    `Refused::VersionMismatch` + close; a malformed payload →
//!    `Refused::Malformed` + close; a bad length prefix, wrong magic or
//!    unknown kind → close with no reply.
//!
//! Spec: docs/50 R50-3, R50-7, R50-17, §3.1-§3.3, §3.6, §7.5, §8.1;
//! docs/questions/Q-218 (A-57), Q-225 (A-59), Q-252 (A-64), Q-265, Q-341,
//! Q-432 (A-98), Q-445, Q-512 (A-112), Q-560; docs/51 §5.7;
//! tokio 1.54.1 docs.rs: `net::UnixListener` (`bind`, `accept`),
//! `net::UnixStream` (`peer_cred`), `net::unix::UCred`, `time::timeout_at`,
//! `time::Instant`, `time::sleep`, `sync::oneshot`, `io::AsyncReadExt`,
//! `io::AsyncWriteExt`.

use crate::binding;
use crate::writer::{AppendJob, JobOutcome, SubmitError, Submitter};
use audit_log::Source;
use config::{AuditSource, AuditdSettings, SourceMap};
use core::fmt;
use ipc::{Direction, FrameReader, Refused, Reply};
use ipc_audit::{
    decode_request, encode_reply, Append, AppendCursor, AuditReply, AuditRequest, EventSource,
    AUDIT_CHANNEL,
};
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::oneshot;
use tokio::time::{timeout_at, Instant};

/// Most simultaneous connections from one mapped source. Project choice:
/// docs/50 names no number for auditd (A-60: such limits are constants in
/// the daemon; docs/questions/Q-265 item 5).
pub const MAX_CONNECTIONS_PER_SOURCE: usize = 4;

/// The socket file's mode: owner and group read/write, nothing for others
/// (docs/50 §3.1: the socket's directory is "owned by the server's uid,
/// mode 0750, group = the channel's clients — defence in depth only; the
/// authorisation itself is the uid map"). Project choice for the file
/// itself (docs/questions/Q-265 item 9).
pub const SOCKET_FILE_MODE: u32 = 0o660;

/// Octets read from a connection per read call at most. Project choice.
const READ_CHUNK: usize = 4096;

/// Wait before accepting again after `accept` failed (e.g. the open-files
/// limit is reached), so a persistent failure does not spin. Project choice.
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(100);

/// What auditd's configuration sets for the listener — **and nothing
/// else** (docs/52 C18, task R15). The per-source connection quota and the
/// shape↔source binding table are not parameters at all: [`serve`] enforces
/// [`MAX_CONNECTIONS_PER_SOURCE`] and [`binding::PRODUCTION`] (A-85), so no
/// code that builds a listener can weaken the binding. (The table was a
/// parameter for the single-uid harness; since task R9b each test sender has
/// its own listener and source, and the parameter had no user left — R15
/// removed it instead of hiding it.)
///
/// Spec: docs/50 §3.6; docs/questions/Q-265 item 5; A-85; docs/52 §3.18;
/// docs/questions/Q-570.
#[derive(Debug, Clone, Copy)]
pub struct ListenerConfig {
    /// How long a started frame may take to arrive, and how long writing a
    /// reply may take.
    pub frame_timeout: Duration,
}

impl ListenerConfig {
    /// The listener's configuration from auditd's settings — the one
    /// product constructor (docs/52 C18, task R15).
    /// Spec: docs/50 §3.6, R50-15.
    #[must_use]
    pub fn from_settings(settings: &AuditdSettings) -> ListenerConfig {
        ListenerConfig {
            frame_timeout: settings.frame_timeout(),
        }
    }
}

/// Why the socket could not be bound.
///
/// Spec: docs/50 §3.1 ("deleting a stale socket file before bind … the
/// daemon manages this explicitly" — done by the root-side preparation,
/// `startup::prepare_socket_directory`, task R11c; task R15b).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindError {
    /// Binding or setting the mode failed — among others, the path is
    /// occupied (a stale socket the preparation did not remove, or another
    /// kind of file: left alone either way).
    Io(io::ErrorKind),
}

impl fmt::Display for BindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BindError::Io(kind) => write!(f, "socket bind failed: {kind}"),
        }
    }
}

impl std::error::Error for BindError {}

/// Bind `audit.sock` at `path` and set the file's mode to
/// [`SOCKET_FILE_MODE`]. Nothing is removed first: the one stale-socket
/// removal is the root-side preparation's
/// (`protected_file::prepare_socket_directory`, relative to the walked and
/// checked directory, before the drop — task R11c); a path occupied after it
/// (only root or auditd's account could have done that) fails the bind
/// (task R15b, docs/questions/Q-631).
///
/// Must be called within a tokio runtime context (tokio `UnixListener::bind`
/// requires "a runtime with IO enabled"; the daemon uses `Runtime::enter`).
///
/// # Errors
/// [`BindError`].
///
/// Spec: docs/50 §3.1; R50-16 (bound only after the log verified);
/// tokio `net::UnixListener::bind`.
pub fn bind(path: &Path) -> Result<UnixListener, BindError> {
    let listener = UnixListener::bind(path).map_err(|e| BindError::Io(e.kind()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(SOCKET_FILE_MODE))
        .map_err(|e| BindError::Io(e.kind()))?;
    Ok(listener)
}

/// The log source of a configured source, and its quota slot.
///
/// Spec: docs/50 §2.4, §3.2; crates/config `AuditSource`; crates/audit-log
/// `Source`.
const fn log_source(source: AuditSource) -> (Source, usize) {
    match source {
        AuditSource::Keyd => (Source::Keyd, 0),
        AuditSource::Dird => (Source::Dird, 1),
        AuditSource::Kdc => (Source::Kdc, 2),
        AuditSource::LdapFront => (Source::LdapFront, 3),
        AuditSource::Admind => (Source::Admind, 4),
    }
}

/// The source a `Pong` reports for a connection whose events are recorded
/// under `source`: the same process, named in the channel's closed table
/// (ipc-audit `EventSource`, whose codes are the log's — pinned by this
/// crate's tests). `None` for auditd's own source, which no peer is ever
/// mapped to (crates/config `SourceMap`), so no `Pong` can name it.
///
/// Spec: docs/50 §3.2, §8.1; docs/questions/Q-512 (A-112), Q-560 item 2.
#[must_use]
pub const fn reported_source(source: Source) -> Option<EventSource> {
    match source {
        Source::Keyd => Some(EventSource::Keyd),
        Source::Dird => Some(EventSource::Dird),
        Source::Kdc => Some(EventSource::Kdc),
        Source::LdapFront => Some(EventSource::LdapFront),
        Source::Admind => Some(EventSource::Admind),
        Source::Auditd => None,
    }
}

/// Open connections per source slot.
#[derive(Debug, Default)]
struct Quota {
    open: [AtomicUsize; 5],
}

/// One held connection slot; released on drop.
#[derive(Debug)]
struct QuotaSlot {
    quota: Arc<Quota>,
    slot: usize,
}

impl Quota {
    /// Take a slot for `slot` if fewer than `max` are open.
    fn acquire(quota: &Arc<Quota>, slot: usize, max: usize) -> Option<QuotaSlot> {
        let counter = quota.open.get(slot)?;
        counter
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |open| {
                (open < max).then(|| open.saturating_add(1))
            })
            .ok()?;
        Some(QuotaSlot {
            quota: Arc::clone(quota),
            slot,
        })
    }
}

impl Drop for QuotaSlot {
    fn drop(&mut self) {
        if let Some(counter) = self.quota.open.get(self.slot) {
            // A closure that always returns `Some` cannot fail.
            let _ = counter.fetch_update(Ordering::AcqRel, Ordering::Acquire, |open| {
                Some(open.saturating_sub(1))
            });
        }
    }
}

/// Accept connections forever, each served by its own task, with the
/// daemon's connection quota ([`MAX_CONNECTIONS_PER_SOURCE`]) and binding
/// table ([`binding::PRODUCTION`]) — neither is a parameter (docs/52 C18,
/// task R15).
///
/// Spec: this module's steps 1-2; docs/50 §3.2, R50-3; A-85.
pub async fn serve(
    listener: UnixListener,
    sources: Arc<SourceMap>,
    submitter: Submitter,
    config: ListenerConfig,
) {
    let quota = Arc::new(Quota::default());
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _address)) => stream,
            Err(_) => {
                tokio::time::sleep(ACCEPT_RETRY_DELAY).await;
                continue;
            }
        };
        // Dropping `stream` closes the connection without a reply.
        let Ok(credentials) = stream.peer_cred() else {
            continue;
        };
        let uid: u32 = credentials.uid();
        let Some(source) = sources.source_of(uid) else {
            submitter.refusals().count_unmapped(uid);
            continue;
        };
        let (source, slot) = log_source(source);
        let Some(held) = Quota::acquire(&quota, slot, MAX_CONNECTIONS_PER_SOURCE) else {
            submitter.refusals().count_over_quota(uid);
            continue;
        };
        tokio::spawn(connection(
            stream,
            source,
            uid,
            submitter.clone(),
            config,
            held,
        ));
    }
}

/// Serve one connection until it closes or breaks a rule.
///
/// Spec: this module's steps 3-5.
async fn connection(
    mut stream: UnixStream,
    source: Source,
    uid: u32,
    submitter: Submitter,
    config: ListenerConfig,
    _held: QuotaSlot,
) {
    // What every `Pong` on this connection reports: derived from the source
    // its records go under. No peer maps to auditd's own source; if one did,
    // the connection closes with no reply (fail closed).
    let Some(reported) = reported_source(source) else {
        return;
    };
    let mut frames = FrameReader::new(AUDIT_CHANNEL.limit(Direction::Request));
    let mut cursor = AppendCursor::new();
    loop {
        if !read_frame(&mut stream, &mut frames, config.frame_timeout).await {
            return;
        }
        let Some(decoded) = frames.body().map(decode_request) else {
            return;
        };
        frames.reset();
        let request = match decoded {
            Ok(request) => request,
            Err(error) => {
                if let Some(refused) = error.refusal() {
                    send(&mut stream, &Reply::Refused(refused), config.frame_timeout).await;
                }
                return;
            }
        };
        let (reply, keep_open) = match request {
            AuditRequest::Ping => {
                let reply = if submitter.is_available() {
                    Reply::Message(AuditReply::Pong(reported))
                } else {
                    Reply::Refused(Refused::Unavailable)
                };
                (reply, true)
            }
            AuditRequest::Append(append) => {
                append_batch(&append, &mut cursor, source, uid, &submitter).await
            }
        };
        if !send(&mut stream, &reply, config.frame_timeout).await || !keep_open {
            return;
        }
    }
}

/// Check the numbering and the source binding, queue the batch, wait for
/// the writer (which runs the resend check), and build the reply; the flag
/// says whether the connection stays open.
///
/// Spec: docs/50 §3.2, §8.1; docs/questions/Q-218 (A-57), Q-252 item 7,
/// Q-265 item 3, Q-341, Q-445; docs/51 §5.7.
async fn append_batch(
    append: &Append,
    cursor: &mut AppendCursor,
    source: Source,
    uid: u32,
    submitter: &Submitter,
) -> (Reply<AuditReply>, bool) {
    let Ok(range) = cursor.check(append) else {
        return (Reply::Refused(Refused::Malformed), false);
    };
    // A shape this source may not send: nothing of the batch is persisted
    // (crate::binding; docs/51 §5.7).
    if !binding::batch_permitted(source, append.events()) {
        submitter.refusals().count_misbound(uid);
        return (Reply::Refused(Refused::Malformed), false);
    }
    let (reply_to, outcome) = oneshot::channel();
    let job = AppendJob {
        source,
        source_uid: uid,
        first_source_seq: append.first_seq(),
        events: append.events().to_vec(),
        numbering: binding::numbering(binding::PRODUCTION, source),
        // No baseline yet: nothing has been acknowledged on this connection
        // (ipc-audit `AppendCursor`: "the first `Append` on a connection sets
        // the baseline").
        first_on_connection: *cursor == AppendCursor::new(),
        reply: reply_to,
    };
    match submitter.submit(job) {
        Ok(()) => {}
        Err(SubmitError::Busy) => return (Reply::Refused(Refused::Busy), true),
        Err(SubmitError::Unavailable) => return (Reply::Refused(Refused::Unavailable), true),
    }
    match outcome.await {
        // Appended now, or (a resend) already persisted: the same Ack.
        Ok(JobOutcome::Persisted(head) | JobOutcome::AlreadyPersisted(head)) => {
            // Advanced only now that the batch is persisted. If no number
            // can follow, the Ack is still sent, then the connection closes.
            let keep_open = cursor.advance(range).is_ok();
            let ack = AppendCursor::ack(range, *head.hash.as_bytes());
            (Reply::Message(AuditReply::Ack(ack)), keep_open)
        }
        // The writer counted it (crate::resend; Q-445): the same answer as a
        // numbering error (Q-265 item 3).
        Ok(JobOutcome::ResendRefused(_)) => (Reply::Refused(Refused::Malformed), false),
        Ok(JobOutcome::Unavailable) | Err(_) => (Reply::Refused(Refused::Unavailable), true),
    }
}

/// Read one whole frame into `frames`. Waits without limit for its first
/// octet; after that the frame must be complete within `limit`. `false`
/// means close: end of stream, an I/O error, a framing error (no reply —
/// docs/50 §3.3) or the deadline.
///
/// Spec: docs/50 §3.3, §3.6; ipc `FrameReader` (`wanted`, `push`).
async fn read_frame(stream: &mut UnixStream, frames: &mut FrameReader, limit: Duration) -> bool {
    let mut chunk = [0u8; READ_CHUNK];
    let mut deadline: Option<Instant> = None;
    while !frames.is_complete() {
        let wanted = frames.wanted().min(READ_CHUNK);
        let Some(buffer) = chunk.get_mut(..wanted) else {
            return false;
        };
        if buffer.is_empty() {
            return false;
        }
        let read = match deadline {
            None => stream.read(buffer).await,
            Some(at) => match timeout_at(at, stream.read(buffer)).await {
                Ok(read) => read,
                Err(_elapsed) => return false,
            },
        };
        let count = match read {
            Ok(0) | Err(_) => return false,
            Ok(count) => count,
        };
        let Some(received) = buffer.get(..count) else {
            return false;
        };
        if frames.push(received).is_err() {
            return false;
        }
        if deadline.is_none() {
            let Some(at) = Instant::now().checked_add(limit) else {
                return false;
            };
            deadline = Some(at);
        }
    }
    true
}

/// Write one reply within `limit`; `false` if it could not be sent.
///
/// Spec: docs/50 §3.3 (replies), §3.6 (deadlines).
async fn send(stream: &mut UnixStream, reply: &Reply<AuditReply>, limit: Duration) -> bool {
    let Ok(frame) = encode_reply(reply) else {
        return false;
    };
    let Some(deadline) = Instant::now().checked_add(limit) else {
        return false;
    };
    matches!(
        timeout_at(deadline, stream.write_all(frame.as_bytes())).await,
        Ok(Ok(()))
    )
}
