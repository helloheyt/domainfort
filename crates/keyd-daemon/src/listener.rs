//! The listener on `keyd.sock`: one tokio task per connection.
//!
//! Per connection, in this order:
//!
//! 1. **Identity** — the peer uid from the kernel's peer credentials (tokio
//!    `UnixStream::peer_cred`: "effective credentials of the process which
//!    called `connect`"), mapped through the `uid → Role` table to a
//!    [`keyd::CallerId`] once for the connection. Unreadable credentials or an
//!    unmapped uid ⇒ the connection is closed **without a reply** (docs/50
//!    §3.2; the audit record docs/50 §3.2 also asks for has no event shape in
//!    ipc-audit — docs/questions/Q-260 item 5).
//! 2. **Quota** — at most `max_connections_per_uid` open connections per
//!    mapped uid; one more is closed without a reply (docs/50 §3.6).
//! 3. **One request, one reply** — read exactly one frame with ipc's
//!    [`FrameReader`] under the channel's request bound (`REQUEST_LIMIT`,
//!    checked before the body is allocated or awaited), never more octets
//!    than the frame still needs; hand it to the engine; write the reply;
//!    only then read the next frame (R50-7: no pipelining, no request id).
//! 4. **Deadlines** — an idle connection may wait for its next request
//!    indefinitely (clients hold a persistent connection), but a frame that
//!    has started must be complete within `frame_timeout`, else the
//!    connection is closed (docs/50 §3.6; `tokio::time::timeout`,
//!    cancellation by drop). Writing a reply is bounded by the same time, so
//!    a peer that stops reading cannot hold the task.
//! 5. **Back-pressure** — the engine queue is bounded; a full queue is
//!    answered `Refused::Busy` at once (R50-7).
//!
//! Spec: docs/50 R50-3, R50-7, §3.1, §3.2, §3.3, §3.6, §3.7; tokio 1.54.1
//! docs.rs: `net::UnixListener::accept`, `net::UnixStream::peer_cred`,
//! `net::unix::UCred::uid`, `time::timeout`, `spawn`,
//! `io::{AsyncReadExt::read, AsyncWriteExt::write_all}`.

use crate::callers::CallerMap;
use crate::engine::{refuse, refuse_and_stay, EngineHandle, SubmitError};
use crate::log::{note, Note, Thinned};
use core::time::Duration;
use ipc::{FrameReader, Refused};
use ipc_keyd::REQUEST_LIMIT;
use ipc_keyd_server::Dispatch;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::time::{sleep, timeout};
use zeroize::Zeroizing;

/// Octets read from the socket per read call at most. Project choice.
const READ_CHUNK: usize = 4096;

/// Pause after a failed `accept` (for example, the open-files limit was
/// reached) so the loop does not spin. Project choice.
const ACCEPT_RETRY: Duration = Duration::from_millis(50);

/// Thinned log counters for what a local peer can trigger at will.
static UNMAPPED: Thinned = Thinned::new(Note::PeerUnmapped);
static UNREADABLE: Thinned = Thinned::new(Note::PeerCredentialsUnreadable);
static OVER_QUOTA: Thinned = Thinned::new(Note::QuotaExceeded);

/// What every connection task shares.
/// Spec: docs/50 §3.2, §3.6.
pub(crate) struct ServeContext {
    callers: CallerMap,
    frame_timeout: Duration,
    max_connections_per_uid: u32,
    engine: EngineHandle,
    /// Open connections per mapped uid.
    open: Mutex<HashMap<u32, u32>>,
    /// Set at shutdown: new requests are answered `Unavailable`.
    draining: AtomicBool,
    /// Requests queued or being answered.
    in_flight: AtomicUsize,
}

impl ServeContext {
    /// Spec: docs/50 §3.2, §3.6.
    pub(crate) fn new(
        callers: CallerMap,
        frame_timeout: Duration,
        max_connections_per_uid: u32,
        engine: EngineHandle,
    ) -> ServeContext {
        ServeContext {
            callers,
            frame_timeout,
            max_connections_per_uid,
            engine,
            open: Mutex::new(HashMap::new()),
            draining: AtomicBool::new(false),
            in_flight: AtomicUsize::new(0),
        }
    }

    /// Stop taking new requests (shutdown). Spec: task P7 ("drain the queue
    /// and close").
    pub(crate) fn start_draining(&self) {
        self.draining.store(true, Ordering::SeqCst);
    }

    /// Requests queued or being answered.
    pub(crate) fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::SeqCst)
    }

    /// Take one of `uid`'s connection slots, or `None` at the quota.
    /// Spec: docs/50 §3.6 ("a connection quota per uid").
    fn acquire(self: &Arc<Self>, uid: u32) -> Option<QuotaSlot> {
        let mut open = self.open.lock().ok()?;
        let count = open.entry(uid).or_insert(0);
        if *count >= self.max_connections_per_uid {
            return None;
        }
        *count = count.saturating_add(1);
        Some(QuotaSlot {
            context: Arc::clone(self),
            uid,
        })
    }
}

/// One held connection slot; given back when the connection ends.
struct QuotaSlot {
    context: Arc<ServeContext>,
    uid: u32,
}

impl Drop for QuotaSlot {
    fn drop(&mut self) {
        if let Ok(mut open) = self.context.open.lock() {
            if let Some(count) = open.get_mut(&self.uid) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    open.remove(&self.uid);
                }
            }
        }
    }
}

/// One request counted as in flight until dropped.
struct InFlight<'a>(&'a AtomicUsize);

impl<'a> InFlight<'a> {
    fn new(counter: &'a AtomicUsize) -> InFlight<'a> {
        counter.fetch_add(1, Ordering::SeqCst);
        InFlight(counter)
    }
}

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Accept connections until the task is aborted, one task each.
/// Spec: docs/50 §3.1, §3.6.
pub(crate) async fn accept_loop(listener: UnixListener, context: Arc<ServeContext>) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                drop(tokio::spawn(connection(stream, Arc::clone(&context))));
            }
            Err(error) => {
                note(
                    Note::AcceptFailed,
                    error.raw_os_error().and_then(|e| u64::try_from(e).ok()),
                );
                sleep(ACCEPT_RETRY).await;
            }
        }
    }
}

/// Why a connection ends without a further reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionEnd {
    /// The peer closed between requests.
    Closed,
    /// The peer closed inside a frame, the frame broke a framing rule, the
    /// deadline passed, or an I/O error.
    Broken,
}

/// Serve one connection (module documentation).
/// Spec: docs/50 R50-3, R50-7, §3.2, §3.3, §3.6.
async fn connection(mut stream: UnixStream, context: Arc<ServeContext>) {
    let uid: u32 = match stream.peer_cred() {
        Ok(credentials) => credentials.uid(),
        Err(_) => {
            UNREADABLE.hit(None);
            return;
        }
    };
    let Some(caller) = context.callers.caller(uid) else {
        UNMAPPED.hit(Some(uid));
        return;
    };
    let Some(_slot) = context.acquire(uid) else {
        OVER_QUOTA.hit(Some(uid));
        return;
    };
    let mut reader = FrameReader::new(REQUEST_LIMIT);
    loop {
        let body = match read_frame(&mut stream, &mut reader, context.frame_timeout).await {
            Ok(body) => body,
            Err(ConnectionEnd::Closed | ConnectionEnd::Broken) => return,
        };
        // A queued request counts as in flight until its reply is written,
        // so that a shutdown drains it (task P7: "drain the queue").
        let (outcome, _counted) = if context.draining.load(Ordering::SeqCst) {
            (refuse(Refused::Unavailable), None)
        } else {
            match context.engine.submit(caller, body) {
                Ok(pending) => {
                    let counted = InFlight::new(&context.in_flight);
                    // The engine dropped the job unanswered: not served.
                    let outcome = pending
                        .await
                        .unwrap_or_else(|_| refuse(Refused::Unavailable));
                    (outcome, Some(counted))
                }
                Err(SubmitError::Busy) => (refuse_and_stay(Refused::Busy), None),
                Err(SubmitError::Stopped) => (refuse(Refused::Unavailable), None),
            }
        };
        if write_reply(&mut stream, &outcome, context.frame_timeout)
            .await
            .is_err()
        {
            return;
        }
        if !matches!(outcome, Dispatch::Reply(_)) {
            return;
        }
    }
}

/// Write the frame of `outcome`, if it has one, within `limit`.
/// Spec: docs/50 §3.6.
async fn write_reply(
    stream: &mut UnixStream,
    outcome: &Dispatch,
    limit: Duration,
) -> Result<(), ConnectionEnd> {
    let frame = match outcome {
        Dispatch::Reply(frame) | Dispatch::ReplyAndClose(frame) => frame,
        Dispatch::Close => return Ok(()),
    };
    timeout(limit, stream.write_all(frame.as_bytes()))
        .await
        .map_err(|_| ConnectionEnd::Broken)?
        .map_err(|_| ConnectionEnd::Broken)
}

/// Read exactly one request frame: no deadline for its first octet (idle),
/// then `frame_timeout` for the rest. Returns the body in a zeroizing buffer
/// (it may carry a password); the reader's own buffer is wiped on reset.
///
/// Spec: docs/50 §3.3 ("`length` checked against the MAX of (channel,
/// direction) before any body byte is allocated or read"; frame buffer
/// zeroized after decoding), §3.6 ("a frame that has started must finish
/// within 5 s … an idle connection is allowed"), R50-7.
async fn read_frame(
    stream: &mut UnixStream,
    reader: &mut FrameReader,
    frame_timeout: Duration,
) -> Result<Zeroizing<Vec<u8>>, ConnectionEnd> {
    let mut chunk = Zeroizing::new([0u8; READ_CHUNK]);
    let mut started: Option<Instant> = None;
    loop {
        if let Some(body) = reader.body() {
            let mut copy = Zeroizing::new(Vec::with_capacity(body.len()));
            copy.extend_from_slice(body);
            reader.reset();
            return Ok(copy);
        }
        let wanted = reader.wanted().min(READ_CHUNK);
        if wanted == 0 {
            return Err(ConnectionEnd::Broken);
        }
        let buffer = chunk.get_mut(..wanted).ok_or(ConnectionEnd::Broken)?;
        let read = match started {
            None => stream.read(buffer).await,
            Some(start) => {
                let left = frame_timeout
                    .checked_sub(start.elapsed())
                    .filter(|left| !left.is_zero())
                    .ok_or(ConnectionEnd::Broken)?;
                timeout(left, stream.read(buffer))
                    .await
                    .map_err(|_| ConnectionEnd::Broken)?
            }
        }
        .map_err(|_| ConnectionEnd::Broken)?;
        if read == 0 {
            return Err(if started.is_none() {
                ConnectionEnd::Closed
            } else {
                ConnectionEnd::Broken
            });
        }
        started.get_or_insert_with(Instant::now);
        let received = buffer.get(..read).ok_or(ConnectionEnd::Broken)?;
        let taken = reader.push(received).map_err(|_| ConnectionEnd::Broken)?;
        if taken != read {
            return Err(ConnectionEnd::Broken);
        }
    }
}
