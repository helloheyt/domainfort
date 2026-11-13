//! The listener on `dird-kdc.sock`: one tokio task per connection.
//!
//! Per connection, in this order:
//!
//! 1. **Identity** — the peer uid from the kernel's peer credentials (tokio
//!    `UnixStream::peer_cred`: "effective credentials of the process which
//!    called `connect`") must be exactly the configured `kdc_uid`; anything
//!    else (or unreadable credentials) ⇒ the connection is closed **without a
//!    reply** (docs/50 §3.2: "dird-kdc.sock ← kdc's uid only"). Counted on
//!    stderr; no audit event (no ipc-audit shape — Q-260 item 5, Q-270
//!    item 6).
//! 2. **Quota** — at most `max_connections` open connections from the kdc
//!    (docs/50 §3.6); one more is closed without a reply.
//! 3. **Connection id** — a number this listener assigns (never from the
//!    peer); the view the kdc pins lives under it (docs/50 §3.4).
//! 4. **One request, one reply** — exactly one frame with ipc's
//!    [`FrameReader`] under the channel's request bound (checked before the
//!    body is allocated or awaited); hand it to the engine; write the reply;
//!    only then read the next frame (R50-7).
//! 5. **Deadlines** — an idle connection may wait indefinitely, a started
//!    frame must be complete within `frame_timeout`, a reply write is bounded
//!    by the same time (docs/50 §3.6).
//! 6. **End** — the engine is told to release the connection's view
//!    (docs/50 §3.4: "released on EndView or disconnect").
//!
//! Spec: docs/50 R50-3, R50-7, §3.1, §3.2, §3.3, §3.4, §3.6, §3.7; tokio
//! 1.54.1 docs.rs: `net::UnixListener::accept`, `net::UnixStream::peer_cred`,
//! `net::unix::UCred::uid`, `time::timeout`, `spawn`,
//! `io::{AsyncReadExt::read, AsyncWriteExt::write_all}`.

use crate::engine::{unavailable, EngineHandle, SubmitError};
use crate::log::{note, Note, Thinned};
use core::time::Duration;
use ipc::{FrameReader, Refused};
use ipc_directory::REQUEST_LIMIT;
use ipc_directory_server::{refuse_and_stay, Dispatch};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::time::{sleep, timeout};
use zeroize::Zeroizing;

/// Octets read from the socket per read call at most. Project choice.
const READ_CHUNK: usize = 4096;

/// Pause after a failed `accept`. Project choice.
const ACCEPT_RETRY: Duration = Duration::from_millis(50);

/// Thinned log counters for what a local peer can trigger at will.
static REFUSED_PEERS: Thinned = Thinned::new(Note::PeerRefused);
static UNREADABLE: Thinned = Thinned::new(Note::PeerCredentialsUnreadable);
static OVER_QUOTA: Thinned = Thinned::new(Note::QuotaExceeded);

/// What every connection task shares.
/// Spec: docs/50 §3.2, §3.6.
pub(crate) struct ServeContext {
    kdc_uid: u32,
    frame_timeout: Duration,
    max_connections: usize,
    engine: EngineHandle,
    open: AtomicUsize,
    next_connection: AtomicU64,
    draining: AtomicBool,
    in_flight: AtomicUsize,
}

impl ServeContext {
    /// Spec: docs/50 §3.2, §3.6.
    pub(crate) fn new(
        kdc_uid: u32,
        frame_timeout: Duration,
        max_connections: usize,
        engine: EngineHandle,
    ) -> ServeContext {
        ServeContext {
            kdc_uid,
            frame_timeout,
            max_connections,
            engine,
            open: AtomicUsize::new(0),
            next_connection: AtomicU64::new(0),
            draining: AtomicBool::new(false),
            in_flight: AtomicUsize::new(0),
        }
    }

    /// Stop taking new requests (shutdown).
    pub(crate) fn start_draining(&self) {
        self.draining.store(true, Ordering::SeqCst);
    }

    /// Requests queued or being answered.
    pub(crate) fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::SeqCst)
    }

    /// Take a connection slot, or `None` at the quota.
    /// Spec: docs/50 §3.6 ("a connection quota").
    fn acquire(self: &Arc<Self>) -> Option<Slot> {
        let mut current = self.open.load(Ordering::SeqCst);
        loop {
            if current >= self.max_connections {
                return None;
            }
            match self.open.compare_exchange(
                current,
                current + 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
        let id = self
            .next_connection
            .fetch_add(1, Ordering::SeqCst)
            .wrapping_add(1);
        Some(Slot {
            context: Arc::clone(self),
            connection: id,
        })
    }
}

/// One held connection slot: given back, and the view released, when the
/// connection ends.
struct Slot {
    context: Arc<ServeContext>,
    connection: u64,
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.context.engine.release(self.connection);
        self.context.open.fetch_sub(1, Ordering::SeqCst);
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

/// Serve one connection (module documentation).
/// Spec: docs/50 R50-3, R50-7, §3.2, §3.3, §3.4, §3.6.
async fn connection(mut stream: UnixStream, context: Arc<ServeContext>) {
    let uid: u32 = match stream.peer_cred() {
        Ok(credentials) => credentials.uid(),
        Err(_) => {
            UNREADABLE.hit(None);
            return;
        }
    };
    if uid != context.kdc_uid {
        REFUSED_PEERS.hit(Some(uid));
        return;
    }
    let Some(slot) = context.acquire() else {
        OVER_QUOTA.hit(Some(uid));
        return;
    };
    let mut reader = FrameReader::new(REQUEST_LIMIT);
    loop {
        let Ok(body) = read_frame(&mut stream, &mut reader, context.frame_timeout).await else {
            return;
        };
        let (outcome, _counted) = if context.draining.load(Ordering::SeqCst) {
            (unavailable(), None)
        } else {
            match context.engine.submit(slot.connection, body) {
                Ok(pending) => {
                    let counted = InFlight::new(&context.in_flight);
                    let outcome = pending.await.unwrap_or_else(|_| unavailable());
                    (outcome, Some(counted))
                }
                Err(SubmitError::Busy) => (refuse_and_stay(Refused::Busy), None),
                Err(SubmitError::Stopped) => (unavailable(), None),
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
) -> Result<(), ()> {
    let frame = match outcome {
        Dispatch::Reply(frame) | Dispatch::ReplyAndClose(frame) => frame,
        Dispatch::Close => return Ok(()),
    };
    timeout(limit, stream.write_all(frame.as_bytes()))
        .await
        .map_err(|_| ())?
        .map_err(|_| ())
}

/// Read exactly one request frame: no deadline for its first octet (idle),
/// then `frame_timeout` for the rest. `Err` on a peer close, a framing
/// error, a deadline or an I/O error.
///
/// Spec: docs/50 §3.3 ("`length` checked against the MAX … before any body
/// byte is allocated or read"), §3.6, R50-7.
async fn read_frame(
    stream: &mut UnixStream,
    reader: &mut FrameReader,
    frame_timeout: Duration,
) -> Result<Zeroizing<Vec<u8>>, ()> {
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
            return Err(());
        }
        let buffer = chunk.get_mut(..wanted).ok_or(())?;
        let read = match started {
            None => stream.read(buffer).await,
            Some(start) => {
                let left = frame_timeout
                    .checked_sub(start.elapsed())
                    .filter(|left| !left.is_zero())
                    .ok_or(())?;
                timeout(left, stream.read(buffer)).await.map_err(|_| ())?
            }
        }
        .map_err(|_| ())?;
        if read == 0 {
            return Err(());
        }
        started.get_or_insert_with(Instant::now);
        let received = buffer.get(..read).ok_or(())?;
        let taken = reader.push(received).map_err(|_| ())?;
        if taken != read {
            return Err(());
        }
    }
}

/// Refused peers counted so far (for the tests' and operators' view of the
/// stderr counters).
#[must_use]
pub fn refused_peer_count() -> u64 {
    REFUSED_PEERS.count()
}
