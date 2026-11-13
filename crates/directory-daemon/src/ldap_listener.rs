//! The listener on `dird-ldap.sock`: one tokio task per channel connection
//! — one client connection of ldap-front, one LDAP session (docs/50 R50-10).
//!
//! Per connection, in this order:
//!
//! 1. **Identity** — the peer uid from the kernel's peer credentials (tokio
//!    `UnixStream::peer_cred`) must be exactly the configured
//!    `ldap_front_uid`; anything else (or unreadable credentials) ⇒ the
//!    connection is closed **without a reply** (docs/50 §3.2:
//!    "dird-ldap.sock ← ldap-front"). Counted on stderr (thinned).
//! 2. **Session bound** — at most `max_sessions` LDAP sessions at once; one
//!    more has its first request (which must arrive within `frame_timeout`)
//!    answered `Refused::Busy`, then is closed (the front closes its client
//!    with a Notice of Disconnection, busy). docs/50 §4.2: "the number
//!    of connections is bounded by the front's connection quota" — dird
//!    bounds it as well, never trusting the front for its own resources.
//! 3. **Connection id** — a number this listener assigns (never from the
//!    peer): the `ldap::Session`'s connection id and the audit events'
//!    (docs/50 §4.2).
//! 4. **One request, then its reply** — exactly one frame with ipc's
//!    [`FrameReader`] under the channel's request bound (checked before the
//!    body is allocated or awaited); the connection state and the body go to
//!    the LDAP engine queue (full ⇒ `Refused::Busy` and close — R50-7; the
//!    front then closes its client); the reply frames are written in order;
//!    only then is the next frame read (R50-7).
//! 5. **Deadlines** — an idle connection may wait indefinitely (the front
//!    enforces InitRecvTimeout / MaxConnIdleTime on its client, docs/50
//!    §4.2), a started frame must be complete within `frame_timeout`, and
//!    each reply frame is written within the same time (docs/50 §3.6).
//! 6. **End** — the dispatch says close (a `Done { Close }`, a refusal, the
//!    front's `Close`), or the peer closes, or a deadline passes: the task
//!    ends and the session is destroyed with it.
//!
//! While dird stops, a new request is answered `Refused::Unavailable` and
//! the connection closes: the front sends its client a Notice of
//! Disconnection (unavailable — RFC 4511 §4.4.1: "the server is shutting
//! down"; App. A).
//!
//! Spec: docs/50 R50-3, R50-7, R50-10, §3.1, §3.2, §3.3, §3.6, §3.7, §4.2;
//! RFC 4511 §4.4.1, App. A; tokio 1.54.1 docs.rs: `net::UnixListener::accept`,
//! `net::UnixStream::peer_cred`, `net::unix::UCred::uid`, `time::timeout`,
//! `spawn`, `io::{AsyncReadExt::read, AsyncWriteExt::write_all}`.

use crate::engine::SubmitError;
use crate::ldap_engine::LdapEngineHandle;
use crate::log::{note, Note, Thinned};
use core::time::Duration;
use ipc::{FrameReader, Refused};
use ipc_ldap::REQUEST_LIMIT;
use ipc_ldap_server::{refuse, Dispatch, LdapConnection};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::time::{sleep, timeout};
use zeroize::Zeroizing;

/// Octets read from the socket per read call at most. Project choice.
const READ_CHUNK: usize = 64 * 1024;

/// Pause after a failed `accept`. Project choice.
const ACCEPT_RETRY: Duration = Duration::from_millis(50);

/// Thinned log counters for what a local peer can trigger at will.
static REFUSED_PEERS: Thinned = Thinned::new(Note::LdapPeerRefused);
static UNREADABLE: Thinned = Thinned::new(Note::PeerCredentialsUnreadable);
static SESSION_LIMIT: Thinned = Thinned::new(Note::LdapSessionLimit);
static BUSY: Thinned = Thinned::new(Note::LdapBusy);

/// What every LDAP connection task shares.
/// Spec: docs/50 §3.2, §3.6, §4.2.
pub(crate) struct LdapServeContext {
    front_uid: u32,
    frame_timeout: Duration,
    max_sessions: usize,
    engine: LdapEngineHandle,
    open: AtomicUsize,
    next_connection: AtomicU64,
    draining: AtomicBool,
    in_flight: AtomicUsize,
}

impl LdapServeContext {
    /// Spec: docs/50 §3.2, §3.6, §4.2.
    pub(crate) fn new(
        front_uid: u32,
        frame_timeout: Duration,
        max_sessions: usize,
        engine: LdapEngineHandle,
    ) -> LdapServeContext {
        LdapServeContext {
            front_uid,
            frame_timeout,
            max_sessions,
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

    /// Take a session slot, or `None` at the bound.
    /// Spec: docs/50 §4.2.
    fn acquire(self: &Arc<Self>) -> Option<SessionSlot> {
        let mut current = self.open.load(Ordering::SeqCst);
        loop {
            if current >= self.max_sessions {
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
        Some(SessionSlot {
            context: Arc::clone(self),
            connection: id,
        })
    }
}

/// One held session slot: given back when the connection ends.
struct SessionSlot {
    context: Arc<LdapServeContext>,
    connection: u64,
}

impl Drop for SessionSlot {
    fn drop(&mut self) {
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
pub(crate) async fn accept_loop(listener: UnixListener, context: Arc<LdapServeContext>) {
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

/// Serve one channel connection (module documentation).
/// Spec: docs/50 R50-3, R50-7, R50-10, §3.2, §3.3, §3.6, §4.2.
async fn connection(mut stream: UnixStream, context: Arc<LdapServeContext>) {
    let uid: u32 = match stream.peer_cred() {
        Ok(credentials) => credentials.uid(),
        Err(_) => {
            UNREADABLE.hit(None);
            return;
        }
    };
    if uid != context.front_uid {
        REFUSED_PEERS.hit(Some(uid));
        return;
    }
    let mut reader = FrameReader::new(REQUEST_LIMIT);
    let Some(slot) = context.acquire() else {
        SESSION_LIMIT.hit(Some(uid));
        // The refusal answers the front's first request (strict request →
        // reply, R50-7), so the front reads it instead of a closed socket;
        // that request must arrive within `frame_timeout` of the accept, so
        // a connection over the bound holds nothing for longer.
        if timeout(
            context.frame_timeout,
            read_frame(&mut stream, &mut reader, context.frame_timeout),
        )
        .await
        .is_ok_and(|frame| frame.is_ok())
        {
            let _ =
                write_dispatch(&mut stream, &refuse(Refused::Busy), context.frame_timeout).await;
        }
        return;
    };
    let mut state = Box::new(LdapConnection::new(slot.connection));
    loop {
        let Ok(body) = read_frame(&mut stream, &mut reader, context.frame_timeout).await else {
            return;
        };
        if context.draining.load(Ordering::SeqCst) {
            let _ = write_dispatch(
                &mut stream,
                &refuse(Refused::Unavailable),
                context.frame_timeout,
            )
            .await;
            return;
        }
        let pending = match context.engine.submit(state, body) {
            Ok(pending) => pending,
            Err(SubmitError::Busy) => {
                BUSY.hit(Some(uid));
                let _ = write_dispatch(&mut stream, &refuse(Refused::Busy), context.frame_timeout)
                    .await;
                return;
            }
            Err(SubmitError::Stopped) => {
                let _ = write_dispatch(
                    &mut stream,
                    &refuse(Refused::Unavailable),
                    context.frame_timeout,
                )
                .await;
                return;
            }
        };
        let counted = InFlight::new(&context.in_flight);
        let Ok((back, dispatch)) = pending.await else {
            drop(counted);
            let _ = write_dispatch(
                &mut stream,
                &refuse(Refused::Unavailable),
                context.frame_timeout,
            )
            .await;
            return;
        };
        state = back;
        let written = write_dispatch(&mut stream, &dispatch, context.frame_timeout).await;
        drop(counted);
        if written.is_err() || dispatch.closes() {
            return;
        }
    }
}

/// Write the frames of `dispatch` in order, each within `limit`.
/// Spec: docs/50 §3.6.
async fn write_dispatch(
    stream: &mut UnixStream,
    dispatch: &Dispatch,
    limit: Duration,
) -> Result<(), ()> {
    for frame in dispatch.frames() {
        timeout(limit, stream.write_all(frame.as_bytes()))
            .await
            .map_err(|_| ())?
            .map_err(|_| ())?;
    }
    Ok(())
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
    let mut chunk = Zeroizing::new(vec![0u8; READ_CHUNK]);
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

/// `dird-ldap.sock` connections refused for their peer uid so far (the
/// tests' and operators' view of the stderr counter).
#[must_use]
pub fn ldap_refused_peer_count() -> u64 {
    REFUSED_PEERS.count()
}
