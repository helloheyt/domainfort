//! The listener on `dird-kpasswd.sock` (task K7, dird side): one tokio task
//! per channel connection from kpasswd-front.
//!
//! Per connection, in this order:
//!
//! 1. **Identity and zone** — the peer uid from the kernel's peer
//!    credentials (tokio `UnixStream::peer_cred`) must be the front's
//!    (`ipc_kpasswd::KpasswdFronts::zone_of`: `kpasswd_front_uid`, never
//!    uid 0); anything else (or unreadable credentials) ⇒ closed **without
//!    a reply**, counted on stderr (thinned). The front's zone becomes the
//!    connection's — fixed before any frame is read, so nothing the front
//!    sends can change it (docs/53 §3.3, §5.6 step 1; docs/50 R50-3; docs/52
//!    §3.3 C3, §7 R14).
//! 2. **Connection bound** — at most `max_connections` (the front's own
//!    bound, `ipc_kpasswd::MAX_FRONT_CONNECTIONS`) at once; one more has its
//!    first request (which must arrive within `frame_timeout`) answered
//!    `Refused::Busy`, then is closed — the front answers HARDERROR.
//! 3. **One request, then its reply** — exactly one frame with ipc's
//!    `FrameReader` under the channel's request bound (checked before the
//!    body is allocated or awaited); the connection state and the body go to
//!    the kpasswd queue (full ⇒ `Refused::Busy` and close — docs/53 §5.6
//!    step 1); the kpasswd thread runs the channel's dispatcher; its frame
//!    is written; the dispatcher's `ReplyAndClose` ends the connection after
//!    a change (one change per connection — RFC 3244 §2; docs/questions/
//!    Q-955 item 7).
//! 4. **Deadlines** — an idle connection may wait indefinitely; a started
//!    frame must be complete within `frame_timeout`, and the reply frame is
//!    written within the same time (docs/50 §3.6).
//!
//! While dird stops, a new request is answered `Refused::Unavailable` and
//! the connection closes.
//!
//! Spec: docs/53 §3.3, §5.6 step 1; docs/50 R50-3, R50-7, §3.1, §3.2, §3.3,
//! §3.6; RFC 3244 §2; tokio 1.54.1 docs.rs: `net::UnixListener::accept`,
//! `net::UnixStream::peer_cred`, `net::unix::UCred::uid`, `time::timeout`,
//! `spawn`, `io::AsyncWriteExt::write_all`.

use crate::engine::SubmitError;
use crate::kpasswd_engine::KpasswdEngineHandle;
use crate::ldap_listener::read_frame;
use crate::log::{note, Note, Thinned};
use core::time::Duration;
use ipc::{FrameReader, Refused};
use ipc_kpasswd::{refuse, Dispatch, KpasswdConnection, KpasswdFronts, REQUEST_LIMIT};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::{UnixListener, UnixStream};
use tokio::time::{sleep, timeout};

/// Pause after a failed `accept`. Project choice.
const ACCEPT_RETRY: Duration = Duration::from_millis(50);

/// Thinned log counters for what a local peer can trigger at will.
static REFUSED_PEERS: Thinned = Thinned::new(Note::KpasswdPeerRefused);
static UNREADABLE: Thinned = Thinned::new(Note::PeerCredentialsUnreadable);
static CONNECTION_LIMIT: Thinned = Thinned::new(Note::KpasswdConnectionLimit);
static BUSY: Thinned = Thinned::new(Note::KpasswdBusy);

/// What every kpasswd connection task shares.
/// Spec: docs/53 §5.6 step 1; docs/50 §3.2, §3.6.
pub(crate) struct KpasswdServeContext {
    fronts: KpasswdFronts,
    frame_timeout: Duration,
    max_connections: usize,
    engine: KpasswdEngineHandle,
    open: AtomicUsize,
    next_connection: AtomicU64,
    draining: AtomicBool,
    in_flight: AtomicUsize,
}

impl KpasswdServeContext {
    /// Spec: docs/53 §5.6 step 1; docs/50 §3.2, §3.6.
    pub(crate) fn new(
        fronts: KpasswdFronts,
        frame_timeout: Duration,
        max_connections: usize,
        engine: KpasswdEngineHandle,
    ) -> KpasswdServeContext {
        KpasswdServeContext {
            fronts,
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

    /// Take a connection slot, or `None` at the bound.
    /// Spec: docs/53 §5.6 step 1.
    fn acquire(self: &Arc<Self>) -> Option<ConnectionSlot> {
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
        Some(ConnectionSlot {
            context: Arc::clone(self),
            connection: id,
        })
    }
}

/// One held connection slot: given back when the connection ends.
struct ConnectionSlot {
    context: Arc<KpasswdServeContext>,
    connection: u64,
}

impl Drop for ConnectionSlot {
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
pub(crate) async fn accept_loop(listener: UnixListener, context: Arc<KpasswdServeContext>) {
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
/// Spec: docs/53 §3.3, §5.6 step 1; docs/50 R50-3, R50-7, §3.2, §3.3, §3.6.
async fn connection(mut stream: UnixStream, context: Arc<KpasswdServeContext>) {
    let uid: u32 = match stream.peer_cred() {
        Ok(credentials) => credentials.uid(),
        Err(_) => {
            UNREADABLE.hit(None);
            return;
        }
    };
    // The zone of the connection: its front's, from the kernel's peer
    // credentials. Spec: docs/50 R50-3, §3.2; docs/53 §3.3; docs/52 R14.
    let Some(zone) = context.fronts.zone_of(uid) else {
        REFUSED_PEERS.hit(Some(uid));
        return;
    };
    let mut reader = FrameReader::new(REQUEST_LIMIT);
    let Some(slot) = context.acquire() else {
        CONNECTION_LIMIT.hit(Some(uid));
        // The refusal answers the front's first request (strict request →
        // reply), which must arrive within `frame_timeout` of the accept.
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
    let mut state = KpasswdConnection::new(slot.connection, zone);
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

/// Write the frame of `dispatch`, if any, within `limit`.
/// Spec: docs/50 §3.6.
async fn write_dispatch(
    stream: &mut UnixStream,
    dispatch: &Dispatch,
    limit: Duration,
) -> Result<(), ()> {
    if let Some(frame) = dispatch.frame() {
        timeout(limit, stream.write_all(frame.as_bytes()))
            .await
            .map_err(|_| ())?
            .map_err(|_| ())?;
    }
    Ok(())
}

/// `dird-kpasswd.sock` connections refused for their peer uid so far (the
/// tests' and operators' view of the stderr counter).
#[must_use]
pub fn kpasswd_refused_peer_count() -> u64 {
    REFUSED_PEERS.count()
}
