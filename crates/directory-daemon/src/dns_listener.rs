//! The listener on `dird-dns.sock` (task DN10a): one tokio task per channel
//! connection from dnsd.
//!
//! Per connection, in this order:
//!
//! 1. **Identity and zone** — the peer uid from the kernel's peer
//!    credentials (tokio `UnixStream::peer_cred`) must be dnsd's
//!    (`ipc_dns_server::DnsFronts::zone_of`: `dnsd_uid`, never uid 0);
//!    anything else (or unreadable credentials) ⇒ closed **without a
//!    reply**, counted on stderr (thinned). dnsd's zone becomes the
//!    connection's — fixed before any frame is read, so nothing dnsd sends
//!    can change it (docs/54 §4.6: "dird accepts only `dnsd_uid` (R50-3)";
//!    A-114; docs/52 §7 R14).
//! 2. **Connection bound** — at most `max_connections` (dnsd's own bound,
//!    `ipc_dns::MAX_DNSD_CONNECTIONS`) at once; one more has its first
//!    request (which must arrive within `frame_timeout`) answered
//!    `Refused::Busy`, then is closed — dnsd answers SERVFAIL.
//! 3. **One request, then its reply** — exactly one frame with ipc's
//!    `FrameReader` under the channel's request bound (checked before the
//!    body is allocated or awaited); the connection state and the body go to
//!    the DNS queue (full ⇒ `Refused::Busy` and close); the DNS thread runs
//!    the channel's dispatcher; its frames are written in order (an image is
//!    one frame per chunk); a dispatch that closes ends the connection.
//! 4. **Deadlines** — an idle connection may wait indefinitely (dnsd holds
//!    its connections for the periodic SERIAL check); a started frame must
//!    be complete within `frame_timeout`, and each reply frame is written
//!    within the same time (docs/50 §3.6).
//!
//! While dird stops, a new request is answered `Refused::Unavailable` and
//! the connection closes.
//!
//! Spec: docs/54 §4.6; docs/50 R50-3, R50-7, §3.1, §3.2, §3.3, §3.6; tokio
//! 1.54.1 docs.rs: `net::UnixListener::accept`, `net::UnixStream::peer_cred`,
//! `net::unix::UCred::uid`, `time::timeout`, `spawn`,
//! `io::AsyncWriteExt::write_all`.

use crate::dns_engine::DnsEngineHandle;
use crate::engine::SubmitError;
use crate::ldap_listener::read_frame;
use crate::log::{note, Note, Thinned};
use core::time::Duration;
use ipc::{FrameReader, Refused};
use ipc_dns::REQUEST_LIMIT;
use ipc_dns_server::{refuse, Dispatch, DnsConnection, DnsFronts};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::{UnixListener, UnixStream};
use tokio::time::{sleep, timeout};

/// Pause after a failed `accept`. Project choice.
const ACCEPT_RETRY: Duration = Duration::from_millis(50);

/// Thinned log counters for what a local peer can trigger at will.
static REFUSED_PEERS: Thinned = Thinned::new(Note::DnsPeerRefused);
static UNREADABLE: Thinned = Thinned::new(Note::PeerCredentialsUnreadable);
static CONNECTION_LIMIT: Thinned = Thinned::new(Note::DnsConnectionLimit);
static BUSY: Thinned = Thinned::new(Note::DnsBusy);

/// What every DNS connection task shares.
/// Spec: docs/54 §4.6; docs/50 §3.2, §3.6.
pub(crate) struct DnsServeContext {
    fronts: DnsFronts,
    frame_timeout: Duration,
    max_connections: usize,
    engine: DnsEngineHandle,
    open: AtomicUsize,
    next_connection: AtomicU64,
    draining: AtomicBool,
    in_flight: AtomicUsize,
}

impl DnsServeContext {
    /// Spec: docs/54 §4.6; docs/50 §3.2, §3.6.
    pub(crate) fn new(
        fronts: DnsFronts,
        frame_timeout: Duration,
        max_connections: usize,
        engine: DnsEngineHandle,
    ) -> DnsServeContext {
        DnsServeContext {
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
    /// Spec: docs/54 §4.6 ("≤ 4 connections from dnsd").
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
    context: Arc<DnsServeContext>,
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
pub(crate) async fn accept_loop(listener: UnixListener, context: Arc<DnsServeContext>) {
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
/// Spec: docs/54 §4.6; docs/50 R50-3, R50-7, §3.2, §3.3, §3.6.
async fn connection(mut stream: UnixStream, context: Arc<DnsServeContext>) {
    let uid: u32 = match stream.peer_cred() {
        Ok(credentials) => credentials.uid(),
        Err(_) => {
            UNREADABLE.hit(None);
            return;
        }
    };
    // The zone of the connection: dnsd's, from the kernel's peer
    // credentials. Spec: docs/50 R50-3, §3.2; docs/54 §4.6; A-114.
    let Some(zone) = context.fronts.zone_of(uid) else {
        REFUSED_PEERS.hit(Some(uid));
        return;
    };
    let mut reader = FrameReader::new(REQUEST_LIMIT);
    let Some(slot) = context.acquire() else {
        CONNECTION_LIMIT.hit(Some(uid));
        // The refusal answers dnsd's first request (strict request → reply),
        // which must arrive within `frame_timeout` of the accept.
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
    let mut state = DnsConnection::new(slot.connection, zone);
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

/// Write the frames of `dispatch`, in order, each within `limit`.
/// Spec: docs/50 §3.6; docs/54 §4.6 (an image travels as its chunks).
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

/// `dird-dns.sock` connections refused for their peer uid so far (the tests'
/// and operators' view of the stderr counter).
#[must_use]
pub fn dns_refused_peer_count() -> u64 {
    REFUSED_PEERS.count()
}
