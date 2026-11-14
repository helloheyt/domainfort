//! The listener on `dird-admin.sock`: one tokio task per admind connection.
//!
//! Per connection, in this order:
//!
//! 1. **Identity** — the peer uid from the kernel's peer credentials (tokio
//!    `UnixStream::peer_cred`) must be exactly the configured `admind_uid`;
//!    anything else (or unreadable credentials) ⇒ the connection is closed
//!    **without a reply** and counted (docs/51 §7.1: "the only peer =
//!    `admind_uid`; another uid ⇒ close + count").
//! 2. **Connection bound** — at most `max_connections` (2) at once; one
//!    more has its first request (which must arrive within
//!    `frame_timeout`) answered `Refused::Busy`, then is closed (docs/51
//!    §7.5: "≤ 2 connections from admind").
//! 3. **One request, then its reply** — exactly one frame with ipc's
//!    `FrameReader` under the channel's request bound (256 KiB), checked
//!    before the body is allocated or awaited — an oversize frame closes the
//!    connection before its body; decoded strictly
//!    (`ipc_dird_admin::decode_request`: a wrong magic or unknown kind ⇒
//!    close; another version ⇒ `Refused{VersionMismatch}` + close; a
//!    malformed payload ⇒ `Refused{Malformed}` + close). `Ping` is answered
//!    here; an operation goes to the admin queue (full ⇒ `Refused::Busy`,
//!    the connection kept), and its reply is written before the next frame
//!    is read (docs/51 §7.5: one request in flight per connection).
//! 4. **Deadlines** — an idle connection may wait indefinitely; a started
//!    frame must be complete within `frame_timeout`, and each reply frame is
//!    written within the same time (docs/50 §3.6).
//!
//! While dird stops, a new request is answered `Refused::Unavailable` and
//! the connection closes.
//!
//! Spec: docs/51 §7.1, §7.5; docs/50 R50-3, R50-7, §3.1, §3.2, §3.3, §3.6,
//! §7.5 (`Ping`); tokio 1.54.1 docs.rs: `net::UnixListener::accept`,
//! `net::UnixStream::peer_cred`, `time::timeout`, `spawn`,
//! `io::AsyncWriteExt::write_all`.

use crate::admin_engine::AdminEngineHandle;
use crate::engine::SubmitError;
use crate::ldap_listener::read_frame;
use crate::log::{note, Note, Thinned};
use core::time::Duration;
use ipc::{EncodedFrame, FrameReader, Refused};
use ipc_dird_admin::{
    decode_request, encode_refusal, encode_reply, RefusalStatus, Rejection, Reply, Request,
    REQUEST_LIMIT,
};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::{UnixListener, UnixStream};
use tokio::time::{sleep, timeout};

/// Pause after a failed `accept`. Project choice.
const ACCEPT_RETRY: Duration = Duration::from_millis(50);

/// Thinned log counters for what a local peer can trigger at will.
static REFUSED_PEERS: Thinned = Thinned::new(Note::AdminPeerRefused);
static UNREADABLE: Thinned = Thinned::new(Note::PeerCredentialsUnreadable);
static CONNECTION_LIMIT: Thinned = Thinned::new(Note::AdminConnectionLimit);
static BUSY: Thinned = Thinned::new(Note::AdminBusy);

/// What every admin connection task shares.
/// Spec: docs/51 §7.1, §7.5.
pub(crate) struct AdminServeContext {
    admind_uid: u32,
    frame_timeout: Duration,
    max_connections: usize,
    engine: AdminEngineHandle,
    open: AtomicUsize,
    draining: AtomicBool,
    in_flight: AtomicUsize,
}

impl AdminServeContext {
    /// Spec: docs/51 §7.1, §7.5.
    pub(crate) fn new(
        admind_uid: u32,
        frame_timeout: Duration,
        max_connections: usize,
        engine: AdminEngineHandle,
    ) -> AdminServeContext {
        AdminServeContext {
            admind_uid,
            frame_timeout,
            max_connections,
            engine,
            open: AtomicUsize::new(0),
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
                Ok(_) => {
                    return Some(Slot {
                        context: Arc::clone(self),
                    })
                }
                Err(actual) => current = actual,
            }
        }
    }
}

/// One held connection slot: given back when the connection ends.
struct Slot {
    context: Arc<AdminServeContext>,
}

impl Drop for Slot {
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
pub(crate) async fn accept_loop(listener: UnixListener, context: Arc<AdminServeContext>) {
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

/// Write one frame within `limit`. Spec: docs/50 §3.6.
async fn write_frame(stream: &mut UnixStream, frame: &EncodedFrame, limit: Duration) -> bool {
    matches!(
        timeout(limit, stream.write_all(frame.as_bytes())).await,
        Ok(Ok(()))
    )
}

/// Write the shared refusal. Spec: docs/50 §3.3; A-59.
async fn write_refusal(stream: &mut UnixStream, refused: Refused, limit: Duration) -> bool {
    match encode_refusal(refused) {
        Ok(frame) => write_frame(stream, &frame, limit).await,
        Err(_) => false,
    }
}

/// Write a typed reply; one that cannot be encoded is answered
/// `Refused{Unavailable}` (cannot happen for a reply the PEP built).
/// Spec: docs/51 §7.3.
async fn write_reply(stream: &mut UnixStream, reply: &Reply, limit: Duration) -> bool {
    let frame = match encode_reply(reply) {
        Ok(frame) => frame,
        Err(_) => match encode_reply(&Reply::Refused(RefusalStatus::Unavailable)) {
            Ok(frame) => frame,
            Err(_) => return false,
        },
    };
    write_frame(stream, &frame, limit).await
}

/// Serve one admin connection (module documentation).
/// Spec: docs/51 §7.1, §7.5; docs/50 R50-3, R50-7, §3.2, §3.3, §3.6.
async fn connection(mut stream: UnixStream, context: Arc<AdminServeContext>) {
    let uid: u32 = match stream.peer_cred() {
        Ok(credentials) => credentials.uid(),
        Err(_) => {
            UNREADABLE.hit(None);
            return;
        }
    };
    if uid != context.admind_uid {
        REFUSED_PEERS.hit(Some(uid));
        return;
    }
    let mut reader = FrameReader::new(REQUEST_LIMIT);
    let limit = context.frame_timeout;
    let Some(_slot) = context.acquire() else {
        CONNECTION_LIMIT.hit(Some(uid));
        if timeout(limit, read_frame(&mut stream, &mut reader, limit))
            .await
            .is_ok_and(|frame| frame.is_ok())
        {
            let _ = write_refusal(&mut stream, Refused::Busy, limit).await;
        }
        return;
    };
    loop {
        let Ok(body) = read_frame(&mut stream, &mut reader, limit).await else {
            return;
        };
        if context.draining.load(Ordering::SeqCst) {
            let _ = write_refusal(&mut stream, Refused::Unavailable, limit).await;
            return;
        }
        let request = decode_request(&body);
        drop(body);
        let (auth, operation) = match request {
            Err(Rejection::Close) => return,
            Err(Rejection::Refuse(refused)) => {
                let _ = write_refusal(&mut stream, refused, limit).await;
                return;
            }
            Ok(Request::Ping) => {
                if !write_reply(&mut stream, &Reply::Pong, limit).await {
                    return;
                }
                continue;
            }
            Ok(Request::Operation { auth, operation }) => (auth, operation),
        };
        let counted = InFlight::new(&context.in_flight);
        let pending = match context.engine.submit(auth, operation) {
            Ok(pending) => pending,
            Err(SubmitError::Busy) => {
                drop(counted);
                BUSY.hit(Some(uid));
                if !write_refusal(&mut stream, Refused::Busy, limit).await {
                    return;
                }
                continue;
            }
            Err(SubmitError::Stopped) => {
                drop(counted);
                let _ = write_refusal(&mut stream, Refused::Unavailable, limit).await;
                return;
            }
        };
        let Ok(reply) = pending.await else {
            drop(counted);
            let _ = write_refusal(&mut stream, Refused::Unavailable, limit).await;
            return;
        };
        let written = write_reply(&mut stream, &reply, limit).await;
        drop(counted);
        if !written {
            return;
        }
    }
}

/// `dird-admin.sock` connections refused for their peer uid so far (the
/// tests' and operators' view of the stderr counter).
#[must_use]
pub fn admin_refused_peer_count() -> u64 {
    REFUSED_PEERS.count()
}
