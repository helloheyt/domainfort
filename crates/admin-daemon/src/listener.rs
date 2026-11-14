//! The listener on `admin.sock`: one tokio task per connection.
//!
//! `admin.sock` is reached by any local account that may enter its
//! directory (mode 0750, group `admin_socket_group` — defence in depth
//! only, docs/50 §3.1, docs/51 §5.1); the authorization itself is Kerberos,
//! decided by dird. Per connection, in this order:
//!
//! 1. **Peer uid** — from the kernel's peer credentials (tokio
//!    `UnixStream::peer_cred`); unreadable ⇒ closed, a noise event
//!    `ConnectionRefused{PeerUnidentified}`. The uid is used only for the
//!    limits below and as the events' `peer_uid` — never as a subject
//!    (docs/51 §5.1).
//! 2. **Connection quota** per uid and in all (crate::rate); over it ⇒ a
//!    noise event `ConnectionRefused{ConnectionLimit}`, the first request
//!    (within `frame_timeout`) answered `Refused::Busy`, then closed (as
//!    dird's admin listener does, docs/51 §7.5).
//! 3. **One request, then its reply** — exactly one frame with ipc's
//!    `FrameReader` under the channel's request bound (288 KiB), checked
//!    before the body is allocated or awaited: an oversize frame closes the
//!    connection before its body (a noise event `MalformedFrame`). An idle
//!    connection may wait indefinitely; a started frame must complete within
//!    `frame_timeout` (docs/50 §3.6). The frame body is a zeroizing buffer,
//!    wiped as soon as it is decoded (docs/50 §3.3).
//! 4. **Request rate** per uid (crate::rate): over it ⇒ `Refused::Busy`,
//!    the connection kept, the frame dropped undecoded — with a noise event
//!    `RateLimited` (task F6, Q-406 item 3).
//! 5. **Decoding** (`ipc_admin::decode_request`): a wrong magic or unknown
//!    kind ⇒ close; another version ⇒ `Refused{VersionMismatch}` + close; a
//!    malformed payload ⇒ `Refused{Malformed}` + close — each with a noise
//!    event `MalformedFrame` naming the rule, or `ValueRefused` when the
//!    typed layer refused a value (task F6; never an octet: the frame may
//!    hold a password). keyadm's former requests (`FetchApproved`,
//!    `Complete`, `ListPendingDestruction`, kinds `0x10`–`0x12`) are
//!    retired by A-102 (docs/52 §4.6; docs/questions/Q-460): they are
//!    unknown kinds of the closed table, so such a frame closes the
//!    connection here, from any uid, and nothing reaches dird (N2).
//! 6. **Dispatch** — `Ping` answered here; a forwarded operation or a
//!    `SetPassword` goes to the worker's bounded queue (full ⇒
//!    `Refused::Busy`, the connection kept), and its answer is written
//!    before the next frame is read (one request in flight, R50-7).
//!
//! While admind stops, a new request is answered `Refused::Unavailable` and
//! the connection closes.
//!
//! Spec: docs/51 §5.1, §5.7 item 3, §7.5, §7.6; docs/50 R50-3, R50-7,
//! §3.1-§3.3, §3.6, §7.5 (`Ping`); A-57; A-64; A-85; tokio 1.54.1 docs.rs:
//! `net::UnixListener::accept`, `net::UnixStream::peer_cred`,
//! `time::timeout`, `spawn`, `io::{AsyncReadExt, AsyncWriteExt}`.

use crate::audit::AuditGate;
use crate::clock;
use crate::log::{note, Note, Thinned};
use crate::rate::{ConnectionQuota, Limits, RateLimiter};
use crate::worker::{Answer, SubmitError, Work, WorkerHandle};
use core::time::Duration;
use ipc::{EncodedFrame, FrameReader, Refused};
use ipc_admin::{
    decode_request, encode_refusal, encode_reply, RefusalStatus, Rejection, Reply, Request,
    REQUEST_LIMIT,
};
use ipc_audit::{AdmindActivity, AdmindEvent, ConnectionRefusal, FrameErrorCode};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::time::{sleep, timeout};
use zeroize::Zeroizing;

/// Pause after a failed `accept`. Project choice.
const ACCEPT_RETRY: Duration = Duration::from_millis(50);

/// Octets read from the socket per read call at most. Project choice.
const READ_CHUNK: usize = 4096;

/// Thinned log counters for what a local peer can trigger at will.
static UNREADABLE: Thinned = Thinned::new(Note::PeerCredentialsUnreadable);
static CONNECTION_LIMIT: Thinned = Thinned::new(Note::ConnectionLimit);
static RATE_LIMITED: Thinned = Thinned::new(Note::RateLimited);
static MALFORMED: Thinned = Thinned::new(Note::MalformedFrame);
static FRAME_TIMEOUT: Thinned = Thinned::new(Note::FrameTimeout);
static BUSY: Thinned = Thinned::new(Note::WorkerBusy);
static WORKER_LOST: Thinned = Thinned::new(Note::WorkerLost);

/// What every connection task shares.
/// Spec: docs/51 §5.1, §7.5; docs/50 §3.6.
pub(crate) struct ServeContext {
    frame_timeout: Duration,
    limits: Limits,
    gate: Arc<AuditGate>,
    worker: WorkerHandle,
    quota: Mutex<ConnectionQuota>,
    rate: Mutex<RateLimiter>,
    draining: AtomicBool,
    in_flight: AtomicUsize,
}

impl ServeContext {
    /// Spec: docs/51 §7.5; docs/50 §3.6.
    pub(crate) fn new(
        frame_timeout: Duration,
        limits: Limits,
        gate: Arc<AuditGate>,
        worker: WorkerHandle,
    ) -> ServeContext {
        ServeContext {
            frame_timeout,
            limits,
            gate,
            worker,
            quota: Mutex::new(ConnectionQuota::default()),
            rate: Mutex::new(RateLimiter::new(
                limits.requests_per_window,
                limits.rate_window,
                limits.max_tracked_uids,
            )),
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

    /// A noise event (refused connection, malformed frame).
    /// Spec: docs/51 §5.7 item 3; A-57; A-85 (Q-340 items 6, 8).
    fn noise(&self, peer_uid: Option<u32>, activity: AdmindActivity) {
        self.gate.noise(&AdmindEvent {
            time: clock::event_time(),
            peer_uid,
            activity,
        });
    }

    /// Take a connection slot, or `None` at the bound (a poisoned lock
    /// refuses — fail closed).
    fn acquire(self: &Arc<Self>, uid: u32) -> Option<Slot> {
        let mut quota = self.quota.lock().ok()?;
        quota.acquire(uid, &self.limits).then(|| Slot {
            context: Arc::clone(self),
            uid,
        })
    }

    /// Count one request of `uid` (a poisoned lock refuses).
    fn admit(&self, uid: u32) -> bool {
        self.rate
            .lock()
            .map(|mut rate| rate.admit(uid, Instant::now()))
            .unwrap_or(false)
    }
}

/// One held connection slot: given back when the connection ends.
struct Slot {
    context: Arc<ServeContext>,
    uid: u32,
}

impl Drop for Slot {
    fn drop(&mut self) {
        if let Ok(mut quota) = self.context.quota.lock() {
            quota.release(self.uid);
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

/// Why no frame was read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FrameFailure {
    /// The peer closed (or an I/O error).
    Closed,
    /// A started frame did not complete in time.
    Timeout,
    /// The frame broke the framing rules (an over-bound length).
    Framing(ipc::Error),
}

/// Read exactly one request frame: no deadline for its first octet (idle),
/// then `frame_timeout` for the rest. The declared length is checked against
/// the request bound before any body octet is allocated or awaited.
/// Spec: docs/50 §3.3, §3.6, R50-7.
async fn read_frame(
    stream: &mut UnixStream,
    reader: &mut FrameReader,
    frame_timeout: Duration,
) -> Result<Zeroizing<Vec<u8>>, FrameFailure> {
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
            return Err(FrameFailure::Closed);
        }
        let buffer = chunk.get_mut(..wanted).ok_or(FrameFailure::Closed)?;
        let read = match started {
            None => stream.read(buffer).await,
            Some(start) => {
                let left = frame_timeout
                    .checked_sub(start.elapsed())
                    .filter(|left| !left.is_zero())
                    .ok_or(FrameFailure::Timeout)?;
                timeout(left, stream.read(buffer))
                    .await
                    .map_err(|_| FrameFailure::Timeout)?
            }
        }
        .map_err(|_| FrameFailure::Closed)?;
        if read == 0 {
            return Err(FrameFailure::Closed);
        }
        started.get_or_insert_with(Instant::now);
        let received = buffer.get(..read).ok_or(FrameFailure::Closed)?;
        let taken = reader.push(received).map_err(FrameFailure::Framing)?;
        if taken != read {
            return Err(FrameFailure::Closed);
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
/// `Refused{OutcomeUnknown}` (cannot happen for the replies admind builds).
/// Spec: docs/51 §7.6.
async fn write_reply(stream: &mut UnixStream, reply: &Reply, limit: Duration) -> bool {
    let frame = match encode_reply(reply) {
        Ok(frame) => frame,
        Err(_) => match encode_reply(&Reply::Refused(RefusalStatus::OutcomeUnknown)) {
            Ok(frame) => frame,
            Err(_) => return false,
        },
    };
    write_frame(stream, &frame, limit).await
}

/// The audit code of a frame that did not decode: the `ipc` rule, or
/// `ValueRefused` for a value the typed layer refused (task F6; before it,
/// `Unlisted` — docs/questions/Q-406 item 3).
fn frame_error(error: Option<ipc::Error>) -> FrameErrorCode {
    error.map_or(FrameErrorCode::ValueRefused, FrameErrorCode::of)
}

/// Serve one connection (module documentation).
/// Spec: docs/51 §5.1, §7.5, §7.6; docs/50 R50-3, R50-7, §3.2, §3.3, §3.6.
async fn connection(mut stream: UnixStream, context: Arc<ServeContext>) {
    let uid: u32 = match stream.peer_cred() {
        Ok(credentials) => credentials.uid(),
        Err(_) => {
            UNREADABLE.hit(None);
            context.noise(
                None,
                AdmindActivity::ConnectionRefused {
                    reason: ConnectionRefusal::PeerUnidentified,
                },
            );
            return;
        }
    };
    let limit = context.frame_timeout;
    let mut reader = FrameReader::new(REQUEST_LIMIT);
    let Some(_slot) = context.acquire(uid) else {
        CONNECTION_LIMIT.hit(Some(uid));
        context.noise(
            Some(uid),
            AdmindActivity::ConnectionRefused {
                reason: ConnectionRefusal::ConnectionLimit,
            },
        );
        if let Ok(Ok(body)) = timeout(limit, read_frame(&mut stream, &mut reader, limit)).await {
            drop(body);
            let _ = write_refusal(&mut stream, Refused::Busy, limit).await;
        }
        return;
    };
    loop {
        let body = match read_frame(&mut stream, &mut reader, limit).await {
            Ok(body) => body,
            Err(FrameFailure::Closed) => return,
            Err(FrameFailure::Timeout) => {
                FRAME_TIMEOUT.hit(Some(uid));
                return;
            }
            Err(FrameFailure::Framing(error)) => {
                MALFORMED.hit(Some(uid));
                context.noise(
                    Some(uid),
                    AdmindActivity::MalformedFrame {
                        error: FrameErrorCode::of(error),
                    },
                );
                return;
            }
        };
        if context.draining.load(Ordering::SeqCst) {
            drop(body);
            let _ = write_refusal(&mut stream, Refused::Unavailable, limit).await;
            return;
        }
        if !context.admit(uid) {
            drop(body);
            RATE_LIMITED.hit(Some(uid));
            // Noise (task F6, Q-406 item 3): nothing was asked of dird or
            // keyd; a flood is counted into a summary, never blocking.
            context.noise(Some(uid), AdmindActivity::RateLimited);
            if !write_refusal(&mut stream, Refused::Busy, limit).await {
                return;
            }
            continue;
        }
        let decoded = decode_request(&body);
        // The frame (which may hold a password) is wiped here.
        drop(body);
        let request = match decoded {
            Ok(request) => request,
            Err(rejected) => {
                MALFORMED.hit(Some(uid));
                context.noise(
                    Some(uid),
                    AdmindActivity::MalformedFrame {
                        error: frame_error(rejected.error),
                    },
                );
                if let Rejection::Refuse(refused) = rejected.action {
                    let _ = write_refusal(&mut stream, refused, limit).await;
                }
                return;
            }
        };
        let work = match request {
            Request::Ping => {
                if !write_reply(&mut stream, &Reply::Pong, limit).await {
                    return;
                }
                continue;
            }
            Request::Forward { auth, operation } => Work::Forward { auth, operation },
            Request::SetPassword(set) => Work::SetPassword(set),
        };
        let lost = work.lost_answer();
        let counted = InFlight::new(&context.in_flight);
        let pending = match context.worker.submit(uid, work) {
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
        let written = match pending.await {
            Ok(Answer::Reply(reply)) => write_reply(&mut stream, &reply, limit).await,
            Ok(Answer::Refused(refused)) => write_refusal(&mut stream, refused, limit).await,
            Err(_) => {
                WORKER_LOST.hit(Some(uid));
                let _ = write_reply(&mut stream, &lost, limit).await;
                false
            }
        };
        drop(counted);
        if !written {
            return;
        }
    }
}
