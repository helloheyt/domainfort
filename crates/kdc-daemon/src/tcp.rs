//! The TCP listener (RFC 4120 §7.2.2): one accept task per configured
//! address, one task per connection.
//!
//! "Each request (KRB_KDC_REQ) and response (KRB_KDC_REP or KRB_ERROR) sent
//! over the TCP stream is preceded by the length of the request as 4 octets
//! in network byte order. The high bit of the length is reserved … If a KDC
//! … receives a request with the high order bit of the length set, it MUST
//! return a KRB-ERROR message with the error KRB_ERR_FIELD_TOOLONG and MUST
//! close the TCP stream." "The KDC MAY close the TCP stream after sending a
//! response, but MAY leave the stream open for a reasonable period of time
//! if it expects a follow-up. Care must be taken in managing TCP/IP
//! connections on the KDC to prevent denial of service attacks based on the
//! number of open TCP/IP connections."
//!
//! Per connection:
//!
//! 1. **Limits** (docs/50 §4.1: "a global Semaphore (e.g. 1024
//!    connections) and a counter per source address (e.g. 16)";
//!    crates/config `max_tcp_connections`,
//!    `max_tcp_connections_per_source`): over either ⇒ closed at once,
//!    nothing read.
//! 2. **Framing** with the library's helpers: `tcp_decode_frame` after every
//!    read — the length (reserved bit, `MAX_REQUEST_LEN`) is checked as soon
//!    as its 4 octets are present, before any message octet is awaited; the
//!    buffer never holds more than `TCP_LENGTH_PREFIX_LEN + MAX_REQUEST_LEN`
//!    octets. A `FramingError` goes to the engine as `Kdc::reject_frame`:
//!    KRB_ERR_FIELD_TOOLONG, then close (RFC 4120 §7.2.2).
//! 3. **Deadlines** (docs/50 §4.1: "first frame within 10 s; a started frame
//!    — within 10 s; idle between requests 30 s"; crates/config): the first
//!    frame must be complete within `first_frame_timeout` of the accept; a
//!    frame, once its first octet arrived, within `frame_timeout`; between a
//!    reply and the next frame's first octet at most `idle_timeout`. A
//!    reply is written within `frame_timeout`. Any deadline ⇒ close.
//! 4. **Request by request** (docs/50 §4.1: "processing request after
//!    request on each connection"): one request at a time goes to the
//!    engine; octets that follow it (RFC 4120 §7.2.2: "A client MAY send
//!    multiple requests before receiving responses") wait in the buffer for
//!    the next turn; replies therefore leave in request order.
//! 5. **Close** after `SendAndClose`, after a withheld answer, when the
//!    engine queue is full (docs/50 §4.1: "full queue ⇒ TCP close"), when
//!    the engine stopped, and after `max_requests_per_tcp_connection`
//!    replies (docs/50 §4.1: "up to 64 requests per connection and then
//!    close").
//!
//! Spec: RFC 4120 §7.2.2, §7.5.9; docs/50 R50-9, §4.1; docs/07 §1;
//! docs/questions/Q-230 items 4, 7 (A-60); tokio 1.54.1 docs.rs:
//! `net::TcpListener::accept`, `net::TcpStream`, `time::timeout`,
//! `io::{AsyncReadExt::read, AsyncWriteExt::write_all}`.

use crate::daemon::{InFlight, Shared};
use crate::log::{note, Note, Thinned};
use crate::queues::{queue_of, Answer, Work};
use core::net::IpAddr;
use core::time::Duration;
use kdc::{
    tcp_decode_frame, tcp_encode_frame, KdcReply, Peer, TcpFrame, Transport, MAX_REQUEST_LEN,
    TCP_LENGTH_PREFIX_LEN,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout};

/// Octets read per read call at most. Project choice.
const READ_CHUNK: usize = 4096;

/// The most octets a connection's buffer holds: one length prefix and one
/// request of the KDC's bound (crates/kdc transport.rs: "At most
/// `TCP_LENGTH_PREFIX_LEN + MAX_REQUEST_LEN` octets are ever needed").
const BUFFER_BOUND: usize = TCP_LENGTH_PREFIX_LEN + MAX_REQUEST_LEN;

/// Pause after a failed `accept` (for example, the open-files limit) so the
/// loop does not spin. Project choice.
const ACCEPT_RETRY: Duration = Duration::from_millis(50);

static LIMITED: Thinned = Thinned::new(Note::TcpLimited);
static QUEUE_FULL: Thinned = Thinned::new(Note::QueueFull);

/// The TCP limits (crates/config `KdcLimits`).
/// Spec: docs/50 §4.1; docs/questions/Q-230 item 4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpLimits {
    /// Open connections, all sources.
    pub max_connections: u32,
    /// Open connections per source address.
    pub max_per_source: u32,
    /// The first frame of a connection, from the accept.
    pub first_frame_timeout: Duration,
    /// A started frame, from its first octet; also the reply write.
    pub frame_timeout: Duration,
    /// Between a reply and the next frame's first octet.
    pub idle_timeout: Duration,
    /// Replies per connection before it is closed.
    pub max_requests: u32,
}

#[derive(Debug, Default)]
struct Open {
    total: u32,
    per_source: HashMap<IpAddr, u32>,
}

/// The connection counters.
/// Spec: docs/50 §4.1; RFC 4120 §7.2.2.
#[derive(Debug)]
pub(crate) struct TcpContext {
    limits: TcpLimits,
    open: Mutex<Open>,
}

impl TcpContext {
    pub(crate) fn new(limits: TcpLimits) -> TcpContext {
        TcpContext {
            limits,
            open: Mutex::new(Open::default()),
        }
    }

    /// Take a connection slot for `source`, or `None` at a limit.
    fn acquire(self: &Arc<Self>, source: IpAddr) -> Option<Slot> {
        let mut open = self.open.lock().ok()?;
        if open.total >= self.limits.max_connections {
            return None;
        }
        let count = open.per_source.entry(source).or_insert(0);
        if *count >= self.limits.max_per_source {
            return None;
        }
        *count = count.saturating_add(1);
        open.total = open.total.saturating_add(1);
        Some(Slot {
            context: Arc::clone(self),
            source,
        })
    }
}

/// One held connection slot; given back when the connection ends.
struct Slot {
    context: Arc<TcpContext>,
    source: IpAddr,
}

impl Drop for Slot {
    fn drop(&mut self) {
        if let Ok(mut open) = self.context.open.lock() {
            open.total = open.total.saturating_sub(1);
            if let Some(count) = open.per_source.get_mut(&self.source) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    open.per_source.remove(&self.source);
                }
            }
        }
    }
}

/// Accept connections until the task is aborted (module documentation).
/// Spec: RFC 4120 §7.2.2; docs/50 §4.1.
pub(crate) async fn accept_tcp(
    listener: TcpListener,
    shared: Arc<Shared>,
    context: Arc<TcpContext>,
) {
    loop {
        match listener.accept().await {
            Ok((stream, address)) => {
                let Some(slot) = context.acquire(address.ip()) else {
                    LIMITED.hit();
                    drop(stream);
                    continue;
                };
                let peer = Peer {
                    transport: Transport::Tcp,
                    src_net: shared.zones.scope(address.ip()),
                };
                drop(tokio::spawn(connection(
                    stream,
                    peer,
                    Arc::clone(&shared),
                    context.limits,
                    slot,
                )));
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

/// The time left until `deadline`, or `None` if it passed.
fn left(deadline: Instant) -> Option<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
}

/// Serve one connection (module documentation).
/// Spec: RFC 4120 §7.2.2; docs/50 §4.1.
async fn connection(
    mut stream: TcpStream,
    peer: Peer,
    shared: Arc<Shared>,
    limits: TcpLimits,
    slot: Slot,
) {
    let _slot = slot;
    let accepted = Instant::now();
    let first_deadline = accepted + limits.first_frame_timeout;
    let mut buffer: Vec<u8> = Vec::new();
    let mut chunk = [0u8; READ_CHUNK];
    let mut replies: u32 = 0;
    let mut idle_since = accepted;
    let mut frame_started: Option<Instant> = None;
    loop {
        // 1. A whole record (or a framing error) in the buffer?
        let work = match tcp_decode_frame(&buffer) {
            Err(error) => Some((Work::RejectFrame(error), 0usize)),
            Ok(TcpFrame::Complete { message, rest }) => {
                let consumed = buffer.len().saturating_sub(rest.len());
                Some((Work::Request(message.to_vec()), consumed))
            }
            Ok(TcpFrame::Incomplete) => None,
        };
        if let Some((work, consumed)) = work {
            let close_after = matches!(work, Work::RejectFrame(_));
            buffer.drain(..consumed.min(buffer.len()));
            let Some(answer) = submit(&shared, work, peer).await else {
                return;
            };
            let (message, close) = match answer {
                Answer::Reply(KdcReply::Send(message)) => (Some(message), false),
                Answer::Reply(KdcReply::SendAndClose(message)) => (Some(message), true),
                Answer::Reply(KdcReply::Silent) | Answer::Withheld => (None, true),
            };
            let Some(message) = message else {
                return;
            };
            let Some(framed) = tcp_encode_frame(&message) else {
                return;
            };
            match timeout(limits.frame_timeout, stream.write_all(&framed)).await {
                Ok(Ok(())) => {}
                _ => return,
            }
            replies = replies.saturating_add(1);
            if close || close_after || replies >= limits.max_requests {
                return;
            }
            idle_since = Instant::now();
            frame_started = if buffer.is_empty() {
                None
            } else {
                Some(idle_since)
            };
            continue;
        }
        // 2. Read more, within the deadline that applies now.
        let first = replies == 0;
        let deadline = match frame_started {
            None if first => first_deadline,
            None => idle_since + limits.idle_timeout,
            Some(started) if first => first_deadline.min(started + limits.frame_timeout),
            Some(started) => started + limits.frame_timeout,
        };
        let Some(wait) = left(deadline) else {
            return;
        };
        let room = BUFFER_BOUND.saturating_sub(buffer.len()).min(READ_CHUNK);
        if room == 0 {
            // Cannot happen: the length is bounded before the message is
            // awaited. Fail closed.
            return;
        }
        let Some(target) = chunk.get_mut(..room) else {
            return;
        };
        let read = match timeout(wait, stream.read(target)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return,
            Ok(Ok(read)) => read,
        };
        let Some(received) = target.get(..read) else {
            return;
        };
        if buffer.is_empty() {
            frame_started = Some(Instant::now());
        }
        buffer.extend_from_slice(received);
    }
}

/// Queue one job for the engine and wait for its answer; `None` closes the
/// connection (queue full, engine stopped, draining).
/// Spec: docs/50 §4.1 ("full queue ⇒ TCP close").
async fn submit(shared: &Arc<Shared>, work: Work, peer: Peer) -> Option<Answer> {
    if shared.draining.load(std::sync::atomic::Ordering::SeqCst) {
        return None;
    }
    let queue = match &work {
        Work::Request(body) => queue_of(body),
        Work::RejectFrame(_) => crate::queues::Queue::As,
    };
    let _counted = InFlight::new(shared);
    match shared.queues.submit(queue, work, peer) {
        Ok(answer) => answer.await.ok(),
        Err(crate::queues::SubmitError::Full) => {
            QUEUE_FULL.hit();
            None
        }
        Err(crate::queues::SubmitError::Stopped) => None,
    }
}
