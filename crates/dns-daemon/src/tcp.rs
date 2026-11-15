//! The TCP listener (RFC 1035 §4.2.2): one accept task per configured
//! address, one task per connection.
//!
//! "The message is prefixed with a two byte length field which gives the
//! message length, excluding the two byte length field." Connection
//! management (RFC 1035 §4.2.2's recommendations, docs/54 §6.7's numbers):
//!
//! 1. **Admission** — a source outside `internal_networks` is closed at once,
//!    before any octet is read (A-114; docs/54 §4.7: "TCP: closed without a
//!    byte"); then a slot of the global bound and one of the source's bound
//!    (`max_tcp_connections` 512, `max_tcp_connections_per_source` 8; the
//!    source keyed as everywhere — IPv4 address / IPv6 /64, crate::source),
//!    or closed at once ("The server should support multiple connections"
//!    — but bounded, docs/07 §1).
//! 2. **Deadlines** — the connection's first octet within
//!    `tcp_first_octet_timeout` (5 s); a message, once its first length
//!    octet arrived, complete within `tcp_frame_timeout` (5 s); between a
//!    reply and the next message's first octet at most `tcp_idle_timeout`
//!    (120 s — "a period on the order of two minutes"); a reply written
//!    within `tcp_frame_timeout`. Any deadline ⇒ close ("a unilateral close
//!    or reset may be used instead of a graceful close").
//! 3. **Framing, bounded** — the two length octets, then exactly that many
//!    message octets, never reading past the message (the next one waits in
//!    the socket); the buffer grows only with the octets that arrived
//!    (crate::limits::TCP_READ_CHUNK), never to the declared length first
//!    (docs/CLEAN-ROOM.md). The length field bounds a message at 65535 octets by
//!    construction; a message shorter than a header is dns-zone's to refuse
//!    (row 2: close).
//! 4. **One message at a time** — read one, answer it, then read the next:
//!    one request in flight per connection, no pipelining (docs/54 §6.7),
//!    replies in request order.
//! 5. **The message limit** — every message passes the per-source and
//!    global TCP limit (R54-10: limits "on UDP and on TCP"); over ⇒ close.
//! 6. **The verdict** (dns-zone, from the current image): a reply built for
//!    TCP is written with its length prefix; silence writes nothing (the
//!    connection goes on); close closes; a forward goes to dird
//!    (crate::forward) — dird's reply is written, `None` closes without a
//!    reply (docs/54 §4.6), any failure writes dns-zone's SERVFAIL fallback.
//! 7. **Close** after `max_requests_per_tcp_connection` (64) messages.
//!
//! Spec: RFC 1035 §4.2.2; RFC 2136 §2.1, §3.8, §6.2, §6.4; docs/54 §4.5,
//! §4.6, §4.7, §6.6, §6.7; A-114; A-140; docs/07 §1; tokio 1.54.1 docs.rs:
//! `net::TcpListener::accept`, `net::TcpStream`, `task::JoinSet`,
//! `time::timeout`, `io::{AsyncReadExt::read, AsyncWriteExt::write_all}`.

use crate::daemon::Shared;
use crate::forward::{ForwardJob, ForwardOutcome};
use crate::limits::{RETRY_PAUSE, TCP_READ_CHUNK};
use crate::log::{
    ACCEPT_FAILED, FORWARD_LIMITED, FORWARD_QUEUE_FULL, FORWARD_UNAVAILABLE, SILENCED,
    SOURCE_NOT_INTERNAL, TCP_LIMITED, TCP_QUERY_LIMITED,
};
use crate::source::source_key;
use core::net::IpAddr;
use core::time::Duration;
use dns_zone::{Forward, Transport, Verdict};
use ipc_dns::{DnsMessage, ForwardRequest, PeerAddress};
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use tokio::time::{sleep, timeout};

/// The length field of a TCP message. Spec: RFC 1035 §4.2.2.
const LENGTH_OCTETS: usize = 2;

/// The TCP bounds (crates/config `DnsdLimits`).
/// Spec: docs/54 §6.7; RFC 1035 §4.2.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpLimits {
    /// Open connections, all sources.
    pub max_connections: u32,
    /// Open connections per source.
    pub max_per_source: u32,
    /// The first octet of a connection, from the accept.
    pub first_octet_timeout: Duration,
    /// A started message, from its first octet; also the reply write.
    pub frame_timeout: Duration,
    /// Between a reply and the next message's first octet.
    pub idle_timeout: Duration,
    /// Messages per connection before it is closed.
    pub max_requests: u32,
}

#[derive(Debug, Default)]
struct Open {
    total: u32,
    per_source: HashMap<IpAddr, u32>,
}

/// The connection counters.
/// Spec: docs/54 §6.7; RFC 1035 §4.2.2.
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

    /// Take a connection slot for the source keyed `key`, or `None` at a
    /// limit. A poisoned counter refuses (fail closed).
    fn acquire(self: &Arc<Self>, key: IpAddr) -> Option<Slot> {
        let mut open = self.open.lock().ok()?;
        if open.total >= self.limits.max_connections {
            return None;
        }
        let count = open.per_source.entry(key).or_insert(0);
        if *count >= self.limits.max_per_source {
            if *count == 0 {
                open.per_source.remove(&key);
            }
            return None;
        }
        *count = count.saturating_add(1);
        open.total = open.total.saturating_add(1);
        Some(Slot {
            context: Arc::clone(self),
            key,
        })
    }
}

/// One held connection slot; given back when the connection ends.
struct Slot {
    context: Arc<TcpContext>,
    key: IpAddr,
}

impl Drop for Slot {
    fn drop(&mut self) {
        if let Ok(mut open) = self.context.open.lock() {
            open.total = open.total.saturating_sub(1);
            let empty = match open.per_source.get_mut(&self.key) {
                Some(count) => {
                    *count = count.saturating_sub(1);
                    *count == 0
                }
                None => false,
            };
            if empty {
                open.per_source.remove(&self.key);
            }
        }
    }
}

/// Accept connections until the task is aborted; the connections are owned
/// by this task's `JoinSet` and end with it (module documentation).
/// Spec: RFC 1035 §4.2.2; docs/54 §4.7, §6.7.
pub(crate) async fn accept_tcp(
    listener: TcpListener,
    shared: Arc<Shared>,
    context: Arc<TcpContext>,
) {
    let mut connections = JoinSet::new();
    loop {
        while connections.try_join_next().is_some() {}
        match listener.accept().await {
            Ok((stream, peer)) => {
                let Some(slot) = admit(&shared, &context, peer.ip()) else {
                    drop(stream);
                    continue;
                };
                connections.spawn(connection(
                    stream,
                    peer.ip(),
                    Arc::clone(&shared),
                    context.limits,
                    slot,
                ));
            }
            Err(_) => {
                ACCEPT_FAILED.hit();
                sleep(RETRY_PAUSE).await;
            }
        }
    }
}

/// The slots for a connection accepted from `peer`, or `None`: close it
/// without reading a byte — an external source (A-114: "TCP: closed without
/// a byte"; no slot is taken for it), a connection limit, or a stop under
/// way (module documentation, item 1).
/// Spec: docs/54 §4.7, §6.7; A-114.
fn admit(shared: &Shared, context: &Arc<TcpContext>, peer: IpAddr) -> Option<Slot> {
    if shared.draining.load(Ordering::SeqCst) {
        return None;
    }
    // Noise: docs/54 §9 ("dropped", "limited").
    if !shared.serves(peer) {
        shared.noise(&SOURCE_NOT_INTERNAL);
        return None;
    }
    let slot = context.acquire(source_key(peer));
    if slot.is_none() {
        shared.noise(&TCP_LIMITED);
    }
    slot
}

/// The instant `after` past `from`; an unrepresentable instant is `from`
/// itself — a deadline already passed, so the connection closes (fail
/// closed, never a panic).
fn deadline_after(from: Instant, after: Duration) -> Instant {
    from.checked_add(after).unwrap_or(from)
}

/// The time left until `deadline`, or `None` if it passed.
fn left(deadline: Instant) -> Option<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
}

/// Read exactly `into.len()` octets before `deadline`; `None` on a deadline,
/// an error or the peer's close.
async fn read_exact_by(stream: &mut TcpStream, into: &mut [u8], deadline: Instant) -> Option<()> {
    let mut filled = 0usize;
    while filled < into.len() {
        let wait = left(deadline)?;
        let target = into.get_mut(filled..)?;
        match timeout(wait, stream.read(target)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return None,
            Ok(Ok(read)) => filled = filled.saturating_add(read),
        }
    }
    Some(())
}

/// Read one message of `length` octets before `deadline`, the buffer growing
/// only with the octets that arrived (module documentation, item 3).
async fn read_message(stream: &mut TcpStream, length: usize, deadline: Instant) -> Option<Vec<u8>> {
    let mut message = Vec::with_capacity(length.min(TCP_READ_CHUNK));
    let mut chunk = [0u8; TCP_READ_CHUNK];
    while message.len() < length {
        let want = length.saturating_sub(message.len()).min(TCP_READ_CHUNK);
        let target = chunk.get_mut(..want)?;
        read_exact_by(stream, target, deadline).await?;
        message.extend_from_slice(target);
    }
    Some(message)
}

/// Write one message with its two-octet length prefix within `wait`; `None`
/// on a deadline, an error, or a message the length field cannot carry
/// (never: dns-zone and the channel bound every reply at 65535 octets).
/// Spec: RFC 1035 §4.2.2.
async fn write_message(stream: &mut TcpStream, message: &[u8], wait: Duration) -> Option<()> {
    let length = u16::try_from(message.len()).ok()?;
    let mut framed = Vec::with_capacity(LENGTH_OCTETS.saturating_add(message.len()));
    framed.extend_from_slice(&length.to_be_bytes());
    framed.extend_from_slice(message);
    match timeout(wait, stream.write_all(&framed)).await {
        Ok(Ok(())) => Some(()),
        _ => None,
    }
}

/// What a connection does after one message.
enum Next {
    /// Read the next message.
    Continue,
    /// Close the connection.
    Close,
}

/// Serve one connection (module documentation).
/// Spec: RFC 1035 §4.2.2; docs/54 §6.7.
async fn connection(
    mut stream: TcpStream,
    peer: IpAddr,
    shared: Arc<Shared>,
    limits: TcpLimits,
    slot: Slot,
) {
    let _slot = slot;
    let key = source_key(peer);
    let accepted = Instant::now();
    let mut served: u32 = 0;
    let mut idle_since = accepted;
    loop {
        // The first length octet: within the first-octet bound for the
        // first message, the idle bound after a reply.
        let first_deadline = if served == 0 {
            deadline_after(accepted, limits.first_octet_timeout)
        } else {
            deadline_after(idle_since, limits.idle_timeout)
        };
        let mut length = [0u8; LENGTH_OCTETS];
        let Some(first) = length.get_mut(..1) else {
            return;
        };
        if read_exact_by(&mut stream, first, first_deadline)
            .await
            .is_none()
        {
            return;
        }
        // The rest of the message: within the frame bound.
        let frame_deadline = deadline_after(Instant::now(), limits.frame_timeout);
        let Some(second) = length.get_mut(1..) else {
            return;
        };
        if read_exact_by(&mut stream, second, frame_deadline)
            .await
            .is_none()
        {
            return;
        }
        let declared = usize::from(u16::from_be_bytes(length));
        let Some(message) = read_message(&mut stream, declared, frame_deadline).await else {
            return;
        };
        if shared.draining.load(Ordering::SeqCst) {
            return;
        }
        // The per-source and global message limit (R54-10). Noise: docs/54
        // §9 ("limited").
        if !shared.tcp_limiter.admit(key, Instant::now()) {
            shared.noise(&TCP_QUERY_LIMITED);
            return;
        }
        let next = answer(&mut stream, &message, peer, &shared, limits.frame_timeout).await;
        served = served.saturating_add(1);
        if matches!(next, Next::Close) || served >= limits.max_requests {
            return;
        }
        idle_since = Instant::now();
    }
}

/// Answer one message (module documentation, item 6).
/// Spec: docs/54 §4.6, §6.6; RFC 2136 §3.8.
async fn answer(
    stream: &mut TcpStream,
    message: &[u8],
    peer: IpAddr,
    shared: &Arc<Shared>,
    write_timeout: Duration,
) -> Next {
    let reply = match shared.verdict(message, Transport::Tcp) {
        Verdict::Reply(reply) if reply.transport() == Transport::Tcp => reply.into_bytes(),
        // Never: dns-zone builds for the transport it is given. Fail closed.
        Verdict::Reply(_) | Verdict::Close => return Next::Close,
        // Noise: docs/54 §9 ("malformed").
        Verdict::Silence(_) => {
            shared.noise(&SILENCED);
            return Next::Continue;
        }
        Verdict::Forward(forward) => match relay(&forward, peer, shared).await {
            Relayed::Reply(octets) => octets,
            Relayed::Nothing => return Next::Close,
        },
    };
    match write_message(stream, &reply, write_timeout).await {
        Some(()) => Next::Continue,
        None => Next::Close,
    }
}

/// What a forward produced for the client.
enum Relayed {
    /// Write these octets (dird's reply, or dns-zone's SERVFAIL fallback).
    Reply(Vec<u8>),
    /// dird answered `None`: close without a reply.
    Nothing,
}

/// Forward one signed UPDATE received over TCP from `peer` and return what
/// to write (crate::forward).
///
/// dird's reply is relayed as dird built it, bounded by the channel at
/// 12 ..= 65535 octets (crates/ipc-dns `DnsMessage`) — the only bound a TCP
/// reply has (RFC 1035 §4.2.2). It is not a dns-zone `Reply`: dns-zone's
/// constructor for forwarded replies (`Reply::from_forwarded`, R3C-10) is
/// task DR2; when it exists, the octets pass through it (docs/questions/
/// Q-952 item 2).
///
/// Spec: docs/54 §4.5, §4.6, §6.6, §6.7; A-140; RFC 2136 §6.2 ("If the
/// original requestor used TCP … the forwarder must use TCP"), §6.4; RFC
/// 8945 §5.5.
async fn relay(forward: &Forward<'_>, peer: IpAddr, shared: &Arc<Shared>) -> Relayed {
    let fallback = || Relayed::Reply(forward.unavailable_reply().as_bytes().to_vec());
    if !shared
        .forward_limiter
        .admit(source_key(peer), Instant::now())
    {
        // Noise: docs/54 §9 ("limited").
        shared.noise(&FORWARD_LIMITED);
        return fallback();
    }
    let Some(request) = DnsMessage::new(forward.message())
        .and_then(|message| ForwardRequest::new(Transport::Tcp, PeerAddress::new(peer), message))
    else {
        return fallback();
    };
    let (answer, outcome) = oneshot::channel();
    if shared
        .forwards
        .try_send(ForwardJob { request, answer })
        .is_err()
    {
        // Noise: docs/54 §9 ("refused" — refused for a full queue;
        // docs/questions/Q-961).
        shared.noise(&FORWARD_QUEUE_FULL);
        return fallback();
    }
    match timeout(shared.forward_answer_timeout, outcome).await {
        Ok(Ok(ForwardOutcome::Relay(Some(reply)))) => Relayed::Reply(reply.as_bytes().to_vec()),
        Ok(Ok(ForwardOutcome::Relay(None))) => Relayed::Nothing,
        Ok(Ok(ForwardOutcome::Unavailable)) => fallback(),
        Ok(Err(_)) | Err(_) => {
            FORWARD_UNAVAILABLE.hit();
            fallback()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::tests::shared_for_test;
    use core::net::{Ipv4Addr, Ipv6Addr};

    fn limits(max_connections: u32, max_per_source: u32) -> TcpLimits {
        TcpLimits {
            max_connections,
            max_per_source,
            first_octet_timeout: Duration::from_secs(5),
            frame_timeout: Duration::from_secs(5),
            idle_timeout: Duration::from_secs(120),
            max_requests: 64,
        }
    }

    /// docs/54 §4.7 (A-114): a connection from outside `internal_networks`
    /// gets no slot (closed without a byte); docs/54 §6.7: the per-source
    /// bound counts an IPv6 /64 as one source, the global bound counts all,
    /// and a slot is given back when its connection ends; a stop under way
    /// admits nothing. Hand-made addresses.
    #[test]
    fn admission_is_internal_and_bounded() {
        let shared = shared_for_test(100);
        let context = Arc::new(TcpContext::new(limits(3, 2)));
        let inside = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));
        let outside = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
        assert!(admit(&shared, &context, outside).is_none());
        let first = admit(&shared, &context, inside).expect("first");
        let second = admit(&shared, &context, inside).expect("second");
        assert!(admit(&shared, &context, inside).is_none(), "per source");
        drop(first);
        let third = admit(&shared, &context, inside).expect("slot given back");
        let other = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 8));
        let fourth = admit(&shared, &context, other).expect("another source");
        let more = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9));
        assert!(admit(&shared, &context, more).is_none(), "global bound");
        drop((second, third, fourth));

        let context = Arc::new(TcpContext::new(limits(8, 1)));
        let a = IpAddr::V6(Ipv6Addr::new(0xfd00, 0x1234, 0, 7, 1, 2, 3, 4));
        let b = IpAddr::V6(Ipv6Addr::new(0xfd00, 0x1234, 0, 7, 5, 6, 7, 8));
        let held = admit(&shared, &context, a).expect("first of the /64");
        assert!(admit(&shared, &context, b).is_none(), "same /64");
        drop(held);
        assert!(admit(&shared, &context, b).is_some(), "given back");

        shared.draining.store(true, Ordering::SeqCst);
        assert!(admit(&shared, &context, inside).is_none(), "draining");
    }
}
