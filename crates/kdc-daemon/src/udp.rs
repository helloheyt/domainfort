//! The UDP listener (RFC 4120 §7.2.1): one task per configured address.
//!
//! "the client shall send a UDP datagram containing only an encoding of the
//! request to the KDC. The KDC will respond with a reply datagram containing
//! only an encoding of the reply message … to the sending port at the
//! sender's IP address. The response to a request made through UDP/IP
//! transport MUST also use UDP/IP transport." So, per datagram:
//!
//! 1. receive into a buffer of `MAX_REQUEST_LEN + 1` octets (tokio
//!    `recv_from`: "If a message is too long to fit in the supplied buffer,
//!    excess bytes may be discarded" — a datagram over the KDC's bound still
//!    arrives over the bound, and `Kdc::handle` silences it by its length;
//!    docs/50 §4.1);
//! 2. the per-source and global limits (crate::rate; Q-223 → A-57 option
//!    (a)): over ⇒ dropped, counted;
//! 3. the queue by the first octet (crate::queues); full ⇒ dropped (docs/50
//!    §4.1: "full queue ⇒ UDP silence");
//! 4. the engine's answer is sent from a short task to the source address
//!    (`KdcReply::Send`); `Silent` and a withheld answer send nothing.
//!
//! No amplification beyond the library's UDP rules: an undecodable datagram
//! gets no reply (crates/kdc: "replying to arbitrary bytes would make the
//! KDC a reflector"; RFC 4120 §5.1.4), a reply above the UDP limit is
//! replaced by KRB_ERR_RESPONSE_TOO_BIG (§7.2.1), an unavailable dependency
//! is silence (A-56) — and the rate limits above (Q-223 option (a); option
//! (b), a size-ratio rule, is left for the lab).
//!
//! Spec: RFC 4120 §7.2.1, §5.1.4; docs/50 R50-9, §4.1; docs/questions/Q-223
//! (A-57); tokio 1.54.1 docs.rs: `net::UdpSocket::{recv_from, send_to}`
//! ("you do not need a `Mutex` to share the `UdpSocket` — an `Arc<UdpSocket>`
//! is enough").

use crate::daemon::{InFlight, Shared};
use crate::log::{note, Note, Thinned};
use crate::queues::{queue_of, Answer, Work};
use crate::rate::SourceLimiter;
use core::time::Duration;
use kdc::{KdcReply, Peer, Transport, MAX_REQUEST_LEN};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::UdpSocket;
use tokio::time::sleep;

/// Pause after a failed receive so the loop does not spin. Project choice.
const RECEIVE_RETRY: Duration = Duration::from_millis(50);

static LIMITED: Thinned = Thinned::new(Note::UdpLimited);
static QUEUE_FULL: Thinned = Thinned::new(Note::QueueFull);

/// Serve one UDP socket until the task is aborted (module documentation).
/// Spec: RFC 4120 §7.2.1; docs/50 §4.1.
pub(crate) async fn serve_udp(
    socket: Arc<UdpSocket>,
    shared: Arc<Shared>,
    limiter: Arc<SourceLimiter>,
) {
    let mut buffer = vec![0u8; MAX_REQUEST_LEN + 1];
    loop {
        let (length, source) = match socket.recv_from(&mut buffer).await {
            Ok(received) => received,
            Err(error) => {
                note(
                    Note::ReceiveFailed,
                    error.raw_os_error().and_then(|e| u64::try_from(e).ok()),
                );
                sleep(RECEIVE_RETRY).await;
                continue;
            }
        };
        if shared.draining.load(Ordering::SeqCst) {
            continue;
        }
        if !limiter.admit(source.ip(), Instant::now()) {
            LIMITED.hit();
            continue;
        }
        let Some(datagram) = buffer.get(..length) else {
            continue;
        };
        let body = datagram.to_vec();
        let queue = queue_of(&body);
        let peer = Peer {
            transport: Transport::Udp,
            src_net: shared.zones.scope(source.ip()),
        };
        let counted = InFlight::new(&shared);
        match shared.queues.submit(queue, Work::Request(body), peer) {
            Ok(answer) => {
                let socket = Arc::clone(&socket);
                drop(tokio::spawn(async move {
                    let _counted = counted;
                    if let Ok(Answer::Reply(
                        KdcReply::Send(message) | KdcReply::SendAndClose(message),
                    )) = answer.await
                    {
                        let _ = socket.send_to(&message, source).await;
                    }
                }));
            }
            Err(_) => {
                drop(counted);
                QUEUE_FULL.hit();
            }
        }
    }
}
