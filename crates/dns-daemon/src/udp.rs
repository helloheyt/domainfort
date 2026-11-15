//! The UDP listener (RFC 1035 §4.2.1): one task per configured address.
//!
//! Per datagram, in order:
//!
//! 1. received into a buffer of 512 + 1 octets — "Messages carried by UDP
//!    are restricted to 512 bytes" (RFC 1035 §4.2.1, §2.3.4); tokio
//!    `recv_from` "If a message is too long to fit in the supplied buffer,
//!    excess bytes may be discarded", so a longer datagram arrives longer
//!    than 512 and dns-zone silences it (docs/54 §3.3: "inbound datagram
//!    > 512 ⇒ silence");
//! 2. a source outside `internal_networks` ⇒ dropped, no reply, counted
//!    (A-114; docs/54 §4.7: "UDP: dropped without a reply");
//! 3. the per-source (IPv4 address / IPv6 /64) and global limit — the shared
//!    `SourceLimiter` (A-154 item 6 (a)) ⇒ over: dropped, counted (docs/54
//!    §6.7: "excess ⇒ silence, counted");
//! 4. dns-zone's verdict from the current image (crate::daemon `Shared::
//!    verdict`) — a [`dns_zone::Reply`] is sent to the source address and
//!    port it came from (RFC 2136 §3.8: "the response will be sent to the
//!    requestor's source UDP port"); its octets were built and size-bounded
//!    by dns-zone for UDP (≤ 512, ≤ k × the request, an error ≤ the request
//!    — A-124), and only a reply built for UDP leaves on UDP; silence sends
//!    nothing (counted).
//!
//! A forward verdict is not produced for UDP by dns-zone today (an UPDATE
//! over UDP ⇒ REFUSED — dns-zone row 7, docs/questions/Q-671). A-140 accepts
//! a signed UPDATE over UDP on a TKEY-established context (task DR2, not
//! built); its reply rule (≤ the request) belongs in dns-zone's reply
//! constructor for forwarded replies (`Reply::from_forwarded`, R3C-10), not
//! here. Until both exist a forward verdict on UDP is answered with silence
//! — fail closed, no second copy of the rule (docs/52 C14; docs/questions/
//! Q-952 item 1).
//!
//! Spec: RFC 1035 §2.3.4, §4.2.1; RFC 2136 §3.8; docs/54 §3.3, §4.7, §6.5,
//! §6.7; A-114; A-124; A-154; tokio 1.54.1 docs.rs: `net::UdpSocket::
//! {recv_from, send_to}` (an `Arc<UdpSocket>` is not needed: one task owns
//! each socket).

use crate::daemon::Shared;
use crate::limits::{RETRY_PAUSE, UDP_RECEIVE_BUFFER};
use crate::log::{FORWARD_ON_UDP, RECEIVE_FAILED, SILENCED, SOURCE_NOT_INTERNAL, UDP_LIMITED};
use crate::source::source_key;
use core::net::IpAddr;
use dns_zone::{Reply, Transport, Verdict};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::UdpSocket;
use tokio::time::sleep;

/// Serve one UDP socket until the task is aborted (module documentation).
/// Spec: RFC 1035 §4.2.1; docs/54 §3.3, §4.7, §6.7.
pub(crate) async fn serve_udp(socket: UdpSocket, shared: Arc<Shared>) {
    let mut buffer = vec![0u8; UDP_RECEIVE_BUFFER];
    loop {
        let (length, source) = match socket.recv_from(&mut buffer).await {
            Ok(received) => received,
            Err(_) => {
                RECEIVE_FAILED.hit();
                sleep(RETRY_PAUSE).await;
                continue;
            }
        };
        let Some(datagram) = buffer.get(..length) else {
            continue;
        };
        if let Some(reply) = handle(&shared, source.ip(), datagram, Instant::now()) {
            let _ = socket.send_to(reply.as_bytes(), source).await;
        }
    }
}

/// What to send for one `datagram` from `source` received at `now` — steps
/// 2–4 of the module documentation — or `None`: nothing. Only a reply built
/// for UDP is returned.
/// Spec: docs/54 §3.3, §4.7, §6.5, §6.7; A-114; A-124; A-154 item 6 (a).
pub(crate) fn handle(
    shared: &Shared,
    source: IpAddr,
    datagram: &[u8],
    now: Instant,
) -> Option<Reply> {
    if shared.draining.load(Ordering::SeqCst) {
        return None;
    }
    // 2. Internal sources only (A-114).
    if !shared.serves(source) {
        SOURCE_NOT_INTERNAL.hit();
        return None;
    }
    // 3. Per-source and global limit (A-154 item 6 (a)).
    if !shared.udp_limiter.admit(source_key(source), now) {
        UDP_LIMITED.hit();
        return None;
    }
    // 4. dns-zone's verdict.
    match shared.verdict(datagram, Transport::Udp) {
        Verdict::Reply(reply) if reply.transport() == Transport::Udp => Some(reply),
        // A reply built for another transport never leaves on UDP (cannot
        // happen: dns-zone builds for the transport it is given). Fail
        // closed.
        Verdict::Reply(_) | Verdict::Silence(_) | Verdict::Close => {
            SILENCED.hit();
            None
        }
        Verdict::Forward(_) => {
            FORWARD_ON_UDP.hit();
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::tests::{example_query, shared_for_test};
    use core::net::Ipv4Addr;

    /// docs/54 §4.7 (A-114): the same well-formed query is answered for a
    /// source inside `internal_networks` and dropped — nothing sent — for one
    /// outside (and for an IPv4-mapped IPv6 spelling of an inside address,
    /// Q-275 item 9); A-154 item 6 (a): past the per-source share, nothing;
    /// draining, nothing. RFC 2782 example zone; hand-made addresses.
    #[test]
    fn only_internal_sources_within_their_share_are_answered() {
        let shared = shared_for_test(2);
        let query = example_query(0x0101);
        let inside = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));
        let outside = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
        let mapped = IpAddr::V6(Ipv4Addr::new(192, 0, 2, 7).to_ipv6_mapped());
        let now = Instant::now();
        assert!(handle(&shared, outside, &query, now).is_none());
        assert!(handle(&shared, mapped, &query, now).is_none());
        let reply = handle(&shared, inside, &query, now).expect("answered");
        assert_eq!(reply.transport(), Transport::Udp);
        assert!(handle(&shared, inside, &query, now).is_some());
        assert!(handle(&shared, inside, &query, now).is_none(), "share used");
        shared.draining.store(true, Ordering::SeqCst);
        let other = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 8));
        assert!(handle(&shared, other, &query, now).is_none(), "draining");
    }
}
