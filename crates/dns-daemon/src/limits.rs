//! dnsd's constants: the rate limits, the forwarding queue, the refresh
//! interval and the bounds of its buffers — each with its source.
//!
//! docs/54 §6.7 names these limits "project choices ⚠"; docs/50's precedent
//! (Q-230 item 4 → A-60) keeps rate limits and queue sizes as constants of
//! the daemon, not configuration keys. The TCP connection bounds and the
//! staleness bound are configuration keys (crates/config `DnsdSettings`).
//! Every value and its reasoning is recorded in docs/questions/Q-951.
//!
//! Spec: docs/54 §4.4, §4.6, §6.7; docs/questions/Q-616 item 10, Q-920 item
//! 9, Q-930 items 6, 7 (A-154), Q-951.

use core::time::Duration;
use rate_limit::SourceLimits;

/// UDP datagrams admitted per source per window. Project choice: a stub
/// resolver sends a handful of queries per name (A, AAAA, search-domain
/// expansions), and a Windows client sends **every** query to the DC (also
/// the names outside the zone, which dnsd refuses — docs/research/r3-c-dns.md
/// O-9), so dnsd's per-source budget is above the kdc's 32 (the kdc's own
/// number, kept in kdc-daemon — A-154 item 3). Keyed by the IPv4 address /
/// IPv6 /64 (A-154 item 6 (a); crate::source).
/// Spec: docs/54 §6.7; docs/questions/Q-616 item 10, Q-951 item 1.
pub const UDP_PER_SOURCE_PER_WINDOW: u32 = 64;

/// UDP datagrams admitted per window from all sources together — the global
/// reply budget (docs/54 §6.7: "a global reply budget"): every reply answers
/// one admitted datagram, so with the size rule (≤ 512 octets, ≤ 4 × the
/// request — dns-zone, A-124) dnsd sends at most 4096 × 512 octets (2 MiB)
/// per window. Project choice.
/// Spec: docs/54 §6.5, §6.7; docs/questions/Q-951 item 1.
pub const UDP_GLOBAL_PER_WINDOW: u32 = 4096;

/// The UDP window. A fixed window admits up to twice the per-window number
/// across a window edge (docs/questions/Q-930 item 7). Project choice.
pub const UDP_WINDOW: Duration = Duration::from_secs(1);

/// dnsd's UDP limits: one [`rate_limit::SourceLimiter`] shared by every UDP
/// socket. Spec: docs/54 §6.7; A-154 item 6 (a).
pub const UDP_LIMITS: SourceLimits = SourceLimits {
    per_source: UDP_PER_SOURCE_PER_WINDOW,
    global: UDP_GLOBAL_PER_WINDOW,
    window: UDP_WINDOW,
};

/// dnsd's limits on TCP messages — the same numbers as UDP, in a separate
/// limiter: R54-10 asks for per-source and global rate limits "on UDP and on
/// TCP", and a separate limiter keeps a forged-source UDP flood (which can
/// spend a victim's UDP budget) from also closing the victim's TCP
/// fallback, whose source the handshake proved (docs/54 §3.3 (b)).
/// Spec: docs/54 §6.6, §6.7 (R54-10); docs/questions/Q-951 item 2.
pub const TCP_MESSAGE_LIMITS: SourceLimits = UDP_LIMITS;

/// Signed UPDATE messages forwarded to dird per source per window: 2.
/// docs/54 §6.7: "UPDATE ≤ 2/s per source". With the fixed window of the
/// shared limiter (A-154 item 6 (a) — no token bucket), at most 4 can pass
/// back to back across a window edge; the window is kept at 1 s rather than
/// widened (e.g. 10 per 5 s) so that edge burst stays this small — the
/// conservative reading A-154 item 7 asks DN11 to choose.
/// Spec: docs/54 §6.7; docs/questions/Q-930 item 7 (A-154), Q-951 item 3.
pub const FORWARD_PER_SOURCE_PER_WINDOW: u32 = 2;

/// Signed UPDATE messages forwarded per window from all sources together:
/// 32, the forwarding queue's capacity — a flood from many internal sources
/// reaches neither dird nor keyd faster than one queue's worth per second
/// (docs/54 §6.7: "a flood does not reach dird and keyd").
/// Spec: docs/54 §6.7; docs/questions/Q-951 item 3.
pub const FORWARD_GLOBAL_PER_WINDOW: u32 = 32;

/// The forwarding window. Spec: as [`FORWARD_PER_SOURCE_PER_WINDOW`].
pub const FORWARD_WINDOW: Duration = Duration::from_secs(1);

/// dnsd's forwarding limits. TKEY has no limit of its own yet: dns-zone does
/// not forward TKEY (task DN9, RFC 2930 — docs/questions/Q-610); when it
/// does, docs/54 §6.7's "TKEY ≤ 1/s per source (burst 5)" gets its own
/// limiter (docs/questions/Q-951 item 3).
/// Spec: docs/54 §6.7.
pub const FORWARD_LIMITS: SourceLimits = SourceLimits {
    per_source: FORWARD_PER_SOURCE_PER_WINDOW,
    global: FORWARD_GLOBAL_PER_WINDOW,
    window: FORWARD_WINDOW,
};

/// Forwarded messages waiting for dird at most; a full queue ⇒ SERVFAIL.
/// Spec: docs/54 §6.7 ("bounded queue (32) ⇒ SERVFAIL"), §6.6 (last row).
pub const FORWARD_QUEUE_CAPACITY: usize = 32;

/// The periodic SERIAL check: every 5 s. Spec: docs/54 §4.4 (b) ("a periodic
/// SERIAL check (for example 5 s ⚠)").
pub const REFRESH_INTERVAL: Duration = Duration::from_secs(5);

/// dnsd's deadline on the dird-dns channel: the channel crate's one value
/// (20 s ⚠, to be pinned against dird's path in DN10 — Q-920 item 9). No
/// second copy (docs/52 §3.14 C14).
pub const DIRD_DEADLINE: Duration = ipc_dns::DEFAULT_DEADLINE;

/// How long the forwarding thread waits for the zone thread to fetch the
/// image named by dird's reply before it relays the reply anyway: one dird
/// deadline (the bound of that fetch). Spec: docs/54 §4.4 (a).
pub const REFRESH_WAIT: Duration = DIRD_DEADLINE;

/// How long a TCP connection waits for its forwarded message's outcome:
/// the forward (≤ one deadline), the image fetch after it (≤ one deadline),
/// and one deadline of queueing; then SERVFAIL. Project choice.
/// Spec: docs/54 §4.6 ("deadline in dnsd"), §6.6 (last row).
pub const FORWARD_ANSWER_TIMEOUT: Duration =
    Duration::from_secs(DIRD_DEADLINE.as_secs().saturating_mul(3));

/// Connections dnsd holds to dird: one for the zone image (refresh), one for
/// forwarded messages — so a slow forward never delays the SERIAL check that
/// keeps the image fresh. Spec: docs/54 §4.4, §4.6 ("≤ 4 connections from
/// dnsd"); docs/questions/Q-951 item 5.
pub const DIRD_CONNECTIONS: usize = 2;

/// The UDP receive buffer: one octet beyond RFC 1035's 512, so a longer
/// datagram arrives longer than 512 and dns-zone silences it (row 1).
/// Spec: RFC 1035 §2.3.4, §4.2.1; docs/54 §3.3, §6.2.
pub const UDP_RECEIVE_BUFFER: usize = dns_zone::limits::MAX_UDP_MESSAGE_OCTETS + 1;

/// Octets read from a TCP stream per read call at most: a message buffer
/// grows with the octets that arrived, never to its declared length first
/// (AGENTS.md §6: no allocation from an attacker-supplied length). Project
/// choice.
pub const TCP_READ_CHUNK: usize = 4096;

/// Open files beyond the TCP connection bound: stdio, the listeners, the two
/// dird connections, the audit check, the runtime's own descriptors, and
/// room for connections accepted only to be closed at a limit. Project
/// choice (the kdc's value, docs/50 §6.1: "nofile according to the
/// connection quotas").
pub const OPEN_FILES_HEADROOM: u64 = 64;

/// Pause after a failed receive or accept so the loop does not spin.
/// Project choice.
pub const RETRY_PAUSE: Duration = Duration::from_millis(50);

// ---- compile-time consistency --------------------------------------------

// The staleness floor of the configuration exceeds one refresh interval
// plus one dird deadline: a slow but answering dird never looks stale
// (crates/config `ZONE_IMAGE_MAX_AGE_SECS`; docs/questions/Q-951 item 4).
const _: () = assert!(
    config::ZONE_IMAGE_MAX_AGE_SECS.min as u64
        > REFRESH_INTERVAL.as_secs() + DIRD_DEADLINE.as_secs()
);
// dnsd stays within the channel's connection bound (docs/54 §4.6).
const _: () = assert!(DIRD_CONNECTIONS <= ipc_dns::MAX_DNSD_CONNECTIONS);
// The forwarding limits never admit more per window than the queue holds.
const _: () = assert!(FORWARD_GLOBAL_PER_WINDOW as usize <= FORWARD_QUEUE_CAPACITY);
const _: () = assert!(FORWARD_QUEUE_CAPACITY >= 1);
// A per-source share is never above the global budget.
const _: () = assert!(UDP_PER_SOURCE_PER_WINDOW <= UDP_GLOBAL_PER_WINDOW);
const _: () = assert!(FORWARD_PER_SOURCE_PER_WINDOW <= FORWARD_GLOBAL_PER_WINDOW);
// The UDP buffer is RFC 1035's bound plus one.
const _: () = assert!(UDP_RECEIVE_BUFFER == 513);
