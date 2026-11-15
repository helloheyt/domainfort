#![forbid(unsafe_code)]
//! `dns-daemon`: dnsd, the DNS network front (docs/54 §4, R54-4; build task
//! DN11; decisions A-119, A-140, A-152, A-154).
//!
//! dnsd answers DNS queries for the one zone of the domain from a typed
//! zone image it fetches from dird and refreshes by SERIAL, and hands every
//! signed UPDATE to dird — the PEP — as opaque octets with the transport and
//! the source address, relaying dird's reply (docs/54 §4.1, option C). It
//! decides nothing about an update and holds **no key, no store and no keyd
//! channel** (docs/54 §4.3, R54-4: "no key, no dirstore, and no access to
//! keyd at all"; it is not mapped in keyd) — `tests/no_store_or_keyd.rs`.
//! Every answer, refusal and size rule is dns-zone's (A-124): dnsd adds the
//! sockets, the limits, the image's freshness and the forwarding, and
//! re-implements none of the answer logic (docs/52 C14).
//!
//! # Process structure (as built)
//!
//! ```text
//!  main (root) ─ config ─ bind UDP+TCP per `listen` ─ hardening ─┐
//!                                                                 ▼
//!  current-thread tokio runtime: serve()
//!   ├─ start: listeners internal? ─ auditd verified (source `dnsd`) ─ zone
//!   │         thread: dird verified + FetchZoneImage{None} ─ forward
//!   │         thread: dird verified ─ only then:
//!   ├─ audit link task: noise counts ⇒ WindowSummary (≤ 1 per heartbeat)
//!   ├─ UDP task per socket ── source internal? ─ UDP limiter ─ dns-zone
//!   │                         verdict ─ Reply (≤ 512, ≤ k × request)
//!   └─ TCP accept task per listener (JoinSet of connections)
//!        connection ── source internal? ─ connection slots ─ 2-octet
//!        framing + deadlines ─ TCP limiter ─ dns-zone verdict ─ Reply |
//!        Forward ─▶ forwarding queue (bounded) ─▶ forward thread ─▶ dird
//!
//!  zone thread (own dird connection): SERIAL check every 5 s, and on the
//!    forward thread's request; the only writer of the image
//!  forward thread (own dird connection): Forward ⇒ Forwarded{reply, serial};
//!    a new SERIAL ⇒ the zone thread fetches before the reply is relayed
//! ```
//!
//! # Fail closed
//!
//! * No image, dird unreachable or an invalid image at start ⇒ no start;
//!   nothing is ever answered before the first image (docs/54 §4.8).
//! * The image not confirmed within `zone_image_max_age` ⇒ SERVFAIL to every
//!   query (dns-zone row 12; docs/54 §4.4).
//! * auditd not verified at start ⇒ no start (docs/50 R50-16): its uid, and
//!   a `Pong` naming dnsd's own source `dnsd` (code 7 — task DN12,
//!   docs/questions/Q-950, Q-960), which auditd gives only to the uid its
//!   `uid_sources` maps to `dnsd`.
//! * A listener or a source outside `internal_networks` ⇒ no start /
//!   dropped (A-114).
//! * A full forwarding queue, a limit, a failed dird call ⇒ SERVFAIL; dird's
//!   `reply: None` ⇒ close (TCP).
//!
//! # Modules
//!
//! | module | what |
//! |---|---|
//! | `daemon` | [`serve`], [`DaemonParams`], [`DaemonControl`], [`DaemonError`], [`Listeners`], [`Stopped`] |
//! | `zone` | the image slot (one writer) and the zone thread |
//! | `forward` | the forwarding queue's thread |
//! | `udp` / `tcp` | the listeners (RFC 1035 §4.2.1 / §4.2.2) |
//! | [`source`] | internal-only, and the per-source key (IPv4 / IPv6 /64) |
//! | [`limits`] | the daemon's constants (docs/questions/Q-951) |
//! | [`audit`] | the start-up check of auditd, and the noise counters as `WindowSummary` (docs/54 §9) |
//! | [`clock`] | the staleness clock |
//! | [`startup`] | configuration, binding, hardening plan |
//! | [`log`] | fixed stderr messages and the noise counters |
//!
//! # Security
//!
//! `#![forbid(unsafe_code)]`; no `unwrap`, `expect` or `panic!` outside
//! tests. Nothing logged carries message octets, names, addresses, TSIGs or
//! any peer-supplied string (docs/54 §9; docs/50 §8.2). Every buffer is
//! bounded (UDP 513 octets; a TCP message grows only with the octets that
//! arrived, at most 65535); every queue is bounded; every wait has a
//! deadline.
//!
//! # Residuals (documented, not hidden)
//!
//! - dnsd's audit is counters only (docs/54 §9): one `WindowSummary` per
//!   audit heartbeat at most (the shared gate's summary pace — Q-989); at a
//!   stop the flush waits, bounded and while auditd is reachable, for the
//!   counts still held; counts it cannot deliver (auditd unreachable, the
//!   grace spent) are lost with the process and stay on the operational log
//!   — docs/questions/Q-961 item 6, Q-989.
//! - No TKEY forwarding and no UDP UPDATE forwarding: dns-zone does not mark
//!   them yet (DN9 / DR2); dird's replies are relayed on TCP without a
//!   dns-zone `Reply::from_forwarded` (DR2) — Q-952.
//! - No seccomp / landlock / namespaces (P-19): a compromised dnsd could
//!   open another socket (docs/54 §12). SIGTERM is not handled (Q-260
//!   item 9). The rate limiters reset when dnsd restarts (docs/54 §8).
//! - The peer check of the dird client uses rustix `socket_peercred`, Linux
//!   only (crates/ipc-dns): elsewhere dnsd's dird connections fail closed;
//!   the tests use an in-process connector to dird's real dispatcher.
//!
//! # Provenance
//!
//! Written only from this project's decided design, opened in-session:
//! docs/CLEAN-ROOM.md, docs/CLEAN-ROOM.md; docs/54 (all — esp. §3.3, §4.1–§4.8, §6.4–§6.7,
//! §8, §9, §10 DN11); docs/research/r3-c-dns.md (§4.1, §5, §6 W17, W21, §9);
//! docs/57; docs/50 (R50-3, R50-14, R50-16, §3.6, §4.1, §6, §7.5, §8.2, §9);
//! docs/07 §1, §8; docs/questions PENDING-OWNER (A-114, A-119, A-122,
//! A-124, A-140, A-149, A-152, A-154), Q-616, Q-619, Q-671, Q-672, Q-920,
//! Q-921, Q-922, Q-930; RFC 1035 §2.3.4, §4.2, §4.2.1, §4.2.2, RFC 2136
//! §2.1, §3.5–§3.8, §6, §7.8, §7.9, RFC 8945 §5.5 (pinned copies in
//! tools/spec-pin/cache, SHA-256 verified against tools/spec-pin/manifest.json
//! this session); the public API of this project's crates dns-zone, ipc-dns,
//! ipc-dns-server, rate-limit, ipc-audit, ipc-audit-client, config,
//! daemon-sandbox and protected-file (kdc-daemon and ldap-front as the
//! pattern); and the docs.rs API pages of tokio 1.54.1 (`net::UdpSocket`,
//! `net::TcpListener`, `net::TcpStream`, `runtime::Builder`, `task::JoinSet`,
//! `sync::{mpsc, oneshot, Notify}`, `time::{timeout, sleep}`,
//! `io::{AsyncReadExt, AsyncWriteExt}`) — API documentation only, never
//! source (P-2). No other implementation, DNS server, daemon or server
//! framework was consulted or recalled (docs/CLEAN-ROOM.md).
//!
//! Spec: docs/54 §4, R54-2, R54-4, R54-10, R54-11, §6.4–§6.7, §10 (DN11);
//! A-119; A-140; A-152; A-154; docs/50 R50-14, R50-16.

pub mod audit;
pub mod clock;
mod daemon;
mod forward;
pub mod limits;
pub mod log;
pub mod source;
pub mod startup;
mod tcp;
mod udp;
mod zone;

pub use daemon::{
    serve, DaemonControl, DaemonError, DaemonParams, DirdEndpoint, Listeners, Stopped,
    ThreadPanicked,
};
pub use tcp::TcpLimits;

/// The test seams (docs/52 C18, task R15): the full parameters and the
/// generic `serve`. Compiled only with the feature `test-seams`, which only
/// dev-dependencies enable; no product source names this module.
#[cfg(feature = "test-seams")]
#[doc(hidden)]
pub mod test_seams;
