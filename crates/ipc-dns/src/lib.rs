#![forbid(unsafe_code)]
//! `ipc-dns`: the dnsd ↔ dird channel (`dird-dns.sock`) — its message set,
//! the zone-image transfer, dird's decoding and reply encoding, and dnsd's
//! synchronous client (docs/54 §4.6, as amended by decision A-140; build task
//! DN7).
//!
//! dnsd is the network front: it answers queries from a typed zone image it
//! pulls from dird by SERIAL, and hands every signed UPDATE (and, with task
//! DN9, every TKEY over TCP) to dird **as opaque octets**, with the transport
//! and the source address it arrived on. dird is the PEP: it decodes the same
//! octets again, has keyd verify the TSIG, decides, writes, and returns the
//! DNS reply (docs/54 §4.1, R54-4, R54-5). dnsd has no key, no store and no
//! keyd mapping; this crate links none of them — no dirstore, redb,
//! directory-pip, directory-admin, keyd, keyd-types, ipc-keyd, krb-crypto,
//! krb-proto or ipc-dns-server (checked by `tests/no_store_dependency.rs`).
//! The dispatcher dird answers with is the separate crate `ipc-dns-server`.
//!
//! # Layers
//!
//! | layer | module | what it checks |
//! |---|---|---|
//! | channel | [`channel`] | magic `0x444E`, exact version 1, per-direction / per-field bounds (pinned to parse-dns and dns-zone), closed kind and code tables (no kind equals `ipc::REFUSED_KIND`) |
//! | values | `values` | SERIAL ≠ 0, the zone, a canonical peer address, a DNS message of 12..=65535 octets (≤ 512 over UDP) |
//! | wire | [`wire`] | fixed-order fields through `ipc` (lengths, markers, closed tables, field domains, no trailing octet) |
//! | image | [`image`] | the image encoding, its chunks, dird's validated [`ImageTransfer`], dnsd's bounded [`ImageAssembly`] (whole images only, built by `ZoneImage::new`) |
//! | server | [`server`] | [`decode_request`] (or how to refuse), [`encode_reply`], [`encode_image_chunks`] |
//! | client | [`client`] | [`DnsClient`]: dird-uid and zone check before sending, deadline, idle check, no resend, strict replies |
//! | socket | `unix` | [`UnixConnector`]: blocking Unix stream, peer uid via rustix (Linux; elsewhere fail closed) |
//!
//! # Wire layout (magic `0x444E` "DN", version 1)
//!
//! Every frame: `length:u32 ‖ magic:u16 ‖ version:u8 ‖ kind:u8 ‖ payload`
//! (docs/50 §3.3).
//!
//! | dir | kind | message | payload | reply |
//! |---|---|---|---|---|
//! | → | `0x01` | `Ping` | — | `Pong` |
//! | → | `0x02` | retired (`DescribeZone`, A-152 — docs/questions/Q-922); refused as an unknown kind | — | — |
//! | → | `0x03` | `FetchZoneImage` | `have: Option<serial:u32>` | `Unchanged`, or `ImageChunk` × 1..=8 |
//! | → | `0x04` | `Forward` | `transport:u8{1 Udp, 2 Tcp} ‖ peer:(u8{4} ‖ [4] \| u8{6} ‖ [16]) ‖ message:bytes<65535>` (12 ≤ len; UDP ⇒ len ≤ 512) | `Forwarded` |
//! | ← | `0x81` | `Pong` | `zone:u8{1 Internal}` | — |
//! | ← | `0x82` | retired (`ZoneDescription`, A-152 — docs/questions/Q-922); refused as an unknown kind | — | — |
//! | ← | `0x83` | `Unchanged` | `serial:u32 (≠ 0, = have)` | — |
//! | ← | `0x84` | `ImageChunk` | `chunk:bytes<1 MiB> (≥ 1; = 1 MiB when more) ‖ more:bool` | — |
//! | ← | `0x85` | `Forwarded` | `reply:Option<bytes<65535>> (12 ≤ len) ‖ serial:u32 (≠ 0)` | — |
//! | ← | `0xFF` | shared `Refused` (A-59) | `code` | — |
//!
//! Request body ≤ 64 KiB + 32; reply body ≤ 1 MiB + 16; an image ≤ 8 MiB
//! ([`channel`]). The image encoding is in [`image`].
//!
//! `DescribeZone` (`0x02`) and its reply `ZoneDescription` (`0x82`) are
//! retired by A-152 (docs/questions/Q-922): `FetchZoneImage { have }`
//! already answers them — `have: None` returns the whole image, apex and
//! SERIAL first; `have: Some(s)` → `Unchanged { s }` is the periodic SERIAL
//! check — so dnsd starts with `Ping` + `FetchZoneImage { have: None }`. The
//! other kinds keep their numbers; the retired ones are never reused.
//!
//! # What A-140 changed, and what the channel carries for it
//!
//! A-140 (docs/research/r3-c-dns.md §4.1 (d), R3C-1, R3C-5) accepts a signed
//! UPDATE over UDP **only** on a GSS context that a TKEY over TCP
//! established, and only from the same IP address; any other source ⇒
//! silence; a UDP reply ≤ the request; an unsigned UDP UPDATE ⇒ REFUSED; TKEY
//! only over TCP. So `Forward` carries exactly the two facts dird needs to
//! enforce that, beyond the message: the **transport** and the **source
//! address** ([`PeerAddress`], canonical, no port) — dird's context table is
//! keyed by `(TKEY peer, key_name)`, so the binding *is* the lookup key; and
//! `Forwarded.reply` is optional, `None` meaning silence (UDP) or a close
//! without a reply (TCP). The unsigned-UDP REFUSED and the k = 1 size rule
//! stay in dns-zone's single construction places (A-124 / R3C-10, task DR2) —
//! the channel carries no second copy of either rule (docs/questions/Q-920).
//!
//! # Security
//!
//! `#![forbid(unsafe_code)]`; no `unwrap`, `expect` or `panic!` outside
//! tests and const evaluation. Every bound is a named constant; nothing is
//! allocated from a peer-supplied length beyond its bound or the octets
//! present. No error and no `Debug` output carries message octets, image
//! octets, TSIGs or GSS tokens (docs/54 §9; docs/50 §8.2).
//!
//! # Provenance
//!
//! Written only from this project's decided design and the allowed
//! specifications, opened in-session: AGENT-ONBOARDING, AGENTS; docs/54 (all,
//! esp. §4.1–§4.8, §6.1, §6.2, §6.6, §7.5, §8, §9, §10 — DN7, §11 — Q-613,
//! Q-619); docs/research/r3-c-dns.md (all; §4.1, §4.4, §5, §6 W1, W21, §9 —
//! DR4); docs/57; docs/50 (§3.1–§3.7, §7.5, the channel-magic registry);
//! docs/questions PENDING-OWNER (A-119, A-122, A-124, A-140), Q-613, Q-619,
//! Q-810, Q-815; RFC 1035 §2.3.4, §3.1, §3.4.1, §4.2–§4.2.2; RFC 2136 §2.1,
//! §3.5–§3.8, §6, §7.8, §7.11; RFC 3645 §2, §4, §4.1.1; RFC 8945 §4.3.2,
//! §5.2, §5.2.1, §5.4, §5.5, §10 (pinned copies in tools/spec-pin/cache,
//! SHA-256 verified against tools/spec-pin/manifest.json this session); the
//! public API of this project's crates ipc, parse-dns and dns-zone (and
//! ipc-dird-admin, ipc-ldap, ipc-ldap-server, ipc-keyd, ipc-audit as the
//! pattern); and the docs.rs API pages of rustix 1.1.6 and zeroize 1.9.1
//! (P-2) and the std 1.95.0 API documentation (`IpAddr::to_canonical`). No
//! other implementation, DNS server, serializer or RPC framework was
//! consulted or recalled (AGENTS.md §1-3).
//!
//! Spec: docs/54 §4.4, §4.6, R54-4, R54-5; A-119; A-140; A-152 (Q-922);
//! docs/50 R50-3, R50-4, R50-7, §3; A-59.

pub mod channel;
pub mod client;
pub mod image;
pub mod server;
#[cfg(unix)]
mod unix;
mod values;
pub mod wire;

pub use channel::{
    DEFAULT_DEADLINE, DNS_CHANNEL, DNS_MAGIC, DNS_VERSION, MAX_DNSD_CONNECTIONS, MAX_IMAGE_CHUNK,
    MAX_IMAGE_CHUNKS, MAX_IMAGE_OCTETS, MAX_MESSAGE, MAX_REPLY_BODY, MAX_REQUEST_BODY,
    MAX_UDP_MESSAGE, MIN_MESSAGE, REPLY_LIMIT, REQUEST_LIMIT,
};
pub use client::{
    ClientConfigError, Connection, Connector, DnsClient, ExpectedDird, ImageFetch, TransportError,
    Unserved,
};
pub use image::{
    decode_image, encode_image, split_image, ImageAssembly, ImageChunk, ImageError, ImageTransfer,
};
pub use server::{decode_request, encode_image_chunks, encode_refusal, encode_reply, Rejection};
#[cfg(unix)]
pub use unix::{UnixConnection, UnixConnector};
pub use values::{DnsMessage, ForwardRequest, Forwarded, FrontZone, PeerAddress, Serial};
pub use wire::{DnsReply, DnsRequest};

// The types of the crates this channel's API speaks in, so that dnsd and
// dird name them through one path.
pub use dns_zone::{
    HostRecordParts, KpasswdService, SoaParameters, ZoneImage, ZoneImageError, ZoneImageParts,
};
pub use parse_dns::{Name, Transport};
