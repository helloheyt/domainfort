#![forbid(unsafe_code)]
//! `ipc-ldap`: the ldap-front ↔ dird channel (`dird-ldap.sock`) — its message
//! set and the front's side of it (docs/50 R50-10, §4.2, §4.3, §10 task P10;
//! docs/49 R49-16; decision A-58).
//!
//! The LDAP engine (the PEP) runs in dird, which owns the directory; the
//! front (task P11) owns TCP, rustls and the framer, re-encodes every client
//! message in parse-ldap's canonical form and hands it to dird over this
//! channel — **one Unix connection to dird per client connection** (R50-10:
//! 1:1, the kernel separates the sessions, no session ids, no multiplexing
//! parser). dird creates one `ldap::Session` per connection and destroys it
//! when the connection ends. The dispatcher that answers from the engine is
//! the separate crate `ipc-ldap-server`, linked only by dird: this crate
//! links no engine, dirstore, redb or directory-pip (checked by
//! `tests/no_engine_dependency.rs`; docs/49 R49-16, docs/25 §3.3).
//!
//! # Layers
//!
//! | layer | module | what it checks |
//! |---|---|---|
//! | channel | [`channel`] | magic, exact version, per-direction / per-field / per-reply bounds, the closed kind and code tables (no kind equals `ipc::REFUSED_KIND`) |
//! | wire | [`wire`] | fixed-order fields through `ipc` (lengths, markers, closed tables, no trailing octet); the response-part rule |
//! | front | [`front`] | [`FrontChannel`]: the session's order, the reply bounds, the reassembly; [`ChannelFailure`] → close with a Notice of Disconnection |
//! | client | [`client`] | [`LdapChannelClient`]: dird-uid check before sending, deadline, one request at a time |
//! | socket | `unix` | [`UnixConnector`]: blocking Unix stream, peer uid via rustix (Linux; elsewhere fail closed) |
//!
//! # Message kinds (magic `0x4C44` "LD", version 1)
//!
//! | dir | kind | message | fields | reply |
//! |---|---|---|---|---|
//! | → dird | `0x01` | `Open` | `listener: Ldap\|Ldaps`, `peer_addr: IPv4\|IPv6` | `0x81` `Opened { framing }` |
//! | → dird | `0x02` | `Message` | `canonical: bytes<1 MiB>`, `tls_established: bool`, `input_pending: bool` | `0x82` `Response { part, more }` × n, then `0x83` `Done { action, framing }` |
//! | → dird | `0x03` | `TlsEstablished` | — | `0x84` `TlsAccepted { framing }` |
//! | → dird | `0x04` | `Close` | — | none |
//! | → dird | `0x05` | `Ping` | — | `0x85` `Pong` |
//! | ← dird | `0xFF` | shared `Refused` (A-59) | `code` | — |
//!
//! `framing` is the authentication state (parse-ldap `AuthState`) whose size
//! bound the front applies to the next message (docs/50 R50-10, §4.2);
//! `action` is `Continue | StartTls | Close`. **No field lets the front claim
//! a bound identity or a channel binding** (A-47; A-54 / Q-190 item 11: "no
//! `channel_binding_verified` flag from the front; only keyd decides"): the
//! front reports only whether TLS protects the message and whether more
//! octets are pending; the client's zone is derived by dird from the peer
//! address through **its own** zone table (docs/50 §4.2); the
//! tls-server-end-point value is computed by dird from the configured
//! certificate (R50-13, L6b — not in phase 1).
//!
//! # Bounds (crate::channel)
//!
//! Request body ≤ 1 MiB + 16 (parse-ldap's post-authentication message
//! bound); reply body ≤ 1 MiB + 16 (one response part); one response ≤ 8 MiB
//! in at most 8 parts (the engine's `MAX_RESPONSE_OCTETS`); one reply ≤ 1,002
//! responses (the engine's 1,000-entry page + SearchResultDone + a notice)
//! and ≤ 8 MiB + 64 KiB. The server crate pins the engine-side numbers at
//! compile time.
//!
//! # Security
//!
//! `#![forbid(unsafe_code)]`; no `unwrap`, `expect` or `panic!` outside
//! tests and const evaluation. Every bound is a named constant; nothing is
//! allocated from a peer-supplied length beyond the bound. No error and no
//! `Debug` output carries frame or message octets (docs/50 §8.2).
//!
//! # Provenance
//!
//! Written only from this project's decided design, opened in-session:
//! AGENT-ONBOARDING, AGENTS, docs/50 (§1 R50-3, R50-4, R50-7, R50-8,
//! R50-10, R50-11, R50-13; §3.1-§3.7; §4.2; §4.3; §7.5; §8.2; §9; §10; the
//! channel-magic registry; decision A-58), docs/49 (R49-6, R49-15, R49-16;
//! §2.4; §4.3; §4.4; §11), docs/questions Q-163 (A-47), Q-190 (A-54), Q-200
//! (A-55), Q-225 (A-59), Q-270 (A-68), Q-275 (A-69), PENDING-OWNER; RFC 4511
//! §4.4, §4.4.1, App. A (pinned, sha256 49c6aab6…06fd, opened this session);
//! the code of this project's crates ipc and parse-ldap (and ipc-directory
//! as the pattern); and the docs.rs API pages of rustix 1.1.6 and zeroize
//! 1.9.1 (P-2). No other implementation, LDAP server, serializer or RPC
//! framework was consulted or recalled (AGENTS.md §1-3).
//!
//! Spec: docs/50 R50-3, R50-4, R50-7, R50-10, §3, §4.2, §4.3, §10 (P10);
//! docs/49 R49-16; A-47; A-54; A-59.

pub mod channel;
pub mod client;
pub mod front;
#[cfg(unix)]
mod unix;
pub mod wire;

pub use channel::{
    ConnectionAction, Listener, LDAP_CHANNEL, LDAP_MAGIC, LDAP_VERSION, MAX_CANONICAL_MESSAGE,
    MAX_REPLY_BODY, MAX_REPLY_OCTETS, MAX_REQUEST_BODY, MAX_RESPONSES, MAX_RESPONSE_MESSAGE,
    MAX_RESPONSE_PART, REPLY_LIMIT, REQUEST_LIMIT, RESULT_RESERVE,
};
pub use client::{
    ping, Connection, Connector, LdapChannelClient, CLOSE_DEADLINE, DEFAULT_DEADLINE,
};
pub use front::{
    notice_of_disconnection, ChannelFailure, Exchange, FrontChannel, Progress, TransportError,
};
#[cfg(unix)]
pub use unix::{UnixConnection, UnixConnector};
pub use wire::{
    split_response, LdapReply, LdapRequest, MessageRequest, ResponsePart, TransportFacts,
};
