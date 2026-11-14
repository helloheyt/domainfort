#![forbid(unsafe_code)]
//! `ipc-directory`: the directory-view channel (`dird-kdc.sock`) — its
//! message set, the typed requests and records, and the kdc's side of it: a
//! synchronous client whose per-request [`RemoteView`], pinned in dird to one
//! dirstore snapshot and one policy version, implements `kdc::AccountSource`
//! and the `pdp::Pip` subset the KDC needs (docs/50 R50-2, §3, §10 task P8;
//! decision A-58).
//!
//! dird is the only process that opens the redb file and holds the
//! `IntegrityKey` (R50-2; Q-213 → A-57); the kdc asks it over this channel.
//! The dispatcher that answers from a real `directory_pip::DirectoryView` is
//! the separate crate `ipc-directory-server`, linked only by dird: this
//! crate links no dirstore, redb or directory-pip (checked by
//! `tests/no_store_dependency.rs`).
//!
//! # Layers
//!
//! | layer | module | what it checks |
//! |---|---|---|
//! | channel | [`channel`] | magic, exact version, per-direction and per-field bounds, the closed kind and code tables (no kind equals `ipc::REFUSED_KIND`) |
//! | wire | [`wire`] | fixed-order fields through `ipc` (lengths, markers, closed tables, no trailing octet); Kerberos values and SIDs opaque |
//! | typed | [`typed`] | `PrincipalName` through krb-proto's DER, realms / salts as KerberosStrings, times through `KerberosTime::new`, SIDs through dtyp; group sets strictly ascending |
//! | client | [`client`] | [`DirectoryClient`], [`RemoteView`], [`UnavailableDirectory`]: dird-uid check before sending, deadline, policy-version check, strict replies, not served → `Unavailable`; a held connection checked before reuse (no default), no resend (Q-312); built only by `DirectoryClient::connect`, which pins dird's domain — then `DescribeDomain` required of every new connection (Q-311, task R9) |
//! | socket | `unix` | [`UnixConnector`]: blocking Unix stream, peer uid via rustix (Linux; elsewhere fail closed), non-blocking idle check |
//!
//! # Message kinds (magic `0x4452` "DR", version 1)
//!
//! | request kind | message | fields | success reply | failure reply |
//! |---|---|---|---|---|
//! | `0x01` | `BeginView` | — | `0x81` `ViewBegun { view: u64, policy_version: u64 }` | `0xF3` `ViewFailure` |
//! | `0x02` | `Client` | `view`, `realm`, `name: DER` | `0x82` `Option<ClientAccount>` | `0xF1` `AccountFailure`, `0xF3` |
//! | `0x03` | `Service` | `view`, `realm`, `name: DER` | `0x83` `Option<ServiceAccount>` | `0xF1`, `0xF3` |
//! | `0x04` | `ExpandGroups` | `view`, `sid` | `0x84` `seq<Sid>` | `0xF2` `PipFailure`, `0xF3` |
//! | `0x05` | `TierOf` | `view`, `sid`, `groups: seq<Sid>` | `0x85` `Tier` | `0xF2`, `0xF3` |
//! | `0x06` | `EndView` | `view` | `0x86` `()` | `0xF3` |
//! | `0x07` | `DescribeDomain` | — | `0x87` `{ realm, naming_context, krbtgt: KeyHandle, policy_version }` | — |
//! | `0x08` | `Ping` | — | `0x88` `()` | — |
//! | — | (any) | — | `0xFF` shared `Refused` (A-59) | — |
//!
//! No message carries a role, a uid, a `now`, a key or a password: the
//! caller is the connection's peer (docs/50 §3.2); account records carry key
//! **handles** only, and salts are public string-to-key hints (RFC 4120
//! 5.2.7.5). Nothing on this channel is secret.
//!
//! # Security
//!
//! `#![forbid(unsafe_code)]`; no `unwrap`, `expect` or `panic!` outside
//! tests and const evaluation. Every bound is a named constant ([`channel`]);
//! nothing is allocated from a peer-supplied length beyond the bound. No
//! error carries frame octets (docs/50 §8.2).
//!
//! # Provenance
//!
//! Written only from this project's decided design, opened in-session:
//! AGENT-ONBOARDING, AGENTS, docs/50 (§1 R50-2..R50-8; §2.2; §3.1-§3.7;
//! §7.5; §8.2; §9; §10; the channel-magic registry; closing decision A-58),
//! docs/47 §8, docs/questions Q-213 / Q-214 / Q-218..Q-220 (A-57), Q-217 /
//! Q-222 (A-56), Q-225 (A-59), Q-245 (A-63), Q-255 (A-65), Q-270,
//! PENDING-OWNER; the code of this project's crates ipc, kdc, pdp,
//! keyd-types, krb-proto, dtyp, directory-pip (its API) and ipc-keyd (the
//! pattern); and the docs.rs API pages of rustix 1.1.6 and zeroize 1.9.1
//! (P-2). No other implementation, directory server, serializer or RPC
//! framework was consulted or recalled (AGENTS.md §1-3).
//!
//! Spec: docs/50 R50-2, R50-3, R50-4, R50-7, R50-8, §3, §7.5, §10 (P8);
//! docs/47 §8; A-56; A-57; A-59; A-63.

pub mod channel;
pub mod client;
pub mod typed;
#[cfg(unix)]
mod unix;
pub mod wire;

pub use channel::{
    ViewFailure, DIRECTORY_CHANNEL, DIRECTORY_MAGIC, DIRECTORY_VERSION, MAX_GROUPS, REPLY_LIMIT,
    REQUEST_LIMIT,
};
pub use client::{
    ClientConfigError, ConnectError, Connection, Connector, DirectoryClient, RemoteView,
    TransportError, UnavailableDirectory, Unserved, DEFAULT_DEADLINE,
};
pub use typed::{ConversionError, DomainDescription, Query, Request};
#[cfg(unix)]
pub use unix::{UnixConnection, UnixConnector};
pub use wire::{DirectoryReply, DirectoryRequest};
