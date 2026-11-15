#![forbid(unsafe_code)]
//! `ipc`: the hand-defined framing and field codec under every local IPC
//! channel (docs/50 §3.3, R50-4; runtime build task P1, docs/50 §10).
//!
//! # Wire layout
//!
//! ```text
//! Frame   := length:u32 (big-endian) ‖ body[length]
//! body    := magic:u16 ‖ version:u8 ‖ kind:u8 ‖ payload
//! payload := the fixed-order fields of that kind; the body ends exactly
//!            after the last field
//! ```
//!
//! Field primitives, each with exactly one valid encoding per value:
//!
//! | field | encoding |
//! |---|---|
//! | `u8` / `u16` / `u32` / `u64` | fixed width, big-endian |
//! | `bool` | `00` (false) or `01` (true); nothing else |
//! | `[u8; N]` | `N` octets, no prefix |
//! | `bytes<max>` | `u32` length ≤ `max`, then the octets |
//! | DER blob ([`DerBlob`]) | as `bytes<max>`; opaque here, decoded by `krb-proto` |
//! | secret ([`Secret`]) | as `bytes<max>`; held in zeroizing buffers |
//! | `Option<T>` | `00`, or `01` then `T` |
//! | `seq<T, max>` | `u32` count ≤ `max`, then the items |
//! | enum | one `u8` from a closed table |
//!
//! # Scope
//!
//! * [`decode_frame`] / [`FrameReader`] cut frames from a stream, checking the
//!   declared length against a per-channel, per-direction [`FrameLimit`]
//!   before any body octet is allocated or awaited.
//! * [`Reader`] / [`Writer`] decode and encode the field primitives; the
//!   reader rejects truncation, trailing octets, out-of-range markers and
//!   over-bound lengths and counts, and never panics.
//! * [`Channel`], [`Payload`], [`MessageSet`], [`encode_frame`] and
//!   [`decode_body`] are the envelope and the message-definition pattern the
//!   channel crates (ipc-keyd, ipc-directory, …) build on: exact version
//!   match (no negotiation), closed kind table, canonical round trip
//!   ([`round_trip_is_canonical`]).
//! * [`Refused`] is the shared transport-level refusal reply. It travels with
//!   the reply kind [`REFUSED_KIND`] (`0xFF`), reserved on every channel and
//!   excluded from every [`MessageSet`] table at compile time;
//!   [`encode_refused`] sends it and [`decode_reply`] routes it ahead of the
//!   channel's table (A-59).
//!
//! Not here: the per-channel message sets, sockets, peer credentials,
//! timeouts and queues (later crates, docs/50 §3.1–§3.6, §10).
//!
//! # Security
//!
//! No serializer framework and no serde (D34). Every bound is a named
//! constant in [`limits`] or a caller-supplied value; nothing is allocated
//! from an attacker-supplied length beyond what the bound allows or the
//! octets present can fill. Buffers that may hold a secret — the frame
//! reader's body, the writer's output, [`EncodedFrame`], [`Secret`] — are
//! zeroizing and are never reallocated in place. No error carries frame
//! octets, and no `Debug` output prints payload octets (docs/CLEAN-ROOM.md;
//! docs/50 §8.2).
//!
//! # Provenance
//!
//! Written only from this project's decided design, opened in-session:
//! docs/50 (§1 R50-4, R50-7, R50-8; §3.1–§3.7; §8.2; §9; §10 and the closing
//! decision, A-58), docs/10 (§2, §3, §9–§12, D34), docs/questions/
//! PENDING-OWNER (A-56..A-58, P-1, P-2), decision A-59 (docs/questions/
//! Q-225: the reserved `REFUSED_KIND`), and the docs.rs API pages of
//! `zeroize` 1.9.1 (`Zeroizing`, `Zeroize`, `ZeroizeOnDrop`). The wire layout
//! and every name come from docs/50 §3.3. No other implementation, serializer
//! or RPC framework was consulted or recalled (docs/CLEAN-ROOM.md).
//!
//! Spec: docs/50 §3.3, §10; R50-4; D34; A-59.

mod envelope;
mod error;
mod frame;
pub mod limits;
mod reader;
mod refused;
mod values;
mod writer;

pub use envelope::{
    decode_body, decode_message, decode_payload, decode_reply, decode_reply_message, encode_frame,
    encode_payload, encode_refused, encode_reply, reply_round_trip_is_canonical,
    round_trip_is_canonical, Channel, Direction, EncodedFrame, MessageSet, Payload, Reply,
};
pub use error::{Error, Result};
pub use frame::{decode_frame, FrameReader, FrameStatus};
pub use limits::{
    FrameLimit, BODY_HEADER_LEN, LENGTH_PREFIX_LEN, MAX_BODY_CEILING, MAX_NESTING, MIN_BODY_LIMIT,
};
pub use reader::Reader;
pub use refused::{kinds_exclude_refused, Refused, REFUSED_KIND};
pub use values::{DerBlob, Secret};
pub use writer::Writer;
