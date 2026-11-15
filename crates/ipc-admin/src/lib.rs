#![forbid(unsafe_code)]
//! `ipc-admin`: the administrators' channel to admind (`admin.sock`) — its
//! message set, the typed requests and replies, admind's request decoding
//! and reply encoding, and a client's request encoding and reply decoding
//! (docs/51 §7.6, R51-7, §12 task A9; decisions A-72, A-73).
//!
//! admind (crates/admin-daemon) is local-only, stateless and has no store
//! (docs/51 §5.1): it checks a request syntactically, forwards it to dird
//! over `dird-admin.sock` (crate ipc-dird-admin), and for a password calls
//! keyd itself. So the operations are dird's — encoded by ipc-dird-admin,
//! byte for byte — except that `BeginPasswordSet` / `CompletePasswordSet`
//! are replaced by **`SetPassword`**, the only message that carries a
//! password: admind runs `BeginPasswordSet` ⇒ `set_secret` (×1 / ×2) ⇒
//! `CompletePasswordSet` itself, and the password never reaches dird
//! (docs/51 §7.6).
//!
//! # Layers
//!
//! | layer | module | what it checks |
//! |---|---|---|
//! | channel | [`channel`] | magic `0x414D`, exact version 1, per-direction / per-field bounds, closed kind and status tables (no kind equals `ipc::REFUSED_KIND`) |
//! | wire | [`wire`] | fixed-order fields through `ipc`; forwarded operations through ipc-dird-admin's own message set |
//! | typed | [`typed`] | dird's typed decoders (UTF-8, GUIDs, SIDs, one spelling of "never"); the password as zeroizing UTF-8 |
//! | codec | [`codec`] | [`decode_request`] (or how to refuse), [`encode_reply`], [`encode_refusal`]; [`encode_request`], [`decode_reply`] |
//!
//! # Wire layout (magic `0x414D` "AM", version 1)
//!
//! Every frame: `length:u32 ‖ magic:u16 ‖ version:u8 ‖ kind:u8 ‖ payload`
//! (docs/50 §3.3). Every operation starts with dird's
//! `auth := requester: bytes<64 KiB> ‖ approvals: seq<_, 0>` — the
//! requester's raw AP-REQ, which admind forwards untouched, and the count of
//! the **retired** in-request approvals, always 0 (docs/questions/Q-882,
//! A-148: every approval is an `Approve` of a pending request dird holds);
//! there is no field in which a client (or admind) could claim a name, SID,
//! tier or "approved" (docs/51 §7.2; A-70).
//!
//! | dir | kind | message | payload |
//! |---|---|---|---|
//! | → | `0x01`–`0x05` | `CreateUser`, `CreateComputer`, `CreateGroup`, `CreateOu`, `CreateContainer` | dird's (`auth` ‖ fields) |
//! | → | `0x08`–`0x0D` | `SetEnabled`, `SetAccountExpires`, `AddMember`, `RemoveMember`, `Delete`, `Lookup` | dird's (`auth` ‖ fields) |
//! | → | `0x14` | `Ping` | — (no `auth`) |
//! | → | `0x0E`, `0x0F` | (retired by task D2-c: `RequestKeyOperation`, the key-only `Approve` — Q-882) | — |
//! | → | `0x17`–`0x1C` | `Propose`, `Approve`, `Reject`, `Withdraw`, `ListRequests`, `ShowRequest` (task D2-c) | dird's (`auth` ‖ fields) |
//! | → | `0x10`–`0x12` | (retired by A-102: keyadm's `FetchApproved`, `Complete`, `ListPendingDestruction`) | — |
//! | → | `0x15` | `SetPassword` | `auth ‖ completion:bytes<64 KiB> ‖ target:[16] ‖ password:secret bytes<1024>` |
//! | → | `0x16` | `ChangePolicy` (task A16) | dird's (`auth` ‖ fields) |
//! | ← | `0x81` | `Created` | dird's: `guid:[16] ‖ sid:Option<bytes<68>>` |
//! | ← | `0x83` | `Done` | — |
//! | ← | `0x84` | `Found` | dird's: `guid ‖ dn:seq<bytes<128>,64> ‖ class:bytes<64> ‖ sid?` |
//! | ← | `0x85` | `Refused` | `status:u8{1 Denied, 2 ApprovalRequired, 3 NotFound, 4 Invalid, 5 Conflict, 6 Unavailable, 7 OutcomeUnknown, 8 Incomplete}` |
//! | ← | `0x86` | `Pong` | — |
//! | ← | `0x87` | `PasswordChanged` | `kvnos:seq<u32,2> ‖ completion_recorded:bool` |
//! | ← | `0x88` | (retired by task D2-c: `KeyRequest`) | — |
//! | ← | `0x8C`–`0x8E` | `PendingRequest`, `RequestList`, `RequestShown` (task D2-c) | dird's |
//! | ← | `0x89`, `0x8A` | (retired by A-102: `Approved`, `PendingDestruction`) | — |
//! | ← | `0x8B` | `PolicyNext` (task A16) | dird's: `version:u64` |
//! | ← | `0xFF` | shared `Refused` (A-59) | `code` |
//!
//! Unused kinds: `0x06` / `0x07` (dird's password-set steps — only admind
//! sends them, to dird), `0x13` (the join token, task A12). Request body
//! ≤ 288 KiB, reply body ≤ 64 KiB ([`channel`]). The synchronous client
//! ([`client`], task A10) is `adminctl`'s when task A11 builds it (keyadm
//! used it until A-102, which took admind out of keyadm's path).
//!
//! `completion` is a second AP-REQ of the requester for dird's
//! `CompletePasswordSet`: dird verifies every request's AP-REQs through
//! keyd, whose replay cache accepts each authenticator once (RFC 4120
//! §3.2.3), so the `BeginPasswordSet` ticket cannot be presented twice —
//! docs/questions/Q-400.
//!
//! # Security
//!
//! `#![forbid(unsafe_code)]`; no `unwrap`, `expect` or `panic!` outside
//! tests and const evaluation. Every bound is a named constant. The
//! password lives in `ipc::Secret` (wire) and a zeroizing `String` (typed),
//! is never printed by any `Debug` (not even its length), has no `Clone` and
//! no `PartialEq`; no error carries frame, AP-REQ or password octets
//! (docs/50 §3.3, §8.2; AGENTS.md §6).
//!
//! # Provenance
//!
//! Written only from this project's decided design, opened in-session:
//! AGENT-ONBOARDING, AGENTS, docs/51 (whole), docs/50 (§2.4, §3, §6.4, §7,
//! §8, §9, the channel-magic registry), docs/47 §9, docs/10 §2, §6, §10,
//! docs/questions Q-220, Q-290, Q-291, Q-340, Q-341, Q-350, Q-365, Q-367,
//! Q-370, Q-378, Q-385..Q-389 and PENDING-OWNER (A-26, A-55, A-56, A-59,
//! A-63, A-64, A-70, A-72, A-73, A-79, A-85, A-88, A-90, A-91, A-92); the
//! public API of this project's crates ipc, ipc-dird-admin, dtyp, ipc-keyd;
//! and the docs.rs API page of zeroize 1.9.1 as already cited in crate ipc
//! (P-2). No other implementation, management protocol, serializer or RPC
//! framework was consulted or recalled (AGENTS.md §1-3).
//!
//! Spec: docs/51 §7.1, §7.2, §7.6, R51-7; docs/50 R50-4, §3.3, §7.5, the
//! channel-magic registry; A-59; A-64; A-72; A-73.

pub mod channel;
pub mod client;
pub mod codec;
pub mod typed;
pub mod wire;

pub use channel::{
    RefusalStatus, ADMIN_CHANNEL, ADMIN_MAGIC, ADMIN_VERSION, MAX_PASSWORD, MAX_REPLY_BODY,
    MAX_REQUEST_BODY, REPLY_LIMIT, REQUEST_LIMIT,
};
pub use client::{AdmindClient, AdmindFailure, AdmindUnserved, RootServerUid, DEFAULT_DEADLINE};
pub use codec::{
    decode_reply, decode_request, encode_refusal, encode_reply, encode_request, EncodeError,
    Rejected, Rejection, ReplyError,
};
pub use typed::{
    answers, forwarded, ConversionError, Password, PasswordChanged, Reply, Request, SetPassword,
};
pub use wire::{AdminReply, AdminRequest, WireSetPassword};
