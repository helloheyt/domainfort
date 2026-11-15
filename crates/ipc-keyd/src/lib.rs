#![forbid(unsafe_code)]
//! `ipc-keyd`: the keyd channel (`keyd.sock`) — its message set, the
//! server-side request decoding and answer encoding, and the synchronous
//! client that implements `KeyCustody` (docs/50 §3, §10 task P5; decision
//! A-58). The dispatcher that calls the real keyd (`execute`, `dispatch`) is
//! the `ipc-keyd-server` crate: this crate depends only on the crypto-free
//! `keyd-types`, never on keyd or krb-crypto (D182; decision A-63).
//!
//! # Layers
//!
//! | layer | module | what it checks |
//! |---|---|---|
//! | channel | [`channel`] | magic, exact version, per-direction body bounds, per-field bounds, the closed kind tables (none equals `ipc::REFUSED_KIND`) |
//! | wire | [`wire`] | fixed-order fields through `ipc` (lengths, markers, closed enum tables, no trailing octet); Kerberos values stay opaque DER |
//! | typed | [`typed`] | every Kerberos value through `krb-proto`'s strict decoder; passwords and salt as UTF-8 |
//! | server | [`server`] | [`decode_request`] / [`encode_answer`]; `ipc_keyd_server::dispatch` calls keyd with the **transport's** caller and the **daemon's** clock between them |
//! | client | [`client`] | [`KeydClient`] / [`IpcKeyd`]: built only with an [`ExpectedPeer`] — on every connection keyd's uid, then the caller role keyd resolves for this process (`Ping`, or `DescribeConfig` when a description is expected) before anything else is sent (task R9, Q-466); deadline, strict reply decoding, transport failure → `Unavailable`; a held connection checked before reuse (no default), no resend (Q-312); `IpcKeyd`: the description it started with expected of every new connection (Q-311, Q-351); a state call only through [`KeydClient::call_with_fate`] — not sent / not performed / outcome unknown (Q-367) — since [`KeydClient::call`] takes only an [`IssuanceCall`] |
//! | socket | `unix` | [`UnixConnector`]: blocking Unix stream, peer uid via rustix (Linux; elsewhere fail closed), non-blocking idle check |
//!
//! # Message kinds
//!
//! | request kind | operation | role (docs/10 §2) | success reply kind | failure reply kind |
//! |---|---|---|---|---|
//! | `0x01` | `verify_preauth` | Kdc | `0x81` `AuthnProof` | `0xF1` `AuthnError` |
//! | `0x02` | `issue_as_rep` | Kdc | `0x82` `AsRepParts` | `0xF2` `IssueError` |
//! | `0x03` | `open_fast_armor` | Kdc | `0x83` `FastArmor` | `0xF1` |
//! | `0x04` | `open_and_verify_tgt` | Kdc | `0x84` `TgtContext` | `0xF1` |
//! | `0x05` | `issue_tgs_rep` | Kdc | `0x85` `TgsRepParts` | `0xF2` |
//! | `0x06` | `seal_fast_error` | Kdc | `0x86` `EncryptedData` | `0xF3` `Error` |
//! | `0x07` | `open_and_verify_service_ticket(principal)` — unbound only (R2: the binding names the key purpose; Q-523) | Ldap | `0x87` `ServiceContext` (with its context id) | `0xF1` |
//! | `0x08` | `set_secret` | Directory | `0x88` `Kvno` | `0xF3` |
//! | `0x09` | `verify_secret` | — (no role since A-102, docs/52 R4) | `0x89` `()` | `0xF3` |
//! | `0x0A` | `create_key` | Admin (before the seal) | `0x8A` `Kvno` | `0xF3` |
//! | `0x0B` | `rotate_key(decision)` | Admin | `0x8B` `Kvno` | `0xF3` |
//! | `0x0C` | `rotate_krbtgt(decision)` | Admin | `0x8C` `Kvno` | `0xF3` |
//! | `0x0D` | `retire_kvno(decision)` | Admin | `0x8D` `()` | `0xF3` |
//! | `0x0E` | `destroy_key_set(decision)` | Admin | `0x8E` `()` | `0xF3` |
//! | `0x0F` | `describe_config` | Kdc, Ldap | `0x8F` `ConfigDescription` ‖ caller `Role` ([`DescribedConfig`]) | `0xF3` |
//! | `0x10` | `ping` | every role | `0x90` caller `Role` (task R9) | `0xF3` |
//! | `0x11` | `grant_set_secret` (task A15a) | Admin (before the seal, A-102) | `0x91` `()` | `0xF3` |
//! | `0x12` | `register_decision` (A-102) | Ldap | `0x92` `()` | `0xF3` |
//! | `0x13` | `seal_ceremony` (A-102) | Admin | `0x93` `()` | `0xF3` |
//! | `0x14` | `list_destroy_decisions` (A-102) | Admin | `0x94` `DestructionPage` | `0xF3` |
//! | `0x15` | `verify_operation_ticket(principal, operation digest)` (Q-523: keeps no context) | Ldap | `0x95` `OperationTicket` (no context id) | `0xF1` |
//! | `0x16` | `open_change_password_request(principal, AP-REQ, KRB-PRIV, peer, local)` (task K4) | Ldap | `0x96` `ChangePasswordContext` (context id, verdict) | `0xF1` |
//! | `0x17` | `complete_change_password(ctx, target)` (task K4; a state call) | Ldap | `0x97` `SealedReply` | `0xF3` |
//! | `0x18` | `seal_change_password_error(ctx, code ≠ 0)` (task K4) | Ldap | `0x98` `SealedReply` | `0xF3` |
//! | `0x19` | `revoke_decision(decision)` (task F3; not a state call — it only makes keyd stricter) | Ldap | `0x99` `()` | `0xF3` |
//! | — | (any) | — | `0xFF` shared `Refused` (A-59) | — |
//!
//! No request carries a role: keyd checks the caller's role from the
//! connection's peer credentials (docs/50 §3.2) against its compile-time
//! capability table (docs/10 §2, I2). The `describe_config` and `ping`
//! replies report that role back to the caller — not secret, never taken
//! from the peer — so that a client of any role refuses a keyd that does
//! not give it its own role (docs/questions/Q-351, A-87; Q-466, A-102). No
//! message has a `now` field (R50-5, A-56): the server passes the daemon's
//! own clock to every operation.
//!
//! # Security
//!
//! `#![forbid(unsafe_code)]`. Every bound is a named constant
//! ([`channel`]); nothing is allocated from a peer-supplied length beyond the
//! bound. Passwords travel only in zeroizing buffers ([`ipc::Secret`] on the
//! wire, [`typed::Password`] in a call) whose `Debug` prints nothing. No
//! error carries frame octets (docs/50 §8.2).
//!
//! # Provenance
//!
//! Written only from this project's decided design, opened in-session:
//! docs/50 (§1 R50-3..R50-8; §3.1-§3.7; §8.2; §9; §10; closing decision
//! A-58), docs/10 (§1-§12), docs/questions Q-217 and Q-222 (A-56), Q-225
//! (A-59), Q-240 (A-62), Q-245 (A-63), PENDING-OWNER (A-56..A-63, P-1, P-2,
//! P-12); the code of this project's crates ipc, keyd, keyd-types, kdc,
//! krb-proto and krb-crypto; and the
//! docs.rs API pages of rustix 1.1.6 and zeroize 1.9.1 (P-2). The wire layout
//! and every name come from docs/50 §3.3-§3.4 and keyd's API. No other
//! implementation, serializer or RPC framework was consulted or recalled
//! (docs/CLEAN-ROOM.md). Task F3 added the caller role of the `describe_config`
//! reply and the client's request fate from docs/questions Q-351, Q-365,
//! Q-367 and PENDING-OWNER A-87, A-88, with docs/10 §2, §7a, §9, §10 and
//! docs/50 §3.4-§3.7. Task A15a added `grant_set_secret` (request `0x11`,
//! reply `0x91`; the additive client method `KeydClient::grant_set_secret`)
//! from docs/51 §5.8, docs/questions Q-291 and PENDING-OWNER A-74, A-88.
//! Task R9 made the peer expectation mandatory ([`ExpectedPeer`]), added
//! the caller role to the `ping` reply, split the client's call API by
//! kind ([`IssuanceCall`] / [`StateCall`], from keyd-types' one table) and
//! removed `Connection::check_idle`'s default, from docs/52 §2 rows 18, 19,
//! 24, §3.10, §3.12, §7 R9, docs/questions Q-312, Q-350, Q-370, Q-403,
//! Q-466 and PENDING-OWNER A-82, A-90, A-94, A-102. Task K4 appended the
//! three change-password operations (`0x16`-`0x18`, replies `0x96`-`0x98`),
//! purpose code 5 and decided-operation code 6 from docs/53 §5.5, §5.7,
//! docs/50 §3.3, RFC 3244 §2 and RFC 4120 §7.1 (pinned, SHA-256 verified),
//! docs/questions Q-601, Q-604, Q-620, Q-661; `KEYD_VERSION` stays 1. Task
//! F3 appended `revoke_decision` (`0x19`, reply `0x99`; the additive client
//! method `KeydClient::revoke_decision`) from docs/52 §4.2, docs/10 §2, §10
//! and docs/questions Q-937 item 6, Q-976; `KEYD_VERSION` stays 1 (the
//! precedent of R9 / Q-523 / Q-661).
//!
//! Spec: docs/50 §3, §10 (P5); R50-3, R50-4, R50-5, R50-7, R50-8; docs/10;
//! A-56; A-59; A-62; D182; A-63; A-87; A-88; docs/52 §7 R9 (A-102).

pub mod channel;
pub mod client;
pub mod server;
pub mod typed;
#[cfg(unix)]
mod unix;
pub mod wire;

pub use channel::{KEYD_CHANNEL, KEYD_MAGIC, KEYD_VERSION, REPLY_LIMIT, REQUEST_LIMIT};
pub use client::{
    CallFailure, ClientConfigError, Connection, Connector, ExpectedDescription, ExpectedPeer,
    IpcKeyd, KeydClient, RequestFate, StateOutcome, TransportError, Unserved, DEFAULT_DEADLINE,
};
pub use server::{decode_request, encode_answer, Rejection};
pub use typed::{
    Answer, Call, ConversionError, DescribedConfig, IssuanceCall, Password, RoutedCall, StateCall,
    TgsFast,
};
// The role a client expects keyd to resolve for it (task R9), re-exported
// beside `ExpectedPeer` for its callers.
pub use keyd_types::Role;
#[cfg(unix)]
pub use unix::{UnixConnection, UnixConnector};
pub use wire::{KeydReply, KeydRequest, WireTime};
// The arguments of `grant_set_secret` and `register_decision`, re-exported
// for their callers (dird, keyadm) beside the client methods (task A15a,
// A-102).
pub use keyd_types::{
    AccountKind, DecidedOperation, DecisionId, DestructionPage, PendingDestruction, SetSecretTarget,
};
// The operation-bound verification's argument and answer (Q-523), for its
// caller (dird).
pub use keyd_types::{OperationDigest, OperationTicket};
// The change-password operations' arguments and answers (task K4), for
// their caller (dird).
pub use keyd_types::{
    ChangePasswordContext, ChangePasswordCtxId, ChangePasswordVerdict, HostAddr, SealedReply,
};
pub use krb_proto::NonZeroResultCode;
