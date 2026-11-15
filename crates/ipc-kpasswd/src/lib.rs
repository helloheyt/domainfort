#![forbid(unsafe_code)]
//! `ipc-kpasswd`: the kpasswd-front ↔ dird channel (`dird-kpasswd.sock`) —
//! its message set, dird's decoding and dispatch skeleton, and the front's
//! asynchronous client (docs/53 §4.3, §5.6, §5.9, R53-4; decision A-117;
//! build task K7, channel part).
//!
//! kpasswd-front is the network front of RFC 3244 on TCP 464: it frames the
//! request, and hands dird the AP-REQ and the KRB-PRIV **as opaque octets**,
//! with the connection's peer and local addresses. dird has keyd open the
//! request (keyd alone decrypts the KRB-PRIV — the new password never leaves
//! keyd), decides, writes, has keyd complete and seal, and returns keyd's
//! sealed reply — or, when there is no keyd context to seal in, the result
//! code of the front's KRB-ERROR (docs/53 §4.3, §5.5–§5.7). The front holds
//! no key, no store and no keyd channel; this crate links none of them.
//!
//! # The new password never crosses this channel in clear — by construction
//!
//! * **No type for it.** The crate links no `krb-proto` and no `krb-crypto`
//!   (checked by `tests/no_cleartext_password.rs` with a positive control),
//!   so none of the types that hold a decrypted KRB-PRIV payload —
//!   krb-proto's `UserData`, `EncKrbPrivPart`, `ChangePasswdData`,
//!   `NewPasswd` — can be named in the message set, and no code linked here
//!   can decrypt a KRB-PRIV. No field is an `ipc::Secret` (the same test
//!   scans the sources).
//! * **No slot for it.** The only request fields are the client's two
//!   messages and two addresses; [`KrbPrivOctets`] always starts with the
//!   KRB-PRIV identifier `[APPLICATION 21]`, whose only payload is the
//!   `enc-part` under the Authenticator's subkey (RFC 4120 §5.7.1; RFC 3244
//!   §2). The cleartext EncKrbPrivPart (`[APPLICATION 28]`) is refused at
//!   construction and at decoding.
//!
//! The front cannot decrypt either: kpasswd-front links no crypto
//! (crates/kpasswd-front `tests/holds_no_key.rs`).
//!
//! # Layers
//!
//! | layer | module | what it checks |
//! |---|---|---|
//! | channel | [`channel`] | magic `0x4B50`, exact version 1, per-direction / per-field bounds, closed kind and code tables (no kind equals `ipc::REFUSED_KIND`), the identifier octets |
//! | values | `values` | the identifier octet and bounds of each Kerberos message, the joint bound of a request's / reply's two messages, canonical addresses, the closed unsealed codes |
//! | wire | [`wire`] | fixed-order fields through `ipc` (lengths, markers, closed tables, field domains, no trailing octet) |
//! | server | [`server`] | dird: [`decode_request`] (or how to refuse), [`encode_reply`], the zone from the front's uid ([`KpasswdFronts`]), the dispatcher ([`KpasswdConnection`]) over a host trait ([`KpasswdHost`]) |
//! | client | [`client`] | the front: [`KpasswdClient`] — dird-uid and zone check on every connection before sending, one deadline, one request per connection, no resend, strict replies |
//!
//! # Wire layout (magic `0x4B50` "KP", version 1)
//!
//! Every frame: `length:u32 ‖ magic:u16 ‖ version:u8 ‖ kind:u8 ‖ payload`
//! (docs/50 §3.3).
//!
//! | dir | kind | message | payload | reply |
//! |---|---|---|---|---|
//! | → | `0x01` | `Ping` | — | `Pong` |
//! | → | `0x02` | `ChangePassword` | `ap_req: bytes ‖ krb_priv: bytes ‖ peer: address ‖ local: address` (AP-REQ starts `0x6E`, KRB-PRIV `0x75`; each ≥ 1, together ≤ 65,529) | `Sealed` or `Unsealed`, then dird closes |
//! | ← | `0x81` | `Pong` | `zone: u8 {1 Internal}` | — |
//! | ← | `0x82` | `Sealed` | `ap_rep: bytes ‖ krb_priv: bytes` (AP-REP starts `0x6F`, KRB-PRIV `0x75`; together ≤ 8,176) | — |
//! | ← | `0x83` | `Unsealed` | `code: u8 {2 HARDERROR, 3 AUTHERROR}` | — |
//! | ← | `0xFF` | shared `Refused` (A-59) | `code` | — |
//!
//! `address := family: u8 {1 IPv4, 2 IPv6} ‖ [4] | [16]` (an IPv4-mapped
//! IPv6 address is refused: RFC 4120 §7.1). Request body ≤ 64 KiB + 64;
//! reply body ≤ 8 KiB ([`channel`]).
//!
//! # Security
//!
//! `#![forbid(unsafe_code)]`; no `unwrap`, `expect` or `panic!` outside
//! tests and const evaluation. Every bound is a named constant; nothing is
//! allocated from a peer-supplied length beyond its bound or the octets
//! present. The forwarded messages and the reply buffers are zeroizing; no
//! error and no `Debug` output carries message octets (docs/53 §9: "never …
//! the KRB-PRIV / AP-REQ octets"; docs/50 §8.2).
//!
//! # Provenance
//!
//! Written only from this project's decided design and the allowed
//! specifications, opened in-session: docs/CLEAN-ROOM.md, docs/CLEAN-ROOM.md; docs/53 (all;
//! esp. §3.3, §4.1–§4.5, §5.1, §5.5–§5.9, §8, §9, §10 K7); docs/50 (§3.1–§3.7,
//! §7.5, the channel-magic registry); docs/questions PENDING-OWNER (A-114,
//! A-117, A-121, A-126, A-142, A-151, A-156), Q-600..Q-605, Q-609, Q-620,
//! Q-621, Q-660..Q-664, Q-945, Q-830, Q-831; docs/research/r3-e (§3);
//! RFC 3244 §2 (pinned, SHA-256 `45b9130f…dec378`, re-verified this session);
//! RFC 4120 (pinned, `368d3cd1…f75b`) §5.5.1, §5.5.2, §5.7.1, §5.10, §7.1,
//! Appendix A; ITU-T X.690 (02/2021, pinned, `6ac799a2…bd6c`) 8.1.2, 8.14;
//! the public API of this project's crate ipc (ipc-dns, ipc-dns-server and
//! ldap-front's dird client as the pattern); and the docs.rs API pages of
//! tokio 1.54.1 and zeroize 1.9.1 (P-2) and the std 1.95.0 API documentation
//! (`IpAddr::to_canonical`). No other implementation, kpasswd server,
//! serializer or RPC framework was consulted or recalled (docs/CLEAN-ROOM.md).
//!
//! Spec: docs/53 §4.3, §5.5–§5.9, R53-4, R53-8; A-117; docs/50 R50-3, R50-4,
//! R50-7, §3; A-59.

pub mod channel;
pub mod client;
pub mod server;
mod values;
pub mod wire;

pub use channel::{
    DEFAULT_DEADLINE, KPASSWD_CHANNEL, KPASSWD_MAGIC, KPASSWD_VERSION, MAX_FRONT_CONNECTIONS,
    MAX_REPLY_BODY, MAX_REQUEST_BODY, MAX_REQUEST_FIELD, MAX_REQUEST_MESSAGES, MAX_RFC3244_MESSAGE,
    MAX_SEALED_MESSAGES, REPLY_LIMIT, REQUEST_LIMIT, RFC3244_HEADER,
};
pub use client::{ClientConfigError, ExpectedDird, KpasswdClient, TransportError, Unserved};
pub use server::{
    decode_request, encode_refusal, encode_reply, refuse, ConnectionId, Dispatch,
    KpasswdConnection, KpasswdFronts, KpasswdHost, Rejection,
};
pub use values::{
    ApRepOctets, ApReqOctets, ChangePasswordRequest, FrontZone, KpasswdAnswer, KrbPrivOctets,
    ObservedAddress, SealedReply, UnsealedCode,
};
pub use wire::{KpasswdReply, KpasswdRequest};

/// The host's refusal on dird's side (re-exported under a distinct name: the
/// client's [`Unserved`] is the front's).
pub use server::Unserved as HostUnserved;
