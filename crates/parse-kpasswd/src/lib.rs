#![forbid(unsafe_code)]
//! `parse-kpasswd`: the strict, bounded framing of the RFC 3244
//! change-password messages (docs/53 §5.1, §5.9; build task K2; decision
//! A-117).
//!
//! # Scope
//!
//! * [`RequestMessage`] — `message length` ‖ `protocol version number`
//!   (0xff80) ‖ `AP_REQ length` ‖ AP-REQ ‖ KRB-PRIV.
//! * [`ReplyMessage`] — `message length` ‖ `protocol version number`
//!   (0x0001) ‖ `AP_REP length` ‖ AP-REP ‖ KRB-PRIV, or `AP_REP length` 0 ‖
//!   KRB-ERROR ([`ReplyBody`]).
//! * The TCP header (4 octets, network byte order, the length of the message):
//!   [`tcp_message_length`] bounds it before any allocation; `parse_tcp` /
//!   `encode_tcp` on each message type handle a whole frame.
//! * [`Error::result_code`] maps every framing failure to the RFC 3244 result
//!   code the front answers with (MALFORMED, or BAD_VERSION) as a
//!   [`NonZeroResultCode`] (defined in krb-proto and re-exported here; there the closed code
//!   set lives so keyd and the front share one type — docs/questions/Q-620).
//!
//! The AP-REQ, AP-REP, KRB-PRIV and KRB-ERROR are **opaque octets** here: the
//! front does not decode DER; keyd decodes the request's messages with
//! krb-proto, and the front encodes its KRB-ERROR with krb-proto (docs/53
//! §5.1, §5.7). Parsing borrows from the input and allocates nothing;
//! encoding allocates exactly the encoded size (≤ 65,535 + 4 octets).
//!
//! **Transport:** TCP only in phase 1 (docs/53 R53-3; docs/questions/Q-602,
//! A-117), so there is no datagram entry point; the message functions take
//! exactly one message.
//!
//! # Strictness (fail closed)
//!
//! Every rule of RFC 3244 §2 that the framing can check, plus the stricter
//! readings of docs/53 §5.1 and docs/questions/Q-603:
//!
//! * TCP header: > 65,535 or < 6 (including 0) ⇒ refused before allocation;
//!   the frame holds exactly the announced octets (no trailing octets — one
//!   request, one reply per connection).
//! * `message length` equals the octets of the message (so it equals the TCP
//!   header); "All 16 bit fields are in big-endian order".
//! * `protocol version number`: exactly 0xff80 in a request (version 1 and
//!   every other value ⇒ [`Error::BadVersion`], answered with
//!   KRB5_KPASSWD_BAD_VERSION — docs/53 R53-2, docs/questions/Q-607), exactly
//!   0x0001 in a reply.
//! * `AP_REQ length` 0 in a request ⇒ refused (a server never parses a
//!   client's KRB-ERROR — Q-603 item 5); the AP length never exceeds the
//!   remaining octets; the KRB-PRIV (or the reply's KRB-ERROR) is non-empty.
//!
//! Each violation is a distinct [`Error`]; nothing panics. Values are valid by
//! construction (only `parse` and the checked constructors build them), so
//! encoding cannot fail and `encode(parse(b)) == b`. `Debug` prints only the
//! lengths of the Kerberos messages (docs/53 §8–§9: no message octets in logs).
//!
//! # Provenance
//!
//! Written only from the allowed specifications, opened in-session (docs/CLEAN-ROOM.md
//! §1-3): RFC 3244 §2 (read in full, pinned SHA-256 `45b9130f…dec378`) and RFC
//! 4120 §5.5.1, §5.5.2, §5.7.1, §5.9.1 (pinned) for the message names; and the
//! project's design docs/53 (§3.2, §3.3, §5.1, §5.7, §5.9, §10 K2) with decision
//! A-117 (docs/questions/Q-602, Q-603, Q-604). No other implementation was
//! consulted or recalled. RFC 3244 has no examples: the tests build every
//! message by hand from its §2 layout.
//!
//! Spec: RFC 3244 §2; docs/53 §5.1, §5.9.

mod error;
pub mod limits;
mod message;
mod tcp;

pub use error::{Error, Result};
pub use krb_proto::NonZeroResultCode;
pub use limits::{MAX_MESSAGE_LEN, MESSAGE_HEADER_LEN, TCP_HEADER_LEN};
pub use message::{
    ReplyBody, ReplyMessage, RequestMessage, REPLY_PROTOCOL_VERSION, REQUEST_PROTOCOL_VERSION,
};
pub use tcp::tcp_message_length;
