//! Framing errors.
//!
//! Hand-rolled, no extra dependency (AGENTS.md §7). Every variant names the
//! one RFC 3244 §2 / docs/53 §5.1 rule the input broke; no variant carries any
//! input octet, so nothing of a message can leak through an error, its
//! `Debug` or its `Display` (AGENTS.md §6). Each maps to the RFC 3244 result
//! code the front answers with ([`Error::result_code`], docs/53 §5.7).

use core::fmt;
use krb_proto::NonZeroResultCode;

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// A framing failure of an RFC 3244 request or reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Error {
    /// The TCP header announces more than
    /// [`crate::limits::MAX_MESSAGE_LEN`] octets — more than the 16-bit
    /// `message length` field can count. Refused before any allocation.
    /// Spec: RFC 3244 §2; docs/53 §5.1 ("> 65,535 ⇒ close before allocation").
    TcpLengthTooLarge,

    /// The TCP header announces fewer octets than the fixed message header
    /// ([`crate::limits::MESSAGE_HEADER_LEN`]), including 0.
    /// Spec: RFC 3244 §2; docs/53 §5.1 ("value 0 ⇒ close"; "message length
    /// ≥ 6").
    TcpLengthTooSmall,

    /// The octets after the TCP header are not exactly the message it
    /// announces: fewer (truncated) or more (trailing octets — RFC 3244 §2
    /// allows "a single request message followed by a single reply message").
    /// Spec: RFC 3244 §2; docs/53 §5.1.
    TcpLengthMismatch,

    /// Fewer octets than a header: the 4-octet TCP header, or the 6-octet
    /// message header. Spec: RFC 3244 §2.
    Truncated,

    /// A message longer than [`crate::limits::MAX_MESSAGE_LEN`] octets (its
    /// length cannot be written in the `message length` field).
    /// Spec: RFC 3244 §2; docs/53 §5.9.
    MessageTooLarge,

    /// The `message length` field does not equal the number of octets in the
    /// message: the message is truncated, or trailing octets follow it.
    /// Spec: RFC 3244 §2 ("contains the number of bytes in the message
    /// including this field"); docs/53 §5.1 (= the TCP header).
    MessageLengthMismatch,

    /// The `protocol version number` is not the one the direction requires:
    /// 0xff80 in a request (version 1 and every other value refused — docs/53
    /// R53-2, docs/questions/Q-607), 0x0001 in a reply.
    /// Spec: RFC 3244 §2; docs/53 §3.2, §5.1.
    BadVersion,

    /// A request whose `AP_REQ length` is 0. RFC 3244 §2 writes that the last
    /// field is then a KRB-ERROR; a server never parses a client's KRB-ERROR,
    /// so the request is malformed.
    /// Spec: RFC 3244 §2; docs/53 §5.1; docs/questions/Q-603 item 5.
    ApReqLengthZero,

    /// A reply built as "AP-REP and KRB-PRIV" with an empty AP-REP: its
    /// `AP_REP length` would be 0, which means a KRB-ERROR reply instead.
    /// (Encoding only — a parsed `AP_REP length` of 0 is the KRB-ERROR form.)
    /// Spec: RFC 3244 §2 ("If the length is zero, then the last field contains
    /// a KRB-ERROR message instead of a KRB-PRIV message").
    ApRepLengthZero,

    /// The `AP_REQ length` / `AP_REP length` exceeds the octets that follow
    /// the header. Spec: RFC 3244 §2; docs/53 §5.1 ("≤ the remainder").
    ApLengthExceedsMessage,

    /// Nothing follows the AP-REQ / AP-REP: the KRB-PRIV message is missing.
    /// Spec: RFC 3244 §2 (the KRB-PRIV message is the last field); docs/53
    /// §5.1 ("the remainder after the AP-REQ = KRB-PRIV, ≥ 1").
    MissingKrbPriv,

    /// A reply with `AP_REP length` 0 and nothing after the header: the
    /// KRB-ERROR message is missing. Spec: RFC 3244 §2.
    MissingKrbError,
}

impl Error {
    /// The RFC 3244 result code the front answers this framing failure with:
    /// KRB5_KPASSWD_BAD_VERSION for [`Error::BadVersion`], otherwise
    /// KRB5_KPASSWD_MALFORMED. Never SUCCESS (the return type cannot hold it).
    ///
    /// Spec: RFC 3244 §2 (result codes 1, 6); docs/53 §5.1 ("framing failure:
    /// TCP ⇒ KRB-ERROR (MALFORMED / BAD_VERSION) and close"), §5.7.
    pub fn result_code(self) -> NonZeroResultCode {
        match self {
            Error::BadVersion => NonZeroResultCode::BadVersion,
            Error::TcpLengthTooLarge
            | Error::TcpLengthTooSmall
            | Error::TcpLengthMismatch
            | Error::Truncated
            | Error::MessageTooLarge
            | Error::MessageLengthMismatch
            | Error::ApReqLengthZero
            | Error::ApRepLengthZero
            | Error::ApLengthExceedsMessage
            | Error::MissingKrbPriv
            | Error::MissingKrbError => NonZeroResultCode::Malformed,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Error::TcpLengthTooLarge => "TCP header announces a message over 65535 octets",
            Error::TcpLengthTooSmall => "TCP header announces a message shorter than its header",
            Error::TcpLengthMismatch => "TCP frame octets differ from the announced length",
            Error::Truncated => "input shorter than a header",
            Error::MessageTooLarge => "message over 65535 octets",
            Error::MessageLengthMismatch => "message length field differs from the message size",
            Error::BadVersion => "protocol version number not supported",
            Error::ApReqLengthZero => "request AP_REQ length is zero",
            Error::ApRepLengthZero => "reply AP-REP is empty",
            Error::ApLengthExceedsMessage => "AP_REQ / AP_REP length exceeds the message",
            Error::MissingKrbPriv => "KRB-PRIV message missing",
            Error::MissingKrbError => "KRB-ERROR message missing",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for Error {}
