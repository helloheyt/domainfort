//! The request and reply messages of RFC 3244 §2.
//!
//! ```text
//! Request:  message length (16) | protocol version number (16) = 0xff80
//!           AP_REQ length (16)  | AP_REQ data | KRB-PRIV message
//! Reply:    message length (16) | protocol version number (16) = 0x0001
//!           AP_REP length (16)  | AP-REP data | KRB-PRIV message
//!           (AP_REP length 0: the last field is a KRB-ERROR message)
//! ```
//!
//! "All 16 bit fields are in big-endian order." The Kerberos messages are
//! opaque octets here (docs/53 §5.1: the front does not decode DER — keyd
//! opens them through krb-proto). Parsing borrows from the input and
//! allocates nothing; encoding allocates exactly the encoded size, which is
//! at most [`MAX_MESSAGE_LEN`] (+ the TCP header).
//!
//! Values are valid by construction: the only ways to obtain a
//! [`RequestMessage`] / [`ReplyMessage`] are `parse` and the checked
//! constructors, which apply the same rules, so `encode` cannot fail and
//! `encode(parse(b)) == b` for every accepted `b`.
//!
//! `Debug` shows only the lengths of the Kerberos messages, never their
//! octets (docs/53 §8–§9: no message octets in any log or event).
//!
//! Spec: RFC 3244 §2; docs/53 §5.1, §5.9; docs/questions/Q-603 item 5.

use crate::error::{Error, Result};
use crate::limits::{MAX_MESSAGE_LEN, MESSAGE_HEADER_LEN};
use crate::tcp::{tcp_frame, tcp_message};
use core::fmt;

/// The request's `protocol version number`: "contains the hex constant 0xff80
/// (big-endian integer)". The only version accepted (docs/53 R53-2): version 1
/// of the original protocol has no source in specs/SOURCES.md
/// (docs/questions/Q-607) and is refused with BAD_VERSION.
/// Spec: RFC 3244 §2; docs/53 §3.2.
pub const REQUEST_PROTOCOL_VERSION: u16 = 0xFF80;

/// The reply's `protocol version number`: "contains the hex constant 0x0001
/// (big-endian integer)". Spec: RFC 3244 §2.
pub const REPLY_PROTOCOL_VERSION: u16 = 0x0001;

// ===========================================================================
// Shared header
// ===========================================================================

/// The fixed header of a message whose `message length` has been checked.
struct Header<'a> {
    /// `protocol version number`.
    version: u16,
    /// `AP_REQ length` / `AP_REP length`.
    ap_length: usize,
    /// Every octet after the 6-octet header.
    rest: &'a [u8],
}

/// Read the fixed header: bound, then `message length` = the octets present.
///
/// Spec: RFC 3244 §2 ("message length field: contains the number of bytes in
/// the message including this field"; "All 16 bit fields are in big-endian
/// order"); docs/53 §5.1.
fn read_header(message: &[u8]) -> Result<Header<'_>> {
    if message.len() > MAX_MESSAGE_LEN {
        return Err(Error::MessageTooLarge);
    }
    let Some((head, rest)) = message.split_first_chunk::<MESSAGE_HEADER_LEN>() else {
        return Err(Error::Truncated);
    };
    let message_length = usize::from(u16::from_be_bytes([head[0], head[1]]));
    if message_length != message.len() {
        return Err(Error::MessageLengthMismatch);
    }
    Ok(Header {
        version: u16::from_be_bytes([head[2], head[3]]),
        ap_length: usize::from(u16::from_be_bytes([head[4], head[5]])),
        rest,
    })
}

/// Write one message: header, then the AP message (may be empty only for a
/// KRB-ERROR reply), then the last message. The caller has checked every
/// rule; the total is re-checked against [`MAX_MESSAGE_LEN`] here so no
/// length is ever truncated into a 16-bit field.
///
/// Spec: RFC 3244 §2.
fn write_message(version: u16, ap: &[u8], last: &[u8]) -> Result<Vec<u8>> {
    let total = message_len(ap, last)?;
    let (Ok(total16), Ok(ap16)) = (u16::try_from(total), u16::try_from(ap.len())) else {
        return Err(Error::MessageTooLarge);
    };
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&total16.to_be_bytes());
    out.extend_from_slice(&version.to_be_bytes());
    out.extend_from_slice(&ap16.to_be_bytes());
    out.extend_from_slice(ap);
    out.extend_from_slice(last);
    Ok(out)
}

/// The encoded size of a message with these two fields, bounded by
/// [`MAX_MESSAGE_LEN`]. Spec: RFC 3244 §2 (16-bit `message length`).
fn message_len(ap: &[u8], last: &[u8]) -> Result<usize> {
    MESSAGE_HEADER_LEN
        .checked_add(ap.len())
        .and_then(|n| n.checked_add(last.len()))
        .filter(|&n| n <= MAX_MESSAGE_LEN)
        .ok_or(Error::MessageTooLarge)
}

/// `Debug` helper: a length, never the octets.
struct Octets(usize);

impl fmt::Debug for Octets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{} octets>", self.0)
    }
}

// ===========================================================================
// Request Message — RFC 3244 §2
// ===========================================================================

/// A change-password **Request Message** (RFC 3244 §2), borrowed from its
/// input: a non-empty AP-REQ and a non-empty KRB-PRIV, in a message of at most
/// [`MAX_MESSAGE_LEN`] octets with protocol version 0xff80.
///
/// The AP-REQ "must be for the service principal kadmin/changepw@REALM" and
/// carry a subkey; the KRB-PRIV's user-data is the ChangePasswdData — those
/// are keyd's checks after krb-proto decodes the octets (docs/53 §5.3–§5.4).
///
/// Spec: RFC 3244 §2; docs/53 §5.1.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RequestMessage<'a> {
    ap_req: &'a [u8],
    krb_priv: &'a [u8],
}

impl<'a> RequestMessage<'a> {
    /// A request with these two messages, checked by the rules `parse`
    /// applies: AP-REQ non-empty ([`Error::ApReqLengthZero`]), KRB-PRIV
    /// non-empty ([`Error::MissingKrbPriv`]), total ≤ [`MAX_MESSAGE_LEN`]
    /// ([`Error::MessageTooLarge`]).
    ///
    /// Spec: RFC 3244 §2; docs/53 §5.1; Q-603 item 5.
    pub fn new(ap_req: &'a [u8], krb_priv: &'a [u8]) -> Result<Self> {
        if ap_req.is_empty() {
            return Err(Error::ApReqLengthZero);
        }
        if krb_priv.is_empty() {
            return Err(Error::MissingKrbPriv);
        }
        message_len(ap_req, krb_priv)?;
        Ok(RequestMessage { ap_req, krb_priv })
    }

    /// Parse exactly one request message (over TCP: the octets after the
    /// 4-octet header). Checks, in this order: size ≤ [`MAX_MESSAGE_LEN`];
    /// at least the 6-octet header; `message length` = the octets given (so
    /// neither truncation nor trailing octets); `protocol version number` =
    /// [`REQUEST_PROTOCOL_VERSION`] ([`Error::BadVersion`]); `AP_REQ length`
    /// ≠ 0 and ≤ the octets after the header; at least one octet of KRB-PRIV.
    ///
    /// Spec: RFC 3244 §2; docs/53 §5.1; Q-603 item 5.
    pub fn parse(message: &'a [u8]) -> Result<Self> {
        let header = read_header(message)?;
        if header.version != REQUEST_PROTOCOL_VERSION {
            return Err(Error::BadVersion);
        }
        if header.ap_length == 0 {
            return Err(Error::ApReqLengthZero);
        }
        let (ap_req, krb_priv) = header
            .rest
            .split_at_checked(header.ap_length)
            .ok_or(Error::ApLengthExceedsMessage)?;
        if krb_priv.is_empty() {
            return Err(Error::MissingKrbPriv);
        }
        Ok(RequestMessage { ap_req, krb_priv })
    }

    /// Parse one whole TCP frame: the 4-octet header announcing exactly the
    /// octets that follow, then one request message ([`Self::parse`]).
    ///
    /// Spec: RFC 3244 §2; docs/53 §5.1 ("message length = the TCP header").
    pub fn parse_tcp(frame: &'a [u8]) -> Result<Self> {
        Self::parse(tcp_message(frame)?)
    }

    /// `AP_REQ data`: the DER of a KRB_AP_REQ (opaque here).
    /// Spec: RFC 3244 §2.
    pub fn ap_req(&self) -> &'a [u8] {
        self.ap_req
    }

    /// `KRB-PRIV message`: the DER of a KRB-PRIV (opaque here).
    /// Spec: RFC 3244 §2.
    pub fn krb_priv(&self) -> &'a [u8] {
        self.krb_priv
    }

    /// The message octets (no TCP header). Cannot fail: the value was checked
    /// when it was built. Spec: RFC 3244 §2.
    pub fn encode(&self) -> Vec<u8> {
        // Every rule was checked by `new` / `parse`; a failure here would be a
        // broken invariant, answered with an empty (unparseable) encoding
        // rather than a panic.
        write_message(REQUEST_PROTOCOL_VERSION, self.ap_req, self.krb_priv).unwrap_or_default()
    }

    /// The TCP frame: the 4-octet header, then [`Self::encode`].
    /// Spec: RFC 3244 §2.
    pub fn encode_tcp(&self) -> Vec<u8> {
        tcp_frame(&self.encode())
    }
}

impl fmt::Debug for RequestMessage<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequestMessage")
            .field("ap_req", &Octets(self.ap_req.len()))
            .field("krb_priv", &Octets(self.krb_priv.len()))
            .finish()
    }
}

// ===========================================================================
// Reply Message — RFC 3244 §2
// ===========================================================================

/// What a reply carries after its header (a view of a [`ReplyMessage`]).
///
/// Spec: RFC 3244 §2 ("AP-REP length: ... If the length is zero, then the
/// last field contains a KRB-ERROR message instead of a KRB-PRIV message").
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ReplyBody<'a> {
    /// `AP_REP length` ≠ 0: the AP-REP, then the KRB-PRIV "encrypted with the
    /// subsession key from the authenticator in the AP-REQ data" (keyd seals
    /// both — docs/53 §5.5).
    ApRep {
        /// `AP-REP data`: the DER of a KRB_AP_REP (opaque here).
        ap_rep: &'a [u8],
        /// `KRB-PRIV message`: the DER of a KRB-PRIV (opaque here).
        krb_priv: &'a [u8],
    },
    /// `AP_REP length` = 0: a KRB-ERROR "sent back without any
    /// encapsulation" (the front encodes it — docs/53 §5.7).
    KrbError {
        /// The DER of a KRB-ERROR (opaque here).
        krb_error: &'a [u8],
    },
}

impl fmt::Debug for ReplyBody<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReplyBody::ApRep { ap_rep, krb_priv } => f
                .debug_struct("ApRep")
                .field("ap_rep", &Octets(ap_rep.len()))
                .field("krb_priv", &Octets(krb_priv.len()))
                .finish(),
            ReplyBody::KrbError { krb_error } => f
                .debug_struct("KrbError")
                .field("krb_error", &Octets(krb_error.len()))
                .finish(),
        }
    }
}

/// A change-password **Reply Message** (RFC 3244 §2), borrowed from its input:
/// protocol version 0x0001, at most [`MAX_MESSAGE_LEN`] octets, and either a
/// non-empty AP-REP followed by a non-empty KRB-PRIV, or (`AP_REP length` 0) a
/// non-empty KRB-ERROR.
///
/// Spec: RFC 3244 §2; docs/53 §5.1, §5.7.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ReplyMessage<'a> {
    body: ReplyBody<'a>,
}

impl<'a> ReplyMessage<'a> {
    /// A reply carrying an AP-REP and a KRB-PRIV (both non-empty —
    /// [`Error::ApRepLengthZero`] / [`Error::MissingKrbPriv`]; total ≤
    /// [`MAX_MESSAGE_LEN`]).
    ///
    /// Spec: RFC 3244 §2.
    pub fn ap_rep(ap_rep: &'a [u8], krb_priv: &'a [u8]) -> Result<Self> {
        if ap_rep.is_empty() {
            return Err(Error::ApRepLengthZero);
        }
        if krb_priv.is_empty() {
            return Err(Error::MissingKrbPriv);
        }
        message_len(ap_rep, krb_priv)?;
        Ok(ReplyMessage {
            body: ReplyBody::ApRep { ap_rep, krb_priv },
        })
    }

    /// A reply carrying only a KRB-ERROR (`AP_REP length` 0; non-empty —
    /// [`Error::MissingKrbError`]; total ≤ [`MAX_MESSAGE_LEN`]).
    ///
    /// Spec: RFC 3244 §2.
    pub fn krb_error(krb_error: &'a [u8]) -> Result<Self> {
        if krb_error.is_empty() {
            return Err(Error::MissingKrbError);
        }
        message_len(&[], krb_error)?;
        Ok(ReplyMessage {
            body: ReplyBody::KrbError { krb_error },
        })
    }

    /// Parse exactly one reply message (over TCP: the octets after the 4-octet
    /// header), with the same discipline as requests (docs/07 §5, docs/50
    /// §3.3: replies are decoded as strictly as requests): size ≤
    /// [`MAX_MESSAGE_LEN`]; the 6-octet header; `message length` = the octets
    /// given; `protocol version number` = [`REPLY_PROTOCOL_VERSION`]; then
    /// either `AP_REP length` 0 and a non-empty KRB-ERROR, or an `AP_REP
    /// length` ≤ the octets after the header and a non-empty KRB-PRIV.
    ///
    /// Spec: RFC 3244 §2.
    pub fn parse(message: &'a [u8]) -> Result<Self> {
        let header = read_header(message)?;
        if header.version != REPLY_PROTOCOL_VERSION {
            return Err(Error::BadVersion);
        }
        if header.ap_length == 0 {
            if header.rest.is_empty() {
                return Err(Error::MissingKrbError);
            }
            return Ok(ReplyMessage {
                body: ReplyBody::KrbError {
                    krb_error: header.rest,
                },
            });
        }
        let (ap_rep, krb_priv) = header
            .rest
            .split_at_checked(header.ap_length)
            .ok_or(Error::ApLengthExceedsMessage)?;
        if krb_priv.is_empty() {
            return Err(Error::MissingKrbPriv);
        }
        Ok(ReplyMessage {
            body: ReplyBody::ApRep { ap_rep, krb_priv },
        })
    }

    /// Parse one whole TCP frame: the 4-octet header announcing exactly the
    /// octets that follow, then one reply message ([`Self::parse`]).
    ///
    /// Spec: RFC 3244 §2.
    pub fn parse_tcp(frame: &'a [u8]) -> Result<Self> {
        Self::parse(tcp_message(frame)?)
    }

    /// What the reply carries.
    pub fn body(&self) -> ReplyBody<'a> {
        self.body
    }

    /// The message octets (no TCP header). Cannot fail: the value was checked
    /// when it was built. Spec: RFC 3244 §2.
    pub fn encode(&self) -> Vec<u8> {
        let (ap, last) = match self.body {
            ReplyBody::ApRep { ap_rep, krb_priv } => (ap_rep, krb_priv),
            ReplyBody::KrbError { krb_error } => (&[][..], krb_error),
        };
        // See `RequestMessage::encode`: no failure is reachable.
        write_message(REPLY_PROTOCOL_VERSION, ap, last).unwrap_or_default()
    }

    /// The TCP frame: the 4-octet header, then [`Self::encode`].
    /// Spec: RFC 3244 §2.
    pub fn encode_tcp(&self) -> Vec<u8> {
        tcp_frame(&self.encode())
    }
}

impl fmt::Debug for ReplyMessage<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ReplyMessage").field(&self.body).finish()
    }
}
