//! KDC messaging over IP: the UDP / TCP split and the TCP record framing, as
//! pure, bounded helpers (main-session decision 1). No sockets: the daemon
//! owns them.
//!
//! The split (RFC 4120 7.2):
//! - **UDP** (7.2.1): one datagram carries exactly one encoded request, and
//!   the reply is one datagram carrying exactly one encoded reply. No
//!   framing. A reply larger than the configured UDP limit is replaced by
//!   KRB_ERR_RESPONSE_TOO_BIG ("forcing the client to retry the request using
//!   the TCP transport"). A message the KDC cannot decode gets no reply over
//!   UDP (5.1.4: "KDCs SHOULD NOT respond to messages received with an
//!   unknown tag over UDP transport in order to avoid denial of service
//!   attacks"; this KDC applies the same silence to every undecodable
//!   datagram — see [`crate::Kdc::handle`]).
//! - **TCP** (7.2.2): every request and reply is preceded by its length as 4
//!   octets in network byte order. The high bit of the length is reserved and
//!   MUST be zero; a KDC that receives it set "MUST return a KRB-ERROR message
//!   with the error KRB_ERR_FIELD_TOOLONG and MUST close the TCP stream". A
//!   length above [`crate::MAX_REQUEST_LEN`] is answered the same way (the
//!   field is "too long for this implementation", 7.5.9). Several requests
//!   may follow each other on one stream; [`tcp_decode_frame`] returns the
//!   first and the bytes after it.
//!
//! Nothing here allocates from an attacker-supplied length: decoding only
//! borrows from the caller's buffer, and the length is checked against the
//! bound before it is used.
//!
//! Spec: RFC 4120 7.2, 7.2.1, 7.2.2, 5.1.4, 7.5.9; main-session decisions 1,
//! 12.

use crate::config::MAX_REQUEST_LEN;

/// The transport a request arrived on. Spec: RFC 4120 7.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transport {
    /// UDP/IP (RFC 4120 7.2.1).
    Udp,
    /// TCP/IP (RFC 4120 7.2.2).
    Tcp,
}

/// How a request arrived, as observed by the daemon (never claimed by the
/// client).
///
/// Spec: RFC 4120 7.2; docs/11 §1 (`Context.src_net`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Peer {
    /// The transport.
    pub transport: Transport,
    /// The network zone of the source (PDP context).
    pub src_net: pdp::IpScope,
}

/// What the daemon must do with the result of one request.
///
/// Messages are unframed: over TCP, the daemon sends
/// [`tcp_encode_frame`]`(message)`.
///
/// Spec: RFC 4120 7.2.1, 7.2.2, 5.1.4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KdcReply {
    /// Send this message (AS-REP, TGS-REP or KRB-ERROR).
    Send(Vec<u8>),
    /// Send this KRB-ERROR, then close the TCP stream (RFC 4120 7.2.2).
    SendAndClose(Vec<u8>),
    /// Send nothing (RFC 4120 5.1.4, over UDP).
    Silent,
}

/// Length of the TCP length prefix, in octets. Spec: RFC 4120 7.2.2 ("4
/// octets in network byte order").
pub const TCP_LENGTH_PREFIX_LEN: usize = 4;

/// The reserved high bit of the TCP length. Spec: RFC 4120 7.2.2.
const TCP_RESERVED_BIT: u32 = 0x8000_0000;

/// Why a TCP record cannot be accepted. Either one is answered with
/// KRB_ERR_FIELD_TOOLONG and the stream is closed
/// ([`crate::Kdc::reject_frame`]).
/// Spec: RFC 4120 7.2.2, 7.5.9.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FramingError {
    /// The reserved high bit of the length is set.
    ReservedBitSet,
    /// The length exceeds [`crate::MAX_REQUEST_LEN`].
    TooLong,
}

/// The result of looking for one TCP record at the start of a buffer.
/// Spec: RFC 4120 7.2.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpFrame<'a> {
    /// One complete request and the bytes that follow it.
    Complete {
        /// The request message (without the length prefix).
        message: &'a [u8],
        /// The bytes after this record (possibly the next record).
        rest: &'a [u8],
    },
    /// The buffer does not yet hold a whole record; read more. At most
    /// `TCP_LENGTH_PREFIX_LEN + MAX_REQUEST_LEN` octets are ever needed.
    Incomplete,
}

/// Find the first TCP record in `buf`.
///
/// The length is validated (reserved bit, bound) as soon as its 4 octets are
/// present, before any message octet is awaited, so a peer cannot make the
/// daemon buffer more than the bound.
///
/// Spec: RFC 4120 7.2.2.
pub fn tcp_decode_frame(buf: &[u8]) -> Result<TcpFrame<'_>, FramingError> {
    let Some((prefix, after)) = buf.split_first_chunk::<TCP_LENGTH_PREFIX_LEN>() else {
        return Ok(TcpFrame::Incomplete);
    };
    let length = u32::from_be_bytes(*prefix);
    if length & TCP_RESERVED_BIT != 0 {
        return Err(FramingError::ReservedBitSet);
    }
    let length = usize::try_from(length).map_err(|_| FramingError::TooLong)?;
    if length > MAX_REQUEST_LEN {
        return Err(FramingError::TooLong);
    }
    match after.split_at_checked(length) {
        Some((message, rest)) => Ok(TcpFrame::Complete { message, rest }),
        None => Ok(TcpFrame::Incomplete),
    }
}

/// Prefix `message` with its length for TCP. `None` if the length does not
/// fit in 31 bits (the high bit is reserved and MUST be zero); every message
/// the KDC builds is far below that (krb-proto bounds encodings at 256 KiB).
///
/// Spec: RFC 4120 7.2.2.
pub fn tcp_encode_frame(message: &[u8]) -> Option<Vec<u8>> {
    let length = u32::try_from(message.len()).ok()?;
    if length & TCP_RESERVED_BIT != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(TCP_LENGTH_PREFIX_LEN + message.len());
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(message);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4120 7.2.2: 4-octet big-endian length, then the message.
    #[test]
    fn frame_round_trip() {
        let framed = tcp_encode_frame(b"abc").unwrap();
        assert_eq!(framed, [0, 0, 0, 3, b'a', b'b', b'c']);
        assert_eq!(
            tcp_decode_frame(&framed),
            Ok(TcpFrame::Complete {
                message: b"abc",
                rest: b""
            })
        );
    }

    /// Two records back to back on one stream (RFC 4120 7.2.2: "A client MAY
    /// send multiple requests before receiving responses").
    #[test]
    fn records_follow_each_other() {
        let mut buf = tcp_encode_frame(b"one").unwrap();
        buf.extend(tcp_encode_frame(b"two").unwrap());
        let Ok(TcpFrame::Complete { message, rest }) = tcp_decode_frame(&buf) else {
            panic!("first record");
        };
        assert_eq!(message, b"one");
        assert_eq!(
            tcp_decode_frame(rest),
            Ok(TcpFrame::Complete {
                message: b"two",
                rest: b""
            })
        );
    }
}
