//! The TCP header: "For TCP transport, there is a 4 octet header in network
//! byte order that precedes the message and specifies the length of the
//! message" (RFC 3244 §2).
//!
//! The front reads the four header octets, calls [`tcp_message_length`] —
//! which bounds the announced length **before** any buffer for the message is
//! allocated (docs/CLEAN-ROOM.md; docs/53 §5.1) — reads exactly that many octets,
//! and parses them with `RequestMessage::parse`. `RequestMessage::parse_tcp`
//! / `ReplyMessage::parse_tcp` do the same on a buffer that already holds one
//! whole frame.

use crate::error::{Error, Result};
use crate::limits::{MAX_MESSAGE_LEN, MESSAGE_HEADER_LEN, TCP_HEADER_LEN};

/// The message length a TCP header announces, bounded: more than
/// [`MAX_MESSAGE_LEN`] ⇒ [`Error::TcpLengthTooLarge`]; fewer than
/// [`MESSAGE_HEADER_LEN`] (including 0) ⇒ [`Error::TcpLengthTooSmall`].
///
/// Spec: RFC 3244 §2 (4 octets, network byte order); docs/53 §5.1 ("value 0
/// or > 65,535 ⇒ close before allocation"; "message length ≥ 6").
pub fn tcp_message_length(header: [u8; TCP_HEADER_LEN]) -> Result<usize> {
    let announced = u32::from_be_bytes(header);
    let length = usize::try_from(announced).map_err(|_| Error::TcpLengthTooLarge)?;
    if length > MAX_MESSAGE_LEN {
        return Err(Error::TcpLengthTooLarge);
    }
    if length < MESSAGE_HEADER_LEN {
        return Err(Error::TcpLengthTooSmall);
    }
    Ok(length)
}

/// Split one whole TCP frame into its message: the header must announce
/// exactly the octets that follow it (no truncation, no trailing octets).
///
/// Spec: RFC 3244 §2; docs/53 §5.1.
pub(crate) fn tcp_message(frame: &[u8]) -> Result<&[u8]> {
    let Some((header, message)) = frame.split_first_chunk::<TCP_HEADER_LEN>() else {
        return Err(Error::Truncated);
    };
    let length = tcp_message_length(*header)?;
    if message.len() != length {
        return Err(Error::TcpLengthMismatch);
    }
    Ok(message)
}

/// Prefix an encoded message (≤ [`MAX_MESSAGE_LEN`] octets, which every
/// encoder of this crate guarantees) with its TCP header.
///
/// Spec: RFC 3244 §2.
pub(crate) fn tcp_frame(message: &[u8]) -> Vec<u8> {
    // `message.len()` ≤ 65,535, so it fits in the 32-bit header; were the
    // invariant ever broken, u32::MAX is a header every reader refuses (fail
    // closed, no panic).
    let length = u32::try_from(message.len()).unwrap_or(u32::MAX);
    let mut out = Vec::with_capacity(TCP_HEADER_LEN + message.len());
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(message);
    out
}
