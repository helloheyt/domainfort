//! dird's side of the codec: decode one request body (or say how to refuse
//! it), and encode the replies. The dispatcher that answers from dird —
//! the connection's zone, the host's refusals — is the separate crate
//! ipc-dns-server; the DNS PEP behind it is dird's (tasks DN8, DN10).
//!
//! The disposition of a body that does not decode follows docs/50 §3.3 and
//! `ipc::Error::refusal`: a wrong magic or an unknown kind ⇒ close without a
//! reply; another version ⇒ `Refused{VersionMismatch}` and close; a payload
//! error (truncation, trailing octet, over-bound length or count, a value
//! outside its field's domain) ⇒ `Refused{Malformed}` and close. Nothing
//! malformed reaches dird's PEP.
//!
//! Spec: docs/54 §4.6; docs/50 §3.3 (the disposition table); A-59.

use crate::channel::DNS_CHANNEL;
use crate::image::ImageTransfer;
use crate::wire::{DnsReply, DnsRequest};
use ipc::{decode_body, encode_frame, encode_refused, Direction, EncodedFrame, Refused};

/// How dird answers a request body that it does not serve.
/// Spec: docs/50 §3.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    /// Close the connection without a reply (wrong magic, unknown kind, a
    /// body outside the envelope bounds).
    Close,
    /// Send the shared refusal, then close.
    Refuse(Refused),
}

/// Decode one request body (as cut by `ipc::FrameReader` under
/// [`crate::REQUEST_LIMIT`]).
///
/// # Errors
/// [`Rejection`] (module documentation).
///
/// Spec: docs/54 §4.6; docs/50 §3.3.
pub fn decode_request(body: &[u8]) -> Result<DnsRequest, Rejection> {
    decode_body::<DnsRequest>(DNS_CHANNEL, Direction::Request, body)
        .map_err(|error| error.refusal().map_or(Rejection::Close, Rejection::Refuse))
}

/// Encode one reply as a frame.
///
/// # Errors
/// An `ipc::Error` (the reply breaks a bound — cannot happen with the value
/// types); the caller answers `Refused{Unavailable}` instead.
///
/// Spec: docs/54 §4.6; docs/50 §3.3.
pub fn encode_reply(reply: &DnsReply) -> Result<EncodedFrame, ipc::Error> {
    encode_frame(DNS_CHANNEL, Direction::Reply, reply)
}

/// Encode a validated image as its `ImageChunk` frames, in order (the last
/// one with `more` clear).
///
/// # Errors
/// An `ipc::Error` (cannot happen: every chunk of an [`ImageTransfer`] fits
/// the reply bound).
///
/// Spec: docs/54 §4.6; crate::image module documentation.
pub fn encode_image_chunks(transfer: &ImageTransfer) -> Result<Vec<EncodedFrame>, ipc::Error> {
    transfer
        .chunks()
        .iter()
        .map(|chunk| encode_reply(&DnsReply::ImageChunk(chunk.clone())))
        .collect()
}

/// Encode the shared refusal on this channel.
///
/// # Errors
/// An `ipc::Error` (cannot happen: every bound has room for it, A-59).
///
/// Spec: docs/50 §3.3; A-59.
pub fn encode_refusal(refused: Refused) -> Result<EncodedFrame, ipc::Error> {
    encode_refused(DNS_CHANNEL, refused)
}
