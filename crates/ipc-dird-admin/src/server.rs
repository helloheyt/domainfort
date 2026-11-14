//! dird's side of the codec: decode one request body into a typed request
//! (or say how to refuse it), and encode a typed reply. The service itself
//! — keyd verification, the write PEP, the audit gate — is dird's
//! (crates/directory-daemon); this crate links none of it.
//!
//! The disposition of a body that does not decode follows docs/50 §3.3 and
//! `ipc::Error::refusal`: a wrong magic or an unknown kind ⇒ close without a
//! reply; another version ⇒ `Refused{VersionMismatch}` and close; a payload
//! error (truncation, trailing octet, over-bound length or count, unknown
//! code) ⇒ `Refused{Malformed}` and close. A value the typed layer refuses
//! (text that is not UTF-8, a second spelling of "never") is `Malformed`
//! too: it never reaches the PEP.
//!
//! Spec: docs/51 §7.1; docs/50 §3.3 (the disposition table); A-59.

use crate::channel::ADMIN_CHANNEL;
use crate::typed::{ConversionError, Reply, Request};
use crate::wire::AdminRequest;
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
/// Spec: docs/51 §7.1; docs/50 §3.3.
pub fn decode_request(body: &[u8]) -> Result<Request, Rejection> {
    let wire = decode_body::<AdminRequest>(ADMIN_CHANNEL, Direction::Request, body)
        .map_err(|error| error.refusal().map_or(Rejection::Close, Rejection::Refuse))?;
    Request::from_wire(&wire).map_err(|_| Rejection::Refuse(Refused::Malformed))
}

/// Why a reply could not be encoded (never the peer's fault).
/// Spec: docs/50 §3.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeError {
    /// The typed reply has no wire form.
    Conversion(ConversionError),
    /// The frame would break a bound.
    Frame(ipc::Error),
}

/// Encode one typed reply as a frame.
///
/// # Errors
/// [`EncodeError`]; the caller answers `Refused{Unavailable}` instead.
///
/// Spec: docs/51 §7.3; docs/50 §3.3.
pub fn encode_reply(reply: &Reply) -> Result<EncodedFrame, EncodeError> {
    let wire = reply.to_wire().map_err(EncodeError::Conversion)?;
    encode_frame(ADMIN_CHANNEL, Direction::Reply, &wire).map_err(EncodeError::Frame)
}

/// Encode the shared refusal on this channel.
///
/// # Errors
/// An `ipc::Error` (cannot happen: every bound has room for it, A-59).
///
/// Spec: docs/50 §3.3; A-59.
pub fn encode_refusal(refused: Refused) -> Result<EncodedFrame, ipc::Error> {
    encode_refused(ADMIN_CHANNEL, refused)
}
