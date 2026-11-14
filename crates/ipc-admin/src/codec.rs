//! The codec entry points: admind's side (decode one request body or say how
//! to refuse it; encode a reply or the shared refusal) and a client's side
//! (encode a request; decode a reply). Sockets, peer credentials, deadlines
//! and queues are admind's (crates/admin-daemon).
//!
//! The disposition of a request body that does not decode follows docs/50
//! §3.3 and `ipc::Error::refusal`: a wrong magic or an unknown kind ⇒ close
//! without a reply; another version ⇒ `Refused{VersionMismatch}` and close;
//! a payload error (truncation, trailing octet, over-bound length or count,
//! unknown code) ⇒ `Refused{Malformed}` and close. A value the typed layer
//! refuses (text that is not UTF-8, a second spelling of "never", a password
//! that is not UTF-8) is `Malformed` too: it never reaches admind's logic.
//!
//! Spec: docs/51 §7.1, §7.6; docs/50 §3.3 (the disposition table); A-59.

use crate::channel::ADMIN_CHANNEL;
use crate::typed::{ConversionError, Reply, Request};
use crate::wire::{AdminReply, AdminRequest};
use ipc::{decode_body, encode_frame, encode_refused, Direction, EncodedFrame, Refused};

/// How admind answers a request body it does not serve.
/// Spec: docs/50 §3.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    /// Close the connection without a reply (wrong magic, unknown kind, a
    /// body outside the envelope bounds).
    Close,
    /// Send the shared refusal, then close.
    Refuse(Refused),
}

/// A request body that was not served: what to do, and the framing /
/// envelope / field rule it broke (`None` when the wire layer accepted it
/// and the typed layer refused a value) — for admind's audit event, which
/// records the class only, never an octet (docs/51 §5.7 item 3; Q-340
/// item 6).
/// Spec: docs/50 §3.3, §8.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rejected {
    /// The disposition.
    pub action: Rejection,
    /// The `ipc` rule broken, if the wire layer refused the body.
    pub error: Option<ipc::Error>,
}

/// Decode one request body (as cut by `ipc::FrameReader` under
/// [`crate::REQUEST_LIMIT`]). The password moves from the body into the
/// typed request's zeroizing buffer; the caller wipes the body (the
/// `FrameReader` does on `reset`).
///
/// # Errors
/// [`Rejected`] (module documentation).
///
/// Spec: docs/51 §7.1, §7.6; docs/50 §3.3.
pub fn decode_request(body: &[u8]) -> Result<Request, Rejected> {
    let wire =
        decode_body::<AdminRequest>(ADMIN_CHANNEL, Direction::Request, body).map_err(|error| {
            Rejected {
                action: error.refusal().map_or(Rejection::Close, Rejection::Refuse),
                error: Some(error),
            }
        })?;
    Request::from_wire(wire).map_err(|_| Rejected {
        action: Rejection::Refuse(Refused::Malformed),
        error: None,
    })
}

/// Why a frame could not be encoded (never the peer's fault).
/// Spec: docs/50 §3.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeError {
    /// The typed value has no wire form on this channel.
    Conversion(ConversionError),
    /// The frame would break a bound, or the kind is not in the table.
    Frame(ipc::Error),
}

/// Encode one typed reply as a frame.
///
/// # Errors
/// [`EncodeError`]; admind then answers `Refused{Unavailable}` instead.
///
/// Spec: docs/51 §7.3, §7.6; docs/50 §3.3.
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

/// Encode one typed request as a frame (a client's side). The frame is a
/// zeroizing buffer: it may hold a password.
///
/// # Errors
/// [`EncodeError`].
///
/// Spec: docs/51 §7.6; docs/50 §3.3.
pub fn encode_request(request: &Request) -> Result<EncodedFrame, EncodeError> {
    let wire = request.to_wire().map_err(EncodeError::Conversion)?;
    encode_frame(ADMIN_CHANNEL, Direction::Request, &wire).map_err(EncodeError::Frame)
}

/// Why a reply body was not accepted (a client's side).
/// Spec: docs/50 §3.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyError {
    /// The body did not decode at the ipc layer.
    Malformed(ipc::Error),
    /// A value of the reply did not pass its strict decoder.
    Conversion(ConversionError),
}

/// Decode one reply body (a client's side): one of this channel's replies,
/// or the shared refusal — with the same strictness as a request (docs/50
/// §3.3).
///
/// # Errors
/// [`ReplyError`].
///
/// Spec: docs/51 §7.6; docs/50 §3.3; A-59.
pub fn decode_reply(body: &[u8]) -> Result<ipc::Reply<Reply>, ReplyError> {
    match ipc::decode_reply::<AdminReply>(ADMIN_CHANNEL, body).map_err(ReplyError::Malformed)? {
        ipc::Reply::Refused(refused) => Ok(ipc::Reply::Refused(refused)),
        ipc::Reply::Message(wire) => Reply::from_wire(&wire)
            .map(ipc::Reply::Message)
            .map_err(ReplyError::Conversion),
    }
}
