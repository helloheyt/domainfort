//! The server side's keyd-free half: decoding one request body
//! ([`decode_request`]) and encoding one answer ([`encode_answer`]).
//!
//! The half that calls keyd — `execute` and `dispatch`, which need the real
//! `keyd::Keyd` — lives in the `ipc-keyd-server` crate, so that this crate
//! (the client side, linked by the kdc) depends only on the crypto-free
//! `keyd-types` and never on krb-crypto (D182; decision A-63). Only the
//! keyd-daemon depends on `ipc-keyd-server`; it also maps peer credentials
//! to a `CallerId` (docs/50 §3.2), answers `Busy` when its bounded queue is
//! full (§3.6) and keeps one request in flight per connection (R50-7).
//!
//! Spec: docs/50 §3.2, §3.3, §3.4, §3.5, R50-3, R50-5, R50-7; docs/10 §2;
//! A-56; A-59; D182; A-63.

use crate::channel::KEYD_CHANNEL;
use crate::typed::{Answer, Call, ConversionError};
use crate::wire::KeydRequest;
use ipc::{decode_body, encode_frame, Direction, EncodedFrame, Refused};

/// Why a request body was rejected before keyd saw it. Carries no octet of
/// the request.
/// Spec: docs/50 §3.3, §8.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    /// The ipc layer refused the body (framing, envelope, a field rule).
    Ipc(ipc::Error),
    /// A Kerberos value, password or salt inside it was refused.
    Value(ConversionError),
}

impl Rejection {
    /// The transport refusal to answer with before closing, or `None` to
    /// close without a reply.
    ///
    /// * ipc errors follow ipc's own table ([`ipc::Error::refusal`]):
    ///   version mismatch → `VersionMismatch`; payload errors → `Malformed`;
    ///   bad prefix, wrong magic, unknown kind → no reply.
    /// * A value krb-proto (or the UTF-8 check) refused → `Malformed`: the
    ///   frame was well-formed at the ipc layer but its content is not.
    ///
    /// Spec: docs/50 §3.3 ("`Malformed` + close"); docs/questions/Q-225
    /// item 3 (A-59).
    #[must_use]
    pub const fn refusal(self) -> Option<Refused> {
        match self {
            Rejection::Ipc(error) => error.refusal(),
            Rejection::Value(_) => Some(Refused::Malformed),
        }
    }
}

/// Decode one request body completely: the ipc layer (bound, magic, exact
/// version, closed kind table, fields, no trailing octet), then every
/// Kerberos value through krb-proto's strict decoder, passwords and salt as
/// UTF-8. No keyd state is touched.
///
/// Spec: docs/50 §3.3, §3.4; docs/questions/Q-225 item 6.
pub fn decode_request(body: &[u8]) -> Result<Call, Rejection> {
    let request: KeydRequest =
        decode_body(KEYD_CHANNEL, Direction::Request, body).map_err(Rejection::Ipc)?;
    Call::from_wire(request).map_err(Rejection::Value)
}

/// Encode an answer as a reply frame.
/// Spec: docs/50 §3.3, §3.4.
pub fn encode_answer(answer: &Answer) -> Result<EncodedFrame, ConversionError> {
    let reply = answer.to_wire()?;
    encode_frame(KEYD_CHANNEL, Direction::Reply, &reply).map_err(|_| ConversionError::KerberosValue)
}
