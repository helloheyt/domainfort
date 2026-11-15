//! One client connection: one request, one reply, close (RFC 3244 §2: "The
//! protocol consists of a single request message followed by a single reply
//! message").
//!
//! # Order
//!
//! 1. **The TCP header** — "a 4 octet header in network byte order that
//!    precedes the message and specifies the length of the message" (RFC
//!    3244 §2) — is read and bounded with parse-kpasswd's
//!    `tcp_message_length` **before** any buffer for the message exists
//!    (docs/53 §5.1: "0 or > 65,535 ⇒ … before allocation"; docs/CLEAN-ROOM.md).
//!    Out of range ⇒ the KRB-ERROR of `Error::result_code` (MALFORMED) and
//!    close.
//! 2. **The message**: exactly the announced octets, into a zeroizing buffer
//!    of exactly that size (it carries the client's KRB-PRIV). The header
//!    and the message must arrive within `tcp_first_frame_timeout` of the
//!    accept (docs/53 §5.1: "the first frame within 10 s") — otherwise, or
//!    if the client closes first, the connection closes **without a reply**
//!    (there is nothing to answer).
//! 3. **The framing** (`RequestMessage::parse`): version 0xff80 only —
//!    every other version, version 1 included, is answered BAD_VERSION, and
//!    every other framing failure (a version-1 request with a broken length
//!    included) MALFORMED (docs/53 §3.2, R53-2; A-117, A-142;
//!    docs/questions/Q-621 item 3). Then the two messages must be an AP-REQ
//!    and a KRB-PRIV by their identifier octets (crates/ipc-kpasswd's value
//!    types) — else MALFORMED.
//! 4. **dird**: one of [`ipc_kpasswd::MAX_FRONT_CONNECTIONS`] slots, taken at
//!    once or HARDERROR (docs/53 §5.6 step 1: "full ⇒ Busy ⇒ the front
//!    answers HARDERROR"); then `KpasswdClient::change_password` with the
//!    connection's peer and local addresses as the kernel reported them.
//!    keyd's sealed reply is relayed unchanged; dird's unsealed code becomes
//!    the front's KRB-ERROR; dird not serving (every `Unserved`, an unknown
//!    outcome included) ⇒ HARDERROR (docs/53 §5.7).
//! 5. **The reply** is written within `tcp_frame_timeout`, then the stream is
//!    shut down and closed.
//!
//! The front never answers a framing failure with silence on TCP (docs/53
//! §5.1: "TCP ⇒ KRB-ERROR (MALFORMED / BAD_VERSION) and close"); silence
//! belongs to UDP, which has no code path (A-117).
//!
//! Spec: RFC 3244 §2; docs/53 R53-2, R53-3, §5.1, §5.6, §5.7; docs/50 §4.1;
//! tokio 1.54.1 docs.rs: `io::AsyncReadExt::read_exact`,
//! `io::AsyncWriteExt::{write_all, shutdown}`, `time::timeout_at`.

use crate::clock::server_time_now;
use crate::daemon::Context;
use crate::log::{Failure, Noise};
use crate::reply::{result_code_of, sealed_reply};
use core::net::SocketAddr;
use ipc_kpasswd::{
    ApReqOctets, ChangePasswordRequest, KpasswdAnswer, KrbPrivOctets, ObservedAddress,
};
use krb_proto::NonZeroResultCode;
use parse_kpasswd::{tcp_message_length, RequestMessage, TCP_HEADER_LEN};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, timeout_at, Instant};
use zeroize::Zeroizing;

// The channel's bounds are RFC 3244's message bounds as parse-kpasswd frames
// them (crates/ipc-kpasswd states them without linking a Kerberos crate; this
// crate links both and pins them at compile time): one framed request always
// fits one `ChangePassword`, and one `Sealed` always fits one reply message.
// Spec: RFC 3244 §2; docs/53 §5.9.
const _: () = assert!(
    ipc_kpasswd::MAX_RFC3244_MESSAGE as usize == parse_kpasswd::MAX_MESSAGE_LEN
        && ipc_kpasswd::RFC3244_HEADER as usize == parse_kpasswd::MESSAGE_HEADER_LEN
        && ipc_kpasswd::MAX_REQUEST_MESSAGES as usize
            == parse_kpasswd::MAX_MESSAGE_LEN - parse_kpasswd::MESSAGE_HEADER_LEN
        && ipc_kpasswd::MAX_SEALED_MESSAGES as usize + parse_kpasswd::MESSAGE_HEADER_LEN
            <= parse_kpasswd::MAX_MESSAGE_LEN
);

/// What reading the request produced.
enum Read {
    /// The whole message (without the TCP header).
    Message(Zeroizing<Vec<u8>>),
    /// The TCP header was out of range: answer this framing error.
    Framing(parse_kpasswd::Error),
    /// The deadline passed, or the client closed or failed first.
    Incomplete,
}

/// Read the TCP header and the message within `deadline` (module
/// documentation, steps 1–2).
/// Spec: RFC 3244 §2; docs/53 §5.1.
async fn read_request(stream: &mut TcpStream, deadline: Instant) -> Read {
    let mut header = [0u8; TCP_HEADER_LEN];
    match timeout_at(deadline, stream.read_exact(&mut header)).await {
        Ok(Ok(_)) => {}
        Ok(Err(_)) | Err(_) => return Read::Incomplete,
    }
    let length = match tcp_message_length(header) {
        Ok(length) => length,
        Err(error) => return Read::Framing(error),
    };
    // Bounded: `length` ≤ 65,535 (parse-kpasswd `MAX_MESSAGE_LEN`).
    let mut message = Zeroizing::new(vec![0u8; length]);
    match timeout_at(deadline, stream.read_exact(&mut message)).await {
        Ok(Ok(_)) => Read::Message(message),
        Ok(Err(_)) | Err(_) => Read::Incomplete,
    }
}

/// The reply to one whole message (module documentation, steps 3–4), or
/// `None` (close without a reply — the clock or an encoder failed: fail
/// closed).
/// Spec: RFC 3244 §2; docs/53 §5.1, §5.6, §5.7.
async fn answer(
    message: &[u8],
    peer: SocketAddr,
    local: SocketAddr,
    context: &Context,
) -> Option<Vec<u8>> {
    let krb_error = |code: NonZeroResultCode| {
        server_time_now().and_then(|time| context.encoder.krb_error(code, time))
    };
    let request = match RequestMessage::parse(message) {
        Ok(request) => request,
        Err(error) => {
            // Noise: docs/53 §9 ("malformed framing, version").
            if error.result_code() == NonZeroResultCode::BadVersion {
                context.noise(Noise::BadVersion);
            } else {
                context.noise(Noise::Malformed);
            }
            return krb_error(error.result_code());
        }
    };
    let forward = ApReqOctets::new(request.ap_req()).and_then(|ap_req| {
        KrbPrivOctets::new(request.krb_priv()).and_then(|krb_priv| {
            ChangePasswordRequest::new(
                ap_req,
                krb_priv,
                ObservedAddress::new(peer.ip()),
                ObservedAddress::new(local.ip()),
            )
        })
    });
    let Some(forward) = forward else {
        context.noise(Noise::Malformed);
        return krb_error(NonZeroResultCode::Malformed);
    };
    let Ok(_slot) = context.dird_slots.try_acquire() else {
        // Noise: refused for the front's own full capacity (docs/questions/
        // Q-961 item 3's "refused", Q-988).
        context.noise(Noise::DirdBusy);
        return krb_error(NonZeroResultCode::HardError);
    };
    match context.client.change_password(&forward).await {
        Ok(KpasswdAnswer::Sealed(sealed)) => match sealed_reply(&sealed) {
            Some(reply) => Some(reply),
            None => krb_error(NonZeroResultCode::HardError),
        },
        Ok(KpasswdAnswer::Unsealed(code)) => krb_error(result_code_of(code)),
        Err(_) => {
            // Not noise: dird's failure (docs/questions/Q-961 item 3, Q-988).
            context.failure(Failure::DirdNotServing);
            krb_error(NonZeroResultCode::HardError)
        }
    }
}

/// Serve one accepted connection (module documentation). `accepted` is when
/// the connection was accepted; `local` its local address.
/// Spec: RFC 3244 §2; docs/53 §5.1, §5.6, §5.7.
pub(crate) async fn run(
    mut stream: TcpStream,
    peer: SocketAddr,
    local: SocketAddr,
    context: Arc<Context>,
    accepted: Instant,
) {
    let deadline = accepted + context.timeouts.first_frame;
    let reply = match read_request(&mut stream, deadline).await {
        Read::Message(message) => answer(&message, peer, local, &context).await,
        Read::Framing(error) => {
            context.noise(Noise::Malformed);
            server_time_now().and_then(|time| context.encoder.krb_error(error.result_code(), time))
        }
        Read::Incomplete => {
            // Noise: a connection closed at the front's layer (docs/53 §9;
            // docs/questions/Q-988).
            context.noise(Noise::TimedOut);
            None
        }
    };
    let Some(reply) = reply else {
        return;
    };
    match timeout(context.timeouts.reply_write, stream.write_all(&reply)).await {
        Ok(Ok(())) => {
            let _ = timeout(context.timeouts.reply_write, stream.shutdown()).await;
        }
        Ok(Err(_)) | Err(_) => context.noise(Noise::TimedOut),
    }
}
