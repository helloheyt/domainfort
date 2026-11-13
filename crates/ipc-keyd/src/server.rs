//! The server side: one request body in, one reply frame (or a close) out.
//!
//! [`dispatch`] is a pure function of the keyd engine, the caller identity
//! the **transport** established, the keyd daemon's **own clock**, and the
//! request body. No socket, queue or thread lives here — that is the
//! keyd-daemon (task P7), which also maps peer credentials to a
//! [`CallerId`] (docs/50 §3.2), answers `Busy` when its bounded queue is full
//! (§3.6) and keeps one request in flight per connection (R50-7).
//!
//! Spec: docs/50 §3.2, §3.3, §3.4, §3.5, R50-3, R50-5, R50-7; docs/10 §2;
//! A-56; A-59.

use crate::channel::KEYD_CHANNEL;
use crate::typed::{Answer, Call, ConversionError};
use crate::wire::KeydRequest;
use core::fmt;
use ipc::{decode_body, encode_frame, encode_refused, Direction, EncodedFrame, Refused};
use keyd::{AuditSink, CallerId, EntropySource, KeyStore, Keyd, TgsFastRequest};
use krb_proto::KerberosTime;

/// What the connection does with the result of one request.
///
/// `Debug` shows only frame lengths (an encoded frame may carry nothing
/// secret in this direction, but it is never printed either way).
///
/// Spec: docs/50 §3.3 (bad prefix, wrong magic, unknown kind ⇒ close without
/// a reply; wrong version ⇒ `Refused{VersionMismatch}` + close; malformed ⇒
/// `Malformed` + close).
pub enum Dispatch {
    /// Send the reply; the connection stays open for the next request.
    Reply(EncodedFrame),
    /// Send the reply (a transport refusal), then close the connection.
    ReplyAndClose(EncodedFrame),
    /// Close the connection without a reply.
    Close,
}

impl fmt::Debug for Dispatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Dispatch::Reply(frame) => f.debug_tuple("Reply").field(&frame.len()).finish(),
            Dispatch::ReplyAndClose(frame) => {
                f.debug_tuple("ReplyAndClose").field(&frame.len()).finish()
            }
            Dispatch::Close => f.write_str("Close"),
        }
    }
}

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

/// Perform one decoded call on `keyd` as `caller` at `now`, returning keyd's
/// outcome unchanged.
///
/// `caller` is the identity of the connection (peer credentials mapped to a
/// role by the daemon, docs/50 §3.2) and `now` is the daemon's own clock
/// (R50-5) — never values from the request, which has no field for either.
///
/// Spec: docs/10 §2 (`CallerId` "derived from the connected peer … not
/// claimed by the caller"), §4-§7א; docs/50 R50-3, R50-5; A-56.
pub fn execute<S: KeyStore, A: AuditSink, E: EntropySource>(
    keyd: &mut Keyd<S, A, E>,
    caller: CallerId,
    now: KerberosTime,
    call: Call,
) -> Answer {
    let caller = &caller;
    let now = &now;
    match call {
        Call::VerifyPreauth {
            client,
            padata,
            armor,
        } => Answer::VerifyPreauth(keyd.verify_preauth(caller, &client, &padata, armor, now)),
        Call::IssueAsRep {
            client,
            krbtgt,
            proof,
            armor,
            template,
        } => Answer::IssueAsRep(
            keyd.issue_as_rep(caller, &client, &krbtgt, &proof, armor, &template, now),
        ),
        Call::OpenFastArmor {
            krbtgt,
            armored_req,
            outer_req_body,
        } => Answer::OpenFastArmor(keyd.open_fast_armor(
            caller,
            &krbtgt,
            &armored_req,
            &outer_req_body,
            now,
        )),
        Call::OpenAndVerifyTgt {
            krbtgt,
            ap_req,
            req_body,
            fast,
        } => {
            let fast = fast.as_ref().map(|fast| TgsFastRequest {
                ap_req_octets: &fast.ap_req_octets,
                armored_req: &fast.armored_req,
            });
            Answer::OpenAndVerifyTgt(
                keyd.open_and_verify_tgt(caller, &krbtgt, &ap_req, &req_body, fast, now),
            )
        }
        Call::IssueTgsRep {
            service,
            ctx,
            template,
        } => Answer::IssueTgsRep(keyd.issue_tgs_rep(caller, &service, &ctx, &template, now)),
        Call::SealFastError {
            conversation,
            error,
            padata,
        } => {
            Answer::SealFastError(keyd.seal_fast_error(caller, &conversation, &error, &padata, now))
        }
        Call::OpenAndVerifyServiceTicket {
            service,
            ap_req_octets,
        } => Answer::OpenAndVerifyServiceTicket(keyd.open_and_verify_service_ticket(
            caller,
            &service,
            &ap_req_octets,
            now,
        )),
        Call::SetSecret {
            handle,
            binding,
            password,
            salt,
        } => Answer::SetSecret(keyd.set_secret(
            caller,
            &handle,
            &binding,
            password.into_inner(),
            &salt,
            now,
        )),
        Call::VerifySecret { handle, candidate } => {
            Answer::VerifySecret(keyd.verify_secret(caller, &handle, candidate.into_inner(), now))
        }
        Call::CreateKey { handle, binding } => {
            Answer::CreateKey(keyd.create_key(caller, &handle, &binding, now))
        }
        Call::RotateKey { handle } => Answer::RotateKey(keyd.rotate_key(caller, &handle, now)),
        Call::RotateKrbtgt { krbtgt, approval } => {
            Answer::RotateKrbtgt(keyd.rotate_krbtgt(caller, &krbtgt, &approval, now))
        }
        Call::RetireKvno { handle, kvno } => {
            Answer::RetireKvno(keyd.retire_kvno(caller, &handle, kvno, now))
        }
        Call::DestroyKeySet { handle } => {
            Answer::DestroyKeySet(keyd.destroy_key_set(caller, &handle, now))
        }
        Call::DescribeConfig => Answer::DescribeConfig(keyd.describe_config(caller, now)),
        Call::Ping => Answer::Ping(keyd.ping(caller, now)),
    }
}

/// Encode an answer as a reply frame.
/// Spec: docs/50 §3.3, §3.4.
pub fn encode_answer(answer: &Answer) -> Result<EncodedFrame, ConversionError> {
    let reply = answer.to_wire()?;
    encode_frame(KEYD_CHANNEL, Direction::Reply, &reply).map_err(|_| ConversionError::KerberosValue)
}

/// A transport refusal frame, then close; a refusal that cannot even be
/// encoded (never, given ipc's `MIN_BODY_LIMIT`) closes without a reply.
/// Spec: docs/50 §3.3; A-59.
fn refuse(refused: Refused) -> Dispatch {
    match encode_refused(KEYD_CHANNEL, refused) {
        Ok(frame) => Dispatch::ReplyAndClose(frame),
        Err(_) => Dispatch::Close,
    }
}

/// Serve one request body of the keyd channel.
///
/// 1. [`decode_request`]; a rejected body is answered as
///    [`Rejection::refusal`] says (`Malformed` / `VersionMismatch` then
///    close, or close without a reply). keyd is not called.
/// 2. [`execute`] with `caller` (from the transport) and `now` (the
///    daemon's clock).
/// 3. The answer is encoded as the operation's reply. A reply that cannot be
///    encoded (krb-proto refuses keyd's own output, or the reply bound is
///    passed) is answered `Refused::Unavailable` and the connection closes:
///    keyd did not deliver the result (fail closed; the client reports
///    `Unavailable`, never `Denied`).
///
/// Spec: docs/50 §3.2 ("`CallerId { uid, role }` built once per connection
/// and handed to every operation"), §3.3, §3.4, §3.5 (R50-5: "keyd-daemon
/// fills `now` of every operation from its own system clock; the field does
/// not exist on the wire"), §3.7; docs/10 §2; A-56; A-59.
pub fn dispatch<S: KeyStore, A: AuditSink, E: EntropySource>(
    keyd: &mut Keyd<S, A, E>,
    caller: CallerId,
    now: KerberosTime,
    request_body: &[u8],
) -> Dispatch {
    let call = match decode_request(request_body) {
        Ok(call) => call,
        Err(rejection) => {
            return match rejection.refusal() {
                Some(refused) => refuse(refused),
                None => Dispatch::Close,
            }
        }
    };
    let answer = execute(keyd, caller, now, call);
    match encode_answer(&answer) {
        Ok(frame) => Dispatch::Reply(frame),
        Err(_) => refuse(Refused::Unavailable),
    }
}
