#![forbid(unsafe_code)]
//! `ipc-keyd-server`: the server side of the keyd channel — one request body
//! in, one reply frame (or a close) out — against the real, in-process keyd.
//!
//! The server side is a pure function of the keyd engine, the caller identity
//! the **transport** established, the keyd daemon's **own clock**, and the
//! request body. No socket, queue or thread lives here — that is the
//! keyd-daemon (task P7), which also maps peer credentials to a
//! [`CallerId`] (docs/50 §3.2), answers `Busy` when its bounded queue is full
//! (§3.6) and keeps one request in flight per connection (R50-7).
//!
//! # Why a separate crate (D182; decision A-63)
//!
//! [`execute`], [`execute_acknowledged`] and `dispatch` call keyd's operations, so they need the
//! real `keyd::Keyd` — and with it the crypto profile (`krb-crypto`), which
//! only the keyd process may link (D182). The rest of the channel — the
//! message set, the codec, `ipc_keyd::decode_request` /
//! `ipc_keyd::encode_answer` and the client (`KeydClient`, `IpcKeyd`) —
//! stays in `ipc-keyd`, which depends only on the crypto-free `keyd-types`.
//! A separate crate, not a cargo feature, because cargo unifies the features
//! of a package across one build: a `server` feature enabled for the
//! keyd-daemon would also be enabled for the kdc-daemon built with it, and
//! put keyd and krb-crypto back into the kdc process. Only the keyd-daemon
//! depends on this crate. `keyd-types/tests/no_crypto_dependency.rs` checks
//! that `ipc-keyd` (the client side) has no krb-crypto in its normal
//! dependencies.
//!
//! Moved unchanged from `ipc-keyd`'s `server` module (task P5).
//!
//! # Running a call: plain, or with the proof of its acknowledged intent
//!
//! (docs/52 §3.11 R6, decision A-102.) [`classify`] decides, from keyd's
//! own authorization step, whether a call needs its intent acknowledged by
//! auditd first (module `intent`). A plain call runs with [`execute`]; a
//! key-state change (or a loosening) that keyd admits is a [`KeyStateCall`]
//! and runs **only** with [`execute_acknowledged`], which takes an
//! `ipc_audit_client::AckedIntent<KeyStateCall>` by value — obtainable only
//! from the daemon's `ipc_audit_client::AuditGate` after auditd acknowledged
//! that
//! call's intent record. [`execute`] checks again when it runs and refuses
//! ([`NotRun`]) to run a call that now needs the proof.
//!
//! The unaudited `dispatch` (one body in, one frame out, keyd run directly)
//! exists only with the `loopback` feature, which no daemon enables: it is
//! the in-process loopback of the tests (this crate's, and keyd-daemon's
//! comparison of its engine with it) — not a path a production build has
//! (docs/52 C18).
//!
//! # keyd's record on the audit channel (task IB1)
//!
//! [`keyd_record`] converts keyd's `AuditRecord` to the audit channel's
//! `ipc_audit::KeydRecord` (module `audit_convert`) — here, on the side that
//! already links keyd, since task IB1 moved it out of an optional feature
//! of crate ipc-audit (class C40; docs/questions/Q-851, decision A-144).
//!
//! # Provenance
//!
//! Written only from this project's decided design — docs/50 (§3.2-§3.7,
//! R50-3, R50-5, R50-7; §10), docs/10 §2, decisions A-56, A-59 — and the
//! code of this project's crates ipc, ipc-keyd and keyd. No other
//! implementation, serializer or RPC framework was consulted or recalled
//! (AGENTS.md §1-3).
//!
//! Spec: docs/50 §3.2, §3.3, §3.4, §3.5, R50-3, R50-5, R50-7; docs/10 §2;
//! A-56; A-59; D182; A-63; docs/52 §3.11 R6 (A-102); Decision: A-144;
//! Q-851 (task IB1).

mod audit_convert;
mod intent;

pub use audit_convert::keyd_record;
pub use intent::{classify, Classified, KeyStateCall, KeyStateIntent, PlainCall};

use core::fmt;
use ipc::EncodedFrame;
use ipc_audit_client::AckedIntent;
use ipc_keyd::{Answer, Call, DescribedConfig};
use keyd::{AuditSink, CallerId, EntropySource, KeyStore, Keyd, TgsFastRequest};
use krb_proto::KerberosTime;
#[cfg(feature = "loopback")]
use {
    ipc::{encode_refused, Refused},
    ipc_keyd::{decode_request, encode_answer, KEYD_CHANNEL},
};

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

/// A plain call was not run: keyd's authorization step now admits it as a
/// change that needs an acknowledged intent (its classification went
/// stale). keyd was not called; the daemon answers `Refused::Unavailable`
/// ("not done", A-86).
/// Spec: docs/52 §3.11 R6 (a); docs/questions/Q-365 (A-88).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotRun;

/// Run a [`PlainCall`] on `keyd` (module documentation): keyd's outcome
/// unchanged — after checking that the call still needs no acknowledged
/// intent.
///
/// # Errors
/// [`NotRun`]: keyd's authorization step now admits it as a key-state
/// change or a loosening — it runs only with its proof
/// ([`execute_acknowledged`]); keyd was not called.
///
/// Spec: docs/52 §3.11 R6 (a); docs/10 §2; docs/50 R50-3, R50-5; A-56;
/// docs/questions/Q-365 (A-88).
pub fn execute<S: KeyStore, A: AuditSink, E: EntropySource>(
    keyd: &mut Keyd<S, A, E>,
    plain: PlainCall,
) -> Result<Answer, NotRun> {
    if !intent::still_plain(keyd, &plain) {
        return Err(NotRun);
    }
    let PlainCall { caller, now, call } = plain;
    Ok(run(keyd, caller, now, call))
}

/// Run a key-state change (or a loosening) whose intent auditd acknowledged:
/// the only way keyd runs one (module documentation). The proof is consumed:
/// one acknowledgement, one change.
/// Spec: docs/52 §3.11 R6 (a); docs/questions/Q-346 (A-86), Q-365 (A-88).
pub fn execute_acknowledged<S: KeyStore, A: AuditSink, E: EntropySource>(
    keyd: &mut Keyd<S, A, E>,
    change: AckedIntent<KeyStateCall>,
) -> Answer {
    let KeyStateCall {
        caller, now, call, ..
    } = change.into_inner();
    run(keyd, caller, now, call)
}

/// Perform one decoded call on `keyd` as `caller` at `now`, returning keyd's
/// outcome unchanged. Private: reached only through [`execute`] (a plain
/// call), [`execute_acknowledged`] (with the proof), and the test-only
/// loopback `dispatch`.
///
/// `caller` is the identity of the connection (peer credentials mapped to a
/// role by the daemon, docs/50 §3.2) and `now` is the daemon's own clock
/// (R50-5) — never values from the request, which has no field for either.
///
/// A described configuration also reports `caller.role` — the role keyd
/// authorized this very call with — beside keyd's description
/// ([`DescribedConfig`]; docs/questions/Q-351, A-87), and so does a
/// successful ping (every role may ping: the probe with which every keyd
/// client verifies its own role on each new connection — task R9,
/// docs/questions/Q-466 item 2, A-102).
///
/// Spec: docs/10 §2 (`CallerId` "derived from the connected peer … not
/// claimed by the caller"), §4-§7א; docs/50 R50-3, R50-5; A-56;
/// docs/questions/Q-351 (A-87).
fn run<S: KeyStore, A: AuditSink, E: EntropySource>(
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
        // R2 (docs/52 §5 item 3): the principal only; keyd derives the key
        // set's purpose from the operation's binding. Q-523: the unbound
        // verification keeps a service context, the operation-bound one
        // none.
        Call::OpenAndVerifyServiceTicket {
            service,
            ap_req_octets,
        } => Answer::OpenAndVerifyServiceTicket(keyd.open_and_verify_service_ticket(
            caller,
            &service,
            &ap_req_octets,
            now,
        )),
        Call::VerifyOperationTicket {
            service,
            operation,
            ap_req_octets,
        } => Answer::VerifyOperationTicket(keyd.verify_operation_ticket(
            caller,
            &service,
            &operation,
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
        // A-102 (docs/52 §4.2): the executions name only dird's decision;
        // keyd runs the registered parameters.
        Call::RotateKey { decision } => Answer::RotateKey(keyd.rotate_key(caller, decision, now)),
        Call::RotateKrbtgt { decision } => {
            Answer::RotateKrbtgt(keyd.rotate_krbtgt(caller, decision, now))
        }
        Call::RetireKvno { decision } => {
            Answer::RetireKvno(keyd.retire_kvno(caller, decision, now))
        }
        Call::DestroyKeySet { decision } => {
            Answer::DestroyKeySet(keyd.destroy_key_set(caller, decision, now))
        }
        // Q-351 (A-87): the role keyd resolved from the peer uid — the one
        // its capability check just used — travels with the description.
        Call::DescribeConfig => {
            Answer::DescribeConfig(keyd.describe_config(caller, now).map(|description| {
                DescribedConfig {
                    description,
                    caller_role: caller.role,
                }
            }))
        }
        // Q-466 item 2 (A-102, task R9): the same role, for every role —
        // the one keyd's capability check just used for this ping.
        Call::Ping => Answer::Ping(keyd.ping(caller, now).map(|()| caller.role)),
        // Task A15a (docs/51 §5.8 option (b)): the lifetime is relative; keyd
        // adds its own `now` — the daemon's clock, never the peer's (R50-5).
        Call::GrantSetSecret {
            kind,
            targets,
            lifetime_secs,
        } => Answer::GrantSetSecret(keyd.grant_set_secret(
            caller,
            kind,
            &targets,
            lifetime_secs,
            now,
        )),
        // A-102 (docs/52 §4.2): dird's decision; the lifetime is relative and
        // keyd adds the daemon's clock (R50-5).
        Call::RegisterDecision {
            id,
            operation,
            approvers,
            lifetime_secs,
        } => Answer::RegisterDecision(keyd.register_decision(
            caller,
            id,
            &operation,
            &approvers,
            lifetime_secs,
            now,
        )),
        Call::SealCeremony => Answer::SealCeremony(keyd.seal_ceremony(caller, now)),
        Call::ListDestroyDecisions { after } => {
            Answer::ListDestroyDecisions(keyd.list_destroy_decisions(caller, after, now))
        }
        // Task K4 (docs/53 §5.5): the change-password operations. The peer
        // and local addresses are the front's kernel's report, carried by
        // dird; `now` is the daemon's clock (R50-5).
        Call::OpenChangePasswordRequest {
            service,
            ap_req_octets,
            krb_priv_octets,
            peer,
            local,
        } => Answer::OpenChangePasswordRequest(keyd.open_change_password_request(
            caller,
            &service,
            &ap_req_octets,
            &krb_priv_octets,
            &peer,
            &local,
            now,
        )),
        Call::CompleteChangePassword { ctx, target } => Answer::CompleteChangePassword(
            keyd.complete_change_password(caller, &ctx, &target, now),
        ),
        Call::SealChangePasswordError { ctx, code } => Answer::SealChangePasswordError(
            keyd.seal_change_password_error(caller, &ctx, code, now),
        ),
        // Task F3 (docs/questions/Q-937 item 6, Q-976): dird takes back a
        // key-operation decision; keyd's clock is the daemon's (R50-5).
        Call::RevokeDecision { id } => {
            Answer::RevokeDecision(keyd.revoke_decision(caller, id, now))
        }
    }
}

/// A transport refusal frame, then close; a refusal that cannot even be
/// encoded (never, given ipc's `MIN_BODY_LIMIT`) closes without a reply.
/// Spec: docs/50 §3.3; A-59.
#[cfg(feature = "loopback")]
fn refuse(refused: Refused) -> Dispatch {
    match encode_refused(KEYD_CHANNEL, refused) {
        Ok(frame) => Dispatch::ReplyAndClose(frame),
        Err(_) => Dispatch::Close,
    }
}

/// Serve one request body of the keyd channel — **without** the audit gate:
/// the in-process loopback of the tests (feature `loopback`, which no
/// daemon enables; module documentation). keyd-daemon serves through its
/// engine (`classify`, the gate, [`execute`] / [`execute_acknowledged`]).
///
/// 1. [`decode_request`]; a rejected body is answered as
///    [`ipc_keyd::Rejection::refusal`] says (`Malformed` / `VersionMismatch`
///    then close, or close without a reply). keyd is not called.
/// 2. keyd runs the call with `caller` (from the transport) and `now` (the
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
/// not exist on the wire"), §3.7; docs/10 §2; A-56; A-59; docs/52 C18.
#[cfg(feature = "loopback")]
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
    let answer = run(keyd, caller, now, call);
    match encode_answer(&answer) {
        Ok(frame) => Dispatch::Reply(frame),
        Err(_) => refuse(Refused::Unavailable),
    }
}
