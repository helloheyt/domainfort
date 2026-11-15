#![no_main]
//! Fuzz target for the keyd channel's client-side reply decoding: the first
//! input octet picks the operation that was called (one of keyd's
//! twenty-four — the three change-password operations of task K4 included;
//! `grant_set_secret`, task A15a, included: its success reply
//! carries no payload; and A-102's `register_decision`, `seal_ceremony`,
//! `list_destroy_decisions`, whose page is bounded by `MAX_DESTROY_PAGE`),
//! the rest is the reply body, decoded as `KeydClient` decodes it —
//! `ipc::decode_reply` (the shared `Refused` routed first, A-59), then
//! `Answer::from_wire` (the reply must belong to the operation; every
//! Kerberos value through krb-proto's strict decoder).
//!
//! docs/CLEAN-ROOM.md / docs/50 §9 (R50-19: "`ipc_keyd_reply` (the client decodes
//! replies)"); docs/50 §3.3 ("replies are decoded with the same
//! strictness"): never a panic; whatever decodes re-encodes to exactly the
//! input. A decoded `DescribeConfig` reply carries the caller role as its
//! last octet, from the closed table 0x01-0x04 (docs/questions/Q-351,
//! A-87): every other value was refused. A decoded `Ping` reply is the
//! envelope and exactly that one octet (task R9, docs/questions/Q-466 item
//! 2): the caller role, from the same table. A decoded `ServiceContext`
//! reply ends in the one-value octet `00` (no operation: the unbound
//! verification), and a decoded `OperationTicket` reply ends in the 32
//! digest octets it names (Q-523: the operation-bound answer, no context).
//! A decoded `ChangePasswordContext` reply (task K4) ends in its verdict's
//! code, from the closed table 0x01-0x05; a decoded `SealedReply` carries a
//! strict AP-REP and a strict KRB-PRIV.
//!
//! Written, not run (PENDING-OWNER P-1).
//!
//! Spec: docs/50 §3.3, §3.4, §9; R50-4; A-59; docs/questions/Q-351 (A-87),
//! Q-466 (A-102), Q-523.

use ipc::{decode_reply, encode_refused, Reply};
use ipc_keyd::channel::MAX_DESTROY_PAGE;
use ipc_keyd::{encode_answer, Answer, KeydReply, KEYD_CHANNEL};
use keyd::{Operation, Role};
use libfuzzer_sys::fuzz_target;

/// The wire code of a caller role (the closed table of crates/ipc-keyd
/// wire.rs; Q-351, Q-466).
fn role_code(role: Role) -> u8 {
    match role {
        Role::Kdc => 0x01,
        Role::Directory => 0x02,
        Role::Admin => 0x03,
        Role::Ldap => 0x04,
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, body)) = data.split_first() else {
        return;
    };
    let operation = Operation::ALL[usize::from(selector) % Operation::ALL.len()];
    match decode_reply::<KeydReply>(KEYD_CHANNEL, body) {
        Ok(Reply::Refused(refused)) => {
            let frame = encode_refused(KEYD_CHANNEL, refused).expect("a refusal encodes");
            assert_eq!(frame.body(), body, "canonical refusal");
        }
        Ok(Reply::Message(reply)) => {
            if let Ok(answer) = Answer::from_wire(operation, reply) {
                assert_eq!(answer.operation(), operation);
                if let Answer::DescribeConfig(Ok(described)) = &answer {
                    let code = role_code(described.caller_role);
                    assert_eq!(body.last(), Some(&code), "the caller role, last");
                }
                if let Answer::Ping(Ok(caller_role)) = &answer {
                    // Envelope (4 octets) ‖ the caller role (Q-466 item 2).
                    assert_eq!(body.len(), 5, "the role is the whole payload");
                    assert_eq!(body.last(), Some(&role_code(*caller_role)));
                }
                if let Answer::GrantSetSecret(Ok(())) = &answer {
                    // The registered grant answers with its kind alone: the
                    // reply carries no payload (docs/questions/Q-450 item 9).
                    let empty = encode_answer(&Answer::GrantSetSecret(Ok(())))
                        .expect("a unit answer encodes");
                    assert_eq!(empty.body(), body, "no payload");
                }
                if let Answer::OpenAndVerifyServiceTicket(Ok(_)) = &answer {
                    assert_eq!(body.last(), Some(&0x00), "bound to no operation");
                }
                if let Answer::VerifyOperationTicket(Ok(ticket)) = &answer {
                    let digest = ticket.operation.as_bytes();
                    assert!(body.ends_with(digest), "the verified digest, last");
                }
                if let Answer::OpenChangePasswordRequest(Ok(context)) = &answer {
                    let code = match context.verdict {
                        keyd::ChangePasswordVerdict::Acceptable => 0x01,
                        keyd::ChangePasswordVerdict::Malformed => 0x02,
                        keyd::ChangePasswordVerdict::InitialFlagNeeded => 0x03,
                        keyd::ChangePasswordVerdict::SetNotSupported => 0x04,
                        keyd::ChangePasswordVerdict::PasswordRefused => 0x05,
                    };
                    assert_eq!(body.last(), Some(&code), "the verdict, last");
                }
                if let Answer::ListDestroyDecisions(Ok(page)) = &answer {
                    assert!(
                        page.entries.len() <= MAX_DESTROY_PAGE as usize,
                        "page bound"
                    );
                }
                let frame = encode_answer(&answer).expect("a decoded answer re-encodes");
                assert_eq!(frame.body(), body, "canonical round trip");
            }
        }
        Err(_) => {}
    }
});
