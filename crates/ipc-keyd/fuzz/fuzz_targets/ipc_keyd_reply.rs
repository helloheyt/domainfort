#![no_main]
//! Fuzz target for the keyd channel's client-side reply decoding: the first
//! input octet picks the operation that was called (one of keyd's sixteen),
//! the rest is the reply body, decoded as `KeydClient` decodes it —
//! `ipc::decode_reply` (the shared `Refused` routed first, A-59), then
//! `Answer::from_wire` (the reply must belong to the operation; every
//! Kerberos value through krb-proto's strict decoder).
//!
//! AGENTS.md §6 / docs/50 §9 (R50-19: "`ipc_keyd_reply` (the client decodes
//! replies)"); docs/50 §3.3 ("replies are decoded with the same
//! strictness"): never a panic; whatever decodes re-encodes to exactly the
//! input.
//!
//! Spec: docs/50 §3.3, §3.4, §9; R50-4; A-59.

use ipc::{decode_reply, encode_refused, Reply};
use ipc_keyd::{encode_answer, Answer, KeydReply, KEYD_CHANNEL};
use keyd::Operation;
use libfuzzer_sys::fuzz_target;

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
                let frame = encode_answer(&answer).expect("a decoded answer re-encodes");
                assert_eq!(frame.body(), body, "canonical round trip");
            }
        }
        Err(_) => {}
    }
});
