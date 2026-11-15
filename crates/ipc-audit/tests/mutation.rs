//! Mutation sweep: every single-octet change and every truncation of valid
//! request, reply and event encodings is either refused or decodes to a
//! value that re-encodes to exactly the mutated octets — never a panic,
//! never a second encoding.
//!
//! Source: docs/50 §3.3 (strict decoding; "every decoder checks
//! `encode(decode(b)) == b`"), §9 (codec tests); docs/CLEAN-ROOM.md (bounded
//! parsers; fuzz targets — this sweep is the deterministic complement of
//! fuzz/).

mod common;

use common::*;
use ipc::{Direction, Reply};
use ipc_audit::{
    decode_event, decode_reply, decode_request, encode_event, encode_reply, encode_request,
    event_round_trip_is_canonical, Ack, Append, AuditReply, AuditRequest, EventBytes, EventSource,
    AUDIT_CHANNEL,
};

const MASKS: [u8; 5] = [0x01, 0x02, 0x10, 0x80, 0xFF];

fn sweep(valid: &[u8], check: impl Fn(&[u8])) {
    for position in 0..valid.len() {
        for mask in MASKS {
            let mut mutated = valid.to_vec();
            mutated[position] ^= mask;
            check(&mutated);
        }
    }
    for len in 0..valid.len() {
        check(&valid[..len]);
    }
    let mut longer = valid.to_vec();
    longer.push(0);
    check(&longer);
}

/// Event encodings of every shape.
#[test]
fn event_mutations() {
    for event in all_samples() {
        let valid = encode_event(&event).unwrap();
        sweep(valid.as_bytes(), |bytes| {
            let peeked = ipc_audit::peek_shape(bytes);
            if let Ok(decoded) = decode_event(bytes) {
                assert_eq!(
                    event_round_trip_is_canonical(bytes),
                    Ok(true),
                    "non-canonical accept"
                );
                // auditd's two-octet peek agrees with the decoder (Q-341).
                assert_eq!(peeked, Some(decoded.shape()));
            }
        });
    }
}

/// Request bodies.
#[test]
fn request_mutations() {
    let events: Vec<EventBytes> = all_samples()
        .iter()
        .take(4)
        .map(|e| encode_event(e).unwrap())
        .collect();
    for request in [
        AuditRequest::Append(Append::new(3, events).unwrap()),
        AuditRequest::Ping,
    ] {
        let frame = encode_request(&request).unwrap();
        sweep(frame.body(), |body| {
            if decode_request(body).is_ok() {
                assert_eq!(
                    ipc::round_trip_is_canonical::<AuditRequest>(
                        AUDIT_CHANNEL,
                        Direction::Request,
                        body
                    ),
                    Ok(true)
                );
            }
        });
    }
}

/// Reply bodies.
#[test]
fn reply_mutations() {
    for reply in [
        Reply::Message(AuditReply::Ack(Ack {
            through_seq: 0x0102_0304_0506_0708,
            head_hash: [0x5C; 32],
        })),
        Reply::Message(AuditReply::Pong(EventSource::Kdc)),
        Reply::Refused(ipc::Refused::Unavailable),
    ] {
        let frame = encode_reply(&reply).unwrap();
        sweep(frame.body(), |body| {
            if decode_reply(body).is_ok() {
                assert_eq!(
                    ipc::reply_round_trip_is_canonical::<AuditReply>(AUDIT_CHANNEL, body),
                    Ok(true)
                );
            }
        });
    }
}

/// Pseudo-random inputs (xorshift, seeded here) for all three decoders.
#[test]
fn arbitrary_input_never_panics() {
    let mut state: u64 = 0xD1B5_4A32_D192_ED03;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let prefixes: Vec<Vec<u8>> = vec![
        vec![],
        vec![ipc_audit::EVENT_FORMAT, 1],
        vec![ipc_audit::EVENT_FORMAT, 2],
        vec![ipc_audit::EVENT_FORMAT, 3],
        vec![ipc_audit::EVENT_FORMAT, 4],
        vec![ipc_audit::EVENT_FORMAT, 5],
        vec![ipc_audit::EVENT_FORMAT, 6],
        encode_request(&AuditRequest::Ping).unwrap().body().to_vec(),
    ];
    for round in 0..5_000 {
        let len = (next() % 300) as usize;
        let mut input = prefixes[round % prefixes.len()].clone();
        input.extend((0..len).map(|_| next() as u8));
        let _ = decode_event(&input);
        let _ = decode_request(&input);
        let _ = decode_reply(&input);
    }
}
