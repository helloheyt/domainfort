#![no_main]
//! Fuzz target for the administrators' channel's server-side request
//! decoding: `ipc::decode_body` (bound, magic, exact version, closed kind
//! table, fields — dird's layouts for the forwarded operations — no
//! trailing octet), then `Request::from_wire` (dird's typed decoders, the
//! password as UTF-8 moved into a zeroizing buffer) — the path
//! `ipc_admin::decode_request` takes in admind.
//!
//! AGENTS.md §6 / docs/50 §9: arbitrary bytes → decoder; never a panic,
//! bounded allocation. Whatever decodes must re-encode to exactly the input
//! (docs/50 §3.3: "a single encoding per value"), and a rejection maps to
//! the refusal table (a shared `Refused`, or a close without a reply).
//!
//! Task A10 added the forwarded key-operation requests. keyadm's three
//! requests (`0x10`–`0x12`) were retired by A-102: nothing decodes with one
//! of those kinds (admind no longer forwards anything for keyadm, N2).
//!
//! Spec: docs/51 §6, §7.1, §7.2, §7.6; docs/50 §3.3, §9; A-59;
//! docs/questions/Q-422, Q-460 (A-102).

use ipc::{decode_body, encode_frame, Direction};
use ipc_admin::{decode_request, encode_request, AdminRequest, Request, ADMIN_CHANNEL};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    match decode_body::<AdminRequest>(ADMIN_CHANNEL, Direction::Request, data) {
        Ok(wire) => {
            let again = encode_frame(ADMIN_CHANNEL, Direction::Request, &wire)
                .expect("a decoded request re-encodes");
            assert_eq!(again.body(), data, "canonical wire round trip");
            assert!(!ipc_admin::channel::request_kind::RETIRED.contains(&data[3]));
            if let Ok(request) = Request::from_wire(wire) {
                let typed = encode_request(&request).expect("a typed request re-encodes");
                assert_eq!(typed.body(), data, "canonical typed round trip");
            }
        }
        Err(error) => {
            // Either a shared refusal or a close; never anything else.
            let _ = error.refusal();
        }
    }
    // admind's entry point over the same octets.
    let _ = decode_request(data);
});
