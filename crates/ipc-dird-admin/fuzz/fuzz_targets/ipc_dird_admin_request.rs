#![no_main]
//! Fuzz target for the admin channel's server-side request decoding:
//! `ipc::decode_body` (bound, magic, exact version, closed kind table,
//! fields, no trailing octet), then `Request::from_wire` (UTF-8 text, one
//! spelling of "never") — the path `ipc_dird_admin::decode_request` takes in
//! dird.
//!
//! AGENTS.md §6 / docs/50 §9 / docs/51 §7.5: arbitrary bytes → decoder;
//! never a panic, bounded allocation. Whatever decodes must re-encode to
//! exactly the input (docs/50 §3.3: "a single encoding per value"), and a
//! rejection maps to the refusal table (a shared `Refused`, or a close
//! without a reply).
//!
//! Spec: docs/51 §7.1-§7.3, §7.5; docs/50 §3.3, §9; A-59.

use ipc::{decode_body, encode_frame, Direction};
use ipc_dird_admin::{decode_request, AdminRequest, Request, ADMIN_CHANNEL};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    match decode_body::<AdminRequest>(ADMIN_CHANNEL, Direction::Request, data) {
        Ok(wire) => {
            let again = encode_frame(ADMIN_CHANNEL, Direction::Request, &wire)
                .expect("a decoded request re-encodes");
            assert_eq!(again.body(), data, "canonical wire round trip");
            if let Ok(request) = Request::from_wire(&wire) {
                let typed = request.to_wire().expect("a typed request re-encodes");
                assert_eq!(typed, wire, "canonical typed round trip");
            }
        }
        Err(error) => {
            // Either a shared refusal or a close; never anything else.
            let _ = error.refusal();
        }
    }
    // The server's entry point over the same octets.
    let _ = decode_request(data);
});
