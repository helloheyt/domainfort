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
//! Task A10 added the key-operation kinds (`RequestKeyOperation`,
//! `Approve`). keyadm's `FetchApproved` / `Complete` /
//! `ListPendingDestruction` (`0x10`–`0x12`) were retired by A-102: nothing
//! decodes with one of those kinds.
//!
//! R2 (docs/52 §5, A-102): every request that decodes has an operation
//! digest (the application data its AP-REQs are bound to), the same from
//! the typed and the wire form. Written, not run (PENDING-OWNER P-1).
//!
//! Spec: docs/51 §6, §7.1-§7.3, §7.5; docs/50 §3.3, §9; A-59;
//! docs/questions/Q-422, Q-460 (A-102); docs/52 §5 item 1.

use ipc::{decode_body, encode_frame, Direction};
use ipc_dird_admin::{
    decode_request, operation_digest, wire_operation_digest, AdminRequest, Request, ADMIN_CHANNEL,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    match decode_body::<AdminRequest>(ADMIN_CHANNEL, Direction::Request, data) {
        Ok(wire) => {
            let again = encode_frame(ADMIN_CHANNEL, Direction::Request, &wire)
                .expect("a decoded request re-encodes");
            assert_eq!(again.body(), data, "canonical wire round trip");
            assert!(!ipc_dird_admin::channel::request_kind::RETIRED.contains(&data[3]));
            if let Ok(request) = Request::from_wire(&wire) {
                let typed = request.to_wire().expect("a typed request re-encodes");
                assert_eq!(typed, wire, "canonical typed round trip");
                // R2 (docs/52 §5): every decoded operation has its operation
                // digest, and the typed and wire forms give the same one.
                if let Request::Operation { operation, .. } = &request {
                    let digest = operation_digest(operation).expect("a decoded operation has a digest");
                    if let AdminRequest::Operation { operation: w, .. } = &wire {
                        assert_eq!(wire_operation_digest(w).ok(), Some(digest));
                    }
                }
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
