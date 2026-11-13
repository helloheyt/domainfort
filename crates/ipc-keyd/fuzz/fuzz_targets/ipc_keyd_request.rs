#![no_main]
//! Fuzz target for the keyd channel's server-side request decoding:
//! `ipc_keyd::decode_request` (the ipc layer — bound, magic, exact version,
//! closed kind table, fields, no trailing octet — then every Kerberos value
//! through krb-proto's strict decoder, passwords and salt as UTF-8).
//!
//! AGENTS.md §6 / docs/50 §9 (R50-19): arbitrary bytes → decoder; never a
//! panic, bounded allocation. Whatever decodes must re-encode to exactly the
//! input (docs/50 §3.3: "a single encoding per value"; "every decoder checks
//! `encode(decode(b)) == b`"), and a rejection maps to the refusal table (a
//! shared `Refused`, or a close without a reply).
//!
//! keyd itself is not called here: `dispatch` adds only `execute` (keyd's
//! own operations, reached through the kdc fuzz target) and the reply
//! encoding.
//!
//! Spec: docs/50 §3.3, §3.4, §9; R50-4; A-59.

use ipc::{encode_frame, Direction};
use ipc_keyd::{decode_request, KEYD_CHANNEL};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|body: &[u8]| {
    match decode_request(body) {
        Ok(call) => {
            let request = call.to_wire().expect("a decoded call re-encodes");
            let frame = encode_frame(KEYD_CHANNEL, Direction::Request, &request)
                .expect("a decoded request fits its own bound");
            assert_eq!(frame.body(), body, "canonical round trip");
        }
        Err(rejection) => {
            // A shared refusal code, or `None`: close without a reply.
            let _ = rejection.refusal();
        }
    }
});
