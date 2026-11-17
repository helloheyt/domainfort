#![no_main]
//! Fuzz target for the payload of the keyd channel's
//! `install_attestation_key` request (kind `0x1A`, task PN9): the input is
//! placed behind a fixed, valid envelope (magic, version, kind), so every
//! mutation exercises the key field — `secret bytes<32>`, its length exactly
//! `ATTESTATION_KEY_OCTETS` — and then the typed layer (the all-zero key
//! refused).
//!
//! docs/CLEAN-ROOM.md / docs/50 §9 (R50-19): arbitrary bytes → decoder; never a
//! panic, bounded allocation (the length is checked against the 32-octet
//! bound before any octet is copied). Whatever decodes is an
//! `install_attestation_key` whose key has exactly 32 octets, not all zero,
//! whose `Debug` shows nothing of it, and which re-encodes to exactly the
//! input (docs/50 §3.3: "a single encoding per value"). A rejection maps to
//! the refusal table — for this kind, within the request bound, always
//! `Malformed` (the envelope is valid, so a close without a reply cannot
//! happen there).
//!
//! Written, not run (PENDING-OWNER P-1).
//!
//! Spec: docs/59 §7.4, §7.5; docs/questions/Q-1033 (A-177); docs/50 §3.3,
//! §8.2, §9; R50-4; A-59.

use ipc::{encode_frame, Direction, Refused};
use ipc_keyd::channel::{request_kind, MAX_REQUEST_BODY};
use ipc_keyd::{
    decode_request, Call, ATTESTATION_KEY_OCTETS, KEYD_CHANNEL, KEYD_MAGIC, KEYD_VERSION,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|payload: &[u8]| {
    let [magic_high, magic_low] = KEYD_MAGIC.to_be_bytes();
    let mut body = vec![
        magic_high,
        magic_low,
        KEYD_VERSION,
        request_kind::INSTALL_ATTESTATION_KEY,
    ];
    body.extend_from_slice(payload);
    match decode_request(&body) {
        Ok(call) => {
            let Call::InstallAttestationKey { key } = &call else {
                panic!("kind 0x1A decodes only as the install");
            };
            assert_eq!(payload.len(), 4 + ATTESTATION_KEY_OCTETS, "exactly one key");
            assert_eq!(key.expose().len(), ATTESTATION_KEY_OCTETS);
            assert!(
                key.expose().iter().any(|&octet| octet != 0),
                "never all zero"
            );
            assert_eq!(format!("{call:?}").matches("redacted").count(), 1);
            let request = call.to_wire().expect("a decoded call re-encodes");
            let frame = encode_frame(KEYD_CHANNEL, Direction::Request, &request)
                .expect("a decoded request fits its own bound");
            assert_eq!(frame.body(), &body[..], "canonical round trip");
        }
        Err(rejection) => {
            // Within the request bound the envelope is valid, so every
            // refusal is the payload's: `Malformed`. Past it the body is
            // refused before the payload is looked at (a close).
            if body.len() <= MAX_REQUEST_BODY as usize {
                assert_eq!(rejection.refusal(), Some(Refused::Malformed));
            }
        }
    }
});
