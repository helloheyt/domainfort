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
//! A decoded `grant_set_secret` (task A15a, kind `0x11`) names at most
//! `MAX_GRANT_TARGETS` key targets — the codec's count bound; keyd judges
//! the rest (docs/questions/Q-450 item 9). A decoded `register_decision`
//! (A-102, kind `0x12`) names at most `MAX_DECISION_APPROVERS` approvers and,
//! for a set-secret decision, at most `MAX_GRANT_TARGETS` targets (docs/52
//! §4.6).
//!
//! A decoded `open_and_verify_service_ticket` (kind `0x07`) carries a
//! principal and a binding from a closed table (`1` Unbound, `2`
//! OperationDigest + 32 octets) and no key purpose — keyd derives it (R2,
//! docs/52 §5 item 3); the reply's operation digest is an optional 32-octet
//! field (the reply target covers it).
//!
//! Written, not run (PENDING-OWNER P-1).
//!
//! Spec: docs/50 §3.3, §3.4, §9; R50-4; A-59; docs/51 §5.8.

use ipc::{encode_frame, Direction};
use ipc_keyd::channel::{MAX_DECISION_APPROVERS, MAX_GRANT_TARGETS};
use ipc_keyd::{decode_request, Call, DecidedOperation, KEYD_CHANNEL};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|body: &[u8]| {
    match decode_request(body) {
        Ok(call) => {
            if let Call::GrantSetSecret { targets, .. } = &call {
                assert!(targets.len() <= MAX_GRANT_TARGETS as usize, "count bound");
            }
            if let Call::RegisterDecision {
                operation,
                approvers,
                ..
            } = &call
            {
                assert!(
                    approvers.len() <= MAX_DECISION_APPROVERS as usize,
                    "approver bound"
                );
                if let DecidedOperation::SetSecret { targets, .. } = operation {
                    assert!(targets.len() <= MAX_GRANT_TARGETS as usize, "count bound");
                }
            }
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
