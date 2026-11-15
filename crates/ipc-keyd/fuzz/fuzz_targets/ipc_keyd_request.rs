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
//! principal and the binding octet, whose closed table is `1` (Unbound)
//! alone since Q-523; a decoded `verify_operation_ticket` (kind `0x15`)
//! carries a principal and a 32-octet operation digest. Neither carries a
//! key purpose — keyd derives it (R2, docs/52 §5 item 3). The target checks
//! that a decoded 0x07 is never operation-bound (Q-523: only the
//! context-free kind 0x15 is).
//!
//! Task K4: a decoded `open_change_password_request` (kind `0x16`) carries
//! no password field and its two addresses in their one encoding — an
//! IPv4-mapped IPv6 address is never decoded as IPv6 (RFC 4120 7.1); a
//! decoded `seal_change_password_error` (kind `0x18`) never carries
//! KRB5_KPASSWD_SUCCESS (the type cannot hold it; RFC 3244 §2); a decoded
//! `register_decision` of a `ChangePassword` decision names one target.
//!
//! Task PN9: a decoded `install_attestation_key` (kind `0x1A`) carries
//! exactly `ATTESTATION_KEY_OCTETS` key octets, never all zero, and its
//! `Debug` says only that it is redacted (docs/59 §7.5; docs/50 §8.2). The
//! dedicated target `ipc_keyd_install_attestation_key` fuzzes its payload
//! alone.
//!
//! Written, not run (PENDING-OWNER P-1).
//!
//! Spec: docs/50 §3.3, §3.4, §9; R50-4; A-59; docs/51 §5.8;
//! docs/questions/Q-523.

use ipc::{encode_frame, Direction};
use ipc_keyd::channel::{request_kind, MAX_DECISION_APPROVERS, MAX_GRANT_TARGETS};
use ipc_keyd::{decode_request, Call, DecidedOperation, ATTESTATION_KEY_OCTETS, KEYD_CHANNEL};
use keyd::{ADDRESS_TYPE_IPV4, ADDRESS_TYPE_IPV6};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|body: &[u8]| {
    match decode_request(body) {
        Ok(call) => {
            if let Call::GrantSetSecret { targets, .. } = &call {
                assert!(targets.len() <= MAX_GRANT_TARGETS as usize, "count bound");
            }
            // Q-523: kind 0x07 decodes only as the unbound verification.
            if matches!(call, Call::OpenAndVerifyServiceTicket { .. }) {
                assert_eq!(
                    body.get(3),
                    Some(&request_kind::OPEN_AND_VERIFY_SERVICE_TICKET)
                );
                assert_eq!(body.get(20), Some(&0x01), "unbound binding octet");
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
            // Task K4: one encoding per address — a decoded IPv6 address is
            // never IPv4-mapped (it would be held as IPv4).
            if let Call::OpenChangePasswordRequest { peer, local, .. } = &call {
                for address in [peer, local] {
                    let len = address.octets().len();
                    assert!(
                        (address.addr_type() == ADDRESS_TYPE_IPV4 && len == 4)
                            || (address.addr_type() == ADDRESS_TYPE_IPV6 && len == 16),
                        "an address of its family"
                    );
                }
            }
            if let Call::SealChangePasswordError { code, .. } = &call {
                assert_ne!(code.value(), 0, "SUCCESS is never sealed as an error");
            }
            // Task PN9: exactly the key's length, never all zero, never shown.
            if let Call::InstallAttestationKey { key } = &call {
                assert_eq!(key.expose().len(), ATTESTATION_KEY_OCTETS);
                assert!(
                    key.expose().iter().any(|&octet| octet != 0),
                    "never all zero"
                );
                assert_eq!(format!("{key:?}"), "AttestationKeyOctets(<redacted>)");
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
