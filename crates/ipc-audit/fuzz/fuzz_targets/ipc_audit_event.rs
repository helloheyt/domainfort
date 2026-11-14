#![no_main]
//! Fuzz target for the audit event decoder (what a log reader or auditd
//! parses from a record payload): `ipc_audit::decode_event`, and the
//! two-octet `ipc_audit::peek_shape` auditd uses for the source binding.
//!
//! AGENTS.md §6 / docs/50 §9 (R50-19, target `ipc_audit_event`): arbitrary
//! bytes → decoder; never a panic, bounded allocation (every count and
//! length is checked against its bound first). Whatever decodes must
//! re-encode to exactly the input (docs/50 §3.3: one encoding per value),
//! must carry the shape `peek_shape` names, and every kept text field must
//! be printable ASCII of at most 256 octets (docs/50 §8.2) — the admin-plane
//! names included (docs/51 §5.7: names only as `AuditText`). Every bounded
//! sequence of the admin-plane shapes stays within its bound. A keyd record's
//! outcome is one of the closed table's seven codes — keyd's five outcomes
//! or keyd-daemon's two phases of a key-state change (`Intent`,
//! `NotPerformed`; decision A-86) — and nothing else. A window summary is
//! exactly its three fixed-width counters (decision A-88 appended the
//! third, `unrecorded_outcomes`; docs/questions/Q-395): 2 + 3 × 8 octets,
//! the counters in their declared order. A `DirAdmin` refusal or failure
//! code is one of its closed table's (A-91 appended three; Q-397).
//!
//! Spec: docs/50 §3.3, §8.1, §8.2; docs/51 §5.7; docs/questions/Q-340,
//! Q-341, Q-346 (A-86), Q-365, Q-366 (A-88), Q-388 (A-91), Q-395, Q-397.

use ipc_audit::{
    decode_event, encode_event, peek_shape, AdminFailure, AdminRefusal, AdmindActivity, AuditText,
    DecisionResult, DirAdminStage, EventBody, KeydOutcome, OutcomeResult, Principal,
    MAX_APPROVERS, MAX_REPORTED_KVNOS, MAX_TARGET_NAMES, MAX_TEXT_OCTETS,
};
use libfuzzer_sys::fuzz_target;

fn text_ok(text: &AuditText) -> bool {
    text.as_text().map_or(true, |t| {
        t.len() <= MAX_TEXT_OCTETS && t.bytes().all(|b| (0x20..=0x7E).contains(&b))
    })
}

fn principal_ok(p: &Principal) -> bool {
    text_ok(p.realm()) && p.components().map_or(true, |c| c.iter().all(text_ok))
}

fuzz_target!(|data: &[u8]| {
    // The peek never panics, whatever the input.
    let peeked = peek_shape(data);
    let Ok(event) = decode_event(data) else {
        return;
    };
    assert_eq!(peeked, Some(event.shape()), "peek agrees with the decoder");
    let bytes = encode_event(&event).expect("a decoded event re-encodes");
    assert_eq!(bytes.as_bytes(), data, "canonical round trip");
    match &event {
        EventBody::Kdc(kdc) => {
            for p in [&kdc.client, &kdc.service, &kdc.armor_principal]
                .into_iter()
                .flatten()
            {
                assert!(principal_ok(p));
            }
        }
        EventBody::Ldap(ldap) => {
            if let Some(bind) = &ldap.bind {
                assert!(bind.name.as_ref().map_or(true, text_ok));
            }
            if let Some(search) = &ldap.search {
                assert!(search.filter_attrs().iter().all(text_ok));
            }
        }
        EventBody::DirAdmin(admin) => {
            assert!(admin.names.as_slice().iter().all(|n| text_ok(&n.text)));
            assert!(admin.names.len() <= MAX_TARGET_NAMES);
            assert!(admin.approvers.len() <= MAX_APPROVERS);
            assert!(admin.reported_kvnos.len() <= MAX_REPORTED_KVNOS);
            // Closed tables (A-91 appended `ObligationRefused` = 20,
            // `ViewUnavailable` = 5, `AuditUnacknowledged` = 6; nothing past
            // them).
            match admin.stage {
                DirAdminStage::Decision(DecisionResult::Refused(refusal))
                | DirAdminStage::Outcome(OutcomeResult::Refused(refusal)) => {
                    assert!((1..=20).contains(&refusal.code()));
                    assert_eq!(AdminRefusal::from_code(refusal.code()), Some(refusal));
                }
                DirAdminStage::Decision(DecisionResult::Failed(failure))
                | DirAdminStage::Outcome(OutcomeResult::Failed(failure)) => {
                    assert!((1..=6).contains(&failure.code()));
                    assert_eq!(AdminFailure::from_code(failure.code()), Some(failure));
                }
                DirAdminStage::Decision(DecisionResult::Proceed)
                | DirAdminStage::Outcome(OutcomeResult::Committed { .. }) => {}
            }
        }
        EventBody::Admind(admind) => {
            if let AdmindActivity::SetPassword { kvnos, .. } = &admind.activity {
                assert!(kvnos.len() <= MAX_REPORTED_KVNOS);
            }
        }
        EventBody::Keyd(keyd) => {
            // Closed table (A-86 appended codes 6 and 7, nothing past them).
            let code = keyd.result.code();
            assert!((1..=7).contains(&code));
            assert_eq!(KeydOutcome::from_code(code), Some(keyd.result));
        }
        EventBody::WindowSummary(summary) => {
            // Fixed width: format, shape, then the three counters in order.
            assert_eq!(data.len(), 2 + 3 * 8);
            assert_eq!(&data[2..10], &summary.suppressed_noise.to_be_bytes()[..]);
            assert_eq!(&data[10..18], &summary.refused_gating.to_be_bytes()[..]);
            assert_eq!(&data[18..26], &summary.unrecorded_outcomes.to_be_bytes()[..]);
        }
    }
});
