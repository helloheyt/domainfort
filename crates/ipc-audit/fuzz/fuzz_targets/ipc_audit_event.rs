#![no_main]
//! Fuzz target for the audit event decoder (what a log reader or auditd
//! parses from a record payload): `ipc_audit::decode_event`.
//!
//! AGENTS.md §6 / docs/50 §9 (R50-19, target `ipc_audit_event`): arbitrary
//! bytes → decoder; never a panic, bounded allocation (every count and
//! length is checked against its bound first). Whatever decodes must
//! re-encode to exactly the input (docs/50 §3.3: one encoding per value),
//! and every kept text field must be printable ASCII of at most 256 octets
//! (docs/50 §8.2).
//!
//! Spec: docs/50 §3.3, §8.1, §8.2.

use ipc_audit::{decode_event, encode_event, AuditText, EventBody, Principal, MAX_TEXT_OCTETS};
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
    let Ok(event) = decode_event(data) else {
        return;
    };
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
        EventBody::Keyd(_) | EventBody::WindowSummary(_) => {}
    }
});
