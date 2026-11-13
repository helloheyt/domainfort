#![no_main]
//! Fuzz target for the audit channel's request decoder (what auditd parses
//! from every sender): `ipc_audit::decode_request`.
//!
//! AGENTS.md §6 / docs/50 §9 (R50-19): arbitrary bytes → decoder; never a
//! panic, bounded allocation. Whatever decodes must re-encode to exactly the
//! input (docs/50 §3.3: "every decoder checks `encode(decode(b)) == b`"), an
//! `Append` must respect its bounds (1..=16 events of 1..=8192 octets,
//! `first_seq` ≥ 1, last number representable), and auditd's per-connection
//! cursor must accept or refuse it without panicking.
//!
//! Spec: docs/50 §3.3, §8.1; A-59.

use ipc::Direction;
use ipc_audit::{
    decode_request, encode_request, AppendCursor, AuditRequest, AUDIT_CHANNEL, MAX_BATCH_EVENTS,
    MAX_EVENT_OCTETS,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(request) = decode_request(data) else {
        return;
    };
    let frame = encode_request(&request).expect("a decoded request re-encodes");
    assert_eq!(frame.body(), data, "canonical round trip");
    assert!(
        ipc::round_trip_is_canonical::<AuditRequest>(AUDIT_CHANNEL, Direction::Request, data)
            .unwrap_or(false)
    );
    if let AuditRequest::Append(append) = &request {
        let events = append.events();
        assert!(!events.is_empty() && events.len() <= MAX_BATCH_EVENTS as usize);
        assert!(events
            .iter()
            .all(|e| !e.is_empty() && e.len() <= MAX_EVENT_OCTETS as usize));
        assert!(append.first_seq() >= 1 && append.last_seq() >= append.first_seq());
        let mut cursor = AppendCursor::new();
        if let Ok(range) = cursor.check(append) {
            let _ = cursor.advance(range);
            let _ = cursor.check(append);
        }
    }
});
