#![no_main]
//! Fuzz target for the audit channel's reply decoder (what every sender
//! parses from auditd): `ipc_audit::decode_reply`, the shared `Refused`
//! included.
//!
//! AGENTS.md §6 / docs/50 §9 (R50-19); docs/50 §3.3 ("replies are decoded
//! with the same strictness"): never a panic; whatever decodes re-encodes to
//! exactly the input; and a decoded `Ack` fed to a sender window that has a
//! batch in flight is either applied (only when it names that batch's last
//! number) or refused — never a panic, never a release of events that were
//! not acknowledged. A decoded `Pong` is exactly the envelope and one octet,
//! the code of the source it names, inside the closed table (task R9b,
//! docs/questions/Q-560: every sender compares that source with its own).
//!
//! Spec: docs/50 §3.3, §8.1; A-59; docs/questions/Q-560.

use ipc::Reply;
use ipc_audit::{
    decode_reply, AuditReply, EventBody, EventSource, SendWindow, WindowConfig, WindowSummary,
    AUDIT_CHANNEL,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(reply) = decode_reply(data) else {
        return;
    };
    assert!(
        ipc::reply_round_trip_is_canonical::<AuditReply>(AUDIT_CHANNEL, data).unwrap_or(false),
        "canonical round trip"
    );
    if let Reply::Message(AuditReply::Pong(source)) = reply {
        assert_eq!(data.len(), ipc::BODY_HEADER_LEN + 1, "the envelope and one octet");
        assert_eq!(data.last().copied(), Some(source.code()), "the source's code");
        assert_eq!(EventSource::from_code(source.code()), Some(source));
    }
    if let Reply::Message(AuditReply::Ack(ack)) = reply {
        let mut window = SendWindow::new(WindowConfig::DEFAULT);
        let event = EventBody::WindowSummary(WindowSummary {
            suppressed_noise: 0,
            refused_gating: 0,
            unrecorded_outcomes: 0,
        });
        for _ in 0..3 {
            let slot = window.reserve().expect("room in a new window");
            window.commit(slot, &event).expect("a summary encodes");
        }
        let batch = window.next_batch().expect("a batch");
        match window.acknowledge(&ack) {
            Ok(freed) => {
                assert_eq!(ack.through_seq, batch.last_seq());
                assert_eq!(freed, 3);
                assert_eq!(window.unacknowledged(), 0);
            }
            Err(_) => {
                assert_ne!(ack.through_seq, batch.last_seq());
                assert_eq!(window.unacknowledged(), 3);
            }
        }
    }
});
