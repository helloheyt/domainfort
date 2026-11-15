//! Unit tests of keyd's gate wrapper (`audit.rs`), in-process: the tests
//! play the audit client at the window level — the gate opened, a batch
//! taken, auditd's `Ack` fed — through ipc-audit-client's dev-only test seams
//! (the link side of the shared gate is crate-private to ipc-audit-client and
//! driven only by its client in a product, task R15b, docs/questions/Q-630).
//! Moved out of `audit.rs` unchanged otherwise.
//!
//! Sources: docs/10 §7א, I8; docs/questions/Q-218 (A-57), A-64, Q-346
//! (A-86), A-88; docs/52 §3.11 R6 (a); docs/50 §8.1. Every value is
//! constructed for these tests.

use super::*;
use ipc_audit::{Ack, KeydOutcome};
use ipc_audit_client::test_seams;
use ipc_audit_client::LinkedGate;
use ipc_keyd::Call;
use ipc_keyd_server::{classify, Classified};
use keyd::{CallerId, KeyHandle, PrincipalId};

/// Play the audit client with a verified connection: auditd reachable.
fn open(gate: &AuditGate) {
    test_seams::set_reachable(gate.audit_gate(), true);
}

/// docs/10 §7א (`describe_config`, `ping`: no key, no secret) and A-57 /
/// A-64 (every operation that touches a key, token or secret gates).
#[test]
fn only_describe_config_and_ping_do_not_gate() {
    for operation in Operation::ALL {
        let expected = !matches!(operation, Operation::DescribeConfig | Operation::Ping);
        assert_eq!(is_gating(operation), expected, "{operation:?}");
    }
}

/// A-57 (fail closed): a new gate counts auditd as unreachable, so a
/// gating operation is refused until the audit client verified it.
#[test]
fn gate_starts_closed() {
    let gate = AuditGate::new(WindowConfig::DEFAULT);
    assert!(!gate.is_reachable());
    assert_eq!(
        gate.admit(Operation::IssueAsRep).map(|_| ()),
        Err(GateClosed)
    );
    assert!(matches!(
        gate.admit(Operation::Ping),
        Ok(Admission::NotGating)
    ));
    open(&gate);
    assert!(matches!(
        gate.admit(Operation::IssueAsRep),
        Ok(Admission::Gating(_))
    ));
}

/// docs/10 I8: a gating operation with no record, or with more records
/// than the buffer keeps, is refused (the reply is not sent).
#[test]
fn a_gating_operation_needs_its_record() {
    let gate = AuditGate::new(WindowConfig::DEFAULT);
    open(&gate);
    let admission = gate.admit(Operation::CreateKey).unwrap();
    assert_eq!(gate.record(admission, &[], false), Err(RecordLost));
    assert_eq!(gate.outstanding(), 0, "the slot was given back");
}

/// The buffer is bounded (AGENTS.md §6) and reports the overflow.
#[test]
fn record_buffer_is_bounded() {
    let mut buffer = RecordBuffer::new();
    let record = AuditRecord {
        ts: krb_proto::KerberosTime::new(2026, 11, 13, 10, 0, 0).unwrap(),
        caller_role: keyd::Role::Kdc,
        caller_uid: 803,
        op: Operation::Ping,
        principal: None,
        purpose: None,
        kvno: None,
        secondary: None,
        approvers: None,
        decision: None,
        result: keyd::AuditOutcome::Success,
        reason: keyd::AuditReason::None,
    };
    for _ in 0..MAX_RECORDS_PER_OPERATION + 2 {
        buffer.record(&record);
    }
    let (records, overflowed) = buffer.take();
    assert_eq!(records.len(), MAX_RECORDS_PER_OPERATION);
    assert!(overflowed);
    assert_eq!(buffer.take(), (Vec::new(), false));
}

/// A key-state change built for these tests: `create_key` by the admin
/// (uid 807) on a PrincipalLongterm handle, classified against the
/// development keyd (admitted: Provisioning, the Admin role, the
/// purpose).
fn change() -> KeyStateCall {
    let call = Call::CreateKey {
        handle: KeyHandle::new(
            PrincipalId::from_bytes([0xA1; 16]),
            keyd::KeyPurpose::PrincipalLongterm,
        ),
        binding: keyd::PrincipalBinding::new(
            krb_proto::Realm::new("EXAMPLE.ORG").unwrap(),
            krb_proto::PrincipalName {
                name_type: 1,
                name_string: vec![krb_proto::KerberosString::new("alice").unwrap()],
            },
        ),
    };
    let caller = CallerId {
        uid: 807,
        role: keyd::Role::Admin,
    };
    let started = krb_proto::KerberosTime::new(2026, 11, 13, 9, 0, 0).unwrap();
    let now = krb_proto::KerberosTime::new(2026, 11, 13, 10, 0, 0).unwrap();
    let keyd =
        crate::startup::development_keyd(krb_proto::Realm::new("EXAMPLE.ORG").unwrap())(&started)
            .unwrap();
    match classify(&keyd, caller, now, call) {
        Classified::KeyStateChange(change) => change,
        other => panic!("{other:?}"),
    }
}

/// A-86 step 1: a key-state change takes its two slots (intent and
/// outcome) or none — refused `GateClosed` (Busy) with auditd unreachable
/// or one slot left, and nothing is left reserved or committed.
#[test]
fn a_key_state_change_takes_two_slots_or_none() {
    let gate = AuditGate::new(WindowConfig::new(2, 1).unwrap());
    assert_eq!(
        gate.begin_key_state_change(change()).map(|_| ()),
        Err(IntentRefused::GateClosed)
    );
    open(&gate);
    let first = gate.admit(Operation::VerifySecret).unwrap();
    assert_eq!(
        gate.begin_key_state_change(change()).map(|_| ()),
        Err(IntentRefused::GateClosed)
    );
    assert_eq!(gate.outstanding(), 1, "only the other operation's slot");
    gate.release(first);
    let pending = gate.begin_key_state_change(change()).unwrap();
    assert_eq!(pending.intent_seq(), 1);
    assert_eq!(gate.outstanding(), 2, "the intent and the outcome's slot");
    let (_change, slot) = gate.give_up(pending);
    assert_eq!(
        gate.finish_key_state_change(slot, &[], false),
        Err(RecordLost)
    );
    assert_eq!(gate.unrecorded_outcomes(), 1, "the gap is counted");
    assert_eq!(gate.outstanding(), 1, "the intent alone");
    // A-88: and into the window's next summary, after the intent (the
    // summary takes the slot the lost outcome left free).
    assert_eq!(
        gate.inspect(ipc_audit::SendWindow::unrecorded_outcomes),
        Some(1)
    );
    let append = test_seams::next_batch(gate.audit_gate()).unwrap();
    let events: Vec<EventBody> = append
        .events()
        .iter()
        .map(|e| ipc_audit::decode_event(e.as_bytes()).unwrap())
        .collect();
    assert_eq!(events.len(), 2);
    assert!(matches!(&events[0], EventBody::Keyd(r) if r.result == KeydOutcome::Intent));
    // The refused second reservation above is counted apart: a refusal
    // ("not done") is not a lost outcome ("done, record lost").
    assert_eq!(
        events[1],
        EventBody::WindowSummary(ipc_audit::WindowSummary {
            suppressed_noise: 0,
            refused_gating: 1,
            unrecorded_outcomes: 1,
        })
    );
}

/// A-86 step 2 / docs/52 R6 (a): `wait_acknowledged` gives the proof
/// once auditd acknowledged the intent — signalled from another thread,
/// as the audit client does — and the change back, without a proof, at
/// the deadline otherwise.
#[test]
fn the_proof_comes_only_with_the_acknowledgement() {
    let gate = std::sync::Arc::new(AuditGate::new(WindowConfig::DEFAULT));
    open(&gate);
    let pending = gate.begin_key_state_change(change()).unwrap();
    let soon = Instant::now() + core::time::Duration::from_millis(50);
    let Waited::NotAcknowledged(change, slot) = gate.wait_acknowledged(pending, soon) else {
        panic!("not acknowledged");
    };
    assert_eq!(change.operation(), Operation::CreateKey);
    assert_eq!(
        gate.abandon_key_state_change(slot, &change.not_performed_event()),
        Ok(())
    );
    let pending = gate.begin_key_state_change(change).unwrap();
    let auditd = {
        let gate = std::sync::Arc::clone(&gate);
        std::thread::spawn(move || {
            std::thread::sleep(core::time::Duration::from_millis(20));
            let append = test_seams::next_batch(gate.audit_gate()).unwrap();
            let ack = Ack {
                through_seq: append.last_seq(),
                head_hash: [0; 32],
            };
            test_seams::acknowledge(gate.audit_gate(), &ack).unwrap();
        })
    };
    let later = Instant::now() + core::time::Duration::from_secs(10);
    let Waited::Acknowledged(acked, slot) = gate.wait_acknowledged(pending, later) else {
        panic!("acknowledged");
    };
    auditd.join().unwrap();
    assert_eq!(acked.get().operation(), Operation::CreateKey);
    assert_eq!(
        gate.finish_key_state_change(slot, &[], false),
        Err(RecordLost)
    );
    assert_eq!(gate.unrecorded_outcomes(), 1);
}
