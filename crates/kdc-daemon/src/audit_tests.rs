//! Unit tests of the kdc's gate wrapper (`audit.rs`), in-process: they open
//! the gate as the audit client does with a verified connection, through
//! ipc-audit's dev-only test seams (the link side of the shared gate is
//! crate-private to ipc-audit and driven only by its client in a product,
//! task R15b, docs/questions/Q-630). Moved out of `audit.rs` unchanged
//! otherwise.
//!
//! Sources: docs/questions/Q-218 (A-57), Q-252 item 9. Every value is
//! constructed for these tests.

use super::*;
use ipc_audit::client::LinkedGate;
use ipc_audit::test_seams;
use kdc::{ArmorAudit, AuditReason, Exchange, Transport};
use krb_proto::KerberosTime;

/// Play the audit client with a verified connection: auditd reachable.
fn open(gate: &AuditGate) {
    test_seams::set_reachable(gate.audit_gate(), true);
}

fn event(exchange: Option<Exchange>, outcome: AuditOutcome) -> AuditEvent {
    AuditEvent {
        time: KerberosTime::new(2026, 11, 13, 10, 0, 0).unwrap(),
        transport: Transport::Tcp,
        exchange,
        client: None,
        service: None,
        armor: ArmorAudit::default(),
        outcome,
        reason: AuditReason::Malformed,
    }
}

/// A-57 (fail closed): a new gate counts auditd as unreachable — no slot.
#[test]
fn the_gate_starts_closed() {
    let gate = AuditGate::new(WindowConfig::DEFAULT);
    assert!(gate.admit().is_none());
    open(&gate);
    assert!(gate.admit().is_some());
}

/// Q-252 item 9: a request with a slot needs exactly its event; none, or
/// an overflow, withholds the reply and gives the slot back.
#[test]
fn a_slot_needs_its_event() {
    let gate = AuditGate::new(WindowConfig::DEFAULT);
    open(&gate);
    let slot = gate.admit().unwrap();
    assert_eq!(gate.record(Some(slot), &[], false), Err(RecordLost));
    assert_eq!(gate.outstanding(), 0);
    let slot = gate.admit().unwrap();
    let issued = event(Some(Exchange::As), AuditOutcome::Issued);
    assert_eq!(
        gate.record(Some(slot), std::slice::from_ref(&issued), false),
        Ok(Recorded::Gating)
    );
    assert_eq!(gate.outstanding(), 1);
    let slot = gate.admit().unwrap();
    assert_eq!(gate.record(Some(slot), &[issued], true), Err(RecordLost));
}

/// Q-218 (a): the event of an undecoded message is noise — its slot is
/// given back; without a slot every event is noise; the window full of
/// gating events admits no request (A-57), noise beyond its share is
/// counted, not queued.
#[test]
fn noise_and_the_full_window() {
    let window = WindowConfig::new(2, 1).unwrap();
    let gate = AuditGate::new(window);
    open(&gate);
    let noise = event(None, AuditOutcome::Dropped);
    assert!(is_noise(&noise));
    let slot = gate.admit().unwrap();
    assert_eq!(
        gate.record(Some(slot), std::slice::from_ref(&noise), false),
        Ok(Recorded::Noise)
    );
    assert_eq!(gate.outstanding(), 1, "queued within the noise share");
    let refused = event(
        Some(Exchange::Tgs),
        AuditOutcome::Refused { error_code: 24 },
    );
    let slot = gate.admit().unwrap();
    assert_eq!(
        gate.record(Some(slot), &[refused], false),
        Ok(Recorded::Gating)
    );
    assert!(gate.admit().is_none(), "window full: no slot");
    assert_eq!(gate.record(None, &[noise], false), Ok(Recorded::Noise));
    assert_eq!(gate.outstanding(), 2, "counted, not queued");
}
