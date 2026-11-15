//! The serial-only zone write (task DN10b; docs/questions/Q-1002, decision
//! A-172): `ZoneSerialWriter` decides an advance in dird's transaction, the
//! decision is acknowledged by a (fake) auditd through the real audit
//! client, and `apply` advances the zone's SERIAL through the one commit —
//! one take of the counter, no object written, no change-seq taken; an
//! advance overtaken by another write is not needed (nothing written); an
//! unacknowledged decision is not performed; a missing or exhausted counter
//! refuses the decision.
//!
//! Source: RFC 2136 §3.6 (autoincrement; "If the zone appears to change,
//! the SOA must appear to change as well"), §7.10 (serial numbers
//! conserved), §7.11 (never zero); docs/54 §5.4; docs/51 §5.7 item 2 (the
//! decision acknowledged before the commit, the outcome after); docs/52
//! §3.11 R6; A-83 (counters only at provisioning); docs/questions/Q-1002,
//! Q-1013. The domain is the shared fixture (tests/common); the counter
//! values and operation numbers are this project's own test data. No
//! vector or fixture comes from any other implementation.

mod common;

use core::num::NonZeroU32;

use common::*;
use directory_admin::{ZoneSerialWriter, CHANGE_SEQ_COUNTER, DNS_ZONE_SERIAL_COUNTER};
use ipc_audit::{
    EventBody, ZoneSerialCause, ZoneSerialFailure, ZoneSerialOutcome, ZoneSerialStage,
};
use ipc_audit_client::IntentRecord;

/// The standard domain plus the zone serial counter (first value `first`),
/// created raw as provisioning does (A-83).
fn domain(test: &str, first: u64, end: u64) -> Domain {
    let d = Domain::new(test);
    let mut txn = d.store.begin_write().unwrap();
    txn.create_counter(DNS_ZONE_SERIAL_COUNTER, first, end)
        .unwrap();
    txn.commit().unwrap();
    d
}

fn writer(d: &Domain) -> ZoneSerialWriter {
    ZoneSerialWriter::new(&d.p1).unwrap()
}

fn serial(value: u32) -> NonZeroU32 {
    NonZeroU32::new(value).unwrap()
}

/// docs/questions/Q-1002 item 2; RFC 2136 §3.6: decided, acknowledged,
/// applied, committed — the SERIAL goes from 1 to 2, the decision and the
/// outcome carry one number, one cause and the SERIAL advanced past; the
/// change-seq counter does not move and no object is written.
#[test]
fn an_acknowledged_advance_takes_the_serial_once() {
    let d = domain("zs-advance", 1, u64::MAX);
    let w = writer(&d);
    let now = provisioned_at();
    let mut txn = d.store.begin_write().unwrap();
    let seq_before = txn.counter(CHANGE_SEQ_COUNTER).unwrap();
    let prepared = w
        .prepare(&txn, 7001, ZoneSerialCause::ServiceStart, &now)
        .unwrap();
    assert_eq!(prepared.from(), serial(1));
    let decision = prepared.decision_event().clone();
    assert_eq!(decision.operation_id, 7001);
    assert_eq!(decision.cause, ZoneSerialCause::ServiceStart);
    assert_eq!(decision.from, serial(1));
    assert_eq!(decision.stage, ZoneSerialStage::Decision);
    assert_eq!(
        prepared.intent_event(),
        EventBody::ZoneSerial(Box::new(decision.clone()))
    );
    let applied = w
        .apply(linked::acknowledged(prepared), &mut txn, &now)
        .unwrap();
    txn.commit().unwrap();
    assert_eq!(applied.serial(), Some(serial(2)));
    let outcome = applied.outcome_event();
    assert_eq!(
        (outcome.operation_id, outcome.cause, outcome.from),
        (7001, ZoneSerialCause::ServiceStart, serial(1))
    );
    assert_eq!(
        outcome.stage,
        ZoneSerialStage::Outcome(ZoneSerialOutcome::Advanced { serial: serial(2) })
    );
    assert_eq!(
        applied.commit_failure_event().stage,
        ZoneSerialStage::Outcome(ZoneSerialOutcome::Failed(ZoneSerialFailure::StoreFailure))
    );
    let snapshot = d.store.snapshot().unwrap();
    assert_eq!(
        snapshot
            .counter(DNS_ZONE_SERIAL_COUNTER)
            .unwrap()
            .unwrap()
            .next_value,
        2
    );
    assert_eq!(snapshot.counter(CHANGE_SEQ_COUNTER).unwrap(), seq_before);
}

/// RFC 2136 §7.10 (serial numbers conserved): the counter moved after the
/// decision — another advance committed in between — so the acknowledged
/// decision is not needed: nothing is written, the outcome says so.
#[test]
fn an_overtaken_advance_is_not_needed() {
    let d = domain("zs-overtaken", 1, u64::MAX);
    let w = writer(&d);
    let now = provisioned_at();
    let first = {
        let txn = d.store.begin_write().unwrap();
        w.prepare(&txn, 7002, ZoneSerialCause::ContentAged, &now)
            .unwrap()
    };
    // Another decision and its write commit first.
    let mut txn = d.store.begin_write().unwrap();
    let other = w
        .prepare(&txn, 7003, ZoneSerialCause::ContentAged, &now)
        .unwrap();
    let applied = w
        .apply(linked::acknowledged(other), &mut txn, &now)
        .unwrap();
    assert_eq!(applied.serial(), Some(serial(2)));
    txn.commit().unwrap();
    // The first one, acknowledged now, finds the counter moved.
    let mut txn = d.store.begin_write().unwrap();
    let applied = w
        .apply(linked::acknowledged(first), &mut txn, &now)
        .unwrap();
    assert_eq!(applied.serial(), None);
    assert_eq!(
        applied.outcome_event().stage,
        ZoneSerialStage::Outcome(ZoneSerialOutcome::NotNeeded)
    );
    assert_eq!(applied.outcome_event().operation_id, 7002);
    assert_eq!(
        txn.counter(DNS_ZONE_SERIAL_COUNTER)
            .unwrap()
            .unwrap()
            .next_value,
        2
    );
}

/// docs/51 §5.7 item 2 (A-85): a decision auditd does not acknowledge gives
/// no proof — `apply` cannot be reached — and its outcome is recorded as not
/// performed (`AuditUnacknowledged`); the counter does not move.
#[test]
fn an_unacknowledged_advance_is_not_performed() {
    let d = domain("zs-unacked", 1, u64::MAX);
    let w = writer(&d);
    let now = provisioned_at();
    let txn = d.store.begin_write().unwrap();
    let prepared = w
        .prepare(&txn, 7004, ZoneSerialCause::ContentAged, &now)
        .unwrap();
    let back = linked::not_acknowledged(prepared);
    let event = back.failure_event(ZoneSerialFailure::AuditUnacknowledged, &now);
    assert_eq!(event.operation_id, 7004);
    assert_eq!(
        event.stage,
        ZoneSerialStage::Outcome(ZoneSerialOutcome::Failed(
            ZoneSerialFailure::AuditUnacknowledged
        ))
    );
    drop(txn);
    assert_eq!(
        d.store
            .snapshot()
            .unwrap()
            .counter(DNS_ZONE_SERIAL_COUNTER)
            .unwrap()
            .unwrap()
            .next_value,
        1
    );
}

/// A-83 (counters only at provisioning): no zone serial counter, or an
/// exhausted one — nothing is decided (`CounterUnavailable`). RFC 2136
/// §7.11: a counter whose next value would show SERIAL 0 is advanced past
/// it (two takes: SERIAL 1).
#[test]
fn the_counter_must_exist_and_zero_is_skipped() {
    let now = provisioned_at();
    let d = Domain::new("zs-no-counter");
    let w = writer(&d);
    let txn = d.store.begin_write().unwrap();
    assert_eq!(
        w.prepare(&txn, 1, ZoneSerialCause::ServiceStart, &now),
        Err(ZoneSerialFailure::CounterUnavailable)
    );
    drop(txn);
    // A counter whose range is used up.
    let d = domain("zs-exhausted", 5, 6);
    let mut txn = d.store.begin_write().unwrap();
    txn.take_counter_value(DNS_ZONE_SERIAL_COUNTER).unwrap();
    txn.commit().unwrap();
    let w = writer(&d);
    let txn = d.store.begin_write().unwrap();
    assert_eq!(
        w.prepare(&txn, 2, ZoneSerialCause::ServiceStart, &now),
        Err(ZoneSerialFailure::CounterUnavailable)
    );
    drop(txn);
    // Next value 2³² − 1 shows SERIAL 2³² − 1; the advance shows 1.
    let d = domain("zs-wrap", (1u64 << 32) - 1, u64::MAX);
    let w = writer(&d);
    let mut txn = d.store.begin_write().unwrap();
    let prepared = w
        .prepare(&txn, 3, ZoneSerialCause::ContentAged, &now)
        .unwrap();
    assert_eq!(prepared.from(), serial(u32::MAX));
    let applied = w
        .apply(linked::acknowledged(prepared), &mut txn, &now)
        .unwrap();
    assert_eq!(applied.serial(), Some(serial(1)));
}
