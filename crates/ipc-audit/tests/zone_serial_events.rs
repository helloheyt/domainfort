//! The `ZoneSerial` shape (task DN10b): dird's serial-only zone write —
//! round trips of every stage, the exact wire layout, the closed code
//! tables, SERIAL 0 refused, strict decoding, `peek_shape`.
//!
//! Source: crate::zone's documented layout (`time ‖ operation_id:u64 ‖
//! cause:u8 ‖ from:u32 ‖ stage`); RFC 2136 §7.11 ("A zone's SOA SERIAL
//! should never be set to zero"); docs/50 §3.3 (exact version, closed codes,
//! no trailing octet, one encoding per value); docs/51 §5.7 item 2 (decision
//! before the commit, outcome after); docs/questions/Q-1002 (A-172), Q-1013.
//! The expected octets are assembled here from that layout; the times and
//! numbers are hand-made test data. No fixture comes from any other
//! implementation.

use core::num::NonZeroU32;

use ipc_audit::{
    decode_event, encode_event, event_round_trip_is_canonical, peek_shape, CalendarTime, EventBody,
    EventError, EventShape, ZoneSerialCause, ZoneSerialEvent, ZoneSerialFailure, ZoneSerialOutcome,
    ZoneSerialOutcomeCode, ZoneSerialPhase, ZoneSerialStage, EVENT_FORMAT, MAX_EVENT_OCTETS,
};

/// 2026-11-15 09:30:15 as the event's calendar time, and its octets
/// (`year:u16 ‖ month ‖ day ‖ hour ‖ minute ‖ second`; 2026 = 0x07EA).
fn time() -> CalendarTime {
    CalendarTime::new(2026, 11, 15, 9, 30, 15).unwrap()
}
const TIME: [u8; 7] = [0x07, 0xEA, 11, 15, 9, 30, 15];

fn serial(value: u32) -> NonZeroU32 {
    NonZeroU32::new(value).unwrap()
}

fn event(cause: ZoneSerialCause, stage: ZoneSerialStage) -> ZoneSerialEvent {
    ZoneSerialEvent {
        time: time(),
        operation_id: 0x0102_0304_0506_0708,
        cause,
        from: serial(2),
        stage,
    }
}

/// Every stage of both causes.
fn samples() -> Vec<ZoneSerialEvent> {
    let mut out = Vec::new();
    for cause in [ZoneSerialCause::ServiceStart, ZoneSerialCause::ContentAged] {
        out.push(event(cause, ZoneSerialStage::Decision));
        out.push(event(
            cause,
            ZoneSerialStage::Outcome(ZoneSerialOutcome::Advanced { serial: serial(3) }),
        ));
        out.push(event(
            cause,
            ZoneSerialStage::Outcome(ZoneSerialOutcome::NotNeeded),
        ));
        for failure in ZoneSerialFailure::ALL {
            out.push(event(
                cause,
                ZoneSerialStage::Outcome(ZoneSerialOutcome::Failed(*failure)),
            ));
        }
    }
    out
}

/// The octets of `event(ContentAged, stage)` with `stage_octets` after the
/// common prefix (module documentation: the documented layout).
fn octets(cause: u8, stage_octets: &[u8]) -> Vec<u8> {
    let mut out = vec![EVENT_FORMAT, 7];
    out.extend_from_slice(&TIME);
    out.extend_from_slice(&0x0102_0304_0506_0708u64.to_be_bytes());
    out.push(cause);
    out.extend_from_slice(&2u32.to_be_bytes());
    out.extend_from_slice(stage_octets);
    out
}

/// docs/50 §3.3: every stage decodes to itself and re-encodes to the same
/// octets; `peek_shape` names `ZoneSerial`; the largest fits the bound.
#[test]
fn every_stage_round_trips() {
    for sample in samples() {
        let body = EventBody::ZoneSerial(Box::new(sample));
        let bytes = encode_event(&body).unwrap();
        assert_eq!(decode_event(bytes.as_bytes()), Ok(body.clone()));
        assert_eq!(event_round_trip_is_canonical(bytes.as_bytes()), Ok(true));
        assert_eq!(peek_shape(bytes.as_bytes()), Some(EventShape::ZoneSerial));
        assert!(bytes.len() <= MAX_EVENT_OCTETS as usize);
    }
}

/// The documented layout, octet for octet: a decision (`1`), an advance
/// (`2 ‖ 1 ‖ serial`), not needed (`2 ‖ 2`), a failure (`2 ‖ 3 ‖ code`).
#[test]
fn the_wire_layout() {
    let aged = ZoneSerialCause::ContentAged;
    let cases = [
        (ZoneSerialStage::Decision, vec![1u8]),
        (
            ZoneSerialStage::Outcome(ZoneSerialOutcome::Advanced { serial: serial(3) }),
            vec![2, 1, 0, 0, 0, 3],
        ),
        (
            ZoneSerialStage::Outcome(ZoneSerialOutcome::NotNeeded),
            vec![2, 2],
        ),
        (
            ZoneSerialStage::Outcome(ZoneSerialOutcome::Failed(
                ZoneSerialFailure::AuditUnacknowledged,
            )),
            vec![2, 3, 1],
        ),
    ];
    for (stage, tail) in cases {
        let body = EventBody::ZoneSerial(Box::new(event(aged, stage)));
        assert_eq!(encode_event(&body).unwrap().as_bytes(), octets(2, &tail));
    }
    let start = EventBody::ZoneSerial(Box::new(event(
        ZoneSerialCause::ServiceStart,
        ZoneSerialStage::Decision,
    )));
    assert_eq!(encode_event(&start).unwrap().as_bytes(), octets(1, &[1]));
}

/// The closed tables keep their codes (append-only, docs/50 §3.3).
#[test]
fn the_code_tables() {
    assert_eq!(ZoneSerialCause::ServiceStart.code(), 1);
    assert_eq!(ZoneSerialCause::ContentAged.code(), 2);
    assert_eq!(ZoneSerialCause::ALL.len(), 2);
    assert_eq!(ZoneSerialPhase::Decision.code(), 1);
    assert_eq!(ZoneSerialPhase::Outcome.code(), 2);
    assert_eq!(ZoneSerialPhase::ALL.len(), 2);
    assert_eq!(ZoneSerialOutcomeCode::Advanced.code(), 1);
    assert_eq!(ZoneSerialOutcomeCode::NotNeeded.code(), 2);
    assert_eq!(ZoneSerialOutcomeCode::Failed.code(), 3);
    assert_eq!(ZoneSerialOutcomeCode::ALL.len(), 3);
    assert_eq!(
        ZoneSerialFailure::ALL
            .iter()
            .map(|f| (f.code(), f.name()))
            .collect::<Vec<_>>(),
        [
            (1, "AuditUnacknowledged"),
            (2, "StoreFailure"),
            (3, "CounterUnavailable"),
            (4, "InternalFailure"),
        ]
    );
    assert_eq!(EventShape::ZoneSerial.code(), 7);
}

/// RFC 2136 §7.11: SERIAL 0 is never shown, so a 0 in `from` or in an
/// advance's `serial` is refused, not decoded.
#[test]
fn serial_zero_is_refused() {
    let mut zero_from = octets(2, &[1]);
    zero_from[2 + 7 + 8 + 1..2 + 7 + 8 + 1 + 4].copy_from_slice(&[0, 0, 0, 0]);
    assert_eq!(decode_event(&zero_from), Err(EventError::InvalidSerial));
    let zero_serial = octets(2, &[2, 1, 0, 0, 0, 0]);
    assert_eq!(decode_event(&zero_serial), Err(EventError::InvalidSerial));
}

/// docs/50 §3.3: a code outside a closed table, a truncated event and a
/// trailing octet are refused.
#[test]
fn strict_decoding() {
    let codec = |e| Err(EventError::Codec(e));
    // cause 3, phase 3, outcome 4, failure 5: outside their tables.
    assert_eq!(
        decode_event(&octets(3, &[1])),
        codec(ipc::Error::UnknownCode)
    );
    assert_eq!(
        decode_event(&octets(2, &[3])),
        codec(ipc::Error::UnknownCode)
    );
    assert_eq!(
        decode_event(&octets(2, &[2, 4])),
        codec(ipc::Error::UnknownCode)
    );
    assert_eq!(
        decode_event(&octets(2, &[2, 3, 5])),
        codec(ipc::Error::UnknownCode)
    );
    // Truncated: the advance without its serial; the decision without
    // its phase.
    assert_eq!(
        decode_event(&octets(2, &[2, 1, 0, 0])),
        codec(ipc::Error::Truncated)
    );
    assert_eq!(decode_event(&octets(2, &[])), codec(ipc::Error::Truncated));
    // A trailing octet after a complete decision.
    assert_eq!(
        decode_event(&octets(2, &[1, 0])),
        codec(ipc::Error::TrailingBytes)
    );
}
