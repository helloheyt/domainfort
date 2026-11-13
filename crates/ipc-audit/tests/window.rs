//! The sender's window and the decided overflow policy.
//!
//! Source: docs/questions/Q-218 option (a), decided A-57 — "no unaudited
//! issuance (docs/37), and log overflow does not turn into shutdown
//! (docs/07 §8)": when the source's window is full, keyd refuses every
//! operation (`Busy`) and the KDC refuses every request that would issue;
//! unauthenticated noise is summarised in counters and rate-limited; the
//! service stays alive. docs/50 R50-17 (bounded window, persistence
//! acknowledgements), §3.6 (one request in flight), §8.1.

mod common;

use common::*;
use ipc_audit::{
    decode_event, Ack, EventBody, NoiseAdmission, SendWindow, WindowConfig, WindowError,
    WindowFull, WindowSummary, MAX_BATCH_EVENTS,
};

fn kdc() -> EventBody {
    EventBody::Kdc(Box::new(kdc_event()))
}

fn noise() -> EventBody {
    EventBody::Kdc(Box::new(ipc_audit::KdcEvent {
        exchange: None,
        client: None,
        service: None,
        armor_principal: None,
        outcome: ipc_audit::KdcOutcome::Dropped,
        reason: ipc_audit::KdcReason::UnsupportedMessageType,
        ..kdc_event()
    }))
}

/// A-57: a full window refuses gating reservations — the caller does not
/// perform the operation — and the refusals are counted.
#[test]
fn full_window_refuses_gating() {
    let config = WindowConfig::new(4, 1).unwrap();
    let mut window = SendWindow::new(config);
    for _ in 0..4 {
        let slot = window.reserve().unwrap();
        window.commit(slot, &kdc()).unwrap();
    }
    assert!(window.is_full());
    assert_eq!(window.reserve(), Err(WindowFull));
    assert_eq!(window.reserve(), Err(WindowFull));
    assert_eq!(window.refused_gating(), 2);
}

/// A-57 ("overflow does not turn into shutdown"): after the
/// acknowledgement the same window serves again — nothing stopped, and the
/// refusals are reported in a summary event.
#[test]
fn window_recovers_and_reports() {
    let config = WindowConfig::new(4, 1).unwrap();
    let mut window = SendWindow::new(config);
    for _ in 0..4 {
        let slot = window.reserve().unwrap();
        window.commit(slot, &kdc()).unwrap();
    }
    assert_eq!(window.reserve(), Err(WindowFull));

    // The batch goes out and is acknowledged after persistence.
    let batch = window.next_batch().unwrap();
    assert_eq!(batch.first_seq(), 1);
    assert_eq!(batch.events().len(), 4);
    assert_eq!(
        window.acknowledge(&Ack {
            through_seq: 4,
            head_hash: [1; 32]
        }),
        Ok(4)
    );
    assert_eq!(window.unacknowledged(), 0);

    // Gating operations proceed again.
    let slot = window.reserve().unwrap();
    window.commit(slot, &kdc()).unwrap();

    // The next batch carries the summary of what was refused, numbered
    // after the events already committed.
    let batch = window.next_batch().unwrap();
    assert_eq!(batch.events().len(), 2);
    assert_eq!((batch.first_seq(), batch.last_seq()), (5, 6));
    let summary = decode_event(batch.events()[1].as_bytes()).unwrap();
    assert_eq!(
        summary,
        EventBody::WindowSummary(WindowSummary {
            suppressed_noise: 0,
            refused_gating: 1,
        })
    );
    assert_eq!(window.refused_gating(), 0);
}

/// Reservations count against the window before their events exist (the
/// slot is held for the whole operation).
#[test]
fn reservations_hold_slots() {
    let mut window = SendWindow::new(WindowConfig::new(2, 0).unwrap());
    let a = window.reserve().unwrap();
    let b = window.reserve().unwrap();
    assert_eq!(window.reserved(), 2);
    assert_eq!(window.reserve(), Err(WindowFull));
    window.release(a);
    let c = window.reserve().unwrap();
    assert_eq!(window.commit(b, &kdc()), Ok(1));
    assert_eq!(window.commit(c, &kdc()), Ok(2));
    assert_eq!(window.reserved(), 0);
}

/// A-57: noise holds at most its share; beyond it, it is counted, not
/// queued — and it never takes the slots gating events need.
#[test]
fn noise_never_starves_gating() {
    let config = WindowConfig::new(8, 2).unwrap();
    let mut window = SendWindow::new(config);
    let mut queued = 0;
    for _ in 0..100 {
        if let NoiseAdmission::Queued { .. } = window.offer_noise(&noise()).unwrap() {
            queued += 1;
        }
    }
    assert_eq!(queued, 2);
    assert_eq!(window.suppressed_noise(), 98);
    // Every remaining slot is available to gating events.
    for _ in 0..6 {
        let slot = window.reserve().unwrap();
        window.commit(slot, &kdc()).unwrap();
    }
    assert_eq!(window.reserve(), Err(WindowFull));
    // Noise is counted while the window is full.
    assert_eq!(window.offer_noise(&noise()), Ok(NoiseAdmission::Counted));

    // The full window's batch goes out first (no slot for a summary yet).
    let full = window.next_batch().unwrap();
    assert_eq!(full.events().len(), 8);
    window
        .acknowledge(&Ack {
            through_seq: full.last_seq(),
            head_hash: [0; 32],
        })
        .unwrap();
    // Then the summary carries both counts.
    let batch = window.next_batch().unwrap();
    assert_eq!(batch.events().len(), 1);
    assert_eq!(
        decode_event(batch.events()[0].as_bytes()).unwrap(),
        EventBody::WindowSummary(WindowSummary {
            suppressed_noise: 99,
            refused_gating: 1,
        })
    );
    // Noise slots were freed with the acknowledgement.
    window
        .acknowledge(&Ack {
            through_seq: batch.last_seq(),
            head_hash: [0; 32],
        })
        .unwrap();
    assert!(matches!(
        window.offer_noise(&noise()),
        Ok(NoiseAdmission::Queued { .. })
    ));
}

/// docs/50 §3.6, §8.1: one batch in flight, at most MAX_BATCH_EVENTS, in
/// sequence order; numbering is contiguous across batches.
#[test]
fn batches_in_order() {
    let mut window = SendWindow::new(WindowConfig::DEFAULT);
    for _ in 0..40 {
        let slot = window.reserve().unwrap();
        window.commit(slot, &kdc()).unwrap();
    }
    let first = window.next_batch().unwrap();
    assert_eq!(first.events().len(), MAX_BATCH_EVENTS as usize);
    assert_eq!((first.first_seq(), first.last_seq()), (1, 16));
    assert!(window.next_batch().is_none(), "one batch in flight");
    window
        .acknowledge(&Ack {
            through_seq: 16,
            head_hash: [0; 32],
        })
        .unwrap();
    let second = window.next_batch().unwrap();
    assert_eq!((second.first_seq(), second.last_seq()), (17, 32));
    window
        .acknowledge(&Ack {
            through_seq: 32,
            head_hash: [0; 32],
        })
        .unwrap();
    let third = window.next_batch().unwrap();
    assert_eq!((third.first_seq(), third.last_seq()), (33, 40));
    assert_eq!(window.last_ack().map(|a| a.through_seq), Some(32));
}

/// An acknowledgement that does not match the batch in flight is refused
/// (the caller closes the connection); nothing is released.
#[test]
fn unexpected_ack_is_refused() {
    let mut window = SendWindow::new(WindowConfig::DEFAULT);
    assert_eq!(
        window.acknowledge(&Ack {
            through_seq: 1,
            head_hash: [0; 32]
        }),
        Err(WindowError::UnexpectedAck)
    );
    for _ in 0..3 {
        let slot = window.reserve().unwrap();
        window.commit(slot, &kdc()).unwrap();
    }
    let batch = window.next_batch().unwrap();
    for wrong in [0, 1, 2, 4, u64::MAX] {
        assert_eq!(
            window.acknowledge(&Ack {
                through_seq: wrong,
                head_hash: [0; 32]
            }),
            Err(WindowError::UnexpectedAck)
        );
    }
    assert_eq!(window.unacknowledged(), 3);
    assert_eq!(batch.last_seq(), 3);
}

/// docs/50 §3.7, §8.1: a lost connection (or a `Refused` reply) puts the
/// batch back; it is resent with the same numbers and octets.
#[test]
fn connection_lost_resends() {
    let mut window = SendWindow::new(WindowConfig::DEFAULT);
    for _ in 0..20 {
        let slot = window.reserve().unwrap();
        window.commit(slot, &kdc()).unwrap();
    }
    let sent = window.next_batch().unwrap();
    window.connection_lost();
    let resent = window.next_batch().unwrap();
    assert_eq!(resent, sent);
    window
        .acknowledge(&Ack {
            through_seq: resent.last_seq(),
            head_hash: [0; 32],
        })
        .unwrap();
    let rest = window.next_batch().unwrap();
    assert_eq!(rest.first_seq(), 17);
    assert_eq!(rest.events().len(), 4);
}

/// Window configuration bounds: at least one slot always left for gating.
#[test]
fn config_bounds() {
    assert!(WindowConfig::new(0, 0).is_none());
    assert!(WindowConfig::new(1, 0).is_some());
    assert!(WindowConfig::new(1, 1).is_none());
    assert!(WindowConfig::new(WindowConfig::MAX_CAPACITY, 0).is_some());
    assert!(WindowConfig::new(WindowConfig::MAX_CAPACITY + 1, 0).is_none());
    let d = WindowConfig::DEFAULT;
    assert!(d.noise_limit() < d.capacity());
}

/// Every event that left the window decodes (they are the encoded events
/// that were committed).
#[test]
fn batch_events_decode() {
    let mut window = SendWindow::new(WindowConfig::DEFAULT);
    for event in all_samples() {
        let slot = window.reserve().unwrap();
        window.commit(slot, &event).unwrap();
    }
    let batch = window.next_batch().unwrap();
    let decoded: Vec<EventBody> = batch
        .events()
        .iter()
        .map(|e| decode_event(e.as_bytes()).unwrap())
        .collect();
    assert_eq!(decoded, all_samples());
}
