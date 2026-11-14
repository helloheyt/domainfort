//! Tier 1 (docs/50 §9): the resend check, in-process — a batch resent after
//! a lost acknowledgement is acknowledged without a second copy, across an
//! auditd restart (the state recovered from the verified log), a partly
//! persisted batch appends only its new tail, a resent event that differs is
//! refused and counted, and a sender that restarts its numbering at 1 is
//! accepted.
//!
//! Each test names its source. Payloads are arbitrary test octets made up
//! here (crate `common::events`); the senders' behaviour exercised is this
//! repository's own `ipc_audit::SendWindow` (numbering from 1, the batch in
//! flight put back in front and resent with the same numbers).

mod common;

use audit_daemon::binding::{bound_source, numbering, PRODUCTION};
use audit_daemon::own_event::{AuditdEvent, ResendsRefused, RESENDS_REFUSED_LEN};
use audit_daemon::recovery::{open_log, StartKind};
use audit_daemon::resend::{Numbering, PersistedTails, Plan, ResendRefusal};
use audit_daemon::segments::{list_segments, segment_path, FileSegments};
use audit_daemon::writer::{self, AppendJob, JobOutcome, LogSink};
use audit_log::{Anchor, ChainHead, Record, SegmentLimit, Source};
use common::*;
use ipc_audit::{EventBytes, EventShape};
use tokio::sync::oneshot;

const OWN_UID: u32 = 4242;
/// The kdc's uid in these tests (made up).
const KDC_UID: u32 = 803;
/// Payload length of every test event.
const LEN: usize = 48;

/// An `Append` of the kdc as the writer receives it.
fn job_on(
    first: u64,
    events: Vec<EventBytes>,
    numbering: Numbering,
    first_on_connection: bool,
) -> (AppendJob, oneshot::Receiver<JobOutcome>) {
    let (reply, outcome) = oneshot::channel();
    (
        AppendJob {
            source: Source::Kdc,
            source_uid: KDC_UID,
            first_source_seq: first,
            events,
            numbering,
            first_on_connection,
            reply,
        },
        outcome,
    )
}

/// The first `Append` on a connection (where a resend comes).
fn first_batch(first: u64, events: Vec<EventBytes>) -> AppendJob {
    job_on(first, events, Numbering::Single, true).0
}

/// A later `Append` on the same connection.
fn next_batch(first: u64, events: Vec<EventBytes>) -> AppendJob {
    job_on(first, events, Numbering::Single, false).0
}

fn open(dir: &TempDir) -> LogSink<FileSegments> {
    open_log(&dir.base(), SegmentLimit::DEFAULT, OWN_UID)
        .expect("the log verifies")
        .sink
}

/// Every record of the log, every segment verified in order from genesis
/// (crates/audit-log's verifier through `read_segment`).
fn log_records(dir: &TempDir) -> Vec<Record> {
    let mut records = Vec::new();
    let mut anchor = Anchor::Genesis;
    for index in list_segments(&dir.base()).expect("segments") {
        let (mut segment, head) = read_segment(&dir.base(), index, anchor);
        records.append(&mut segment);
        anchor = Anchor::After(head);
    }
    records
}

/// `(source, source_seq, payload)` of the kdc's records.
fn kdc_events(records: &[Record]) -> Vec<(u64, Vec<u8>)> {
    records
        .iter()
        .filter(|r| r.source == Source::Kdc)
        .map(|r| {
            assert_eq!(r.source_uid, KDC_UID);
            (r.source_seq, r.payload.clone())
        })
        .collect()
}

/// The expected `(source_seq, payload)` list for `events` numbered from
/// `first`.
fn numbered(first: u64, events: &[EventBytes]) -> Vec<(u64, Vec<u8>)> {
    (first..)
        .zip(events)
        .map(|(seq, event)| (seq, event.as_bytes().to_vec()))
        .collect()
}

fn persisted(outcome: Result<JobOutcome, writer::PersistError>) -> ChainHead {
    match outcome {
        Ok(JobOutcome::Persisted(head)) => head,
        other => panic!("expected Persisted, got {other:?}"),
    }
}

// ---- layouts and the numbering of a source ---------------------------------

/// Source: audit_daemon::own_event layout, kind 0x04 (docs/questions/Q-445
/// item 6).
#[test]
fn resends_refused_layout() {
    let record = AuditdEvent::ResendsRefused(ResendsRefused {
        mismatched: 2,
        unverifiable: 5,
        last_uid: KDC_UID,
    });
    assert_eq!(record.encode(), expected_resends(2, 5, KDC_UID));
    assert_eq!(record.encode().len(), RESENDS_REFUSED_LEN);
}

/// Source: docs/50 §3.2, R50-3 (one source per uid); docs/questions/Q-341
/// (A-85: dird's LDAP and admin events share its one window), Q-432
/// residual (the single-uid harness's one label), Q-445 item 5.
#[test]
fn production_gives_every_source_one_numbering() {
    for source in Source::ALL {
        assert_eq!(
            numbering(PRODUCTION, source),
            Numbering::Single,
            "{source:?}"
        );
    }
    // Every shape bound to one label, as the single-uid harness does: that
    // label carries several senders' numberings.
    fn one_label(shape: EventShape) -> Option<Source> {
        bound_source(shape).map(|_| Source::Kdc)
    }
    assert_eq!(numbering(one_label, Source::Kdc), Numbering::Shared);
    assert_eq!(numbering(one_label, Source::Dird), Numbering::Single);
    // dird's two shapes under another label are still one sender's.
    fn dird_as_kdc(shape: EventShape) -> Option<Source> {
        matches!(shape, EventShape::Ldap | EventShape::DirAdmin).then_some(Source::Kdc)
    }
    assert_eq!(numbering(dird_as_kdc, Source::Kdc), Numbering::Single);
}

/// Source: crate::resend ("what auditd remembers"): auditd's own records
/// are not in the state; a source never seen appends everything.
#[test]
fn the_state_holds_sender_sources_only() {
    let mut tails = PersistedTails::new();
    tails.observe(Source::Auditd, OWN_UID, 1, b"own", None);
    assert!(tails.tail(Source::Auditd).is_none());
    let batch = events(2, LEN, 1);
    assert_eq!(
        tails.plan(Source::Kdc, KDC_UID, 5, &batch, Numbering::Single, true),
        Plan::Append { skip: 0 }
    );
    tails.observe(Source::Kdc, KDC_UID, 5, batch[0].as_bytes(), None);
    let tail = tails.tail(Source::Kdc).expect("seen");
    assert_eq!(
        (tail.uid(), tail.last_seq(), tail.remembered()),
        (KDC_UID, 5, 1)
    );
}

// ---- a resend after a lost acknowledgement ----------------------------------

/// Source: decision A-98 (follow-up F8: "recognise a batch whose source
/// sequence range it already persisted — per-source cursor recovered from
/// the verified log at start — and acknowledge it without appending it
/// again"); docs/questions/Q-432 item 5 (auditd stopped after the sync and
/// before the `Ack`); docs/50 §7.5 (the log verified at start, A-66), §8.1.
/// auditd persists a batch and stops before the acknowledgement leaves; the
/// next start recovers the kdc's counter from the log; the sender's resend
/// on its next connection is acknowledged with the head of the record that
/// holds its last event, nothing appended; the log holds one copy and
/// verifies.
#[test]
fn a_resend_after_auditd_restarts_is_acknowledged_once() {
    let dir = TempDir::new();
    let mut sink = open(&dir);
    let before = events(4, LEN, 1);
    persisted(sink.persist_batch(&first_batch(1, before.clone())));
    let lost = events(3, LEN, 2);
    let head = persisted(sink.persist_batch(&next_batch(5, lost.clone())));
    // auditd stops after the sync, before the Ack leaves.
    drop(sink);

    let reopened = open_log(&dir.base(), SegmentLimit::DEFAULT, OWN_UID).expect("verifies");
    assert_eq!(reopened.start, StartKind::Resumed);
    let tail = reopened.sink.tails().tail(Source::Kdc).expect("recovered");
    assert_eq!((tail.uid(), tail.last_seq()), (KDC_UID, 7));
    let mut sink = reopened.sink;

    // The sender resends the batch it saw no Ack for, on a new connection.
    assert_eq!(
        sink.persist_batch(&first_batch(5, lost.clone())),
        Ok(JobOutcome::AlreadyPersisted(head))
    );
    assert_eq!(sink.head(), head, "nothing appended");
    // ... and goes on.
    let after = events(1, LEN, 3);
    persisted(sink.persist_batch(&next_batch(8, after.clone())));
    drop(sink);

    let records = log_records(&dir);
    let mut expected = numbered(1, &before);
    expected.extend(numbered(5, &lost));
    expected.extend(numbered(8, &after));
    assert_eq!(kdc_events(&records), expected, "one copy of every event");
    let again = open_log(&dir.base(), SegmentLimit::DEFAULT, OWN_UID).expect("verifies");
    assert_eq!(again.start, StartKind::Resumed);
}

/// Source: as above, and docs/50 §3.6 (one bounded writer queue; the reply
/// in a `oneshot`). The connection breaks while its batch waits in the
/// writer's queue (the receiver is gone); the sender's resend, queued after
/// it, is answered `AlreadyPersisted` — the check runs on the writer
/// thread, so it sees the first copy persisted.
#[test]
fn a_resend_queued_behind_its_first_copy_is_not_appended() {
    let dir = TempDir::new();
    let sink = open(&dir);
    let (submitter, inbox) = writer::queue(4);
    let thread = std::thread::spawn(move || writer::run(sink, inbox));

    let (job, outcome) = job_on(1, events(2, LEN, 1), Numbering::Single, true);
    submitter.submit(job).expect("queued");
    assert!(matches!(
        outcome.blocking_recv(),
        Ok(JobOutcome::Persisted(_))
    ));
    let batch = events(3, LEN, 2);
    let (job, outcome) = job_on(3, batch.clone(), Numbering::Single, false);
    drop(outcome); // the connection broke
    submitter.submit(job).expect("queued");
    let (job, outcome) = job_on(3, batch.clone(), Numbering::Single, true);
    submitter.submit(job).expect("queued");
    match outcome.blocking_recv() {
        Ok(JobOutcome::AlreadyPersisted(head)) => assert_eq!(head.seq, 5),
        other => panic!("expected AlreadyPersisted, got {other:?}"),
    }
    drop(submitter);
    assert_eq!(thread.join().unwrap(), Ok(()));

    let records = log_records(&dir);
    assert_eq!(records.len(), 5);
    assert_eq!(kdc_events(&records)[2..], numbered(3, &batch)[..]);
}

// ---- a partly persisted batch ----------------------------------------------------

/// Source: crate::resend rule 2 (a partly persisted batch); ipc-audit
/// `SendWindow::connection_lost` / `next_batch` (the batch in flight goes
/// back in front; the next batch takes it and up to 16 events behind it);
/// docs/questions/Q-445 item 2. The sender had more events by the time it
/// resent: only the events after the last persisted number are appended,
/// the Ack names the last event; a second resend is wholly persisted.
#[test]
fn a_partly_persisted_batch_appends_only_its_new_tail() {
    let dir = TempDir::new();
    let mut sink = open(&dir);
    persisted(sink.persist_batch(&first_batch(1, events(4, LEN, 1))));
    let lost = events(3, LEN, 2);
    persisted(sink.persist_batch(&next_batch(5, lost.clone())));

    let mut resend = lost.clone();
    let newer = events(3, LEN, 3);
    resend.extend(newer.iter().cloned());
    let head = persisted(sink.persist_batch(&first_batch(5, resend.clone())));
    assert_eq!(head.seq, 10, "three records appended");
    assert_eq!(
        sink.persist_batch(&first_batch(5, resend.clone())),
        Ok(JobOutcome::AlreadyPersisted(head))
    );
    drop(sink);

    let records = log_records(&dir);
    assert_eq!(kdc_events(&records)[4..], numbered(5, &resend)[..]);
    assert_eq!(records.len(), 10);
}

/// Source: crate::resend rule 2; docs/questions/Q-250 item 8, Q-265 item 1
/// (a torn last segment is recovered into a new segment anchored at
/// `last_good`); docs/50 §7.5. A crash tears the write of a batch inside
/// its fourth record: the first three records of the batch are part of the
/// chain, the batch was never acknowledged, and the sender resends all of
/// it — only its last two events are appended, after the recovery record.
#[test]
fn a_torn_batch_is_completed_by_its_resend() {
    let dir = TempDir::new();
    let mut sink = open(&dir);
    persisted(sink.persist_batch(&first_batch(1, events(4, LEN, 1))));
    let torn = events(5, LEN, 2);
    persisted(sink.persist_batch(&next_batch(5, torn.clone())));
    drop(sink);
    // Keep records 1..=7 and a few octets of record 8.
    let cut = header_len() + 7 * record_len(LEN) as u64 + 5;
    std::fs::OpenOptions::new()
        .write(true)
        .open(segment_path(&dir.base(), 1))
        .and_then(|file| file.set_len(cut))
        .expect("cut");

    let reopened = open_log(&dir.base(), SegmentLimit::DEFAULT, OWN_UID).expect("recovered");
    let StartKind::Recovered(recovered) = reopened.start else {
        panic!("expected a recovery, got {:?}", reopened.start);
    };
    assert_eq!(recovered.last_good.seq, 7);
    let tail = reopened.sink.tails().tail(Source::Kdc).expect("recovered");
    assert_eq!(tail.last_seq(), 7);
    let mut sink = reopened.sink;
    let head = persisted(sink.persist_batch(&first_batch(5, torn.clone())));
    // Records: 1..=7, the recovery record (8), events 8 and 9 (9, 10).
    assert_eq!(head.seq, 10);
    drop(sink);

    let again = open_log(&dir.base(), SegmentLimit::DEFAULT, OWN_UID).expect("verifies");
    assert_eq!(again.start, StartKind::Resumed);
    drop(again);
    let (second, _) = read_segment(&dir.base(), 2, Anchor::After(recovered.last_good));
    assert_eq!(second.len(), 3);
    assert_eq!(second[0].source, Source::Auditd);
    assert_eq!(kdc_events(&second), numbered(8, &torn[3..]));
}

// ---- refusals ------------------------------------------------------------------

/// Source: decision A-98 / the F8 brief ("a resent event must be
/// byte-identical to the persisted one for the same (source, source_seq);
/// a mismatch is a forgery or corruption signal: refuse the batch, count
/// it"); docs/50 §3.2 ("closed + an audit record"); docs/questions/Q-218
/// (A-57: "summarised in counters"), Q-445 items 3, 6. A resend whose middle
/// event differs is refused, nothing of it appended; the true resend is
/// still recognised afterwards; the refusal is written as a
/// `ResendsRefused` record.
#[test]
fn a_resent_event_that_differs_is_refused_and_counted() {
    let dir = TempDir::new();
    let mut sink = open(&dir);
    persisted(sink.persist_batch(&first_batch(1, events(4, LEN, 1))));
    let lost = events(3, LEN, 2);
    let head = persisted(sink.persist_batch(&next_batch(5, lost.clone())));
    let mut forged = lost.clone();
    forged[1] = events(1, LEN, 9).remove(0);
    let mut forged_longer = forged.clone();
    forged_longer.extend(events(2, LEN, 3));

    let (submitter, inbox) = writer::queue(4);
    let thread = std::thread::spawn(move || writer::run(sink, inbox));
    for batch in [forged, forged_longer] {
        let (job, outcome) = job_on(5, batch, Numbering::Single, true);
        submitter.submit(job).expect("queued");
        assert_eq!(
            outcome.blocking_recv(),
            Ok(JobOutcome::ResendRefused(ResendRefusal::Mismatched))
        );
    }
    let (job, outcome) = job_on(5, lost.clone(), Numbering::Single, true);
    submitter.submit(job).expect("queued");
    assert_eq!(
        outcome.blocking_recv(),
        Ok(JobOutcome::AlreadyPersisted(head))
    );
    drop(submitter);
    assert_eq!(thread.join().unwrap(), Ok(()));

    let records = log_records(&dir);
    assert_eq!(kdc_events(&records)[4..], numbered(5, &lost)[..]);
    let own: Vec<&Record> = records
        .iter()
        .filter(|r| r.source == Source::Auditd)
        .collect();
    let counted: u64 = own
        .iter()
        .map(|r| {
            assert_eq!(&r.payload[..2], &[0xAD, 0x04]);
            u64::from_be_bytes(r.payload[2..10].try_into().unwrap())
        })
        .sum();
    assert_eq!(counted, 2, "both refusals counted as mismatched");
    assert_eq!(
        own.last().map(|r| r.payload[18..22].to_vec()),
        Some(KDC_UID.to_be_bytes().to_vec())
    );
}

/// Source: crate::resend rule 2 ("no sender resends with a hole, or stops
/// short of the batch it resends": a batch that ends inside a batch auditd
/// appended, or that reuses persisted numbers after a number auditd never
/// received); docs/questions/Q-445 item 3. Both are refused as
/// unverifiable, counted apart from mismatches.
#[test]
fn a_batch_that_reuses_numbers_unverifiably_is_refused() {
    let dir = TempDir::new();
    let mut sink = open(&dir);
    let ten = events(10, LEN, 1);
    persisted(sink.persist_batch(&first_batch(1, ten.clone())));
    // Ends at 7, inside the batch 1..=10, though every octet matches.
    assert_eq!(
        sink.persist_batch(&first_batch(5, ten[4..7].to_vec())),
        Ok(JobOutcome::ResendRefused(ResendRefusal::Unverifiable))
    );
    // A gap: 11..=19 never arrive, 20..=22 do (accepted: nothing overlaps).
    let later = events(3, LEN, 2);
    persisted(sink.persist_batch(&first_batch(20, later.clone())));
    // Reusing 19 (never received) .. 22.
    let mut across = events(1, LEN, 3);
    across.extend(later.iter().cloned());
    let (submitter, inbox) = writer::queue(4);
    let thread = std::thread::spawn(move || writer::run(sink, inbox));
    let (job, outcome) = job_on(19, across, Numbering::Single, true);
    submitter.submit(job).expect("queued");
    assert_eq!(
        outcome.blocking_recv(),
        Ok(JobOutcome::ResendRefused(ResendRefusal::Unverifiable))
    );
    drop(submitter);
    assert_eq!(thread.join().unwrap(), Ok(()));

    let records = log_records(&dir);
    let mut expected = numbered(1, &ten);
    expected.extend(numbered(20, &later));
    assert_eq!(kdc_events(&records), expected);
    let last = records.last().expect("records");
    assert_eq!(last.source, Source::Auditd);
    assert_eq!(last.payload, expected_resends(0, 1, KDC_UID));
}

// ---- a sender that restarts --------------------------------------------------------

/// Source: ipc-audit `SendWindow::new` ("the first event gets sequence
/// number 1" — every sender lifetime numbers from 1, no epoch); decision
/// A-64 ("logged twice possible, never zero"); crate::resend rule 1;
/// docs/questions/Q-445 item 4. After auditd restarts, a restarted kdc
/// numbers from 1 again: accepted as a new numbering; its own resend is
/// recognised against the new numbering (not the old one, whose events
/// under the same numbers differ); a third lifetime whose first batch is
/// byte-identical to the second's is still appended — a batch from 1 is
/// never taken for a duplicate.
#[test]
fn a_restarted_sender_numbering_from_one_is_accepted() {
    let dir = TempDir::new();
    let mut sink = open(&dir);
    let first_life = events(5, LEN, 1);
    persisted(sink.persist_batch(&first_batch(1, first_life.clone())));
    drop(sink);

    let mut sink = open(&dir);
    let second_life = events(5, LEN, 2);
    persisted(sink.persist_batch(&first_batch(1, second_life[..3].to_vec())));
    let head = persisted(sink.persist_batch(&next_batch(4, second_life[3..].to_vec())));
    // That Ack is lost; the resend is checked against the second lifetime.
    assert_eq!(
        sink.persist_batch(&first_batch(4, second_life[3..].to_vec())),
        Ok(JobOutcome::AlreadyPersisted(head))
    );
    drop(sink);

    let mut sink = open(&dir);
    persisted(sink.persist_batch(&first_batch(1, second_life[..3].to_vec())));
    drop(sink);

    let mut expected = numbered(1, &first_life);
    expected.extend(numbered(1, &second_life));
    expected.extend(numbered(1, &second_life[..3]));
    assert_eq!(kdc_events(&log_records(&dir)), expected);
}

/// Source: crate::resend (only a connection's first batch can be a resend;
/// "the current numbering"); ipc-audit `AppendCursor` (a later batch on a
/// connection continues the numbers the connection acknowledged); docs/50
/// §3.6 (the writer's queue: a batch received from a dying sender may still
/// be queued); docs/questions/Q-445 item 3. A batch of the kdc's previous
/// lifetime is persisted after the restarted kdc's first batch (it was
/// still queued): the restarted kdc's next batch on its connection is
/// appended, not refused, and its later resend on a new connection is still
/// recognised.
#[test]
fn a_late_batch_of_a_previous_lifetime_does_not_block_the_restarted_sender() {
    let dir = TempDir::new();
    let mut sink = open(&dir);
    let previous = events(18, LEN, 1);
    persisted(sink.persist_batch(&first_batch(1, previous[..16].to_vec())));
    let restarted = events(6, LEN, 2);
    persisted(sink.persist_batch(&first_batch(1, restarted[..3].to_vec())));
    // The previous lifetime's last batch, persisted late.
    persisted(sink.persist_batch(&next_batch(17, previous[16..].to_vec())));
    // The restarted kdc goes on on its connection: 4..=6.
    let head = persisted(sink.persist_batch(&next_batch(4, restarted[3..].to_vec())));
    // That Ack is lost; the resend on a new connection is recognised.
    assert_eq!(
        sink.persist_batch(&first_batch(4, restarted[3..].to_vec())),
        Ok(JobOutcome::AlreadyPersisted(head))
    );
    drop(sink);
    let records = log_records(&dir);
    assert_eq!(kdc_events(&records).len(), 16 + 3 + 2 + 3);
}

/// Source: docs/50 §3.2 (the transport identity: uid → source);
/// crates/config (a source is named by one uid); crate::resend ("a
/// different uid under the same source starts a fresh state"). After a
/// configuration change, the kdc runs under another uid: its numbers are
/// not checked against the old uid's.
#[test]
fn another_uid_under_the_same_source_starts_afresh() {
    let dir = TempDir::new();
    let mut sink = open(&dir);
    persisted(sink.persist_batch(&first_batch(1, events(5, LEN, 1))));
    let (mut moved, _) = job_on(3, events(2, LEN, 2), Numbering::Single, true);
    moved.source_uid = 900;
    persisted(sink.persist_batch(&moved));
    let tail = sink.tails().tail(Source::Kdc).expect("seen");
    assert_eq!(
        (tail.uid(), tail.last_seq(), tail.remembered()),
        (900, 4, 2)
    );
}

// ---- a label shared by several numberings (test harnesses) ---------------------------

/// Source: crate::resend ("a source shared by several numberings");
/// docs/questions/Q-432 residual (the single-uid harness: several senders,
/// independent numberings, one label), Q-445 item 5. Two senders number
/// from 1 under one label: nothing is refused; on a connection's first
/// batch, leading events equal in number and octets to a remembered event
/// are duplicates — across an auditd restart too; a reused number with
/// other octets is appended.
#[test]
fn a_shared_label_recognises_resends_and_refuses_nothing() {
    let dir = TempDir::new();
    let mut sink = open(&dir);
    let a = events(7, LEN, 1);
    let b = events(5, LEN, 2);
    let shared = |first: u64, batch: &[EventBytes], first_on_connection: bool| {
        job_on(
            first,
            batch.to_vec(),
            Numbering::Shared,
            first_on_connection,
        )
        .0
    };
    persisted(sink.persist_batch(&shared(1, &a[..4], true)));
    persisted(sink.persist_batch(&shared(1, &b[..3], true)));
    persisted(sink.persist_batch(&shared(5, &a[4..6], false)));
    let b_head = persisted(sink.persist_batch(&shared(4, &b[3..5], false)));
    // a's Ack of 5..=6 is lost; a resends 5..=7: only 7 is appended.
    persisted(sink.persist_batch(&shared(5, &a[4..7], true)));
    // auditd restarts; b's Ack of 4..=5 was lost too.
    drop(sink);
    let mut sink = open(&dir);
    assert_eq!(
        sink.persist_batch(&shared(4, &b[3..5], true)),
        Ok(JobOutcome::AlreadyPersisted(b_head))
    );
    // A reused number with other octets: appended, not refused.
    let other = events(1, LEN, 3);
    persisted(sink.persist_batch(&shared(4, &other, true)));
    drop(sink);

    let records = log_records(&dir);
    let mut expected = numbered(1, &a[..4]);
    expected.extend(numbered(1, &b[..3]));
    expected.extend(numbered(5, &a[4..6]));
    expected.extend(numbered(4, &b[3..5]));
    expected.extend(numbered(7, &a[6..7]));
    expected.extend(numbered(4, &other));
    assert_eq!(kdc_events(&records), expected);
    assert!(records.iter().all(|r| r.source != Source::Auditd));
}
