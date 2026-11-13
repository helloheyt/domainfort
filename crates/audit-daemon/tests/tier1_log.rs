//! Tier 1 (docs/50 §9): in-process, no sockets — start-up verification and
//! recovery, the single writer, rotation, and auditd's own record layout.
//!
//! Each test names its source. Payloads are arbitrary test octets; expected
//! encodings come from this project's layouts (`audit_daemon::own_event`,
//! crates/audit-log `format`).

mod common;

use audit_daemon::binding::{batch_permitted, bound_source, permits};
use audit_daemon::own_event::{
    AuditdEvent, EventsMisbound, PeersRefused, SegmentRecovered, TornKind, EVENTS_MISBOUND_LEN,
};
use audit_daemon::recovery::{open_log, StartKind, StartupError};
use audit_daemon::segments::{
    list_segments, segment_path, ListingError, SegmentFactory, SEGMENT_DIGITS,
};
use audit_daemon::writer::{self, AppendJob, JobOutcome, LogSink, SubmitError, WriterFailure};
use audit_log::{
    verify_log, Anchor, BreakKind, ChainHead, LogWriter, SegmentLimit, Source, Storage,
    GENESIS_HASH,
};
use common::*;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;
use tokio::sync::oneshot;

const OWN_UID: u32 = 4242;

fn make_job(
    first: u64,
    events: Vec<ipc_audit::EventBytes>,
) -> (AppendJob, oneshot::Receiver<JobOutcome>) {
    let (reply, outcome) = oneshot::channel();
    (
        AppendJob {
            source: Source::Kdc,
            source_uid: 803,
            first_source_seq: first,
            events,
            reply,
        },
        outcome,
    )
}

// ---- layouts ----------------------------------------------------------------

/// Source: audit_daemon::own_event layout (docs/questions/Q-265 item 4);
/// Q-250 item 8.
#[test]
fn own_event_layouts() {
    let head = ChainHead {
        seq: 7,
        hash: audit_log::RecordHash::from_bytes([0x5A; 32]),
    };
    let recovered = AuditdEvent::SegmentRecovered(SegmentRecovered {
        segment: 3,
        torn: TornKind::RecordTruncated,
        last_good: head,
        break_offset: 1000,
        segment_octets: 1010,
    });
    assert_eq!(
        recovered.encode(),
        expected_recovered(3, 0x02, head, 1000, 1010)
    );
    let refused = AuditdEvent::PeersRefused(PeersRefused {
        unmapped: 2,
        over_quota: 1,
        last_uid: 501,
    });
    assert_eq!(refused.encode(), expected_refused(2, 1, 501));
    // Kind 0x03, appended for the source binding (docs/questions/Q-341).
    let misbound = AuditdEvent::EventsMisbound(EventsMisbound {
        refused_batches: 3,
        last_uid: 803,
    });
    assert_eq!(misbound.encode(), expected_misbound(3, 803));
    assert_eq!(misbound.encode().len(), EVENTS_MISBOUND_LEN);
}

// ---- the source binding of the event shapes ----------------------------------

/// Source: docs/50 §3.2 (the source is the connection's uid), §4.2 (dird
/// writes the LDAP events), §8.1; docs/51 §5.7 (dird is the source of the
/// admin write events; admind sends its own); docs/questions/Q-341
/// (option (a): every shape bound, `WindowSummary` from any source).
#[test]
fn binding_table() {
    use ipc_audit::EventShape;
    assert_eq!(bound_source(EventShape::Kdc), Some(Source::Kdc));
    assert_eq!(bound_source(EventShape::Keyd), Some(Source::Keyd));
    assert_eq!(bound_source(EventShape::Ldap), Some(Source::Dird));
    assert_eq!(bound_source(EventShape::DirAdmin), Some(Source::Dird));
    assert_eq!(bound_source(EventShape::Admind), Some(Source::Admind));
    assert_eq!(bound_source(EventShape::WindowSummary), None);
    // No shape is bound to ldap-front (it sends no events) or to auditd
    // (its own records never come over the socket).
    for shape in EventShape::ALL {
        assert_ne!(bound_source(*shape), Some(Source::LdapFront));
        assert_ne!(bound_source(*shape), Some(Source::Auditd));
    }
    // Every shape of the closed table is classified (a new shape fails
    // the exhaustive match in `bound_source` until it is).
    assert_eq!(EventShape::ALL.len(), 6);
}

/// Source: docs/50 §3.2, §4.2, §8.1; docs/51 §5.7; docs/questions/Q-341.
/// Each shape is permitted only from its sender, `WindowSummary` from any;
/// opaque payloads (not in the event format) from any source, as before.
#[test]
fn binding_permits() {
    let dir_admin = encoded(&dir_admin_pair());
    let admind = encoded(&admind_events());
    for source in Source::ALL {
        for event in &dir_admin {
            assert_eq!(permits(source, event), source == Source::Dird, "{source:?}");
        }
        for event in &admind {
            assert_eq!(
                permits(source, event),
                source == Source::Admind,
                "{source:?}"
            );
        }
        // Opaque test payloads (not the event format) are not bound.
        for event in events(4, 32, 7) {
            assert!(permits(source, &event));
        }
        // The older shapes (only the shape octet is read): Kdc ⇐ kdc,
        // Keyd ⇐ keyd, Ldap ⇐ dird, WindowSummary ⇐ any.
        for (shape, sender) in [
            (1u8, Some(Source::Kdc)),
            (2, Some(Source::Keyd)),
            (3, Some(Source::Dird)),
            (4, None),
        ] {
            let event = ipc_audit::EventBytes::new(vec![ipc_audit::EVENT_FORMAT, shape]).unwrap();
            let expected = match sender {
                Some(sender) => sender == source,
                None => true,
            };
            assert_eq!(
                permits(source, &event),
                expected,
                "{source:?} shape {shape}"
            );
        }
        // Another format octet: not bound.
        let event = ipc_audit::EventBytes::new(vec![ipc_audit::EVENT_FORMAT + 1, 1]).unwrap();
        assert!(permits(source, &event));
        // A shape code past the table, or another format octet: not bound.
        let event = ipc_audit::EventBytes::new(vec![ipc_audit::EVENT_FORMAT, 7, 0]).unwrap();
        assert!(permits(source, &event));
        let event = ipc_audit::EventBytes::new(vec![0xAD, 5]).unwrap();
        assert!(permits(source, &event));
    }
    // The shape octet alone decides — the rest is never decoded.
    let bare = ipc_audit::EventBytes::new(vec![ipc_audit::EVENT_FORMAT, 5]).unwrap();
    assert!(permits(Source::Dird, &bare));
    assert!(!permits(Source::Kdc, &bare));
    // One misbound event refuses the whole batch.
    let mut batch = events(3, 32, 9);
    assert!(batch_permitted(Source::Kdc, &batch));
    batch.push(dir_admin[0].clone());
    assert!(!batch_permitted(Source::Kdc, &batch));
    assert!(batch_permitted(Source::Dird, &batch));
}

/// Source: docs/51 §5.7 (the new shapes are persisted like every event),
/// docs/50 §3.2, §8.1 (transport identity), §7.5 (the chain verifies at the
/// next start). The admin-plane events are stored through the existing
/// writer path, verify, and decode back to themselves.
#[test]
fn admin_events_persist_and_verify_at_restart() {
    let dir = TempDir::new();
    let mut sink = open_log(&dir.base(), SegmentLimit::DEFAULT, OWN_UID)
        .expect("created")
        .sink;
    let dir_admin = dir_admin_pair();
    let admind = admind_events();
    sink.append_events(Source::Dird, 802, 1, &encoded(&dir_admin))
        .expect("dird batch persisted");
    let persisted = sink
        .append_events(Source::Admind, 806, 1, &encoded(&admind))
        .expect("admind batch persisted");
    drop(sink);

    // The next start verifies every segment (A-66) and resumes.
    let reopened = open_log(&dir.base(), SegmentLimit::DEFAULT, OWN_UID).expect("verifies");
    assert_eq!(reopened.start, StartKind::Resumed);
    assert_eq!(reopened.sink.head(), persisted.head);
    drop(reopened);

    let (records, head) = read_segment(&dir.base(), 1, Anchor::Genesis);
    assert_eq!(head, persisted.head);
    assert_eq!(records.len(), 4);
    let expected: Vec<(Source, u32, u64, &ipc_audit::EventBody)> = vec![
        (Source::Dird, 802, 1, &dir_admin[0]),
        (Source::Dird, 802, 2, &dir_admin[1]),
        (Source::Admind, 806, 1, &admind[0]),
        (Source::Admind, 806, 2, &admind[1]),
    ];
    for (record, (source, uid, seq, event)) in records.iter().zip(expected) {
        assert_eq!(record.source, source);
        assert_eq!(record.source_uid, uid);
        assert_eq!(record.source_seq, seq);
        assert_eq!(&ipc_audit::decode_event(&record.payload).unwrap(), event);
    }
}

/// Source: audit_daemon::segments naming rule (docs/questions/Q-265 item 2).
#[test]
fn segment_names_have_twenty_digits() {
    let path = segment_path(std::path::Path::new("/var/log/audit/a.log"), 12);
    assert_eq!(
        path.to_str(),
        Some("/var/log/audit/a.log.00000000000000000012")
    );
    assert_eq!(SEGMENT_DIGITS, 20);
}

// ---- start-up ---------------------------------------------------------------

/// Source: docs/50 §7.5 (auditd opens the file and verifies the chain);
/// Q-250 item 2 (genesis).
#[test]
fn empty_directory_creates_segment_one_then_resumes() {
    let dir = TempDir::new();
    let opened = open_log(&dir.base(), SegmentLimit::DEFAULT, OWN_UID).expect("created");
    assert_eq!(opened.start, StartKind::Created);
    assert_eq!(opened.sink.head(), ChainHead::GENESIS);
    assert_eq!(opened.sink.segment(), 1);
    drop(opened);
    assert_eq!(segment_bytes(&dir.base(), 1).len() as u64, header_len());

    let reopened = open_log(&dir.base(), SegmentLimit::DEFAULT, OWN_UID).expect("resumed");
    assert_eq!(reopened.start, StartKind::Resumed);
    assert_eq!(reopened.sink.segment(), 1);
}

/// Source: docs/50 §8.1 (the acknowledgement names what was persisted),
/// §3.2 (source and uid from the transport); docs/37 §2.
#[test]
fn appended_batch_persists_with_transport_identity() {
    let dir = TempDir::new();
    let mut sink = open_log(&dir.base(), SegmentLimit::DEFAULT, OWN_UID)
        .expect("created")
        .sink;
    let batch = events(3, 40, 1);
    let persisted = sink
        .append_events(Source::Dird, 802, 10, &batch)
        .expect("persisted");
    assert_eq!(persisted.first_seq, 1);
    assert_eq!(persisted.head.seq, 3);
    drop(sink);

    let (records, head) = read_segment(&dir.base(), 1, Anchor::Genesis);
    assert_eq!(head, persisted.head);
    assert_eq!(records.len(), 3);
    for (i, record) in records.iter().enumerate() {
        assert_eq!(record.source, Source::Dird);
        assert_eq!(record.source_uid, 802);
        assert_eq!(record.source_seq, 10 + i as u64);
        assert_eq!(record.payload, batch[i].as_bytes());
    }
}

// ---- the writer thread ------------------------------------------------------

/// A storage whose sync can be held, recording the order of calls.
#[derive(Clone)]
struct GateStorage {
    state: Arc<(Mutex<GateState>, Condvar)>,
}

#[derive(Default)]
struct GateState {
    ops: Vec<&'static str>,
    hold_sync: bool,
    fail_sync: bool,
}

impl GateStorage {
    fn new() -> GateStorage {
        GateStorage {
            state: Arc::new((Mutex::new(GateState::default()), Condvar::new())),
        }
    }

    fn set(&self, f: impl FnOnce(&mut GateState)) {
        let (lock, changed) = &*self.state;
        f(&mut lock.lock().unwrap());
        changed.notify_all();
    }

    fn ops(&self) -> Vec<&'static str> {
        self.state.0.lock().unwrap().ops.clone()
    }
}

impl Storage for GateStorage {
    fn write_all(&mut self, _octets: &[u8]) -> io::Result<()> {
        self.state.0.lock().unwrap().ops.push("write");
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.state.0.lock().unwrap().ops.push("flush");
        Ok(())
    }

    fn sync(&mut self) -> io::Result<()> {
        let (lock, changed) = &*self.state;
        let mut state = lock.lock().unwrap();
        while state.hold_sync {
            state = changed.wait(state).unwrap();
        }
        if state.fail_sync {
            return Err(io::Error::other("injected sync failure"));
        }
        state.ops.push("sync");
        Ok(())
    }
}

struct GateFactory;

impl SegmentFactory for GateFactory {
    type Storage = GateStorage;

    fn create(&mut self, _index: u64) -> io::Result<GateStorage> {
        Err(io::Error::other("no rotation in this test"))
    }
}

/// Source: docs/50 §8.1 ("auditd acknowledges the last sequence number
/// persisted"); crates/audit-log writer (ack only after sync); A-57.
#[test]
fn writer_acknowledges_only_after_sync() {
    let storage = GateStorage::new();
    let log = LogWriter::create(storage.clone(), SegmentLimit::DEFAULT).expect("header");
    let sink = LogSink::new(log, 1, GateFactory, OWN_UID);
    let (submitter, inbox) = writer::queue(4);
    let thread = std::thread::spawn(move || writer::run(sink, inbox));

    storage.set(|s| {
        s.ops.clear();
        s.hold_sync = true;
    });
    let (job, mut outcome) = make_job(1, events(2, 16, 2));
    submitter.submit(job).expect("queued");
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        matches!(outcome.try_recv(), Err(oneshot::error::TryRecvError::Empty)),
        "no answer while the sync is held"
    );
    assert_eq!(storage.ops(), ["write", "flush"]);

    storage.set(|s| s.hold_sync = false);
    let answer = outcome.blocking_recv().expect("answered");
    assert!(matches!(answer, JobOutcome::Persisted(head) if head.seq == 2));
    assert_eq!(storage.ops(), ["write", "flush", "sync"]);

    drop(submitter);
    assert_eq!(thread.join().unwrap(), Ok(()));
}

/// Source: docs/questions/Q-250 item 7 (a failed sync poisons the writer;
/// nothing is acknowledged); Q-265 item 7; docs/50 §3.7 (`Unavailable`,
/// fail closed).
#[test]
fn failed_sync_answers_unavailable_and_stops_the_writer() {
    let storage = GateStorage::new();
    let log = LogWriter::create(storage.clone(), SegmentLimit::DEFAULT).expect("header");
    let sink = LogSink::new(log, 1, GateFactory, OWN_UID);
    let (submitter, inbox) = writer::queue(4);
    let thread = std::thread::spawn(move || writer::run(sink, inbox));

    storage.set(|s| s.fail_sync = true);
    let (job, outcome) = make_job(1, events(1, 16, 3));
    submitter.submit(job).expect("queued");
    assert_eq!(outcome.blocking_recv(), Ok(JobOutcome::Unavailable));
    assert_eq!(thread.join().unwrap(), Err(WriterFailure::Poisoned));
    assert!(!submitter.is_available());
    let (job, _outcome) = make_job(2, events(1, 16, 3));
    assert_eq!(submitter.submit(job), Err(SubmitError::Unavailable));
}

/// Source: docs/07 §8 ("the log does not bring the service down when it
/// fills"); docs/questions/Q-250 item 6 (rotate to a new segment anchored
/// at the current head; one chain across files); A-57.
#[test]
fn segment_full_rotates_and_the_chain_continues() {
    let dir = TempDir::new();
    let limit = SegmentLimit::new(SegmentLimit::MIN).expect("limit");
    let sink = open_log(&dir.base(), limit, OWN_UID).expect("created").sink;
    let (submitter, inbox) = writer::queue(4);
    let thread = std::thread::spawn(move || writer::run(sink, inbox));

    // 16 events of 8 KiB per batch: the fifth batch no longer fits.
    let mut last = ChainHead::GENESIS;
    for batch in 0..5u64 {
        let (job, outcome) = make_job(1 + batch * 16, events(16, 8192, batch as u8));
        submitter.submit(job).expect("queued");
        match outcome.blocking_recv().expect("answered") {
            JobOutcome::Persisted(head) => last = head,
            JobOutcome::Unavailable => panic!("batch {batch} refused"),
        }
    }
    drop(submitter);
    assert_eq!(thread.join().unwrap(), Ok(()));
    assert_eq!(last.seq, 80);

    assert_eq!(list_segments(&dir.base()), Ok(vec![1, 2]));
    let (first, first_head) = read_segment(&dir.base(), 1, Anchor::Genesis);
    assert_eq!(first.len(), 64);
    let (second, second_head) = read_segment(&dir.base(), 2, Anchor::After(first_head));
    assert_eq!(second.len(), 16);
    assert_eq!(second_head, last);
    let files = [1, 2].map(|i| std::fs::File::open(segment_path(&dir.base(), i)).unwrap());
    assert_eq!(
        verify_log(files, Anchor::Genesis, limit, Some(last)),
        Ok(last)
    );

    let reopened = open_log(&dir.base(), limit, OWN_UID).expect("resumed");
    assert_eq!(reopened.start, StartKind::Resumed);
    assert_eq!(reopened.sink.segment(), 2);
    assert_eq!(reopened.sink.head(), last);
}

// ---- torn-tail recovery -----------------------------------------------------

/// Source: docs/questions/Q-250 item 8 (keep the damaged segment, start a new
/// segment anchored at `last_good`, write an `Auditd` record — never
/// truncate); docs/37 §2 (append-only); docs/50 §7.5.
#[test]
fn torn_record_starts_a_new_segment_at_last_good() {
    let dir = TempDir::new();
    let built = build_log(&dir.base(), &[4], 50);
    // A crash during the last write: the fourth record is cut short.
    let full = built.lengths[0];
    let cut = full - 10;
    OpenOptions::new()
        .write(true)
        .open(segment_path(&dir.base(), 1))
        .unwrap()
        .set_len(cut)
        .unwrap();
    let torn_before = segment_bytes(&dir.base(), 1);
    let last_good = built.heads[2];
    let break_offset = full - record_len(50) as u64;

    let opened = open_log(&dir.base(), SegmentLimit::DEFAULT, OWN_UID).expect("recovered");
    let expected = SegmentRecovered {
        segment: 1,
        torn: TornKind::RecordTruncated,
        last_good,
        break_offset,
        segment_octets: cut,
    };
    assert_eq!(opened.start, StartKind::Recovered(expected));
    assert_eq!(opened.sink.segment(), 2);
    let mut sink = opened.sink;
    let after = sink
        .append_events(Source::Kdc, 803, 5, &events(2, 30, 9))
        .expect("append");
    drop(sink);

    // The torn segment is unchanged; segment 2 continues from `last_good`
    // and begins with the recovery record.
    assert_eq!(segment_bytes(&dir.base(), 1), torn_before);
    let (records, head) = read_segment(&dir.base(), 2, Anchor::After(last_good));
    assert_eq!(records.len(), 3);
    assert_eq!(records[0].source, Source::Auditd);
    assert_eq!(records[0].source_uid, OWN_UID);
    assert_eq!(records[0].seq, last_good.seq + 1);
    assert_eq!(
        records[0].payload,
        expected_recovered(1, 0x02, last_good, break_offset, cut)
    );
    assert_eq!(head, after.head);

    // A restart verifies the whole log end to end and resumes.
    let reopened = open_log(&dir.base(), SegmentLimit::DEFAULT, OWN_UID).expect("verified");
    assert_eq!(reopened.start, StartKind::Resumed);
    assert_eq!(reopened.sink.head(), after.head);
}

/// Source: docs/questions/Q-250 items 6, 8 (a crash while a rotation starts
/// a segment leaves a header cut short); Q-265 item 1.
#[test]
fn torn_header_after_rotation_is_recovered() {
    let dir = TempDir::new();
    let built = build_log(&dir.base(), &[3], 20);
    // Segment 2 was created but its header never reached the disk.
    std::fs::write(segment_path(&dir.base(), 2), [b'A', b'U', b'D']).unwrap();
    let head = built.heads[2];

    let opened = open_log(&dir.base(), SegmentLimit::DEFAULT, OWN_UID).expect("recovered");
    let expected = SegmentRecovered {
        segment: 2,
        torn: TornKind::HeaderTruncated,
        last_good: head,
        break_offset: 0,
        segment_octets: 3,
    };
    assert_eq!(opened.start, StartKind::Recovered(expected));
    assert_eq!(opened.sink.segment(), 3);
    drop(opened);

    let (records, _) = read_segment(&dir.base(), 3, Anchor::After(head));
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].payload, expected_recovered(2, 0x01, head, 0, 3));
    let again = open_log(&dir.base(), SegmentLimit::DEFAULT, OWN_UID).expect("verified");
    assert_eq!(again.start, StartKind::Resumed);
}

/// Source: docs/questions/Q-250 item 8; this crate's recovery rule for a
/// recovery interrupted after its header was synced (crate::recovery).
#[test]
fn interrupted_recovery_is_completed() {
    let dir = TempDir::new();
    let built = build_log(&dir.base(), &[2], 20);
    let cut = built.lengths[0] - 1;
    OpenOptions::new()
        .write(true)
        .open(segment_path(&dir.base(), 1))
        .unwrap()
        .set_len(cut)
        .unwrap();
    let last_good = built.heads[0];
    // The recovery segment's header is on disk, its record is not.
    let storage = audit_log::FileStorage::create_new(&segment_path(&dir.base(), 2)).unwrap();
    drop(LogWriter::start_segment(storage, last_good, SegmentLimit::DEFAULT).unwrap());

    let opened = open_log(&dir.base(), SegmentLimit::DEFAULT, OWN_UID).expect("completed");
    assert!(matches!(opened.start, StartKind::Recovered(r) if r.segment == 1));
    assert_eq!(opened.sink.segment(), 2);
    drop(opened);
    let (records, _) = read_segment(&dir.base(), 2, Anchor::After(last_good));
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].source, Source::Auditd);
    let again = open_log(&dir.base(), SegmentLimit::DEFAULT, OWN_UID).expect("verified");
    assert_eq!(again.start, StartKind::Resumed);
}

// ---- refusal: a break in the middle -----------------------------------------

fn flip(base: &std::path::Path, index: u64, offset: u64) {
    let path = segment_path(base, index);
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[offset as usize] ^= 0x01;
    std::fs::write(&path, bytes).unwrap();
}

fn refused(dir: &TempDir) -> StartupError {
    let error = open_log(&dir.base(), SegmentLimit::DEFAULT, OWN_UID).expect_err("refused");
    assert!(error.is_chain_break(), "{error:?} is a chain break");
    error
}

/// Source: docs/37 §2 ("deleting or changing a record breaks the chain and
/// is detected"); docs/50 §7.5; task P6b (refuse to start, fail closed).
#[test]
fn altered_record_in_an_earlier_segment_refuses_start() {
    let dir = TempDir::new();
    build_log(&dir.base(), &[3, 2], 20);
    // An octet of record 2's payload: record 3 no longer links.
    let offset = header_len() + record_len(20) as u64 + record_len(20) as u64 - 1;
    flip(&dir.base(), 1, offset);
    assert_eq!(
        refused(&dir),
        StartupError::ChainBreak {
            segment: 1,
            kind: BreakKind::LinkMismatch,
            at_seq: 3
        }
    );
}

/// Source: docs/37 §2; docs/50 §7.5.
#[test]
fn altered_record_in_the_last_segment_refuses_start() {
    let dir = TempDir::new();
    build_log(&dir.base(), &[2, 3], 20);
    let offset = header_len() + record_len(20) as u64 - 1;
    flip(&dir.base(), 2, offset);
    assert!(matches!(
        refused(&dir),
        StartupError::ChainBreak {
            segment: 2,
            kind: BreakKind::LinkMismatch,
            ..
        }
    ));
}

/// Source: docs/37 §2 (a deleted part of the log is detected); Q-265 item 2.
#[test]
fn missing_segment_refuses_start() {
    let dir = TempDir::new();
    build_log(&dir.base(), &[1, 1, 1], 20);
    std::fs::remove_file(segment_path(&dir.base(), 2)).unwrap();
    assert_eq!(
        refused(&dir),
        StartupError::Listing(ListingError::SegmentMissing { expected: 2 })
    );
}

/// Source: Q-265 item 2 (strict listing: a name with the segment prefix must
/// be exactly 20 digits naming 1 ..= u64::MAX; a file at the base path, or
/// a segment that is not a regular file, is refused).
#[test]
fn stray_segment_names_refuse_start() {
    let bad_names = [
        "audit.log.7",
        "audit.log.0000000000000000001",   // 19 digits
        "audit.log.000000000000000000001", // 21 digits
        "audit.log.00000000000000000000",  // segment 0
        "audit.log.99999999999999999999",  // above u64::MAX
        "audit.log.0000000000000000000x",
        "audit.log.",
        "audit.log",
    ];
    for name in bad_names {
        let dir = TempDir::new();
        build_log(&dir.base(), &[1], 20);
        std::fs::write(dir.path().join(name), b"x").unwrap();
        assert_eq!(
            refused(&dir),
            StartupError::Listing(ListingError::UnexpectedFile),
            "{name}"
        );
    }

    // A symbolic link named like the next segment is refused, not followed.
    let dir = TempDir::new();
    build_log(&dir.base(), &[1], 20);
    std::os::unix::fs::symlink(segment_path(&dir.base(), 1), segment_path(&dir.base(), 2)).unwrap();
    assert_eq!(
        refused(&dir),
        StartupError::Listing(ListingError::UnexpectedFile)
    );

    // Names that are not the log's are left alone.
    let dir = TempDir::new();
    build_log(&dir.base(), &[1], 20);
    std::fs::write(dir.path().join("audit.logs"), b"x").unwrap();
    std::fs::write(dir.path().join("other.log.00000000000000000001"), b"x").unwrap();
    let opened = open_log(&dir.base(), SegmentLimit::DEFAULT, OWN_UID).expect("resumed");
    assert_eq!(opened.start, StartKind::Resumed);
}

/// Source: Q-250 item 8; crate::recovery (a torn segment in the middle is
/// accepted only before its recovery record).
#[test]
fn torn_segment_without_recovery_record_refuses_start() {
    let dir = TempDir::new();
    let built = build_log(&dir.base(), &[2], 20);
    let cut = built.lengths[0] - 5;
    OpenOptions::new()
        .write(true)
        .open(segment_path(&dir.base(), 1))
        .unwrap()
        .set_len(cut)
        .unwrap();
    // A forged next segment anchored at last_good whose first record is an
    // ordinary event, not the recovery record.
    let storage = audit_log::FileStorage::create_new(&segment_path(&dir.base(), 2)).unwrap();
    let mut forged =
        LogWriter::start_segment(storage, built.heads[0], SegmentLimit::DEFAULT).unwrap();
    let entry = audit_log::Entry {
        source: Source::Kdc,
        source_uid: 1234,
        source_seq: 9,
        payload: b"forged",
    };
    forged
        .append(&entry, audit_log::Timestamp::new(1, 0).unwrap())
        .unwrap();
    drop(forged);
    assert_eq!(
        refused(&dir),
        StartupError::RecoveryRecordMissing { segment: 1 }
    );
}

/// Source: Q-250 item 8; docs/37 §2 (the recovery record pins the torn
/// segment's length: octets added later are detected).
#[test]
fn octets_added_to_a_recovered_segment_refuse_start() {
    let dir = TempDir::new();
    let built = build_log(&dir.base(), &[2], 20);
    OpenOptions::new()
        .write(true)
        .open(segment_path(&dir.base(), 1))
        .unwrap()
        .set_len(built.lengths[0] - 3)
        .unwrap();
    drop(open_log(&dir.base(), SegmentLimit::DEFAULT, OWN_UID).expect("recovered"));
    let mut torn = OpenOptions::new()
        .append(true)
        .open(segment_path(&dir.base(), 1))
        .unwrap();
    torn.write_all(&[0x00]).unwrap();
    drop(torn);
    assert_eq!(
        refused(&dir),
        StartupError::RecoveryRecordMissing { segment: 1 }
    );
}

/// Source: Q-265 item 1 (a tail of zero octets is not a torn record: it is
/// refused, the verifier cannot tell it from tampering).
#[test]
fn zero_filled_tail_refuses_start() {
    let dir = TempDir::new();
    build_log(&dir.base(), &[2], 20);
    let mut file = OpenOptions::new()
        .append(true)
        .open(segment_path(&dir.base(), 1))
        .unwrap();
    file.write_all(&[0u8; 16]).unwrap();
    drop(file);
    assert!(matches!(
        refused(&dir),
        StartupError::ChainBreak {
            segment: 1,
            kind: BreakKind::RecordLengthOutOfBounds,
            ..
        }
    ));
}

/// Source: docs/37 §2 (a replaced first segment is detected: genesis
/// anchor); Q-250 item 2.
#[test]
fn first_segment_not_at_genesis_refuses_start() {
    let dir = TempDir::new();
    let storage = audit_log::FileStorage::create_new(&segment_path(&dir.base(), 1)).unwrap();
    let anchor = ChainHead {
        seq: 5,
        hash: audit_log::RecordHash::from_bytes([7; 32]),
    };
    assert_ne!(anchor.hash, GENESIS_HASH);
    drop(LogWriter::start_segment(storage, anchor, SegmentLimit::DEFAULT).unwrap());
    assert!(matches!(
        refused(&dir),
        StartupError::ChainBreak {
            segment: 1,
            kind: BreakKind::AnchorMismatch,
            ..
        }
    ));
}

// ---- the binary's early refusals (no hardening reached) ---------------------

/// Source: docs/50 §7.5 (exit with an error code on any start-up failure),
/// §8.2 (fixed texts); task P6b (argv config path).
#[test]
fn binary_without_argument_exits_with_usage() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_audit-daemon"))
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.starts_with("audit-daemon: usage:"), "{stderr}");
}

/// Source: docs/50 §7.1 (configuration root:0644); Q-230 item 16 (file
/// modes are the daemon's checks).
#[test]
fn binary_refuses_a_writable_configuration() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new();
    let path = dir.path().join("auditd.conf");
    std::fs::write(&path, settings_text(&dir, 801, 5)).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_audit-daemon"))
        .arg(&path)
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        stderr.trim_end(),
        "audit-daemon: configuration file is writable by group or others"
    );
}
