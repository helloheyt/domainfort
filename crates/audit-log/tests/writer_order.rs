//! The acknowledgement means "synced": the writer returns a record's
//! sequence number and hash only after write → flush → sync succeeded, and a
//! failure at any step acknowledges nothing and poisons the writer.
//!
//! Source: docs/50 R50-17 ("processes deliver events in a bounded window and
//! wait for persistence acknowledgements"), §8.1 ("auditd acknowledges the
//! last sequence number persisted"); AGENTS.md §6 (fail closed);
//! docs/questions/Q-250 item 7.

mod common;

use audit_log::{AppendError, Entry, LogWriter, SegmentLimit, Source};
use common::{payload, time, FailAt, MemStorage, Op};

fn entry(data: &[u8], n: u64) -> Entry<'_> {
    Entry {
        source: Source::Keyd,
        source_uid: 801,
        source_seq: n,
        payload: data,
    }
}

/// docs/50 §8.1: per batch, exactly write, flush, sync — and only then the
/// acknowledgement reaches the caller.
#[test]
fn ack_comes_after_sync() {
    let storage = MemStorage::new();
    let mut writer = LogWriter::create(storage.clone(), SegmentLimit::DEFAULT).unwrap();
    // The header is written and synced at creation.
    assert_eq!(storage.ops(), vec![Op::Write, Op::Flush, Op::Sync]);
    for n in 1..=3u64 {
        let data = payload(n);
        let persisted = writer.append(&entry(&data, n), time(n)).unwrap();
        storage.mark_ack();
        assert_eq!(persisted.head.seq, n);
        // Everything acknowledged is in the durable copy.
        assert_eq!(storage.durable(), storage.bytes());
    }
    let ops = storage.ops();
    assert_eq!(
        ops,
        vec![
            Op::Write,
            Op::Flush,
            Op::Sync,
            Op::Write,
            Op::Flush,
            Op::Sync,
            Op::Ack,
            Op::Write,
            Op::Flush,
            Op::Sync,
            Op::Ack,
            Op::Write,
            Op::Flush,
            Op::Sync,
            Op::Ack,
        ]
    );
}

/// A batch is one write and one sync: one acknowledgement for all of it.
#[test]
fn batch_is_one_sync() {
    let storage = MemStorage::new();
    let mut writer = LogWriter::create(storage.clone(), SegmentLimit::DEFAULT).unwrap();
    let datas: Vec<Vec<u8>> = (1..=10).map(payload).collect();
    let entries: Vec<Entry<'_>> = datas.iter().zip(1u64..).map(|(d, n)| entry(d, n)).collect();
    writer.append_batch(&entries, time(1)).unwrap();
    storage.mark_ack();
    assert_eq!(
        &storage.ops()[3..],
        &[Op::Write, Op::Flush, Op::Sync, Op::Ack]
    );
}

/// A failed sync acknowledges nothing, keeps the head, and poisons the
/// writer: every later append is refused without touching the storage.
#[test]
fn failed_sync_is_never_acknowledged() {
    for fail in [FailAt::Write, FailAt::Flush, FailAt::Sync] {
        let storage = MemStorage::new();
        let mut writer = LogWriter::create(storage.clone(), SegmentLimit::DEFAULT).unwrap();
        let data = payload(1);
        writer.append(&entry(&data, 1), time(1)).unwrap();
        let head = writer.head();
        let durable = storage.durable();

        storage.fail_next(fail);
        let result = writer.append(&entry(&data, 2), time(2));
        assert!(
            matches!(result, Err(AppendError::Io(_))),
            "{fail:?}: {result:?}"
        );
        assert!(writer.is_poisoned());
        assert_eq!(writer.head(), head, "head not advanced");
        assert_eq!(storage.durable(), durable, "nothing new is durable");

        let ops_before = storage.ops().len();
        assert_eq!(
            writer.append(&entry(&data, 3), time(3)),
            Err(AppendError::Poisoned)
        );
        assert_eq!(storage.ops().len(), ops_before, "storage untouched");
        let next = MemStorage::new();
        assert_eq!(writer.rotate(next).err(), Some(AppendError::Poisoned));
    }
}

/// A failed segment creation reports the error (nothing to acknowledge).
#[test]
fn failed_create() {
    let storage = MemStorage::new();
    storage.fail_next(FailAt::Sync);
    assert!(matches!(
        LogWriter::create(storage, SegmentLimit::DEFAULT),
        Err(AppendError::Io(_))
    ));
}

/// A failed rotation leaves the writer on its old segment, not poisoned.
#[test]
fn failed_rotation_keeps_the_old_segment() {
    let storage = MemStorage::new();
    let mut writer = LogWriter::create(storage.clone(), SegmentLimit::DEFAULT).unwrap();
    let data = payload(1);
    writer.append(&entry(&data, 1), time(1)).unwrap();
    let next = MemStorage::new();
    next.fail_next(FailAt::Sync);
    assert!(matches!(writer.rotate(next), Err(AppendError::Io(_))));
    assert!(!writer.is_poisoned());
    writer.append(&entry(&data, 2), time(2)).unwrap();
    assert_eq!(writer.head().seq, 2);
    let bytes = storage.bytes();
    audit_log::verify_segment(
        &bytes[..],
        audit_log::Anchor::Genesis,
        SegmentLimit::DEFAULT,
        Some(writer.head()),
    )
    .unwrap();
}
