//! Bounds: oversize records are refused before anything is written, the
//! segment bound turns into rotation (never shutdown), and the verifier
//! checks every declared length before reading.
//!
//! Source: docs/50 §3.3 ("audit ≤ 8 KiB per event"); docs/07 §8 ("the log
//! does not bring the service down when it fills"; "a separate disk
//! quota"); docs/questions/Q-218 (A-57: log overflow does not turn into
//! shutdown); AGENTS.md §6 (bounded parsers, no allocation from an
//! attacker-supplied length); docs/questions/Q-250 items 3, 4, 6.

mod common;

use audit_log::{
    verify_segment, Anchor, AppendError, BreakKind, ChainHead, Entry, LogWriter, SegmentHeader,
    SegmentLimit, Source, MAX_BATCH_RECORDS, MAX_PAYLOAD_LEN, MAX_RECORD_LEN, SEGMENT_HEADER_LEN,
};
use common::{time, MemStorage, Op};

fn entry(data: &[u8]) -> Entry<'_> {
    Entry {
        source: Source::Kdc,
        source_uid: 803,
        source_seq: 1,
        payload: data,
    }
}

/// docs/50 §3.3: a payload over 8 KiB is refused, and nothing is written.
#[test]
fn oversize_record_is_refused() {
    let storage = MemStorage::new();
    let mut writer = LogWriter::create(storage.clone(), SegmentLimit::DEFAULT).unwrap();
    let ops = storage.ops().len();
    let big = vec![0x41u8; MAX_PAYLOAD_LEN + 1];
    assert_eq!(
        writer.append(&entry(&big), time(1)),
        Err(AppendError::PayloadOutOfBounds { index: 0 })
    );
    assert_eq!(storage.ops().len(), ops, "nothing written");
    assert!(!writer.is_poisoned());
    // The largest allowed payload is accepted.
    let max = vec![0x41u8; MAX_PAYLOAD_LEN];
    writer.append(&entry(&max), time(1)).unwrap();
    // An empty payload is refused (docs/questions/Q-250 item 3).
    assert_eq!(
        writer.append(&entry(&[]), time(1)),
        Err(AppendError::PayloadOutOfBounds { index: 0 })
    );
}

/// One oversize entry refuses the whole batch, before anything is written.
#[test]
fn oversize_entry_refuses_the_batch() {
    let storage = MemStorage::new();
    let mut writer = LogWriter::create(storage.clone(), SegmentLimit::DEFAULT).unwrap();
    let ok = vec![1u8; 10];
    let big = vec![1u8; MAX_PAYLOAD_LEN + 1];
    let entries = [entry(&ok), entry(&ok), entry(&big)];
    let ops = storage.ops().len();
    assert_eq!(
        writer.append_batch(&entries, time(1)),
        Err(AppendError::PayloadOutOfBounds { index: 2 })
    );
    assert_eq!(storage.ops().len(), ops);
    assert_eq!(writer.head(), ChainHead::GENESIS);
}

/// Batch bounds: empty and over [`MAX_BATCH_RECORDS`] are refused.
#[test]
fn batch_bounds() {
    let storage = MemStorage::new();
    let mut writer = LogWriter::create(storage, SegmentLimit::DEFAULT).unwrap();
    assert_eq!(
        writer.append_batch(&[], time(1)),
        Err(AppendError::EmptyBatch)
    );
    let data = [7u8];
    let entries = vec![entry(&data); MAX_BATCH_RECORDS + 1];
    assert_eq!(
        writer.append_batch(&entries, time(1)),
        Err(AppendError::BatchTooLarge)
    );
    writer
        .append_batch(&entries[..MAX_BATCH_RECORDS], time(1))
        .unwrap();
}

/// docs/07 §8, A-57: a full segment refuses the batch before writing
/// (`SegmentFull`), the writer is not poisoned, and after rotation the same
/// batch is accepted — overflow becomes rotation, never shutdown.
#[test]
fn full_segment_rotates() {
    let limit = SegmentLimit::new(SegmentLimit::MIN).unwrap();
    let storage = MemStorage::new();
    let mut writer = LogWriter::create(storage.clone(), limit).unwrap();
    let max = vec![0x55u8; MAX_PAYLOAD_LEN];
    let entries = vec![entry(&max); MAX_BATCH_RECORDS];
    writer.append_batch(&entries, time(1)).unwrap();
    assert_eq!(
        writer.segment_len(),
        (SEGMENT_HEADER_LEN + MAX_BATCH_RECORDS * MAX_RECORD_LEN) as u64
    );
    let ops = storage.ops().len();
    assert_eq!(
        writer.append(&entry(&max), time(2)),
        Err(AppendError::SegmentFull)
    );
    assert_eq!(storage.ops().len(), ops, "nothing written");
    assert!(!writer.is_poisoned());

    let next = MemStorage::new();
    writer.rotate(next.clone()).unwrap();
    let persisted = writer.append(&entry(&max), time(2)).unwrap();
    assert_eq!(persisted.first_seq, MAX_BATCH_RECORDS as u64 + 1);
    assert_eq!(&next.ops()[..3], &[Op::Write, Op::Flush, Op::Sync]);

    let segments = [storage.bytes(), next.bytes()];
    let head = audit_log::verify_log(
        segments.iter().map(|b| &b[..]),
        Anchor::Genesis,
        limit,
        Some(writer.head()),
    )
    .unwrap();
    assert_eq!(head, persisted.head);
}

/// [`SegmentLimit`]: below the minimum (one full batch must fit) or above
/// the ceiling is refused.
#[test]
fn segment_limit_range() {
    assert!(SegmentLimit::new(SegmentLimit::MIN - 1).is_none());
    assert!(SegmentLimit::new(SegmentLimit::MIN).is_some());
    assert!(SegmentLimit::new(SegmentLimit::CEILING).is_some());
    assert!(SegmentLimit::new(SegmentLimit::CEILING + 1).is_none());
    assert!(SegmentLimit::DEFAULT.max_octets() >= SegmentLimit::MIN);
}

/// AGENTS.md §6: a declared record length over the bound is refused at the
/// prefix — before the (absent) body is awaited — not reported as a
/// truncation.
#[test]
fn declared_length_checked_before_reading() {
    let mut bytes = SegmentHeader {
        anchor: ChainHead::GENESIS,
    }
    .encode()
    .to_vec();
    bytes.extend_from_slice(&u32::MAX.to_be_bytes());
    let error =
        verify_segment(&bytes[..], Anchor::Genesis, SegmentLimit::DEFAULT, None).unwrap_err();
    assert_eq!(error.kind, BreakKind::RecordLengthOutOfBounds);
    assert_eq!(error.at_seq, 1);

    // Below the smallest record: refused too.
    let mut bytes = SegmentHeader {
        anchor: ChainHead::GENESIS,
    }
    .encode()
    .to_vec();
    bytes.extend_from_slice(&3u32.to_be_bytes());
    bytes.extend_from_slice(&[0, 0, 0]);
    let error =
        verify_segment(&bytes[..], Anchor::Genesis, SegmentLimit::DEFAULT, None).unwrap_err();
    assert_eq!(error.kind, BreakKind::RecordLengthOutOfBounds);
}

/// The verifier enforces the segment bound it is given.
#[test]
fn segment_too_large_for_the_verifier() {
    let storage = MemStorage::new();
    let mut writer = LogWriter::create(storage.clone(), SegmentLimit::DEFAULT).unwrap();
    let max = vec![1u8; MAX_PAYLOAD_LEN];
    let entries = vec![entry(&max); MAX_BATCH_RECORDS];
    writer.append_batch(&entries, time(1)).unwrap();
    writer.append(&entry(&max), time(1)).unwrap();
    let bytes = storage.bytes();
    let small = SegmentLimit::new(SegmentLimit::MIN).unwrap();
    let error = verify_segment(&bytes[..], Anchor::Genesis, small, None).unwrap_err();
    assert_eq!(error.kind, BreakKind::SegmentTooLarge);
    assert_eq!(error.at_seq, MAX_BATCH_RECORDS as u64 + 1);
    // Resuming a writer on it with the small limit is refused.
    let verified =
        verify_segment(&bytes[..], Anchor::Genesis, SegmentLimit::DEFAULT, None).unwrap();
    assert_eq!(
        LogWriter::resume(storage, &verified, small).err(),
        Some(AppendError::ResumeOverLimit)
    );
}

/// The record sequence never wraps: a writer whose head is at `u64::MAX`
/// refuses to append.
#[test]
fn sequence_never_wraps() {
    let storage = MemStorage::new();
    let anchor = ChainHead {
        seq: u64::MAX,
        hash: audit_log::RecordHash::from_bytes([9; 32]),
    };
    let mut writer = LogWriter::start_segment(storage, anchor, SegmentLimit::DEFAULT).unwrap();
    let data = [1u8];
    assert_eq!(
        writer.append(&entry(&data), time(1)),
        Err(AppendError::SequenceExhausted)
    );
    let anchor = ChainHead {
        seq: u64::MAX - 1,
        hash: audit_log::RecordHash::from_bytes([9; 32]),
    };
    let mut writer =
        LogWriter::start_segment(MemStorage::new(), anchor, SegmentLimit::DEFAULT).unwrap();
    let entries = [entry(&data), entry(&data)];
    assert_eq!(
        writer.append_batch(&entries, time(1)),
        Err(AppendError::SequenceExhausted)
    );
    writer.append(&entry(&data), time(1)).unwrap();
    assert_eq!(writer.head().seq, u64::MAX);
}

/// Timestamps: one encoding per instant.
#[test]
fn timestamp_bounds() {
    assert!(audit_log::Timestamp::new(0, 999_999_999).is_some());
    assert!(audit_log::Timestamp::new(0, 1_000_000_000).is_none());
    let now = audit_log::Timestamp::now().unwrap();
    assert!(now.secs() > 1_700_000_000);
}
