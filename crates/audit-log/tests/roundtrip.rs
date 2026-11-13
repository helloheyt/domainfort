//! Append → verify round trips.
//!
//! Source: docs/37 §2 (hash-chained, append-only log); docs/50 R50-17, §8.1
//! (auditd appends, sets the source from the connection, acknowledges what
//! it persisted), §7.5 (auditd verifies the chain at start); the format of
//! crate::format (this project's own). Payloads are arbitrary test octets.

mod common;

use audit_log::{
    verify_log, verify_segment, Anchor, ChainHead, Entry, FileStorage, LogWriter, SegmentLimit,
    SegmentReader, Source, GENESIS_HASH,
};
use common::{build_log, payload, source, temp_dir, time, MemStorage};

/// docs/37 §2: a log of many records verifies end to end, and its head is
/// the writer's.
#[test]
fn many_records_verify() {
    let (storage, heads, writer) = build_log(300);
    let bytes = storage.bytes();
    let verified = verify_segment(&bytes[..], Anchor::Genesis, SegmentLimit::DEFAULT, None)
        .expect("valid log");
    assert_eq!(verified.records(), 300);
    assert_eq!(verified.head(), writer.head());
    assert_eq!(verified.head(), *heads.last().unwrap());
    assert_eq!(verified.anchor(), ChainHead::GENESIS);
    assert_eq!(verified.len(), bytes.len() as u64);
    assert_eq!(writer.segment_len(), bytes.len() as u64);
}

/// docs/50 §3.2, R50-17: every field read back is what was appended — the
/// source and uid from the connection, the sender's sequence number, the
/// payload, auditd's time — and each record links to the previous head.
#[test]
fn records_read_back_exactly() {
    let (storage, heads, _) = build_log(40);
    let bytes = storage.bytes();
    let mut reader =
        SegmentReader::open(&bytes[..], Anchor::Genesis, SegmentLimit::DEFAULT, None).unwrap();
    let mut n = 0u64;
    while let Some(record) = reader.next_record().unwrap() {
        n += 1;
        assert_eq!(record.seq, n);
        assert_eq!(record.prev_hash, heads[(n - 1) as usize].hash);
        assert_eq!(record.source, source(n));
        assert_eq!(record.source_uid, 800 + n as u32);
        assert_eq!(record.source_seq, n);
        assert_eq!(record.payload, payload(n));
        assert_eq!(record.time, time(1_700_000_000 + n));
        assert_eq!(reader.head(), heads[n as usize]);
    }
    assert_eq!(n, 40);
    reader.finish().unwrap();
}

/// docs/37 §2: the first record links to the genesis value (32 zero
/// octets, sequence 0) — docs/questions/Q-250 item 2.
#[test]
fn first_record_links_to_genesis() {
    let (storage, _, _) = build_log(1);
    let bytes = storage.bytes();
    let mut reader =
        SegmentReader::open(&bytes[..], Anchor::Genesis, SegmentLimit::DEFAULT, None).unwrap();
    let first = reader.next_record().unwrap().unwrap();
    assert_eq!(first.seq, 1);
    assert_eq!(first.prev_hash, GENESIS_HASH);
    assert_eq!(GENESIS_HASH.as_bytes(), &[0u8; 32]);
}

/// docs/50 §8.1: a batch is persisted as consecutive records with one
/// acknowledgement naming its first sequence and its last head.
#[test]
fn batches_verify() {
    let storage = MemStorage::new();
    let mut writer = LogWriter::create(storage.clone(), SegmentLimit::DEFAULT).unwrap();
    let mut seq = 0u64;
    for batch_len in [1usize, 2, 7, 64, 3, 64, 1] {
        let payloads: Vec<Vec<u8>> = (0..batch_len).map(|i| payload(seq + i as u64)).collect();
        let entries: Vec<Entry<'_>> = payloads
            .iter()
            .enumerate()
            .map(|(i, p)| Entry {
                source: Source::Kdc,
                source_uid: 803,
                source_seq: seq + i as u64 + 1,
                payload: p,
            })
            .collect();
        let persisted = writer.append_batch(&entries, time(1_000 + seq)).unwrap();
        assert_eq!(persisted.first_seq, seq + 1);
        seq += batch_len as u64;
        assert_eq!(persisted.head.seq, seq);
        assert_eq!(writer.head(), persisted.head);
    }
    let bytes = storage.bytes();
    let verified = verify_segment(
        &bytes[..],
        Anchor::Genesis,
        SegmentLimit::DEFAULT,
        Some(writer.head()),
    )
    .unwrap();
    assert_eq!(verified.records(), seq);
}

/// docs/07 §8 / Q-218 (A-57): rotation continues one chain across
/// segments; each later segment is anchored at the previous head, and the
/// log verifies as a whole.
#[test]
fn rotation_keeps_one_chain() {
    let first = MemStorage::new();
    let mut writer = LogWriter::create(first.clone(), SegmentLimit::DEFAULT).unwrap();
    let mut segments = vec![first];
    let mut n = 0u64;
    for _ in 0..4 {
        for _ in 0..25 {
            n += 1;
            let data = payload(n);
            writer
                .append(
                    &Entry {
                        source: source(n),
                        source_uid: 900,
                        source_seq: n,
                        payload: &data,
                    },
                    time(n),
                )
                .unwrap();
        }
        let next = MemStorage::new();
        let head_before = writer.head();
        writer.rotate(next.clone()).unwrap();
        assert_eq!(writer.segment_anchor(), head_before);
        segments.push(next);
    }
    let all: Vec<Vec<u8>> = segments.iter().map(MemStorage::bytes).collect();
    let head = verify_log(
        all.iter().map(|b| &b[..]),
        Anchor::Genesis,
        SegmentLimit::DEFAULT,
        Some(writer.head()),
    )
    .unwrap();
    assert_eq!(head, writer.head());
    assert_eq!(head.seq, 100);
    // The last segment holds only its header: its head is its anchor.
    let last = verify_segment(
        &all[4][..],
        Anchor::After(writer.head()),
        SegmentLimit::DEFAULT,
        None,
    )
    .unwrap();
    assert_eq!(last.records(), 0);
}

/// docs/50 §7.5: after a restart auditd verifies the segment and continues
/// appending to it; the chain is unbroken.
#[test]
fn resume_after_verify_continues_the_chain() {
    let (storage, _, writer) = build_log(10);
    drop(writer);
    let bytes = storage.bytes();
    let verified =
        verify_segment(&bytes[..], Anchor::Genesis, SegmentLimit::DEFAULT, None).unwrap();
    let mut resumed = LogWriter::resume(storage.clone(), &verified, SegmentLimit::DEFAULT).unwrap();
    assert_eq!(resumed.head(), verified.head());
    let data = payload(11);
    let persisted = resumed
        .append(
            &Entry {
                source: Source::Keyd,
                source_uid: 801,
                source_seq: 1,
                payload: &data,
            },
            time(99),
        )
        .unwrap();
    assert_eq!(persisted.first_seq, 11);
    let bytes = storage.bytes();
    let again = verify_segment(
        &bytes[..],
        Anchor::Genesis,
        SegmentLimit::DEFAULT,
        Some(persisted.head),
    )
    .unwrap();
    assert_eq!(again.records(), 11);
}

/// docs/50 §6.4, §8.1: the file-backed storage writes a segment that
/// verifies, refuses to overwrite an existing segment, and reopens in
/// append mode for a resumed writer.
#[test]
fn file_storage_round_trip() {
    let dir = temp_dir("file");
    let path = dir.join("segment-0001");
    let storage = FileStorage::create_new(&path).unwrap();
    let mut writer = LogWriter::create(storage, SegmentLimit::DEFAULT).unwrap();
    for n in 1..=20u64 {
        let data = payload(n);
        writer
            .append(
                &Entry {
                    source: Source::Dird,
                    source_uid: 802,
                    source_seq: n,
                    payload: &data,
                },
                time(n),
            )
            .unwrap();
    }
    let head = writer.head();
    drop(writer);

    // A second create of the same path is refused (never overwritten).
    assert!(FileStorage::create_new(&path).is_err());

    let file = std::fs::File::open(&path).unwrap();
    let verified = verify_segment(
        std::io::BufReader::new(file),
        Anchor::Genesis,
        SegmentLimit::DEFAULT,
        Some(head),
    )
    .unwrap();
    assert_eq!(verified.records(), 20);

    let mut resumed = LogWriter::resume(
        FileStorage::open_append(&path).unwrap(),
        &verified,
        SegmentLimit::DEFAULT,
    )
    .unwrap();
    let data = payload(21);
    let persisted = resumed
        .append(
            &Entry {
                source: Source::Dird,
                source_uid: 802,
                source_seq: 21,
                payload: &data,
            },
            time(21),
        )
        .unwrap();
    drop(resumed);
    let file = std::fs::File::open(&path).unwrap();
    let verified = verify_segment(
        file,
        Anchor::Genesis,
        SegmentLimit::DEFAULT,
        Some(persisted.head),
    )
    .unwrap();
    assert_eq!(verified.records(), 21);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o077,
            0,
            "segment is not readable by group or others"
        );
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// docs/37 §2 (D157), docs/questions/Q-251: the signing hook is handed the
/// persisted head only.
#[test]
fn sign_hook_sees_the_persisted_head() {
    struct Recorder(Vec<ChainHead>);
    impl audit_log::HeadSigner for Recorder {
        type Signature = u64;
        type Error = ();
        fn sign_head(&mut self, head: &ChainHead) -> Result<u64, ()> {
            self.0.push(*head);
            Ok(head.seq)
        }
    }
    let (storage, _, writer) = build_log(5);
    let mut signer = Recorder(Vec::new());
    assert_eq!(writer.sign_head(&mut signer), Ok(5));
    assert_eq!(signer.0, vec![writer.head()]);
    // A failed sync leaves the head (and so what is signed) where it was.
    storage.fail_next(common::FailAt::Sync);
    let mut writer = writer;
    let data = payload(6);
    assert!(writer
        .append(
            &Entry {
                source: Source::Kdc,
                source_uid: 803,
                source_seq: 6,
                payload: &data,
            },
            time(6),
        )
        .is_err());
    assert_eq!(writer.sign_head(&mut signer), Ok(5));
}
