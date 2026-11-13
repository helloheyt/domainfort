//! Tamper and truncation detection: every change is reported as the first
//! break, at the sequence number the verifier's table names.
//!
//! Source: docs/37 §2 ("deleting or changing a record breaks the chain and
//! is detected"), §8 ("trace deletion by an attacker | hash-chain +
//! off-box"); docs/50 §7.5; crate::verify's detection table (this project's
//! own). Logs are built by this crate's writer from arbitrary test octets.

mod common;

use audit_log::{
    verify_log, verify_segment, Anchor, BreakKind, ChainHead, SegmentLimit, VerifyError,
    SEGMENT_HEADER_LEN,
};
use common::{build_log, record_offsets};

const COUNT: u64 = 30;

/// Offsets of the fields inside a record (from the record's first octet):
/// crate::format layout.
const SEQ: usize = 4;
const PREV_HASH: usize = 12;
const TIME_SECS: usize = 44;
const TIME_NANOS: usize = 52;
const SOURCE: usize = 56;
const SOURCE_UID: usize = 57;
const SOURCE_SEQ: usize = 61;
const PAYLOAD_LEN: usize = 69;
const PAYLOAD: usize = 73;

fn log() -> (Vec<u8>, Vec<ChainHead>, Vec<usize>) {
    let (storage, heads, _) = build_log(COUNT);
    let bytes = storage.bytes();
    let offsets = record_offsets(&bytes);
    assert_eq!(offsets.len(), COUNT as usize + 1);
    (bytes, heads, offsets)
}

fn verify(bytes: &[u8], checkpoint: Option<ChainHead>) -> Result<u64, VerifyError> {
    verify_segment(bytes, Anchor::Genesis, SegmentLimit::DEFAULT, checkpoint).map(|v| v.records())
}

/// Start offset of the record with sequence `seq`.
fn at(offsets: &[usize], seq: u64) -> usize {
    offsets[(seq - 1) as usize]
}

fn expect_break(result: Result<u64, VerifyError>, kind: BreakKind, at_seq: u64) -> VerifyError {
    let error = result.expect_err("tampering must be detected");
    assert_eq!(error.kind, kind, "{error:?}");
    assert_eq!(error.at_seq, at_seq, "{error:?}");
    error
}

/// docs/37 §2: a flipped octet in a record's payload breaks the next link.
#[test]
fn flipped_payload_octet_breaks_next_link() {
    let (mut bytes, heads, offsets) = log();
    bytes[at(&offsets, 10) + PAYLOAD] ^= 0x01;
    let error = expect_break(verify(&bytes, None), BreakKind::LinkMismatch, 11);
    assert_eq!(error.offset as usize, at(&offsets, 11));
    // Record 10 itself verified against record 9; the last good head is the
    // (altered) record 10 — the chain names the break at the link 10 → 11.
    assert_eq!(error.last_good.seq, 10);
    assert_ne!(error.last_good.hash, heads[10].hash);
}

/// docs/37 §2: every other non-length field of record `n` is covered too.
#[test]
fn flipped_field_octets_break_next_link() {
    for field in [TIME_SECS, SOURCE_UID, SOURCE_SEQ, TIME_NANOS] {
        let (mut bytes, _, offsets) = log();
        // The low bit of the last octet keeps every value canonical (nanos
        // stays below one second), so only the chain can tell.
        let width = match field {
            TIME_SECS | SOURCE_SEQ => 8,
            _ => 4,
        };
        bytes[at(&offsets, 7) + field + width - 1] ^= 0x01;
        expect_break(verify(&bytes, None), BreakKind::LinkMismatch, 8);
    }
}

/// A source code changed to another valid code is a link break; to a code
/// outside the closed table, a typed break at that record.
#[test]
fn flipped_source_octet() {
    let (mut bytes, _, offsets) = log();
    let pos = at(&offsets, 5) + SOURCE;
    bytes[pos] = if bytes[pos] == 1 { 2 } else { 1 };
    expect_break(verify(&bytes, None), BreakKind::LinkMismatch, 6);

    let (mut bytes, _, offsets) = log();
    bytes[at(&offsets, 5) + SOURCE] = 0;
    expect_break(verify(&bytes, None), BreakKind::UnknownSource, 5);
}

/// A record's own `prev_hash` altered: the break is at that record.
#[test]
fn flipped_prev_hash_breaks_that_link() {
    let (mut bytes, _, offsets) = log();
    bytes[at(&offsets, 12) + PREV_HASH + 31] ^= 0x80;
    expect_break(verify(&bytes, None), BreakKind::LinkMismatch, 12);
}

/// A record's `seq` altered: a sequence gap at that record.
#[test]
fn flipped_seq_is_a_gap() {
    let (mut bytes, _, offsets) = log();
    bytes[at(&offsets, 3) + SEQ + 7] ^= 0x04;
    let error = expect_break(
        verify(&bytes, None),
        BreakKind::SequenceGap { found: 3 ^ 4 },
        3,
    );
    assert_eq!(error.last_good.seq, 2);
}

/// The time's nanoseconds pushed to a second or more: not canonical.
#[test]
fn non_canonical_time_is_refused() {
    let (mut bytes, _, offsets) = log();
    let pos = at(&offsets, 4) + TIME_NANOS;
    bytes[pos..pos + 4].copy_from_slice(&1_000_000_000u32.to_be_bytes());
    expect_break(verify(&bytes, None), BreakKind::InvalidTimestamp, 4);
}

/// Length fields altered: a framing break at that record.
#[test]
fn flipped_length_fields() {
    // payload_len no longer matches record_len.
    let (mut bytes, _, offsets) = log();
    bytes[at(&offsets, 9) + PAYLOAD_LEN + 3] ^= 0x01;
    expect_break(verify(&bytes, None), BreakKind::PayloadLengthMismatch, 9);

    // record_len far over the bound: refused before any body is read.
    let (mut bytes, _, offsets) = log();
    bytes[at(&offsets, 9)] ^= 0x40;
    expect_break(verify(&bytes, None), BreakKind::RecordLengthOutOfBounds, 9);

    // record_len one larger: the record swallows an octet of the next.
    let (mut bytes, _, offsets) = log();
    bytes[at(&offsets, 9) + 3] = bytes[at(&offsets, 9) + 3].wrapping_add(1);
    let error = verify(&bytes, None).expect_err("detected");
    assert_eq!(error.at_seq, 9, "{error:?}");
}

/// The last record altered: the chain alone cannot show it; a checkpoint
/// (the last acknowledgement or a signed head) does, at that record.
#[test]
fn altered_last_record_needs_a_checkpoint() {
    let (mut bytes, heads, offsets) = log();
    bytes[at(&offsets, COUNT) + PAYLOAD] ^= 0x10;
    assert_eq!(verify(&bytes, None), Ok(COUNT));
    expect_break(
        verify(&bytes, Some(heads[COUNT as usize])),
        BreakKind::CheckpointMismatch,
        COUNT,
    );
}

/// docs/37 §2 ("deleting … a record breaks the chain"): a deleted record is
/// a gap where it should stand.
#[test]
fn deleted_record_is_a_gap() {
    let (bytes, _, offsets) = log();
    let mut cut = bytes[..at(&offsets, 17)].to_vec();
    cut.extend_from_slice(&bytes[at(&offsets, 18)..]);
    expect_break(verify(&cut, None), BreakKind::SequenceGap { found: 18 }, 17);
}

/// A deleted record whose successors were renumbered still breaks the link.
#[test]
fn deleted_and_renumbered_breaks_the_link() {
    let (bytes, _, offsets) = log();
    let mut cut = bytes[..at(&offsets, 17)].to_vec();
    cut.extend_from_slice(&bytes[at(&offsets, 18)..]);
    // Renumber record 18 → 17 (the octets of the following records stay).
    let pos = at(&offsets, 17) + SEQ;
    cut[pos..pos + 8].copy_from_slice(&17u64.to_be_bytes());
    expect_break(verify(&cut, None), BreakKind::LinkMismatch, 17);
}

/// Two records swapped: a gap at the first of them.
#[test]
fn reordered_records_are_a_gap() {
    let (bytes, _, offsets) = log();
    let (a, b, c) = (at(&offsets, 20), at(&offsets, 21), at(&offsets, 22));
    let mut swapped = bytes[..a].to_vec();
    swapped.extend_from_slice(&bytes[b..c]);
    swapped.extend_from_slice(&bytes[a..b]);
    swapped.extend_from_slice(&bytes[c..]);
    expect_break(
        verify(&swapped, None),
        BreakKind::SequenceGap { found: 21 },
        20,
    );
}

/// A record inserted (a copy of an earlier one): a gap.
#[test]
fn inserted_record_is_a_gap() {
    let (bytes, _, offsets) = log();
    let mut grown = bytes[..at(&offsets, 6)].to_vec();
    grown.extend_from_slice(&bytes[at(&offsets, 2)..at(&offsets, 3)]);
    grown.extend_from_slice(&bytes[at(&offsets, 6)..]);
    expect_break(verify(&grown, None), BreakKind::SequenceGap { found: 2 }, 6);
}

/// The tail cut inside a record (or inside its length prefix): a truncation
/// at that record.
#[test]
fn truncated_tail_inside_a_record() {
    let (bytes, heads, offsets) = log();
    let last = at(&offsets, COUNT);
    for cut in [
        last + 1,
        last + 3,
        last + 4,
        last + PAYLOAD,
        bytes.len() - 1,
    ] {
        let error = expect_break(
            verify(&bytes[..cut], None),
            BreakKind::RecordTruncated,
            COUNT,
        );
        assert_eq!(error.last_good, heads[(COUNT - 1) as usize]);
        assert_eq!(error.offset as usize, last);
    }
}

/// The tail cut at a record boundary: a valid shorter chain — detected only
/// against a checkpoint, at the first missing record.
#[test]
fn truncated_tail_at_a_boundary_needs_a_checkpoint() {
    let (bytes, heads, offsets) = log();
    let cut = &bytes[..at(&offsets, 28)];
    assert_eq!(verify(cut, None), Ok(27));
    let error = expect_break(
        verify(cut, Some(heads[COUNT as usize])),
        BreakKind::CheckpointNotReached,
        28,
    );
    assert_eq!(error.last_good, heads[27]);
    // A checkpoint inside what is left still passes.
    assert_eq!(verify(cut, Some(heads[20])), Ok(27));
    // Everything cut (header only).
    let error = expect_break(
        verify(&bytes[..SEGMENT_HEADER_LEN], Some(heads[1])),
        BreakKind::CheckpointNotReached,
        1,
    );
    assert_eq!(error.last_good, ChainHead::GENESIS);
}

/// A chain rewritten from record 5 on (every hash recomputed — what an
/// attacker with write access can do) is valid on its own and refused
/// against a checkpoint taken before the rewrite (docs/37 §2: signed head /
/// off-box copy).
#[test]
fn rewritten_chain_fails_the_checkpoint() {
    let (_, original_heads, _) = build_log(10);
    // Same writer, same inputs except event 5's payload.
    let storage = common::MemStorage::new();
    let mut writer = audit_log::LogWriter::create(storage.clone(), SegmentLimit::DEFAULT).unwrap();
    for n in 1..=10u64 {
        let mut data = common::payload(n);
        if n == 5 {
            data[0] ^= 0xFF;
        }
        writer
            .append(
                &audit_log::Entry {
                    source: common::source(n),
                    source_uid: 800 + n as u32,
                    source_seq: n,
                    payload: &data,
                },
                common::time(1_700_000_000 + n),
            )
            .unwrap();
    }
    let forged = storage.bytes();
    assert_eq!(verify(&forged, None), Ok(10));
    assert_eq!(verify(&forged, Some(original_heads[4])), Ok(10));
    expect_break(
        verify(&forged, Some(original_heads[5])),
        BreakKind::CheckpointMismatch,
        5,
    );
}

/// The header: magic, version and anchor are checked.
#[test]
fn header_tampering() {
    let (bytes, heads, _) = log();
    let mut bad = bytes.clone();
    bad[0] ^= 0x20;
    expect_break(verify(&bad, None), BreakKind::BadMagic, 1);

    let mut bad = bytes.clone();
    bad[8] = 2;
    expect_break(verify(&bad, None), BreakKind::UnsupportedVersion, 1);

    let mut bad = bytes.clone();
    bad[9 + 7] ^= 0x01; // anchor_seq
    expect_break(verify(&bad, None), BreakKind::AnchorMismatch, 1);

    let mut bad = bytes.clone();
    bad[17] ^= 0x01; // anchor_hash
    expect_break(verify(&bad, None), BreakKind::AnchorMismatch, 1);

    expect_break(verify(&bytes[..10], None), BreakKind::HeaderTruncated, 1);
    expect_break(verify(&[], None), BreakKind::HeaderTruncated, 1);

    // The right segment under the wrong expected anchor.
    let error = verify_segment(
        &bytes[..],
        Anchor::After(heads[3]),
        SegmentLimit::DEFAULT,
        None,
    )
    .unwrap_err();
    assert_eq!(error.kind, BreakKind::AnchorMismatch);
    assert_eq!(error.at_seq, 4);

    // Trusted: the header is taken as given; an anchor at sequence 0 must
    // still be genesis.
    let mut bad = bytes.clone();
    bad[17] ^= 0x01;
    let error = verify_segment(&bad[..], Anchor::Trusted, SegmentLimit::DEFAULT, None).unwrap_err();
    assert_eq!(error.kind, BreakKind::AnchorMismatch);
}

/// Rotated segments reordered or one removed: the next segment's anchor no
/// longer matches.
#[test]
fn reordered_or_missing_segment() {
    let first = common::MemStorage::new();
    let mut writer = audit_log::LogWriter::create(first.clone(), SegmentLimit::DEFAULT).unwrap();
    let mut segments = vec![first];
    let mut n = 0u64;
    for _ in 0..3 {
        for _ in 0..5 {
            n += 1;
            let data = common::payload(n);
            writer
                .append(
                    &audit_log::Entry {
                        source: audit_log::Source::Kdc,
                        source_uid: 803,
                        source_seq: n,
                        payload: &data,
                    },
                    common::time(n),
                )
                .unwrap();
        }
        let next = common::MemStorage::new();
        writer.rotate(next.clone()).unwrap();
        segments.push(next);
    }
    let all: Vec<Vec<u8>> = segments.iter().map(common::MemStorage::bytes).collect();

    let order = [&all[0], &all[2], &all[1], &all[3]];
    let error = verify_log(
        order.iter().map(|b| &b[..]),
        Anchor::Genesis,
        SegmentLimit::DEFAULT,
        None,
    )
    .unwrap_err();
    assert_eq!(error.segment, 1);
    assert_eq!(error.error.kind, BreakKind::AnchorMismatch);
    assert_eq!(error.error.at_seq, 6);

    let missing = [&all[0], &all[2], &all[3]];
    let error = verify_log(
        missing.iter().map(|b| &b[..]),
        Anchor::Genesis,
        SegmentLimit::DEFAULT,
        None,
    )
    .unwrap_err();
    assert_eq!(error.segment, 1);
    assert_eq!(error.error.kind, BreakKind::AnchorMismatch);

    // The first segment removed: only a trusted start passes, and a
    // checkpoint from before the cut is then not checkable — the head after
    // it must still be reached.
    let tail = [&all[1], &all[2], &all[3]];
    let error = verify_log(
        tail.iter().map(|b| &b[..]),
        Anchor::Genesis,
        SegmentLimit::DEFAULT,
        None,
    )
    .unwrap_err();
    assert_eq!(error.error.kind, BreakKind::AnchorMismatch);
    let head = verify_log(
        tail.iter().map(|b| &b[..]),
        Anchor::Trusted,
        SegmentLimit::DEFAULT,
        Some(writer.head()),
    )
    .unwrap();
    assert_eq!(head, writer.head());
}

/// A break is sticky: a caller that ignores it cannot conclude success.
#[test]
fn breaks_are_sticky() {
    let (mut bytes, _, offsets) = log();
    bytes[at(&offsets, 3) + PAYLOAD] ^= 0x01;
    let mut reader =
        audit_log::SegmentReader::open(&bytes[..], Anchor::Genesis, SegmentLimit::DEFAULT, None)
            .unwrap();
    let first = loop {
        match reader.next_record() {
            Ok(Some(_)) => continue,
            Ok(None) => panic!("break not reported"),
            Err(error) => break error,
        }
    };
    assert_eq!(reader.next_record(), Err(first));
    assert_eq!(reader.finish(), Err(first));
}
