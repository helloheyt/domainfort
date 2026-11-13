//! Mutation sweep: every single-octet change and every truncation of a small
//! log is detected against its final head, and the verifier never panics on
//! any of them, nor on arbitrary input.
//!
//! Source: docs/37 §2 (tamper-evident log); AGENTS.md §6 (strict, bounded
//! parsers that fail closed; fuzz targets — this sweep is the deterministic
//! complement of fuzz/audit_log_verify).

mod common;

use audit_log::{verify_segment, Anchor, SegmentLimit, SegmentReader};
use common::build_log;

/// docs/37 §2: with the final head as checkpoint, any changed octet — header
/// or record, any field — is a break; never a panic.
#[test]
fn every_flipped_octet_is_detected() {
    let (storage, heads, _) = build_log(4);
    let bytes = storage.bytes();
    let head = *heads.last().unwrap();
    for position in 0..bytes.len() {
        for mask in [0x01u8, 0x02, 0x10, 0x80, 0xFF] {
            let mut mutated = bytes.clone();
            mutated[position] ^= mask;
            let result = verify_segment(
                &mutated[..],
                Anchor::Genesis,
                SegmentLimit::DEFAULT,
                Some(head),
            );
            assert!(
                result.is_err(),
                "flip {mask:#04x} at {position} not detected"
            );
            // The trusted-anchor walk must not panic either.
            let _ = verify_segment(&mutated[..], Anchor::Trusted, SegmentLimit::DEFAULT, None);
        }
    }
}

/// Every truncation is detected against the final head.
#[test]
fn every_truncation_is_detected() {
    let (storage, heads, _) = build_log(4);
    let bytes = storage.bytes();
    let head = *heads.last().unwrap();
    for len in 0..bytes.len() {
        let result = verify_segment(
            &bytes[..len],
            Anchor::Genesis,
            SegmentLimit::DEFAULT,
            Some(head),
        );
        assert!(result.is_err(), "truncation to {len} not detected");
    }
    assert!(verify_segment(
        &bytes[..],
        Anchor::Genesis,
        SegmentLimit::DEFAULT,
        Some(head)
    )
    .is_ok());
}

/// Arbitrary octets after a valid header, and arbitrary whole inputs, never
/// panic; a pseudo-random sweep (xorshift, seeded here) over lengths and
/// contents.
#[test]
fn arbitrary_input_never_panics() {
    let (storage, _, _) = build_log(2);
    let valid = storage.bytes();
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for round in 0..2_000 {
        let len = (next() % 400) as usize;
        let mut input: Vec<u8> = (0..len).map(|_| next() as u8).collect();
        if round % 2 == 0 {
            // Keep a valid header (and sometimes more) so the record parser
            // is reached.
            let keep = (next() as usize % valid.len()).max(audit_log::SEGMENT_HEADER_LEN);
            let mut prefixed = valid[..keep].to_vec();
            prefixed.append(&mut input);
            input = prefixed;
        }
        for anchor in [Anchor::Genesis, Anchor::Trusted] {
            if let Ok(mut reader) =
                SegmentReader::open(&input[..], anchor, SegmentLimit::DEFAULT, None)
            {
                while let Ok(Some(_)) = reader.next_record() {}
            }
        }
    }
}
