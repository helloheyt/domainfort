#![no_main]
//! Fuzz target for the audit-log segment verifier: `audit_log::SegmentReader`
//! and `audit_log::verify_segment` on arbitrary octets.
//!
//! AGENTS.md §6 / docs/50 §9 (R50-19): arbitrary bytes → parser; never a
//! panic, bounded allocation (every declared record length is checked against
//! `MAX_RECORD_LEN` before the body is read). The first input octet picks the
//! anchor (genesis, trusted, or after the head named by the next 40 octets)
//! and whether a checkpoint is given; the rest is the segment. Properties:
//!
//! * the streaming walk and the one-call verifier agree (same result);
//! * a verified segment's length is exactly the octets consumed, and its
//!   record count is the number of records the walk yielded;
//! * every yielded record links to the previous head and carries the next
//!   sequence number;
//! * a break is sticky (`finish` after a break reports the same break).
//!
//! Spec: docs/37 §2; docs/50 §7.5; audit-log crate::verify.

use audit_log::{verify_segment, Anchor, ChainHead, RecordHash, SegmentLimit, SegmentReader};
use libfuzzer_sys::fuzz_target;

fn head_from(octets: &[u8]) -> Option<(ChainHead, &[u8])> {
    let (seq, rest) = octets.split_first_chunk::<8>()?;
    let (hash, rest) = rest.split_first_chunk::<32>()?;
    Some((
        ChainHead {
            seq: u64::from_be_bytes(*seq),
            hash: RecordHash::from_bytes(*hash),
        },
        rest,
    ))
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    let (anchor, rest) = match selector & 0x03 {
        0 => (Anchor::Genesis, rest),
        1 => (Anchor::Trusted, rest),
        _ => match head_from(rest) {
            Some((head, rest)) => (Anchor::After(head), rest),
            None => return,
        },
    };
    let (checkpoint, segment) = if selector & 0x04 != 0 {
        match head_from(rest) {
            Some((head, rest)) => (Some(head), rest),
            None => return,
        }
    } else {
        (None, rest)
    };
    let limit = SegmentLimit::LARGEST;

    let one_call = verify_segment(segment, anchor, limit, checkpoint);

    let walked = match SegmentReader::open(segment, anchor, limit, checkpoint) {
        Err(error) => {
            assert_eq!(one_call, Err(error));
            return;
        }
        Ok(mut reader) => {
            let mut count = 0u64;
            let mut previous = reader.head();
            let broke = loop {
                match reader.next_record() {
                    Ok(Some(record)) => {
                        assert_eq!(record.seq, previous.seq + 1);
                        assert_eq!(record.prev_hash, previous.hash);
                        assert!(!record.payload.is_empty());
                        assert!(record.payload.len() <= audit_log::MAX_PAYLOAD_LEN);
                        previous = reader.head();
                        count += 1;
                    }
                    Ok(None) => break None,
                    Err(error) => break Some(error),
                }
            };
            let finished = reader.finish();
            if let Some(error) = broke {
                assert_eq!(finished, Err(error), "breaks are sticky");
            } else if let Ok(verified) = &finished {
                assert_eq!(verified.records(), count);
                assert_eq!(verified.len(), segment.len() as u64);
            }
            finished
        }
    };
    assert_eq!(walked, one_call, "walk and one-call verifier agree");
});
