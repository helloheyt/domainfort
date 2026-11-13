//! The audit channel's message set: round trips, canonical encoding, bounds,
//! the reserved refusal kind, and auditd's per-connection sequence check.
//!
//! Source: docs/50 §3.3 (framing, magic/version/kind, per-direction bounds,
//! canonical round trip, "audit ≤ 8 KiB per event"), §3.6, §7.5 (Ping),
//! §8.1 (events with the source's sequence number; acknowledgement of the
//! last persisted), R50-17; A-59 (REFUSED_KIND). Event octets are arbitrary
//! test values made up here.

use ipc::{decode_frame, Direction, FrameStatus, Refused, Reply, REFUSED_KIND};
use ipc_audit::{
    decode_reply, decode_request, encode_reply, encode_request, Ack, Append, AppendCursor,
    AuditReply, AuditRequest, EventBytes, SeqRange, SequenceError, AUDIT_CHANNEL, AUDIT_MAGIC,
    AUDIT_VERSION, KIND_ACK, KIND_APPEND, KIND_PING, KIND_PONG, MAX_BATCH_EVENTS, MAX_EVENT_OCTETS,
    REPLY_BODY_LIMIT, REQUEST_BODY_LIMIT,
};

fn event(len: usize, fill: u8) -> EventBytes {
    EventBytes::new(vec![fill; len]).expect("valid event length")
}

fn append(first_seq: u64, count: usize) -> Append {
    Append::new(
        first_seq,
        (0..count).map(|i| event(1 + i, i as u8)).collect(),
    )
    .unwrap()
}

/// Cut the single frame out of an encoding and return its body.
fn body(frame: &[u8], direction: Direction) -> Vec<u8> {
    match decode_frame(frame, AUDIT_CHANNEL.limit(direction)).unwrap() {
        FrameStatus::Complete { body, frame_len } => {
            assert_eq!(frame_len, frame.len());
            body.to_vec()
        }
        FrameStatus::NeedMore { .. } => panic!("incomplete frame"),
    }
}

/// docs/50 §3.3, §8.1: Append and Ping round trip, canonically.
#[test]
fn request_round_trips() {
    for request in [
        AuditRequest::Append(append(1, 1)),
        AuditRequest::Append(append(77, 16)),
        AuditRequest::Ping,
    ] {
        let frame = encode_request(&request).unwrap();
        let body = body(frame.as_bytes(), Direction::Request);
        assert_eq!(&body[..2], &AUDIT_MAGIC.to_be_bytes());
        assert_eq!(body[2], AUDIT_VERSION);
        assert_eq!(decode_request(&body).unwrap(), request);
        assert!(ipc::round_trip_is_canonical::<AuditRequest>(
            AUDIT_CHANNEL,
            Direction::Request,
            &body
        )
        .unwrap());
    }
}

/// docs/50 §8.1; A-59: Ack, Pong and the shared Refused round trip.
#[test]
fn reply_round_trips() {
    for reply in [
        Reply::Message(AuditReply::Ack(Ack {
            through_seq: 42,
            head_hash: [0xA5; 32],
        })),
        Reply::Message(AuditReply::Pong),
        Reply::Refused(Refused::Busy),
        Reply::Refused(Refused::Unavailable),
    ] {
        let frame = encode_reply(&reply).unwrap();
        let body = body(frame.as_bytes(), Direction::Reply);
        assert_eq!(decode_reply(&body).unwrap(), reply);
        assert!(ipc::reply_round_trip_is_canonical::<AuditReply>(AUDIT_CHANNEL, &body).unwrap());
    }
}

/// The exact field layout of Append and Ack (docs/50 §3.3 primitives).
#[test]
fn field_layout() {
    let request = AuditRequest::Append(Append::new(5, vec![event(3, 0xEE)]).unwrap());
    let frame = encode_request(&request).unwrap();
    let mut expected = Vec::new();
    expected.extend_from_slice(&AUDIT_MAGIC.to_be_bytes());
    expected.push(AUDIT_VERSION);
    expected.push(KIND_APPEND);
    expected.extend_from_slice(&5u64.to_be_bytes());
    expected.extend_from_slice(&1u32.to_be_bytes());
    expected.extend_from_slice(&3u32.to_be_bytes());
    expected.extend_from_slice(&[0xEE; 3]);
    assert_eq!(frame.body(), &expected[..]);

    let reply = Reply::Message(AuditReply::Ack(Ack {
        through_seq: 9,
        head_hash: [1; 32],
    }));
    let frame = encode_reply(&reply).unwrap();
    let mut expected = Vec::new();
    expected.extend_from_slice(&AUDIT_MAGIC.to_be_bytes());
    expected.push(AUDIT_VERSION);
    expected.push(KIND_ACK);
    expected.extend_from_slice(&9u64.to_be_bytes());
    expected.extend_from_slice(&[1; 32]);
    assert_eq!(frame.body(), &expected[..]);
    assert_eq!(frame.body().len() as u32, REPLY_BODY_LIMIT);
}

/// docs/50 §3.3 ("audit ≤ 8 KiB per event"; a bound per direction): the
/// largest batch fits the request bound exactly; more is refused at
/// construction and at decoding.
#[test]
fn request_bounds() {
    let largest = Append::new(
        1,
        (0..MAX_BATCH_EVENTS)
            .map(|_| event(MAX_EVENT_OCTETS as usize, 0x42))
            .collect(),
    )
    .unwrap();
    let frame = encode_request(&AuditRequest::Append(largest)).unwrap();
    assert_eq!(frame.body().len() as u32, REQUEST_BODY_LIMIT);

    // Construction bounds.
    assert!(EventBytes::new(vec![0; MAX_EVENT_OCTETS as usize + 1]).is_none());
    assert!(EventBytes::new(Vec::new()).is_none());
    assert!(Append::new(1, Vec::new()).is_none());
    assert!(Append::new(0, vec![event(1, 0)]).is_none());
    assert!(Append::new(1, vec![event(1, 0); MAX_BATCH_EVENTS as usize + 1]).is_none());
    assert!(Append::new(u64::MAX, vec![event(1, 0); 2]).is_none());
    assert!(Append::new(u64::MAX, vec![event(1, 0)]).is_some());

    // A declared frame length over the request bound is refused at the
    // prefix (before the body is awaited).
    let mut prefix = (REQUEST_BODY_LIMIT + 1).to_be_bytes().to_vec();
    prefix.extend_from_slice(&[0; 8]);
    assert_eq!(
        decode_frame(&prefix, AUDIT_CHANNEL.limit(Direction::Request)).err(),
        Some(ipc::Error::FrameTooLarge)
    );
    // The reply direction is bounded at the Ack size.
    let prefix = (REPLY_BODY_LIMIT + 1).to_be_bytes();
    assert_eq!(
        decode_frame(&prefix, AUDIT_CHANNEL.limit(Direction::Reply)).err(),
        Some(ipc::Error::FrameTooLarge)
    );
}

/// Hand-built Append bodies that break a bound are refused with the codec's
/// error (→ `Refused::Malformed` + close, A-59).
#[test]
fn malformed_append_bodies() {
    let header = |out: &mut Vec<u8>| {
        out.extend_from_slice(&AUDIT_MAGIC.to_be_bytes());
        out.push(AUDIT_VERSION);
        out.push(KIND_APPEND);
    };
    // Count over the bound.
    let mut b = Vec::new();
    header(&mut b);
    b.extend_from_slice(&1u64.to_be_bytes());
    b.extend_from_slice(&(MAX_BATCH_EVENTS + 1).to_be_bytes());
    assert_eq!(decode_request(&b), Err(ipc::Error::CountOverBound));
    // Empty batch.
    let mut b = Vec::new();
    header(&mut b);
    b.extend_from_slice(&1u64.to_be_bytes());
    b.extend_from_slice(&0u32.to_be_bytes());
    assert_eq!(decode_request(&b), Err(ipc::Error::CountOverBound));
    // Event over the bound.
    let mut b = Vec::new();
    header(&mut b);
    b.extend_from_slice(&1u64.to_be_bytes());
    b.extend_from_slice(&1u32.to_be_bytes());
    b.extend_from_slice(&(MAX_EVENT_OCTETS + 1).to_be_bytes());
    assert_eq!(decode_request(&b), Err(ipc::Error::LengthOverBound));
    // Empty event.
    let mut b = Vec::new();
    header(&mut b);
    b.extend_from_slice(&1u64.to_be_bytes());
    b.extend_from_slice(&1u32.to_be_bytes());
    b.extend_from_slice(&0u32.to_be_bytes());
    assert_eq!(decode_request(&b), Err(ipc::Error::LengthOverBound));
    // first_seq 0.
    let mut b = Vec::new();
    header(&mut b);
    b.extend_from_slice(&0u64.to_be_bytes());
    b.extend_from_slice(&1u32.to_be_bytes());
    b.extend_from_slice(&1u32.to_be_bytes());
    b.push(7);
    assert_eq!(decode_request(&b), Err(ipc::Error::UnknownCode));
    // Trailing octet.
    let good = encode_request(&AuditRequest::Ping).unwrap();
    let mut b = good.body().to_vec();
    b.push(0);
    assert_eq!(decode_request(&b), Err(ipc::Error::TrailingBytes));
    // Truncated.
    let good = encode_request(&AuditRequest::Append(append(3, 2))).unwrap();
    let b = &good.body()[..good.body().len() - 1];
    assert_eq!(decode_request(b), Err(ipc::Error::Truncated));
}

/// docs/50 §3.3: wrong magic, wrong version, an unknown kind and the
/// reserved REFUSED_KIND in the request direction are refused.
#[test]
fn envelope_checks() {
    let good = encode_request(&AuditRequest::Ping).unwrap().body().to_vec();
    let mut b = good.clone();
    b[0] ^= 0x01;
    assert_eq!(decode_request(&b), Err(ipc::Error::WrongMagic));
    let mut b = good.clone();
    b[2] = AUDIT_VERSION + 1;
    assert_eq!(decode_request(&b), Err(ipc::Error::VersionMismatch));
    for kind in [0x00, 0x03, 0x7F, REFUSED_KIND] {
        let mut b = good.clone();
        b[3] = kind;
        assert_eq!(
            decode_request(&b),
            Err(ipc::Error::UnknownKind),
            "{kind:#x}"
        );
    }
    // A reply kind 0x03 is unknown too; 0xFF is the shared refusal.
    let pong = encode_reply(&Reply::Message(AuditReply::Pong)).unwrap();
    let mut b = pong.body().to_vec();
    b[3] = 0x03;
    assert_eq!(decode_reply(&b), Err(ipc::Error::UnknownKind));
}

/// A-59: neither table lists the reserved kind (also asserted at compile
/// time in the crate).
#[test]
fn kind_tables_exclude_refused() {
    use ipc::MessageSet;
    assert!(ipc::kinds_exclude_refused(AuditRequest::KINDS));
    assert!(ipc::kinds_exclude_refused(AuditReply::KINDS));
    assert_eq!(AuditRequest::KINDS, &[KIND_APPEND, KIND_PING]);
    assert_eq!(AuditReply::KINDS, &[KIND_ACK, KIND_PONG]);
}

/// docs/50 §8.1: auditd's cursor takes the first batch as the baseline,
/// then requires contiguous numbering; it advances only when told (after
/// persistence) and acknowledges the batch's last number.
#[test]
fn append_cursor() {
    let mut cursor = AppendCursor::new();
    let first = append(10, 3);
    let range = cursor.check(&first).unwrap();
    assert_eq!(
        range,
        SeqRange {
            first: 10,
            last: 12
        }
    );
    // Not advanced yet: the same batch is still acceptable (a retry).
    assert_eq!(cursor.check(&first), Ok(range));
    cursor.advance(range).unwrap();
    assert_eq!(
        cursor.check(&append(12, 1)),
        Err(SequenceError::OutOfOrder { expected: 13 })
    );
    assert_eq!(
        cursor.check(&append(14, 1)),
        Err(SequenceError::OutOfOrder { expected: 13 })
    );
    let next = cursor.check(&append(13, 2)).unwrap();
    assert_eq!(
        AppendCursor::ack(next, [3; 32]),
        Ack {
            through_seq: 14,
            head_hash: [3; 32]
        }
    );
    // Exhaustion: nothing follows u64::MAX.
    let last = Append::new(u64::MAX, vec![event(1, 0)]).unwrap();
    let mut fresh = AppendCursor::new();
    let range = fresh.check(&last).unwrap();
    assert_eq!(fresh.advance(range), Err(SequenceError::Exhausted));
}
