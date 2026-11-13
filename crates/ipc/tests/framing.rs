//! Stream framing on split and concatenated buffers; the per-channel bound
//! applied at the length prefix; truncation sweeps.
//!
//! Source: docs/50 §3.3 ("Frame := length:u32 (big-endian) ‖ body[length]";
//! "`length` is checked against the MAX of (channel, direction) **before** any
//! body byte is allocated or read; 0 or > MAX ⇒ close"; the frame buffer is
//! zeroized after decoding), R50-4, R50-7 (one request in flight: the reader
//! takes only the current frame's octets).

mod common;

use common::{raw_frame, KIND_LOOKUP, REQUEST_LIMIT, SAMPLE};
use ipc::{
    decode_frame, Error, FrameLimit, FrameReader, FrameStatus, BODY_HEADER_LEN, LENGTH_PREFIX_LEN,
    MAX_BODY_CEILING, MIN_BODY_LIMIT,
};

/// A Lookup frame of the sample channel: 4 + 4 + 18 octets.
fn lookup_frame(fill: u8) -> Vec<u8> {
    let mut payload = vec![fill; 16];
    payload.push(0x07);
    payload.push(0x01);
    raw_frame(SAMPLE.magic(), SAMPLE.version(), KIND_LOOKUP, &payload)
}

// ---- FrameLimit ---------------------------------------------------------------

#[test]
fn frame_limit_must_hold_the_refused_reply_and_stay_under_the_ceiling() {
    // At least the envelope plus one octet (the shared Refused reply, A-59).
    for max in 0..MIN_BODY_LIMIT {
        assert_eq!(FrameLimit::new(max), None, "max {max}");
    }
    assert_eq!(FrameLimit::new(5).map(FrameLimit::max_body), Some(5));
    assert_eq!(
        FrameLimit::new(MAX_BODY_CEILING).map(FrameLimit::max_body),
        Some(MAX_BODY_CEILING)
    );
    assert_eq!(FrameLimit::new(MAX_BODY_CEILING + 1), None);
    assert_eq!(FrameLimit::new(u32::MAX), None);
    assert_eq!(BODY_HEADER_LEN, 4);
    assert_eq!(LENGTH_PREFIX_LEN, 4);
}

// ---- decode_frame -----------------------------------------------------------

#[test]
fn empty_and_partial_buffers_need_more() {
    let frame = lookup_frame(0x33);
    assert_eq!(
        decode_frame(&[], REQUEST_LIMIT),
        Ok(FrameStatus::NeedMore { frame_len: None })
    );
    for cut in 1..LENGTH_PREFIX_LEN {
        assert_eq!(
            decode_frame(&frame[..cut], REQUEST_LIMIT),
            Ok(FrameStatus::NeedMore { frame_len: None }),
            "cut {cut}"
        );
    }
    // From the prefix on, the total length is known.
    for cut in LENGTH_PREFIX_LEN..frame.len() {
        assert_eq!(
            decode_frame(&frame[..cut], REQUEST_LIMIT),
            Ok(FrameStatus::NeedMore {
                frame_len: Some(frame.len())
            }),
            "cut {cut}"
        );
    }
}

#[test]
fn a_whole_frame_is_complete() {
    let frame = lookup_frame(0x33);
    assert_eq!(
        decode_frame(&frame, REQUEST_LIMIT),
        Ok(FrameStatus::Complete {
            body: &frame[LENGTH_PREFIX_LEN..],
            frame_len: frame.len()
        })
    );
}

#[test]
fn concatenated_frames_are_cut_one_by_one() {
    let first = lookup_frame(0x01);
    let second = lookup_frame(0x02);
    let third = raw_frame(SAMPLE.magic(), SAMPLE.version(), 0x55, &[]);
    let mut stream = Vec::new();
    stream.extend_from_slice(&first);
    stream.extend_from_slice(&second);
    stream.extend_from_slice(&third);

    let mut rest = &stream[..];
    let mut bodies = Vec::new();
    while let Ok(FrameStatus::Complete { body, frame_len }) = decode_frame(rest, REQUEST_LIMIT) {
        bodies.push(body.to_vec());
        rest = &rest[frame_len..];
    }
    assert!(rest.is_empty());
    assert_eq!(
        bodies,
        vec![
            first[LENGTH_PREFIX_LEN..].to_vec(),
            second[LENGTH_PREFIX_LEN..].to_vec(),
            third[LENGTH_PREFIX_LEN..].to_vec(),
        ]
    );
}

#[test]
fn declared_length_over_the_bound_is_refused_from_the_prefix_alone() {
    let max = REQUEST_LIMIT.max_body();
    // Only the four prefix octets: refused before any body octet is awaited.
    assert_eq!(
        decode_frame(&(max + 1).to_be_bytes(), REQUEST_LIMIT),
        Err(Error::FrameTooLarge)
    );
    assert_eq!(
        decode_frame(&u32::MAX.to_be_bytes(), REQUEST_LIMIT),
        Err(Error::FrameTooLarge)
    );
    // Exactly the bound is acceptable (and needs its body).
    assert_eq!(
        decode_frame(&max.to_be_bytes(), REQUEST_LIMIT),
        Ok(FrameStatus::NeedMore {
            frame_len: Some(LENGTH_PREFIX_LEN + max as usize)
        })
    );
}

#[test]
fn the_bound_is_per_direction() {
    // A body that fits the request bound is refused under the reply bound.
    let body_len = common::REPLY_LIMIT.max_body() + 1;
    let prefix = body_len.to_be_bytes();
    assert!(decode_frame(&prefix, REQUEST_LIMIT).is_ok());
    assert_eq!(
        decode_frame(&prefix, common::REPLY_LIMIT),
        Err(Error::FrameTooLarge)
    );
}

#[test]
fn declared_length_below_the_envelope_is_refused() {
    for declared in 0..BODY_HEADER_LEN as u32 {
        let mut frame = declared.to_be_bytes().to_vec();
        frame.extend_from_slice(&[0; 3]);
        assert_eq!(
            decode_frame(&frame, REQUEST_LIMIT),
            Err(Error::FrameTooShort),
            "declared {declared}"
        );
    }
}

// ---- FrameReader ------------------------------------------------------------

#[test]
fn frame_reader_accepts_a_frame_byte_by_byte() {
    let frame = lookup_frame(0x44);
    let mut reader = FrameReader::new(REQUEST_LIMIT);
    for (index, octet) in frame.iter().enumerate() {
        let expected = if index < LENGTH_PREFIX_LEN {
            LENGTH_PREFIX_LEN - index
        } else {
            frame.len() - index
        };
        assert_eq!(reader.wanted(), expected, "index {index}");
        assert!(reader.body().is_none());
        assert_eq!(reader.push(&[*octet]), Ok(1));
    }
    assert!(reader.is_complete());
    assert_eq!(reader.wanted(), 0);
    assert_eq!(reader.body(), Some(&frame[LENGTH_PREFIX_LEN..]));
    // Nothing more is taken while the frame is held.
    assert_eq!(reader.push(&[0xAA]), Ok(0));
}

#[test]
fn frame_reader_accepts_every_two_piece_split() {
    let frame = lookup_frame(0x45);
    for cut in 0..=frame.len() {
        let mut reader = FrameReader::new(REQUEST_LIMIT);
        let (head, tail) = frame.split_at(cut);
        let mut taken = reader.push(head).unwrap();
        taken += reader.push(tail).unwrap();
        assert_eq!(taken, frame.len(), "cut {cut}");
        assert_eq!(
            reader.body(),
            Some(&frame[LENGTH_PREFIX_LEN..]),
            "cut {cut}"
        );
    }
}

#[test]
fn frame_reader_takes_only_the_current_frame_from_concatenated_input() {
    let first = lookup_frame(0x01);
    let second = lookup_frame(0x02);
    let mut stream = first.clone();
    stream.extend_from_slice(&second);

    let mut reader = FrameReader::new(REQUEST_LIMIT);
    let taken = reader.push(&stream).unwrap();
    assert_eq!(taken, first.len());
    assert_eq!(reader.body(), Some(&first[LENGTH_PREFIX_LEN..]));

    reader.reset();
    assert!(reader.body().is_none());
    assert_eq!(reader.wanted(), LENGTH_PREFIX_LEN);
    let taken = reader.push(&stream[first.len()..]).unwrap();
    assert_eq!(taken, second.len());
    assert_eq!(reader.body(), Some(&second[LENGTH_PREFIX_LEN..]));
}

#[test]
fn frame_reader_wanted_never_pulls_in_the_next_frame() {
    // Reading exactly `wanted()` octets at a time ends on the frame boundary.
    let first = lookup_frame(0x0A);
    let second = lookup_frame(0x0B);
    let mut stream = first.clone();
    stream.extend_from_slice(&second);
    let mut reader = FrameReader::new(REQUEST_LIMIT);
    let mut offset = 0;
    while !reader.is_complete() {
        let wanted = reader.wanted();
        assert!(wanted > 0);
        let taken = reader.push(&stream[offset..offset + wanted]).unwrap();
        assert_eq!(taken, wanted);
        offset += taken;
    }
    assert_eq!(offset, first.len());
}

#[test]
fn frame_reader_refuses_an_over_bound_length_at_the_prefix() {
    let mut reader = FrameReader::new(REQUEST_LIMIT);
    let declared = REQUEST_LIMIT.max_body() + 1;
    assert_eq!(
        reader.push(&declared.to_be_bytes()),
        Err(Error::FrameTooLarge)
    );
    // Sticky: later input, and a reset, do not revive the stream.
    assert_eq!(reader.push(&[0; 16]), Err(Error::FrameTooLarge));
    assert_eq!(reader.wanted(), 0);
    reader.reset();
    assert_eq!(reader.push(&lookup_frame(0)), Err(Error::FrameTooLarge));
    assert!(reader.body().is_none());
}

#[test]
fn frame_reader_refuses_a_short_length_at_the_prefix() {
    let mut reader = FrameReader::new(REQUEST_LIMIT);
    assert_eq!(reader.push(&[0, 0, 0, 3]), Err(Error::FrameTooShort));
    let mut reader = FrameReader::new(REQUEST_LIMIT);
    assert_eq!(reader.push(&[0, 0]), Ok(2));
    assert_eq!(reader.push(&[0, 0, 0xFF]), Err(Error::FrameTooShort));
}

#[test]
fn frame_reader_reset_releases_the_body() {
    let frame = lookup_frame(0x99);
    let mut reader = FrameReader::new(REQUEST_LIMIT);
    reader.push(&frame).unwrap();
    assert!(reader.is_complete());
    // Debug shows lengths only, never the held octets (0x99 = 153).
    let shown = format!("{reader:?}");
    assert!(shown.contains("body_len: 22"), "{shown}");
    assert!(!shown.contains("153"), "{shown}");
    reader.reset();
    assert!(!reader.is_complete());
    assert!(reader.body().is_none());
    assert!(format!("{reader:?}").contains("body_len: 0"));
}

// ---- truncation sweep ---------------------------------------------------------

#[test]
fn every_truncation_of_a_frame_is_incomplete_never_an_error_or_a_frame() {
    let frame = lookup_frame(0x5C);
    for cut in 0..frame.len() {
        let status = decode_frame(&frame[..cut], REQUEST_LIMIT);
        assert!(
            matches!(status, Ok(FrameStatus::NeedMore { .. })),
            "cut {cut}: {status:?}"
        );
        let mut reader = FrameReader::new(REQUEST_LIMIT);
        assert_eq!(reader.push(&frame[..cut]), Ok(cut));
        assert!(!reader.is_complete(), "cut {cut}");
    }
}
