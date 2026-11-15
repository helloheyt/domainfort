#![no_main]
//! Fuzz target for the IPC stream framer: `ipc::decode_frame` and
//! `ipc::FrameReader`.
//!
//! docs/CLEAN-ROOM.md / docs/50 §9 (R50-19): arbitrary bytes → framer; never a
//! panic, bounded allocation. The first input octet picks the body bound and
//! the chunk size the stream arrives in; the rest is the stream. Every frame
//! the stateless decoder cuts must lie inside the buffer and within the bound
//! (docs/50 §3.3: the bound is applied to the declared length before the body
//! is awaited), and the accumulating reader, fed the same stream in chunks,
//! must cut exactly the same frames and fail exactly when the decoder fails.
//!
//! Spec: docs/50 §3.3; R50-4; R50-7.

use ipc::{decode_frame, FrameLimit, FrameReader, FrameStatus, LENGTH_PREFIX_LEN};
use libfuzzer_sys::fuzz_target;

/// Body bounds exercised: the smallest allowed (`MIN_BODY_LIMIT`), small,
/// medium, and one that a 16-bit length can exceed.
const LIMITS: [u32; 4] = [ipc::MIN_BODY_LIMIT, 64, 4096, 65_536];

fuzz_target!(|data: &[u8]| {
    let Some((&selector, stream)) = data.split_first() else {
        return;
    };
    let Some(limit) = FrameLimit::new(LIMITS[usize::from(selector & 0x03)]) else {
        return;
    };
    let chunk = usize::from(selector >> 2) + 1;

    // Stateless decoder: cut every frame.
    let mut expected: Vec<Vec<u8>> = Vec::new();
    let mut decoder_failed = false;
    let mut rest = stream;
    loop {
        match decode_frame(rest, limit) {
            Ok(FrameStatus::Complete { body, frame_len }) => {
                assert!(frame_len <= rest.len(), "a complete frame is buffered");
                assert_eq!(frame_len, LENGTH_PREFIX_LEN + body.len());
                assert!(body.len() >= ipc::BODY_HEADER_LEN, "envelope fits");
                assert!(body.len() <= limit.max_body() as usize, "frames are bounded");
                expected.push(body.to_vec());
                rest = &rest[frame_len..];
            }
            Ok(FrameStatus::NeedMore { frame_len }) => {
                if let Some(total) = frame_len {
                    assert!(total > rest.len());
                    assert!(total <= LENGTH_PREFIX_LEN + limit.max_body() as usize);
                }
                break;
            }
            Err(_) => {
                decoder_failed = true;
                break;
            }
        }
    }

    // Accumulating reader on the same stream, in chunks.
    let mut reader = FrameReader::new(limit);
    let mut cut: Vec<Vec<u8>> = Vec::new();
    let mut reader_failed = false;
    'stream: for piece in stream.chunks(chunk) {
        let mut piece = piece;
        while !piece.is_empty() {
            match reader.push(piece) {
                Ok(taken) => {
                    assert!(taken <= piece.len());
                    piece = &piece[taken..];
                    if let Some(body) = reader.body() {
                        cut.push(body.to_vec());
                        reader.reset();
                    } else {
                        // An incomplete frame takes everything it is given
                        // (this also rules out a zero-progress loop).
                        assert!(piece.is_empty(), "incomplete frame left input");
                    }
                }
                Err(_) => {
                    reader_failed = true;
                    break 'stream;
                }
            }
        }
    }
    assert_eq!(cut, expected, "both framers cut the same frames");
    assert_eq!(reader_failed, decoder_failed, "both framers fail together");
});
