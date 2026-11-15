#![no_main]
//! Fuzz target for the sealed key store's persisted format (task KL1).
//!
//! docs/CLEAN-ROOM.md / docs/32 §8 require a fuzz target for every parser before
//! it merges to `main`; a key-store file is untrusted when read back (r4-c
//! §3.6: whoever can write the disk can change it). Arbitrary bytes are fed
//! to `KeyRecord::parse` and `ParsedHeader::parse`, and — for an accepted
//! record — the rest of the input to `parse_body`: none may panic, hang or
//! over-allocate; each fails closed with a `FormatError`. Whatever is
//! accepted re-encodes to the identical octets (canonical encoding), stays
//! within its bound, and keeps the format's rules (1 or 2 versions, the
//! previous kvno below the current one). The same property runs
//! deterministically in crates/keyd-types/tests/sealed_store_format.rs.
//!
//! The suite registry here is fuzz data (two codes with distinct lengths):
//! no suite is registered in the product yet (docs/questions/Q-906).
//!
//! Spec: docs/research/r4-c-key-lifecycle.md §3.3, §3.6, §8.3; docs/CLEAN-ROOM.md

use keyd_types::sealed_store::{
    encode_header, encode_record, parse_body, KeyRecord, ParsedHeader, SealingSuite,
    MAX_KEY_RECORD_OCTETS, MAX_STORE_HEADER_OCTETS,
};
use libfuzzer_sys::fuzz_target;

/// Fuzz-only registry: two codes, every other one unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FuzzSuite {
    A,
    B,
}

impl SealingSuite for FuzzSuite {
    fn from_code(code: u16) -> Option<Self> {
        match code {
            1 => Some(FuzzSuite::A),
            2 => Some(FuzzSuite::B),
            _ => None,
        }
    }
    fn code(self) -> u16 {
        match self {
            FuzzSuite::A => 1,
            FuzzSuite::B => 2,
        }
    }
    fn seal_overhead(self) -> usize {
        match self {
            FuzzSuite::A => 28,
            FuzzSuite::B => 0,
        }
    }
    fn digest_len(self) -> usize {
        match self {
            FuzzSuite::A => 32,
            FuzzSuite::B => 48,
        }
    }
}

fuzz_target!(|data: &[u8]| {
    if let Ok(record) = KeyRecord::<FuzzSuite>::parse(data) {
        assert!(data.len() <= MAX_KEY_RECORD_OCTETS, "records are bounded");
        let aad = record.aad();
        if let Some(previous) = &aad.previous {
            assert!(previous.kvno < aad.current.kvno, "previous below current");
        }
        assert_eq!(
            encode_record(aad, record.sealed()).expect("re-encodes"),
            data,
            "parse then encode is exact"
        );
        // Treat the sealed octets as a plaintext candidate: exactly the
        // body length parses, anything else is refused, never a panic.
        let _ = parse_body(aad, record.sealed());
        if let Some(plain) = record.sealed().get(..aad.body_len()) {
            assert!(parse_body(aad, plain).is_ok(), "an exact body parses");
        }
    }
    if let Ok(parsed) = ParsedHeader::<FuzzSuite>::parse(data) {
        assert!(data.len() <= MAX_STORE_HEADER_OCTETS, "headers are bounded");
        assert!(parsed.header().generation >= 1, "G is at least 1");
        assert_eq!(
            encode_header(parsed.header(), parsed.sealed()).expect("re-encodes"),
            data,
            "header round trip"
        );
    }
});
