#![no_main]
//! Fuzz target for the strict DER decoder.
//!
//! AGENTS.md §6 / docs/32 §8 require a fuzz target for every parser before it
//! merges to `main`. Arbitrary bytes are fed to [`parse_asn1::decode`]: the
//! decoder must never panic, hang, or over-allocate on any input (it fails
//! closed with a `Result` error instead). When it *does* accept input, that
//! input was canonical DER, so re-encoding the decoded value must reproduce the
//! exact bytes (X.690 (02/2021) clause 10: DER is a single canonical encoding).
//!
//! Spec: X.690 clauses 8, 10, 11.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(value) = parse_asn1::decode(data) {
        // Accepted input is canonical DER; it must round-trip exactly.
        let reencoded =
            parse_asn1::encode(&value).expect("re-encoding a decoded value must succeed");
        assert_eq!(
            reencoded.as_slice(),
            data,
            "decode then encode must reproduce canonical input"
        );
    }
});
