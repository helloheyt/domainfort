#![no_main]
//! Fuzz target for dirstore's record decoders.
//!
//! AGENTS.md §6 / docs/32 §8 (D138) require a fuzz target for every parser
//! before it merges to `main`. Record bodies read back from disk are treated
//! as untrusted (docs/32 §3: tag first, then bounded parse), so arbitrary
//! bytes are fed to every body decoder: none may panic, hang, or over-allocate
//! (each fails closed with a `DecodeError`). When the object decoder accepts
//! the input, the codec is canonical, so re-encoding must reproduce the input
//! exactly: `encode(decode(b)) == b` (src/record.rs "Rules").
//!
//! Spec: docs/32 §8 (D138); docs/10 D34; src/record.rs layout.

use libfuzzer_sys::fuzz_target;

const G: dtyp::Guid = dtyp::Guid {
    data1: 1,
    data2: 2,
    data3: 3,
    data4: [4, 5, 6, 7, 8, 9, 10, 11],
};

fuzz_target!(|data: &[u8]| {
    if let Ok(obj) = dirstore::record::decode_object_body(G, data) {
        let again = dirstore::record::encode_object_body(&obj)
            .expect("a decoded object must re-encode");
        assert_eq!(again.as_slice(), data, "the codec must be canonical");
    }
    if let Ok(child) = dirstore::record::decode_name_index_body(data) {
        assert_eq!(dirstore::record::encode_name_index_body(child).as_slice(), data);
    }
    if let Ok(count) = dirstore::record::decode_child_count_body(data) {
        assert_eq!(dirstore::record::encode_child_count_body(count).as_slice(), data);
    }
    let _ = dirstore::record::decode_meta_body(data);
});
