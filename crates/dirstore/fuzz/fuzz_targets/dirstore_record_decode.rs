#![no_main]
//! Fuzz target for dirstore's record decoders.
//!
//! AGENTS.md §6 / docs/32 §8 (D138) require a fuzz target for every parser
//! before it merges to `main`. Record bodies — and the reverse-link keys a
//! prefix scan reads back — come from disk and are treated as untrusted
//! (docs/32 §3: tag first, then bounded parse), so arbitrary bytes are fed to
//! every decoder: none may panic, hang, or over-allocate (each fails closed
//! with a `DecodeError`). When a decoder accepts the input, the codec is
//! canonical, so re-encoding must reproduce the input exactly:
//! `encode(decode(b)) == b` (src/record.rs "Rules").
//!
//! Not built or run: the fuzz dependencies await owner approval (P-1).
//!
//! Spec: docs/32 §8 (D138); docs/10 D34; docs/46 §8.4-§8.5; docs/51 §8.3
//! (counter record); src/record.rs layout.

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
    // Reverse-link records (docs/46 §8.4): the key and the body.
    if let Ok((target, id, source)) = dirstore::record::decode_back_link_key(data) {
        assert_eq!(
            dirstore::record::back_link_key(target, id, source).as_slice(),
            data
        );
    }
    if dirstore::record::decode_back_link_body(data).is_ok() {
        assert_eq!(dirstore::record::encode_back_link_body().as_slice(), data);
    }
    // Unique-index records (docs/46 §8.5).
    if let Ok(owner) = dirstore::record::decode_unique_index_body(data) {
        assert_eq!(
            dirstore::record::encode_unique_index_body(owner).as_slice(),
            data
        );
    }
    let _ = dirstore::record::decode_meta_body(data);
    // Named-counter records (docs/51 §8.3, A-75): a body the decoder accepts
    // is inside its range and re-encodes to the same bytes.
    if let Ok(state) = dirstore::record::decode_counter_body(data) {
        assert!(state.first_value < state.end_exclusive);
        assert!(state.first_value <= state.next_value);
        assert!(state.next_value <= state.end_exclusive);
        let again = dirstore::record::encode_counter_body(&state)
            .expect("a decoded counter must re-encode");
        assert_eq!(again.as_slice(), data, "the codec must be canonical");
    }
});
