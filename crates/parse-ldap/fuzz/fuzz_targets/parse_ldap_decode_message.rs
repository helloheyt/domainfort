#![no_main]
//! Fuzz target for `parse_ldap::decode_message`.
//!
//! docs/CLEAN-ROOM.md / docs/32 §8 require a fuzz target for every parser before it
//! merges to `main` (docs/49 §2.5). Arbitrary bytes are decoded as a request
//! and as a response, under the wire and the canonical profiles, with both
//! session bounds: none may panic, hang, or over-allocate — each fails closed
//! with a `parse_ldap::Error`.
//!
//! When an input is accepted, the canonical re-encoding (docs/49 §11, R49-16)
//! must succeed, must be no longer than the input, must decode under the
//! canonical profile to the same value, and must re-encode to itself. Input
//! accepted by the canonical profile must already be in canonical form.
//!
//! Spec: RFC 4511 §4, §5.1, App. B; X.690 clauses 8 and 10.1; A-45.

use libfuzzer_sys::fuzz_target;
use parse_ldap::{decode_message, encode_message, AuthState, DecodeOptions, Direction, Profile};

fn check(data: &[u8], direction: Direction, auth: AuthState) {
    let max_message_octets = auth.max_message_octets();
    let wire = DecodeOptions {
        direction,
        profile: Profile::Wire,
        max_message_octets,
    };
    let canonical = DecodeOptions {
        direction,
        profile: Profile::Canonical,
        max_message_octets,
    };

    if let Ok(value) = decode_message(data, &wire) {
        let encoded = encode_message(&value).expect("an accepted value must re-encode");
        assert!(
            encoded.len() <= data.len(),
            "canonical form is never longer"
        );
        let again = decode_message(&encoded, &canonical)
            .expect("the canonical re-encoding must decode canonically");
        assert_eq!(
            again, value,
            "canonical re-encoding must preserve the value"
        );
        assert_eq!(
            encode_message(&again).expect("re-encode"),
            encoded,
            "the canonical encoding must be stable"
        );
    }

    if let Ok(value) = decode_message(data, &canonical) {
        let encoded = encode_message(&value).expect("an accepted value must re-encode");
        assert_eq!(
            encoded.as_slice(),
            data,
            "canonical input is already canonical"
        );
    }
}

fuzz_target!(|data: &[u8]| {
    for direction in [Direction::Request, Direction::Response] {
        for auth in [AuthState::Unauthenticated, AuthState::Authenticated] {
            check(data, direction, auth);
        }
    }
});
