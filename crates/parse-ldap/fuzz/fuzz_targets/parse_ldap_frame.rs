#![no_main]
//! Fuzz target for `parse_ldap::frame_length`, the TCP stream framer.
//!
//! docs/CLEAN-ROOM.md / docs/32 §8 (docs/49 §2.5: "arbitrary bytes → framer →
//! decode; never a panic, bounded allocation"). The buffer is treated as a
//! byte stream: every complete frame the framer reports must lie inside the
//! buffer and within the session bound, and is then decoded as a request
//! (which may fail, but must not panic). The framer must never report a frame
//! whose announced size exceeds the bound (docs/49 §2.4; [MS-ADTS]
//! 3.1.1.3.4.6).
//!
//! Spec: RFC 4511 §4.1.1, §5.2; X.690 8.1.2–8.1.3; A-45.

use libfuzzer_sys::fuzz_target;
use parse_ldap::{decode_message, frame_length, AuthState, DecodeOptions, Frame};

fuzz_target!(|data: &[u8]| {
    for auth in [AuthState::Unauthenticated, AuthState::Authenticated] {
        let options = DecodeOptions::request(auth);
        let mut rest = data;
        loop {
            match frame_length(rest, auth) {
                Ok(Frame::Complete { length }) => {
                    assert!(length > 0, "a frame has at least an identifier");
                    assert!(length <= rest.len(), "a complete frame is buffered");
                    assert!(length <= auth.max_message_octets(), "frames are bounded");
                    let (pdu, tail) = rest.split_at(length);
                    let _ = decode_message(pdu, &options);
                    rest = tail;
                }
                Ok(Frame::NeedMore) | Err(_) => break,
            }
        }
    }
});
