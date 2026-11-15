#![no_main]
//! Fuzz target for the RFC 3244 request framing.
//!
//! docs/CLEAN-ROOM.md / docs/32 §8 / docs/53 §5.9 require a fuzz target for every
//! parser before it merges to `main`. Arbitrary bytes are fed to
//! `RequestMessage::parse` (one message), `RequestMessage::parse_tcp` (one
//! whole TCP frame) and `tcp_message_length` (the 4-octet header): none may
//! panic, hang or over-allocate — each fails closed with a
//! `parse_kpasswd::Error`. When a message is accepted, its invariants hold
//! (non-empty AP-REQ and KRB-PRIV, ≤ 65,535 octets) and re-encoding
//! reproduces the exact input (docs/50 §3.3). The same property runs
//! deterministically in `tests/robustness.rs`.
//!
//! Spec: RFC 3244 §2; docs/53 §5.1, §5.9.

use libfuzzer_sys::fuzz_target;
use parse_kpasswd::{
    tcp_message_length, RequestMessage, MAX_MESSAGE_LEN, MESSAGE_HEADER_LEN, TCP_HEADER_LEN,
};

fuzz_target!(|data: &[u8]| {
    if let Ok(message) = RequestMessage::parse(data) {
        assert!(!message.ap_req().is_empty(), "AP_REQ length 0 is refused");
        assert!(!message.krb_priv().is_empty(), "a KRB-PRIV follows");
        assert!(data.len() <= MAX_MESSAGE_LEN, "messages are bounded");
        assert_eq!(message.encode(), data, "parse then encode is exact");
    }
    if let Ok(message) = RequestMessage::parse_tcp(data) {
        assert_eq!(message.encode_tcp(), data, "TCP frame round trip");
    }
    if let Some((header, _)) = data.split_first_chunk::<TCP_HEADER_LEN>() {
        if let Ok(length) = tcp_message_length(*header) {
            assert!(
                (MESSAGE_HEADER_LEN..=MAX_MESSAGE_LEN).contains(&length),
                "the announced length is bounded before allocation"
            );
        }
    }
});
