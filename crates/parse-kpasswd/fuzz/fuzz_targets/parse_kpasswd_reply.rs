#![no_main]
//! Fuzz target for the RFC 3244 reply framing.
//!
//! docs/CLEAN-ROOM.md / docs/32 §8 / docs/53 §5.9 require a fuzz target for every
//! parser before it merges to `main`; replies are decoded as strictly as
//! requests (docs/07 §5, docs/50 §3.3). Arbitrary bytes are fed to
//! `ReplyMessage::parse` and `ReplyMessage::parse_tcp`: none may panic, hang
//! or over-allocate. When a reply is accepted, its body is either a non-empty
//! AP-REP and KRB-PRIV or a non-empty KRB-ERROR, and re-encoding reproduces
//! the exact input. The same property runs deterministically in
//! `tests/robustness.rs`.
//!
//! Spec: RFC 3244 §2; docs/53 §5.1, §5.9.

use libfuzzer_sys::fuzz_target;
use parse_kpasswd::{ReplyBody, ReplyMessage, MAX_MESSAGE_LEN};

fuzz_target!(|data: &[u8]| {
    if let Ok(message) = ReplyMessage::parse(data) {
        match message.body() {
            ReplyBody::ApRep { ap_rep, krb_priv } => {
                assert!(!ap_rep.is_empty(), "AP_REP length 0 means KRB-ERROR");
                assert!(!krb_priv.is_empty(), "a KRB-PRIV follows the AP-REP");
            }
            ReplyBody::KrbError { krb_error } => {
                assert!(!krb_error.is_empty(), "a KRB-ERROR is present");
            }
        }
        assert!(data.len() <= MAX_MESSAGE_LEN, "messages are bounded");
        assert_eq!(message.encode(), data, "parse then encode is exact");
    }
    if let Ok(message) = ReplyMessage::parse_tcp(data) {
        assert_eq!(message.encode_tcp(), data, "TCP frame round trip");
    }
});
