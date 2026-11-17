#![no_main]
//! Fuzz target for the RFC 4121 §4.2.6.2 Wrap token reader and profile.
//!
//! docs/CLEAN-ROOM.md / docs/60 §10 LG1. Arbitrary bytes go to the structural
//! reader (`WrapHeader::read`) and to the profile parser
//! (`ReceivedWrapToken::parse`) under every expectation the first octet of
//! the input selects: neither may panic, hang or over-allocate. An accepted
//! token was not sealed, names the expected sender and AcceptorSubkey, has
//! EC = the expected checksum length, is within the 1 KiB bound, reads the
//! same header as the structural reader, and lays out checksum input and
//! checksum that together cover the token exactly. The same property runs
//! deterministically in `tests/robustness.rs`.
//!
//! Spec: RFC 4121 §4.2.2–§4.2.6.2; docs/60 §3.4, R60-11.

use core::num::NonZeroU16;
use gss_token::{ReceivedWrapToken, Sender, WrapExpectation, WrapHeader, MAX_WRAP_TOKEN_LEN};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let Some((&selector, data)) = input.split_first() else {
        return;
    };
    let structural = WrapHeader::read(data);
    let sender = if selector & 1 == 0 {
        Sender::Initiator
    } else {
        Sender::Acceptor
    };
    let acceptor_subkey = selector & 2 != 0;
    let checksum_len = NonZeroU16::new(u16::from(selector >> 2).max(1)).unwrap_or(NonZeroU16::MIN);
    let expected = WrapExpectation {
        sender,
        acceptor_subkey,
        checksum_len,
    };
    if let Ok(token) = ReceivedWrapToken::parse(data, expected) {
        let header = *token.header();
        assert_eq!(structural, Ok(header), "the profile reads the same header");
        assert!(!header.sealed(), "Sealed is refused");
        assert_eq!(header.sender(), sender);
        assert_eq!(header.acceptor_subkey(), acceptor_subkey);
        assert_eq!(header.ec(), checksum_len.get());
        assert!(data.len() <= MAX_WRAP_TOKEN_LEN, "tokens are bounded");
        assert_eq!(token.checksum().len(), usize::from(checksum_len.get()));
        assert_eq!(
            token.checksum_input().len() + token.checksum().len(),
            data.len(),
            "checksum input and checksum cover the token"
        );
        let plaintext = token.into_verified_plaintext(|_, _| true);
        assert!(plaintext.is_ok());
    }
});
