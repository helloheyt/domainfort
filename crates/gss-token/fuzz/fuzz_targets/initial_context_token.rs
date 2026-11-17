#![no_main]
//! Fuzz target for the RFC 2743 §3.1 / RFC 4121 §4.1 context-establishment
//! token decoder.
//!
//! AGENTS.md §6 / docs/32 §8 / docs/60 §10 LG1 require a fuzz target for
//! every parser before it merges to `main`. Arbitrary bytes are decoded under
//! both TOK_IDs: the decoder must never panic, hang or allocate — it fails
//! closed with a `gss_token::Error`. An accepted token carries the expected
//! TOK_ID and a non-empty Kerberos message, is within the 64 KiB bound, and
//! is canonical, so re-encoding reproduces the exact input. The same property
//! runs deterministically in `tests/robustness.rs`.
//!
//! Spec: RFC 2743 §3.1; RFC 4121 §4.1; [MS-KILE] 1.9.1; docs/60 R60-11.

use gss_token::{ContextEstablishmentToken, TokId, MAX_CONTEXT_TOKEN_LEN};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    for expected in [TokId::KrbApReq, TokId::KrbApRep] {
        if let Ok(token) = ContextEstablishmentToken::decode(data, expected) {
            assert_eq!(token.tok_id(), expected, "the expected TOK_ID only");
            assert!(
                !token.kerberos_message().is_empty(),
                "a Kerberos message follows"
            );
            assert!(data.len() <= MAX_CONTEXT_TOKEN_LEN, "tokens are bounded");
            assert_eq!(token.encode(), data, "decode then encode is exact");
        }
    }
});
