//! Deterministic never-panic smoke test, running the properties of the three
//! cargo-fuzz targets in `fuzz/` (docs/CLEAN-ROOM.md: every parser gets a fuzz
//! target; the harness itself needs cargo-fuzz and its dependency, which this
//! environment may not have).
//!
//! Seeds are hand-built tokens (`common/mod.rs`, from the RFC layouts); every
//! truncation and every single-octet substitution (several values per
//! position) of each seed is fed to every entry point. Each must return `Ok`
//! or `Err` without panicking, and anything accepted must satisfy the
//! invariants the profile promises.

mod common;

use common::*;
use core::num::NonZeroU16;
use gss_token::{
    AuthenticatorChecksum, ChecksumField, ContextEstablishmentToken, ReceivedWrapToken, Sender,
    TokId, WrapExpectation, WrapHeader, GSS_CHECKSUM_TYPE, MAX_CONTEXT_TOKEN_LEN,
    MAX_WRAP_TOKEN_LEN,
};

/// The property of `fuzz_targets/initial_context_token.rs`.
fn check_context_token(data: &[u8]) {
    for expected in [TokId::KrbApReq, TokId::KrbApRep] {
        if let Ok(token) = ContextEstablishmentToken::decode(data, expected) {
            assert_eq!(token.tok_id(), expected);
            assert!(!token.kerberos_message().is_empty());
            assert!(data.len() <= MAX_CONTEXT_TOKEN_LEN);
            // Accepted tokens are canonical: re-encoding is exact.
            assert_eq!(token.encode(), data);
            assert_eq!(token.encoded_len(), data.len());
        }
    }
}

/// The property of `fuzz_targets/wrap_token.rs`.
fn check_wrap_token(data: &[u8]) {
    let structural = WrapHeader::read(data);
    for sender in [Sender::Initiator, Sender::Acceptor] {
        for acceptor_subkey in [false, true] {
            for checksum_len in [1u16, 3, 12, 16, 24] {
                let expected = WrapExpectation {
                    sender,
                    acceptor_subkey,
                    checksum_len: NonZeroU16::new(checksum_len).unwrap(),
                };
                if let Ok(token) = ReceivedWrapToken::parse(data, expected) {
                    let header = *token.header();
                    assert_eq!(structural, Ok(header), "the profile reads the same header");
                    assert!(!header.sealed());
                    assert_eq!(header.sender(), sender);
                    assert_eq!(header.acceptor_subkey(), acceptor_subkey);
                    assert_eq!(header.ec(), checksum_len);
                    assert!(data.len() <= MAX_WRAP_TOKEN_LEN);
                    assert_eq!(token.checksum().len(), usize::from(checksum_len));
                    let input_len = token.checksum_input().len();
                    assert_eq!(input_len + token.checksum().len(), data.len());
                    assert_eq!(
                        &token.checksum_input()[input_len - 16..],
                        &header.checksum_header()
                    );
                    let plaintext = token.into_verified_plaintext(|_, _| true).unwrap();
                    assert_eq!(plaintext.len(), input_len - 16);
                }
            }
        }
    }
}

/// The property of `fuzz_targets/authenticator_checksum.rs`.
fn check_checksum(data: &[u8]) {
    for cksumtype in [GSS_CHECKSUM_TYPE, 0] {
        let result = AuthenticatorChecksum::from_authenticator(
            Some(ChecksumField {
                cksumtype,
                checksum: data,
            }),
            Some(9),
        );
        if let Ok(accepted) = result {
            assert_eq!(cksumtype, GSS_CHECKSUM_TYPE);
            assert!(data.len() >= 24);
            let flags = accepted.flags();
            assert!(!flags.deleg() && flags.integ() && flags.mutual());
            assert_ne!(accepted.bnd().octets(), &[0u8; 16]);
            assert_eq!(accepted.bnd().octets(), &data[4..20]);
            assert_eq!(accepted.initiator_seq_number(), 9);
        }
    }
}

fn mutations(seed: &[u8]) -> Vec<Vec<u8>> {
    let mut out = vec![seed.to_vec()];
    for cut in 0..seed.len() {
        out.push(seed[..cut].to_vec());
    }
    for at in 0..seed.len() {
        for value in [0x00u8, 0x01, 0x05, 0x06, 0x60, 0x7F, 0x80, 0x81, 0xFF] {
            let mut m = seed.to_vec();
            m[at] = value;
            out.push(m);
        }
        let mut m = seed.to_vec();
        m[at] ^= 0xFF;
        out.push(m);
    }
    let mut longer = seed.to_vec();
    longer.push(0x00);
    out.push(longer);
    out
}

#[test]
fn context_token_seeds_and_mutations_never_panic() {
    let seeds = [
        frame(TOK_AP_REQ, &ap_req_stand_in(1)),
        frame(TOK_AP_REQ, &ap_req_stand_in(200)),
        frame(TOK_AP_REP, &ap_req_stand_in(30)),
        frame_with_oid(&TRUNCATED_OID, &[0x01, 0x00, 0x6E]),
    ];
    for seed in &seeds {
        for m in mutations(seed) {
            check_context_token(&m);
        }
    }
}

#[test]
fn wrap_token_seeds_and_mutations_never_panic() {
    let mut data = vec![0x01, 0x00, 0x00, 0x00];
    data.extend([0xC5; 12]);
    let seeds = [
        wrap_token(wrap_header(0x04, 12, 0, 1), &data),
        wrap_token(wrap_header(0x05, 12, 5, 2), &data),
        wrap_token(wrap_header(0x04, 3, 3, 3), &[1, 2, 3, 4, 5, 6, 7, 8]),
        wrap_token(wrap_header(0x06, 0, 28, 4), &[0x55; 40]),
        wrap_header(0x04, 1, 65_535, 5).to_vec(),
    ];
    for seed in &seeds {
        for m in mutations(seed) {
            check_wrap_token(&m);
        }
    }
}

#[test]
fn checksum_seeds_and_mutations_never_panic() {
    let seeds = [
        checksum(16, BND, INTEG_MUTUAL, &[]),
        checksum(16, BND, INTEG_MUTUAL | 1, &[1, 0, 2, 0, 0x76, 0]),
        checksum(16, BND, 0xFFFF_FFFE, &[0xEE; 8]),
    ];
    for seed in &seeds {
        for m in mutations(seed) {
            check_checksum(&m);
        }
    }
}
