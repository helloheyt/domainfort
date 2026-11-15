//! Deterministic never-panic smoke test (complements the cargo-fuzz targets
//! in `fuzz/`, which are pending owner approval of their harness dependency,
//! PENDING-OWNER P-1). It runs the same property the fuzz targets check.
//!
//! Seeds are hand-built RFC 3244 §2 messages (`common/mod.rs`); every
//! truncation and every single-octet substitution of each seed — and of its
//! TCP frame — is fed to every entry point. Each must return `Ok` or `Err`
//! without panicking; anything accepted must satisfy the invariants and
//! re-encode to the identical octets (docs/50 §3.3 round trip).

mod common;

use common::*;
use parse_kpasswd::{
    tcp_message_length, ReplyBody, ReplyMessage, RequestMessage, MAX_MESSAGE_LEN,
    MESSAGE_HEADER_LEN, TCP_HEADER_LEN,
};

/// The property of `fuzz_targets/parse_kpasswd_request.rs`.
fn check_request(data: &[u8]) {
    if let Ok(message) = RequestMessage::parse(data) {
        assert!(!message.ap_req().is_empty());
        assert!(!message.krb_priv().is_empty());
        assert!(data.len() <= MAX_MESSAGE_LEN);
        assert_eq!(message.encode(), data);
    }
    if let Ok(message) = RequestMessage::parse_tcp(data) {
        assert_eq!(message.encode_tcp(), data);
    }
    check_tcp_header(data);
}

/// The property of `fuzz_targets/parse_kpasswd_reply.rs`.
fn check_reply(data: &[u8]) {
    if let Ok(message) = ReplyMessage::parse(data) {
        match message.body() {
            ReplyBody::ApRep { ap_rep, krb_priv } => {
                assert!(!ap_rep.is_empty() && !krb_priv.is_empty());
            }
            ReplyBody::KrbError { krb_error } => assert!(!krb_error.is_empty()),
        }
        assert_eq!(message.encode(), data);
    }
    if let Ok(message) = ReplyMessage::parse_tcp(data) {
        assert_eq!(message.encode_tcp(), data);
    }
    check_tcp_header(data);
}

fn check_tcp_header(data: &[u8]) {
    if let Some((header, _)) = data.split_first_chunk::<TCP_HEADER_LEN>() {
        if let Ok(length) = tcp_message_length(*header) {
            assert!((MESSAGE_HEADER_LEN..=MAX_MESSAGE_LEN).contains(&length));
        }
    }
}

fn seeds() -> Vec<Vec<u8>> {
    let request = request(&ap_req_octets(), &krb_priv_octets());
    let reply = reply(&ap_rep_octets(), &krb_priv_octets());
    let error = error_reply(&krb_error_octets());
    let minimal = request_min();
    vec![
        tcp(&request),
        tcp(&reply),
        tcp(&error),
        tcp(&minimal),
        request,
        reply,
        error,
        minimal,
    ]
}

fn request_min() -> Vec<u8> {
    common::request(&[0x6E], &[0x75])
}

#[test]
fn seeds_round_trip() {
    for seed in seeds() {
        check_request(&seed);
        check_reply(&seed);
    }
}

#[test]
fn every_truncation_fails_closed() {
    for seed in seeds() {
        for len in 0..seed.len() {
            check_request(&seed[..len]);
            check_reply(&seed[..len]);
        }
    }
}

#[test]
fn every_single_octet_substitution_fails_closed() {
    // Substitutions chosen to hit the length fields (0x00, 0x01, 0x7F, 0x80,
    // 0xFF), the version octets (0xFF, 0x80, 0x01) and arbitrary values.
    const SUBSTITUTES: [u8; 8] = [0x00, 0x01, 0x06, 0x7F, 0x80, 0xA5, 0xFE, 0xFF];
    for seed in seeds() {
        let mut mutated = seed.clone();
        for i in 0..seed.len() {
            for &octet in &SUBSTITUTES {
                mutated[i] = octet;
                check_request(&mutated);
                check_reply(&mutated);
            }
            mutated[i] = seed[i];
        }
    }
}
