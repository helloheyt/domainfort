//! The two fuzz targets' bodies (`fuzz/bodies/`), compiled and run by
//! `cargo test` over hand-made inputs: every message of the channel, every
//! truncation of it, every single-bit flip of it, and assorted garbage — so
//! the targets build and their properties hold before the fuzz workspace
//! itself is built (PENDING-OWNER P-1).
//!
//! Sources: docs/53 §5.9 (`ipc_kpasswd_request`, `ipc_kpasswd_reply`);
//! docs/50 §3.3, §9; docs/CLEAN-ROOM.md Inputs are encoded by this crate from the
//! hand-made values of tests/common.

mod common;

#[path = "../fuzz/bodies/ipc_kpasswd_request.rs"]
mod request_body;

#[path = "../fuzz/bodies/ipc_kpasswd_reply.rs"]
mod reply_body;

use common::*;
use ipc::Refused;
use ipc_kpasswd::{encode_refusal, FrontZone, KpasswdReply, KpasswdRequest, UnsealedCode};

fn requests() -> Vec<Vec<u8>> {
    vec![
        request_body(&KpasswdRequest::Ping),
        request_body(&KpasswdRequest::ChangePassword(request())),
    ]
}

fn replies() -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = [
        KpasswdReply::Pong {
            zone: FrontZone::Internal,
        },
        KpasswdReply::Sealed(sealed()),
        KpasswdReply::Unsealed(UnsealedCode::HardError),
        KpasswdReply::Unsealed(UnsealedCode::AuthError),
    ]
    .iter()
    .map(reply_body)
    .collect();
    for refused in [Refused::Busy, Refused::Unavailable, Refused::Malformed] {
        out.push(encode_refusal(refused).unwrap().body().to_vec());
    }
    out
}

/// Every truncation and every single-bit flip of `input`, and `input`.
fn variants(input: &[u8]) -> Vec<Vec<u8>> {
    let mut out = vec![input.to_vec()];
    for len in 0..input.len() {
        out.push(input[..len].to_vec());
    }
    for index in 0..input.len() {
        for bit in 0..8 {
            let mut flipped = input.to_vec();
            flipped[index] ^= 1 << bit;
            out.push(flipped);
        }
    }
    out
}

fn garbage() -> Vec<Vec<u8>> {
    vec![
        Vec::new(),
        vec![0x4B],
        vec![0x4B, 0x50],
        vec![0x4B, 0x50, 0x01],
        vec![0x4B, 0x50, 0x01, 0x02, 0xFF, 0xFF, 0xFF, 0xFF],
        vec![0x4B, 0x50, 0x01, 0x82, 0x00, 0x00, 0x00, 0x00],
        vec![0x4B, 0x50, 0x01, 0xFF, 0x09],
        vec![0xFF; 64],
    ]
}

/// docs/53 §5.9; docs/CLEAN-ROOM.md: the request body holds over every variant.
#[test]
fn the_request_target_holds() {
    for input in requests().iter().flat_map(|r| variants(r)).chain(garbage()) {
        request_body::run(&input);
    }
}

/// docs/53 §5.9; docs/CLEAN-ROOM.md: the reply body holds over every variant.
#[test]
fn the_reply_target_holds() {
    for input in replies().iter().flat_map(|r| variants(r)).chain(garbage()) {
        reply_body::run(&input);
    }
}
