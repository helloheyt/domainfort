#![no_main]
//! Fuzz target `ipc_kpasswd_request` (docs/53 §5.9; AGENTS.md §6): dird's
//! decoding of an arbitrary request body of the kpasswd-front ↔ dird
//! channel. The checks are in `../bodies/ipc_kpasswd_request.rs`, shared
//! with the crate's `tests/fuzz_bodies.rs`. Written, not run
//! (PENDING-OWNER P-1).
//!
//! Spec: docs/53 §4.3, §5.9; docs/50 §3.3, §9.

#[path = "../bodies/ipc_kpasswd_request.rs"]
mod body;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| body::run(data));
