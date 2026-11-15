#![no_main]
//! Fuzz target `ipc_dns_request` (docs/54 §4.6, §10.3; AGENTS.md §6): dird's
//! decoding of an arbitrary request body of the dnsd ↔ dird channel. The
//! checks are in `../bodies/ipc_dns_request.rs`, shared with the crate's
//! `tests/fuzz_bodies.rs`. Written, not run (PENDING-OWNER P-1).
//!
//! Spec: docs/54 §4.6, §10.3; docs/50 §3.3, §9; A-140.

#[path = "../bodies/ipc_dns_request.rs"]
mod body;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| body::run(data));
