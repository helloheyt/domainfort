#![no_main]
//! Fuzz target `ipc_dns_reply` (docs/54 §4.6, §10.3; docs/CLEAN-ROOM.md): dnsd's
//! decoding of an arbitrary reply body of the dnsd ↔ dird channel, and of the
//! same octets as a reassembled zone-image payload. The checks are in
//! `../bodies/ipc_dns_reply.rs`, shared with the crate's
//! `tests/fuzz_bodies.rs`. Written, not run (PENDING-OWNER P-1).
//!
//! Spec: docs/54 §4.4, §4.6, §10.3; docs/50 §3.3, §9.

#[path = "../bodies/ipc_dns_reply.rs"]
mod body;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| body::run(data));
