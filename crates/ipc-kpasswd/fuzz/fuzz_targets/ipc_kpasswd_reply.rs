#![no_main]
//! Fuzz target `ipc_kpasswd_reply` (docs/53 §5.9; docs/CLEAN-ROOM.md): the
//! front's decoding of an arbitrary reply body of the kpasswd-front ↔ dird
//! channel. The checks are in `../bodies/ipc_kpasswd_reply.rs`, shared with
//! the crate's `tests/fuzz_bodies.rs`. Written, not run (PENDING-OWNER P-1).
//!
//! Spec: docs/53 §5.5–§5.7, §5.9; docs/50 §3.3, §9.

#[path = "../bodies/ipc_kpasswd_reply.rs"]
mod body;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| body::run(data));
