#![no_main]
//! Fuzz target for the admin channel's client-side reply decoding:
//! `ipc::decode_reply` (bound, magic, exact version, the shared `Refused`
//! ahead of the closed reply table, fields, no trailing octet), then
//! `Reply::from_wire` (GUIDs, SIDs through dtyp, realms / salts / binding
//! names through krb-proto) — what admind's `AdminClient` does with every
//! reply (docs/50 §3.3: "replies are decoded with the same strictness").
//!
//! Arbitrary bytes → decoder; never a panic, bounded allocation; whatever
//! decodes re-encodes to exactly the input.
//!
//! Task A10 added the replies `KeyRequest`, `Approved`, `PendingDestruction`
//! (closed tables for their operation, key reference and account kind).
//!
//! Spec: docs/51 §6, §7.3, §7.5; docs/50 §3.3, §9; A-59; docs/questions/
//! Q-422.

use ipc::{decode_reply, encode_reply, Reply as IpcReply};
use ipc_dird_admin::{AdminReply, Reply, ADMIN_CHANNEL};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(reply) = decode_reply::<AdminReply>(ADMIN_CHANNEL, data) {
        let again = encode_reply(ADMIN_CHANNEL, &reply).expect("a decoded reply re-encodes");
        assert_eq!(again.body(), data, "canonical wire round trip");
        if let IpcReply::Message(wire) = reply {
            if let Ok(typed) = Reply::from_wire(&wire) {
                let back = typed.to_wire().expect("a typed reply re-encodes");
                assert_eq!(back, wire, "canonical typed round trip");
            }
        }
    }
});
