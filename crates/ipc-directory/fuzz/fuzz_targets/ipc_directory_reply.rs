#![no_main]
//! Fuzz target for the directory-view channel's client-side reply decoding:
//! the first input octet picks the request that was sent, the rest is the
//! reply body, decoded as `DirectoryClient` decodes it — `ipc::decode_reply`
//! (the shared `Refused` routed first, A-59), then the typed reader of that
//! request (`into_client`, `into_service`, `into_groups`, `into_tier`,
//! `into_domain`, `into_view_begun`), every value through its strict decoder.
//!
//! docs/CLEAN-ROOM.md / docs/50 §9 (R50-19: "the client decodes replies");
//! docs/50 §3.3 ("replies are decoded with the same strictness"): never a
//! panic; whatever decodes re-encodes to exactly the input.
//!
//! Spec: docs/50 §3.3, §3.4, §9; R50-4; A-59.

use ipc::{decode_reply, encode_frame, encode_refused, Direction, Reply};
use ipc_directory::wire::DirectoryReply;
use ipc_directory::DIRECTORY_CHANNEL;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&selector, body)) = data.split_first() else {
        return;
    };
    match decode_reply::<DirectoryReply>(DIRECTORY_CHANNEL, body) {
        Ok(Reply::Refused(refused)) => {
            let frame = encode_refused(DIRECTORY_CHANNEL, refused).expect("a refusal encodes");
            assert_eq!(frame.body(), body, "canonical refusal");
        }
        Ok(Reply::Message(reply)) => {
            let frame = encode_frame(DIRECTORY_CHANNEL, Direction::Reply, &reply)
                .expect("a decoded reply re-encodes");
            assert_eq!(frame.body(), body, "canonical round trip");
            match selector % 6 {
                0 => {
                    let _ = reply.into_client();
                }
                1 => {
                    let _ = reply.into_service();
                }
                2 => {
                    let _ = reply.into_groups();
                }
                3 => {
                    let _ = reply.into_tier();
                }
                4 => {
                    let _ = reply.into_domain();
                }
                _ => {
                    let _ = reply.into_view_begun();
                }
            }
        }
        Err(_) => {}
    }
});
