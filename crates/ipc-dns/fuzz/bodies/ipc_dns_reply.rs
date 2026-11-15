//! The body of the `ipc_dns_reply` fuzz target — dnsd's side: an arbitrary
//! reply body through `ipc::decode_reply` (bound, magic, exact version, the
//! shared `Refused` ahead of the closed reply table, fields, field domains,
//! no trailing octet), an image chunk through `ImageAssembly`, and the same
//! octets as a reassembled zone-image payload through `decode_image` and
//! `ZoneImage::new` — what dnsd's `DnsClient` does with dird's octets
//! (docs/50 §3.3: "replies are decoded with the same strictness").
//!
//! Properties (docs/CLEAN-ROOM.md; docs/50 §3.3, §9; docs/54 §4.4, §4.6, §10.3):
//! never a panic, bounded allocation (an image ≤ 8 MiB); whatever decodes
//! re-encodes to exactly the input, the frame and the image payload alike.
//!
//! Shared by the fuzz target (`fuzz/fuzz_targets/ipc_dns_reply.rs`) and by
//! `tests/fuzz_bodies.rs` (see the request body's note).

use ipc::{decode_reply, encode_reply, Reply};
use ipc_dns::{decode_image, encode_image, DnsReply, ImageAssembly, ZoneImage, DNS_CHANNEL};

/// Run the target's checks over `data`.
pub fn run(data: &[u8]) {
    if let Ok(reply) = decode_reply::<DnsReply>(DNS_CHANNEL, data) {
        let again = encode_reply(DNS_CHANNEL, &reply).expect("a decoded reply re-encodes");
        assert_eq!(again.body(), data, "canonical wire round trip");
        if let Reply::Message(DnsReply::ImageChunk(chunk)) = &reply {
            // A lone chunk: more follow, or a whole (tiny) image to validate.
            let _ = ImageAssembly::new().push(chunk);
        }
    }
    // The same octets as the reassembled image payload.
    if let Ok(parts) = decode_image(data) {
        let again = encode_image(&parts).expect("a decoded image re-encodes");
        assert_eq!(&again[..], data, "canonical image round trip");
        let _ = ZoneImage::new(parts);
    }
}
