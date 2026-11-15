//! The body of the `ipc_dns_request` fuzz target — dird's side: an arbitrary
//! request body through `ipc::decode_body` (bound, magic, exact version,
//! closed kind table, fields, field domains, no trailing octet) and through
//! `ipc_dns::decode_request`, the entry point dird's dispatcher
//! (ipc-dns-server) takes.
//!
//! Properties (docs/CLEAN-ROOM.md; docs/50 §3.3, §9; docs/54 §4.6, §10.3):
//! arbitrary bytes → decoder, never a panic, bounded allocation; whatever
//! decodes re-encodes to exactly the input ("a single encoding per value");
//! a decoded `Forward` keeps its transport's bound (12 ..= 512 octets over
//! UDP, 12 ..= 65535 over TCP — RFC 1035 §2.3.4, §4.1.1, §4.2) and a
//! canonical peer address (A-140); a rejection maps to the refusal table
//! (a shared `Refused`, or a close without a reply), the same from both
//! entry points.
//!
//! Shared by the fuzz target (`fuzz/fuzz_targets/ipc_dns_request.rs`) and
//! by `tests/fuzz_bodies.rs`, which runs it over hand-made inputs so the
//! body compiles and holds in every `cargo test` (the fuzz workspace itself
//! is built only after PENDING-OWNER P-1).

use ipc::{decode_body, encode_frame, Direction};
use ipc_dns::{decode_request, DnsRequest, Rejection, DNS_CHANNEL, MIN_MESSAGE};

/// Run the target's checks over `data`.
pub fn run(data: &[u8]) {
    let decoded = decode_body::<DnsRequest>(DNS_CHANNEL, Direction::Request, data);
    match &decoded {
        Ok(request) => {
            let again = encode_frame(DNS_CHANNEL, Direction::Request, request)
                .expect("a decoded request re-encodes");
            assert_eq!(again.body(), data, "canonical wire round trip");
            if let DnsRequest::Forward(forward) = request {
                let len = forward.message().len();
                assert!(len >= MIN_MESSAGE);
                assert!(len <= forward.transport().max_message_octets());
                let address = forward.peer().address();
                assert_eq!(address, address.to_canonical());
            }
        }
        Err(error) => {
            // Either a shared refusal or a close; never anything else.
            let _ = error.refusal();
        }
    }
    // dird's entry point over the same octets agrees.
    match (decode_request(data), decoded) {
        (Ok(a), Ok(b)) => assert_eq!(a, b),
        (Err(Rejection::Close), Err(error)) => assert_eq!(error.refusal(), None),
        (Err(Rejection::Refuse(refused)), Err(error)) => {
            assert_eq!(error.refusal(), Some(refused));
        }
        _ => panic!("the two entry points disagree"),
    }
}
