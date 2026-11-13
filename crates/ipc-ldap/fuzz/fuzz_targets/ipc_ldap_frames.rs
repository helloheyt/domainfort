#![no_main]
//! Fuzz target for both directions of the ldap-front ↔ dird channel.
//!
//! * Selector even — dird's side: the rest is one request body, decoded by
//!   `ipc::decode_body::<LdapRequest>` (bound, magic, exact version, closed
//!   kind table, fields, no trailing octet). Whatever decodes re-encodes to
//!   exactly the input; a rejection maps to the refusal table.
//! * Selector odd — the front's side: the rest is split into reply bodies
//!   (each prefixed by a one-octet length) and fed to a `FrontChannel` that
//!   opened a session and sent a message — `ipc::decode_reply` (the shared
//!   `Refused` routed first), the session's order, the part rule, the
//!   reassembly and the per-reply bounds. Whatever decodes as a single reply
//!   re-encodes to exactly its body.
//!
//! AGENTS.md §6 / docs/50 §9 (R50-19: `ipc_ldap_frames`; the client decodes
//! replies); docs/50 §3.3 ("replies are decoded with the same strictness"):
//! never a panic, bounded allocation.
//!
//! Spec: docs/50 §3.3, §4.2, §9; R50-4; A-59.

use ipc::{decode_body, decode_reply, encode_frame, encode_refused, Direction, Reply};
use ipc_ldap::{
    FrontChannel, LdapReply, LdapRequest, Listener, TransportFacts, LDAP_CHANNEL,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    if selector % 2 == 0 {
        match decode_body::<LdapRequest>(LDAP_CHANNEL, Direction::Request, rest) {
            Ok(request) => {
                let again = encode_frame(LDAP_CHANNEL, Direction::Request, &request)
                    .expect("a decoded request re-encodes");
                assert_eq!(again.body(), rest, "canonical request round trip");
            }
            Err(error) => {
                // Either a shared refusal or a close; never anything else.
                let _ = error.refusal();
            }
        }
        return;
    }
    let mut front = FrontChannel::new();
    let peer = core::net::IpAddr::V4(core::net::Ipv4Addr::new(10, 0, 0, 1));
    if front.encode_open(Listener::Ldap, peer).is_err() {
        return;
    }
    let mut input = rest;
    let mut opened = false;
    while let Some((&len, tail)) = input.split_first() {
        let len = usize::from(len).min(tail.len());
        let (body, next) = tail.split_at(len);
        input = next;
        match decode_reply::<LdapReply>(LDAP_CHANNEL, body) {
            Ok(Reply::Message(reply)) => {
                let again = encode_frame(LDAP_CHANNEL, Direction::Reply, &reply)
                    .expect("a decoded reply re-encodes");
                assert_eq!(again.body(), body, "canonical reply round trip");
            }
            Ok(Reply::Refused(refused)) => {
                let again = encode_refused(LDAP_CHANNEL, refused).expect("a refusal encodes");
                assert_eq!(again.body(), body, "canonical refusal");
            }
            Err(_) => {}
        }
        if front.accept_reply(body).is_err() {
            return;
        }
        if !opened && front.is_ready() {
            opened = true;
            if front
                .encode_message(&[0x30, 0x00], TransportFacts::default())
                .is_err()
            {
                return;
            }
        }
    }
});
