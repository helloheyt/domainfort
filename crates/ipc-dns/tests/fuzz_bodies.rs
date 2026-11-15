//! The two fuzz targets' bodies (`fuzz/bodies/`), compiled and run by
//! `cargo test` over hand-made inputs: every message of the channel, every
//! truncation of it, every single-bit flip of it, an image payload and its
//! flips, and assorted garbage — so the targets build and their properties
//! hold before the fuzz workspace itself is built (PENDING-OWNER P-1).
//!
//! Sources: docs/54 §4.6, §10.3 (`ipc_dns_request`, `ipc_dns_reply`);
//! docs/50 §3.3, §9; AGENTS.md §6; A-152 / docs/questions/Q-922 (the
//! retired kinds `0x02` / `0x82` are among the garbage inputs). Inputs are
//! encoded by this crate from hand-made values and the RFC 2782 "Fictional
//! example" zone.

mod common;

#[path = "../fuzz/bodies/ipc_dns_request.rs"]
mod request_body;

#[path = "../fuzz/bodies/ipc_dns_reply.rs"]
mod reply_body;

use common::{message_octets, rfc2782_parts};
use core::net::{IpAddr, Ipv4Addr};
use ipc::{encode_frame, Direction, Refused};
use ipc_dns::{
    encode_image, encode_refusal, encode_reply, DnsMessage, DnsReply, DnsRequest, ForwardRequest,
    Forwarded, FrontZone, ImageChunk, PeerAddress, Serial, Transport, DNS_CHANNEL,
};

fn serial(value: u32) -> Serial {
    Serial::new(value).expect("non-zero")
}

fn requests() -> Vec<Vec<u8>> {
    let forward = |transport, len| {
        DnsRequest::Forward(
            ForwardRequest::new(
                transport,
                PeerAddress::new(IpAddr::V4(Ipv4Addr::new(10, 1, 0, 52))),
                DnsMessage::new(&message_octets(len)).unwrap(),
            )
            .unwrap(),
        )
    };
    [
        DnsRequest::Ping,
        DnsRequest::FetchZoneImage { have: None },
        DnsRequest::FetchZoneImage {
            have: Some(serial(3)),
        },
        forward(Transport::Udp, 40),
        forward(Transport::Tcp, 64),
    ]
    .iter()
    .map(|request| {
        encode_frame(DNS_CHANNEL, Direction::Request, request)
            .unwrap()
            .body()
            .to_vec()
    })
    .collect()
}

fn replies() -> Vec<Vec<u8>> {
    let mut bodies: Vec<Vec<u8>> = [
        DnsReply::Pong {
            zone: FrontZone::Internal,
        },
        DnsReply::Unchanged { serial: serial(9) },
        DnsReply::ImageChunk(
            ImageChunk::new(&encode_image(&rfc2782_parts()).unwrap(), false).unwrap(),
        ),
        DnsReply::Forwarded(Forwarded {
            reply: Some(DnsMessage::new(&message_octets(20)).unwrap()),
            serial: serial(10),
        }),
        DnsReply::Forwarded(Forwarded {
            reply: None,
            serial: serial(10),
        }),
    ]
    .iter()
    .map(|reply| encode_reply(reply).unwrap().body().to_vec())
    .collect();
    bodies.push(encode_refusal(Refused::Busy).unwrap().body().to_vec());
    bodies
}

/// Every truncation and every single-bit flip of `input`, and `input`.
fn mutations(input: &[u8]) -> Vec<Vec<u8>> {
    let mut out = vec![input.to_vec()];
    for cut in 0..input.len() {
        out.push(input[..cut].to_vec());
    }
    for at in 0..input.len() {
        for bit in 0..8 {
            let mut flipped = input.to_vec();
            flipped[at] ^= 1 << bit;
            out.push(flipped);
        }
    }
    out
}

fn garbage() -> Vec<Vec<u8>> {
    vec![
        vec![],
        vec![0x44, 0x4E, 0x01],
        vec![0x44, 0x4E, 0x01, 0x04, 0xFF, 0xFF, 0xFF, 0xFF],
        vec![0x44, 0x4E, 0x01, 0x84, 0xFF, 0xFF, 0xFF, 0xFF, 0x00],
        // The retired `DescribeZone` and `ZoneDescription` (A-152): the
        // former layouts — no payload; an apex and a SERIAL.
        vec![0x44, 0x4E, 0x01, 0x02],
        [
            &[0x44, 0x4E, 0x01, 0x82, 0, 0, 0, 13][..],
            &b"\x07example\x03com\x00"[..],
            &[0, 0, 0, 9][..],
        ]
        .concat(),
        vec![0xFF; 64],
        vec![0x00; 64],
    ]
}

/// docs/54 §10.3 `ipc_dns_request`: the body holds over every input here.
#[test]
fn the_request_target_holds_over_hand_made_inputs() {
    for input in requests().iter().chain(replies().iter()) {
        for mutated in mutations(input) {
            request_body::run(&mutated);
        }
    }
    for input in garbage() {
        request_body::run(&input);
    }
}

/// docs/54 §10.3 `ipc_dns_reply`: the body holds over every input here,
/// the image payload and its mutations included.
#[test]
fn the_reply_target_holds_over_hand_made_inputs() {
    let image = encode_image(&rfc2782_parts()).unwrap();
    for input in replies()
        .iter()
        .chain(requests().iter())
        .chain(core::iter::once(&image))
    {
        for mutated in mutations(input) {
            reply_body::run(&mutated);
        }
    }
    for input in garbage() {
        reply_body::run(&input);
    }
}
