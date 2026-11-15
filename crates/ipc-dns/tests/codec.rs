//! Tier 1 (docs/50 §9: in-process codecs): every message of the dnsd ↔ dird
//! channel round-trips canonically (`encode(decode(b)) == b`), every bound
//! holds on both sides, and every malformed input is refused with the
//! disposition of ipc's refusal table.
//!
//! Sources: docs/50 §3.3 (framing, magic, exact version, closed kinds,
//! primitives, "no trailing octet", "round-trip … in property tests");
//! docs/54 §4.6 (the channel's messages, magic `0x444E`); A-140 /
//! docs/research/r3-c-dns.md §4.1 (`Forward { transport, peer, message }`,
//! `Forwarded { reply: Option }`); A-59 (`REFUSED_KIND`); RFC 1035 §2.3.4,
//! §3.1, §4.1.1, §4.2.1, §4.2.2 (message and name bounds); RFC 2136 §7.11
//! (SERIAL ≠ 0); RFC 2782 "Fictional example" (the apex). Every value is
//! hand-made or from those sources.

mod common;

use common::{message_octets, name, reply_body};
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use ipc::{
    decode_body, decode_reply, encode_frame, encode_refused, reply_round_trip_is_canonical,
    round_trip_is_canonical, Direction, Error, Refused, Reply, REFUSED_KIND,
};
use ipc_dns::channel::{codes, reply_kind, request_kind};
use ipc_dns::{
    decode_request, DnsMessage, DnsReply, DnsRequest, ForwardRequest, Forwarded, FrontZone,
    ImageChunk, Name, PeerAddress, Rejection, Serial, Transport, ZoneDescription, DNS_CHANNEL,
    DNS_MAGIC, DNS_VERSION, MAX_IMAGE_CHUNK, MAX_MESSAGE, MAX_REPLY_BODY, MAX_REQUEST_BODY,
    MAX_UDP_MESSAGE, MIN_MESSAGE,
};

const CHUNK: usize = MAX_IMAGE_CHUNK as usize;

fn serial(value: u32) -> Serial {
    Serial::new(value).expect("non-zero serial")
}

fn v4(a: u8, b: u8, c: u8, d: u8) -> PeerAddress {
    PeerAddress::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)))
}

fn v6() -> PeerAddress {
    PeerAddress::new(IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x53)))
}

fn forward(transport: Transport, peer: PeerAddress, len: usize) -> DnsRequest {
    let message = DnsMessage::new(&message_octets(len)).expect("message");
    DnsRequest::Forward(ForwardRequest::new(transport, peer, message).expect("fits transport"))
}

fn every_request() -> Vec<DnsRequest> {
    vec![
        DnsRequest::Ping,
        DnsRequest::DescribeZone,
        DnsRequest::FetchZoneImage { have: None },
        DnsRequest::FetchZoneImage {
            have: Some(serial(1_995_032_001)),
        },
        forward(Transport::Udp, v4(172, 30, 79, 13), 210),
        forward(Transport::Udp, v6(), MAX_UDP_MESSAGE as usize),
        forward(Transport::Tcp, v4(10, 2, 0, 27), MIN_MESSAGE),
        forward(Transport::Tcp, v6(), MAX_MESSAGE as usize),
    ]
}

fn every_reply() -> Vec<DnsReply> {
    vec![
        DnsReply::Pong {
            zone: FrontZone::Internal,
        },
        DnsReply::ZoneDescription(
            ZoneDescription::new(name("example.com"), serial(1_995_032_001)).expect("apex"),
        ),
        DnsReply::Unchanged { serial: serial(7) },
        DnsReply::ImageChunk(ImageChunk::new(&[0x01, 0x02, 0x03], false).expect("chunk")),
        DnsReply::ImageChunk(ImageChunk::new(&vec![0xAB; CHUNK], true).expect("chunk")),
        DnsReply::ImageChunk(ImageChunk::new(&vec![0xCD; CHUNK], false).expect("chunk")),
        DnsReply::Forwarded(Forwarded {
            reply: Some(DnsMessage::new(&message_octets(12)).expect("message")),
            serial: serial(u32::MAX),
        }),
        DnsReply::Forwarded(Forwarded {
            reply: Some(DnsMessage::new(&message_octets(MAX_MESSAGE as usize)).expect("message")),
            serial: serial(1),
        }),
        DnsReply::Forwarded(Forwarded {
            reply: None,
            serial: serial(2),
        }),
    ]
}

fn request_body(request: &DnsRequest) -> Vec<u8> {
    encode_frame(DNS_CHANNEL, Direction::Request, request)
        .expect("request encodes")
        .body()
        .to_vec()
}

/// A frame body built by hand: the envelope with `kind`, then `payload`.
fn raw_body(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut body = DNS_MAGIC.to_be_bytes().to_vec();
    body.push(DNS_VERSION);
    body.push(kind);
    body.extend_from_slice(payload);
    body
}

fn decode_request_body(body: &[u8]) -> Result<DnsRequest, Error> {
    decode_body::<DnsRequest>(DNS_CHANNEL, Direction::Request, body)
}

fn decode_reply_body(body: &[u8]) -> Result<Reply<DnsReply>, Error> {
    decode_reply::<DnsReply>(DNS_CHANNEL, body)
}

// ---- channel identity -------------------------------------------------------

/// docs/54 §4.6: magic `0x444E` ("DN"), version 1; docs/50 §3.3 bounds.
#[test]
fn the_channel_identity_is_the_plans() {
    assert_eq!(DNS_MAGIC, 0x444E);
    assert_eq!(&DNS_MAGIC.to_be_bytes(), b"DN");
    assert_eq!(DNS_VERSION, 1);
    assert_eq!(MAX_REQUEST_BODY, 64 * 1024 + 32);
    assert_eq!(MAX_REPLY_BODY, 1024 * 1024 + 16);
    assert_eq!(MIN_MESSAGE, 12);
    assert_eq!(MAX_UDP_MESSAGE, 512);
    assert_eq!(MAX_MESSAGE, 65_535);
    assert!(!request_kind::ALL.contains(&REFUSED_KIND));
    assert!(!reply_kind::ALL.contains(&REFUSED_KIND));
}

// ---- round trips -------------------------------------------------------------

/// docs/50 §3.3: every request round-trips canonically, on the wire and as a
/// value.
#[test]
fn every_request_round_trips() {
    for request in every_request() {
        let body = request_body(&request);
        assert_eq!(decode_request_body(&body), Ok(request.clone()));
        assert_eq!(
            round_trip_is_canonical::<DnsRequest>(DNS_CHANNEL, Direction::Request, &body),
            Ok(true)
        );
        assert_eq!(decode_request(&body), Ok(request));
    }
}

/// docs/50 §3.3: every reply round-trips canonically, the shared refusal
/// included (A-59).
#[test]
fn every_reply_round_trips() {
    for reply in every_reply() {
        let body = reply_body(&reply);
        assert_eq!(decode_reply_body(&body), Ok(Reply::Message(reply)));
        assert_eq!(
            reply_round_trip_is_canonical::<DnsReply>(DNS_CHANNEL, &body),
            Ok(true)
        );
    }
    for refused in [
        Refused::Busy,
        Refused::Unavailable,
        Refused::Malformed,
        Refused::VersionMismatch,
    ] {
        let body = encode_refused(DNS_CHANNEL, refused).expect("encodes");
        assert_eq!(decode_reply_body(body.body()), Ok(Reply::Refused(refused)));
        assert_eq!(
            reply_round_trip_is_canonical::<DnsReply>(DNS_CHANNEL, body.body()),
            Ok(true)
        );
    }
}

/// The wire layouts of docs/54 §4.6 / A-140, octet by octet (crate table).
#[test]
fn the_layouts_are_the_documented_ones() {
    assert_eq!(request_body(&DnsRequest::Ping), raw_body(0x01, &[]));
    assert_eq!(request_body(&DnsRequest::DescribeZone), raw_body(0x02, &[]));
    assert_eq!(
        request_body(&DnsRequest::FetchZoneImage { have: None }),
        raw_body(0x03, &[0x00])
    );
    assert_eq!(
        request_body(&DnsRequest::FetchZoneImage {
            have: Some(serial(0x0102_0304))
        }),
        raw_body(0x03, &[0x01, 0x01, 0x02, 0x03, 0x04])
    );
    let message = message_octets(12);
    let mut payload = vec![codes::TRANSPORT_UDP, codes::FAMILY_V4, 172, 30, 79, 13];
    payload.extend_from_slice(&12u32.to_be_bytes());
    payload.extend_from_slice(&message);
    assert_eq!(
        request_body(&forward(Transport::Udp, v4(172, 30, 79, 13), 12)),
        raw_body(0x04, &payload)
    );
    assert_eq!(
        reply_body(&DnsReply::Pong {
            zone: FrontZone::Internal
        }),
        raw_body(0x81, &[codes::ZONE_INTERNAL])
    );
    let mut forwarded = raw_body(0x85, &[0x00]);
    forwarded.extend_from_slice(&9u32.to_be_bytes());
    assert_eq!(
        reply_body(&DnsReply::Forwarded(Forwarded {
            reply: None,
            serial: serial(9)
        })),
        forwarded
    );
}

// ---- the envelope ------------------------------------------------------------

/// docs/50 §3.3: wrong magic ⇒ close; another version ⇒
/// `Refused{VersionMismatch}`; unknown kind ⇒ close; trailing ⇒ `Malformed`.
#[test]
fn the_envelope_is_strict() {
    let mut wrong_magic = request_body(&DnsRequest::Ping);
    wrong_magic[0] = 0x4C;
    assert_eq!(decode_request_body(&wrong_magic), Err(Error::WrongMagic));
    assert_eq!(decode_request(&wrong_magic), Err(Rejection::Close));

    let mut wrong_version = request_body(&DnsRequest::Ping);
    wrong_version[2] = 2;
    assert_eq!(
        decode_request_body(&wrong_version),
        Err(Error::VersionMismatch)
    );
    assert_eq!(
        decode_request(&wrong_version),
        Err(Rejection::Refuse(Refused::VersionMismatch))
    );

    for kind in [0x00, 0x05, 0x81, 0x85, REFUSED_KIND] {
        let body = raw_body(kind, &[]);
        assert_eq!(
            decode_request_body(&body),
            Err(Error::UnknownKind),
            "{kind:#x}"
        );
        assert_eq!(decode_request(&body), Err(Rejection::Close));
    }
    for kind in [0x01, 0x04, 0x80, 0x86] {
        let body = raw_body(kind, &[]);
        assert_eq!(
            decode_reply_body(&body),
            Err(Error::UnknownKind),
            "{kind:#x}"
        );
    }

    let mut trailing = request_body(&DnsRequest::DescribeZone);
    trailing.push(0);
    assert_eq!(decode_request_body(&trailing), Err(Error::TrailingBytes));
    assert_eq!(
        decode_request(&trailing),
        Err(Rejection::Refuse(Refused::Malformed))
    );

    let mut reply_trailing = reply_body(&DnsReply::Unchanged { serial: serial(1) });
    reply_trailing.push(0);
    assert_eq!(
        decode_reply_body(&reply_trailing),
        Err(Error::TrailingBytes)
    );

    assert_eq!(decode_request_body(&[0x44]), Err(Error::FrameTooShort));
}

/// docs/50 §3.3: a body over the direction's bound is refused before
/// anything else.
#[test]
fn bodies_over_the_bounds_are_refused() {
    let request = vec![0u8; MAX_REQUEST_BODY as usize + 1];
    assert_eq!(decode_request_body(&request), Err(Error::FrameTooLarge));
    let reply = vec![0u8; MAX_REPLY_BODY as usize + 1];
    assert_eq!(decode_reply_body(&reply), Err(Error::FrameTooLarge));
}

/// docs/50 §3.3: every truncation of every message is refused, never a
/// panic.
#[test]
fn every_truncation_is_refused() {
    for request in every_request() {
        let body = request_body(&request);
        for cut in 4..body.len() {
            assert!(decode_request_body(&body[..cut]).is_err(), "cut {cut}");
        }
    }
    for reply in every_reply() {
        let body = reply_body(&reply);
        for cut in 4..body.len() {
            assert!(decode_reply_body(&body[..cut]).is_err(), "cut {cut}");
        }
    }
}

// ---- Forward (A-140) ---------------------------------------------------------

/// RFC 1035 §4.1.1, §2.3.4, §4.2.1, §4.2.2: a forwarded message is 12 ..=
/// 512 octets over UDP and 12 ..= 65535 over TCP — on construction and on
/// the wire.
#[test]
fn forwarded_messages_are_bounded_by_their_transport() {
    assert!(DnsMessage::new(&message_octets(12)).is_some());
    assert!(DnsMessage::new(&[0u8; 11]).is_none());
    assert!(DnsMessage::new(&vec![0u8; MAX_MESSAGE as usize + 1]).is_none());

    let udp_full = DnsMessage::new(&message_octets(512)).expect("message");
    let udp_over = DnsMessage::new(&message_octets(513)).expect("message");
    assert!(ForwardRequest::new(Transport::Udp, v6(), udp_full).is_some());
    assert!(ForwardRequest::new(Transport::Udp, v6(), udp_over.clone()).is_none());
    assert!(ForwardRequest::new(Transport::Tcp, v6(), udp_over).is_some());

    // On the wire: transport, peer, then the message bytes.
    let wire = |transport: u8, len: u32, octets: usize| {
        let mut payload = vec![transport, codes::FAMILY_V4, 10, 1, 0, 52];
        payload.extend_from_slice(&len.to_be_bytes());
        payload.extend_from_slice(&message_octets(octets.max(12))[..octets]);
        raw_body(request_kind::FORWARD, &payload)
    };
    // Too short for a header.
    assert_eq!(
        decode_request_body(&wire(codes::TRANSPORT_TCP, 11, 11)),
        Err(Error::LengthOverBound)
    );
    assert_eq!(
        decode_request_body(&wire(codes::TRANSPORT_UDP, 0, 0)),
        Err(Error::LengthOverBound)
    );
    // A UDP-borne message over 512 octets.
    assert_eq!(
        decode_request_body(&wire(codes::TRANSPORT_UDP, 513, 513)),
        Err(Error::LengthOverBound)
    );
    assert!(decode_request_body(&wire(codes::TRANSPORT_UDP, 512, 512)).is_ok());
    // Over the TCP bound (the length alone is refused before any octet).
    assert_eq!(
        decode_request_body(&wire(codes::TRANSPORT_TCP, 65_536, 0)),
        Err(Error::LengthOverBound)
    );
    assert!(decode_request_body(&wire(codes::TRANSPORT_TCP, 513, 513)).is_ok());
    // Every malformed Forward is `Malformed` for dird.
    assert_eq!(
        decode_request(&wire(codes::TRANSPORT_UDP, 513, 513)),
        Err(Rejection::Refuse(Refused::Malformed))
    );
}

/// docs/50 §3.3 (closed tables): unknown transport and address-family
/// codes are refused.
#[test]
fn forward_codes_are_closed() {
    for transport in [0x00, 0x03, 0xFF] {
        let mut payload = vec![transport, codes::FAMILY_V4, 10, 1, 0, 52];
        payload.extend_from_slice(&12u32.to_be_bytes());
        payload.extend_from_slice(&message_octets(12));
        assert_eq!(
            decode_request_body(&raw_body(request_kind::FORWARD, &payload)),
            Err(Error::UnknownCode)
        );
    }
    for family in [0x00, 0x05, 0x01, 0x02] {
        let mut payload = vec![codes::TRANSPORT_TCP, family, 10, 1, 0, 52];
        payload.extend_from_slice(&12u32.to_be_bytes());
        payload.extend_from_slice(&message_octets(12));
        assert_eq!(
            decode_request_body(&raw_body(request_kind::FORWARD, &payload)),
            Err(Error::UnknownCode)
        );
    }
}

/// docs/50 §3.3 (one encoding per value) for the peer address dird keys its
/// context table by (A-140; r3-c §4.4): an IPv4-mapped IPv6 address is held
/// — and sent — as its IPv4 form, and its IPv6 spelling is refused.
#[test]
fn the_peer_address_has_one_spelling() {
    let mapped = IpAddr::V6(Ipv4Addr::new(172, 30, 79, 13).to_ipv6_mapped());
    let peer = PeerAddress::new(mapped);
    assert_eq!(peer.address(), IpAddr::V4(Ipv4Addr::new(172, 30, 79, 13)));
    assert_eq!(peer, v4(172, 30, 79, 13));
    assert_eq!(
        request_body(&forward(Transport::Udp, peer, 12)),
        request_body(&forward(Transport::Udp, v4(172, 30, 79, 13), 12))
    );

    let mut payload = vec![codes::TRANSPORT_UDP, codes::FAMILY_V6];
    payload.extend_from_slice(&Ipv4Addr::new(172, 30, 79, 13).to_ipv6_mapped().octets());
    payload.extend_from_slice(&12u32.to_be_bytes());
    payload.extend_from_slice(&message_octets(12));
    assert_eq!(
        decode_request_body(&raw_body(request_kind::FORWARD, &payload)),
        Err(Error::UnknownCode)
    );
    // A genuine IPv6 address is kept as it is.
    assert_eq!(
        v6().address(),
        IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x53))
    );
}

/// docs/54 §4.1 / RFC 8945 §4.3.2, §5.5: the message octets cross the
/// channel exactly as given — never re-encoded.
#[test]
fn the_forwarded_octets_are_untouched() {
    let octets = message_octets(300);
    let request = forward(Transport::Tcp, v4(10, 1, 0, 52), 300);
    let DnsRequest::Forward(decoded) = decode_request_body(&request_body(&request)).unwrap() else {
        panic!("not a forward");
    };
    assert_eq!(decoded.message().as_bytes(), &octets[..]);
    assert_eq!(decoded.transport(), Transport::Tcp);
    assert_eq!(decoded.peer(), v4(10, 1, 0, 52));
    // `Debug` shows no octet (docs/54 §9).
    let printed = format!("{decoded:?}");
    assert!(printed.contains("len: 300"), "{printed}");
    assert!(!printed.contains("165"), "{printed}");
}

// ---- SERIAL, zone, apex ------------------------------------------------------

/// RFC 2136 §7.11: a zero SERIAL has no representation — not in `have`, not
/// in any reply.
#[test]
fn a_zero_serial_is_refused_everywhere() {
    assert_eq!(Serial::new(0), None);
    assert_eq!(
        decode_request_body(&raw_body(
            request_kind::FETCH_ZONE_IMAGE,
            &[0x01, 0, 0, 0, 0]
        )),
        Err(Error::UnknownCode)
    );
    let unchanged = raw_body(reply_kind::UNCHANGED, &[0, 0, 0, 0]);
    assert_eq!(decode_reply_body(&unchanged), Err(Error::UnknownCode));

    let forwarded = raw_body(reply_kind::FORWARDED, &[0x00, 0, 0, 0, 0]);
    assert_eq!(decode_reply_body(&forwarded), Err(Error::UnknownCode));

    let mut description = raw_body(reply_kind::ZONE_DESCRIPTION, &[]);
    let apex = name("example.com");
    description.extend_from_slice(&(apex.as_wire().len() as u32).to_be_bytes());
    description.extend_from_slice(apex.as_wire());
    description.extend_from_slice(&[0, 0, 0, 0]);
    assert_eq!(decode_reply_body(&description), Err(Error::UnknownCode));
}

/// docs/50 §3.3: the option marker of `have` is `00` or `01` only.
#[test]
fn the_have_marker_is_canonical() {
    assert_eq!(
        decode_request_body(&raw_body(
            request_kind::FETCH_ZONE_IMAGE,
            &[0x02, 0, 0, 0, 1]
        )),
        Err(Error::InvalidOptionMarker)
    );
}

/// docs/54 §4.6: the `Pong` zone is a closed table (phase 1: `Internal`).
#[test]
fn the_pong_zone_is_closed() {
    for code in [0x00, 0x02, 0xFF] {
        let body = raw_body(reply_kind::PONG, &[code]);
        assert_eq!(decode_reply_body(&body), Err(Error::UnknownCode));
    }
    assert_eq!(
        FrontZone::from_code(codes::ZONE_INTERNAL),
        Some(FrontZone::Internal)
    );
    assert_eq!(FrontZone::Internal.code(), codes::ZONE_INTERNAL);
}

/// RFC 1035 §2.3.1, §3.1, §4.1.4; docs/54 §3.1: the apex is one
/// uncompressed name, not the root, every label LDH — on construction and
/// on the wire.
#[test]
fn the_apex_is_strict() {
    assert!(ZoneDescription::new(Name::root(), serial(1)).is_none());
    assert!(ZoneDescription::new(name("_tcp.example.com"), serial(1)).is_none());
    assert!(ZoneDescription::new(name("*.example.com"), serial(1)).is_none());
    assert!(ZoneDescription::new(name("example.com"), serial(1)).is_some());

    let description = |apex_field: &[u8]| {
        let mut body = raw_body(reply_kind::ZONE_DESCRIPTION, &[]);
        body.extend_from_slice(&(apex_field.len() as u32).to_be_bytes());
        body.extend_from_slice(apex_field);
        body.extend_from_slice(&1u32.to_be_bytes());
        body
    };
    // Valid.
    assert!(decode_reply_body(&description(b"\x07example\x03com\x00")).is_ok());
    // The root.
    assert_eq!(
        decode_reply_body(&description(b"\x00")),
        Err(Error::UnknownCode)
    );
    // A compression pointer (no message to point into).
    assert_eq!(
        decode_reply_body(&description(b"\x07example\xc0\x00")),
        Err(Error::UnknownCode)
    );
    // Octets after the root label.
    assert_eq!(
        decode_reply_body(&description(b"\x07example\x03com\x00\x00")),
        Err(Error::UnknownCode)
    );
    // No terminating root label.
    assert_eq!(
        decode_reply_body(&description(b"\x07example\x03com")),
        Err(Error::UnknownCode)
    );
    // A reserved label type (RFC 1035 §4.1.4: "10 and 01 combinations").
    assert_eq!(
        decode_reply_body(&description(b"\x47example\x00")),
        Err(Error::UnknownCode)
    );
    // A non-LDH label.
    assert_eq!(
        decode_reply_body(&description(b"\x04_tcp\x07example\x00")),
        Err(Error::UnknownCode)
    );
    // Over 255 octets: the field bound.
    assert_eq!(
        decode_reply_body(&description(&[0x01; 256])),
        Err(Error::LengthOverBound)
    );
}

// ---- image chunks ------------------------------------------------------------

/// docs/54 §4.6; the dird-ldap part rule: a chunk is 1 ..= 1 MiB, exactly
/// 1 MiB when `more` — on construction, encoding and decoding.
#[test]
fn image_chunks_keep_their_rule() {
    assert!(ImageChunk::new(&[], false).is_none());
    assert!(ImageChunk::new(&[], true).is_none());
    assert!(ImageChunk::new(&[1], true).is_none());
    assert!(ImageChunk::new(&vec![0; CHUNK - 1], true).is_none());
    assert!(ImageChunk::new(&vec![0; CHUNK + 1], false).is_none());
    assert!(ImageChunk::new(&vec![0; CHUNK], true).is_some());
    assert!(ImageChunk::new(&[1], false).is_some());

    let chunk_body = |len: usize, more: u8| {
        let mut body = raw_body(reply_kind::IMAGE_CHUNK, &[]);
        body.extend_from_slice(&(len as u32).to_be_bytes());
        body.extend_from_slice(&vec![0x5A; len]);
        body.push(more);
        body
    };
    assert_eq!(
        decode_reply_body(&chunk_body(0, 0)),
        Err(Error::LengthOverBound)
    );
    assert_eq!(
        decode_reply_body(&chunk_body(10, 1)),
        Err(Error::LengthOverBound)
    );
    assert_eq!(
        decode_reply_body(&chunk_body(10, 2)),
        Err(Error::InvalidBoolean)
    );
    assert!(decode_reply_body(&chunk_body(CHUNK, 1)).is_ok());
    // Over the chunk bound: refused at the length, before the octets.
    let mut over = raw_body(reply_kind::IMAGE_CHUNK, &[]);
    over.extend_from_slice(&(MAX_IMAGE_CHUNK + 1).to_be_bytes());
    assert_eq!(decode_reply_body(&over), Err(Error::LengthOverBound));
}

/// docs/54 §4.6 / A-140: the optional reply of `Forwarded` is 12 ..= 65535
/// octets when present.
#[test]
fn forwarded_replies_are_bounded() {
    let body = |marker: u8, len: Option<usize>| {
        let mut body = raw_body(reply_kind::FORWARDED, &[marker]);
        if let Some(len) = len {
            body.extend_from_slice(&(len as u32).to_be_bytes());
            body.extend_from_slice(&message_octets(len.max(12))[..len]);
        }
        body.extend_from_slice(&5u32.to_be_bytes());
        body
    };
    assert!(decode_reply_body(&body(0x00, None)).is_ok());
    assert!(decode_reply_body(&body(0x01, Some(12))).is_ok());
    assert_eq!(
        decode_reply_body(&body(0x01, Some(11))),
        Err(Error::LengthOverBound)
    );
    assert_eq!(
        decode_reply_body(&body(0x02, Some(12))),
        Err(Error::InvalidOptionMarker)
    );
    let mut over = raw_body(reply_kind::FORWARDED, &[0x01]);
    over.extend_from_slice(&65_536u32.to_be_bytes());
    assert_eq!(decode_reply_body(&over), Err(Error::LengthOverBound));
}

/// docs/50 §3.3 ("bound per direction"): the largest request and the largest
/// reply fit; the encoder never produces a body the peer would refuse.
#[test]
fn the_largest_messages_fit_their_bounds() {
    let largest_request = request_body(&forward(Transport::Tcp, v6(), MAX_MESSAGE as usize));
    assert!(largest_request.len() <= MAX_REQUEST_BODY as usize);
    let largest_reply = reply_body(&DnsReply::ImageChunk(
        ImageChunk::new(&vec![0; CHUNK], true).unwrap(),
    ));
    assert!(largest_reply.len() <= MAX_REPLY_BODY as usize);
}
