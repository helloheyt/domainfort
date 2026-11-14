//! Tier 1 (docs/50 §9: in-process codecs): every message of the ldap-front ↔
//! dird channel round-trips canonically (`encode(decode(b)) == b`), every
//! bound holds on both sides, and every malformed input is refused with the
//! disposition of ipc's refusal table.
//!
//! Sources: docs/50 §3.3 (framing, magic, exact version, closed kinds,
//! primitives, "no trailing octet", "round-trip … in property tests"), §4.2
//! (the channel's messages), A-59 (`REFUSED_KIND`); crates/ipc-ldap channel
//! documentation (the response-part rule). Every value is hand-made.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use ipc::{
    decode_body, decode_reply, encode_frame, encode_refused, reply_round_trip_is_canonical,
    round_trip_is_canonical, Direction, Error, Refused, Reply, REFUSED_KIND,
};
use ipc_ldap::channel::{codes, reply_kind, request_kind};
use ipc_ldap::{
    split_response, ConnectionAction, LdapReply, LdapRequest, Listener, MessageRequest,
    ReportedPeer, ResponsePart, TransportFacts, LDAP_CHANNEL, LDAP_MAGIC, LDAP_VERSION,
    MAX_CANONICAL_MESSAGE, MAX_REPLY_BODY, MAX_REQUEST_BODY, MAX_RESPONSE_MESSAGE,
    MAX_RESPONSE_PART,
};
use parse_ldap::AuthState;
use zeroize::Zeroizing;

const PART: usize = MAX_RESPONSE_PART as usize;

fn message(octets: &[u8], tls: bool, pending: bool) -> LdapRequest {
    LdapRequest::Message(MessageRequest {
        canonical: Zeroizing::new(octets.to_vec()),
        transport: TransportFacts {
            tls_established: tls,
            input_pending: pending,
        },
    })
}

fn every_request() -> Vec<LdapRequest> {
    vec![
        LdapRequest::Open {
            listener: Listener::Ldap,
            reported_peer: ReportedPeer::new(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))),
        },
        LdapRequest::Open {
            listener: Listener::Ldaps,
            reported_peer: ReportedPeer::new(IpAddr::V6(Ipv6Addr::new(
                0xfd00, 0, 0, 0, 0, 0, 0, 7,
            ))),
        },
        message(&[0x30, 0x05, 0x02, 0x01, 0x01, 0x42, 0x00], false, false),
        message(&[0x30, 0x00], true, true),
        message(&[], false, true),
        LdapRequest::TlsEstablished,
        LdapRequest::Close,
        LdapRequest::Ping,
    ]
}

fn every_reply() -> Vec<LdapReply> {
    vec![
        LdapReply::Opened {
            framing: AuthState::Unauthenticated,
        },
        LdapReply::Opened {
            framing: AuthState::Authenticated,
        },
        LdapReply::Response(ResponsePart::new(&[0x30, 0x03, 0x02, 0x01, 0x05], false).unwrap()),
        LdapReply::Response(ResponsePart::new(&vec![0xAB; PART], true).unwrap()),
        LdapReply::Response(ResponsePart::new(&vec![0xCD; PART], false).unwrap()),
        LdapReply::Done {
            action: ConnectionAction::Continue,
            framing: AuthState::Unauthenticated,
        },
        LdapReply::Done {
            action: ConnectionAction::StartTls,
            framing: AuthState::Unauthenticated,
        },
        LdapReply::Done {
            action: ConnectionAction::Close,
            framing: AuthState::Authenticated,
        },
        LdapReply::TlsAccepted {
            framing: AuthState::Unauthenticated,
        },
        LdapReply::Pong,
    ]
}

/// docs/50 §3.3 ("round-trip: every decoder checks `encode(decode(b)) ==
/// b`"): every request and reply kind decodes back to itself and re-encodes
/// to the same octets; the envelope carries the registered magic and the one
/// version.
#[test]
fn every_message_round_trips_canonically() {
    for request in every_request() {
        let frame = encode_frame(LDAP_CHANNEL, Direction::Request, &request).unwrap();
        let body = frame.body();
        assert_eq!(&body[..2], &LDAP_MAGIC.to_be_bytes());
        assert_eq!(body[2], LDAP_VERSION);
        let back: LdapRequest = decode_body(LDAP_CHANNEL, Direction::Request, body).unwrap();
        assert_eq!(back, request);
        assert!(
            round_trip_is_canonical::<LdapRequest>(LDAP_CHANNEL, Direction::Request, body).unwrap()
        );
    }
    for reply in every_reply() {
        let frame = encode_frame(LDAP_CHANNEL, Direction::Reply, &reply).unwrap();
        let back: Reply<LdapReply> = decode_reply(LDAP_CHANNEL, frame.body()).unwrap();
        assert_eq!(back, Reply::Message(reply));
        assert!(reply_round_trip_is_canonical::<LdapReply>(LDAP_CHANNEL, frame.body()).unwrap());
    }
}

/// docs/50 §3.3 (fixed-order fields, enum = `u8` from a closed table): the
/// exact octets of an `Open` (IPv4 and IPv6), a `Message`, a `Done` and a
/// `Response`, written out by hand from the field table.
#[test]
fn hand_written_octets() {
    let open = encode_frame(
        LDAP_CHANNEL,
        Direction::Request,
        &LdapRequest::Open {
            listener: Listener::Ldaps,
            reported_peer: ReportedPeer::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9))),
        },
    )
    .unwrap();
    assert_eq!(
        open.as_bytes(),
        &[0, 0, 0, 10, 0x4C, 0x44, 1, 0x01, 0x02, 0x04, 192, 0, 2, 9]
    );
    let v6 = encode_frame(
        LDAP_CHANNEL,
        Direction::Request,
        &LdapRequest::Open {
            listener: Listener::Ldap,
            reported_peer: ReportedPeer::new(IpAddr::V6(Ipv6Addr::LOCALHOST)),
        },
    )
    .unwrap();
    let mut expected = vec![0, 0, 0, 22, 0x4C, 0x44, 1, 0x01, 0x01, 0x06];
    expected.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
    assert_eq!(v6.as_bytes(), &expected[..]);
    let msg = encode_frame(
        LDAP_CHANNEL,
        Direction::Request,
        &message(&[0x30, 0x00], true, false),
    )
    .unwrap();
    assert_eq!(
        msg.as_bytes(),
        &[0, 0, 0, 12, 0x4C, 0x44, 1, 0x02, 0, 0, 0, 2, 0x30, 0x00, 0x01, 0x00]
    );
    let done = encode_frame(
        LDAP_CHANNEL,
        Direction::Reply,
        &LdapReply::Done {
            action: ConnectionAction::StartTls,
            framing: AuthState::Unauthenticated,
        },
    )
    .unwrap();
    assert_eq!(
        done.as_bytes(),
        &[0, 0, 0, 6, 0x4C, 0x44, 1, 0x83, 0x02, 0x01]
    );
    let part = encode_frame(
        LDAP_CHANNEL,
        Direction::Reply,
        &LdapReply::Response(ResponsePart::new(&[0x30, 0x00], false).unwrap()),
    )
    .unwrap();
    assert_eq!(
        part.as_bytes(),
        &[0, 0, 0, 11, 0x4C, 0x44, 1, 0x82, 0, 0, 0, 2, 0x30, 0x00, 0x00]
    );
}

/// docs/50 §3.3 ("`kind` closed"; A-59): no kind of either table is the
/// reserved `REFUSED_KIND`; the shared refusal is routed ahead of the reply
/// table and round-trips; in the request direction it is an unknown kind.
#[test]
fn the_refused_kind_is_reserved() {
    assert!(!request_kind::ALL.contains(&REFUSED_KIND));
    assert!(!reply_kind::ALL.contains(&REFUSED_KIND));
    for refused in [
        Refused::Busy,
        Refused::Unavailable,
        Refused::Malformed,
        Refused::VersionMismatch,
    ] {
        let frame = encode_refused(LDAP_CHANNEL, refused).unwrap();
        assert_eq!(
            decode_reply::<LdapReply>(LDAP_CHANNEL, frame.body()).unwrap(),
            Reply::Refused(refused)
        );
        assert_eq!(
            decode_body::<LdapRequest>(LDAP_CHANNEL, Direction::Request, frame.body()).err(),
            Some(Error::UnknownKind)
        );
    }
}

/// docs/50 §3.3 (magic mismatch ⇒ close; version ≠ current ⇒
/// `Refused{VersionMismatch}`; unknown kind ⇒ close; trailing ⇒
/// `Malformed`): each refusal of a request, and its disposition.
#[test]
fn malformed_requests_are_refused() {
    let ping = encode_frame(LDAP_CHANNEL, Direction::Request, &LdapRequest::Ping).unwrap();
    let body = ping.body().to_vec();
    let decode = |b: &[u8]| decode_body::<LdapRequest>(LDAP_CHANNEL, Direction::Request, b);

    let mut wrong_magic = body.clone();
    wrong_magic[0] = 0x44;
    assert_eq!(decode(&wrong_magic).err(), Some(Error::WrongMagic));
    assert_eq!(Error::WrongMagic.refusal(), None);

    let mut wrong_version = body.clone();
    wrong_version[2] = 2;
    assert_eq!(decode(&wrong_version).err(), Some(Error::VersionMismatch));
    assert_eq!(
        Error::VersionMismatch.refusal(),
        Some(Refused::VersionMismatch)
    );

    let mut unknown = body.clone();
    unknown[3] = 0x06;
    assert_eq!(decode(&unknown).err(), Some(Error::UnknownKind));

    let mut trailing = body.clone();
    trailing.push(0);
    assert_eq!(decode(&trailing).err(), Some(Error::TrailingBytes));
    assert_eq!(Error::TrailingBytes.refusal(), Some(Refused::Malformed));

    // Open: an unknown listener code, an unknown address family, a short
    // address.
    let open = |listener: u8, family: u8, octets: &[u8]| {
        let mut b = vec![0x4C, 0x44, 1, request_kind::OPEN, listener, family];
        b.extend_from_slice(octets);
        b
    };
    assert!(decode(&open(0x01, codes::FAMILY_V4, &[10, 0, 0, 1])).is_ok());
    assert_eq!(
        decode(&open(0x03, codes::FAMILY_V4, &[10, 0, 0, 1])).err(),
        Some(Error::UnknownCode)
    );
    assert_eq!(
        decode(&open(0x01, 0x05, &[10, 0, 0, 1])).err(),
        Some(Error::UnknownCode)
    );
    assert_eq!(
        decode(&open(0x01, codes::FAMILY_V6, &[10, 0, 0, 1])).err(),
        Some(Error::Truncated)
    );

    // Message: a boolean other than 00 / 01.
    let mut bad_bool = vec![0x4C, 0x44, 1, request_kind::MESSAGE, 0, 0, 0, 0];
    bad_bool.extend_from_slice(&[0x02, 0x00]);
    assert_eq!(decode(&bad_bool).err(), Some(Error::InvalidBoolean));
}

/// docs/50 §3.3 ("`length` checked against the MAX of (channel, direction)
/// before any body byte is allocated"); docs/49 §2.4: the canonical message
/// is bounded by parse-ldap's post-authentication bound on both sides, and
/// the body bounds of both directions are the documented numbers.
#[test]
fn the_canonical_message_bound_holds_both_ways() {
    assert_eq!(
        MAX_CANONICAL_MESSAGE as usize,
        parse_ldap::MAX_AUTH_MESSAGE_OCTETS
    );
    assert_eq!(MAX_REQUEST_BODY, MAX_CANONICAL_MESSAGE + 16);
    assert_eq!(MAX_REPLY_BODY, MAX_RESPONSE_PART + 16);
    let largest = message(&vec![0x30; MAX_CANONICAL_MESSAGE as usize], true, true);
    let frame = encode_frame(LDAP_CHANNEL, Direction::Request, &largest).unwrap();
    assert!(frame.body().len() <= MAX_REQUEST_BODY as usize);
    let back: LdapRequest = decode_body(LDAP_CHANNEL, Direction::Request, frame.body()).unwrap();
    assert_eq!(back, largest);

    let over = message(
        &vec![0x30; MAX_CANONICAL_MESSAGE as usize + 1],
        false,
        false,
    );
    assert!(encode_frame(LDAP_CHANNEL, Direction::Request, &over).is_err());
    // A hand-built body announcing one octet more than the bound.
    let mut body = vec![0x4C, 0x44, 1, request_kind::MESSAGE];
    body.extend_from_slice(&(MAX_CANONICAL_MESSAGE + 1).to_be_bytes());
    body.resize(body.len() + MAX_CANONICAL_MESSAGE as usize + 1, 0x30);
    body.extend_from_slice(&[0, 0]);
    assert!(decode_body::<LdapRequest>(LDAP_CHANNEL, Direction::Request, &body).is_err());
}

/// crates/ipc-ldap channel documentation (the response-part rule: 1 ..=
/// `MAX_RESPONSE_PART` octets, exactly that many when more follow): parts
/// that break it are refused by the constructor, the encoder and the
/// decoder alike.
#[test]
fn the_response_part_rule() {
    assert!(ResponsePart::new(&[], false).is_none());
    assert!(ResponsePart::new(&[], true).is_none());
    assert!(ResponsePart::new(&[1, 2, 3], true).is_none());
    assert!(ResponsePart::new(&vec![0; PART + 1], false).is_none());
    assert!(ResponsePart::new(&vec![0; PART], true).is_some());

    let decode = |b: &[u8]| decode_reply::<LdapReply>(LDAP_CHANNEL, b);
    let part_body = |octets: &[u8], more: u8| {
        let mut b = vec![0x4C, 0x44, 1, reply_kind::RESPONSE];
        b.extend_from_slice(&u32::try_from(octets.len()).unwrap().to_be_bytes());
        b.extend_from_slice(octets);
        b.push(more);
        b
    };
    assert!(decode(&part_body(&[0x30, 0x00], 0)).is_ok());
    assert_eq!(
        decode(&part_body(&[], 0)).err(),
        Some(Error::LengthOverBound)
    );
    assert_eq!(
        decode(&part_body(&[0x30, 0x00], 1)).err(),
        Some(Error::LengthOverBound)
    );
    assert!(decode(&part_body(&vec![7; PART], 1)).is_ok());
    // One octet over the part bound.
    assert!(decode(&part_body(&vec![7; PART + 1], 0)).is_err());
}

/// crates/ipc-ldap channel documentation: a response has exactly one
/// division into parts — full parts, then the rest; an empty response and
/// one over `MAX_RESPONSE_MESSAGE` have none; the parts concatenate back.
#[test]
fn split_response_is_the_one_division() {
    assert!(split_response(&[]).is_none());
    assert!(split_response(&vec![1; MAX_RESPONSE_MESSAGE + 1]).is_none());
    for len in [1, PART - 1, PART, PART + 1, 3 * PART, MAX_RESPONSE_MESSAGE] {
        let response: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let parts = split_response(&response).unwrap();
        assert_eq!(parts.len(), len.div_ceil(PART));
        let (last, rest) = parts.split_last().unwrap();
        assert!(!last.more());
        assert!(rest.iter().all(|p| p.more() && p.octets().len() == PART));
        let joined: Vec<u8> = parts.iter().flat_map(|p| p.octets().to_vec()).collect();
        assert_eq!(joined, response);
    }
    assert_eq!(MAX_RESPONSE_MESSAGE.div_ceil(PART), 8);
}

/// docs/50 §3.3 ("enum = `u8` from a closed table"): every code table is a
/// bijection on its values and refuses everything else.
#[test]
fn code_tables_are_closed() {
    for listener in [Listener::Ldap, Listener::Ldaps] {
        assert_eq!(
            codes::listener_from(codes::listener(listener)),
            Some(listener)
        );
    }
    for action in [
        ConnectionAction::Continue,
        ConnectionAction::StartTls,
        ConnectionAction::Close,
    ] {
        assert_eq!(codes::action_from(codes::action(action)), Some(action));
    }
    for state in [AuthState::Unauthenticated, AuthState::Authenticated] {
        assert_eq!(codes::framing_from(codes::framing(state)), Some(state));
    }
    for code in [0x00, 0x04, 0x7F, 0xFF] {
        assert_eq!(codes::listener_from(code), None);
        assert_eq!(codes::action_from(code), None);
        assert_eq!(codes::framing_from(code), None);
    }
}

/// docs/50 §8.2 ("no `Debug` output prints payload octets"): the debug form
/// of a message shows the length, never the octets.
#[test]
fn debug_output_carries_no_octets() {
    let request = message(&[0x30, 0x03, 0x04, 0x01, 0x5A], false, false);
    let text = format!("{request:?}");
    assert!(text.contains("canonical_len: 5"));
    assert!(!text.contains("90")); // 0x5A
    let part = ResponsePart::new(&[0x5A; 3], false).unwrap();
    let text = format!("{part:?}");
    assert!(text.contains("len: 3"));
    assert!(!text.contains("90"));
}
