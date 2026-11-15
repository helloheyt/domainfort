//! dnsd's client over scripted in-process connections: the peer is verified
//! on every connection before anything else is sent (dird's uid, then a
//! `Pong` naming the expected zone), a held connection is checked before
//! reuse, a request is never resent, replies are decoded strictly and must
//! answer the request, and a zone image is returned only whole and valid.
//!
//! Sources: docs/54 §4.4 (refresh by SERIAL; atomic replacement), §4.6
//! (`Ping` → `Pong { zone }`, "no client without an expectation (C12)"; one
//! request in flight; `Busy` ⇒ SERVFAIL), §6.6; A-140 (`Forward` with
//! transport and peer; `Forwarded.reply: Option`); docs/50 R50-3 (the client
//! verifies the server's uid), §3.3 (replies decoded with the same
//! strictness), §3.6, §3.7; docs/questions/Q-312 (idle check, no resend);
//! RFC 2782 "Fictional example" (the zone); A-152 / docs/questions/Q-922
//! (`DescribeZone` retired: the calls that probe the connection here are the
//! periodic SERIAL check, `FetchZoneImage { have: Some(s) }` → `Unchanged`).
//! Every value is hand-made or from those sources.

mod common;

use common::{
    large_parts, message_octets, refusal_body, reply_body, rfc2782_parts, Script,
    ScriptedConnector, DIRD_UID, RFC2782_SERIAL,
};
use core::net::{IpAddr, Ipv4Addr};
use ipc::{Direction, Error, Refused};
use ipc_dns::channel::request_kind;
use ipc_dns::{
    encode_image, split_image, ClientConfigError, DnsClient, DnsMessage, DnsReply, DnsRequest,
    ExpectedDird, ForwardRequest, Forwarded, FrontZone, ImageChunk, ImageError, ImageFetch,
    ImageTransfer, PeerAddress, Serial, Transport, TransportError, Unserved, ZoneImage,
    ZoneImageError, DEFAULT_DEADLINE, DNS_CHANNEL, MAX_IMAGE_CHUNK,
};
use std::time::Duration;

fn serial(value: u32) -> Serial {
    Serial::new(value).expect("non-zero")
}

fn pong() -> Vec<u8> {
    reply_body(&DnsReply::Pong {
        zone: FrontZone::Internal,
    })
}

/// The SERIAL of the image dnsd answers from in these tests (RFC 2782
/// "Fictional example").
fn current() -> Serial {
    serial(RFC2782_SERIAL)
}

/// dird's confirmation that [`current`] is current (docs/54 §4.4, §4.6).
fn unchanged() -> Vec<u8> {
    reply_body(&DnsReply::Unchanged { serial: current() })
}

fn expected() -> ExpectedDird {
    ExpectedDird::new(DIRD_UID, FrontZone::Internal).expect("non-root")
}

fn new_client(scripts: Vec<Script>) -> DnsClient<ScriptedConnector> {
    DnsClient::new(
        ScriptedConnector::new(scripts),
        expected(),
        DEFAULT_DEADLINE,
    )
}

fn sent_kinds(client: &DnsClient<ScriptedConnector>) -> Vec<u8> {
    client.connector().log.borrow().kinds()
}

fn forward_request() -> ForwardRequest {
    ForwardRequest::new(
        Transport::Udp,
        PeerAddress::new(IpAddr::V4(Ipv4Addr::new(172, 30, 79, 13))),
        DnsMessage::new(&message_octets(210)).expect("message"),
    )
    .expect("fits UDP")
}

fn chunk_bodies(chunks: &[ImageChunk]) -> Vec<Vec<u8>> {
    chunks
        .iter()
        .map(|chunk| reply_body(&DnsReply::ImageChunk(chunk.clone())))
        .collect()
}

// ---- the expectation ---------------------------------------------------------

/// docs/50 §3.2 ("uid 0 is never mapped"): no client expects a root dird.
#[test]
fn no_client_expects_a_root_dird() {
    assert_eq!(
        ExpectedDird::new(0, FrontZone::Internal),
        Err(ClientConfigError::RootServerUid)
    );
    let expected = expected();
    assert_eq!(expected.uid(), DIRD_UID);
    assert_eq!(expected.zone(), FrontZone::Internal);
}

/// docs/50 R50-3: another uid at the socket receives nothing at all.
#[test]
fn another_peer_uid_receives_nothing() {
    let mut script = Script::dird(vec![pong()]);
    script.uid = Ok(DIRD_UID + 1);
    let mut client = new_client(vec![script]);
    assert_eq!(
        client.fetch_zone_image(Some(current())),
        Err(Unserved::PeerMismatch)
    );
    assert!(sent_kinds(&client).is_empty());
    assert!(!client.is_connected());
}

/// docs/50 R50-3 (fail closed): unreadable peer credentials send nothing.
#[test]
fn unreadable_peer_credentials_send_nothing() {
    let mut script = Script::dird(vec![pong()]);
    script.uid = Err(TransportError::PeerCredentials);
    let mut client = new_client(vec![script]);
    assert_eq!(
        client.ping(),
        Err(Unserved::Transport(TransportError::PeerCredentials))
    );
    assert!(sent_kinds(&client).is_empty());
}

/// docs/54 §4.6: the first frame on every new connection is `Ping`, and the
/// request goes only after a `Pong` naming the expected zone.
#[test]
fn every_connection_is_verified_before_the_request() {
    let mut client = new_client(vec![Script::dird(vec![pong(), unchanged()])]);
    assert_eq!(
        client.fetch_zone_image(Some(current())),
        Ok(ImageFetch::Unchanged(current()))
    );
    assert_eq!(
        sent_kinds(&client),
        vec![request_kind::PING, request_kind::FETCH_ZONE_IMAGE]
    );
    assert!(client.is_connected());
}

/// docs/54 §4.6: a `Pong` whose zone is not in the closed table, a reply
/// that is not a `Pong`, or a refusal of the probe — the connection is
/// dropped and only the `Ping` was sent.
#[test]
fn a_failed_probe_sends_only_the_ping() {
    let mut bad_zone = pong();
    *bad_zone.last_mut().unwrap() = 0x02;
    for (reply, outcome) in [
        (bad_zone, Unserved::MalformedReply(Error::UnknownCode)),
        (
            reply_body(&DnsReply::Unchanged { serial: serial(1) }),
            Unserved::UnexpectedReply,
        ),
        (
            refusal_body(Refused::Busy),
            Unserved::Refused(Refused::Busy),
        ),
        (
            refusal_body(Refused::VersionMismatch),
            Unserved::Refused(Refused::VersionMismatch),
        ),
    ] {
        let mut client = new_client(vec![Script::dird(vec![reply, unchanged()])]);
        assert_eq!(client.fetch_zone_image(Some(current())), Err(outcome));
        assert_eq!(sent_kinds(&client), vec![request_kind::PING]);
        assert!(!client.is_connected());
    }
}

/// docs/50 §3.6 / Q-312: a held connection that is still usable is reused
/// without a second probe; one that is not is dropped, and the new one is
/// verified before the request.
#[test]
fn a_held_connection_is_checked_before_reuse() {
    let mut client = new_client(vec![Script::dird(vec![pong(), unchanged(), unchanged()])]);
    client.fetch_zone_image(Some(current())).expect("first");
    client
        .fetch_zone_image(Some(current()))
        .expect("second, same connection");
    assert_eq!(
        sent_kinds(&client),
        vec![
            request_kind::PING,
            request_kind::FETCH_ZONE_IMAGE,
            request_kind::FETCH_ZONE_IMAGE
        ]
    );
    assert_eq!(client.connector().log.borrow().connects, 1);

    let mut stale = Script::dird(vec![pong(), unchanged()]);
    stale.idle = Err(TransportError::Closed);
    let mut client = new_client(vec![stale, Script::dird(vec![pong(), unchanged()])]);
    client.fetch_zone_image(Some(current())).expect("first");
    client
        .fetch_zone_image(Some(current()))
        .expect("second, new connection");
    let log = client.connector().log.borrow();
    assert_eq!(log.connects, 2);
    let per_connection: Vec<(usize, u8)> = log
        .sent
        .iter()
        .map(|(number, body)| (*number, body[3]))
        .collect();
    assert_eq!(
        per_connection,
        vec![
            (1, request_kind::PING),
            (1, request_kind::FETCH_ZONE_IMAGE),
            (2, request_kind::PING),
            (2, request_kind::FETCH_ZONE_IMAGE)
        ]
    );
}

/// docs/50 §3.7 / Q-312: a request is never sent twice — after a failure
/// past the write, the call fails and the next call starts over.
#[test]
fn a_request_is_never_resent() {
    let mut first = Script::dird(vec![pong()]);
    first.replies.push_back(Err(TransportError::Closed));
    let mut client = new_client(vec![
        first,
        Script::dird(vec![
            pong(),
            reply_body(&DnsReply::Forwarded(Forwarded {
                reply: None,
                serial: serial(3),
            })),
        ]),
    ]);
    assert_eq!(
        client.forward(&forward_request()),
        Err(Unserved::Transport(TransportError::Closed))
    );
    assert!(!client.is_connected());
    // One forward on the first connection, none resent there.
    assert_eq!(
        sent_kinds(&client),
        vec![request_kind::PING, request_kind::FORWARD]
    );
    client.forward(&forward_request()).expect("next call");
    assert_eq!(client.connector().log.borrow().connects, 2);
}

/// docs/50 §3.6: an expired deadline sends nothing.
#[test]
fn an_expired_deadline_sends_nothing() {
    let mut client = DnsClient::new(
        ScriptedConnector::new(vec![Script::dird(vec![pong()])]),
        expected(),
        Duration::ZERO,
    );
    assert_eq!(
        client.ping(),
        Err(Unserved::Transport(TransportError::DeadlineExceeded))
    );
    assert!(sent_kinds(&client).is_empty());
}

// ---- replies -----------------------------------------------------------------

/// docs/54 §4.6; A-59: the shared refusal is reported and the connection
/// dropped (dnsd answers SERVFAIL — docs/54 §6.6).
#[test]
fn a_refusal_drops_the_connection() {
    let mut client = new_client(vec![Script::dird(vec![
        pong(),
        refusal_body(Refused::Busy),
    ])]);
    assert_eq!(
        client.forward(&forward_request()),
        Err(Unserved::Refused(Refused::Busy))
    );
    assert!(!client.is_connected());
}

/// docs/50 §3.3: a reply that does not decode, or does not answer the
/// request, is refused — a frame of the retired `ZoneDescription` kind
/// (`0x82`, A-152 / Q-922) included: it is an unknown kind.
#[test]
fn replies_must_decode_and_answer_the_request() {
    let mut wrong_magic = unchanged();
    wrong_magic[0] = 0x4C;
    let mut client = new_client(vec![Script::dird(vec![pong(), wrong_magic])]);
    assert_eq!(
        client.fetch_zone_image(Some(current())),
        Err(Unserved::MalformedReply(Error::WrongMagic))
    );

    let mut retired = unchanged();
    retired[3] = 0x82;
    let mut client = new_client(vec![Script::dird(vec![pong(), retired])]);
    assert_eq!(
        client.fetch_zone_image(Some(current())),
        Err(Unserved::MalformedReply(Error::UnknownKind))
    );
    assert!(!client.is_connected());

    let mut client = new_client(vec![Script::dird(vec![pong(), pong()])]);
    assert_eq!(
        client.forward(&forward_request()),
        Err(Unserved::UnexpectedReply)
    );
    let mut client = new_client(vec![Script::dird(vec![
        pong(),
        reply_body(&DnsReply::Forwarded(Forwarded {
            reply: None,
            serial: current(),
        })),
    ])]);
    assert_eq!(
        client.fetch_zone_image(Some(current())),
        Err(Unserved::UnexpectedReply)
    );
}

/// A-140: the forward carries the transport, the peer and the exact
/// message; dird's answer — a reply or none — comes back as is.
#[test]
fn a_forward_carries_transport_peer_and_message() {
    let answered = Forwarded {
        reply: Some(DnsMessage::new(&message_octets(210)).expect("message")),
        serial: serial(1_995_032_002),
    };
    let mut client = new_client(vec![Script::dird(vec![
        pong(),
        reply_body(&DnsReply::Forwarded(answered.clone())),
        reply_body(&DnsReply::Forwarded(Forwarded {
            reply: None,
            serial: serial(1_995_032_002),
        })),
    ])]);
    assert_eq!(client.forward(&forward_request()), Ok(answered));
    let silent = client.forward(&forward_request()).expect("silence");
    assert_eq!(silent.reply, None);

    let log = client.connector().log.borrow();
    let body = &log.sent[1].1;
    let request: DnsRequest = ipc::decode_body(DNS_CHANNEL, Direction::Request, body).unwrap();
    assert_eq!(request, DnsRequest::Forward(forward_request()));
}

// ---- the zone image ----------------------------------------------------------

/// docs/54 §4.4: a current SERIAL is confirmed with `Unchanged`.
#[test]
fn a_current_serial_is_confirmed() {
    let mut client = new_client(vec![Script::dird(vec![
        pong(),
        reply_body(&DnsReply::Unchanged {
            serial: serial(1_995_032_001),
        }),
    ])]);
    assert_eq!(
        client.fetch_zone_image(Some(serial(1_995_032_001))),
        Ok(ImageFetch::Unchanged(serial(1_995_032_001)))
    );
}

/// docs/54 §4.6: `Unchanged` must confirm the SERIAL dnsd has; with no
/// image, or another SERIAL, it answers nothing.
#[test]
fn unchanged_must_confirm_what_dnsd_has() {
    for have in [None, Some(serial(5))] {
        let mut client = new_client(vec![Script::dird(vec![
            pong(),
            reply_body(&DnsReply::Unchanged { serial: serial(6) }),
        ])]);
        assert_eq!(
            client.fetch_zone_image(have),
            Err(Unserved::UnexpectedReply)
        );
        assert!(!client.is_connected());
    }
}

/// docs/54 §4.4, §4.6: a new image arrives in chunks and is returned whole
/// and validated — equal to the zone dird sent.
#[test]
fn a_new_image_arrives_whole_and_valid() {
    let parts = large_parts(12_000);
    let transfer = ImageTransfer::new(&parts).expect("valid");
    assert!(transfer.chunks().len() >= 2, "{}", transfer.chunks().len());
    let mut replies = vec![pong()];
    replies.extend(chunk_bodies(transfer.chunks()));
    let mut client = new_client(vec![Script::dird(replies)]);
    let fetched = client.fetch_zone_image(Some(serial(1))).expect("image");
    let expected = ZoneImage::new(parts).expect("valid");
    assert_eq!(fetched, ImageFetch::Image(Box::new(expected)));
    assert_eq!(
        sent_kinds(&client),
        vec![request_kind::PING, request_kind::FETCH_ZONE_IMAGE]
    );
}

/// docs/54 §4.6: dird answers `Unchanged` for the SERIAL dnsd has, never the
/// same image again; and nothing follows the first chunk but chunks.
#[test]
fn an_image_must_be_new_and_chunks_must_not_mix() {
    let transfer = ImageTransfer::new(&rfc2782_parts()).expect("valid");
    let mut replies = vec![pong()];
    replies.extend(chunk_bodies(transfer.chunks()));
    let mut client = new_client(vec![Script::dird(replies)]);
    assert_eq!(
        client.fetch_zone_image(Some(serial(1_995_032_001))),
        Err(Unserved::UnexpectedReply)
    );

    let full = ImageChunk::new(&vec![0; MAX_IMAGE_CHUNK as usize], true).expect("chunk");
    let mut client = new_client(vec![Script::dird(vec![
        pong(),
        reply_body(&DnsReply::ImageChunk(full)),
        reply_body(&DnsReply::Unchanged { serial: serial(9) }),
    ])]);
    assert_eq!(
        client.fetch_zone_image(Some(serial(9))),
        Err(Unserved::UnexpectedReply)
    );
}

/// docs/54 §4.6 (total ≤ 8 MiB): chunks past the image bound are refused —
/// the assembly never grows beyond it.
#[test]
fn image_chunks_past_the_bound_are_refused() {
    let full = ImageChunk::new(&vec![0; MAX_IMAGE_CHUNK as usize], true).expect("chunk");
    let mut replies = vec![pong()];
    for _ in 0..9 {
        replies.push(reply_body(&DnsReply::ImageChunk(full.clone())));
    }
    let mut client = new_client(vec![Script::dird(replies)]);
    assert_eq!(
        client.fetch_zone_image(None),
        Err(Unserved::InvalidImage(ImageError::OverBound))
    );
    assert!(!client.is_connected());
}

/// docs/50 §3.3 / A-124: an image dird should never have sent — a payload
/// that does not decode, or parts that are not a zone — is refused.
#[test]
fn an_invalid_image_is_refused() {
    let mut replies = vec![pong()];
    replies.extend(chunk_bodies(&split_image(&[0xEE; 64]).expect("splits")));
    let mut client = new_client(vec![Script::dird(replies)]);
    assert!(matches!(
        client.fetch_zone_image(None),
        Err(Unserved::InvalidImage(ImageError::Payload(_)))
    ));

    let mut parts = rfc2782_parts();
    parts
        .hosts
        .push(common::host(b"server", &[[10, 0, 0, 1]], 60));
    let mut replies = vec![pong()];
    replies.extend(chunk_bodies(
        &split_image(&encode_image(&parts).expect("encodes")).expect("splits"),
    ));
    let mut client = new_client(vec![Script::dird(replies)]);
    assert_eq!(
        client.fetch_zone_image(None),
        Err(Unserved::InvalidImage(ImageError::Zone(
            ZoneImageError::DuplicateHost
        )))
    );
}
