//! dird's dispatcher of the dnsd ↔ dird channel: the connection's zone
//! comes from dnsd's peer uid and is named in every `Pong`; every request
//! reaches the host only when it decodes; the host's answers become the
//! documented replies (the image in chunks, `Unchanged` only for the SERIAL
//! dnsd has); host refusals and malformed requests close the connection
//! with the documented refusal; and dnsd's client, run against this
//! dispatcher, gets exactly what the host answered.
//!
//! Sources: docs/54 §4.4, §4.6 (the channel; `Pong { zone }`; `Busy` ⇒
//! SERVFAIL), §6.6; A-114 (one dnsd, internal only); A-140 / docs/research/
//! r3-c-dns.md §4.1 (`Forward { transport, peer, message }`,
//! `Forwarded.reply: Option`); docs/50 R50-3 (uid 0 never mapped), §3.3 (the
//! disposition table); A-59; A-152 / docs/questions/Q-922 (`DescribeZone`
//! retired: kind `0x02` is an unknown kind; dnsd starts with `Ping` +
//! `FetchZoneImage { have: None }`); RFC 2782 "Fictional example" (the
//! zone). Every value is hand-made or from those sources.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use ipc::{decode_reply, Refused, Reply};
use ipc_dns::{
    Connection, Connector, DnsClient, DnsMessage, DnsReply, DnsRequest, ExpectedDird,
    ForwardRequest, Forwarded, FrontZone, HostRecordParts, ImageAssembly, ImageFetch,
    ImageTransfer, KpasswdService, Name, PeerAddress, Serial, SoaParameters, Transport,
    TransportError, Unserved as ClientUnserved, ZoneImage, ZoneImageParts, DEFAULT_DEADLINE,
    DNS_CHANNEL, DNS_MAGIC, DNS_VERSION,
};
use ipc_dns_server::{Dispatch, DnsConnection, DnsFronts, ImageAnswer, Unserved, ZoneHost};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::net::Ipv4Addr as StdIpv4;
use std::rc::Rc;
use std::time::Duration;
use zeroize::Zeroizing;

/// Hand-made uids.
const DNSD_UID: u32 = 61_005;
const DIRD_UID: u32 = 61_002;

/// RFC 2782 "Fictional example": SERIAL.
const SERIAL: u32 = 1_995_032_001;

fn serial(value: u32) -> Serial {
    Serial::new(value).expect("non-zero")
}

fn name(dotted: &str) -> Name {
    Name::from_dotted(dotted).expect("name")
}

fn host(label: &str, address: [u8; 4]) -> HostRecordParts {
    HostRecordParts {
        label: label.as_bytes().to_vec(),
        addresses: vec![StdIpv4::from(address)],
        ttl: 3600,
    }
}

/// The RFC 2782 example zone (DC `server`), with `extra` hand-made member
/// hosts of 63-octet labels to make the image span several chunks.
fn parts(extra: u32) -> ZoneImageParts {
    let mut hosts = vec![
        host("old-slow-box", [172, 30, 79, 11]),
        host("sysadmins-box", [172, 30, 79, 12]),
        host("new-fast-box", [172, 30, 79, 13]),
    ];
    for index in 0..extra {
        let mut label = b"h".to_vec();
        label.extend_from_slice(&[b'x'; 54]);
        label.extend_from_slice(format!("{index:08x}").as_bytes());
        let [_, b, c, _] = index.to_be_bytes();
        hosts.push(HostRecordParts {
            label,
            addresses: (1..=8u8).map(|d| StdIpv4::new(10, b, c, d)).collect(),
            ttl: 3600,
        });
    }
    ZoneImageParts {
        apex: name("example.com"),
        serial: SERIAL,
        soa: SoaParameters {
            rname: name("root.example.com"),
            refresh: 3600,
            retry: 3600,
            expire: 604_800,
            minimum: 86_400,
        },
        infrastructure_ttl: 3600,
        dc: host("server", [172, 30, 79, 10]),
        hosts,
        kpasswd: KpasswdService::Absent,
    }
}

/// A hand-made message of `len` octets: an UPDATE header (RFC 1035 §4.1.1
/// layout, RFC 2136 §2.2 opcode 5), then filler.
fn message(len: usize) -> DnsMessage {
    let mut octets = vec![0xAB, 0xCD, 0x28, 0x00, 0, 1, 0, 1, 0, 3, 0, 1];
    octets.resize(len, 0x5C);
    DnsMessage::new(&octets).expect("message")
}

fn udp_forward() -> ForwardRequest {
    ForwardRequest::new(
        Transport::Udp,
        PeerAddress::new(IpAddr::V4(Ipv4Addr::new(172, 30, 79, 13))),
        message(210),
    )
    .expect("fits")
}

fn tcp_forward() -> ForwardRequest {
    ForwardRequest::new(
        Transport::Tcp,
        PeerAddress::new(IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x14))),
        message(3400),
    )
    .expect("fits")
}

fn request_body(request: &DnsRequest) -> Vec<u8> {
    ipc::encode_frame(DNS_CHANNEL, ipc::Direction::Request, request)
        .expect("encodes")
        .body()
        .to_vec()
}

fn replies(dispatch: &Dispatch) -> Vec<Reply<DnsReply>> {
    dispatch
        .frames()
        .iter()
        .map(|frame| decode_reply::<DnsReply>(DNS_CHANNEL, frame.body()).expect("decodes"))
        .collect()
}

/// What the test host answers and what it was asked.
struct TestHost {
    current: ImageTransfer,
    /// When set, `zone_image` answers this regardless of the request.
    image_override: Option<Result<ImageAnswer, Unserved>>,
    forward_answer: Result<Forwarded, Unserved>,
    image_requests: Vec<Option<Serial>>,
    forwards: Vec<(FrontZone, ForwardRequest)>,
    calls: usize,
}

impl TestHost {
    fn new(extra: u32) -> TestHost {
        TestHost {
            current: ImageTransfer::new(&parts(extra)).expect("valid"),
            image_override: None,
            forward_answer: Ok(Forwarded {
                reply: Some(message(12)),
                serial: serial(SERIAL + 1),
            }),
            image_requests: Vec::new(),
            forwards: Vec::new(),
            calls: 0,
        }
    }
}

impl ZoneHost for TestHost {
    fn zone_image(&mut self, have: Option<Serial>) -> Result<ImageAnswer, Unserved> {
        self.calls += 1;
        self.image_requests.push(have);
        if let Some(answer) = &self.image_override {
            return answer.clone();
        }
        if have == Some(self.current.serial()) {
            Ok(ImageAnswer::Unchanged(self.current.serial()))
        } else {
            Ok(ImageAnswer::Image(self.current.clone()))
        }
    }

    fn forward(
        &mut self,
        zone: FrontZone,
        request: &ForwardRequest,
    ) -> Result<Forwarded, Unserved> {
        self.calls += 1;
        self.forwards.push((zone, request.clone()));
        self.forward_answer.clone()
    }
}

fn connection() -> DnsConnection {
    let zone = DnsFronts::new(DNSD_UID)
        .zone_of(DNSD_UID)
        .expect("dnsd's uid");
    DnsConnection::new(7, zone)
}

// ---- the zone ------------------------------------------------------------------

/// docs/54 §4.6; docs/50 R50-3; A-114: only dnsd's uid has a zone (the
/// internal one); uid 0 never does, even if configured.
#[test]
fn only_dnsd_has_a_zone() {
    let fronts = DnsFronts::new(DNSD_UID);
    assert_eq!(fronts.zone_of(DNSD_UID), Some(FrontZone::Internal));
    assert_eq!(fronts.zone_of(DIRD_UID), None);
    assert_eq!(fronts.zone_of(0), None);
    assert_eq!(DnsFronts::new(0).zone_of(0), None);
    let connection = connection();
    assert_eq!(connection.zone(), FrontZone::Internal);
    assert_eq!(connection.id(), 7);
}

/// docs/54 §4.6: `Ping` → `Pong` naming the connection's zone; the
/// connection stays open and the host is not asked.
#[test]
fn ping_names_the_connections_zone() {
    let mut connection = connection();
    let mut host = TestHost::new(0);
    let dispatch = connection.handle(&request_body(&DnsRequest::Ping), &mut host);
    assert!(!dispatch.closes());
    assert_eq!(
        replies(&dispatch),
        vec![Reply::Message(DnsReply::Pong {
            zone: FrontZone::Internal
        })]
    );
    assert_eq!(host.calls, 0);
}

// ---- host refusals ----------------------------------------------------------------

/// docs/54 §4.6 ("queue full ⇒ `Busy` ⇒ dnsd answers SERVFAIL"); docs/50
/// §3.7: a host refusal is the shared refusal, then close — and a closed
/// connection answers nothing.
#[test]
fn host_refusals_close_the_connection() {
    for (unserved, refused) in [
        (Unserved::Busy, Refused::Busy),
        (Unserved::Unavailable, Refused::Unavailable),
    ] {
        let mut connection = connection();
        let mut host = TestHost::new(0);
        host.image_override = Some(Err(unserved));
        let dispatch = connection.handle(
            &request_body(&DnsRequest::FetchZoneImage { have: None }),
            &mut host,
        );
        assert!(dispatch.closes());
        assert_eq!(replies(&dispatch), vec![Reply::Refused(refused)]);
        assert!(connection.is_closed());
        let after = connection.handle(&request_body(&DnsRequest::Ping), &mut host);
        assert!(matches!(after, Dispatch::Close));
    }

    let mut connection = connection();
    let mut host = TestHost::new(0);
    host.forward_answer = Err(Unserved::Unavailable);
    let dispatch = connection.handle(
        &request_body(&DnsRequest::Forward(udp_forward())),
        &mut host,
    );
    assert_eq!(
        replies(&dispatch),
        vec![Reply::Refused(Refused::Unavailable)]
    );
    assert!(connection.is_closed());
}

// ---- FetchZoneImage ----------------------------------------------------------------

/// docs/54 §4.4, §4.6: without a current SERIAL, the image arrives as its
/// chunks and reassembles into the host's zone.
#[test]
fn a_new_image_is_sent_in_chunks() {
    let mut connection = connection();
    let mut host = TestHost::new(12_000);
    let dispatch = connection.handle(
        &request_body(&DnsRequest::FetchZoneImage { have: None }),
        &mut host,
    );
    assert!(!dispatch.closes());
    let replies = replies(&dispatch);
    assert!(replies.len() >= 2, "{}", replies.len());
    let mut assembly = ImageAssembly::new();
    let mut image = None;
    for reply in replies {
        let Reply::Message(DnsReply::ImageChunk(chunk)) = reply else {
            panic!("not a chunk");
        };
        image = assembly.push(&chunk).expect("valid");
    }
    assert_eq!(
        image.expect("complete"),
        ZoneImage::new(parts(12_000)).expect("valid")
    );
    assert_eq!(host.image_requests, vec![None]);
}

/// docs/54 §4.6: the current SERIAL is answered `Unchanged` — also when the
/// host hands back the image dnsd already has.
#[test]
fn the_current_serial_is_unchanged() {
    let mut connection = connection();
    let mut host = TestHost::new(0);
    let have = Some(serial(SERIAL));
    let dispatch = connection.handle(
        &request_body(&DnsRequest::FetchZoneImage { have }),
        &mut host,
    );
    assert_eq!(
        replies(&dispatch),
        vec![Reply::Message(DnsReply::Unchanged {
            serial: serial(SERIAL)
        })]
    );

    host.image_override = Some(Ok(ImageAnswer::Image(host.current.clone())));
    let dispatch = connection.handle(
        &request_body(&DnsRequest::FetchZoneImage { have }),
        &mut host,
    );
    assert_eq!(
        replies(&dispatch),
        vec![Reply::Message(DnsReply::Unchanged {
            serial: serial(SERIAL)
        })]
    );
    assert!(!connection.is_closed());
}

/// Fail closed: a host that says "unchanged" for a SERIAL dnsd does not have
/// contradicts the request — `Refused{Unavailable}` + close.
#[test]
fn a_contradicting_unchanged_fails_closed() {
    for have in [None, Some(serial(5))] {
        let mut connection = connection();
        let mut host = TestHost::new(0);
        host.image_override = Some(Ok(ImageAnswer::Unchanged(serial(SERIAL))));
        let dispatch = connection.handle(
            &request_body(&DnsRequest::FetchZoneImage { have }),
            &mut host,
        );
        assert_eq!(
            replies(&dispatch),
            vec![Reply::Refused(Refused::Unavailable)]
        );
        assert!(connection.is_closed());
    }
}

// ---- Forward (A-140) ----------------------------------------------------------------

/// A-140: the host receives the connection's zone and the exact transport,
/// peer and message; its answer — a reply, or none — goes back as is.
#[test]
fn a_forward_reaches_the_host_unchanged() {
    let mut connection = connection();
    let mut host = TestHost::new(0);
    let dispatch = connection.handle(
        &request_body(&DnsRequest::Forward(udp_forward())),
        &mut host,
    );
    assert!(!dispatch.closes());
    assert_eq!(
        replies(&dispatch),
        vec![Reply::Message(DnsReply::Forwarded(
            host.forward_answer.clone().unwrap()
        ))]
    );
    host.forward_answer = Ok(Forwarded {
        reply: None,
        serial: serial(SERIAL),
    });
    let dispatch = connection.handle(
        &request_body(&DnsRequest::Forward(tcp_forward())),
        &mut host,
    );
    assert_eq!(
        replies(&dispatch),
        vec![Reply::Message(DnsReply::Forwarded(Forwarded {
            reply: None,
            serial: serial(SERIAL)
        }))]
    );
    assert_eq!(
        host.forwards,
        vec![
            (FrontZone::Internal, udp_forward()),
            (FrontZone::Internal, tcp_forward())
        ]
    );
}

// ---- malformed requests ---------------------------------------------------------------

/// docs/50 §3.3: nothing malformed reaches the host — wrong magic or unknown
/// kind ⇒ close without a reply; another version ⇒ `VersionMismatch`; a
/// payload error ⇒ `Malformed`; each closes the connection.
#[test]
fn malformed_requests_never_reach_the_host() {
    let mut truncated = request_body(&DnsRequest::FetchZoneImage {
        have: Some(serial(9)),
    });
    truncated.pop();
    let mut udp_too_long = request_body(&DnsRequest::Forward(udp_forward()));
    // Rewrite the length to 513 and append the missing octets.
    let length_at = 4 + 1 + 1 + 4;
    udp_too_long[length_at..length_at + 4].copy_from_slice(&513u32.to_be_bytes());
    udp_too_long.resize(length_at + 4 + 513, 0x5C);
    let mut wrong_magic = request_body(&DnsRequest::Ping);
    wrong_magic[1] ^= 0xFF;
    let mut wrong_version = request_body(&DnsRequest::Ping);
    wrong_version[2] = DNS_VERSION + 1;
    let unknown_kind = vec![
        DNS_MAGIC.to_be_bytes()[0],
        DNS_MAGIC.to_be_bytes()[1],
        DNS_VERSION,
        0x09,
    ];

    for (body, expected) in [
        (truncated, Some(Refused::Malformed)),
        (udp_too_long, Some(Refused::Malformed)),
        (wrong_version, Some(Refused::VersionMismatch)),
        (wrong_magic, None),
        (unknown_kind, None),
    ] {
        let mut connection = connection();
        let mut host = TestHost::new(0);
        let dispatch = connection.handle(&body, &mut host);
        assert!(dispatch.closes());
        match expected {
            Some(refused) => assert_eq!(replies(&dispatch), vec![Reply::Refused(refused)]),
            None => assert!(matches!(dispatch, Dispatch::Close)),
        }
        assert_eq!(host.calls, 0);
        assert!(connection.is_closed());
    }
}

/// A-152 / docs/questions/Q-922: the retired `DescribeZone` (`0x02`) is an
/// unknown kind — dird closes without a reply and the host is not asked,
/// with or without a payload; and the connection answers nothing after.
#[test]
fn the_retired_describe_zone_never_reaches_the_host() {
    let envelope = [
        DNS_MAGIC.to_be_bytes()[0],
        DNS_MAGIC.to_be_bytes()[1],
        DNS_VERSION,
        0x02,
    ];
    for body in [envelope.to_vec(), [&envelope[..], &[0x00][..]].concat()] {
        let mut connection = connection();
        let mut host = TestHost::new(0);
        let dispatch = connection.handle(&body, &mut host);
        assert!(matches!(dispatch, Dispatch::Close));
        assert!(dispatch.frames().is_empty());
        assert_eq!(host.calls, 0);
        assert!(connection.is_closed());
        let after = connection.handle(&request_body(&DnsRequest::Ping), &mut host);
        assert!(matches!(after, Dispatch::Close));
    }
}

// ---- end to end: dnsd's client against this dispatcher ---------------------------------

/// An in-process connection whose far end is a `DnsConnection` with a host.
struct Loopback {
    uid: u32,
    connection: DnsConnection,
    host: Rc<RefCell<TestHost>>,
    pending: VecDeque<Vec<u8>>,
}

impl Connection for Loopback {
    fn peer_uid(&self) -> Result<u32, TransportError> {
        Ok(self.uid)
    }

    fn send(&mut self, frame: &[u8], _deadline: Duration) -> Result<(), TransportError> {
        if self.connection.is_closed() {
            return Err(TransportError::Closed);
        }
        let dispatch = self
            .connection
            .handle(&frame[4..], &mut *self.host.borrow_mut());
        self.pending
            .extend(dispatch.frames().iter().map(|frame| frame.body().to_vec()));
        Ok(())
    }

    fn receive(
        &mut self,
        limit: ipc::FrameLimit,
        _deadline: Duration,
    ) -> Result<Zeroizing<Vec<u8>>, TransportError> {
        let body = self.pending.pop_front().ok_or(TransportError::Closed)?;
        if body.len() > limit.max_body() as usize {
            return Err(TransportError::Framing);
        }
        Ok(Zeroizing::new(body))
    }

    fn check_idle(&mut self) -> Result<(), TransportError> {
        if self.connection.is_closed() || !self.pending.is_empty() {
            Err(TransportError::Closed)
        } else {
            Ok(())
        }
    }
}

struct LoopbackConnector {
    host: Rc<RefCell<TestHost>>,
    next_id: u64,
}

impl Connector for LoopbackConnector {
    type Connection = Loopback;

    fn connect(&mut self) -> Result<Loopback, TransportError> {
        self.next_id += 1;
        Ok(Loopback {
            uid: DIRD_UID,
            connection: DnsConnection::new(self.next_id, FrontZone::Internal),
            host: Rc::clone(&self.host),
            pending: VecDeque::new(),
        })
    }
}

/// docs/54 §4.8 (dnsd's start — since A-152 / Q-922 `Ping` +
/// `FetchZoneImage { have: None }`, whose image carries the apex and the
/// SERIAL), §4.4 (refresh by SERIAL), §4.5 / A-140 (`Forward`): dnsd's
/// client gets exactly what dird's host answered, over the dispatcher, and
/// a host refusal reaches it as the shared refusal.
#[test]
fn dnsd_and_dird_agree_end_to_end() {
    let host = Rc::new(RefCell::new(TestHost::new(12_000)));
    let connector = LoopbackConnector {
        host: Rc::clone(&host),
        next_id: 0,
    };
    let expected = ExpectedDird::new(DIRD_UID, FrontZone::Internal).expect("non-root");
    let mut client = DnsClient::new(connector, expected, DEFAULT_DEADLINE);

    client.ping().expect("ping");
    let ImageFetch::Image(image) = client.fetch_zone_image(None).expect("image") else {
        panic!("expected an image");
    };
    assert_eq!(image.apex(), &name("example.com"));
    assert_eq!(image.serial(), SERIAL);
    assert_eq!(*image, ZoneImage::new(parts(12_000)).expect("valid"));
    assert_eq!(
        client.fetch_zone_image(Some(serial(SERIAL))),
        Ok(ImageFetch::Unchanged(serial(SERIAL)))
    );

    let forwarded = client.forward(&udp_forward()).expect("forward");
    assert_eq!(forwarded.serial, serial(SERIAL + 1));
    assert_eq!(
        host.borrow().forwards,
        vec![(FrontZone::Internal, udp_forward())]
    );

    host.borrow_mut().forward_answer = Err(Unserved::Busy);
    assert_eq!(
        client.forward(&tcp_forward()),
        Err(ClientUnserved::Refused(Refused::Busy))
    );
    assert!(!client.is_connected());
    // The next call reconnects, verifies and is served.
    host.borrow_mut().forward_answer = Ok(Forwarded {
        reply: None,
        serial: serial(SERIAL + 1),
    });
    assert_eq!(client.forward(&tcp_forward()).expect("served").reply, None);
}
