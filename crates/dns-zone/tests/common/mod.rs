//! Shared fixtures, request builders and the invariant checker.
//!
//! Sources of the values: the zone of RFC 2782's "Fictional example"
//! (`example.com`, SOA `server.example.com. root.example.com. ( 1995032001 3600
//! 3600 604800 86400 )`, hosts `server` 172.30.79.10, `old-slow-box`
//! 172.30.79.11, `sysadmins-box` 172.30.79.12, `new-fast-box` 172.30.79.13)
//! and the addresses of RFC 1034 §3.7.1 (10.2.0.27, 128.9.0.33, 10.1.0.52,
//! 128.9.0.32). TTLs, IDs and the 8-address DC are hand-made. Request octets
//! are either encoded by parse-dns from typed values or laid out by hand from
//! the field layouts of RFC 1035 §4.1.1–§4.1.3 and RFC 8945 §4.2. No octet
//! comes from any other implementation or capture.

#![allow(dead_code)]

use dns_zone::limits::{MAX_TTL, UDP_AMPLIFICATION_FACTOR};
use dns_zone::{
    answer, HostRecordParts, KpasswdService, SoaParameters, Transport, Verdict, ZoneImage,
    ZoneImageParts, ZoneState,
};
use parse_dns::{
    decode, decode_header, Class, Header, Message, Name, Opcode, Profile, Question, RData, Rcode,
    RrType, TsigError, TsigMac, TsigRecord, TsigTime,
};
use std::net::Ipv4Addr;

/// TYPE values used only as numbers. Spec: RFC 1035 §3.2.2 (CNAME 5, PTR 12,
/// MX 15, TXT 16).
pub const T_CNAME: u16 = 5;
pub const T_PTR: u16 = 12;
pub const T_MX: u16 = 15;
pub const T_TXT: u16 = 16;
/// CLASS CH. Spec: RFC 1035 §3.2.4.
pub const C_CH: u16 = 3;

/// RFC 2782 "Fictional example" SOA timers.
pub const RFC2782_SERIAL: u32 = 1_995_032_001;
pub const RFC2782_REFRESH: u32 = 3600;
pub const RFC2782_RETRY: u32 = 3600;
pub const RFC2782_EXPIRE: u32 = 604_800;
pub const RFC2782_MINIMUM: u32 = 86_400;

/// Hand-made TTLs: one below MINIMUM (floored), one above (kept).
pub const TTL_BELOW_MINIMUM: u32 = 3600;
pub const TTL_ABOVE_MINIMUM: u32 = 172_800;

pub fn name(dotted: &str) -> Name {
    Name::from_dotted(dotted).expect("test name")
}

pub fn host(label: &str, addresses: &[[u8; 4]], ttl: u32) -> HostRecordParts {
    HostRecordParts {
        label: label.as_bytes().to_vec(),
        addresses: addresses.iter().map(|a| Ipv4Addr::from(*a)).collect(),
        ttl,
    }
}

/// The parts of the RFC 2782 example zone as this server would serve it.
pub fn rfc2782_parts(kpasswd: KpasswdService) -> ZoneImageParts {
    ZoneImageParts {
        apex: name("example.com"),
        serial: RFC2782_SERIAL,
        soa: SoaParameters {
            rname: name("root.example.com"),
            refresh: RFC2782_REFRESH,
            retry: RFC2782_RETRY,
            expire: RFC2782_EXPIRE,
            minimum: RFC2782_MINIMUM,
        },
        infrastructure_ttl: TTL_BELOW_MINIMUM,
        dc: host("server", &[[172, 30, 79, 10]], TTL_BELOW_MINIMUM),
        hosts: vec![
            host("old-slow-box", &[[172, 30, 79, 11]], TTL_ABOVE_MINIMUM),
            host("sysadmins-box", &[[172, 30, 79, 12]], TTL_BELOW_MINIMUM),
            host(
                "new-fast-box",
                &[[172, 30, 79, 13], [10, 2, 0, 27], [128, 9, 0, 33]],
                TTL_ABOVE_MINIMUM,
            ),
        ],
        kpasswd,
    }
}

pub fn rfc2782_zone() -> ZoneImage {
    ZoneImage::new(rfc2782_parts(KpasswdService::Absent)).expect("valid image")
}

pub fn rfc2782_zone_with_kpasswd() -> ZoneImage {
    ZoneImage::new(rfc2782_parts(KpasswdService::Present)).expect("valid image")
}

/// A DC with eight addresses (the bound of docs/54 §4.4): the largest
/// additional section any reply carries.
pub fn eight_address_dc_zone() -> ZoneImage {
    let mut parts = rfc2782_parts(KpasswdService::Present);
    parts.dc = host(
        "server",
        &[
            [172, 30, 79, 10],
            [10, 2, 0, 27],
            [128, 9, 0, 33],
            [10, 1, 0, 52],
            [128, 9, 0, 32],
            [172, 30, 79, 20],
            [172, 30, 79, 21],
            [172, 30, 79, 22],
        ],
        TTL_ABOVE_MINIMUM,
    );
    ZoneImage::new(parts).expect("valid image")
}

/// A zone whose apex and DC label are long (stresses every size bound).
pub fn long_name_zone() -> ZoneImage {
    let label = "a".repeat(63);
    let apex = format!("{label}.{label}.{}.example.com", "b".repeat(40));
    let mut parts = rfc2782_parts(KpasswdService::Present);
    parts.apex = name(&apex);
    parts.dc = host(&"c".repeat(50), &[[172, 30, 79, 10], [10, 2, 0, 27]], 600);
    parts.hosts = vec![host(&"d".repeat(60), &[[172, 30, 79, 11]], 600)];
    ZoneImage::new(parts).expect("valid image")
}

pub fn all_zones() -> Vec<ZoneImage> {
    vec![
        rfc2782_zone(),
        rfc2782_zone_with_kpasswd(),
        eight_address_dc_zone(),
        long_name_zone(),
    ]
}

// ---- requests --------------------------------------------------------------

/// A QUERY request header. Spec: RFC 1035 §4.1.1.
pub fn query_header(id: u16, rd: bool) -> Header {
    Header {
        id,
        qr: false,
        opcode: Opcode::Query,
        aa: false,
        tc: false,
        rd,
        ra: false,
        rcode: Rcode::NOERROR,
    }
}

/// A one-question QUERY encoded by parse-dns. Spec: RFC 1035 §4.1.1, §4.1.2.
pub fn query_msg(id: u16, qname: &Name, qtype: u16, qclass: u16, rd: bool) -> Message {
    Message {
        header: query_header(id, rd),
        question: Some(Question {
            qname: qname.clone(),
            qtype: RrType(qtype),
            qclass: Class(qclass),
        }),
        answer: Vec::new(),
        authority: Vec::new(),
        additional: Vec::new(),
        tsig: None,
    }
}

pub fn query(id: u16, qname: &str, qtype: u16, qclass: u16, rd: bool) -> Vec<u8> {
    parse_dns::encode(&query_msg(id, &name(qname), qtype, qclass, rd)).expect("encode")
}

/// A request TSIG RR. Spec: RFC 8945 §4.2 (Error zero in requests; Original
/// ID equal to the message ID).
pub fn request_tsig(key: &str, algorithm: &str, id: u16) -> TsigRecord {
    TsigRecord {
        key_name: name(key),
        algorithm_name: name(algorithm),
        time_signed: TsigTime::new(1_700_000_000).expect("48-bit"),
        fudge: 300,
        mac: TsigMac::new(vec![0x5A; 28]).expect("mac"),
        original_id: id,
        error: TsigError::NOERROR,
        other_data: Vec::new(),
    }
}

/// An UPDATE request: zone section only, optionally signed.
/// Spec: RFC 2136 §2.2, §2.3 (ZTYPE SOA, ZCLASS the zone's class).
pub fn update_msg(id: u16, zone: &str, tsig: Option<TsigRecord>) -> Message {
    Message {
        header: Header {
            id,
            qr: false,
            opcode: Opcode::Update,
            aa: false,
            tc: false,
            rd: false,
            ra: false,
            rcode: Rcode::NOERROR,
        },
        question: Some(Question {
            qname: name(zone),
            qtype: RrType::SOA,
            qclass: Class::IN,
        }),
        answer: Vec::new(),
        authority: Vec::new(),
        additional: Vec::new(),
        tsig,
    }
}

pub fn update(id: u16, zone: &str, tsig: Option<TsigRecord>) -> Vec<u8> {
    parse_dns::encode(&update_msg(id, zone, tsig)).expect("encode")
}

// ---- hand layouts ----------------------------------------------------------

/// The 12-octet header. Spec: RFC 1035 §4.1.1.
pub fn raw_header(id: u16, flags: u16, qd: u16, an: u16, ns: u16, ar: u16) -> Vec<u8> {
    [id, flags, qd, an, ns, ar]
        .iter()
        .flat_map(|w| w.to_be_bytes())
        .collect()
}

/// An uncompressed name. Spec: RFC 1035 §3.1.
pub fn raw_name(dotted: &str) -> Vec<u8> {
    name(dotted).as_wire().to_vec()
}

/// A compression pointer. Spec: RFC 1035 §4.1.4.
pub fn raw_pointer(offset: u16) -> Vec<u8> {
    (0xC000 | offset).to_be_bytes().to_vec()
}

/// A resource record. Spec: RFC 1035 §4.1.3.
pub fn raw_rr(owner: &[u8], rr_type: u16, class: u16, ttl: u32, rdata: &[u8]) -> Vec<u8> {
    let mut out = owner.to_vec();
    out.extend_from_slice(&rr_type.to_be_bytes());
    out.extend_from_slice(&class.to_be_bytes());
    out.extend_from_slice(&ttl.to_be_bytes());
    out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    out.extend_from_slice(rdata);
    out
}

/// TSIG RDATA (uncompressed algorithm name). Spec: RFC 8945 §4.2.
pub fn raw_tsig_rdata(algorithm: &str, mac: &[u8], original_id: u16) -> Vec<u8> {
    let mut out = raw_name(algorithm);
    out.extend_from_slice(&1_700_000_000u64.to_be_bytes()[2..]);
    out.extend_from_slice(&300u16.to_be_bytes());
    out.extend_from_slice(&(mac.len() as u16).to_be_bytes());
    out.extend_from_slice(mac);
    out.extend_from_slice(&original_id.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out
}

/// Appends one additional record to an encoded request, fixing ARCOUNT.
/// Spec: RFC 1035 §4.1.1 (ARCOUNT), §4.1.3.
pub fn with_additional(mut request: Vec<u8>, record: &[u8]) -> Vec<u8> {
    let arcount = u16::from_be_bytes([request[10], request[11]]) + 1;
    request[10..12].copy_from_slice(&arcount.to_be_bytes());
    request.extend_from_slice(record);
    request
}

// ---- running and checking ---------------------------------------------------

pub fn run<'a>(image: &ZoneImage, request: &'a [u8], transport: Transport) -> Verdict<'a> {
    answer(ZoneState::Current(image), request, transport)
}

pub fn reply_message(verdict: &Verdict<'_>, transport: Transport) -> Message {
    match verdict {
        Verdict::Reply(reply) => decode(reply.as_bytes(), Profile::Response(transport))
            .expect("reply decodes under the Response profile")
            .into_message(),
        other => panic!("expected a reply, got {other:?}"),
    }
}

pub fn udp(image: &ZoneImage, request: &[u8]) -> Message {
    let verdict = run(image, request, Transport::Udp);
    check(Some(image), request, Transport::Udp, &verdict);
    reply_message(&verdict, Transport::Udp)
}

pub fn tcp(image: &ZoneImage, request: &[u8]) -> Message {
    let verdict = run(image, request, Transport::Tcp);
    check(Some(image), request, Transport::Tcp, &verdict);
    reply_message(&verdict, Transport::Tcp)
}

/// The invariants every verdict must satisfy (docs/54 §6.4–§6.6):
///
/// * a UDP reply is ≤ 512 octets and ≤ k × the request; an error reply ≤ the
///   request (§6.5);
/// * every reply re-decodes with parse-dns (`Response` profile, or the header
///   alone for the NOTIMP reply to an unmodelled opcode), copies ID and
///   OPCODE, has QR = 1 and RA = 0;
/// * a QUERY reply echoes the question octets exactly, carries only A / NS /
///   SOA / SRV records of class IN, answers only the QNAME with the QTYPE,
///   adds only the DC's A records, never an authority section, TTLs within
///   [MINIMUM, 2^31 − 1], and no record at all for a name outside the zone;
/// * a TC reply carries no record; a TSIG appears only as BADKEY, unsigned,
///   in reply to a request that carried one;
/// * Forward only for an UPDATE over TCP with a gss-tsig TSIG, with the exact
///   request octets; Close only over TCP.
pub fn check(image: Option<&ZoneImage>, request: &[u8], transport: Transport, verdict: &Verdict) {
    match verdict {
        Verdict::Silence(_) => {}
        Verdict::Close => assert_eq!(transport, Transport::Tcp, "close is TCP only"),
        Verdict::Forward(forward) => {
            assert_eq!(transport, Transport::Tcp, "forward is TCP only");
            assert_eq!(forward.message(), request, "forwarded octets unchanged");
            let decoded = decode(request, Profile::Query(Transport::Tcp)).expect("decodes");
            let message = decoded.message();
            assert_eq!(message.header.opcode, Opcode::Update);
            assert!(message
                .tsig
                .as_ref()
                .expect("signed")
                .algorithm_is_gss_tsig());
            let fallback = forward.unavailable_reply();
            let reply = decode(fallback.as_bytes(), Profile::Response(Transport::Tcp))
                .expect("fallback decodes")
                .into_message();
            assert_eq!(reply.header.rcode, Rcode::SERVFAIL);
            assert_eq!(reply.header.opcode, Opcode::Update);
            assert_eq!(reply.header.id, message.header.id);
            assert!(reply.question.is_none() && reply.tsig.is_none());
        }
        Verdict::Reply(reply) => check_reply(image, request, transport, reply),
    }
}

fn check_reply(
    image: Option<&ZoneImage>,
    request: &[u8],
    transport: Transport,
    reply: &dns_zone::Reply,
) {
    let octets = reply.as_bytes();
    assert_eq!(
        reply.transport(),
        transport,
        "a reply is built for its transport"
    );
    if transport == Transport::Udp {
        assert!(octets.len() <= 512, "UDP reply over 512 octets");
        assert!(
            octets.len() <= UDP_AMPLIFICATION_FACTOR * request.len(),
            "UDP reply over k × request ({} > {} × {})",
            octets.len(),
            UDP_AMPLIFICATION_FACTOR,
            request.len()
        );
        if reply.rcode() != Rcode::NOERROR {
            assert!(
                octets.len() <= request.len(),
                "UDP error reply larger than request"
            );
        }
    }
    let request_header = decode_header(request, transport).expect("request header decoded");
    let reply_header = decode_header(octets, transport).expect("reply header");
    assert!(reply_header.qr, "QR = 1");
    assert!(!reply_header.ra, "RA = 0");
    assert_eq!(reply_header.id, request_header.id, "ID copied");
    assert_eq!(reply_header.opcode, request_header.opcode, "OPCODE copied");
    assert_eq!(reply_header.rcode, reply.rcode());
    assert_eq!(reply_header.tc, reply.is_truncated());

    if request_header.known_opcode().is_none() {
        assert_eq!(octets.len(), 12, "NOTIMP is header only");
        assert_eq!(reply.rcode(), Rcode::NOTIMP);
        assert_eq!(
            (
                reply_header.qdcount,
                reply_header.ancount,
                reply_header.nscount,
                reply_header.arcount
            ),
            (0, 0, 0, 0)
        );
        return;
    }

    let message = decode(octets, Profile::Response(transport))
        .expect("reply decodes under the Response profile")
        .into_message();
    let request_message = decode(request, Profile::Query(transport))
        .ok()
        .map(|d| d.into_message());

    if message.header.tc {
        assert!(message.answer.is_empty() && message.additional.is_empty());
        assert!(message.tsig.is_none());
    }
    assert!(message.authority.is_empty(), "no authority section");

    if let Some(tsig) = &message.tsig {
        assert_eq!(tsig.error, TsigError::BADKEY);
        assert!(tsig.mac.as_bytes().is_empty(), "unsigned");
        assert!(tsig.other_data.is_empty());
        let request_tsig = request_message
            .as_ref()
            .and_then(|m| m.tsig.as_ref())
            .expect("a TSIG only answers a TSIG");
        assert_eq!(tsig.key_name, request_tsig.key_name);
        assert_eq!(message.header.rcode, Rcode::NOTAUTH);
    }

    match message.header.opcode {
        Opcode::Update => {
            assert!(message.question.is_none(), "UPDATE reply: zero counts");
            assert!(message.answer.is_empty() && message.additional.is_empty());
        }
        Opcode::Query => {
            if let Some(question) = &message.question {
                let asked = request_message
                    .as_ref()
                    .and_then(|m| m.question.clone())
                    .expect("a question is echoed only from a decoded request");
                assert_eq!(
                    question.qname.as_wire(),
                    asked.qname.as_wire(),
                    "QNAME octets echoed"
                );
                assert_eq!(
                    (question.qtype, question.qclass),
                    (asked.qtype, asked.qclass)
                );
                check_records(image, &message, question);
            } else {
                assert!(message.answer.is_empty() && message.additional.is_empty());
            }
        }
    }
}

fn check_records(image: Option<&ZoneImage>, message: &Message, question: &Question) {
    let records = message.answer.iter().chain(&message.additional);
    let Some(image) = image else {
        assert_eq!(records.count(), 0, "no data without a zone");
        return;
    };
    if !question.qname.is_subdomain_of(image.apex()) {
        assert_eq!(records.count(), 0, "no data for a name outside the zone");
        return;
    }
    for record in records {
        assert_eq!(record.class, Class::IN);
        assert!(
            record.ttl >= image.minimum() && record.ttl <= MAX_TTL,
            "TTL in range"
        );
        assert!(matches!(
            record.rdata,
            RData::A(_) | RData::Ns(_) | RData::Soa(_) | RData::Srv(_)
        ));
    }
    for record in &message.answer {
        assert_eq!(record.name, question.qname, "answers own QNAME");
        assert_eq!(record.rr_type(), question.qtype, "answers match QTYPE");
    }
    for record in &message.additional {
        assert_eq!(record.rr_type(), RrType::A);
        assert_eq!(
            &record.name,
            image.dc_name(),
            "additional: the DC's addresses"
        );
    }
    if !message.answer.is_empty() || message.header.rcode == Rcode::NXDOMAIN {
        assert!(message.header.aa, "authoritative data carries AA");
    }
}
