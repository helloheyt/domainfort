//! The canonical encoder and the decoder agree: `decode(encode(m)) == m` and
//! `encode(decode(b)) == b` for canonical octets (docs/54 §6.3, §10.2;
//! docs/50 §3.3 "round-trip"), and the encoder refuses every value that would
//! not read back (docs/54 §6.3: the server never emits what it cannot parse
//! back).
//!
//! Values are built from the record layouts of RFC 1035 §3.3.11, §3.3.13,
//! §3.4.1, RFC 2782, RFC 2136 §2.4–§2.5 and RFC 8945 §4.2.

mod common;

use common::*;
use parse_dns::{
    decode, Class, Error, Header, Message, Name, Opcode, Profile, Question, RData, Rcode,
    ResourceRecord, RrType, Soa, Srv, Transport, TsigError, TsigMac, TsigRecord, TsigTime,
    MAX_TSIG_TIME_SIGNED,
};
use std::net::Ipv4Addr;

fn n(dotted: &str) -> Name {
    Name::from_dotted(dotted).unwrap()
}

fn hdr(id: u16, qr: bool, opcode: Opcode, rcode: Rcode) -> Header {
    Header {
        id,
        qr,
        opcode,
        aa: false,
        tc: false,
        rd: false,
        ra: false,
        rcode,
    }
}

fn record(name: &str, class: Class, ttl: u32, rdata: RData) -> ResourceRecord {
    ResourceRecord {
        name: n(name),
        class,
        ttl,
        rdata,
    }
}

fn tsig(error: TsigError, mac: Vec<u8>, other: Vec<u8>) -> TsigRecord {
    TsigRecord {
        key_name: n("key.example.com"),
        algorithm_name: n("gss-tsig"),
        time_signed: TsigTime::new(1_700_000_000).unwrap(),
        fudge: 300,
        mac: TsigMac::new(mac).unwrap(),
        original_id: 0x2468,
        error,
        other_data: other,
    }
}

/// encode → decode under `profile` gives the value back, and re-encoding the
/// decoded value gives the same octets.
fn assert_round_trip(message: &Message, profile: Profile) -> Vec<u8> {
    let wire = message.encode().unwrap();
    let decoded = decode(&wire, profile).unwrap();
    assert_eq!(decoded.message(), message);
    assert_eq!(decoded.message().encode().unwrap(), wire);
    wire
}

#[test]
fn srv_answer_with_additional_address() {
    // Source: RFC 2782 (SRV format; Target addresses in the Additional Data
    // section); RFC 1035 §3.4.1; docs/54 §6.4 step 6.
    let mut header = hdr(0x0101, true, Opcode::Query, Rcode::NOERROR);
    header.aa = true;
    header.rd = true;
    let message = Message {
        header,
        question: Some(Question {
            qname: n("_kerberos._tcp.EXAMPLE.COM"),
            qtype: RrType::SRV,
            qclass: Class::IN,
        }),
        answer: vec![record(
            "_kerberos._tcp.EXAMPLE.COM",
            Class::IN,
            600,
            RData::Srv(Srv {
                priority: 0,
                weight: 0,
                port: 88,
                target: n("dc.example.com"),
            }),
        )],
        authority: vec![],
        additional: vec![record(
            "dc.example.com",
            Class::IN,
            600,
            RData::A(Ipv4Addr::new(10, 2, 0, 52)),
        )],
        tsig: None,
    };
    let wire = assert_round_trip(&message, Profile::Response(Transport::Udp));
    assert!(wire.len() <= 512);
}

#[test]
fn soa_and_ns_answers() {
    // Source: RFC 1035 §3.3.11, §3.3.13.
    let mut header = hdr(2, true, Opcode::Query, Rcode::NOERROR);
    header.aa = true;
    let message = Message {
        header,
        question: Some(Question {
            qname: n("example.com"),
            qtype: RrType::SOA,
            qclass: Class::IN,
        }),
        answer: vec![record(
            "example.com",
            Class::IN,
            3600,
            RData::Soa(Soa {
                mname: n("dc.example.com"),
                rname: n("hostmaster.example.com"),
                serial: 1,
                refresh: 900,
                retry: 600,
                expire: 86400,
                minimum: 3600,
            }),
        )],
        authority: vec![record(
            "example.com",
            Class::IN,
            3600,
            RData::Ns(n("dc.example.com")),
        )],
        additional: vec![],
        tsig: None,
    };
    assert_round_trip(&message, Profile::Response(Transport::Udp));
}

#[test]
fn error_responses_header_and_question_only() {
    // Source: RFC 1035 §4.1.1 (RCODE 1–5); docs/54 §6.5 ("every error
    // response on UDP = header + question at most").
    for rcode in [
        Rcode::FORMERR,
        Rcode::SERVFAIL,
        Rcode::NXDOMAIN,
        Rcode::NOTIMP,
        Rcode::REFUSED,
    ] {
        for question in [
            None,
            Some(Question {
                qname: n("x.example.com"),
                qtype: RrType::ANY,
                qclass: Class::IN,
            }),
        ] {
            let message = Message {
                header: hdr(3, true, Opcode::Query, rcode),
                question,
                answer: vec![],
                authority: vec![],
                additional: vec![],
                tsig: None,
            };
            assert_round_trip(&message, Profile::Response(Transport::Udp));
        }
    }
}

#[test]
fn truncated_response_flag() {
    // Source: RFC 1035 §4.1.1 (TC), §4.2.1; docs/54 §3.3 (UPDATE/TKEY over
    // UDP ⇒ TC = 1, header + question).
    let mut header = hdr(4, true, Opcode::Query, Rcode::NOERROR);
    header.tc = true;
    let message = Message {
        header,
        question: Some(Question {
            qname: n("example.com"),
            qtype: RrType::SOA,
            qclass: Class::IN,
        }),
        answer: vec![],
        authority: vec![],
        additional: vec![],
        tsig: None,
    };
    assert_round_trip(&message, Profile::Response(Transport::Udp));
}

#[test]
fn signed_update_response() {
    // Source: RFC 2136 §3.8 (response: copy ID and Opcode, zero counts, QR =
    // 1); RFC 8945 §4.2, §5.3 (signed response); §5.2.3 (BADTIME: Other Len
    // 6); §5.3.2 (unsigned error: empty MAC).
    for (rcode, tsig) in [
        (
            Rcode::NOERROR,
            tsig(TsigError::NOERROR, vec![9; 28], vec![]),
        ),
        (
            Rcode::REFUSED,
            tsig(TsigError::NOERROR, vec![9; 28], vec![]),
        ),
        (
            Rcode::NXRRSET,
            tsig(TsigError::NOERROR, vec![9; 28], vec![]),
        ),
        (
            Rcode::NOTAUTH,
            tsig(TsigError::BADTIME, vec![9; 28], vec![0, 0, 0x65, 0, 0, 1]),
        ),
        (Rcode::NOTAUTH, tsig(TsigError::BADKEY, vec![], vec![])),
        (Rcode::NOTAUTH, tsig(TsigError::BADSIG, vec![], vec![])),
    ] {
        let message = Message {
            header: hdr(0x2468, true, Opcode::Update, rcode),
            question: None,
            answer: vec![],
            authority: vec![],
            additional: vec![],
            tsig: Some(tsig),
        };
        assert_round_trip(&message, Profile::Response(Transport::Tcp));
    }
}

#[test]
fn signed_update_request_with_every_form() {
    // Source: RFC 2136 §2.3 (zone), §2.4.1–§2.4.5 (prerequisites), §2.5.1–
    // §2.5.4 (updates); RFC 8945 §5.1 (the TSIG last); docs/54 §6.2.
    let host = "host.example.com";
    let message = Message {
        header: hdr(0x2468, false, Opcode::Update, Rcode::NOERROR),
        question: Some(Question {
            qname: n("example.com"),
            qtype: RrType::SOA,
            qclass: Class::IN,
        }),
        answer: vec![
            record(host, Class::ANY, 0, RData::Empty(RrType::A)),
            record(host, Class::IN, 0, RData::A(Ipv4Addr::new(10, 2, 0, 52))),
            record(host, Class::NONE, 0, RData::Empty(RrType::A)),
            record(host, Class::ANY, 0, RData::Empty(RrType::ANY)),
            record(host, Class::NONE, 0, RData::Empty(RrType::ANY)),
        ],
        authority: vec![
            record(host, Class::IN, 300, RData::A(Ipv4Addr::new(192, 0, 5, 6))),
            record(host, Class::ANY, 0, RData::Empty(RrType::A)),
            record(host, Class::ANY, 0, RData::Empty(RrType::ANY)),
            record(host, Class::NONE, 0, RData::A(Ipv4Addr::new(192, 0, 5, 6))),
        ],
        additional: vec![],
        tsig: Some(tsig(TsigError::NOERROR, vec![1; 28], vec![])),
    };
    assert_round_trip(&message, Profile::Query(Transport::Tcp));
    assert_round_trip(&message, Profile::Forwarded);
}

#[test]
fn query_request_round_trip() {
    // Source: RFC 1035 §4.1.1, §4.1.2; docs/54 §6.2.
    let mut header = hdr(0x7777, false, Opcode::Query, Rcode::NOERROR);
    header.rd = true;
    let message = Message {
        header,
        question: Some(Question {
            qname: n("_ldap._tcp.example.com"),
            qtype: RrType::SRV,
            qclass: Class::IN,
        }),
        answer: vec![],
        authority: vec![],
        additional: vec![],
        tsig: None,
    };
    assert_round_trip(&message, Profile::Query(Transport::Udp));
}

#[test]
fn canonical_octets_reencode_identically() {
    // Source: docs/54 §10.2 ("encode(decode(b)) == b for every canonical
    // message (no compression)"); docs/50 §3.3.
    let alg = name("gss-tsig");
    let mac = [3u8; 28];
    let samples: Vec<(Vec<u8>, Profile)> = vec![
        (
            cat(&[
                &header(1, QUERY | 0x0100, 1, 0, 0, 0),
                &question(&name("a.example.com"), T_A, C_IN),
            ]),
            Profile::Query(Transport::Udp),
        ),
        (signed_update(0x1357), Profile::Forwarded),
        (
            cat(&[
                &header(2, QR | 0x0400, 1, 1, 1, 1),
                &question(&name("example.com"), T_NS, C_IN),
                &rr(
                    &name("example.com"),
                    T_NS,
                    C_IN,
                    60,
                    &name("dc.example.com"),
                ),
                &rr(
                    &name("example.com"),
                    T_SOA,
                    C_IN,
                    60,
                    &soa_rdata(
                        &name("dc.example.com"),
                        &name("h.example.com"),
                        [7, 6, 5, 4, 3],
                    ),
                ),
                &rr(&name("dc.example.com"), T_A, C_IN, 60, &[10, 2, 0, 52]),
            ]),
            Profile::Response(Transport::Udp),
        ),
        (
            cat(&[
                &header(3, QR | UPDATE | 9, 0, 0, 0, 1),
                &tsig_rr(
                    &name("k.example.com"),
                    &tsig_rdata(&gss_tsig_fields(&alg, &mac, 3)),
                ),
            ]),
            Profile::Response(Transport::Tcp),
        ),
    ];
    for (wire, profile) in samples {
        let decoded = decode(&wire, profile).unwrap();
        assert_eq!(decoded.message().encode().unwrap(), wire);
    }
}

#[test]
fn case_is_preserved_through_the_codec() {
    // Source: RFC 1035 §2.3.3 ("When data enters the domain system, its
    // original case should be preserved whenever possible").
    let wire = cat(&[
        &header(1, QUERY, 1, 0, 0, 0),
        &question(&name("MiXeD.Example.COM"), T_A, C_IN),
    ]);
    let decoded = decode(&wire, Profile::Query(Transport::Udp)).unwrap();
    assert_eq!(decoded.message().encode().unwrap(), wire);
}

// ---- encoder refusals (docs/54 §6.3) ----

fn base_response() -> Message {
    Message {
        header: hdr(1, true, Opcode::Query, Rcode::NOERROR),
        question: None,
        answer: vec![],
        authority: vec![],
        additional: vec![],
        tsig: None,
    }
}

#[test]
fn skipped_rdata_cannot_be_encoded() {
    // Source: docs/54 §6.1, §6.4 (skipped records are never echoed): the
    // octets were never retained.
    let mut message = base_response();
    message.additional.push(record(
        ".",
        Class::IN,
        0,
        RData::Unknown {
            rr_type: RrType(41),
            rdlength: 0,
        },
    ));
    assert_eq!(message.encode().unwrap_err(), Error::InvalidValue);
}

#[test]
fn typed_rdata_needs_in_or_none() {
    // Source: RFC 1035 §4.1.3, RFC 1034 §3.6 (A RDATA is class-specific);
    // the decoder types RDATA only under IN or NONE.
    let mut message = base_response();
    message.answer.push(record(
        "a",
        Class(3),
        0,
        RData::A(Ipv4Addr::new(10, 2, 0, 52)),
    ));
    assert_eq!(message.encode().unwrap_err(), Error::InvalidValue);
    let mut message = base_response();
    message
        .answer
        .push(record("a", Class::ANY, 0, RData::Ns(n("b"))));
    assert_eq!(message.encode().unwrap_err(), Error::InvalidValue);
}

#[test]
fn empty_rdata_needs_any_or_none() {
    // Source: RFC 2136 §2.4, §2.5 (empty RDATA only with CLASS ANY or NONE);
    // RFC 8945 §5.1 (a TSIG-typed record only as the TSIG RR).
    let mut message = base_response();
    message
        .answer
        .push(record("a", Class::IN, 0, RData::Empty(RrType::A)));
    assert_eq!(message.encode().unwrap_err(), Error::InvalidValue);
    let mut message = base_response();
    message
        .additional
        .push(record("a", Class::ANY, 0, RData::Empty(RrType::TSIG)));
    assert_eq!(message.encode().unwrap_err(), Error::InvalidValue);
}

#[test]
fn update_header_flags_cannot_be_encoded() {
    // Source: RFC 2136 §2.2 ("UPDATE uses only one flag bit (QR)").
    for flag in 0..4 {
        let mut message = base_response();
        message.header.opcode = Opcode::Update;
        match flag {
            0 => message.header.aa = true,
            1 => message.header.tc = true,
            2 => message.header.rd = true,
            _ => message.header.ra = true,
        }
        assert_eq!(message.encode().unwrap_err(), Error::InvalidValue);
    }
}

#[test]
fn oversize_message_cannot_be_encoded() {
    // Source: RFC 1035 §4.2.2 (at most 65535 octets on any transport).
    let mut message = base_response();
    let long = Name::from_labels(vec![[b'x'; 63]; 3]).unwrap();
    let rr = ResourceRecord {
        name: long,
        class: Class::IN,
        ttl: 0,
        rdata: RData::A(Ipv4Addr::new(10, 2, 0, 52)),
    };
    message.answer = vec![rr; 400]; // 400 × 207 octets > 65535
    assert_eq!(message.encode().unwrap_err(), Error::MessageTooLarge);
}

#[test]
fn bounded_value_types() {
    // Source: RFC 1035 §4.1.1 (RCODE is 4 bits); RFC 8945 §4.2 (Time Signed is
    // 48 bits); docs/54 §6.2 (MAC ≤ 64).
    assert!(Rcode::new(15).is_some());
    assert!(Rcode::new(16).is_none());
    assert!(TsigTime::new(MAX_TSIG_TIME_SIGNED).is_some());
    assert!(TsigTime::new(MAX_TSIG_TIME_SIGNED + 1).is_none());
    assert!(TsigMac::new(vec![0; 64]).is_some());
    assert!(TsigMac::new(vec![0; 65]).is_none());
    assert_eq!(
        Opcode::from_value(Opcode::Update.value()),
        Some(Opcode::Update)
    );
    assert_eq!(Opcode::from_value(1), None);
}
