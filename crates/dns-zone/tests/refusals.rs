//! dnsd's refusal table (docs/54 §6.6, dnsd rows) row by row, as built — see
//! the table in `src/answer.rs`.
//!
//! Sources: docs/54 §3.2, §3.3, §4.4, §4.5 step 1, §6.2, §6.5, §6.6, §7.5;
//! RFC 1034 §3.7.1, §3.7.2; RFC 1035 §2.3.4, §3.2.3, §4.1.1, §4.2.2; RFC 2136
//! §2.2, §3, §3.1.1, §3.3.1, §3.8; RFC 8945 §4.2, §5.2, §5.2.1, §5.3.2;
//! docs/questions/Q-616, Q-671. Requests are hand-made (tests/common).

mod common;

use common::*;
use dns_zone::{answer, Silence, Transport, Verdict, ZoneState};
use parse_dns::{decode_header, Opcode, Rcode, TsigError};

const IN: u16 = 1;
const BOTH: [Transport; 2] = [Transport::Udp, Transport::Tcp];

fn verdict<'a>(request: &'a [u8], transport: Transport) -> Verdict<'a> {
    let zone = rfc2782_zone();
    let verdict = answer(ZoneState::Current(&zone), request, transport);
    check(Some(&zone), request, transport, &verdict);
    verdict
}

fn reply_octets(verdict: &Verdict<'_>) -> Vec<u8> {
    match verdict {
        Verdict::Reply(reply) => reply.as_bytes().to_vec(),
        other => panic!("expected a reply, got {other:?}"),
    }
}

/// A QUERY for `server.example.com A` with the given flag word and counts.
fn raw_query(flags: u16, qd: u16, an: u16, ns: u16, ar: u16) -> Vec<u8> {
    let mut out = raw_header(0x2000, flags, qd, an, ns, ar);
    out.extend_from_slice(&raw_name("server.example.com"));
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&IN.to_be_bytes());
    out
}

#[test]
fn row1_udp_datagram_over_512_is_silent_rfc1035_2_3_4() {
    // docs/54 §3.3: an inbound datagram > 512 is never decoded; no reply = no
    // reflection.
    let base = query(0x2001, "server.example.com", 1, IN, false);
    // An additional record of a type parse-dns skips (TXT) pads it to 513.
    let pad = 513 - base.len() - 11;
    let request = with_additional(base, &raw_rr(&[0], T_TXT, IN, 0, &vec![0x41; pad]));
    assert_eq!(request.len(), 513);
    assert!(matches!(
        verdict(&request, Transport::Udp),
        Verdict::Silence(Silence::OversizeDatagram)
    ));
    // 512 octets is still a datagram (RFC 1035 §2.3.4 "512 octets or less").
    let base = query(0x2001, "server.example.com", 1, IN, false);
    let request = with_additional(base, &raw_rr(&[0], T_TXT, IN, 0, &vec![0x41; pad - 1]));
    assert_eq!(request.len(), 512);
    assert!(matches!(
        verdict(&request, Transport::Udp),
        Verdict::Reply(_)
    ));
    // Over TCP the 513 octets are an ordinary message (RFC 1035 §4.2.2).
    let base = query(0x2001, "server.example.com", 1, IN, false);
    let request = with_additional(base, &raw_rr(&[0], T_TXT, IN, 0, &vec![0x41; pad]));
    let tcp = reply_octets(&verdict(&request, Transport::Tcp));
    assert_eq!(
        decode_header(&tcp, Transport::Tcp).unwrap().rcode,
        Rcode::NOERROR
    );
}

#[test]
fn row2_shorter_than_a_header_rfc1035_4_1_1() {
    for len in [0usize, 1, 11] {
        let request = vec![0u8; len];
        assert!(matches!(
            verdict(&request, Transport::Udp),
            Verdict::Silence(Silence::Malformed)
        ));
        assert!(matches!(verdict(&request, Transport::Tcp), Verdict::Close));
    }
}

#[test]
fn row3_responses_are_never_answered_docs54_6_6() {
    let request = raw_query(0x8000, 1, 0, 0, 0);
    for transport in BOTH {
        assert!(matches!(
            verdict(&request, transport),
            Verdict::Silence(Silence::Response)
        ));
    }
}

#[test]
fn row4_other_opcodes_are_notimp_header_only_rfc1034_3_7_2() {
    // IQUERY (1), STATUS (2) and every reserved value: NOTIMP with the OPCODE
    // "copied into the response" (RFC 1035 §4.1.1), header only.
    for opcode in (1u16..=4).chain(6..=15) {
        let request = raw_query((opcode << 11) | 0x0100, 1, 0, 0, 0);
        for transport in BOTH {
            let octets = reply_octets(&verdict(&request, transport));
            assert_eq!(octets.len(), 12);
            let header = decode_header(&octets, transport).unwrap();
            assert_eq!(header.opcode, opcode as u8);
            assert_eq!(header.rcode, Rcode::NOTIMP);
            assert!(header.qr && !header.rd && !header.aa && !header.tc && !header.ra);
            assert_eq!(header.id, 0x2000);
        }
    }
}

#[test]
fn row5_section_counts_outside_the_profile_are_formerr_docs54_6_2() {
    // QUERY: QDCOUNT = 1, ANCOUNT = NSCOUNT = 0, ARCOUNT ≤ 4 (docs/54 §6.2) —
    // a header-level fault: FORMERR on both transports, header only.
    let cases = [
        raw_query(0x0100, 0, 0, 0, 0),
        raw_query(0x0100, 2, 0, 0, 0),
        raw_query(0x0100, 1, 1, 0, 0),
        raw_query(0x0100, 1, 0, 1, 0),
        raw_query(0x0100, 1, 0, 0, 5),
    ];
    for request in &cases {
        for transport in BOTH {
            let octets = reply_octets(&verdict(request, transport));
            assert_eq!(octets.len(), 12);
            let header = decode_header(&octets, transport).unwrap();
            assert_eq!(header.rcode, Rcode::FORMERR);
            assert_eq!(header.opcode, 0);
            assert!(header.rd, "RD copied");
        }
    }
    // UPDATE: ZOCOUNT = 1 (RFC 2136 §3.1.1 "exactly one RR … else signal
    // FORMERR"), PRCOUNT / UPCOUNT ≤ 16, ADCOUNT ≤ 1 (docs/54 §6.2).
    for (zo, pr, up, ad) in [
        (0u16, 0u16, 0u16, 0u16),
        (2, 0, 0, 0),
        (1, 17, 0, 0),
        (1, 0, 17, 0),
        (1, 0, 0, 2),
    ] {
        let mut request = raw_header(0x2002, 5 << 11, zo, pr, up, ad);
        request.extend_from_slice(&raw_name("example.com"));
        request.extend_from_slice(&6u16.to_be_bytes());
        request.extend_from_slice(&IN.to_be_bytes());
        for transport in BOTH {
            let octets = reply_octets(&verdict(&request, transport));
            let header = decode_header(&octets, transport).unwrap();
            assert_eq!(header.rcode, Rcode::FORMERR);
            assert_eq!(header.opcode, 5);
            assert_eq!(octets.len(), 12);
        }
    }
}

#[test]
fn row6_malformed_bodies_udp_silent_tcp_formerr_docs54_6_6() {
    let good = query(0x2003, "server.example.com", 1, IN, true);
    let mut trailing = good.clone();
    trailing.push(0);
    let truncated = good[..good.len() - 2].to_vec();
    // A label whose length octet starts with `01` (RFC 1035 §4.1.4 reserved).
    let mut reserved = raw_header(0x2003, 0x0100, 1, 0, 0, 0);
    reserved.extend_from_slice(&[0x41, b'a', 0, 0, 1, 0, 1]);
    // A forward pointer as QNAME (docs/54 §6.3).
    let mut forward = raw_header(0x2003, 0x0100, 1, 0, 0, 0);
    forward.extend_from_slice(&raw_pointer(20));
    forward.extend_from_slice(&[0, 1, 0, 1]);
    for request in [trailing, truncated, reserved, forward] {
        assert!(matches!(
            verdict(&request, Transport::Udp),
            Verdict::Silence(Silence::Malformed)
        ));
        let octets = reply_octets(&verdict(&request, Transport::Tcp));
        assert_eq!(octets.len(), 12);
        let header = decode_header(&octets, Transport::Tcp).unwrap();
        assert_eq!(header.rcode, Rcode::FORMERR);
        assert!(header.rd);
    }
}

#[test]
fn row7_update_over_udp_is_refused_never_forwarded_q671() {
    // docs/54 §3.3: UPDATE only over TCP. UPDATE has no TC bit (RFC 2136
    // §2.2), so the interim is REFUSED, header only (Q-671).
    for tsig in [
        None,
        Some(request_tsig("key.example.com", "gss-tsig", 0x2004)),
    ] {
        let request = update(0x2004, "example.com", tsig);
        let octets = reply_octets(&verdict(&request, Transport::Udp));
        assert_eq!(octets.len(), 12);
        let header = decode_header(&octets, Transport::Udp).unwrap();
        assert_eq!((header.opcode, header.rcode), (5, Rcode::REFUSED));
        assert!(!header.tc, "no TC bit in an UPDATE header");
    }
}

#[test]
fn row8_unsigned_update_over_tcp_is_refused_rfc2136_3_3_1() {
    // docs/54 §4.5 step 1: dird never sees an unsigned UPDATE.
    let request = update(0x2005, "example.com", None);
    let octets = reply_octets(&verdict(&request, Transport::Tcp));
    assert_eq!(octets.len(), 12, "RFC 2136 §3.8: zero counts");
    let header = decode_header(&octets, Transport::Tcp).unwrap();
    assert_eq!(
        (header.opcode, header.rcode, header.id),
        (5, Rcode::REFUSED, 0x2005)
    );
}

#[test]
fn row9_update_with_a_non_gss_algorithm_is_badkey_unsigned_rfc8945_5_2_1() {
    // No shared TSIG secret exists anywhere (docs/54 §7.5): every other
    // algorithm is an unrecognized key — NOTAUTH + BADKEY, unsigned (§5.3.2:
    // MAC Size 0, empty MAC).
    for algorithm in ["hmac-sha256", "hmac-sha1", "HMAC-MD5.SIG-ALG.REG.INT"] {
        let tsig = request_tsig("key.example.com", algorithm, 0x2006);
        let request = update(0x2006, "example.com", Some(tsig.clone()));
        let reply = tcp(&rfc2782_zone(), &request);
        assert_eq!(reply.header.opcode, Opcode::Update);
        assert_eq!(reply.header.rcode, Rcode::NOTAUTH);
        assert!(reply.question.is_none());
        let back = reply.tsig.expect("TSIG RR in the response (RFC 8945 §5.2)");
        assert_eq!(back.error, TsigError::BADKEY);
        assert!(back.mac.as_bytes().is_empty());
        assert_eq!(back.key_name, tsig.key_name);
        assert_eq!(back.algorithm_name, tsig.algorithm_name);
        assert_eq!(back.original_id, 0x2006);
        assert_eq!(
            (back.time_signed, back.fudge),
            (tsig.time_signed, tsig.fudge)
        );
        assert!(back.other_data.is_empty());
    }
}

#[test]
fn row10_gss_tsig_update_over_tcp_is_forwarded_unchanged_docs54_4_5() {
    // The algorithm name compares as a name — case-insensitive (Q-642 item
    // 10).
    for algorithm in ["gss-tsig", "GSS-TSIG"] {
        let request = update(
            0x2007,
            "example.com",
            Some(request_tsig("k.example.com", algorithm, 0x2007)),
        );
        match verdict(&request, Transport::Tcp) {
            Verdict::Forward(forward) => {
                assert_eq!(forward.message(), request.as_slice());
                assert_eq!(forward.unavailable_reply().rcode(), Rcode::SERVFAIL);
                assert_eq!(forward.unavailable_reply().as_bytes().len(), 12);
            }
            other => panic!("expected forward, got {other:?}"),
        }
    }
    // The zone named is dird's to judge (docs/54 §6.6: NOTAUTH in dird).
    let foreign = update(
        0x2008,
        "example.org",
        Some(request_tsig("k.example.org", "gss-tsig", 0x2008)),
    );
    assert!(matches!(
        verdict(&foreign, Transport::Tcp),
        Verdict::Forward(_)
    ));
}

#[test]
fn row11_tsig_on_a_query_is_badkey_unsigned_docs54_7_5() {
    // dnsd knows no key: "If a non-forwarding server does not recognize the
    // key" — NOTAUTH + BADKEY, unsigned (RFC 8945 §5.2.1, §5.3.2).
    for algorithm in ["gss-tsig", "hmac-sha256"] {
        let mut message = query_msg(0x2009, &name("server.example.com"), 1, IN, true);
        message.tsig = Some(request_tsig("key.example.com", algorithm, 0x2009));
        let request = parse_dns::encode(&message).unwrap();
        for transport in BOTH {
            let zone = rfc2782_zone();
            let verdict = answer(ZoneState::Current(&zone), &request, transport);
            check(Some(&zone), &request, transport, &verdict);
            let reply = reply_message(&verdict, transport);
            assert_eq!(reply.header.rcode, Rcode::NOTAUTH);
            assert!(!reply.header.aa);
            assert!(
                reply.answer.is_empty(),
                "no data for a request that failed the key check"
            );
            assert_eq!(reply.tsig.expect("TSIG").error, TsigError::BADKEY);
        }
    }
}

#[test]
fn row12_unavailable_zone_is_servfail_docs54_4_4() {
    let request = query(0x200A, "server.example.com", 1, IN, false);
    for transport in BOTH {
        let verdict = answer(ZoneState::Unavailable, &request, transport);
        check(None, &request, transport, &verdict);
        let reply = reply_message(&verdict, transport);
        assert_eq!(reply.header.rcode, Rcode::SERVFAIL);
        assert!(reply.answer.is_empty() && reply.additional.is_empty());
        assert!(reply.question.is_some(), "header + question (docs/54 §6.5)");
    }
}

#[test]
fn row12_staleness_is_a_parameter_q616_item6() {
    let zone = rfc2782_zone();
    assert!(matches!(
        ZoneState::from_confirmation(&zone, 100, 160, 60),
        ZoneState::Current(_)
    ));
    assert!(matches!(
        ZoneState::from_confirmation(&zone, 100, 161, 60),
        ZoneState::Unavailable
    ));
    // A clock reading before the confirmation: fail closed.
    assert!(matches!(
        ZoneState::from_confirmation(&zone, 100, 99, 60),
        ZoneState::Unavailable
    ));
    assert!(matches!(
        ZoneState::from_confirmation(&zone, 0, u64::MAX, u64::MAX),
        ZoneState::Current(_)
    ));
}

#[test]
fn row13_policy_qtypes_are_refused_rfc1035_3_2_3() {
    // TSIG (250), AXFR (252), MAILB (253), MAILA (254), "*" (255) — docs/54
    // §6.6 "QTYPE ∈ {250, 252–255}"; refusals carry no data and no AA.
    for qtype in [250u16, 252, 253, 254, 255] {
        for qname in [
            "example.com",
            "server.example.com",
            "_ldap._tcp.example.com",
        ] {
            for transport in BOTH {
                let reply = match transport {
                    Transport::Udp => udp(&rfc2782_zone(), &query(0x200B, qname, qtype, IN, false)),
                    Transport::Tcp => tcp(&rfc2782_zone(), &query(0x200B, qname, qtype, IN, false)),
                };
                assert_eq!(reply.header.rcode, Rcode::REFUSED, "{qname}/{qtype}");
                assert!(!reply.header.aa);
                assert!(reply.answer.is_empty() && reply.additional.is_empty());
            }
        }
    }
}

#[test]
fn row14_classes_other_than_in_are_refused_rfc1034_3_7_1() {
    // QCLASS "*" answers "can never be authoritative" (RFC 1034 §3.7.1); every
    // class but IN is refused (docs/54 §6.4).
    for qclass in [0u16, 2, C_CH, 4, 254, 255, 65535] {
        let reply = udp(
            &rfc2782_zone(),
            &query(0x200C, "server.example.com", 1, qclass, false),
        );
        assert_eq!(reply.header.rcode, Rcode::REFUSED, "{qclass}");
        assert!(reply.answer.is_empty());
    }
}

#[test]
fn row15_names_outside_the_zone_are_refused_without_data_docs54_6_4() {
    // RFC 1034 §3.1: inside = ends with the zone's labels. "xexample.com" ends
    // with the octets but not the labels.
    for qname in [
        ".",
        "com",
        "example.org",
        "xexample.com",
        "server.example.net",
        "example.com.org",
    ] {
        for qtype in [1u16, 2, 6, 33] {
            let reply = udp(&rfc2782_zone(), &query(0x200D, qname, qtype, IN, true));
            assert_eq!(reply.header.rcode, Rcode::REFUSED, "{qname}");
            assert!(!reply.header.aa);
            assert!(reply.answer.is_empty() && reply.additional.is_empty());
        }
    }
}

#[test]
fn request_flags_and_z_are_ignored_rfc2136_2_2_q616_item5() {
    // AA, TC, RA and the Z bits of a request, and its RCODE, change nothing;
    // the reply's Z is zero.
    let zone = rfc2782_zone();
    let plain = udp(&zone, &raw_query(0x0000, 1, 0, 0, 0));
    let noisy = udp(
        &zone,
        &raw_query(0x0400 | 0x0200 | 0x0080 | 0x0070 | 0x0005, 1, 0, 0, 0),
    );
    assert_eq!(plain, noisy);
    let request = raw_query(0x0070, 1, 0, 0, 0);
    let verdict = run(&zone, &request, Transport::Udp);
    let octets = reply_octets(&verdict);
    assert_eq!(u16::from_be_bytes([octets[2], octets[3]]) & 0x0070, 0);
}

#[test]
fn unmodelled_additional_records_are_skipped_never_echoed_q616_item4() {
    // A record of a type parse-dns does not model (TXT, RFC 1035 §3.3.14) in
    // a query's additional section: skipped by RDLENGTH, never returned.
    let marker = [0xA5u8; 24];
    let request = with_additional(
        query(0x200E, "server.example.com", 1, IN, false),
        &raw_rr(&[0], T_TXT, IN, 0, &marker),
    );
    let zone = rfc2782_zone();
    let verdict = run(&zone, &request, Transport::Udp);
    check(Some(&zone), &request, Transport::Udp, &verdict);
    let octets = reply_octets(&verdict);
    assert!(!octets.windows(marker.len()).any(|w| w == marker));
    let reply = reply_message(&verdict, Transport::Udp);
    assert_eq!(reply.answer.len(), 1);
    assert!(reply.additional.is_empty());
}
