//! Attack tests from docs/54 §8 and §10.2 that fall to dnsd's answer
//! function: amplification bound, ANY / AXFR refused, zone walking, wildcard
//! and `_` names, out-of-zone names, unsigned or UDP UPDATE never forwarded,
//! oversize datagrams, reflection of client octets.
//!
//! Sources: docs/54 §3.2, §3.3, §5.3, §6.4, §6.5, §8, §10.2; RFC 1034 §4.3.3
//! ("A * label appearing in a query name has no special effect"); RFC 1035
//! §2.3.4, §4.1.1 (TC), §4.1.4 (compression), §4.2.1; RFC 8945 §5.2.1;
//! docs/questions/Q-616, Q-671, Q-672. Requests are hand-made.

mod common;

use common::*;
use dns_zone::limits::UDP_AMPLIFICATION_FACTOR;
use dns_zone::{
    answer, udp_reply_limit, KpasswdService, Silence, Transport, Verdict, ZoneImage,
    ZoneImageError, ZoneState,
};
use parse_dns::{Rcode, RrType};

const IN: u16 = 1;

fn reply_len(verdict: &Verdict<'_>) -> usize {
    match verdict {
        Verdict::Reply(reply) => reply.as_bytes().len(),
        other => panic!("expected a reply, got {other:?}"),
    }
}

#[test]
fn udp_amplification_is_bounded_by_k_docs54_6_5() {
    // A DC with eight addresses makes NS and SRV answers carry eight
    // additional A records: far over k × a short query. Over UDP the reply
    // becomes TC = 1 (header + question); over TCP the full answer goes out.
    let zone = eight_address_dc_zone();
    for (qname, qtype) in [
        ("example.com", 2u16),
        ("_ldap._tcp.example.com", 33),
        ("_kerberos._udp.example.com", 33),
    ] {
        let request = query(0x3001, qname, qtype, IN, false);
        let udp_verdict = run(&zone, &request, Transport::Udp);
        check(Some(&zone), &request, Transport::Udp, &udp_verdict);
        let Verdict::Reply(reply) = &udp_verdict else {
            panic!()
        };
        assert!(reply.is_truncated(), "{qname}: TC over UDP");
        assert_eq!(
            reply.as_bytes().len(),
            request.len(),
            "TC reply = header + question"
        );
        let full = tcp(&zone, &request);
        assert!(!full.header.tc);
        assert_eq!(full.additional.len(), 8);
        assert!(parse_dns::encode(&full).unwrap().len() > UDP_AMPLIFICATION_FACTOR * request.len());
    }
}

/// Over UDP: (full reply octets, truncated?) for one query.
fn measure(zone: &ZoneImage, qname: &str, qtype: u16) -> (usize, bool) {
    let request = query(0x3009, qname, qtype, IN, false);
    let full = parse_dns::encode(&tcp(zone, &request)).unwrap().len();
    let verdict = run(zone, &request, Transport::Udp);
    check(Some(zone), &request, Transport::Udp, &verdict);
    let Verdict::Reply(reply) = &verdict else {
        panic!()
    };
    (full, reply.is_truncated())
}

#[test]
fn k4_measured_against_phase1_answers_q672() {
    // Q-616 item 2 asks k = 4 to be measured "with the real SRV/A answers".
    // These fix the measured sizes (uncompressed encoding, docs/54 §6.3) that
    // docs/questions/Q-672 reports: everything fits for a short DC name with
    // one address; a second DC address or a long DC label pushes NS, SOA or
    // SRV answers over k × request, so those go TC = 1 over UDP.
    let mut parts = rfc2782_parts(KpasswdService::Present);
    parts.apex = common::name("corp.example.com");
    parts.soa.rname = common::name("hostmaster.corp.example.com");
    parts.hosts.clear();
    parts.dc = host("dc01", &[[172, 30, 79, 10]], 600);
    let one_address = ZoneImage::new(parts.clone()).unwrap();
    parts.dc = host("dc01", &[[172, 30, 79, 10], [10, 2, 0, 27]], 600);
    let two_addresses = ZoneImage::new(parts.clone()).unwrap();
    parts.dc = host("domaincontroller1", &[[172, 30, 79, 10]], 600);
    let long_label = ZoneImage::new(parts).unwrap();

    let apex = "corp.example.com";
    assert_eq!(measure(&one_address, apex, 6), (134, false));
    assert_eq!(measure(&one_address, apex, 2), (122, false));
    assert_eq!(
        measure(&one_address, "_ldap._tcp.corp.example.com", 33),
        (150, false)
    );
    assert_eq!(
        measure(&one_address, "_kerberos._udp.corp.example.com", 33),
        (158, false)
    );
    assert_eq!(measure(&two_addresses, apex, 2), (159, true));
    assert_eq!(
        measure(&two_addresses, "_ldap._tcp.corp.example.com", 33),
        (187, true)
    );
    assert_eq!(
        measure(&two_addresses, "_kerberos._udp.corp.example.com", 33),
        (195, false)
    );
    assert_eq!(measure(&long_label, apex, 6), (147, true));
    assert_eq!(measure(&long_label, apex, 2), (148, true));
    assert_eq!(
        measure(&long_label, "_ldap._tcp.corp.example.com", 33),
        (176, false)
    );
    // The RFC 2782 example zone: every phase-1 answer fits.
    let zone = rfc2782_zone_with_kpasswd();
    for (qname, qtype) in [
        ("example.com", 6u16),
        ("example.com", 2),
        ("server.example.com", 1),
        ("_kerberos._udp.example.com", 33),
        ("_kerberos._tcp.example.com", 33),
        ("_ldap._tcp.example.com", 33),
        ("_kpasswd._udp.example.com", 33),
    ] {
        assert!(!measure(&zone, qname, qtype).1, "{qname}");
    }
}

#[test]
fn udp_limit_function_docs54_6_5() {
    // ≤ 512 and ≤ k × request for answers; ≤ request for errors.
    assert_eq!(
        udp_reply_limit(Rcode::NOERROR, 29),
        29 * UDP_AMPLIFICATION_FACTOR
    );
    assert_eq!(udp_reply_limit(Rcode::NOERROR, 200), 512);
    for rcode in [
        Rcode::NXDOMAIN,
        Rcode::REFUSED,
        Rcode::FORMERR,
        Rcode::SERVFAIL,
        Rcode::NOTIMP,
        Rcode::NOTAUTH,
    ] {
        assert_eq!(udp_reply_limit(rcode, 40), 40);
        assert_eq!(udp_reply_limit(rcode, 512), 512);
    }
}

#[test]
fn badkey_reply_cannot_amplify_through_a_compressed_key_name_rfc1035_4_1_4() {
    // The TSIG key name may be a pointer to QNAME (2 octets in the request);
    // the canonical reply spells it out (docs/54 §6.3). With a long QNAME the
    // unsigned BADKEY reply would exceed the request: the error-reply bound
    // turns it into TC = 1 over UDP; TCP carries it whole.
    let zone = long_name_zone();
    let qname = format!("q.{}", "x".repeat(60))
        + "."
        + &"y".repeat(60)
        + "."
        + &"z".repeat(60)
        + ".example.com";
    let base = query(0x3002, &qname, 1, IN, false);
    // TSIG: NAME = pointer to the QNAME at offset 12, TYPE 250, CLASS ANY,
    // TTL 0 (RFC 8945 §4.2).
    let tsig = raw_rr(
        &raw_pointer(12),
        250,
        255,
        0,
        &raw_tsig_rdata("gss-tsig", &[0x11; 16], 0x3002),
    );
    let request = with_additional(base, &tsig);
    let udp_verdict = run(&zone, &request, Transport::Udp);
    check(Some(&zone), &request, Transport::Udp, &udp_verdict);
    let Verdict::Reply(reply) = &udp_verdict else {
        panic!()
    };
    assert!(reply.is_truncated());
    assert!(reply.as_bytes().len() <= request.len());
    let full = tcp(&zone, &request);
    assert_eq!(full.header.rcode, Rcode::NOTAUTH);
    assert!(full.tsig.is_some());
}

#[test]
fn any_axfr_and_mail_qtypes_are_refused_docs54_6_5_and_8() {
    // "QTYPE * ⇒ REFUSED — there is no "answer of every type"" (§6.5); AXFR
    // refused on both transports — no zone transfer (§3.2).
    for zone in all_zones() {
        for qtype in [
            RrType::ANY.0,
            RrType::AXFR.0,
            RrType::MAILA.0,
            RrType::MAILB.0,
        ] {
            let apex = zone.apex().clone();
            let request = parse_dns::encode(&query_msg(0x3003, &apex, qtype, IN, false)).unwrap();
            for transport in [Transport::Udp, Transport::Tcp] {
                let verdict = run(&zone, &request, transport);
                check(Some(&zone), &request, transport, &verdict);
                let reply = reply_message(&verdict, transport);
                assert_eq!(reply.header.rcode, Rcode::REFUSED);
                assert!(reply.answer.is_empty() && reply.additional.is_empty());
            }
        }
    }
}

#[test]
fn zone_walking_learns_only_the_name_asked_docs54_8() {
    // No NSEC (no DNSSEC in phase 1), no AXFR, no ANY: each reply holds only
    // records owned by QNAME, plus the DC's address for SRV / NS. A name the
    // client did not guess never appears in a reply.
    let zone = rfc2782_zone();
    let hidden = ["old-slow-box", "sysadmins-box", "new-fast-box"];
    for qname in [
        "example.com",
        "_ldap._tcp.example.com",
        "_tcp.example.com",
        "nosuch.example.com",
        "server.example.com",
    ] {
        for qtype in 0u16..=260 {
            let request = query(0x3004, qname, qtype, IN, false);
            for transport in [Transport::Udp, Transport::Tcp] {
                let verdict = run(&zone, &request, transport);
                check(Some(&zone), &request, transport, &verdict);
                if let Verdict::Reply(reply) = &verdict {
                    for label in hidden {
                        assert!(
                            !reply
                                .as_bytes()
                                .windows(label.len())
                                .any(|w| w == label.as_bytes()),
                            "{qname}/{qtype} leaked {label}"
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn wildcard_label_has_no_effect_rfc1034_4_3_3() {
    // "A * label appearing in a query name has no special effect": `*` never
    // matches (no wildcard is representable — docs/54 §5.3), so the answer is
    // a name error, and an image with a `*` host cannot be built.
    let zone = rfc2782_zone();
    for qname in [
        "*.example.com",
        "*._tcp.example.com",
        "*.server.example.com",
    ] {
        let reply = udp(&zone, &query(0x3005, qname, 1, IN, false));
        assert_eq!(reply.header.rcode, Rcode::NXDOMAIN, "{qname}");
        assert!(reply.answer.is_empty());
    }
    let mut parts = rfc2782_parts(KpasswdService::Absent);
    parts.hosts.push(host("*", &[[172, 30, 79, 40]], 600));
    assert_eq!(
        ZoneImage::new(parts).unwrap_err(),
        ZoneImageError::HostLabelNotLdh
    );
}

#[test]
fn underscore_names_cannot_be_hosts_docs54_5_3() {
    // A computer named like an SRV label cannot shadow the infrastructure
    // records: `_kerberos` is not an LDH label.
    for label in ["_kerberos", "_tcp", "_ldap"] {
        let mut parts = rfc2782_parts(KpasswdService::Present);
        parts.hosts.push(host(label, &[[172, 30, 79, 41]], 600));
        assert_eq!(
            ZoneImage::new(parts).unwrap_err(),
            ZoneImageError::HostLabelNotLdh
        );
    }
}

#[test]
fn no_data_for_names_outside_the_zone_docs54_6_4() {
    // No cache, no recursion, no root hints: outside the zone is REFUSED with
    // no record, whatever QTYPE and RD (docs/54 §3.2, §6.4).
    let zone = rfc2782_zone();
    for qname in ["example.net", "server.example.org", "com", "."] {
        for qtype in [1u16, 2, 6, 33, 255] {
            for rd in [false, true] {
                let reply = udp(&zone, &query(0x3006, qname, qtype, IN, rd));
                assert_eq!(reply.header.rcode, Rcode::REFUSED);
                assert!(!reply.header.ra, "no recursion offered");
                assert!(reply.answer.is_empty() && reply.additional.is_empty());
            }
        }
    }
}

#[test]
fn unsigned_or_udp_updates_never_reach_dird_docs54_4_5() {
    // "dird never sees an unsigned UPDATE" (§4.5 step 1); UPDATE only over
    // TCP (§3.3).
    let zone = rfc2782_zone();
    let cases: [(Vec<u8>, Transport); 4] = [
        (update(0x3007, "example.com", None), Transport::Tcp),
        (update(0x3007, "example.com", None), Transport::Udp),
        (
            update(
                0x3007,
                "example.com",
                Some(request_tsig("k.example.com", "gss-tsig", 0x3007)),
            ),
            Transport::Udp,
        ),
        (
            update(
                0x3007,
                "example.com",
                Some(request_tsig("k.example.com", "hmac-sha256", 0x3007)),
            ),
            Transport::Tcp,
        ),
    ];
    for (request, transport) in &cases {
        let verdict = run(&zone, request, *transport);
        check(Some(&zone), request, *transport, &verdict);
        assert!(!matches!(verdict, Verdict::Forward(_)));
    }
}

#[test]
fn oversize_udp_datagram_is_silent_docs54_10_2() {
    // "UDP 513 octets" (§10.2): silence, not decoded.
    let request = vec![0u8; 513];
    assert!(matches!(
        answer(ZoneState::Unavailable, &request, Transport::Udp),
        Verdict::Silence(Silence::OversizeDatagram)
    ));
    let request = vec![0u8; 65_536];
    assert!(matches!(
        answer(ZoneState::Unavailable, &request, Transport::Tcp),
        Verdict::Close
    ));
}

#[test]
fn error_replies_never_exceed_the_request_docs54_6_5() {
    // Refusals of every kind, with requests padded by a skipped additional
    // record: the reply is the header and question at most, never the pad.
    let zone = rfc2782_zone();
    let pad = raw_rr(&[0], T_TXT, IN, 0, &[0x5Cu8; 300]);
    for (qname, qtype, qclass) in [
        ("example.org", 1u16, IN),
        ("server.example.com", 255, IN),
        ("server.example.com", 1, C_CH),
        ("nosuch.example.com", 1, IN),
    ] {
        for padded in [false, true] {
            let base = query(0x3008, qname, qtype, qclass, false);
            let request = if padded {
                with_additional(base, &pad)
            } else {
                base
            };
            let verdict = run(&zone, &request, Transport::Udp);
            check(Some(&zone), &request, Transport::Udp, &verdict);
            assert!(reply_len(&verdict) <= 12 + raw_name(qname).len() + 4);
        }
    }
}
