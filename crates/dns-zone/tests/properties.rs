//! Property tests by exhaustive enumeration over bounded domains (no random
//! generator): every verdict satisfies the invariants of `common::check` —
//! the UDP size bound of docs/54 §6.5, re-decoding with parse-dns's Response
//! profile, ID / OPCODE / question echo, only A / NS / SOA / SRV data, no data
//! outside the zone, Forward only for a signed UPDATE over TCP — and `answer`
//! is total (never panics) on every truncation and single-octet mutation of
//! valid requests.
//!
//! Sources: docs/54 §6.4–§6.6, §10.2 ("amplification ratio ≤ k (property)");
//! RFC 1035 §4.1.1–§4.1.3 (the fields mutated). Requests are built from
//! typed values with parse-dns or by hand.

mod common;

use common::*;
use dns_zone::{answer, Transport, Verdict, ZoneImage, ZoneState};
use parse_dns::{Name, Rcode};

const TRANSPORTS: [Transport; 2] = [Transport::Udp, Transport::Tcp];

/// QNAMEs covering every node kind, case variants, empty non-terminals,
/// absent names inside the zone, deeper names, and names outside it.
fn qnames(zone: &ZoneImage) -> Vec<Name> {
    let apex = zone.apex().clone();
    let below = |prefix: &str| -> Name {
        let mut labels: Vec<Vec<u8>> = prefix.split('.').map(|l| l.as_bytes().to_vec()).collect();
        labels.extend(apex.labels().map(<[u8]>::to_vec));
        Name::from_labels(labels).expect("fits")
    };
    let dc_label = zone
        .dc_name()
        .labels()
        .next()
        .map(|l| String::from_utf8_lossy(l).into_owned())
        .expect("label");
    let mut out = vec![
        apex.clone(),
        below(&dc_label),
        below(&dc_label.to_ascii_uppercase()),
        below("_kerberos._udp"),
        below("_KERBEROS._TCP"),
        below("_ldap._tcp"),
        below("_kpasswd._tcp"),
        below("_kpasswd._udp"),
        below("_tcp"),
        below("_udp"),
        below("nosuch"),
        below("*"),
        below(&format!("x.{dc_label}")),
        below("a._ldap._tcp"),
        below("_ldap"),
        Name::root(),
        Name::from_dotted("example.org").unwrap(),
        Name::from_dotted("com").unwrap(),
    ];
    // The apex's parent, and a sibling that shares the apex's last octets.
    let labels: Vec<&[u8]> = apex.labels().collect();
    out.push(Name::from_labels(labels[1..].iter().copied()).unwrap());
    let mut sibling = labels.iter().map(|l| l.to_vec()).collect::<Vec<_>>();
    sibling[0].insert(0, b'x');
    if let Ok(name) = Name::from_labels(sibling) {
        out.push(name);
    }
    for host in ["old-slow-box", "new-fast-box", "sysadmins-box"] {
        out.push(below(host));
    }
    out
}

fn every_qtype() -> impl Iterator<Item = u16> {
    (0u16..=260).chain([65_280, 65_534, 65_535])
}

#[test]
fn every_query_satisfies_the_invariants_qtype_sweep() {
    let mut cases = 0usize;
    for zone in all_zones() {
        for qname in qnames(&zone) {
            for qtype in every_qtype() {
                for rd in [false, true] {
                    let request =
                        parse_dns::encode(&query_msg(0x4000, &qname, qtype, 1, rd)).unwrap();
                    for transport in TRANSPORTS {
                        let verdict = answer(ZoneState::Current(&zone), &request, transport);
                        check(Some(&zone), &request, transport, &verdict);
                        assert!(
                            matches!(verdict, Verdict::Reply(_)),
                            "a decodable query is answered"
                        );
                        cases += 1;
                    }
                }
            }
        }
    }
    assert!(cases > 90_000, "{cases}");
}

#[test]
fn every_query_satisfies_the_invariants_class_sweep() {
    for zone in all_zones() {
        for qname in qnames(&zone) {
            for qtype in [1u16, 2, 6, 33, 250, 252, 255] {
                for qclass in [0u16, 1, 2, 3, 4, 254, 255, 65_535] {
                    let request =
                        parse_dns::encode(&query_msg(0x4001, &qname, qtype, qclass, false))
                            .unwrap();
                    for transport in TRANSPORTS {
                        let verdict = answer(ZoneState::Current(&zone), &request, transport);
                        check(Some(&zone), &request, transport, &verdict);
                        if qclass != 1 {
                            let Verdict::Reply(reply) = &verdict else {
                                panic!()
                            };
                            assert_eq!(reply.rcode(), Rcode::REFUSED);
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn an_unavailable_zone_never_yields_data() {
    // docs/54 §4.4: stale ⇒ SERVFAIL; no record ever.
    let zone = rfc2782_zone();
    for qname in qnames(&zone) {
        for qtype in every_qtype() {
            let request = parse_dns::encode(&query_msg(0x4002, &qname, qtype, 1, false)).unwrap();
            for transport in TRANSPORTS {
                let verdict = answer(ZoneState::Unavailable, &request, transport);
                check(None, &request, transport, &verdict);
                let Verdict::Reply(reply) = &verdict else {
                    panic!()
                };
                assert_eq!(reply.rcode(), Rcode::SERVFAIL);
            }
        }
    }
}

/// Valid requests of every shape the table distinguishes.
fn base_requests(zone: &ZoneImage) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for qname in qnames(zone).into_iter().take(12) {
        for qtype in [1u16, 2, 6, 33, 255] {
            out.push(parse_dns::encode(&query_msg(0x4003, &qname, qtype, 1, true)).unwrap());
        }
    }
    let mut signed = query_msg(0x4004, zone.dc_name(), 1, 1, false);
    signed.tsig = Some(request_tsig("key.example.com", "gss-tsig", 0x4004));
    out.push(parse_dns::encode(&signed).unwrap());
    out.push(update(0x4005, "example.com", None));
    out.push(update(
        0x4006,
        "example.com",
        Some(request_tsig("k.example.com", "gss-tsig", 0x4006)),
    ));
    out.push(update(
        0x4007,
        "example.com",
        Some(request_tsig("k.example.com", "hmac-sha256", 0x4007)),
    ));
    out.push(with_additional(
        query(0x4008, "server.example.com", 1, 1, false),
        &raw_rr(&[0], T_TXT, 1, 0, &[0x77; 9]),
    ));
    out
}

#[test]
fn answer_is_total_on_truncations_and_mutations() {
    // Every prefix and every single-octet replacement of every base request,
    // on both transports, against a current and an unavailable zone: one
    // verdict each, satisfying the invariants (never a panic).
    let mutations = |original: u8| {
        [
            0x00u8,
            0xFF,
            0xC0,
            0x3F,
            0x80,
            original ^ 0x20,
            original.wrapping_add(1),
        ]
    };
    let mut cases = 0usize;
    for zone in [rfc2782_zone(), eight_address_dc_zone()] {
        for base in base_requests(&zone) {
            let mut variants = Vec::new();
            for len in 0..base.len() {
                variants.push(base[..len].to_vec());
            }
            for at in 0..base.len() {
                for value in mutations(base[at]) {
                    let mut mutated = base.clone();
                    mutated[at] = value;
                    variants.push(mutated);
                }
            }
            cases += variants.len();
            for request in &variants {
                for transport in TRANSPORTS {
                    let verdict = answer(ZoneState::Current(&zone), request, transport);
                    check(Some(&zone), request, transport, &verdict);
                    let verdict = answer(ZoneState::Unavailable, request, transport);
                    check(None, request, transport, &verdict);
                }
            }
        }
    }
    assert!(cases > 20_000, "{cases}");
}

#[test]
fn every_header_flag_and_opcode_combination() {
    // All 2^16 flag words on a fixed body: QR / OPCODE / AA / TC / RD / RA / Z
    // / RCODE in every combination (RFC 1035 §4.1.1).
    let zone = rfc2782_zone();
    let body = query(0x4009, "server.example.com", 1, 1, false);
    for flags in 0u16..=u16::MAX {
        let mut request = body.clone();
        request[2..4].copy_from_slice(&flags.to_be_bytes());
        for transport in TRANSPORTS {
            let verdict = answer(ZoneState::Current(&zone), &request, transport);
            check(Some(&zone), &request, transport, &verdict);
            let opcode = (flags >> 11) & 0x0F;
            match (flags & 0x8000 != 0, opcode) {
                (true, _) => assert!(matches!(verdict, Verdict::Silence(_))),
                (false, 0) => {
                    let Verdict::Reply(reply) = &verdict else {
                        panic!()
                    };
                    assert_eq!(reply.rcode(), Rcode::NOERROR);
                }
                // An UPDATE whose zone entry is the A question: forwarded
                // never (unsigned) — REFUSED.
                (false, 5) => {
                    let Verdict::Reply(reply) = &verdict else {
                        panic!()
                    };
                    assert_eq!(reply.rcode(), Rcode::REFUSED);
                }
                (false, _) => {
                    let Verdict::Reply(reply) = &verdict else {
                        panic!()
                    };
                    assert_eq!(reply.rcode(), Rcode::NOTIMP);
                }
            }
        }
    }
}
