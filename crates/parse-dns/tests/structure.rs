//! Field layouts decode to the right values. Each test names the section whose
//! layout it builds by hand.

mod common;

use common::*;
use parse_dns::{
    decode, decode_header, Class, Error, Name, Opcode, Profile, RData, Rcode, RrType, Transport,
    TsigError,
};
use std::net::Ipv4Addr;

const UDP: Profile = Profile::Query(Transport::Udp);
const TCP: Profile = Profile::Query(Transport::Tcp);
const RESPONSE_UDP: Profile = Profile::Response(Transport::Udp);

fn n(dotted: &str) -> Name {
    Name::from_dotted(dotted).unwrap()
}

#[test]
fn header_bit_layout() {
    // Source: RFC 1035 §4.1.1 (QR | Opcode | AA | TC | RD | RA | Z | RCODE),
    // §2.3.2 (bit 0 is the most significant).
    let flags = QR | 0x0400 | 0x0200 | 0x0100 | 0x0080 | 0x0003;
    let wire = cat(&[
        &header(0xBEEF, flags, 1, 0, 0, 0),
        &question(&name("a"), T_A, C_IN),
    ]);
    let decoded = decode(&wire, RESPONSE_UDP).unwrap();
    let h = &decoded.message().header;
    assert_eq!(h.id, 0xBEEF);
    assert!(h.qr && h.aa && h.tc && h.rd && h.ra);
    assert_eq!(h.opcode, Opcode::Query);
    assert_eq!(h.rcode, Rcode::NXDOMAIN);

    // Each flag alone.
    for (bit, pick) in [(0x0400u16, 0usize), (0x0200, 1), (0x0100, 2), (0x0080, 3)] {
        let wire = cat(&[
            &header(1, QR | bit, 1, 0, 0, 0),
            &question(&name("a"), T_A, C_IN),
        ]);
        let h = decode(&wire, RESPONSE_UDP).unwrap().into_message().header;
        let got = [h.aa, h.tc, h.rd, h.ra];
        for (i, value) in got.iter().enumerate() {
            assert_eq!(*value, i == pick, "bit {bit:#06x}");
        }
    }
}

#[test]
fn z_bits_ignored_on_decode() {
    // Source: RFC 2136 §2.2 ("A non-zero Z field should be ignored"); docs/54
    // §6.2 (Z/AD/CD in a request — ignored); docs/questions/Q-616 item 5.
    let wire = cat(&[
        &header(1, QUERY | 0x0070, 1, 0, 0, 0),
        &question(&name("a"), T_A, C_IN),
    ]);
    let plain = cat(&[
        &header(1, QUERY, 1, 0, 0, 0),
        &question(&name("a"), T_A, C_IN),
    ]);
    assert_eq!(
        decode(&wire, UDP).unwrap().message(),
        decode(&plain, UDP).unwrap().message()
    );
    // And never encoded.
    assert_eq!(
        decode(&wire, UDP).unwrap().message().encode().unwrap(),
        plain
    );
}

#[test]
fn decode_header_reads_every_opcode_and_count() {
    // Source: RFC 1035 §4.1.1 (OPCODE 0–15; the four counts); docs/54 §6.6
    // (NOTIMP / FORMERR are answered from the header alone).
    for opcode in 0u16..16 {
        let wire = header(0x0102, (opcode << 11) | 0x0100, 1, 2, 3, 4);
        let h = decode_header(&wire, Transport::Udp).unwrap();
        assert_eq!(h.opcode, opcode as u8);
        assert_eq!(h.id, 0x0102);
        assert!(h.rd && !h.qr);
        assert_eq!((h.qdcount, h.ancount, h.nscount, h.arcount), (1, 2, 3, 4));
        assert_eq!(
            h.known_opcode(),
            match opcode {
                0 => Some(Opcode::Query),
                5 => Some(Opcode::Update),
                _ => None,
            }
        );
    }
}

#[test]
fn question_fields() {
    // Source: RFC 1035 §4.1.2 (QNAME, QTYPE, QCLASS; "this field may be an odd
    // number of octets; no padding is used").
    let wire = cat(&[
        &header(9, QUERY, 1, 0, 0, 0),
        &question(&name("_kerberos._udp.example.com"), T_SRV, C_IN),
    ]);
    let q = decode(&wire, UDP).unwrap().into_message().question.unwrap();
    assert_eq!(q.qname, n("_kerberos._udp.example.com"));
    assert_eq!(q.qtype, RrType::SRV);
    assert_eq!(q.qclass, Class::IN);
}

#[test]
fn a_record() {
    // Source: RFC 1035 §3.4.1 (ADDRESS: a 32 bit Internet address; the
    // example address "10.2.0.52").
    let wire = cat(&[
        &header(1, QR, 1, 1, 0, 0),
        &question(&name("host.example.com"), T_A, C_IN),
        &rr(&name("host.example.com"), T_A, C_IN, 3600, &[10, 2, 0, 52]),
    ]);
    let m = decode(&wire, RESPONSE_UDP).unwrap().into_message();
    let record = &m.answer[0];
    assert_eq!(record.name, n("host.example.com"));
    assert_eq!(record.class, Class::IN);
    assert_eq!(record.ttl, 3600);
    assert_eq!(record.rr_type(), RrType::A);
    assert_eq!(record.rdata, RData::A(Ipv4Addr::new(10, 2, 0, 52)));
}

#[test]
fn ns_record() {
    // Source: RFC 1035 §3.3.11 (NSDNAME).
    let wire = cat(&[
        &header(1, QR, 1, 1, 0, 0),
        &question(&name("example.com"), T_NS, C_IN),
        &rr(
            &name("example.com"),
            T_NS,
            C_IN,
            3600,
            &name("dc.example.com"),
        ),
    ]);
    let m = decode(&wire, RESPONSE_UDP).unwrap().into_message();
    assert_eq!(m.answer[0].rdata, RData::Ns(n("dc.example.com")));
}

#[test]
fn soa_record() {
    // Source: RFC 1035 §3.3.13 (MNAME, RNAME, SERIAL, REFRESH, RETRY,
    // EXPIRE, MINIMUM — unsigned 32-bit).
    let rdata = soa_rdata(
        &name("dc.example.com"),
        &name("hostmaster.example.com"),
        [0xFFFF_FFFF, 900, 600, 86400, 3600],
    );
    let wire = cat(&[
        &header(1, QR, 1, 1, 0, 0),
        &question(&name("example.com"), T_SOA, C_IN),
        &rr(&name("example.com"), T_SOA, C_IN, 3600, &rdata),
    ]);
    let m = decode(&wire, RESPONSE_UDP).unwrap().into_message();
    let RData::Soa(soa) = &m.answer[0].rdata else {
        panic!("SOA");
    };
    assert_eq!(soa.mname, n("dc.example.com"));
    assert_eq!(soa.rname, n("hostmaster.example.com"));
    assert_eq!(
        (soa.serial, soa.refresh, soa.retry, soa.expire, soa.minimum),
        (0xFFFF_FFFF, 900, 600, 86400, 3600)
    );
}

#[test]
fn srv_record() {
    // Source: RFC 2782 (Priority, Weight, Port — 16 bit unsigned, network
    // order — then Target; the lookup name `_ldap._tcp.example.com`).
    let wire = cat(&[
        &header(1, QR, 1, 1, 0, 0),
        &question(&name("_ldap._tcp.example.com"), T_SRV, C_IN),
        &rr(
            &name("_ldap._tcp.example.com"),
            T_SRV,
            C_IN,
            600,
            &srv_rdata(1, 65535, 389, &name("dc.example.com")),
        ),
    ]);
    let m = decode(&wire, RESPONSE_UDP).unwrap().into_message();
    let RData::Srv(srv) = &m.answer[0].rdata else {
        panic!("SRV");
    };
    assert_eq!((srv.priority, srv.weight, srv.port), (1, 65535, 389));
    assert_eq!(srv.target, n("dc.example.com"));
}

#[test]
fn srv_target_root_means_not_available() {
    // Source: RFC 2782 ("A Target of "." means that the service is decidedly
    // not available at this domain").
    let wire = cat(&[
        &header(1, QR, 1, 1, 0, 0),
        &question(&name("_ldap._tcp.example.com"), T_SRV, C_IN),
        &rr(
            &name("_ldap._tcp.example.com"),
            T_SRV,
            C_IN,
            0,
            &srv_rdata(0, 0, 0, &name(".")),
        ),
    ]);
    let m = decode(&wire, RESPONSE_UDP).unwrap().into_message();
    let RData::Srv(srv) = &m.answer[0].rdata else {
        panic!("SRV");
    };
    assert!(srv.target.is_root());
}

#[test]
fn update_prerequisite_forms() {
    // Source: RFC 2136 §2.4.1 (ANY, rdlength 0), §2.4.2 (zone class, full
    // RRset), §2.4.3 (NONE, rdlength 0), §2.4.4 (ANY ANY), §2.4.5 (NONE ANY).
    let host = name("host.example.com");
    let wire = cat(&[
        &header(3, UPDATE, 1, 5, 0, 0),
        &question(&name("example.com"), T_SOA, C_IN),
        &rr(&host, T_A, C_ANY, 0, &[]),
        &rr(&host, T_A, C_IN, 0, &[10, 2, 0, 52]),
        &rr(&host, T_A, C_NONE, 0, &[]),
        &rr(&host, T_ANY, C_ANY, 0, &[]),
        &rr(&host, T_ANY, C_NONE, 0, &[]),
    ]);
    let m = decode(&wire, TCP).unwrap().into_message();
    let zone = m.zone().unwrap();
    assert_eq!(
        (zone.qname.clone(), zone.qtype, zone.qclass),
        (n("example.com"), RrType::SOA, Class::IN)
    );
    let got: Vec<_> = m
        .prerequisites()
        .iter()
        .map(|r| (r.class, r.rdata.clone()))
        .collect();
    assert_eq!(
        got,
        vec![
            (Class::ANY, RData::Empty(RrType::A)),
            (Class::IN, RData::A(Ipv4Addr::new(10, 2, 0, 52))),
            (Class::NONE, RData::Empty(RrType::A)),
            (Class::ANY, RData::Empty(RrType::ANY)),
            (Class::NONE, RData::Empty(RrType::ANY)),
        ]
    );
    assert!(m.updates().is_empty());
}

#[test]
fn update_section_forms() {
    // Source: RFC 2136 §2.5.1 (add: zone class), §2.5.2 (delete RRset: ANY,
    // rdlength 0), §2.5.3 (delete all RRsets: ANY ANY), §2.5.4 (delete an RR:
    // NONE with the RDATA to match).
    let host = name("host.example.com");
    let wire = cat(&[
        &header(4, UPDATE, 1, 0, 4, 0),
        &question(&name("example.com"), T_SOA, C_IN),
        &rr(&host, T_A, C_IN, 300, &[192, 0, 5, 6]),
        &rr(&host, T_A, C_ANY, 0, &[]),
        &rr(&host, T_ANY, C_ANY, 0, &[]),
        &rr(&host, T_A, C_NONE, 0, &[192, 0, 5, 6]),
    ]);
    let m = decode(&wire, TCP).unwrap().into_message();
    let got: Vec<_> = m
        .updates()
        .iter()
        .map(|r| (r.class, r.ttl, r.rdata.clone()))
        .collect();
    assert_eq!(
        got,
        vec![
            (Class::IN, 300, RData::A(Ipv4Addr::new(192, 0, 5, 6))),
            (Class::ANY, 0, RData::Empty(RrType::A)),
            (Class::ANY, 0, RData::Empty(RrType::ANY)),
            (Class::NONE, 0, RData::A(Ipv4Addr::new(192, 0, 5, 6))),
        ]
    );
}

#[test]
fn update_header_uses_only_qr() {
    // Source: RFC 2136 §2.2 ("UPDATE uses only one flag bit (QR)"; the other
    // positions are Z, "should be ignored").
    let wire = cat(&[
        &header(5, UPDATE | 0x0780 | 0x0070, 1, 0, 0, 0),
        &question(&name("example.com"), T_SOA, C_IN),
    ]);
    let h = decode(&wire, TCP).unwrap().into_message().header;
    assert_eq!(h.opcode, Opcode::Update);
    assert!(!h.aa && !h.tc && !h.rd && !h.ra);
}

#[test]
fn query_has_no_update_sections() {
    // Source: RFC 2136 §2 (the section names apply to UPDATE only).
    let wire = cat(&[
        &header(1, QUERY, 1, 0, 0, 0),
        &question(&name("a"), T_A, C_IN),
    ]);
    let m = decode(&wire, UDP).unwrap().into_message();
    assert!(m.zone().is_none());
    assert!(m.prerequisites().is_empty() && m.updates().is_empty());
    assert!(m.question.is_some());
}

#[test]
fn unknown_type_is_skipped_not_retained() {
    // Source: docs/54 §6.1 ("any other type: opaque RDATA bounded by RDLENGTH,
    // kept only for skipping"), §6.4 (additional records of a query are
    // skipped by RDLENGTH, never echoed); docs/questions/Q-616 item 4.
    let wire = cat(&[
        &header(1, QUERY, 1, 0, 0, 1),
        &question(&name("a.example.com"), T_A, C_IN),
        &rr(&name(""), 41, 4096, 0, &[0xDE, 0xAD, 0xBE, 0xEF, 0x00]),
    ]);
    let m = decode(&wire, UDP).unwrap().into_message();
    assert_eq!(
        m.additional[0].rdata,
        RData::Unknown {
            rr_type: RrType(41),
            rdlength: 5
        }
    );
    assert_eq!(m.additional[0].class, Class(4096));
}

#[test]
fn class_other_than_in_is_carried_for_policy() {
    // Source: docs/54 §6.6 (QCLASS ≠ IN ⇒ REFUSED is dnsd's decision, not a
    // decode error); RFC 1035 §3.2.4 (CH = 3); RFC 1034 §3.6 (the A RDATA
    // format differs by class, so an A record of class CH is not typed).
    let wire = cat(&[
        &header(1, QUERY, 1, 0, 0, 1),
        &question(&name("a.example.com"), T_A, C_CH),
        &rr(
            &name("a.example.com"),
            T_A,
            C_CH,
            0,
            &cat(&[&name("x"), &[0, 1]]),
        ),
    ]);
    let m = decode(&wire, UDP).unwrap().into_message();
    assert_eq!(m.question.unwrap().qclass, Class(3));
    assert_eq!(
        m.additional[0].rdata,
        RData::Unknown {
            rr_type: RrType::A,
            rdlength: 5
        }
    );
}

#[test]
fn qtype_values_are_carried_for_policy() {
    // Source: RFC 1035 §3.2.3 (AXFR 252, MAILB 253, MAILA 254, * 255); docs/54
    // §3.2, §6.6 (REFUSED by dnsd policy, not a decode error).
    for qtype in [252u16, 253, 254, 255, 250, 28] {
        let wire = cat(&[
            &header(1, QUERY, 1, 0, 0, 0),
            &question(&name("a"), qtype, C_IN),
        ]);
        let q = decode(&wire, UDP).unwrap().into_message().question.unwrap();
        assert_eq!(q.qtype, RrType(qtype));
    }
    assert_eq!(RrType::AXFR, RrType(252));
    assert_eq!(RrType::ANY, RrType(255));
}

#[test]
fn tsig_fields() {
    // Source: RFC 8945 §4.2 (NAME, TYPE 250, CLASS ANY, TTL 0; Algorithm Name,
    // Time Signed (48 bits), Fudge, MAC Size, MAC, Original ID, Error, Other
    // Len, Other Data); RFC 3645 §8 (gss-tsig).
    let alg = name("GSS-TSIG");
    let mac: Vec<u8> = (0u8..28).collect();
    let fields = TsigFields {
        algorithm: &alg,
        time_signed: 0x0000_8000_0000_0001,
        fudge: 300,
        mac: &mac,
        original_id: 0x4321,
        error: 0,
        other: &[9, 8, 7],
    };
    let wire = cat(&[
        &header(0x4321, QUERY, 1, 0, 0, 1),
        &question(&name("a.example.com"), T_A, C_IN),
        &tsig_rr(&name("key.example.com"), &tsig_rdata(&fields)),
    ]);
    let m = decode(&wire, UDP).unwrap().into_message();
    let tsig = m.tsig.unwrap();
    assert!(m.additional.is_empty());
    assert_eq!(tsig.key_name, n("key.example.com"));
    assert_eq!(tsig.algorithm_name, n("gss-tsig"));
    assert!(
        tsig.algorithm_is_gss_tsig(),
        "compared as a name, case-insensitively"
    );
    assert_eq!(tsig.time_signed.seconds(), 0x8000_0000_0001);
    assert_eq!(tsig.fudge, 300);
    assert_eq!(tsig.mac.as_bytes(), &mac[..]);
    assert_eq!(tsig.original_id, 0x4321);
    assert_eq!(tsig.error, TsigError::NOERROR);
    assert_eq!(tsig.other_data, vec![9, 8, 7]);
}

#[test]
fn tsig_other_algorithm_is_not_gss_tsig() {
    // Source: RFC 8945 §6 (Table 3 names; hmac-sha256); docs/54 §4.5 step 1
    // (algorithm ≠ gss-tsig ⇒ BADKEY in dnsd — the decision is the caller's).
    for algorithm in ["hmac-sha256", "gss-tsig.example", "gss"] {
        let alg = name(algorithm);
        let mac = [0u8; 32];
        let wire = cat(&[
            &header(1, QUERY, 1, 0, 0, 1),
            &question(&name("a"), T_A, C_IN),
            &tsig_rr(&name("k"), &tsig_rdata(&gss_tsig_fields(&alg, &mac, 1))),
        ]);
        let tsig = decode(&wire, UDP).unwrap().into_message().tsig.unwrap();
        assert!(!tsig.algorithm_is_gss_tsig(), "{algorithm}");
    }
}

#[test]
fn tsig_response_error_and_empty_mac() {
    // Source: RFC 8945 §5.3.2 (unsigned error: "MAC Size == 0 and empty MAC"),
    // §5.2.3 (BADTIME: Other Len 6, the server's time in Other Data), §3.
    let alg = name("gss-tsig");
    let fields = TsigFields {
        algorithm: &alg,
        time_signed: 1_700_000_000,
        fudge: 300,
        mac: &[],
        original_id: 7,
        error: 18,
        other: &[0, 0, 0x65, 0x53, 0xF1, 0x00],
    };
    let wire = cat(&[
        &header(7, QR | UPDATE | 9, 0, 0, 0, 1),
        &tsig_rr(&name("key.example.com"), &tsig_rdata(&fields)),
    ]);
    let m = decode(&wire, Profile::Response(Transport::Tcp))
        .unwrap()
        .into_message();
    assert_eq!(m.header.rcode, Rcode::NOTAUTH);
    let tsig = m.tsig.unwrap();
    assert_eq!(tsig.error, TsigError::BADTIME);
    assert!(tsig.mac.as_bytes().is_empty());
    assert_eq!(tsig.other_data.len(), 6);
}

#[test]
fn forwarded_profile_accepts_signed_update() {
    // Source: docs/54 §4.5, §6.1 (dird decodes the forwarded octets with the
    // same crate and bounds; the TSIG is present).
    let wire = signed_update(0x0A0B);
    let decoded = decode(&wire, Profile::Forwarded).unwrap();
    let m = decoded.message();
    assert_eq!(m.zone().unwrap().qname, n("example.com"));
    assert_eq!(m.updates()[0].rdata, RData::A(Ipv4Addr::new(10, 2, 0, 52)));
    assert!(m.tsig.as_ref().unwrap().algorithm_is_gss_tsig());
    assert_eq!(decoded.wire(), &wire[..]);
}

#[test]
fn request_mac_input_components() {
    // Source: RFC 8945 §4.3.2 (verify against the message with the TSIG RR
    // removed, ARCOUNT decremented, ID replaced by the Original ID), §4.3.1
    // Table 1 (Request MAC = MAC Size ‖ MAC Data exactly as transmitted).
    let alg = name("gss-tsig");
    let mac: Vec<u8> = (100u8..128).collect();
    let body = cat(&[
        &question(&name("example.com"), T_SOA, C_IN),
        &rr(&name("host.example.com"), T_A, C_IN, 300, &[10, 2, 0, 52]),
    ]);
    // Message ID 0x1111, Original ID 0x2222 (as when a request is forwarded,
    // RFC 8945 §4.2 "Original ID").
    let unsigned = cat(&[&header(0x1111, UPDATE, 1, 0, 1, 0), &body]);
    let wire = cat(&[
        &header(0x1111, UPDATE, 1, 0, 1, 1),
        &body,
        &tsig_rr(
            &name("key.example.com"),
            &tsig_rdata(&gss_tsig_fields(&alg, &mac, 0x2222)),
        ),
    ]);
    let decoded = decode(&wire, Profile::Forwarded).unwrap();
    let component = decoded.tsig_message_component().unwrap();
    let mut expected = unsigned.clone();
    expected[0..2].copy_from_slice(&0x2222u16.to_be_bytes());
    assert_eq!(component, expected);
    assert_eq!(&component[2..], &unsigned[2..]);

    let request_mac = decoded.request_mac_component().unwrap();
    assert_eq!(&request_mac[..2], &[0, 28]);
    assert_eq!(&request_mac[2..], &mac[..]);
}

#[test]
fn no_tsig_no_mac_components() {
    // Source: RFC 8945 §4.3 (the components exist only for a TSIG).
    let wire = cat(&[
        &header(1, QUERY, 1, 0, 0, 0),
        &question(&name("a"), T_A, C_IN),
    ]);
    let decoded = decode(&wire, UDP).unwrap();
    assert!(decoded.tsig_message_component().is_none());
    assert!(decoded.request_mac_component().is_none());
}

#[test]
fn outgoing_message_component_excludes_tsig() {
    // Source: RFC 8945 §4.3.2 ("before the TSIG RR has been added to the
    // additional section and before the DNS Message Header's ARCOUNT has been
    // incremented").
    let wire = signed_update(0x0C0D);
    let mut response = decode(&wire, Profile::Forwarded).unwrap().into_message();
    response.header.qr = true;
    response.question = None;
    response.authority.clear();
    let component = response.tsig_message_component().unwrap();
    assert_eq!(component, header(0x0C0D, QR | UPDATE, 0, 0, 0, 0));
    let full = response.encode().unwrap();
    assert_eq!(&full[..10], &component[..10]);
    assert_eq!(&full[10..12], &[0, 1], "ARCOUNT counts the TSIG");
    assert_eq!(&full[12..], &tsig_part(&wire)[..]);
}

/// The TSIG RR at the end of `signed_update` (key name 17 octets, RDATA).
fn tsig_part(wire: &[u8]) -> Vec<u8> {
    let alg = name("gss-tsig");
    let mac = [0xA5u8; 28];
    let id = u16::from_be_bytes([wire[0], wire[1]]);
    tsig_rr(
        &name("key.example.com"),
        &tsig_rdata(&gss_tsig_fields(&alg, &mac, id)),
    )
}

#[test]
fn name_value_rules() {
    // Source: RFC 1035 §3.1 (case-insensitive comparison for ASCII letters,
    // exact for other codes), §2.3.3 (case preserved); RFC 1034 §3.1 (printed
    // form, subdomain test by suffix).
    let upper = n("A.ISI.EDU");
    let lower = n("a.isi.edu.");
    assert_eq!(upper, lower);
    assert_ne!(upper.as_wire(), lower.as_wire());
    assert_ne!(n("a-b.edu"), n("a_b.edu"));
    assert_ne!(
        Name::from_labels([&[0xC1u8][..]]).unwrap(),
        Name::from_labels([&[0xE1u8][..]]).unwrap()
    );
    assert_eq!(upper.label_count(), 3);
    assert_eq!(
        upper.labels().collect::<Vec<_>>(),
        vec![&b"A"[..], b"ISI", b"EDU"]
    );
    assert!(n("A.B.C.D").is_subdomain_of(&n("b.c.d")));
    assert!(n("A.B.C.D").is_subdomain_of(&n("A.B.C.D")));
    assert!(n("A.B.C.D").is_subdomain_of(&Name::root()));
    assert!(!n("XB.C.D").is_subdomain_of(&n("B.C.D")));
    assert!(!n("C.D").is_subdomain_of(&n("B.C.D")));
    assert!(Name::root().is_root());
    assert_eq!(Name::from_dotted(".").unwrap(), Name::root());
    assert_eq!(
        Name::decode_uncompressed(&name("F.ISI.ARPA")).unwrap(),
        n("f.isi.arpa")
    );
}

#[test]
fn debug_output_never_shows_mac_key_name_or_octets() {
    // Source: docs/54 §9 ("never in a log: message octets, GSS tokens, MICs …
    // raw key_name"); docs/CLEAN-ROOM.md `Debug` of the decoded types shows only
    // lengths for these fields.
    let alg = name("gss-tsig");
    let mac = [0xE7u8; 28];
    let wire = cat(&[
        &header(5, UPDATE, 1, 0, 0, 1),
        &question(&name("example.com"), T_SOA, C_IN),
        &tsig_rr(
            &name("zq-private-key-label.example.com"),
            &tsig_rdata(&gss_tsig_fields(&alg, &mac, 5)),
        ),
    ]);
    let decoded = decode(&wire, Profile::Forwarded).unwrap();
    for text in [
        format!("{decoded:?}"),
        format!("{:?}", decoded.message()),
        format!("{:?}", decoded.message().tsig),
    ] {
        assert!(!text.contains("zq-private-key-label"), "{text}");
        assert!(!text.contains("231"), "MAC octets: {text}");
        assert!(text.contains("28 octets"), "{text}");
    }
    assert!(!format!("{decoded:?}").contains("[0, 5"), "no raw octets");
}

#[test]
fn name_constructor_bounds() {
    // Source: RFC 1035 §2.3.4, §3.1 (label ≤ 63, name ≤ 255); RFC 1034 §3.1
    // (the null label is the root's).
    assert!(Name::from_labels([[b'x'; 63]]).is_ok());
    assert_eq!(
        Name::from_labels([[b'x'; 64]]).unwrap_err(),
        Error::LabelTooLong
    );
    assert_eq!(Name::from_dotted("a..b").unwrap_err(), Error::EmptyLabel);
    assert_eq!(Name::from_dotted("").unwrap_err(), Error::EmptyLabel);
    // 127 one-octet labels: 254 + 1 = 255 octets.
    let labels = vec![[b'z'; 1]; 127];
    let longest = Name::from_labels(&labels).unwrap();
    assert_eq!((longest.wire_len(), longest.label_count()), (255, 127));
    let labels = vec![[b'z'; 1]; 128];
    assert_eq!(Name::from_labels(&labels).unwrap_err(), Error::NameTooLong);
    // decode_uncompressed refuses pointers and trailing octets.
    assert_eq!(
        Name::decode_uncompressed(&[0xC0, 0x0C]).unwrap_err(),
        Error::CompressionNotAllowed
    );
    assert_eq!(
        Name::decode_uncompressed(&[0, 0]).unwrap_err(),
        Error::TrailingData
    );
    assert_eq!(
        Name::decode_uncompressed(&[3, b'a']).unwrap_err(),
        Error::Truncated
    );
    assert_eq!(
        Name::decode_uncompressed(&[0x40]).unwrap_err(),
        Error::ReservedLabelType
    );
}
