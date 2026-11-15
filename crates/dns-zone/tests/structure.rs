//! Structure of the answers and of the zone image, each test naming the
//! section it follows.
//!
//! Sources: RFC 1034 §3.1, §4.3.1, §4.3.2; RFC 1035 §2.3.1, §2.3.3, §2.3.4,
//! §3.3.11, §3.3.13, §3.4.1, §4.1.1, §6.2; RFC 2136 §7.11; RFC 2782 (format,
//! Target, "Fictional example"); RFC 4120 §7.2.3.1–§7.2.3.3; [MS-ADTS]
//! v20261026 §6.3.2.3; docs/54 §3.1, §4.4, §5.3, §5.5, §6.4; docs/questions/
//! Q-614, Q-618. Zone values from RFC 2782's example (see tests/common).

mod common;

use common::*;
use dns_zone::limits::{MAX_HOST_ADDRESSES, MAX_HOST_RECORDS, MAX_TTL};
use dns_zone::{
    is_ldh_label, KpasswdService, SrvService, Transport, ZoneImage, ZoneImageError, ZoneImageParts,
    SRV_PRIORITY, SRV_WEIGHT,
};
use parse_dns::{Class, Name, RData, Rcode, ResourceRecord, Soa, Srv};
use std::net::Ipv4Addr;

const IN: u16 = 1;

fn a(addr: [u8; 4]) -> RData {
    RData::A(Ipv4Addr::from(addr))
}

fn rr(owner: &str, ttl: u32, rdata: RData) -> ResourceRecord {
    ResourceRecord {
        name: name(owner),
        class: Class::IN,
        ttl,
        rdata,
    }
}

// ---- answers -----------------------------------------------------------------

#[test]
fn soa_at_apex_rfc1035_3_3_13() {
    // RFC 1035 §3.3.13 layout; MNAME = the DC (docs/54 §3.1); TTL floored by
    // MINIMUM (§3.3.13, §6.2); "SOA records cause no additional section
    // processing".
    let zone = rfc2782_zone();
    let reply = udp(&zone, &query(0x1001, "example.com", 6, IN, false));
    assert_eq!(reply.header.rcode, Rcode::NOERROR);
    assert!(reply.header.aa);
    assert_eq!(
        reply.answer,
        vec![rr(
            "example.com",
            RFC2782_MINIMUM,
            RData::Soa(Soa {
                mname: name("server.example.com"),
                rname: name("root.example.com"),
                serial: RFC2782_SERIAL,
                refresh: RFC2782_REFRESH,
                retry: RFC2782_RETRY,
                expire: RFC2782_EXPIRE,
                minimum: RFC2782_MINIMUM,
            }),
        )]
    );
    assert!(reply.additional.is_empty());
}

#[test]
fn ns_at_apex_adds_the_dc_address_rfc1035_3_3_11() {
    // NS "cause both the usual additional section processing to locate a type
    // A record" (RFC 1035 §3.3.11); one server (OD-2, docs/54 §3.1).
    let zone = rfc2782_zone();
    let reply = udp(&zone, &query(0x1002, "example.com", 2, IN, false));
    assert_eq!(
        reply.answer,
        vec![rr(
            "example.com",
            RFC2782_MINIMUM,
            RData::Ns(name("server.example.com"))
        )]
    );
    assert_eq!(
        reply.additional,
        vec![rr(
            "server.example.com",
            RFC2782_MINIMUM,
            a([172, 30, 79, 10])
        )]
    );
}

/// A zone whose DC is the first KDC of RFC 4120 §7.2.3.3.
fn rfc4120_zone() -> ZoneImage {
    let mut parts = rfc2782_parts(KpasswdService::Absent);
    parts.dc = host("kdc1", &[[172, 30, 79, 10]], TTL_BELOW_MINIMUM);
    parts.hosts.clear();
    ZoneImage::new(parts).expect("valid image")
}

#[test]
fn kerberos_srv_records_rfc4120_7_2_3_3() {
    // "_kerberos._udp.EXAMPLE.COM. IN SRV 0 0 88 kdc1.example.com." and the
    // "_tcp" twin (RFC 4120 §7.2.3.3, the priority-0 KDC; a second KDC is not
    // representable in phase 1 — OD-2). The realm is written in upper case:
    // DNS matches it case-insensitively (§7.2.3.1).
    let zone = rfc4120_zone();
    for owner in ["_kerberos._udp.EXAMPLE.COM", "_kerberos._tcp.EXAMPLE.COM"] {
        let reply = udp(&zone, &query(0x1003, owner, 33, IN, true));
        assert_eq!(reply.header.rcode, Rcode::NOERROR);
        assert!(reply.header.aa);
        assert_eq!(reply.answer.len(), 1);
        let record = &reply.answer[0];
        assert_eq!(record.name, name(owner));
        assert_eq!(record.class, Class::IN);
        assert_eq!(
            record.rdata,
            RData::Srv(Srv {
                priority: 0,
                weight: 0,
                port: 88,
                target: name("kdc1.example.com"),
            })
        );
        // RFC 2782: Target addresses "in the Additional Data section".
        assert_eq!(
            reply.additional,
            vec![rr(
                "kdc1.example.com",
                RFC2782_MINIMUM,
                a([172, 30, 79, 10])
            )]
        );
    }
}

#[test]
fn ldap_srv_record_ms_adts_6_3_2_3() {
    // [MS-ADTS] §6.3.2.3: "_ldap._tcp.X"; Port "Set to 389 for LDAP service";
    // Target "the fully qualified DNS name of the server"; Class IN.
    let zone = rfc2782_zone();
    let reply = udp(
        &zone,
        &query(0x1004, "_ldap._tcp.example.com", 33, IN, false),
    );
    assert_eq!(
        reply.answer,
        vec![rr(
            "_ldap._tcp.example.com",
            RFC2782_MINIMUM,
            RData::Srv(Srv {
                priority: SRV_PRIORITY,
                weight: SRV_WEIGHT,
                port: 389,
                target: name("server.example.com"),
            }),
        )]
    );
}

#[test]
fn kpasswd_srv_only_when_kpasswd_exists_q618() {
    // docs/54 §3.1, Q-618 item 1: `_kpasswd` records only when the service
    // exists; [MS-ADTS] §6.3.2.3: port 464, both "_kpasswd._tcp.X" and
    // "_kpasswd._udp.X".
    let without = rfc2782_zone();
    let with = rfc2782_zone_with_kpasswd();
    for owner in ["_kpasswd._tcp.example.com", "_kpasswd._udp.example.com"] {
        let reply = udp(&without, &query(0x1005, owner, 33, IN, false));
        assert_eq!(reply.header.rcode, Rcode::NXDOMAIN);
        let reply = udp(&with, &query(0x1005, owner, 33, IN, false));
        assert_eq!(reply.header.rcode, Rcode::NOERROR);
        match &reply.answer[0].rdata {
            RData::Srv(srv) => assert_eq!(srv.port, 464),
            other => panic!("not SRV: {other:?}"),
        }
    }
    assert_eq!(without.srv_services().count(), 3);
    assert_eq!(with.srv_services().count(), 5);
}

#[test]
fn srv_set_names_and_ports_ms_adts_6_3_2_3_rfc4120_7_2_3_2() {
    // The closed phase-1 set (Q-618 item 1) with the names and ports of
    // [MS-ADTS] §6.3.2.3 and RFC 4120 §7.2.3.2.
    let expected: [(SrvService, &[u8], &[u8], u16); 5] = [
        (SrvService::KerberosUdp, b"_kerberos", b"_udp", 88),
        (SrvService::KerberosTcp, b"_kerberos", b"_tcp", 88),
        (SrvService::LdapTcp, b"_ldap", b"_tcp", 389),
        (SrvService::KpasswdTcp, b"_kpasswd", b"_tcp", 464),
        (SrvService::KpasswdUdp, b"_kpasswd", b"_udp", 464),
    ];
    for (service, svc, proto, port) in expected {
        assert_eq!(service.service_label(), svc);
        assert_eq!(service.proto_label(), proto);
        assert_eq!(service.port(), port);
    }
    // Both "udp" and "tcp" Kerberos records MUST be specified (RFC 4120
    // §7.2.3.2): present whatever the kpasswd setting.
    for kpasswd in [KpasswdService::Absent, KpasswdService::Present] {
        assert!(SrvService::KerberosUdp.synthesized_with(kpasswd));
        assert!(SrvService::KerberosTcp.synthesized_with(kpasswd));
    }
}

#[test]
fn srv_target_is_never_compressed_rfc2782() {
    // RFC 2782: "name compression is not to be used for this field". The reply
    // decodes under parse-dns's Response profile, which refuses every
    // pointer; and the Target's full wire form follows the SRV fixed fields.
    let zone = rfc2782_zone();
    let request = query(0x1006, "_kerberos._tcp.example.com", 33, IN, false);
    let verdict = run(&zone, &request, Transport::Udp);
    let dns_zone::Verdict::Reply(reply) = &verdict else {
        panic!("reply expected");
    };
    let mut srv_rdata = Vec::new();
    for field in [0u16, 0, 88] {
        srv_rdata.extend_from_slice(&field.to_be_bytes());
    }
    srv_rdata.extend_from_slice(&raw_name("server.example.com"));
    let octets = reply.as_bytes();
    assert!(octets
        .windows(srv_rdata.len())
        .any(|w| w == srv_rdata.as_slice()));
    assert!(reply_has_no_pointer(octets));
}

/// The Response profile refuses any compression pointer (Q-642 item 1).
fn reply_has_no_pointer(octets: &[u8]) -> bool {
    parse_dns::decode(octets, parse_dns::Profile::Response(Transport::Udp)).is_ok()
}

#[test]
fn host_a_records_rfc1035_3_4_1() {
    // "Hosts that have multiple Internet addresses will have multiple A
    // records"; "A records cause no additional section processing" (RFC 1035
    // §3.4.1). TTL above MINIMUM kept, below floored (§3.3.13).
    let zone = rfc2782_zone();
    let reply = udp(
        &zone,
        &query(0x1007, "new-fast-box.example.com", 1, IN, false),
    );
    assert_eq!(
        reply.answer,
        vec![
            rr(
                "new-fast-box.example.com",
                TTL_ABOVE_MINIMUM,
                a([172, 30, 79, 13])
            ),
            rr(
                "new-fast-box.example.com",
                TTL_ABOVE_MINIMUM,
                a([10, 2, 0, 27])
            ),
            rr(
                "new-fast-box.example.com",
                TTL_ABOVE_MINIMUM,
                a([128, 9, 0, 33])
            ),
        ]
    );
    assert!(reply.additional.is_empty());
    let reply = udp(
        &zone,
        &query(0x1008, "sysadmins-box.example.com", 1, IN, false),
    );
    assert_eq!(
        reply.answer,
        vec![rr(
            "sysadmins-box.example.com",
            RFC2782_MINIMUM,
            a([172, 30, 79, 12])
        )]
    );
}

#[test]
fn ttl_floor_is_minimum_rfc1035_3_3_13_and_6_2() {
    // "the TTL field is set to the maximum of the TTL field from the RR and the
    // MINIMUM field" — applied when copying into the response (§6.2).
    let zone = rfc2782_zone();
    assert_eq!(zone.minimum(), RFC2782_MINIMUM);
    for (qname, qtype) in [
        ("example.com", 6),
        ("example.com", 2),
        ("server.example.com", 1),
        ("old-slow-box.example.com", 1),
        ("_ldap._tcp.example.com", 33),
    ] {
        let reply = udp(&zone, &query(0x1009, qname, qtype, IN, false));
        for record in reply.answer.iter().chain(&reply.additional) {
            assert!(record.ttl >= RFC2782_MINIMUM);
        }
    }
}

#[test]
fn name_error_is_authoritative_without_soa_rfc1034_4_3_2_step_3c() {
    // "If the name is original, set an authoritative name error"; no "*"
    // label (docs/54 §6.4); no SOA in negative answers (docs/54 §6.4, Q-616
    // item 7 — RFC 1034 §4.3.4 makes it optional).
    let zone = rfc2782_zone();
    for qname in [
        "nosuch.example.com",
        "x.server.example.com",
        "a._kerberos._udp.example.com",
        "_kerberos.example.com",
        "_none.example.com",
        "_kerberos._sctp.example.com",
    ] {
        let reply = udp(&zone, &query(0x100A, qname, 1, IN, false));
        assert_eq!(reply.header.rcode, Rcode::NXDOMAIN, "{qname}");
        assert!(reply.header.aa);
        assert!(reply.answer.is_empty() && reply.additional.is_empty());
    }
}

#[test]
fn nodata_for_an_existing_name_rfc1034_4_3_2_step_3a() {
    // A whole match with no RR of QTYPE: NOERROR, empty answer, AA (docs/54
    // §6.4 step 3a); no CNAME anywhere (docs/54 §3.1); no A at the apex in
    // phase 1 ([MS-ADTS] §6.3.2.4 apex A waits for the Windows face — Q-618
    // item 2).
    let zone = rfc2782_zone();
    for (qname, qtype) in [
        ("server.example.com", T_MX),
        ("server.example.com", T_CNAME),
        ("server.example.com", T_TXT),
        ("server.example.com", 33),
        ("example.com", 1),
        ("example.com", 33),
        ("_ldap._tcp.example.com", 1),
        ("_kerberos._udp.example.com", T_PTR),
    ] {
        let reply = udp(&zone, &query(0x100B, qname, qtype, IN, false));
        assert_eq!(reply.header.rcode, Rcode::NOERROR, "{qname}/{qtype}");
        assert!(reply.header.aa);
        assert!(reply.answer.is_empty() && reply.additional.is_empty());
    }
}

#[test]
fn empty_non_terminal_is_nodata_rfc1034_3_1() {
    // `_tcp.example.com` lies on the path to `_ldap._tcp.example.com`: a node
    // whose resource set is empty (RFC 1034 §3.1), matched whole (§4.3.2 3a).
    let zone = rfc2782_zone();
    for qname in ["_tcp.example.com", "_UDP.example.com"] {
        for qtype in [1, 33, 6] {
            let reply = udp(&zone, &query(0x100C, qname, qtype, IN, false));
            assert_eq!(reply.header.rcode, Rcode::NOERROR, "{qname}");
            assert!(reply.header.aa);
            assert!(reply.answer.is_empty());
        }
    }
}

#[test]
fn names_match_case_insensitively_rfc1035_2_3_3() {
    // "all comparisons between character strings … are done in a
    // case-insensitive manner"; the reply echoes the question as received and
    // copies the zone's records with the zone's case (RFC 1035 §2.3.3: case
    // "should be preserved").
    let zone = rfc2782_zone();
    let request = query(0x100D, "SERVER.Example.COM", 1, IN, false);
    let reply = udp(&zone, &request);
    let question = reply.question.as_ref().expect("question");
    assert_eq!(
        question.qname.as_wire(),
        raw_name("SERVER.Example.COM").as_slice()
    );
    assert_eq!(reply.answer.len(), 1);
    assert_eq!(
        reply.answer[0].name.as_wire(),
        raw_name("server.example.com").as_slice()
    );
}

#[test]
fn header_fields_rfc1035_4_1_1_and_rfc1034_4_3_1() {
    // ID copied; RD "copied into the response"; RA = 0 — no recursive service
    // (RFC 1034 §4.3.1; docs/54 §3.2); OPCODE copied; Z zero.
    let zone = rfc2782_zone();
    for rd in [false, true] {
        let reply = udp(&zone, &query(0xBEEF, "server.example.com", 1, IN, rd));
        assert_eq!(reply.header.id, 0xBEEF);
        assert_eq!(reply.header.rd, rd);
        assert!(!reply.header.ra);
        assert!(reply.header.qr);
        assert_eq!(reply.header.opcode, parse_dns::Opcode::Query);
    }
}

#[test]
fn tcp_answers_equal_udp_answers_when_they_fit_rfc1035_4_2() {
    let zone = rfc2782_zone();
    let request = query(0x100E, "_ldap._tcp.example.com", 33, IN, false);
    assert_eq!(udp(&zone, &request), tcp(&zone, &request));
}

// ---- zone image validation --------------------------------------------------

fn build(edit: impl FnOnce(&mut ZoneImageParts)) -> Result<ZoneImage, ZoneImageError> {
    let mut parts = rfc2782_parts(KpasswdService::Present);
    edit(&mut parts);
    ZoneImage::new(parts)
}

#[test]
fn ldh_label_rule_rfc1035_2_3_1() {
    // "start with a letter, end with a letter or digit, and have as interior
    // characters only letters, digits, and hyphen … 63 characters or less".
    for good in ["a", "a1", "a-b", "server", "A-1-b", &"x".repeat(63)] {
        assert!(is_ldh_label(good.as_bytes()), "{good}");
    }
    let too_long = "x".repeat(64);
    for bad in [
        "",
        "*",
        "_kerberos",
        "_tcp",
        "1abc",
        "-ab",
        "ab-",
        "a.b",
        "a_b",
        "a b",
        &too_long,
    ] {
        assert!(!is_ldh_label(bad.as_bytes()), "{bad}");
    }
    assert!(!is_ldh_label(&[b'a', 0xC3, 0xA9]));
}

#[test]
fn host_label_must_be_one_ldh_label_docs54_5_3() {
    // `*`, `_` and dotted labels are unrepresentable: no wildcard, no SRV
    // shadowing, no multi-label host (docs/54 §5.3, §8).
    for label in ["*", "_kerberos", "_tcp", "9host", "a.b", "host-"] {
        assert_eq!(
            build(|p| p.hosts.push(host(label, &[[172, 30, 79, 30]], 600))).unwrap_err(),
            ZoneImageError::HostLabelNotLdh,
            "{label}"
        );
        assert_eq!(
            build(|p| p.dc.label = label.as_bytes().to_vec()).unwrap_err(),
            ZoneImageError::HostLabelNotLdh
        );
    }
}

#[test]
fn apex_rules_rfc1034_3_1_and_rfc1035_2_3_4() {
    assert_eq!(
        build(|p| p.apex = Name::root()).unwrap_err(),
        ZoneImageError::ApexIsRoot
    );
    assert_eq!(
        build(|p| p.apex = name("_msdcs.example.com")).unwrap_err(),
        ZoneImageError::ApexLabelNotLdh
    );
    // 241 octets of apex: "_kerberos._udp." (15 octets) would push the SRV
    // owner past 255 (RFC 1035 §2.3.4).
    let long = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(47)
    );
    assert_eq!(name(&long).wire_len(), 241);
    assert_eq!(
        build(|p| p.apex = name(&long)).unwrap_err(),
        ZoneImageError::ApexTooLong
    );
}

#[test]
fn host_name_must_fit_255_octets_rfc1035_2_3_4() {
    // 200-octet apex: SRV owners fit (15 + 200), a 63-octet host label does
    // not (64 + 200).
    let apex = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(6)
    );
    assert_eq!(name(&apex).wire_len(), 200);
    let label = "h".repeat(63);
    assert_eq!(
        build(|p| {
            p.apex = name(&apex);
            p.dc = host("dc", &[[172, 30, 79, 10]], 600);
            p.hosts = vec![host(&label, &[[172, 30, 79, 11]], 600)];
        })
        .unwrap_err(),
        ZoneImageError::HostNameTooLong
    );
}

#[test]
fn serial_is_never_zero_rfc2136_7_11() {
    assert_eq!(
        build(|p| p.serial = 0).unwrap_err(),
        ZoneImageError::SerialZero
    );
    assert!(build(|p| p.serial = 1).is_ok());
    assert!(build(|p| p.serial = u32::MAX).is_ok());
}

#[test]
fn ttls_are_positive_signed_32_bit_rfc1035_2_3_4() {
    let over = MAX_TTL + 1;
    assert_eq!(
        build(|p| p.infrastructure_ttl = over).unwrap_err(),
        ZoneImageError::TtlOutOfRange
    );
    assert_eq!(
        build(|p| p.soa.minimum = over).unwrap_err(),
        ZoneImageError::TtlOutOfRange
    );
    assert_eq!(
        build(|p| p.dc.ttl = over).unwrap_err(),
        ZoneImageError::TtlOutOfRange
    );
    assert_eq!(
        build(|p| p.hosts[0].ttl = over).unwrap_err(),
        ZoneImageError::TtlOutOfRange
    );
    assert!(build(|p| {
        p.infrastructure_ttl = MAX_TTL;
        p.soa.minimum = MAX_TTL;
        p.dc.ttl = MAX_TTL;
    })
    .is_ok());
}

#[test]
fn rname_names_a_mailbox_rfc1035_3_3_13() {
    assert_eq!(
        build(|p| p.soa.rname = Name::root()).unwrap_err(),
        ZoneImageError::RnameIsRoot
    );
}

#[test]
fn host_labels_are_unique_without_case_rfc1034_3_1() {
    // "you are free to create a node with label "A" or a node with label "a",
    // but not both as brothers".
    assert_eq!(
        build(|p| p.hosts.push(host("SERVER", &[[172, 30, 79, 31]], 600))).unwrap_err(),
        ZoneImageError::DuplicateHost
    );
    assert_eq!(
        build(|p| p
            .hosts
            .push(host("Old-Slow-Box", &[[172, 30, 79, 31]], 600)))
        .unwrap_err(),
        ZoneImageError::DuplicateHost
    );
}

#[test]
fn host_addresses_docs54_4_4_and_5_5() {
    // 1..=8 addresses (docs/54 §4.4), distinct, never loopback / unspecified /
    // multicast (docs/54 §5.5; Q-614 item 8).
    assert_eq!(
        build(|p| p.hosts[0].addresses.clear()).unwrap_err(),
        ZoneImageError::HostAddressCount
    );
    assert_eq!(
        build(|p| p.dc.addresses.clear()).unwrap_err(),
        ZoneImageError::HostAddressCount
    );
    let nine: Vec<Ipv4Addr> = (1..=9).map(|i| Ipv4Addr::new(172, 30, 79, i)).collect();
    assert_eq!(
        build(|p| p.hosts[0].addresses = nine[..MAX_HOST_ADDRESSES + 1].to_vec()).unwrap_err(),
        ZoneImageError::HostAddressCount
    );
    assert!(build(|p| p.hosts[0].addresses = nine[..MAX_HOST_ADDRESSES].to_vec()).is_ok());
    assert_eq!(
        build(|p| p.hosts[0].addresses = vec![Ipv4Addr::new(172, 30, 79, 11); 2]).unwrap_err(),
        ZoneImageError::DuplicateAddress
    );
    for bad in [
        Ipv4Addr::new(127, 0, 0, 1),
        Ipv4Addr::new(0, 0, 0, 0),
        Ipv4Addr::new(224, 0, 0, 1),
    ] {
        assert_eq!(
            build(|p| p.hosts[0].addresses = vec![bad]).unwrap_err(),
            ZoneImageError::AddressNotAllowed
        );
    }
}

#[test]
fn host_count_bound_docs54_4_4_q670() {
    // MAX_HOST_RECORDS counts the DC (Q-670 item 3).
    let hosts = |n: usize| -> Vec<dns_zone::HostRecordParts> {
        (0..n)
            .map(|i| {
                host(
                    &format!("h{i}"),
                    &[[10, (i >> 16) as u8 | 1, (i >> 8) as u8, i as u8]],
                    600,
                )
            })
            .collect()
    };
    let at_bound = build(|p| p.hosts = hosts(MAX_HOST_RECORDS - 1)).expect("at bound");
    assert_eq!(at_bound.host_count(), MAX_HOST_RECORDS);
    assert_eq!(
        build(|p| p.hosts = hosts(MAX_HOST_RECORDS)).unwrap_err(),
        ZoneImageError::TooManyHosts
    );
}

#[test]
fn image_accessors_and_debug_docs54_4_4_and_9() {
    let zone = rfc2782_zone();
    assert_eq!(zone.apex(), &name("example.com"));
    assert_eq!(zone.serial(), RFC2782_SERIAL);
    assert_eq!(zone.dc_name(), &name("server.example.com"));
    assert_eq!(zone.host_count(), 4);
    // The debug line names no host (docs/54 §9).
    let debug = format!("{zone:?}");
    assert!(!debug.contains("old-slow-box") && !debug.contains("172"));
}
