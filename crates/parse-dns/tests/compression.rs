//! Name compression (RFC 1035 §4.1.4) and its strict rules (docs/54 §6.3;
//! docs/questions/Q-640).
//!
//! Each test names its source. The first test embeds the RFC 1035 §4.1.4
//! example — F.ISI.ARPA at offset 20, FOO.F.ISI.ARPA at 40, ARPA at 64 and the
//! root at 92, octet for octet as in the figure — inside a message whose
//! other fields are built by hand around it.

mod common;

use common::*;
use parse_dns::{decode, Error, Name, Profile, RData, Transport};

const TCP: Profile = Profile::Query(Transport::Tcp);

fn n(dotted: &str) -> Name {
    Name::from_dotted(dotted).unwrap()
}

/// The octets the RFC 1035 §4.1.4 figure shows at each offset.
fn figure() -> [(usize, Vec<u8>); 4] {
    [
        // 20: 1 F | 3 I | S I | 4 A | R P | A 0
        (
            20,
            vec![1, b'F', 3, b'I', b'S', b'I', 4, b'A', b'R', b'P', b'A', 0],
        ),
        // 40: 3 F | O O | 1 1 | 20
        (40, vec![3, b'F', b'O', b'O', 0xC0, 20]),
        // 64: 1 1 | 26
        (64, vec![0xC0, 26]),
        // 92: 0
        (92, vec![0]),
    ]
}

/// The message around the figure (QUERY request, one question, three
/// additional records — within the docs/54 §6.2 QUERY bounds):
///
/// | offset | content |
/// |---|---|
/// | 0–11 | header (RFC 1035 §4.1.1) |
/// | 12–31 | QNAME `XXXXXXX.F.ISI.ARPA` — the F.ISI.ARPA of the figure at 20 |
/// | 32–35 | QTYPE A, QCLASS IN |
/// | 36–45 | AR1 owner `BAR` + the figure's FOO.F.ISI.ARPA at 40 (pointer to 20) |
/// | 46–55 | AR1 TYPE NS, CLASS IN, TTL, RDLENGTH 10 |
/// | 56–65 | AR1 NSDNAME `YYYYYYY` + the figure's ARPA at 64 (pointer to 26) |
/// | 66–77 | AR2 owner `ZZZZZZZZZ` + pointer to 64 (a pointer to a pointer) |
/// | 78–91 | AR2 TYPE A, CLASS IN, TTL, RDLENGTH 4, 10.2.0.52 (RFC 1035 §3.4.1) |
/// | 92 | AR3 owner: the figure's root at 92 |
/// | 93–104 | AR3 TYPE NS, CLASS IN, TTL, RDLENGTH 2, pointer to 40 |
fn rfc1035_example_message() -> Vec<u8> {
    let qname = cat(&[&[7], b"XXXXXXX", &name("F.ISI.ARPA")]);
    let ar1_owner = cat(&[&[3], b"BAR", &[3], b"FOO", &pointer(20)]);
    let ar1_rdata = cat(&[&[7], b"YYYYYYY", &pointer(26)]);
    let ar2_owner = cat(&[&[9], b"ZZZZZZZZZ", &pointer(64)]);
    let message = cat(&[
        &header(0x1234, QUERY, 1, 0, 0, 3),
        &question(&qname, T_A, C_IN),
        &rr(&ar1_owner, T_NS, C_IN, 3600, &ar1_rdata),
        &rr(&ar2_owner, T_A, C_IN, 3600, &[10, 2, 0, 52]),
        &rr(&name(""), T_NS, C_IN, 3600, &pointer(40)),
    ]);
    assert_eq!(message.len(), 105);
    message
}

#[test]
fn rfc1035_section_4_1_4_example() {
    // Source: RFC 1035 §4.1.4 (the F.ISI.ARPA / FOO.F.ISI.ARPA / ARPA / root
    // figure, offsets 20/40/64/92).
    let message = rfc1035_example_message();
    for (offset, octets) in figure() {
        assert_eq!(
            &message[offset..offset + octets.len()],
            &octets[..],
            "offset {offset}"
        );
    }

    let decoded = decode(&message, TCP).unwrap();
    let m = decoded.message();
    assert_eq!(m.question.as_ref().unwrap().qname, n("XXXXXXX.F.ISI.ARPA"));
    let [ar1, ar2, ar3] = &m.additional[..] else {
        panic!("three additional records");
    };
    // "FOO.F.ISI.ARPA is shown at offset 40; this definition uses a pointer to
    // concatenate a label for FOO to the previously defined F.ISI.ARPA."
    assert_eq!(ar1.name, n("BAR.FOO.F.ISI.ARPA"));
    // "The domain name ARPA is defined at offset 64 using a pointer to the
    // ARPA component of the name F.ISI.ARPA at 20."
    assert_eq!(ar1.rdata, RData::Ns(n("YYYYYYY.ARPA")));
    assert_eq!(ar2.name, n("ZZZZZZZZZ.ARPA"));
    // "The root domain name is defined by a single octet of zeros at 92."
    assert!(ar3.name.is_root());
    assert_eq!(ar3.rdata, RData::Ns(n("FOO.F.ISI.ARPA")));
    // Case is preserved as received (RFC 1035 §2.3.3).
    assert_eq!(ar3.rdata, RData::Ns(n("foo.f.isi.arpa")));
    if let RData::Ns(target) = &ar3.rdata {
        assert_eq!(target.as_wire(), &name("FOO.F.ISI.ARPA")[..]);
    }
}

#[test]
fn rfc1035_example_names_in_canonical_reencoding() {
    // Source: RFC 1035 §4.1.4 ("Programs are free to avoid using pointers in
    // messages they generate"); docs/54 §6.3 — the re-encoding carries every
    // name in full: as a response it reads back under the profile that
    // refuses every pointer, and as a request it reads back to the same value.
    let original = rfc1035_example_message();
    let decoded = decode(&original, TCP).unwrap();
    let encoded = decoded.message().encode().unwrap();
    assert!(
        encoded.len() > 105,
        "uncompressed is longer than the 105 octets"
    );
    let again = decode(&encoded, TCP).unwrap();
    assert_eq!(again.message(), decoded.message());

    let mut response = decoded.message().clone();
    response.header.qr = true;
    let encoded = response.encode().unwrap();
    let back = decode(&encoded, Profile::Response(Transport::Tcp)).unwrap();
    assert_eq!(back.message(), &response);
}

#[test]
fn forward_pointer_rejected() {
    // Source: RFC 1035 §4.1.4 ("a pointer to a prior occurance"); docs/54
    // §6.3 (OFFSET strictly less than the pointer's position).
    let qname = cat(&[&name("a")[..2], &pointer(40)]);
    let message = cat(&[&header(1, QUERY, 1, 0, 0, 0), &question(&qname, T_A, C_IN)]);
    assert_eq!(
        decode(&message, TCP).unwrap_err(),
        Error::PointerNotBackward
    );
}

#[test]
fn self_pointer_rejected() {
    // Source: RFC 1035 §4.1.4; docs/54 §6.3 — a pointer to its own position
    // is not "prior".
    let message = cat(&[
        &header(1, QUERY, 1, 0, 0, 0),
        &question(&pointer(12), T_A, C_IN),
    ]);
    assert_eq!(
        decode(&message, TCP).unwrap_err(),
        Error::PointerNotBackward
    );
}

#[test]
fn pointer_loop_through_a_label_rejected() {
    // Source: RFC 1035 §4.1.4; docs/questions/Q-640. QNAME = label "a" at 12,
    // then a pointer at 14 back to 12: backwards, but into the name being
    // decoded — following it would repeat "a" forever. Refused at once: a
    // name's own positions become targets only after it has terminated.
    let qname = cat(&[&[1, b'a'], &pointer(12)]);
    let message = cat(&[&header(1, QUERY, 1, 0, 0, 0), &question(&qname, T_A, C_IN)]);
    assert_eq!(decode(&message, TCP).unwrap_err(), Error::PointerTarget);
}

#[test]
fn mutual_pointers_cannot_form_a_loop() {
    // Source: RFC 1035 §4.1.4; docs/54 §6.3. Two names pointing at each other
    // (QNAME at 12 → the owner at 18, the owner at 18 → 12): whichever comes
    // first must point forward, and is refused.
    let message = cat(&[
        &header(1, QUERY, 1, 0, 0, 1),
        &question(&pointer(18), T_A, C_IN), // 12..17
        &rr(&pointer(12), T_A, C_IN, 0, &[10, 2, 0, 52]),
    ]);
    assert_eq!(
        decode(&message, TCP).unwrap_err(),
        Error::PointerNotBackward
    );
}

#[test]
fn pointer_into_header_rejected() {
    // Source: RFC 1035 §4.1.1 (the header holds no domain name), §4.1.4.
    let message = cat(&[
        &header(1, QUERY, 1, 0, 0, 1),
        &question(&name("a.example"), T_A, C_IN),
        &rr(&pointer(4), T_A, C_IN, 0, &[10, 2, 0, 52]),
    ]);
    assert_eq!(decode(&message, TCP).unwrap_err(), Error::PointerTarget);
}

#[test]
fn pointer_into_middle_of_label_rejected() {
    // Source: RFC 1035 §4.1.4. Offset 23 is the octet "I" of the label ISI of
    // the figure's F.ISI.ARPA at 20 — not where any name occurs.
    let mut message = rfc1035_example_message();
    // Re-point AR3's RDATA (offsets 103–104) at 23.
    message[103..105].copy_from_slice(&pointer(23));
    assert_eq!(decode(&message, TCP).unwrap_err(), Error::PointerTarget);
}

#[test]
fn pointer_into_integer_field_rejected() {
    // Source: RFC 1035 §4.1.2 (QTYPE is a two octet code, not a name), §4.1.4.
    // Offset 32 is the QTYPE of the example message.
    let mut message = rfc1035_example_message();
    message[103..105].copy_from_slice(&pointer(32));
    assert_eq!(decode(&message, TCP).unwrap_err(), Error::PointerTarget);
}

#[test]
fn pointer_into_skipped_rdata_rejected() {
    // Source: docs/54 §6.1 (RDATA of an unmodelled type is skipped, not
    // decoded); docs/questions/Q-640. TYPE 99 is not modelled; its RDATA holds
    // a well-formed name at 30, which is therefore not a decoded occurrence.
    let message = cat(&[
        &header(1, QUERY, 1, 0, 0, 2),
        &question(&name("a"), T_A, C_IN),        // 12..18
        &rr(&name(""), 99, C_IN, 0, &name("b")), // 19..32, RDATA at 30
        &rr(&pointer(30), T_A, C_IN, 0, &[10, 2, 0, 52]),
    ]);
    assert_eq!(decode(&message, TCP).unwrap_err(), Error::PointerTarget);
}

#[test]
fn pointer_to_terminating_zero_is_the_root() {
    // Source: RFC 1035 §4.1.4 ("The root domain name is defined by a single
    // octet of zeros"); the zero octet ending a decoded name is an occurrence
    // of the root.
    let message = cat(&[
        &header(1, QUERY, 1, 0, 0, 1),
        &question(&name("a"), T_A, C_IN), // terminator at 14
        &rr(&pointer(14), T_A, C_IN, 0, &[10, 2, 0, 52]),
    ]);
    let decoded = decode(&message, TCP).unwrap();
    assert!(decoded.message().additional[0].name.is_root());
}

#[test]
fn pointer_chains_take_one_hop_per_name() {
    // Source: RFC 1035 §4.1.4 (a name may be "a pointer"; its target is a
    // prior occurrence, which may itself be a pointer); docs/questions/Q-640.
    // An UPDATE at its count bounds (docs/54 §6.2): the zone, then 32 records
    // whose owners each point at the previous owner — a chain 32 deep. Every name is resolved by one lookup of an already decoded suffix.
    let zone = name("example.com");
    let mut body = question(&zone, T_SOA, C_IN); // ZNAME at 12
    let mut previous_pointer_at: u16 = 12;
    for i in 0..32u16 {
        let start = (12 + body.len()) as u16;
        let owner = if i == 0 {
            // "a" + pointer to the zone name: the first link.
            cat(&[&[1, b'a'], &pointer(12)])
        } else {
            pointer(previous_pointer_at)
        };
        // The next owner points where this owner occurs: for the first, at
        // its label "a"; for the others, at their pointer — both occurrences
        // of a.example.com. (A pointer to the first owner's own pointer, at
        // start + 2, would be an occurrence of example.com only.)
        previous_pointer_at = start;
        body.extend(rr(&owner, T_ANY, C_ANY, 0, &[]));
    }
    let message = cat(&[&header(7, UPDATE, 1, 16, 16, 0), &body]);
    let decoded = decode(&message, TCP).unwrap();
    let m = decoded.message();
    assert_eq!(m.prerequisites().len(), 16);
    assert_eq!(m.updates().len(), 16);
    for record in m.prerequisites().iter().chain(m.updates()) {
        assert_eq!(record.name, n("a.example.com"));
    }
}

#[test]
fn name_longer_than_255_after_expansion_rejected() {
    // Source: RFC 1035 §2.3.4, §3.1 ("the total length of a domain name …
    // is restricted to 255 octets"); docs/54 §6.2 ("after unpacking").
    // QNAME of 251 octets (five 49-octet labels + root), then an owner of
    // one 4-octet label + pointer to it: 5 + 251 = 256.
    let label = [b'q'; 49];
    let mut qname = Vec::new();
    for _ in 0..5 {
        qname.push(49);
        qname.extend_from_slice(&label);
    }
    qname.push(0);
    assert_eq!(qname.len(), 251);
    let owner = cat(&[&[4], b"long", &pointer(12)]);
    let message = cat(&[
        &header(1, QUERY, 1, 0, 0, 1),
        &question(&qname, T_A, C_IN),
        &rr(&owner, T_A, C_IN, 0, &[10, 2, 0, 52]),
    ]);
    assert_eq!(decode(&message, TCP).unwrap_err(), Error::NameTooLong);

    // One octet shorter label: 4 + 251 = 255 decodes.
    let owner = cat(&[&[3], b"lon", &pointer(12)]);
    let message = cat(&[
        &header(1, QUERY, 1, 0, 0, 1),
        &question(&qname, T_A, C_IN),
        &rr(&owner, T_A, C_IN, 0, &[10, 2, 0, 52]),
    ]);
    let decoded = decode(&message, TCP).unwrap();
    assert_eq!(decoded.message().additional[0].name.wire_len(), 255);
}

#[test]
fn reserved_label_types_rejected() {
    // Source: RFC 1035 §4.1.4 ("The 10 and 01 combinations are reserved for
    // future use"); docs/54 §6.2 (FORMERR).
    for first in [0x40u8, 0x7F, 0x80, 0xBF] {
        let qname = [first, 0, 0];
        let message = cat(&[&header(1, QUERY, 1, 0, 0, 0), &question(&qname, T_A, C_IN)]);
        assert_eq!(
            decode(&message, TCP).unwrap_err(),
            Error::ReservedLabelType,
            "{first:#x}"
        );
    }
}

#[test]
fn srv_target_compression_rejected() {
    // Source: RFC 2782 ("Unless and until permitted by future standards
    // action, name compression is not to be used for this field"); docs/54
    // §6.3.
    let target = pointer(12);
    let message = cat(&[
        &header(1, QUERY, 1, 0, 0, 1),
        &question(&name("_ldap._tcp.example.com"), T_SRV, C_IN),
        &rr(&name(""), T_SRV, C_IN, 0, &srv_rdata(0, 0, 389, &target)),
    ]);
    assert_eq!(
        decode(&message, TCP).unwrap_err(),
        Error::CompressionNotAllowed
    );
}

#[test]
fn tsig_algorithm_name_compression_rejected() {
    // Source: RFC 8945 §4.2 (Algorithm Name: "this name MUST NOT be
    // compressed"); docs/54 §6.3.
    let alg_qname = name("gss-tsig");
    let mac = [1u8; 28];
    let compressed = pointer(12);
    let fields = gss_tsig_fields(&compressed, &mac, 1);
    let message = cat(&[
        &header(1, QUERY, 1, 0, 0, 1),
        &question(&alg_qname, T_A, C_IN),
        &tsig_rr(&name("key"), &tsig_rdata(&fields)),
    ]);
    assert_eq!(
        decode(&message, TCP).unwrap_err(),
        Error::CompressionNotAllowed
    );
}

#[test]
fn tsig_key_name_may_be_compressed() {
    // Source: RFC 1035 §4.1.4 (owner names may be compressed); RFC 8945 §4.2
    // forbids compression only for the Algorithm Name.
    let alg = name("gss-tsig");
    let mac = [1u8; 28];
    let message = cat(&[
        &header(1, QUERY, 1, 0, 0, 1),
        &question(&name("key.example.com"), T_A, C_IN),
        &tsig_rr(&pointer(12), &tsig_rdata(&gss_tsig_fields(&alg, &mac, 1))),
    ]);
    let decoded = decode(&message, TCP).unwrap();
    let tsig = decoded.message().tsig.as_ref().unwrap();
    assert_eq!(tsig.key_name, n("key.example.com"));
    assert!(tsig.algorithm_is_gss_tsig());
}

#[test]
fn canonical_profile_rejects_every_pointer() {
    // Source: docs/54 §6.3 (the server encodes without compression; the
    // profile that reads its replies back accepts only that form).
    let message = cat(&[
        &header(1, QR | QUERY, 1, 1, 0, 0),
        &question(&name("a.example"), T_A, C_IN),
        &rr(&pointer(12), T_A, C_IN, 60, &[10, 2, 0, 52]),
    ]);
    assert_eq!(
        decode(&message, Profile::Response(Transport::Udp)).unwrap_err(),
        Error::CompressionNotAllowed
    );
}

#[test]
fn ns_and_soa_rdata_names_may_be_compressed() {
    // Source: RFC 1035 §3.3 ("NS, SOA, CNAME, and PTR … all domain names in
    // the RDATA section of these RRs may be compressed"), §4.1.4 ("the length
    // of the compressed name is used in the length calculation").
    let soa = soa_rdata(
        &pointer(12),
        &cat(&[&[10], b"hostmaster", &pointer(12)]),
        [1, 2, 3, 4, 5],
    );
    let message = cat(&[
        &header(1, UPDATE, 1, 0, 2, 0),
        &question(&name("example.com"), T_SOA, C_IN),
        &rr(
            &pointer(12),
            T_NS,
            C_IN,
            0,
            &cat(&[&[2], b"ns", &pointer(12)]),
        ),
        &rr(&pointer(12), T_SOA, C_IN, 0, &soa),
    ]);
    let decoded = decode(&message, TCP).unwrap();
    let m = decoded.message();
    assert_eq!(m.updates()[0].rdata, RData::Ns(n("ns.example.com")));
    let RData::Soa(soa) = &m.updates()[1].rdata else {
        panic!("SOA");
    };
    assert_eq!(soa.mname, n("example.com"));
    assert_eq!(soa.rname, n("hostmaster.example.com"));
    assert_eq!((soa.serial, soa.minimum), (1, 5));
}
