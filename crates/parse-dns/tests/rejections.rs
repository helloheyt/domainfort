//! Every bound and every malformed form is refused, with its typed error.
//!
//! Each test names its source: the RFC section or the docs/54 bound the input
//! violates. Inputs are assembled by hand from the field layouts in `common`.
//! (Compression-pointer refusals are in `compression.rs`.)

mod common;

use common::*;
use parse_dns::{
    decode, decode_header, Error, Profile, Section, Transport, MAX_TSIG_MAC_OCTETS,
    MAX_UDP_MESSAGE_OCTETS,
};

const UDP: Profile = Profile::Query(Transport::Udp);
const TCP: Profile = Profile::Query(Transport::Tcp);

fn query() -> Vec<u8> {
    cat(&[
        &header(1, QUERY, 1, 0, 0, 0),
        &question(&name("a.example.com"), T_A, C_IN),
    ])
}

fn err(wire: &[u8], profile: Profile) -> Error {
    decode(wire, profile).unwrap_err()
}

// ---- framing (RFC 1035 §2.3.4, §4.1, §4.2) ----

#[test]
fn truncated_header_rejected() {
    // Source: RFC 1035 §4.1.1 (the header is six 16-bit fields).
    let full = query();
    for len in 0..12 {
        assert_eq!(err(&full[..len], UDP), Error::Truncated, "len {len}");
        assert_eq!(
            decode_header(&full[..len], Transport::Udp).unwrap_err(),
            Error::Truncated
        );
    }
}

#[test]
fn oversize_udp_message_rejected() {
    // Source: RFC 1035 §2.3.4 ("UDP messages 512 octets or less"), §4.2.1;
    // docs/54 §6.2 (a larger datagram is not decoded — silence).
    // A query padded with a skipped additional record to exactly 512 octets.
    let base = query();
    let pad = MAX_UDP_MESSAGE_OCTETS - base.len() - 11;
    let mut wire = cat(&[
        &header(1, QUERY, 1, 0, 0, 1),
        &base[12..],
        &rr(&name(""), 99, C_IN, 0, &vec![0u8; pad]),
    ]);
    assert_eq!(wire.len(), 512);
    assert!(decode(&wire, UDP).is_ok());
    // One octet more (RDLENGTH grown with it): 513.
    wire = cat(&[
        &header(1, QUERY, 1, 0, 0, 1),
        &base[12..],
        &rr(&name(""), 99, C_IN, 0, &vec![0u8; pad + 1]),
    ]);
    assert_eq!(wire.len(), 513);
    assert_eq!(err(&wire, UDP), Error::MessageTooLarge);
    assert_eq!(
        decode_header(&wire, Transport::Udp).unwrap_err(),
        Error::MessageTooLarge
    );
    assert_eq!(
        err(&wire, Profile::Response(Transport::Udp)),
        Error::MessageTooLarge
    );
    // The same message is fine on TCP.
    assert!(decode(&wire, TCP).is_ok());
}

#[test]
fn oversize_tcp_message_rejected() {
    // Source: RFC 1035 §4.2.2 (two-octet length prefix: at most 65535);
    // docs/54 §4.6, §6.2 (forwarded messages have the same bound).
    let mut wire = query();
    wire.resize(65_536, 0);
    for profile in [TCP, Profile::Forwarded, Profile::Response(Transport::Tcp)] {
        assert_eq!(err(&wire, profile), Error::MessageTooLarge);
    }
    assert_eq!(
        decode_header(&wire, Transport::Tcp).unwrap_err(),
        Error::MessageTooLarge
    );
}

#[test]
fn trailing_octets_rejected() {
    // Source: docs/54 §6.2 ("after the last record — exactly the end of the
    // message"); docs/50 §3.3.
    let mut wire = query();
    wire.push(0);
    assert_eq!(err(&wire, UDP), Error::TrailingData);
}

#[test]
fn counts_exceeding_the_message_rejected() {
    // Source: RFC 1035 §4.1.1 (counts number the entries present); docs/CLEAN-ROOM.md
    // §6 (no allocation from attacker-supplied counts). Checked before any
    // section is read.
    let wire = cat(&[
        &header(1, QUERY, 1, 0, 0, 4),
        &question(&name("a"), T_A, C_IN),
    ]);
    assert_eq!(err(&wire, UDP), Error::CountExceedsMessage);
    let wire = cat(&[
        &header(1, QR, 1, 65535, 65535, 65535),
        &question(&name("a"), T_A, C_IN),
    ]);
    assert_eq!(
        err(&wire, Profile::Response(Transport::Tcp)),
        Error::CountExceedsMessage
    );
    // A question count with no question at all.
    let wire = header(1, QUERY, 1, 0, 0, 0);
    assert_eq!(err(&wire, UDP), Error::CountExceedsMessage);
}

#[test]
fn truncated_fields_rejected() {
    // Source: RFC 1035 §4.1.2 (QTYPE, QCLASS), §4.1.3 (RDLENGTH counts octets
    // that must be present).
    // QCLASS missing: QNAME "a" (3) + QTYPE (2) satisfies the 5-octet minimum.
    let wire = cat(&[
        &header(1, QUERY, 1, 0, 0, 0),
        &name("a"),
        &T_A.to_be_bytes(),
    ]);
    assert_eq!(err(&wire, UDP), Error::Truncated);
    // A label running past the end.
    let wire = cat(&[&header(1, QUERY, 1, 0, 0, 0), &[9, b'a', b'b', b'c', b'd']]);
    assert_eq!(err(&wire, UDP), Error::Truncated);
    // RDLENGTH beyond the message.
    let wire = cat(&[
        &header(1, QUERY, 1, 0, 0, 1),
        &question(&name("a"), T_A, C_IN),
        &rr_with_rdlength(&name(""), T_A, C_IN, 0, 40, &[10, 2, 0, 52]),
    ]);
    assert_eq!(err(&wire, UDP), Error::Truncated);
}

// ---- direction and opcode (RFC 1035 §4.1.1; RFC 2136 §2.2) ----

#[test]
fn response_where_request_expected_rejected() {
    // Source: RFC 1035 §4.1.1 (QR); docs/54 §6.6 (QR = 1 ⇒ silence).
    let mut wire = query();
    wire[2] |= 0x80;
    assert_eq!(err(&wire, UDP), Error::UnexpectedDirection);
    assert_eq!(
        err(&signed_update_as_response(), Profile::Forwarded),
        Error::UnexpectedDirection
    );
}

fn signed_update_as_response() -> Vec<u8> {
    let mut wire = signed_update(3);
    wire[2] |= 0x80;
    wire
}

#[test]
fn request_where_response_expected_rejected() {
    // Source: RFC 1035 §4.1.1 (QR); docs/54 §6.1 (`Response`).
    assert_eq!(
        err(&query(), Profile::Response(Transport::Udp)),
        Error::UnexpectedDirection
    );
}

#[test]
fn unsupported_opcodes_rejected() {
    // Source: RFC 1035 §4.1.1 (1 IQUERY, 2 STATUS, 3–15 reserved); RFC 1034
    // §3.7.2; RFC 2136 §3; docs/54 §3.2 (NOTIMP).
    for opcode in (1u16..16).filter(|&o| o != 5) {
        let wire = cat(&[
            &header(1, opcode << 11, 1, 0, 0, 0),
            &question(&name("a"), T_A, C_IN),
        ]);
        assert_eq!(err(&wire, UDP), Error::UnsupportedOpcode, "opcode {opcode}");
    }
    // QUERY is not forwarded to dird in phase 1 (docs/54 §4.6; TKEY is DN9).
    assert_eq!(err(&query(), Profile::Forwarded), Error::UnsupportedOpcode);
}

// ---- section counts (docs/54 §6.2) ----

#[test]
fn query_count_bounds() {
    // Source: docs/54 §6.2 (QUERY: QDCOUNT = 1, ANCOUNT = NSCOUNT = 0,
    // ARCOUNT ≤ 4).
    let q = question(&name("a"), T_A, C_IN);
    let a = rr(&name("a"), T_A, C_IN, 0, &[10, 2, 0, 52]);
    let cases: [(Vec<u8>, Section); 5] = [
        (header(1, QUERY, 0, 0, 0, 0), Section::Question),
        (
            cat(&[&header(1, QUERY, 2, 0, 0, 0), &q, &q]),
            Section::Question,
        ),
        (
            cat(&[&header(1, QUERY, 1, 1, 0, 0), &q, &a]),
            Section::Answer,
        ),
        (
            cat(&[&header(1, QUERY, 1, 0, 1, 0), &q, &a]),
            Section::Authority,
        ),
        (
            cat(&[&header(1, QUERY, 1, 0, 0, 5), &q, &a, &a, &a, &a, &a]),
            Section::Additional,
        ),
    ];
    for (wire, section) in cases {
        assert_eq!(err(&wire, UDP), Error::SectionCount(section));
    }
    // ARCOUNT = 4 is within the bound.
    let wire = cat(&[&header(1, QUERY, 1, 0, 0, 4), &q, &a, &a, &a, &a]);
    assert!(decode(&wire, UDP).is_ok());
}

#[test]
fn update_count_bounds() {
    // Source: RFC 2136 §2.3 (exactly one zone); docs/54 §6.2 (ZOCOUNT = 1,
    // PRCOUNT ≤ 16, UPCOUNT ≤ 16, ADCOUNT = 1 — the TSIG).
    let z = question(&name("example.com"), T_SOA, C_IN);
    let r = rr(&name("h.example.com"), T_A, C_ANY, 0, &[]);
    let many = |k: usize| r.repeat(k);
    let cases: [(Vec<u8>, Section); 5] = [
        (header(1, UPDATE, 0, 0, 0, 0), Section::Question),
        (
            cat(&[&header(1, UPDATE, 2, 0, 0, 0), &z, &z]),
            Section::Question,
        ),
        (
            cat(&[&header(1, UPDATE, 1, 17, 0, 0), &z, &many(17)]),
            Section::Answer,
        ),
        (
            cat(&[&header(1, UPDATE, 1, 0, 17, 0), &z, &many(17)]),
            Section::Authority,
        ),
        (
            cat(&[&header(1, UPDATE, 1, 0, 0, 2), &z, &many(2)]),
            Section::Additional,
        ),
    ];
    for (wire, section) in cases {
        assert_eq!(err(&wire, TCP), Error::SectionCount(section), "{section}");
        assert_eq!(err(&wire, Profile::Forwarded), Error::SectionCount(section));
    }
    // 16 + 16 is within the bound.
    let wire = cat(&[&header(1, UPDATE, 1, 16, 16, 0), &z, &many(32)]);
    assert!(decode(&wire, TCP).is_ok());
}

#[test]
fn response_holds_at_most_one_question() {
    // Source: docs/54 §6.2 (QDCOUNT = 1); the model holds one question.
    let q = question(&name("a"), T_A, C_IN);
    let wire = cat(&[&header(1, QR, 2, 0, 0, 0), &q, &q]);
    assert_eq!(
        err(&wire, Profile::Response(Transport::Udp)),
        Error::SectionCount(Section::Question)
    );
}

// ---- names (RFC 1035 §2.3.4, §3.1, §4.1.4) ----

#[test]
fn label_longer_than_63_rejected() {
    // Source: RFC 1035 §3.1 ("The high order two bits of every length octet
    // must be zero"), §4.1.4 (01 reserved); docs/54 §6.2. A 64-octet label's
    // length octet is 0x40.
    let mut qname = vec![64u8];
    qname.extend_from_slice(&[b'x'; 64]);
    qname.push(0);
    let wire = cat(&[&header(1, QUERY, 1, 0, 0, 0), &question(&qname, T_A, C_IN)]);
    assert_eq!(err(&wire, TCP), Error::ReservedLabelType);
}

#[test]
fn name_longer_than_255_rejected() {
    // Source: RFC 1035 §2.3.4, §3.1; RFC 1034 §3.1. Four 63-octet labels:
    // 4 × 64 + 1 = 257 octets.
    let mut qname = Vec::new();
    for _ in 0..4 {
        qname.push(63);
        qname.extend_from_slice(&[b'x'; 63]);
    }
    qname.push(0);
    let wire = cat(&[&header(1, QUERY, 1, 0, 0, 0), &question(&qname, T_A, C_IN)]);
    assert_eq!(err(&wire, TCP), Error::NameTooLong);
}

// ---- RDATA (RFC 1035 §3.2.1, §4.1.3; docs/54 §6.2) ----

#[test]
fn rdlength_mismatch_rejected() {
    // Source: docs/54 §6.2 (RDLENGTH equal exactly to the decoded RDATA);
    // RFC 1035 §3.4.1 (A is 4 octets), §3.3.11, §3.3.13; RFC 2782.
    let q = question(&name("a"), T_A, C_IN);
    let cases: [Vec<u8>; 6] = [
        rr(&name(""), T_A, C_IN, 0, &[10, 2, 0]),
        rr(&name(""), T_A, C_IN, 0, &[10, 2, 0, 52, 0]),
        rr(&name(""), T_A, C_IN, 0, &[]),
        rr(&name(""), T_NS, C_IN, 0, &cat(&[&name("ns"), &[0]])),
        rr(
            &name(""),
            T_SOA,
            C_IN,
            0,
            &soa_rdata(&name("m"), &name("r"), [1, 2, 3, 4, 5])[..20],
        ),
        rr(
            &name(""),
            T_SRV,
            C_IN,
            0,
            &srv_rdata(0, 0, 88, &name("t"))[..5],
        ),
    ];
    for (i, record) in cases.iter().enumerate() {
        let wire = cat(&[&header(1, QUERY, 1, 0, 0, 1), &q, record]);
        assert_eq!(err(&wire, UDP), Error::RdataLength, "case {i}");
    }
    // A name inside RDATA that runs past RDLENGTH.
    let wire = cat(&[
        &header(1, QUERY, 1, 0, 0, 1),
        &q,
        &rr_with_rdlength(&name(""), T_NS, C_IN, 0, 2, &name("ns")),
    ]);
    assert_eq!(err(&wire, UDP), Error::RdataLength);
}

// ---- TSIG (RFC 8945 §4.2, §5.1, §5.2; docs/54 §6.2) ----

/// A TSIG RR (gss-tsig, key `key.example.com`) with the given MAC and Error.
fn tsig_with(mac: &[u8], error: u16) -> Vec<u8> {
    let alg = name("gss-tsig");
    let mut fields = gss_tsig_fields(&alg, mac, 1);
    fields.error = error;
    tsig_rr(&name("key.example.com"), &tsig_rdata(&fields))
}

const MAC28: [u8; 28] = [7u8; 28];

#[test]
fn tsig_not_last_rejected() {
    // Source: RFC 8945 §5.2 ("If multiple TSIG records are detected or a TSIG
    // record is present in any other position … FORMERR"), §5.1.
    let q = question(&name("a"), T_A, C_IN);
    let tsig = tsig_with(&MAC28, 0);
    let other = rr(&name(""), 99, C_IN, 0, &[]);
    let wire = cat(&[&header(1, QUERY, 1, 0, 0, 2), &q, &tsig, &other]);
    assert_eq!(err(&wire, UDP), Error::MisplacedTsig);
    // Two TSIGs.
    let wire = cat(&[&header(1, QUERY, 1, 0, 0, 2), &q, &tsig, &tsig]);
    assert_eq!(err(&wire, UDP), Error::MisplacedTsig);
    // In the answer section of a response.
    let wire = cat(&[&header(1, QR, 1, 1, 0, 0), &q, &tsig]);
    assert_eq!(
        err(&wire, Profile::Response(Transport::Udp)),
        Error::MisplacedTsig
    );
    // In the prerequisite section of an UPDATE.
    let wire = cat(&[
        &header(1, UPDATE, 1, 1, 0, 0),
        &question(&name("example.com"), T_SOA, C_IN),
        &tsig,
    ]);
    assert_eq!(err(&wire, TCP), Error::MisplacedTsig);
}

#[test]
fn tsig_class_and_ttl_enforced() {
    // Source: RFC 8945 §4.2 ("CLASS: This MUST be ANY", "TTL: This MUST be
    // 0"), §5.2 ("cannot be interpreted … FORMERR").
    let q = question(&name("a"), T_A, C_IN);
    let alg = name("gss-tsig");
    let mac = [7u8; 28];
    let rdata = tsig_rdata(&gss_tsig_fields(&alg, &mac, 1));
    for (class, ttl) in [(C_IN, 0u32), (C_NONE, 0), (C_ANY, 1)] {
        let wire = cat(&[
            &header(1, QUERY, 1, 0, 0, 1),
            &q,
            &rr(&name("key"), T_TSIG, class, ttl, &rdata),
        ]);
        assert_eq!(
            err(&wire, UDP),
            Error::MalformedTsig,
            "class {class} ttl {ttl}"
        );
    }
}

#[test]
fn tsig_error_must_be_zero_in_requests() {
    // Source: RFC 8945 §4.2 (Error: "In requests, this MUST be zero").
    let q = question(&name("a"), T_A, C_IN);
    let wire = cat(&[&header(1, QUERY, 1, 0, 0, 1), &q, &tsig_with(&MAC28, 17)]);
    assert_eq!(err(&wire, UDP), Error::MalformedTsig);
    // A response may carry it (RFC 8945 §5.3.2).
    let wire = cat(&[&header(1, QR | 9, 1, 0, 0, 1), &q, &tsig_with(&MAC28, 17)]);
    assert!(decode(&wire, Profile::Response(Transport::Udp)).is_ok());
}

#[test]
fn tsig_mac_bound() {
    // Source: docs/54 §6.2 ("MAC Size ≤ 64"); RFC 8945 §5.2.2.1.
    let q = question(&name("a"), T_A, C_IN);
    let long = [1u8; MAX_TSIG_MAC_OCTETS + 1];
    let wire = cat(&[&header(1, QUERY, 1, 0, 0, 1), &q, &tsig_with(&long, 0)]);
    assert_eq!(err(&wire, TCP), Error::TsigMacTooLong);
    let max = [1u8; MAX_TSIG_MAC_OCTETS];
    let wire = cat(&[&header(1, QUERY, 1, 0, 0, 1), &q, &tsig_with(&max, 0)]);
    assert!(decode(&wire, TCP).is_ok());
}

#[test]
fn tsig_rdata_length_enforced() {
    // Source: RFC 8945 §4.2 (MAC Size and Other Len give the field lengths);
    // docs/54 §6.2 (RDLENGTH exact).
    let q = question(&name("a"), T_A, C_IN);
    let alg = name("gss-tsig");
    let mac = [7u8; 28];
    let fields = gss_tsig_fields(&alg, &mac, 1);
    // MAC Size claims more than the RDATA holds.
    let short = tsig_rdata_with_mac_size(&fields, 40);
    let wire = cat(&[
        &header(1, QUERY, 1, 0, 0, 1),
        &q,
        &tsig_rr(&name("k"), &short),
    ]);
    assert_eq!(err(&wire, UDP), Error::RdataLength);
    // An octet after Other Data inside RDLENGTH.
    let mut extra = tsig_rdata(&fields);
    extra.push(0);
    let wire = cat(&[
        &header(1, QUERY, 1, 0, 0, 1),
        &q,
        &tsig_rr(&name("k"), &extra),
    ]);
    assert_eq!(err(&wire, UDP), Error::RdataLength);
}

#[test]
fn forwarded_update_requires_tsig() {
    // Source: docs/54 §4.5 step 1 (dird never sees an unsigned UPDATE), §6.2.
    let wire = cat(&[
        &header(1, UPDATE, 1, 0, 1, 0),
        &question(&name("example.com"), T_SOA, C_IN),
        &rr(&name("h.example.com"), T_A, C_IN, 60, &[10, 2, 0, 52]),
    ]);
    assert_eq!(err(&wire, Profile::Forwarded), Error::MissingTsig);
    // dnsd decodes it, to answer REFUSED (RFC 2136 §3.3.1; docs/54 §6.6).
    assert!(decode(&wire, TCP).unwrap().message().tsig.is_none());
}

#[test]
fn update_additional_holds_only_the_tsig() {
    // Source: docs/questions/Q-615 item 8; docs/54 §5.5 ("Additional — only
    // the TSIG"); RFC 2136 §2.6.
    let wire = cat(&[
        &header(1, UPDATE, 1, 0, 0, 1),
        &question(&name("example.com"), T_SOA, C_IN),
        &rr(&name("ns.example.com"), T_A, C_IN, 60, &[10, 2, 0, 52]),
    ]);
    assert_eq!(err(&wire, TCP), Error::UnexpectedRecord);
    assert_eq!(err(&wire, Profile::Forwarded), Error::UnexpectedRecord);
}

#[test]
fn every_prefix_of_a_valid_message_is_refused() {
    // Source: RFC 1035 §4.1 (every field present); docs/54 §6.2 (bounded,
    // fail closed). No prefix panics or decodes.
    let wire = signed_update(0x0F0F);
    assert!(decode(&wire, Profile::Forwarded).is_ok());
    for len in 0..wire.len() {
        assert!(
            decode(&wire[..len], Profile::Forwarded).is_err(),
            "prefix {len}"
        );
        assert!(decode(&wire[..len], TCP).is_err(), "prefix {len}");
    }
}
