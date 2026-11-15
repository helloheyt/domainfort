#![no_main]
//! Fuzz target for domain names (docs/54 §10.3 `dns_name`).
//!
//! AGENTS.md §6 requires a fuzz target for every parser before it merges to
//! `main`. The input is cut at each 0xFF octet into up to 33 pieces, and an
//! UPDATE request is built around them: the first piece is the ZNAME, each
//! further piece the owner name of an empty-RDATA record (RFC 2136 §2.4.4
//! form). Compression pointers in the pieces therefore land on real message
//! offsets, and the decoder's pointer rules (RFC 1035 §4.1.4; docs/54 §6.3;
//! docs/questions/Q-640) are exercised. The same input also goes through the
//! standalone constructors (`Name::decode_uncompressed`, `Name::from_dotted`).
//!
//! Properties: no panic; every accepted name is within RFC 1035 §3.1 bounds,
//! is its own uncompressed wire form, rebuilds from its labels, and is equal
//! (case-insensitively, RFC 1035 §3.1) to its lowercased form.
//!
//! Spec: RFC 1035 §3.1, §4.1.4; RFC 1034 §3.1; RFC 2136 §2.3, §2.4.4.

use libfuzzer_sys::fuzz_target;
use parse_dns::{
    decode, Name, Profile, Transport, MAX_LABELS, MAX_LABEL_OCTETS, MAX_NAME_OCTETS,
    UPDATE_MAX_PRCOUNT, UPDATE_MAX_UPCOUNT,
};

fn check(name: &Name) {
    assert!(name.wire_len() <= MAX_NAME_OCTETS);
    assert!(name.label_count() <= MAX_LABELS);
    assert!(name.labels().all(|l| !l.is_empty() && l.len() <= MAX_LABEL_OCTETS));
    let again = Name::decode_uncompressed(name.as_wire()).expect("a name is its wire form");
    assert_eq!(again.as_wire(), name.as_wire());
    let rebuilt = Name::from_labels(name.labels()).expect("labels rebuild the name");
    assert_eq!(rebuilt.as_wire(), name.as_wire());
    let lower: Vec<Vec<u8>> = name.labels().map(|l| l.to_ascii_lowercase()).collect();
    assert_eq!(&Name::from_labels(&lower).unwrap(), name);
    assert!(name.is_subdomain_of(&Name::root()));
    assert!(name.is_subdomain_of(name));
}

fuzz_target!(|data: &[u8]| {
    if let Ok(name) = Name::decode_uncompressed(data) {
        check(&name);
        assert_eq!(name.wire_len(), data.len());
    }
    if let Ok(text) = core::str::from_utf8(data) {
        if let Ok(name) = Name::from_dotted(text) {
            check(&name);
        }
    }

    let max_records = usize::from(UPDATE_MAX_PRCOUNT + UPDATE_MAX_UPCOUNT);
    let pieces: Vec<&[u8]> = data.split(|&b| b == 0xFF).take(1 + max_records).collect();
    let Some((zname, owners)) = pieces.split_first() else {
        return;
    };
    let prcount = owners.len().min(usize::from(UPDATE_MAX_PRCOUNT));
    let upcount = owners.len() - prcount;

    // Header: UPDATE request (RFC 2136 §2.2), ZOCOUNT 1, PRCOUNT, UPCOUNT,
    // ADCOUNT 0.
    let mut wire = Vec::new();
    for word in [0u16, 5 << 11, 1, prcount as u16, upcount as u16, 0] {
        wire.extend_from_slice(&word.to_be_bytes());
    }
    // Zone: ZNAME, ZTYPE SOA (6), ZCLASS IN (1) — RFC 2136 §2.3.
    wire.extend_from_slice(zname);
    wire.extend_from_slice(&[0, 6, 0, 1]);
    // Records: owner, TYPE ANY, CLASS ANY, TTL 0, RDLENGTH 0 — RFC 2136 §2.4.4.
    for owner in owners {
        wire.extend_from_slice(owner);
        wire.extend_from_slice(&[0, 255, 0, 255, 0, 0, 0, 0, 0, 0]);
    }

    let Ok(decoded) = decode(&wire, Profile::Query(Transport::Tcp)) else {
        return;
    };
    let message = decoded.message();
    check(&message.question.as_ref().expect("one zone").qname);
    for record in message.answer.iter().chain(&message.authority) {
        check(&record.name);
    }
});
