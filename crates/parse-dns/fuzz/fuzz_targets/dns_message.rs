#![no_main]
//! Fuzz target for `parse_dns::decode` (docs/54 §10.3 `dns_message`).
//!
//! docs/CLEAN-ROOM.md requires a fuzz target for every parser before it merges to
//! `main`. Arbitrary octets are decoded under every profile: none may panic,
//! hang or over-allocate — each fails closed with a `parse_dns::Error`.
//!
//! When an input is accepted:
//!
//! * the header-only decode agrees with it (docs/54 §6.6);
//! * every name is within the RFC 1035 §3.1 bounds and is its own
//!   uncompressed wire form;
//! * if no record was skipped, the canonical encoding succeeds, decodes back to
//!   the same value under the matching profile, and re-encodes to itself
//!   (docs/54 §6.3, §10.2); a skipped record makes encoding refuse;
//! * input accepted by a `Response` profile was already canonical: its
//!   encoding equals the input except for the ignored flag bits (Z; for
//!   UPDATE also AA/TC/RD/RA — RFC 2136 §2.2).
//!
//! Spec: RFC 1035 §3.1, §4.1, §4.1.4; RFC 2136 §2; RFC 8945 §4.2, §5.2;
//! docs/54 §6.1–§6.3.

use libfuzzer_sys::fuzz_target;
use parse_dns::{
    decode, decode_header, Error, Message, Name, Opcode, Profile, RData, Transport,
    MAX_LABEL_OCTETS, MAX_NAME_OCTETS,
};

const PROFILES: [Profile; 5] = [
    Profile::Query(Transport::Udp),
    Profile::Query(Transport::Tcp),
    Profile::Forwarded,
    Profile::Response(Transport::Udp),
    Profile::Response(Transport::Tcp),
];

fn check_name(name: &Name) {
    assert!(name.wire_len() <= MAX_NAME_OCTETS);
    assert!(name.labels().all(|l| !l.is_empty() && l.len() <= MAX_LABEL_OCTETS));
    let again = Name::decode_uncompressed(name.as_wire()).expect("a name is its wire form");
    assert_eq!(again.as_wire(), name.as_wire());
}

fn names(message: &Message) -> Vec<&Name> {
    let mut out = Vec::new();
    if let Some(q) = &message.question {
        out.push(&q.qname);
    }
    for record in message
        .answer
        .iter()
        .chain(&message.authority)
        .chain(&message.additional)
    {
        out.push(&record.name);
        match &record.rdata {
            RData::Ns(name) => out.push(name),
            RData::Soa(soa) => {
                out.push(&soa.mname);
                out.push(&soa.rname);
            }
            RData::Srv(srv) => out.push(&srv.target),
            _ => {}
        }
    }
    if let Some(tsig) = &message.tsig {
        out.push(&tsig.key_name);
        out.push(&tsig.algorithm_name);
    }
    out
}

fn skipped(message: &Message) -> bool {
    message
        .answer
        .iter()
        .chain(&message.authority)
        .chain(&message.additional)
        .any(|r| matches!(r.rdata, RData::Unknown { .. }))
}

fuzz_target!(|data: &[u8]| {
    for profile in PROFILES {
        let result = decode(data, profile);
        if data.len() > profile.max_message_octets() {
            assert_eq!(result.err(), Some(Error::MessageTooLarge));
            continue;
        }
        let Ok(decoded) = result else {
            continue;
        };
        let message = decoded.message();

        let header = decode_header(data, Transport::Tcp).expect("header decodes");
        assert_eq!(header.id, message.header.id);
        assert_eq!(header.qr, message.header.qr);
        assert_eq!(header.known_opcode(), Some(message.header.opcode));

        for name in names(message) {
            check_name(name);
        }

        let encoded = message.encode();
        if skipped(message) {
            assert_eq!(encoded, Err(Error::InvalidValue));
            continue;
        }
        let encoded = encoded.expect("an accepted value without skipped RDATA encodes");
        let back_profile = match profile {
            Profile::Response(_) => Profile::Response(Transport::Tcp),
            Profile::Forwarded => Profile::Forwarded,
            Profile::Query(_) => Profile::Query(Transport::Tcp),
        };
        let again = decode(&encoded, back_profile).expect("the canonical encoding decodes");
        assert_eq!(again.message(), message);
        assert_eq!(again.message().encode().as_deref(), Ok(&encoded[..]));

        if let Profile::Response(_) = profile {
            assert_eq!(encoded.len(), data.len(), "canonical input has no pointer");
            let ignored: u16 = match message.header.opcode {
                Opcode::Query => 0x0070,
                Opcode::Update => 0x07F0,
            };
            let flags = |b: &[u8]| u16::from_be_bytes([b[2], b[3]]) & !ignored;
            assert_eq!(flags(&encoded), flags(data));
            assert_eq!(&encoded[..2], &data[..2]);
            assert_eq!(&encoded[4..], &data[4..]);
        }
    }
});
