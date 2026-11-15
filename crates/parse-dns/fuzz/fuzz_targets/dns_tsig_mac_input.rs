#![no_main]
//! Fuzz target for the TSIG MAC input components (docs/54 §10.3
//! `dns_tsig_mac_input`).
//!
//! docs/CLEAN-ROOM.md requires a fuzz target for every parser before it merges to
//! `main`. For every input that decodes with a TSIG RR under a request
//! profile:
//!
//! * the "DNS Message" component is the received octets up to the TSIG RR,
//!   with only the ID (now the Original ID) and ARCOUNT (one less) changed
//!   (RFC 8945 §4.3.2);
//! * that component decodes to the same message without its TSIG, with the
//!   Original ID as ID — the bytes the MAC covers are the bytes decided on
//!   (docs/54 §4.1, class C2);
//! * the "Request MAC" component is MAC Size ‖ MAC (RFC 8945 §4.3.1, Table 1).
//!
//! The "TSIG Variables" component is not built yet (docs/questions/Q-641).
//!
//! Spec: RFC 8945 §4.3.1, §4.3.2, §5.2; docs/54 §7.4.

use libfuzzer_sys::fuzz_target;
use parse_dns::{decode, Profile, Transport};

const PROFILES: [Profile; 3] = [
    Profile::Query(Transport::Udp),
    Profile::Query(Transport::Tcp),
    Profile::Forwarded,
];

fuzz_target!(|data: &[u8]| {
    for profile in PROFILES {
        let Ok(decoded) = decode(data, profile) else {
            continue;
        };
        let message = decoded.message();
        let Some(tsig) = &message.tsig else {
            assert!(decoded.tsig_message_component().is_none());
            assert!(decoded.request_mac_component().is_none());
            continue;
        };

        let component = decoded.tsig_message_component().expect("TSIG present");
        assert!(component.len() < data.len());
        assert_eq!(&component[..2], &tsig.original_id.to_be_bytes());
        assert_eq!(&component[2..10], &data[2..10]);
        let arcount = |b: &[u8]| u16::from_be_bytes([b[10], b[11]]);
        assert_eq!(arcount(&component) + 1, arcount(data));
        assert_eq!(&component[12..], &data[12..component.len()]);

        let stripped = decode(&component, Profile::Query(Transport::Tcp))
            .expect("the message without its TSIG decodes");
        let stripped = stripped.message();
        assert!(stripped.tsig.is_none());
        assert_eq!(stripped.header.id, tsig.original_id);
        assert_eq!(stripped.question, message.question);
        assert_eq!(stripped.answer, message.answer);
        assert_eq!(stripped.authority, message.authority);
        assert_eq!(stripped.additional, message.additional);

        let request_mac = decoded.request_mac_component().expect("TSIG present");
        let mac = tsig.mac.as_bytes();
        assert_eq!(&request_mac[..2], &(mac.len() as u16).to_be_bytes());
        assert_eq!(&request_mac[2..], mac);
    }
});
