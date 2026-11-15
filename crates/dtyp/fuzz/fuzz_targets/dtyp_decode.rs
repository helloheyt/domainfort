#![no_main]
//! Fuzz target for the security data-type decoders.
//!
//! docs/CLEAN-ROOM.md / docs/32 §8 require a fuzz target for every parser before it
//! merges to `main`. Arbitrary bytes are fed to every decoder in `dtyp`: none
//! may panic, hang, or over-allocate on any input (each fails closed with a
//! `Result` error instead). When a decoder accepts the input, the value must
//! re-encode, and the canonical encoding must be a fixed point:
//! `decode(encode(v)) == v`. (Exact `encode(decode(b)) == b` holds only for
//! canonical input: [MS-DTYP] 2.4.6 allows any component order and 2.4.4.1
//! allows ignored padding inside AceSize, both of which re-encode canonically.)
//! If the input is UTF-8 and parses as a SID string, the canonical string must
//! re-parse to the same SID and differ from the input only in letter case
//! (quoted ABNF literals and HEXDIG are case-insensitive, RFC 5234 §2.3).
//! A decoded descriptor is also used as the parent of CreateSecurityDescriptor
//! (container and leaf child): no panic, and any computed descriptor must
//! encode and decode back to itself.
//! If the input is UTF-8 and parses as a GUID text (the lower-case
//! `8-4-4-4-12` form, task F7), its text must be exactly the input (one
//! spelling per value); any 16 octets are a GUID packet, whose text must
//! parse back to the same GUID.
//!
//! Spec: [MS-DTYP] 2.3.4.2, 2.4.2.1, 2.4.2.2, 2.4.4.1, 2.4.5, 2.4.6, 2.5.1.1,
//! 2.5.3.4.1; [MS-DRSR] 5.16.3.16; RFC 5234 §2.3.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(sd) = dtyp::SecurityDescriptor::decode(data) {
        let bytes = sd.encode().expect("a decoded descriptor must re-encode");
        let again = dtyp::SecurityDescriptor::decode(&bytes).expect("canonical output must decode");
        assert_eq!(again, sd, "decode(encode(v)) must equal v");
        let token = dtyp::Token {
            owner: dtyp::Sid::new(dtyp::SECURITY_NT_AUTHORITY, &[21, 1, 2, 3, 1000])
                .expect("five sub-authorities"),
            primary_group: dtyp::Sid::new(dtyp::SECURITY_NT_AUTHORITY, &[21, 1, 2, 3, 513])
                .expect("five sub-authorities"),
            default_dacl: None,
        };
        for container in [true, false] {
            if let Ok(child) = dtyp::create_security_descriptor(
                Some(&sd),
                None,
                container,
                None,
                dtyp::AutoInheritFlags::default(),
                &token,
                &dtyp::GenericMapping::ACTIVE_DIRECTORY,
            ) {
                let bytes = child.encode().expect("a computed descriptor must encode");
                assert_eq!(
                    dtyp::SecurityDescriptor::decode(&bytes).expect("and decode"),
                    child
                );
            }
        }
    }
    if let Ok(acl) = dtyp::Acl::decode(data) {
        let bytes = acl.encode().expect("a decoded ACL must re-encode");
        assert_eq!(dtyp::Acl::decode(&bytes).expect("must decode"), acl);
    }
    if let Ok(ace) = dtyp::Ace::decode(data) {
        let bytes = ace.encode().expect("a decoded ACE must re-encode");
        assert_eq!(dtyp::Ace::decode(&bytes).expect("must decode"), ace);
    }
    if let Ok(sid) = dtyp::Sid::decode(data) {
        assert_eq!(dtyp::Sid::decode(&sid.encode()).expect("must decode"), sid);
    }
    if let Ok(packet) = <&[u8; dtyp::GUID_PACKET_LEN]>::try_from(data) {
        let guid = dtyp::Guid::from_packet(packet);
        assert_eq!(
            dtyp::Guid::parse_text(&guid.to_text()).expect("a GUID's text must parse"),
            guid
        );
    }
    if let Ok(text) = core::str::from_utf8(data) {
        if let Ok(guid) = dtyp::Guid::parse_text(text) {
            assert_eq!(guid.to_text(), text, "one spelling per GUID");
        }
        if let Ok(sid) = dtyp::Sid::parse_sid_string(text) {
            let canonical = sid.to_sid_string();
            assert_eq!(
                dtyp::Sid::parse_sid_string(&canonical).expect("canonical form must parse"),
                sid
            );
            assert!(
                canonical.eq_ignore_ascii_case(text),
                "only letter case may differ"
            );
        }
    }
});
