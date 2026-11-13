#![no_main]
//! Fuzz target for `parse_ldap::dn`, the RFC 4514 / `<GUID=hex>` DN parser.
//!
//! AGENTS.md §6 / docs/32 §8 (every parser gets a fuzz target before it
//! merges to main; docs/49 §2.5: "`dn` when the DN module is written"). On any
//! UTF-8 input the parser must not panic, and:
//!
//! * a parsed [`Dn`] has at most `MAX_DN_RDNS` RDNs, each value non-empty
//!   printable ASCII of at most `MAX_RDN_VALUE_OCTETS` octets (Q-080, Q-090);
//! * its canonical encoding is no longer than the input and parses back to
//!   the same value (RFC 4514 §2 output conforms to §3);
//! * each comparison key is the value with only A–Z folded (Q-080 item 2);
//! * the directory-component path rebuilds the same DN from `att=value`
//!   components (docs/47 §8.2).
//!
//! Spec: RFC 4514 §2, §3; [MS-ADTS] 3.1.1.3.1.2.4; docs/49 R49-11, §2.4.

use libfuzzer_sys::fuzz_target;
use parse_ldap::dn::{parse_ldap_dn, Dn, LdapDn};
use parse_ldap::{MAX_DN_RDNS, MAX_LDAPDN_OCTETS, MAX_RDN_VALUE_OCTETS};

fuzz_target!(|data: &[u8]| {
    let Ok(input) = core::str::from_utf8(data) else {
        return;
    };
    let parsed = parse_ldap_dn(input);
    if input.len() > MAX_LDAPDN_OCTETS {
        assert!(parsed.is_err(), "input bound enforced");
    }
    let Ok(LdapDn::Distinguished(dn)) = parsed else {
        return;
    };
    assert!(dn.rdns().len() <= MAX_DN_RDNS, "RDN count bounded");
    let mut components = Vec::with_capacity(dn.rdns().len());
    for rdn in dn.rdns() {
        let value = rdn.value().as_bytes();
        assert!(!value.is_empty() && value.len() <= MAX_RDN_VALUE_OCTETS);
        assert!(value.iter().all(|b| (0x20..=0x7E).contains(b)));
        let key = rdn.comparison_key();
        assert_eq!(key.len(), value.len());
        for (k, v) in key.iter().zip(value) {
            assert_eq!(*k, v.to_ascii_lowercase());
        }
        components.push(format!("{}={}", rdn.attribute_type().as_str(), rdn.value()));
    }
    let encoded = dn.encode();
    assert!(encoded.len() <= input.len(), "canonical form never grows");
    assert_eq!(Dn::parse(&encoded).as_ref(), Ok(&dn), "encode/parse round trip");
    assert_eq!(Dn::from_directory_rdns(&components).as_ref(), Ok(&dn));
});
