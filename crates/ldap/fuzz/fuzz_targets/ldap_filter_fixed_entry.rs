#![no_main]
//! Fuzz target for the LDAP engine's filter evaluation
//! (crates/ldap/src/search/filter.rs, through `ldap::fuzz_hooks`).
//!
//! The input is taken as the octets of one Filter element, placed in a
//! SearchRequest built here (RFC 4511 §4.5.1), and decoded by parse-ldap the
//! way the front decodes a client's request (wire profile, authenticated
//! bound — docs/49 §2.3, §2.4). Every decoded filter is evaluated over the
//! fixed in-memory entry of `ldap::fuzz_hooks` with the engine's own code
//! (the three-valued tree, the steps of an item, assertion parsing and
//! comparison). Nothing panics, and the three-valued laws of RFC 4511
//! §4.5.1.7 hold:
//!
//! * not swaps TRUE and FALSE and keeps Undefined, so not(not(f)) = f;
//! * a one-element and / or equals its element;
//! * and with a FALSE item is FALSE (`secret` "does not exist", docs/49
//!   §6.5); or with a TRUE item is TRUE (`cn` is present and readable);
//! * or with an Undefined item (`shoeSize`, unrecognised) is TRUE only when
//!   the filter is TRUE, Undefined otherwise.
//!
//! Spec: RFC 4511 §4.5.1, §4.5.1.7; docs/49 §2.3, §6.2, §6.5; X.690
//! (02/2021) 8.1.3.4, 8.1.3.5 (the lengths written here).

use ldap::fuzz_hooks::evaluate_on_fixed_entry;
use libfuzzer_sys::fuzz_target;
use parse_ldap::{decode_message, AuthState, DecodeOptions, Filter, ProtocolOp};

/// One element with a minimal definite length: the short form for 0..=127,
/// else the long form with the fewest length octets. Spec: X.690 8.1.3.4,
/// 8.1.3.5.
fn tlv(identifier: u8, contents: &[u8]) -> Vec<u8> {
    let mut out = vec![identifier];
    let len = contents.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let octets = (len as u64).to_be_bytes();
        let skip = octets.iter().take_while(|b| **b == 0).count();
        out.push(0x80 | (octets.len() - skip) as u8);
        out.extend_from_slice(&octets[skip..]);
    }
    out.extend_from_slice(contents);
    out
}

/// `LDAPMessage { 1, SearchRequest { "", baseObject, neverDerefAliases, 0,
/// 0, FALSE, <filter>, {} } }`. Spec: RFC 4511 §4.1.1, §4.5.1.
fn search_with_filter(filter: &[u8]) -> Vec<u8> {
    let mut request = vec![
        0x04, 0x00, // baseObject ""
        0x0A, 0x01, 0x00, // scope baseObject
        0x0A, 0x01, 0x00, // derefAliases neverDerefAliases
        0x02, 0x01, 0x00, // sizeLimit 0
        0x02, 0x01, 0x00, // timeLimit 0
        0x01, 0x01, 0x00, // typesOnly FALSE
    ];
    request.extend_from_slice(filter);
    request.extend_from_slice(&[0x30, 0x00]); // attributes: empty selection
    let mut message = vec![0x02, 0x01, 0x01]; // messageID 1
    message.extend_from_slice(&tlv(0x63, &request)); // [APPLICATION 3]
    tlv(0x30, &message)
}

fn not(f: Filter) -> Filter {
    Filter::Not(Box::new(f))
}

fn present(description: &str) -> Filter {
    Filter::Present(description.to_owned())
}

fuzz_target!(|data: &[u8]| {
    let octets = search_with_filter(data);
    let options = DecodeOptions::request(AuthState::Authenticated);
    let Ok(message) = decode_message(&octets, &options) else {
        return;
    };
    let ProtocolOp::SearchRequest(request) = message.protocol_op else {
        return;
    };
    let f = request.filter;
    let e = evaluate_on_fixed_entry(&f);

    // not. Spec: RFC 4511 §4.5.1.7.
    assert_eq!(evaluate_on_fixed_entry(&not(f.clone())), e.map(|b| !b));
    assert_eq!(evaluate_on_fixed_entry(&not(not(f.clone()))), e);

    // One-element and / or.
    assert_eq!(evaluate_on_fixed_entry(&Filter::And(vec![f.clone()])), e);
    assert_eq!(evaluate_on_fixed_entry(&Filter::Or(vec![f.clone()])), e);

    // FALSE dominates and; TRUE dominates or.
    assert_eq!(
        evaluate_on_fixed_entry(&Filter::And(vec![f.clone(), present("secret")])),
        Some(false)
    );
    assert_eq!(
        evaluate_on_fixed_entry(&Filter::Or(vec![f.clone(), present("cn")])),
        Some(true)
    );

    // or with Undefined.
    let with_undefined = evaluate_on_fixed_entry(&Filter::Or(vec![f, present("shoeSize")]));
    assert_eq!(with_undefined, e.filter(|b| *b));
});
