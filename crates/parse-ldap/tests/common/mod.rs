//! Shared helpers for the integration tests.
//!
//! The element builder is derived independently from X.690 8.1.3.4 / 8.1.3.5
//! (minimal definite lengths), so test inputs do not depend on the crate's own
//! encoder. Messages are assembled from RFC 4511 App. B.
#![allow(dead_code)]

use parse_ldap::{decode_message, AuthState, DecodeOptions, Direction, LdapMessage, Profile};
use parse_ldap::{Error, Result};

/// One element with a minimal definite length. Spec: X.690 8.1.1.1,
/// 8.1.3.4 (short form <= 127), 8.1.3.5 (long form, minimum octets: 10.1).
pub fn tlv(identifier: u8, contents: &[u8]) -> Vec<u8> {
    let mut out = vec![identifier];
    let len = contents.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = (len as u32).to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        out.push(0x80 | (4 - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
    out.extend_from_slice(contents);
    out
}

/// `LDAPMessage ::= SEQUENCE { messageID, protocolOp, controls [0] OPTIONAL }`
/// with messageID 1 and the given protocolOp element. Spec: RFC 4511 §4.1.1.
pub fn message(op: &[u8]) -> Vec<u8> {
    let mut contents = vec![0x02, 0x01, 0x01];
    contents.extend_from_slice(op);
    tlv(0x30, &contents)
}

/// A SearchRequest message around `filter` (one complete Filter element):
/// baseObject "", scope baseObject, neverDerefAliases, no limits, typesOnly
/// FALSE, no attributes. Spec: RFC 4511 §4.5.1.
pub fn search_with_filter(filter: &[u8]) -> Vec<u8> {
    let mut contents = vec![
        0x04, 0x00, // baseObject ""
        0x0A, 0x01, 0x00, // scope baseObject
        0x0A, 0x01, 0x00, // derefAliases neverDerefAliases
        0x02, 0x01, 0x00, // sizeLimit 0
        0x02, 0x01, 0x00, // timeLimit 0
        0x01, 0x01, 0x00, // typesOnly FALSE
    ];
    contents.extend_from_slice(filter);
    contents.extend_from_slice(&[0x30, 0x00]); // attributes: empty selection
    message(&tlv(0x63, &contents))
}

/// `present [7] "a"`. Spec: RFC 4511 §4.5.1 (implicit, primitive).
pub const PRESENT_A: [u8; 3] = [0x87, 0x01, 0x61];

pub fn wire_request() -> DecodeOptions {
    DecodeOptions::request(AuthState::Unauthenticated)
}

pub fn canonical_request() -> DecodeOptions {
    DecodeOptions::canonical_request(AuthState::Unauthenticated)
}

pub fn wire_response() -> DecodeOptions {
    DecodeOptions {
        direction: Direction::Response,
        profile: Profile::Wire,
        max_message_octets: AuthState::Authenticated.max_message_octets(),
    }
}

pub fn canonical_response() -> DecodeOptions {
    DecodeOptions {
        direction: Direction::Response,
        profile: Profile::Canonical,
        max_message_octets: AuthState::Authenticated.max_message_octets(),
    }
}

/// Decode a request from the wire.
pub fn decode_request(bytes: &[u8]) -> Result<LdapMessage> {
    decode_message(bytes, &wire_request())
}

/// The error a request decode must produce.
pub fn request_error(bytes: &[u8]) -> Error {
    match decode_request(bytes) {
        Ok(m) => panic!("expected a rejection, decoded {m:?}"),
        Err(e) => e,
    }
}
