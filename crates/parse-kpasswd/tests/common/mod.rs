//! Shared helpers for building RFC 3244 messages by hand.
//!
//! RFC 3244 has no examples, so every test message is assembled here octet by
//! octet from the §2 diagrams — independently of this crate's encoder:
//!
//! ```text
//! message length (16) | protocol version number (16)
//! AP_REQ / AP_REP length (16) | AP data | KRB-PRIV (or KRB-ERROR)
//! ```
//!
//! "All 16 bit fields are in big-endian order"; the TCP header is "a 4 octet
//! header in network byte order". The Kerberos messages inside are arbitrary
//! octets unless a test says otherwise (the framing treats them as opaque).
//! No message comes from any other implementation.
#![allow(dead_code)] // each test binary uses a different subset

/// A 16-bit field, big-endian. RFC 3244 §2.
pub fn be16(n: u16) -> [u8; 2] {
    n.to_be_bytes()
}

/// A message with every header field given explicitly (so tests can make any
/// of them wrong). RFC 3244 §2 (request and reply diagrams).
pub fn raw_message(message_length: u16, version: u16, ap_length: u16, body: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&be16(message_length));
    out.extend_from_slice(&be16(version));
    out.extend_from_slice(&be16(ap_length));
    for part in body {
        out.extend_from_slice(part);
    }
    out
}

/// A well-formed message: `message length` = 6 + both fields, `AP length` =
/// the first field. RFC 3244 §2.
pub fn message(version: u16, ap: &[u8], last: &[u8]) -> Vec<u8> {
    let total = u16::try_from(6 + ap.len() + last.len()).expect("test message fits");
    let ap_length = u16::try_from(ap.len()).expect("test AP fits");
    raw_message(total, version, ap_length, &[ap, last])
}

/// A well-formed request (version 0xff80). RFC 3244 §2.
pub fn request(ap_req: &[u8], krb_priv: &[u8]) -> Vec<u8> {
    message(0xFF80, ap_req, krb_priv)
}

/// A well-formed AP-REP + KRB-PRIV reply (version 0x0001). RFC 3244 §2.
pub fn reply(ap_rep: &[u8], krb_priv: &[u8]) -> Vec<u8> {
    message(0x0001, ap_rep, krb_priv)
}

/// A well-formed KRB-ERROR reply (version 0x0001, AP_REP length 0).
/// RFC 3244 §2.
pub fn error_reply(krb_error: &[u8]) -> Vec<u8> {
    message(0x0001, &[], krb_error)
}

/// Prefix a message with a 4-octet big-endian TCP header holding `length`.
/// RFC 3244 §2.
pub fn tcp_with(length: u32, message: &[u8]) -> Vec<u8> {
    let mut out = length.to_be_bytes().to_vec();
    out.extend_from_slice(message);
    out
}

/// Prefix a message with its correct TCP header. RFC 3244 §2.
pub fn tcp(message: &[u8]) -> Vec<u8> {
    tcp_with(u32::try_from(message.len()).unwrap(), message)
}

/// Arbitrary stand-ins for the opaque Kerberos messages. The first octet is
/// the DER identifier of the named message (RFC 4120 5.10 application tags
/// 14, 15, 21, 30 → 0x6E, 0x6F, 0x75, 0x7E; X.690 8.1.2) only to make dumps
/// readable — the framing never looks at it.
pub fn ap_req_octets() -> Vec<u8> {
    let mut v = vec![0x6E, 0x10];
    v.extend(0x20..0x30);
    v
}

pub fn ap_rep_octets() -> Vec<u8> {
    let mut v = vec![0x6F, 0x08];
    v.extend(0x50..0x58);
    v
}

pub fn krb_priv_octets() -> Vec<u8> {
    let mut v = vec![0x75, 0x0C];
    v.extend(0x60..0x6C);
    v
}

pub fn krb_error_octets() -> Vec<u8> {
    let mut v = vec![0x7E, 0x06];
    v.extend(0x70..0x76);
    v
}
