//! Shared test values for the dird-kpasswd channel.
//!
//! The Kerberos messages are **opaque** to this channel, so the tests use
//! hand-made octet strings that only have the shape the channel checks: the
//! first octet is the identifier of the message's `[APPLICATION n]` tag
//! (RFC 4120 §5.10: AP-REQ 14, AP-REP 15, KRB-PRIV 21; X.690 8.1.2.2: class
//! application `01`, constructed `1`, the tag number in bits 5–1), the rest
//! filler. No vector comes from any other implementation; RFC 3244 and RFC
//! 4120 have no examples.

#![allow(dead_code)]

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use ipc::{encode_frame, Direction};
use ipc_kpasswd::{
    ApRepOctets, ApReqOctets, ChangePasswordRequest, KpasswdReply, KpasswdRequest, KrbPrivOctets,
    ObservedAddress, SealedReply, KPASSWD_CHANNEL,
};

/// `[APPLICATION 14]`, constructed. Source: RFC 4120 §5.10; X.690 8.1.2.2.
pub const AP_REQ: u8 = 0x6E;
/// `[APPLICATION 15]`, constructed. Source: RFC 4120 §5.10; X.690 8.1.2.2.
pub const AP_REP: u8 = 0x6F;
/// `[APPLICATION 21]`, constructed. Source: RFC 4120 §5.10; X.690 8.1.2.2.
pub const KRB_PRIV: u8 = 0x75;
/// `[APPLICATION 28]` (EncKrbPrivPart), constructed. Source: RFC 4120
/// §5.10; X.690 8.1.2.2.
pub const ENC_KRB_PRIV_PART: u8 = 0x7C;
/// UNIVERSAL 16 (SEQUENCE), constructed — what a bare ChangePasswdData
/// starts with. Source: X.690 8.1.2.2, Table 1; X.680 Table 1 (SEQUENCE 16).
pub const SEQUENCE: u8 = 0x30;

/// `len` octets starting with `identifier`, then `fill`.
pub fn octets(identifier: u8, len: usize, fill: u8) -> Vec<u8> {
    let mut out = vec![fill; len];
    if let Some(first) = out.first_mut() {
        *first = identifier;
    }
    out
}

/// The client address of the tests: 192.0.2.10 (TEST-NET-1 documentation
/// range, chosen as obviously fake test data).
pub fn peer_v4() -> ObservedAddress {
    ObservedAddress::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)))
}

/// The local address of the tests: 2001:db8::464 (documentation prefix,
/// obviously fake test data).
pub fn local_v6() -> ObservedAddress {
    ObservedAddress::new(IpAddr::V6(Ipv6Addr::new(
        0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x464,
    )))
}

/// A request with a 40-octet AP-REQ and a 24-octet KRB-PRIV.
pub fn request() -> ChangePasswordRequest {
    ChangePasswordRequest::new(
        ApReqOctets::new(&octets(AP_REQ, 40, 0xA1)).expect("ap-req"),
        KrbPrivOctets::new(&octets(KRB_PRIV, 24, 0xB2)).expect("krb-priv"),
        peer_v4(),
        local_v6(),
    )
    .expect("request")
}

/// A sealed reply with a 30-octet AP-REP and a 20-octet KRB-PRIV.
pub fn sealed() -> SealedReply {
    SealedReply::new(
        ApRepOctets::new(&octets(AP_REP, 30, 0xC3)).expect("ap-rep"),
        KrbPrivOctets::new(&octets(KRB_PRIV, 20, 0xD4)).expect("krb-priv"),
    )
    .expect("sealed")
}

/// The body of `request` (without the length prefix).
pub fn request_body(request: &KpasswdRequest) -> Vec<u8> {
    encode_frame(KPASSWD_CHANNEL, Direction::Request, request)
        .expect("encodes")
        .body()
        .to_vec()
}

/// The body of `reply` (without the length prefix).
pub fn reply_body(reply: &KpasswdReply) -> Vec<u8> {
    encode_frame(KPASSWD_CHANNEL, Direction::Reply, reply)
        .expect("encodes")
        .body()
        .to_vec()
}
