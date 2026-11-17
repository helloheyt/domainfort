//! Hand-built inputs for the tests, written from the layouts of the
//! specifications — independent of the crate's own encoders, so a test that
//! compares the two catches a mistake in either.
//!
//! * RFC 2743 §3.1 — the framed token: 0x60, length (2a/2b), 0x06, OID
//!   length, OID octets, inner token.
//! * [MS-KILE] 1.9.1 / 3.1.1.7 — the two OIDs, encoded by RFC 2743 §3.1
//!   element 5 by hand below.
//! * RFC 4121 §4.1.1 — the authenticator checksum layout (little-endian).
//! * RFC 4121 §4.2.6.2 — the Wrap header layout (big-endian).
//!
//! No octet here comes from any other implementation or its test suite.

#![allow(dead_code)]

/// The Kerberos V5 OID 1.2.840.113554.1.2.2 ([MS-KILE] 1.9.1) encoded by
/// hand by RFC 2743 §3.1 element 5:
///
/// * 5a: 1 × 40 + 2 = 42 = 0x2A;
/// * 5b: 840 = 6·128 + 72 → 0x86 0x48;
/// * 5b: 113554 = 6·128² + 119·128 + 18 → 0x86 0xF7 0x12;
/// * 5b: 1, 2, 2 → 0x01 0x02 0x02.
pub const KRB5_OID: [u8; 9] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x02];

/// The truncated OID 1.2.840.48018.1.2.2 ([MS-KILE] 3.1.1.7), by hand:
/// 48018 = 2·128² + 119·128 + 18 → 0x82 0xF7 0x12; the other arcs as above.
pub const TRUNCATED_OID: [u8; 9] = [0x2A, 0x86, 0x48, 0x82, 0xF7, 0x12, 0x01, 0x02, 0x02];

/// RFC 4121 §4.1 TOK_IDs.
pub const TOK_AP_REQ: [u8; 2] = [0x01, 0x00];
pub const TOK_AP_REP: [u8; 2] = [0x02, 0x00];
pub const TOK_KRB_ERROR: [u8; 2] = [0x03, 0x00];

/// A length by RFC 2743 §3.1 2a/2b, by hand: one octet below 128; otherwise
/// 0x80 | count, then the value big-endian in the minimum octets.
pub fn length(value: usize) -> Vec<u8> {
    if value < 128 {
        vec![value as u8]
    } else if value < 0x100 {
        vec![0x81, value as u8]
    } else if value < 0x1_0000 {
        vec![0x82, (value >> 8) as u8, value as u8]
    } else {
        vec![0x83, (value >> 16) as u8, (value >> 8) as u8, value as u8]
    }
}

/// A framed token by RFC 2743 §3.1 with an arbitrary OID and inner token.
pub fn frame_with_oid(oid: &[u8], inner: &[u8]) -> Vec<u8> {
    let mut body = vec![0x06];
    body.extend(length(oid.len()));
    body.extend_from_slice(oid);
    body.extend_from_slice(inner);
    let mut token = vec![0x60];
    token.extend(length(body.len()));
    token.extend(body);
    token
}

/// A framed Kerberos V5 token: TOK_ID then the Kerberos message (RFC 4121
/// §4.1).
pub fn frame(tok_id: [u8; 2], kerberos_message: &[u8]) -> Vec<u8> {
    let mut inner = tok_id.to_vec();
    inner.extend_from_slice(kerberos_message);
    frame_with_oid(&KRB5_OID, &inner)
}

/// Stand-in octets for a Kerberos message: opaque to this crate (keyd
/// decodes the AP-REQ with krb-proto), so any non-empty octets serve. The
/// first octet is the [APPLICATION 14] constructed tag of KRB_AP_REQ
/// (RFC 4120 §5.5.1) only to make the role readable.
pub fn ap_req_stand_in(len: usize) -> Vec<u8> {
    let mut m = vec![0x6E];
    m.extend((1..len).map(|i| (i % 251) as u8));
    m
}

/// The authenticator checksum by RFC 4121 §4.1.1: Lgth (LE) ‖ Bnd ‖ Flags
/// (LE) ‖ trailing octets.
pub fn checksum(lgth: u32, bnd: [u8; 16], flags: u32, trailing: &[u8]) -> Vec<u8> {
    let mut c = lgth.to_le_bytes().to_vec();
    c.extend_from_slice(&bnd);
    c.extend_from_slice(&flags.to_le_bytes());
    c.extend_from_slice(trailing);
    c
}

/// A non-zero `Bnd` stand-in (the real value is an MD5 dird computes — task
/// LC1; opaque here).
pub const BND: [u8; 16] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xF1, 0x02,
];

/// GSS_C_INTEG_FLAG | GSS_C_MUTUAL_FLAG (RFC 4121 §4.1.1.1: 32 | 2).
pub const INTEG_MUTUAL: u32 = 32 | 2;

/// A Wrap header by RFC 4121 §4.2.6.2: 05 04, Flags, FF, EC, RRC, SND_SEQ
/// (big-endian).
pub fn wrap_header(flags: u8, ec: u16, rrc: u16, snd_seq: u64) -> [u8; 16] {
    let mut h = [0u8; 16];
    h[0] = 0x05;
    h[1] = 0x04;
    h[2] = flags;
    h[3] = 0xFF;
    h[4..6].copy_from_slice(&ec.to_be_bytes());
    h[6..8].copy_from_slice(&rrc.to_be_bytes());
    h[8..16].copy_from_slice(&snd_seq.to_be_bytes());
    h
}

/// A whole Wrap token: header ‖ data (data already in its on-the-wire, i.e.
/// rotated, order).
pub fn wrap_token(header: [u8; 16], data: &[u8]) -> Vec<u8> {
    let mut t = header.to_vec();
    t.extend_from_slice(data);
    t
}
