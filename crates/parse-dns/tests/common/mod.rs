//! Hand builders for DNS wire octets, each following the field layout of the
//! section it cites. No octet here comes from any other implementation or
//! capture; every message in the tests is assembled from these field layouts.

#![allow(dead_code)]

/// Header flag word of a QUERY request: QR = 0, OPCODE = 0. Spec: RFC 1035
/// §4.1.1.
pub const QUERY: u16 = 0x0000;
/// Header flag word of an UPDATE request: QR = 0, OPCODE = 5 (bits 1–4).
/// Spec: RFC 2136 §2.2.
pub const UPDATE: u16 = 5 << 11;
/// The QR bit (bit 0, the most significant). Spec: RFC 1035 §4.1.1, §2.3.2.
pub const QR: u16 = 0x8000;

/// TYPE values. Spec: RFC 1035 §3.2.2, §3.2.3; RFC 2782; RFC 8945 §3.
pub const T_A: u16 = 1;
pub const T_NS: u16 = 2;
pub const T_SOA: u16 = 6;
pub const T_SRV: u16 = 33;
pub const T_TSIG: u16 = 250;
pub const T_ANY: u16 = 255;
/// CLASS values. Spec: RFC 1035 §3.2.4, §3.2.5; RFC 2136 §1.3.
pub const C_IN: u16 = 1;
pub const C_CH: u16 = 3;
pub const C_NONE: u16 = 254;
pub const C_ANY: u16 = 255;

/// The 12-octet header. Spec: RFC 1035 §4.1.1.
pub fn header(id: u16, flags: u16, qd: u16, an: u16, ns: u16, ar: u16) -> Vec<u8> {
    [id, flags, qd, an, ns, ar]
        .iter()
        .flat_map(|w| w.to_be_bytes())
        .collect()
}

/// An uncompressed name from dotted text ("" or "." is the root).
/// Spec: RFC 1035 §3.1.
pub fn name(dotted: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in dotted.split('.').filter(|l| !l.is_empty()) {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

/// A compression pointer to `offset`. Spec: RFC 1035 §4.1.4.
pub fn pointer(offset: u16) -> Vec<u8> {
    assert!(offset < 0x4000);
    (0xC000 | offset).to_be_bytes().to_vec()
}

/// A question entry. Spec: RFC 1035 §4.1.2.
pub fn question(qname: &[u8], qtype: u16, qclass: u16) -> Vec<u8> {
    let mut out = qname.to_vec();
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&qclass.to_be_bytes());
    out
}

/// A resource record with RDLENGTH = `rdata.len()`. Spec: RFC 1035 §4.1.3.
pub fn rr(owner: &[u8], rr_type: u16, class: u16, ttl: u32, rdata: &[u8]) -> Vec<u8> {
    rr_with_rdlength(owner, rr_type, class, ttl, rdata.len() as u16, rdata)
}

/// A resource record with an explicit RDLENGTH. Spec: RFC 1035 §4.1.3.
pub fn rr_with_rdlength(
    owner: &[u8],
    rr_type: u16,
    class: u16,
    ttl: u32,
    rdlength: u16,
    rdata: &[u8],
) -> Vec<u8> {
    let mut out = owner.to_vec();
    out.extend_from_slice(&rr_type.to_be_bytes());
    out.extend_from_slice(&class.to_be_bytes());
    out.extend_from_slice(&ttl.to_be_bytes());
    out.extend_from_slice(&rdlength.to_be_bytes());
    out.extend_from_slice(rdata);
    out
}

/// SOA RDATA. Spec: RFC 1035 §3.3.13.
pub fn soa_rdata(mname: &[u8], rname: &[u8], fields: [u32; 5]) -> Vec<u8> {
    let mut out = mname.to_vec();
    out.extend_from_slice(rname);
    for f in fields {
        out.extend_from_slice(&f.to_be_bytes());
    }
    out
}

/// SRV RDATA. Spec: RFC 2782.
pub fn srv_rdata(priority: u16, weight: u16, port: u16, target: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for f in [priority, weight, port] {
        out.extend_from_slice(&f.to_be_bytes());
    }
    out.extend_from_slice(target);
    out
}

/// TSIG RDATA fields. Spec: RFC 8945 §4.2.
pub struct TsigFields<'a> {
    pub algorithm: &'a [u8],
    pub time_signed: u64,
    pub fudge: u16,
    pub mac: &'a [u8],
    pub original_id: u16,
    pub error: u16,
    pub other: &'a [u8],
}

/// TSIG RDATA, MAC Size = `mac.len()`. Spec: RFC 8945 §4.2.
pub fn tsig_rdata(f: &TsigFields<'_>) -> Vec<u8> {
    tsig_rdata_with_mac_size(f, f.mac.len() as u16)
}

/// TSIG RDATA with an explicit MAC Size. Spec: RFC 8945 §4.2.
pub fn tsig_rdata_with_mac_size(f: &TsigFields<'_>, mac_size: u16) -> Vec<u8> {
    let mut out = f.algorithm.to_vec();
    out.extend_from_slice(&f.time_signed.to_be_bytes()[2..]);
    out.extend_from_slice(&f.fudge.to_be_bytes());
    out.extend_from_slice(&mac_size.to_be_bytes());
    out.extend_from_slice(f.mac);
    out.extend_from_slice(&f.original_id.to_be_bytes());
    out.extend_from_slice(&f.error.to_be_bytes());
    out.extend_from_slice(&(f.other.len() as u16).to_be_bytes());
    out.extend_from_slice(f.other);
    out
}

/// A TSIG RR (CLASS ANY, TTL 0) with the given key name and RDATA.
/// Spec: RFC 8945 §4.2.
pub fn tsig_rr(key_name: &[u8], rdata: &[u8]) -> Vec<u8> {
    rr(key_name, T_TSIG, C_ANY, 0, rdata)
}

/// Default request TSIG fields: algorithm gss-tsig (RFC 3645 §8), a 28-octet
/// MAC placeholder (not a real MIC — the codec treats it as opaque), Error 0.
pub fn gss_tsig_fields<'a>(algorithm: &'a [u8], mac: &'a [u8], original_id: u16) -> TsigFields<'a> {
    TsigFields {
        algorithm,
        time_signed: 1_700_000_000,
        fudge: 300,
        mac,
        original_id,
        error: 0,
        other: &[],
    }
}

/// Concatenates parts.
pub fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

/// A minimal valid UPDATE request (zone `example.com` IN SOA, no
/// prerequisites, one "Add to an RRset" A record, signed with a gss-tsig TSIG
/// whose key name is `key.example.com`). Spec: RFC 2136 §2.3, §2.5.1;
/// RFC 8945 §4.2, §5.1.
pub fn signed_update(id: u16) -> Vec<u8> {
    let alg = name("gss-tsig");
    let mac = [0xA5u8; 28];
    cat(&[
        &header(id, UPDATE, 1, 0, 1, 1),
        &question(&name("example.com"), T_SOA, C_IN),
        &rr(&name("host.example.com"), T_A, C_IN, 3600, &[10, 2, 0, 52]),
        &tsig_rr(
            &name("key.example.com"),
            &tsig_rdata(&gss_tsig_fields(&alg, &mac, id)),
        ),
    ])
}
