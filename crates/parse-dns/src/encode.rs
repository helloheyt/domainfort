//! The canonical encoder (the server's replies, and test requests).
//!
//! Canonical means: no compression pointer anywhere (RFC 1035 §4.1.4:
//! "Programs are free to avoid using pointers in messages they generate";
//! docs/54 §6.3 — phase 1 encodes without compression), Z zero, counts equal
//! to the section lengths, the TSIG RR last in the additional section with
//! CLASS ANY and TTL 0. The encoder refuses every value the decoder would not
//! read back as the same value ([`Error::InvalidValue`]), so the server never
//! emits what it cannot parse back: `decode(encode(m))` yields `m` under the
//! profile matching `m`'s direction and counts (docs/54 §6.3, §10.2).

use crate::error::{Error, Result};
use crate::limits::MAX_TCP_MESSAGE_OCTETS;
use crate::name::Name;
use crate::types::{Class, Message, Opcode, Question, RData, ResourceRecord, RrType, TsigRecord};

/// Canonical encoding of `message`.
///
/// Spec: RFC 1035 §4.1–§4.1.3; RFC 2136 §2; RFC 2782; RFC 8945 §4.2, §5.1;
/// docs/54 §6.3.
pub fn encode(message: &Message) -> Result<Vec<u8>> {
    encode_inner(message, true)
}

/// The encoding of `message` without its TSIG RR (ARCOUNT not counting it):
/// the outgoing "DNS Message" MAC component. Spec: RFC 8945 §4.3.2.
pub(crate) fn encode_without_tsig(message: &Message) -> Result<Vec<u8>> {
    encode_inner(message, false)
}

fn encode_inner(message: &Message, with_tsig: bool) -> Result<Vec<u8>> {
    let header = &message.header;
    // RFC 2136 §2.2: UPDATE uses only QR — AA/TC/RD/RA are Z positions.
    if header.opcode == Opcode::Update && (header.aa || header.tc || header.rd || header.ra) {
        return Err(Error::InvalidValue);
    }
    let tsig = if with_tsig {
        message.tsig.as_ref()
    } else {
        None
    };

    let count = |n: usize| u16::try_from(n).map_err(|_| Error::MessageTooLarge);
    let qdcount = count(usize::from(message.question.is_some()))?;
    let ancount = count(message.answer.len())?;
    let nscount = count(message.authority.len())?;
    let arcount = count(message.additional.len() + usize::from(tsig.is_some()))?;

    // RFC 1035 §4.1.1: QR | OPCODE | AA | TC | RD | RA | Z = 0 | RCODE.
    let mut flags = u16::from(header.opcode.value()) << 11 | u16::from(header.rcode.value());
    for (set, bit) in [
        (header.qr, 0x8000),
        (header.aa, 0x0400),
        (header.tc, 0x0200),
        (header.rd, 0x0100),
        (header.ra, 0x0080),
    ] {
        if set {
            flags |= bit;
        }
    }

    let mut out = Vec::new();
    for word in [header.id, flags, qdcount, ancount, nscount, arcount] {
        out.extend_from_slice(&word.to_be_bytes());
    }
    if let Some(question) = &message.question {
        put_question(&mut out, question);
    }
    for record in message
        .answer
        .iter()
        .chain(&message.authority)
        .chain(&message.additional)
    {
        put_record(&mut out, record)?;
    }
    if let Some(tsig) = tsig {
        put_tsig(&mut out, tsig)?;
    }
    if out.len() > MAX_TCP_MESSAGE_OCTETS {
        return Err(Error::MessageTooLarge);
    }
    Ok(out)
}

fn put_name(out: &mut Vec<u8>, name: &Name) {
    // Uncompressed: the name's own wire form (RFC 1035 §3.1, §4.1.4).
    out.extend_from_slice(name.as_wire());
}

/// Spec: RFC 1035 §4.1.2.
fn put_question(out: &mut Vec<u8>, question: &Question) {
    put_name(out, &question.qname);
    out.extend_from_slice(&question.qtype.0.to_be_bytes());
    out.extend_from_slice(&question.qclass.0.to_be_bytes());
}

/// Spec: RFC 1035 §4.1.3.
fn put_record(out: &mut Vec<u8>, record: &ResourceRecord) -> Result<()> {
    let rr_type = record.rr_type();
    let class = record.class;
    let mut rdata = Vec::new();
    match &record.rdata {
        // The decoder types RDATA only under IN or NONE (types.rs, RData).
        RData::A(_) | RData::Ns(_) | RData::Soa(_) | RData::Srv(_)
            if class != Class::IN && class != Class::NONE =>
        {
            return Err(Error::InvalidValue);
        }
        // RFC 1035 §3.4.1.
        RData::A(address) => rdata.extend_from_slice(&address.octets()),
        // RFC 1035 §3.3.11.
        RData::Ns(nsdname) => put_name(&mut rdata, nsdname),
        // RFC 1035 §3.3.13.
        RData::Soa(soa) => {
            put_name(&mut rdata, &soa.mname);
            put_name(&mut rdata, &soa.rname);
            for field in [soa.serial, soa.refresh, soa.retry, soa.expire, soa.minimum] {
                rdata.extend_from_slice(&field.to_be_bytes());
            }
        }
        // RFC 2782: Target never compressed.
        RData::Srv(srv) => {
            for field in [srv.priority, srv.weight, srv.port] {
                rdata.extend_from_slice(&field.to_be_bytes());
            }
            put_name(&mut rdata, &srv.target);
        }
        // RFC 2136 meta forms: only under ANY or NONE; a TSIG-typed record
        // exists only in the TSIG slot (RFC 8945 §5.1).
        RData::Empty(empty_type) => {
            if (class != Class::ANY && class != Class::NONE) || *empty_type == RrType::TSIG {
                return Err(Error::InvalidValue);
            }
        }
        // Skipped on decode; the octets were never retained (docs/54 §6.4).
        RData::Unknown { .. } => return Err(Error::InvalidValue),
    }
    put_name(out, &record.name);
    out.extend_from_slice(&rr_type.0.to_be_bytes());
    out.extend_from_slice(&class.0.to_be_bytes());
    out.extend_from_slice(&record.ttl.to_be_bytes());
    put_rdata(out, &rdata)
}

/// The TSIG RR: NAME, TYPE TSIG, CLASS ANY, TTL 0, RDATA.
/// Spec: RFC 8945 §4.2.
fn put_tsig(out: &mut Vec<u8>, tsig: &TsigRecord) -> Result<()> {
    let mut rdata = Vec::new();
    // "this name MUST NOT be compressed".
    put_name(&mut rdata, &tsig.algorithm_name);
    rdata.extend_from_slice(&tsig.time_signed.seconds().to_be_bytes()[2..]);
    rdata.extend_from_slice(&tsig.fudge.to_be_bytes());
    let mac = tsig.mac.as_bytes();
    rdata.extend_from_slice(&(mac.len() as u16).to_be_bytes());
    rdata.extend_from_slice(mac);
    rdata.extend_from_slice(&tsig.original_id.to_be_bytes());
    rdata.extend_from_slice(&tsig.error.0.to_be_bytes());
    let other_len = u16::try_from(tsig.other_data.len()).map_err(|_| Error::MessageTooLarge)?;
    rdata.extend_from_slice(&other_len.to_be_bytes());
    rdata.extend_from_slice(&tsig.other_data);

    put_name(out, &tsig.key_name);
    out.extend_from_slice(&RrType::TSIG.0.to_be_bytes());
    out.extend_from_slice(&Class::ANY.0.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    put_rdata(out, &rdata)
}

/// RDLENGTH then RDATA. Spec: RFC 1035 §4.1.3.
fn put_rdata(out: &mut Vec<u8>, rdata: &[u8]) -> Result<()> {
    let rdlength = u16::try_from(rdata.len()).map_err(|_| Error::MessageTooLarge)?;
    out.extend_from_slice(&rdlength.to_be_bytes());
    out.extend_from_slice(rdata);
    Ok(())
}
