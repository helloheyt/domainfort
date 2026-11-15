//! The strict, bounded decoder.
//!
//! Order of work (fail closed at the first violation, AGENTS.md §6):
//!
//! 1. message size against the transport bound, before any octet is read
//!    (RFC 1035 §2.3.4, §4.2.1, §4.2.2);
//! 2. header (RFC 1035 §4.1.1), QR and OPCODE against the profile;
//! 3. section counts against the profile bounds (docs/54 §6.2), then against
//!    the octets present with every entry at its smallest — before any
//!    allocation (AGENTS.md §6);
//! 4. sections front to back; names through [`crate::name`] (compression with
//!    one hop per name, by construction); RDATA of the modelled types decoded
//!    with RDLENGTH matched exactly (docs/54 §6.2); other RDATA skipped;
//! 5. the TSIG RR only as the last additional record (RFC 8945 §5.2);
//! 6. nothing after the last record (docs/54 §6.2).

use crate::error::{Error, Result, Section};
use crate::limits::{
    HEADER_OCTETS, MAX_TCP_MESSAGE_OCTETS, MAX_TSIG_MAC_OCTETS, MAX_UDP_MESSAGE_OCTETS,
    MIN_NAME_OCTETS, QUERY_MAX_ARCOUNT, QUERY_QDCOUNT, QUESTION_FIXED_OCTETS, RR_FIXED_OCTETS,
    UPDATE_MAX_ADCOUNT, UPDATE_MAX_PRCOUNT, UPDATE_MAX_UPCOUNT, UPDATE_ZOCOUNT,
};
use crate::name::{decode_name, Compression, Name, NameTable};
use crate::types::{
    tsig_mac, Class, Header, Message, Opcode, Question, RData, Rcode, ResourceRecord, RrType, Soa,
    Srv, TsigError, TsigRecord, TsigTime,
};
use core::fmt;
use std::net::Ipv4Addr;

/// The transport a message arrived on (or will leave on).
///
/// Spec: RFC 1035 §4.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// UDP: at most 512 octets. Spec: RFC 1035 §2.3.4, §4.2.1.
    Udp,
    /// TCP: at most 65535 octets (the two-octet length prefix).
    /// Spec: RFC 1035 §4.2.2.
    Tcp,
}

impl Transport {
    /// The largest message this transport carries.
    pub const fn max_message_octets(self) -> usize {
        match self {
            Transport::Udp => MAX_UDP_MESSAGE_OCTETS,
            Transport::Tcp => MAX_TCP_MESSAGE_OCTETS,
        }
    }
}

/// Which side decodes, and so which bounds apply (docs/54 §6.1). dnsd and
/// dird decode with the same crate and the same bounds (docs/07 §5 via
/// docs/54 §6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// dnsd: a request (QR = 0) received on the given transport — QUERY
    /// (QDCOUNT = 1, ANCOUNT = NSCOUNT = 0, ARCOUNT ≤ 4) or UPDATE
    /// (ZOCOUNT = 1, PRCOUNT ≤ 16, UPCOUNT ≤ 16, ADCOUNT ≤ 1, the TSIG only —
    /// an unsigned UPDATE decodes, so that dnsd can answer REFUSED, RFC 2136
    /// §3.3.1). Compression allowed where RFC 1035 §4.1.4 allows it.
    /// Spec: docs/54 §6.1 (`Query`), §6.2.
    Query(Transport),
    /// dird: an UPDATE dnsd forwarded (always TCP-sourced, ≤ 65535 octets) —
    /// the same bounds, and the TSIG is required (dird never sees an unsigned
    /// UPDATE). QUERY is not forwarded in phase 1 (TKEY is blocked — DN9,
    /// docs/questions/Q-610), so it is refused here.
    /// Spec: docs/54 §4.5, §4.6, §6.1 (`Forwarded`), §6.2.
    Forwarded,
    /// A response (QR = 1) in the canonical form the encoder produces: no
    /// compression pointer anywhere, at most one question. Used to read back
    /// the server's own replies (round trip; test clients).
    /// Spec: docs/54 §6.1 (`Response`), §6.3, §10.2 (round trip);
    /// docs/questions/Q-642 item 1.
    Response(Transport),
}

impl Profile {
    /// The largest message this profile decodes.
    pub const fn max_message_octets(self) -> usize {
        match self {
            Profile::Query(transport) | Profile::Response(transport) => {
                transport.max_message_octets()
            }
            Profile::Forwarded => MAX_TCP_MESSAGE_OCTETS,
        }
    }

    const fn compression(self) -> Compression {
        match self {
            Profile::Query(_) | Profile::Forwarded => Compression::Allowed,
            Profile::Response(_) => Compression::Forbidden,
        }
    }

    const fn is_request(self) -> bool {
        !matches!(self, Profile::Response(_))
    }
}

/// The header exactly as carried, with its counts — enough to answer a
/// message that does not decode (FORMERR / NOTIMP with the request's ID and
/// OPCODE, docs/54 §6.6) or to drop a response (QR = 1).
///
/// Spec: RFC 1035 §4.1.1; RFC 2136 §2.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireHeader {
    /// ID.
    pub id: u16,
    /// QR.
    pub qr: bool,
    /// OPCODE, any of the 16 values.
    pub opcode: u8,
    /// AA.
    pub aa: bool,
    /// TC.
    pub tc: bool,
    /// RD.
    pub rd: bool,
    /// RA.
    pub ra: bool,
    /// RCODE.
    pub rcode: Rcode,
    /// QDCOUNT (UPDATE: ZOCOUNT).
    pub qdcount: u16,
    /// ANCOUNT (UPDATE: PRCOUNT).
    pub ancount: u16,
    /// NSCOUNT (UPDATE: UPCOUNT).
    pub nscount: u16,
    /// ARCOUNT (UPDATE: ADCOUNT).
    pub arcount: u16,
}

impl WireHeader {
    /// The OPCODE, if it is one this codec decodes.
    pub fn known_opcode(&self) -> Option<Opcode> {
        Opcode::from_value(self.opcode)
    }
}

/// Decodes only the header, after the size check of `transport`.
///
/// Spec: RFC 1035 §4.1.1 (bit 0 is the most significant — §2.3.2:
/// QR | OPCODE(4) | AA | TC | RD | RA | Z(3) | RCODE(4)).
pub fn decode_header(wire: &[u8], transport: Transport) -> Result<WireHeader> {
    if wire.len() > transport.max_message_octets() {
        return Err(Error::MessageTooLarge);
    }
    read_wire_header(wire)
}

fn read_wire_header(wire: &[u8]) -> Result<WireHeader> {
    let header = wire.get(..HEADER_OCTETS).ok_or(Error::Truncated)?;
    let word = |i: usize| u16::from_be_bytes([header[i], header[i + 1]]);
    let flags = word(2);
    Ok(WireHeader {
        id: word(0),
        qr: flags & 0x8000 != 0,
        opcode: ((flags >> 11) & 0x0F) as u8,
        aa: flags & 0x0400 != 0,
        tc: flags & 0x0200 != 0,
        rd: flags & 0x0100 != 0,
        ra: flags & 0x0080 != 0,
        // Z (0x0070) is not read: ignored on decode (RFC 2136 §2.2; docs/54
        // §6.2; docs/questions/Q-616 item 5).
        rcode: Rcode::new((flags & 0x000F) as u8).ok_or(Error::Truncated)?,
        qdcount: word(4),
        ancount: word(6),
        nscount: word(8),
        arcount: word(10),
    })
}

/// A decoded message bound to the exact octets it was decoded from.
///
/// The TSIG MAC is computed over the octets received (RFC 8945 §4.3.2), so
/// whoever acts on the message must act on the same octets the MAC covers
/// (docs/54 §4.1, class C2). This type is produced only by [`decode`], and
/// derives the MAC input components from its own octets — a component of one
/// message cannot be paired with the decoded content of another.
///
/// Its `Debug` output omits the octets (length only): message octets are
/// never logged (docs/54 §9).
#[derive(Clone)]
pub struct DecodedMessage<'a> {
    wire: &'a [u8],
    message: Message,
    tsig_offset: Option<usize>,
}

impl fmt::Debug for DecodedMessage<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DecodedMessage")
            .field("wire_octets", &self.wire.len())
            .field("message", &self.message)
            .field("tsig_offset", &self.tsig_offset)
            .finish()
    }
}

impl<'a> DecodedMessage<'a> {
    /// The decoded message.
    pub fn message(&self) -> &Message {
        &self.message
    }

    /// The decoded message, releasing the octets.
    pub fn into_message(self) -> Message {
        self.message
    }

    /// The octets the message was decoded from.
    pub fn wire(&self) -> &'a [u8] {
        self.wire
    }

    /// The "DNS Message" component of the MAC input for verifying the received
    /// TSIG: the received octets without the TSIG RR, ARCOUNT decremented,
    /// and the ID replaced by the TSIG's Original ID. `None` without a TSIG.
    ///
    /// Spec: RFC 8945 §4.3.2 ("When verifying an incoming message, the TSIG is
    /// checked against the message after the TSIG RR has been removed, the
    /// ARCOUNT decremented, and the message ID replaced by the original
    /// message ID from the TSIG if those IDs differ").
    ///
    /// The TSIG Variables component (RFC 8945 §4.3.3) is not built here: its
    /// names are "in canonical wire format", defined by RFC 4034 §6.2, which
    /// has not been opened (docs/questions/Q-641).
    pub fn tsig_message_component(&self) -> Option<Vec<u8>> {
        let offset = self.tsig_offset?;
        let tsig = self.message.tsig.as_ref()?;
        let mut octets = self.wire.get(..offset)?.to_vec();
        // The TSIG is counted in ARCOUNT (it is the last additional record),
        // so ARCOUNT ≥ 1 here.
        let arcount = u16::from_be_bytes([octets[10], octets[11]]).checked_sub(1)?;
        octets[0..2].copy_from_slice(&tsig.original_id.to_be_bytes());
        octets[10..12].copy_from_slice(&arcount.to_be_bytes());
        Some(octets)
    }

    /// The "Request MAC" component for the MAC input of the response to this
    /// request: MAC Size (16 bits, network order) then the MAC octets exactly
    /// as transmitted. `None` without a TSIG. Include it only once the
    /// request MAC has validated (RFC 8945 §4.3.1, §5.3.2).
    ///
    /// Spec: RFC 8945 §4.3.1 (Table 1).
    pub fn request_mac_component(&self) -> Option<Vec<u8>> {
        let tsig = self.message.tsig.as_ref()?;
        let mac = tsig.mac.as_bytes();
        let mut octets = Vec::with_capacity(2 + mac.len());
        octets.extend_from_slice(&(mac.len() as u16).to_be_bytes());
        octets.extend_from_slice(mac);
        Some(octets)
    }
}

/// Decodes one DNS message under `profile`.
///
/// Spec: RFC 1035 §4.1–§4.1.4; RFC 2136 §2; RFC 2782; RFC 8945 §4.2, §5.2;
/// docs/54 §6.1–§6.3.
pub fn decode(wire: &[u8], profile: Profile) -> Result<DecodedMessage<'_>> {
    if wire.len() > profile.max_message_octets() {
        return Err(Error::MessageTooLarge);
    }
    let raw = read_wire_header(wire)?;

    if raw.qr == profile.is_request() {
        return Err(Error::UnexpectedDirection);
    }
    let opcode = raw.known_opcode().ok_or(Error::UnsupportedOpcode)?;
    if profile == Profile::Forwarded && opcode != Opcode::Update {
        return Err(Error::UnsupportedOpcode);
    }
    check_counts(profile, opcode, &raw)?;

    // Every entry costs at least its smallest encoding; refuse counts the
    // message cannot hold before reserving anything for them.
    let minimum = usize::from(raw.qdcount) * (MIN_NAME_OCTETS + QUESTION_FIXED_OCTETS)
        + (usize::from(raw.ancount) + usize::from(raw.nscount) + usize::from(raw.arcount))
            * (MIN_NAME_OCTETS + RR_FIXED_OCTETS);
    if minimum > wire.len() - HEADER_OCTETS {
        return Err(Error::CountExceedsMessage);
    }

    let header = match opcode {
        Opcode::Query => Header {
            id: raw.id,
            qr: raw.qr,
            opcode,
            aa: raw.aa,
            tc: raw.tc,
            rd: raw.rd,
            ra: raw.ra,
            rcode: raw.rcode,
        },
        // RFC 2136 §2.2: UPDATE uses only QR; the other flag positions are Z,
        // and "A non-zero Z field should be ignored".
        Opcode::Update => Header {
            id: raw.id,
            qr: raw.qr,
            opcode,
            aa: false,
            tc: false,
            rd: false,
            ra: false,
            rcode: raw.rcode,
        },
    };

    let mut reader = Reader {
        wire,
        at: HEADER_OCTETS,
        table: NameTable::new(profile.compression()),
        compression: profile.compression(),
    };

    let question = match raw.qdcount {
        0 => None,
        _ => Some(reader.question()?),
    };
    let answer = reader.records(raw.ancount)?;
    let authority = reader.records(raw.nscount)?;

    let mut additional = Vec::with_capacity(usize::from(raw.arcount));
    let mut tsig = None;
    let mut tsig_offset = None;
    for index in 0..raw.arcount {
        let start = reader.at;
        match reader.record()? {
            Decoded::Record(record) => {
                if opcode == Opcode::Update && profile.is_request() {
                    return Err(Error::UnexpectedRecord);
                }
                additional.push(record);
            }
            Decoded::Tsig(record) => {
                if index + 1 != raw.arcount {
                    return Err(Error::MisplacedTsig);
                }
                if profile.is_request() && record.error != TsigError::NOERROR {
                    return Err(Error::MalformedTsig);
                }
                tsig = Some(record);
                tsig_offset = Some(start);
            }
        }
    }

    if reader.at != wire.len() {
        return Err(Error::TrailingData);
    }
    if profile == Profile::Forwarded && tsig.is_none() {
        return Err(Error::MissingTsig);
    }

    Ok(DecodedMessage {
        wire,
        message: Message {
            header,
            question,
            answer,
            authority,
            additional,
            tsig,
        },
        tsig_offset,
    })
}

/// Section counts against the profile bounds. Spec: docs/54 §6.2; RFC 2136
/// §2.3.
fn check_counts(profile: Profile, opcode: Opcode, raw: &WireHeader) -> Result<()> {
    let fail = |section| Err(Error::SectionCount(section));
    match (profile, opcode) {
        (Profile::Response(_), _) => {
            // The model holds at most one question (docs/54 §6.2).
            if raw.qdcount > 1 {
                return fail(Section::Question);
            }
        }
        (_, Opcode::Query) => {
            if raw.qdcount != QUERY_QDCOUNT {
                return fail(Section::Question);
            }
            if raw.ancount != 0 {
                return fail(Section::Answer);
            }
            if raw.nscount != 0 {
                return fail(Section::Authority);
            }
            if raw.arcount > QUERY_MAX_ARCOUNT {
                return fail(Section::Additional);
            }
        }
        (_, Opcode::Update) => {
            if raw.qdcount != UPDATE_ZOCOUNT {
                return fail(Section::Question);
            }
            if raw.ancount > UPDATE_MAX_PRCOUNT {
                return fail(Section::Answer);
            }
            if raw.nscount > UPDATE_MAX_UPCOUNT {
                return fail(Section::Authority);
            }
            if raw.arcount > UPDATE_MAX_ADCOUNT {
                return fail(Section::Additional);
            }
        }
    }
    Ok(())
}

/// What one record decoded to.
enum Decoded {
    Record(ResourceRecord),
    Tsig(TsigRecord),
}

/// Front-to-back reader over one message.
struct Reader<'a> {
    wire: &'a [u8],
    at: usize,
    table: NameTable,
    compression: Compression,
}

impl Reader<'_> {
    fn take(&mut self, n: usize, limit: usize) -> Result<&[u8]> {
        let end = self.at.checked_add(n).ok_or(Error::Truncated)?;
        if end > limit {
            return Err(Error::Truncated);
        }
        let octets = &self.wire[self.at..end];
        self.at = end;
        Ok(octets)
    }

    fn u16(&mut self, limit: usize) -> Result<u16> {
        let b = self.take(2, limit)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self, limit: usize) -> Result<u32> {
        let b = self.take(4, limit)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// An unsigned 48-bit integer in network order. Spec: RFC 8945 §4.2.
    fn u48(&mut self, limit: usize) -> Result<u64> {
        let b = self.take(6, limit)?;
        Ok(b.iter()
            .fold(0u64, |acc, &octet| (acc << 8) | u64::from(octet)))
    }

    fn name(&mut self, limit: usize, compression: Compression) -> Result<Name> {
        // The profile can forbid compression everywhere; a field can forbid
        // it locally.
        let compression = match self.compression {
            Compression::Forbidden => Compression::Forbidden,
            Compression::Allowed => compression,
        };
        let (name, next) = decode_name(self.wire, self.at, limit, compression, &mut self.table)?;
        self.at = next;
        Ok(name)
    }

    /// One question entry. Spec: RFC 1035 §4.1.2; RFC 2136 §2.3.
    fn question(&mut self) -> Result<Question> {
        let end = self.wire.len();
        let qname = self.name(end, Compression::Allowed)?;
        let qtype = RrType(self.u16(end)?);
        let qclass = Class(self.u16(end)?);
        Ok(Question {
            qname,
            qtype,
            qclass,
        })
    }

    /// `count` records of a section that may not hold the TSIG RR.
    fn records(&mut self, count: u16) -> Result<Vec<ResourceRecord>> {
        let mut records = Vec::with_capacity(usize::from(count));
        for _ in 0..count {
            match self.record()? {
                Decoded::Record(record) => records.push(record),
                // RFC 8945 §5.2: a TSIG anywhere but last in the additional
                // section is FORMERR.
                Decoded::Tsig(_) => return Err(Error::MisplacedTsig),
            }
        }
        Ok(records)
    }

    /// One resource record. Spec: RFC 1035 §4.1.3.
    fn record(&mut self) -> Result<Decoded> {
        let end = self.wire.len();
        let name = self.name(end, Compression::Allowed)?;
        let rr_type = RrType(self.u16(end)?);
        let class = Class(self.u16(end)?);
        let ttl = self.u32(end)?;
        let rdlength = self.u16(end)?;
        let rdata_end = self.at + usize::from(rdlength);
        if rdata_end > end {
            return Err(Error::Truncated);
        }

        if rr_type == RrType::TSIG {
            // RFC 8945 §4.2: CLASS MUST be ANY, TTL MUST be 0.
            if class != Class::ANY || ttl != 0 {
                return Err(Error::MalformedTsig);
            }
            let tsig = self.tsig_rdata(name, rdata_end).map_err(rdata_bound)?;
            return Ok(Decoded::Tsig(tsig));
        }

        let rdata = self
            .rdata(rr_type, class, rdlength, rdata_end)
            .map_err(rdata_bound)?;
        if self.at != rdata_end {
            return Err(Error::RdataLength);
        }
        Ok(Decoded::Record(ResourceRecord {
            name,
            class,
            ttl,
            rdata,
        }))
    }

    /// RDATA of a non-TSIG record ending at `rdata_end`.
    fn rdata(
        &mut self,
        rr_type: RrType,
        class: Class,
        rdlength: u16,
        rdata_end: usize,
    ) -> Result<RData> {
        // RFC 2136 §2.4.1, §2.4.3–§2.4.5, §2.5.2, §2.5.3: RDLENGTH zero under
        // CLASS ANY or NONE — the meta forms.
        if rdlength == 0 && (class == Class::ANY || class == Class::NONE) {
            return Ok(RData::Empty(rr_type));
        }
        // Typed RDATA only where its format is the one this codec knows: IN,
        // and NONE (§2.5.4 — the RR to delete, in the zone class's format).
        if class == Class::IN || class == Class::NONE {
            match rr_type {
                // RFC 1035 §3.4.1: a 32 bit Internet address.
                RrType::A => {
                    let b = self.take(4, rdata_end)?;
                    return Ok(RData::A(Ipv4Addr::new(b[0], b[1], b[2], b[3])));
                }
                // RFC 1035 §3.3.11: NSDNAME, compressible (§3.3).
                RrType::NS => {
                    return Ok(RData::Ns(self.name(rdata_end, Compression::Allowed)?));
                }
                // RFC 1035 §3.3.13: MNAME, RNAME (compressible, §3.3), then
                // five 32-bit fields.
                RrType::SOA => {
                    let mname = self.name(rdata_end, Compression::Allowed)?;
                    let rname = self.name(rdata_end, Compression::Allowed)?;
                    return Ok(RData::Soa(Soa {
                        mname,
                        rname,
                        serial: self.u32(rdata_end)?,
                        refresh: self.u32(rdata_end)?,
                        retry: self.u32(rdata_end)?,
                        expire: self.u32(rdata_end)?,
                        minimum: self.u32(rdata_end)?,
                    }));
                }
                // RFC 2782: Priority, Weight, Port, Target (never compressed).
                RrType::SRV => {
                    let priority = self.u16(rdata_end)?;
                    let weight = self.u16(rdata_end)?;
                    let port = self.u16(rdata_end)?;
                    let target = self.name(rdata_end, Compression::Forbidden)?;
                    return Ok(RData::Srv(Srv {
                        priority,
                        weight,
                        port,
                        target,
                    }));
                }
                _ => {}
            }
        }
        // docs/54 §6.1: any other RDATA is skipped by RDLENGTH, never retained.
        self.at = rdata_end;
        Ok(RData::Unknown { rr_type, rdlength })
    }

    /// TSIG RDATA ending at `rdata_end`, which must be consumed exactly.
    /// Spec: RFC 8945 §4.2.
    fn tsig_rdata(&mut self, key_name: Name, rdata_end: usize) -> Result<TsigRecord> {
        // "As per [RFC3597], this name MUST NOT be compressed."
        let algorithm_name = self.name(rdata_end, Compression::Forbidden)?;
        let time_signed = TsigTime::new(self.u48(rdata_end)?).ok_or(Error::MalformedTsig)?;
        let fudge = self.u16(rdata_end)?;
        let mac_size = usize::from(self.u16(rdata_end)?);
        // docs/54 §6.2: MAC Size ≤ 64, checked before the MAC is read.
        if mac_size > MAX_TSIG_MAC_OCTETS {
            return Err(Error::TsigMacTooLong);
        }
        let mac = tsig_mac(self.take(mac_size, rdata_end)?)?;
        let original_id = self.u16(rdata_end)?;
        let error = TsigError(self.u16(rdata_end)?);
        let other_len = usize::from(self.u16(rdata_end)?);
        let other_data = self.take(other_len, rdata_end)?.to_vec();
        if self.at != rdata_end {
            return Err(Error::RdataLength);
        }
        Ok(TsigRecord {
            key_name,
            algorithm_name,
            time_signed,
            fudge,
            mac,
            original_id,
            error,
            other_data,
        })
    }
}

/// Inside RDATA the bound is RDLENGTH (already checked to lie within the
/// message), so running past it means RDLENGTH is too short for the fields.
fn rdata_bound(error: Error) -> Error {
    match error {
        Error::Truncated => Error::RdataLength,
        other => other,
    }
}
