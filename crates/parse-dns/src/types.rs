//! The message model: header, question, resource records, TSIG.
//!
//! The model is shaped so that what the specifications forbid in phase 1 has
//! no representation (docs/CLEAN-ROOM.md):
//!
//! * section counts are not stored — they are the lengths of the sections, so
//!   a count that disagrees with the records cannot exist;
//! * at most one question (docs/54 §6.2; RFC 2136 §2.3);
//! * the TSIG RR has its own slot, which the encoder always writes last in
//!   the additional section, with CLASS ANY and TTL 0 — "not last", "more
//!   than one" and a wrong CLASS/TTL cannot be expressed (RFC 8945 §4.2, §5.1);
//! * the header has no Z field (it is ignored on decode and always zero on
//!   encode — RFC 2136 §2.2; docs/54 §6.2);
//! * RDATA of a type the codec does not model is skipped on decode and its
//!   octets are never retained, so no reply can reflect them (docs/54 §6.1,
//!   §6.4 "never echoed").

use crate::error::{Error, Result};
use crate::limits::{MAX_TSIG_MAC_OCTETS, MAX_TSIG_TIME_SIGNED};
use crate::name::Name;
use core::fmt;
use std::net::Ipv4Addr;

/// A TYPE / QTYPE value. Values not named here are carried as numbers.
///
/// Spec: RFC 1035 §3.2.2 (TYPE), §3.2.3 (QTYPE); RFC 2782; RFC 8945 §3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RrType(pub u16);

impl RrType {
    /// A — a host address. Spec: RFC 1035 §3.2.2.
    pub const A: RrType = RrType(1);
    /// NS — an authoritative name server. Spec: RFC 1035 §3.2.2.
    pub const NS: RrType = RrType(2);
    /// SOA — marks the start of a zone of authority. Spec: RFC 1035 §3.2.2.
    pub const SOA: RrType = RrType(6);
    /// SRV — location of services. Spec: RFC 2782 ("whose DNS type code is
    /// 33").
    pub const SRV: RrType = RrType(33);
    /// TSIG — transaction signature (a meta-RR). Spec: RFC 8945 §3, §4.1.
    pub const TSIG: RrType = RrType(250);
    /// AXFR — a request for a transfer of an entire zone (QTYPE only).
    /// Spec: RFC 1035 §3.2.3.
    pub const AXFR: RrType = RrType(252);
    /// MAILB — mailbox-related records (QTYPE only). Spec: RFC 1035 §3.2.3.
    pub const MAILB: RrType = RrType(253);
    /// MAILA — mail agent RRs (QTYPE only, obsolete). Spec: RFC 1035 §3.2.3.
    pub const MAILA: RrType = RrType(254);
    /// ANY ("*" in RFC 1035) — all records. A QTYPE, and the TYPE of the
    /// UPDATE meta forms. Spec: RFC 1035 §3.2.3; RFC 2136 §2.4.4, §2.5.3.
    pub const ANY: RrType = RrType(255);
}

/// A CLASS / QCLASS value. Values not named here are carried as numbers.
///
/// Spec: RFC 1035 §3.2.4, §3.2.5; RFC 2136 §1.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Class(pub u16);

impl Class {
    /// IN — the Internet. Spec: RFC 1035 §3.2.4.
    pub const IN: Class = Class(1);
    /// NONE — used by UPDATE prerequisites and deletions. Spec: RFC 2136 §1.3.
    pub const NONE: Class = Class(254);
    /// ANY ("*" in RFC 1035) — any class; the CLASS of the TSIG RR and of the
    /// UPDATE meta forms. Spec: RFC 1035 §3.2.5; RFC 2136 §2.4.1; RFC 8945 §4.2.
    pub const ANY: Class = Class(255);
}

/// The opcodes this codec decodes into a [`Message`]. Every other value is
/// refused with [`Error::UnsupportedOpcode`] and visible only through
/// [`crate::WireHeader`].
///
/// Spec: RFC 1035 §4.1.1 (OPCODE 0 = QUERY); RFC 2136 §1.3, §2.2 (UPDATE = 5);
/// docs/54 §3.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Opcode {
    /// A standard query (0). Spec: RFC 1035 §4.1.1.
    Query,
    /// A dynamic update (5). Spec: RFC 2136 §2.2.
    Update,
}

impl Opcode {
    /// The 4-bit OPCODE value. Spec: RFC 1035 §4.1.1; RFC 2136 §2.2.
    pub const fn value(self) -> u8 {
        match self {
            Opcode::Query => 0,
            Opcode::Update => 5,
        }
    }

    /// The opcode for a 4-bit OPCODE value, if this codec decodes it.
    pub const fn from_value(value: u8) -> Option<Opcode> {
        match value {
            0 => Some(Opcode::Query),
            5 => Some(Opcode::Update),
            _ => None,
        }
    }
}

/// A 4-bit header RCODE (0..=15).
///
/// Spec: RFC 1035 §4.1.1 (0–5); RFC 2136 §1.3, §2.2 (6–10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Rcode(u8);

impl Rcode {
    /// No error condition. Spec: RFC 1035 §4.1.1; RFC 2136 §2.2.
    pub const NOERROR: Rcode = Rcode(0);
    /// Format error. Spec: RFC 1035 §4.1.1.
    pub const FORMERR: Rcode = Rcode(1);
    /// Server failure. Spec: RFC 1035 §4.1.1.
    pub const SERVFAIL: Rcode = Rcode(2);
    /// Name error. Spec: RFC 1035 §4.1.1.
    pub const NXDOMAIN: Rcode = Rcode(3);
    /// Not implemented. Spec: RFC 1035 §4.1.1.
    pub const NOTIMP: Rcode = Rcode(4);
    /// Refused. Spec: RFC 1035 §4.1.1.
    pub const REFUSED: Rcode = Rcode(5);
    /// Some name that ought not to exist, does exist. Spec: RFC 2136 §2.2.
    pub const YXDOMAIN: Rcode = Rcode(6);
    /// Some RRset that ought not to exist, does exist. Spec: RFC 2136 §2.2.
    pub const YXRRSET: Rcode = Rcode(7);
    /// Some RRset that ought to exist, does not exist. Spec: RFC 2136 §2.2.
    pub const NXRRSET: Rcode = Rcode(8);
    /// Not authoritative for the zone (also the RCODE of TSIG errors).
    /// Spec: RFC 2136 §2.2; RFC 8945 §5.2.1.
    pub const NOTAUTH: Rcode = Rcode(9);
    /// A name is not within the zone. Spec: RFC 2136 §2.2.
    pub const NOTZONE: Rcode = Rcode(10);

    /// The RCODE for a value that fits the 4-bit field.
    pub const fn new(value: u8) -> Option<Rcode> {
        if value <= 0x0F {
            Some(Rcode(value))
        } else {
            None
        }
    }

    /// The 4-bit value.
    pub const fn value(self) -> u8 {
        self.0
    }
}

/// The 16-bit Error field of a TSIG RR (an extended RCODE covering TSIG
/// processing). Values not named here are carried as numbers.
///
/// Spec: RFC 8945 §3, §4.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TsigError(pub u16);

impl TsigError {
    /// No error — the only value allowed in a request. Spec: RFC 8945 §4.2
    /// ("In requests, this MUST be zero"); RFC 2136 §2.2 (mnemonic of 0).
    pub const NOERROR: TsigError = TsigError(0);
    /// BADSIG. Spec: RFC 8945 §3.
    pub const BADSIG: TsigError = TsigError(16);
    /// BADKEY. Spec: RFC 8945 §3.
    pub const BADKEY: TsigError = TsigError(17);
    /// BADTIME. Spec: RFC 8945 §3.
    pub const BADTIME: TsigError = TsigError(18);
    /// BADTRUNC. Spec: RFC 8945 §3.
    pub const BADTRUNC: TsigError = TsigError(22);
}

/// The header of a decoded [`Message`] (counts excluded: they are the section
/// lengths; Z excluded: ignored on decode, zero on encode).
///
/// For UPDATE the AA, TC, RD and RA positions are part of Z (RFC 2136 §2.2:
/// "UPDATE uses only one flag bit (QR)"): they are ignored on decode (always
/// `false` here) and the encoder refuses them set.
///
/// Spec: RFC 1035 §4.1.1; RFC 2136 §2.2; docs/54 §6.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// ID. Spec: RFC 1035 §4.1.1.
    pub id: u16,
    /// QR: `false` for a query/request, `true` for a response.
    pub qr: bool,
    /// OPCODE.
    pub opcode: Opcode,
    /// AA — Authoritative Answer (QUERY only).
    pub aa: bool,
    /// TC — TrunCation (QUERY only).
    pub tc: bool,
    /// RD — Recursion Desired (QUERY only).
    pub rd: bool,
    /// RA — Recursion Available (QUERY only).
    pub ra: bool,
    /// RCODE.
    pub rcode: Rcode,
}

/// A question entry (for UPDATE, the zone entry: ZNAME, ZTYPE, ZCLASS).
///
/// Spec: RFC 1035 §4.1.2; RFC 2136 §2.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    /// QNAME (UPDATE: ZNAME).
    pub qname: Name,
    /// QTYPE (UPDATE: ZTYPE).
    pub qtype: RrType,
    /// QCLASS (UPDATE: ZCLASS).
    pub qclass: Class,
}

/// SOA RDATA. Spec: RFC 1035 §3.3.13.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Soa {
    /// MNAME — the primary name server for the zone.
    pub mname: Name,
    /// RNAME — the mailbox of the person responsible for the zone.
    pub rname: Name,
    /// SERIAL — unsigned 32-bit version number of the zone.
    pub serial: u32,
    /// REFRESH, in seconds.
    pub refresh: u32,
    /// RETRY, in seconds.
    pub retry: u32,
    /// EXPIRE, in seconds.
    pub expire: u32,
    /// MINIMUM — the minimum TTL exported with any RR from the zone.
    pub minimum: u32,
}

/// SRV RDATA. Spec: RFC 2782 ("The format of the SRV RR").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Srv {
    /// Priority (0–65535; lowest first).
    pub priority: u16,
    /// Weight (0–65535).
    pub weight: u16,
    /// Port on the target host.
    pub port: u16,
    /// Target — never compressed ("name compression is not to be used for
    /// this field"); "." means the service is not available.
    pub target: Name,
}

/// The RDATA of a resource record, as far as the codec models it.
///
/// Typed RDATA (A, NS, SOA, SRV) is decoded only under CLASS IN, or NONE (the
/// UPDATE "Delete an RR from an RRset" form, whose RDATA has the zone class's
/// format) — RFC 1035 §4.1.3 ("if the TYPE is A and the CLASS is IN, the RDATA
/// field is a 4 octet ARPA Internet address"), RFC 1034 §3.6 (A differs in
/// other classes), RFC 2782 ("SRV records occur in the IN Class"), RFC 2136
/// §2.5.4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RData {
    /// A: ADDRESS. Spec: RFC 1035 §3.4.1.
    A(Ipv4Addr),
    /// NS: NSDNAME. Spec: RFC 1035 §3.3.11.
    Ns(Name),
    /// SOA. Spec: RFC 1035 §3.3.13.
    Soa(Soa),
    /// SRV. Spec: RFC 2782.
    Srv(Srv),
    /// RDLENGTH zero under CLASS ANY or NONE: the UPDATE prerequisite and
    /// deletion forms, carrying only the TYPE they name.
    /// Spec: RFC 2136 §2.4.1, §2.4.3–§2.4.5, §2.5.2, §2.5.3.
    Empty(RrType),
    /// A record whose RDATA the codec does not model (another TYPE, or a
    /// modelled TYPE under another CLASS). Only TYPE and RDLENGTH are kept:
    /// the RDATA octets were skipped, never retained, and such a record cannot
    /// be encoded. Spec: docs/54 §6.1 ("any other type: opaque RDATA bounded
    /// by RDLENGTH, kept only for skipping"), §6.4.
    Unknown {
        /// TYPE.
        rr_type: RrType,
        /// RDLENGTH of the skipped RDATA.
        rdlength: u16,
    },
}

impl RData {
    /// The TYPE of a record with this RDATA.
    pub fn rr_type(&self) -> RrType {
        match self {
            RData::A(_) => RrType::A,
            RData::Ns(_) => RrType::NS,
            RData::Soa(_) => RrType::SOA,
            RData::Srv(_) => RrType::SRV,
            RData::Empty(rr_type) | RData::Unknown { rr_type, .. } => *rr_type,
        }
    }
}

/// A resource record other than the TSIG RR.
///
/// Spec: RFC 1035 §3.2.1, §4.1.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceRecord {
    /// NAME — the owner name.
    pub name: Name,
    /// CLASS.
    pub class: Class,
    /// TTL, as carried (RFC 1035 §4.1.3 calls it unsigned 32-bit; §2.3.4 and
    /// §3.2.1 limit it to positive signed values — range policy belongs to
    /// the consumer, docs/54 §5.5, §6.4).
    pub ttl: u32,
    /// RDATA (its TYPE is [`RData::rr_type`]).
    pub rdata: RData,
}

impl ResourceRecord {
    /// TYPE.
    pub fn rr_type(&self) -> RrType {
        self.rdata.rr_type()
    }
}

/// A TSIG Time Signed value: seconds since 1970-01-01 UTC, 48 bits.
///
/// Spec: RFC 8945 §4.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TsigTime(u64);

impl TsigTime {
    /// The value, if it fits in 48 bits.
    pub const fn new(seconds: u64) -> Option<TsigTime> {
        if seconds <= MAX_TSIG_TIME_SIGNED {
            Some(TsigTime(seconds))
        } else {
            None
        }
    }

    /// Seconds since 1970-01-01 UTC.
    pub const fn seconds(self) -> u64 {
        self.0
    }
}

/// A TSIG MAC (possibly empty, as in unsigned error replies), at most
/// [`MAX_TSIG_MAC_OCTETS`] octets.
///
/// Its `Debug` output shows only the length: for GSS-TSIG the MAC is a GSS MIC
/// token, which is never logged (docs/54 §9).
///
/// Spec: RFC 8945 §4.2, §5.3.2 ("MAC Size == 0 and empty MAC"); docs/54 §6.2.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct TsigMac(Vec<u8>);

impl fmt::Debug for TsigMac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TsigMac({} octets)", self.0.len())
    }
}

impl TsigMac {
    /// The MAC, if it is within the bound.
    pub fn new(octets: Vec<u8>) -> Option<TsigMac> {
        if octets.len() <= MAX_TSIG_MAC_OCTETS {
            Some(TsigMac(octets))
        } else {
            None
        }
    }

    /// The MAC octets, exactly as transmitted.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// The TSIG RR: its owner name (the key name) and RDATA. Its TYPE is TSIG,
/// its CLASS is ANY and its TTL is 0 — fixed, so not stored.
///
/// Its `Debug` output omits the key name, the MAC and Other Data (lengths
/// only): none of them is ever logged (docs/54 §9 — raw key_name, MICs).
///
/// Spec: RFC 8945 §4.2.
#[derive(Clone, PartialEq, Eq)]
pub struct TsigRecord {
    /// NAME — the name of the key (for GSS-TSIG, the key_name of the context —
    /// RFC 3645 §5.1).
    pub key_name: Name,
    /// Algorithm Name — never compressed.
    pub algorithm_name: Name,
    /// Time Signed.
    pub time_signed: TsigTime,
    /// Fudge — allowed time difference in seconds.
    pub fudge: u16,
    /// MAC (its length is the MAC Size field).
    pub mac: TsigMac,
    /// Original ID.
    pub original_id: u16,
    /// Error.
    pub error: TsigError,
    /// Other Data (its length is the Other Len field).
    pub other_data: Vec<u8>,
}

impl fmt::Debug for TsigRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TsigRecord")
            .field("key_name_octets", &self.key_name.wire_len())
            .field("algorithm_name", &self.algorithm_name)
            .field("time_signed", &self.time_signed)
            .field("fudge", &self.fudge)
            .field("mac", &self.mac)
            .field("original_id", &self.original_id)
            .field("error", &self.error)
            .field("other_data_octets", &self.other_data.len())
            .finish()
    }
}

/// The TSIG Algorithm Name of GSS-TSIG, in printed form.
///
/// Spec: RFC 3645 §8 ("The IANA has reserved the TSIG Algorithm name gss-tsig");
/// RFC 8945 §6 (Table 3).
pub const GSS_TSIG_ALGORITHM: &str = "gss-tsig";

impl TsigRecord {
    /// Whether the Algorithm Name is `gss-tsig` (compared as a name: ASCII
    /// case-insensitive). Spec: RFC 3645 §8; RFC 1035 §3.1; docs/54 §4.5
    /// step 1.
    pub fn algorithm_is_gss_tsig(&self) -> bool {
        let mut labels = self.algorithm_name.labels();
        matches!(
            (labels.next(), labels.next()),
            (Some(label), None) if label.eq_ignore_ascii_case(GSS_TSIG_ALGORITHM.as_bytes())
        )
    }
}

/// A DNS message: QUERY or UPDATE, request or response.
///
/// Spec: RFC 1035 §4.1; RFC 2136 §2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// Header (counts derive from the sections).
    pub header: Header,
    /// Question section — at most one entry (UPDATE: the Zone section).
    pub question: Option<Question>,
    /// Answer section (UPDATE: Prerequisite section).
    pub answer: Vec<ResourceRecord>,
    /// Authority section (UPDATE: Update section).
    pub authority: Vec<ResourceRecord>,
    /// Additional section without the TSIG RR (UPDATE: Additional Data).
    pub additional: Vec<ResourceRecord>,
    /// The TSIG RR, always the last record of the additional section.
    pub tsig: Option<TsigRecord>,
}

impl Message {
    /// The Zone section of an UPDATE (`None` for QUERY). Spec: RFC 2136 §2.3.
    pub fn zone(&self) -> Option<&Question> {
        match self.header.opcode {
            Opcode::Update => self.question.as_ref(),
            Opcode::Query => None,
        }
    }

    /// The Prerequisite section of an UPDATE (empty for QUERY).
    /// Spec: RFC 2136 §2.4.
    pub fn prerequisites(&self) -> &[ResourceRecord] {
        match self.header.opcode {
            Opcode::Update => &self.answer,
            Opcode::Query => &[],
        }
    }

    /// The Update section of an UPDATE (empty for QUERY). Spec: RFC 2136 §2.5.
    pub fn updates(&self) -> &[ResourceRecord] {
        match self.header.opcode {
            Opcode::Update => &self.authority,
            Opcode::Query => &[],
        }
    }

    /// Canonical encoding (see [`crate::encode`]).
    pub fn encode(&self) -> Result<Vec<u8>> {
        crate::encode::encode(self)
    }

    /// The "DNS Message" component of the MAC input for this outgoing
    /// message: its canonical encoding before the TSIG RR is added, with
    /// ARCOUNT not counting it. Spec: RFC 8945 §4.3.2 ("When creating an
    /// outgoing message, the TSIG is based on the message content before the
    /// TSIG RR has been added to the additional section and before the DNS
    /// Message Header's ARCOUNT has been incremented").
    pub fn tsig_message_component(&self) -> Result<Vec<u8>> {
        crate::encode::encode_without_tsig(self)
    }
}

/// Builds a [`TsigMac`] or reports the bound. Used by the decoder.
pub(crate) fn tsig_mac(octets: &[u8]) -> Result<TsigMac> {
    TsigMac::new(octets.to_vec()).ok_or(Error::TsigMacTooLong)
}
