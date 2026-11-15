#![forbid(unsafe_code)]
//! `parse-dns`: the strict, bounded DNS message codec (docs/54 R54-7,
//! §6.1–§6.3; build task DN1; decision A-119).
//!
//! # Scope (phase 1, docs/54 §3)
//!
//! * [`decode`] decodes one message — QUERY or UPDATE, under a [`Profile`]
//!   that fixes the side (dnsd, dird, or the server's own replies), the
//!   transport bound and the section counts: header (RFC 1035 §4.1.1, RFC
//!   2136 §2.2), question / zone (§4.1.2, RFC 2136 §2.3), resource records
//!   (§4.1.3) with typed RDATA for A (§3.4.1), NS (§3.3.11), SOA (§3.3.13),
//!   SRV (RFC 2782), the RFC 2136 §2.4/§2.5 empty-RDATA forms, and the TSIG
//!   RR (RFC 8945 §4.2) as the last additional record. Any other RDATA is
//!   skipped by RDLENGTH and not retained (docs/54 §6.1).
//! * [`decode_header`] reads only the header, so a message that does not
//!   decode can still be answered (FORMERR / NOTIMP, docs/54 §6.6).
//! * [`encode`] produces the canonical form: no compression, Z zero, the TSIG
//!   last (docs/54 §6.3). It refuses whatever the decoder would not read back
//!   as the same value.
//! * TSIG MAC input (RFC 8945 §4.3): the "Request MAC" and "DNS Message"
//!   components ([`DecodedMessage::request_mac_component`],
//!   [`DecodedMessage::tsig_message_component`],
//!   [`Message::tsig_message_component`]). The "TSIG Variables" component
//!   needs RFC 4034 §6.2 (canonical name form), not yet opened —
//!   docs/questions/Q-641.
//! * TKEY is not modelled (RFC 2930 is not in specs/SOURCES.md — docs/54
//!   §3.2, docs/questions/Q-610; task DN9): a TKEY RR decodes as
//!   [`RData::Unknown`].
//!
//! # Strictness and bounds
//!
//! Messages ≤ 512 octets on UDP and ≤ 65535 on TCP (RFC 1035 §2.3.4, §4.2);
//! labels ≤ 63 and names ≤ 255 octets after decompression (RFC 1035 §3.1);
//! length octets `01`/`10` refused (§4.1.4); section counts bounded per
//! profile and checked against the octets present before any allocation
//! (docs/54 §6.2; AGENTS.md §6); RDLENGTH must equal the decoded RDATA for the
//! modelled types; nothing may follow the last record; the TSIG RR exactly
//! once and last (RFC 8945 §5.2), CLASS ANY, TTL 0, MAC ≤ 64 octets,
//! Algorithm Name uncompressed. No recursion anywhere: names are read with a
//! loop bounded by the 255-octet limit.
//!
//! Compression pointers point strictly backwards (docs/54 §6.3) and only at a
//! position where a name already decoded from the same message occurs; the
//! suffix there is already decoded, so each name takes at most one pointer
//! hop, pointer loops cannot be expressed, and no pointer can land in the
//! header, inside a label or inside an integer field (see [`name`];
//! docs/questions/Q-640). Every rejection is a typed [`Error`]; nothing
//! panics.
//!
//! # Provenance
//!
//! Written only from the allowed specifications, opened in-session from the
//! pinned copies in `tools/spec-pin/cache/` (AGENTS.md §1-3): RFC 1034 §3.1,
//! §3.6; RFC 1035 §2.3.1–§2.3.4, §3.1, §3.2.1–§3.2.5, §3.3, §3.3.11, §3.3.13,
//! §3.4.1, §4.1–§4.1.4, §4.2–§4.2.2; RFC 2136 §1–§1.3, §2–§2.6, §3.4.1, §3.8;
//! RFC 2782; RFC 3645 §5.1, §8; RFC 8945 §3, §4.1–§4.3.3.1, §5.1–§5.3.2, §6;
//! and the project's decided design docs/54 (A-119) with docs/questions/
//! Q-613, Q-615, Q-616. No other implementation was consulted or recalled.
//!
//! Spec: RFC 1035 §4; RFC 2136 §2; RFC 8945 §4; docs/54 §6.

mod decode;
mod encode;
mod error;
pub mod limits;
pub mod name;
mod types;

pub use decode::{decode, decode_header, DecodedMessage, Profile, Transport, WireHeader};
pub use encode::encode;
pub use error::{Error, Result, Section};
pub use limits::{
    HEADER_OCTETS, MAX_LABELS, MAX_LABEL_OCTETS, MAX_NAME_OCTETS, MAX_TCP_MESSAGE_OCTETS,
    MAX_TSIG_MAC_OCTETS, MAX_TSIG_TIME_SIGNED, MAX_UDP_MESSAGE_OCTETS, QUERY_MAX_ARCOUNT,
    QUERY_QDCOUNT, UPDATE_MAX_ADCOUNT, UPDATE_MAX_PRCOUNT, UPDATE_MAX_UPCOUNT, UPDATE_ZOCOUNT,
};
pub use name::{Labels, Name};
pub use types::{
    Class, Header, Message, Opcode, Question, RData, Rcode, ResourceRecord, RrType, Soa, Srv,
    TsigError, TsigMac, TsigRecord, TsigTime, GSS_TSIG_ALGORITHM,
};
