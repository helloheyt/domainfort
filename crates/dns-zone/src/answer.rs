//! dnsd's answer function: every request maps to exactly one [`Verdict`].
//!
//! [`answer`] is total — any octet string on either transport yields one
//! verdict, never a panic: a bounded [`Reply`], [`Verdict::Silence`],
//! [`Verdict::Close`] (TCP), or [`Verdict::Forward`] (a signed UPDATE over
//! TCP, handed to dird as opaque octets). It reads no clock and does no I/O:
//! the zone's freshness is a parameter ([`ZoneState`]).
//!
//! # The refusal table as built (docs/54 §6.6, dnsd rows; checked in order)
//!
//! | # | Request | Verdict |
//! |---|---|---|
//! | 1 | UDP datagram > 512 octets | silence |
//! | 2 | shorter than a header | UDP: silence; TCP: close |
//! | 3 | QR = 1 | silence |
//! | 4 | OPCODE other than QUERY (0) / UPDATE (5) | NOTIMP, header only |
//! | 5 | a section count outside the profile (QUERY: QDCOUNT ≠ 1, AN/NS ≠ 0, AR > 4; UPDATE: ZO ≠ 1, PR/UP > 16, AD > 1) | FORMERR, header only |
//! | 6 | any other decode failure | UDP: silence; TCP: FORMERR, header only |
//! | 7 | UPDATE over UDP | REFUSED, header only (interim — docs/questions/Q-671) |
//! | 8 | UPDATE over TCP without TSIG | REFUSED, header only |
//! | 9 | UPDATE over TCP, TSIG algorithm ≠ gss-tsig | NOTAUTH + TSIG BADKEY, unsigned |
//! | 10 | UPDATE over TCP, TSIG gss-tsig | forward to dird (fallback SERVFAIL) |
//! | 11 | QUERY carrying a TSIG | NOTAUTH + TSIG BADKEY, unsigned |
//! | 12 | zone image unavailable or stale | SERVFAIL |
//! | 13 | QTYPE TSIG / AXFR / MAILB / MAILA / `*` | REFUSED |
//! | 14 | QCLASS ≠ IN | REFUSED |
//! | 15 | QNAME outside the zone | REFUSED |
//! | 16 | QNAME inside the zone, no such node | NXDOMAIN, AA |
//! | 17 | node without RRs of QTYPE | NOERROR, no answer (NODATA), AA |
//! | 18 | node with RRs of QTYPE | NOERROR, AA, the RRs (+ the DC's A records for SRV / NS) |
//! | — | any UDP reply over the bound of docs/54 §6.5 | TC = 1, header + question |
//!
//! Every reply copies the ID and OPCODE; QUERY replies copy RD and the
//! question, never set RA, and carry no SOA in negative answers (docs/54
//! §6.4); UPDATE replies carry zero section counts (RFC 2136 §3.8). Refusals
//! are identical whichever rule refused, so they reveal nothing about the
//! zone (docs/54 §6.6 "no oracle").
//!
//! Spec: docs/54 §3.2, §3.3, §4.4, §4.5 step 1, §6.4–§6.6, §7.5; RFC 1034
//! §3.7.1, §3.7.2, §4.3.1, §4.3.2; RFC 1035 §4.1.1, §4.2.1, §6.2; RFC 2136
//! §3, §3.1.1, §3.3.1, §3.8; RFC 8945 §5.2, §5.2.1, §5.3.2.

use crate::image::{Lookup, ZoneImage};
use crate::reply::{self, Reply};
use parse_dns::{
    decode, decode_header, Class, DecodedMessage, Error, Header, Message, Opcode, Profile,
    Question, Rcode, ResourceRecord, RrType, Transport, TsigError, TsigMac, TsigRecord, WireHeader,
};

/// Whether dnsd currently has a zone image it may answer from.
///
/// Spec: docs/54 §4.4 (bounded staleness: past `zone_image_max_age` without
/// confirming SERIAL with dird, "SERVFAIL to every query (fail closed)");
/// docs/questions/Q-616 item 6.
#[derive(Debug, Clone, Copy)]
pub enum ZoneState<'a> {
    /// An image confirmed recently enough.
    Current(&'a ZoneImage),
    /// No image, or one not confirmed within its maximum age.
    Unavailable,
}

impl<'a> ZoneState<'a> {
    /// The image, if it was confirmed no more than `max_age` seconds before
    /// `now` (both read by dnsd from its own clock — this crate reads none).
    /// A `now` earlier than `confirmed_at` is treated as stale: fail closed.
    ///
    /// Spec: docs/54 §4.4; docs/questions/Q-616 item 6; docs/CLEAN-ROOM.md (fail
    /// closed).
    pub fn from_confirmation(
        image: &'a ZoneImage,
        confirmed_at: u64,
        now: u64,
        max_age: u64,
    ) -> ZoneState<'a> {
        match now.checked_sub(confirmed_at) {
            Some(age) if age <= max_age => ZoneState::Current(image),
            _ => ZoneState::Unavailable,
        }
    }
}

/// What dnsd does with one request.
#[derive(Debug)]
pub enum Verdict<'a> {
    /// Send nothing (UDP: drop the datagram; TCP: no reply to this message).
    Silence(Silence),
    /// TCP only: close the connection without sending a byte.
    /// Spec: docs/54 §6.6 ("FORMERR if the header decoded, otherwise close").
    Close,
    /// Send these octets.
    Reply(Reply),
    /// Hand these exact octets to dird (`Forward`, docs/54 §4.6); if dird
    /// cannot take them, send [`Forward::unavailable_reply`].
    Forward(Forward<'a>),
}

/// Why a request gets no reply (for dnsd's noise counters — docs/54 §9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Silence {
    /// A UDP datagram over 512 octets. Spec: docs/54 §3.3, §6.2; RFC 1035
    /// §2.3.4.
    OversizeDatagram,
    /// Malformed past the header (UDP), or shorter than a header.
    /// Spec: docs/54 §6.6; docs/questions/Q-616 item 9.
    Malformed,
    /// A response (QR = 1). Spec: docs/54 §6.6 ("no answer to answers").
    Response,
    /// No reply form fit or encoded (not reachable with the replies this
    /// crate builds; silence is the fail-closed outcome).
    Unencodable,
}

/// A signed UPDATE received over TCP, to be handed to dird unchanged.
///
/// Built only by [`answer`] for an UPDATE that arrived over TCP, decoded
/// under the `Query` profile and carries a TSIG whose algorithm is
/// `gss-tsig` — dird never sees an unsigned UPDATE (docs/54 §4.5 step 1).
#[derive(Debug)]
pub struct Forward<'a> {
    message: &'a [u8],
    unavailable: Reply,
}

impl<'a> Forward<'a> {
    /// The request octets, exactly as received (the TSIG MAC covers them —
    /// RFC 8945 §4.3.2; docs/54 §4.1).
    pub fn message(&self) -> &'a [u8] {
        self.message
    }

    /// SERVFAIL (UPDATE, zero counts, unsigned) for when dird is unavailable or
    /// its queue is full. Spec: docs/54 §6.6 (last row); RFC 2136 §2.2
    /// (SERVFAIL "a forwarding timeout"), §3.8.
    pub fn unavailable_reply(&self) -> &Reply {
        &self.unavailable
    }
}

/// QTYPEs refused by policy: TSIG (a meta-RR, never queried), zone transfer,
/// the mailbox QTYPEs, and `*` — no answer "of every type" (zone walking,
/// amplification).
///
/// Spec: docs/54 §3.2, §6.5, §6.6 ("QTYPE ∈ {250, 252–255}"); RFC 1035
/// §3.2.3, §4.1.1 (RCODE 5: "may not wish to perform a particular operation
/// (e.g., zone transfer)"); RFC 8945 §4.1.
const REFUSED_QTYPES: [RrType; 5] = [
    RrType::TSIG,
    RrType::AXFR,
    RrType::MAILB,
    RrType::MAILA,
    RrType::ANY,
];

/// Answers one request received on `transport`.
///
/// Spec: see the module documentation (docs/54 §6.6 as built).
pub fn answer<'a>(zone: ZoneState<'_>, request: &'a [u8], transport: Transport) -> Verdict<'a> {
    // Row 1 (and the TCP framing bound): never decoded.
    if request.len() > transport.max_message_octets() {
        return match transport {
            Transport::Udp => Verdict::Silence(Silence::OversizeDatagram),
            Transport::Tcp => Verdict::Close,
        };
    }
    // Row 2.
    let Ok(header) = decode_header(request, transport) else {
        return match transport {
            Transport::Udp => Verdict::Silence(Silence::Malformed),
            Transport::Tcp => Verdict::Close,
        };
    };
    // Row 3.
    if header.qr {
        return Verdict::Silence(Silence::Response);
    }
    // Row 4.
    let Some(opcode) = header.known_opcode() else {
        return reply::not_implemented(header.id, header.opcode, request.len(), transport)
            .map_or(Verdict::Silence(Silence::Unencodable), Verdict::Reply);
    };
    // Rows 5 and 6.
    let decoded = match decode(request, Profile::Query(transport)) {
        Ok(decoded) => decoded,
        Err(Error::SectionCount(_)) => {
            return finish(format_error(&header, opcode), request.len(), transport);
        }
        Err(_) => {
            return match transport {
                Transport::Udp => Verdict::Silence(Silence::Malformed),
                Transport::Tcp => finish(format_error(&header, opcode), request.len(), transport),
            };
        }
    };
    match opcode {
        Opcode::Update => update(&decoded, request, transport),
        Opcode::Query => query(zone, &decoded, request.len(), transport),
    }
}

/// Rows 7–10: UPDATE. dnsd holds no key, so it forwards only what dird may
/// verify, and answers everything else itself.
///
/// Spec: docs/54 §3.3, §4.5 step 1, §6.6; RFC 2136 §3.3.1 (REFUSED), §3.8
/// (zero counts); RFC 8945 §5.2.1 (BADKEY, unsigned), §5.3.2; docs/54 §3.6,
/// §6.6, §7.5 (only gss-tsig; no shared TSIG secret exists).
fn update<'a>(
    decoded: &DecodedMessage<'_>,
    request: &'a [u8],
    transport: Transport,
) -> Verdict<'a> {
    let message = decoded.message();
    let id = message.header.id;
    let request_octets = request.len();
    // Row 7 — docs/54 §3.3 asks TC = 1 here, but UPDATE has no TC bit (RFC
    // 2136 §2.2: "UPDATE uses only one flag bit (QR)"; the position is Z,
    // which "should be ignored"), so a client would read NOERROR as success.
    // Interim: REFUSED (Q-616 item 1's alternative); docs/questions/Q-671.
    if transport == Transport::Udp {
        return finish(
            update_reply(id, Rcode::REFUSED, None),
            request_octets,
            transport,
        );
    }
    match &message.tsig {
        // Row 8.
        None => finish(
            update_reply(id, Rcode::REFUSED, None),
            request_octets,
            transport,
        ),
        // Row 9.
        Some(tsig) if !tsig.algorithm_is_gss_tsig() => finish(
            update_reply(id, Rcode::NOTAUTH, Some(bad_key(tsig))),
            request_octets,
            transport,
        ),
        // Row 10.
        Some(_) => match reply::build(
            update_reply(id, Rcode::SERVFAIL, None),
            request_octets,
            transport,
        ) {
            Some(unavailable) => Verdict::Forward(Forward {
                message: request,
                unavailable,
            }),
            None => Verdict::Silence(Silence::Unencodable),
        },
    }
}

/// Rows 11–18: QUERY.
///
/// Spec: docs/54 §6.4, §6.6, §7.5; RFC 1034 §4.3.2; RFC 8945 §5.2.1.
fn query(
    zone: ZoneState<'_>,
    decoded: &DecodedMessage<'_>,
    request_octets: usize,
    transport: Transport,
) -> Verdict<'static> {
    let message = decoded.message();
    // The Query profile requires exactly one question (row 5).
    let Some(question) = message.question.as_ref() else {
        return Verdict::Silence(Silence::Unencodable);
    };
    let base = QueryReply {
        request: &message.header,
        question,
    };

    // Row 11 — key check first (RFC 8945 §5.2 order): dnsd knows no key at
    // all, so any TSIG on a query is BADKEY, unsigned (docs/54 §7.5).
    if let Some(tsig) = &message.tsig {
        return finish(
            base.reply(
                Rcode::NOTAUTH,
                false,
                Vec::new(),
                Vec::new(),
                Some(bad_key(tsig)),
            ),
            request_octets,
            transport,
        );
    }
    // Row 12.
    let ZoneState::Current(image) = zone else {
        return finish(base.error(Rcode::SERVFAIL), request_octets, transport);
    };
    // Rows 13, 14.
    if REFUSED_QTYPES.contains(&question.qtype) || question.qclass != Class::IN {
        return finish(base.error(Rcode::REFUSED), request_octets, transport);
    }
    let message = match image.lookup(&question.qname) {
        // Row 15 — no cache and no root hints for RFC 1034 §4.3.2 step 4.
        Lookup::OutsideZone => base.error(Rcode::REFUSED),
        // Row 16 — "set an authoritative name error" (RFC 1034 §4.3.2 3c).
        Lookup::NoSuchName => base.reply(Rcode::NXDOMAIN, true, Vec::new(), Vec::new(), None),
        // Rows 17, 18 — RFC 1034 §4.3.2 3a and step 6.
        Lookup::Node(node) => {
            let records = image.records(&node, question.qtype);
            base.reply(
                Rcode::NOERROR,
                true,
                records.answer,
                records.additional,
                None,
            )
        }
    };
    finish(message, request_octets, transport)
}

/// The fixed parts of every reply to one QUERY.
struct QueryReply<'m> {
    request: &'m Header,
    question: &'m Question,
}

impl QueryReply<'_> {
    /// A QUERY reply: ID copied, QR = 1, RD copied, RA = 0, the question
    /// copied, no authority section.
    ///
    /// Spec: RFC 1035 §4.1.1 (ID "copied", RD "copied into the response", RA
    /// "set or cleared"); RFC 1034 §4.3.1 (RA = 0: no recursive service),
    /// §4.3.2 step 1; docs/54 §3.2 ("RA = 0 in every response; RD copied"),
    /// §6.4 (no SOA in negative answers).
    fn reply(
        &self,
        rcode: Rcode,
        authoritative: bool,
        answer: Vec<ResourceRecord>,
        additional: Vec<ResourceRecord>,
        tsig: Option<TsigRecord>,
    ) -> Message {
        Message {
            header: Header {
                id: self.request.id,
                qr: true,
                opcode: Opcode::Query,
                aa: authoritative,
                tc: false,
                rd: self.request.rd,
                ra: false,
                rcode,
            },
            question: Some(self.question.clone()),
            answer,
            authority: Vec::new(),
            additional,
            tsig,
        }
    }

    /// An error reply: header + question, not authoritative. Spec: docs/54
    /// §6.5 ("every error response on UDP … header + question at most").
    fn error(&self, rcode: Rcode) -> Message {
        self.reply(rcode, false, Vec::new(), Vec::new(), None)
    }
}

/// An UPDATE reply: ID and OPCODE copied, QR = 1, zero section counts, and the
/// TSIG RR when one is required.
///
/// Spec: RFC 2136 §3.8 ("copying the ID and Opcode fields … placing zeros (0)
/// in the these "count" fields"), §2.2 (UPDATE uses only QR); RFC 8945 §5.2
/// ("REQUIRED to return a TSIG RR in the response").
fn update_reply(id: u16, rcode: Rcode, tsig: Option<TsigRecord>) -> Message {
    Message {
        header: Header {
            id,
            qr: true,
            opcode: Opcode::Update,
            aa: false,
            tc: false,
            rd: false,
            ra: false,
            rcode,
        },
        question: None,
        answer: Vec::new(),
        authority: Vec::new(),
        additional: Vec::new(),
        tsig,
    }
}

/// FORMERR with the header only: ID and OPCODE copied, RD copied for QUERY.
///
/// Spec: RFC 1035 §4.1.1 (RCODE 1: "unable to interpret the query"); RFC 2136
/// §3.1.1 (FORMERR), §3.8; docs/54 §6.6.
fn format_error(header: &WireHeader, opcode: Opcode) -> Message {
    Message {
        header: Header {
            id: header.id,
            qr: true,
            opcode,
            aa: false,
            tc: false,
            rd: opcode == Opcode::Query && header.rd,
            ra: false,
            rcode: Rcode::FORMERR,
        },
        question: None,
        answer: Vec::new(),
        authority: Vec::new(),
        additional: Vec::new(),
        tsig: None,
    }
}

/// The unsigned BADKEY TSIG RR answering `request`: same key name and
/// algorithm, the client's Time Signed and Fudge, MAC Size 0 and empty MAC,
/// the original request ID, Error BADKEY, no Other Data.
///
/// Spec: RFC 8945 §5.2.1 ("RCODE 9 (NOTAUTH) and TSIG ERROR 17 (BADKEY)
/// … MUST be unsigned"), §5.3.2 ("unsigned error message (MAC Size == 0 and
/// empty MAC)"), §4.2 (Original ID "the ID of the original DNS request";
/// Other Data empty unless BADTIME); docs/questions/Q-670 item 7.
fn bad_key(request: &TsigRecord) -> TsigRecord {
    TsigRecord {
        key_name: request.key_name.clone(),
        algorithm_name: request.algorithm_name.clone(),
        time_signed: request.time_signed,
        fudge: request.fudge,
        mac: TsigMac::default(),
        original_id: request.original_id,
        error: TsigError::BADKEY,
        other_data: Vec::new(),
    }
}

/// Encodes `message` through the one reply chokepoint ([`reply::build`]).
fn finish(message: Message, request_octets: usize, transport: Transport) -> Verdict<'static> {
    reply::build(message, request_octets, transport)
        .map_or(Verdict::Silence(Silence::Unencodable), Verdict::Reply)
}
