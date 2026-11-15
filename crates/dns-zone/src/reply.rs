//! Replies: the one place reply octets come into existence, and so the one
//! place the transport size rule is enforced.
//!
//! **Class closed here (AGENTS.md §6.1): a UDP reply larger than the
//! amplification bound.** Rather than checking at each call site, a [`Reply`]
//! can only be built by this module, and every constructor applies the bound
//! of docs/54 §6.5 to the encoded octets: over UDP a reply is at most 512
//! octets and at most `k` × the request ([`UDP_AMPLIFICATION_FACTOR`]), an
//! error reply at most the request itself; a reply that does not fit is
//! replaced by a TC = 1 reply holding the header and the question, which is
//! never larger than the request. A `Reply` that breaks the bound is not
//! representable, and each records the transport whose bound it satisfies
//! ([`Reply::transport`]); dnsd sends only `Reply` octets, on that transport
//! (task DN11).
//!
//! Every reply but one is a parse-dns [`Message`] encoded by parse-dns's
//! canonical encoder (no compression — docs/54 §6.3). The exception is the
//! header-only NOTIMP reply to an opcode parse-dns does not model (it decodes
//! only QUERY and UPDATE): RFC 1035 §4.1.1 requires the OPCODE "copied into
//! the response", which a parse-dns `Header` cannot carry, so those 12 octets
//! are laid out here (docs/questions/Q-670 item 9).

use crate::limits::{MAX_UDP_MESSAGE_OCTETS, UDP_AMPLIFICATION_FACTOR};
use parse_dns::{Header, Message, Opcode, Rcode, Transport, HEADER_OCTETS};

/// The octets of one reply, already within the bound of the transport it
/// answers on.
///
/// Its `Debug` output shows the length, RCODE and TC only — reply octets are
/// not logged (docs/54 §9).
#[derive(Clone, PartialEq, Eq)]
pub struct Reply {
    octets: Vec<u8>,
    rcode: Rcode,
    truncated: bool,
    transport: Transport,
}

impl core::fmt::Debug for Reply {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Reply")
            .field("octets", &self.octets.len())
            .field("rcode", &self.rcode)
            .field("truncated", &self.truncated)
            .field("transport", &self.transport)
            .finish()
    }
}

impl Reply {
    /// The reply octets (a DNS message; over TCP the caller adds the
    /// two-octet length prefix — RFC 1035 §4.2.2).
    pub fn as_bytes(&self) -> &[u8] {
        &self.octets
    }

    /// The reply octets, owned.
    pub fn into_bytes(self) -> Vec<u8> {
        self.octets
    }

    /// The header RCODE (for dnsd's counters — docs/54 §9).
    pub fn rcode(&self) -> Rcode {
        self.rcode
    }

    /// Whether this is the TC = 1 form (header + question) that replaced a
    /// reply over the UDP bound. Spec: docs/54 §6.5.
    pub fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// The transport whose bound this reply was built within; it must leave
    /// on that transport. Spec: docs/54 §6.5; RFC 1035 §4.2.
    pub fn transport(&self) -> Transport {
        self.transport
    }
}

/// The largest reply that may answer, over UDP, a request of
/// `request_octets` octets with the given RCODE: 512 octets, and at most `k`
/// × the request — or the request itself for any RCODE other than NOERROR.
///
/// Spec: docs/54 §6.5 ("≤ 512 octets … ≤ k × (request size)"; "every error
/// response on UDP … never larger than the request"); RFC 1035 §2.3.4,
/// §4.2.1; docs/questions/Q-616 items 2, 9.
pub fn udp_reply_limit(rcode: Rcode, request_octets: usize) -> usize {
    let relative = if rcode == Rcode::NOERROR {
        request_octets.saturating_mul(UDP_AMPLIFICATION_FACTOR)
    } else {
        request_octets
    };
    relative.min(MAX_UDP_MESSAGE_OCTETS)
}

/// The bound for a reply on `transport`. Over TCP the two-octet length prefix
/// is the only bound (RFC 1035 §4.2.2), and the encoder already refuses more.
fn limit(transport: Transport, rcode: Rcode, request_octets: usize) -> usize {
    match transport {
        Transport::Udp => udp_reply_limit(rcode, request_octets),
        Transport::Tcp => transport.max_message_octets(),
    }
}

/// Encodes `message` as the reply to a request of `request_octets` octets on
/// `transport`. If it exceeds the bound, the reply becomes header + question
/// with TC = 1 (QUERY only — UPDATE has no TC bit, RFC 2136 §2.2). `None` if
/// no form fits or encodes (never for the replies this crate builds; the
/// caller then stays silent — fail closed).
///
/// Spec: docs/54 §6.5; RFC 1035 §4.1.1 (TC: "truncated due to length greater
/// than that permitted on the transmission channel"), §4.2.1 ("Longer
/// messages are truncated and the TC bit is set").
pub(crate) fn build(
    message: Message,
    request_octets: usize,
    transport: Transport,
) -> Option<Reply> {
    let rcode = message.header.rcode;
    let bound = limit(transport, rcode, request_octets);
    let octets = parse_dns::encode(&message).ok()?;
    if octets.len() <= bound {
        return Some(Reply {
            octets,
            rcode,
            truncated: false,
            transport,
        });
    }
    if message.header.opcode != Opcode::Query {
        return None;
    }
    // docs/54 §6.5: TC = 1, header + question (≤ the request: its question is
    // the request's own question, which is never compressed — no name
    // precedes it — so it occupies the same octets).
    let truncated = Message {
        header: Header {
            tc: true,
            ..message.header
        },
        question: message.question,
        answer: Vec::new(),
        authority: Vec::new(),
        additional: Vec::new(),
        tsig: None,
    };
    let octets = parse_dns::encode(&truncated).ok()?;
    (octets.len() <= bound).then_some(Reply {
        octets,
        rcode,
        truncated: true,
        transport,
    })
}

/// The header-only NOTIMP reply to an opcode other than QUERY and UPDATE: ID
/// and OPCODE copied, QR = 1, every other flag and Z zero, RCODE = 4, all
/// counts zero (no section of a message whose opcode is not understood is
/// echoed). 12 octets, so never larger than the request (which has at least a
/// header).
///
/// Spec: RFC 1035 §4.1.1 (header layout; OPCODE "copied into the response";
/// RCODE 4 "does not support the requested kind of query"; Z "Must be zero");
/// RFC 1034 §3.7.2 ("return a not-implemented error response"); RFC 2136 §3
/// (NOTIMP for an opcode "not recognized"); docs/54 §3.2, §6.6.
pub(crate) fn not_implemented(
    id: u16,
    opcode: u8,
    request_octets: usize,
    transport: Transport,
) -> Option<Reply> {
    let flags = 0x8000 | (u16::from(opcode & 0x0F) << 11) | u16::from(Rcode::NOTIMP.value());
    let mut octets = Vec::with_capacity(HEADER_OCTETS);
    for word in [id, flags, 0, 0, 0, 0] {
        octets.extend_from_slice(&word.to_be_bytes());
    }
    let bound = limit(transport, Rcode::NOTIMP, request_octets);
    (octets.len() <= bound).then_some(Reply {
        octets,
        rcode: Rcode::NOTIMP,
        truncated: false,
        transport,
    })
}
