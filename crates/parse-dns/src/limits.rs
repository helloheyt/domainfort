//! Resource bounds of the codec, each a named constant with its source.
//!
//! The message, label and name bounds are fixed by RFC 1035; the per-opcode
//! section counts and the TSIG MAC bound are project choices fixed by docs/54
//! §6.2 (A-119). Every count is also checked against the octets actually
//! present before anything is allocated (AGENTS.md §6): a count can never make
//! the decoder reserve more than the bounded message can hold.

/// Octets in the header section: six 16-bit fields (ID, the flag word,
/// QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT). Spec: RFC 1035 §4.1.1.
pub const HEADER_OCTETS: usize = 12;

/// Largest message carried by UDP. Spec: RFC 1035 §2.3.4 ("UDP messages 512
/// octets or less"), §4.2.1 ("Messages carried by UDP are restricted to 512
/// bytes"); docs/54 §3.3, §6.2 (a larger datagram is never decoded).
pub const MAX_UDP_MESSAGE_OCTETS: usize = 512;

/// Largest message carried by TCP: what the two-octet length prefix can state.
/// Spec: RFC 1035 §4.2.2 ("prefixed with a two byte length field"); docs/54
/// §6.2. dird's forwarded messages have the same bound (docs/54 §4.6, §6.1).
pub const MAX_TCP_MESSAGE_OCTETS: usize = 65_535;

/// Longest label. Spec: RFC 1035 §2.3.4 ("labels 63 octets or less"), §3.1
/// (the six low bits of the length octet).
pub const MAX_LABEL_OCTETS: usize = 63;

/// Longest domain name, counting label octets and label length octets
/// (including the terminating zero length octet of the root label), after any
/// compression pointer is followed. Spec: RFC 1035 §2.3.4, §3.1; RFC 1034
/// §3.1; docs/54 §6.2 ("after unpacking").
pub const MAX_NAME_OCTETS: usize = 255;

/// Most non-root labels in one name. Spec: docs/54 §6.2 ("≤ 127 labels").
/// Implied by [`MAX_NAME_OCTETS`]: the shortest label costs two octets (length
/// octet + one octet) and the root costs one, so no name within 255 octets can
/// carry more — the decoder never needs a separate counter for it.
pub const MAX_LABELS: usize = 127;

/// QDCOUNT of a QUERY request: exactly one question. Spec: docs/54 §6.2
/// (project choice; RFC 1035 §4.1.2 says "usually 1").
pub const QUERY_QDCOUNT: u16 = 1;

/// Most additional records in a QUERY request (the TSIG, if any, included).
/// Spec: docs/54 §6.2 (project choice). ANCOUNT and NSCOUNT of a QUERY
/// request are zero (same row).
pub const QUERY_MAX_ARCOUNT: u16 = 4;

/// ZOCOUNT of an UPDATE request: exactly one zone. Spec: RFC 2136 §2.3 ("the
/// Zone Section is allowed to contain exactly one record"); docs/54 §6.2.
pub const UPDATE_ZOCOUNT: u16 = 1;

/// Most prerequisite RRs in an UPDATE request. Spec: docs/54 §6.2 (project
/// choice).
pub const UPDATE_MAX_PRCOUNT: u16 = 16;

/// Most update RRs in an UPDATE request. Spec: docs/54 §6.2 (project choice).
pub const UPDATE_MAX_UPCOUNT: u16 = 16;

/// Most additional records in an UPDATE request: only the TSIG. Spec: docs/54
/// §6.2 ("ADCOUNT = 1 (the TSIG)"); docs/questions/Q-615 item 8 (anything
/// else in the Additional Data section is FORMERR).
pub const UPDATE_MAX_ADCOUNT: u16 = 1;

/// Longest TSIG MAC. Spec: docs/54 §6.2 ("MAC Size ≤ 64"); RFC 8945 §4.2
/// (MAC Size field), §5.2.2.1 (a MAC longer than the algorithm's output is
/// FORMERR).
pub const MAX_TSIG_MAC_OCTETS: usize = 64;

/// Largest TSIG Time Signed value: the field is an unsigned 48-bit integer.
/// Spec: RFC 8945 §4.2.
pub const MAX_TSIG_TIME_SIGNED: u64 = (1 << 48) - 1;

/// Octets of a question entry after QNAME (QTYPE, QCLASS). Spec: RFC 1035
/// §4.1.2.
pub(crate) const QUESTION_FIXED_OCTETS: usize = 4;

/// Octets of a resource record after NAME (TYPE, CLASS, TTL, RDLENGTH).
/// Spec: RFC 1035 §4.1.3.
pub(crate) const RR_FIXED_OCTETS: usize = 10;

/// Octets of the shortest name: the root, one zero length octet. Spec: RFC
/// 1035 §3.1.
pub(crate) const MIN_NAME_OCTETS: usize = 1;

// ---- compile-time consistency of the bounds (docs/54 §6.1 "const assert") ----

// The 127-label bound is exactly what 255 octets allow (see MAX_LABELS).
const _: () = assert!(2 * MAX_LABELS + MIN_NAME_OCTETS == MAX_NAME_OCTETS);
// A label length fits the six low bits of a length octet (RFC 1035 §3.1).
const _: () = assert!(MAX_LABEL_OCTETS == 0x3F);
// Both transports carry at least a header; TCP is what a u16 prefix states.
const _: () = assert!(HEADER_OCTETS <= MAX_UDP_MESSAGE_OCTETS);
const _: () = assert!(MAX_UDP_MESSAGE_OCTETS <= MAX_TCP_MESSAGE_OCTETS);
const _: () = assert!(MAX_TCP_MESSAGE_OCTETS == u16::MAX as usize);
// A QUERY request at its count bounds (one root-named question, four
// root-named empty records) fits in one UDP datagram.
const _: () = assert!(
    HEADER_OCTETS
        + MIN_NAME_OCTETS
        + QUESTION_FIXED_OCTETS
        + QUERY_MAX_ARCOUNT as usize * (MIN_NAME_OCTETS + RR_FIXED_OCTETS)
        <= MAX_UDP_MESSAGE_OCTETS
);
// An UPDATE request at its count bounds fits in one TCP message even with
// every name at its longest (it is carried by TCP only — docs/54 §3.3).
const _: () = assert!(
    HEADER_OCTETS
        + (UPDATE_ZOCOUNT as usize) * (MAX_NAME_OCTETS + QUESTION_FIXED_OCTETS)
        + (UPDATE_MAX_PRCOUNT as usize + UPDATE_MAX_UPCOUNT as usize)
            * (MAX_NAME_OCTETS + RR_FIXED_OCTETS)
        <= MAX_TCP_MESSAGE_OCTETS
);
// The MAC Size field is 16 bits wide (RFC 8945 §4.2).
const _: () = assert!(MAX_TSIG_MAC_OCTETS <= u16::MAX as usize);
