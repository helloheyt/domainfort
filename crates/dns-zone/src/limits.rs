//! Bounds of the zone image and of the replies, each a named constant with its
//! source.
//!
//! The UDP bounds come from RFC 1035 and docs/54 §6.5 (A-119); the host-record
//! bounds from docs/54 §4.4 / §5.2; the TTL bound from RFC 1035 §2.3.4. The
//! host-count bound is a project choice docs/54 does not fix — recorded in
//! docs/questions/Q-670 item 3.

use parse_dns::{HEADER_OCTETS, MAX_NAME_OCTETS, MAX_TCP_MESSAGE_OCTETS};

pub use parse_dns::MAX_UDP_MESSAGE_OCTETS;

/// `k`: a reply sent over UDP is at most `k` × the size of the request it
/// answers (and at most 512 octets); a larger reply is replaced by a TC = 1
/// reply (header + question). This bounds the UDP amplification ratio by
/// construction.
///
/// Spec: docs/54 §6.5 ("k = 4"); docs/questions/Q-616 item 2; decision A-119
/// (the plan accepted as phase 1). Measured against the phase-1 answers in
/// docs/questions/Q-672.
pub const UDP_AMPLIFICATION_FACTOR: usize = 4;

/// Most IPv4 addresses one host record carries.
///
/// Spec: docs/54 §4.4 ("≤ 8 IPv4 addresses"), §5.2, §5.5; docs/questions/Q-614
/// item 2.
pub const MAX_HOST_ADDRESSES: usize = 8;

/// Largest TTL (and SOA MINIMUM, which becomes a TTL — RFC 1035 §3.3.13):
/// "positive values of a signed 32 bit number".
///
/// Spec: RFC 1035 §2.3.4; §3.2.1 ("a 32 bit signed integer").
pub const MAX_TTL: u32 = 0x7FFF_FFFF;

/// Most host records (the DC's own included) in one zone image.
///
/// docs/54 fixes no count; this project choice keeps the worst-case content of
/// the host records inside the 8 MiB total of one `FetchZoneImage` transfer
/// (docs/54 §4.6, "total ≤ 8 MiB ⚠") — see the assertion below.
///
/// Spec: docs/54 §4.4, §4.6; docs/questions/Q-670 item 3 (⚠ project choice).
pub const MAX_HOST_RECORDS: usize = 65_536;

/// The whole-image transfer bound of the dird-dns channel.
///
/// Spec: docs/54 §4.6 (`FetchZoneImage`: "total ≤ 8 MiB ⚠").
pub const MAX_IMAGE_TRANSFER_OCTETS: usize = 8 * 1024 * 1024;

/// What one host record carries at most (docs/54 §4.4: label, addresses,
/// TTL): a label with its length octet (RFC 1035 §3.1: ≤ 63 octets), a 32-bit
/// TTL, an address count octet, and eight 32-bit addresses (RFC 1035 §3.4.1).
const MAX_HOST_RECORD_CONTENT_OCTETS: usize = 1 + 63 + 4 + 1 + MAX_HOST_ADDRESSES * 4;

/// Octets of a resource record after NAME (TYPE, CLASS, TTL, RDLENGTH).
/// Spec: RFC 1035 §4.1.3.
const RR_FIXED_OCTETS: usize = 10;

// ---- compile-time consistency (docs/54 §6.1 "const assert") ----------------

// k ≥ 1: the TC reply (header + question) is never larger than the request,
// so it always fits the relative bound.
const _: () = assert!(UDP_AMPLIFICATION_FACTOR >= 1);
// The host records of a full image fit the transfer bound.
const _: () =
    assert!(MAX_HOST_RECORDS * MAX_HOST_RECORD_CONTENT_OCTETS <= MAX_IMAGE_TRANSFER_OCTETS);
// The largest reply this crate can build fits one TCP message (RFC 1035
// §4.2.2): header, question (name + 4), one answer RR whose RDATA holds at
// most two names and 20 octets (SOA, RFC 1035 §3.3.13), up to eight address
// records in the additional section (or eight in the answer), and the TSIG RR
// of a BADKEY reply (key name, then two names' worth plus 16 octets of fixed
// RDATA fields — RFC 8945 §4.2).
const _: () = assert!(
    HEADER_OCTETS
        + (MAX_NAME_OCTETS + 4)
        + (MAX_NAME_OCTETS + RR_FIXED_OCTETS + 2 * MAX_NAME_OCTETS + 20)
        + MAX_HOST_ADDRESSES * (MAX_NAME_OCTETS + RR_FIXED_OCTETS + 4)
        + (MAX_NAME_OCTETS + RR_FIXED_OCTETS + MAX_NAME_OCTETS + 16)
        <= MAX_TCP_MESSAGE_OCTETS
);
// The UDP bound is RFC 1035's 512 octets.
const _: () = assert!(MAX_UDP_MESSAGE_OCTETS == 512);
// MAX_TTL is the largest positive signed 32-bit value.
const _: () = assert!(MAX_TTL as i64 == i32::MAX as i64);
