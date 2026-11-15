//! The dird-dns channel's fixed identity: magic, version, the per-direction
//! body bounds, the per-field bounds, the closed kind tables and the closed
//! code tables.
//!
//! # Where the numbers come from
//!
//! * **A forwarded DNS message** is at most what the TCP two-octet length
//!   prefix can state, 65535 octets (RFC 1035 §4.2.2), and at most 512 octets
//!   when it arrived over UDP (RFC 1035 §2.3.4, §4.2.1); at least a header,
//!   12 octets (RFC 1035 §4.1.1). Both pinned to parse-dns's constants
//!   (docs/54 §6.2: dird decodes "with the same crate and the same bounds").
//! * **Request direction: 64 KiB + 32.** The largest request is a `Forward`:
//!   the envelope (4), the transport (1), the peer address (1 + 16) and the
//!   message (4 + 65535) — 65561 octets. docs/54 §4.6 proposed "request
//!   ≤ 64 KiB + 16" before A-140 added the transport and the peer to
//!   `Forward`; the bound grew by 16 for them (docs/questions/Q-920 item 2).
//! * **Reply direction: 1 MiB + 16.** The largest reply is one zone-image
//!   chunk: the envelope, a 1 MiB chunk with its length, and the `more`
//!   flag (docs/54 §4.6: "chunks ≤ 1 MiB, total ≤ 8 MiB ⚠" — the dird-ldap
//!   chunk pattern, docs/50 "bounds of `dird-ldap.sock`", Q-280). A
//!   `Forwarded` reply (≤ 65548 octets) is smaller.
//! * **A zone image** is at most dns-zone's `MAX_IMAGE_TRANSFER_OCTETS`
//!   (8 MiB) in at most [`MAX_IMAGE_CHUNKS`] chunks; its fields are bounded by
//!   dns-zone's own bounds (a host label ≤ 63 octets, ≤ 8 addresses, ≤ 65535
//!   member hosts) — checked at compile time below.
//!
//! Spec: docs/54 §4.6 (the codec of `crates/ipc`: `length:u32 ‖ magic:u16 ‖
//! version:u8 ‖ kind:u8 ‖ payload`; exact version; closed `kind`; no trailing
//! octet; `REFUSED_KIND = 0xFF`; magic `0x444E` "DN"); docs/50 §3.3, the
//! channel-magic registry (A-64); A-59; A-140.

use core::time::Duration;
use ipc::{Channel, FrameLimit};

/// The channel's magic: the ASCII octets "DN". Proposed by docs/54 §4.6 —
/// distinct from `0x4B44`, `0xA7D1`, `0x4452`, `0x4C44`, `0x4441`, `0x414D`,
/// every magic of this workspace's channel crates — and accepted with the
/// plan (A-119). Its row
/// in docs/50's channel-magic registry is still to be added (DN0, A-64;
/// docs/questions/Q-619 item 1, Q-921 item 1).
/// Spec: docs/54 §4.6; docs/50 §3.3, the channel-magic registry.
pub const DNS_MAGIC: u16 = 0x444E;

/// The one version of the channel this build speaks; any other is refused
/// (`Refused::VersionMismatch`), never negotiated.
/// Spec: docs/50 §3.3 ("exact version … no negotiation and no fallback");
/// docs/54 §4.6 ("exact version"); D57.
pub const DNS_VERSION: u8 = 1;

/// Fewest octets of a DNS message: its header.
/// Spec: RFC 1035 §4.1.1 (six 16-bit fields); docs/54 §6.2 ("≥ 12 (header)").
pub const MIN_MESSAGE: usize = parse_dns::HEADER_OCTETS;

/// Most octets of a DNS message that arrived over UDP.
/// Spec: RFC 1035 §2.3.4 ("UDP messages 512 octets or less"), §4.2.1;
/// docs/research/r3-c-dns.md §9 DR1 ("`Forwarded` profile also for UPDATE
/// over UDP (≤ 512)").
pub const MAX_UDP_MESSAGE: u32 = 512;

/// Most octets of any DNS message on this channel: what the TCP two-octet
/// length prefix can state.
/// Spec: RFC 1035 §4.2.2 ("prefixed with a two byte length field");
/// docs/54 §4.6 (`message: bytes ≤ 65535`, `reply: Option<bytes ≤ 65535>`).
pub const MAX_MESSAGE: u32 = 65_535;

/// Most octets of a domain name in its uncompressed wire form.
/// Spec: RFC 1035 §2.3.4 ("names 255 octets or less"), §3.1.
pub const MAX_NAME: u32 = 255;

/// Most octets of one host label.
/// Spec: RFC 1035 §2.3.4 ("labels 63 octets or less"); docs/54 §5.3.
pub const MAX_LABEL: u32 = 63;

/// Most addresses of one host record.
/// Spec: docs/54 §4.4 ("≤ 8 IPv4 addresses"); dns-zone `MAX_HOST_ADDRESSES`.
pub const MAX_ADDRESSES: u32 = 8;

/// Most member host records (the DC's own excluded) of one image: one fewer
/// than dns-zone's `MAX_HOST_RECORDS`, which counts the DC.
/// Spec: docs/54 §4.4; dns-zone `MAX_HOST_RECORDS` (docs/questions/Q-670
/// item 3).
pub const MAX_MEMBER_HOSTS: u32 = 65_535;

/// Most octets of one zone-image chunk: 1 MiB.
/// Spec: docs/54 §4.6 ("chunks ≤ 1 MiB"); the dird-ldap response-part
/// pattern (docs/50 "bounds of `dird-ldap.sock`"; Q-280 item 2).
pub const MAX_IMAGE_CHUNK: u32 = 1024 * 1024;

/// Most octets of one encoded zone image: dns-zone's transfer bound, 8 MiB.
/// Spec: docs/54 §4.6 ("total ≤ 8 MiB ⚠"); dns-zone
/// `MAX_IMAGE_TRANSFER_OCTETS`.
pub const MAX_IMAGE_OCTETS: usize = dns_zone::limits::MAX_IMAGE_TRANSFER_OCTETS;

/// Most chunks of one zone image (every chunk but the last is exactly
/// [`MAX_IMAGE_CHUNK`] octets).
/// Spec: docs/54 §4.6; module documentation.
pub const MAX_IMAGE_CHUNKS: usize = MAX_IMAGE_OCTETS.div_ceil(MAX_IMAGE_CHUNK as usize);

/// Request body bound: 64 KiB + 32 (module documentation).
/// Spec: docs/54 §4.6; A-140; docs/questions/Q-920 item 2.
pub const MAX_REQUEST_BODY: u32 = 64 * 1024 + 32;

/// Reply body bound: one image chunk and its framing, [`MAX_IMAGE_CHUNK`]
/// + 16.
/// Spec: docs/54 §4.6 ("reply ≤ 1 MiB + 16").
pub const MAX_REPLY_BODY: u32 = MAX_IMAGE_CHUNK + 16;

/// The request direction's [`FrameLimit`]; a bound outside ipc's range stops
/// the build here (const evaluation), never at run time.
/// Spec: docs/50 §3.3; A-59 (`FrameLimit` range).
pub const REQUEST_LIMIT: FrameLimit = match FrameLimit::new(MAX_REQUEST_BODY) {
    Some(limit) => limit,
    None => panic!("MAX_REQUEST_BODY is outside the ipc FrameLimit range"),
};

/// The reply direction's [`FrameLimit`]. Spec: docs/50 §3.3; A-59.
pub const REPLY_LIMIT: FrameLimit = match FrameLimit::new(MAX_REPLY_BODY) {
    Some(limit) => limit,
    None => panic!("MAX_REPLY_BODY is outside the ipc FrameLimit range"),
};

/// The bound of one encoded zone image (a standalone payload, not a frame).
/// Spec: docs/54 §4.6; dns-zone `MAX_IMAGE_TRANSFER_OCTETS`.
pub const IMAGE_LIMIT: FrameLimit = match FrameLimit::new(MAX_IMAGE_OCTETS as u32) {
    Some(limit) => limit,
    None => panic!("MAX_IMAGE_OCTETS is outside the ipc FrameLimit range"),
};

/// The dnsd ↔ dird channel (`dird-dns.sock`, docs/54 §4.6).
/// Spec: docs/54 §4.6; docs/50 §3.3.
pub const DNS_CHANNEL: Channel = Channel::new(DNS_MAGIC, DNS_VERSION, REQUEST_LIMIT, REPLY_LIMIT);

/// Most connections dnsd opens to dird at once (dird refuses more — task
/// DN10). Project choice.
/// Spec: docs/54 §4.6 ("≤ 4 connections from dnsd ⚠").
pub const MAX_DNSD_CONNECTIONS: usize = 4;

/// The default deadline of one call of dnsd's client: 20 s. A forwarded
/// UPDATE makes, in dird, two keyd calls (`gss_verify_mic`, `gss_get_mic`;
/// docs/54 §7.3, §7.5) at keyd's 2 s client deadline (docs/50 §3.6) and waits
/// for auditd's acknowledgement of the decision before the commit (docs/54
/// §4.5 step 7; the audit client's 5 s exchange bound) — 9 s; doubled for one
/// request queued ahead of it in dird's bounded DNS queue, rounded up.
/// docs/54 §4.6 asks for a deadline "above keyd's deadline × 3". ⚠ Project
/// choice — dird's real path is pinned against it in task DN10
/// (docs/questions/Q-921 item 3).
/// Spec: docs/54 §4.6; docs/50 §3.6.
pub const DEFAULT_DEADLINE: Duration = Duration::from_secs(20);

/// The envelope: magic, version, kind.
const ENVELOPE: usize = 4;
/// Octets of the largest peer address field: family + an IPv6 address.
const LARGEST_PEER: usize = 1 + 16;
/// Body octets of the largest `Forward`.
const LARGEST_FORWARD: usize = ENVELOPE + 1 + LARGEST_PEER + 4 + MAX_MESSAGE as usize;
/// Body octets of the largest `ImageChunk`.
const LARGEST_CHUNK: usize = ENVELOPE + 4 + MAX_IMAGE_CHUNK as usize + 1;
/// Body octets of the largest `Forwarded`.
const LARGEST_FORWARDED: usize = ENVELOPE + 1 + 4 + MAX_MESSAGE as usize + 4;

/// Octets of one host record of an encoded image at its largest: the label
/// with its length, the address count and eight addresses, the TTL.
const LARGEST_HOST: usize = (4 + MAX_LABEL as usize) + (4 + MAX_ADDRESSES as usize * 4) + 4;
/// Octets of an encoded image at its largest: apex, SERIAL, RNAME, four SOA
/// timers, the infrastructure TTL, the DC, the member hosts, the kpasswd
/// flag.
const LARGEST_IMAGE: usize = (4 + MAX_NAME as usize)
    + 4
    + (4 + MAX_NAME as usize)
    + 4 * 4
    + 4
    + LARGEST_HOST
    + 4
    + MAX_MEMBER_HOSTS as usize * LARGEST_HOST
    + 1;

// The bounds agree with the values they are derived from and fit the body
// bounds; checked at compile time, never at run time.
const _: () = assert!(MIN_MESSAGE == 12);
const _: () = assert!(MAX_UDP_MESSAGE as usize == parse_dns::MAX_UDP_MESSAGE_OCTETS);
const _: () = assert!(MAX_MESSAGE as usize == parse_dns::MAX_TCP_MESSAGE_OCTETS);
const _: () = assert!(MAX_NAME as usize == parse_dns::MAX_NAME_OCTETS);
const _: () = assert!(MAX_LABEL as usize == parse_dns::MAX_LABEL_OCTETS);
const _: () = assert!(MAX_ADDRESSES as usize == dns_zone::limits::MAX_HOST_ADDRESSES);
const _: () = assert!(MAX_MEMBER_HOSTS as usize + 1 == dns_zone::limits::MAX_HOST_RECORDS);
const _: () = assert!(LARGEST_FORWARD <= MAX_REQUEST_BODY as usize);
const _: () = assert!(LARGEST_CHUNK <= MAX_REPLY_BODY as usize);
const _: () = assert!(LARGEST_FORWARDED <= MAX_REPLY_BODY as usize);
const _: () = assert!(LARGEST_IMAGE <= MAX_IMAGE_OCTETS);
const _: () = assert!(MAX_IMAGE_CHUNKS * MAX_IMAGE_CHUNK as usize == MAX_IMAGE_OCTETS);
const _: () = assert!(MAX_IMAGE_CHUNK as usize <= MAX_IMAGE_OCTETS);

// ---- kinds -----------------------------------------------------------------

/// Request kinds (dnsd → dird): docs/54 §4.6's table. Values are a project
/// choice. **`0x02` (`DescribeZone`) is retired by A-152 and never reused**
/// (docs/questions/Q-922): `FetchZoneImage { have }` already answers it —
/// `have: Some(s)` → `Unchanged { s }` is the periodic SERIAL check, and
/// `have: None` returns the whole image, whose first fields are the apex and
/// the SERIAL — so dnsd's start is `Ping` + `FetchZoneImage { have: None }`.
/// The remaining kinds keep their numbers; `0x02` is refused like any
/// unknown kind (docs/50 §3.3: close without a reply).
/// Spec: docs/54 §4.6; docs/50 §3.3 ("`kind` closed"), §7.5 (`Ping` on every
/// channel); docs/25 §3 (D101–D104: minimise the operations); A-152.
pub mod request_kind {
    /// `Ping`: peer verification on every new connection (R9) and health
    /// check; the reply names the zone dird assigned (R14, R9b pattern).
    /// Spec: docs/54 §4.6.
    pub const PING: u8 = 0x01;
    // 0x02 (`DescribeZone`): retired by A-152, never reused
    // (docs/questions/Q-922).
    /// `FetchZoneImage { have }`: the image, unless dnsd's SERIAL is current.
    /// Spec: docs/54 §4.4, §4.6.
    pub const FETCH_ZONE_IMAGE: u8 = 0x03;
    /// `Forward { transport, peer, message }`: a signed UPDATE (or, with
    /// task DN9, a TKEY over TCP) as received, for dird's PEP.
    /// Spec: docs/54 §4.5, §4.6; docs/research/r3-c-dns.md §4.1 (A-140).
    pub const FORWARD: u8 = 0x04;

    /// The kinds retired by A-152 (`DescribeZone`) — kept only so that
    /// tests can show the closed table refuses them; never in [`ALL`] (a
    /// compile-time check below), never reused.
    /// Spec: docs/questions/Q-922 (A-152).
    pub const RETIRED: &[u8] = &[0x02];

    /// The closed request table. Spec: docs/54 §4.6; docs/50 §3.3; A-152.
    pub const ALL: &[u8] = &[PING, FETCH_ZONE_IMAGE, FORWARD];
}

/// Reply kinds (dird → dnsd). [`ipc::REFUSED_KIND`] (`0xFF`) is reserved for
/// the shared transport refusal (A-59). Values are a project choice.
/// **`0x82` (`ZoneDescription`, the reply to the retired `DescribeZone`) is
/// retired by A-152 and never reused** (docs/questions/Q-922).
/// Spec: docs/54 §4.6 (the reply column); docs/50 §3.3; A-59; A-152.
pub mod reply_kind {
    /// `Pong { zone }`: the reply to `Ping`. Spec: docs/54 §4.6.
    pub const PONG: u8 = 0x81;
    // 0x82 (`ZoneDescription`): retired by A-152, never reused
    // (docs/questions/Q-922).
    /// `Unchanged { serial }`: dnsd's image is current.
    /// Spec: docs/54 §4.6.
    pub const UNCHANGED: u8 = 0x83;
    /// `ImageChunk { chunk, more }`: one chunk of the encoded image.
    /// Spec: docs/54 §4.6.
    pub const IMAGE_CHUNK: u8 = 0x84;
    /// `Forwarded { reply, serial }`: dird's answer to a `Forward`.
    /// Spec: docs/54 §4.6; A-140.
    pub const FORWARDED: u8 = 0x85;

    /// The reply kinds retired by A-152 (`ZoneDescription`); never in
    /// [`ALL`] (a compile-time check below), never reused.
    /// Spec: docs/questions/Q-922 (A-152).
    pub const RETIRED: &[u8] = &[0x82];

    /// The closed reply table (without the reserved `REFUSED_KIND`).
    /// Spec: docs/54 §4.6; docs/50 §3.3; A-59; A-152.
    pub const ALL: &[u8] = &[PONG, UNCHANGED, IMAGE_CHUNK, FORWARDED];
}

/// Whether `kinds` lists no value twice. Compile-time helper.
const fn all_distinct(kinds: &[u8]) -> bool {
    let mut i = 0;
    while i < kinds.len() {
        let mut j = i + 1;
        while j < kinds.len() {
            if kinds[i] == kinds[j] {
                return false;
            }
            j += 1;
        }
        i += 1;
    }
    true
}

/// Whether no value of `kinds` is listed in `retired`. Compile-time helper.
const fn none_retired(kinds: &[u8], retired: &[u8]) -> bool {
    let mut i = 0;
    while i < kinds.len() {
        let mut j = 0;
        while j < retired.len() {
            if kinds[i] == retired[j] {
                return false;
            }
            j += 1;
        }
        i += 1;
    }
    true
}

// No kind equals the reserved `REFUSED_KIND` (A-59), each table is a set, and
// no retired kind is back in its table (A-152: never reused). Evaluated at
// compile time: a table that breaks any rule does not build.
const _: () = assert!(ipc::kinds_exclude_refused(request_kind::ALL));
const _: () = assert!(ipc::kinds_exclude_refused(reply_kind::ALL));
const _: () = assert!(all_distinct(request_kind::ALL));
const _: () = assert!(all_distinct(reply_kind::ALL));
const _: () = assert!(none_retired(request_kind::ALL, request_kind::RETIRED));
const _: () = assert!(none_retired(reply_kind::ALL, reply_kind::RETIRED));

// ---- closed value tables ---------------------------------------------------

/// Wire codes of the closed value tables (project choices; one octet each,
/// docs/50 §3.3: "enum = `u8` from a closed table").
pub mod codes {
    /// `Pong.zone`: the internal front (the only zone of phase 1).
    /// Spec: docs/54 §4.6 (`FrontZone::Internal`); A-114.
    pub const ZONE_INTERNAL: u8 = 0x01;

    /// `Forward.transport`: the message arrived over UDP.
    /// Spec: RFC 1035 §4.2.1; A-140.
    pub const TRANSPORT_UDP: u8 = 0x01;
    /// `Forward.transport`: the message arrived over TCP.
    /// Spec: RFC 1035 §4.2.2; A-140.
    pub const TRANSPORT_TCP: u8 = 0x02;

    /// `Forward.peer`: an IPv4 address (4 octets) follows.
    pub const FAMILY_V4: u8 = 0x04;
    /// `Forward.peer`: an IPv6 address (16 octets) follows; never an
    /// IPv4-mapped one (the IPv4 form is the only spelling of those).
    pub const FAMILY_V6: u8 = 0x06;

    /// Image `kpasswd`: no `_kpasswd` SRV records.
    /// Spec: docs/54 §3.1; dns-zone `KpasswdService::Absent`.
    pub const KPASSWD_ABSENT: u8 = 0x01;
    /// Image `kpasswd`: the `_kpasswd` SRV records are synthesized.
    /// Spec: docs/54 §3.1; dns-zone `KpasswdService::Present`.
    pub const KPASSWD_PRESENT: u8 = 0x02;
}
