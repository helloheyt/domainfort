#![forbid(unsafe_code)]
//! `dns-zone`: the zone image dnsd answers from, and dnsd's answer function
//! (docs/54 §4.4, §6.4–§6.6; build task DN2; decision A-119).
//!
//! Pure: no I/O, no sockets, no clock reads — the zone's freshness is a
//! parameter ([`ZoneState::from_confirmation`]).
//!
//! # Scope (phase 1, docs/54 §3)
//!
//! * [`ZoneImage`] — the typed, immutable, bounded snapshot: apex, SERIAL,
//!   SOA parameters, the DC's host record, member host records (label,
//!   1..=8 IPv4 addresses, TTL — nothing else of a directory object), and the
//!   synthesized NS / SOA / SRV records (docs/54 §3.1, §4.4, §5.1;
//!   docs/questions/Q-618 item 1). Built only by [`ZoneImage::new`], which
//!   validates every part, so an invalid image — a wildcard or `_` host, a
//!   name outside the zone, an SRV Target without address records — cannot
//!   exist.
//! * [`answer`] — maps every request octet string to exactly one
//!   [`Verdict`]: a bounded [`Reply`], silence, close, or a signed UPDATE
//!   forwarded to dird. Authoritative only: no recursion, no cache, no
//!   wildcard, no CNAME, no zone transfer, `*` refused, no SOA in negative
//!   answers (docs/54 §3.2, §6.4). The refusal table as built is in the
//!   documentation of `src/answer.rs`.
//! * The UDP size rule (docs/54 §6.5): a UDP reply is at most 512 octets and
//!   at most `k` × the request ([`limits::UDP_AMPLIFICATION_FACTOR`], k = 4);
//!   an error reply at most the request; otherwise TC = 1 with header and
//!   question. Enforced in the one place a [`Reply`] can be built.
//!
//! Every reply is a parse-dns `Message` encoded by parse-dns's canonical
//! encoder, except the 12-octet NOTIMP reply to an opcode parse-dns does not
//! model (docs/questions/Q-670 item 9).
//!
//! # Not here
//!
//! TKEY (RFC 2930 is not in specs/SOURCES.md — docs/questions/Q-610; task
//! DN9): until then a TKEY query is an ordinary query of an unknown QTYPE.
//! AAAA (RFC 3596, Q-610): an AAAA query on an existing name is NODATA.
//! Rate limits, listeners, the image transfer and its refresh: dnsd (DN3,
//! DN7, DN11).
//!
//! # Provenance
//!
//! Written only from the allowed specifications, opened in-session from the
//! pinned copies in `tools/spec-pin/cache/` with SHA-256 verified against
//! `tools/spec-pin/manifest.json` (docs/CLEAN-ROOM.md): RFC 1034 §3.1, §3.6,
//! §3.7–§3.7.2, §4.3.1–§4.3.4; RFC 1035 §2.3.1–§2.3.4, §3.1–§3.2.5, §3.3,
//! §3.3.11, §3.3.13, §3.4.1, §4.1–§4.1.3, §4.2–§4.2.2, §6.2; RFC 2136 §1.1,
//! §2–§2.3, §3, §3.1, §3.3, §3.8, §7.8, §7.11; RFC 2782 (whole); RFC 4120
//! §7.2.3–§7.2.3.3; RFC 8945 §4.2, §4.3.1–§4.3.3, §5.1–§5.3.2; [MS-ADTS]
//! v20261026 §6.3.2.3, §6.3.2.4; and the project's decided design docs/54
//! (A-119) with docs/questions/Q-613, Q-614, Q-616, Q-618, Q-642. No other
//! implementation was consulted or recalled.
//!
//! Spec: RFC 1034 §4.3.2; RFC 1035 §4.1, §6.2; docs/54 §4.4, §6.4–§6.6.

mod answer;
mod image;
pub mod limits;
mod reply;
mod srv;

pub use answer::{answer, Forward, Silence, Verdict, ZoneState};
pub use image::{
    is_host_address, is_ldh_label, HostRecordParts, SoaParameters, ZoneImage, ZoneImageError,
    ZoneImageParts,
};
pub use parse_dns::Transport;
pub use reply::{udp_reply_limit, Reply};
pub use srv::{KpasswdService, SrvService, SRV_PRIORITY, SRV_WEIGHT};
