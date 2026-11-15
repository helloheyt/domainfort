//! The source of a request: whether dnsd serves it at all, and the one key
//! "per source" means for every limiter and counter.
//!
//! * **Served only from inside.** A source outside `internal_networks` is
//!   dropped without a byte (UDP: no reply; TCP: closed before any octet is
//!   read) — "internal" is enforced by the owner of the facts, the socket
//!   (A-114 on Q-469 (b); docs/54 §4.7), with the configuration's one match
//!   (`config::is_internal`: same family only, an IPv4-mapped IPv6 address
//!   not rewritten — Q-275 item 9), not a third copy of it.
//! * **The key.** An IPv4 source is keyed by its address, an IPv6 source by
//!   its /64 prefix — the low 64 bits zeroed — so a host that rotates its
//!   interface identifier inside one /64 counts once (docs/54 §6.7: "per
//!   source (IPv4 address / IPv6 /64 prefix)"; A-154 item 6 (a): the shared
//!   limiter is used as is, the caller passes the prefix). An IPv4-mapped
//!   IPv6 address is keyed as the IPv4 address it maps (std
//!   `IpAddr::to_canonical`), so one host has one key — as the channel
//!   spells the forwarded peer (crates/ipc-dns `PeerAddress`).
//!
//! Spec: docs/54 §4.7, §6.7; A-114; A-154 item 6 (a); docs/questions/Q-275
//! item 9, Q-930 item 6; std API documentation (`IpAddr::to_canonical`,
//! `Ipv6Addr::from_bits` / `u128::from`).

use config::Network;
use core::net::{IpAddr, Ipv6Addr};

/// The high 64 bits of an IPv6 address: its /64 prefix.
/// Spec: docs/54 §6.7.
const IPV6_PREFIX_MASK: u128 = u128::MAX << 64;

/// The key under which `address` is limited and counted (module
/// documentation). Spec: docs/54 §6.7; A-154 item 6 (a).
#[must_use]
pub fn source_key(address: IpAddr) -> IpAddr {
    match address.to_canonical() {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & IPV6_PREFIX_MASK)),
    }
}

/// Whether dnsd serves `source`: it lies in one of the internal networks —
/// the configuration's one match. Spec: docs/54 §4.7; A-114.
#[must_use]
pub fn is_served(internal: &[Network], source: IpAddr) -> bool {
    config::is_internal(internal, source)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::net::Ipv4Addr;

    /// docs/54 §6.7 ("IPv4 address / IPv6 /64 prefix"); A-154 item 6 (a):
    /// two addresses in one /64 share a key, another /64 does not; an IPv4
    /// address is its own key; an IPv4-mapped IPv6 address has its IPv4 key.
    /// Addresses from the documentation ranges (hand-made).
    #[test]
    fn ipv6_sources_are_keyed_by_their_64_prefix() {
        let a = IpAddr::V6(Ipv6Addr::new(0xfd00, 0x1234, 0, 7, 1, 2, 3, 4));
        let b = IpAddr::V6(Ipv6Addr::new(0xfd00, 0x1234, 0, 7, 0xffff, 0, 0, 9));
        let c = IpAddr::V6(Ipv6Addr::new(0xfd00, 0x1234, 0, 8, 1, 2, 3, 4));
        assert_eq!(source_key(a), source_key(b));
        assert_ne!(source_key(a), source_key(c));
        assert_eq!(
            source_key(a),
            IpAddr::V6(Ipv6Addr::new(0xfd00, 0x1234, 0, 7, 0, 0, 0, 0))
        );
        let v4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53));
        assert_eq!(source_key(v4), v4);
        let mapped = IpAddr::V6(Ipv4Addr::new(192, 0, 2, 53).to_ipv6_mapped());
        assert_eq!(source_key(mapped), v4);
    }

    /// docs/54 §4.7; A-114; Q-275 item 9: the configuration's match decides,
    /// and an IPv4-mapped IPv6 source is not served through an IPv4 network.
    #[test]
    fn only_internal_sources_are_served() {
        let net = Network::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)), 24).expect("network");
        let inside = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));
        let outside = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
        let mapped = IpAddr::V6(Ipv4Addr::new(192, 0, 2, 7).to_ipv6_mapped());
        assert!(is_served(&[net], inside));
        assert!(!is_served(&[net], outside));
        assert!(!is_served(&[net], mapped));
        assert!(!is_served(&[], inside));
    }
}
