//! The zone table: the source address of a request → `Peer.src_net`.
//!
//! docs/50 §4.1: "`Peer.src_net` — mapped from the source address by a zone
//! table in the configuration (CIDR → `IpScope::Internal`; everything else
//! `External`) — the daemon sees it, the client does not claim it"; §4.2:
//! "the mapping belongs to the PEP". The configuration carries the entries
//! (`internal_networks`, crates/config: canonical network address, host
//! bits zero, prefix ≥ 1); the match is here.
//!
//! A source matches an entry of its own address family only: an IPv4 source
//! is compared with the IPv4 entries, an IPv6 source (an IPv4-mapped one
//! included) with the IPv6 entries. No address is rewritten, so nothing is
//! classified Internal by a translation the operator did not write (fail
//! closed, docs/questions/Q-275 item 9). An empty table makes every source
//! External — the restrictive scope (docs/questions/Q-230 item 8).
//!
//! Spec: docs/50 §4.1, §4.2; docs/11 §1 (`Context.src_net`);
//! docs/questions/Q-230 item 8 (A-60).

use core::net::IpAddr;
use pdp::IpScope;

/// One internal network: an address with all bits past the prefix zero,
/// and the prefix length (1 ..= 32 or 1 ..= 128).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Network {
    address: IpAddr,
    prefix_len: u8,
}

impl Network {
    /// A network, or `None` if the prefix is 0 or longer than the address,
    /// or a host bit is set (the configuration's rules, Q-230 item 8).
    #[must_use]
    pub fn new(address: IpAddr, prefix_len: u8) -> Option<Network> {
        let width = match address {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix_len == 0 || prefix_len > width {
            return None;
        }
        let network = Network {
            address,
            prefix_len,
        };
        network.contains(address).then_some(network)
    }

    /// Whether `source` lies in this network (same family only).
    #[must_use]
    pub fn contains(&self, source: IpAddr) -> bool {
        match (self.address, source) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix_len))
                    .unwrap_or(0);
                u32::from(ip) & mask == u32::from(net)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix_len))
                    .unwrap_or(0);
                u128::from(ip) & mask == u128::from(net)
            }
            _ => false,
        }
    }
}

/// The internal networks; everything else is External.
/// Spec: docs/50 §4.1.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ZoneTable {
    internal: Vec<Network>,
}

impl ZoneTable {
    /// A table of `internal` networks.
    #[must_use]
    pub fn new(internal: Vec<Network>) -> ZoneTable {
        ZoneTable { internal }
    }

    /// The table of the configuration's `internal_networks` (already
    /// validated by crates/config).
    #[must_use]
    pub fn from_settings(networks: &[config::Network]) -> ZoneTable {
        ZoneTable {
            internal: networks
                .iter()
                .filter_map(|n| Network::new(n.address(), n.prefix_len()))
                .collect(),
        }
    }

    /// The zone of `source`. Spec: docs/50 §4.1; docs/11 §1.
    #[must_use]
    pub fn scope(&self, source: IpAddr) -> IpScope {
        if self.internal.iter().any(|n| n.contains(source)) {
            IpScope::Internal
        } else {
            IpScope::External
        }
    }

    /// The number of internal networks.
    #[must_use]
    pub fn len(&self) -> usize {
        self.internal.len()
    }

    /// Whether the table has no entry (every source External).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.internal.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::net::{Ipv4Addr, Ipv6Addr};

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    /// docs/50 §4.1 (CIDR → Internal, else External); Q-230 item 8 (host
    /// bits zero, prefix ≥ 1, empty table ⇒ External); Q-275 item 9 (no
    /// family translation).
    #[test]
    fn cidr_entries_classify_sources() {
        let ten = Network::new(v4(10, 0, 0, 0), 8).unwrap();
        let ula = Network::new(IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0)), 16).unwrap();
        let table = ZoneTable::new(vec![ten, ula]);
        assert_eq!(table.scope(v4(10, 200, 3, 4)), IpScope::Internal);
        assert_eq!(table.scope(v4(11, 0, 0, 1)), IpScope::External);
        assert_eq!(
            table.scope(IpAddr::V6(Ipv6Addr::new(0xfd00, 1, 2, 3, 4, 5, 6, 7))),
            IpScope::Internal
        );
        assert_eq!(
            table.scope(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))),
            IpScope::External
        );
        // An IPv4-mapped IPv6 source is not rewritten into IPv4.
        let mapped = IpAddr::V6(Ipv4Addr::new(10, 1, 1, 1).to_ipv6_mapped());
        assert_eq!(table.scope(mapped), IpScope::External);
        assert_eq!(
            ZoneTable::default().scope(v4(10, 0, 0, 1)),
            IpScope::External
        );
        // Host bits, prefix 0 and over-long prefixes are refused.
        assert!(Network::new(v4(10, 0, 0, 1), 8).is_none());
        assert!(Network::new(v4(10, 0, 0, 0), 0).is_none());
        assert!(Network::new(v4(10, 0, 0, 0), 33).is_none());
        let host = Network::new(v4(192, 168, 1, 7), 32).unwrap();
        assert!(host.contains(v4(192, 168, 1, 7)));
        assert!(!host.contains(v4(192, 168, 1, 8)));
    }
}
