//! The zone table: the source address of a request → `Peer.src_net`.
//!
//! docs/50 §4.1: "`Peer.src_net` — mapped from the source address by a zone
//! table in the configuration (CIDR → `IpScope::Internal`; everything else
//! `External`) — the daemon sees it, the client does not claim it"; §4.2:
//! "the mapping belongs to the PEP". The configuration carries the entries
//! (`internal_networks`, crates/config: canonical network address, host
//! bits zero, prefix ≥ 1) **and the one match** (`config::Network::contains`
//! / `config::is_internal`: same address family only, an IPv4-mapped IPv6
//! address not rewritten — docs/questions/Q-275 item 9): the kdc's own copy
//! of the containment code is gone (task R15b, docs/questions/Q-632; A-114's
//! follow-up), so the kdc, its configuration's listener rule and
//! ldap-front classify an address by the same code. The mapping to an
//! `IpScope` stays here, in the PEP.
//!
//! The table also checks the kdc's listeners (docs/50 R50-9, "binding to
//! internal interfaces only"): [`ZoneTable::is_internal`].
//!
//! Spec: docs/50 R50-9, §4.1, §4.2; docs/11 §1 (`Context.src_net`);
//! docs/questions/Q-230 item 8 (A-60), Q-275 item 9 (A-69), Q-580 (A-114),
//! Q-632.

use config::Network;
use core::net::IpAddr;
use pdp::IpScope;

/// The internal networks; everything else is External.
/// Spec: docs/50 §4.1.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ZoneTable {
    internal: Vec<Network>,
}

impl ZoneTable {
    /// A table of `internal` networks (crates/config's type: only the
    /// parser's rules make one — `config::Network::new`).
    #[must_use]
    pub fn new(internal: Vec<Network>) -> ZoneTable {
        ZoneTable { internal }
    }

    /// The table of the configuration's `internal_networks` (already
    /// validated by crates/config).
    #[must_use]
    pub fn from_settings(networks: &[Network]) -> ZoneTable {
        ZoneTable {
            internal: networks.to_vec(),
        }
    }

    /// Whether `address` lies in an internal network — the configuration's
    /// one match (`config::is_internal`). Spec: docs/50 §4.1; Q-275 item 9.
    #[must_use]
    pub fn is_internal(&self, address: IpAddr) -> bool {
        config::is_internal(&self.internal, address)
    }

    /// The zone of `source`. Spec: docs/50 §4.1; docs/11 §1.
    #[must_use]
    pub fn scope(&self, source: IpAddr) -> IpScope {
        if self.is_internal(source) {
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

    /// docs/50 §4.1 (CIDR → Internal, else External); Q-230 item 8 (empty
    /// table ⇒ External); Q-275 item 9 (no family translation) — through
    /// crates/config's one match (its own rules — host bits, prefix bounds —
    /// are tested there: crates/config tests `network_containment`).
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
        // The same answers as the configuration's match, for every address
        // above (one implementation).
        for address in [v4(10, 200, 3, 4), v4(11, 0, 0, 1), mapped] {
            assert_eq!(
                table.is_internal(address),
                config::is_internal(&[ten, ula], address)
            );
        }
    }
}
