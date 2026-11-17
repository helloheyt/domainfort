//! The DNS host record of a computer object — the rules its one writer
//! (crates/directory-admin, the write checker's `DnsSelfUpdate`), the PIP
//! (`Pip::object_tier` of `Resource::Dns`) and the zone projection
//! (crate::zone) all read here, once (docs/52 C14: one rule, one place).
//!
//! # The record is an attribute of its owner (docs/54 §5.2; Q-614)
//!
//! A host's addresses are values of the internal attribute
//! `ad_schema::HOST_ADDRESS` on its own computer object — one 4-octet value
//! per IPv4 address (RFC 1035 §3.4.1). The tombstone of a `Delete` removes
//! them in the same transaction (A-18), so a record outliving its owner —
//! the dangling-record class — cannot exist. Each value's dirstore
//! attr-stamp is its registration time: a value kept by a write keeps its
//! stamp, a value (re)added gets the write's (dirstore
//! `AttributeChange::Replace`).
//!
//! # The name is derived from the identity (docs/54 §5.3; Q-614 item 3)
//!
//! The host's label is its computerName — the sAMAccountName without the
//! final "$" ([MS-ADTS] 3.1.1.5.3.1.1.2: dNSHostName is "computerName.
//! fullDomainDnsName, where computerName is the current sAMAccountName of
//! the object (without the final "$" character)") — and only if that is one
//! RFC 1035 §2.3.1 preferred-syntax label and the object's dNSHostName is
//! exactly `<label>.<zone>` (compared without case, RFC 1035 §2.3.3). So a
//! host name is one LDH label below the apex: `*`, `_`, a dot — a wildcard,
//! a shadowed SRV name, a multi-level name — have no representation.
//! Stricter than [MS-SAMR]: a digit-first computerName has no host record
//! (RFC 1123 is not in specs/SOURCES.md — Q-614 item 3).
//!
//! # One equivalence, one lookup (task PN4b; docs/questions/Q-1036 item 6)
//!
//! "Without case" is the principal namespace's one fold
//! (`principal_names::fold` — [MS-KILE] 3.1.5.7, Q-080), not a comparison of
//! this module's own: the host name, the label and the zone are names of
//! the namespace (a computer's dNSHostName is its `HostName` key, docs/59
//! §4.1), so the DNS owner rule, rule N6 of the one write checker (which
//! asks [`host_label`]) and the namespace cannot disagree on what is "the
//! same name" (class C49). And the owner of a label is found by the key
//! `fold(<label>.<zone>)` in the namespace's unique index — the one probe
//! of crate::resolve — never through a per-attribute index (docs/59 §5.3):
//! the index makes every host name's holder unique over the union of all
//! kinds, and the rule above then requires the holder's computerName to be
//! the label.
//!
//! # An address is registrable only inside the configured networks
//!
//! Never loopback, unspecified or multicast (crate dns-zone
//! `is_host_address` — the image's own rule), and inside one of the
//! registrable networks (`config::Network::contains`, the one address
//! matcher — A-114). At most [`MAX_HOST_ADDRESSES`] per host (the image's
//! bound).
//!
//! Spec: docs/54 §4.4, §5.2-§5.5; docs/59 §4.1, §5.3; docs/questions/Q-614
//! items 1-3, 7, 8, Q-991, Q-1036 item 6; [MS-ADTS] v20261026
//! 3.1.1.5.3.1.1.2; [MS-KILE] v20261110 3.1.5.7; RFC 1035 §2.3.1, §2.3.3,
//! §3.4.1; RFC 2136 §3.6, §7.11 (the zone serial).

use crate::error::Fault;
use crate::record;
use crate::view::DirectoryView;
use config::Network;
use dirstore::CounterState;
use dtyp::Guid;
use pdp::{PipError, Tier};
use principal_names::fold;
use std::net::{IpAddr, Ipv4Addr};

pub use ad_schema::HOST_ADDRESS;
pub use dns_zone::limits::MAX_HOST_ADDRESSES;

/// The name of the zone's serial counter (the A1 named-counter mechanism,
/// A-75 / A-83): created by the provisioning session only, taken in the
/// **same** `WriteTxn` as every write that changes the zone's content
/// (crates/directory-admin `invariants`), so "the zone's contents and the
/// SOA's SERIAL be tightly synchronized" holds by construction.
/// Spec: docs/54 §5.4; RFC 2136 §3.6; A-75; A-83; dirstore
/// `MAX_COUNTER_NAME_LEN` (alphabet `a-z 0-9 . - _`).
pub const DNS_ZONE_SERIAL_COUNTER: &str = "dns-zone-serial";

/// The first value of the zone serial counter; its range ends at `u64::MAX`
/// (exclusive), like the change-seq's. Project choice: 1, never 0 (RFC 2136
/// §7.11). docs/questions/Q-991 item 6.
pub const DNS_ZONE_SERIAL_FIRST: u64 = 1;

/// One past the last zone serial counter value. Spec: dirstore
/// `CounterState` (half-open range).
pub const DNS_ZONE_SERIAL_END_EXCLUSIVE: u64 = u64::MAX;

/// The trailing character of a computer's sAMAccountName. Spec: [MS-SAMR]
/// 3.1.1.6 item 11 ("MUST end with a single '$'"), as quoted by [MS-ADTS]
/// 3.1.1.5.3.1.1.2 ("without the final "$" character").
const COMPUTER_SUFFIX: char = '$';

/// The label separator of a DNS name in text form. Spec: RFC 1035 §2.3.1
/// (`<subdomain> "." <label>`).
const LABEL_SEPARATOR: char = '.';

/// `true` if the names `a` and `b` are the same name without case: equal
/// after the principal namespace's one fold, each a name the fold accepts
/// (non-empty printable ASCII within the key bound — anything else is no
/// name, so no match: fail closed). The only comparison of names in this
/// module (module documentation, "One equivalence, one lookup").
/// Spec: RFC 1035 §2.3.3 ("all comparisons between character strings
/// (e.g., labels, domain names, etc.) are done in a case-insensitive
/// manner"); [MS-KILE] 3.1.5.7; Q-080 items 1-2; docs/questions/Q-1036
/// item 6.
fn same_name(a: &str, b: &str) -> bool {
    matches!((fold(a), fold(b)), (Some(a), Some(b)) if a == b)
}

/// The SOA SERIAL of the zone whose serial counter is in `state`: the value
/// the **next** take returns, modulo 2³² — so every take (every content
/// change) moves it — and `None` when that is 0, which a zone never shows
/// (the writer takes once more instead, crates/directory-admin). A counter
/// that is exhausted still names its last state.
/// Spec: docs/54 §5.4 ("SERIAL = the counter value mod 2³², and 0
/// skipped"); RFC 2136 §7.11 ("should never be set to zero … increment it
/// again or set it to one"), §3.6.
#[must_use]
pub fn zone_serial(state: &CounterState) -> Option<u32> {
    // The low 32 bits: the modulo-2³² arithmetic of RFC 2136 §3.6.
    let serial = u32::try_from(state.next_value & u64::from(u32::MAX)).ok()?;
    (serial != 0).then_some(serial)
}

/// The host label of a computer whose sAMAccountName is `sam_account_name`
/// and whose dNSHostName is `dns_host_name`, in the zone `zone` (the naming
/// context's DNS name, A-53) — `None` when the object has no host name
/// (module documentation, "The name is derived from the identity"): the
/// sAMAccountName does not end with "$", its computerName is not one LDH
/// label, or the dNSHostName is not exactly `<computerName>.<zone>` without
/// case — compared through the namespace's one fold (module documentation,
/// "One equivalence, one lookup"). The label returned is the
/// sAMAccountName's own spelling.
/// Spec: [MS-ADTS] 3.1.1.5.3.1.1.2; RFC 1035 §2.3.1, §2.3.3; [MS-KILE]
/// 3.1.5.7; docs/54 §5.3; docs/questions/Q-614 item 3, Q-1036 item 6.
#[must_use]
pub fn host_label<'s>(
    sam_account_name: &'s str,
    dns_host_name: &str,
    zone: &str,
) -> Option<&'s str> {
    let label = computer_label(sam_account_name)?;
    if zone.is_empty() {
        return None;
    }
    let (first, rest) = dns_host_name.split_once(LABEL_SEPARATOR)?;
    (same_name(first, label) && same_name(rest, zone)).then_some(label)
}

/// The label half of [`host_label`]: the computerName of a computer
/// account — its sAMAccountName without the final "$" — when that name is
/// one RFC 1035 §2.3.1 label; `None` otherwise. [`host_label`] is built on
/// it, so a caller that must say *why* a host name is refused (the
/// computer's name, or the zone it would sit in — crate directory-admin
/// `own_host_name`, task PN6b) asks the same rule instead of a copy of it
/// (class C49; A-185).
/// Spec: [MS-ADTS] 3.1.1.5.3.1.1.2 (computerName = the sAMAccountName
/// "without the final '$' character"); RFC 1035 §2.3.1; docs/54 §5.3;
/// docs/questions/Q-614 item 3.
#[must_use]
pub fn computer_label(sam_account_name: &str) -> Option<&str> {
    let label = sam_account_name.strip_suffix(COMPUTER_SUFFIX)?;
    dns_zone::is_ldh_label(label.as_bytes()).then_some(label)
}

/// The stored value of the host address `address`: its four octets in
/// network order. Spec: RFC 1035 §3.4.1, §2.3.2; ad-schema
/// `HOST_ADDRESS_OCTETS`.
#[must_use]
pub fn host_address_value(address: Ipv4Addr) -> Vec<u8> {
    address.octets().to_vec()
}

/// The host address a stored value holds; `None` for a value that is not
/// four octets (the store refuses one; an inconsistent record otherwise).
/// Spec: RFC 1035 §3.4.1; ad-schema `HOST_ADDRESS_OCTETS`.
#[must_use]
pub fn host_address_of(value: &[u8]) -> Option<Ipv4Addr> {
    <[u8; 4]>::try_from(value).ok().map(Ipv4Addr::from)
}

/// Whether `address` may be registered (module documentation): an allowed
/// host address (dns-zone `is_host_address` — never loopback, unspecified
/// or multicast) inside one of `networks`. No network ⇒ nothing is
/// registrable (fail closed).
/// Spec: docs/54 §5.5 ("address inside `dns_registrable_networks` and not
/// loopback/unspecified/multicast"); docs/questions/Q-614 item 8; A-114.
#[must_use]
pub fn registrable(address: Ipv4Addr, networks: &[Network]) -> bool {
    dns_zone::is_host_address(address) && config::is_internal(networks, IpAddr::V4(address))
}

impl DirectoryView<'_> {
    /// The zone of this view: the naming context's DNS name (A-53) — the
    /// apex of the one zone docs/54 §3.1 serves.
    /// Spec: docs/54 §3.1, §5.1; A-53; RFC 1035 §2.3.1.
    #[must_use]
    pub fn zone_name(&self) -> String {
        self.ctx.naming_context().dns_name()
    }

    /// The owner of the host name `key` in the zone `zone`: the one computer
    /// object whose host label it is (module documentation) — the holder of
    /// the `HostName` key `fold(<key>.<zone>)`, found by the one probe of
    /// the namespace's unique index (crate::resolve `host_name_holder`;
    /// docs/questions/Q-1036 item 6), then checked by the host-name rule
    /// against its stored values. `None` when the zone is not this view's,
    /// `key` is not one LDH label, or no computer owns it. A GUID only (an
    /// authority read: nothing of the object is handed back).
    ///
    /// # Errors
    /// `PipError::Unavailable` when the store fails or a record is
    /// inconsistent (a key its holder's names do not give included).
    ///
    /// Spec: docs/54 §5.3, §5.6; docs/59 §4.1, §5.3; docs/questions/Q-614
    /// items 3, 6, Q-1036 item 6; [MS-ADTS] 3.1.1.5.3.1.1.2; RFC 1035
    /// §2.3.1, §2.3.3.
    pub fn dns_record_owner(&self, zone: &str, key: &str) -> Result<Option<Guid>, PipError> {
        Ok(self.record_owner(zone, key)?)
    }

    /// [`DirectoryView::dns_record_owner`] with internal faults.
    fn record_owner(&self, zone: &str, key: &str) -> Result<Option<Guid>, Fault> {
        let ids = self.ctx.ids;
        let own_zone = self.zone_name();
        if !same_name(zone, &own_zone) || !dns_zone::is_ldh_label(key.as_bytes()) {
            return Ok(None);
        }
        // The dNSHostName the label's owner carries, `<computerName>.<zone>`
        // ([MS-ADTS] 3.1.1.5.3.1.1.2) — its `HostName` key once folded.
        let mut host_name = String::with_capacity(key.len() + 1 + own_zone.len());
        host_name.push_str(key);
        host_name.push(LABEL_SEPARATOR);
        host_name.push_str(&own_zone);
        let Some(obj) = self.host_name_holder(&host_name)? else {
            return Ok(None);
        };
        if self.most_specific_class(&obj)? != ids.computer {
            return Ok(None);
        }
        let stored = record::text(&obj, ids.sam_account_name)?.ok_or(Fault::Unavailable)?;
        let Some(dns_host_name) = record::text(&obj, ids.dns_host_name)? else {
            return Ok(None);
        };
        Ok(match host_label(stored, dns_host_name, &own_zone) {
            Some(label) if same_name(label, key) => Some(obj.guid),
            _ => None,
        })
    }

    /// `object_tier` of the DNS record `key` in `zone` (`Pip::object_tier`
    /// of `Resource::Dns { zone, record: Some(key) }`): the directory-object
    /// tier of its owner ([`DirectoryView::dns_record_owner`]) — the same
    /// rule as for a write to that object, A-36's Tier0 default for an
    /// unclassified one included; no owner ⇒ Tier0 (fail closed).
    /// Spec: docs/54 §5.6; docs/questions/Q-614 item 6; docs/47 §6.3; A-36.
    pub(crate) fn dns_record_tier(&self, zone: &str, key: &str) -> Result<Tier, PipError> {
        let Some(owner) = self.record_owner(zone, key)? else {
            return Ok(Tier::Tier0);
        };
        match self.dn_of(owner)? {
            Some(dn) => Ok(self.dir_object_tier(&dn)?),
            None => Ok(Tier::Tier0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// [MS-ADTS] 3.1.1.5.3.1.1.2 (computerName.fullDomainDnsName), RFC 1035
    /// §2.3.1 (the label grammar), §2.3.3 (case): names are this project's
    /// test data.
    #[test]
    fn the_host_label_rule() {
        let zone = "example.test";
        assert_eq!(host_label("ws01$", "ws01.example.test", zone), Some("ws01"));
        assert_eq!(host_label("WS01$", "ws01.example.test", zone), Some("WS01"));
        assert_eq!(host_label("ws01$", "WS01.Example.TEST", zone), Some("ws01"));
        assert_eq!(host_label("a$", "a.example.test", zone), Some("a"));
        // Not a computer name, not `<label>.<zone>`, not LDH.
        for (sam, host) in [
            ("ws01", "ws01.example.test"),
            ("ws01$", "ws02.example.test"),
            ("ws01$", "ws01.other.test"),
            ("ws01$", "ws01.example.test.evil"),
            ("ws01$", "ws01"),
            ("ws01$", "x.ws01.example.test"),
            ("1ws$", "1ws.example.test"),
            ("ws-$", "ws-.example.test"),
            ("w_s$", "w_s.example.test"),
            ("*$", "*.example.test"),
            ("_ldap$", "_ldap.example.test"),
            ("ws01$$", "ws01$.example.test"),
            ("$", ".example.test"),
        ] {
            assert_eq!(host_label(sam, host, zone), None, "{sam} {host}");
        }
        let long = format!("{}$", "a".repeat(64));
        assert_eq!(
            host_label(&long, &format!("{}.example.test", "a".repeat(64)), zone),
            None
        );
        assert_eq!(host_label("ws01$", "ws01.", ""), None);
    }

    /// docs/questions/Q-1036 item 6 (one fold — class C49); Q-080 items 1-2
    /// (printable ASCII, A-Z folded); RFC 1035 §2.3.3: names compare
    /// through the namespace's fold — equal without case; a name the fold
    /// has no key for (empty, a non-printable octet) equals nothing, itself
    /// included (fail closed).
    #[test]
    fn names_compare_through_the_namespace_fold() {
        assert!(same_name("WS01", "ws01"));
        assert!(same_name("Example.Test", "example.TEST"));
        assert!(!same_name("ws01", "ws02"));
        assert!(!same_name("", ""));
        assert!(!same_name("ex\tample", "ex\tample"));
        assert!(!same_name("caf\u{e9}", "caf\u{e9}"));
        // So a zone or host name the fold refuses gives no host label.
        assert_eq!(host_label("ws01$", "ws01.ex\tample", "ex\tample"), None);
        assert_eq!(
            host_label("ws01$", "WS01.EXAMPLE.TEST", "example.test"),
            Some("ws01")
        );
    }

    /// RFC 2136 §7.11 (never zero), §3.6 (modulo 2³²); docs/54 §5.4.
    #[test]
    fn the_zone_serial_skips_zero() {
        let state = |next_value| CounterState {
            first_value: 1,
            next_value,
            end_exclusive: u64::MAX,
        };
        assert_eq!(zone_serial(&state(1)), Some(1));
        assert_eq!(zone_serial(&state(0xFFFF_FFFF)), Some(0xFFFF_FFFF));
        assert_eq!(zone_serial(&state(0x1_0000_0000)), None);
        assert_eq!(zone_serial(&state(0x1_0000_0001)), Some(1));
    }

    /// RFC 1035 §3.4.1 (four octets, network order); docs/54 §5.5.
    #[test]
    fn addresses_and_networks() {
        let a = Ipv4Addr::new(192, 0, 2, 10);
        assert_eq!(host_address_value(a), vec![192, 0, 2, 10]);
        assert_eq!(host_address_of(&[192, 0, 2, 10]), Some(a));
        assert_eq!(host_address_of(&[192, 0, 2]), None);
        let net = Network::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)), 24).unwrap();
        assert!(registrable(a, &[net]));
        assert!(!registrable(Ipv4Addr::new(198, 51, 100, 1), &[net]));
        assert!(!registrable(a, &[]));
        let any = Network::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 1).unwrap();
        for bad in [
            Ipv4Addr::new(127, 0, 0, 1),
            Ipv4Addr::new(0, 0, 0, 0),
            Ipv4Addr::new(224, 0, 0, 1),
        ] {
            assert!(!registrable(bad, &[net, any]), "{bad}");
        }
    }
}
