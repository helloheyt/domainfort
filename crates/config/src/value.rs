//! Typed values: each setting's octets are accepted only in one canonical
//! spelling of one type.
//!
//! No value type admits `$`, `{`, `}`, `~`, `%` or a space inside a scalar, so
//! a value that looks like an environment reference (`$HOME/run`, `${X}`) is
//! **rejected**, never expanded and never taken literally (docs/50 §7.1: "no
//! override from the environment"; docs/questions/Q-230 item 9).
//!
//! Spec: docs/50 R50-15, §7.1 ("every value typed: integer in range, duration
//! with a unit, absolute path, CIDR, numeric id").

use core::net::{IpAddr, SocketAddr};
use core::time::Duration;
use std::path::Path;

use crate::error::ErrorKind;
use crate::limits::{Bound, MAX_LIST_ITEMS};

/// The list separator: exactly a comma and one space.
/// Spec: docs/50 §7.1; docs/questions/Q-230 item 14.
const LIST_SEPARATOR: &str = ", ";

/// The separator inside a map entry `<uid>:<name>`.
/// Spec: docs/50 §3.2; docs/questions/Q-230 item 5.
const MAP_SEPARATOR: char = ':';

/// The unit suffix of a duration: seconds only.
/// Spec: docs/50 §7.1 ("a duration with a unit"); Q-230 item 13.
const SECONDS_SUFFIX: &str = "s";

/// The attribute of every naming-context component, lower case.
/// Spec: docs/50 §7.1 ("naming context (A-53)"); crates/directory-pip
/// `NC_RDN_ATTRIBUTE` ("dc").
const NC_COMPONENT_PREFIX: &str = "dc=";

/// The separator of naming-context components (no space after the comma, per
/// A-53). Spec: docs/questions/PENDING-OWNER A-53.
const NC_COMPONENT_SEPARATOR: char = ',';

/// Most components in a naming context: 16.
/// Spec: crates/directory-pip `MAX_NC_LABELS` (16), which re-validates.
pub const MAX_NAMING_CONTEXT_LABELS: usize = 16;

/// The all-ones account id, never accepted (docs/questions/Q-230 item 6).
const ALL_ONES_ID: u32 = u32::MAX;

// ---- integers and durations -------------------------------------------------

/// A canonical unsigned decimal: one or more digits, no sign, no leading zero
/// (except `0` itself), within `u32`. Spec: docs/50 §7.1 (typed values; one
/// spelling per value).
pub(crate) fn decimal_u32(text: &str) -> Result<u32, ErrorKind> {
    let bytes = text.as_bytes();
    let canonical = !bytes.is_empty()
        && bytes.iter().all(u8::is_ascii_digit)
        && (bytes.len() == 1 || bytes.first() != Some(&b'0'));
    if !canonical {
        return Err(ErrorKind::InvalidInteger);
    }
    let mut value: u32 = 0;
    for &b in bytes {
        value = value
            .checked_mul(10)
            .and_then(|v| v.checked_add(u32::from(b - b'0')))
            .ok_or(ErrorKind::InvalidInteger)?;
    }
    Ok(value)
}

/// An integer limit inside its documented range.
/// Spec: docs/50 §3.6, §4.1 (the limits); docs/questions/Q-230 item 4.
pub(crate) fn bounded(text: &str, bound: Bound) -> Result<u32, ErrorKind> {
    let value = decimal_u32(text)?;
    if bound.admits(value) {
        Ok(value)
    } else {
        Err(ErrorKind::OutOfRange)
    }
}

/// A duration `<seconds>s` inside its documented range, in seconds.
/// Spec: docs/50 §7.1 ("a duration with a unit"); §3.6, §4.1, §4.2.
pub(crate) fn duration_secs(text: &str, bound: Bound) -> Result<u32, ErrorKind> {
    let digits = text
        .strip_suffix(SECONDS_SUFFIX)
        .ok_or(ErrorKind::InvalidDuration)?;
    let value = decimal_u32(digits).map_err(|_| ErrorKind::InvalidDuration)?;
    if bound.admits(value) {
        Ok(value)
    } else {
        Err(ErrorKind::OutOfRange)
    }
}

/// Seconds as a [`Duration`].
pub(crate) fn seconds(secs: u32) -> Duration {
    Duration::from_secs(u64::from(secs))
}

/// A numeric account id (uid or gid): never 0 and never all-ones.
/// Spec: docs/50 R50-3 ("uid 0 is never mapped"), §7.1 ("uids/gids numeric —
/// no NSS lookup"); docs/questions/Q-230 item 6.
pub(crate) fn account_id(text: &str) -> Result<u32, ErrorKind> {
    let id = decimal_u32(text)?;
    if id == 0 || id == ALL_ONES_ID {
        return Err(ErrorKind::ReservedId);
    }
    Ok(id)
}

// ---- paths ------------------------------------------------------------------

/// A canonical absolute path.
///
/// Starts with `/`; one or more components of `A-Z a-z 0-9 . _ -`, none empty,
/// `.` or `..`; no trailing `/`. The configuration never opens the path: the
/// daemon checks ownership and mode when it uses it (docs/50 §5.3: the TLS key
/// file is root:0400; §7.1: the configuration itself is root:0644).
///
/// Spec: docs/50 §7.1 ("absolute path"); docs/questions/Q-230 item 16.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbsolutePath(String);

impl AbsolutePath {
    /// The path as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The path as a [`Path`].
    #[must_use]
    pub fn as_path(&self) -> &Path {
        Path::new(&self.0)
    }
}

/// The path component alphabet. Spec: docs/questions/Q-230 item 16.
const fn is_path_octet(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')
}

/// Parses an [`AbsolutePath`]. Spec: docs/50 §7.1.
pub(crate) fn absolute_path(text: &str) -> Result<AbsolutePath, ErrorKind> {
    let relative = text.strip_prefix('/').ok_or(ErrorKind::InvalidPath)?;
    for component in relative.split('/') {
        let valid = !component.is_empty()
            && component != "."
            && component != ".."
            && component.bytes().all(is_path_octet);
        if !valid {
            return Err(ErrorKind::InvalidPath);
        }
    }
    Ok(AbsolutePath(text.to_owned()))
}

// ---- names ------------------------------------------------------------------

/// The realm: one or more of `A-Z a-z 0-9 . -`. The daemon re-validates it as
/// a KerberosString (crates/krb-proto) and against the naming context
/// (crates/ldap, A-55).
/// Spec: docs/50 §7.1 ("realm"); docs/questions/Q-230 item 15.
pub(crate) fn realm(text: &str) -> Result<String, ErrorKind> {
    let valid = !text.is_empty()
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'));
    if valid {
        Ok(text.to_owned())
    } else {
        Err(ErrorKind::InvalidRealm)
    }
}

/// The naming context — the DN of the domain root (A-53) — as its labels.
///
/// Written `dc=<label>,…,dc=<label>`, leaf first, `dc` in lower case, no space
/// after a comma, 1 ..= [`MAX_NAMING_CONTEXT_LABELS`] components, each label
/// one or more of `A-Z a-z 0-9 -`. The daemon builds
/// `directory_pip::NamingContext::new(labels)`, which re-validates.
///
/// Spec: docs/50 §7.1 ("naming context (A-53)"); docs/questions/PENDING-OWNER
/// A-53, A-55; docs/questions/Q-230 item 15.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamingContextLabels(Vec<String>);

impl NamingContextLabels {
    /// The labels n1 … nk, leaf first.
    #[must_use]
    pub fn labels(&self) -> &[String] {
        &self.0
    }
}

/// Parses [`NamingContextLabels`]. Spec: docs/50 §7.1; A-53.
pub(crate) fn naming_context(text: &str) -> Result<NamingContextLabels, ErrorKind> {
    let mut labels = Vec::new();
    for component in text.split(NC_COMPONENT_SEPARATOR) {
        if labels.len() == MAX_NAMING_CONTEXT_LABELS {
            return Err(ErrorKind::InvalidNamingContext);
        }
        let label = component
            .strip_prefix(NC_COMPONENT_PREFIX)
            .ok_or(ErrorKind::InvalidNamingContext)?;
        let valid = !label.is_empty()
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-');
        if !valid {
            return Err(ErrorKind::InvalidNamingContext);
        }
        labels.push(label.to_owned());
    }
    Ok(NamingContextLabels(labels))
}

/// One name from a fixed list, matched exactly (case-sensitive).
/// Spec: docs/50 §3.2, §7.3, §8.1 (the closed name sets).
pub(crate) fn named<N: Copy>(text: &str, names: &[(&str, N)]) -> Result<N, ErrorKind> {
    names
        .iter()
        .find(|(name, _)| *name == text)
        .map(|&(_, value)| value)
        .ok_or(ErrorKind::UnknownName)
}

// ---- addresses --------------------------------------------------------------

/// A listener socket address, in the one spelling the standard library prints
/// for it (`192.0.2.1:88`, `[2001:db8::1]:636`): non-zero port, no IPv6 flow
/// information or scope, and an address that names a single interface (not
/// unspecified, multicast or the IPv4 broadcast address).
///
/// Spec: docs/50 §7.1 ("listen addresses"), §4.1 ("bind to internal
/// interfaces only"); docs/questions/Q-230 item 7.
pub(crate) fn listener_address(text: &str) -> Result<SocketAddr, ErrorKind> {
    let address: SocketAddr = text.parse().map_err(|_| ErrorKind::InvalidSocketAddress)?;
    let plain = match address {
        SocketAddr::V4(_) => true,
        SocketAddr::V6(v6) => v6.flowinfo() == 0 && v6.scope_id() == 0,
    };
    if !plain || address.port() == 0 || address.to_string() != text {
        return Err(ErrorKind::InvalidSocketAddress);
    }
    let interface = match address.ip() {
        IpAddr::V4(ip) => !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast(),
        IpAddr::V6(ip) => !ip.is_unspecified() && !ip.is_multicast(),
    };
    if !interface {
        return Err(ErrorKind::NotAnInterfaceAddress);
    }
    Ok(address)
}

/// A network of the zone table: an address and a prefix length.
///
/// Spec: docs/50 §4.1 ("a zone table in the configuration — CIDR →
/// `IpScope::Internal`, everything else `External`"), §4.2 (dird's own zone
/// table). Mapping a peer address through the table is the PEP's job (§4.2:
/// "the mapping belongs to the PEP"), so this type only carries the entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Network {
    address: IpAddr,
    prefix_len: u8,
}

impl Network {
    /// The network address (all bits past the prefix are zero).
    #[must_use]
    pub const fn address(&self) -> IpAddr {
        self.address
    }

    /// The prefix length: 1 ..= 32 (IPv4) or 1 ..= 128 (IPv6).
    #[must_use]
    pub const fn prefix_len(&self) -> u8 {
        self.prefix_len
    }
}

/// Parses a [`Network`] `<address>/<prefix>`: the address in the standard
/// library's printed spelling, the prefix a canonical decimal, host bits zero,
/// prefix 0 refused.
/// Spec: docs/50 §7.1 ("CIDR"), §4.1; docs/questions/Q-230 item 8.
pub(crate) fn network(text: &str) -> Result<Network, ErrorKind> {
    let (address_text, prefix_text) = text.split_once('/').ok_or(ErrorKind::InvalidNetwork)?;
    let address: IpAddr = address_text
        .parse()
        .map_err(|_| ErrorKind::InvalidNetwork)?;
    if address.to_string() != address_text {
        return Err(ErrorKind::InvalidNetwork);
    }
    let prefix = decimal_u32(prefix_text).map_err(|_| ErrorKind::InvalidNetwork)?;
    let width: u32 = match address {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if prefix > width {
        return Err(ErrorKind::InvalidNetwork);
    }
    if prefix == 0 {
        return Err(ErrorKind::NetworkTooBroad);
    }
    // The host bits are the `width - prefix` low-order bits: all-ones shifted
    // right by `prefix` (a full-width shift, prefix == width, leaves none).
    let host_set = match address {
        IpAddr::V4(ip) => {
            let host_mask = u32::MAX.checked_shr(prefix).unwrap_or(0);
            u32::from(ip) & host_mask != 0
        }
        IpAddr::V6(ip) => {
            let host_mask = u128::MAX.checked_shr(prefix).unwrap_or(0);
            u128::from(ip) & host_mask != 0
        }
    };
    if host_set {
        return Err(ErrorKind::NetworkHostBits);
    }
    let prefix_len = u8::try_from(prefix).map_err(|_| ErrorKind::InvalidNetwork)?;
    Ok(Network {
        address,
        prefix_len,
    })
}

// ---- lists and maps ---------------------------------------------------------

/// The items of a list: 1 ..= [`MAX_LIST_ITEMS`] parts separated by exactly
/// `", "`, each parsed by `item`.
/// Spec: docs/50 §7.1; docs/questions/Q-230 item 14.
fn items<T>(text: &str, item: impl Fn(&str) -> Result<T, ErrorKind>) -> Result<Vec<T>, ErrorKind> {
    let mut items: Vec<T> = Vec::new();
    for part in text.split(LIST_SEPARATOR) {
        if items.len() == MAX_LIST_ITEMS {
            return Err(ErrorKind::TooManyItems);
        }
        // No list item type contains a space or a comma, so an empty part or
        // a part holding either means the separator was not exactly ", ".
        if part.is_empty() || part.contains([' ', ',']) {
            return Err(ErrorKind::InvalidList);
        }
        items.push(item(part)?);
    }
    Ok(items)
}

/// A list (see [`items`]) in which no item is repeated.
/// Spec: docs/50 §7.1; docs/questions/Q-230 item 14.
pub(crate) fn list<T: PartialEq>(
    text: &str,
    item: impl Fn(&str) -> Result<T, ErrorKind>,
) -> Result<Vec<T>, ErrorKind> {
    let values = items(text, item)?;
    for (index, value) in values.iter().enumerate() {
        if values.get(..index).unwrap_or_default().contains(value) {
            return Err(ErrorKind::DuplicateEntry);
        }
    }
    Ok(values)
}

/// A map from account ids to names of a fixed list: `<uid>:<Name>` entries in
/// a list. Every uid is an account id (never 0 — R50-3), each uid appears
/// once ("one Role per uid") and each name once (Q-230 item 5).
/// Spec: docs/50 R50-3, §3.2 ("a uid that appears twice ⇒ keyd does not
/// start").
pub(crate) fn id_map<N: Copy + PartialEq>(
    text: &str,
    names: &[(&str, N)],
) -> Result<Vec<(u32, N)>, ErrorKind> {
    let entries = items(text, |entry| {
        let (id_text, name_text) = entry
            .split_once(MAP_SEPARATOR)
            .ok_or(ErrorKind::InvalidMapEntry)?;
        Ok((account_id(id_text)?, named(name_text, names)?))
    })?;
    for (index, (id, name)) in entries.iter().enumerate() {
        let earlier = entries.get(..index).unwrap_or_default();
        if earlier.iter().any(|(other, _)| other == id) {
            return Err(ErrorKind::DuplicateId);
        }
        if earlier.iter().any(|(_, other)| other == name) {
            return Err(ErrorKind::DuplicateEntry);
        }
    }
    Ok(entries)
}
