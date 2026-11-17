//! The zone image: the typed, immutable, bounded snapshot dnsd answers from.
//!
//! Built only through [`ZoneImage::new`], which validates every part, so an
//! invalid image cannot exist (docs/CLEAN-ROOM.md — unrepresentable states):
//!
//! * every host name is exactly one RFC 1035 §2.3.1 LDH label below the apex,
//!   so `*`, `_` and multi-label host names — wildcards, shadowing of an SRV
//!   name, a host "inside" another — have no representation (docs/54 §5.3);
//! * the infrastructure records (SOA, NS, SRV) are not inputs: they are
//!   synthesized from the apex and the DC's host label (docs/54 §5.1), so an
//!   SRV record for a foreign target, or outside the zone, cannot be expressed;
//! * the DC is a host record with at least one address, so the SRV Target, the
//!   NS name and MNAME always have address records (RFC 2782: "There MUST be
//!   one or more address records for this name");
//! * a host carries 1..=8 distinct addresses, never loopback, unspecified or
//!   multicast (docs/54 §4.4, §5.5); two hosts never share a label in any case
//!   (RFC 1034 §3.1); SERIAL is never zero (RFC 2136 §7.11); every TTL is a
//!   positive signed 32-bit value (RFC 1035 §2.3.4);
//! * the image carries nothing else of a directory object — only host label,
//!   addresses and TTL (docs/54 §4.4: "the type itself limits what can reach
//!   the network").
//!
//! Spec: docs/54 §3.1, §4.4, §5.1–§5.4; docs/questions/Q-613 item 3, Q-614,
//! Q-618 item 1.

use crate::limits::{MAX_HOST_ADDRESSES, MAX_HOST_RECORDS, MAX_TTL};
use crate::srv::{KpasswdService, SrvService, SRV_PRIORITY, SRV_WEIGHT};
use core::fmt;
use parse_dns::{Class, Name, RData, ResourceRecord, RrType, Soa, Srv};
use std::collections::BTreeMap;
use std::net::Ipv4Addr;

/// The SOA parameters that come from dird's configuration (MNAME and SERIAL
/// do not: MNAME is the DC's name, SERIAL the zone counter).
///
/// Spec: docs/54 §3.1 (SOA row: "RNAME and REFRESH/RETRY/EXPIRE/MINIMUM — dird
/// configuration ⚠"); RFC 1035 §3.3.13; docs/questions/Q-619 item 5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SoaParameters {
    /// RNAME — the mailbox of the person responsible for the zone.
    pub rname: Name,
    /// REFRESH, in seconds.
    pub refresh: u32,
    /// RETRY, in seconds.
    pub retry: u32,
    /// EXPIRE, in seconds.
    pub expire: u32,
    /// MINIMUM — the floor of every TTL sent from the zone (≤ [`MAX_TTL`]).
    pub minimum: u32,
}

/// One host record as dird projects it from a computer object: the host
/// label, its addresses, its TTL — nothing else.
///
/// Spec: docs/54 §4.4 ("{LDH label, ≤ 8 IPv4 addresses, TTL}"), §5.2, §5.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostRecordParts {
    /// The single label below the apex (the computer's name — docs/54 §5.3),
    /// in the case dird holds it.
    pub label: Vec<u8>,
    /// The host's addresses, 1..=8, distinct.
    pub addresses: Vec<Ipv4Addr>,
    /// The TTL of the host's A records (≤ [`MAX_TTL`]).
    pub ttl: u32,
}

/// Everything [`ZoneImage::new`] validates.
///
/// Spec: docs/54 §4.4 ("apex, SERIAL, SOA parameters, NS, SRV list, host
/// records").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneImageParts {
    /// The apex: the DNS name of the NC (A-53), one or more LDH labels.
    pub apex: Name,
    /// SERIAL — the `dns-zone-serial` counter value, never zero (docs/54 §5.4).
    pub serial: u32,
    /// The configured SOA fields.
    pub soa: SoaParameters,
    /// The TTL of the synthesized SOA, NS and SRV records (≤ [`MAX_TTL`]).
    pub infrastructure_ttl: u32,
    /// The DC's own host record: its label is the first label of MNAME, of the
    /// NS name and of every SRV Target (docs/54 §3.1).
    pub dc: HostRecordParts,
    /// The member hosts (the DC excluded).
    pub hosts: Vec<HostRecordParts>,
    /// Whether the `_kpasswd` SRV records are synthesized (docs/54 §3.1).
    pub kpasswd: KpasswdService,
}

/// Why [`ZoneImage::new`] refused its parts. No variant carries a name or an
/// address — only which rule failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ZoneImageError {
    /// The apex is the root. The zone is the NC's DNS name (docs/54 §3.1,
    /// A-53), which has labels; a root apex would place every name inside the
    /// zone. Spec: RFC 1034 §3.1 ("at or below").
    ApexIsRoot,
    /// An apex label is not an RFC 1035 §2.3.1 LDH label.
    ApexLabelNotLdh,
    /// A synthesized SRV owner name (two labels plus the apex) would exceed
    /// 255 octets. Spec: RFC 1035 §2.3.4, §3.1.
    ApexTooLong,
    /// RNAME is the root, which names no mailbox. Spec: RFC 1035 §3.3.13.
    RnameIsRoot,
    /// SERIAL is zero. Spec: RFC 2136 §7.11 ("should never be set to zero");
    /// docs/54 §5.4.
    SerialZero,
    /// A TTL (or MINIMUM) above the positive signed 32-bit range.
    /// Spec: RFC 1035 §2.3.4.
    TtlOutOfRange,
    /// More host records than [`MAX_HOST_RECORDS`] (the DC counts).
    TooManyHosts,
    /// A host label is not one RFC 1035 §2.3.1 LDH label. Spec: docs/54 §5.3.
    HostLabelNotLdh,
    /// A host label plus the apex exceed 255 octets. Spec: RFC 1035 §2.3.4.
    HostNameTooLong,
    /// Two hosts (the DC included) share a label, compared without case.
    /// Spec: RFC 1034 §3.1 ("not both as brothers"); RFC 1035 §2.3.3.
    DuplicateHost,
    /// A host has no address, or more than [`MAX_HOST_ADDRESSES`].
    /// Spec: docs/54 §4.4.
    HostAddressCount,
    /// A host lists one address twice. Spec: RFC 1034 §3.6 (a *set* of RRs);
    /// RFC 2136 §1.1.1 (equal RRs).
    DuplicateAddress,
    /// A loopback, unspecified or multicast address. Spec: docs/54 §5.5;
    /// docs/questions/Q-614 item 8.
    AddressNotAllowed,
}

impl fmt::Display for ZoneImageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ZoneImageError::ApexIsRoot => "zone apex is the root",
            ZoneImageError::ApexLabelNotLdh => "zone apex label is not a letter-digit-hyphen label",
            ZoneImageError::ApexTooLong => "zone apex leaves no room for the service record names",
            ZoneImageError::RnameIsRoot => "SOA RNAME is the root",
            ZoneImageError::SerialZero => "SOA SERIAL is zero",
            ZoneImageError::TtlOutOfRange => "TTL outside the positive signed 32-bit range",
            ZoneImageError::TooManyHosts => "more host records than the image bound",
            ZoneImageError::HostLabelNotLdh => "host label is not a letter-digit-hyphen label",
            ZoneImageError::HostNameTooLong => "host name longer than 255 octets",
            ZoneImageError::DuplicateHost => "two host records share a label",
            ZoneImageError::HostAddressCount => "host address count outside 1..=8",
            ZoneImageError::DuplicateAddress => "host lists the same address twice",
            ZoneImageError::AddressNotAllowed => "loopback, unspecified or multicast address",
        })
    }
}

impl std::error::Error for ZoneImageError {}

/// A validated host record: its full name (label + apex) and A data.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct HostRecord {
    pub(crate) name: Name,
    pub(crate) addresses: Vec<Ipv4Addr>,
    pub(crate) ttl: u32,
}

/// The typed, immutable, bounded snapshot dnsd answers queries from.
///
/// Spec: docs/54 §4.4; docs/questions/Q-613 item 2 (a); A-119.
#[derive(Clone, PartialEq, Eq)]
pub struct ZoneImage {
    apex: Name,
    apex_label_count: usize,
    serial: u32,
    soa: Soa,
    infrastructure_ttl: u32,
    dc_fqdn: Name,
    /// Hosts keyed by their label in ASCII lower case (RFC 1035 §3.1: labels
    /// compare case-insensitively; LDH labels are ASCII). The DC is one of them.
    hosts: BTreeMap<Vec<u8>, HostRecord>,
    dc_key: Vec<u8>,
    /// The synthesized SRV owners, each with its owner name.
    srv: Vec<(SrvService, Name)>,
}

impl fmt::Debug for ZoneImage {
    /// The apex, SERIAL and counts only: zone content is not secret (docs/54
    /// §4.4, "privacy"), but a debug line never lists every host name
    /// (docs/54 §9 — no per-query or bulk content in logs).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ZoneImage")
            .field("apex", &self.apex)
            .field("serial", &self.serial)
            .field("host_records", &self.hosts.len())
            .field("srv_records", &self.srv.len())
            .finish()
    }
}

/// What a QNAME is in this zone.
///
/// Spec: RFC 1034 §4.3.2 step 2 (nearest zone), step 3 (matching down: a
/// whole match, or a label that does not exist).
pub(crate) enum Lookup<'a> {
    /// QNAME is not at or below the apex (RFC 1034 §3.1).
    OutsideZone,
    /// QNAME is inside the zone but no node of that name exists (RFC 1034
    /// §4.3.2 step 3c, with no "*" label — docs/54 §6.4).
    NoSuchName,
    /// QNAME names a node of the zone (RFC 1034 §4.3.2 step 3a).
    Node(Node<'a>),
}

/// A node of the zone. Spec: RFC 1034 §3.1 ("Each node … corresponds to a
/// resource set (which may be empty)").
pub(crate) enum Node<'a> {
    /// The apex: SOA and NS.
    Apex,
    /// A host: A records.
    Host(&'a HostRecord),
    /// A synthesized SRV owner.
    Srv(SrvService, &'a Name),
    /// `_tcp.<apex>` or `_udp.<apex>` while an SRV owner lies below it: a node
    /// with an empty resource set (RFC 1034 §3.1), so QNAME matches it whole
    /// (§4.3.2 step 3a) and the answer is NODATA, not a name error.
    EmptyNonTerminal,
}

/// The records a node holds for one QTYPE, and the records step 6 adds.
pub(crate) struct NodeRecords {
    pub(crate) answer: Vec<ResourceRecord>,
    pub(crate) additional: Vec<ResourceRecord>,
}

impl ZoneImage {
    /// Validates `parts` and builds the image.
    ///
    /// Spec: docs/54 §4.4, §5.1, §5.3; RFC 1035 §2.3.1, §2.3.4; RFC 1034 §3.1;
    /// RFC 2136 §7.11; RFC 2782 (Target).
    pub fn new(parts: ZoneImageParts) -> Result<ZoneImage, ZoneImageError> {
        let ZoneImageParts {
            apex,
            serial,
            soa,
            infrastructure_ttl,
            dc,
            hosts,
            kpasswd,
        } = parts;

        if serial == 0 {
            return Err(ZoneImageError::SerialZero);
        }
        if infrastructure_ttl > MAX_TTL || soa.minimum > MAX_TTL {
            return Err(ZoneImageError::TtlOutOfRange);
        }
        if apex.is_root() {
            return Err(ZoneImageError::ApexIsRoot);
        }
        if !apex.labels().all(is_ldh_label) {
            return Err(ZoneImageError::ApexLabelNotLdh);
        }
        if soa.rname.is_root() {
            return Err(ZoneImageError::RnameIsRoot);
        }
        // `hosts` excludes the DC, which takes one more slot.
        if hosts.len() >= MAX_HOST_RECORDS {
            return Err(ZoneImageError::TooManyHosts);
        }

        // The synthesized SRV owners: two labels below the apex.
        let mut srv = Vec::with_capacity(SrvService::ALL.len());
        for service in SrvService::ALL {
            if service.synthesized_with(kpasswd) {
                let owner = below_apex(&apex, &[service.service_label(), service.proto_label()])
                    .ok_or(ZoneImageError::ApexTooLong)?;
                srv.push((service, owner));
            }
        }

        let dc_key = dc.label.to_ascii_lowercase();
        let mut table = BTreeMap::new();
        for parts in core::iter::once(dc).chain(hosts) {
            let key = parts.label.to_ascii_lowercase();
            let record = host_record(&apex, parts)?;
            if table.insert(key, record).is_some() {
                return Err(ZoneImageError::DuplicateHost);
            }
        }
        let dc_fqdn = match table.get(&dc_key) {
            Some(record) => record.name.clone(),
            // Unreachable: the DC was inserted first and a duplicate returns.
            None => return Err(ZoneImageError::DuplicateHost),
        };

        let apex_label_count = apex.label_count();
        Ok(ZoneImage {
            soa: Soa {
                mname: dc_fqdn.clone(),
                rname: soa.rname,
                serial,
                refresh: soa.refresh,
                retry: soa.retry,
                expire: soa.expire,
                minimum: soa.minimum,
            },
            apex,
            apex_label_count,
            serial,
            infrastructure_ttl,
            dc_fqdn,
            hosts: table,
            dc_key,
            srv,
        })
    }

    /// The apex (the zone's name). Spec: docs/54 §4.6 (`DescribeZone`).
    pub fn apex(&self) -> &Name {
        &self.apex
    }

    /// SERIAL. Spec: docs/54 §4.4 (dnsd pulls a new image when it changes),
    /// §5.4.
    pub fn serial(&self) -> u32 {
        self.serial
    }

    /// The DC's fully qualified name: MNAME, the NS name and every SRV Target.
    /// Spec: docs/54 §3.1; [MS-ADTS] §6.3.2.3 (Target "the fully qualified DNS
    /// name of the server").
    pub fn dc_name(&self) -> &Name {
        &self.dc_fqdn
    }

    /// MINIMUM: the floor of every TTL in a reply. Spec: RFC 1035 §3.3.13.
    pub fn minimum(&self) -> u32 {
        self.soa.minimum
    }

    /// Number of host records, the DC's included.
    pub fn host_count(&self) -> usize {
        self.hosts.len()
    }

    /// The synthesized SRV services, in image order.
    pub fn srv_services(&self) -> impl Iterator<Item = SrvService> + '_ {
        self.srv.iter().map(|(service, _)| *service)
    }

    /// The TTL a record carries in a reply: the maximum of its own TTL and
    /// MINIMUM. Spec: RFC 1035 §3.3.13 ("the TTL field is set to the maximum of
    /// the TTL field from the RR and the MINIMUM field in the appropriate
    /// SOA"), §6.2; docs/54 §6.4.
    pub(crate) fn reply_ttl(&self, ttl: u32) -> u32 {
        ttl.max(self.soa.minimum)
    }

    /// Where QNAME lies in this zone. Name comparison is case-insensitive
    /// (RFC 1035 §2.3.3, §3.1; docs/questions/Q-642 item 10).
    ///
    /// Spec: RFC 1034 §4.3.2 steps 2–3 (one zone; no delegation below the
    /// apex, so step 3b never happens; no "*" label, so step 3c is a name
    /// error — docs/54 §6.4).
    pub(crate) fn lookup<'a>(&'a self, qname: &Name) -> Lookup<'a> {
        if !qname.is_subdomain_of(&self.apex) {
            return Lookup::OutsideZone;
        }
        let depth = qname.label_count().saturating_sub(self.apex_label_count);
        let mut labels = qname.labels();
        match (depth, labels.next(), labels.next()) {
            (0, _, _) => Lookup::Node(Node::Apex),
            (1, Some(label), _) => {
                if let Some(host) = self.hosts.get(&label.to_ascii_lowercase()) {
                    return Lookup::Node(Node::Host(host));
                }
                let above_srv = self
                    .srv
                    .iter()
                    .any(|(service, _)| service.proto_label().eq_ignore_ascii_case(label));
                if above_srv {
                    Lookup::Node(Node::EmptyNonTerminal)
                } else {
                    Lookup::NoSuchName
                }
            }
            (2, Some(first), Some(second)) => self
                .srv
                .iter()
                .find(|(service, _)| {
                    service.service_label().eq_ignore_ascii_case(first)
                        && service.proto_label().eq_ignore_ascii_case(second)
                })
                .map_or(Lookup::NoSuchName, |(service, owner)| {
                    Lookup::Node(Node::Srv(*service, owner))
                }),
            _ => Lookup::NoSuchName,
        }
    }

    /// The records of `node` that match `qtype`, with TTLs already floored by
    /// MINIMUM, and the address records RFC 1034 §4.3.2 step 6 adds.
    ///
    /// Spec: RFC 1034 §4.3.2 step 3a ("copy all RRs which match QTYPE into the
    /// answer section"), step 6; RFC 1035 §3.3.11 (NS: "additional section
    /// processing to locate a type A record"), §3.3.13 (SOA: none), §3.4.1 (A:
    /// none); RFC 2782 (Target addresses "in the Additional Data section");
    /// docs/54 §3.1, §6.4.
    pub(crate) fn records(&self, node: &Node<'_>, qtype: RrType) -> NodeRecords {
        let mut answer = Vec::new();
        let mut additional = Vec::new();
        match node {
            Node::Apex if qtype == RrType::SOA => {
                answer.push(self.rr(
                    &self.apex,
                    self.infrastructure_ttl,
                    RData::Soa(self.soa.clone()),
                ));
            }
            Node::Apex if qtype == RrType::NS => {
                answer.push(self.rr(
                    &self.apex,
                    self.infrastructure_ttl,
                    RData::Ns(self.dc_fqdn.clone()),
                ));
                self.push_dc_addresses(&mut additional);
            }
            Node::Host(host) if qtype == RrType::A => {
                for address in &host.addresses {
                    answer.push(self.rr(&host.name, host.ttl, RData::A(*address)));
                }
            }
            Node::Srv(service, owner) if qtype == RrType::SRV => {
                answer.push(self.rr(
                    owner,
                    self.infrastructure_ttl,
                    RData::Srv(Srv {
                        priority: SRV_PRIORITY,
                        weight: SRV_WEIGHT,
                        port: service.port(),
                        target: self.dc_fqdn.clone(),
                    }),
                ));
                self.push_dc_addresses(&mut additional);
            }
            // A node without RRs of QTYPE: NODATA (docs/54 §6.4 step 3a).
            Node::Apex | Node::Host(_) | Node::Srv(..) | Node::EmptyNonTerminal => {}
        }
        NodeRecords { answer, additional }
    }

    /// The DC's A records, for the additional section.
    fn push_dc_addresses(&self, out: &mut Vec<ResourceRecord>) {
        if let Some(dc) = self.hosts.get(&self.dc_key) {
            for address in &dc.addresses {
                out.push(self.rr(&dc.name, dc.ttl, RData::A(*address)));
            }
        }
    }

    /// One IN-class record with its reply TTL. Spec: RFC 1035 §4.1.3; §3.3.13
    /// (TTL floor); RFC 2782 ("SRV records occur in the IN Class").
    fn rr(&self, owner: &Name, ttl: u32, rdata: RData) -> ResourceRecord {
        ResourceRecord {
            name: owner.clone(),
            class: Class::IN,
            ttl: self.reply_ttl(ttl),
            rdata,
        }
    }
}

/// Validates one host record and builds its full name.
fn host_record(apex: &Name, parts: HostRecordParts) -> Result<HostRecord, ZoneImageError> {
    if parts.ttl > MAX_TTL {
        return Err(ZoneImageError::TtlOutOfRange);
    }
    if !is_ldh_label(&parts.label) {
        return Err(ZoneImageError::HostLabelNotLdh);
    }
    if parts.addresses.is_empty() || parts.addresses.len() > MAX_HOST_ADDRESSES {
        return Err(ZoneImageError::HostAddressCount);
    }
    for (index, address) in parts.addresses.iter().enumerate() {
        if !is_host_address(*address) {
            return Err(ZoneImageError::AddressNotAllowed);
        }
        if parts.addresses[..index].contains(address) {
            return Err(ZoneImageError::DuplicateAddress);
        }
    }
    let name =
        below_apex(apex, &[parts.label.as_slice()]).ok_or(ZoneImageError::HostNameTooLong)?;
    Ok(HostRecord {
        name,
        addresses: parts.addresses,
        ttl: parts.ttl,
    })
}

/// `prefix` labels followed by the apex labels, if the name fits 255 octets.
/// Spec: RFC 1035 §3.1.
fn below_apex(apex: &Name, prefix: &[&[u8]]) -> Option<Name> {
    Name::from_labels(prefix.iter().copied().chain(apex.labels())).ok()
}

/// Whether `address` may be a host's A record address: never loopback,
/// unspecified or multicast. The one statement of the rule — the image
/// validates every host with it, and the directory's write checker (task
/// DN6, crates/directory-admin, through crates/directory-pip) accepts a
/// registered address only by it, so a stored address the image would
/// refuse cannot be written (docs/52 C14: one rule, one place).
///
/// Spec: docs/54 §4.4, §5.5 ("not loopback/unspecified/multicast");
/// docs/questions/Q-614 item 8.
pub fn is_host_address(address: Ipv4Addr) -> bool {
    !(address.is_loopback() || address.is_unspecified() || address.is_multicast())
}

/// Whether `label` is an RFC 1035 §2.3.1 preferred-syntax label: it starts
/// with a letter, ends with a letter or digit, has only letters, digits and
/// hyphens inside, and is 63 characters or less.
///
/// Spec: RFC 1035 §2.3.1 (`<label> ::= <letter> [ [ <ldh-str> ] <let-dig> ]`;
/// "Labels must be 63 characters or less"); docs/54 §5.3; Q-614 item 3.
pub fn is_ldh_label(label: &[u8]) -> bool {
    let (Some(first), Some(last)) = (label.first(), label.last()) else {
        return false;
    };
    label.len() <= 63
        && first.is_ascii_alphabetic()
        && last.is_ascii_alphanumeric()
        && label
            .iter()
            .all(|octet| octet.is_ascii_alphanumeric() || *octet == b'-')
}
