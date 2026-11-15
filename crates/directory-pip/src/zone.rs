//! The zone projection: the one function from the directory to the zone
//! image dnsd answers from (docs/54 §4.4; task DN6, decision A-119) — for
//! dird's DNS channel (task DN10a: `ZoneHost::zone_image`).
//!
//! # What it is
//!
//! [`DirectoryView::zone_projection`] reads ONE snapshot (this view's — the
//! authority's own read, docs/questions/Q-486 item 5; pinned by the A-111
//! scan in tests/pep_receives_only_the_gate.rs) and builds a
//! `dns_zone::ZoneImage` with the zone crate's own validating constructor:
//!
//! - **apex** — the naming context's DNS name (A-53);
//! - **SERIAL** — the `dns-zone-serial` counter ([`crate::zone_serial`]):
//!   every write that changes what this function returns takes that counter
//!   in its own transaction (crates/directory-admin `invariants`), so a
//!   change of content is a change of SERIAL (RFC 2136 §3.6) — except the
//!   changes time alone makes, which [`ZoneProjection::valid_until`] names
//!   (below);
//! - **SOA parameters, TTLs, the `_kpasswd` switch** — dird's configuration
//!   ([`ZoneParameters`]); SOA, NS and SRV are synthesized by the image from
//!   the apex and the DC's name, never stored (docs/54 §5.1);
//! - **the DC's host record** — the one computer account with
//!   userAccountControl ST (OD-2: one DC), its label by the host-name rule
//!   (crate::host), its addresses as provisioned (never aged: the DC has no
//!   key set in phase 1 and cannot re-register — docs/54 §3.1);
//! - **the member hosts** — every other computer holding host addresses
//!   whose account is usable now (not disabled, not expired — the KDC's own
//!   `usable_at`, docs/47 §4), whose names pass the host-name rule, keeping
//!   only the addresses registered less than `max_record_age` ago and still
//!   inside the registrable networks (docs/54 §4.4, §5.2; Q-614 items 7-8).
//!   Nothing else of a directory object reaches the image (its type has
//!   nothing else — docs/54 §4.4).
//!
//! # The time it holds for
//!
//! Two filters depend on the clock, not on a write: an address's age and an
//! account's accountExpires. [`ZoneProjection::valid_until`] is the earliest
//! instant at which either would change this function's answer without any
//! write. Until then, the image is a function of the SERIAL; from then on,
//! the caller must not serve or confirm an image of the same SERIAL —
//! docs/questions/Q-993 records the residual and the recommended step for
//! the channel (DN10a).
//!
//! # Bounds and failure
//!
//! The walk reads at most [`MAX_ZONE_WALK_OBJECTS`] objects and descends at
//! most `MAX_DN_DEPTH` levels; beyond either, or on any store fault, an
//! inconsistent record, no DC, two DCs, a DC without a host name or an
//! address, or a SERIAL the zone cannot show — no image (fail closed: dnsd
//! keeps its last image until its age bound, then SERVFAIL — docs/54 §4.4).
//! A member host whose stored record no longer fits the rules (e.g. after a
//! change of the registrable networks) is left out of the image, not served.
//!
//! Spec: docs/54 §3.1, §4.4, §5.1-§5.4; RFC 1034 §3.1; RFC 1035 §2.3.4,
//! §3.4.1; RFC 2136 §3.6, §7.11; docs/47 §4 (`usable_at`); A-53; A-119;
//! docs/questions/Q-613 item 3, Q-614 items 7-8, Q-991, Q-993.

use crate::error::Fault;
use crate::host::{
    host_address_of, host_label, registrable, zone_serial, DNS_ZONE_SERIAL_COUNTER, HOST_ADDRESS,
};
use crate::record;
use crate::state;
use crate::time::{dstime_of, time_of_dstime};
use crate::view::{DirectoryView, MAX_DN_DEPTH};
use config::Network;
use core::fmt;
use dirstore::{ChildCursor, Object, MAX_CHILDREN_PER_PAGE};
use dns_zone::{
    HostRecordParts, KpasswdService, SoaParameters, ZoneImage, ZoneImageError, ZoneImageParts,
};
use dtyp::Guid;
use krb_proto::KerberosTime;
use parse_dns::Name;
use std::collections::VecDeque;
use std::net::Ipv4Addr;

/// Most objects one projection reads. docs/54 fixes none; this project
/// choice bounds the walk's work (AGENTS.md §6) at four times the image's
/// own host bound (`dns_zone::limits::MAX_HOST_RECORDS`, 65 536), leaving
/// room for the users, groups and containers beside the computers.
/// docs/questions/Q-991 item 9 (⚠ to be measured).
pub const MAX_ZONE_WALK_OBJECTS: usize = 262_144;

/// dird's zone configuration: what the image takes that the directory does
/// not hold.
/// Spec: docs/54 §3.1 (SOA row: "RNAME and REFRESH/RETRY/EXPIRE/MINIMUM —
/// dird configuration ⚠"), §4.4, §5.2 (`dns_record_max_age`), §5.5
/// (`dns_registrable_networks`); docs/questions/Q-619 item 5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneParameters {
    /// RNAME, REFRESH, RETRY, EXPIRE, MINIMUM of the synthesized SOA.
    pub soa: SoaParameters,
    /// The TTL of the synthesized SOA, NS and SRV records.
    pub infrastructure_ttl: u32,
    /// The TTL of every host's A records — one value for the zone (RFC 2136
    /// §7.12: "recommended that all TTLs in an RRset be set to the same
    /// value"; no stored per-host TTL — docs/questions/Q-991 item 4).
    pub host_ttl: u32,
    /// Whether the `_kpasswd` SRV records are synthesized (docs/54 §3.1).
    pub kpasswd: KpasswdService,
    /// `dns_record_max_age`, in seconds: an address registered longer ago
    /// is left out (docs/54 §5.2; Q-614 item 7). Zero leaves every member
    /// address out.
    pub max_record_age: u64,
    /// `dns_registrable_networks`: a member address outside every one is
    /// left out (docs/54 §5.5; Q-614 item 8).
    pub registrable_networks: Vec<Network>,
}

/// The projection's answer: the image, and the instant it holds until.
/// Spec: module documentation; docs/questions/Q-993.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneProjection {
    image: ZoneImage,
    /// The parts `image` was validated from — what the channel encodes
    /// (crates/ipc-dns `ImageTransfer::new`, which validates them again);
    /// task DN10a, docs/questions/Q-1000 item 2.
    parts: ZoneImageParts,
    valid_until: Option<KerberosTime>,
}

impl ZoneProjection {
    /// The zone image (its SERIAL is the `dns-zone-serial` counter's).
    #[must_use]
    pub fn image(&self) -> &ZoneImage {
        &self.image
    }

    /// The image, by value.
    #[must_use]
    pub fn into_image(self) -> ZoneImage {
        self.image
    }

    /// The parts the image was validated from (`ZoneImage::new` accepted
    /// exactly these), for dird's DNS channel: the transfer encoding takes
    /// parts, not an image (crates/ipc-dns `ImageTransfer::new`; task DN10a).
    /// Spec: docs/54 §4.4, §4.6; docs/questions/Q-1000 item 2.
    #[must_use]
    pub fn parts(&self) -> &ZoneImageParts {
        &self.parts
    }

    /// The earliest instant at which the clock alone — an address reaching
    /// `max_record_age`, an account reaching its accountExpires — changes
    /// what the projection returns; `None` if nothing in the image ages. At
    /// or after it, an image of the same SERIAL must not be served as
    /// current (module documentation; docs/questions/Q-993).
    #[must_use]
    pub fn valid_until(&self) -> Option<KerberosTime> {
        self.valid_until
    }
}

/// Why no image was built. No variant carries a name, an address or any
/// directory value (AGENTS.md §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ZoneProjectionError {
    /// The store failed, or a record is inconsistent (fail closed).
    Unavailable,
    /// The walk would read more than [`MAX_ZONE_WALK_OBJECTS`] objects, or
    /// descend deeper than `MAX_DN_DEPTH`.
    TooLarge,
    /// No `dns-zone-serial` counter (a store not provisioned for DNS —
    /// A-83: never created here), or its state names SERIAL 0.
    NoZoneSerial,
    /// No computer account with userAccountControl ST, or more than one
    /// (OD-2: one DC).
    DcAccount,
    /// The DC's names do not pass the host-name rule (crate::host).
    DcName,
    /// The DC holds no host address.
    DcAddress,
    /// The naming context's labels do not form a DNS name.
    Apex,
    /// `now` is outside the DSTIME range.
    Time,
    /// The zone crate refused the parts.
    Image(ZoneImageError),
}

impl fmt::Display for ZoneProjectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZoneProjectionError::Unavailable => {
                f.write_str("directory unavailable or inconsistent")
            }
            ZoneProjectionError::TooLarge => {
                f.write_str("directory larger than the zone walk bound")
            }
            ZoneProjectionError::NoZoneSerial => f.write_str("no usable zone serial counter"),
            ZoneProjectionError::DcAccount => f.write_str("not exactly one DC account"),
            ZoneProjectionError::DcName => f.write_str("DC account has no host name"),
            ZoneProjectionError::DcAddress => f.write_str("DC account has no host address"),
            ZoneProjectionError::Apex => f.write_str("naming context is not a DNS name"),
            ZoneProjectionError::Time => f.write_str("time outside the directory's range"),
            ZoneProjectionError::Image(e) => write!(f, "zone image refused: {e}"),
        }
    }
}

impl std::error::Error for ZoneProjectionError {}

impl From<Fault> for ZoneProjectionError {
    fn from(_: Fault) -> ZoneProjectionError {
        ZoneProjectionError::Unavailable
    }
}

impl From<dirstore::Error> for ZoneProjectionError {
    fn from(_: dirstore::Error) -> ZoneProjectionError {
        ZoneProjectionError::Unavailable
    }
}

/// A computer holding host addresses (or the DC account), as read by the
/// walk.
struct Holder {
    obj: Object,
    dc: bool,
}

/// The running minimum of [`ZoneProjection::valid_until`], in DSTIME
/// seconds.
#[derive(Default)]
struct Horizon(Option<i64>);

impl Horizon {
    fn at(&mut self, dstime: i64) {
        self.0 = Some(self.0.map_or(dstime, |t| t.min(dstime)));
    }
}

impl DirectoryView<'_> {
    /// The zone image of this view at `now` (module documentation).
    ///
    /// # Errors
    /// [`ZoneProjectionError`] — no image is served from a directory that
    /// cannot be projected whole (fail closed).
    ///
    /// Spec: docs/54 §4.4, §5.1-§5.4; RFC 2136 §3.6; module documentation.
    pub fn zone_projection(
        &self,
        params: &ZoneParameters,
        now: &KerberosTime,
    ) -> Result<ZoneProjection, ZoneProjectionError> {
        let now_dstime = dstime_of(now).ok_or(ZoneProjectionError::Time)?;
        let zone = self.zone_name();
        let apex = Name::from_labels(
            self.ctx
                .naming_context()
                .labels()
                .iter()
                .map(String::as_bytes),
        )
        .map_err(|_| ZoneProjectionError::Apex)?;
        let serial = self
            .snapshot
            .counter(DNS_ZONE_SERIAL_COUNTER)?
            .as_ref()
            .and_then(zone_serial)
            .ok_or(ZoneProjectionError::NoZoneSerial)?;
        let holders = self.host_holders()?;
        let mut dc = None;
        let mut hosts = Vec::new();
        let mut horizon = Horizon::default();
        for holder in holders {
            if holder.dc {
                if dc.is_some() {
                    return Err(ZoneProjectionError::DcAccount);
                }
                dc = Some(self.dc_record(&holder.obj, &zone, params)?);
            } else if let Some(host) =
                self.member_record(&holder, &zone, params, now, now_dstime, &mut horizon)?
            {
                hosts.push(host);
            }
        }
        let dc = dc.ok_or(ZoneProjectionError::DcAccount)?;
        let parts = ZoneImageParts {
            apex,
            serial,
            soa: params.soa.clone(),
            infrastructure_ttl: params.infrastructure_ttl,
            dc,
            hosts,
            kpasswd: params.kpasswd,
        };
        let image = ZoneImage::new(parts.clone()).map_err(ZoneProjectionError::Image)?;
        let valid_until = match horizon.0 {
            None => None,
            Some(t) => Some(time_of_dstime(t).ok_or(ZoneProjectionError::Time)?),
        };
        Ok(ZoneProjection {
            image,
            parts,
            valid_until,
        })
    }

    /// Every computer of the naming context that holds host addresses, and
    /// every DC account (ST) whether it does or not: a breadth-first walk
    /// from the NC root over the children pages, bounded by
    /// [`MAX_ZONE_WALK_OBJECTS`] objects and `MAX_DN_DEPTH` levels.
    /// Spec: docs/54 §4.4; dirstore `Snapshot::children` (bounded paging);
    /// AGENTS.md §6 (bounded work).
    fn host_holders(&self) -> Result<Vec<Holder>, ZoneProjectionError> {
        let ids = self.ctx.ids;
        let root = self.nc_root()?;
        let mut queue: VecDeque<(Guid, usize)> = VecDeque::from([(root, 0)]);
        let mut read = 0usize;
        let mut holders = Vec::new();
        while let Some((guid, depth)) = queue.pop_front() {
            read += 1;
            if read > MAX_ZONE_WALK_OBJECTS {
                return Err(ZoneProjectionError::TooLarge);
            }
            let obj = self
                .snapshot
                .get_object(guid)?
                .ok_or(ZoneProjectionError::Unavailable)?;
            if self.most_specific_class(&obj)? == ids.computer {
                let account = self.account(&obj)?.ok_or(Fault::Unavailable)?;
                let dc = state::is_dc_account(account.uac);
                if dc || obj.attribute(HOST_ADDRESS).is_some() {
                    holders.push(Holder { obj, dc });
                }
            }
            let mut cursor: Option<ChildCursor> = None;
            loop {
                let page =
                    self.snapshot
                        .children(Some(guid), cursor.as_ref(), MAX_CHILDREN_PER_PAGE)?;
                if !page.children.is_empty() && depth + 1 > MAX_DN_DEPTH {
                    return Err(ZoneProjectionError::TooLarge);
                }
                for child in page.children {
                    if read + queue.len() >= MAX_ZONE_WALK_OBJECTS {
                        return Err(ZoneProjectionError::TooLarge);
                    }
                    queue.push_back((child, depth + 1));
                }
                match page.next {
                    Some(next) => cursor = Some(next),
                    None => break,
                }
            }
        }
        Ok(holders)
    }

    /// The DC's host record: its label by the host-name rule, its stored
    /// addresses as provisioned (not aged, not filtered by the registrable
    /// networks — the image itself refuses a forbidden address), the zone's
    /// host TTL.
    /// Spec: docs/54 §3.1 (the DC's A: "written in `provision domain`
    /// only"), §5.3; crate::host.
    fn dc_record(
        &self,
        obj: &Object,
        zone: &str,
        params: &ZoneParameters,
    ) -> Result<HostRecordParts, ZoneProjectionError> {
        let label = self
            .holder_label(obj, zone)?
            .ok_or(ZoneProjectionError::DcName)?;
        let addresses = stored_addresses(obj)?
            .into_iter()
            .map(|(address, _)| address)
            .collect::<Vec<_>>();
        if addresses.is_empty() {
            return Err(ZoneProjectionError::DcAddress);
        }
        Ok(HostRecordParts {
            label: label.into_bytes(),
            addresses,
            ttl: params.host_ttl,
        })
    }

    /// A member host's record, or `None` when it is not in the image: its
    /// account not usable at `now` (disabled, expired — docs/47 §4), its
    /// names not passing the host-name rule, or no address left after the
    /// age and network filters. Each kept address, and an account that will
    /// expire, moves the horizon (module documentation).
    /// Spec: docs/54 §4.4, §5.2, §5.5; docs/47 §4 (`usable_at`); Q-614
    /// items 7-8.
    fn member_record(
        &self,
        holder: &Holder,
        zone: &str,
        params: &ZoneParameters,
        now: &KerberosTime,
        now_dstime: i64,
        horizon: &mut Horizon,
    ) -> Result<Option<HostRecordParts>, ZoneProjectionError> {
        let obj = &holder.obj;
        let account = self.account(obj)?.ok_or(Fault::Unavailable)?;
        let account_state = self.state_of(obj, &account)?;
        if !account_state.usable_at(now) {
            return Ok(None);
        }
        let Some(label) = self.holder_label(obj, zone)? else {
            return Ok(None);
        };
        let max_age = i64::try_from(params.max_record_age).unwrap_or(i64::MAX);
        let mut kept = Vec::new();
        let mut ages = Horizon::default();
        for (address, registered) in stored_addresses(obj)? {
            // Registered at `registered` (DSTIME); out of the image from
            // `registered + max_age` on.
            let expires = registered.saturating_add(max_age);
            if now_dstime < expires && registrable(address, &params.registrable_networks) {
                kept.push(address);
                ages.at(expires);
            }
        }
        if kept.is_empty() {
            return Ok(None);
        }
        if let Some(t) = ages.0 {
            horizon.at(t);
        }
        if let Some(expires) = account_state.expires {
            horizon.at(dstime_of(&expires).ok_or(ZoneProjectionError::Time)?);
        }
        Ok(Some(HostRecordParts {
            label: label.into_bytes(),
            addresses: kept,
            ttl: params.host_ttl,
        }))
    }

    /// The host label of a computer holding host addresses (crate::host
    /// `host_label` over its stored sAMAccountName and dNSHostName).
    fn holder_label(&self, obj: &Object, zone: &str) -> Result<Option<String>, Fault> {
        let ids = self.ctx.ids;
        let sam = record::text(obj, ids.sam_account_name)?.ok_or(Fault::Unavailable)?;
        let Some(dns_host_name) = record::text(obj, ids.dns_host_name)? else {
            return Ok(None);
        };
        Ok(host_label(sam, dns_host_name, zone).map(str::to_owned))
    }
}

/// The stored host addresses of `obj` with each value's registration time
/// (its attr-stamp's wall clock — DSTIME seconds, the one unit every writer
/// of the store uses: crates/directory-admin `wall_clock` = this crate's
/// `dstime_of`). A value that is not four octets, or a wall clock outside
/// the DSTIME range, is an inconsistent record.
/// Spec: crate::host (module documentation); RFC 1035 §3.4.1; dirstore
/// `AttrStamp::wall_clock`; docs/questions/Q-991 item 5.
fn stored_addresses(obj: &Object) -> Result<Vec<(Ipv4Addr, i64)>, Fault> {
    let Some(attribute) = obj.attribute(HOST_ADDRESS) else {
        return Ok(Vec::new());
    };
    attribute
        .values
        .iter()
        .map(|v| {
            let address = host_address_of(&v.value).ok_or(Fault::Unavailable)?;
            let registered = i64::try_from(v.stamp.wall_clock.0).map_err(|_| Fault::Unavailable)?;
            Ok((address, registered))
        })
        .collect()
}
