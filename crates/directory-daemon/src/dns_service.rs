//! dird's DNS service (task DN10a; docs/54 §4.3–§4.6): its parameters and
//! the host of the dnsd ↔ dird channel's dispatcher — dird's answer to
//! `FetchZoneImage`, from its one zone projection over one snapshot.
//!
//! # What it serves (docs/54 §4.4, §4.6)
//!
//! `dird-dns.sock` admits dnsd's uid only (`dnsd_uid`, docs/50 R50-3); the
//! connection's zone is fixed from that uid before any frame is read
//! (crate ipc-dns-server `DnsFronts`, A-114 — dird holds no zone table).
//! Each request is decoded and answered by the channel's own dispatcher
//! (`DnsConnection::handle`) on the DNS thread (crate::dns_engine), whose
//! host is [`DnsWorker`] here:
//!
//! * `Ping` ⇒ `Pong { zone }` (the dispatcher);
//! * `FetchZoneImage { have }` ⇒ the zone image of
//!   `DirectoryView::zone_projection` (crate directory-pip — the one function
//!   from the directory to the image, A-111 scan rule 3) at dird's clock,
//!   over one fresh snapshot: `Unchanged` when `have` is its SERIAL, the
//!   image's chunks otherwise (crate ipc-dns `ImageTransfer`, built only
//!   from parts `ZoneImage::new` accepts);
//! * `Forward` (a signed UPDATE; with task DN9 a TKEY) ⇒ **refused** with the
//!   channel's shared refusal `Unavailable` — the DNS PEP (tasks DN8/DN9,
//!   blocked on owner items: RFC 2930 / P-13, keyd's GSS capability Q-612)
//!   does not exist in this build, so there is **no code path that reads a
//!   forwarded message**: [`DnsWorker::forward`] never looks at it. dnsd
//!   answers its client SERVFAIL (docs/54 §6.6: "dird not available ⇒
//!   SERVFAIL").
//!
//! # The SERIAL and the clock (docs/questions/Q-993 item 3, A-170)
//!
//! Every write that changes the zone takes the zone serial in its own
//! transaction (crate directory-admin, the one commit — A-170). What no
//! write changes is the clock: a member host's address reaching
//! `dns_record_max_age`, an account reaching accountExpires. The projection
//! names the instant ([`ZoneProjection::valid_until`]); this host keeps, for
//! the SERIAL it last projected, the instant its content holds until (the
//! first projection's `valid_until` under that SERIAL — later projections
//! under the same SERIAL before it are equal). Past it, the content under
//! that SERIAL has changed with no write: an `Unchanged` would confirm a
//! stale image and a new image under the same SERIAL would give one SERIAL
//! two contents (RFC 2136 §3.6: "If the zone appears to change, the SOA must
//! appear to change as well"). A-170 decided the fix: dird advances the
//! serial **through the same one checker** and projects again. That checked
//! write — a serial-only `Op` with its own audit decision (Q-993 item 3) —
//! is a change to crate directory-admin (and an audit shape, Q-962) outside
//! this task's files: docs/questions/Q-1002. Until it exists the host
//! **fails closed** there: `Unavailable`, so dnsd keeps its image until its
//! staleness bound and then answers SERVFAIL (docs/54 §4.4). In a product
//! build of today no member host can hold an address (the DNS PEP is not
//! built), so `valid_until` is always `None` and the branch is not reached.
//!
//! Spec: docs/54 §4.3, §4.4, §4.6, §4.8, §6.6; RFC 2136 §3.6, §7.11;
//! docs/50 R50-3, R50-7, §3.2; A-114; A-119; A-152; A-170; docs/questions/
//! Q-619 item 5, Q-993, Q-1000, Q-1002.
//!
//! Written only from this project's decided design and the allowed
//! specifications, opened in this session: AGENT-ONBOARDING, AGENTS; docs/54
//! (§1–§6, §10); docs/50 (§2.4, §3.1–§3.7, §7.5, §8); PENDING-OWNER (A-119,
//! A-152, A-157, A-160, A-163, A-170); docs/questions Q-619, Q-973,
//! Q-991..Q-994; the pinned RFC 1035 (§2.3.4, §3.2.1, §3.3.13, §5.3, §8) and
//! RFC 2136 (§3.6, §7.11) — SHA-256 verified against
//! tools/spec-pin/manifest.json; and this repository's own code (crates
//! ipc-dns, ipc-dns-server, directory-pip, dns-zone; this crate's kpasswd
//! service as the pattern). No other implementation was consulted or
//! recalled (AGENTS.md §1-3).

use crate::clock::SharedClock;
use crate::log::{note, Note, Thinned};
use core::fmt;
use directory_pip::{
    DirectoryContext, TierMap, ZoneParameters, ZoneProjection, ZoneProjectionError,
};
use dirstore::Store;
use ipc_dns::{ForwardRequest, Forwarded, FrontZone, ImageTransfer, Serial};
use ipc_dns_server::{ImageAnswer, Unserved, ZoneHost};
use krb_proto::KerberosTime;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Connections dnsd may hold open at once on `dird-dns.sock`: the channel's
/// own bound (crate ipc-dns `MAX_DNSD_CONNECTIONS`, docs/54 §4.6: "≤ 4
/// connections from dnsd"), so dnsd within its bound never meets dird's.
/// Spec: docs/54 §4.6.
pub const MAX_DNS_CONNECTIONS: usize = ipc_dns::MAX_DNSD_CONNECTIONS;

/// Requests the DNS thread's queue holds before a request is answered
/// `Busy`: one per connection dnsd may hold. The channel is strictly
/// request → reply, one request in flight per connection (docs/54 §4.6), so
/// a dnsd within its connection bound never fills it; a flood on dnsd's
/// sockets never reaches this queue at all (dnsd answers queries from its
/// image — docs/54 §4.4). Project choice (docs/54 §4.6 gives a bounded queue,
/// no number; docs/questions/Q-1000 item 6).
pub const DNS_QUEUE_CAPACITY: usize = MAX_DNS_CONNECTIONS;

/// Largest DNS queue accepted. Project bound (AGENTS.md §6).
pub const MAX_DNS_QUEUE_CAPACITY: usize = 16;

// One request in flight per connection: the queue holds every connection's.
const _: () = assert!(DNS_QUEUE_CAPACITY >= MAX_DNS_CONNECTIONS);
const _: () = assert!(DNS_QUEUE_CAPACITY <= MAX_DNS_QUEUE_CAPACITY);
// dird's configuration bounds every zone time value (TTLs, MINIMUM, the
// SOA's intervals) by the zone image's own TTL bound: a configured value the
// image would refuse cannot be parsed (crates/config is a leaf and cannot
// see crates/dns-zone, so the pin is here).
const _: () = assert!(config::limits::DNS_TIME_SECS.max == dns_zone::limits::MAX_TTL);

/// The log code of an image the channel could not encode (cannot happen:
/// the projection's parts already passed `ZoneImage::new`, and the worst
/// case fits the transfer bound — crate ipc-dns). Spec: docs/50 §8.2.
const IMAGE_ENCODING_CODE: u64 = 98;

/// `Forward` requests refused (thinned log): the DNS PEP is not built.
static FORWARD_REFUSED: Thinned = Thinned::new(Note::DnsForwardRefused);
/// Image fetches refused because the content under the current SERIAL has
/// changed with the clock and the serial cannot yet be advanced (thinned).
static SERIAL_ADVANCE_NEEDED: Thinned = Thinned::new(Note::DnsSerialAdvanceNeeded);

/// What dird's configuration sets for the DNS service — **and nothing
/// else** (docs/52 C18): `dird_dns_socket`, `dnsd_uid` and the zone values
/// (crate config `DnsServiceSettings`, built by `startup::dns_params`). The
/// connection and queue bounds are the daemon's constants
/// ([`MAX_DNS_CONNECTIONS`], [`DNS_QUEUE_CAPACITY`]).
/// Spec: docs/54 §4.6; docs/questions/Q-619 item 5, Q-1001.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsParams {
    /// `dird_dns_socket`.
    pub socket: PathBuf,
    /// `dnsd_uid`: the only peer admitted (docs/54 §4.6; docs/50 R50-3).
    pub dnsd_uid: u32,
    /// The zone values of the image (SOA fields, TTLs, the `_kpasswd`
    /// switch, `dns_record_max_age`, `dns_registrable_networks`).
    pub zone: ZoneParameters,
}

/// Everything the DNS service runs with: the product [`DnsParams`] plus the
/// seams. Built for a product dird only by [`DnsServeParams::production`].
/// Spec: docs/54 §4.6; docs/52 C18.
#[derive(Debug, Clone)]
pub(crate) struct DnsServeParams {
    /// `dird_dns_socket`.
    pub socket: PathBuf,
    /// `dnsd_uid`.
    pub dnsd_uid: u32,
    /// The zone values.
    pub zone: ZoneParameters,
    /// Connections dnsd may hold ([`MAX_DNS_CONNECTIONS`]).
    pub max_connections: usize,
    /// The DNS queue ([`DNS_QUEUE_CAPACITY`]).
    pub queue_capacity: usize,
}

impl DnsServeParams {
    /// The product parameters with the daemon's constants.
    /// Spec: docs/54 §4.6; docs/52 C18.
    pub(crate) fn production(dns: DnsParams) -> DnsServeParams {
        DnsServeParams {
            socket: dns.socket,
            dnsd_uid: dns.dnsd_uid,
            zone: dns.zone,
            max_connections: MAX_DNS_CONNECTIONS,
            queue_capacity: DNS_QUEUE_CAPACITY,
        }
    }
}

/// Why the DNS service did not start (dird's other services run — the
/// admin and kpasswd services' precedent, docs/51 §4.6).
/// Spec: docs/54 §4.8; docs/51 §4.6.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsNotStarted {
    /// The schema, the directory context or the tier map refused the
    /// configuration.
    Configuration,
    /// The directory could not be read.
    DirectoryUnreadable,
    /// dird's clock gave no time.
    Clock,
    /// The zone cannot be projected from this directory (no DC account, no
    /// DC host address — docs/54 §3.1: "written in `provision domain`
    /// only" — no zone serial counter, …): nothing would be served.
    Zone(ZoneProjectionError),
    /// The socket could not be bound, or its path is occupied.
    Bind,
    /// The DNS thread could not be started.
    Spawn,
}

impl DnsNotStarted {
    /// A numeric code for the fixed log note (docs/50 §8.2): 1..=5 for the
    /// five reasons, 10 + the projection's own code for a zone that cannot
    /// be projected.
    #[must_use]
    pub const fn code(self) -> u64 {
        match self {
            DnsNotStarted::Configuration => 1,
            DnsNotStarted::DirectoryUnreadable => 2,
            DnsNotStarted::Bind => 3,
            DnsNotStarted::Spawn => 4,
            DnsNotStarted::Clock => 5,
            DnsNotStarted::Zone(error) => 10 + projection_code(error),
        }
    }
}

impl fmt::Display for DnsNotStarted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnsNotStarted::Configuration => f.write_str("DNS service configuration refused"),
            DnsNotStarted::DirectoryUnreadable => f.write_str("directory unreadable"),
            DnsNotStarted::Clock => f.write_str("dird's clock gave no time"),
            DnsNotStarted::Zone(error) => write!(f, "zone not projectable: {error}"),
            DnsNotStarted::Bind => f.write_str("dird-dns socket could not be bound"),
            DnsNotStarted::Spawn => f.write_str("DNS thread could not be started"),
        }
    }
}

/// A numeric code per projection error, for the fixed log notes (docs/50
/// §8.2: codes, never content). `ZoneProjectionError` is non-exhaustive: a
/// kind added later logs as 99 until it is given a code here.
/// Spec: crate directory-pip `ZoneProjectionError`; docs/50 §8.2.
#[must_use]
pub const fn projection_code(error: ZoneProjectionError) -> u64 {
    match error {
        ZoneProjectionError::Unavailable => 1,
        ZoneProjectionError::TooLarge => 2,
        ZoneProjectionError::NoZoneSerial => 3,
        ZoneProjectionError::DcAccount => 4,
        ZoneProjectionError::DcName => 5,
        ZoneProjectionError::DcAddress => 6,
        ZoneProjectionError::Apex => 7,
        ZoneProjectionError::Time => 8,
        ZoneProjectionError::Image(_) => 9,
        _ => 99,
    }
}

/// The content dird last projected: its SERIAL and the instant until which
/// the content under that SERIAL holds (module documentation, "The SERIAL
/// and the clock").
/// Spec: docs/questions/Q-993 item 3 (A-170); crate directory-pip
/// `ZoneProjection::valid_until`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Projected {
    serial: Serial,
    holds_until: Option<KerberosTime>,
}

/// What the DNS thread owns: the store (read only — this service writes
/// nothing), the context and tier map of its views, the zone values, dird's
/// clock, and the content it last projected.
/// Spec: docs/54 §4.4; docs/50 R50-7.
pub(crate) struct DnsWorker {
    /// The store (shared; only read here).
    pub(crate) store: Arc<Store>,
    /// The directory context (A-53).
    pub(crate) ctx: DirectoryContext,
    /// The tier map of the loaded policy (a view needs one; the projection
    /// reads no tier).
    pub(crate) tiers: TierMap,
    /// The zone values.
    pub(crate) zone: ZoneParameters,
    /// dird's clock.
    pub(crate) clock: SharedClock,
    /// The SERIAL last projected and its content's horizon.
    projected: Option<Projected>,
}

impl DnsWorker {
    /// A worker that has projected nothing yet.
    /// Spec: docs/54 §4.4.
    pub(crate) fn new(
        store: Arc<Store>,
        ctx: DirectoryContext,
        tiers: TierMap,
        zone: ZoneParameters,
        clock: SharedClock,
    ) -> DnsWorker {
        DnsWorker {
            store,
            ctx,
            tiers,
            zone,
            clock,
            projected: None,
        }
    }

    /// The zone projection at dird's clock, over one fresh snapshot.
    ///
    /// # Errors
    /// [`DnsNotStarted::Clock`], [`DnsNotStarted::DirectoryUnreadable`] (no
    /// snapshot), [`DnsNotStarted::Zone`].
    ///
    /// Spec: docs/54 §4.4; crate directory-pip `zone_projection`.
    pub(crate) fn project(&self) -> Result<(ZoneProjection, KerberosTime), DnsNotStarted> {
        let now = self.clock.now().ok_or(DnsNotStarted::Clock)?;
        let view = self
            .ctx
            .view(&self.store, &self.tiers)
            .map_err(|_| DnsNotStarted::DirectoryUnreadable)?;
        let projection = view
            .zone_projection(&self.zone, &now)
            .map_err(DnsNotStarted::Zone)?;
        Ok((projection, now))
    }
}

impl ZoneHost for DnsWorker {
    /// The zone image, or `Unchanged` when `have` is its SERIAL (module
    /// documentation, "What it serves" and "The SERIAL and the clock").
    /// Spec: docs/54 §4.4, §4.6; RFC 2136 §3.6; docs/questions/Q-993 item 3
    /// (A-170), Q-1002.
    fn zone_image(&mut self, have: Option<Serial>) -> Result<ImageAnswer, Unserved> {
        let (projection, now) = match self.project() {
            Ok(projected) => projected,
            Err(reason) => {
                zone_unavailable(reason.code());
                return Err(Unserved::Unavailable);
            }
        };
        // SERIAL is never 0 in a projected image (RFC 2136 §7.11; crate
        // dns-zone refuses one) — fail closed if it were.
        let serial = Serial::new(projection.image().serial()).ok_or(Unserved::Unavailable)?;
        // The horizon of the content under this SERIAL: the first
        // projection's under it (the content is the same until then).
        let holds_until = match self.projected {
            Some(last) if last.serial == serial => last.holds_until,
            _ => projection.valid_until(),
        };
        self.projected = Some(Projected {
            serial,
            holds_until,
        });
        if holds_until.is_some_and(|until| now >= until) {
            // The clock changed the content under this SERIAL (Q-993 item
            // 3). The fix decided by A-170 — advance the serial through the
            // one checker, then project again — waits on Q-1002: until
            // then, neither confirm nor send (fail closed).
            SERIAL_ADVANCE_NEEDED.hit(None);
            return Err(Unserved::Unavailable);
        }
        if have == Some(serial) {
            return Ok(ImageAnswer::Unchanged(serial));
        }
        match ImageTransfer::new(projection.parts()) {
            Ok(transfer) => Ok(ImageAnswer::Image(transfer)),
            Err(_) => {
                zone_unavailable(IMAGE_ENCODING_CODE);
                Err(Unserved::Unavailable)
            }
        }
    }

    /// Refused without reading the request (module documentation): the DNS
    /// PEP of docs/54 §4.5 / §7.5 is not built (tasks DN8, DN9).
    /// Spec: docs/54 §4.5, §6.6 ("dird not available ⇒ SERVFAIL"), §10
    /// (DN8, DN9); docs/questions/Q-1000 item 4.
    fn forward(
        &mut self,
        zone: FrontZone,
        _request: &ForwardRequest,
    ) -> Result<Forwarded, Unserved> {
        // The zone was fixed by the listener from dnsd's peer uid; phase 1
        // has one (A-114).
        match zone {
            FrontZone::Internal => {}
        }
        FORWARD_REFUSED.hit(None);
        Err(Unserved::Unavailable)
    }
}

/// Fetches refused because no image could be built (counted for the
/// thinned note below).
static ZONE_UNAVAILABLE: AtomicU64 = AtomicU64::new(0);

/// Note a fetch refused for want of an image, with the reason's code —
/// thinned like every note a peer can trigger at will (dnsd chooses how
/// often it fetches): written for the 1st, 2nd, 4th, 8th … event only
/// (crate::log, docs/07 §8).
/// Spec: docs/50 §8.2; docs/07 §8 (rate limit for the log).
fn zone_unavailable(code: u64) {
    let count = ZONE_UNAVAILABLE
        .fetch_add(1, Ordering::Relaxed)
        .saturating_add(1);
    if count.is_power_of_two() {
        note(Note::DnsZoneUnavailable, Some(code));
    }
}

/// `Forward` requests refused so far (the tests' view of the stderr
/// counter).
#[must_use]
pub fn dns_forward_refused_count() -> u64 {
    FORWARD_REFUSED.count()
}
