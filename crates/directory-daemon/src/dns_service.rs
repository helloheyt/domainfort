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
//! # The SERIAL and the clock (docs/questions/Q-993 item 3, Q-1002; A-170, A-172)
//!
//! Every write that changes the zone takes the zone serial in its own
//! transaction (crate directory-admin, the one commit — A-170). What no
//! write changes is the clock — a member host's address reaching
//! `dns_record_max_age`, an account reaching accountExpires — and dird's
//! own zone configuration across a restart. For both, dird advances the
//! serial **through the same one checker** (task DN10b: directory-admin
//! `ZoneSerialWriter` — the serial-only `Op`, its `ZoneSerial` decision
//! acknowledged by auditd before the write, its outcome after; one writer of
//! the counter):
//!
//! * **at every start of the DNS service** (cause `ServiceStart`), before
//!   the first image is served: every image of this process then has a
//!   SERIAL after every SERIAL an earlier process served, whatever changed
//!   in dird's file (Q-1002 item 4 (b); docs/54 §5.4). A start whose advance
//!   fails does not serve (fail closed — [`DnsNotStarted::SerialAdvance`]).
//! * **when the content under the current SERIAL changed with the clock**
//!   (cause `ContentAged`). This host keeps, for the SERIAL it last
//!   projected, the interval of dird's clock over which that SERIAL's
//!   content is known constant: from the earliest instant it was projected
//!   at (`known_from`) to the first projection's
//!   [`ZoneProjection::valid_until`] (`holds_until`). The projection only
//!   loses members as time moves forward (addresses age out, accounts
//!   expire; nothing enters without a write), so a fetch at `now` sees the
//!   same content iff `now` lies in that interval — or `now` lies before it
//!   (dird's clock went back) and the projection at `now` changes nothing
//!   until `known_from` (its own `valid_until` is after it), which widens the
//!   interval. Otherwise the content changed under one SERIAL: an
//!   `Unchanged` would confirm a stale image and a new image under it would
//!   give one SERIAL two contents (RFC 2136 §3.6: "If the zone appears to
//!   change, the SOA must appear to change as well") — so the serial is
//!   advanced and the zone projected again.
//!
//! **The bound (a clock jump must not turn into a write storm).** A clock
//! that jumps forward collapses every ageing into one advance; one that
//! flaps back and forth could ask for an advance at each swing. So a
//! `ContentAged` advance is attempted at most once per
//! [`MIN_SERIAL_ADVANCE_INTERVAL`], measured on the monotonic clock (which
//! no wall-clock jump moves); a fetch that needs one sooner is refused
//! `Unavailable` (fail closed: neither a stale confirmation nor a second
//! content under one SERIAL), counted on stderr. The interval is short
//! enough that dnsd — which re-checks every 5 s and goes stale only after
//! `zone_image_max_age` (at least 30 s) — never reaches its staleness bound
//! because of it (pinned at compile time below). RFC 2136 §7.10 allows the
//! deferral ("so that serial numbers can be conserved"). Every clock-driven
//! attempt that reaches the audit gate counts, so a failing advance does not
//! retry faster either; the start's advance (once per process, not the
//! clock) does not count.
//!
//! Spec: docs/54 §4.3, §4.4, §4.6, §4.8, §5.4, §6.6; RFC 2136 §3.6, §7.10,
//! §7.11; docs/50 R50-3, R50-7, §3.2; docs/51 §5.7 item 2; A-85; A-114;
//! A-119; A-152; A-170; A-172; docs/questions/Q-619 item 5, Q-993, Q-1000,
//! Q-1002, Q-1013, Q-1015.
//!
//! Written only from this project's decided design and the allowed
//! specifications, opened in this session: docs/CLEAN-ROOM.md; docs/54
//! (§1–§6, §10); docs/50 (§2.4, §3.1–§3.7, §7.5, §8); PENDING-OWNER (A-119,
//! A-152, A-157, A-160, A-163, A-170); docs/questions Q-619, Q-973,
//! Q-991..Q-994; the pinned RFC 1035 (§2.3.4, §3.2.1, §3.3.13, §5.3, §8) and
//! RFC 2136 (§3.6, §7.11) — SHA-256 verified against
//! tools/spec-pin/manifest.json; and this repository's own code (crates
//! ipc-dns, ipc-dns-server, directory-pip, dns-zone; this crate's kpasswd
//! service as the pattern). The serial advance (task DN10b) was written
//! only from, opened in this session: docs/questions Q-962, Q-991..Q-994,
//! Q-1000..Q-1004, PENDING-OWNER (A-85, A-119, A-160, A-163, A-167, A-170,
//! A-172), docs/54 (§3.1, §4.4–§4.8, §5, §9, §10), docs/50 §8, the pinned
//! RFC 2136 §3.6, §7.10, §7.11, and this crate's admin thread as the
//! pattern of an acknowledged decision. No other implementation was
//! consulted or recalled (docs/CLEAN-ROOM.md).

use crate::clock::SharedClock;
use crate::ldap_audit::AuditGate;
use crate::log::{note, Note, Thinned};
use crate::operation_ids::OperationIds;
use core::fmt;
use core::time::Duration;
use directory_admin::ZoneSerialWriter;
use directory_pip::{
    DirectoryContext, TierMap, ZoneParameters, ZoneProjection, ZoneProjectionError,
};
use dirstore::Store;
use ipc_audit::{Reservation, ZoneSerialCause, ZoneSerialEvent, ZoneSerialFailure};
use ipc_dns::{ForwardRequest, Forwarded, FrontZone, ImageTransfer, Serial};
use ipc_dns_server::{ImageAnswer, Unserved, ZoneHost};
use krb_proto::KerberosTime;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

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

/// Largest DNS queue accepted. Project bound (docs/CLEAN-ROOM.md).
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
/// changed with the clock and the previous advance is too recent (thinned).
static SERIAL_ADVANCE_DEFERRED: Thinned = Thinned::new(Note::DnsSerialAdvanceDeferred);

/// The least time between two serial advances for the clock (`ContentAged`
/// — module documentation, "The bound"), on the monotonic clock. Project
/// choice (docs/54 gives none; docs/questions/Q-1015 item 3): one advance at
/// most per 10 s, so a flapping wall clock costs at most one counter take
/// and two audit events per 10 s, while a refusal it causes never outlasts
/// dnsd's staleness floor (below).
/// Spec: RFC 2136 §7.10 (deferral, serial numbers conserved); docs/54 §4.4.
pub const MIN_SERIAL_ADVANCE_INTERVAL: Duration = Duration::from_secs(10);

/// dnsd's periodic SERIAL check (docs/54 §4.4 (b): "every 5 s"; crates/
/// dns-daemon `REFRESH_INTERVAL`, not linked here).
const DNSD_REFRESH_SECS: u64 = 5;

// A deferred advance refuses dnsd's fetches for at most the interval, and
// dnsd's next check comes within one refresh interval after it: together
// under dnsd's staleness floor (crate config `ZONE_IMAGE_MAX_AGE_SECS.min`,
// 30 s — docs/54 §4.4, Q-616 item 6), so the bound alone never makes dnsd
// answer SERVFAIL.
const _: () = assert!(
    MIN_SERIAL_ADVANCE_INTERVAL.as_secs() + DNSD_REFRESH_SECS
        < config::ZONE_IMAGE_MAX_AGE_SECS.min as u64
);

/// How long the DNS thread waits for auditd to acknowledge a serial
/// advance's decision event: the wait of every dird decision
/// (`DECISION_ACK_DEADLINE`, 2 s — A-85), within dnsd's channel deadline
/// (crate ipc-dns `DEFAULT_DEADLINE`, 20 s) for the fetch that triggers it.
/// Spec: docs/51 §5.7 item 2; docs/50 §3.6 (bounded waits).
const SERIAL_ACK_DEADLINE: Duration = crate::admin_service::DECISION_ACK_DEADLINE;
const _: () = assert!(SERIAL_ACK_DEADLINE.as_secs() * 4 <= ipc_dns::DEFAULT_DEADLINE.as_secs());

/// Why a serial advance did not happen (logged with [`Self::code`]).
/// Spec: module documentation; docs/questions/Q-1015.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerialAdvanceStop {
    /// No audit slot: auditd unreachable or the window full — nothing was
    /// decided (A-57: "no unaudited state change").
    AuditUnavailable,
    /// The previous `ContentAged` advance was less than
    /// [`MIN_SERIAL_ADVANCE_INTERVAL`] ago.
    Deferred,
    /// dird's clock gave no time.
    Clock,
    /// The decided write did not happen (its outcome event says why).
    Failed(ZoneSerialFailure),
}

impl SerialAdvanceStop {
    /// A numeric code for the fixed log notes (docs/50 §8.2): 1..=3, and
    /// 10 + the failure's audit code.
    #[must_use]
    pub const fn code(self) -> u64 {
        match self {
            SerialAdvanceStop::AuditUnavailable => 1,
            SerialAdvanceStop::Deferred => 2,
            SerialAdvanceStop::Clock => 3,
            SerialAdvanceStop::Failed(failure) => 10 + failure.code() as u64,
        }
    }
}

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
    /// The least time between two `ContentAged` serial advances
    /// ([`MIN_SERIAL_ADVANCE_INTERVAL`]).
    pub min_serial_advance_interval: Duration,
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
            min_serial_advance_interval: MIN_SERIAL_ADVANCE_INTERVAL,
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
    /// The start's serial advance (task DN10b; module documentation) did
    /// not happen: serving now could show the zone values of this process
    /// under a SERIAL an earlier one served (fail closed).
    SerialAdvance(SerialAdvanceStop),
}

impl DnsNotStarted {
    /// A numeric code for the fixed log note (docs/50 §8.2): 1..=5 for the
    /// five reasons, 10 + the projection's own code for a zone that cannot
    /// be projected, 200 + the stop's code for the start's serial advance.
    #[must_use]
    pub const fn code(self) -> u64 {
        match self {
            DnsNotStarted::Configuration => 1,
            DnsNotStarted::DirectoryUnreadable => 2,
            DnsNotStarted::Bind => 3,
            DnsNotStarted::Spawn => 4,
            DnsNotStarted::Clock => 5,
            DnsNotStarted::Zone(error) => 10 + projection_code(error),
            DnsNotStarted::SerialAdvance(stop) => 200 + stop.code(),
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
            DnsNotStarted::SerialAdvance(stop) => {
                write!(
                    f,
                    "zone serial not advanced at start (code {})",
                    stop.code()
                )
            }
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

/// The content dird last projected: its SERIAL and the interval of dird's
/// clock over which the content under that SERIAL is known constant —
/// `[known_from, holds_until)` (module documentation, "The SERIAL and the
/// clock").
/// Spec: docs/questions/Q-993 item 3 (A-170), Q-1015 item 1; crate
/// directory-pip `ZoneProjection::valid_until`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Projected {
    serial: Serial,
    known_from: KerberosTime,
    holds_until: Option<KerberosTime>,
}

impl Projected {
    /// Whether the content projected at `now` (`projection`, of this
    /// record's SERIAL) differs from this SERIAL's known content: `now` at or
    /// past `holds_until` (something aged out), or before `known_from` with
    /// a change between the two (the projection at `now` changes at or
    /// before `known_from`). The projection only loses members as time
    /// moves forward, so inside the interval nothing changed.
    /// Spec: module documentation; RFC 2136 §3.6.
    fn changed_at(&self, projection: &ZoneProjection, now: KerberosTime) -> bool {
        if self.holds_until.is_some_and(|until| now >= until) {
            return true;
        }
        now < self.known_from
            && projection
                .valid_until()
                .is_some_and(|until| until <= self.known_from)
    }
}

/// How the DNS thread advances the zone's SERIAL (task DN10b): the door of
/// the serial-only write (directory-admin `ZoneSerialWriter`), dird's audit
/// gate (the decision acknowledged before the write — A-85), dird's one
/// counter of operation numbers, the bound and the instant of the last
/// attempt (monotonic).
/// Spec: module documentation; docs/questions/Q-1002 item 4, Q-1015.
pub(crate) struct SerialAdvance {
    /// The serial-only write's door.
    pub(crate) writer: ZoneSerialWriter,
    /// dird's audit gate (one window for every dird event — A-85).
    pub(crate) gate: Arc<AuditGate>,
    /// dird's one counter of operation numbers (crate::operation_ids).
    pub(crate) ids: Arc<OperationIds>,
    /// [`MIN_SERIAL_ADVANCE_INTERVAL`] (a test seam may shorten it).
    pub(crate) min_interval: Duration,
    /// When the last `ContentAged` advance was attempted (it reached the
    /// audit gate).
    last: Option<Instant>,
}

impl SerialAdvance {
    /// No advance attempted yet.
    pub(crate) fn new(
        writer: ZoneSerialWriter,
        gate: Arc<AuditGate>,
        ids: Arc<OperationIds>,
        min_interval: Duration,
    ) -> SerialAdvance {
        SerialAdvance {
            writer,
            gate,
            ids,
            min_interval,
            last: None,
        }
    }
}

/// What the DNS thread owns: the store (shared; read by the projection,
/// written only through the serial-only checked write), the context and
/// tier map of its views, the zone values, dird's clock, the serial
/// advance, and the content it last projected.
/// Spec: docs/54 §4.4; docs/50 R50-7; docs/questions/Q-1002.
pub(crate) struct DnsWorker {
    /// The store (shared).
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
    /// The serial advance (task DN10b).
    advance: SerialAdvance,
    /// The SERIAL last projected and the interval its content is known for.
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
        advance: SerialAdvance,
    ) -> DnsWorker {
        DnsWorker {
            store,
            ctx,
            tiers,
            zone,
            clock,
            advance,
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

    /// The start of the DNS service (module documentation): the zone must
    /// project (a zone that cannot is no service — nothing is written for
    /// it); then the serial advance of the start (`ServiceStart`); then the
    /// first projection under the new SERIAL, remembered. Returns that
    /// SERIAL. Runs on the DNS thread, before any request (the decision's
    /// acknowledgement is awaited there, never on the runtime).
    ///
    /// # Errors
    /// [`DnsNotStarted`] — nothing is served.
    ///
    /// Spec: docs/54 §4.8 (serve only after the first image), §5.4;
    /// docs/questions/Q-1002 item 4 (b) (A-172).
    pub(crate) fn start(&mut self) -> Result<u32, DnsNotStarted> {
        self.project()?;
        self.advance_serial(ZoneSerialCause::ServiceStart)
            .map_err(DnsNotStarted::SerialAdvance)?;
        let (projection, now) = self.project()?;
        let serial = Serial::new(projection.image().serial())
            .ok_or(DnsNotStarted::Zone(ZoneProjectionError::NoZoneSerial))?;
        self.remember(serial, &projection, now);
        Ok(serial.get())
    }

    /// Remember that `projection` (SERIAL `serial`) was served at `now`: a
    /// new SERIAL starts a new interval `[now, valid_until)`; the same SERIAL
    /// widens `known_from` back to `now` (the caller checked nothing changed
    /// in between — [`Projected::changed_at`]).
    /// Spec: module documentation.
    fn remember(&mut self, serial: Serial, projection: &ZoneProjection, now: KerberosTime) {
        self.projected = Some(match self.projected {
            Some(last) if last.serial == serial => Projected {
                known_from: if now < last.known_from {
                    now
                } else {
                    last.known_from
                },
                ..last
            },
            _ => Projected {
                serial,
                known_from: now,
                holds_until: projection.valid_until(),
            },
        });
    }

    /// Advance the zone's SERIAL through the one checker (module
    /// documentation; directory-admin `ZoneSerialWriter`): the bound (for
    /// `ContentAged`), two audit slots (the decision and the outcome —
    /// none ⇒ nothing decided), the transaction first, the decision,
    /// auditd's acknowledgement within [`SERIAL_ACK_DEADLINE`], the
    /// serial-only write, the commit, the outcome event. Returns the new
    /// SERIAL (`None`: another write had advanced it already).
    ///
    /// # Errors
    /// [`SerialAdvanceStop`]; nothing was written.
    ///
    /// Spec: docs/51 §5.7 item 2 ("decision acknowledged ⇒ commit ⇒
    /// outcome"); docs/52 §3.11 R6; A-57; A-85; RFC 2136 §3.6, §7.10;
    /// docs/questions/Q-1002 item 4, Q-1015.
    fn advance_serial(&mut self, cause: ZoneSerialCause) -> Result<Option<u32>, SerialAdvanceStop> {
        let attempt = Instant::now();
        if cause == ZoneSerialCause::ContentAged
            && self
                .advance
                .last
                .is_some_and(|last| attempt.duration_since(last) < self.advance.min_interval)
        {
            return Err(SerialAdvanceStop::Deferred);
        }
        let now = self.clock.now().ok_or(SerialAdvanceStop::Clock)?;
        let gate = Arc::clone(&self.advance.gate);
        let mut slots = gate
            .admit_slots(2)
            .ok_or(SerialAdvanceStop::AuditUnavailable)?
            .into_iter();
        let (Some(decision_slot), Some(outcome_slot)) = (slots.next(), slots.next()) else {
            return Err(SerialAdvanceStop::Failed(
                ZoneSerialFailure::InternalFailure,
            ));
        };
        // From here on a clock-driven attempt counts for the bound, whatever
        // its end. The start's advance (once per process) does not: it is
        // not the clock, and a content ageing just after a start is served
        // at once.
        if cause == ZoneSerialCause::ContentAged {
            self.advance.last = Some(attempt);
        }
        let failed = |failure| SerialAdvanceStop::Failed(failure);
        let mut txn = match self.store.begin_write() {
            Ok(txn) => txn,
            Err(_) => {
                gate.release(decision_slot);
                gate.release(outcome_slot);
                return Err(failed(ZoneSerialFailure::StoreFailure));
            }
        };
        let operation_id = self.advance.ids.next();
        let prepared = match self.advance.writer.prepare(&txn, operation_id, cause, &now) {
            Ok(prepared) => prepared,
            Err(failure) => {
                drop(txn);
                gate.release(decision_slot);
                gate.release(outcome_slot);
                return Err(failed(failure));
            }
        };
        let pending = match gate.begin_intent(decision_slot, prepared) {
            Ok(pending) => pending,
            Err(_) => {
                drop(txn);
                gate.release(outcome_slot);
                return Err(failed(ZoneSerialFailure::InternalFailure));
            }
        };
        let acked = match gate.wait_acknowledged(pending, Instant::now() + SERIAL_ACK_DEADLINE) {
            Ok(acked) => acked,
            Err(prepared) => {
                drop(txn);
                let failure = ZoneSerialFailure::AuditUnacknowledged;
                record_outcome(&gate, outcome_slot, &prepared.failure_event(failure, &now));
                return Err(failed(failure));
            }
        };
        match self.advance.writer.apply(acked, &mut txn, &now) {
            Err(not_written) => {
                drop(txn);
                record_outcome(&gate, outcome_slot, not_written.event());
                Err(failed(not_written.failure()))
            }
            Ok(applied) => match txn.commit() {
                Ok(()) => {
                    record_outcome(&gate, outcome_slot, applied.outcome_event());
                    let serial = applied.serial().map(core::num::NonZeroU32::get);
                    if let Some(serial) = serial {
                        note(Note::DnsSerialAdvanced, Some(u64::from(serial)));
                    }
                    Ok(serial)
                }
                Err(_) => {
                    record_outcome(&gate, outcome_slot, applied.commit_failure_event());
                    Err(failed(ZoneSerialFailure::StoreFailure))
                }
            },
        }
    }
}

/// Put a serial advance's outcome event into its reserved slot; one that
/// cannot be committed is counted for the next `WindowSummary`
/// (`unrecorded_outcomes`, A-88) — the log then holds the decision without
/// its outcome, and says so.
/// Spec: docs/51 §5.7 item 2; A-88 (Q-366 option (a)).
fn record_outcome(gate: &AuditGate, slot: Reservation, event: &ZoneSerialEvent) {
    if gate.commit_zone_serial(slot, event).is_err() {
        gate.count_unrecorded_outcome();
    }
}

impl ZoneHost for DnsWorker {
    /// The zone image, or `Unchanged` when `have` is its SERIAL (module
    /// documentation, "What it serves" and "The SERIAL and the clock"): a
    /// content that changed with the clock under the current SERIAL first
    /// has the serial advanced through the one checker (bounded), then is
    /// projected again; an advance that does not happen refuses the fetch
    /// (fail closed).
    /// Spec: docs/54 §4.4, §4.6; RFC 2136 §3.6, §7.10; docs/questions/Q-993
    /// item 3 (A-170), Q-1002 (A-172), Q-1015.
    fn zone_image(&mut self, have: Option<Serial>) -> Result<ImageAnswer, Unserved> {
        let (mut projection, mut now) = match self.project() {
            Ok(projected) => projected,
            Err(reason) => {
                zone_unavailable(reason.code());
                return Err(Unserved::Unavailable);
            }
        };
        // SERIAL is never 0 in a projected image (RFC 2136 §7.11; crate
        // dns-zone refuses one) — fail closed if it were.
        let mut serial = Serial::new(projection.image().serial()).ok_or(Unserved::Unavailable)?;
        let changed = self
            .projected
            .is_some_and(|last| last.serial == serial && last.changed_at(&projection, now));
        if changed {
            // The clock changed the content under this SERIAL (Q-993 item
            // 3): advance it through the one checker, then project again.
            match self.advance_serial(ZoneSerialCause::ContentAged) {
                Ok(_) => {}
                Err(SerialAdvanceStop::Deferred) => {
                    SERIAL_ADVANCE_DEFERRED.hit(None);
                    return Err(Unserved::Unavailable);
                }
                Err(stop) => {
                    serial_advance_failed(stop.code());
                    return Err(Unserved::Unavailable);
                }
            }
            (projection, now) = match self.project() {
                Ok(projected) => projected,
                Err(reason) => {
                    zone_unavailable(reason.code());
                    return Err(Unserved::Unavailable);
                }
            };
            serial = Serial::new(projection.image().serial()).ok_or(Unserved::Unavailable)?;
            // The counter moved (this advance, or another write's): a new
            // SERIAL, a new interval. Anything else is not served.
            if self.projected.is_some_and(|last| last.serial == serial) {
                serial_advance_failed(
                    SerialAdvanceStop::Failed(ZoneSerialFailure::InternalFailure).code(),
                );
                return Err(Unserved::Unavailable);
            }
        }
        self.remember(serial, &projection, now);
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

/// Serial advances that did not happen (counted for the thinned note
/// below).
static SERIAL_ADVANCE_FAILED: AtomicU64 = AtomicU64::new(0);

/// Note a fetch refused because its serial advance did not happen, with the
/// stop's code — thinned (1st, 2nd, 4th, 8th … event), as every note dnsd's
/// fetches can trigger (crate::log, docs/07 §8).
/// Spec: docs/50 §8.2; docs/07 §8.
fn serial_advance_failed(code: u64) {
    let count = SERIAL_ADVANCE_FAILED
        .fetch_add(1, Ordering::Relaxed)
        .saturating_add(1);
    if count.is_power_of_two() {
        note(Note::DnsSerialAdvanceFailed, Some(code));
    }
}

/// Fetches refused because the serial advance their content needed was
/// deferred by the bound (the tests' view of the stderr counter).
#[must_use]
pub fn dns_serial_advance_deferred_count() -> u64 {
    SERIAL_ADVANCE_DEFERRED.count()
}

/// `Forward` requests refused so far (the tests' view of the stderr
/// counter).
#[must_use]
pub fn dns_forward_refused_count() -> u64 {
    FORWARD_REFUSED.count()
}
