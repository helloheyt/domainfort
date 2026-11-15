//! dnsd's configuration file (task DN11).
//!
//! dnsd is the DNS network front (docs/54 §4.3, R54-4): it listens on UDP
//! and TCP (port 53 by RFC 1035 §4.2.1 / §4.2.2) on the configured interface
//! addresses only, answers queries from the zone image it fetches from dird
//! over `dird-dns.sock`, and hands signed UPDATE messages to dird as opaque
//! octets. It talks only to dird and auditd (docs/54 §4.7: "dnsd creates only
//! the two Unix connections").
//!
//! **No secrets and no keyd.** dnsd holds no key, no token, no GSS context,
//! and is not mapped in keyd (docs/54 §4.3, R54-4), so its file has no keyd
//! endpoint and no path to any protected key (docs/50 §7.1).
//!
//! **Internal listeners only** (docs/54 §4.7; A-114 on docs/questions/Q-469
//! (b); A-119): the zone table `internal_networks` is required, and every
//! `listen` address must lie in one of its networks (`ListenerNotInternal`)
//! — the rule and the one match (`value::is_internal`) of ldap-front's and
//! the kdc's files. dnsd also serves only sources inside the table (the
//! daemon drops every other one; crates/dns-daemon).
//!
//! **Port 53 only** (task DN10d; A-178 on docs/questions/Q-1025 item 1): the
//! zone's NS record and the SOA's MNAME name the DC as the zone's name server
//! (docs/54 §3.1), and a name server is reached on port 53 — no record
//! carries another (RFC 1035 §3.3.11, §4.2). So every `listen` address must
//! be on [`crate::StandardPort::Dns`] (`NonStandardPort`) — the rule and the
//! one port table of the kdc's, ldap-front's and kpasswd-front's advertised
//! listeners. Addresses stay configurable.
//!
//! **Not here:** `dns_registrable_networks` (docs/questions/Q-619 item 4)
//! constrains which addresses a host may register — a rule of dird's zone
//! projection and write checker (docs/54 §4.4, §5.5), not of dnsd, which
//! only serves the image dird built; the dird channel's deadline, which is
//! the channel crate's one value (`ipc_dns::DEFAULT_DEADLINE`, Q-920 item 9
//! — a second copy here would diverge, docs/52 §3.14 C14); the rate limits
//! and the forwarding queue, which are the daemon's constants (A-60 / Q-230
//! item 4 precedent). docs/questions/Q-951.
//!
//! Spec: docs/54 §3.1, §3.3, §4.3, §4.4, §4.6, §4.7, §6.7; docs/questions/
//! Q-616 items 6, 10, Q-619 item 4, Q-1025 item 1 (A-178); docs/50 R50-15,
//! §2.4, §3.6, §4.1, §7.1; RFC 1035 §3.3.11, §4.2, §4.2.1, §4.2.2.

use core::net::SocketAddr;
use core::time::Duration;

use crate::error::{Error, ErrorKind};
use crate::format::{Document, Located};
use crate::limits::Bound;
use crate::schema::{
    self, Account, Distinct, Endpoint, AUDITD_UID, AUDIT_SOCKET, DIRD_DNS_SOCKET, DIRD_UID,
    INTERNAL_NETWORKS, RUN_AS_GID, RUN_AS_UID,
};
use crate::standard_port::StandardPort;
use crate::value::{self, Network};

/// Key: the interface addresses, each served on UDP and on TCP, every one on
/// port 53 ([`crate::StandardPort::Dns`], the only port accepted).
/// Spec: RFC 1035 §4.2 ("TCP … on server port 53 … as well as datagram access
/// using UDP"); docs/54 §4.3, §4.7; docs/questions/Q-1025 item 1.
const LISTEN: &str = "listen";
/// Key: the bounded staleness of the zone image. Spec: docs/54 §4.4
/// (`zone_image_max_age`); docs/questions/Q-616 item 6.
const ZONE_IMAGE_MAX_AGE: &str = "zone_image_max_age";
/// Key: global TCP connection bound. Spec: docs/54 §6.7.
const MAX_TCP_CONNECTIONS: &str = "max_tcp_connections";
/// Key: TCP connections per source. Spec: docs/54 §6.7.
const MAX_TCP_CONNECTIONS_PER_SOURCE: &str = "max_tcp_connections_per_source";
/// Key: time for the first octet of a TCP connection. Spec: docs/54 §6.7
/// ("first byte within 5 s").
const TCP_FIRST_OCTET_TIMEOUT: &str = "tcp_first_octet_timeout";
/// Key: time for a started TCP message (its length field and the message)
/// to complete. Spec: docs/54 §6.7 ("a frame that started — within 5 s").
const TCP_FRAME_TIMEOUT: &str = "tcp_frame_timeout";
/// Key: idle time between messages on a TCP connection. Spec: docs/54 §6.7;
/// RFC 1035 §4.2.2.
const TCP_IDLE_TIMEOUT: &str = "tcp_idle_timeout";
/// Key: messages per TCP connection before it is closed. Spec: docs/54 §6.7.
const MAX_REQUESTS_PER_TCP_CONNECTION: &str = "max_requests_per_tcp_connection";

/// The zone image's maximum age: 60 s (default and ceiling), at least 30 s.
///
/// * Ceiling and default — docs/54 §4.4 ("for example 60 s ⚠"; Q-616 item
///   6), read as Q-230 item 4 reads every docs value: an operator may tighten
///   it, never loosen it.
/// * Floor — the image is confirmed by a periodic SERIAL check every 5 s
///   (docs/54 §4.4 (b)) that may take up to the dird channel's deadline
///   (20 s, crates/ipc-dns `DEFAULT_DEADLINE`, Q-920 item 9); a bound at or
///   under 25 s would make an answering but slow dird look stale. 30 s
///   leaves a margin. crates/dns-daemon asserts the floor against its own
///   refresh interval and that deadline at compile time (this crate is a
///   leaf and cannot see them).
///
/// Spec: docs/54 §4.4; docs/questions/Q-616 item 6, Q-920 item 9, Q-951.
pub const ZONE_IMAGE_MAX_AGE_SECS: Bound = Bound {
    min: 30,
    max: 60,
    default: 60,
};
/// dnsd's global TCP connection bound: at most 512.
/// Spec: docs/54 §6.7 ("≤ 512 connections in total"); Q-616 item 10.
pub const DNSD_MAX_TCP_CONNECTIONS_BOUND: Bound = Bound::up_to(512);
/// dnsd's TCP connections per source: at most 8, never above the global
/// bound. Spec: docs/54 §6.7 ("≤ 8 per source"); Q-616 item 10.
pub const DNSD_MAX_TCP_CONNECTIONS_PER_SOURCE_BOUND: Bound = Bound::up_to(8);
/// The first octet of a dnsd TCP connection: within 5 s.
/// Spec: docs/54 §6.7 ("first byte within 5 s"); Q-616 item 10.
pub const DNSD_TCP_FIRST_OCTET_TIMEOUT_SECS: Bound = Bound::up_to(5);
/// A started dnsd TCP message: within 5 s.
/// Spec: docs/54 §6.7 ("a frame that started — within 5 s").
pub const DNSD_TCP_FRAME_TIMEOUT_SECS: Bound = Bound::up_to(5);
/// Idle between messages on a dnsd TCP connection: 120 s.
/// Spec: docs/54 §6.7 ("idle ≤ 120 s"); RFC 1035 §4.2.2 ("it should wait
/// until the connection has been idle for a period on the order of two
/// minutes"); Q-616 item 10.
pub const DNSD_TCP_IDLE_TIMEOUT_SECS: Bound = Bound::up_to(120);
/// Messages per dnsd TCP connection: at most 64, then close.
/// Spec: docs/54 §6.7 ("≤ 64 requests per connection"); Q-616 item 10.
pub const DNSD_MAX_REQUESTS_PER_TCP_CONNECTION_BOUND: Bound = Bound::up_to(64);

/// dnsd's staleness bound, TCP connection bounds and timeouts.
///
/// Spec: docs/54 §4.4, §6.7; docs/questions/Q-230 item 4, Q-616 items 6, 10.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsdLimits {
    zone_image_max_age: Duration,
    max_tcp_connections: u32,
    max_tcp_connections_per_source: u32,
    tcp_first_octet_timeout: Duration,
    tcp_frame_timeout: Duration,
    tcp_idle_timeout: Duration,
    max_requests_per_tcp_connection: u32,
}

impl DnsdLimits {
    /// How long the zone image may go without its SERIAL confirmed by dird
    /// before dnsd answers SERVFAIL to every query (fail closed).
    /// Spec: docs/54 §4.4; Q-616 item 6.
    #[must_use]
    pub const fn zone_image_max_age(&self) -> Duration {
        self.zone_image_max_age
    }

    /// Global TCP connection bound. Spec: docs/54 §6.7.
    #[must_use]
    pub const fn max_tcp_connections(&self) -> u32 {
        self.max_tcp_connections
    }

    /// TCP connections per source (≤ the global bound). Spec: docs/54 §6.7.
    #[must_use]
    pub const fn max_tcp_connections_per_source(&self) -> u32 {
        self.max_tcp_connections_per_source
    }

    /// Time allowed for a connection's first octet. Spec: docs/54 §6.7.
    #[must_use]
    pub const fn tcp_first_octet_timeout(&self) -> Duration {
        self.tcp_first_octet_timeout
    }

    /// Time allowed for a started message. Spec: docs/54 §6.7.
    #[must_use]
    pub const fn tcp_frame_timeout(&self) -> Duration {
        self.tcp_frame_timeout
    }

    /// Idle time allowed between messages. Spec: docs/54 §6.7; RFC 1035
    /// §4.2.2.
    #[must_use]
    pub const fn tcp_idle_timeout(&self) -> Duration {
        self.tcp_idle_timeout
    }

    /// Messages per connection before it is closed. Spec: docs/54 §6.7.
    #[must_use]
    pub const fn max_requests_per_tcp_connection(&self) -> u32 {
        self.max_requests_per_tcp_connection
    }
}

/// dnsd's settings, as parsed and validated from its file.
///
/// Spec: docs/50 R50-15, §7.1; docs/54 §4.3; docs/questions/Q-619 item 4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsdSettings {
    run_as: Account,
    listen: Vec<SocketAddr>,
    internal_networks: Vec<Network>,
    dird: Endpoint,
    audit: Endpoint,
    limits: DnsdLimits,
}

/// The per-source bound may not exceed the global bound; reported at the
/// later of the two keys that were given (Q-230 item 4).
/// Spec: docs/54 §6.7.
fn check_connection_bounds(global: &Located<u32>, per_source: &Located<u32>) -> Result<(), Error> {
    if per_source.value <= global.value {
        return Ok(());
    }
    let (line, key) = if per_source.line >= global.line {
        (per_source.line, MAX_TCP_CONNECTIONS_PER_SOURCE)
    } else {
        (global.line, MAX_TCP_CONNECTIONS)
    };
    Err(Error::at(line, key, ErrorKind::InconsistentLimits))
}

impl DnsdSettings {
    /// The closed key table of dnsd's file. Spec: docs/50 R50-15.
    pub const KEYS: &'static [&'static str] = &[
        RUN_AS_UID,
        RUN_AS_GID,
        LISTEN,
        INTERNAL_NETWORKS,
        DIRD_DNS_SOCKET,
        DIRD_UID,
        AUDIT_SOCKET,
        AUDITD_UID,
        ZONE_IMAGE_MAX_AGE,
        MAX_TCP_CONNECTIONS,
        MAX_TCP_CONNECTIONS_PER_SOURCE,
        TCP_FIRST_OCTET_TIMEOUT,
        TCP_FRAME_TIMEOUT,
        TCP_IDLE_TIMEOUT,
        MAX_REQUESTS_PER_TCP_CONNECTION,
    ];

    /// Parses and validates dnsd's file. Required: `run_as_uid`,
    /// `run_as_gid`, `listen` (each address served on UDP and TCP, every one
    /// on port 53 — `NonStandardPort`, task DN10d),
    /// `internal_networks` (every `listen` address inside one of them —
    /// `ListenerNotInternal`), `dird_dns_socket` + `dird_uid`,
    /// `audit_socket`, `auditd_uid`. Optional: `zone_image_max_age` (30s ..=
    /// 60s, default 60s) and the TCP limits (docs/54 §6.7 value as default
    /// and ceiling; the per-source bound never above the global one).
    ///
    /// # Errors
    /// Any rule of the format or of this schema (see [`crate::ErrorKind`]).
    ///
    /// Spec: docs/54 §3.1, §4.3, §4.4, §4.6, §4.7, §6.7; docs/50 R50-15,
    /// §7.1; RFC 1035 §4.2; docs/questions/Q-619 item 4, Q-1025 item 1.
    pub fn parse(input: &[u8]) -> Result<Self, Error> {
        let doc = Document::parse(input, Self::KEYS)?;
        let mut all = Distinct::default();
        let run_as = schema::account(&doc, &mut all)?;
        let listen = doc.required(LISTEN, |text| value::list(text, value::listener_address))?;
        // Task DN10d (A-178 on Q-1025 item 1): the NS record names the DC as
        // the zone's name server, reached on port 53 (RFC 1035 §4.2) — every
        // listener is on it, by the one port table and rule (checked right
        // after the list, before the zone-table rule, as for the kdc).
        schema::check_standard_port(Some(&listen), LISTEN, StandardPort::Dns)?;
        // docs/54 §4.7 (A-114): `internal_networks` is mandatory and every
        // listener lies inside it — the rule and the one match of the kdc's
        // and ldap-front's files.
        let internal_networks = doc
            .required(INTERNAL_NETWORKS, |text| value::list(text, value::network))?
            .value;
        schema::check_internal([(Some(&listen), LISTEN)], &internal_networks)?;
        let listen = listen.value;
        let dird = schema::endpoint(&doc, &mut all, DIRD_DNS_SOCKET, DIRD_UID)?;
        let audit = schema::endpoint(&doc, &mut all, AUDIT_SOCKET, AUDITD_UID)?;
        let global = schema::limit(&doc, MAX_TCP_CONNECTIONS, DNSD_MAX_TCP_CONNECTIONS_BOUND)?;
        let per_source = schema::limit(
            &doc,
            MAX_TCP_CONNECTIONS_PER_SOURCE,
            DNSD_MAX_TCP_CONNECTIONS_PER_SOURCE_BOUND,
        )?;
        check_connection_bounds(&global, &per_source)?;
        let limits = DnsdLimits {
            zone_image_max_age: schema::duration(
                &doc,
                ZONE_IMAGE_MAX_AGE,
                ZONE_IMAGE_MAX_AGE_SECS,
            )?,
            max_tcp_connections: global.value,
            max_tcp_connections_per_source: per_source.value,
            tcp_first_octet_timeout: schema::duration(
                &doc,
                TCP_FIRST_OCTET_TIMEOUT,
                DNSD_TCP_FIRST_OCTET_TIMEOUT_SECS,
            )?,
            tcp_frame_timeout: schema::duration(
                &doc,
                TCP_FRAME_TIMEOUT,
                DNSD_TCP_FRAME_TIMEOUT_SECS,
            )?,
            tcp_idle_timeout: schema::duration(&doc, TCP_IDLE_TIMEOUT, DNSD_TCP_IDLE_TIMEOUT_SECS)?,
            max_requests_per_tcp_connection: schema::limit(
                &doc,
                MAX_REQUESTS_PER_TCP_CONNECTION,
                DNSD_MAX_REQUESTS_PER_TCP_CONNECTION_BOUND,
            )?
            .value,
        };
        Ok(DnsdSettings {
            run_as,
            listen,
            internal_networks,
            dird,
            audit,
            limits,
        })
    }

    /// The account dnsd drops to after binding. Spec: docs/54 §4.3, §4.7;
    /// docs/50 §6.2, §6.4.
    #[must_use]
    pub const fn run_as(&self) -> Account {
        self.run_as
    }

    /// The interface addresses, each served on UDP and on TCP (at least one;
    /// none repeated; each inside an internal network; every one on port 53,
    /// [`crate::StandardPort::Dns`]).
    /// Spec: RFC 1035 §4.2; docs/54 §4.3, §4.7; docs/questions/Q-1025 item 1.
    #[must_use]
    pub fn listen(&self) -> &[SocketAddr] {
        &self.listen
    }

    /// The zone table: every listener address lies in one of these networks,
    /// and dnsd serves only sources that do (crates/dns-daemon).
    /// Spec: docs/54 §4.7; A-114.
    #[must_use]
    pub fn internal_networks(&self) -> &[Network] {
        &self.internal_networks
    }

    /// dird's `dird-dns.sock` and uid (dnsd verifies the uid and the zone in
    /// dird's `Pong` on every connection). Spec: docs/54 §4.6; docs/50 R50-3.
    #[must_use]
    pub fn dird(&self) -> &Endpoint {
        &self.dird
    }

    /// auditd's socket and uid. Spec: docs/54 §4.8, §9; docs/50 R50-16.
    #[must_use]
    pub fn audit(&self) -> &Endpoint {
        &self.audit
    }

    /// The staleness bound, TCP connection bounds and timeouts.
    /// Spec: docs/54 §4.4, §6.7.
    #[must_use]
    pub const fn limits(&self) -> &DnsdLimits {
        &self.limits
    }
}
