//! kdc's configuration file.
//!
//! The kdc listens on UDP and TCP (port 88 by RFC 4120 §7.2.1/§7.2.2, as
//! quoted in docs/50 §4.1) on the configured interface addresses only, holds no
//! key (docs/50 §2.4), and talks to keyd (`Role::Kdc`), to dird (the view
//! protocol) and to auditd. Its realm and krbtgt handle come from keyd
//! (`DescribeConfig`) and dird (`DescribeDomain`) at start (§7.5), so they are
//! not settings.
//!
//! **No secrets** — the kdc holds none (docs/50 §2.4; docs/30 §1).
//!
//! The policy store is the file dird loads too (docs/50 §7.2): its signed
//! format (Q-219 → A-57) does not exist yet, so — as in dird's file — the
//! operator must name the UNSIGNED development format explicitly,
//! `policy_store_format = unsigned-development`, the only accepted value
//! (A-68; docs/questions/Q-270 item 2, Q-275 item 2).
//!
//! **Internal listeners only** (task R15b, docs/questions/Q-632): docs/50
//! R50-9 binds the kdc's listeners "to internal interfaces only" (and §4.1
//! for UDP, Q-223 → A-57 (a)), so the zone table (`internal_networks`) is
//! required and every `listen` address must lie in one of its networks
//! (`ListenerNotInternal`) — the rule and the one match (`value::is_internal`)
//! ldap-front's file has (docs/52 R14, A-114). Sources outside the table are
//! still served, as `External` (docs/50 §4.1 — Q-632 item 3).
//!
//! **Port 88 only** (task DN10c; A-176 on docs/questions/Q-1016 item 4): the
//! zone advertises the KDC at `_kerberos._udp` / `_kerberos._tcp` on port 88
//! (crates/dns-zone, from [`crate::StandardPort::Kerberos`]), so every
//! `listen` address must be on that port (`NonStandardPort`); the address is
//! the operator's.
//!
//! Spec: docs/50 R50-9, R50-15, §2.4, §3.6, §4.1, §7.1, §7.2, §7.5; RFC 4120
//! §7.2.1, §7.2.2, §7.2.3.2; docs/questions/Q-1024.

use core::net::SocketAddr;
use core::time::Duration;

use crate::dird::{PolicyStoreFormat, POLICY_STORE_FORMAT, POLICY_STORE_FORMATS};
use crate::error::{Error, ErrorKind};
use crate::format::{Document, Located};
use crate::limits::{Bound, KEYD_DEADLINE_SECS};
use crate::schema::{
    self, Account, Distinct, Endpoint, AUDITD_UID, AUDIT_SOCKET, DIRD_DEADLINE, DIRD_KDC_SOCKET,
    DIRD_UID, INTERNAL_NETWORKS, KEYD_DEADLINE, KEYD_SOCKET, KEYD_UID, POLICY_STORE_PATH,
    RUN_AS_GID, RUN_AS_UID,
};
use crate::standard_port::StandardPort;
use crate::value::{self, AbsolutePath, Network};

/// Key: the interface addresses, each served on UDP and TCP.
/// Spec: docs/50 §4.1, §7.1 ("listen addresses").
const LISTEN: &str = "listen";
/// Key: global TCP connection bound. Spec: docs/50 §4.1.
const MAX_TCP_CONNECTIONS: &str = "max_tcp_connections";
/// Key: TCP connections per source address. Spec: docs/50 §4.1.
const MAX_TCP_CONNECTIONS_PER_SOURCE: &str = "max_tcp_connections_per_source";
/// Key: time for the first frame of a TCP connection. Spec: docs/50 §4.1.
const TCP_FIRST_FRAME_TIMEOUT: &str = "tcp_first_frame_timeout";
/// Key: time for a started TCP frame to complete. Spec: docs/50 §4.1.
const TCP_FRAME_TIMEOUT: &str = "tcp_frame_timeout";
/// Key: idle time between requests on a TCP connection. Spec: docs/50 §4.1.
const TCP_IDLE_TIMEOUT: &str = "tcp_idle_timeout";
/// Key: requests per TCP connection before it is closed. Spec: docs/50 §4.1.
const MAX_REQUESTS_PER_TCP_CONNECTION: &str = "max_requests_per_tcp_connection";

/// Global TCP connection bound: at most 1024.
/// Spec: docs/50 §4.1 ("a global Semaphore (for example 1024 connections)").
pub const MAX_TCP_CONNECTIONS_BOUND: Bound = Bound::up_to(1024);
/// TCP connections per source address: at most 16, and never above the
/// global bound.
/// Spec: docs/50 §4.1 ("a counter per source address (for example 16)").
pub const MAX_TCP_CONNECTIONS_PER_SOURCE_BOUND: Bound = Bound::up_to(16);
/// First frame of a TCP connection: within 10 s.
/// Spec: docs/50 §4.1 ("first frame within 10 s").
pub const TCP_FIRST_FRAME_TIMEOUT_SECS: Bound = Bound::up_to(10);
/// A started TCP frame: within 10 s.
/// Spec: docs/50 §4.1 ("a frame that has started — within 10 s").
pub const TCP_FRAME_TIMEOUT_SECS: Bound = Bound::up_to(10);
/// Idle between requests: 30 s. Spec: docs/50 §4.1 ("idle between requests
/// 30 s").
pub const TCP_IDLE_TIMEOUT_SECS: Bound = Bound::up_to(30);
/// Requests per TCP connection: at most 64, then close.
/// Spec: docs/50 §4.1 ("up to 64 requests per connection and then close");
/// RFC 4120 §7.2.2 as quoted there ("MAY close … after sending a response").
pub const MAX_REQUESTS_PER_TCP_CONNECTION_BOUND: Bound = Bound::up_to(64);
/// The kdc's deadline on the dird-kdc channel: 2 s.
/// Spec: docs/50 §3.6 ("deadline in the client — dird-kdc: 2 s").
pub const DIRD_KDC_DEADLINE_SECS: Bound = Bound::up_to(2);

/// The kdc's listener, connection and deadline limits.
///
/// Spec: docs/50 §3.6, §4.1; docs/questions/Q-230 item 4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdcLimits {
    max_tcp_connections: u32,
    max_tcp_connections_per_source: u32,
    tcp_first_frame_timeout: Duration,
    tcp_frame_timeout: Duration,
    tcp_idle_timeout: Duration,
    max_requests_per_tcp_connection: u32,
    keyd_deadline: Duration,
    dird_deadline: Duration,
}

impl KdcLimits {
    /// Global TCP connection bound. Spec: docs/50 §4.1.
    #[must_use]
    pub const fn max_tcp_connections(&self) -> u32 {
        self.max_tcp_connections
    }

    /// TCP connections per source address (≤ the global bound).
    /// Spec: docs/50 §4.1.
    #[must_use]
    pub const fn max_tcp_connections_per_source(&self) -> u32 {
        self.max_tcp_connections_per_source
    }

    /// Time allowed for a connection's first frame. Spec: docs/50 §4.1.
    #[must_use]
    pub const fn tcp_first_frame_timeout(&self) -> Duration {
        self.tcp_first_frame_timeout
    }

    /// Time allowed for a started frame. Spec: docs/50 §4.1.
    #[must_use]
    pub const fn tcp_frame_timeout(&self) -> Duration {
        self.tcp_frame_timeout
    }

    /// Idle time allowed between requests. Spec: docs/50 §4.1.
    #[must_use]
    pub const fn tcp_idle_timeout(&self) -> Duration {
        self.tcp_idle_timeout
    }

    /// Requests per connection before it is closed. Spec: docs/50 §4.1.
    #[must_use]
    pub const fn max_requests_per_tcp_connection(&self) -> u32 {
        self.max_requests_per_tcp_connection
    }

    /// Deadline for an answer from keyd. Spec: docs/50 §3.6.
    #[must_use]
    pub const fn keyd_deadline(&self) -> Duration {
        self.keyd_deadline
    }

    /// Deadline for an answer from dird. Spec: docs/50 §3.6.
    #[must_use]
    pub const fn dird_deadline(&self) -> Duration {
        self.dird_deadline
    }
}

/// kdc's settings, as parsed and validated from its file.
///
/// Spec: docs/50 R50-15, §2.4, §7.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KdcSettings {
    run_as: Account,
    listen: Vec<SocketAddr>,
    internal_networks: Vec<Network>,
    keyd: Endpoint,
    dird: Endpoint,
    policy_store_path: AbsolutePath,
    policy_store_format: PolicyStoreFormat,
    audit: Endpoint,
    limits: KdcLimits,
}

/// The per-source bound may not exceed the global bound; reported at the
/// later of the two keys that were given (Q-230 item 4).
/// Spec: docs/50 §4.1.
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

impl KdcSettings {
    /// The closed key table of kdc's file. Spec: docs/50 R50-15.
    pub const KEYS: &'static [&'static str] = &[
        RUN_AS_UID,
        RUN_AS_GID,
        LISTEN,
        INTERNAL_NETWORKS,
        KEYD_SOCKET,
        KEYD_UID,
        DIRD_KDC_SOCKET,
        DIRD_UID,
        POLICY_STORE_PATH,
        POLICY_STORE_FORMAT,
        AUDIT_SOCKET,
        AUDITD_UID,
        MAX_TCP_CONNECTIONS,
        MAX_TCP_CONNECTIONS_PER_SOURCE,
        TCP_FIRST_FRAME_TIMEOUT,
        TCP_FRAME_TIMEOUT,
        TCP_IDLE_TIMEOUT,
        MAX_REQUESTS_PER_TCP_CONNECTION,
        KEYD_DEADLINE,
        DIRD_DEADLINE,
    ];

    /// Parses and validates kdc's file. Required: `run_as_uid`,
    /// `run_as_gid`, `listen` (every address on port 88 — `NonStandardPort`;
    /// task DN10c), `internal_networks` (every `listen` address
    /// inside one of them — `ListenerNotInternal`; task R15b),
    /// `keyd_socket` + `keyd_uid`, `dird_kdc_socket` + `dird_uid`,
    /// `policy_store_path`, `policy_store_format` (only
    /// `unsigned-development`, A-68), `audit_socket`, `auditd_uid`.
    /// Optional: the limits (docs/50 value as default and ceiling).
    ///
    /// # Errors
    /// Any rule of the format or of this schema (see [`crate::ErrorKind`]).
    ///
    /// Spec: docs/50 R50-9, R50-15, §3.6, §4.1, §7.1, §7.2; RFC 4120
    /// §7.2.3.2; docs/questions/Q-1024.
    pub fn parse(input: &[u8]) -> Result<Self, Error> {
        let doc = Document::parse(input, Self::KEYS)?;
        let mut all = Distinct::default();
        let run_as = schema::account(&doc, &mut all)?;
        let listen = doc.required(LISTEN, |text| value::list(text, value::listener_address))?;
        // Task DN10c (A-176 on Q-1016 item 4): the zone advertises the KDC
        // on port 88, UDP and TCP — every `listen` address is on it.
        schema::check_standard_port(Some(&listen), LISTEN, StandardPort::Kerberos)?;
        // Required (task R15b): the kdc binds to internal interfaces only
        // (docs/50 R50-9, §4.1; Q-223 → A-57 (a)), so every `listen` address
        // lies in a network of the zone table — the rule and the match
        // ldap-front's file has (docs/52 R14, Q-580, A-114; Q-632).
        let internal_networks = doc
            .required(INTERNAL_NETWORKS, |text| value::list(text, value::network))?
            .value;
        schema::check_internal([(Some(&listen), LISTEN)], &internal_networks)?;
        let listen = listen.value;
        let keyd = schema::endpoint(&doc, &mut all, KEYD_SOCKET, KEYD_UID)?;
        let dird = schema::endpoint(&doc, &mut all, DIRD_KDC_SOCKET, DIRD_UID)?;
        let policy_store_path = schema::path(&doc, &mut all, POLICY_STORE_PATH)?;
        let policy_store_format = doc
            .required(POLICY_STORE_FORMAT, |text| {
                value::named(text, POLICY_STORE_FORMATS)
            })?
            .value;
        let audit = schema::endpoint(&doc, &mut all, AUDIT_SOCKET, AUDITD_UID)?;
        let global = schema::limit(&doc, MAX_TCP_CONNECTIONS, MAX_TCP_CONNECTIONS_BOUND)?;
        let per_source = schema::limit(
            &doc,
            MAX_TCP_CONNECTIONS_PER_SOURCE,
            MAX_TCP_CONNECTIONS_PER_SOURCE_BOUND,
        )?;
        check_connection_bounds(&global, &per_source)?;
        let limits = KdcLimits {
            max_tcp_connections: global.value,
            max_tcp_connections_per_source: per_source.value,
            tcp_first_frame_timeout: schema::duration(
                &doc,
                TCP_FIRST_FRAME_TIMEOUT,
                TCP_FIRST_FRAME_TIMEOUT_SECS,
            )?,
            tcp_frame_timeout: schema::duration(&doc, TCP_FRAME_TIMEOUT, TCP_FRAME_TIMEOUT_SECS)?,
            tcp_idle_timeout: schema::duration(&doc, TCP_IDLE_TIMEOUT, TCP_IDLE_TIMEOUT_SECS)?,
            max_requests_per_tcp_connection: schema::limit(
                &doc,
                MAX_REQUESTS_PER_TCP_CONNECTION,
                MAX_REQUESTS_PER_TCP_CONNECTION_BOUND,
            )?
            .value,
            keyd_deadline: schema::duration(&doc, KEYD_DEADLINE, KEYD_DEADLINE_SECS)?,
            dird_deadline: schema::duration(&doc, DIRD_DEADLINE, DIRD_KDC_DEADLINE_SECS)?,
        };
        Ok(KdcSettings {
            run_as,
            listen,
            internal_networks,
            keyd,
            dird,
            policy_store_path,
            policy_store_format,
            audit,
            limits,
        })
    }

    /// The account kdc drops to after binding. Spec: docs/50 §6.2, §6.4.
    #[must_use]
    pub const fn run_as(&self) -> Account {
        self.run_as
    }

    /// The interface addresses, each served on UDP and on TCP (at least one;
    /// none repeated; every one on port 88 — [`crate::StandardPort::Kerberos`]).
    /// Spec: docs/50 §4.1; RFC 4120 §7.2.3.2; docs/questions/Q-1024.
    #[must_use]
    pub fn listen(&self) -> &[SocketAddr] {
        &self.listen
    }

    /// The zone table for `Peer.src_net`: sources inside these networks are
    /// `Internal`, all others `External`; at least one network, and every
    /// `listen` address inside one. Spec: docs/50 R50-9, §4.1.
    #[must_use]
    pub fn internal_networks(&self) -> &[Network] {
        &self.internal_networks
    }

    /// keyd's socket and uid. Spec: docs/50 §3.2.
    #[must_use]
    pub fn keyd(&self) -> &Endpoint {
        &self.keyd
    }

    /// dird's `dird-kdc.sock` and uid. Spec: docs/50 §3.2, §3.4.
    #[must_use]
    pub fn dird(&self) -> &Endpoint {
        &self.dird
    }

    /// The signed policy store (the same file dird loads). Spec: docs/50 §7.2.
    #[must_use]
    pub fn policy_store_path(&self) -> &AbsolutePath {
        &self.policy_store_path
    }

    /// The format of the policy store: only the unsigned development format
    /// exists (Q-219 → A-57 not defined yet). Spec: docs/50 §7.2; A-68;
    /// docs/questions/Q-270 item 2.
    #[must_use]
    pub const fn policy_store_format(&self) -> PolicyStoreFormat {
        self.policy_store_format
    }

    /// auditd's socket and uid. Spec: docs/50 §2.4, R50-17.
    #[must_use]
    pub fn audit(&self) -> &Endpoint {
        &self.audit
    }

    /// The listener, connection and deadline limits. Spec: docs/50 §3.6, §4.1.
    #[must_use]
    pub const fn limits(&self) -> &KdcLimits {
        &self.limits
    }
}
