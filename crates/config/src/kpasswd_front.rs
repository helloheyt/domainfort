//! kpasswd-front's configuration file.
//!
//! kpasswd-front is the network front of the change-password service (RFC
//! 3244 §2) on **TCP 464 only** (docs/53 R53-3; A-117: "TCP 464 only, only
//! inside `internal_networks`" — UDP has no code path, docs/questions/Q-602
//! (a)). It frames requests (crates/parse-kpasswd), encodes its own
//! KRB-ERRORs, and talks only to dird (`dird-kpasswd.sock`, crates/
//! ipc-kpasswd) and auditd. It holds no key, no store and no keyd channel
//! (docs/53 R53-4).
//!
//! **No secrets** — the front holds none (the new password travels inside
//! the client's KRB-PRIV, which only keyd decrypts).
//!
//! **Internal listeners only** — the rule of ldap-front's and the kdc's
//! files (docs/52 R14, A-114; docs/53 §3.3: "`internal_networks` required
//! in the front's file; every listen address inside them"): the zone table
//! is required and every `listen` address must lie in one of its networks
//! (`ListenerNotInternal`, the one match `value::is_internal`). The front
//! closes every connection whose source is outside the table before a byte
//! (crates/kpasswd-front).
//!
//! **The realm** names the service realm of the front's KRB-ERRORs (RFC 4120
//! §5.9.1 `realm`; docs/53 §5.7: "`realm` = the realm, `sname` =
//! `kadmin/changepw`"); the front has no keyd to ask. It must be dird's
//! realm (docs/questions/Q-955 item 4).
//!
//! **Limits** are the kdc's TCP limits — the same bounds, the same keys
//! (docs/53 §5.1: "a global and per-source connection quota, as the kdc,
//! docs/50 §4.1"; "the first frame within 10 s") — with no idle timeout and
//! no request count: one request and one reply per connection (RFC 3244 §2).
//! `tcp_frame_timeout` bounds the write of the reply.
//!
//! Spec: docs/53 R53-3, R53-4, §3.3, §5.1, §5.6, §5.7, §10 (K8); docs/50
//! R50-15, §2.4, §3.6, §4.1, §6.2, §7.1; docs/52 §7 R14; RFC 3244 §2.

use core::net::SocketAddr;
use core::time::Duration;

use crate::error::{Error, ErrorKind};
use crate::format::{Document, Located};
use crate::kdc::{
    MAX_TCP_CONNECTIONS_BOUND, MAX_TCP_CONNECTIONS_PER_SOURCE_BOUND, TCP_FIRST_FRAME_TIMEOUT_SECS,
    TCP_FRAME_TIMEOUT_SECS,
};
use crate::limits::Bound;
use crate::schema::{
    self, Account, Distinct, Endpoint, AUDITD_UID, AUDIT_SOCKET, DIRD_DEADLINE, DIRD_UID,
    INTERNAL_NETWORKS, RUN_AS_GID, RUN_AS_UID,
};
use crate::value::{self, Network};

/// Key: the TCP listener addresses (port 464). Spec: docs/53 R53-3, §3.3;
/// docs/50 §7.1 ("listen addresses").
const LISTEN: &str = "listen";
/// Key: the realm the front's KRB-ERRORs name. Spec: docs/53 §5.7; RFC 4120
/// §5.9.1.
const REALM: &str = "realm";
/// Key: path of `dird-kpasswd.sock`. Spec: docs/53 §4.3; docs/50 the
/// channel-magic registry.
const DIRD_KPASSWD_SOCKET: &str = "dird_kpasswd_socket";
/// Key: global TCP connection bound. Spec: docs/53 §5.1; docs/50 §4.1.
const MAX_TCP_CONNECTIONS: &str = "max_tcp_connections";
/// Key: TCP connections per source address. Spec: docs/53 §5.1; docs/50
/// §4.1.
const MAX_TCP_CONNECTIONS_PER_SOURCE: &str = "max_tcp_connections_per_source";
/// Key: time for the request frame of a connection, from the accept.
/// Spec: docs/53 §5.1 ("the first frame within 10 s").
const TCP_FIRST_FRAME_TIMEOUT: &str = "tcp_first_frame_timeout";
/// Key: time for the reply to be written. Spec: docs/50 §4.1.
const TCP_FRAME_TIMEOUT: &str = "tcp_frame_timeout";

/// kpasswd-front's deadline on the dird-kpasswd channel: at most 25 s (the
/// default), at least 11 s — one pass of dird's path without a request
/// queued ahead (three keyd calls at 2 s and the audit acknowledgement at
/// 5 s; crates/ipc-kpasswd `DEFAULT_DEADLINE`). A shorter deadline would make
/// the front answer HARDERROR to changes dird is still completing (an
/// unknown outcome, docs/53 §5.6 step 6). ⚠ Project choice
/// (docs/questions/Q-955 item 3).
/// Spec: docs/53 §5.6; docs/50 §3.6.
pub const DIRD_KPASSWD_DEADLINE_SECS: Bound = Bound {
    min: 11,
    max: 25,
    default: 25,
};

/// kpasswd-front's connection, timeout and deadline limits.
///
/// Spec: docs/53 §5.1; docs/50 §3.6, §4.1; docs/questions/Q-230 item 4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KpasswdFrontLimits {
    max_tcp_connections: u32,
    max_tcp_connections_per_source: u32,
    tcp_first_frame_timeout: Duration,
    tcp_frame_timeout: Duration,
    dird_deadline: Duration,
}

impl KpasswdFrontLimits {
    /// Global TCP connection bound. Spec: docs/53 §5.1; docs/50 §4.1.
    #[must_use]
    pub const fn max_tcp_connections(&self) -> u32 {
        self.max_tcp_connections
    }

    /// TCP connections per source address (≤ the global bound).
    /// Spec: docs/53 §5.1; docs/50 §4.1.
    #[must_use]
    pub const fn max_tcp_connections_per_source(&self) -> u32 {
        self.max_tcp_connections_per_source
    }

    /// Time allowed for the request frame, from the accept.
    /// Spec: docs/53 §5.1.
    #[must_use]
    pub const fn tcp_first_frame_timeout(&self) -> Duration {
        self.tcp_first_frame_timeout
    }

    /// Time allowed for writing the reply. Spec: docs/50 §4.1.
    #[must_use]
    pub const fn tcp_frame_timeout(&self) -> Duration {
        self.tcp_frame_timeout
    }

    /// Deadline for dird's answer to one request. Spec: docs/53 §5.6.
    #[must_use]
    pub const fn dird_deadline(&self) -> Duration {
        self.dird_deadline
    }
}

/// kpasswd-front's settings, as parsed and validated from its file.
///
/// Spec: docs/50 R50-15, §2.4, §7.1; docs/53 §10 (K8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KpasswdFrontSettings {
    run_as: Account,
    listen: Vec<SocketAddr>,
    internal_networks: Vec<Network>,
    realm: String,
    dird: Endpoint,
    audit: Endpoint,
    limits: KpasswdFrontLimits,
}

/// The per-source bound may not exceed the global bound; reported at the
/// later of the two keys that were given (the kdc file's rule, Q-230 item
/// 4). Spec: docs/50 §4.1.
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

impl KpasswdFrontSettings {
    /// The closed key table of kpasswd-front's file. Spec: docs/50 R50-15.
    pub const KEYS: &'static [&'static str] = &[
        RUN_AS_UID,
        RUN_AS_GID,
        LISTEN,
        INTERNAL_NETWORKS,
        REALM,
        DIRD_KPASSWD_SOCKET,
        DIRD_UID,
        AUDIT_SOCKET,
        AUDITD_UID,
        MAX_TCP_CONNECTIONS,
        MAX_TCP_CONNECTIONS_PER_SOURCE,
        TCP_FIRST_FRAME_TIMEOUT,
        TCP_FRAME_TIMEOUT,
        DIRD_DEADLINE,
    ];

    /// Parses and validates kpasswd-front's file. Required: `run_as_uid`,
    /// `run_as_gid`, `listen`, `internal_networks` (every `listen` address
    /// inside one of them — `ListenerNotInternal`), `realm`,
    /// `dird_kpasswd_socket` + `dird_uid`, `audit_socket`, `auditd_uid`.
    /// Optional: the limits (the docs/50 / docs/53 value as default and
    /// ceiling; the per-source bound ≤ the global one) and `dird_deadline`
    /// (11s ..= 25s, default 25s).
    ///
    /// # Errors
    /// Any rule of the format or of this schema (see [`crate::ErrorKind`]).
    ///
    /// Spec: docs/53 R53-3, §3.3, §5.1, §5.7; docs/50 R50-15, §3.6, §4.1,
    /// §7.1; docs/52 §7 R14.
    pub fn parse(input: &[u8]) -> Result<Self, Error> {
        let doc = Document::parse(input, Self::KEYS)?;
        let mut all = Distinct::default();
        let run_as = schema::account(&doc, &mut all)?;
        let listen = doc.required(LISTEN, |text| value::list(text, value::listener_address))?;
        let internal_networks = doc
            .required(INTERNAL_NETWORKS, |text| value::list(text, value::network))?
            .value;
        schema::check_internal([(Some(&listen), LISTEN)], &internal_networks)?;
        let listen = listen.value;
        let realm = doc.required(REALM, value::realm)?.value;
        let dird = schema::endpoint(&doc, &mut all, DIRD_KPASSWD_SOCKET, DIRD_UID)?;
        let audit = schema::endpoint(&doc, &mut all, AUDIT_SOCKET, AUDITD_UID)?;
        let global = schema::limit(&doc, MAX_TCP_CONNECTIONS, MAX_TCP_CONNECTIONS_BOUND)?;
        let per_source = schema::limit(
            &doc,
            MAX_TCP_CONNECTIONS_PER_SOURCE,
            MAX_TCP_CONNECTIONS_PER_SOURCE_BOUND,
        )?;
        check_connection_bounds(&global, &per_source)?;
        let limits = KpasswdFrontLimits {
            max_tcp_connections: global.value,
            max_tcp_connections_per_source: per_source.value,
            tcp_first_frame_timeout: schema::duration(
                &doc,
                TCP_FIRST_FRAME_TIMEOUT,
                TCP_FIRST_FRAME_TIMEOUT_SECS,
            )?,
            tcp_frame_timeout: schema::duration(&doc, TCP_FRAME_TIMEOUT, TCP_FRAME_TIMEOUT_SECS)?,
            dird_deadline: schema::duration(&doc, DIRD_DEADLINE, DIRD_KPASSWD_DEADLINE_SECS)?,
        };
        Ok(KpasswdFrontSettings {
            run_as,
            listen,
            internal_networks,
            realm,
            dird,
            audit,
            limits,
        })
    }

    /// The account kpasswd-front drops to after binding (docs/50 §6.2).
    /// Spec: docs/53 R53-3; docs/50 §6.2, §6.4.
    #[must_use]
    pub const fn run_as(&self) -> Account {
        self.run_as
    }

    /// The TCP listener addresses (at least one; none repeated; each inside
    /// an internal network). Spec: docs/53 R53-3, §3.3.
    #[must_use]
    pub fn listen(&self) -> &[SocketAddr] {
        &self.listen
    }

    /// The zone table: the internal networks. Every listener address lies in
    /// one of them, and the front serves only clients whose source address
    /// does. Spec: docs/53 §3.3; docs/52 §7 R14; A-114.
    #[must_use]
    pub fn internal_networks(&self) -> &[Network] {
        &self.internal_networks
    }

    /// The realm of the front's KRB-ERRORs (`A-Z a-z 0-9 . -`; the front
    /// re-validates it as a KerberosString). Spec: docs/53 §5.7; RFC 4120
    /// §5.9.1.
    #[must_use]
    pub fn realm(&self) -> &str {
        &self.realm
    }

    /// dird's `dird-kpasswd.sock` and uid. Spec: docs/53 §4.3; docs/50 §3.2.
    #[must_use]
    pub fn dird(&self) -> &Endpoint {
        &self.dird
    }

    /// auditd's socket and uid. Spec: docs/53 §9; docs/50 §2.4, R50-17.
    #[must_use]
    pub fn audit(&self) -> &Endpoint {
        &self.audit
    }

    /// The connection, timeout and deadline limits. Spec: docs/53 §5.1;
    /// docs/50 §3.6, §4.1.
    #[must_use]
    pub const fn limits(&self) -> &KpasswdFrontLimits {
        &self.limits
    }
}
