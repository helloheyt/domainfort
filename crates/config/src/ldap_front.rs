//! ldap-front's configuration file.
//!
//! ldap-front terminates TLS (rustls), frames LDAP and re-encodes it to the
//! canonical form, and talks only to dird (one Unix connection per client
//! connection) and auditd (docs/50 §2.4, R50-10). It listens on TCP 389
//! (StartTLS) and/or 636 (LDAPS) (§4.2).
//!
//! **No secrets.** The DC's TLS private key is never a setting: the file names
//! only the **paths** of the operator-supplied DER certificate and key. The key
//! file is root-owned mode 0400 and is read as root before the privilege drop;
//! the daemon checks that mode when it loads them, and that the certificate
//! is ECDSA P-256 / SHA-256: one DER X.509 v3 certificate whose
//! signatureAlgorithm equals tbsCertificate.signature and is
//! ecdsa-with-SHA256, whose subject key is EC P-256 and matches the P-256
//! private key, and whose validity contains the start-up time (docs/50
//! R50-12, §5.3, §6.4; Q-221 → A-57 option A; Q-320).
//!
//! **Internal listeners only** (docs/52 §7 R14; A-102 on docs/questions/Q-469
//! (b): "one front per zone; external LDAP connections are not in phase 1").
//! The file carries the zone table (`internal_networks`, required: CIDR →
//! Internal, everything else External — docs/50 §4.1, the same entries and
//! match rule as the kdc's) and every `ldap_listen` / `ldaps_listen` address
//! must lie in one of its networks (`ListenerNotInternal`). The front owns
//! the TCP socket, so the table is read here — for its listeners and for
//! the source of every accepted connection (crates/ldap-front) — and dird
//! no longer maps a reported address at all (docs/questions/Q-580).
//!
//! Spec: docs/50 R50-10, R50-12, R50-15, §2.4, §3.6, §4.1, §4.2, §5.3, §7.1;
//! docs/52 §7 R14.

use core::net::SocketAddr;
use core::time::Duration;

use crate::error::{Error, ErrorKind};
use crate::format::{Document, Located};
use crate::limits::Bound;
use crate::schema::{
    self, Account, Distinct, Endpoint, AUDITD_UID, AUDIT_SOCKET, DIRD_DEADLINE, DIRD_LDAP_SOCKET,
    DIRD_UID, INTERNAL_NETWORKS, RUN_AS_GID, RUN_AS_UID,
};
use crate::value::{self, AbsolutePath, Network};

/// Key: TCP listeners for LDAP with StartTLS (port 389). Spec: docs/50 §4.2.
const LDAP_LISTEN: &str = "ldap_listen";
/// Key: TCP listeners for LDAPS (port 636). Spec: docs/50 §4.2.
const LDAPS_LISTEN: &str = "ldaps_listen";
/// Key: path of the DC certificate (DER). Spec: docs/50 R50-12, §5.3.
const TLS_CERTIFICATE_PATH: &str = "tls_certificate_path";
/// Key: path of the DC private key (DER, root:0400). Spec: docs/50 R50-12.
const TLS_PRIVATE_KEY_PATH: &str = "tls_private_key_path";
/// Key: InitRecvTimeout. Spec: docs/50 §4.2.
const INIT_RECV_TIMEOUT: &str = "init_recv_timeout";
/// Key: MaxConnIdleTime. Spec: docs/50 §4.2.
const MAX_CONN_IDLE_TIME: &str = "max_conn_idle_time";
/// Key: TLS handshake timeout. Spec: docs/50 §4.2.
const TLS_HANDSHAKE_TIMEOUT: &str = "tls_handshake_timeout";

/// InitRecvTimeout: 30 s.
/// Spec: docs/50 §4.2 ("InitRecvTimeout 30 s"; docs/50 anchors these bounds
/// to the [MS-ADTS] 3.1.1.3.4.6 policy names through docs/49 §10.2).
pub const INIT_RECV_TIMEOUT_SECS: Bound = Bound::up_to(30);
/// MaxConnIdleTime: 300 s. Spec: docs/50 §4.2 ("MaxConnIdleTime 300 s").
pub const MAX_CONN_IDLE_TIME_SECS: Bound = Bound::up_to(300);
/// TLS handshake: within 10 s. Spec: docs/50 §4.2 ("TLS handshake within
/// 10 s").
pub const TLS_HANDSHAKE_TIMEOUT_SECS: Bound = Bound::up_to(10);
/// ldap-front's deadline on the dird-ldap channel: 65 s, and above the
/// engine's 60-second query bound.
/// Spec: docs/50 §3.6 ("dird-ldap: 65 s (above `MAX_QUERY_SECONDS` = 60 of the
/// engine)"); crates/ldap search/limits.rs `MAX_QUERY_SECONDS`.
pub const DIRD_LDAP_DEADLINE_SECS: Bound = Bound {
    min: 61,
    max: 65,
    default: 65,
};

/// ldap-front's timeouts and deadline.
///
/// Spec: docs/50 §3.6, §4.2; docs/questions/Q-230 item 4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LdapFrontLimits {
    init_recv_timeout: Duration,
    max_conn_idle_time: Duration,
    tls_handshake_timeout: Duration,
    dird_deadline: Duration,
}

impl LdapFrontLimits {
    /// InitRecvTimeout. Spec: docs/50 §4.2.
    #[must_use]
    pub const fn init_recv_timeout(&self) -> Duration {
        self.init_recv_timeout
    }

    /// MaxConnIdleTime. Spec: docs/50 §4.2.
    #[must_use]
    pub const fn max_conn_idle_time(&self) -> Duration {
        self.max_conn_idle_time
    }

    /// TLS handshake timeout. Spec: docs/50 §4.2.
    #[must_use]
    pub const fn tls_handshake_timeout(&self) -> Duration {
        self.tls_handshake_timeout
    }

    /// Deadline for dird's answer to one message. Spec: docs/50 §3.6.
    #[must_use]
    pub const fn dird_deadline(&self) -> Duration {
        self.dird_deadline
    }
}

/// ldap-front's settings, as parsed and validated from its file.
///
/// Spec: docs/50 R50-15, §2.4, §7.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdapFrontSettings {
    run_as: Account,
    ldap_listen: Vec<SocketAddr>,
    ldaps_listen: Vec<SocketAddr>,
    internal_networks: Vec<Network>,
    tls_certificate_path: AbsolutePath,
    tls_private_key_path: AbsolutePath,
    dird: Endpoint,
    audit: Endpoint,
    limits: LdapFrontLimits,
}

/// No address may serve both StartTLS and LDAPS; reported at the later list.
/// Spec: docs/50 §4.2, §4.3 step 6 (on 636 TLS starts at the first octet, on
/// 389 only after StartTLS); docs/questions/Q-230 item 7.
fn check_disjoint(
    ldap: Option<&Located<Vec<SocketAddr>>>,
    ldaps: Option<&Located<Vec<SocketAddr>>>,
) -> Result<(), Error> {
    let (Some(ldap), Some(ldaps)) = (ldap, ldaps) else {
        return Ok(());
    };
    if ldap
        .value
        .iter()
        .any(|address| ldaps.value.contains(address))
    {
        let (line, key) = if ldaps.line >= ldap.line {
            (ldaps.line, LDAPS_LISTEN)
        } else {
            (ldap.line, LDAP_LISTEN)
        };
        return Err(Error::at(line, key, ErrorKind::DuplicateEntry));
    }
    Ok(())
}

impl LdapFrontSettings {
    /// The closed key table of ldap-front's file. Spec: docs/50 R50-15.
    pub const KEYS: &'static [&'static str] = &[
        RUN_AS_UID,
        RUN_AS_GID,
        LDAP_LISTEN,
        LDAPS_LISTEN,
        INTERNAL_NETWORKS,
        TLS_CERTIFICATE_PATH,
        TLS_PRIVATE_KEY_PATH,
        DIRD_LDAP_SOCKET,
        DIRD_UID,
        AUDIT_SOCKET,
        AUDITD_UID,
        INIT_RECV_TIMEOUT,
        MAX_CONN_IDLE_TIME,
        TLS_HANDSHAKE_TIMEOUT,
        DIRD_DEADLINE,
    ];

    /// Parses and validates ldap-front's file. Required: `run_as_uid`,
    /// `run_as_gid`, at least one of `ldap_listen` / `ldaps_listen` (no
    /// address in both), `internal_networks` (every listener address inside
    /// one of them), `tls_certificate_path`, `tls_private_key_path`,
    /// `dird_ldap_socket` + `dird_uid`, `audit_socket`, `auditd_uid`.
    /// Optional: the timeouts (docs/50 value as default and ceiling) and
    /// `dird_deadline` (61s ..= 65s, default 65s).
    ///
    /// # Errors
    /// Any rule of the format or of this schema (see [`crate::ErrorKind`]).
    ///
    /// Spec: docs/50 R50-10, R50-12, R50-15, §3.6, §4.1, §4.2, §5.3, §7.1;
    /// docs/52 §7 R14.
    pub fn parse(input: &[u8]) -> Result<Self, Error> {
        let doc = Document::parse(input, Self::KEYS)?;
        let mut all = Distinct::default();
        let run_as = schema::account(&doc, &mut all)?;
        let ldap = doc.optional(LDAP_LISTEN, |text| {
            value::list(text, value::listener_address)
        })?;
        let ldaps = doc.optional(LDAPS_LISTEN, |text| {
            value::list(text, value::listener_address)
        })?;
        if ldap.is_none() && ldaps.is_none() {
            return Err(Error::file(ErrorKind::NoListener));
        }
        check_disjoint(ldap.as_ref(), ldaps.as_ref())?;
        let internal_networks = doc
            .required(INTERNAL_NETWORKS, |text| value::list(text, value::network))?
            .value;
        schema::check_internal(
            [(ldap.as_ref(), LDAP_LISTEN), (ldaps.as_ref(), LDAPS_LISTEN)],
            &internal_networks,
        )?;
        let tls_certificate_path = schema::path(&doc, &mut all, TLS_CERTIFICATE_PATH)?;
        let tls_private_key_path = schema::path(&doc, &mut all, TLS_PRIVATE_KEY_PATH)?;
        let dird = schema::endpoint(&doc, &mut all, DIRD_LDAP_SOCKET, DIRD_UID)?;
        let audit = schema::endpoint(&doc, &mut all, AUDIT_SOCKET, AUDITD_UID)?;
        let limits = LdapFrontLimits {
            init_recv_timeout: schema::duration(&doc, INIT_RECV_TIMEOUT, INIT_RECV_TIMEOUT_SECS)?,
            max_conn_idle_time: schema::duration(
                &doc,
                MAX_CONN_IDLE_TIME,
                MAX_CONN_IDLE_TIME_SECS,
            )?,
            tls_handshake_timeout: schema::duration(
                &doc,
                TLS_HANDSHAKE_TIMEOUT,
                TLS_HANDSHAKE_TIMEOUT_SECS,
            )?,
            dird_deadline: schema::duration(&doc, DIRD_DEADLINE, DIRD_LDAP_DEADLINE_SECS)?,
        };
        Ok(LdapFrontSettings {
            run_as,
            ldap_listen: ldap.map_or_else(Vec::new, |located| located.value),
            ldaps_listen: ldaps.map_or_else(Vec::new, |located| located.value),
            internal_networks,
            tls_certificate_path,
            tls_private_key_path,
            dird,
            audit,
            limits,
        })
    }

    /// The account ldap-front drops to after binding and reading the key.
    /// Spec: docs/50 §6.2, §6.4.
    #[must_use]
    pub const fn run_as(&self) -> Account {
        self.run_as
    }

    /// The StartTLS listeners (port 389); may be empty if LDAPS is
    /// configured. Spec: docs/50 §4.2.
    #[must_use]
    pub fn ldap_listen(&self) -> &[SocketAddr] {
        &self.ldap_listen
    }

    /// The LDAPS listeners (port 636); may be empty if StartTLS is
    /// configured. Spec: docs/50 §4.2.
    #[must_use]
    pub fn ldaps_listen(&self) -> &[SocketAddr] {
        &self.ldaps_listen
    }

    /// The zone table: the internal networks. Every listener address lies
    /// in one of them, and the front serves only clients whose source
    /// address does (crates/ldap-front).
    /// Spec: docs/50 §4.1; docs/52 §7 R14; A-102 on docs/questions/Q-469.
    #[must_use]
    pub fn internal_networks(&self) -> &[Network] {
        &self.internal_networks
    }

    /// Path of the operator-supplied DC certificate (DER).
    /// Spec: docs/50 R50-12, §5.3.
    #[must_use]
    pub fn tls_certificate_path(&self) -> &AbsolutePath {
        &self.tls_certificate_path
    }

    /// Path of the DC private key (DER; root:0400, read before the drop).
    /// Spec: docs/50 R50-12, §5.3, §6.4.
    #[must_use]
    pub fn tls_private_key_path(&self) -> &AbsolutePath {
        &self.tls_private_key_path
    }

    /// dird's `dird-ldap.sock` and uid. Spec: docs/50 §3.2, §4.2.
    #[must_use]
    pub fn dird(&self) -> &Endpoint {
        &self.dird
    }

    /// auditd's socket and uid. Spec: docs/50 §2.4, R50-17.
    #[must_use]
    pub fn audit(&self) -> &Endpoint {
        &self.audit
    }

    /// The timeouts and the dird deadline. Spec: docs/50 §3.6, §4.2.
    #[must_use]
    pub const fn limits(&self) -> &LdapFrontLimits {
        &self.limits
    }
}
