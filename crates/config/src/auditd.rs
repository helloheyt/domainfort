//! auditd's configuration file.
//!
//! auditd listens on `audit.sock`, appends every daemon's events to one
//! hash-chained file, and sets each record's source **from the connection's
//! uid**, never from the event body (docs/50 R50-17, §3.2, §8.1). Its file
//! names the socket, the audit file, the `uid → source` map, the account to
//! drop to, and the frame timeout.
//!
//! **No secrets** — the hash chain is unsigned in phase 1 (no HSM, Q-212;
//! docs/50 §8.1), so there is no signing key to point to.
//!
//! Spec: docs/50 R50-17, R50-15, §2.4, §3.2, §3.6, §7.1, §8.1.

use core::time::Duration;

use crate::error::Error;
use crate::format::Document;
use crate::limits::FRAME_TIMEOUT_SECS;
use crate::schema::{self, Account, Distinct, AUDIT_SOCKET, FRAME_TIMEOUT, RUN_AS_GID, RUN_AS_UID};
use crate::value::{self, AbsolutePath};

/// Key: the append-only, hash-chained audit file. Spec: docs/50 §2.4, §6.4,
/// §8.1.
const AUDIT_LOG_PATH: &str = "audit_log_path";
/// Key: the `uid → source` map. Spec: docs/50 §3.2.
const UID_SOURCES: &str = "uid_sources";

/// The daemon an audit connection comes from, set from its uid.
///
/// Spec: docs/50 §3.2 ("auditd: every service uid, each marked as the event
/// source — the source is set from the uid, not from the event body"), §8.1
/// ("every daemon writes to `audit.sock` only"), §2.4 (the processes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditSource {
    /// keyd (`keyd::AuditRecord`; auditd accepts the `Keyd` shape only from
    /// this source — docs/questions/Q-341).
    Keyd,
    /// dird (the LDAP engine's `Outcome.audit`, R49-14, and the admin-plane
    /// `DirAdmin` events, docs/51 §5.7; auditd accepts the `Ldap` and
    /// `DirAdmin` shapes only from this source — docs/questions/Q-341).
    Dird,
    /// kdc (`kdc::AuditEvent`; auditd accepts the `Kdc` shape only from this
    /// source — docs/questions/Q-341).
    Kdc,
    /// ldap-front.
    LdapFront,
    /// admind (its `Admind` events, which auditd accepts only from this
    /// source — docs/51 §5.7 item 3, docs/questions/Q-341).
    Admind,
    /// dnsd, the DNS front (only `WindowSummary` counters — docs/54 §9; no
    /// shape is bound to it). Spec: docs/54 §4.3, §9; docs/questions/Q-619
    /// item 2, Q-950 (A-157), Q-960.
    Dnsd,
    /// kpasswd-front (no events — docs/53 §9; no shape is bound to it).
    /// Spec: docs/53 §9; docs/questions/Q-955 item 1 (A-158), Q-960.
    KpasswdFront,
}

/// The accepted spellings of [`AuditSource`]: the process names of docs/50
/// §2.4, docs/54 §4.3 (`dnsd`) and docs/53 (`kpasswd-front`). Spec: docs/50
/// §2.4, §3.2; docs/54 §4.3; docs/53 §9.
const SOURCE_NAMES: &[(&str, AuditSource)] = &[
    ("keyd", AuditSource::Keyd),
    ("dird", AuditSource::Dird),
    ("kdc", AuditSource::Kdc),
    ("ldap-front", AuditSource::LdapFront),
    ("admind", AuditSource::Admind),
    ("dnsd", AuditSource::Dnsd),
    ("kpasswd-front", AuditSource::KpasswdFront),
];

/// auditd's static `uid → source` map.
///
/// Invariants (checked when the file is parsed; there is no other
/// constructor): at least one entry; uid 0 never mapped; each uid one source;
/// each source at most one uid; auditd's own uid not mapped
/// (docs/questions/Q-230 items 5, 6). An unmapped uid is refused.
///
/// Spec: docs/50 R50-3 (applied to auditd's channel), §3.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceMap {
    entries: Vec<(u32, AuditSource)>,
}

impl SourceMap {
    /// The source of `uid`, or `None` if it is not mapped. `source_of(0)` is
    /// always `None`.
    #[must_use]
    pub fn source_of(&self, uid: u32) -> Option<AuditSource> {
        self.entries
            .iter()
            .find(|(mapped, _)| *mapped == uid)
            .map(|&(_, source)| source)
    }

    /// The entries, in file order.
    pub fn iter(&self) -> impl Iterator<Item = (u32, AuditSource)> + '_ {
        self.entries.iter().copied()
    }

    /// The number of mapped uids (at least 1).
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Always `false`: an empty map is rejected.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// auditd's settings, as parsed and validated from its file.
///
/// Spec: docs/50 R50-15, §2.4, §7.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditdSettings {
    run_as: Account,
    audit_socket: AbsolutePath,
    audit_log_path: AbsolutePath,
    uid_sources: SourceMap,
    frame_timeout: Duration,
}

impl AuditdSettings {
    /// The closed key table of auditd's file. Spec: docs/50 R50-15.
    pub const KEYS: &'static [&'static str] = &[
        RUN_AS_UID,
        RUN_AS_GID,
        AUDIT_SOCKET,
        AUDIT_LOG_PATH,
        UID_SOURCES,
        FRAME_TIMEOUT,
    ];

    /// Parses and validates auditd's file. Required: `run_as_uid`,
    /// `run_as_gid`, `audit_socket`, `audit_log_path`, `uid_sources`.
    /// Optional: `frame_timeout` (5s).
    ///
    /// # Errors
    /// Any rule of the format or of this schema (see [`crate::ErrorKind`]).
    ///
    /// Spec: docs/50 R50-15, R50-17, §3.2, §3.6, §7.1.
    pub fn parse(input: &[u8]) -> Result<Self, Error> {
        let doc = Document::parse(input, Self::KEYS)?;
        let mut all = Distinct::default();
        let run_as = schema::account(&doc, &mut all)?;
        let audit_socket = schema::path(&doc, &mut all, AUDIT_SOCKET)?;
        let audit_log_path = schema::path(&doc, &mut all, AUDIT_LOG_PATH)?;
        let sources = doc.required(UID_SOURCES, |text| value::id_map(text, SOURCE_NAMES))?;
        for &(uid, _) in &sources.value {
            all.id(UID_SOURCES, uid, sources.line)?;
        }
        let frame_timeout = schema::duration(&doc, FRAME_TIMEOUT, FRAME_TIMEOUT_SECS)?;
        Ok(AuditdSettings {
            run_as,
            audit_socket,
            audit_log_path,
            uid_sources: SourceMap {
                entries: sources.value,
            },
            frame_timeout,
        })
    }

    /// The account auditd drops to. Spec: docs/50 §6.1, §6.4.
    #[must_use]
    pub const fn run_as(&self) -> Account {
        self.run_as
    }

    /// The path auditd listens on. Spec: docs/50 §2.4, §3.1.
    #[must_use]
    pub fn audit_socket(&self) -> &AbsolutePath {
        &self.audit_socket
    }

    /// The append-only audit file. Spec: docs/50 §2.4, §8.1.
    #[must_use]
    pub fn audit_log_path(&self) -> &AbsolutePath {
        &self.audit_log_path
    }

    /// The `uid → source` map. Spec: docs/50 §3.2.
    #[must_use]
    pub fn uid_sources(&self) -> &SourceMap {
        &self.uid_sources
    }

    /// How long a started frame may take to arrive. Spec: docs/50 §3.6.
    #[must_use]
    pub const fn frame_timeout(&self) -> Duration {
        self.frame_timeout
    }
}
