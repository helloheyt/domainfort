//! admind's configuration file.
//!
//! admind is the management plane: it listens on the local `admin.sock` and
//! talks to dird (writes, over `dird-admin.sock`), to keyd as `Role::Directory`
//! (`set_secret`, `verify_secret`) and to auditd (docs/50 §2.4). The daemon
//! itself is blocked on Q-220 (task P13): how administrators authenticate to
//! `admin.sock` (A-57: Kerberos through a dedicated keyd role, two uids for
//! admind and keyadm) is not decided in a form this schema can carry, so the
//! file has no caller setting for `admin.sock` yet (docs/questions/Q-230
//! item 12).
//!
//! **No secrets.** Passwords pass through admind in memory only (`mlockall`,
//! docs/50 §6.4) and never appear in its configuration.
//!
//! Spec: docs/50 R50-15, §2.4, §3.1, §3.2, §3.6, §6.4, §7.1; docs/questions/
//! Q-220.

use core::time::Duration;

use crate::error::Error;
use crate::format::Document;
use crate::limits::{FRAME_TIMEOUT_SECS, KEYD_DEADLINE_SECS};
use crate::schema::{
    self, Account, Distinct, Endpoint, AUDITD_UID, AUDIT_SOCKET, DIRD_ADMIN_SOCKET, DIRD_UID,
    FRAME_TIMEOUT, KEYD_DEADLINE, KEYD_SOCKET, KEYD_UID, RUN_AS_GID, RUN_AS_UID,
};
use crate::value::AbsolutePath;

/// Key: the local socket admind listens on. Spec: docs/50 §2.4, §3.1.
const ADMIN_SOCKET: &str = "admin_socket";

/// admind's settings, as parsed and validated from its file.
///
/// Spec: docs/50 R50-15, §2.4, §7.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmindSettings {
    run_as: Account,
    admin_socket: AbsolutePath,
    dird: Endpoint,
    keyd: Endpoint,
    audit: Endpoint,
    frame_timeout: Duration,
    keyd_deadline: Duration,
}

impl AdmindSettings {
    /// The closed key table of admind's file. Spec: docs/50 R50-15.
    pub const KEYS: &'static [&'static str] = &[
        RUN_AS_UID,
        RUN_AS_GID,
        ADMIN_SOCKET,
        DIRD_ADMIN_SOCKET,
        DIRD_UID,
        KEYD_SOCKET,
        KEYD_UID,
        AUDIT_SOCKET,
        AUDITD_UID,
        FRAME_TIMEOUT,
        KEYD_DEADLINE,
    ];

    /// Parses and validates admind's file. Required: `run_as_uid`,
    /// `run_as_gid`, `admin_socket`, `dird_admin_socket` + `dird_uid`,
    /// `keyd_socket` + `keyd_uid`, `audit_socket`, `auditd_uid`. Optional:
    /// `frame_timeout` (5s), `keyd_deadline` (2s).
    ///
    /// # Errors
    /// Any rule of the format or of this schema (see [`crate::ErrorKind`]).
    ///
    /// Spec: docs/50 R50-15, §2.4, §3.2, §3.6, §7.1.
    pub fn parse(input: &[u8]) -> Result<Self, Error> {
        let doc = Document::parse(input, Self::KEYS)?;
        let mut all = Distinct::default();
        let run_as = schema::account(&doc, &mut all)?;
        let admin_socket = schema::path(&doc, &mut all, ADMIN_SOCKET)?;
        let dird = schema::endpoint(&doc, &mut all, DIRD_ADMIN_SOCKET, DIRD_UID)?;
        let keyd = schema::endpoint(&doc, &mut all, KEYD_SOCKET, KEYD_UID)?;
        let audit = schema::endpoint(&doc, &mut all, AUDIT_SOCKET, AUDITD_UID)?;
        let frame_timeout = schema::duration(&doc, FRAME_TIMEOUT, FRAME_TIMEOUT_SECS)?;
        let keyd_deadline = schema::duration(&doc, KEYD_DEADLINE, KEYD_DEADLINE_SECS)?;
        Ok(AdmindSettings {
            run_as,
            admin_socket,
            dird,
            keyd,
            audit,
            frame_timeout,
            keyd_deadline,
        })
    }

    /// The account admind drops to. Spec: docs/50 §6.1, §6.4.
    #[must_use]
    pub const fn run_as(&self) -> Account {
        self.run_as
    }

    /// The local socket admind listens on. Spec: docs/50 §2.4.
    #[must_use]
    pub fn admin_socket(&self) -> &AbsolutePath {
        &self.admin_socket
    }

    /// dird's `dird-admin.sock` and uid. Spec: docs/50 §2.3, §3.2.
    #[must_use]
    pub fn dird(&self) -> &Endpoint {
        &self.dird
    }

    /// keyd's socket and uid (admind holds `Role::Directory`). Spec: docs/50
    /// §2.4, §3.2.
    #[must_use]
    pub fn keyd(&self) -> &Endpoint {
        &self.keyd
    }

    /// auditd's socket and uid. Spec: docs/50 §2.4, R50-17.
    #[must_use]
    pub fn audit(&self) -> &Endpoint {
        &self.audit
    }

    /// How long a started frame may take to arrive. Spec: docs/50 §3.6.
    #[must_use]
    pub const fn frame_timeout(&self) -> Duration {
        self.frame_timeout
    }

    /// Deadline for an answer from keyd. Spec: docs/50 §3.6.
    #[must_use]
    pub const fn keyd_deadline(&self) -> Duration {
        self.keyd_deadline
    }
}
