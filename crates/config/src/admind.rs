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
//! **keyadm and the socket group** (docs/51 §4.6, task A4): `keyadm_uid` is
//! the only peer uid for which admind forwards the operations reserved to
//! keyadm (`FetchApproved`, `Complete`, `ListPendingDestruction` — docs/51
//! §6, §7.3: "admind forwards only if the peer's uid = `keyadm_uid`"); it
//! takes part in the file's uid distinctness rule (one account per process,
//! docs/50 §2.4) and is never 0. `admin_socket_group` is the gid of the
//! group that may enter `admin.sock`'s directory (docs/50 §3.1: "mode 0750,
//! group = the channel's clients" — defence in depth only; the
//! authorization itself is Kerberos, docs/51 §5.1, §5.3); a numeric gid,
//! never 0 (docs/50 §7.1: no name-service lookup).
//!
//! **The minimum password length** (task A9; decision A-79 / P-24):
//! `min_password_length` is the least number of characters admind accepts
//! in a `SetPassword` — **required**, 12 ..= 256, never a default
//! ([`crate::limits::MIN_PASSWORD_LENGTH`]). [MS-SAMR] 3.1.1.7.2 item 3.2.1
//! takes it from the domain's Effective-MinimumPasswordLength; the phase-1
//! schema has no minPwdLength (docs/51 §11, §14), so admind's file carries
//! it.
//!
//! Spec: docs/50 R50-15, §2.4, §3.1, §3.2, §3.6, §6.4, §7.1; docs/51 §4.6,
//! §5.1, §6, §7.3, §11; [MS-SAMR] 3.1.1.7.2; A-79; P-24;
//! docs/questions/Q-220, Q-401.

use core::time::Duration;

use crate::error::Error;
use crate::format::Document;
use crate::limits::{FRAME_TIMEOUT_SECS, KEYD_DEADLINE_SECS, MIN_PASSWORD_LENGTH};
use crate::schema::{
    self, Account, Distinct, Endpoint, AUDITD_UID, AUDIT_SOCKET, DIRD_ADMIN_SOCKET, DIRD_UID,
    FRAME_TIMEOUT, KEYD_DEADLINE, KEYD_SOCKET, KEYD_UID, RUN_AS_GID, RUN_AS_UID,
};
use crate::value::{self, AbsolutePath};

/// Key: the local socket admind listens on. Spec: docs/50 §2.4, §3.1.
const ADMIN_SOCKET: &str = "admin_socket";
/// Key: the gid of the group admitted to `admin.sock`'s directory.
/// Spec: docs/51 §4.6 ("gid of the access group for `admin.sock`
/// (defence in depth, docs/50 §3.1)"); docs/50 §3.1.
const ADMIN_SOCKET_GROUP: &str = "admin_socket_group";
/// Key: the uid of keyadm, the only peer for which admind forwards the
/// operations reserved to keyadm. Spec: docs/51 §4.6, §6, §7.3.
const KEYADM_UID: &str = "keyadm_uid";
/// Key: the least number of characters of a password admind sets.
/// Spec: [MS-SAMR] 3.1.1.7.2 item 3.2.1; A-79; P-24.
const MIN_PASSWORD_LENGTH_KEY: &str = "min_password_length";

/// admind's settings, as parsed and validated from its file.
///
/// Spec: docs/50 R50-15, §2.4, §7.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmindSettings {
    run_as: Account,
    admin_socket: AbsolutePath,
    admin_socket_group: u32,
    keyadm_uid: u32,
    dird: Endpoint,
    keyd: Endpoint,
    audit: Endpoint,
    min_password_length: u32,
    frame_timeout: Duration,
    keyd_deadline: Duration,
}

impl AdmindSettings {
    /// The closed key table of admind's file. Spec: docs/50 R50-15.
    pub const KEYS: &'static [&'static str] = &[
        RUN_AS_UID,
        RUN_AS_GID,
        ADMIN_SOCKET,
        ADMIN_SOCKET_GROUP,
        KEYADM_UID,
        MIN_PASSWORD_LENGTH_KEY,
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
    /// `run_as_gid`, `admin_socket`, `admin_socket_group` (a gid, never 0),
    /// `keyadm_uid` (never 0, distinct from every other uid of the file),
    /// `min_password_length` (12 ..= 256, no default), `dird_admin_socket` +
    /// `dird_uid`, `keyd_socket` + `keyd_uid`, `audit_socket`,
    /// `auditd_uid`. Optional: `frame_timeout` (5s), `keyd_deadline` (2s).
    ///
    /// # Errors
    /// Any rule of the format or of this schema (see [`crate::ErrorKind`]).
    ///
    /// Spec: docs/50 R50-15, §2.4, §3.2, §3.6, §7.1; A-79; P-24.
    pub fn parse(input: &[u8]) -> Result<Self, Error> {
        let doc = Document::parse(input, Self::KEYS)?;
        let mut all = Distinct::default();
        let run_as = schema::account(&doc, &mut all)?;
        let admin_socket = schema::path(&doc, &mut all, ADMIN_SOCKET)?;
        // A gid: not part of the uid distinctness rule (as `run_as_gid`,
        // crate::schema::account), but never 0 or all-ones.
        let admin_socket_group = doc.required(ADMIN_SOCKET_GROUP, value::account_id)?.value;
        let keyadm_uid = schema::id(&doc, &mut all, KEYADM_UID)?;
        // Required, never defaulted (A-79: "a required configuration key").
        let min_password_length = doc
            .required(MIN_PASSWORD_LENGTH_KEY, |text| {
                value::bounded(text, MIN_PASSWORD_LENGTH)
            })?
            .value;
        let dird = schema::endpoint(&doc, &mut all, DIRD_ADMIN_SOCKET, DIRD_UID)?;
        let keyd = schema::endpoint(&doc, &mut all, KEYD_SOCKET, KEYD_UID)?;
        let audit = schema::endpoint(&doc, &mut all, AUDIT_SOCKET, AUDITD_UID)?;
        let frame_timeout = schema::duration(&doc, FRAME_TIMEOUT, FRAME_TIMEOUT_SECS)?;
        let keyd_deadline = schema::duration(&doc, KEYD_DEADLINE, KEYD_DEADLINE_SECS)?;
        Ok(AdmindSettings {
            run_as,
            admin_socket,
            admin_socket_group,
            keyadm_uid,
            dird,
            keyd,
            audit,
            min_password_length,
            frame_timeout,
            keyd_deadline,
        })
    }

    /// The least number of characters of a password admind sets (12 ..=
    /// 256). Spec: [MS-SAMR] 3.1.1.7.2 item 3.2.1; A-79; P-24.
    #[must_use]
    pub const fn min_password_length(&self) -> u32 {
        self.min_password_length
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

    /// The gid of the group admitted to `admin.sock`'s directory (defence
    /// in depth). Spec: docs/51 §4.6; docs/50 §3.1.
    #[must_use]
    pub const fn admin_socket_group(&self) -> u32 {
        self.admin_socket_group
    }

    /// keyadm's uid: the only peer for which admind forwards the
    /// operations reserved to keyadm. Spec: docs/51 §4.6, §6, §7.3.
    #[must_use]
    pub const fn keyadm_uid(&self) -> u32 {
        self.keyadm_uid
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
