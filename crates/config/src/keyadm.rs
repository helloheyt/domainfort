//! keyadm's configuration file.
//!
//! keyadm is the one-shot tier-0 key-administration tool: run by hand under
//! its own uid, which keyd maps to `Role::Admin`; it has no Kerberos client
//! and no access to dird (docs/50 §2.4; docs/51 §6; PENDING-OWNER A-57,
//! A-72). Its file names keyd's socket, the uid keyd must present in its
//! peer credentials (R50-3: "the client also verifies the server's uid" —
//! before anything is sent), and the client deadline; and — for the
//! commands that act on an approved request or sweep deleted accounts
//! (task A10: keyadm sends `FetchApproved` / `Complete` /
//! `ListPendingDestruction` to `admin.sock`, docs/51 §6) — admind's socket
//! and uid, an optional pair (both or neither; without it only `ceremony`
//! runs).
//!
//! There is no `run_as_uid` / `run_as_gid`: keyadm is not started as root to
//! drop privileges like a daemon (docs/50 §6.2); it is started directly as
//! its own account (docs/51 §4.3 step 11: "in the uid of keyadm =
//! Role::Admin") — docs/questions/Q-347 item 2.
//!
//! **No secrets.** keyadm handles none: keyd computes every key and returns
//! only kvnos (docs/10 §7, I1).
//!
//! Spec: docs/50 R50-3, R50-15, §2.4, §3.2, §3.6, §7.1; docs/51 §4.3 step 11,
//! §6; PENDING-OWNER A-57, A-60, A-72.

use core::time::Duration;

use crate::error::{Error, ErrorKind};
use crate::format::Document;
use crate::limits::KEYD_DEADLINE_SECS;
use crate::schema::{self, Distinct, Endpoint, KEYD_DEADLINE, KEYD_SOCKET, KEYD_UID};
use crate::value;

/// Key: path of `admin.sock` (admind's socket). Spec: docs/50 §2.4, §3.1;
/// docs/51 §6 (keyadm sends its requests to `admin.sock`).
const ADMIN_SOCKET: &str = "admin_socket";
/// Key: the uid admind runs as (verified by keyadm before it sends).
/// Spec: docs/50 R50-3, §3.2.
const ADMIND_UID: &str = "admind_uid";

/// keyadm's settings, as parsed and validated from its file.
///
/// Spec: docs/50 R50-15, §2.4, §7.1; docs/51 §6.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyadmSettings {
    keyd: Endpoint,
    keyd_deadline: Duration,
    admind: Option<Endpoint>,
}

impl KeyadmSettings {
    /// The closed key table of keyadm's file. Spec: docs/50 R50-15.
    pub const KEYS: &'static [&'static str] = &[
        KEYD_SOCKET,
        KEYD_UID,
        KEYD_DEADLINE,
        ADMIN_SOCKET,
        ADMIND_UID,
    ];

    /// Parses and validates keyadm's file. Required: `keyd_socket` +
    /// `keyd_uid` (never 0 — R50-3; the ipc-keyd client refuses a root
    /// server uid as well). Optional: `keyd_deadline` (2s, at most 2s);
    /// `admin_socket` + `admind_uid` (both or neither — `IncompletePair`;
    /// the uid never 0 and distinct from keyd's, the path distinct from
    /// keyd's socket).
    ///
    /// # Errors
    /// Any rule of the format or of this schema (see [`crate::ErrorKind`]).
    ///
    /// Spec: docs/50 R50-3, R50-15, §3.2, §3.6, §7.1.
    pub fn parse(input: &[u8]) -> Result<Self, Error> {
        let doc = Document::parse(input, Self::KEYS)?;
        let mut all = Distinct::default();
        let keyd = schema::endpoint(&doc, &mut all, KEYD_SOCKET, KEYD_UID)?;
        let keyd_deadline = schema::duration(&doc, KEYD_DEADLINE, KEYD_DEADLINE_SECS)?;
        // admind (task A10): both or neither (as dird's keyd pair, Q-385
        // item 1).
        let admin_socket = doc.optional(ADMIN_SOCKET, value::absolute_path)?;
        let admind_uid = doc.optional(ADMIND_UID, value::account_id)?;
        let admind = match (admin_socket, admind_uid) {
            (None, None) => None,
            (Some(socket), None) => {
                return Err(Error::at(
                    socket.line,
                    ADMIN_SOCKET,
                    ErrorKind::IncompletePair,
                ))
            }
            (None, Some(uid)) => {
                return Err(Error::at(uid.line, ADMIND_UID, ErrorKind::IncompletePair))
            }
            (Some(socket), Some(uid)) => {
                all.path(ADMIN_SOCKET, &socket.value, socket.line)?;
                all.id(ADMIND_UID, uid.value, uid.line)?;
                Some(Endpoint::from_parts(socket.value, uid.value))
            }
        };
        Ok(KeyadmSettings {
            keyd,
            keyd_deadline,
            admind,
        })
    }

    /// admind's socket and the uid admind must have, if configured (the
    /// commands that need an approved request or the tombstone listing).
    /// Spec: docs/50 R50-3, §3.2; docs/51 §6.
    #[must_use]
    pub fn admind(&self) -> Option<&Endpoint> {
        self.admind.as_ref()
    }

    /// keyd's socket and the uid keyd must have. Spec: docs/50 R50-3, §3.2.
    #[must_use]
    pub fn keyd(&self) -> &Endpoint {
        &self.keyd
    }

    /// Deadline for an answer from keyd. Spec: docs/50 §3.6 ("keyd: 2 s").
    #[must_use]
    pub const fn keyd_deadline(&self) -> Duration {
        self.keyd_deadline
    }
}
