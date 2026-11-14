//! keyadm's configuration file.
//!
//! keyadm is the one-shot tier-0 key-administration tool: run by hand under
//! its own uid, which keyd maps to `Role::Admin`; it has no Kerberos client
//! and no access to dird (docs/50 §2.4; docs/51 §6; PENDING-OWNER A-57,
//! A-72). Its file names keyd's socket, the uid keyd must present in its
//! peer credentials (R50-3: "the client also verifies the server's uid" —
//! before anything is sent), and the client deadline — and nothing else:
//! keyadm talks to **keyd only** (docs/51 §6; A-102, docs/52 §4.6). Its key
//! operations run the decisions dird registered in keyd, by decision id, and
//! its sweep executes the destroy decisions dird registered; the
//! `admin_socket` + `admind_uid` pair of task A10 (keyadm → admind → dird)
//! is gone with the channel (an unknown key is refused, docs/50 R50-15).
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
//! §6; PENDING-OWNER A-57, A-60, A-72; docs/52 §4.6 (A-102).

use core::time::Duration;

use crate::error::Error;
use crate::format::Document;
use crate::limits::KEYD_DEADLINE_SECS;
use crate::schema::{self, Distinct, Endpoint, KEYD_DEADLINE, KEYD_SOCKET, KEYD_UID};

/// keyadm's settings, as parsed and validated from its file.
///
/// Spec: docs/50 R50-15, §2.4, §7.1; docs/51 §6.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyadmSettings {
    keyd: Endpoint,
    keyd_deadline: Duration,
}

impl KeyadmSettings {
    /// The closed key table of keyadm's file. Spec: docs/50 R50-15.
    pub const KEYS: &'static [&'static str] = &[KEYD_SOCKET, KEYD_UID, KEYD_DEADLINE];

    /// Parses and validates keyadm's file. Required: `keyd_socket` +
    /// `keyd_uid` (never 0 — R50-3; the ipc-keyd client refuses a root
    /// server uid as well). Optional: `keyd_deadline` (2s, at most 2s).
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
        Ok(KeyadmSettings {
            keyd,
            keyd_deadline,
        })
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
