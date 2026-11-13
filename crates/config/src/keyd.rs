//! keyd's configuration file.
//!
//! keyd holds every long-term key, has no network socket and listens only on
//! `keyd.sock` (docs/50 §2.4). Its file names the realm, the socket, the static
//! `uid → Role` map that is the **only** source of a caller's role (R50-3), the
//! key-store kind (R50-18), the audit endpoint, the account to drop to, and the
//! §3.6 limits that docs/50 gives a value for.
//!
//! **No secrets.** No key, password or seed is ever a setting: keys live in
//! keyd's store, opened at start (docs/50 §7.3; docs/10 §11), and the
//! configuration names at most a path to a protected file (docs/50 §7.1: "no
//! secrets in the configuration — only paths to protected files"; docs/21 D95).
//! The `KeydConfig` tunables of the keyd library (enctypes, clock skew, token
//! lifetime, table bounds) keep their library defaults and are not settings
//! here (docs/questions/Q-230 item 12).
//!
//! Spec: docs/50 R50-3, R50-6, R50-15, R50-18, §2.4, §3.2, §3.6, §7.1, §7.3.

use core::time::Duration;

use crate::error::Error;
use crate::format::Document;
use crate::limits::{Bound, FRAME_TIMEOUT_SECS};
use crate::schema::{
    self, Account, Distinct, Endpoint, AUDITD_UID, AUDIT_SOCKET, FRAME_TIMEOUT, KEYD_SOCKET,
    RUN_AS_GID, RUN_AS_UID,
};
use crate::value::{self, AbsolutePath};

/// Key: the realm keyd serves (`KeydConfig::new(realm)`). Spec: docs/50 §7.1.
const REALM: &str = "realm";
/// Key: the `uid → Role` map. Spec: docs/50 R50-3, §3.2.
const UID_ROLES: &str = "uid_roles";
/// Key: the key-store kind. Spec: docs/50 R50-18, §7.3.
const KEY_STORE: &str = "key_store";
/// Key: connections allowed per mapped uid. Spec: docs/50 §3.6.
const MAX_CONNECTIONS_PER_UID: &str = "max_connections_per_uid";

/// Connections one mapped uid may hold open at once: at most 8.
/// Spec: docs/50 §3.6 ("a connection quota per uid (for example kdc ≤ 8)");
/// docs/questions/Q-230 item 4.
pub const MAX_CONNECTIONS_PER_UID_BOUND: Bound = Bound::up_to(8);

/// The role a mapped uid holds — the names of the keyd library's `Role` enum.
///
/// This crate does not depend on keyd: the daemon maps each name to
/// `keyd::Role` (`Kdc`, `Directory`, `Admin`, `Ldap`; crates/keyd authz.rs) and
/// builds `CallerId { uid, role }` once per connection (docs/50 §3.2). A role
/// added to keyd later (docs/questions/Q-220, A-57) is added here with it.
///
/// Spec: docs/50 R50-3, §3.2; docs/10 §2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleName {
    /// `Role::Kdc` — the kdc process (docs/50 §2.4).
    Kdc,
    /// `Role::Directory` — admind (docs/50 §2.4; Q-220 A-57).
    Directory,
    /// `Role::Admin` — the one-off `keyadm` tool (docs/50 §2.4; Q-220 A-57).
    Admin,
    /// `Role::Ldap` — dird, from L7 on (docs/50 §2.3, P-13).
    Ldap,
}

/// The accepted spellings of [`RoleName`], exactly as the keyd library names
/// its `Role` variants (case-sensitive). Spec: docs/50 §3.2; crates/keyd
/// authz.rs.
const ROLE_NAMES: &[(&str, RoleName)] = &[
    ("Kdc", RoleName::Kdc),
    ("Directory", RoleName::Directory),
    ("Admin", RoleName::Admin),
    ("Ldap", RoleName::Ldap),
];

/// keyd's static `uid → Role` map.
///
/// Invariants (checked when the file is parsed; there is no other
/// constructor): at least one entry; uid 0 is never mapped ("the host's root
/// does not get a Role for free"); each uid exactly one role ("a uid that
/// appears twice ⇒ keyd does not start"); each role at most one uid
/// (docs/questions/Q-230 item 5); no mapped uid equals another uid of the file
/// (keyd's own, auditd's).
///
/// An unmapped uid gets no role: the daemon closes the connection and audits
/// it (docs/50 §3.2).
///
/// Spec: docs/50 R50-3, §3.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleMap {
    entries: Vec<(u32, RoleName)>,
}

impl RoleMap {
    /// The role of `uid`, or `None` if it is not mapped. `role_of(0)` is
    /// always `None`.
    #[must_use]
    pub fn role_of(&self, uid: u32) -> Option<RoleName> {
        self.entries
            .iter()
            .find(|(mapped, _)| *mapped == uid)
            .map(|&(_, role)| role)
    }

    /// The entries, in file order.
    pub fn iter(&self) -> impl Iterator<Item = (u32, RoleName)> + '_ {
        self.entries.iter().copied()
    }

    /// The number of mapped uids (at least 1).
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Always `false`: an empty map is rejected (Q-230 item 5).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Where keyd's keys are held.
///
/// Phase 1 has only one store: the in-memory store of the keyd library, which
/// loses every key on restart and refuses krbtgt unless built for insecure
/// development (A-16). Until the owner decides the persistent sealed store
/// (Q-212 → P-17), keyd runs **only** in this mode, and the operator must say
/// so explicitly with `key_store = insecure-development` (R50-18: "clearly
/// marked"). A production kind is added here when P-17 is decided.
///
/// Spec: docs/50 R50-18, §7.3; docs/questions/Q-230 item 10.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyStoreKind {
    /// The in-memory, insecure development store (docs/50 §7.3).
    InsecureDevelopment,
}

/// The accepted spellings of [`KeyStoreKind`]. Spec: docs/50 R50-18.
const KEY_STORE_KINDS: &[(&str, KeyStoreKind)] =
    &[("insecure-development", KeyStoreKind::InsecureDevelopment)];

/// keyd's settings, as parsed and validated from its file.
///
/// Spec: docs/50 R50-15, §2.4, §7.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeydSettings {
    run_as: Account,
    realm: String,
    keyd_socket: AbsolutePath,
    uid_roles: RoleMap,
    key_store: KeyStoreKind,
    audit: Endpoint,
    frame_timeout: Duration,
    max_connections_per_uid: u32,
}

impl KeydSettings {
    /// The closed key table of keyd's file. Spec: docs/50 R50-15.
    pub const KEYS: &'static [&'static str] = &[
        RUN_AS_UID,
        RUN_AS_GID,
        REALM,
        KEYD_SOCKET,
        UID_ROLES,
        KEY_STORE,
        AUDIT_SOCKET,
        AUDITD_UID,
        FRAME_TIMEOUT,
        MAX_CONNECTIONS_PER_UID,
    ];

    /// Parses and validates keyd's file. Required: `run_as_uid`,
    /// `run_as_gid`, `realm`, `keyd_socket`, `uid_roles`, `key_store`,
    /// `audit_socket`, `auditd_uid`. Optional (docs/50 value as default and
    /// ceiling): `frame_timeout` (5s), `max_connections_per_uid` (8).
    ///
    /// # Errors
    /// Any rule of the format or of this schema (see [`crate::ErrorKind`]).
    ///
    /// Spec: docs/50 R50-3, R50-15, R50-18, §3.2, §3.6, §7.1.
    pub fn parse(input: &[u8]) -> Result<Self, Error> {
        let doc = Document::parse(input, Self::KEYS)?;
        let mut all = Distinct::default();
        let run_as = schema::account(&doc, &mut all)?;
        let realm = doc.required(REALM, value::realm)?.value;
        let keyd_socket = schema::path(&doc, &mut all, KEYD_SOCKET)?;
        let audit = schema::endpoint(&doc, &mut all, AUDIT_SOCKET, AUDITD_UID)?;
        let roles = doc.required(UID_ROLES, |text| value::id_map(text, ROLE_NAMES))?;
        for &(uid, _) in &roles.value {
            all.id(UID_ROLES, uid, roles.line)?;
        }
        let key_store = doc
            .required(KEY_STORE, |text| value::named(text, KEY_STORE_KINDS))?
            .value;
        let frame_timeout = schema::duration(&doc, FRAME_TIMEOUT, FRAME_TIMEOUT_SECS)?;
        let max_connections_per_uid =
            schema::limit(&doc, MAX_CONNECTIONS_PER_UID, MAX_CONNECTIONS_PER_UID_BOUND)?.value;
        Ok(KeydSettings {
            run_as,
            realm,
            keyd_socket,
            uid_roles: RoleMap {
                entries: roles.value,
            },
            key_store,
            audit,
            frame_timeout,
            max_connections_per_uid,
        })
    }

    /// The account keyd drops to. Spec: docs/50 §6.1, §6.4.
    #[must_use]
    pub const fn run_as(&self) -> Account {
        self.run_as
    }

    /// The realm (`KeydConfig::new(realm)`). Spec: docs/50 §7.1.
    #[must_use]
    pub fn realm(&self) -> &str {
        &self.realm
    }

    /// The path keyd listens on. Spec: docs/50 §2.4, §3.1.
    #[must_use]
    pub fn keyd_socket(&self) -> &AbsolutePath {
        &self.keyd_socket
    }

    /// The `uid → Role` map. Spec: docs/50 R50-3, §3.2.
    #[must_use]
    pub fn uid_roles(&self) -> &RoleMap {
        &self.uid_roles
    }

    /// The key-store kind. Spec: docs/50 R50-18, §7.3.
    #[must_use]
    pub const fn key_store(&self) -> KeyStoreKind {
        self.key_store
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

    /// Connections one mapped uid may hold. Spec: docs/50 §3.6.
    #[must_use]
    pub const fn max_connections_per_uid(&self) -> u32 {
        self.max_connections_per_uid
    }
}
