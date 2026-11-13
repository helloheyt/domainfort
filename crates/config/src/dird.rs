//! dird's configuration file.
//!
//! dird is the sole owner of the redb file and runs the LDAP engine (docs/50
//! R50-1, R50-2). It serves three channels — `dird-kdc.sock`,
//! `dird-ldap.sock`, `dird-admin.sock` — each admitting exactly one peer uid
//! (§3.2), loads the signed policy store (which carries the TierMap, A-36)
//! (§7.2), and maps LDAP peer addresses through its **own** zone table (§4.2).
//!
//! **No secrets.** The dirstore `IntegrityKey` is never a setting (docs/50
//! §7.4: "never in a readable file next to the DB"); its source is decided in
//! Q-213 (A-57) with the sealing mechanism of Q-212 (P-17), and is added to
//! this schema only when that is decided (docs/questions/Q-230 item 12).
//!
//! Spec: docs/50 R50-2, R50-15, §2.4, §3.2, §3.4, §4.2, §7.1, §7.2, §7.4.

use core::time::Duration;

use crate::error::{Error, ErrorKind};
use crate::format::Document;
use crate::limits::{Bound, FRAME_TIMEOUT_SECS};
use crate::schema::{
    self, Account, Distinct, Endpoint, AUDITD_UID, AUDIT_SOCKET, DIRD_ADMIN_SOCKET,
    DIRD_KDC_SOCKET, DIRD_LDAP_SOCKET, FRAME_TIMEOUT, INTERNAL_NETWORKS, POLICY_STORE_PATH,
    RUN_AS_GID, RUN_AS_UID,
};
use crate::value::{self, AbsolutePath, NamingContextLabels, Network};

/// Key: the realm. Spec: docs/50 §7.1; A-55 (must match the naming context).
const REALM: &str = "realm";
/// Key: the DN of the domain root. Spec: docs/50 §7.1 ("naming context
/// (A-53)").
const NAMING_CONTEXT: &str = "naming_context";
/// Key: the redb file dird alone opens. Spec: docs/50 R50-2, §2.4, §6.4.
const DATABASE_PATH: &str = "database_path";
/// Key: the only uid admitted on `dird-kdc.sock`. Spec: docs/50 §3.2.
const KDC_UID: &str = "kdc_uid";
/// Key: the only uid admitted on `dird-ldap.sock`. Spec: docs/50 §3.2.
const LDAP_FRONT_UID: &str = "ldap_front_uid";
/// Key: the only uid admitted on `dird-admin.sock`. Spec: docs/50 §3.2.
const ADMIND_UID: &str = "admind_uid";
/// Key: how long a `BeginView` snapshot stays pinned. Spec: docs/50 §3.4.
const VIEW_LIFETIME: &str = "view_lifetime";

/// Lifetime of a view pinned by `BeginView`: at most 5 s.
/// Spec: docs/50 §3.4 ("expires after ≤ 5 s (project choice)").
pub const VIEW_LIFETIME_SECS: Bound = Bound::up_to(5);

/// A channel dird serves: its socket path and the one peer uid admitted on it.
///
/// Spec: docs/50 §3.1 (a socket per server and channel), §3.2 ("dird-kdc.sock
/// ← kdc's uid only; dird-ldap.sock ← ldap-front; dird-admin.sock ← admind").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Channel {
    socket: AbsolutePath,
    peer_uid: u32,
}

impl Channel {
    /// The path dird listens on for this channel.
    #[must_use]
    pub fn socket(&self) -> &AbsolutePath {
        &self.socket
    }

    /// The only peer uid admitted; every other uid is closed and audited.
    #[must_use]
    pub const fn peer_uid(&self) -> u32 {
        self.peer_uid
    }
}

/// dird's settings, as parsed and validated from its file.
///
/// Spec: docs/50 R50-15, §2.4, §7.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirdSettings {
    run_as: Account,
    realm: String,
    naming_context: NamingContextLabels,
    database_path: AbsolutePath,
    policy_store_path: AbsolutePath,
    kdc_channel: Channel,
    ldap_channel: Channel,
    admin_channel: Option<Channel>,
    internal_networks: Vec<Network>,
    audit: Endpoint,
    frame_timeout: Duration,
    view_lifetime: Duration,
}

/// A served channel from its socket key and peer-uid key.
fn channel(
    doc: &Document<'_>,
    all: &mut Distinct,
    socket_key: &'static str,
    uid_key: &'static str,
) -> Result<Channel, Error> {
    let socket = schema::path(doc, all, socket_key)?;
    let peer_uid = schema::id(doc, all, uid_key)?;
    Ok(Channel { socket, peer_uid })
}

impl DirdSettings {
    /// The closed key table of dird's file. Spec: docs/50 R50-15.
    pub const KEYS: &'static [&'static str] = &[
        RUN_AS_UID,
        RUN_AS_GID,
        REALM,
        NAMING_CONTEXT,
        DATABASE_PATH,
        POLICY_STORE_PATH,
        DIRD_KDC_SOCKET,
        KDC_UID,
        DIRD_LDAP_SOCKET,
        LDAP_FRONT_UID,
        DIRD_ADMIN_SOCKET,
        ADMIND_UID,
        INTERNAL_NETWORKS,
        AUDIT_SOCKET,
        AUDITD_UID,
        FRAME_TIMEOUT,
        VIEW_LIFETIME,
    ];

    /// Parses and validates dird's file. Required: `run_as_uid`,
    /// `run_as_gid`, `realm`, `naming_context`, `database_path`,
    /// `policy_store_path`, `dird_kdc_socket` with `kdc_uid`,
    /// `dird_ldap_socket` with `ldap_front_uid`, `audit_socket`, `auditd_uid`.
    /// Optional: `dird_admin_socket` with `admind_uid` (both or neither —
    /// admind is blocked on Q-220, task P13), `internal_networks` (absent ⇒
    /// every peer is `External`), `frame_timeout` (5s), `view_lifetime` (5s).
    ///
    /// # Errors
    /// Any rule of the format or of this schema (see [`crate::ErrorKind`]).
    ///
    /// Spec: docs/50 R50-15, §3.2, §3.4, §4.2, §7.1, §7.2.
    pub fn parse(input: &[u8]) -> Result<Self, Error> {
        let doc = Document::parse(input, Self::KEYS)?;
        let mut all = Distinct::default();
        let run_as = schema::account(&doc, &mut all)?;
        let realm = doc.required(REALM, value::realm)?.value;
        let naming_context = doc.required(NAMING_CONTEXT, value::naming_context)?.value;
        let database_path = schema::path(&doc, &mut all, DATABASE_PATH)?;
        let policy_store_path = schema::path(&doc, &mut all, POLICY_STORE_PATH)?;
        let kdc_channel = channel(&doc, &mut all, DIRD_KDC_SOCKET, KDC_UID)?;
        let ldap_channel = channel(&doc, &mut all, DIRD_LDAP_SOCKET, LDAP_FRONT_UID)?;
        let admin_socket = doc.optional(DIRD_ADMIN_SOCKET, value::absolute_path)?;
        let admin_uid = doc.optional(ADMIND_UID, value::account_id)?;
        let admin_channel = match (admin_socket, admin_uid) {
            (None, None) => None,
            (Some(socket), None) => {
                return Err(Error::at(
                    socket.line,
                    DIRD_ADMIN_SOCKET,
                    ErrorKind::IncompletePair,
                ))
            }
            (None, Some(uid)) => {
                return Err(Error::at(uid.line, ADMIND_UID, ErrorKind::IncompletePair))
            }
            (Some(socket), Some(uid)) => {
                all.path(DIRD_ADMIN_SOCKET, &socket.value, socket.line)?;
                all.id(ADMIND_UID, uid.value, uid.line)?;
                Some(Channel {
                    socket: socket.value,
                    peer_uid: uid.value,
                })
            }
        };
        let internal_networks = doc
            .optional(INTERNAL_NETWORKS, |text| value::list(text, value::network))?
            .map_or_else(Vec::new, |located| located.value);
        let audit = schema::endpoint(&doc, &mut all, AUDIT_SOCKET, AUDITD_UID)?;
        let frame_timeout = schema::duration(&doc, FRAME_TIMEOUT, FRAME_TIMEOUT_SECS)?;
        let view_lifetime = schema::duration(&doc, VIEW_LIFETIME, VIEW_LIFETIME_SECS)?;
        Ok(DirdSettings {
            run_as,
            realm,
            naming_context,
            database_path,
            policy_store_path,
            kdc_channel,
            ldap_channel,
            admin_channel,
            internal_networks,
            audit,
            frame_timeout,
            view_lifetime,
        })
    }

    /// The account dird drops to. Spec: docs/50 §6.1, §6.4.
    #[must_use]
    pub const fn run_as(&self) -> Account {
        self.run_as
    }

    /// The realm (checked against the naming context by crates/ldap, A-55).
    /// Spec: docs/50 §7.1.
    #[must_use]
    pub fn realm(&self) -> &str {
        &self.realm
    }

    /// The naming context's labels, for `directory_pip::NamingContext::new`.
    /// Spec: docs/50 §7.1; A-53.
    #[must_use]
    pub fn naming_context(&self) -> &NamingContextLabels {
        &self.naming_context
    }

    /// The redb file. Spec: docs/50 R50-2, §6.4.
    #[must_use]
    pub fn database_path(&self) -> &AbsolutePath {
        &self.database_path
    }

    /// The signed policy store (rules, anonymous allowlist, TierMap — A-36).
    /// Spec: docs/50 §7.2.
    #[must_use]
    pub fn policy_store_path(&self) -> &AbsolutePath {
        &self.policy_store_path
    }

    /// `dird-kdc.sock` and kdc's uid. Spec: docs/50 §3.2, §3.4.
    #[must_use]
    pub fn kdc_channel(&self) -> &Channel {
        &self.kdc_channel
    }

    /// `dird-ldap.sock` and ldap-front's uid. Spec: docs/50 §3.2, §4.2.
    #[must_use]
    pub fn ldap_channel(&self) -> &Channel {
        &self.ldap_channel
    }

    /// `dird-admin.sock` and admind's uid, when configured. Spec: docs/50
    /// §3.2; Q-220.
    #[must_use]
    pub fn admin_channel(&self) -> Option<&Channel> {
        self.admin_channel.as_ref()
    }

    /// dird's zone table: peers inside these networks are `Internal`, all
    /// others `External`. Spec: docs/50 §4.2.
    #[must_use]
    pub fn internal_networks(&self) -> &[Network] {
        &self.internal_networks
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

    /// How long a pinned view lives. Spec: docs/50 §3.4.
    #[must_use]
    pub const fn view_lifetime(&self) -> Duration {
        self.view_lifetime
    }
}
