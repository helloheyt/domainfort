//! The start-up steps `main` runs before the runtime exists: reading the
//! configuration, the development integrity key and the development policy
//! (all as root, before the drop), the socket directory, the hardening plan,
//! and the serving parameters.
//!
//! Spec: docs/50 R50-2, R50-14, R50-15, §3.1, §6.1, §6.2, §6.4, §7.1, §7.2,
//! §7.4, §7.5; docs/questions/Q-213, Q-219 (A-57), Q-230 (A-60), Q-235
//! (A-61), Q-270.

use crate::admin_service::{
    AdminParams, DecisionAckDeadline, KeydTicketVerifier, TicketVerifier, VerifierFactory,
    ADMIN_QUEUE_CAPACITY, DESTROY_RECONCILE_INTERVAL, MAX_ADMIN_CONNECTIONS,
};
use crate::audit_link::AuditEndpoint;
use crate::clock::SharedClock;
use crate::daemon::{
    DaemonParams, ENGINE_QUEUE_CAPACITY, LDAP_QUEUE_CAPACITY, MAX_KDC_CONNECTIONS,
    MAX_LDAP_SESSIONS, MAX_OPEN_VIEWS,
};
use crate::policy::{read_file, DevelopmentPolicy, LoadError, PolicyError};
use crate::zones::ZoneTable;
use config::{DirdSettings, IntegrityKeySource, PolicyStoreFormat};
use core::fmt;
use daemon_sandbox::{HardeningPlan, PlanError, ProcessIdentity};
use directory_pip::NamingContext;
use dirstore::{IntegrityKey, INTEGRITY_KEY_LEN};
use ipc_audit::WindowConfig;
use keyd_types::KeydConfig;
use krb_proto::Realm;
use protected_file::{FileFacts, OpenError, Refusal, PERMISSION_BITS};
use std::io::Read;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;
use zeroize::Zeroizing;

/// The owner of the files dird reads before its drop: root.
/// Spec: docs/50 §7.1 ("file root:0644"), §7.4; Q-270 item 1.
const ROOT_UID: u32 = 0;

/// The permission bits of the development integrity-key file: exactly 0400.
/// Spec: docs/50 §7.4, R50-12 ("the file 0400"); docs/questions/Q-270
/// item 1.
const INTEGRITY_KEY_FILE_MODE: u32 = 0o400;

/// Open files beyond the kdc's connection quota and the LDAP session bound:
/// stdio, the two listeners, the audit connection, the redb file, the
/// runtime's own descriptors, and room for connections accepted only to be
/// closed (refused peers). Project choice (docs/50 §6.1: "nofile according
/// to the connection quotas").
pub const OPEN_FILES_HEADROOM: u64 = 32;

/// Mode of the socket directory: owner all, group enter, other nothing.
/// Spec: docs/50 §3.1 ("each socket in its own directory, owned by the
/// server's uid, mode 0750").
pub const SOCKET_DIRECTORY_MODE: u32 = 0o750;

/// Why start-up failed. Carries no file content (docs/50 §8.2; the
/// configuration's own errors never echo a value, A-60; the key never
/// appears anywhere).
/// Spec: docs/50 §7.5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartupError {
    /// The configuration file could not be opened or read.
    ConfigUnreadable,
    /// The configuration file is not a regular file (a symbolic link
    /// included) owned by root and writable only by its owner (docs/50
    /// §7.1: "file root:0644").
    ConfigPermissions,
    /// The configuration file is larger than the format allows.
    ConfigTooLarge,
    /// The configuration was refused (`config::Error`, without the value).
    Config(String),
    /// The realm is not a valid KerberosString.
    Realm,
    /// The naming context was refused by directory-pip's label rules.
    NamingContext,
    /// The integrity-key file could not be opened or read.
    KeyUnreadable,
    /// The integrity-key file is not a regular file owned by root with mode
    /// 0400 (Q-270 item 1).
    KeyPermissions,
    /// The integrity-key file does not hold exactly 32 octets.
    KeyLength,
    /// The policy file could not be opened or read.
    PolicyUnreadable,
    /// The policy file is not a regular file owned by root, not writable by
    /// group or others.
    PolicyPermissions,
    /// The policy file was refused.
    Policy(PolicyError),
    /// The socket path has no parent directory.
    SocketDirectory,
    /// The socket directory exists but is not a directory owned by dird's
    /// account with no group write and no access for others.
    SocketDirectoryPermissions,
    /// The socket directory could not be created or handed to dird's
    /// account.
    SocketDirectoryCreate,
    /// The provisioning manifest was refused (unreadable, not root-owned,
    /// writable by group or others, too large, or its content).
    Manifest(String),
    /// The admin channel is configured without the settings it requires
    /// (the configuration refuses this; kept as a fail-closed guard).
    AdminSettings,
}

impl fmt::Display for StartupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StartupError::ConfigUnreadable => f.write_str("configuration file unreadable"),
            StartupError::ConfigPermissions => f.write_str(
                "configuration file must be a regular file owned by root, not writable by group or others",
            ),
            StartupError::ConfigTooLarge => f.write_str("configuration file too large"),
            StartupError::Config(error) => write!(f, "configuration refused: {error}"),
            StartupError::Realm => f.write_str("realm is not a valid Kerberos realm"),
            StartupError::NamingContext => f.write_str("naming context refused"),
            StartupError::KeyUnreadable => f.write_str("integrity key file unreadable"),
            StartupError::KeyPermissions => f.write_str(
                "integrity key file must be a regular file owned by root with mode 0400",
            ),
            StartupError::KeyLength => f.write_str("integrity key file must hold exactly 32 octets"),
            StartupError::PolicyUnreadable => f.write_str("policy file unreadable"),
            StartupError::PolicyPermissions => f.write_str(
                "policy file must be a regular file owned by root, not writable by group or others",
            ),
            StartupError::Policy(error) => write!(f, "{error}"),
            StartupError::SocketDirectory => f.write_str("dird-kdc socket path has no directory"),
            StartupError::SocketDirectoryPermissions => f.write_str(
                "dird-kdc socket directory must be owned by dird's account, with no group write and no access for others",
            ),
            StartupError::SocketDirectoryCreate => {
                f.write_str("dird-kdc socket directory could not be created")
            }
            StartupError::Manifest(error) => write!(f, "provisioning manifest refused: {error}"),
            StartupError::AdminSettings => {
                f.write_str("admin channel configured without its required settings")
            }
        }
    }
}

impl std::error::Error for StartupError {}

/// Read and parse dird's configuration file: a regular file owned by root
/// and not writable by group or others, at most
/// `config::limits::MAX_FILE_OCTETS` octets.
///
/// # Errors
/// [`StartupError`].
///
/// Spec: docs/50 R50-15, §7.1; docs/questions/Q-230; Q-270 items 1-2.
pub fn read_settings(path: &Path) -> Result<DirdSettings, StartupError> {
    read_settings_owned_by(path, ROOT_UID)
}

/// Read and parse dird's configuration file, which must be owned by `owner`
/// (root in the daemon — [`read_settings`]; the test account in tests, as
/// [`read_integrity_key`] and [`read_policy`] take it). The file is reached
/// through crates/protected-file (task F7, A-86 follow-up): the path is
/// inspected without following a symbolic link (a link is refused as
/// [`StartupError::ConfigPermissions`], before any open), opened with
/// O_NOFOLLOW, and the rule applied again to the opened descriptor.
///
/// # Errors
/// [`StartupError`].
///
/// Spec: docs/50 R50-15, §7.1; docs/questions/Q-230; Q-270 items 1-2; A-86.
pub fn read_settings_owned_by(path: &Path, owner: u32) -> Result<DirdSettings, StartupError> {
    let contents =
        protected_file::read_configuration_file(path, owner, config::limits::MAX_FILE_OCTETS)
            .map_err(|refusal| match refusal {
                Refusal::Unreadable(_) => StartupError::ConfigUnreadable,
                Refusal::Rule(_) => StartupError::ConfigPermissions,
                Refusal::TooLarge => StartupError::ConfigTooLarge,
            })?;
    let settings =
        DirdSettings::parse(&contents).map_err(|error| StartupError::Config(error.to_string()))?;
    // Only the development sources exist (config enforces it; these
    // exhaustive matches fail to compile when another is added).
    match settings.integrity_key_source() {
        IntegrityKeySource::InsecureDevelopmentFile => {}
    }
    match settings.policy_store_format() {
        PolicyStoreFormat::UnsignedDevelopment => {}
    }
    Ok(settings)
}

/// Read the development integrity key (Q-213 interim; Q-270 item 1): a
/// regular file (not a symbolic link — neither at the path nor when opened,
/// crates/protected-file) owned by `owner` (root in the daemon), mode
/// exactly 0400, holding exactly 32 octets. Read as root
/// before the privilege drop; the reading buffer is wiped when this returns
/// (the key lives on only inside [`IntegrityKey`], itself wiped on drop).
///
/// # Errors
/// [`StartupError`] (never carrying a key octet).
///
/// Spec: docs/50 §7.1 ("only paths to protected files"), §7.4, R50-12 (the
/// same pattern for the TLS key: "read as root before the drop, the file
/// 0400"); docs/questions/Q-213 (A-57); AGENTS.md §6 (secrets).
pub fn read_integrity_key(path: &Path, owner: u32) -> Result<IntegrityKey, StartupError> {
    // Spec: docs/50 §7.4; Q-270 item 1 (root, mode exactly 0400); A-86
    // (crates/protected-file: no symbolic link is followed, the rule is
    // applied to the path and to the opened descriptor); Q-468 (A-102: every
    // directory on the path is root's or `owner`'s and not writable by group
    // or others — a directory that is not is the key's permission refusal).
    let key_file_rule = |facts: &FileFacts| {
        let exact = facts.mode & PERMISSION_BITS == INTEGRITY_KEY_FILE_MODE;
        if facts.regular_file && facts.owner_uid == owner && exact {
            Ok(())
        } else {
            Err(StartupError::KeyPermissions)
        }
    };
    let file = protected_file::open(path, owner, key_file_rule).map_err(|error| match error {
        OpenError::Io(_) => StartupError::KeyUnreadable,
        OpenError::Path(_) => StartupError::KeyPermissions,
        OpenError::Refused(refusal) => refusal,
    })?;
    let mut buffer = Zeroizing::new([0u8; INTEGRITY_KEY_LEN + 1]);
    let mut filled = 0usize;
    let mut reader = file.take(u64::try_from(INTEGRITY_KEY_LEN + 1).unwrap_or(u64::MAX));
    loop {
        let slot = buffer.get_mut(filled..).ok_or(StartupError::KeyLength)?;
        if slot.is_empty() {
            break;
        }
        match reader.read(slot) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(StartupError::KeyUnreadable),
        }
    }
    if filled != INTEGRITY_KEY_LEN {
        return Err(StartupError::KeyLength);
    }
    let mut key = Zeroizing::new([0u8; INTEGRITY_KEY_LEN]);
    key.copy_from_slice(
        buffer
            .get(..INTEGRITY_KEY_LEN)
            .ok_or(StartupError::KeyLength)?,
    );
    Ok(IntegrityKey::from_bytes(&key))
}

/// Read the development policy file through the shared loader
/// (`policy_store::read_file`, moved there unchanged, A-68): a regular file
/// owned by `owner` (root in the daemon), not writable by group or others,
/// at most `MAX_POLICY_FILE` octets, decoded by
/// [`DevelopmentPolicy::decode`]. Absent ⇒ refused (fail closed).
///
/// # Errors
/// [`StartupError`].
///
/// Spec: docs/50 §7.2 ("invalid … ⇒ do not start"); docs/questions/Q-219
/// (A-57), Q-270 item 2; A-68.
pub fn read_policy(path: &Path, owner: u32) -> Result<DevelopmentPolicy, StartupError> {
    read_file(path, owner).map_err(|error| match error {
        LoadError::Unreadable => StartupError::PolicyUnreadable,
        LoadError::Permissions => StartupError::PolicyPermissions,
        LoadError::Policy(error) => StartupError::Policy(error),
    })
}

/// The privileged set-up (as root, before the drop): the directories of
/// `dird_kdc_socket` and `dird_ldap_socket` (docs/50 §3.1: "each socket in
/// its own directory"). Missing ⇒ created with mode 0750 and handed to
/// dird's account; present ⇒ it must be a directory owned by dird's uid
/// with no group write and no access for others.
///
/// # Errors
/// [`StartupError`].
///
/// Spec: docs/50 §3.1, §6.2; docs/questions/Q-260 item 6 (the group is not
/// a setting).
pub fn prepare_socket_directory(settings: &DirdSettings) -> Result<(), StartupError> {
    let admin_socket = settings.admin_channel().map(config::Channel::socket);
    for socket in [
        Some(settings.kdc_channel().socket()),
        Some(settings.ldap_channel().socket()),
        admin_socket,
    ]
    .into_iter()
    .flatten()
    {
        let directory = socket
            .as_path()
            .parent()
            .ok_or(StartupError::SocketDirectory)?;
        prepare_directory(directory, settings)?;
    }
    Ok(())
}

/// One socket directory (see [`prepare_socket_directory`]).
/// Spec: docs/50 §3.1, §6.2.
fn prepare_directory(directory: &Path, settings: &DirdSettings) -> Result<(), StartupError> {
    let account = settings.run_as();
    match std::fs::symlink_metadata(directory) {
        Ok(metadata) => {
            if !metadata.is_dir() || metadata.uid() != account.uid() || metadata.mode() & 0o027 != 0
            {
                return Err(StartupError::SocketDirectoryPermissions);
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::DirBuilder::new()
                .mode(SOCKET_DIRECTORY_MODE)
                .create(directory)
                .map_err(|_| StartupError::SocketDirectoryCreate)?;
            std::fs::set_permissions(
                directory,
                std::fs::Permissions::from_mode(SOCKET_DIRECTORY_MODE),
            )
            .map_err(|_| StartupError::SocketDirectoryCreate)?;
            std::os::unix::fs::chown(directory, Some(account.uid()), Some(account.gid()))
                .map_err(|_| StartupError::SocketDirectoryCreate)
        }
        Err(_) => Err(StartupError::SocketDirectoryCreate),
    }
}

/// dird's hardening plan: the docs/50 §6.4 baseline (drop to `run_as_uid` /
/// `run_as_gid` with the supplementary groups cleared, no_new_privs, every
/// capability dropped, core limit 0, not dumpable, umask 077), an open-files
/// limit sized from the kdc's connection quota, and the working directory
/// `/` (the open-files limit also covers the LDAP sessions). No `mlockall`
/// (docs/50 §6.4 names it for keyd and admind, not dird);
/// no chroot (the redb file and `audit.sock` live in other directories).
///
/// # Errors
/// [`PlanError`] (a uid / gid of 0 is refused — the configuration refuses it
/// too).
///
/// Spec: docs/50 R50-14, §6.1, §6.2, §6.4; docs/questions/Q-235 (A-61).
pub fn hardening_plan(settings: &DirdSettings) -> Result<HardeningPlan, PlanError> {
    let account = settings.run_as();
    let identity = ProcessIdentity::new(account.uid(), account.gid())?;
    let open_files = u64::try_from(MAX_KDC_CONNECTIONS.saturating_add(MAX_LDAP_SESSIONS))
        .unwrap_or(u64::MAX)
        .saturating_add(OPEN_FILES_HEADROOM);
    HardeningPlan::daemon_baseline(identity)
        .open_files_limit(open_files)
        .working_directory("/")
        .build()
}

/// The serving parameters from dird's configuration, with the daemon's
/// constants for what the file does not set (Q-230 item 4) and keyd's
/// non-secret configuration for the realm (library defaults, as keyd-daemon
/// builds it — docs/47 R47-10; Q-270 item 7).
///
/// # Errors
/// [`StartupError::Realm`], [`StartupError::NamingContext`].
///
/// Spec: docs/50 §3.2, §3.4, §3.6, §7.1; docs/47 §7.3 (R47-10); A-53.
pub fn params(settings: &DirdSettings) -> Result<DaemonParams, StartupError> {
    let realm = Realm::new(settings.realm()).map_err(|_| StartupError::Realm)?;
    let naming_context = NamingContext::new(settings.naming_context().labels())
        .map_err(|_| StartupError::NamingContext)?;
    Ok(DaemonParams {
        kdc_socket: settings.kdc_channel().socket().as_path().to_path_buf(),
        kdc_uid: settings.kdc_channel().peer_uid(),
        audit: AuditEndpoint {
            socket: settings.audit().socket().as_path().to_path_buf(),
            uid: settings.audit().uid(),
        },
        frame_timeout: settings.frame_timeout(),
        view_lifetime: settings.view_lifetime(),
        max_views: MAX_OPEN_VIEWS,
        max_connections: MAX_KDC_CONNECTIONS,
        queue_capacity: ENGINE_QUEUE_CAPACITY,
        naming_context,
        keyd: KeydConfig::new(realm),
        ldap_socket: settings.ldap_channel().socket().as_path().to_path_buf(),
        ldap_front_uid: settings.ldap_channel().peer_uid(),
        max_ldap_sessions: MAX_LDAP_SESSIONS,
        ldap_queue_capacity: LDAP_QUEUE_CAPACITY,
        dns_host_name: settings.dns_host_name().to_owned(),
        zones: ZoneTable::from_settings(settings.internal_networks()),
        audit_window: WindowConfig::DEFAULT,
        clock: SharedClock::system(),
    })
}

/// Read the provisioning manifest (docs/51 §4.3 step 8) through the shared
/// reader of crate provision-manifest — a regular file owned by root, not
/// writable by group or others, bounded, strictly parsed — as root before
/// the drop. Read only when the admin channel is configured.
///
/// # Errors
/// [`StartupError::Manifest`] (no file content).
///
/// Spec: docs/51 §4.3 step 8; docs/50 §7.1; docs/questions/Q-386.
pub fn read_provision_manifest(path: &Path) -> Result<provision_manifest::Manifest, StartupError> {
    provision_manifest::read_manifest(path)
        .map_err(|error| StartupError::Manifest(error.to_string()))
}

/// The admin service's parameters (task A8), when the admin channel is
/// configured: the socket and admind's uid, keyd's endpoint as a verifier
/// factory (ipc-keyd's Unix connector, keyd's uid, the keyd channel's 2 s
/// deadline — Role::Ldap, A-73), the ticket-age threshold, the quorum, the
/// node-id, the manifest, and the daemon's constants for the connection
/// bound, the queue and the acknowledgement wait.
///
/// # Errors
/// [`StartupError::Realm`], [`StartupError::AdminSettings`].
///
/// Spec: docs/51 §4.6, §5.5, §5.6, §7.1, §7.5; A-73; P-22;
/// docs/questions/Q-385.
pub fn admin_params(
    settings: &DirdSettings,
    manifest: Option<provision_manifest::Manifest>,
) -> Result<Option<AdminParams>, StartupError> {
    let Some(channel) = settings.admin_channel() else {
        return Ok(None);
    };
    let service = settings
        .admin_service()
        .ok_or(StartupError::AdminSettings)?;
    let node_id = settings.node_id().ok_or(StartupError::AdminSettings)?;
    let manifest = manifest.ok_or(StartupError::AdminSettings)?;
    let quorum = usize::try_from(service.quorum()).map_err(|_| StartupError::AdminSettings)?;
    let realm = Realm::new(settings.realm()).map_err(|_| StartupError::Realm)?;
    let keyd: Option<VerifierFactory> = settings.keyd().map(|endpoint| {
        let path = endpoint.socket().as_path().to_path_buf();
        let uid = endpoint.uid();
        let factory: VerifierFactory = Arc::new(move || {
            let client = ipc_keyd::KeydClient::new(
                ipc_keyd::UnixConnector::new(path.clone()),
                uid,
                ipc_keyd::DEFAULT_DEADLINE,
            )
            .ok()?;
            let verifier: Box<dyn TicketVerifier> =
                Box::new(KeydTicketVerifier::new(client, realm.clone()));
            Some(verifier)
        });
        factory
    });
    Ok(Some(AdminParams {
        socket: channel.socket().as_path().to_path_buf(),
        admind_uid: channel.peer_uid(),
        keyd,
        ticket_age_max: service.ticket_age_max(),
        quorum,
        node_id: dirstore::NodeId(node_id),
        manifest,
        max_connections: MAX_ADMIN_CONNECTIONS,
        queue_capacity: ADMIN_QUEUE_CAPACITY,
        ack_deadline: DecisionAckDeadline::PRODUCTION,
        key_request_lifetime: directory_admin::KEY_REQUEST_LIFETIME,
        destroy_reconcile_interval: DESTROY_RECONCILE_INTERVAL,
    }))
}
