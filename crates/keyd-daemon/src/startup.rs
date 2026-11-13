//! The start-up steps `main` runs before the runtime exists: reading the
//! configuration, the privileged setup, the hardening plan, and the keyd
//! constructor of the development store.
//!
//! Spec: docs/50 R50-14, R50-15, R50-18, §3.1, §6.1, §6.2, §6.4, §7.1,
//! §7.3, §7.5; docs/questions/Q-230, Q-235 (A-61).

use crate::audit::RecordBuffer;
use config::{KeyStoreKind, KeydSettings};
use core::fmt;
use daemon_sandbox::{HardeningPlan, PlanError, ProcessIdentity};
use keyd::{ConfigError, InMemoryKeyStore, Keyd, KeydConfig, OsEntropy};
use krb_proto::{KerberosTime, Realm};
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::Path;

/// Key sets the development store holds at most. Project choice — the
/// store's capacity is not a setting (docs/questions/Q-230 item 12: library
/// tunables are not settings; Q-260 item 7).
pub const KEY_STORE_CAPACITY: usize = 4096;

/// The locked-memory limit set before `mlockall` (docs/50 §6.1: "keyd — also
/// MEMLOCK before the drop"; daemon-sandbox requires one with
/// `lock_all_memory`). ⚠ Unmeasured (docs/questions/Q-235 item 7 left the
/// value to P7): a project choice of 256 MiB pending a measurement —
/// docs/questions/Q-260 item 8.
pub const LOCKED_MEMORY_LIMIT: u64 = 256 * 1024 * 1024;

/// Open files beyond the connection quotas: stdio, the listener, the audit
/// connection, the runtime's own descriptors, `/dev/urandom`, and room for
/// connections that are accepted only to be closed (unmapped peers).
/// Project choice (docs/50 §6.1: "nofile according to the connection
/// quotas"; §6.4: keyd "small nofile").
pub const OPEN_FILES_HEADROOM: u64 = 32;

/// Mode of the socket directory: owner all, group enter, other nothing.
/// Spec: docs/50 §3.1 ("each socket in its own directory, owned by the
/// server's uid, mode 0750").
pub const SOCKET_DIRECTORY_MODE: u32 = 0o750;

/// Why start-up failed. Carries no file content (docs/50 §8.2; the
/// configuration's own errors never echo a value, A-60).
/// Spec: docs/50 §7.5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartupError {
    /// The configuration file could not be opened or read.
    ConfigUnreadable,
    /// The configuration file is not a regular file owned by root and
    /// writable only by its owner (docs/50 §7.1: "file root:0644").
    ConfigPermissions,
    /// The configuration file is larger than the format allows.
    ConfigTooLarge,
    /// The configuration was refused (`config::Error`, rendered without the
    /// offending value).
    Config(String),
    /// The realm is not a valid KerberosString.
    Realm,
    /// The socket path has no parent directory.
    SocketDirectory,
    /// The socket directory exists but is not a directory owned by the
    /// account keyd drops to with no access for others and no group write.
    SocketDirectoryPermissions,
    /// The socket directory could not be created or handed to keyd's
    /// account.
    SocketDirectoryCreate,
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
            StartupError::SocketDirectory => f.write_str("keyd socket path has no directory"),
            StartupError::SocketDirectoryPermissions => f.write_str(
                "keyd socket directory must be owned by keyd's account, with no group write and no access for others",
            ),
            StartupError::SocketDirectoryCreate => {
                f.write_str("keyd socket directory could not be created")
            }
        }
    }
}

impl std::error::Error for StartupError {}

/// Read and parse keyd's configuration file.
///
/// The file must be a regular file owned by root and not writable by group
/// or others (docs/50 §7.1: "file root:0644 (not secret)"; crates/config:
/// "file modes … are the daemon's checks"). At most
/// `config::limits::MAX_FILE_OCTETS` + 1 octets are read, so an oversized
/// file is refused without reading it whole.
///
/// # Errors
/// [`StartupError`].
///
/// Spec: docs/50 R50-15, §7.1; docs/questions/Q-230; Q-260 item 6.
pub fn read_settings(path: &Path) -> Result<KeydSettings, StartupError> {
    let file = File::open(path).map_err(|_| StartupError::ConfigUnreadable)?;
    let metadata = file
        .metadata()
        .map_err(|_| StartupError::ConfigUnreadable)?;
    if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(StartupError::ConfigPermissions);
    }
    let bound = config::limits::MAX_FILE_OCTETS;
    let mut contents = Vec::with_capacity(bound);
    file.take(u64::try_from(bound).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut contents)
        .map_err(|_| StartupError::ConfigUnreadable)?;
    if contents.len() > bound {
        return Err(StartupError::ConfigTooLarge);
    }
    let settings =
        KeydSettings::parse(&contents).map_err(|error| StartupError::Config(error.to_string()))?;
    // R50-18: only the insecure development store exists (config enforces
    // it; this exhaustive match fails to compile when another is added).
    match settings.key_store() {
        KeyStoreKind::InsecureDevelopment => {}
    }
    Ok(settings)
}

/// keyd's realm as a KerberosString.
///
/// # Errors
/// [`StartupError::Realm`].
///
/// Spec: docs/50 §7.1; RFC 4120 5.2.1 (krb-proto's rule).
pub fn realm(settings: &KeydSettings) -> Result<Realm, StartupError> {
    Realm::new(settings.realm()).map_err(|_| StartupError::Realm)
}

/// The privileged set-up (as root, before the drop): the socket's own
/// directory. Missing ⇒ created with mode 0750 and handed to keyd's account
/// (uid and gid); present ⇒ it must be a directory owned by keyd's uid with
/// no group write and no access for others. The socket file itself is bound
/// later, after the drop, by keyd's account.
///
/// # Errors
/// [`StartupError`].
///
/// Spec: docs/50 §3.1 ("each socket in its own directory, owned by the
/// server's uid, mode 0750, group = the channel's clients" — the group is not
/// a setting: docs/questions/Q-260 item 6), §6.2.
pub fn prepare_socket_directory(settings: &KeydSettings) -> Result<(), StartupError> {
    let directory = settings
        .keyd_socket()
        .as_path()
        .parent()
        .ok_or(StartupError::SocketDirectory)?;
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

/// keyd's hardening plan: the docs/50 §6.4 baseline (drop to `run_as_uid` /
/// `run_as_gid` with the supplementary groups cleared, no_new_privs, every
/// capability dropped, core limit 0, not dumpable, umask 077) plus keyd's
/// row: `mlockall` with its MEMLOCK limit, a small open-files limit sized
/// from the connection quotas, and the working directory `/`.
///
/// No chroot: docs/50 §6.4 suggests "chroot to the socket directory", but
/// the audit client must reach `audit_socket` (another directory) on every
/// reconnection after the drop — docs/questions/Q-260 item 8.
///
/// # Errors
/// [`PlanError`] (a uid / gid of 0 is refused — the configuration refuses it
/// too).
///
/// Spec: docs/50 R50-14, §6.1, §6.2, §6.4; docs/questions/Q-235 (A-61).
pub fn hardening_plan(settings: &KeydSettings) -> Result<HardeningPlan, PlanError> {
    let account = settings.run_as();
    let identity = ProcessIdentity::new(account.uid(), account.gid())?;
    let mapped = u64::try_from(settings.uid_roles().len()).unwrap_or(u64::MAX);
    let open_files = mapped
        .saturating_mul(u64::from(settings.max_connections_per_uid()))
        .saturating_add(OPEN_FILES_HEADROOM);
    HardeningPlan::daemon_baseline(identity)
        .lock_all_memory()
        .locked_memory_limit(LOCKED_MEMORY_LIMIT)
        .open_files_limit(open_files)
        .working_directory("/")
        .build()
}

/// The keyd constructor of the daemon: the library defaults for `realm`
/// (docs/questions/Q-230 item 12), the INSECURE DEVELOPMENT in-memory store
/// (the only store until P-17: every key lost on restart; krbtgt accepted
/// only because this constructor says so — D178, A-16), the daemon's record
/// buffer, the kernel CSPRNG (`Keyd::new`), and the hold-down start the
/// engine read from keyd's clock.
///
/// Spec: docs/50 R50-6, R50-18, §7.3; docs/10 §11; docs/questions/Q-212
/// (P-17).
pub fn development_keyd(
    realm: Realm,
) -> impl FnOnce(&KerberosTime) -> Result<Keyd<InMemoryKeyStore, RecordBuffer, OsEntropy>, ConfigError>
{
    move |started_at| {
        Keyd::new(
            KeydConfig::new(realm),
            InMemoryKeyStore::new_insecure_development_allowing_krbtgt(KEY_STORE_CAPACITY),
            RecordBuffer::new(),
            started_at,
        )
    }
}
