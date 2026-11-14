//! The start-up steps `main` runs before the runtime exists: reading the
//! configuration, the privileged set-up (the socket directory), the
//! hardening plan, and the serving parameters.
//!
//! Spec: docs/50 R50-14, R50-15, §3.1, §6.1, §6.2, §6.4 (admind row:
//! `mlockall` — passwords in transit), §7.1, §7.5; docs/51 §4.6, §5.1;
//! docs/questions/Q-230 (A-60), Q-235 (A-61).

use crate::audit_link::AuditEndpoint;
use crate::daemon::DaemonParams;
use crate::links::{unix_dird, unix_keyd, RootServerUid};
use crate::rate::MAX_CONNECTIONS;
use config::AdmindSettings;
use core::fmt;
use daemon_sandbox::{HardeningPlan, PlanError, ProcessIdentity};
use protected_file::{ExistingGroup, Refusal, SocketDirectoryError, SocketDirectoryOwner};
use std::path::Path;

/// The owner admind's configuration file must have: root.
/// Spec: docs/50 §7.1 ("file root:0644 (not secret)").
const ROOT_UID: u32 = 0;

/// The locked-memory limit set before `mlockall` (docs/50 §6.4: admind
/// `mlockall`; daemon-sandbox requires a MEMLOCK limit with
/// `lock_all_memory`). ⚠ Unmeasured: keyd-daemon's value (256 MiB, a
/// project choice pending a measurement — docs/questions/Q-260 item 8),
/// kept until admind's footprint is measured — docs/questions/Q-408.
pub const LOCKED_MEMORY_LIMIT: u64 = 256 * 1024 * 1024;

/// Open files beyond the connection bound: stdio, the listener, the audit,
/// dird and keyd connections, the runtime's own descriptors, and room for
/// connections that are accepted only to be refused. Project choice
/// (docs/50 §6.1: "nofile according to the connection quotas").
pub const OPEN_FILES_HEADROOM: u64 = 32;

/// Mode of the socket directory: owner all, group enter, other nothing —
/// the one value crates/protected-file creates every socket directory with.
/// Spec: docs/50 §3.1 ("each socket in its own directory, owned by the
/// server's uid, mode 0750, group = the channel's clients"); docs/51 §5.1.
pub const SOCKET_DIRECTORY_MODE: u32 = protected_file::SOCKET_DIRECTORY_MODE;

/// Why start-up failed. Carries no file content (docs/50 §8.2; the
/// configuration's own errors never echo a value, A-60).
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
    /// The socket path has no parent directory.
    SocketDirectory,
    /// The socket directory exists but is not a directory owned by admind's
    /// account with group `admin_socket_group`, no group write and no
    /// access for others, or a directory on its path is a symbolic link,
    /// owned by neither root nor admind's account, or writable by group or
    /// others (task R11c).
    SocketDirectoryPermissions,
    /// The socket directory could not be created or handed over.
    SocketDirectoryCreate,
    /// A server uid of 0 (the configuration refuses it already).
    ServerUid,
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
            StartupError::SocketDirectory => f.write_str("admin socket path has no directory"),
            StartupError::SocketDirectoryPermissions => f.write_str(
                "admin socket directory must be owned by admind's account and the admin socket group, with no group write and no access for others",
            ),
            StartupError::SocketDirectoryCreate => {
                f.write_str("admin socket directory could not be created")
            }
            StartupError::ServerUid => f.write_str("a server uid of 0 is refused"),
        }
    }
}

impl std::error::Error for StartupError {}

/// Read and parse admind's configuration file.
///
/// The file must be a regular file owned by root and not writable by group
/// or others (docs/50 §7.1: "file root:0644 (not secret)"). At most
/// `config::limits::MAX_FILE_OCTETS` + 1 octets are read, so an oversized
/// file is refused without reading it whole.
///
/// # Errors
/// [`StartupError`].
///
/// Spec: docs/50 R50-15, §7.1; docs/questions/Q-230.
pub fn read_settings(path: &Path) -> Result<AdmindSettings, StartupError> {
    read_settings_owned_by(path, ROOT_UID)
}

/// Read and parse admind's configuration file, which must be owned by
/// `owner` (root in the daemon — [`read_settings`]; the test account in
/// tests, as kdc-daemon's and ldap-front's `read_settings`). The file is
/// reached through crates/protected-file (task F7, A-86 follow-up): the path
/// is inspected without following a symbolic link (a link is refused as
/// [`StartupError::ConfigPermissions`], before any open), opened with
/// O_NOFOLLOW, and the rule applied again to the opened descriptor.
///
/// # Errors
/// [`StartupError`].
///
/// Spec: docs/50 R50-15, §7.1; docs/questions/Q-230; A-86.
pub fn read_settings_owned_by(path: &Path, owner: u32) -> Result<AdmindSettings, StartupError> {
    let contents =
        protected_file::read_configuration_file(path, owner, config::limits::MAX_FILE_OCTETS)
            .map_err(|refusal| match refusal {
                Refusal::Unreadable(_) => StartupError::ConfigUnreadable,
                Refusal::Rule(_) => StartupError::ConfigPermissions,
                Refusal::TooLarge => StartupError::ConfigTooLarge,
            })?;
    AdmindSettings::parse(&contents).map_err(|error| StartupError::Config(error.to_string()))
}

/// The privileged set-up (as root, before the drop): `admin.sock`'s own
/// directory, through the one implementation every socket-serving daemon
/// shares (`protected_file::prepare_socket_directory`, task R11c): its
/// parent walked from `/` (no link, every directory root's or admind's,
/// none writable by group or others); missing ⇒ created relative to the
/// parent, mode exactly 0750, owner admind's uid, group
/// `admin_socket_group`, set with `fchmod` / `fchown` on its own descriptor —
/// never by path; present ⇒ it must be a directory (not a link) with exactly
/// that owner and group, no group write and no access for others; a stale
/// socket in it is removed relative to its descriptor. The socket file is
/// bound later, after the drop, by admind's account.
///
/// # Errors
/// [`StartupError`].
///
/// Spec: docs/50 §3.1 ("each socket in its own directory, owned by the
/// server's uid, mode 0750, group = the channel's clients — defence in
/// depth only"), §6.2; docs/51 §4.6 (`admin_socket_group`), §5.1; docs/52
/// §3.13 (C13); docs/questions/Q-532 item 1 (A-109), Q-550.
pub fn prepare_socket_directory(settings: &AdmindSettings) -> Result<(), StartupError> {
    protected_file::prepare_socket_directory(
        settings.admin_socket().as_path(),
        SocketDirectoryOwner {
            uid: settings.run_as().uid(),
            gid: settings.admin_socket_group(),
            existing_group: ExistingGroup::Configured,
        },
    )
    .map_err(|error| match error {
        SocketDirectoryError::NoSocketDirectory => StartupError::SocketDirectory,
        SocketDirectoryError::NotAnAccount
        | SocketDirectoryError::Path(_)
        | SocketDirectoryError::Directory(_) => StartupError::SocketDirectoryPermissions,
        SocketDirectoryError::Io(_) => StartupError::SocketDirectoryCreate,
    })
}

/// admind's hardening plan: the docs/50 §6.4 baseline (drop to `run_as_uid`
/// / `run_as_gid` with the supplementary groups cleared, no_new_privs, every
/// capability dropped, core limit 0, not dumpable, umask 077) plus admind's
/// row: `mlockall` with its MEMLOCK limit (passwords in transit), an
/// open-files limit sized from the connection bound, the working directory
/// `/`. No chroot: the audit, dird and keyd sockets are in other
/// directories and are reconnected after the drop (as keyd-daemon,
/// docs/questions/Q-260 item 8). mlockall is reachable without `unsafe`
/// (daemon-sandbox `lock_all_memory`, rustix `mm::mlockall`, docs/50 §6.1);
/// seccomp / landlock / namespaces are not (P-19).
///
/// # Errors
/// [`PlanError`] (a uid / gid of 0 is refused — the configuration refuses
/// it too).
///
/// Spec: docs/50 R50-14, §6.1, §6.2, §6.3, §6.4; docs/51 §7.6 ("admind
/// `mlockall`"); docs/questions/Q-235 (A-61).
pub fn hardening_plan(settings: &AdmindSettings) -> Result<HardeningPlan, PlanError> {
    let account = settings.run_as();
    let identity = ProcessIdentity::new(account.uid(), account.gid())?;
    let open_files = u64::try_from(MAX_CONNECTIONS)
        .unwrap_or(u64::MAX)
        .saturating_add(OPEN_FILES_HEADROOM);
    HardeningPlan::daemon_baseline(identity)
        .lock_all_memory()
        .locked_memory_limit(LOCKED_MEMORY_LIMIT)
        .open_files_limit(open_files)
        .working_directory("/")
        .build()
}

/// The serving parameters from admind's configuration — the one product
/// constructor (docs/52 C18, task R15) — with the production clients of
/// dird and keyd. The daemon's constants for what the file does not set
/// (Q-230 item 4) are added by `serve`.
///
/// # Errors
/// [`StartupError::ServerUid`].
///
/// Spec: docs/50 §3.2, §3.6, §7.1; docs/51 §5.1, §7.6; A-79.
pub fn params(settings: &AdmindSettings) -> Result<DaemonParams, StartupError> {
    let dird = unix_dird(settings.dird().socket().as_path(), settings.dird().uid())
        .map_err(|RootServerUid| StartupError::ServerUid)?;
    let keyd = unix_keyd(
        settings.keyd().socket().as_path(),
        settings.keyd().uid(),
        settings.keyd_deadline(),
    )
    .map_err(|RootServerUid| StartupError::ServerUid)?;
    Ok(DaemonParams {
        admin_socket: settings.admin_socket().as_path().to_path_buf(),
        audit: AuditEndpoint {
            socket: settings.audit().socket().as_path().to_path_buf(),
            uid: settings.audit().uid(),
        },
        frame_timeout: settings.frame_timeout(),
        min_password_length: settings.min_password_length(),
        dird,
        keyd,
    })
}
