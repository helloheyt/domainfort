//! The start-up steps `main` runs before the runtime exists, as root:
//! reading the configuration, binding the TCP listeners, and the hardening
//! plan.
//!
//! # Files (docs/50 R50-15, §7.1)
//!
//! The configuration is a regular file owned by root and not writable by
//! group or others ("root:0644"), at most `config::limits::MAX_FILE_OCTETS`
//! octets, reached through crates/protected-file (task F7, A-86 follow-up):
//! every directory of the path walked from `/` without following a link,
//! the file inspected without following a symbolic link, opened with
//! O_NOFOLLOW and the rule applied again to the opened descriptor. The owner
//! is a parameter so that the tests can use their own uid; `main` passes 0.
//! The front reads no other file (it holds no key and no certificate).
//!
//! # Bound before the drop, served after the dependencies
//!
//! docs/53 §3.3 (port 464 is privileged, "as 88/389/636"): "start as root ⇒
//! read the configuration ⇒ `bind` ⇒ setrlimit ⇒ drop gid / groups / uid ⇒
//! no_new_privs ⇒ drop capabilities ⇒ non-dumpable ⇒ only then the
//! runtime" (docs/50 §6.2). The daemon serves the sockets only after auditd
//! and dird were verified (crate::daemon).
//!
//! Spec: docs/53 R53-3, §3.3; docs/50 R50-14, R50-15, §6.1, §6.2, §6.4,
//! §7.1, §7.5; docs/questions/Q-230 (A-60), Q-235 (A-61), Q-468 (A-102).

use crate::daemon::Listeners;
use config::KpasswdFrontSettings;
use core::fmt;
use core::net::SocketAddr;
use daemon_sandbox::{HardeningPlan, PlanError, ProcessIdentity};
use protected_file::{configuration_file_rule, OpenError};
use std::fs::File;
use std::io::Read;
use std::path::Path;

/// Open files beyond the client connections (each holds its TCP stream and,
/// while dird answers, a Unix stream to dird — at most
/// `ipc_kpasswd::MAX_FRONT_CONNECTIONS` of those): stdio, the listeners, the
/// start-up connections, the runtime's own descriptors, and room for
/// connections accepted only to be closed at a limit. Project choice
/// (docs/50 §6.1: "nofile according to the connection quotas").
pub const OPEN_FILES_HEADROOM: u64 = 64;

/// Why start-up failed. Carries no file content (docs/50 §8.2; the
/// configuration's own errors never echo a value, A-60).
/// Spec: docs/50 §7.5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartupError {
    /// The configuration file could not be opened or read.
    ConfigUnreadable,
    /// The configuration file is not a regular file (a symbolic link
    /// included) owned by root and writable only by its owner.
    ConfigPermissions,
    /// The configuration file is larger than the format allows.
    ConfigTooLarge,
    /// The configuration was refused (`config::Error`, without the value).
    Config(String),
    /// A listener could not be bound (the OS error number, if any).
    Bind(Option<i32>),
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
            StartupError::Bind(Some(code)) => write!(f, "listener could not be bound [{code}]"),
            StartupError::Bind(None) => f.write_str("listener could not be bound"),
        }
    }
}

impl std::error::Error for StartupError {}

/// Read at most `bound` octets of `file` into `buffer`, which must be
/// `bound + 1` octets long (zero-filled); it is filled in place, never grown,
/// then truncated to the octets read. `Err(true)` if the file is longer than
/// `bound`, `Err(false)` on a read failure.
/// Spec: docs/CLEAN-ROOM.md (bounded reads).
fn read_bounded(mut file: File, bound: usize, buffer: &mut Vec<u8>) -> Result<(), bool> {
    let mut filled = 0usize;
    loop {
        let Some(space) = buffer.get_mut(filled..) else {
            return Err(false);
        };
        if space.is_empty() {
            break;
        }
        match file.read(space) {
            Ok(0) => break,
            Ok(read) => filled = filled.saturating_add(read),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(false),
        }
    }
    if filled > bound {
        return Err(true);
    }
    buffer.truncate(filled);
    Ok(())
}

/// Read and parse kpasswd-front's configuration file: a regular file owned
/// by `owner` (root in the daemon) and not writable by group or others, at
/// most `config::limits::MAX_FILE_OCTETS` octets (module documentation).
///
/// # Errors
/// [`StartupError`].
///
/// Spec: docs/50 R50-15, §7.1; docs/questions/Q-230 (A-60), Q-468 (A-102).
pub fn read_settings(path: &Path, owner: u32) -> Result<KpasswdFrontSettings, StartupError> {
    let file = protected_file::open(path, owner, |facts| {
        configuration_file_rule(facts, owner).map_err(|_| ())
    })
    .map_err(|error| match error {
        OpenError::Io(_) => StartupError::ConfigUnreadable,
        OpenError::Path(_) | OpenError::Refused(()) => StartupError::ConfigPermissions,
    })?;
    let bound = config::limits::MAX_FILE_OCTETS;
    let mut contents = vec![0u8; bound.saturating_add(1)];
    read_bounded(file, bound, &mut contents).map_err(|too_large| {
        if too_large {
            StartupError::ConfigTooLarge
        } else {
            StartupError::ConfigUnreadable
        }
    })?;
    KpasswdFrontSettings::parse(&contents).map_err(|error| StartupError::Config(error.to_string()))
}

/// Bind the configured TCP listeners (port 464 — the port the zone
/// advertises: crates/config refuses any other, task DN10c — and refuses
/// unspecified, multicast and port-0 addresses and any address outside the
/// internal networks). TCP only: no UDP socket is ever created (A-117;
/// docs/questions/Q-602 (a)). Called as root, before the drop (module
/// documentation).
///
/// # Errors
/// [`StartupError::Bind`].
///
/// Spec: docs/53 R53-3, §3.3; RFC 3244 §2 ("TCP port 464"); [MS-ADTS]
/// §6.3.2.3; docs/50 §6.2; docs/questions/Q-1024.
pub fn bind_listeners(settings: &KpasswdFrontSettings) -> Result<Listeners, StartupError> {
    bind_addresses(settings.listen())
}

/// The binding itself, over the addresses [`bind_listeners`] takes from the
/// settings — its only product caller, so every address is one the front's
/// schema accepted (port 464). Crate-private: the in-crate test binds it on
/// a loopback port the system picks (task DN10c — no product path takes an
/// address that is not from the file).
pub(crate) fn bind_addresses(addresses: &[SocketAddr]) -> Result<Listeners, StartupError> {
    let tcp = addresses
        .iter()
        .map(|address| {
            std::net::TcpListener::bind(address)
                .map_err(|error| StartupError::Bind(error.raw_os_error()))
        })
        .collect::<Result<_, _>>()?;
    Ok(Listeners { tcp })
}

/// kpasswd-front's hardening plan: the docs/50 §6.4 baseline (drop to
/// `run_as_uid` / `run_as_gid` with the supplementary groups cleared,
/// no_new_privs, every capability dropped — the bind happened before — core
/// limit 0, not dumpable, umask 077), an open-files limit sized from the
/// connection bound, and the working directory `/`. No `mlockall` (§6.4
/// names it for keyd and admind; the front holds no secret), no chroot (the
/// dird and audit sockets live in two directories).
///
/// # Errors
/// [`PlanError`] (a uid / gid of 0 is refused — the configuration refuses it
/// too).
///
/// Spec: docs/53 §3.3; docs/50 R50-14, §6.1, §6.2, §6.4; docs/questions/
/// Q-235 (A-61).
pub fn hardening_plan(settings: &KpasswdFrontSettings) -> Result<HardeningPlan, PlanError> {
    let account = settings.run_as();
    let identity = ProcessIdentity::new(account.uid(), account.gid())?;
    let listeners = u64::try_from(settings.listen().len()).unwrap_or(u64::MAX);
    let dird = u64::try_from(ipc_kpasswd::MAX_FRONT_CONNECTIONS).unwrap_or(u64::MAX);
    let open_files = u64::from(settings.limits().max_tcp_connections())
        .saturating_add(dird)
        .saturating_add(listeners)
        .saturating_add(OPEN_FILES_HEADROOM);
    HardeningPlan::daemon_baseline(identity)
        .open_files_limit(open_files)
        .working_directory("/")
        .build()
}
