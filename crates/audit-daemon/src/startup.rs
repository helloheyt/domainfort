//! The pieces of `main` that are not the log or the socket: the argument,
//! the configuration file, the hardening plan, fixed texts and exit codes.
//!
//! # The start-up sequence (`main`)
//!
//! 1. Claim `SingleThreadProof` — the first statement (docs/50 R50-14; A-61).
//! 2. Install the panic hook: a fixed message and the code location only
//!    (docs/50 §8.2).
//! 3. Read the configuration file named by the one argument: an absolute
//!    path to a regular file owned by root and not writable by group or
//!    others (docs/50 §7.1: "root:0644 (not secret)"; docs/questions/Q-230
//!    item 16: file modes are the daemon's checks), at most
//!    `config::limits::MAX_FILE_OCTETS`; parse `AuditdSettings`.
//! 4. Harden ([`hardening_plan`]: the docs/50 §6.4 baseline — drop to
//!    `run_as_uid` / `run_as_gid` with no supplementary groups, no_new_privs,
//!    no capabilities, core limit 0, not dumpable, umask 077 — plus an
//!    open-files limit), before any thread exists.
//! 5. Verify and open the log **after** hardening, as auditd's own uid. The
//!    file permissions do not require root: the log directory and segments
//!    belong to auditd (docs/50 §2.4 "auditd … holds the audit file", §6.4
//!    "append write access to the audit file only"), and running the
//!    verifier — which parses files that may have been tampered with — after
//!    the drop keeps it out of a privileged process (docs/03 principles:
//!    parsers run unprivileged). A break refuses the start (exit
//!    [`EXIT_CHAIN_BREAK`]); a torn tail is recovered (crate::recovery).
//! 6. Print the start notice and the signing mode (UNSIGNED, P-20).
//! 7. Build the tokio runtime with an explicit worker count (docs/50 §6.2:
//!    overrides `TOKIO_WORKER_THREADS`).
//! 8. Bind `audit_socket` (stale socket removed; mode 0660) — only now,
//!    after the log verified (docs/50 R50-16, §7.5).
//! 9. Spawn the listener; the main thread becomes the writer
//!    (crate::writer). If the writer fails, the daemon exits
//!    [`EXIT_WRITER`] and the service manager restarts it (docs/50 §7.5).
//!
//! Spec: docs/50 R50-14, R50-15, R50-16, §6.2, §6.4, §7.1, §7.5, §8.2;
//! docs/questions/Q-230 (A-60), Q-235 (A-61), Q-265.

use crate::recovery::StartKind;
use config::AuditdSettings;
use core::fmt;
use daemon_sandbox::{HardeningPlan, PlanError, ProcessIdentity};
use std::ffi::OsString;
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// Exit code: any start-up failure other than a chain break. Project choice.
pub const EXIT_STARTUP: u8 = 1;
/// Exit code: the log failed verification (tamper or double fault) — the
/// daemon refuses to start. Project choice.
pub const EXIT_CHAIN_BREAK: u8 = 2;
/// Exit code: the writer stopped while running (the restart's start-up
/// verification and recovery take over). Project choice.
pub const EXIT_WRITER: u8 = 3;

/// The open-files limit: the standard streams, the segment being written
/// and one being read at start, the listener, and up to
/// `MAX_CONNECTIONS_PER_SOURCE` connections for each of the five sources,
/// with room for connections accepted only to be refused. Project choice
/// (docs/50 §6.1: "nofile according to the connection quotas").
pub const OPEN_FILES_LIMIT: u64 = 64;

/// tokio worker threads: the writer holds the main thread, the runtime only
/// accepts and serves connections. Project choice.
pub const WORKER_THREADS: usize = 2;

/// Why the configuration could not be read.
///
/// Spec: docs/50 §7.1; docs/questions/Q-230 item 16.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingsError {
    /// Not exactly one argument, or not an absolute path.
    Usage,
    /// The file could not be opened or read.
    Io(io::ErrorKind),
    /// Not a regular file.
    NotAFile,
    /// Writable by group or others.
    Writable,
    /// Not owned by root.
    NotRootOwned,
    /// Larger than `config::limits::MAX_FILE_OCTETS`.
    TooLarge,
    /// Refused by the parser (the error never echoes the input — A-60).
    Config(config::Error),
}

impl fmt::Display for SettingsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SettingsError::Usage => {
                f.write_str("usage: audit-daemon <absolute path of the configuration file>")
            }
            SettingsError::Io(kind) => write!(f, "configuration file unreadable: {kind}"),
            SettingsError::NotAFile => f.write_str("configuration path is not a regular file"),
            SettingsError::Writable => {
                f.write_str("configuration file is writable by group or others")
            }
            SettingsError::NotRootOwned => f.write_str("configuration file is not owned by root"),
            SettingsError::TooLarge => f.write_str("configuration file is too large"),
            SettingsError::Config(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for SettingsError {}

/// The configuration path: exactly one argument after the program name, an
/// absolute path.
///
/// # Errors
/// [`SettingsError::Usage`].
///
/// Spec: task P6b ("parse `AuditdSettings` from the argv config path");
/// docs/50 §7.1 (no environment override).
pub fn config_path<I: IntoIterator<Item = OsString>>(args: I) -> Result<PathBuf, SettingsError> {
    let mut args = args.into_iter().skip(1);
    let (Some(path), None) = (args.next(), args.next()) else {
        return Err(SettingsError::Usage);
    };
    let path = PathBuf::from(path);
    if path.is_absolute() {
        Ok(path)
    } else {
        Err(SettingsError::Usage)
    }
}

/// Read and parse the configuration file at `path` (checks in this
/// module's step 3).
///
/// # Errors
/// [`SettingsError`].
///
/// Spec: docs/50 R50-15, §7.1; docs/questions/Q-230 item 16 (A-60).
pub fn read_settings(path: &Path) -> Result<AuditdSettings, SettingsError> {
    let file = std::fs::File::open(path).map_err(|e| SettingsError::Io(e.kind()))?;
    // The checks use the opened file's metadata, not the path's again.
    let metadata = file.metadata().map_err(|e| SettingsError::Io(e.kind()))?;
    if !metadata.is_file() {
        return Err(SettingsError::NotAFile);
    }
    if metadata.mode() & 0o022 != 0 {
        return Err(SettingsError::Writable);
    }
    if metadata.uid() != 0 {
        return Err(SettingsError::NotRootOwned);
    }
    let bound = config::limits::MAX_FILE_OCTETS;
    let mut octets = Vec::new();
    file.take(u64::try_from(bound).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut octets)
        .map_err(|e| SettingsError::Io(e.kind()))?;
    if octets.len() > bound {
        return Err(SettingsError::TooLarge);
    }
    AuditdSettings::parse(&octets).map_err(SettingsError::Config)
}

/// The hardening plan: the docs/50 §6.4 baseline for `run_as_uid` /
/// `run_as_gid`, plus [`OPEN_FILES_LIMIT`]. No chroot: the configuration
/// names no chroot directory (docs/questions/Q-230 item 12; docs/50 §6.1
/// "⚠ to be estimated") — docs/questions/Q-265 item 10.
///
/// # Errors
/// [`PlanError`] (e.g. uid or gid 0).
///
/// Spec: docs/50 R50-14, §6.1, §6.4; crates/daemon-sandbox
/// `HardeningPlan::daemon_baseline`.
pub fn hardening_plan(settings: &AuditdSettings) -> Result<HardeningPlan, PlanError> {
    let account = settings.run_as();
    let identity = ProcessIdentity::new(account.uid(), account.gid())?;
    HardeningPlan::daemon_baseline(identity)
        .open_files_limit(OPEN_FILES_LIMIT)
        .build()
}

/// The fixed start-up line for what start-up found (stderr).
/// Spec: docs/50 §8.2 (fixed codes and identifiers only).
#[must_use]
pub fn start_notice(start: StartKind) -> String {
    match start {
        StartKind::Created => "audit-daemon: audit log created".to_owned(),
        StartKind::Resumed => "audit-daemon: audit log verified end to end".to_owned(),
        StartKind::Recovered(recovered) => format!(
            "audit-daemon: torn audit log segment {} recovered at sequence {}; \
             the log continues in a new segment",
            recovered.segment, recovered.last_good.seq
        ),
    }
}

/// Replace the panic output with a fixed message and the code location —
/// never the panic payload, which could carry data (docs/50 §8.2).
///
/// Spec: docs/50 §8.2 ("panic: a hook that prints a fixed message + location
/// only").
pub fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| match info.location() {
        Some(location) => eprintln!(
            "audit-daemon: internal error at {}:{}",
            location.file(),
            location.line()
        ),
        None => eprintln!("audit-daemon: internal error"),
    }));
}
