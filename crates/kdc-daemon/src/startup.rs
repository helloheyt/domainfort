//! The start-up steps `main` runs before the runtime exists, as root:
//! reading the configuration, reading the policy file, binding the
//! listeners, and the hardening plan.
//!
//! # Bound before the drop, served after the dependencies (Q-275 item 3)
//!
//! docs/50 §6.2: "run as root ⇒ read the configuration … ⇒ `bind` ⇒
//! setrlimit ⇒ drop gid/groups/uid ⇒ no_new_privs ⇒ drop capabilities ⇒
//! … ⇒ **only then** the runtime …; the listeners are handed to tokio with
//! `from_std`". docs/50 R50-16 / §7.5 step 4: "only after all these
//! succeeded are 88/udp+tcp bound". The two meet here: port 88 needs the
//! privilege the drop removes (and capabilities are per thread, so they
//! cannot be kept for a later bind once the runtime's threads exist), while
//! keyd and dird can only be asked after the drop (keyd never maps uid 0,
//! R50-3). So `main` binds as root before the drop, and the daemon serves
//! the sockets only after auditd, keyd and dird were verified (crate::
//! daemon step 5): until then nothing is read from them or answered. A TCP
//! handshake can complete into the kernel's backlog meanwhile, and UDP
//! datagrams wait in the receive buffer; a failed start closes them all.
//!
//! Spec: docs/50 R50-14, R50-15, R50-16, §3.1, §6.1, §6.2, §6.4, §7.1, §7.2,
//! §7.5; docs/questions/Q-230 (A-60), Q-235 (A-61), Q-270 item 2, A-68.

use crate::daemon::Listeners;
use config::{KdcSettings, PolicyStoreFormat};
use core::fmt;
use daemon_sandbox::{HardeningPlan, PlanError, ProcessIdentity};
use policy_store::{read_file, DevelopmentPolicy, LoadError};
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// Open files beyond the TCP connection bound: stdio, the listeners, the
/// keyd, dird and audit connections, the runtime's own descriptors, and
/// room for connections accepted only to be closed at a limit. Project
/// choice (docs/50 §6.1: "nofile according to the connection quotas").
pub const OPEN_FILES_HEADROOM: u64 = 64;

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
    /// The configuration was refused (`config::Error`, without the value).
    Config(String),
    /// The policy file was refused (`policy_store::LoadError`).
    Policy(LoadError),
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
            StartupError::Policy(error) => write!(f, "{error}"),
            StartupError::Bind(Some(code)) => write!(f, "listener could not be bound [{code}]"),
            StartupError::Bind(None) => f.write_str("listener could not be bound"),
        }
    }
}

impl std::error::Error for StartupError {}

/// Read and parse the kdc's configuration file: a regular file owned by
/// `owner` (root in the daemon) and not writable by group or others, at
/// most `config::limits::MAX_FILE_OCTETS` octets.
///
/// # Errors
/// [`StartupError`].
///
/// Spec: docs/50 R50-15, §7.1; docs/questions/Q-230; A-68.
pub fn read_settings(path: &Path, owner: u32) -> Result<KdcSettings, StartupError> {
    let file = File::open(path).map_err(|_| StartupError::ConfigUnreadable)?;
    let metadata = file
        .metadata()
        .map_err(|_| StartupError::ConfigUnreadable)?;
    if !metadata.is_file() || metadata.uid() != owner || metadata.mode() & 0o022 != 0 {
        return Err(StartupError::ConfigPermissions);
    }
    let bound = config::limits::MAX_FILE_OCTETS;
    let mut contents = Vec::new();
    file.take(u64::try_from(bound).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut contents)
        .map_err(|_| StartupError::ConfigUnreadable)?;
    if contents.len() > bound {
        return Err(StartupError::ConfigTooLarge);
    }
    let settings =
        KdcSettings::parse(&contents).map_err(|error| StartupError::Config(error.to_string()))?;
    // Only the unsigned development format exists (config enforces it; this
    // exhaustive match fails to compile when another is added).
    match settings.policy_store_format() {
        PolicyStoreFormat::UnsignedDevelopment => {}
    }
    Ok(settings)
}

/// Read the policy file — the same file dird loads (docs/50 §7.2) — through
/// the shared loader: owned by `owner` (root in the daemon), not writable by
/// group or others, bounded, strictly decoded (format 2, A-68). Read as root
/// before the drop.
///
/// # Errors
/// [`StartupError::Policy`].
///
/// Spec: docs/50 §6.2, §7.2; A-68.
pub fn read_policy(path: &Path, owner: u32) -> Result<DevelopmentPolicy, StartupError> {
    read_file(path, owner).map_err(StartupError::Policy)
}

/// Bind one UDP socket and one TCP listener per configured address (docs/50
/// §4.1: "each address served on UDP and TCP"; the addresses are interface
/// addresses only — crates/config refuses the unspecified ones, Q-230 item
/// 7). Called as root, before the drop (module documentation).
///
/// # Errors
/// [`StartupError::Bind`].
///
/// Spec: RFC 4120 §7.2.1, §7.2.2; docs/50 R50-9, §4.1, §6.2.
pub fn bind_listeners(settings: &KdcSettings) -> Result<Listeners, StartupError> {
    let mut listeners = Listeners::default();
    for address in settings.listen() {
        let udp = std::net::UdpSocket::bind(address)
            .map_err(|error| StartupError::Bind(error.raw_os_error()))?;
        let tcp = std::net::TcpListener::bind(address)
            .map_err(|error| StartupError::Bind(error.raw_os_error()))?;
        listeners.udp.push(udp);
        listeners.tcp.push(tcp);
    }
    Ok(listeners)
}

/// The kdc's hardening plan: the docs/50 §6.4 baseline (drop to `run_as_uid`
/// / `run_as_gid` with the supplementary groups cleared, no_new_privs, every
/// capability dropped — the kdc's row: "capabilities only until the bind",
/// and the bind happened before — core limit 0, not dumpable, umask 077), an
/// open-files limit sized from the TCP connection bound, and the working
/// directory `/`. No `mlockall` (§6.4 names it for keyd and admind; the kdc
/// holds no key, docs/30 §1), no chroot (the keyd, dird and audit sockets
/// live in three directories; Q-260 item 8).
///
/// # Errors
/// [`PlanError`] (a uid / gid of 0 is refused — the configuration refuses it
/// too).
///
/// Spec: docs/50 R50-14, §6.1, §6.2, §6.4; docs/questions/Q-235 (A-61).
pub fn hardening_plan(settings: &KdcSettings) -> Result<HardeningPlan, PlanError> {
    let account = settings.run_as();
    let identity = ProcessIdentity::new(account.uid(), account.gid())?;
    let listeners = u64::try_from(settings.listen().len())
        .unwrap_or(u64::MAX)
        .saturating_mul(2);
    let open_files = u64::from(settings.limits().max_tcp_connections())
        .saturating_add(listeners)
        .saturating_add(OPEN_FILES_HEADROOM);
    HardeningPlan::daemon_baseline(identity)
        .open_files_limit(open_files)
        .working_directory("/")
        .build()
}
