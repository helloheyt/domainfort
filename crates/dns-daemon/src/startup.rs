//! The start-up steps `main` runs before the runtime exists, as root:
//! reading the configuration, binding the listeners, and the hardening plan.
//!
//! # Bound before the drop, served after the dependencies
//!
//! docs/54 §4.7 (docs/50 §6.2): "root ⇒ read the configuration (protected-
//! file, R11b) ⇒ `bind` UDP+TCP 53 on every configured address ⇒ setrlimit
//! ⇒ drop gid/groups/uid ⇒ no_new_privs ⇒ remove capabilities ⇒ non-dumpable
//! ⇒ **only then** the tokio runtime". Port 53 needs the privilege the drop
//! removes, while auditd and dird can only be asked after it — so `main`
//! binds as root before the drop, and the daemon serves the sockets only
//! after auditd, dird and the zone image are there (crate::daemon): until
//! then nothing is read from them or answered.
//!
//! dnsd opens no other socket: only the two Unix connections to dird (zone,
//! forwarding) and the audit check (docs/54 §4.7: "no outbound socket";
//! enforced by the code, not by seccomp — P-19).
//!
//! Spec: docs/54 §4.3, §4.7; docs/50 R50-14, R50-15, §6.1, §6.2, §6.4, §7.1,
//! §7.5; docs/questions/Q-235 (A-61).

use crate::daemon::Listeners;
use crate::limits::OPEN_FILES_HEADROOM;
use config::DnsdSettings;
use core::fmt;
use daemon_sandbox::{HardeningPlan, PlanError, ProcessIdentity};
use protected_file::Refusal;
use std::path::Path;

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

/// Read and parse dnsd's configuration file: a regular file owned by
/// `owner` (root in the daemon) and not writable by group or others, at most
/// `config::limits::MAX_FILE_OCTETS` octets, reached through
/// crates/protected-file (the path inspected without following a link,
/// opened with O_NOFOLLOW, the rule applied again to the opened descriptor).
///
/// # Errors
/// [`StartupError`].
///
/// Spec: docs/54 §4.7 ("reading the configuration (protected-file, R11b)");
/// docs/50 R50-15, §7.1.
pub fn read_settings(path: &Path, owner: u32) -> Result<DnsdSettings, StartupError> {
    let contents =
        protected_file::read_configuration_file(path, owner, config::limits::MAX_FILE_OCTETS)
            .map_err(|refusal| match refusal {
                Refusal::Unreadable(_) => StartupError::ConfigUnreadable,
                Refusal::Rule(_) => StartupError::ConfigPermissions,
                Refusal::TooLarge => StartupError::ConfigTooLarge,
            })?;
    DnsdSettings::parse(&contents).map_err(|error| StartupError::Config(error.to_string()))
}

/// Bind one UDP socket and one TCP listener per configured address (RFC
/// 1035 §4.2: "TCP … on server port 53 … as well as datagram access using
/// UDP"; the addresses are interface addresses inside `internal_networks`
/// only — crates/config refuses any other). Called as root, before the drop.
///
/// # Errors
/// [`StartupError::Bind`].
///
/// Spec: RFC 1035 §4.2, §4.2.1, §4.2.2; docs/54 §4.7; docs/50 §6.2.
pub fn bind_listeners(settings: &DnsdSettings) -> Result<Listeners, StartupError> {
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

/// dnsd's hardening plan: the docs/50 §6.4 baseline (drop to `run_as_uid` /
/// `run_as_gid` with the supplementary groups cleared, no_new_privs, every
/// capability dropped — dnsd's row: "binds 53 and then drops privileges; no
/// capabilities, no_new_privs, non-dumpable, core = 0", docs/54 §4.3 — core
/// limit 0, not dumpable, umask 077), an open-files limit sized from the TCP
/// connection bound, and the working directory `/`. No `mlockall` (dnsd
/// holds no key, docs/54 §4.3), no chroot (the dird and audit sockets live in
/// two directories, as for the kdc — Q-260 item 8).
///
/// # Errors
/// [`PlanError`] (a uid / gid of 0 is refused — the configuration refuses it
/// too).
///
/// Spec: docs/54 §4.3, §4.7; docs/50 R50-14, §6.1, §6.2, §6.4;
/// docs/questions/Q-235 (A-61).
pub fn hardening_plan(settings: &DnsdSettings) -> Result<HardeningPlan, PlanError> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use daemon_sandbox::Step;

    /// A hand-made dnsd file (docs/54 §4.3; Q-619 item 4).
    const FILE: &str = "\
run_as_uid = 808
run_as_gid = 809
listen = 192.0.2.53:53, 192.0.2.54:53
internal_networks = 192.0.2.0/24
dird_dns_socket = /run/dird/dns/dird-dns.sock
dird_uid = 802
audit_socket = /run/auditd/audit.sock
auditd_uid = 805
max_tcp_connections = 100
";

    /// docs/54 §4.3 ("binds 53 and then drops privileges; no capabilities,
    /// no_new_privs, non-dumpable, core = 0"); docs/50 §6.4 (the baseline;
    /// nofile from the connection bound): the plan drops to the configured
    /// account, sets no_new_privs, drops every capability, disables core
    /// dumps, is not dumpable, and bounds open files by 100 connections + 2
    /// × 2 listeners + the headroom; no mlockall, no chroot.
    #[test]
    fn the_plan_is_the_baseline_with_dnsds_numbers() {
        let settings = DnsdSettings::parse(FILE.as_bytes()).expect("valid");
        let plan = hardening_plan(&settings).expect("plan");
        let identity = plan.identity().expect("drops identity");
        assert_eq!((identity.uid(), identity.gid()), (808, 809));
        assert!(plan.sets_no_new_privs());
        assert!(plan.drops_capabilities());
        assert!(plan.disables_core_dumps());
        assert!(plan.makes_not_dumpable());
        assert_eq!(plan.open_files_limit(), Some(100 + 4 + OPEN_FILES_HEADROOM));
        assert!(!plan.locks_all_memory());
        assert!(plan.change_root().is_none());
        assert_eq!(plan.working_directory(), Some(Path::new("/")));
        assert!(plan.contains(Step::ClearCapabilitySets));
        assert!(plan.contains(Step::DropBoundingCapabilities));
    }
}
