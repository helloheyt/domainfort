//! The start-up steps `main` runs before the runtime exists, as root:
//! reading the configuration, reading the DC certificate and key, building
//! the TLS configuration, binding the listeners, and the hardening plan.
//!
//! # Files (docs/50 R50-12, R50-15, §5.3, §6.4, §7.1)
//!
//! | file | must be | bound |
//! |---|---|---|
//! | configuration | a regular file owned by root, not group/other-writable ("root:0644") | `config::limits::MAX_FILE_OCTETS` |
//! | certificate (DER) | a regular file owned by root, not group/other-writable (public, but not replaceable) | [`MAX_CERTIFICATE_OCTETS`] |
//! | private key (PKCS#8 DER) | a regular file owned by root, mode exactly 0400 ("the key file is root-owned mode 0400 and is read as root before the privilege drop", crates/config) | [`MAX_PRIVATE_KEY_OCTETS`] |
//!
//! The key is read into a buffer allocated once at its bound (never grown,
//! so never reallocated) and wiped when it drops — right after the TLS
//! configuration is built ([`load_tls_config`]; task P11: "zeroize the key
//! bytes after building the rustls config"). The owner is a parameter so
//! that the tests can use their own uid; `main` passes 0.
//!
//! # Bound before the drop, served after the dependencies
//!
//! docs/50 §6.2: "run as root ⇒ read the configuration and the TLS key ⇒
//! `bind` ⇒ … drop … ⇒ **only then** the runtime …; the listeners are handed
//! to tokio with `from_std`". The daemon serves the sockets only after
//! auditd and dird were verified (crate::daemon) — the kdc daemon's
//! arrangement (Q-275 item 3).
//!
//! Spec: docs/50 R50-12, R50-14, R50-15, R50-16, §5.3, §6.1, §6.2, §6.4,
//! §7.1, §7.5; docs/questions/Q-221 (A-57), Q-230 (A-60), Q-235 (A-61).

use crate::daemon::{Listeners, MAX_CONNECTIONS};
use crate::tls::{server_config, CredentialError, DcCredential, TlsConfigError};
use config::LdapFrontSettings;
use core::fmt;
use daemon_sandbox::{HardeningPlan, PlanError, ProcessIdentity};
use rustls::server::ServerConfig;
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::Arc;
use zeroize::Zeroizing;

/// Most octets of the certificate file. Project choice (one DER certificate
/// is a few hundred octets to a few KiB).
pub const MAX_CERTIFICATE_OCTETS: usize = 64 * 1024;

/// Most octets of the private-key file. Project choice (a PKCS#8 ECDSA
/// P-256 key is far smaller).
pub const MAX_PRIVATE_KEY_OCTETS: usize = 16 * 1024;

/// The permission bits the key file must have exactly.
/// Spec: docs/50 R50-12 ("the file 0400").
pub const PRIVATE_KEY_MODE: u32 = 0o400;

/// Open files beyond the client connections (each client connection holds
/// a TCP stream and a Unix stream to dird): stdio, the listeners, the
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
    /// The configuration file is not a regular file owned by root and
    /// writable only by its owner.
    ConfigPermissions,
    /// The configuration file is larger than the format allows.
    ConfigTooLarge,
    /// The configuration was refused (`config::Error`, without the value).
    Config(String),
    /// The certificate file could not be opened or read.
    CertificateUnreadable,
    /// The certificate file is not a regular file owned by root and
    /// writable only by its owner.
    CertificatePermissions,
    /// The certificate file is larger than [`MAX_CERTIFICATE_OCTETS`].
    CertificateTooLarge,
    /// The key file could not be opened or read.
    KeyUnreadable,
    /// The key file is not a regular file owned by root with mode 0400.
    KeyPermissions,
    /// The key file is larger than [`MAX_PRIVATE_KEY_OCTETS`].
    KeyTooLarge,
    /// The certificate and key were refused.
    Credential(CredentialError),
    /// The TLS configuration could not be built.
    Tls(TlsConfigError),
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
            StartupError::CertificateUnreadable => f.write_str("certificate file unreadable"),
            StartupError::CertificatePermissions => f.write_str(
                "certificate file must be a regular file owned by root, not writable by group or others",
            ),
            StartupError::CertificateTooLarge => f.write_str("certificate file too large"),
            StartupError::KeyUnreadable => f.write_str("private key file unreadable"),
            StartupError::KeyPermissions => {
                f.write_str("private key file must be a regular file owned by root with mode 0400")
            }
            StartupError::KeyTooLarge => f.write_str("private key file too large"),
            StartupError::Credential(error) => write!(f, "{error}"),
            StartupError::Tls(error) => write!(f, "{error}"),
            StartupError::Bind(Some(code)) => write!(f, "listener could not be bound [{code}]"),
            StartupError::Bind(None) => f.write_str("listener could not be bound"),
        }
    }
}

impl std::error::Error for StartupError {}

/// Read at most `bound` octets of `file` into `buffer`, which must be
/// `bound + 1` octets long (zero-filled); it is filled in place, never grown
/// (so never reallocated), then truncated to the octets read. `Err(true)`
/// if the file is longer than `bound`, `Err(false)` on a read failure.
/// Spec: AGENTS.md §6 (bounded reads; secrets never copied around).
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

/// Read and parse ldap-front's configuration file: a regular file owned by
/// `owner` (root in the daemon) and not writable by group or others, at
/// most `config::limits::MAX_FILE_OCTETS` octets.
///
/// # Errors
/// [`StartupError`].
///
/// Spec: docs/50 R50-15, §7.1; docs/questions/Q-230 (A-60).
pub fn read_settings(path: &Path, owner: u32) -> Result<LdapFrontSettings, StartupError> {
    let file = File::open(path).map_err(|_| StartupError::ConfigUnreadable)?;
    let metadata = file
        .metadata()
        .map_err(|_| StartupError::ConfigUnreadable)?;
    if !metadata.is_file() || metadata.uid() != owner || metadata.mode() & 0o022 != 0 {
        return Err(StartupError::ConfigPermissions);
    }
    let bound = config::limits::MAX_FILE_OCTETS;
    let mut contents = vec![0u8; bound.saturating_add(1)];
    read_bounded(file, bound, &mut contents).map_err(|too_large| {
        if too_large {
            StartupError::ConfigTooLarge
        } else {
            StartupError::ConfigUnreadable
        }
    })?;
    LdapFrontSettings::parse(&contents).map_err(|error| StartupError::Config(error.to_string()))
}

/// Read the DC certificate (DER): a regular file owned by `owner`, not
/// writable by group or others, at most [`MAX_CERTIFICATE_OCTETS`].
///
/// # Errors
/// [`StartupError`].
///
/// Spec: docs/50 R50-12, §5.3.
pub fn read_certificate(path: &Path, owner: u32) -> Result<Vec<u8>, StartupError> {
    let file = File::open(path).map_err(|_| StartupError::CertificateUnreadable)?;
    let metadata = file
        .metadata()
        .map_err(|_| StartupError::CertificateUnreadable)?;
    if !metadata.is_file() || metadata.uid() != owner || metadata.mode() & 0o022 != 0 {
        return Err(StartupError::CertificatePermissions);
    }
    let mut contents = vec![0u8; MAX_CERTIFICATE_OCTETS.saturating_add(1)];
    read_bounded(file, MAX_CERTIFICATE_OCTETS, &mut contents).map_err(|too_large| {
        if too_large {
            StartupError::CertificateTooLarge
        } else {
            StartupError::CertificateUnreadable
        }
    })?;
    Ok(contents)
}

/// Read the DC private key (PKCS#8 DER): a regular file owned by `owner`
/// with permission bits exactly 0400, at most [`MAX_PRIVATE_KEY_OCTETS`],
/// into a wiped-on-drop buffer that never grows (module documentation).
///
/// # Errors
/// [`StartupError`].
///
/// Spec: docs/50 R50-12, §5.3, §6.4; AGENTS.md §6.
pub fn read_private_key(path: &Path, owner: u32) -> Result<Zeroizing<Vec<u8>>, StartupError> {
    let file = File::open(path).map_err(|_| StartupError::KeyUnreadable)?;
    let metadata = file.metadata().map_err(|_| StartupError::KeyUnreadable)?;
    if !metadata.is_file()
        || metadata.uid() != owner
        || metadata.mode() & 0o7777 != PRIVATE_KEY_MODE
    {
        return Err(StartupError::KeyPermissions);
    }
    let mut contents = Zeroizing::new(vec![0u8; MAX_PRIVATE_KEY_OCTETS.saturating_add(1)]);
    read_bounded(file, MAX_PRIVATE_KEY_OCTETS, &mut contents).map_err(|too_large| {
        if too_large {
            StartupError::KeyTooLarge
        } else {
            StartupError::KeyUnreadable
        }
    })?;
    Ok(contents)
}

/// Read the certificate and key named by `settings`, check them, and build
/// the docs/50 R50-11 server configuration. The key octets are wiped when
/// this returns (their buffer drops here).
///
/// # Errors
/// [`StartupError`].
///
/// Spec: docs/50 R50-11, R50-12, §5.1, §5.3, §6.2.
pub fn load_tls_config(
    settings: &LdapFrontSettings,
    owner: u32,
) -> Result<Arc<ServerConfig>, StartupError> {
    let certificate = read_certificate(settings.tls_certificate_path().as_path(), owner)?;
    let key = read_private_key(settings.tls_private_key_path().as_path(), owner)?;
    let credential = DcCredential::from_der(certificate, &key).map_err(StartupError::Credential)?;
    drop(key);
    server_config(credential.resolver()).map_err(StartupError::Tls)
}

/// Bind the configured StartTLS and LDAPS listeners (docs/50 §4.2; crates/
/// config refuses unspecified, multicast and port-0 addresses). Called as
/// root, before the drop (module documentation).
///
/// # Errors
/// [`StartupError::Bind`].
///
/// Spec: RFC 4511 §5.2; docs/50 §4.2, §6.2.
pub fn bind_listeners(settings: &LdapFrontSettings) -> Result<Listeners, StartupError> {
    let bind = |address: &core::net::SocketAddr| {
        std::net::TcpListener::bind(address)
            .map_err(|error| StartupError::Bind(error.raw_os_error()))
    };
    Ok(Listeners {
        ldap: settings
            .ldap_listen()
            .iter()
            .map(bind)
            .collect::<Result<_, _>>()?,
        ldaps: settings
            .ldaps_listen()
            .iter()
            .map(bind)
            .collect::<Result<_, _>>()?,
    })
}

/// ldap-front's hardening plan: the docs/50 §6.4 baseline (drop to
/// `run_as_uid` / `run_as_gid` with the supplementary groups cleared,
/// no_new_privs, every capability dropped — ldap-front's row: "the TLS key
/// is read as root, then the privileges drop", and the bind happened before
/// — core limit 0, not dumpable, umask 077), an open-files limit sized from
/// the connection bound (two descriptors per client connection), and the
/// working directory `/`. No `mlockall` (§6.4 names it for keyd and admind),
/// no chroot (the dird and audit sockets live in two directories; Q-260
/// item 8).
///
/// # Errors
/// [`PlanError`] (a uid / gid of 0 is refused — the configuration refuses it
/// too).
///
/// Spec: docs/50 R50-14, §6.1, §6.2, §6.4; docs/questions/Q-235 (A-61).
pub fn hardening_plan(settings: &LdapFrontSettings) -> Result<HardeningPlan, PlanError> {
    let account = settings.run_as();
    let identity = ProcessIdentity::new(account.uid(), account.gid())?;
    let listeners = u64::try_from(
        settings
            .ldap_listen()
            .len()
            .saturating_add(settings.ldaps_listen().len()),
    )
    .unwrap_or(u64::MAX);
    let open_files = u64::try_from(MAX_CONNECTIONS)
        .unwrap_or(u64::MAX)
        .saturating_mul(2)
        .saturating_add(listeners)
        .saturating_add(OPEN_FILES_HEADROOM);
    HardeningPlan::daemon_baseline(identity)
        .open_files_limit(open_files)
        .working_directory("/")
        .build()
}
