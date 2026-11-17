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
//! Every file is reached through crates/protected-file (task F7, A-86
//! follow-up): the path is inspected without following a symbolic link (a
//! link is refused as that file's permissions error, before any open),
//! opened with O_NOFOLLOW, and the rule applied again to the opened
//! descriptor.
//!
//! # Bound before the drop, served after the dependencies
//!
//! docs/50 §6.2: "run as root ⇒ read the configuration and the TLS key ⇒
//! `bind` ⇒ … drop … ⇒ **only then** the runtime …; the listeners are handed
//! to tokio with `from_std`". The daemon serves the sockets only after
//! auditd and dird were verified (crate::daemon) — the kdc daemon's
//! arrangement (Q-275 item 3).
//!
//! # A StartTLS listener on 389, always (task DN10d)
//!
//! The file always has at least one StartTLS listener, every one on port
//! 389 — crates/config refuses a file without `ldap_listen` (A-178 on
//! docs/questions/Q-1025 item 3: the zone advertises `_ldap._tcp` on 389)
//! and any other port for it (`NonStandardPort`, task DN10c) — and
//! [`bind_listeners`] binds exactly the file's addresses. The binding
//! itself is the crate-private `bind_addresses`, whose only product caller
//! is [`bind_listeners`]; the in-crate test binds it on loopback ports the
//! system picks. No product path and no test seam takes an address that is
//! not from the file (the arrangement of the kdc and kpasswd-front —
//! docs/questions/Q-1024 item 5).
//!
//! Spec: docs/50 R50-12, R50-14, R50-15, R50-16, §4.2, §5.3, §6.1, §6.2,
//! §6.4, §7.1, §7.5; docs/questions/Q-221 (A-57), Q-230 (A-60), Q-235
//! (A-61), Q-1025 item 3 (A-178).

use crate::daemon::{Listeners, MAX_CONNECTIONS};
use crate::tls::{server_config, CredentialError, DcCredential, TlsConfigError};
use config::LdapFrontSettings;
use core::fmt;
use core::net::SocketAddr;
use daemon_sandbox::{HardeningPlan, PlanError, ProcessIdentity};
use protected_file::{configuration_file_rule, FileFacts, OpenError, PERMISSION_BITS};
use rustls::pki_types::UnixTime;
use rustls::server::ServerConfig;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

/// Most octets of the certificate file: the certificate reader's own bound
/// (crates/parse-x509; project choice — one DER certificate is a few hundred
/// octets to a few KiB).
pub const MAX_CERTIFICATE_OCTETS: usize = parse_x509::MAX_CERTIFICATE_OCTETS;

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
    /// The configuration file is not a regular file (a symbolic link
    /// included) owned by root and writable only by its owner.
    ConfigPermissions,
    /// The configuration file is larger than the format allows.
    ConfigTooLarge,
    /// The configuration was refused (`config::Error`, without the value).
    Config(String),
    /// The certificate file could not be opened or read.
    CertificateUnreadable,
    /// The certificate file is not a regular file (a symbolic link
    /// included) owned by root and writable only by its owner.
    CertificatePermissions,
    /// The certificate file is larger than [`MAX_CERTIFICATE_OCTETS`].
    CertificateTooLarge,
    /// The key file could not be opened or read.
    KeyUnreadable,
    /// The key file is not a regular file (a symbolic link included) owned
    /// by root with mode 0400.
    KeyPermissions,
    /// The key file is larger than [`MAX_PRIVATE_KEY_OCTETS`].
    KeyTooLarge,
    /// The system clock reads a time before 1970 (no validity decision is
    /// possible).
    ClockBeforeEpoch,
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
            StartupError::ClockBeforeEpoch => {
                f.write_str("system clock reads a time before 1970; certificate validity unknown")
            }
            StartupError::Credential(error) => write!(f, "{error}"),
            StartupError::Tls(error) => write!(f, "{error}"),
            StartupError::Bind(Some(code)) => write!(f, "listener could not be bound [{code}]"),
            StartupError::Bind(None) => f.write_str("listener could not be bound"),
        }
    }
}

impl std::error::Error for StartupError {}

/// Open the protected file at `path` through crates/protected-file (task F7,
/// A-86 follow-up; task T, Q-468): every directory on the path is walked
/// from `/` without following a link and must be root's or `owner`'s and
/// not writable by group or others; the file is inspected without following
/// a symbolic link, opened with O_NOFOLLOW, and `accepted` applied to the
/// facts of the file and of the opened descriptor. A link (whose facts are
/// never a regular file's), a directory breaking that rule or a file
/// `accepted` refuses is `refused`; a failure to inspect or open is
/// `unreadable`.
/// Spec: docs/50 §7.1, R50-12, §5.3; A-86; Q-468 (A-102).
fn open_protected(
    path: &Path,
    owner: u32,
    accepted: impl Fn(&FileFacts) -> bool,
    unreadable: StartupError,
    refused: StartupError,
) -> Result<File, StartupError> {
    protected_file::open(
        path,
        owner,
        |facts| {
            if accepted(facts) {
                Ok(())
            } else {
                Err(())
            }
        },
    )
    .map_err(|error| match error {
        OpenError::Io(_) => unreadable,
        OpenError::Path(_) | OpenError::Refused(()) => refused,
    })
}

/// Read at most `bound` octets of `file` into `buffer`, which must be
/// `bound + 1` octets long (zero-filled); it is filled in place, never grown
/// (so never reallocated), then truncated to the octets read. `Err(true)`
/// if the file is longer than `bound`, `Err(false)` on a read failure.
/// Spec: docs/CLEAN-ROOM.md (bounded reads; secrets never copied around).
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
    let file = open_protected(
        path,
        owner,
        |facts| configuration_file_rule(facts, owner).is_ok(),
        StartupError::ConfigUnreadable,
        StartupError::ConfigPermissions,
    )?;
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
    let file = open_protected(
        path,
        owner,
        |facts| configuration_file_rule(facts, owner).is_ok(),
        StartupError::CertificateUnreadable,
        StartupError::CertificatePermissions,
    )?;
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
/// Spec: docs/50 R50-12, §5.3, §6.4; docs/CLEAN-ROOM.md
pub fn read_private_key(path: &Path, owner: u32) -> Result<Zeroizing<Vec<u8>>, StartupError> {
    let file = open_protected(
        path,
        owner,
        |facts| {
            facts.regular_file
                && facts.owner_uid == owner
                && facts.mode & PERMISSION_BITS == PRIVATE_KEY_MODE
        },
        StartupError::KeyUnreadable,
        StartupError::KeyPermissions,
    )?;
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

/// The start-up time for the certificate's validity check (R50-12; RFC
/// 5280 §4.1.2.5): the system clock as seconds since 1970-01-01T00:00:00Z.
/// A clock before 1970 is refused (fail closed: no trustworthy time, no
/// validity decision).
///
/// # Errors
/// [`StartupError::ClockBeforeEpoch`].
///
/// Spec: docs/50 R50-12, §7.5; RFC 5280 §4.1.2.5; docs.rs rustls-pki-types
/// 1.16.0 `UnixTime::since_unix_epoch` ("Convert a Duration since the start
/// of 1970 to a UnixTime"); docs/questions/Q-320 item 4.
pub fn start_time() -> Result<UnixTime, StartupError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(UnixTime::since_unix_epoch)
        .map_err(|_| StartupError::ClockBeforeEpoch)
}

/// Read the certificate and key named by `settings`, check them at the
/// start-up time `now` ([`start_time`] in the daemon), and build the
/// docs/50 R50-11 server configuration. The key octets are wiped when this
/// returns (their buffer drops here).
///
/// # Errors
/// [`StartupError`].
///
/// Spec: docs/50 R50-11, R50-12, §5.1, §5.3, §6.2; RFC 5280 §4.1.2.5.
pub fn load_tls_config(
    settings: &LdapFrontSettings,
    owner: u32,
    now: UnixTime,
) -> Result<Arc<ServerConfig>, StartupError> {
    let certificate = read_certificate(settings.tls_certificate_path().as_path(), owner)?;
    let key = read_private_key(settings.tls_private_key_path().as_path(), owner)?;
    let credential =
        DcCredential::from_der(certificate, &key, now).map_err(StartupError::Credential)?;
    drop(key);
    server_config(credential.resolver()).map_err(StartupError::Tls)
}

/// Bind the configured StartTLS and LDAPS listeners (docs/50 §4.2; crates/
/// config refuses unspecified, multicast and port-0 addresses, a file
/// without a StartTLS listener, and a StartTLS listener off port 389 —
/// tasks DN10c, DN10d). Called as root, before the drop (module
/// documentation).
///
/// # Errors
/// [`StartupError::Bind`].
///
/// Spec: RFC 4511 §5.2; docs/50 §4.2, §6.2; docs/questions/Q-1025 item 3.
pub fn bind_listeners(settings: &LdapFrontSettings) -> Result<Listeners, StartupError> {
    bind_addresses(settings.ldap_listen(), settings.ldaps_listen())
}

/// The binding itself, over the StartTLS and LDAPS addresses
/// [`bind_listeners`] takes from the settings — its only product caller, so
/// every address is one ldap-front's schema accepted. Crate-private: the
/// in-crate test binds it on loopback ports the system picks (module
/// documentation, "A StartTLS listener on 389, always").
/// Spec: RFC 4511 §5.2; docs/50 §4.2, §6.2; docs/questions/Q-1025 item 3.
fn bind_addresses(ldap: &[SocketAddr], ldaps: &[SocketAddr]) -> Result<Listeners, StartupError> {
    let bind = |address: &SocketAddr| {
        std::net::TcpListener::bind(address)
            .map_err(|error| StartupError::Bind(error.raw_os_error()))
    };
    Ok(Listeners {
        ldap: ldap.iter().map(bind).collect::<Result<_, _>>()?,
        ldaps: ldaps.iter().map(bind).collect::<Result<_, _>>()?,
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A loopback address on a port the system picks (never a privileged
    /// one), free when returned.
    fn free_loopback() -> SocketAddr {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = probe.local_addr().unwrap();
        drop(probe);
        address
    }

    /// docs/50 §4.2, §6.2: each configured StartTLS and LDAPS address is
    /// bound as a TCP listener at that address, on its own list; an address
    /// already taken refuses the start. In-crate, through the crate-private
    /// `bind_addresses`, on loopback ports the system picks — ldap-front's
    /// file names port 389 for StartTLS only (tasks DN10c, DN10d). Moved
    /// from tests/startup_files.rs (docs/questions/Q-1025 item 3).
    /// Hand-made values.
    #[test]
    fn the_listeners_are_bound() {
        let ldap = free_loopback();
        let ldaps = free_loopback();
        if ldap == ldaps {
            return; // the system handed the same port twice: nothing to check
        }
        let listeners = bind_addresses(&[ldap], &[ldaps]).unwrap();
        assert_eq!((listeners.ldap.len(), listeners.ldaps.len()), (1, 1));
        assert_eq!(listeners.ldap[0].local_addr().unwrap(), ldap);
        assert_eq!(listeners.ldaps[0].local_addr().unwrap(), ldaps);
        assert!(matches!(
            bind_addresses(&[ldap], &[]),
            Err(StartupError::Bind(_))
        ));
        assert!(matches!(
            bind_addresses(&[], &[ldaps]),
            Err(StartupError::Bind(_))
        ));
    }
}
