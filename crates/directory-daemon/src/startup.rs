//! The start-up steps `main` runs before the runtime exists: reading the
//! configuration, the development integrity key, the name-resolution
//! attestation key (task PN10) and the development policy (all as root,
//! before the drop), the socket directory, the hardening plan, and the
//! serving parameters.
//!
//! Both keys are 32-octet root-owned files of mode exactly 0400, read by the
//! one reader [`read_key_file`] (crates/protected-file underneath): the
//! integrity key of the store (docs/50 §7.4) and the attestation key dird
//! tags its name resolutions with (docs/59 §7.4) — two keys, two files,
//! never one key for both (A-129: "never the dirstore integrity key").
//!
//! Spec: docs/50 R50-2, R50-14, R50-15, §3.1, §6.1, §6.2, §6.4, §7.1, §7.2,
//! §7.4, §7.5; docs/questions/Q-213, Q-219 (A-57), Q-230 (A-60), Q-235
//! (A-61), Q-270; docs/59 §7.4, §10 (the PN10 row); docs/questions/Q-1011
//! item 2 (A-173), Q-1046.

use crate::admin_service::{AdminParams, KeydEndpoint};
use crate::audit_link::AuditEndpoint;
use crate::daemon::{DaemonParams, MAX_KDC_CONNECTIONS, MAX_LDAP_SESSIONS};
use crate::dns_service::DnsParams;
use crate::kpasswd_service::KpasswdParams;
use crate::policy::{read_file, DevelopmentPolicy, LoadError, PolicyError};
use crate::policy_next::PolicyNextFile;
use config::{DirdSettings, IntegrityKeySource, PolicyStoreFormat};
use core::fmt;
use daemon_sandbox::{HardeningPlan, PlanError, ProcessIdentity};
use directory_pip::{DnsName, KpasswdService, NamingContext, SoaParameters, ZoneParameters};
use dirstore::{IntegrityKey, INTEGRITY_KEY_LEN};
use ipc_directory_server::{SharedAttestationKey, ATTESTATION_KEY_LEN};
use keyd_types::KeydConfig;
use krb_proto::Realm;
use protected_file::{
    ExistingGroup, FileFacts, OpenError, Refusal, SocketDirectoryError, SocketDirectoryOwner,
    PERMISSION_BITS,
};
use std::io::Read;
use std::path::Path;
use zeroize::Zeroizing;

/// The owner of the files dird reads before its drop: root.
/// Spec: docs/50 §7.1 ("file root:0644"), §7.4; Q-270 item 1.
const ROOT_UID: u32 = 0;

/// The permission bits of the development integrity-key file: exactly 0400.
/// Spec: docs/50 §7.4, R50-12 ("the file 0400"); docs/questions/Q-270
/// item 1.
const INTEGRITY_KEY_FILE_MODE: u32 = 0o400;

/// Octets of every key file dird reads: the integrity key's and the
/// attestation key's lengths, which are the same (both 32 — checked below),
/// so one reader serves both.
/// Spec: dirstore `INTEGRITY_KEY_LEN`; name-attestation
/// `ATTESTATION_KEY_LEN`; docs/59 §7.4.
const KEY_FILE_LEN: usize = INTEGRITY_KEY_LEN;
const _: () = assert!(ATTESTATION_KEY_LEN == KEY_FILE_LEN);

/// Open files beyond the served channels' connection bounds
/// ([`MAX_SERVED_CONNECTIONS`]): stdio, the listeners, the audit connection,
/// the redb file, the keyd clients' connections, the runtime's own
/// descriptors, and room for connections accepted only to be closed
/// (refused peers). Project choice (docs/50 §6.1: "nofile according to the
/// connection quotas").
pub const OPEN_FILES_HEADROOM: u64 = 32;

/// Every connection dird may hold open as a server at once: the bound of
/// each channel it serves — the kdc's quota, the LDAP sessions, admind's,
/// kpasswd-front's and (task DN10a) dnsd's connections — summed in this one
/// place, whether or not a service is configured, so no channel's bound can
/// be left out of the open-files limit (docs/questions/Q-1000 item 9; before
/// task DN10a the admin and kpasswd channels were not counted).
/// Spec: docs/50 §6.1 ("nofile according to the connection quotas"), §3.6;
/// docs/54 §4.6.
pub const MAX_SERVED_CONNECTIONS: usize = MAX_KDC_CONNECTIONS
    + MAX_LDAP_SESSIONS
    + crate::admin_service::MAX_ADMIN_CONNECTIONS
    + crate::kpasswd_service::MAX_KPASSWD_CONNECTIONS
    + crate::dns_service::MAX_DNS_CONNECTIONS;

/// Mode of the socket directory: owner all, group enter, other nothing —
/// the one value crates/protected-file creates every socket directory with.
/// Spec: docs/50 §3.1 ("each socket in its own directory, owned by the
/// server's uid, mode 0750").
pub const SOCKET_DIRECTORY_MODE: u32 = protected_file::SOCKET_DIRECTORY_MODE;

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
    /// account with no group write and no access for others, or a directory
    /// on its path is a symbolic link, owned by neither root nor dird's
    /// account, or writable by group or others (task R11c).
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
    /// The directory of `policy_next_path` could not be prepared (a link or
    /// a foreign or open directory on its path, an existing directory not
    /// dird's or open to others, or the creation failed) — task A16.
    PolicyNextDirectory,
    /// `dns_soa_rname` does not form a DNS name (crates/parse-dns refused
    /// its labels) — task DN10a.
    DnsRname,
    /// `attestation_key_path` is not configured: dird cannot attest a name
    /// resolution, so it does not start (task PN10; fail closed).
    AttestationKeyNotConfigured,
    /// The attestation-key file could not be opened or read.
    AttestationKeyUnreadable,
    /// The attestation-key file is not a regular file owned by root with
    /// mode 0400.
    AttestationKeyPermissions,
    /// The attestation-key file does not hold exactly 32 octets.
    AttestationKeyLength,
    /// The attestation key was refused (all zero octets — a file never
    /// filled; crate name-attestation).
    AttestationKeyRefused,
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
            StartupError::PolicyNextDirectory => f.write_str(
                "policy.next directory must be dird's, with no group write and no access for others, on a path of root's or dird's directories",
            ),
            StartupError::DnsRname => f.write_str("dns_soa_rname is not a DNS name"),
            StartupError::AttestationKeyNotConfigured => {
                f.write_str("attestation_key_path is not configured")
            }
            StartupError::AttestationKeyUnreadable => {
                f.write_str("attestation key file unreadable")
            }
            StartupError::AttestationKeyPermissions => f.write_str(
                "attestation key file must be a regular file owned by root with mode 0400",
            ),
            StartupError::AttestationKeyLength => {
                f.write_str("attestation key file must hold exactly 32 octets")
            }
            StartupError::AttestationKeyRefused => f.write_str("attestation key refused"),
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

/// Which of dird's key files [`read_key_file`] reads — for its refusals
/// (each file has its own fixed message; none carries an octet).
/// Spec: docs/50 §7.4; docs/59 §7.4; AGENTS.md §6.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyFile {
    /// The dirstore integrity key (docs/50 §7.4).
    Integrity,
    /// The name-resolution attestation key (docs/59 §7.4).
    Attestation,
}

impl KeyFile {
    /// The file could not be opened or read.
    fn unreadable(self) -> StartupError {
        match self {
            KeyFile::Integrity => StartupError::KeyUnreadable,
            KeyFile::Attestation => StartupError::AttestationKeyUnreadable,
        }
    }

    /// The file breaks the rule (regular, root's — `owner`'s —, 0400) or a
    /// directory on its path does.
    fn permissions(self) -> StartupError {
        match self {
            KeyFile::Integrity => StartupError::KeyPermissions,
            KeyFile::Attestation => StartupError::AttestationKeyPermissions,
        }
    }

    /// The file does not hold exactly [`KEY_FILE_LEN`] octets.
    fn length(self) -> StartupError {
        match self {
            KeyFile::Integrity => StartupError::KeyLength,
            KeyFile::Attestation => StartupError::AttestationKeyLength,
        }
    }
}

/// Read one of dird's key files — the one reader both keys share (module
/// documentation): a regular file (not a symbolic link — neither at the path
/// nor when opened, crates/protected-file) owned by `owner` (root in the
/// daemon), mode exactly 0400, holding exactly 32 octets, every directory on
/// its path root's or `owner`'s and not writable by group or others. Read as
/// root before the privilege drop; the reading buffer is wiped (the octets
/// live on only in the returned `Zeroizing` buffer, which the caller hands
/// to the key's own type and drops).
///
/// # Errors
/// [`StartupError`] (never carrying a key octet).
///
/// Spec: docs/50 §7.1 ("only paths to protected files"), §7.4, R50-12 (the
/// same pattern for the TLS key: "read as root before the drop, the file
/// 0400"); docs/questions/Q-213 (A-57), Q-270 item 1; A-86; Q-468 (A-102);
/// docs/59 §7.4; AGENTS.md §6 (secrets).
fn read_key_file(
    path: &Path,
    owner: u32,
    which: KeyFile,
) -> Result<Zeroizing<[u8; KEY_FILE_LEN]>, StartupError> {
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
            Err(which.permissions())
        }
    };
    let file = protected_file::open(path, owner, key_file_rule).map_err(|error| match error {
        OpenError::Io(_) => which.unreadable(),
        OpenError::Path(_) => which.permissions(),
        OpenError::Refused(refusal) => refusal,
    })?;
    let mut buffer = Zeroizing::new([0u8; KEY_FILE_LEN + 1]);
    let mut filled = 0usize;
    let mut reader = file.take(u64::try_from(KEY_FILE_LEN + 1).unwrap_or(u64::MAX));
    loop {
        let slot = buffer.get_mut(filled..).ok_or(which.length())?;
        if slot.is_empty() {
            break;
        }
        match reader.read(slot) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(which.unreadable()),
        }
    }
    if filled != KEY_FILE_LEN {
        return Err(which.length());
    }
    let mut key = Zeroizing::new([0u8; KEY_FILE_LEN]);
    key.copy_from_slice(buffer.get(..KEY_FILE_LEN).ok_or(which.length())?);
    Ok(key)
}

/// Read the development integrity key (Q-213 interim; Q-270 item 1): a
/// regular file (not a symbolic link — neither at the path nor when opened,
/// crates/protected-file) owned by `owner` (root in the daemon), mode
/// exactly 0400, holding exactly 32 octets ([`read_key_file`]). Read as root
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
    let key = read_key_file(path, owner, KeyFile::Integrity)?;
    Ok(IntegrityKey::from_bytes(&key))
}

/// Read dird's name-resolution attestation key (task PN10; docs/59 §7.4) from
/// `attestation_key_path` — the file the provisioning tool writes (task
/// PN12; docs/questions/Q-1011 item 2) — with the one key-file reader
/// ([`read_key_file`]: regular, owned by `owner` — root in the daemon —,
/// mode exactly 0400, exactly 32 octets, no symbolic link, the path's
/// directories root's or `owner`'s). Read as root before the privilege drop;
/// the octets live on only inside the `AttestationKey` (wiped on drop, no
/// accessor, no `Debug`), shared by dird's signers. An all-zero key is
/// refused (crate name-attestation: a file never filled).
///
/// # Errors
/// [`StartupError`] (never carrying a key octet).
///
/// Spec: docs/59 §7.4; docs/questions/Q-1011 item 2 (A-173: "written to
/// dird's protected key file"), Q-1046 item 5; docs/50 §7.1, §7.4; AGENTS.md
/// §6 (secrets, fail closed).
pub fn read_attestation_key(path: &Path, owner: u32) -> Result<SharedAttestationKey, StartupError> {
    let octets = read_key_file(path, owner, KeyFile::Attestation)?;
    SharedAttestationKey::from_bytes(&octets).map_err(|_| StartupError::AttestationKeyRefused)
}

/// The configured `attestation_key_path`, or — not configured — the
/// start-up refusal (task PN10: dird does not start without its attestation
/// key; the configuration accepts the file without it only until the
/// provisioning tool writes it, task PN12).
///
/// # Errors
/// [`StartupError::AttestationKeyNotConfigured`].
///
/// Spec: docs/59 §7.4; docs/questions/Q-1046 item 5; AGENTS.md §6 (fail
/// closed).
pub fn attestation_key_path(settings: &DirdSettings) -> Result<&Path, StartupError> {
    settings
        .attestation_key_path()
        .map(config::AbsolutePath::as_path)
        .ok_or(StartupError::AttestationKeyNotConfigured)
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
/// `dird_kdc_socket`, `dird_ldap_socket` and, when configured,
/// `dird_admin_socket`, `dird_kpasswd_socket` (task K7) and
/// `dird_dns_socket` (task DN10a) (docs/50 §3.1:
/// "each socket in its own directory"), each through the one implementation
/// every socket-serving
/// daemon shares (`protected_file::prepare_socket_directory`, task R11c):
/// its parent walked from `/` (no link, every directory root's or dird's,
/// none writable by group or others); missing ⇒ created relative to the
/// parent, mode exactly 0750, handed to dird's account with `fchmod` /
/// `fchown` on its own descriptor — never by path; present ⇒ it must be a
/// directory (not a link) owned by dird's uid with no group write and no
/// access for others (its group is the operator's choice of the channel's
/// clients); a stale socket in it is removed relative to its descriptor.
///
/// # Errors
/// [`StartupError`].
///
/// Spec: docs/50 §3.1, §6.2; docs/questions/Q-260 item 6 (the group is not
/// a setting); docs/52 §3.13 (C13); docs/questions/Q-532 item 1 (A-109),
/// Q-550.
pub fn prepare_socket_directory(settings: &DirdSettings) -> Result<(), StartupError> {
    let account = settings.run_as();
    let owner = SocketDirectoryOwner {
        uid: account.uid(),
        gid: account.gid(),
        existing_group: ExistingGroup::ChosenByOperator,
    };
    let admin_socket = settings.admin_channel().map(config::Channel::socket);
    let kpasswd_socket = settings.kpasswd_channel().map(config::Channel::socket);
    // Task DN10a: `dird-dns.sock`, when the DNS channel is configured.
    let dns_socket = settings.dns_service().map(|dns| dns.channel().socket());
    for socket in [
        Some(settings.kdc_channel().socket()),
        Some(settings.ldap_channel().socket()),
        admin_socket,
        kpasswd_socket,
        dns_socket,
    ]
    .into_iter()
    .flatten()
    {
        protected_file::prepare_socket_directory(socket.as_path(), owner).map_err(|error| {
            match error {
                SocketDirectoryError::NoSocketDirectory => StartupError::SocketDirectory,
                SocketDirectoryError::NotAnAccount
                | SocketDirectoryError::Path(_)
                | SocketDirectoryError::Directory(_) => StartupError::SocketDirectoryPermissions,
                SocketDirectoryError::Io(_) => StartupError::SocketDirectoryCreate,
            }
        })?;
    }
    Ok(())
}

/// dird's hardening plan: the docs/50 §6.4 baseline (drop to `run_as_uid` /
/// `run_as_gid` with the supplementary groups cleared, no_new_privs, every
/// capability dropped, core limit 0, not dumpable, umask 077), an open-files
/// limit sized from every served channel's connection bound
/// ([`MAX_SERVED_CONNECTIONS`]) and the headroom, and the working directory
/// `/`. No `mlockall`
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
    let open_files = u64::try_from(MAX_SERVED_CONNECTIONS)
        .unwrap_or(u64::MAX)
        .saturating_add(OPEN_FILES_HEADROOM);
    HardeningPlan::daemon_baseline(identity)
        .open_files_limit(open_files)
        .working_directory("/")
        .build()
}

/// The serving parameters from dird's configuration — the one product
/// constructor (docs/52 C18, task R15) — with keyd's non-secret
/// configuration for the realm (library defaults, as keyd-daemon builds it —
/// docs/47 R47-10; Q-270 item 7) and dird's attestation key, read from
/// `attestation_key_path` ([`read_attestation_key`], task PN10). The
/// daemon's constants for what the file does not set (Q-230 item 4) are
/// added by `serve`.
///
/// # Errors
/// [`StartupError::Realm`], [`StartupError::NamingContext`].
///
/// Spec: docs/50 §3.2, §3.4, §3.6, §7.1; docs/47 §7.3 (R47-10); A-53;
/// docs/59 §7.4.
pub fn params(
    settings: &DirdSettings,
    attestation_key: SharedAttestationKey,
) -> Result<DaemonParams, StartupError> {
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
        naming_context,
        keyd: KeydConfig::new(realm),
        ldap_socket: settings.ldap_channel().socket().as_path().to_path_buf(),
        ldap_front_uid: settings.ldap_channel().peer_uid(),
        dns_host_name: settings.dns_host_name().to_owned(),
        attestation_key,
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
/// configured — the one product constructor (docs/52 C18, task R15): the
/// socket and admind's uid, keyd's endpoint (its socket and uid — the
/// production keyd client over it, Role::Ldap, A-73, is built by
/// `serve_with_admin`), the ticket-age threshold, the quorum, the node-id
/// and the manifest. The daemon's constants for the connection bound, the
/// queue and the acknowledgement wait are added by `serve_with_admin`.
///
/// # Errors
/// [`StartupError::AdminSettings`].
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
    let keyd = settings.keyd().map(|endpoint| KeydEndpoint {
        socket: endpoint.socket().as_path().to_path_buf(),
        uid: endpoint.uid(),
    });
    Ok(Some(AdminParams {
        socket: channel.socket().as_path().to_path_buf(),
        admind_uid: channel.peer_uid(),
        keyd,
        ticket_age_max: service.ticket_age_max(),
        quorum,
        node_id: dirstore::NodeId(node_id),
        manifest,
        // Task A16: `policy_next_path`, owned by dird's own account — a
        // configured value of the product parameters.
        policy_next: service
            .policy_next()
            .map(|path| PolicyNextFile::new(path.as_path().to_path_buf(), settings.run_as().uid())),
    }))
}

/// The kpasswd service's parameters (task K7; docs/53 §5.6), when the
/// kpasswd channel is configured — the one product constructor (docs/52
/// C18): `dird_kpasswd_socket` and `kpasswd_front_uid`. Everything else it
/// runs with is the admin service's and the daemon's constants
/// (`serve_with_services`).
/// Spec: docs/53 §5.6 step 1; docs/questions/Q-955 item 13.
#[must_use]
pub fn kpasswd_params(settings: &DirdSettings) -> Option<KpasswdParams> {
    settings.kpasswd_channel().map(|channel| KpasswdParams {
        socket: channel.socket().as_path().to_path_buf(),
        front_uid: channel.peer_uid(),
    })
}

/// The DNS service's parameters (task DN10a; docs/54 §4.6), when the DNS
/// channel is configured — the one product constructor (docs/52 C18):
/// `dird_dns_socket`, `dnsd_uid` and the zone values of the image
/// (`ZoneParameters`, crate directory-pip): the SOA's RNAME as a DNS name
/// (its labels in order — RFC 1035 §3.3.13, §8), REFRESH / RETRY / EXPIRE /
/// MINIMUM, the infrastructure and host TTLs, `dns_record_max_age` and
/// `dns_registrable_networks` as configured — and the `_kpasswd` switch from
/// whether the kpasswd channel is configured (docs/54 §3.1: "synthesized
/// only when kpasswd exists"; one fact, not a second key — docs/questions/
/// Q-1001 item 5).
///
/// # Errors
/// [`StartupError::DnsRname`].
///
/// Spec: docs/54 §3.1, §4.4, §4.6, §5.2, §5.5; RFC 1035 §3.3.13;
/// docs/questions/Q-619 item 5, Q-991 item 4 (A-170), Q-1001.
pub fn dns_params(settings: &DirdSettings) -> Result<Option<DnsParams>, StartupError> {
    let Some(dns) = settings.dns_service() else {
        return Ok(None);
    };
    let soa = dns.soa();
    let rname = DnsName::from_labels(soa.rname().split('.').map(str::as_bytes))
        .map_err(|_| StartupError::DnsRname)?;
    let kpasswd = if settings.kpasswd_channel().is_some() {
        KpasswdService::Present
    } else {
        KpasswdService::Absent
    };
    Ok(Some(DnsParams {
        socket: dns.channel().socket().as_path().to_path_buf(),
        dnsd_uid: dns.channel().peer_uid(),
        zone: ZoneParameters {
            soa: SoaParameters {
                rname,
                refresh: soa.refresh(),
                retry: soa.retry(),
                expire: soa.expire(),
                minimum: soa.minimum(),
            },
            infrastructure_ttl: dns.infrastructure_ttl(),
            host_ttl: dns.host_ttl(),
            kpasswd,
            max_record_age: dns.record_max_age().as_secs(),
            registrable_networks: dns.registrable_networks().to_vec(),
        },
    }))
}

/// The directory of `policy.next` (task A16, docs/51 §5.10), when the admin
/// service names one: prepared as root before the drop through the one
/// implementation every daemon-owned directory shares
/// (`protected_file::prepare_daemon_directory`, the socket directory's
/// steps): its parent walked from `/` (no link, every directory root's or
/// dird's, none writable by group or others); missing ⇒ created relative to
/// the parent, mode exactly 0750, handed to dird's account with `fchmod` /
/// `fchown` on its own descriptor; present ⇒ it must be dird's, with no
/// group write and no access for others. Nothing in it is removed (a pending
/// `policy.next` survives a restart).
///
/// # Errors
/// [`StartupError::PolicyNextDirectory`].
///
/// Spec: docs/51 §5.10; docs/52 §3.13 (C13); docs/questions/Q-591.
pub fn prepare_policy_next_directory(settings: &DirdSettings) -> Result<(), StartupError> {
    let Some(path) = settings
        .admin_service()
        .and_then(config::AdminServiceSettings::policy_next)
    else {
        return Ok(());
    };
    let account = settings.run_as();
    let owner = SocketDirectoryOwner {
        uid: account.uid(),
        gid: account.gid(),
        existing_group: ExistingGroup::ChosenByOperator,
    };
    protected_file::prepare_daemon_directory(path.as_path(), owner)
        .map_err(|_| StartupError::PolicyNextDirectory)
}
