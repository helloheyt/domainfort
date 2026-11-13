//! Tier 1 (docs/50 §9): the start-up file rules of crates/ldap-front
//! startup — the configuration (root-owned, not group/other-writable,
//! bounded), the DC certificate (the same), the DC key (root-owned, mode
//! exactly 0400, bounded) — with the test's own uid as the owner (`main`
//! passes 0); the TLS configuration built from files; the hardening plan;
//! the listeners bound from the configuration.
//!
//! Sources: docs/50 R50-12 ("the key file 0400, read as root before the
//! privilege drop"), R50-14, R50-15, §5.3, §6.1, §6.4, §7.1; crates/config
//! `LdapFrontSettings` (its sample in crates/config/tests/common). Every
//! value is made here; the keys are generated per run (tests/common/tls.rs).

#[path = "common/cert.rs"]
mod cert_support;

#[path = "common/tls.rs"]
mod tls_support;

use ldap_front::startup::{
    bind_listeners, hardening_plan, load_tls_config, read_certificate, read_private_key,
    read_settings, StartupError, MAX_CERTIFICATE_OCTETS, MAX_PRIVATE_KEY_OCTETS,
    OPEN_FILES_HEADROOM,
};
use ldap_front::tls::CredentialError;
use ldap_front::MAX_CONNECTIONS;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

/// A unique temporary directory, removed on drop.
struct TempDir(PathBuf);

static NEXT: AtomicU32 = AtomicU32::new(0);

impl TempDir {
    fn new() -> TempDir {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("lfs-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    /// The uid that owns files this process creates.
    fn uid(&self) -> u32 {
        std::fs::metadata(&self.0).unwrap().uid()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn write(path: &Path, octets: &[u8], mode: u32) {
    std::fs::write(path, octets).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// A configuration for `dir` (the crates/config sample's shape, with the
/// certificate and key paths in `dir` and the given listener).
fn settings_text(dir: &TempDir, listen: &str) -> String {
    format!(
        "run_as_uid = 61004\nrun_as_gid = 61004\nldaps_listen = {listen}\n\
         tls_certificate_path = {}\ntls_private_key_path = {}\n\
         dird_ldap_socket = /run/dird/ldap/dird-ldap.sock\ndird_uid = 61002\n\
         audit_socket = /run/auditd/audit.sock\nauditd_uid = 61005\n",
        dir.join("cert.der").display(),
        dir.join("key.der").display()
    )
}

/// docs/50 R50-12, §5.3, §6.4: the key file must be owned by the owner and
/// have mode exactly 0400; anything else is refused before a byte of it is
/// used; a file over the bound is refused.
#[test]
fn the_key_file_rules() {
    let dir = TempDir::new();
    let owner = dir.uid();
    let key = tls_support::p256_key();
    let path = dir.join("key.der");
    write(&path, &key, 0o400);
    assert_eq!(
        read_private_key(&path, owner).unwrap().as_slice(),
        key.as_slice()
    );
    assert_eq!(
        read_private_key(&path, owner.wrapping_add(1)).err(),
        Some(StartupError::KeyPermissions)
    );
    for mode in [0o600, 0o440, 0o404, 0o4400] {
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        assert_eq!(
            read_private_key(&path, owner).err(),
            Some(StartupError::KeyPermissions),
            "mode {mode:o}"
        );
    }
    // Mode 0000: refused either way (unreadable to a non-root owner).
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
    assert!(read_private_key(&path, owner).is_err());
    let large = dir.join("large.der");
    write(&large, &vec![0u8; MAX_PRIVATE_KEY_OCTETS + 1], 0o400);
    assert_eq!(
        read_private_key(&large, owner).err(),
        Some(StartupError::KeyTooLarge)
    );
    let exact = dir.join("exact.der");
    write(&exact, &vec![0u8; MAX_PRIVATE_KEY_OCTETS], 0o400);
    assert_eq!(
        read_private_key(&exact, owner).unwrap().len(),
        MAX_PRIVATE_KEY_OCTETS
    );
    assert_eq!(
        read_private_key(&dir.join("absent.der"), owner).err(),
        Some(StartupError::KeyUnreadable)
    );
    assert_eq!(
        read_private_key(&dir.0, owner).err(),
        Some(StartupError::KeyPermissions)
    );
}

/// docs/50 R50-12, §5.3: the certificate is public but must not be
/// replaceable — owned by the owner, not group/other-writable, bounded.
#[test]
fn the_certificate_file_rules() {
    let dir = TempDir::new();
    let owner = dir.uid();
    let path = dir.join("cert.der");
    write(&path, b"certificate octets", 0o644);
    assert_eq!(
        read_certificate(&path, owner).unwrap(),
        b"certificate octets"
    );
    for mode in [0o664, 0o646] {
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        assert_eq!(
            read_certificate(&path, owner).err(),
            Some(StartupError::CertificatePermissions)
        );
    }
    let large = dir.join("large.der");
    write(&large, &vec![0u8; MAX_CERTIFICATE_OCTETS + 1], 0o644);
    assert_eq!(
        read_certificate(&large, owner).err(),
        Some(StartupError::CertificateTooLarge)
    );
}

/// docs/50 R50-15, §7.1 ("file root:0644"): the configuration's owner and
/// mode, then its content.
#[test]
fn the_configuration_file_rules() {
    let dir = TempDir::new();
    let owner = dir.uid();
    let path = dir.join("ldap-front.conf");
    write(&path, settings_text(&dir, "10.0.0.5:636").as_bytes(), 0o644);
    let settings = read_settings(&path, owner).unwrap();
    assert_eq!(settings.ldaps_listen().len(), 1);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
    assert_eq!(
        read_settings(&path, owner).err(),
        Some(StartupError::ConfigPermissions)
    );
    let bad = dir.join("bad.conf");
    write(&bad, b"no_such_key = 1\n", 0o644);
    assert!(matches!(
        read_settings(&bad, owner),
        Err(StartupError::Config(_))
    ));
}

/// docs/50 R50-12, §5.3 (task P11: the key is checked against the
/// certificate; Q-320: the certificate's own checks): from files, with a
/// real per-run certificate (tests/common/cert.rs) — a P-384 key is refused
/// as not P-256, a P-256 key that is not the certificate's fails the match,
/// the right key builds the configuration, and the same certificate is
/// refused at a start time after its notAfter (RFC 5280 §4.1.2.5).
#[test]
fn the_tls_configuration_from_files() {
    let dir = TempDir::new();
    let owner = dir.uid();
    let config_path = dir.join("ldap-front.conf");
    write(
        &config_path,
        settings_text(&dir, "10.0.0.5:636").as_bytes(),
        0o644,
    );
    let settings = read_settings(&config_path, owner).unwrap();
    let now = ldap_front::startup::start_time().unwrap();
    let pki = tls_support::pki();
    let key_path = dir.join("key.der");
    let replace_key = |octets: &[u8]| {
        if key_path.exists() {
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        write(&key_path, octets, 0o400);
    };
    write(&dir.join("cert.der"), &pki.server_certificate, 0o644);
    replace_key(&tls_support::p384_pkcs8());
    assert_eq!(
        load_tls_config(&settings, owner, now).err(),
        Some(StartupError::Credential(CredentialError::NotP256))
    );
    replace_key(&tls_support::p256_key());
    assert_eq!(
        load_tls_config(&settings, owner, now).err(),
        Some(StartupError::Credential(CredentialError::KeyMismatch))
    );
    replace_key(&pki.server_key);
    assert!(load_tls_config(&settings, owner, now).is_ok());
    // A certificate that ended at 2025-01-01T00:00:10Z, loaded now.
    let mut short = cert_support::EndEntity::server(&pki.server_key);
    short.not_after = cert_support::build::utc_time("250101000010Z");
    write(&dir.join("cert.der"), &pki.ca.issue(&short), 0o644);
    assert_eq!(
        load_tls_config(&settings, owner, now).err(),
        Some(StartupError::Credential(CredentialError::Expired))
    );
}

/// docs/50 R50-14, §6.1 ("nofile according to the connection quotas"),
/// §6.4 (the baseline): the plan drops to the configured account, sets
/// no_new_privs, drops every capability, disables core dumps, makes the
/// process not dumpable, and bounds the open files by two descriptors per
/// connection plus the listeners and the headroom.
#[test]
fn the_hardening_plan() {
    let dir = TempDir::new();
    let settings =
        config::LdapFrontSettings::parse(settings_text(&dir, "10.0.0.5:636").as_bytes()).unwrap();
    let plan = hardening_plan(&settings).unwrap();
    let identity = plan.identity().unwrap();
    assert_eq!((identity.uid(), identity.gid()), (61004, 61004));
    assert!(plan.sets_no_new_privs());
    assert!(plan.drops_capabilities());
    assert!(plan.disables_core_dumps());
    assert!(plan.makes_not_dumpable());
    assert!(!plan.locks_all_memory());
    assert_eq!(
        plan.open_files_limit(),
        Some(MAX_CONNECTIONS as u64 * 2 + 1 + OPEN_FILES_HEADROOM)
    );
}

/// docs/50 §4.2, §6.2: the configured listener is bound (a loopback high
/// port found free just before; never a privileged port).
#[test]
fn the_listeners_are_bound() {
    let dir = TempDir::new();
    let free = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = free.local_addr().unwrap();
    drop(free);
    let settings =
        config::LdapFrontSettings::parse(settings_text(&dir, &address.to_string()).as_bytes())
            .unwrap();
    let listeners = bind_listeners(&settings).unwrap();
    assert!(listeners.ldap.is_empty());
    assert_eq!(listeners.ldaps.len(), 1);
    assert_eq!(listeners.ldaps[0].local_addr().unwrap(), address);
}
