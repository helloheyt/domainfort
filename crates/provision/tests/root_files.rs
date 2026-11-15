//! The two root-owned inputs of `provision first-admin-secret`, read
//! directly (`first_admin::root_files`): admind's configuration file and the
//! provisioning manifest, each accepted through its own path and refused
//! through a symbolic link (task F7: one reader — crates/protected-file and
//! crates/provision-manifest's `read_manifest_owned_by` — A-86 / A-96
//! follow-ups, Q-414 item 4).
//!
//! The tests run as an ordinary account, which stands in for root (the
//! readers take the owner, as `run`'s `root_uid`).
//!
//! Sources: docs/51 §4.3 steps 7, 8, 12; docs/50 §7.1 ("file root:0644");
//! A-86; A-96. The admind text is hand-written in the docs/50 §7.1 format
//! (obviously fake ids and paths); the manifest is provision-manifest's
//! documented example (obviously fake values).

use provision::first_admin::root_files::{read_admind_settings, read_manifest, RootFileError};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use test_scratch::ScratchDir;

/// admind's required keys (docs/50 §2.4, §3.2; docs/51 §4.6; A-79).
const ADMIND: &str = "\
run_as_uid = 806
run_as_gid = 806
admin_socket = /run/admind/admin.sock
admin_socket_group = 810
min_password_length = 14
dird_admin_socket = /run/dird/admin/dird-admin.sock
dird_uid = 802
keyd_socket = /run/keyd/keyd.sock
keyd_uid = 801
audit_socket = /run/auditd/audit.sock
auditd_uid = 805
";

/// The manifest example of crates/provision-manifest's documentation.
const MANIFEST: &str = "\
manifest_version = 1
realm = EXAMPLE.TEST
domain_sid = S-1-5-21-1-2-3
naming_context = dc=example,dc=test
dc_fqdn = dc1.example.test
krbtgt = 00000000-0000-0000-0000-000000000001:NT-SRV-INST:krbtgt/EXAMPLE.TEST
ldap_service = 00000000-0000-0000-0000-000000000002:NT-SRV-HST:ldap/dc1.example.test
admin_service = 00000000-0000-0000-0000-000000000003:NT-SRV-HST:admind/dc1.example.test
change_password_service = 00000000-0000-0000-0000-000000000006:NT-SRV-INST:kadmin/changepw
first_admins = 00000000-0000-0000-0000-000000000004:NT-PRINCIPAL:alice, 00000000-0000-0000-0000-000000000005:NT-PRINCIPAL:bob
first_admin_salts = salt-a, salt-b
";

/// A scratch directory inside the workspace (crates/test-scratch: the
/// protected-file walk from `/` accepts it; Q-480), removed on drop.
struct Scratch(PathBuf, #[allow(dead_code)] ScratchDir);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        let dir = ScratchDir::new(&format!("prov-rootfiles-{tag}")).unwrap();
        Scratch(dir.path().to_path_buf(), dir)
    }
}

fn write(path: &Path, text: &str) {
    std::fs::write(path, text).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
}

/// A-86 / A-96: each file is read through its own path, and a symbolic link
/// to it is `NotRegular` — never followed; another owner is `NotRootOwned`.
#[test]
fn a_symbolic_link_to_a_valid_root_file_is_refused() {
    let dir = Scratch::new("link");
    let admind = dir.0.join("admind.conf");
    write(&admind, ADMIND);
    let manifest = dir.0.join("manifest");
    write(&manifest, MANIFEST);
    let uid = std::fs::metadata(&admind).unwrap().uid();
    assert_eq!(
        read_admind_settings(&admind, uid)
            .unwrap()
            .admin_socket_group(),
        810
    );
    assert_eq!(
        read_manifest(&manifest, uid).unwrap().first_admins().len(),
        2
    );
    let admind_link = dir.0.join("admind-link.conf");
    std::os::unix::fs::symlink(&admind, &admind_link).unwrap();
    assert_eq!(
        read_admind_settings(&admind_link, uid).unwrap_err(),
        RootFileError::NotRegular
    );
    let manifest_link = dir.0.join("manifest-link");
    std::os::unix::fs::symlink(&manifest, &manifest_link).unwrap();
    assert_eq!(
        read_manifest(&manifest_link, uid).unwrap_err(),
        RootFileError::NotRegular
    );
    assert_eq!(
        read_admind_settings(&admind, uid.wrapping_add(1)).unwrap_err(),
        RootFileError::NotRootOwned
    );
    assert_eq!(
        read_manifest(&manifest, uid.wrapping_add(1)).unwrap_err(),
        RootFileError::NotRootOwned
    );
}

/// Task T (docs/52 R11; Q-468 options 1, 2(b), A-102): every directory on
/// each file's path is checked — a symbolic link in a directory component is
/// `NotRegular`, a directory writable by group or others is
/// `WritableByOthers`; both files through real, unwritable directories are
/// read.
#[test]
fn a_link_or_a_writable_directory_on_the_path_is_refused() {
    let dir = Scratch::new("dirs");
    let real = dir.0.join("real");
    std::fs::create_dir(&real).unwrap();
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o755)).unwrap();
    let admind = real.join("admind.conf");
    write(&admind, ADMIND);
    let manifest = real.join("manifest");
    write(&manifest, MANIFEST);
    let uid = std::fs::metadata(&admind).unwrap().uid();
    assert!(read_admind_settings(&admind, uid).is_ok());
    assert!(read_manifest(&manifest, uid).is_ok());
    std::os::unix::fs::symlink(&real, dir.0.join("via")).unwrap();
    assert_eq!(
        read_admind_settings(&dir.0.join("via/admind.conf"), uid).unwrap_err(),
        RootFileError::NotRegular
    );
    assert_eq!(
        read_manifest(&dir.0.join("via/manifest"), uid).unwrap_err(),
        RootFileError::NotRegular
    );
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o775)).unwrap();
    assert_eq!(
        read_admind_settings(&admind, uid).unwrap_err(),
        RootFileError::WritableByOthers
    );
    assert_eq!(
        read_manifest(&manifest, uid).unwrap_err(),
        RootFileError::WritableByOthers
    );
}
