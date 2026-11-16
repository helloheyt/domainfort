//! Tier 1 (docs/50 §9: in-process): dird's start-up inputs.
//!
//! * the UNSIGNED development policy file through the shared crate
//!   (policy-store, A-68): its tier map classifies as written, and a
//!   format-1 file (this crate's own file before A-68) is refused at load.
//!   The format tests themselves — round trip, canonical encoding, the
//!   marker, every content rule — moved to crates/policy-store/tests with
//!   the decoder (docs/50 §7.2; Q-219 → A-57; Q-270 item 2);
//! * the development integrity-key file — owner, mode 0400, exactly 32
//!   octets, no symbolic link; a key read from it opens the store it sealed
//!   and no other (docs/50 §7.4; Q-213 → A-57; Q-270 item 1);
//! * the name-resolution attestation-key file (task PN10) — the same rule,
//!   an all-zero key refused, the key path required by the start though the
//!   configuration accepts the file without it (docs/59 §7.4; Q-1011 item
//!   2; docs/questions/Q-1046 item 5);
//! * the policy file's owner / mode checks and its absence (fail closed);
//! * the configuration's owner check; the serving parameters and the
//!   hardening plan derived from a configuration (docs/50 §6.4, §7.1);
//! * the socket directories, prepared by descriptor through
//!   crates/protected-file (docs/50 §3.1; task R11c, docs/questions Q-532
//!   item 1).
//!
//! The root-owned case cannot be made by an unprivileged test: the reading
//! functions take the expected owner, and `main` passes uid 0.
//!
//! Sources: docs/50 R50-14, §3.3, §6.4, §7.1, §7.2, §7.4, §9; [MS-DTYP]
//! 2.4.2.2; A-36; A-68; docs/questions/Q-213, Q-219, Q-270; docs/59 §7.4
//! (task PN10). Every value is hand-made.

mod support;

use directory_daemon::policy::{
    tier_map, DevelopmentPolicy, MandatoryFast, PolicyError, MARKER, SUPERSEDED_FORMAT,
};
use directory_daemon::startup::{
    attestation_key_path, hardening_plan, params, prepare_socket_directory, read_attestation_key,
    read_integrity_key, read_policy, read_settings, read_settings_owned_by, StartupError,
    SOCKET_DIRECTORY_MODE,
};
use dirstore::Store;
use dtyp::{Sid, SECURITY_NT_AUTHORITY};
use pdp::{Dn, PolicyVersion, RuleId, Tier};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use support::TempDir;
// The files the tests read through crates/protected-file live in a scratch
// directory the walk from `/` accepts (crates/test-scratch, Q-480); sockets
// stay in `TempDir`.
use test_scratch::ScratchDir;

fn sid(rid: u32) -> Sid {
    Sid::new(SECURITY_NT_AUTHORITY, &[21, 7, 8, 9, rid]).unwrap()
}

fn sample_policy() -> DevelopmentPolicy {
    DevelopmentPolicy {
        version: PolicyVersion(42),
        principals: [
            (sid(512), Tier::Tier0),
            (sid(1030), Tier::Tier2),
            (sid(1101), Tier::Tier1),
        ]
        .into_iter()
        .collect(),
        subtrees: vec![
            (
                Dn::new(vec![
                    String::from("ou=Servers"),
                    String::from("dc=example"),
                    String::from("dc=org"),
                ]),
                Tier::Tier1,
            ),
            (
                Dn::new(vec![
                    String::from("ou=Staff"),
                    String::from("dc=example"),
                    String::from("dc=org"),
                ]),
                Tier::Tier2,
            ),
        ],
        mandatory_fast: MandatoryFast {
            bootstrap_group: sid(1500),
            first_rule_id: RuleId(100),
        },
        rules: Vec::new(),
        anonymous: Vec::new(),
    }
}

fn write(path: &Path, octets: &[u8], mode: u32) {
    std::fs::write(path, octets).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// docs/47 §6.3 (R47-9); A-36; A-68: the tier map dird builds from the
/// shared file's entries is accepted (the shared decoder refuses every DN
/// directory-pip would refuse), for the sample and for the empty policy.
#[test]
fn the_shared_policy_gives_dird_its_tier_map() {
    let policy = sample_policy();
    let decoded = DevelopmentPolicy::decode(&policy.encode().unwrap()).unwrap();
    assert_eq!(decoded, policy);
    assert!(tier_map(&decoded).is_ok());
    assert!(tier_map(&support::policy(1)).is_ok());
}

/// A-68 ("old version refused or migrated, as documented"): dird's own
/// format-1 file of task P8 — marker ‖ 1 ‖ version ‖ principals ‖ subtrees —
/// no longer starts dird; it must be re-encoded as format 2.
#[test]
fn a_format_1_policy_file_is_refused_at_load() {
    let dir = ScratchDir::new("dird-startup").unwrap();
    let uid = dir.uid().unwrap();
    let mut v1 = MARKER.to_vec();
    v1.push(SUPERSEDED_FORMAT);
    v1.extend_from_slice(&1u64.to_be_bytes());
    v1.extend_from_slice(&0u32.to_be_bytes());
    v1.extend_from_slice(&0u32.to_be_bytes());
    let path = dir.join("v1.store");
    write(&path, &v1, 0o644);
    assert_eq!(
        read_policy(&path, uid).err(),
        Some(StartupError::Policy(PolicyError::Superseded))
    );
}

/// docs/50 §7.4, R50-12 (the root-only 0400 file read before the drop);
/// Q-213 (A-57); Q-270 item 1: the key file must be a regular file of the
/// expected owner, mode exactly 0400, exactly 32 octets; a key read from it
/// opens the store it sealed, and a store sealed with another key refuses it
/// (`Tamper`, docs/50 §7.5 step 3).
#[test]
fn the_integrity_key_file_is_checked_and_opens_its_store() {
    let dir = ScratchDir::new("dird-startup").unwrap();
    let uid = dir.uid().unwrap();
    let key_path = dir.join("integrity.key");
    write(&key_path, &support::TEST_KEY, 0o400);
    let store_path = dir.join("s.redb");
    drop(support::Directory::standard(&store_path));
    let p1 = ad_schema::phase1().unwrap();

    let key = read_integrity_key(&key_path, uid).unwrap();
    assert!(Store::open(&store_path, key, p1.schema().clone()).is_ok());

    let other = dir.join("other.key");
    write(&other, &[0x11; 32], 0o400);
    let wrong = read_integrity_key(&other, uid).unwrap();
    assert!(matches!(
        Store::open(&store_path, wrong, p1.schema().clone()),
        Err(dirstore::Error::Tamper(_))
    ));

    assert_eq!(
        read_integrity_key(&key_path, uid + 1).err(),
        Some(StartupError::KeyPermissions)
    );
    for mode in [0o600, 0o440, 0o404, 0o500, 0o4400] {
        let path = dir.join(format!("k{mode:o}"));
        write(&path, &support::TEST_KEY, 0o600);
        // set_permissions may refuse the set-uid bit for a non-root user:
        // the mode actually set is what is checked.
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode));
        assert_eq!(
            read_integrity_key(&path, uid).err(),
            Some(StartupError::KeyPermissions),
            "mode {mode:o}"
        );
    }
    for length in [0usize, 31, 33, 64] {
        let path = dir.join(format!("len{length}"));
        write(&path, &vec![0x5D; length], 0o400);
        assert_eq!(
            read_integrity_key(&path, uid).err(),
            Some(StartupError::KeyLength),
            "length {length}"
        );
    }
    let link = dir.join("link.key");
    std::os::unix::fs::symlink(&key_path, &link).unwrap();
    assert_eq!(
        read_integrity_key(&link, uid).err(),
        Some(StartupError::KeyPermissions)
    );
    assert_eq!(
        read_integrity_key(&dir.join("absent.key"), uid).err(),
        Some(StartupError::KeyUnreadable)
    );
    // The error never carries key octets.
    let shown = format!("{:?} {}", StartupError::KeyLength, StartupError::KeyLength);
    assert!(!shown.contains("5d") && !shown.contains("93"));
}

/// docs/59 §7.4 (dird's protected key file); docs/questions/Q-1011 item 2
/// (A-173), Q-1046 item 5 (task PN10): the attestation-key file obeys the
/// integrity key's rule — the expected owner, mode exactly 0400, exactly 32
/// octets, no symbolic link, present — through the one reader, with its own
/// refusals; an all-zero key (a file never filled) is refused; a refusal
/// carries no key octet, and the key's handle prints none.
#[test]
fn the_attestation_key_file_is_checked() {
    let dir = ScratchDir::new("dird-startup").unwrap();
    let uid = dir.uid().unwrap();
    let key_path = dir.join("attestation.key");
    write(&key_path, &support::TEST_ATTESTATION_KEY, 0o400);
    let key = read_attestation_key(&key_path, uid).unwrap();
    assert_eq!(format!("{key:?}"), "SharedAttestationKey(..)");

    assert_eq!(
        read_attestation_key(&key_path, uid + 1).err(),
        Some(StartupError::AttestationKeyPermissions)
    );
    for mode in [0o600, 0o440, 0o404, 0o500] {
        let path = dir.join(format!("a{mode:o}"));
        write(&path, &support::TEST_ATTESTATION_KEY, 0o600);
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode));
        assert_eq!(
            read_attestation_key(&path, uid).err(),
            Some(StartupError::AttestationKeyPermissions),
            "mode {mode:o}"
        );
    }
    for length in [0usize, 31, 33, 64] {
        let path = dir.join(format!("alen{length}"));
        write(&path, &vec![0x5D; length], 0o400);
        assert_eq!(
            read_attestation_key(&path, uid).err(),
            Some(StartupError::AttestationKeyLength),
            "length {length}"
        );
    }
    let zero = dir.join("zero.key");
    write(&zero, &[0u8; 32], 0o400);
    assert_eq!(
        read_attestation_key(&zero, uid).err(),
        Some(StartupError::AttestationKeyRefused)
    );
    let link = dir.join("alink.key");
    std::os::unix::fs::symlink(&key_path, &link).unwrap();
    assert_eq!(
        read_attestation_key(&link, uid).err(),
        Some(StartupError::AttestationKeyPermissions)
    );
    assert_eq!(
        read_attestation_key(&dir.join("absent.key"), uid).err(),
        Some(StartupError::AttestationKeyUnreadable)
    );
    // The integrity key's refusals stay its own (the one reader, two files).
    assert_eq!(
        read_integrity_key(&dir.join("absent.key"), uid).err(),
        Some(StartupError::KeyUnreadable)
    );
    for refusal in [
        StartupError::AttestationKeyNotConfigured,
        StartupError::AttestationKeyUnreadable,
        StartupError::AttestationKeyPermissions,
        StartupError::AttestationKeyLength,
        StartupError::AttestationKeyRefused,
    ] {
        let shown = format!("{refusal:?} {refusal}");
        assert!(!shown.contains("4b") && !shown.contains("75"), "{shown}");
    }
}

/// docs/59 §7.4; docs/questions/Q-1046 item 5 (task PN10): the configuration
/// accepts dird's file without `attestation_key_path` (until the
/// provisioning tool writes it, task PN12), but dird's start does not — and
/// with the key the start's parameters carry it.
#[test]
fn the_start_requires_the_attestation_key_path() {
    let without = config::DirdSettings::parse(DIRD.as_bytes()).unwrap();
    assert_eq!(
        attestation_key_path(&without).err(),
        Some(StartupError::AttestationKeyNotConfigured)
    );
    let with = config::DirdSettings::parse(
        format!("{DIRD}attestation_key_path = /etc/dird/attestation.key\n").as_bytes(),
    )
    .unwrap();
    assert_eq!(
        attestation_key_path(&with).unwrap(),
        Path::new("/etc/dird/attestation.key")
    );
    let p = params(&with, support::attestation_key()).unwrap();
    assert_eq!(
        format!("{:?}", p.attestation_key),
        "SharedAttestationKey(..)"
    );
}

/// docs/50 §7.2 ("dird loads the same file at start"; absent or invalid ⇒
/// do not start): the policy file must be of the expected owner and not
/// writable by group or others; absent is refused.
#[test]
fn the_policy_file_is_checked_and_absent_is_refused() {
    let dir = ScratchDir::new("dird-startup").unwrap();
    let uid = dir.uid().unwrap();
    let path = dir.join("policy.store");
    let file = sample_policy().encode().unwrap();
    write(&path, &file, 0o644);
    assert_eq!(read_policy(&path, uid).unwrap(), sample_policy());
    assert_eq!(
        read_policy(&path, uid + 1).err(),
        Some(StartupError::PolicyPermissions)
    );
    for mode in [0o664, 0o646, 0o666] {
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        assert_eq!(
            read_policy(&path, uid).err(),
            Some(StartupError::PolicyPermissions),
            "mode {mode:o}"
        );
    }
    assert_eq!(
        read_policy(&dir.join("absent"), uid).err(),
        Some(StartupError::PolicyUnreadable)
    );
    let broken = dir.join("broken.store");
    write(&broken, b"not a policy", 0o644);
    assert_eq!(
        read_policy(&broken, uid).err(),
        Some(StartupError::Policy(PolicyError::NotMarked))
    );
}

/// A dird configuration (docs/50 §7.1) with the development sources named
/// explicitly (Q-270 items 1-2); account 61002.
const DIRD: &str = "\
run_as_uid = 61002
run_as_gid = 61002
realm = EXAMPLE.ORG
naming_context = dc=example,dc=org
dns_host_name = dc1.example.org
database_path = /var/lib/dird/directory.redb
integrity_key_source = insecure-development-file
integrity_key_path = /etc/dird/integrity.key
policy_store_path = /etc/domain/policy.store
policy_store_format = unsigned-development
dird_kdc_socket = /run/dird/kdc/dird-kdc.sock
kdc_uid = 61003
dird_ldap_socket = /run/dird/ldap/dird-ldap.sock
ldap_front_uid = 61004
audit_socket = /run/auditd/audit.sock
auditd_uid = 61005
view_lifetime = 3s
";

/// Task R11c (docs/50 §3.1; docs/52 C13; docs/questions Q-532 item 1,
/// A-109): dird's socket directories are created by descriptor — mode 0750
/// exactly, owned by dird's account (the test account stands in) — and a
/// symbolic link at one of their names is refused without anything being
/// changed through it.
#[test]
fn the_socket_directories_are_prepared_by_descriptor() {
    let dir = ScratchDir::new("dird-sock").unwrap();
    let uid = dir.uid().unwrap();
    if uid == 0 {
        return;
    }
    // The scratch directory's group: one the test account belongs to, so
    // the owner change of a created directory is allowed unprivileged.
    let gid = std::fs::metadata(dir.path()).unwrap().gid();
    let text = |kdc: &Path, ldap: &Path| {
        DIRD.replace("run_as_uid = 61002", &format!("run_as_uid = {uid}"))
            .replace("run_as_gid = 61002", &format!("run_as_gid = {gid}"))
            .replace(
                "dird_kdc_socket = /run/dird/kdc/dird-kdc.sock",
                &format!("dird_kdc_socket = {}/dird-kdc.sock", kdc.display()),
            )
            .replace(
                "dird_ldap_socket = /run/dird/ldap/dird-ldap.sock",
                &format!("dird_ldap_socket = {}/dird-ldap.sock", ldap.display()),
            )
    };
    let settings = |text: String| config::DirdSettings::parse(text.as_bytes()).unwrap();
    let (kdc, ldap) = (dir.join("kdc"), dir.join("ldap"));
    assert_eq!(
        prepare_socket_directory(&settings(text(&kdc, &ldap))),
        Ok(())
    );
    for created in [&kdc, &ldap] {
        let metadata = std::fs::symlink_metadata(created).unwrap();
        assert!(metadata.is_dir());
        assert_eq!(metadata.mode() & 0o7777, SOCKET_DIRECTORY_MODE);
        assert_eq!((metadata.uid(), metadata.gid()), (uid, gid));
    }
    let real = dir.join("real");
    std::fs::create_dir(&real).unwrap();
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
    let link = dir.join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    assert_eq!(
        prepare_socket_directory(&settings(text(&kdc, &link))),
        Err(StartupError::SocketDirectoryPermissions)
    );
    assert_eq!(std::fs::metadata(&real).unwrap().mode() & 0o7777, 0o700);
}

/// docs/50 §3.2, §3.4, §6.4, §7.1; Q-230 item 4: the serving parameters
/// come from the configuration and the daemon's constants; the hardening
/// plan is the §6.4 baseline for dird's account, with a bounded open-files
/// limit and no memory locking; a configuration not owned by root is
/// refused before it is parsed.
#[test]
fn parameters_plan_and_configuration_owner() {
    let settings = config::DirdSettings::parse(DIRD.as_bytes()).unwrap();
    // docs/52 C18 (task R15): the product parameters carry only the file's
    // values; the constants the product `serve` adds are read back through
    // the test seam's conversion (the one `serve` uses).
    let p = directory_daemon::test_seams::DaemonParams::from(
        params(&settings, support::attestation_key()).unwrap(),
    );
    assert_eq!(p.kdc_uid, 61003);
    assert_eq!(p.kdc_socket, Path::new("/run/dird/kdc/dird-kdc.sock"));
    assert_eq!(p.audit.uid, 61005);
    assert_eq!(p.view_lifetime, core::time::Duration::from_secs(3));
    assert_eq!(p.max_views, directory_daemon::MAX_OPEN_VIEWS);
    assert_eq!(p.max_connections, directory_daemon::MAX_KDC_CONNECTIONS);
    assert_eq!(p.naming_context.labels(), ["example", "org"]);
    assert_eq!(p.keyd.realm.as_str(), "EXAMPLE.ORG");
    // The LDAP service (task P10; docs/50 §3.2, §4.2; Q-280 items 4, 6).
    assert_eq!(p.ldap_socket, Path::new("/run/dird/ldap/dird-ldap.sock"));
    assert_eq!(p.ldap_front_uid, 61004);
    assert_eq!(p.dns_host_name, "dc1.example.org");
    assert_eq!(p.max_ldap_sessions, directory_daemon::MAX_LDAP_SESSIONS);
    assert_eq!(p.ldap_queue_capacity, directory_daemon::LDAP_QUEUE_CAPACITY);

    let plan = hardening_plan(&settings).unwrap();
    let identity = plan.identity().unwrap();
    assert_eq!((identity.uid(), identity.gid()), (61002, 61002));
    assert!(plan.sets_no_new_privs());
    assert!(plan.drops_capabilities());
    assert!(plan.disables_core_dumps());
    assert!(plan.makes_not_dumpable());
    assert!(!plan.locks_all_memory());
    assert_eq!(plan.file_mode_mask(), Some(0o077));
    // Sized from every served channel's connection bound — the kdc's quota,
    // the LDAP sessions, admind's, kpasswd-front's and dnsd's connections
    // (docs/50 §6.1: "nofile according to the connection quotas";
    // docs/questions/Q-1000 item 9).
    assert_eq!(
        directory_daemon::startup::MAX_SERVED_CONNECTIONS,
        directory_daemon::MAX_KDC_CONNECTIONS
            + directory_daemon::MAX_LDAP_SESSIONS
            + directory_daemon::MAX_ADMIN_CONNECTIONS
            + directory_daemon::MAX_KPASSWD_CONNECTIONS
            + directory_daemon::MAX_DNS_CONNECTIONS
    );
    assert_eq!(
        plan.open_files_limit(),
        Some(
            u64::try_from(directory_daemon::startup::MAX_SERVED_CONNECTIONS).unwrap()
                + directory_daemon::startup::OPEN_FILES_HEADROOM
        )
    );

    let dir = TempDir::new();
    let path = dir.join("dird.conf");
    write(&path, DIRD.as_bytes(), 0o644);
    if support::my_uid(&dir) != 0 {
        assert_eq!(
            read_settings(&path).err(),
            Some(StartupError::ConfigPermissions)
        );
    }
}

/// Task F7 (A-86 follow-up, "O_NOFOLLOW in every reader"): with the test
/// account standing in for root, dird's configuration and policy files are
/// read through their own paths, and a symbolic link to either is refused
/// as a permissions error (not a regular file) — never followed. (The
/// integrity key's link case is in
/// `the_integrity_key_file_is_checked_and_opens_its_store`; the manifest's
/// in crates/provision-manifest tests/no_follow.rs.)
#[test]
fn a_symbolic_link_to_a_valid_configuration_or_policy_is_refused() {
    let dir = ScratchDir::new("dird-startup").unwrap();
    let uid = dir.uid().unwrap();
    let config = dir.join("dird.conf");
    write(&config, DIRD.as_bytes(), 0o644);
    assert!(read_settings_owned_by(&config, uid).is_ok());
    let config_link = dir.join("dird-link.conf");
    std::os::unix::fs::symlink(&config, &config_link).unwrap();
    assert_eq!(
        read_settings_owned_by(&config_link, uid).err(),
        Some(StartupError::ConfigPermissions)
    );
    assert_eq!(
        read_settings(&config_link).err(),
        Some(StartupError::ConfigPermissions)
    );
    let policy = dir.join("policy.store");
    write(&policy, &sample_policy().encode().unwrap(), 0o644);
    assert_eq!(read_policy(&policy, uid).unwrap(), sample_policy());
    let policy_link = dir.join("policy-link.store");
    std::os::unix::fs::symlink(&policy, &policy_link).unwrap();
    assert_eq!(
        read_policy(&policy_link, uid).err(),
        Some(StartupError::PolicyPermissions)
    );
}

/// Task T (docs/52 R11; Q-468 options 1, 2(b), A-102): every directory on
/// the path of dird's configuration, policy and integrity key is checked —
/// a symbolic link in a directory component, or a directory writable by
/// group or others, is refused as that file's permissions error; the three
/// files through real, unwritable directories are read, and another
/// expected owner refuses the test account's directory.
#[test]
fn a_link_or_a_writable_directory_on_the_path_is_refused() {
    let dir = ScratchDir::new("dird-startup").unwrap();
    let uid = dir.uid().unwrap();
    let real = dir.join("real");
    std::fs::create_dir(&real).unwrap();
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
    let config = real.join("dird.conf");
    write(&config, DIRD.as_bytes(), 0o644);
    let policy = real.join("policy.store");
    write(&policy, &sample_policy().encode().unwrap(), 0o644);
    let key = real.join("integrity.key");
    write(&key, &support::TEST_KEY, 0o400);
    assert!(read_settings_owned_by(&config, uid).is_ok());
    assert_eq!(read_policy(&policy, uid).unwrap(), sample_policy());
    assert!(read_integrity_key(&key, uid).is_ok());
    let via = dir.join("via");
    std::os::unix::fs::symlink(&real, &via).unwrap();
    assert_eq!(
        read_settings_owned_by(&via.join("dird.conf"), uid).err(),
        Some(StartupError::ConfigPermissions)
    );
    assert_eq!(
        read_policy(&via.join("policy.store"), uid).err(),
        Some(StartupError::PolicyPermissions)
    );
    assert_eq!(
        read_integrity_key(&via.join("integrity.key"), uid).err(),
        Some(StartupError::KeyPermissions)
    );
    assert_eq!(
        read_integrity_key(&key, uid + 1).err(),
        Some(StartupError::KeyPermissions)
    );
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o730)).unwrap();
    assert_eq!(
        read_settings_owned_by(&config, uid).err(),
        Some(StartupError::ConfigPermissions)
    );
    assert_eq!(
        read_policy(&policy, uid).err(),
        Some(StartupError::PolicyPermissions)
    );
    assert_eq!(
        read_integrity_key(&key, uid).err(),
        Some(StartupError::KeyPermissions)
    );
}
