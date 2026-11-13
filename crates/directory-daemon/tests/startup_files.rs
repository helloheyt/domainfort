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
//! * the policy file's owner / mode checks and its absence (fail closed);
//! * the configuration's owner check; the serving parameters and the
//!   hardening plan derived from a configuration (docs/50 §6.4, §7.1).
//!
//! The root-owned case cannot be made by an unprivileged test: the reading
//! functions take the expected owner, and `main` passes uid 0.
//!
//! Sources: docs/50 R50-14, §3.3, §6.4, §7.1, §7.2, §7.4, §9; [MS-DTYP]
//! 2.4.2.2; A-36; A-68; docs/questions/Q-213, Q-219, Q-270. Every value is
//! hand-made.

mod support;

use directory_daemon::policy::{
    tier_map, DevelopmentPolicy, MandatoryFast, PolicyError, MARKER, SUPERSEDED_FORMAT,
};
use directory_daemon::startup::{
    hardening_plan, params, read_integrity_key, read_policy, read_settings, StartupError,
};
use dirstore::Store;
use dtyp::{Sid, SECURITY_NT_AUTHORITY};
use pdp::{Dn, PolicyVersion, RuleId, Tier};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use support::TempDir;

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
    let dir = TempDir::new();
    let uid = support::my_uid(&dir);
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
    let dir = TempDir::new();
    let uid = support::my_uid(&dir);
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
        let path = dir.join(&format!("k{mode:o}"));
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
        let path = dir.join(&format!("len{length}"));
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

/// docs/50 §7.2 ("dird loads the same file at start"; absent or invalid ⇒
/// do not start): the policy file must be of the expected owner and not
/// writable by group or others; absent is refused.
#[test]
fn the_policy_file_is_checked_and_absent_is_refused() {
    let dir = TempDir::new();
    let uid = support::my_uid(&dir);
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

/// docs/50 §3.2, §3.4, §6.4, §7.1; Q-230 item 4: the serving parameters
/// come from the configuration and the daemon's constants; the hardening
/// plan is the §6.4 baseline for dird's account, with a bounded open-files
/// limit and no memory locking; a configuration not owned by root is
/// refused before it is parsed.
#[test]
fn parameters_plan_and_configuration_owner() {
    let settings = config::DirdSettings::parse(DIRD.as_bytes()).unwrap();
    let p = params(&settings).unwrap();
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
    // Sized from the kdc's quota and the LDAP session bound (docs/50 §6.1:
    // "nofile according to the connection quotas").
    assert_eq!(
        plan.open_files_limit(),
        Some(
            u64::try_from(
                directory_daemon::MAX_KDC_CONNECTIONS + directory_daemon::MAX_LDAP_SESSIONS
            )
            .unwrap()
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
