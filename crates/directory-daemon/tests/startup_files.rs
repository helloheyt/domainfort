//! Tier 1 (docs/50 §9: in-process): dird's start-up inputs.
//!
//! * the UNSIGNED development policy file — round trip, canonical encoding,
//!   the marker, every content rule (docs/50 §7.2; Q-219 → A-57; Q-270
//!   item 2);
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
//! 2.4.2.2; A-36; docs/questions/Q-213, Q-219, Q-270. Every value is
//! hand-made.

mod support;

use directory_daemon::policy::{DevelopmentPolicy, PolicyError, FORMAT, MARKER, MAX_POLICY_FILE};
use directory_daemon::startup::{
    hardening_plan, params, read_integrity_key, read_policy, read_settings, StartupError,
};
use dirstore::Store;
use dtyp::{Sid, SECURITY_NT_AUTHORITY};
use pdp::{Dn, PolicyVersion, Tier};
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
    }
}

fn write(path: &Path, octets: &[u8], mode: u32) {
    std::fs::write(path, octets).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// docs/50 §3.3 (round trip; "a single encoding per value"), §7.2; A-36:
/// the policy file round-trips; its first octets are the marker; the tier
/// map it gives classifies as written.
#[test]
fn the_development_policy_round_trips_and_is_marked() {
    let policy = sample_policy();
    let file = policy.encode().unwrap();
    assert_eq!(&file[..MARKER.len()], MARKER);
    assert_eq!(file[MARKER.len()], FORMAT);
    assert_eq!(DevelopmentPolicy::decode(&file).unwrap(), policy);
    assert!(policy.tier_map().is_ok());
    let empty = support::policy(1);
    assert_eq!(
        DevelopmentPolicy::decode(&empty.encode().unwrap()).unwrap(),
        empty
    );
    // Every single-octet change is refused or re-encodes to itself.
    for at in 0..file.len() {
        for flip in [0x01u8, 0x80] {
            let mut changed = file.clone();
            changed[at] ^= flip;
            if let Ok(decoded) = DevelopmentPolicy::decode(&changed) {
                assert_eq!(decoded.encode().unwrap(), changed, "octet {at}");
            }
        }
    }
}

/// docs/50 §7.2 ("invalid … ⇒ do not start"); Q-270 item 2: an unmarked
/// file, another format, a structure error, a bad or unordered SID, a
/// repeated or empty or malformed DN, an Untiered entry, an oversized file —
/// each refused.
#[test]
fn the_development_policy_refuses_every_broken_rule() {
    let file = sample_policy().encode().unwrap();
    // Unmarked (a signed or foreign file is not silently read as this one).
    let mut unmarked = file.clone();
    unmarked[0] = b'S';
    assert_eq!(
        DevelopmentPolicy::decode(&unmarked),
        Err(PolicyError::NotMarked)
    );
    assert_eq!(DevelopmentPolicy::decode(&[]), Err(PolicyError::NotMarked));
    // Another format number.
    let mut format = file.clone();
    format[MARKER.len()] = FORMAT + 1;
    assert_eq!(DevelopmentPolicy::decode(&format), Err(PolicyError::Format));
    // A trailing octet; a truncation.
    let mut trailing = file.clone();
    trailing.push(0);
    assert!(matches!(
        DevelopmentPolicy::decode(&trailing),
        Err(PolicyError::Structure(ipc::Error::TrailingBytes))
    ));
    assert!(matches!(
        DevelopmentPolicy::decode(&file[..file.len() - 1]),
        Err(PolicyError::Structure(_))
    ));
    // Too large.
    let mut huge = MARKER.to_vec();
    huge.resize(MAX_POLICY_FILE as usize + 1, 0);
    assert_eq!(DevelopmentPolicy::decode(&huge), Err(PolicyError::TooLarge));

    // Build files with broken content through the raw layout:
    // marker ‖ format ‖ version ‖ principals ‖ subtrees.
    let raw = |principals: &[(Vec<u8>, u8)], subtrees: &[(Vec<&str>, u8)]| {
        let mut out = MARKER.to_vec();
        out.push(FORMAT);
        out.extend_from_slice(&7u64.to_be_bytes());
        out.extend_from_slice(&u32::try_from(principals.len()).unwrap().to_be_bytes());
        for (packet, tier) in principals {
            out.extend_from_slice(&u32::try_from(packet.len()).unwrap().to_be_bytes());
            out.extend_from_slice(packet);
            out.push(*tier);
        }
        out.extend_from_slice(&u32::try_from(subtrees.len()).unwrap().to_be_bytes());
        for (dn, tier) in subtrees {
            out.extend_from_slice(&u32::try_from(dn.len()).unwrap().to_be_bytes());
            for component in dn {
                out.extend_from_slice(&u32::try_from(component.len()).unwrap().to_be_bytes());
                out.extend_from_slice(component.as_bytes());
            }
            out.push(*tier);
        }
        out
    };
    assert!(
        DevelopmentPolicy::decode(&raw(&[(sid(1).encode(), 0)], &[(vec!["ou=A", "dc=x"], 1)]))
            .is_ok()
    );
    let mut bad_revision = sid(1).encode();
    bad_revision[0] = 2;
    assert_eq!(
        DevelopmentPolicy::decode(&raw(&[(bad_revision, 0)], &[])),
        Err(PolicyError::Principal)
    );
    assert_eq!(
        DevelopmentPolicy::decode(&raw(&[(sid(2).encode(), 0), (sid(1).encode(), 0)], &[])),
        Err(PolicyError::Principal)
    );
    assert_eq!(
        DevelopmentPolicy::decode(&raw(&[(sid(1).encode(), 0), (sid(1).encode(), 1)], &[])),
        Err(PolicyError::Principal)
    );
    assert_eq!(
        DevelopmentPolicy::decode(&raw(&[(sid(1).encode(), 3)], &[])),
        Err(PolicyError::Untiered)
    );
    assert!(matches!(
        DevelopmentPolicy::decode(&raw(&[(sid(1).encode(), 4)], &[])),
        Err(PolicyError::Structure(ipc::Error::UnknownCode))
    ));
    for dn in [
        vec![],
        vec!["ou"],
        vec!["=x"],
        vec!["ou="],
        vec!["ou=\u{7f}"],
    ] {
        assert_eq!(
            DevelopmentPolicy::decode(&raw(&[], &[(dn.clone(), 1)])),
            Err(PolicyError::Subtree),
            "{dn:?}"
        );
    }
    assert_eq!(
        DevelopmentPolicy::decode(&raw(&[], &[(vec!["ou=A"], 1), (vec!["ou=A"], 2)])),
        Err(PolicyError::Subtree)
    );
    assert_eq!(
        DevelopmentPolicy::decode(&raw(&[], &[(vec!["ou=A"], 3)])),
        Err(PolicyError::Untiered)
    );
    // The encoder refuses what the decoder refuses.
    let mut untiered = sample_policy();
    untiered.principals.insert(sid(9), Tier::Untiered);
    assert_eq!(untiered.encode(), Err(PolicyError::Untiered));
    let mut empty_dn = sample_policy();
    empty_dn.subtrees.push((Dn::new(Vec::new()), Tier::Tier0));
    assert_eq!(empty_dn.encode(), Err(PolicyError::Subtree));
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

    let plan = hardening_plan(&settings).unwrap();
    let identity = plan.identity().unwrap();
    assert_eq!((identity.uid(), identity.gid()), (61002, 61002));
    assert!(plan.sets_no_new_privs());
    assert!(plan.drops_capabilities());
    assert!(plan.disables_core_dumps());
    assert!(plan.makes_not_dumpable());
    assert!(!plan.locks_all_memory());
    assert_eq!(plan.file_mode_mask(), Some(0o077));
    assert!(plan.open_files_limit().is_some_and(|n| n <= 64));

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
