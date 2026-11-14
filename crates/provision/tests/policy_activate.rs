//! `provision policy --activate-next` (task A16; docs/51 §5.10, R51-21:
//! "activation — root"): root installs the `policy.next` dird wrote for an
//! approved tier-map change, and removes it — and refuses every file the
//! online path could not have produced.
//!
//! What is checked: a tier-map successor (version + 1, rules unchanged) is
//! installed root:0644 through the edit's own installer, loadable by dird's
//! and the kdc's loaders, and `policy.next` is removed; refused, with
//! nothing installed and `policy.next` left in place: nothing pending, a
//! file that does not decode, a skipped, equal or older version, a changed
//! rule set, a group-writable file, a link at `policy.next`, a link in a
//! directory of its path, a file owned by another account than dird's; an
//! activation interrupted after the install is completed by a re-run; a
//! dird configuration without `policy_next_path` has nothing to activate;
//! the command line.
//!
//! Sources: docs/51 §5.10; A-69 (the version every view compares); A-80;
//! A-113 (root's directories); docs/52 §3.13 (C13); policy-store
//! `check_tier_map_successor`; docs/questions/Q-590, Q-591. Fixtures:
//! tests/common (the test's uid stands in for root — the recorder's
//! `root_uid` — and for dird's account). Every value is hand-made test data.

mod common;

use common::*;

use std::ffi::OsString;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};

use directory_daemon::startup::read_policy;
use pdp::{Dn, PolicyVersion, Tier};
use policy_store::{DevelopmentPolicy, SuccessorError};
use provision::cli::{parse, CliError, Command};
use provision::policy::{edit_tier_map, TierChange};
use provision::update::{activate_policy_next, ActivateError};
use provision::{provision_domain, Owner, Staged};

/// A provisioned domain (dird's account: `dird_uid`) and its plan, with
/// dird's own `policy.next` directory (mode 0700) created as dird does at
/// its start.
fn provisioned(
    dir: &TempDir,
    uid: u32,
    dird_uid: u32,
) -> (provision::DomainInput, provision::Plan) {
    let input = input(dir, dird_uid, 61007);
    let (plan, _) = provision_domain(
        &input,
        now(),
        &mut CountingRandom::default(),
        &mut Recorder::new(uid),
        &mut HaltAt::never(),
    )
    .unwrap();
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(input.paths.policy_next.parent())
        .unwrap();
    (input, plan)
}

fn lab_dn() -> Dn {
    Dn::new(vec!["ou=Lab".into(), "dc=example".into(), "dc=test".into()])
}

/// `bytes` as `policy.next`, with `mode`.
fn write_next(input: &provision::DomainInput, bytes: &[u8], mode: u32) -> PathBuf {
    let next = input.paths.policy_next.as_path().to_path_buf();
    std::fs::write(&next, bytes).unwrap();
    std::fs::set_permissions(&next, std::fs::Permissions::from_mode(mode)).unwrap();
    next
}

/// The successor the online path writes for one added subtree.
fn successor(plan: &provision::Plan) -> (DevelopmentPolicy, Vec<u8>) {
    edit_tier_map(
        &plan.policy,
        &[TierChange::AddSubtree(lab_dn(), Tier::Tier1)],
    )
    .unwrap()
}

fn exists(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

/// docs/51 §5.10: the successor is installed (root:0644, the edit's
/// installer, version 1 → 2), both daemons' loaders read it, the rows it
/// changed are reported, and `policy.next` is removed.
#[test]
fn activation_installs_the_successor_and_removes_policy_next() {
    let dir = TempDir::new();
    let uid = my_uid(&dir);
    if skip_as_root(uid) {
        return;
    }
    let (input, plan) = provisioned(&dir, uid, uid);
    let (next, bytes) = successor(&plan);
    let next_path = write_next(&input, &bytes, 0o600);
    let mut recorder = Recorder::new(uid);
    let activated = activate_policy_next(&input.paths.dird_config, &mut recorder).unwrap();
    assert_eq!(activated.version, PolicyVersion(2));
    assert!(!activated.completed_earlier);
    assert_eq!(
        activated.changes,
        vec![TierChange::AddSubtree(lab_dn(), Tier::Tier1)]
    );
    assert_eq!(
        recorder.records,
        vec![(Staged::PolicyUpdate, Owner { uid: 0, gid: 0 })]
    );
    let installed = input.paths.policy.as_path();
    assert_eq!(mode(installed), 0o644);
    assert_eq!(read_policy(installed, uid).unwrap(), next);
    assert_eq!(
        kdc_daemon::startup::read_policy(installed, uid).unwrap(),
        next
    );
    assert!(!exists(&next_path), "policy.next removed");
    assert!(
        !exists(&dir.join("etc/policy.store.next")),
        "no staging left"
    );
    // Nothing is pending any more.
    assert_eq!(
        activate_policy_next(&input.paths.dird_config, &mut Recorder::new(uid)).unwrap_err(),
        ActivateError::NothingPending
    );
}

/// docs/51 §5.10 (A-69): a `policy.next` the online path could not have
/// produced is refused — malformed, a skipped / equal / older version, a
/// changed rule set, group-writable — and nothing is installed; the file is
/// left for the operator.
#[test]
fn files_the_online_path_cannot_produce_are_refused() {
    let dir = TempDir::new();
    let uid = my_uid(&dir);
    if skip_as_root(uid) {
        return;
    }
    let (input, plan) = provisioned(&dir, uid, uid);
    let installed_before = std::fs::read(input.paths.policy.as_path()).unwrap();
    let activate = || activate_policy_next(&input.paths.dird_config, &mut Recorder::new(uid));
    let (next, _) = successor(&plan);
    let encoded = |p: &DevelopmentPolicy| {
        // Encoded without the edit (the format's own encoder still checks
        // its content rules).
        p.encode().unwrap()
    };

    write_next(&input, b"UNSIGNED-DEV-DIRD-POLICY\x02broken", 0o600);
    assert!(matches!(
        activate().unwrap_err(),
        ActivateError::NextRefused(policy_store::LoadError::Policy(_))
    ));
    for version in [3, 1, 0] {
        let mut skipped = next.clone();
        skipped.version = PolicyVersion(version);
        write_next(&input, &encoded(&skipped), 0o600);
        assert_eq!(
            activate().unwrap_err(),
            ActivateError::NotASuccessor(SuccessorError::Version),
            "version {version}"
        );
    }
    let mut rules = next.clone();
    rules.rules.pop();
    write_next(&input, &encoded(&rules), 0o600);
    assert_eq!(
        activate().unwrap_err(),
        ActivateError::NotASuccessor(SuccessorError::NotATierMapEdit)
    );
    write_next(&input, &encoded(&next), 0o620);
    assert_eq!(
        activate().unwrap_err(),
        ActivateError::NextRefused(policy_store::LoadError::Permissions)
    );
    assert!(exists(input.paths.policy_next.as_path()), "left in place");
    assert_eq!(
        std::fs::read(input.paths.policy.as_path()).unwrap(),
        installed_before,
        "nothing installed"
    );
}

/// docs/52 §3.13 (C13), docs/questions/Q-591: `policy.next` is reached by
/// the walk from `/` with dird's account as its owner — a link at its name,
/// a link in a directory of its path, and a file owned by another account
/// than dird's are refused before anything is read or installed.
#[test]
fn a_link_or_a_foreign_owner_is_refused() {
    let dir = TempDir::new();
    let uid = my_uid(&dir);
    if skip_as_root(uid) {
        return;
    }
    let (input, plan) = provisioned(&dir, uid, uid);
    let installed_before = std::fs::read(input.paths.policy.as_path()).unwrap();
    let (_, bytes) = successor(&plan);
    let activate = || activate_policy_next(&input.paths.dird_config, &mut Recorder::new(uid));
    let next_path = input.paths.policy_next.as_path().to_path_buf();
    let next_dir = input.paths.policy_next.parent().to_path_buf();

    // A link at policy.next's name, to a valid successor elsewhere.
    let elsewhere = dir.join("var/elsewhere.next");
    std::fs::write(&elsewhere, &bytes).unwrap();
    std::fs::set_permissions(&elsewhere, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::os::unix::fs::symlink(&elsewhere, &next_path).unwrap();
    assert_eq!(
        activate().unwrap_err(),
        ActivateError::NextRefused(policy_store::LoadError::Permissions)
    );
    assert!(exists(&elsewhere), "the link's target untouched");
    std::fs::remove_file(&next_path).unwrap();

    // A link in place of policy.next's directory.
    let real = dir.join("var/real-policy-dir");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&real)
        .unwrap();
    std::fs::write(real.join("policy.next"), &bytes).unwrap();
    std::fs::remove_dir(&next_dir).unwrap();
    std::os::unix::fs::symlink(&real, &next_dir).unwrap();
    assert_eq!(
        activate().unwrap_err(),
        ActivateError::NextPath(protected_file::PathBreak::NotADirectory)
    );
    assert!(exists(&real.join("policy.next")), "not removed through it");
    assert_eq!(
        std::fs::read(input.paths.policy.as_path()).unwrap(),
        installed_before
    );

    // Owned by another account than dird's: a domain whose dird account is
    // another uid (the test cannot give a file away, so the file — and its
    // directory — are the test's and dird is someone else). The walk refuses
    // already at the directory, which is neither root's nor dird's (the
    // file-owner rule on its own is crates/protected-file's
    // `configuration_file_rule`, tested there).
    let other = TempDir::new();
    let (input, plan) = provisioned(&other, uid, uid + 1);
    let (_, bytes) = successor(&plan);
    write_next(&input, &bytes, 0o600);
    let installed_before = std::fs::read(input.paths.policy.as_path()).unwrap();
    assert_eq!(
        activate_policy_next(&input.paths.dird_config, &mut Recorder::new(uid)).unwrap_err(),
        ActivateError::NextPath(protected_file::PathBreak::DirectoryWrongOwner)
    );
    assert_eq!(
        std::fs::read(input.paths.policy.as_path()).unwrap(),
        installed_before
    );
}

/// An activation interrupted after the install (policy.next still there,
/// already installed) is completed by a re-run: recognised, only removed,
/// nothing installed again.
#[test]
fn an_interrupted_activation_is_completed_by_a_re_run() {
    let dir = TempDir::new();
    let uid = my_uid(&dir);
    if skip_as_root(uid) {
        return;
    }
    let (input, plan) = provisioned(&dir, uid, uid);
    let installed = std::fs::read(input.paths.policy.as_path()).unwrap();
    let next_path = write_next(&input, &installed, 0o600);
    let mut recorder = Recorder::new(uid);
    let activated = activate_policy_next(&input.paths.dird_config, &mut recorder).unwrap();
    assert!(activated.completed_earlier);
    assert!(activated.changes.is_empty());
    assert_eq!(activated.version, plan.policy.version);
    assert!(recorder.records.is_empty(), "nothing installed again");
    assert!(!exists(&next_path));
}

/// Without `policy_next_path` in dird's configuration there is nothing to
/// activate; a dird configuration that is not root's is refused.
#[test]
fn a_dird_configuration_without_policy_next_path_has_nothing_to_activate() {
    let dir = TempDir::new();
    let uid = my_uid(&dir);
    if skip_as_root(uid) {
        return;
    }
    let (input, _) = provisioned(&dir, uid, uid);
    let text = std::fs::read_to_string(input.paths.dird_config.as_path()).unwrap();
    let without: String = text
        .lines()
        .filter(|l| !l.starts_with("policy_next_path = "))
        .map(|l| format!("{l}\n"))
        .collect();
    let config = path(&dir, "etc/dird-without.conf");
    std::fs::write(config.as_path(), without).unwrap();
    std::fs::set_permissions(config.as_path(), std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        activate_policy_next(&config, &mut Recorder::new(uid)).unwrap_err(),
        ActivateError::NotConfigured
    );
    assert!(matches!(
        activate_policy_next(&input.paths.dird_config, &mut Recorder::new(uid + 1)).unwrap_err(),
        ActivateError::DirdConfig(_)
    ));
}

/// The command line: `policy --activate-next --dird-config <path>` in
/// either order and nothing else.
#[test]
fn the_activation_command_line() {
    let os = |args: &[&str]| args.iter().map(OsString::from).collect::<Vec<_>>();
    for args in [
        [
            "policy",
            "--activate-next",
            "--dird-config",
            "/etc/dird.conf",
        ],
        [
            "policy",
            "--dird-config",
            "/etc/dird.conf",
            "--activate-next",
        ],
    ] {
        let Command::ActivatePolicyNext { dird_config } = parse(os(&args)).unwrap() else {
            panic!("not an activation");
        };
        assert_eq!(dird_config.as_str(), "/etc/dird.conf");
    }
    for bad in [
        vec!["policy", "--activate-next"],
        vec!["policy", "--activate-next", "--dird-config"],
        vec!["policy", "--activate-next", "--dird-config", "--x"],
        vec![
            "policy",
            "--activate-next",
            "--dird-config",
            "/etc/dird.conf",
            "--add-principal",
        ],
        vec!["policy", "--activate-next", "--policy-path", "/etc/p"],
    ] {
        assert!(
            matches!(parse(os(&bad)), Err(CliError::Usage(_))),
            "{bad:?}"
        );
    }
}
