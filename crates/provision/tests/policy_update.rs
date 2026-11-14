//! `provision policy` (R51-21, A-80): the offline tier-map edit on a
//! provisioned policy file — decode, edit, bump the version, write
//! atomically root:0644 — and its refusals (not root-owned, not decodable,
//! not a regular file, a leftover `.next` file, an edit that would leave no
//! Tier0 principal, rows already present / absent).
//!
//! Sources: docs/51 §5.10; A-80 (Q-299 (a)); A-69 (the version every view
//! compares; dird's and kdc's loaders); policy-store `read_file`.
//! Fixtures: tests/common (the test's uid stands in for root — the
//! recorder's `root_uid`).

mod common;

use common::*;

use std::os::unix::fs::{MetadataExt, PermissionsExt};

use directory_daemon::startup::read_policy;
use pdp::{Dn, Tier};
use provision::policy::{edit_tier_map, EditError, TierChange};
use provision::update::{update_policy, UpdateError};
use provision::{provision_domain, ObjectRole, Owner, Staged};

/// A provisioned domain's policy file (and the plan).
fn provisioned(dir: &TempDir, uid: u32) -> (provision::DomainInput, provision::Plan) {
    let input = input(dir, uid, 61007);
    let (plan, _) = provision_domain(
        &input,
        now(),
        &mut CountingRandom::default(),
        &mut Recorder::new(uid),
        &mut HaltAt::never(),
    )
    .unwrap();
    (input, plan)
}

fn staff_dn() -> Dn {
    Dn::new(vec![
        "ou=Staff".into(),
        "dc=example".into(),
        "dc=test".into(),
    ])
}

/// docs/51 §5.10: rows added and removed, `policy_version` 1 → 2, the file
/// rewritten root:0644, loadable by dird's and kdc's loaders.
#[test]
fn the_tier_map_edit_bumps_the_version_and_writes_atomically() {
    let dir = TempDir::new();
    let uid = my_uid(&dir);
    if skip_as_root(uid) {
        return;
    }
    let (input, plan) = provisioned(&dir, uid);
    let path = &input.paths.policy;
    let helpdesk =
        dtyp::Sid::parse_sid_string(&format!("{}-1200", plan.domain_sid.to_sid_string())).unwrap();
    let mut recorder = Recorder::new(uid);
    let version = update_policy(
        path,
        &[
            TierChange::AddPrincipal(helpdesk, Tier::Tier1),
            TierChange::AddSubtree(staff_dn(), Tier::Tier1),
        ],
        &mut recorder,
    )
    .unwrap();
    assert_eq!(version.0, 2);
    assert_eq!(
        recorder.records,
        vec![(Staged::PolicyUpdate, Owner { uid: 0, gid: 0 })]
    );
    assert_eq!(mode(path.as_path()), 0o644);
    assert!(std::fs::symlink_metadata(dir.join("etc/policy.store.next")).is_err());
    let policy = read_policy(path.as_path(), uid).unwrap();
    assert_eq!(policy.version.0, 2);
    assert_eq!(policy.principals.get(&helpdesk), Some(&Tier::Tier1));
    assert!(policy.subtrees.contains(&(staff_dn(), Tier::Tier1)));
    // Everything else is unchanged.
    assert_eq!(policy.rules, plan.policy.rules);
    assert_eq!(policy.mandatory_fast, plan.policy.mandatory_fast);
    let kdc = kdc_daemon::startup::read_policy(path.as_path(), uid).unwrap();
    assert_eq!(kdc, policy);
    // And back.
    let version = update_policy(
        path,
        &[
            TierChange::RemovePrincipal(helpdesk),
            TierChange::RemoveSubtree(staff_dn()),
        ],
        &mut Recorder::new(uid),
    )
    .unwrap();
    assert_eq!(version.0, 3);
    let policy = read_policy(path.as_path(), uid).unwrap();
    assert_eq!(policy.principals, plan.policy.principals);
    assert_eq!(policy.subtrees, plan.policy.subtrees);
}

/// docs/51 §5.10 ("refuse if the file doesn't decode or isn't
/// root-owned"): a file of another owner, a group-writable file, a file
/// that does not decode, a link — each refused, the file unchanged.
#[test]
fn files_the_daemons_would_refuse_are_refused() {
    let dir = TempDir::new();
    let uid = my_uid(&dir);
    if skip_as_root(uid) {
        return;
    }
    let (input, plan) = provisioned(&dir, uid);
    let path = &input.paths.policy;
    let original = std::fs::read(path.as_path()).unwrap();
    let change = [TierChange::AddSubtree(staff_dn(), Tier::Tier1)];
    // Not owned by "root" (the recorder's root uid is another uid).
    let err = update_policy(path, &change, &mut Recorder::new(uid + 1)).unwrap_err();
    assert!(matches!(
        err,
        UpdateError::Load(policy_store::LoadError::Permissions)
    ));
    // Group-writable.
    std::fs::set_permissions(path.as_path(), std::fs::Permissions::from_mode(0o664)).unwrap();
    let err = update_policy(path, &change, &mut Recorder::new(uid)).unwrap_err();
    assert!(matches!(
        err,
        UpdateError::Load(policy_store::LoadError::Permissions)
    ));
    std::fs::set_permissions(path.as_path(), std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(std::fs::read(path.as_path()).unwrap(), original);
    // Not decodable.
    let other = common::path(&dir, "etc/garbage.store");
    std::fs::write(other.as_path(), b"UNSIGNED-DEV-DIRD-POLICY\x02broken").unwrap();
    let err = update_policy(&other, &change, &mut Recorder::new(uid)).unwrap_err();
    assert!(matches!(
        err,
        UpdateError::Load(policy_store::LoadError::Policy(_))
    ));
    // A link to the real file.
    let link = common::path(&dir, "etc/link.store");
    std::os::unix::fs::symlink(path.as_path(), link.as_path()).unwrap();
    assert_eq!(
        update_policy(&link, &change, &mut Recorder::new(uid)).unwrap_err(),
        UpdateError::NotRegular
    );
    assert_eq!(read_policy(path.as_path(), uid).unwrap(), plan.policy);
}

/// A `.next` file left by an interrupted run is refused, never reused or
/// overwritten; the policy file is unchanged.
#[test]
fn a_leftover_next_file_is_refused() {
    let dir = TempDir::new();
    let uid = my_uid(&dir);
    if skip_as_root(uid) {
        return;
    }
    let (input, plan) = provisioned(&dir, uid);
    let next = dir.join("etc/policy.store.next");
    std::fs::write(&next, b"half").unwrap();
    let err = update_policy(
        &input.paths.policy,
        &[TierChange::AddSubtree(staff_dn(), Tier::Tier1)],
        &mut Recorder::new(uid),
    )
    .unwrap_err();
    assert!(matches!(err, UpdateError::Next(..)));
    assert_eq!(std::fs::read(&next).unwrap(), b"half");
    assert_eq!(
        read_policy(input.paths.policy.as_path(), uid).unwrap(),
        plan.policy
    );
    assert_eq!(
        std::fs::metadata(input.paths.policy.as_path())
            .unwrap()
            .uid(),
        uid
    );
}

/// The edit's own rules (docs/51 §5.10; Q-379): rows already present or
/// absent, no change, no Tier0 principal left, Untiered (policy-store).
#[test]
fn the_edit_refuses_what_it_must() {
    let dir = TempDir::new();
    let plan = provision::Plan::build(
        &input(&dir, 61002, 61007),
        now(),
        &mut CountingRandom::default(),
    )
    .unwrap();
    let p = &plan.policy;
    let tier0 = plan.object(ObjectRole::Tier0Group).unwrap().sid.unwrap();
    let tier0_ou = p.subtrees[0].0.clone();
    assert_eq!(edit_tier_map(p, &[]).unwrap_err(), EditError::NoChange);
    assert_eq!(
        edit_tier_map(p, &[TierChange::AddPrincipal(tier0, Tier::Tier1)]).unwrap_err(),
        EditError::PrincipalPresent
    );
    assert_eq!(
        edit_tier_map(p, &[TierChange::RemoveSubtree(staff_dn())]).unwrap_err(),
        EditError::SubtreeAbsent
    );
    assert_eq!(
        edit_tier_map(p, &[TierChange::AddSubtree(tier0_ou.clone(), Tier::Tier0)]).unwrap_err(),
        EditError::SubtreePresent
    );
    assert_eq!(
        edit_tier_map(p, &[TierChange::RemovePrincipal(tier0)]).unwrap_err(),
        EditError::NoTier0Principal
    );
    let other = dtyp::Sid::parse_sid_string("S-1-5-21-1-2-3-4000").unwrap();
    assert_eq!(
        edit_tier_map(p, &[TierChange::RemovePrincipal(other)]).unwrap_err(),
        EditError::PrincipalAbsent
    );
    assert!(matches!(
        edit_tier_map(p, &[TierChange::AddPrincipal(other, Tier::Untiered)]).unwrap_err(),
        EditError::Refused(_)
    ));
    // Replacing the Tier-0 group by another Tier0 principal is allowed.
    let (next, _) = edit_tier_map(
        p,
        &[
            TierChange::AddPrincipal(other, Tier::Tier0),
            TierChange::RemovePrincipal(tier0),
        ],
    )
    .unwrap();
    assert_eq!(next.version.0, 2);
    let mut max = p.clone();
    max.version = pdp::PolicyVersion(u64::MAX);
    assert_eq!(
        edit_tier_map(&max, &[TierChange::AddSubtree(staff_dn(), Tier::Tier1)]).unwrap_err(),
        EditError::VersionOverflow
    );
}
