//! The tier-map edit (task A16): the one implementation both policy-change
//! paths use — its refusals, its successor rule, its difference report and
//! its command-line spelling.
//!
//! Sources: crates/policy-store module `edit` (docs/51 §5.10, R51-21; A-80;
//! docs/questions/Q-379, Q-590). The fixtures are tests/common's hand-made
//! sample policy; no vector comes from any other implementation.

mod common;

use common::{dn, sample_policy, sid};
use pdp::{PolicyVersion, Tier};
use policy_store::{
    check_tier_map_successor, edit_tier_map, tier_map_difference, DevelopmentPolicy, EditError,
    SuccessorError, TierChange,
};

fn staff() -> pdp::Dn {
    dn(&["ou=Staff", "dc=example", "dc=org"])
}

fn lab() -> pdp::Dn {
    dn(&["ou=Lab", "dc=example", "dc=org"])
}

/// docs/51 §5.10: rows added and removed in order, the version bumped by
/// one, the encoding decodes to the same value, everything else unchanged.
#[test]
fn the_edit_bumps_the_version_and_encodes() {
    let p = sample_policy();
    let (next, file) = edit_tier_map(
        &p,
        &[
            TierChange::AddPrincipal(sid(1200), Tier::Tier1),
            TierChange::RemoveSubtree(staff()),
            TierChange::AddSubtree(lab(), Tier::Tier2),
        ],
    )
    .unwrap();
    assert_eq!(next.version, PolicyVersion(43));
    assert_eq!(next.principals.get(&sid(1200)), Some(&Tier::Tier1));
    assert!(!next.subtrees.iter().any(|(d, _)| *d == staff()));
    assert!(next.subtrees.contains(&(lab(), Tier::Tier2)));
    assert_eq!(next.rules, p.rules);
    assert_eq!(next.anonymous, p.anonymous);
    assert_eq!(next.mandatory_fast, p.mandatory_fast);
    assert_eq!(DevelopmentPolicy::decode(&file).unwrap(), next);
}

/// docs/51 §5.10; docs/questions/Q-379: every refusal of the edit.
#[test]
fn the_edit_refuses_what_it_must() {
    let p = sample_policy();
    assert_eq!(edit_tier_map(&p, &[]).unwrap_err(), EditError::NoChange);
    assert_eq!(
        edit_tier_map(&p, &[TierChange::AddPrincipal(sid(512), Tier::Tier1)]).unwrap_err(),
        EditError::PrincipalPresent
    );
    assert_eq!(
        edit_tier_map(&p, &[TierChange::RemovePrincipal(sid(4000))]).unwrap_err(),
        EditError::PrincipalAbsent
    );
    assert_eq!(
        edit_tier_map(&p, &[TierChange::AddSubtree(staff(), Tier::Tier1)]).unwrap_err(),
        EditError::SubtreePresent
    );
    assert_eq!(
        edit_tier_map(&p, &[TierChange::RemoveSubtree(lab())]).unwrap_err(),
        EditError::SubtreeAbsent
    );
    assert_eq!(
        edit_tier_map(&p, &[TierChange::RemovePrincipal(sid(512))]).unwrap_err(),
        EditError::NoTier0Principal
    );
    assert!(matches!(
        edit_tier_map(&p, &[TierChange::AddPrincipal(sid(4000), Tier::Untiered)]).unwrap_err(),
        EditError::Refused(_)
    ));
    let mut max = p.clone();
    max.version = PolicyVersion(u64::MAX);
    assert_eq!(
        edit_tier_map(&max, &[TierChange::AddSubtree(lab(), Tier::Tier1)]).unwrap_err(),
        EditError::VersionOverflow
    );
}

/// Module `edit`, "the successor rule": exactly what the edit produces is a
/// successor; a skipped, equal or older version, a changed rule set,
/// anonymous allowlist or mandatory-FAST entry, or a map without a Tier0
/// principal is not.
#[test]
fn the_successor_rule() {
    let p = sample_policy();
    let (next, _) = edit_tier_map(&p, &[TierChange::AddSubtree(lab(), Tier::Tier1)]).unwrap();
    assert_eq!(check_tier_map_successor(&p, &next), Ok(()));

    for version in [41, 42, 44, u64::MAX] {
        let mut skipped = next.clone();
        skipped.version = PolicyVersion(version);
        assert_eq!(
            check_tier_map_successor(&p, &skipped),
            Err(SuccessorError::Version),
            "{version}"
        );
    }
    let mut rules = next.clone();
    rules.rules.pop();
    assert_eq!(
        check_tier_map_successor(&p, &rules),
        Err(SuccessorError::NotATierMapEdit)
    );
    let mut anonymous = next.clone();
    anonymous.anonymous.clear();
    assert_eq!(
        check_tier_map_successor(&p, &anonymous),
        Err(SuccessorError::NotATierMapEdit)
    );
    let mut fast = next.clone();
    fast.mandatory_fast.bootstrap_group = sid(7777);
    assert_eq!(
        check_tier_map_successor(&p, &fast),
        Err(SuccessorError::NotATierMapEdit)
    );
    let mut no_tier0 = next.clone();
    no_tier0.principals.remove(&sid(512));
    assert_eq!(
        check_tier_map_successor(&p, &no_tier0),
        Err(SuccessorError::NoTier0Principal)
    );
    // The installed file at its maximum version has no successor.
    let mut max = p.clone();
    max.version = PolicyVersion(u64::MAX);
    assert_eq!(
        check_tier_map_successor(&max, &next),
        Err(SuccessorError::Version)
    );
}

/// Module `edit`: the difference between two maps in the edit's vocabulary
/// (a changed tier is a removal and an addition), and the command-line
/// spelling of each change.
#[test]
fn the_difference_and_the_spelling() {
    let p = sample_policy();
    let (next, _) = edit_tier_map(
        &p,
        &[
            TierChange::RemovePrincipal(sid(1101)),
            TierChange::AddPrincipal(sid(1101), Tier::Tier2),
            TierChange::RemoveSubtree(staff()),
            TierChange::AddSubtree(lab(), Tier::Tier1),
        ],
    )
    .unwrap();
    let changes = tier_map_difference(&p, &next);
    assert_eq!(
        changes,
        vec![
            TierChange::RemovePrincipal(sid(1101)),
            TierChange::RemoveSubtree(staff()),
            TierChange::AddPrincipal(sid(1101), Tier::Tier2),
            TierChange::AddSubtree(lab(), Tier::Tier1),
        ]
    );
    let spelled: Vec<String> = changes.iter().map(ToString::to_string).collect();
    assert_eq!(
        spelled,
        vec![
            "--remove-principal S-1-5-21-7-8-9-1101",
            "--remove-subtree ou=Staff dc=example dc=org",
            "--add-principal S-1-5-21-7-8-9-1101 Tier2",
            "--add-subtree Tier1 ou=Lab dc=example dc=org",
        ]
    );
    assert!(tier_map_difference(&p, &p).is_empty());
}
