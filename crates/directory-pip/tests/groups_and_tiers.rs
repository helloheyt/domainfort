//! Group expansion and tiers over the directory.
//!
//! Sources (named per test): docs/47 §5.3 (R47-8), §6.3 (R47-9), §8.2;
//! Q-116 / A-37 (one closure, security groups only, bounds, cycle = error);
//! Q-117 / A-36 (tier map, structural Tier0, unclassified = Tier0 for
//! writes); [MS-DRSR] 4.1.8.2.2, 4.1.8.2.6, 4.1.8.3; [MS-ADTS] 2.2.12,
//! 2.2.16. Test data: tests/common.

mod common;

use common::*;
use directory_pip::{TierMap, ViewError, MAX_EXPANDED_GROUPS, MAX_NESTING_DEPTH};
use kdc::{AccountSource, AccountSourceError};
use krb_proto::constants::KRB_NT_PRINCIPAL;
use pdp::{
    Dn, FilePath, KerbResKind, Pip, PipError, PolicyScope, RecordKey, Resource, ShareId, Spn, Tier,
    ZoneId,
};
use std::collections::{BTreeMap, BTreeSet};

fn sids(ids: &[u32]) -> BTreeSet<dtyp::Sid> {
    ids.iter().map(|i| sid_of(*i)).collect()
}

fn client_groups(
    view: &impl AccountSource,
    sam: &str,
) -> Result<BTreeSet<dtyp::Sid>, AccountSourceError> {
    view.client(&realm(), &name(KRB_NT_PRINCIPAL, &[sam]))
        .map(|c| c.expect(sam).groups)
}

/// docs/47 §5.3 items 1-2: alice ∈ staff (global, security) ∈ allstaff
/// (universal, security) — the closure holds both; alice ∈ mail
/// (distribution) ∈ hidden (security): mail is not security-enabled, so it
/// is neither entered nor traversed and hidden is not reached ([MS-DRSR]
/// 4.1.8.2.6 "GROUP_TYPE_SECURITY_ENABLED in w!groupType"; 4.1.8.3
/// subgraph). Item 5: `Pip::expand_groups` and `ClientAccount.groups` are
/// the same set.
#[test]
fn nested_closure_security_groups_only() {
    let d = Dir::standard("closure");
    let view = d.view();
    let expected = sids(&[STAFF, ALLSTAFF]);
    assert_eq!(client_groups(&view, "alice"), Ok(expected.clone()));
    assert_eq!(view.expand_groups(&sid_of(ALICE)), Ok(expected));
    // bob is in no group.
    assert_eq!(client_groups(&view, "bob"), Ok(BTreeSet::new()));
    // The expansion of a group: staff ∈ allstaff.
    assert_eq!(view.expand_groups(&sid_of(STAFF)), Ok(sids(&[ALLSTAFF])));
    // An unknown SID.
    assert_eq!(
        view.expand_groups(&account_sid(9999)),
        Err(PipError::NotFound)
    );
}

/// A diamond (alice ∈ a, alice ∈ b, a ∈ c, b ∈ c) is not a cycle: Closure
/// is reachability ([MS-DRSR] 4.1.8.2.2) — each group once.
#[test]
fn diamond_is_not_a_cycle() {
    let d = Dir::standard("diamond");
    d.create_all(vec![
        d.group(70, STAFF_OU, "a", GLOBAL_SECURITY, &[ALICE]),
        d.group(71, STAFF_OU, "b", GLOBAL_SECURITY, &[ALICE]),
        d.group(72, STAFF_OU, "c", UNIVERSAL_SECURITY, &[70, 71]),
    ]);
    let view = d.view();
    assert_eq!(
        client_groups(&view, "alice"),
        Ok(sids(&[STAFF, ALLSTAFF, 70, 71, 72]))
    );
}

/// docs/47 §5.3 item 4 (A-37): a cycle among security groups is an error
/// (fail closed), stricter than [MS-DRSR] 4.1.8.2.2 reachability. bob ∈ c1
/// ∈ c2 ∈ c1.
#[test]
fn cycle_is_an_error() {
    let d = Dir::standard("cycle");
    d.create_all(vec![
        d.group(80, STAFF_OU, "c1", GLOBAL_SECURITY, &[BOB]),
        d.group(81, STAFF_OU, "c2", GLOBAL_SECURITY, &[80]),
    ]);
    d.set(80, "member", vec![ref_to(BOB), ref_to(81)]);
    let view = d.view();
    assert_eq!(client_groups(&view, "bob"), Err(AccountSourceError::Failed));
    assert_eq!(view.expand_groups(&sid_of(BOB)), Err(PipError::Unavailable));
    // A group in the cycle, expanded itself, meets itself.
    assert_eq!(view.expand_groups(&sid_of(80)), Err(PipError::Unavailable));
    // alice, not in the cycle, is unaffected.
    assert_eq!(client_groups(&view, "alice"), Ok(sids(&[STAFF, ALLSTAFF])));
}

/// A loop through a distribution group is no cycle: the distribution group
/// is not traversed (docs/47 §5.3 item 1).
#[test]
fn loop_through_a_distribution_group_is_not_traversed() {
    let d = Dir::standard("dist-loop");
    d.create_all(vec![
        d.group(85, STAFF_OU, "s1", GLOBAL_SECURITY, &[BOB]),
        d.group(86, STAFF_OU, "d1", GLOBAL_DISTRIBUTION, &[85]),
    ]);
    d.set(85, "member", vec![ref_to(BOB), ref_to(86)]);
    let view = d.view();
    assert_eq!(client_groups(&view, "bob"), Ok(sids(&[85])));
}

/// docs/47 §5.3 item 3: nesting depth 16 is allowed, 17 is an error —
/// never a partial set. bob ∈ n1 ∈ n2 ∈ ... ∈ nK.
#[test]
fn nesting_depth_bound() {
    let chain = |d: &Dir, levels: u32| {
        let mut objects = Vec::new();
        for level in 1..=levels {
            let id = 100 + level;
            let member = if level == 1 { BOB } else { id - 1 };
            objects.push(d.group(
                id,
                STAFF_OU,
                &format!("n{level}"),
                GLOBAL_SECURITY,
                &[member],
            ));
        }
        d.create_all(objects);
    };
    assert_eq!(MAX_NESTING_DEPTH, 16);
    let d = Dir::standard("depth-16");
    chain(&d, 16);
    let groups = client_groups(&d.view(), "bob").unwrap();
    assert_eq!(groups.len(), 16);
    let d = Dir::standard("depth-17");
    chain(&d, 17);
    assert_eq!(
        client_groups(&d.view(), "bob"),
        Err(AccountSourceError::Failed)
    );
    assert_eq!(
        d.view().expand_groups(&sid_of(BOB)),
        Err(PipError::Unavailable)
    );
}

/// docs/47 §5.3 item 3: the longest path counts, whichever path reaches the
/// group first. bob ∈ top directly, and bob ∈ n1 ∈ ... ∈ n16 ∈ top: top is
/// at level 17 on the long path — an error. Back links come in GUID order,
/// so top = guid(50) is explored first (short path, then met again done)
/// and top = guid(150) last (long path first).
#[test]
fn nesting_depth_counts_the_longest_path() {
    for top in [50u32, 150] {
        let d = Dir::standard(&format!("depth-longest-{top}"));
        let mut objects = Vec::new();
        for level in 1..=16u32 {
            let id = 100 + level;
            let member = if level == 1 { BOB } else { id - 1 };
            objects.push(d.group(
                id,
                STAFF_OU,
                &format!("n{level}"),
                GLOBAL_SECURITY,
                &[member],
            ));
        }
        objects.push(d.group(top, STAFF_OU, "top", GLOBAL_SECURITY, &[BOB, 116]));
        d.create_all(objects);
        assert_eq!(
            client_groups(&d.view(), "bob"),
            Err(AccountSourceError::Failed),
            "{top}"
        );
        // Fifteen levels below top is fine: drop n16 from the chain.
        let d = Dir::standard(&format!("depth-longest-ok-{top}"));
        let mut objects = Vec::new();
        for level in 1..=15u32 {
            let id = 100 + level;
            let member = if level == 1 { BOB } else { id - 1 };
            objects.push(d.group(
                id,
                STAFF_OU,
                &format!("n{level}"),
                GLOBAL_SECURITY,
                &[member],
            ));
        }
        objects.push(d.group(top, STAFF_OU, "top", GLOBAL_SECURITY, &[BOB, 115]));
        d.create_all(objects);
        assert_eq!(
            client_groups(&d.view(), "bob").map(|g| g.len()),
            Ok(16),
            "{top}"
        );
    }
}

/// docs/47 §5.3 item 3: more than MAX_EXPANDED_GROUPS (1024) groups is an
/// error (precedent: STATUS_TOO_MANY_CONTEXT_IDS, [MS-DRSR] 4.1.8.1.5).
#[test]
fn group_count_bound() {
    assert_eq!(MAX_EXPANDED_GROUPS, 1024);
    let d = Dir::standard("count");
    let count = u32::try_from(MAX_EXPANDED_GROUPS).unwrap() + 1;
    let objects = (0..count)
        .map(|i| {
            d.group(
                2000 + i,
                STAFF_OU,
                &format!("m{i}"),
                GLOBAL_SECURITY,
                &[BOB],
            )
        })
        .collect();
    d.create_all(objects);
    let view = d.view();
    assert_eq!(client_groups(&view, "bob"), Err(AccountSourceError::Failed));
    assert_eq!(view.expand_groups(&sid_of(BOB)), Err(PipError::Unavailable));
}

fn dn_of(view: &directory_pip::DirectoryView<'_>, id: u32) -> Dn {
    view.dn_of(guid(id)).unwrap().expect("live object")
}

fn dir(view: &directory_pip::DirectoryView<'_>, id: u32) -> Resource {
    Resource::DirObject {
        dn: dn_of(view, id),
        attr: None,
    }
}

/// docs/47 §6.3 (R47-9): `tier_of` = the most privileged map tier of
/// {p} ∪ g, Tier0 for a DC account (ST, [MS-ADTS] 2.2.16); nothing ⇒
/// Untiered. `ClientAccount.tier` is the same function (P3).
#[test]
fn subject_tiers() {
    let d = Dir::standard("subject-tier");
    // No entries: Untiered, except the DC account.
    let view = d.view();
    assert_eq!(
        view.tier_of(&sid_of(ALICE), &sids(&[STAFF, ALLSTAFF])),
        Ok(Tier::Untiered)
    );
    assert_eq!(
        view.tier_of(&sid_of(DC01), &BTreeSet::new()),
        Ok(Tier::Tier0)
    );
    // A SID that is not a directory object has no ST: map only.
    assert_eq!(
        view.tier_of(&account_sid(9999), &BTreeSet::new()),
        Ok(Tier::Untiered)
    );
    // Through a nested group: allstaff → Tier1, staff → Tier2.
    let tiers = TierMap::new(
        BTreeMap::from([
            (sid_of(ALLSTAFF), Tier::Tier1),
            (sid_of(STAFF), Tier::Tier2),
            (sid_of(TIER0), Tier::Tier0),
        ]),
        Vec::new(),
    )
    .unwrap();
    let view = d.view_with(&tiers);
    let alice = view
        .client(&realm(), &name(KRB_NT_PRINCIPAL, &["alice"]))
        .unwrap()
        .unwrap();
    assert_eq!(alice.tier, Tier::Tier1);
    assert_eq!(view.tier_of(&alice.sid, &alice.groups), Ok(Tier::Tier1));
    let root = view
        .client(&realm(), &name(KRB_NT_PRINCIPAL, &["rootadmin"]))
        .unwrap()
        .unwrap();
    assert_eq!(root.tier, Tier::Tier0);
    assert_eq!(
        view.tier_of(&sid_of(BOB), &BTreeSet::new()),
        Ok(Tier::Untiered)
    );
}

/// docs/47 §6.3; A-36: `object_tier` — the domain root, the krbtgt account
/// and a DC account are Tier0; an object no rule classifies is Tier0 for
/// writes; a subtree entry classifies an OU and what is under it; a
/// principal object takes the tier its SID and groups map to; the most
/// privileged classification wins.
#[test]
fn object_tiers() {
    let d = Dir::standard("object-tier");
    let view = d.view();
    // Unclassified: every directory object is Tier0 for writes.
    for id in [STAFF_OU, ALICE, BOB, STAFF, MAIL, USERS_CN] {
        assert_eq!(view.object_tier(&dir(&view, id)), Ok(Tier::Tier0), "{id}");
    }
    let staff_ou = dn_of(&view, STAFF_OU);
    let admins_ou = dn_of(&view, ADMINS_OU);
    let users_cn = dn_of(&view, USERS_CN);
    let tiers = TierMap::new(
        BTreeMap::from([
            (sid_of(ALLSTAFF), Tier::Tier1),
            (sid_of(TIER0), Tier::Tier0),
        ]),
        vec![
            (staff_ou, Tier::Tier2),
            (admins_ou, Tier::Tier0),
            (users_cn, Tier::Tier2),
        ],
    )
    .unwrap();
    let view = d.view_with(&tiers);
    let tier = |id| view.object_tier(&dir(&view, id));
    // Structural Tier0, whatever the subtree says.
    assert_eq!(tier(ROOT), Ok(Tier::Tier0));
    assert_eq!(tier(KRBTGT), Ok(Tier::Tier0));
    assert_eq!(tier(DC01), Ok(Tier::Tier0));
    // A classified subtree.
    assert_eq!(tier(STAFF_OU), Ok(Tier::Tier2));
    assert_eq!(tier(BOB), Ok(Tier::Tier2));
    assert_eq!(tier(MAIL), Ok(Tier::Tier2));
    // A principal whose (nested) group maps to Tier1: the more privileged.
    assert_eq!(tier(ALICE), Ok(Tier::Tier1));
    assert_eq!(tier(STAFF), Ok(Tier::Tier1));
    assert_eq!(tier(ALLSTAFF), Ok(Tier::Tier1));
    // The tier-0 subtree and its members.
    assert_eq!(tier(ADMINS_OU), Ok(Tier::Tier0));
    assert_eq!(tier(ROOTADMIN), Ok(Tier::Tier0));
    assert_eq!(tier(TIER0), Ok(Tier::Tier0));
    // Users container classified Tier2.
    assert_eq!(tier(USERS_CN), Ok(Tier::Tier2));
}

/// docs/06 §9; A-36: every resource the map cannot classify is Tier0 for
/// writes — a policy scope, and RPC / file / Kerberos resources; and a DNS
/// record whose owner the map does not classify (task DN6: a record's tier
/// is its owning computer's — docs/54 §5.6, Q-614 item 6; here ws01 is
/// unclassified, so Tier0 by A-36; tests/zone_projection.rs covers the
/// classified case).
#[test]
fn non_directory_resources_are_tier0() {
    let d = Dir::standard("resource-tier");
    let view = d.view();
    for r in [
        Resource::Policy {
            scope: PolicyScope("tiers".into()),
        },
        Resource::RpcMethod {
            iface: guid(9),
            opnum: 1,
        },
        Resource::File {
            share: ShareId("sysvol".into()),
            path: FilePath(vec!["a".into()]),
        },
        Resource::Dns {
            zone: ZoneId("example.test".into()),
            record: Some(RecordKey("ws01".into())),
        },
        Resource::Kerberos {
            kind: KerbResKind::Service(Spn("host/ws01.example.test".into())),
        },
    ] {
        assert_eq!(view.object_tier(&r), Ok(Tier::Tier0));
    }
    // An unknown DN: NotFound (Deny).
    let ghost = Resource::DirObject {
        dn: Dn::new(vec![
            "cn=ghost".into(),
            "dc=example".into(),
            "dc=test".into(),
        ]),
        attr: None,
    };
    assert_eq!(view.object_tier(&ghost), Err(PipError::NotFound));
}

/// A subtree entry with no RDN would classify everything: refused.
#[test]
fn empty_subtree_is_refused() {
    assert_eq!(
        TierMap::new(BTreeMap::new(), vec![(Dn::new(Vec::new()), Tier::Tier2)]),
        Err(ViewError::TierMap)
    );
}
