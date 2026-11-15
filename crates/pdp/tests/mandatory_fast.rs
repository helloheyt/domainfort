//! Mandatory FAST in the rule language: `Match.auth`, the negated subject
//! predicate, and the default rule set.
//!
//! Source: docs/48 §7.1 (FAST for every principal and exchange in phase 1),
//! §7.2 (layer 2: option (i) `Match.auth: AuthMatch { armored }` on the
//! Allow side; option (ii) an explicit Deny with `SubjectMatch::NotMemberOf`),
//! §7.3 (bootstrap exception: an unarmored AS only for a computer account,
//! TGT only; "TGS is always armored"); Q-127 interim decision (owner item
//! P-10: (1)–(5), (c) = (ii)); docs/11 §3 (rules; explicit Deny wins; no
//! matching Allow → Deny), §10 (P2, P4). Hand-made cases; every SID is a
//! hand-made label in the layout of [MS-DTYP] 2.4.2 (see `common`); no
//! vector from another implementation.

mod common;

use common::*;
use dtyp::Sid;
use pdp::access_check::rights::RIGHT_GENERIC_READ;
use pdp::{
    decide, mandatory_fast_rules, AccessRequest, Action, AuthMatch, Context, Effect, KerbResKind,
    Match, PolicySnapshot, ReasonCode, Resource, Rule, RuleId, Spn, Subject, SubjectMatch, Tier,
    Transport, TransportSec, MANDATORY_FAST_RULE_COUNT,
};

/// The first rule id of the default set in these tests.
const FIRST: u32 = 40;

/// A group designated bootstrap-allowed by policy data (hand-made SID; the
/// role docs/48 §7.2 (i) gives "the computer group").
fn bootstrap_group() -> Sid {
    nt_sid(&[21, 100, 200, 300, 1201])
}

/// A machine account, member of `bootstrap_group()` through its expanded
/// groups (docs/11 §1).
fn machine() -> Subject {
    subject(
        nt_sid(&[21, 100, 200, 300, 1301]),
        &[bootstrap_group()],
        Tier::Tier1,
    )
}

/// A regular user, not in the bootstrap group.
fn regular() -> Subject {
    the_user()
}

/// The default set for `bootstrap_group()`, ids FIRST..FIRST+3.
fn default_set() -> PolicySnapshot {
    policy(mandatory_fast_rules(bootstrap_group(), RuleId(FIRST)).expect("ids fit"))
}

fn tgt() -> Resource {
    Resource::Kerberos {
        kind: KerbResKind::Tgt,
    }
}

fn service() -> Resource {
    Resource::Kerberos {
        kind: KerbResKind::Service(Spn("host/files.test".into())),
    }
}

/// A Kerberos request as the KDC PEP builds it (docs/48 §4.2): transport
/// Kerberos, no transport protection (A-22), `armored` as given.
fn kdc_request(s: Subject, action: Action, resource: Resource, armored: bool) -> AccessRequest {
    let mut s = s;
    s.auth.armored = armored;
    AccessRequest {
        subject: s,
        resource,
        action,
        context: Context {
            transport: Transport::Kerberos,
            transport_sec: TransportSec::NONE,
            ..strong_context()
        },
    }
}

fn pip() -> MockPip {
    MockPip::with_sd(sd(None, vec![]))
}

fn reason(req: &AccessRequest, pol: &PolicySnapshot) -> ReasonCode {
    decide(req, pol, &pip()).reason
}

// ----------------------------------------------------------- AS ----

/// docs/48 §7.2 (i), §7.1; Q-127 (1): an armored AS is allowed under the
/// default set, for a regular subject and for a bootstrap-set subject.
#[test]
fn armored_as_is_allowed() {
    for s in [regular(), machine()] {
        let req = kdc_request(s, Action::KdcAs, tgt(), true);
        assert_eq!(reason(&req, &default_set()), ReasonCode::Allowed, "{req:?}");
    }
}

/// docs/48 §7.2 (ii), §7.3; Q-127 (2), (4): an unarmored AS by a regular
/// subject is denied by the explicit Deny (first + 0).
#[test]
fn unarmored_as_is_denied_for_a_regular_subject() {
    for resource in [tgt(), service()] {
        let req = kdc_request(regular(), Action::KdcAs, resource, false);
        assert_eq!(
            reason(&req, &default_set()),
            ReasonCode::CoarseDeny(RuleId(FIRST))
        );
    }
}

/// docs/48 §7.3 (a); Q-127 (4): an unarmored AS for a TGT by a member of the
/// bootstrap set is allowed — membership through the expanded groups, or
/// the principal being the designated SID itself (`MemberOf` semantics).
#[test]
fn unarmored_as_for_a_tgt_is_allowed_for_a_bootstrap_subject() {
    let req = kdc_request(machine(), Action::KdcAs, tgt(), false);
    assert_eq!(reason(&req, &default_set()), ReasonCode::Allowed);
    let itself = subject(bootstrap_group(), &[], Tier::Tier1);
    let req = kdc_request(itself, Action::KdcAs, tgt(), false);
    assert_eq!(reason(&req, &default_set()), ReasonCode::Allowed);
}

/// docs/48 §7.3 ("only a TGT"); Q-127 (4): the bootstrap Allow names the
/// TGT, so an unarmored AS by a bootstrap subject for any other target is
/// not granted (no matching Allow → Deny, P2).
#[test]
fn unarmored_bootstrap_as_is_tgt_only() {
    let req = kdc_request(machine(), Action::KdcAs, service(), false);
    assert_eq!(reason(&req, &default_set()), ReasonCode::NoGrant);
}

// ---------------------------------------------------------- TGS ----

/// docs/48 §7.3 ("TGS is always armored"); Q-127 (2): an unarmored TGS is
/// denied for everyone — a regular subject (first + 0) and a bootstrap
/// subject (first + 1) alike; armored, both are allowed.
#[test]
fn unarmored_tgs_is_denied_for_everyone() {
    let cases = [(regular(), FIRST), (machine(), FIRST + 1)];
    for (s, rule) in cases {
        for resource in [tgt(), service()] {
            let req = kdc_request(s.clone(), Action::KdcTgs, resource.clone(), false);
            assert_eq!(
                reason(&req, &default_set()),
                ReasonCode::CoarseDeny(RuleId(rule)),
                "{req:?}"
            );
            let armored = kdc_request(s.clone(), Action::KdcTgs, resource, true);
            assert_eq!(reason(&armored, &default_set()), ReasonCode::Allowed);
        }
    }
}

/// docs/48 §7.1 (every exchange), §7.2 (i) (the grants name KdcAs / KdcTgs
/// only): an unarmored S4U request is denied for everyone; an armored one
/// is not denied by the set, but not granted either (NoGrant).
#[test]
fn s4u_requires_armor_and_is_not_granted() {
    for action in [Action::KdcS4u2Self, Action::KdcS4u2Proxy] {
        for s in [regular(), machine()] {
            let unarmored = kdc_request(s.clone(), action.clone(), service(), false);
            assert_eq!(
                decide(&unarmored, &default_set(), &pip()).effect,
                Effect::Deny
            );
            assert!(matches!(
                reason(&unarmored, &default_set()),
                ReasonCode::CoarseDeny(_)
            ));
            let armored = kdc_request(s, action.clone(), service(), true);
            assert_eq!(reason(&armored, &default_set()), ReasonCode::NoGrant);
        }
    }
}

// ------------------------------------------- option (ii) vs (i) ----

/// docs/48 §7.2: option (i) alone is opened by a later broad Allow; option
/// (ii)'s explicit Deny wins (docs/11 §3, P4). With an Allow-everything rule
/// added to the default set, unarmored TGS and unarmored AS by a regular
/// subject stay denied; armored requests and the bootstrap AS stay allowed.
#[test]
fn explicit_denies_hold_against_a_broad_allow() {
    let mut rules = default_set().rules().to_vec();
    rules.push(allow_everything(1));
    let broad = policy(rules);
    for s in [regular(), machine()] {
        let tgs = kdc_request(s.clone(), Action::KdcTgs, service(), false);
        assert_eq!(decide(&tgs, &broad, &pip()).effect, Effect::Deny);
        let armored = kdc_request(s, Action::KdcTgs, service(), true);
        assert_eq!(reason(&armored, &broad), ReasonCode::Allowed);
    }
    let as_regular = kdc_request(regular(), Action::KdcAs, tgt(), false);
    assert_eq!(
        reason(&as_regular, &broad),
        ReasonCode::CoarseDeny(RuleId(FIRST))
    );
    let as_machine = kdc_request(machine(), Action::KdcAs, tgt(), false);
    assert_eq!(reason(&as_machine, &broad), ReasonCode::Allowed);
}

// --------------------------------------------------- NotMemberOf ----

/// docs/48 §7.2 (ii); docs/11 §3, P4: a Deny with `NotMemberOf(g)` does not
/// deny a subject in `g` (through its groups, or as `g` itself) and denies
/// every other subject.
#[test]
fn deny_not_member_of_denies_only_non_members() {
    let deny_outside = Rule {
        id: RuleId(9),
        effect: Effect::Deny,
        when: Match {
            subject: SubjectMatch::NotMemberOf(group()),
            ..match_all()
        },
        obligations: vec![],
    };
    let pol = policy(vec![allow_everything(1), deny_outside]);
    let pip = MockPip::with_sd(sd(
        None,
        vec![
            allow(RIGHT_GENERIC_READ, group()),
            allow(RIGHT_GENERIC_READ, other_user()),
        ],
    ));
    let read = |s: Subject| decide(&dir_request(s, Action::DirRead, None), &pol, &pip).reason;

    assert_eq!(read(the_user()), ReasonCode::Allowed); // in group() via groups
    assert_eq!(
        read(subject(group(), &[], Tier::Tier1)),
        ReasonCode::Allowed
    );
    assert_eq!(
        read(subject(other_user(), &[other_group()], Tier::Tier1)),
        ReasonCode::CoarseDeny(RuleId(9))
    );
    assert_eq!(
        read(subject(user(), &[], Tier::Tier1)),
        ReasonCode::CoarseDeny(RuleId(9))
    );
}

/// Q-130 (fail closed): a negated subject predicate takes effect in Deny
/// rules only. An Allow with `NotMemberOf` grants nothing — not even to a
/// subject outside the named group.
#[test]
fn negated_subject_in_an_allow_grants_nothing() {
    let rule = Rule {
        id: RuleId(3),
        effect: Effect::Allow,
        when: Match {
            subject: SubjectMatch::NotMemberOf(other_group()),
            ..match_all()
        },
        obligations: vec![],
    };
    assert!(rule
        .when
        .matches(&kdc_request(regular(), Action::KdcAs, tgt(), true)));
    let pol = policy(vec![rule]);
    for armored in [true, false] {
        let req = kdc_request(regular(), Action::KdcAs, tgt(), armored);
        assert!(!pol.rules().iter().any(|r| r.applies(&req)));
        assert_eq!(reason(&req, &pol), ReasonCode::NoGrant);
    }
}

// ------------------------------------------------------- AuthMatch ----

/// docs/48 §7.2 (i); docs/11 §1, §3: `AuthMatch::ANY` matches either value
/// of `armored`, `ARMORED` only `true`, `UNARMORED` only `false` — at the
/// matcher and as an Allow in layer 3 (here on a directory read, to show the
/// matcher is not tied to Kerberos actions).
#[test]
fn auth_match_follows_armored() {
    let pip = MockPip::with_sd(sd(None, vec![allow(RIGHT_GENERIC_READ, group())]));
    let cases = [
        (AuthMatch::ANY, true, true),
        (AuthMatch::ANY, false, true),
        (AuthMatch::ARMORED, true, true),
        (AuthMatch::ARMORED, false, false),
        (AuthMatch::UNARMORED, true, false),
        (AuthMatch::UNARMORED, false, true),
    ];
    for (auth, armored, expected) in cases {
        let mut req = dir_request(the_user(), Action::DirRead, Some(attr_alone()));
        req.subject.auth.armored = armored;
        assert_eq!(auth.matches(&req.subject.auth), expected);
        let pol = policy(vec![Rule {
            id: RuleId(1),
            effect: Effect::Allow,
            when: Match {
                auth,
                ..match_all()
            },
            obligations: vec![],
        }]);
        let d = decide(&req, &pol, &pip);
        assert_eq!(d.effect == Effect::Allow, expected, "{auth:?} {armored}");
        if !expected {
            assert_eq!(d.reason, ReasonCode::NoGrant);
        }
    }
}

// ------------------------------------------------- policy, not code ----

/// The bootstrap set is policy data (Q-127 interim; the task's "not
/// hard-wired"): with no rules, every Kerberos request is NoGrant, armored
/// or not; and the same unarmored AS is allowed or denied depending only on
/// which SID the snapshot names.
#[test]
fn bootstrap_set_is_policy_data() {
    for action in [Action::KdcAs, Action::KdcTgs] {
        for armored in [true, false] {
            let req = kdc_request(machine(), action.clone(), tgt(), armored);
            assert_eq!(reason(&req, &policy(vec![])), ReasonCode::NoGrant);
        }
    }
    let req = kdc_request(machine(), Action::KdcAs, tgt(), false);
    let names_machines = policy(mandatory_fast_rules(bootstrap_group(), RuleId(1)).expect("fit"));
    let names_other = policy(mandatory_fast_rules(other_group(), RuleId(1)).expect("fit"));
    assert_eq!(reason(&req, &names_machines), ReasonCode::Allowed);
    assert_eq!(
        reason(&req, &names_other),
        ReasonCode::CoarseDeny(RuleId(1))
    );
}

/// The set has `MANDATORY_FAST_RULE_COUNT` rules with consecutive ids from
/// `first_id`, two Deny rules first; ids that would overflow `u32` give no
/// set at all (no partial policy).
#[test]
fn rule_ids_are_consecutive_and_never_overflow() {
    let rules = mandatory_fast_rules(bootstrap_group(), RuleId(FIRST)).expect("ids fit");
    assert_eq!(rules.len(), MANDATORY_FAST_RULE_COUNT as usize);
    let ids: Vec<u32> = rules.iter().map(|r| r.id.0).collect();
    assert_eq!(ids, vec![FIRST, FIRST + 1, FIRST + 2, FIRST + 3]);
    let effects: Vec<Effect> = rules.iter().map(|r| r.effect).collect();
    assert_eq!(
        effects,
        vec![Effect::Deny, Effect::Deny, Effect::Allow, Effect::Allow]
    );
    let last_fit = u32::MAX - (MANDATORY_FAST_RULE_COUNT - 1);
    assert!(mandatory_fast_rules(bootstrap_group(), RuleId(last_fit)).is_some());
    assert!(mandatory_fast_rules(bootstrap_group(), RuleId(last_fit + 1)).is_none());
}
