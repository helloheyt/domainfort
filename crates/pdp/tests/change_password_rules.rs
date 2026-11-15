//! The change-password service's AS rule set (task K5): the resource kind
//! `KerbResKind::ChangePassword` and `change_password_as_rules`, alone and
//! beside the mandatory-FAST set and a broad grant.
//!
//! Source: docs/53 R53-1 (users only), R53-6, §5.2 (a ticket for
//! `kadmin/changepw` only from an armored AS; "the PDP: `KdcAs` on this
//! service's resource, `armored` required (A-39), users only (a data
//! rule)"); A-117; A-142 (no FAST exception for that AS, in any version);
//! docs/48 §7.2 (an explicit Deny holds against a broader Allow), (i) ("the
//! computer group"); docs/11 §3 (explicit Deny wins; no matching Allow →
//! Deny), §10 (P2, P4); A-139 (one name space: the PDP never compares the
//! service's name). Hand-made cases; every SID is a hand-made label in the
//! layout of [MS-DTYP] 2.4.2 (see `common`); no vector from another
//! implementation.

mod common;

use common::*;
use dtyp::Sid;
use pdp::{
    change_password_as_rules, decide, mandatory_fast_rules, AccessRequest, Action, AuthMatch,
    Context, Effect, KerbResKind, PolicySnapshot, ReasonCode, Resource, ResourceMatch, Rule,
    RuleId, Spn, Subject, SubjectMatch, Tier, Transport, TransportSec,
    CHANGE_PASSWORD_AS_RULE_COUNT, MANDATORY_FAST_RULE_COUNT,
};

/// The first rule id of the mandatory-FAST set in these tests; the
/// change-password set follows it.
const FAST: u32 = 40;
const CHANGE_PASSWORD: u32 = FAST + MANDATORY_FAST_RULE_COUNT;

/// The computer group (the mandatory-FAST bootstrap group, docs/48 §7.2 (i);
/// hand-made SID).
fn computers() -> Sid {
    nt_sid(&[21, 100, 200, 300, 1201])
}

/// A machine account, member of `computers()` through its expanded groups.
fn machine() -> Subject {
    subject(
        nt_sid(&[21, 100, 200, 300, 1301]),
        &[computers()],
        Tier::Tier1,
    )
}

/// A regular user, not in the computer group.
fn user_subject() -> Subject {
    the_user()
}

fn change_password() -> Resource {
    Resource::Kerberos {
        kind: KerbResKind::ChangePassword,
    }
}

fn tgt() -> Resource {
    Resource::Kerberos {
        kind: KerbResKind::Tgt,
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

/// The deployment's default Kerberos rules (policy-store's snapshot order):
/// the mandatory-FAST set, then the change-password set, then `extra`.
fn deployment(extra: Vec<Rule>) -> PolicySnapshot {
    let mut rules = mandatory_fast_rules(computers(), RuleId(FAST)).expect("ids fit");
    rules.extend(change_password_as_rules(computers(), RuleId(CHANGE_PASSWORD)).expect("ids fit"));
    rules.extend(extra);
    policy(rules)
}

fn reason(req: &AccessRequest, pol: &PolicySnapshot) -> ReasonCode {
    decide(req, pol, &MockPip::with_sd(sd(None, vec![]))).reason
}

/// docs/53 §5.2 ("`KdcAs` on this service's resource, `armored`
/// required"): an armored AS by a user for the change-password service is
/// granted by the mandatory-FAST Allow (armored, any Kerberos target).
#[test]
fn armored_user_as_is_allowed() {
    let req = kdc_request(user_subject(), Action::KdcAs, change_password(), true);
    assert_eq!(reason(&req, &deployment(vec![])), ReasonCode::Allowed);
    assert_eq!(
        reason(&req, &deployment(vec![allow_everything(1)])),
        ReasonCode::Allowed
    );
}

/// A-142 (no FAST exception for the AS to `kadmin/changepw`, in any
/// version); docs/48 §7.2 (an explicit Deny wins over a broader Allow,
/// docs/11 P4): unarmored, the AS is denied for every subject — the user by
/// the mandatory-FAST Deny (first + 0); the computer-group member, whom the
/// mandatory-FAST set exempts for its TGT, by this set's first rule — also
/// when an Allow-everything rule is added.
#[test]
fn unarmored_as_is_denied_for_everyone_even_under_a_broad_allow() {
    for extra in [vec![], vec![allow_everything(1)]] {
        let pol = deployment(extra);
        let user = kdc_request(user_subject(), Action::KdcAs, change_password(), false);
        assert_eq!(reason(&user, &pol), ReasonCode::CoarseDeny(RuleId(FAST)));
        let machine = kdc_request(machine(), Action::KdcAs, change_password(), false);
        assert_eq!(
            reason(&machine, &pol),
            ReasonCode::CoarseDeny(RuleId(CHANGE_PASSWORD))
        );
    }
    // Without this set, the broad Allow would have granted the computer's
    // unarmored AS (the gap documented in crates/pdp mandatory_fast.rs).
    let mut fast_only = mandatory_fast_rules(computers(), RuleId(FAST)).expect("ids fit");
    fast_only.push(allow_everything(1));
    let machine = kdc_request(machine(), Action::KdcAs, change_password(), false);
    assert_eq!(reason(&machine, &policy(fast_only)), ReasonCode::Allowed);
}

/// docs/53 R53-1 ("users only"), §5.2 ("users only (a data rule)"): a
/// member of the computer group is denied the AS for the change-password
/// service even armored and under a broad Allow (second rule) — and keeps
/// its TGT (armored or, as the bootstrap, unarmored).
#[test]
fn the_computer_group_is_denied_armored_too_but_keeps_its_tgt() {
    for extra in [vec![], vec![allow_everything(1)]] {
        let pol = deployment(extra);
        let armored = kdc_request(machine(), Action::KdcAs, change_password(), true);
        assert_eq!(
            reason(&armored, &pol),
            ReasonCode::CoarseDeny(RuleId(CHANGE_PASSWORD + 1))
        );
        for armored in [true, false] {
            let own_tgt = kdc_request(machine(), Action::KdcAs, tgt(), armored);
            assert_eq!(reason(&own_tgt, &pol), ReasonCode::Allowed, "{armored}");
        }
        // The group SID itself as the principal (`MemberOf` semantics).
        let itself = subject(computers(), &[], Tier::Tier1);
        let req = kdc_request(itself, Action::KdcAs, change_password(), true);
        assert_eq!(
            reason(&req, &pol),
            ReasonCode::CoarseDeny(RuleId(CHANGE_PASSWORD + 1))
        );
    }
}

/// The set only narrows (docs/11 P4): it names `KdcAs` on the
/// change-password resource and nothing else — every TGT and service
/// request decides as under the mandatory-FAST set alone, and no rule of
/// the set is an Allow.
#[test]
fn the_set_touches_nothing_else() {
    let fast_only = policy(mandatory_fast_rules(computers(), RuleId(FAST)).expect("ids fit"));
    let both = deployment(vec![]);
    let service = Resource::Kerberos {
        kind: KerbResKind::Service(Spn("host/files.test".into())),
    };
    for s in [user_subject(), machine()] {
        for action in [Action::KdcAs, Action::KdcTgs] {
            for resource in [tgt(), service.clone()] {
                for armored in [true, false] {
                    let req = kdc_request(s.clone(), action.clone(), resource.clone(), armored);
                    assert_eq!(reason(&req, &both), reason(&req, &fast_only), "{req:?}");
                }
            }
        }
    }
    let rules = change_password_as_rules(computers(), RuleId(1)).expect("ids fit");
    assert!(rules.iter().all(|r| r.effect == Effect::Deny));
    assert!(rules.iter().all(|r| r.when.resource
        == ResourceMatch::Kerberos {
            kind: Some(KerbResKind::ChangePassword)
        }));
}

/// A-139 (one name space, one canonicalisation function): the PDP never
/// compares the service's name — a rule naming `Service(Spn("kadmin/changepw"))`
/// does not apply to the change-password resource, and a rule naming the
/// change-password resource does not apply to any SPN, that one included.
#[test]
fn the_resource_is_not_an_spn() {
    let spn_rule = Rule {
        id: RuleId(7),
        effect: Effect::Deny,
        when: pdp::Match {
            resource: ResourceMatch::Kerberos {
                kind: Some(KerbResKind::Service(Spn("kadmin/changepw".into()))),
            },
            ..match_all()
        },
        obligations: vec![],
    };
    let req = kdc_request(user_subject(), Action::KdcAs, change_password(), true);
    assert!(!spn_rule.applies(&req));
    let as_spn = kdc_request(
        user_subject(),
        Action::KdcAs,
        Resource::Kerberos {
            kind: KerbResKind::Service(Spn("kadmin/changepw".into())),
        },
        false,
    );
    for rule in change_password_as_rules(computers(), RuleId(1)).expect("ids fit") {
        assert!(!rule.applies(&as_spn));
    }
}

/// The set has `CHANGE_PASSWORD_AS_RULE_COUNT` rules with consecutive ids
/// from `first_id`, the unarmored Deny first; ids that would overflow `u32`
/// give no set at all (no partial policy).
#[test]
fn rule_ids_are_consecutive_and_never_overflow() {
    let rules = change_password_as_rules(computers(), RuleId(9)).expect("ids fit");
    assert_eq!(rules.len(), CHANGE_PASSWORD_AS_RULE_COUNT as usize);
    let ids: Vec<u32> = rules.iter().map(|r| r.id.0).collect();
    assert_eq!(ids, vec![9, 10]);
    assert_eq!(rules[0].when.auth, AuthMatch::UNARMORED);
    assert_eq!(rules[0].when.subject, SubjectMatch::Any);
    assert_eq!(rules[1].when.auth, AuthMatch::ANY);
    assert_eq!(rules[1].when.subject, SubjectMatch::MemberOf(computers()));
    let last_fit = u32::MAX - (CHANGE_PASSWORD_AS_RULE_COUNT - 1);
    assert!(change_password_as_rules(computers(), RuleId(last_fit)).is_some());
    assert!(change_password_as_rules(computers(), RuleId(last_fit + 1)).is_none());
}
