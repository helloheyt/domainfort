//! The project rules that are stricter than the specifications (docs/11 §5,
//! D37), each tested against a control case that the specifications alone
//! would allow.
//!
//! Source: docs/11 §4-§5 (rules 5a-5d), [MS-DTYP] v20241119 2.5.3.2 (what the
//! specification alone would do), [MS-ADTS] v20261026 5.1.3.3.1. Hand-made
//! cases; no vector from another implementation.

mod common;

use common::*;
use dtyp::ace_type;
use pdp::access_check::rights::*;
use pdp::{
    acl_grants, dacl_preconditions, decide, Action, AttrClass, AttrId, ControlRightId, DaclRefusal,
    DirObjectContext, Effect, ObjClass, ReasonCode, Right, Tier,
};

fn object() -> DirObjectContext {
    DirObjectContext {
        object_class: class_user(),
        object_sid: None,
    }
}

/// Every kind of right, for "denies every right" checks.
fn every_right() -> Vec<Right> {
    vec![
        Right::Object {
            mask: RIGHT_DS_READ_PROPERTY,
        },
        Right::Object {
            mask: RIGHT_READ_CONTROL,
        },
        Right::Object {
            mask: GENERIC_ALL_MAPPING,
        },
        Right::Property {
            mask: RIGHT_DS_WRITE_PROPERTY,
            property_set: Some(propset()),
            attribute: attr_in_set(),
        },
        Right::CreateChild {
            class: class_group(),
        },
        Right::ControlAccess { right: right_a() },
    ]
}

// ----------------------------------------------------------------- 5a ----

/// Rule 5a: an absent DACL (DP clear) ⇒ DENY. [MS-DTYP] 2.5.3.2 says "No
/// DACL ... any access check will succeed" and [MS-ADTS] 5.1.3.3.1 "grants
/// full access" — this project removes that default.
#[test]
fn rule_5a_absent_dacl_denies_every_right() {
    let s = the_user();
    // Even for the owner (who would otherwise have implied rights).
    for owner in [None, Some(user()), Some(other_user())] {
        let d = sd_without_dacl(owner);
        assert_eq!(dacl_preconditions(&d), Err(DaclRefusal::AbsentDacl));
        for right in every_right() {
            assert!(!acl_grants(&s, &d, &object(), &right), "{right:?}");
        }
    }
}

/// Rule 5a through `decide`: layer 5 denies with reason `Acl`, although every
/// other layer allows.
#[test]
fn rule_5a_absent_dacl_denies_through_decide() {
    let pip = MockPip::with_sd(sd_without_dacl(Some(other_user())));
    let pol = policy(vec![allow_everything(1)]);
    let d = decide(
        &dir_request(the_user(), Action::DirRead, Some(attr_alone())),
        &pol,
        &pip,
    );
    assert_eq!(d.effect, Effect::Deny);
    assert_eq!(d.reason, ReasonCode::Acl);
    // Control: a DACL that grants the right is allowed.
    let pip = MockPip::with_sd(sd(
        Some(other_user()),
        vec![allow(RIGHT_DS_READ_PROPERTY, user())],
    ));
    let d = decide(
        &dir_request(the_user(), Action::DirRead, Some(attr_alone())),
        &pol,
        &pip,
    );
    assert_eq!(d.effect, Effect::Allow);
}

/// Rule 5a, second half: an empty DACL ⇒ deny, as the specs say ([MS-DTYP]
/// 2.5.3.2 "no principal can gain access ... except through the implied
/// access of the owner"; [MS-ADTS] 5.1.3.3.2 rule 2).
#[test]
fn rule_5a_empty_dacl_denies() {
    let s = the_user();
    let d = sd(Some(other_user()), vec![]);
    assert_eq!(dacl_preconditions(&d), Ok(()));
    for right in every_right() {
        assert!(!acl_grants(&s, &d, &object(), &right), "{right:?}");
    }
}

// ----------------------------------------------------------------- 5b ----

/// The AceTypes kept as `Ace::Unsupported` by dtyp ([MS-DTYP] 2.4.4.1):
/// alarm, compound, callback (allowed / denied / object), audit callback,
/// mandatory label, resource attribute, scoped policy, and the reserved
/// alarm types.
fn unsupported_types() -> Vec<u8> {
    vec![
        ace_type::SYSTEM_ALARM_ACE_TYPE,
        ace_type::ACCESS_ALLOWED_COMPOUND_ACE_TYPE,
        ace_type::SYSTEM_ALARM_OBJECT_ACE_TYPE,
        ace_type::ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
        ace_type::ACCESS_DENIED_CALLBACK_ACE_TYPE,
        ace_type::ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE,
        ace_type::ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE,
        ace_type::SYSTEM_AUDIT_CALLBACK_ACE_TYPE,
        ace_type::SYSTEM_ALARM_CALLBACK_ACE_TYPE,
        ace_type::SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE,
        ace_type::SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE,
        ace_type::SYSTEM_MANDATORY_LABEL_ACE_TYPE,
        ace_type::SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE,
        ace_type::SYSTEM_SCOPED_POLICY_ID_ACE_TYPE,
    ]
}

/// Rule 5b: ANY `Ace::Unsupported` in the DACL ⇒ DENY, even next to an ACE
/// that grants everything, and wherever it sits. [MS-DTYP] 2.5.3.2 would
/// evaluate callback ACEs and has no case for the others (they would be
/// skipped).
#[test]
fn rule_5b_unsupported_ace_denies_even_with_grant_all() {
    let s = the_user();
    for t in unsupported_types() {
        for aces in [
            vec![allow(RIGHT_GENERIC_ALL, group()), unsupported(t)],
            vec![unsupported(t), allow(RIGHT_GENERIC_ALL, group())],
        ] {
            let d = sd(Some(user()), aces);
            assert_eq!(
                dacl_preconditions(&d),
                Err(DaclRefusal::UnsupportedAce),
                "type {t:#x}"
            );
            for right in every_right() {
                assert!(!acl_grants(&s, &d, &object(), &right), "type {t:#x}");
            }
        }
    }
    // Control: the same DACL without the unsupported ACE grants everything.
    let d = sd(Some(user()), vec![allow(RIGHT_GENERIC_ALL, group())]);
    for right in every_right() {
        assert!(acl_grants(&s, &d, &object(), &right), "{right:?}");
    }
}

/// Rule 5b holds whatever the ACE's flags: an inherit-only unsupported ACE
/// (which would never be evaluated for this object) still denies.
#[test]
fn rule_5b_inherit_only_unsupported_ace_still_denies() {
    let s = the_user();
    let d = sd(
        None,
        vec![
            inherit_only(unsupported(ace_type::ACCESS_ALLOWED_CALLBACK_ACE_TYPE)),
            allow(RIGHT_GENERIC_ALL, user()),
        ],
    );
    assert_eq!(dacl_preconditions(&d), Err(DaclRefusal::UnsupportedAce));
    assert!(!acl_grants(
        &s,
        &d,
        &object(),
        &Right::Object {
            mask: RIGHT_DS_READ_PROPERTY
        }
    ));
}

/// Rule 5b also covers audit ACEs placed in a DACL ([MS-DTYP] 2.4.5: "the
/// DACL MUST NOT contain ACE types that belong in the SACL").
#[test]
fn rule_5b_audit_ace_in_dacl_denies() {
    let s = the_user();
    let audit = dtyp::Ace::SystemAudit(dtyp::MaskSidAce {
        ace_flags: dtyp::ace_flags::SUCCESSFUL_ACCESS_ACE_FLAG,
        mask: dtyp::AccessMask(RIGHT_DS_READ_PROPERTY),
        sid: everyone(),
    });
    let d = sd(None, vec![audit, allow(RIGHT_GENERIC_ALL, user())]);
    assert_eq!(dacl_preconditions(&d), Err(DaclRefusal::UnsupportedAce));
    assert!(!acl_grants(
        &s,
        &d,
        &object(),
        &Right::Object {
            mask: RIGHT_DS_READ_PROPERTY
        }
    ));
}

/// A structurally invalid descriptor is refused too (fail closed, D40):
/// here an object ACE inside an ACL_REVISION (0x02) ACL, which [MS-DTYP]
/// 2.4.5 does not permit.
#[test]
fn invalid_descriptor_denies() {
    let s = the_user();
    let mut d = sd(None, vec![allow_obj(RIGHT_GENERIC_ALL, None, user())]);
    if let Some(dacl) = d.dacl.as_mut() {
        dacl.acl_revision = dtyp::ACL_REVISION;
    }
    assert_eq!(dacl_preconditions(&d), Err(DaclRefusal::InvalidDescriptor));
    assert!(!acl_grants(
        &s,
        &d,
        &object(),
        &Right::Object {
            mask: RIGHT_DS_READ_PROPERTY
        }
    ));
}

// ----------------------------------------------------------------- 5c ----

/// Rule 5c: an attribute of class Secret is unreachable — Deny(NoSuchPath)
/// for reads and writes, even with an ACL that grants everything, an Allow-all
/// policy and a Tier-0 subject (P6).
#[test]
fn rule_5c_secret_attribute_is_unreachable() {
    let mut pip = MockPip::with_sd(sd(None, vec![allow(RIGHT_GENERIC_ALL, group())]));
    pip.attr_classes
        .insert(AttrId(attr_alone()), AttrClass::Secret);
    pip.tiers.insert(user(), Tier::Tier0);
    let admin = subject(user(), &[group()], Tier::Tier0);
    let pol = policy(vec![allow_everything(1)]);
    for action in [Action::DirRead, Action::DirWrite] {
        let d = decide(
            &dir_request(admin.clone(), action.clone(), Some(attr_alone())),
            &pol,
            &pip,
        );
        assert_eq!(d.effect, Effect::Deny, "{action:?}");
        assert_eq!(d.reason, ReasonCode::NoSuchPath, "{action:?}");
    }
    // Control: a Normal attribute on the same object is allowed.
    let d = decide(
        &dir_request(admin, Action::DirRead, Some(attr_in_set())),
        &pol,
        &pip,
    );
    assert_eq!(d.effect, Effect::Allow);
}

/// Rule 5c: a Sensitive attribute needs its control access right in addition
/// to the ACL grant ([MS-ADTS] 5.1.3.3.4 for the right; 3.1.1.4.4 for the
/// confidential-attribute model: "(RIGHT_DS_READ_PROPERTY) and
/// (RIGHT_DS_CONTROL_ACCESS)").
#[test]
fn rule_5c_sensitive_attribute_needs_its_control_right() {
    let pol = policy(vec![allow_everything(1)]);
    let sensitive = AttrClass::Sensitive {
        control_access_right: ControlRightId(right_a()),
    };
    // RP granted, control right not granted ⇒ Deny(Sensitive).
    let mut pip = MockPip::with_sd(sd(None, vec![allow(RIGHT_DS_READ_PROPERTY, user())]));
    pip.attr_classes.insert(AttrId(attr_alone()), sensitive);
    let d = decide(
        &dir_request(the_user(), Action::DirRead, Some(attr_alone())),
        &pol,
        &pip,
    );
    assert_eq!(d.effect, Effect::Deny);
    assert_eq!(d.reason, ReasonCode::Sensitive);

    // RP and the named control right ⇒ Allow.
    let mut pip = MockPip::with_sd(sd(
        None,
        vec![
            allow(RIGHT_DS_READ_PROPERTY, user()),
            allow_obj(RIGHT_DS_CONTROL_ACCESS, Some(right_a()), group()),
        ],
    ));
    pip.attr_classes.insert(AttrId(attr_alone()), sensitive);
    let d = decide(
        &dir_request(the_user(), Action::DirRead, Some(attr_alone())),
        &pol,
        &pip,
    );
    assert_eq!(d.effect, Effect::Allow);

    // A different control right does not count.
    let mut pip = MockPip::with_sd(sd(
        None,
        vec![
            allow(RIGHT_DS_READ_PROPERTY, user()),
            allow_obj(RIGHT_DS_CONTROL_ACCESS, Some(right_b()), group()),
        ],
    ));
    pip.attr_classes.insert(AttrId(attr_alone()), sensitive);
    let d = decide(
        &dir_request(the_user(), Action::DirRead, Some(attr_alone())),
        &pol,
        &pip,
    );
    assert_eq!(d.reason, ReasonCode::Sensitive);
}

// ----------------------------------------------------------------- 5d ----

fn tier0_object_pip(aces: Vec<dtyp::Ace>) -> MockPip {
    let mut pip = MockPip::with_sd(sd(None, aces));
    pip.object_tiers.insert(obj_dn(), Tier::Tier0);
    pip
}

/// Rule 5d / P5: a Tier-0 object is not writable by a lower-tier subject,
/// even though the ACL grants everything to Everyone and the policy allows
/// everything.
#[test]
fn rule_5d_tier0_object_not_writable_by_lower_tier_even_if_acl_grants() {
    let pip = tier0_object_pip(vec![allow(RIGHT_GENERIC_ALL, group())]);
    let pol = policy(vec![allow_everything(1)]);
    for action in [
        Action::DirWrite,
        Action::DirDelete,
        Action::DirAddChild(ObjClass(class_group())),
        Action::DirControlRight(ControlRightId(right_a())),
    ] {
        let attr = if action == Action::DirWrite {
            Some(attr_alone())
        } else {
            None
        };
        let d = decide(&dir_request(the_user(), action.clone(), attr), &pol, &pip);
        assert_eq!(d.effect, Effect::Deny, "{action:?}");
        assert_eq!(d.reason, ReasonCode::TierViolation, "{action:?}");
    }
}

/// Rule 5d: a Tier-0 subject passes layer 4 (and the ACL then decides).
#[test]
fn rule_5d_tier0_subject_may_write_tier0_object() {
    let mut pip = tier0_object_pip(vec![allow(RIGHT_GENERIC_ALL, group())]);
    pip.tiers.insert(user(), Tier::Tier0);
    let admin = subject(user(), &[group()], Tier::Tier0);
    let pol = policy(vec![allow_everything(1)]);
    let d = decide(
        &dir_request(admin, Action::DirWrite, Some(attr_alone())),
        &pol,
        &pip,
    );
    assert_eq!(d.effect, Effect::Allow);
}

/// Rule 5d concerns writes only: a lower-tier subject may still read a
/// Tier-0 object the ACL lets it read.
#[test]
fn rule_5d_reads_are_not_affected() {
    let pip = tier0_object_pip(vec![allow(RIGHT_GENERIC_READ, group())]);
    let pol = policy(vec![allow_everything(1)]);
    let d = decide(
        &dir_request(the_user(), Action::DirRead, Some(attr_alone())),
        &pol,
        &pip,
    );
    assert_eq!(d.effect, Effect::Allow);
}

/// Rule 5d is checked BEFORE the ACL (layer 4 before layer 5): with the
/// descriptor lookup failing, a lower-tier write is still reported as a tier
/// violation — the ACL was never consulted.
#[test]
fn rule_5d_checked_before_the_acl() {
    let mut pip = tier0_object_pip(vec![]);
    pip.failing = Failing::SecurityDescriptor;
    let pol = policy(vec![allow_everything(1)]);
    let d = decide(
        &dir_request(the_user(), Action::DirWrite, Some(attr_alone())),
        &pol,
        &pip,
    );
    assert_eq!(d.reason, ReasonCode::TierViolation);
}

/// Rule 5d applies to non-directory resources too (e.g. an RPC method the
/// PIP classifies as Tier 0), where there is no ACL at all.
#[test]
fn rule_5d_applies_to_rpc_methods() {
    let mut pip = MockPip::with_sd(sd(None, vec![]));
    pip.default_object_tier = Tier::Tier0;
    let pol = policy(vec![allow_everything(1)]);
    let req = pdp::AccessRequest {
        subject: the_user(),
        resource: pdp::Resource::RpcMethod {
            iface: guid(0x77),
            opnum: 3,
        },
        action: Action::RpcCall,
        context: strong_context(),
    };
    let d = decide(&req, &pol, &pip);
    assert_eq!(d.reason, ReasonCode::TierViolation);
}
