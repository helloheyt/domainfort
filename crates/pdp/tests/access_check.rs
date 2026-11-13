//! `acl_grants` cases hand-derived from the access-check texts.
//!
//! Source of every case: [MS-DTYP] v20241119 2.5.3.2 (Access Check Algorithm
//! Pseudocode) and [MS-ADTS] v20261026 5.1.3.3.2 / 5.1.3.3.3 / 5.1.3.3.4,
//! worked by hand from the clause named on each test. No vector comes from
//! another implementation.

mod common;

use common::*;
use pdp::access_check::rights::*;
use pdp::{acl_grants, DirObjectContext, Right, Subject};

fn object() -> DirObjectContext {
    DirObjectContext {
        object_class: class_user(),
        object_sid: None,
    }
}

fn whole(mask: u32) -> Right {
    Right::Object { mask }
}

fn prop(mask: u32, attribute: dtyp::Guid) -> Right {
    let property_set = if attribute == attr_in_set() || attribute == attr_in_set_2() {
        Some(propset())
    } else {
        None
    };
    Right::Property {
        mask,
        property_set,
        attribute,
    }
}

fn grants(s: &Subject, aces: Vec<dtyp::Ace>, right: Right) -> bool {
    acl_grants(s, &sd(Some(other_user()), aces), &object(), &right)
}

// ------------------------------------------------ simple ACEs, ordering ----

/// [MS-DTYP] 2.5.3.2 "CASE Allow Access ... Remove ACE.AccessMask from
/// RemainingAccess"; [MS-ADTS] 5.1.3.3.2 step 4.4.
#[test]
fn allow_ace_for_token_sid_grants_its_rights() {
    let s = the_user();
    assert!(grants(
        &s,
        vec![allow(RIGHT_DS_READ_PROPERTY, user())],
        whole(RIGHT_DS_READ_PROPERTY)
    ));
}

/// [MS-DTYP] 2.5.3.2 "IF RemainingAccess to 0 THEN Return success Else
/// Return access_denied"; [MS-ADTS] 5.1.3.1 (end of DACL ⇒ deny).
#[test]
fn no_matching_ace_denies() {
    let s = the_user();
    assert!(!grants(
        &s,
        vec![allow(RIGHT_DS_WRITE_PROPERTY, user())],
        whole(RIGHT_DS_READ_PROPERTY)
    ));
}

/// [MS-DTYP] 2.5.3.2 "Allow Access" removes each ACE's mask from
/// RemainingAccess in turn; [MS-ADTS] 5.1.3.3.2 step 4.4 adds each to G.
#[test]
fn partial_grants_accumulate_across_aces() {
    let s = the_user();
    let both = RIGHT_DS_READ_PROPERTY | RIGHT_DS_WRITE_PROPERTY;
    assert!(grants(
        &s,
        vec![
            allow(RIGHT_DS_READ_PROPERTY, user()),
            allow(RIGHT_DS_WRITE_PROPERTY, group()),
        ],
        whole(both)
    ));
    assert!(!grants(
        &s,
        vec![allow(RIGHT_DS_READ_PROPERTY, user())],
        whole(both)
    ));
}

/// [MS-DTYP] 2.5.3.2 "CASE Deny Access ... IF any bit of RemainingAccess is
/// in ACE.AccessMask THEN ... Return access_denied"; [MS-ADTS] 5.1.3.1
/// (order matters; a deny met first wins).
#[test]
fn deny_before_allow_denies() {
    let s = the_user();
    assert!(!grants(
        &s,
        vec![
            deny(RIGHT_DS_READ_PROPERTY, group()),
            allow(RIGHT_DS_READ_PROPERTY, user()),
        ],
        whole(RIGHT_DS_READ_PROPERTY)
    ));
}

/// [MS-DTYP] 2.5.3.2: once the allow cleared the bit, the deny finds no
/// pending bit; [MS-ADTS] 5.1.3.3.2 step 4.3 ("the access rights in M are not
/// in G" — RP already is) and 5.1.3.1 ("If the access check process
/// encounters the ACE that allows access ... before the ACE that denies ...
/// the principal is allowed").
#[test]
fn allow_before_deny_grants() {
    let s = the_user();
    assert!(grants(
        &s,
        vec![
            allow(RIGHT_DS_READ_PROPERTY, group()),
            deny(RIGHT_DS_READ_PROPERTY, user()),
        ],
        whole(RIGHT_DS_READ_PROPERTY)
    ));
}

/// [MS-DTYP] 2.5.3.2 "IF any bit of RemainingAccess is in ACE.AccessMask THEN
/// ... Return access_denied" — the whole request fails, not just that bit.
#[test]
fn deny_of_any_pending_right_denies_the_whole_request() {
    let s = the_user();
    let aces = vec![
        allow(RIGHT_DS_READ_PROPERTY, user()),
        deny(RIGHT_DS_READ_PROPERTY | RIGHT_DS_WRITE_PROPERTY, user()),
        allow(RIGHT_DS_WRITE_PROPERTY, user()),
    ];
    assert!(!grants(
        &s,
        aces.clone(),
        whole(RIGHT_DS_READ_PROPERTY | RIGHT_DS_WRITE_PROPERTY)
    ));
    // RP alone was satisfied before the deny.
    assert!(grants(&s, aces, whole(RIGHT_DS_READ_PROPERTY)));
}

/// [MS-DTYP] 2.5.3.1.1 SidInToken; [MS-ADTS] 5.1.3.3.2 step 4.2 ("If the SID
/// in the ACE does not match any SID in the requester's security context,
/// skip the ACE").
#[test]
fn ace_for_other_sid_is_skipped() {
    let s = the_user();
    assert!(!grants(
        &s,
        vec![allow(RIGHT_DS_READ_PROPERTY, other_user())],
        whole(RIGHT_DS_READ_PROPERTY)
    ));
    // ...and a deny for someone else does not block the user.
    assert!(grants(
        &s,
        vec![
            deny(RIGHT_DS_READ_PROPERTY, other_group()),
            allow(RIGHT_DS_READ_PROPERTY, user()),
        ],
        whole(RIGHT_DS_READ_PROPERTY)
    ));
}

/// [MS-DTYP] 2.5.2 (Sids[] holds "the SIDs of all groups to which the user
/// belongs") and 2.5.3.1.1.
#[test]
fn ace_for_group_in_token_applies() {
    let s = the_user();
    assert!(grants(
        &s,
        vec![allow(RIGHT_DS_LIST_CONTENTS, group())],
        whole(RIGHT_DS_LIST_CONTENTS)
    ));
    let not_member = subject(user(), &[], pdp::Tier::Tier1);
    assert!(!grants(
        &not_member,
        vec![allow(RIGHT_DS_LIST_CONTENTS, group())],
        whole(RIGHT_DS_LIST_CONTENTS)
    ));
}

/// [MS-DTYP] 2.5.3.2 "IF ACE.AceFlags does not contain INHERIT_ONLY_ACE
/// THEN"; [MS-ADTS] 5.1.3.3.2 step 4.1 ("If the 'Inherit Only' (IO) flag is
/// set in the ACE, skip the ACE").
#[test]
fn inherit_only_allow_is_skipped() {
    let s = the_user();
    assert!(!grants(
        &s,
        vec![inherit_only(allow(RIGHT_DS_READ_PROPERTY, user()))],
        whole(RIGHT_DS_READ_PROPERTY)
    ));
}

/// Same clauses as above, for a deny ACE.
#[test]
fn inherit_only_deny_is_skipped() {
    let s = the_user();
    assert!(grants(
        &s,
        vec![
            inherit_only(deny(RIGHT_DS_READ_PROPERTY, user())),
            allow(RIGHT_DS_READ_PROPERTY, user()),
        ],
        whole(RIGHT_DS_READ_PROPERTY)
    ));
}

/// [MS-DTYP] 2.5.3.2 "CASE Deny Access: IF ACE.AccessMask equals 0 ... THEN
/// Break" — a deny with no rights has no effect.
#[test]
fn zero_mask_deny_has_no_effect() {
    let s = the_user();
    assert!(grants(
        &s,
        vec![deny(0, user()), allow(RIGHT_DS_READ_PROPERTY, user())],
        whole(RIGHT_DS_READ_PROPERTY)
    ));
}

// ---------------------------------------- object ACEs, property sets ----

/// [MS-DTYP] 2.5.3.2 "CASE Object Allow Access ... Locate node n ... Remove
/// ACE.AccessMask from n.Remaining"; [MS-ADTS] 5.1.3.3.3 step 3.5 and step 4
/// (check Grant(u) of the attribute node).
#[test]
fn object_allow_on_attribute_grants_that_attribute_only() {
    let s = the_user();
    let aces = vec![allow_obj(
        RIGHT_DS_READ_PROPERTY,
        Some(attr_alone()),
        user(),
    )];
    assert!(grants(
        &s,
        aces.clone(),
        prop(RIGHT_DS_READ_PROPERTY, attr_alone())
    ));
    assert!(!grants(
        &s,
        aces.clone(),
        prop(RIGHT_DS_READ_PROPERTY, attr_in_set())
    ));
    // Not the whole object (5.1.3.3.3 step 4 "Grant(r)").
    assert!(!grants(&s, aces.clone(), whole(RIGHT_DS_READ_PROPERTY)));
    // Not another right on the same attribute.
    assert!(!grants(
        &s,
        aces,
        prop(RIGHT_DS_WRITE_PROPERTY, attr_alone())
    ));
}

/// [MS-ADTS] 5.1.3.3.3 step 3.5 ("For every descendant node u of v ... add
/// the rights in M to Grant(u)"); [MS-DTYP] 2.5.3.2 ("FOR each node ns such
/// that ns is a descendent of n DO Remove ACE.AccessMask from ns.Remaining").
#[test]
fn object_allow_on_property_set_grants_its_attributes() {
    let s = the_user();
    let aces = vec![allow_obj(RIGHT_DS_WRITE_PROPERTY, Some(propset()), group())];
    assert!(grants(
        &s,
        aces.clone(),
        prop(RIGHT_DS_WRITE_PROPERTY, attr_in_set())
    ));
    assert!(grants(
        &s,
        aces.clone(),
        prop(RIGHT_DS_WRITE_PROPERTY, attr_in_set_2())
    ));
    // An attribute outside the set is not a descendant.
    assert!(!grants(
        &s,
        aces,
        prop(RIGHT_DS_WRITE_PROPERTY, attr_alone())
    ));
}

/// [MS-ADTS] 5.1.3.3.3 step 3.8 (deny at v and its descendants not yet
/// granted) then 3.3 (a later simple allow cannot add rights in Deny(u));
/// [MS-DTYP] 2.5.3.2 "CASE Object Deny Access ... If any bit of n.Remaining
/// is in ACE.AccessMask THEN ... Return access_denied".
#[test]
fn object_deny_on_property_set_blocks_member_attributes() {
    let s = the_user();
    let aces = vec![
        deny_obj(RIGHT_DS_READ_PROPERTY, Some(propset()), user()),
        allow(RIGHT_DS_READ_PROPERTY, user()),
    ];
    assert!(!grants(
        &s,
        aces.clone(),
        prop(RIGHT_DS_READ_PROPERTY, attr_in_set())
    ));
    // The attribute outside the set is untouched by the deny.
    assert!(grants(&s, aces, prop(RIGHT_DS_READ_PROPERTY, attr_alone())));
}

/// [MS-DTYP] 2.4.4.3 ("If the AccessCheck algorithm ... does not find an
/// appropriate GUID, then that ACE will be ignored"); [MS-ADTS] 5.1.3.3.3
/// steps 3.5 / 3.8 ("If there exists no node v ... such that Guid(v) = g,
/// then skip the ACE").
#[test]
fn object_ace_with_guid_outside_the_tree_is_ignored() {
    let s = the_user();
    assert!(!grants(
        &s,
        vec![allow_obj(RIGHT_DS_READ_PROPERTY, Some(guid(0x99)), user())],
        prop(RIGHT_DS_READ_PROPERTY, attr_alone())
    ));
    assert!(grants(
        &s,
        vec![
            deny_obj(RIGHT_DS_READ_PROPERTY, Some(guid(0x99)), user()),
            allow(RIGHT_DS_READ_PROPERTY, user()),
        ],
        prop(RIGHT_DS_READ_PROPERTY, attr_alone())
    ));
}

/// [MS-ADTS] 5.1.3.3.3 step 3.4 ("'Object Access Allowed' and the ObjectType
/// field in the ACE is not present, then treat the ACE type as 'Access
/// Allowed'") and step 3.7 (the same for denies); [MS-DTYP] 2.4.4.3
/// ("Otherwise, the ObjectType field is ignored").
#[test]
fn object_ace_without_object_type_acts_as_simple_ace() {
    let s = the_user();
    let allow_all_attrs = vec![allow_obj(RIGHT_DS_READ_PROPERTY, None, user())];
    assert!(grants(
        &s,
        allow_all_attrs.clone(),
        whole(RIGHT_DS_READ_PROPERTY)
    ));
    assert!(grants(
        &s,
        allow_all_attrs,
        prop(RIGHT_DS_READ_PROPERTY, attr_in_set())
    ));
    assert!(!grants(
        &s,
        vec![
            deny_obj(RIGHT_DS_READ_PROPERTY, None, user()),
            allow(RIGHT_DS_READ_PROPERTY, user()),
        ],
        prop(RIGHT_DS_READ_PROPERTY, attr_alone())
    ));
}

/// [MS-ADTS] 5.1.3.3.3 step 3.8 then 3.5: a deny on one attribute does not
/// affect a sibling attribute granted through the property set, and a deny on
/// the attribute after it was granted does not revoke the grant (step 3.8:
/// "If the rights in M are not in Grant(v)"); [MS-DTYP] 2.5.3.2 agrees (the
/// node's Remaining is already clear).
#[test]
fn attribute_deny_after_attribute_grant_keeps_grant() {
    let s = the_user();
    assert!(grants(
        &s,
        vec![
            allow_obj(RIGHT_DS_READ_PROPERTY, Some(attr_alone()), user()),
            deny_obj(RIGHT_DS_READ_PROPERTY, Some(attr_alone()), user()),
        ],
        prop(RIGHT_DS_READ_PROPERTY, attr_alone())
    ));
}

/// The texts diverge (Q-051), and the stricter result is kept: [MS-ADTS]
/// 5.1.3.3.3 step 3.6 leaves the attribute's earlier grant in place, but
/// [MS-DTYP] 2.5.3.2 "CASE Deny Access" tests the top-level RemainingAccess,
/// which an object ACE never reduces ⇒ access_denied.
#[test]
fn simple_deny_after_object_grant_denies() {
    let s = the_user();
    assert!(!grants(
        &s,
        vec![
            allow_obj(RIGHT_DS_READ_PROPERTY, Some(attr_alone()), user()),
            deny(RIGHT_DS_READ_PROPERTY, user()),
        ],
        prop(RIGHT_DS_READ_PROPERTY, attr_alone())
    ));
}

/// Divergence (Q-051), stricter result kept: [MS-ADTS] 5.1.3.3.3 step 3.8
/// does not revoke the attribute's earlier grant, but [MS-DTYP] 2.5.3.2
/// "Object Deny Access" finds the bit still in the property set node's
/// Remaining ⇒ access_denied.
#[test]
fn property_set_deny_after_attribute_grant_denies() {
    let s = the_user();
    assert!(!grants(
        &s,
        vec![
            allow_obj(RIGHT_DS_READ_PROPERTY, Some(attr_in_set()), user()),
            deny_obj(RIGHT_DS_READ_PROPERTY, Some(propset()), user()),
        ],
        prop(RIGHT_DS_READ_PROPERTY, attr_in_set())
    ));
}

// ---------------------------------------------------------- create child ----

/// [MS-ADTS] 3.1.1.5.2.1 (CC "for the objectClass of the object being
/// added"), 5.1.3.2 (CC: "The ObjectType member of an ACE can contain a GUID
/// that identifies the objectClass of child object ... If ObjectType does not
/// contain a GUID, the ACE controls the creation of all child object
/// classes"); 5.1.3.3.3 steps 3.3 / 3.5.
#[test]
fn create_child_object_ace_names_the_child_class() {
    let s = the_user();
    let typed = vec![allow_obj(
        RIGHT_DS_CREATE_CHILD,
        Some(class_group()),
        user(),
    )];
    assert!(grants(
        &s,
        typed.clone(),
        Right::CreateChild {
            class: class_group()
        }
    ));
    assert!(!grants(&s, typed, Right::CreateChild { class: guid(0x12) }));
    let simple = vec![allow(RIGHT_DS_CREATE_CHILD, user())];
    assert!(grants(
        &s,
        simple.clone(),
        Right::CreateChild { class: guid(0x12) }
    ));
    assert!(grants(
        &s,
        simple,
        Right::CreateChild {
            class: class_group()
        }
    ));
}

/// [MS-ADTS] 5.1.3.3.3 step 3.8 then 3.3; [MS-DTYP] 2.5.3.2 "Object Deny
/// Access".
#[test]
fn create_child_deny_for_one_class() {
    let s = the_user();
    let aces = vec![
        deny_obj(RIGHT_DS_CREATE_CHILD, Some(class_group()), user()),
        allow(RIGHT_DS_CREATE_CHILD, user()),
    ];
    assert!(!grants(
        &s,
        aces.clone(),
        Right::CreateChild {
            class: class_group()
        }
    ));
    assert!(grants(&s, aces, Right::CreateChild { class: guid(0x12) }));
}

/// A child of the object's own class (two nodes with one GUID — the object
/// type tree uses the first match; object_tree.rs). [MS-ADTS] 5.1.3.3.3 step
/// 3.5.
#[test]
fn create_child_of_the_same_class_as_the_parent() {
    let s = the_user();
    assert!(grants(
        &s,
        vec![allow_obj(RIGHT_DS_CREATE_CHILD, Some(class_user()), user())],
        Right::CreateChild {
            class: class_user()
        }
    ));
}

// --------------------------------------------------- control access rights ----

/// [MS-ADTS] 5.1.3.3.4 step 3.4 ("'Object Access Allowed' the access right
/// RIGHT_DS_CONTROL_ACCESS (CR) is present in M, and the ObjectType field in
/// the ACE contains a GUID value equal to G, then grant").
#[test]
fn control_access_object_ace_names_the_right() {
    let s = the_user();
    let aces = vec![allow_obj(RIGHT_DS_CONTROL_ACCESS, Some(right_a()), user())];
    assert!(grants(
        &s,
        aces.clone(),
        Right::ControlAccess { right: right_a() }
    ));
    assert!(!grants(&s, aces, Right::ControlAccess { right: right_b() }));
}

/// [MS-ADTS] 5.1.3.3.4 step 3.3 ("... and the ObjectType field in the ACE is
/// not present, then grant the requested control access right"); 5.1.3.2.1.
#[test]
fn control_access_without_object_type_covers_every_right() {
    let s = the_user();
    let aces = vec![allow_obj(RIGHT_DS_CONTROL_ACCESS, None, user())];
    assert!(grants(
        &s,
        aces.clone(),
        Right::ControlAccess { right: right_a() }
    ));
    assert!(grants(&s, aces, Right::ControlAccess { right: right_b() }));
}

/// [MS-ADTS] 5.1.3.3.4 steps 3.6 then 3.4: the first matching ACE decides
/// ("Stop any further access checks").
#[test]
fn control_access_first_matching_ace_decides() {
    let s = the_user();
    assert!(!grants(
        &s,
        vec![
            deny_obj(RIGHT_DS_CONTROL_ACCESS, Some(right_a()), group()),
            allow_obj(RIGHT_DS_CONTROL_ACCESS, Some(right_a()), user()),
        ],
        Right::ControlAccess { right: right_a() }
    ));
    assert!(grants(
        &s,
        vec![
            allow_obj(RIGHT_DS_CONTROL_ACCESS, Some(right_a()), user()),
            deny_obj(RIGHT_DS_CONTROL_ACCESS, Some(right_a()), group()),
        ],
        Right::ControlAccess { right: right_a() }
    ));
    // A deny for another right does not stop the check.
    assert!(grants(
        &s,
        vec![
            deny_obj(RIGHT_DS_CONTROL_ACCESS, Some(right_b()), user()),
            allow_obj(RIGHT_DS_CONTROL_ACCESS, Some(right_a()), user()),
        ],
        Right::ControlAccess { right: right_a() }
    ));
}

/// [MS-ADTS] 5.1.3.3.4 steps 3.3-3.6 all require "RIGHT_DS_CONTROL_ACCESS
/// (CR) is present in M".
#[test]
fn control_access_requires_the_cr_bit() {
    let s = the_user();
    assert!(!grants(
        &s,
        vec![allow_obj(RIGHT_DS_READ_PROPERTY, Some(right_a()), user())],
        Right::ControlAccess { right: right_a() }
    ));
}

/// A simple ACE has no ObjectType, so it "control[s] the right to perform all
/// control access right controlled operations" ([MS-ADTS] 5.1.3.2 CR,
/// 5.1.3.2.1); [MS-DTYP] 2.5.3.2 "Allow Access" / "Deny Access" agree.
/// Recorded in Q-051.
#[test]
fn control_access_through_simple_aces() {
    let s = the_user();
    assert!(grants(
        &s,
        vec![allow(RIGHT_DS_CONTROL_ACCESS, user())],
        Right::ControlAccess { right: right_a() }
    ));
    assert!(!grants(
        &s,
        vec![
            deny(RIGHT_DS_CONTROL_ACCESS, user()),
            allow_obj(RIGHT_DS_CONTROL_ACCESS, Some(right_a()), user()),
        ],
        Right::ControlAccess { right: right_a() }
    ));
}

/// [MS-ADTS] 5.1.3.3.4 rule 2 ("If the DACL does not have any ACE, then deny
/// the requester the requested control access right").
#[test]
fn control_access_empty_dacl_denies() {
    let s = the_user();
    assert!(!grants(
        &s,
        vec![],
        Right::ControlAccess { right: right_a() }
    ));
}

// ------------------------------------------------------- owner implicit ----

fn owned_by_user(aces: Vec<dtyp::Ace>) -> dtyp::SecurityDescriptor {
    sd(Some(user()), aces)
}

/// [MS-DTYP] 2.5.3.2 (the owner is implicitly granted READ_CONTROL; overview:
/// an empty DACL admits no one "except through the implied access of the
/// owner"); [MS-ADTS] 5.1.3.3.1 ("even with an empty DACL ... the current
/// OWNER of an object is implicitly granted RIGHT_READ_CONTROL") — and,
/// project decision A-21 (Q-050), nothing more: the implicit WRITE_DAC is
/// blocked as in the BlockOwnerImplicitRights mode of [MS-ADTS] 5.1.3.3.1 /
/// 6.1.3.4.
#[test]
fn owner_gets_only_read_control_with_empty_dacl() {
    let s = the_user();
    let o = object();
    let d = owned_by_user(vec![]);
    assert!(acl_grants(&s, &d, &o, &whole(RIGHT_READ_CONTROL)));
    assert!(!acl_grants(&s, &d, &o, &whole(RIGHT_WRITE_DAC)));
    assert!(!acl_grants(
        &s,
        &d,
        &o,
        &whole(RIGHT_READ_CONTROL | RIGHT_WRITE_DAC)
    ));
    // Nothing else is implied.
    assert!(!acl_grants(
        &s,
        &d,
        &o,
        &whole(RIGHT_READ_CONTROL | RIGHT_DELETE)
    ));
}

/// A-21 (Q-050): no owner ever holds WRITE_DAC implicitly — whatever the
/// DACL holds (as long as it does not grant WD), whether the owner SID is the
/// user's own or a group the user belongs to. READ_CONTROL stays implied
/// when no ACE "from object owner" is present ([MS-DTYP] 2.5.3.2).
#[test]
fn owner_never_gets_write_dac_implicitly() {
    let o = object();
    for owner in [user(), group()] {
        for aces in [
            vec![],
            vec![allow(RIGHT_DS_READ_PROPERTY, other_group())],
            vec![allow(RIGHT_READ_CONTROL, other_user())],
            vec![deny(RIGHT_DS_WRITE_PROPERTY, other_user())],
        ] {
            let d = sd(Some(owner), aces.clone());
            let s = the_user();
            assert!(
                !acl_grants(&s, &d, &o, &whole(RIGHT_WRITE_DAC)),
                "{owner:?} {aces:?}"
            );
            assert!(
                acl_grants(&s, &d, &o, &whole(RIGHT_READ_CONTROL)),
                "{owner:?} {aces:?}"
            );
        }
    }
}

/// A-21: administrators — and owners — get WRITE_DAC through an explicit ACE
/// ([MS-DTYP] 2.5.3.2 "Allow Access"; [MS-ADTS] 5.1.3.3.2 step 4.4).
#[test]
fn explicit_write_dac_ace_for_owner_grants() {
    let s = the_user();
    let o = object();
    let d = owned_by_user(vec![allow(RIGHT_WRITE_DAC, user())]);
    assert!(acl_grants(&s, &d, &o, &whole(RIGHT_WRITE_DAC)));
    let d = owned_by_user(vec![allow(RIGHT_WRITE_DAC | RIGHT_READ_CONTROL, group())]);
    assert!(acl_grants(
        &s,
        &d,
        &o,
        &whole(RIGHT_WRITE_DAC | RIGHT_READ_CONTROL)
    ));
}

/// WRITE_OWNER is implied only with SeTakeOwnershipPrivilege ([MS-DTYP]
/// 2.5.3.2; [MS-ADTS] 5.1.3.3.1 "If the user possesses the
/// SE_TAKE_OWNERSHIP_PRIVILEGE, then RIGHT_WRITE_OWNER access is implied"),
/// although [MS-ADTS] 5.1.3.3.2 step 3 adds WO for every owner — the
/// conflict resolves to the stricter result (Q-050, A-21).
#[test]
fn owner_does_not_get_write_owner_implicitly() {
    let s = the_user();
    assert!(!acl_grants(
        &s,
        &owned_by_user(vec![]),
        &object(),
        &whole(RIGHT_WRITE_OWNER)
    ));
}

/// [MS-ADTS] 5.1.3.3.2 rule 2; [MS-DTYP] 2.5.3.2 overview ("no principal can
/// gain access to the object, except through the implied access of the
/// owner").
#[test]
fn non_owner_gets_nothing_from_empty_dacl() {
    let s = the_user();
    assert!(!acl_grants(
        &s,
        &sd(Some(other_user()), vec![]),
        &object(),
        &whole(RIGHT_READ_CONTROL)
    ));
}

/// [MS-DTYP] 2.5.3.2 ("IF DACL does not contain ACEs from object owner THEN
/// Remove READ_CONTROL and WRITE_DAC") — read broadly (Q-050, A-21): an ACE
/// whose trustee is the owner SID suppresses the implicit READ_CONTROL.
#[test]
fn owner_implicit_rights_suppressed_by_ace_for_owner() {
    let s = the_user();
    let d = owned_by_user(vec![allow(RIGHT_DS_READ_PROPERTY, user())]);
    assert!(!acl_grants(&s, &d, &object(), &whole(RIGHT_READ_CONTROL)));
    // Granted explicitly, it is of course available.
    let d = owned_by_user(vec![allow(RIGHT_READ_CONTROL, user())]);
    assert!(acl_grants(&s, &d, &object(), &whole(RIGHT_READ_CONTROL)));
}

/// [MS-DTYP] 2.4.2.4 (OWNER_RIGHTS: "When an ACE that carries this SID is
/// applied to an object, the system ignores the implicit READ_CONTROL and
/// WRITE_DAC permissions for the object owner").
#[test]
fn owner_implicit_rights_suppressed_by_owner_rights_ace() {
    let s = the_user();
    let d = owned_by_user(vec![allow(RIGHT_DS_READ_PROPERTY, owner_rights())]);
    assert!(!acl_grants(&s, &d, &object(), &whole(RIGHT_READ_CONTROL)));
}

/// OWNER_RIGHTS "represents the current owner of the object" ([MS-DTYP]
/// 2.4.2.4); exact SidInToken (2.5.3.1.1) matches only a token holding
/// S-1-3-4. Q-050 (A-21) strict interim reading — verify in lab recording
/// (docs/44): a deny applies if either reading applies, a grant only if both
/// do.
#[test]
fn owner_rights_ace_matching_is_fail_closed() {
    let owner = the_user();
    let d = owned_by_user(vec![
        deny(RIGHT_DS_READ_PROPERTY, owner_rights()),
        allow(RIGHT_DS_READ_PROPERTY, user()),
    ]);
    assert!(!acl_grants(
        &owner,
        &d,
        &object(),
        &whole(RIGHT_DS_READ_PROPERTY)
    ));

    let d = owned_by_user(vec![allow(RIGHT_DS_READ_PROPERTY, owner_rights())]);
    assert!(!acl_grants(
        &owner,
        &d,
        &object(),
        &whole(RIGHT_DS_READ_PROPERTY)
    ));

    let owner_with_sid = subject(user(), &[owner_rights()], pdp::Tier::Tier1);
    assert!(acl_grants(
        &owner_with_sid,
        &d,
        &object(),
        &whole(RIGHT_DS_READ_PROPERTY)
    ));
    // Not the owner: the grant does not apply even with S-1-3-4 in the token.
    let not_owner = subject(other_user(), &[owner_rights()], pdp::Tier::Tier1);
    assert!(!acl_grants(
        &not_owner,
        &d,
        &object(),
        &whole(RIGHT_DS_READ_PROPERTY)
    ));
}

// ------------------------------------------------------- principal self ----

/// [MS-DTYP] 2.5.3.1.1 ("IF SidToTest is the Well Known SID PRINCIPAL_SELF
/// THEN set SidToTest to be PrincipalSelfSubstitute"); [MS-ADTS] 5.1.3.3
/// ("the server replaces them with O!objectSid").
#[test]
fn principal_self_is_replaced_by_object_sid() {
    let s = the_user();
    let d = sd(
        Some(other_user()),
        vec![allow(RIGHT_DS_READ_PROPERTY, principal_self())],
    );
    let self_object = DirObjectContext {
        object_class: class_user(),
        object_sid: Some(user()),
    };
    assert!(acl_grants(
        &s,
        &d,
        &self_object,
        &whole(RIGHT_DS_READ_PROPERTY)
    ));
    let other_object = DirObjectContext {
        object_class: class_user(),
        object_sid: Some(other_user()),
    };
    assert!(!acl_grants(
        &s,
        &d,
        &other_object,
        &whole(RIGHT_DS_READ_PROPERTY)
    ));
    // No objectSid: PrincipalSelfSubst is null and matches nothing.
    assert!(!acl_grants(
        &s,
        &d,
        &object(),
        &whole(RIGHT_DS_READ_PROPERTY)
    ));
}

// -------------------------------------------- generic rights and X bits ----

/// [MS-ADTS] 5.1.3.2 ("GR = (RC | LC | RP | LO)").
#[test]
fn generic_read_in_ace_is_mapped() {
    let s = the_user();
    let aces = vec![allow(RIGHT_GENERIC_READ, user())];
    for right in [
        RIGHT_READ_CONTROL,
        RIGHT_DS_LIST_CONTENTS,
        RIGHT_DS_READ_PROPERTY,
        RIGHT_DS_LIST_OBJECT,
    ] {
        assert!(grants(&s, aces.clone(), whole(right)));
    }
    assert!(!grants(&s, aces, whole(RIGHT_DS_WRITE_PROPERTY)));
}

/// [MS-ADTS] 5.1.3.2 ("GA = (DE | RC | WD | WO | CC | DC | DT | RP | WP | LC
/// | LO | CR | VW)").
#[test]
fn generic_all_in_ace_is_mapped() {
    let s = the_user();
    let aces = vec![allow(RIGHT_GENERIC_ALL, group())];
    assert!(grants(&s, aces.clone(), whole(GENERIC_ALL_MAPPING)));
    assert!(grants(
        &s,
        aces.clone(),
        prop(RIGHT_DS_WRITE_PROPERTY, attr_in_set())
    ));
    assert!(grants(&s, aces, Right::ControlAccess { right: right_a() }));
    // A generic deny is mapped too.
    assert!(!grants(
        &s,
        vec![
            deny(RIGHT_GENERIC_WRITE, user()),
            allow(RIGHT_GENERIC_ALL, user())
        ],
        whole(RIGHT_DS_WRITE_PROPERTY)
    ));
}

/// [MS-ADTS] 5.1.3.2 ("X: Ignored. These bits are ignored in Active Directory
/// DACLs").
#[test]
fn x_bits_in_ace_are_ignored() {
    let s = the_user();
    // SYNCHRONIZE (0x00100000) and bit 0x00000200 are X positions.
    let x_only = 0x0010_0000 | 0x0000_0200;
    assert!(!grants(
        &s,
        vec![allow(x_only, user())],
        whole(RIGHT_DS_READ_PROPERTY)
    ));
    assert!(grants(
        &s,
        vec![deny(x_only, user()), allow(RIGHT_DS_READ_PROPERTY, user())],
        whole(RIGHT_DS_READ_PROPERTY)
    ));
}

/// A request may name only the specific rights of [MS-ADTS] 5.1.3.2: an
/// empty mask, a generic right, an X bit, MAXIMUM_ALLOWED or
/// ACCESS_SYSTEM_SECURITY is refused (fail closed, D40).
#[test]
fn malformed_request_masks_are_refused() {
    let s = the_user();
    let aces = vec![allow(RIGHT_GENERIC_ALL, user())];
    for mask in [
        0,
        RIGHT_GENERIC_READ,
        0x0000_0200,
        MAXIMUM_ALLOWED,
        ACCESS_SYSTEM_SECURITY,
    ] {
        assert!(!grants(&s, aces.clone(), whole(mask)), "mask {mask:#x}");
        assert!(
            !grants(&s, aces.clone(), prop(mask, attr_alone())),
            "mask {mask:#x}"
        );
    }
}

/// The [MS-ADTS] 5.1.3.2 values agree with the [MS-DTYP] 2.4.3 / 2.4.4.3 /
/// 2.5.1.1 values carried by `dtyp::AccessMask`.
#[test]
fn adts_right_values_match_dtyp_constants() {
    use dtyp::AccessMask as M;
    assert_eq!(RIGHT_DS_CREATE_CHILD, M::ADS_RIGHT_DS_CREATE_CHILD);
    assert_eq!(RIGHT_DS_DELETE_CHILD, M::ADS_RIGHT_DS_DELETE_CHILD);
    assert_eq!(RIGHT_DS_LIST_CONTENTS, M::DIRECTORY_OBJECT_LIST_CHILDREN);
    assert_eq!(RIGHT_DS_WRITE_PROPERTY_EXTENDED, M::ADS_RIGHT_DS_SELF);
    assert_eq!(RIGHT_DS_READ_PROPERTY, M::ADS_RIGHT_DS_READ_PROP);
    assert_eq!(RIGHT_DS_WRITE_PROPERTY, M::ADS_RIGHT_DS_WRITE_PROP);
    assert_eq!(RIGHT_DS_DELETE_TREE, M::DIRECTORY_OBJECT_DELETE_TREE);
    assert_eq!(RIGHT_DS_LIST_OBJECT, M::DIRECTORY_OBJECT_LIST_OBJECT);
    assert_eq!(RIGHT_DS_CONTROL_ACCESS, M::ADS_RIGHT_DS_CONTROL_ACCESS);
    assert_eq!(RIGHT_DELETE, M::DELETE);
    assert_eq!(RIGHT_READ_CONTROL, M::READ_CONTROL);
    assert_eq!(RIGHT_WRITE_DAC, M::WRITE_DACL);
    assert_eq!(RIGHT_WRITE_OWNER, M::WRITE_OWNER);
    assert_eq!(RIGHT_GENERIC_ALL, M::GENERIC_ALL);
    assert_eq!(RIGHT_GENERIC_EXECUTE, M::GENERIC_EXECUTE);
    assert_eq!(RIGHT_GENERIC_WRITE, M::GENERIC_WRITE);
    assert_eq!(RIGHT_GENERIC_READ, M::GENERIC_READ);
    assert_eq!(ACCESS_SYSTEM_SECURITY, M::ACCESS_SYSTEM_SECURITY);
    assert_eq!(MAXIMUM_ALLOWED, M::MAXIMUM_ALLOWED);
    // GA maps to exactly the specific positions of the diagram.
    assert_eq!(GENERIC_ALL_MAPPING, DIRECTORY_RIGHTS);
}
