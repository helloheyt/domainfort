//! `decide_visibility`: search results are filtered, never refused.
//!
//! Source: docs/11 §7; docs/06 §7; [MS-ADTS] v20261026 3.1.1.4.3
//! (RIGHT_DS_LIST_CONTENTS on the parent; RIGHT_DS_READ_PROPERTY on each
//! attribute, otherwise "does not exist"), 5.1.3.3.6. Hand-made cases.

mod common;

use std::collections::BTreeSet;

use common::*;
use pdp::access_check::rights::*;
use pdp::{decide_visibility, AttrClass, AttrId, AuthStrength, DirObjectRef, Dn, Tier};

fn candidate() -> DirObjectRef {
    DirObjectRef {
        dn: obj_dn(),
        parent: Some(parent_dn()),
        attrs: vec![AttrId(attr_alone()), AttrId(attr_in_set())],
    }
}

/// A PIP where the parent grants LC to the user and the object grants RP on
/// `attr_alone` only.
fn pip_with_parent_list() -> MockPip {
    let mut pip = MockPip::with_sd(sd(
        None,
        vec![allow_obj(
            RIGHT_DS_READ_PROPERTY,
            Some(attr_alone()),
            user(),
        )],
    ));
    pip.sds.insert(
        parent_dn(),
        sd(None, vec![allow(RIGHT_DS_LIST_CONTENTS, group())]),
    );
    pip
}

/// [MS-ADTS] 3.1.1.4.3: visible through LC on the parent; only the readable
/// attributes are returned, the others are treated as absent.
#[test]
fn visible_object_returns_only_readable_attributes() {
    let pol = policy(vec![allow_everything(1)]);
    let out = decide_visibility(
        &the_user(),
        &strong_context(),
        &[candidate()],
        &pol,
        &pip_with_parent_list(),
    );
    assert_eq!(out.len(), 1);
    assert_eq!(
        out[0].readable_attrs,
        BTreeSet::from([AttrId(attr_alone())])
    );
}

/// [MS-ADTS] 3.1.1.4.3 / 5.1.3.3.6: without LC on the parent the object is
/// not visible — it is filtered out, not an error.
#[test]
fn object_without_list_right_on_parent_is_filtered_out() {
    let mut pip = pip_with_parent_list();
    pip.sds.insert(parent_dn(), sd(None, vec![]));
    let pol = policy(vec![allow_everything(1)]);
    let out = decide_visibility(&the_user(), &strong_context(), &[candidate()], &pol, &pip);
    assert!(out.is_empty());
}

/// docs/11 §7: every layer applies — an unauthenticated subject sees
/// nothing, and a Secret attribute is never returned (P6).
#[test]
fn every_layer_applies_to_search() {
    let pol = policy(vec![allow_everything(1)]);
    let mut anon = the_user();
    anon.auth.strength = AuthStrength::Unauth;
    let out = decide_visibility(
        &anon,
        &strong_context(),
        &[candidate()],
        &pol,
        &pip_with_parent_list(),
    );
    assert!(out.is_empty());

    let mut pip = pip_with_parent_list();
    pip.sds
        .insert(obj_dn(), sd(None, vec![allow(RIGHT_GENERIC_ALL, group())]));
    pip.attr_classes
        .insert(AttrId(attr_alone()), AttrClass::Secret);
    pip.tiers.insert(user(), Tier::Tier0);
    let admin = subject(user(), &[group()], Tier::Tier0);
    let out = decide_visibility(&admin, &strong_context(), &[candidate()], &pol, &pip);
    assert_eq!(out.len(), 1);
    assert_eq!(
        out[0].readable_attrs,
        BTreeSet::from([AttrId(attr_in_set())])
    );
}

/// A naming-context root (no parent) is visible only with a positive list
/// decision on itself (visibility.rs: no object is visible without a
/// decision), and an unknown object (PIP absence) is filtered out (D40).
#[test]
fn naming_context_root_and_unknown_objects() {
    let pol = policy(vec![allow_everything(1)]);
    let root = Dn::new(vec!["dc=test".into()]);
    let mut pip = pip_with_parent_list();
    pip.sds.insert(
        root.clone(),
        sd(None, vec![allow(RIGHT_DS_LIST_CONTENTS, user())]),
    );
    let nc_root = DirObjectRef {
        dn: root.clone(),
        parent: None,
        attrs: vec![],
    };
    let unknown = DirObjectRef {
        dn: Dn::new(vec!["cn=ghost".into(), "dc=test".into()]),
        parent: Some(Dn::new(vec!["ou=gone".into(), "dc=test".into()])),
        attrs: vec![AttrId(attr_alone())],
    };
    let out = decide_visibility(
        &the_user(),
        &strong_context(),
        &[nc_root.clone(), unknown],
        &pol,
        &pip,
    );
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].obj, nc_root);

    pip.sds.insert(root, sd(None, vec![]));
    let out = decide_visibility(&the_user(), &strong_context(), &[nc_root], &pol, &pip);
    assert!(out.is_empty());
}
