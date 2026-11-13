//! Integration: a descriptor computed by `dtyp::create_security_descriptor`
//! ([MS-DTYP] 2.5.3.4.1, task A2 of docs/51 §12) evaluated by `acl_grants`.
//!
//! Sources: [MS-DTYP] v20241119 2.5.3.4.1-2.5.3.4.4, 2.5.3.4.7 (how the
//! child's DACL is computed) and 2.5.3.2 (access check); [MS-ADTS] v20261026
//! 6.1.3 item 5 (the Active Directory inputs: IsContainerObject TRUE, the
//! GenericMapping table) and 5.1.3.2 / 5.1.3.3.x (directory access check);
//! project decisions A-13 (no DACL ⇒ deny), A-21 (no implicit WRITE_DAC for
//! the owner), A-76 (CreatorDescriptor NULL, owner / group from the
//! requester), A-84 (Q-335 option (b): INHERIT_ONLY parent ACEs are inherited
//! by their other flags; CREATOR_* substituted in effective ACEs only; [MS-ADTS]
//! 6.1.3 items 2, 4, 6). Each case is worked by hand from those texts; fixtures are the
//! hand-made ones of `common`. No vector comes from any other implementation.
//!
//! This file is in `pdp` because the access check is here; `dtyp` cannot
//! depend on `pdp` (the dependency goes the other way).

mod common;

use common::*;
use dtyp::{
    ace_flags, create_security_descriptor, AutoInheritFlags, GenericMapping, Guid,
    SecurityDescriptor, Token,
};
use pdp::access_check::rights::*;
use pdp::{acl_grants, DirObjectContext, Right, Subject};

/// The requester creating the child: owner and group = its SID (A-76;
/// [MS-ADTS] 6.1.3.7 — the DAG is undefined in phase 1).
fn creator_token() -> Token {
    Token {
        owner: user(),
        primary_group: user(),
        default_dacl: None,
    }
}

/// CreateSecurityDescriptor with the [MS-ADTS] 6.1.3 item 5 inputs:
/// IsContainerObject TRUE, CreatorDescriptor NULL (A-76), the requester's
/// token, the Active Directory GenericMapping, ObjectTypes = the child's
/// most specific class (item 4).
fn child_of(parent: &SecurityDescriptor, class: Guid) -> SecurityDescriptor {
    let sd = create_security_descriptor(
        Some(parent),
        None,
        true,
        Some(&[class]),
        AutoInheritFlags::default(),
        &creator_token(),
        &GenericMapping::ACTIVE_DIRECTORY,
    )
    .expect("CreateSecurityDescriptor succeeds");
    // The computed descriptor survives the strict codec unchanged.
    let bytes = sd.encode().expect("encodes");
    assert_eq!(SecurityDescriptor::decode(&bytes).expect("decodes"), sd);
    sd
}

fn ctx(class: Guid) -> DirObjectContext {
    DirObjectContext {
        object_class: class,
        superclasses: vec![],
        object_sid: None,
    }
}

fn whole(mask: u32) -> Right {
    Right::Object { mask }
}

/// Subject X: holds the group `group()` that the parent's inheritable ACE
/// names. Subject Y: another user, not in that group.
fn subject_x() -> Subject {
    the_user()
}
fn subject_y() -> Subject {
    subject(other_user(), &[other_group()], pdp::Tier::Tier1)
}

const CI: u8 = ace_flags::CONTAINER_INHERIT_ACE;
const IO: u8 = ace_flags::INHERIT_ONLY_ACE;

/// Parent: an inheritable (CI) allow of RP | WP to `group()`. Child (2.5.3.4.4,
/// container): an effective copy with INHERITED_ACE ⇒ [MS-DTYP] 2.5.3.2 /
/// [MS-ADTS] 5.1.3.3.2 grant X (a member) RP and WP on the child; Y, who
/// matches no ACE, is denied (A-13: nothing else in the DACL). A right the
/// ACE does not carry (DELETE) is denied to X too.
#[test]
fn inheritable_allow_on_the_parent_grants_that_right_on_the_child() {
    let parent = sd(
        Some(other_user()),
        vec![with_flags(
            allow(RIGHT_DS_READ_PROPERTY | RIGHT_DS_WRITE_PROPERTY, group()),
            CI,
        )],
    );
    let child = child_of(&parent, class_user());
    let object = ctx(class_user());
    assert!(acl_grants(
        &subject_x(),
        &child,
        &object,
        &whole(RIGHT_DS_READ_PROPERTY)
    ));
    assert!(acl_grants(
        &subject_x(),
        &child,
        &object,
        &whole(RIGHT_DS_WRITE_PROPERTY)
    ));
    assert!(!acl_grants(
        &subject_y(),
        &child,
        &object,
        &whole(RIGHT_DS_READ_PROPERTY)
    ));
    assert!(!acl_grants(
        &subject_x(),
        &child,
        &object,
        &whole(RIGHT_DELETE)
    ));
}

/// An inheritable deny before the allow keeps its order in the child's
/// effective copies (2.5.3.4.4 ExplicitACL in parent order) ⇒ denied.
#[test]
fn inherited_deny_keeps_its_effect() {
    let parent = sd(
        Some(other_user()),
        vec![
            with_flags(deny(RIGHT_DS_WRITE_PROPERTY, user()), CI),
            with_flags(allow(RIGHT_DS_WRITE_PROPERTY, group()), CI),
        ],
    );
    let child = child_of(&parent, class_user());
    assert!(!acl_grants(
        &subject_x(),
        &child,
        &ctx(class_user()),
        &whole(RIGHT_DS_WRITE_PROPERTY)
    ));
}

/// An object ACE scoped to the user class by InheritedObjectType (2.4.4.3;
/// 2.5.3.4.4 "ObjectTypes contains ACE.ObjectGUID", Q-336): a user child gets
/// the effective copy ⇒ granted; a group child gets only the inherit-only
/// copy, which the access check skips ⇒ denied.
#[test]
fn inherited_object_type_scopes_the_grant_to_the_child_class() {
    let scoped = dtyp::Ace::AccessAllowedObject(dtyp::ObjectAce {
        ace_flags: CI,
        mask: dtyp::AccessMask(RIGHT_DS_READ_PROPERTY),
        object_type: None,
        inherited_object_type: Some(class_user()),
        sid: group(),
    });
    let parent = sd(Some(other_user()), vec![scoped]);
    let user_child = child_of(&parent, class_user());
    let group_child = child_of(&parent, class_group());
    let read = whole(RIGHT_DS_READ_PROPERTY);
    assert!(acl_grants(
        &subject_x(),
        &user_child,
        &ctx(class_user()),
        &read
    ));
    assert!(!acl_grants(
        &subject_x(),
        &group_child,
        &ctx(class_group()),
        &read
    ));
}

/// A generic right in the parent ACE: 2.5.3.4.7 adds GENERIC_READ_MAPPING
/// (RC | LC | RP | LO, [MS-ADTS] 6.1.3 item 5.6) to the child's ACE, so RP is
/// granted on the child.
#[test]
fn generic_read_in_the_parent_ace_grants_read_property_on_the_child() {
    let parent = sd(
        Some(other_user()),
        vec![with_flags(allow(RIGHT_GENERIC_READ, group()), CI)],
    );
    let child = child_of(&parent, class_user());
    let object = ctx(class_user());
    assert!(acl_grants(
        &subject_x(),
        &child,
        &object,
        &whole(RIGHT_DS_READ_PROPERTY)
    ));
    assert!(!acl_grants(
        &subject_x(),
        &child,
        &object,
        &whole(RIGHT_DS_WRITE_PROPERTY)
    ));
}

/// A parent with no inheritable DACL ACE and a token without a default DACL:
/// the child has no DACL (2.5.3.4.2) ⇒ every request is denied (A-13, rule
/// 5a) — even for the trustee the parent's non-inheritable ACE names.
#[test]
fn child_without_inheritable_aces_is_denied_to_everyone() {
    let parent = sd(
        Some(other_user()),
        vec![allow(RIGHT_DS_READ_PROPERTY, group())],
    );
    let child = child_of(&parent, class_user());
    assert_eq!(child.dacl, None);
    assert!(!acl_grants(
        &subject_x(),
        &child,
        &ctx(class_user()),
        &whole(RIGHT_DS_READ_PROPERTY)
    ));
}

/// A-21: the creator owns the child (A-76) but gets no implicit WRITE_DAC
/// and no WRITE_OWNER — CreateSecurityDescriptor adds no ACE for the owner —
/// and keeps only the implicit READ_CONTROL (pdp OWNER_IMPLICIT_RIGHTS).
#[test]
fn the_creator_owns_the_child_without_implicit_write_dac() {
    let parent = sd(
        Some(other_user()),
        vec![with_flags(allow(RIGHT_DS_READ_PROPERTY, other_group()), CI)],
    );
    let child = child_of(&parent, class_user());
    assert_eq!(child.owner_sid, Some(user()));
    let owner = subject(user(), &[], pdp::Tier::Tier1);
    let object = ctx(class_user());
    assert!(!acl_grants(
        &owner,
        &child,
        &object,
        &whole(RIGHT_WRITE_DAC)
    ));
    assert!(!acl_grants(
        &owner,
        &child,
        &object,
        &whole(RIGHT_WRITE_OWNER)
    ));
    assert!(acl_grants(
        &owner,
        &child,
        &object,
        &whole(RIGHT_READ_CONTROL)
    ));
}

/// The same inputs as `child_of`, with the child created by `creator`
/// (owner and group = its SID, A-76).
fn child_created_by(
    parent: &SecurityDescriptor,
    class: Guid,
    creator: dtyp::Sid,
) -> SecurityDescriptor {
    let token = Token {
        owner: creator,
        primary_group: creator,
        default_dacl: None,
    };
    let sd = create_security_descriptor(
        Some(parent),
        None,
        true,
        Some(&[class]),
        AutoInheritFlags::default(),
        &token,
        &GenericMapping::ACTIVE_DIRECTORY,
    )
    .expect("CreateSecurityDescriptor succeeds");
    assert_eq!(
        SecurityDescriptor::decode(&sd.encode().expect("encodes")).expect("decodes"),
        sd
    );
    sd
}

/// A-84 (Q-335 option (b)): an INHERIT_ONLY parent ACE is inherited by its CI
/// flag ([MS-DTYP] 2.5.3.4.4, paragraph after the pseudocode: "the decision is
/// based on other flags"), so it grants on the child.
#[test]
fn inherit_only_parent_ace_grants_on_the_child_a84() {
    let io_parent = sd(
        Some(other_user()),
        vec![with_flags(allow(RIGHT_DS_READ_PROPERTY, group()), CI | IO)],
    );
    let child = child_of(&io_parent, class_user());
    let read = whole(RIGHT_DS_READ_PROPERTY);
    assert!(acl_grants(&subject_x(), &child, &ctx(class_user()), &read));
    assert!(!acl_grants(&subject_y(), &child, &ctx(class_user()), &read));
}

/// Depth 3 — root → OU → user (A-84): an inheritable allow on the root is
/// effective on the OU and on the user, so the access check grants it on the
/// user; another SID is still denied.
#[test]
fn inheritable_allow_on_the_root_grants_on_the_ou_and_on_the_user_a84() {
    let root = sd(
        Some(other_user()),
        vec![with_flags(
            allow(RIGHT_DS_READ_PROPERTY | RIGHT_DS_WRITE_PROPERTY, group()),
            CI,
        )],
    );
    let ou = child_of(&root, class_group());
    let user_object = child_of(&ou, class_user());
    let write = whole(RIGHT_DS_WRITE_PROPERTY);
    assert!(acl_grants(&subject_x(), &ou, &ctx(class_group()), &write));
    assert!(acl_grants(
        &subject_x(),
        &user_object,
        &ctx(class_user()),
        &write
    ));
    assert!(!acl_grants(
        &subject_y(),
        &user_object,
        &ctx(class_user()),
        &write
    ));
    // And one level further down.
    let below = child_of(&user_object, class_user());
    assert!(acl_grants(&subject_x(), &below, &ctx(class_user()), &write));
}

/// CREATOR_OWNER across generations (A-84; [MS-ADTS] 6.1.3 item 6): the root
/// grants CREATOR_OWNER RP | WP. The OU's creator gets it on the OU; the
/// user's creator gets it on the user; the OU's creator — the intermediate
/// owner — gets nothing on the user (the OU's inherit-only copy kept the
/// placeholder).
#[test]
fn creator_owner_grants_each_creator_and_not_the_intermediate_owner_a84() {
    let creator_owner = dtyp::Sid::new(dtyp::CREATOR_SID_AUTHORITY, &[0]).expect("S-1-3-0");
    let root = sd(
        Some(other_user()),
        vec![with_flags(
            allow(
                RIGHT_DS_READ_PROPERTY | RIGHT_DS_WRITE_PROPERTY,
                creator_owner,
            ),
            CI,
        )],
    );
    let ou_creator = subject(user(), &[], pdp::Tier::Tier1);
    let user_creator = subject(other_user(), &[], pdp::Tier::Tier1);
    let ou = child_created_by(&root, class_group(), user());
    let user_object = child_created_by(&ou, class_user(), other_user());
    let write = whole(RIGHT_DS_WRITE_PROPERTY);
    assert!(acl_grants(&ou_creator, &ou, &ctx(class_group()), &write));
    assert!(!acl_grants(&user_creator, &ou, &ctx(class_group()), &write));
    assert!(acl_grants(
        &user_creator,
        &user_object,
        &ctx(class_user()),
        &write
    ));
    assert!(!acl_grants(
        &ou_creator,
        &user_object,
        &ctx(class_user()),
        &write
    ));
}

/// NO_PROPAGATE_INHERIT_ACE stops at depth 1: root (CI|NP) → OU granted →
/// user under the OU has no DACL ⇒ denied (A-13).
#[test]
fn no_propagate_inherit_stops_at_depth_one() {
    let root = sd(
        Some(other_user()),
        vec![with_flags(
            allow(RIGHT_DS_READ_PROPERTY, group()),
            CI | ace_flags::NO_PROPAGATE_INHERIT_ACE,
        )],
    );
    let ou = child_of(&root, class_group());
    let user_object = child_of(&ou, class_user());
    let read = whole(RIGHT_DS_READ_PROPERTY);
    assert!(acl_grants(&subject_x(), &ou, &ctx(class_group()), &read));
    assert_eq!(user_object.dacl, None);
    assert!(!acl_grants(
        &subject_x(),
        &user_object,
        &ctx(class_user()),
        &read
    ));
}

/// An InheritedObjectType mismatch at depth 2: the root's ACE is scoped to
/// the user class. The OU (group class here) is denied; under the OU a user
/// object is granted and a group object is denied ([MS-ADTS] 6.1.3 item 4).
#[test]
fn inherited_object_type_mismatch_at_depth_two_is_denied() {
    let scoped = dtyp::Ace::AccessAllowedObject(dtyp::ObjectAce {
        ace_flags: CI,
        mask: dtyp::AccessMask(RIGHT_DS_READ_PROPERTY),
        object_type: None,
        inherited_object_type: Some(class_user()),
        sid: group(),
    });
    let root = sd(Some(other_user()), vec![scoped]);
    let ou = child_of(&root, class_group());
    let read = whole(RIGHT_DS_READ_PROPERTY);
    assert!(!acl_grants(&subject_x(), &ou, &ctx(class_group()), &read));
    let user_object = child_of(&ou, class_user());
    let group_object = child_of(&ou, class_group());
    assert!(acl_grants(
        &subject_x(),
        &user_object,
        &ctx(class_user()),
        &read
    ));
    assert!(!acl_grants(
        &subject_x(),
        &group_object,
        &ctx(class_group()),
        &read
    ));
}

/// The two transcriptions of the [MS-ADTS] Active Directory generic mapping —
/// dtyp's (6.1.3 item 5.6) and pdp's (5.1.3.2) — agree.
#[test]
fn active_directory_generic_mapping_matches_the_pdp_table() {
    let m = GenericMapping::ACTIVE_DIRECTORY;
    assert_eq!(m.generic_read, GENERIC_READ_MAPPING);
    assert_eq!(m.generic_write, GENERIC_WRITE_MAPPING);
    assert_eq!(m.generic_execute, GENERIC_EXECUTE_MAPPING);
    assert_eq!(m.generic_all, GENERIC_ALL_MAPPING);
}
